#!/usr/bin/env python3
"""Secret-scanner event log: one JSON line per noteworthy scanner outcome.

Every component (agent hooks, the pre-write hook, the Git pre-commit
dispatcher, the Forgejo hook reconciler) appends to one per-host file,
``~/.local/state/secret-scanner/events.jsonl``. A user timer ships new lines
to the fleet's VictoriaLogs on iad-ci, so every host's errors can be queried
in one place:

    secret-scanner-events query --since 24h          # fleet-wide, central
    secret-scanner-events tail                       # this host, local file

The log never holds scanned content. Callers pass outcome metadata only; any
captured scanner or Git text (stderr, finding locations, block reasons) is
scanned again before it is written and withheld if it matches a rule. Logging
must never change a hook decision, so ``record`` swallows every error.
"""

import argparse
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


SOURCE = "secret-scanner"
DEFAULT_URL = "https://victorialogs-iad-ci-ts.ardenone.com:8444"
STREAM_FIELDS = "source,host,component"
EVENTS = "events.jsonl"
ROTATED = "events.jsonl.1"
CURSOR = "ship-cursor.json"
SHIP_STATUS = "ship-status.json"
LOCK = "events.lock"
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_LINE_BYTES = 16 * 1024
MAX_TEXT_CHARS = 2000
MAX_MESSAGE_CHARS = 300
MAX_LIST_ITEMS = 20
SHIP_BATCH_BYTES = 512 * 1024
VERIFY_TIMEOUT_SECONDS = 3
WITHHELD = "[withheld: matched a secret-scanner rule]"
UNVERIFIED = "[withheld: could not be re-scanned]"
CA_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
)
OUTCOMES = ("blocked", "denied", "error", "warning", "slow", "ok")


def state_dir() -> Path:
    override = os.environ.get("SECRET_SCANNER_LOG_DIR")
    return Path(override) if override else Path.home() / ".local/state/secret-scanner"


def enabled() -> bool:
    return os.environ.get("SECRET_SCANNER_LOG", "").strip().lower() not in {
        "off", "0", "false", "no",
    }


def central_url() -> str:
    return os.environ.get("SECRET_SCANNER_LOG_URL", DEFAULT_URL).rstrip("/")


def scanner_path() -> str:
    return os.environ.get("SECRET_SCANNER_BIN") or str(Path.home() / ".local/bin/secret-scanner")


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def host() -> str:
    return socket.gethostname().split(".", 1)[0]


def text(value, limit: int = MAX_TEXT_CHARS) -> str:
    """Printable text, tail-truncated: a failure's cause is usually last."""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = "".join(
        ch if ch in "\n\t" or (ch >= " " and ch != "\x7f") else "?" for ch in str(value)
    ).strip()
    if len(value) > limit:
        value = "..." + value[-limit:]
    return value


def clean(value):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        items = [clean(item) for item in list(value)[:MAX_LIST_ITEMS]]
        if len(value) > MAX_LIST_ITEMS:
            items.append(f"...and {len(value) - MAX_LIST_ITEMS} more")
        return items
    return text(value)


def _strings(value) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return [value] if isinstance(value, str) else []


def verify(fields: dict) -> str | None:
    """None when captured text is safe to log, else the replacement text."""
    payload = "\n".join(s for v in fields.values() for s in _strings(v)).encode()
    if not payload.strip():
        return None
    try:
        result = subprocess.run(
            [scanner_path(), "--stdin", "--quiet", "--path-label", "<event-log>"],
            input=payload, capture_output=True, check=False,
            timeout=VERIFY_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return UNVERIFIED
    if result.returncode in (0, 3):
        return None
    return WITHHELD if result.returncode == 1 else UNVERIFIED


def _rotate_if_needed(directory: Path, path: Path) -> None:
    try:
        if path.stat().st_size < MAX_FILE_BYTES:
            return
    except FileNotFoundError:
        return
    lock = os.open(directory / LOCK, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return  # another writer is rotating
        try:
            if path.stat().st_size >= MAX_FILE_BYTES:
                os.replace(path, directory / ROTATED)
        except FileNotFoundError:
            pass
    finally:
        os.close(lock)


def append(event: dict) -> None:
    directory = state_dir()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / EVENTS
    data = (json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    if len(data) > MAX_LINE_BYTES:
        for key in ("stderr", "detail", "reason", "findings"):
            if key in event:
                event[key] = "[truncated: event exceeded the line limit]"
        data = (json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n").encode()
    _rotate_if_needed(directory, path)
    # One O_APPEND write per event keeps concurrent writers from interleaving.
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)


def record(component: str, outcome: str, message: str, *,
           untrusted: dict | None = None, **fields) -> None:
    """Append one event; never raises.

    ``fields`` must be metadata the caller generated (paths, exit codes,
    durations, tool names). Anything captured from the scanner or Git goes in
    ``untrusted``; it is re-scanned and withheld if it matches a rule.
    """
    if not enabled():
        return
    try:
        event = {
            "ts": now(), "source": SOURCE, "host": host(),
            "component": component, "outcome": outcome,
            "msg": text(message, MAX_MESSAGE_CHARS),
            "pid": os.getpid(),
        }
        for key, value in fields.items():
            if value is not None:
                event[key] = clean(value)
        captured = {
            key: clean(value) for key, value in (untrusted or {}).items()
            if value not in (None, "", b"", [], ())
        }
        if captured:
            replacement = verify(captured)
            if replacement is not None:
                captured = {key: replacement for key in captured}
                event["withheld"] = True
            event.update(captured)
        append(event)
    except Exception:  # noqa: BLE001 -- the log must never break a hook
        pass


# --- shipping --------------------------------------------------------------

def _load_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_json(path: Path, value: dict) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(value, handle, sort_keys=True)
        handle.write("\n")
    os.replace(temporary, path)


def _ssl_context() -> ssl.SSLContext:
    for candidate in (os.environ.get("SSL_CERT_FILE"), os.environ.get("NIX_SSL_CERT_FILE"),
                      *CA_BUNDLES):
        if candidate and Path(candidate).is_file():
            return ssl.create_default_context(cafile=candidate)
    return ssl.create_default_context()


def post(url: str, body: bytes, timeout: float) -> None:
    query = urllib.parse.urlencode({
        "_stream_fields": STREAM_FIELDS, "_time_field": "ts", "_msg_field": "msg",
    })
    request = urllib.request.Request(
        f"{url}/insert/jsonline?{query}", data=body, method="POST",
        headers={"Content-Type": "application/stream+json"},
    )
    context = _ssl_context() if url.startswith("https:") else None
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        if response.status // 100 != 2:
            raise OSError(f"HTTP {response.status}")


def _ship_file(path: Path, offset: int, url: str, timeout: float, cursor_path: Path,
               inode: int) -> tuple[int, int]:
    """Ship complete lines from offset; returns (new offset, lines shipped)."""
    shipped = 0
    with path.open("rb") as handle:
        size = os.fstat(handle.fileno()).st_size
        if offset > size:
            offset = 0  # truncated or replaced under the same inode
        while offset < size:
            handle.seek(offset)
            chunk = handle.read(SHIP_BATCH_BYTES)
            end = chunk.rfind(b"\n")
            if end < 0:
                if len(chunk) < SHIP_BATCH_BYTES:
                    break  # a writer is mid-line; ship it next run
                end = len(chunk) - 1  # an over-long line cannot be valid; skip it
            lines = []
            for raw in chunk[: end + 1].splitlines():
                try:
                    event = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(event, dict):
                    lines.append(json.dumps(event, separators=(",", ":"), ensure_ascii=False))
            if lines:
                post(url, ("\n".join(lines) + "\n").encode(), timeout)
                shipped += len(lines)
            offset += end + 1
            _save_json(cursor_path, {"inode": inode, "offset": offset})
    return offset, shipped


def ship(url: str | None = None, timeout: float = 20.0) -> int:
    url = (url or central_url()).rstrip("/")
    directory = state_dir()
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    cursor_path = directory / CURSOR
    status_path = directory / SHIP_STATUS
    status = _load_json(status_path)
    status["last_attempt"] = now()
    status["url"] = url
    if url.lower() == "off":
        status["last_error"] = "shipping disabled (SECRET_SCANNER_LOG_URL=off)"
        _save_json(status_path, status)
        return 0
    lock = os.open(directory / f"{CURSOR}.lock", os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0  # another shipper run is active
        cursor = _load_json(cursor_path)
        live = directory / EVENTS
        rotated = directory / ROTATED
        try:
            live_inode = live.stat().st_ino
        except FileNotFoundError:
            live_inode = None
        plan = []
        if cursor.get("inode") and cursor.get("inode") != live_inode:
            try:
                if rotated.stat().st_ino == cursor["inode"]:
                    plan.append((rotated, int(cursor.get("offset", 0))))
            except FileNotFoundError:
                pass
            if live_inode is not None:
                plan.append((live, 0))
        elif live_inode is not None:
            plan.append((live, int(cursor.get("offset", 0))))
        shipped = 0
        try:
            for path, offset in plan:
                inode = path.stat().st_ino
                _, count = _ship_file(path, offset, url, timeout, cursor_path, inode)
                shipped += count
        except (OSError, urllib.error.URLError, ValueError) as error:
            status["last_error"] = f"{now()} {type(error).__name__}: {text(error, 300)}"
            _save_json(status_path, status)
            print(f"secret-scanner-events: ship failed: {status['last_error']}", file=sys.stderr)
            return 1
        if plan and plan[-1][0] == live:
            # Point the cursor at the live file even when nothing new was shipped.
            current = _load_json(cursor_path)
            if current.get("inode") != live_inode:
                _save_json(cursor_path, {"inode": live_inode, "offset": 0})
        status["last_success"] = now()
        status["last_shipped_lines"] = shipped
        status.pop("last_error", None)
        _save_json(status_path, status)
        return 0
    finally:
        os.close(lock)


# --- reading ---------------------------------------------------------------

def _format(event: dict) -> str:
    parts = [
        str(event.get("ts") or event.get("_time", ""))[:23],
        str(event.get("host", "?")),
        str(event.get("component", "?")),
        str(event.get("outcome", "?")),
    ]
    for key in ("repo", "cwd"):
        if event.get(key):
            parts.append(f"{key}={event[key]}")
            break
    if event.get("scanner_rc") is not None:
        parts.append(f"rc={event['scanner_rc']}")
    if event.get("duration_ms") is not None:
        parts.append(f"{event['duration_ms']}ms")
    line = "  ".join(parts)
    message = str(event.get("msg") or event.get("_msg") or "")
    line += f"\n    {message}"
    stderr = event.get("stderr")
    if stderr:
        tail = str(stderr).strip().splitlines()[-3:]
        line += "".join(f"\n    stderr: {item}" for item in tail)
    return line


def _local_events() -> list[dict]:
    events = []
    for name in (ROTATED, EVENTS):
        try:
            raw = (state_dir() / name).read_bytes()
        except OSError:
            continue
        for line in raw.splitlines():
            try:
                event = json.loads(line)
            except ValueError:
                continue
            if isinstance(event, dict):
                events.append(event)
    return events


def tail(count: int, as_json: bool) -> int:
    events = _local_events()[-count:]
    if not events:
        print(f"no events in {state_dir() / EVENTS}")
    for event in events:
        print(json.dumps(event) if as_json else _format(event))
    return 0


def query(since: str, hosts: list[str], components: list[str], outcomes: list[str],
          limit: int, as_json: bool, timeout: float) -> int:
    filters = [f"_time:{since}", '{source="secret-scanner"}']
    for name, values in (("host", hosts), ("component", components), ("outcome", outcomes)):
        if values:
            filters.append("(" + " OR ".join(f"{name}:={json.dumps(v)}" for v in values) + ")")
    logsql = " ".join(filters)
    params = urllib.parse.urlencode({"query": logsql, "limit": str(limit)})
    url = f"{central_url()}/select/logsql/query?{params}"
    context = _ssl_context() if url.startswith("https:") else None
    try:
        with urllib.request.urlopen(url, timeout=timeout, context=context) as response:
            body = response.read()
    except (OSError, urllib.error.URLError) as error:
        print(f"secret-scanner-events: query failed: {error}", file=sys.stderr)
        print("secret-scanner-events: this host's own events: secret-scanner-events tail",
              file=sys.stderr)
        return 1
    events = []
    for line in body.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict):
            events.append(event)
    events.sort(key=lambda e: str(e.get("_time", "")))
    if not events:
        print(f"no events: {logsql}")
    for event in events:
        print(json.dumps(event) if as_json else _format(event))
    return 0


def status() -> int:
    directory = state_dir()
    live = directory / EVENTS
    cursor = _load_json(directory / CURSOR)
    ship_status = _load_json(directory / SHIP_STATUS)
    try:
        stat = live.stat()
        size, inode = stat.st_size, stat.st_ino
    except FileNotFoundError:
        size, inode = 0, None
    backlog = size - int(cursor.get("offset", 0)) if cursor.get("inode") == inode else size
    events = _local_events()
    report = {
        "host": host(),
        "log": str(live),
        "events_local": len(events),
        "last_event": events[-1].get("ts") if events else None,
        "unshipped_bytes": max(backlog, 0),
        "central": central_url(),
        **{f"ship_{key}": value for key, value in ship_status.items() if key != "url"},
    }
    print(json.dumps(report, indent=2))
    return 0


# --- CLI for shell callers ------------------------------------------------------

def _read_capture(path: str | None, limit: int = 64 * 1024) -> bytes | None:
    if not path:
        return None
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - limit))
            return handle.read()
    except OSError:
        return None


def _field(value: str):
    key, separator, raw = value.partition("=")
    if not separator or not key.isidentifier():
        raise argparse.ArgumentTypeError("--field needs key=value")
    return key, int(raw) if raw.lstrip("-").isdigit() else raw


def cli_record(args) -> int:
    untrusted = {}
    stderr = _read_capture(args.stderr_file)
    if stderr:
        untrusted["stderr"] = stderr
    findings = _read_capture(args.findings_file)
    if findings:
        lines = findings.decode("utf-8", errors="replace").splitlines()
        untrusted["findings"] = lines
        args.field.append(("finding_count", len(lines)))
    record(args.component, args.outcome, args.message, untrusted=untrusted,
           **dict(args.field))
    return 0


def cli_unit_result(args) -> int:
    """ExecStopPost helper: record a oneshot unit's result with its journal tail."""
    result = os.environ.get("SERVICE_RESULT", "unknown")
    exit_code = os.environ.get("EXIT_CODE", "")
    exit_status = os.environ.get("EXIT_STATUS", "")
    fields = {"unit": args.unit, "service_result": result,
              "exit_code": exit_code or None, "exit_status": exit_status or None}
    if result == "success":
        record(args.component, "ok", f"{args.unit} succeeded", **fields)
        return 0
    journal = None
    invocation = os.environ.get("INVOCATION_ID")
    selectors = [[f"_SYSTEMD_INVOCATION_ID={invocation}"]] if invocation else []
    selectors.append(["-u", args.unit, "--since", "-30min"])
    for selector in selectors:
        try:
            journal = subprocess.run(
                ["journalctl", "--user", *selector, "-o", "cat", "--no-pager", "-n", "40"],
                capture_output=True, check=False, timeout=10,
            ).stdout
        except (OSError, subprocess.TimeoutExpired):
            journal = None
        if journal and journal.strip() and b"-- No entries --" not in journal:
            break
        journal = None
    record(args.component, "error",
           f"{args.unit} failed: result={result} {exit_code}={exit_status}".strip(),
           untrusted={"stderr": journal}, **fields)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="secret-scanner-events",
        description="Secret-scanner event log: record, ship, and read scanner outcomes.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    show = commands.add_parser("tail", help="show this host's recent events")
    show.add_argument("-n", "--count", type=int, default=20)
    show.add_argument("--json", action="store_true")

    fleet = commands.add_parser("query", help="query every host's events in VictoriaLogs")
    fleet.add_argument("--since", default="24h", help="LogsQL duration, e.g. 1h, 7d")
    fleet.add_argument("--host", action="append", default=[])
    fleet.add_argument("--component", action="append", default=[])
    fleet.add_argument("--outcome", action="append", default=[], choices=OUTCOMES)
    fleet.add_argument("--limit", type=int, default=200)
    fleet.add_argument("--json", action="store_true")
    fleet.add_argument("--timeout", type=float, default=30.0)

    commands.add_parser("status", help="local log size, shipping backlog, last ship")

    send = commands.add_parser("ship", help="send unshipped events to VictoriaLogs")
    send.add_argument("--url", default=None)
    send.add_argument("--timeout", type=float, default=20.0)

    write = commands.add_parser("record", help="append an event (for shell callers)")
    write.add_argument("--component", required=True)
    write.add_argument("--outcome", required=True, choices=OUTCOMES)
    write.add_argument("--message", required=True)
    write.add_argument("--field", type=_field, action="append", default=[])
    write.add_argument("--stderr-file", help="captured stderr; re-scanned before logging")
    write.add_argument("--findings-file", help="path:line:rule report; re-scanned before logging")

    unit = commands.add_parser("unit-result", help="ExecStopPost: record a unit's result")
    unit.add_argument("--component", required=True)
    unit.add_argument("--unit", required=True)

    args = parser.parse_args(argv)
    if args.command == "tail":
        return tail(args.count, args.json)
    if args.command == "query":
        return query(args.since, args.host, args.component, args.outcome, args.limit,
                     args.json, args.timeout)
    if args.command == "status":
        return status()
    if args.command == "ship":
        return ship(args.url, args.timeout)
    if args.command == "record":
        return cli_record(args)
    return cli_unit_result(args)


if __name__ == "__main__":
    sys.exit(main())

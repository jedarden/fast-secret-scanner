#!/usr/bin/env python3
"""Install the secret-scanner event log on this host, then prove it end to end.

Installs hooks/scanlog.py, the `secret-scanner-events` command and the
shipping timer. Refreshes the hook helpers, Git dispatcher and reconcile unit
this host already runs. It never enables a hook the host does not have, and
never edits agent settings or Git configuration. With --apply it then records
a canary event, ships it, and finds it in the central VictoriaLogs.

    python3 scripts/install-event-log.py            # dry run
    python3 scripts/install-event-log.py --apply
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
import uuid


REPO = Path(__file__).resolve().parents[1]
HOME = Path.home()
SHARE = HOME / ".local/share/secret-scanner"
UNITS = HOME / ".config/systemd/user"
COMMAND = HOME / ".local/bin/secret-scanner-events"
DISPATCH_MARKER = b"Shared Git hook dispatcher: fast Rust scan"
WRAPPER = (
    "#!/bin/sh\n"
    "# Installed by fast-secret-scanner scripts/install-event-log.py\n"
    'exec python3 "$HOME/.local/share/secret-scanner/scanlog.py" "$@"\n'
)


def git_global(key: str) -> str:
    result = subprocess.run(["git", "config", "--global", "--get", key],
                            capture_output=True, text=True, check=False)
    return result.stdout.strip()


def dispatchers() -> list[Path]:
    """Installed copies of hooks/git-dispatch: the active global hook path's
    dispatcher, plus this project's own state directory, when they are ours."""
    found = []
    active = git_global("core.hooksPath")
    for directory in ([Path(active).expanduser()] if active else []) + [SHARE / "hooks"]:
        candidate = directory / "dispatch"
        try:
            if DISPATCH_MARKER in candidate.read_bytes()[:400] and candidate not in found:
                found.append(candidate)
        except OSError:
            continue
    return found


def plan() -> list[tuple[bytes, Path, int, str]]:
    items = [
        ((REPO / "hooks/scanlog.py").read_bytes(), SHARE / "scanlog.py", 0o755, "event log"),
        (WRAPPER.encode(), COMMAND, 0o755, "command"),
    ]
    for name in ("agent_hook.py", "prewrite_hook.py"):
        if (SHARE / name).exists():
            items.append(((REPO / "hooks" / name).read_bytes(), SHARE / name, 0o755,
                          "refresh installed hook"))
    for path in dispatchers():
        items.append(((REPO / "hooks/git-dispatch").read_bytes(), path, 0o755,
                      "refresh installed Git dispatcher"))
    for name in ("secret-scanner-log-ship.service", "secret-scanner-log-ship.timer"):
        items.append(((REPO / "deploy/systemd" / name).read_bytes(), UNITS / name, 0o644,
                      "shipping unit"))
    reconcile = UNITS / "secret-scanner-reconcile.service"
    if reconcile.exists():
        items.append(((REPO / "deploy/systemd/secret-scanner-reconcile.service").read_bytes(),
                      reconcile, 0o644, "refresh installed reconcile unit"))
    return items


def atomic_write(content: bytes, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temporary:
        temporary.write(content)
        temporary_path = Path(temporary.name)
    os.chmod(temporary_path, mode)
    os.replace(temporary_path, destination)


def systemctl(*args: str) -> None:
    subprocess.run(["systemctl", "--user", *args], check=True)


def verify(timeout: float) -> None:
    canary = f"install-canary-{uuid.uuid4().hex[:12]}"
    events = [sys.executable, str(SHARE / "scanlog.py")]
    subprocess.run([*events, "record", "--component", "event-log", "--outcome", "ok",
                    "--message", "event log installed", "--field", f"canary={canary}"],
                   check=True)
    shipped = subprocess.run([*events, "ship"], check=False)
    if shipped.returncode != 0:
        raise SystemExit("verify: shipping failed; see `secret-scanner-events status`")
    url = os.environ.get("SECRET_SCANNER_LOG_URL", "https://victorialogs-iad-ci-ts.ardenone.com:8444")
    query = urllib.parse.urlencode({
        "query": f'_time:30m {{source="secret-scanner"}} canary:="{canary}"', "limit": "5",
    })
    sys.path.insert(0, str(SHARE))
    import scanlog  # the installed copy: its CA-bundle discovery
    deadline = time.monotonic() + timeout
    while True:
        try:
            with urllib.request.urlopen(f"{url.rstrip('/')}/select/logsql/query?{query}",
                                        timeout=15, context=scanlog._ssl_context()) as response:
                rows = [json.loads(line) for line in response.read().splitlines() if line.strip()]
        except OSError as error:
            rows, last = [], error
        else:
            last = None
        if rows:
            row = rows[0]
            print(f"verify: canary {canary} found centrally (host={row.get('host')}, "
                  f"_time={row.get('_time')})")
            return
        if time.monotonic() > deadline:
            raise SystemExit(f"verify: canary {canary} not found in {url} after {timeout:.0f}s"
                             + (f" ({last})" if last else ""))
        time.sleep(3)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true", help="install after a dry run")
    parser.add_argument("--no-verify", action="store_true",
                        help="skip the end-to-end canary (offline installs)")
    parser.add_argument("--verify-timeout", type=float, default=60.0)
    args = parser.parse_args()

    units_changed = False
    for content, destination, mode, reason in plan():
        try:
            current = destination.read_bytes()
        except OSError:
            current = None
        state = "unchanged" if current == content else "install" if current is None else "update"
        print(f"{state:9} {destination}  ({reason})")
        if state != "unchanged" and args.apply:
            atomic_write(content, destination, mode)
            units_changed |= destination.parent == UNITS
    if not args.apply:
        print("dry run; re-run with --apply")
        return
    if units_changed:
        systemctl("daemon-reload")
    systemctl("enable", "--now", "secret-scanner-log-ship.timer")
    if shutil.which("secret-scanner-events") is None:
        print(f"note: {COMMAND.parent} is not on PATH here; use {COMMAND}")
    if not args.no_verify:
        verify(args.verify_timeout)


if __name__ == "__main__":
    main()

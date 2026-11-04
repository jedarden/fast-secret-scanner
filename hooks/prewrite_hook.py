#!/usr/bin/env python3
"""Scan proposed writes and literal shell commands before agent tools run."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


def _load_event_log():
    """The shared event log sits beside this hook. A missing or broken copy
    disables logging, never scanning."""
    try:
        spec = importlib.util.spec_from_file_location(
            "secret_scanner_event_log", Path(__file__).resolve().with_name("scanlog.py")
        )
        if spec is None or spec.loader is None:
            return None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except Exception:  # noqa: BLE001
        return None


EVENT_LOG = _load_event_log()
DETAILS = (
    " Details: `secret-scanner-events tail` (~/.local/state/secret-scanner/events.jsonl)."
    if EVENT_LOG is not None else ""
)
SLOW_SCAN_MS = 10_000
FINDING_RULE = re.compile(r"^<proposed-write>:[1-9][0-9]*:([a-z][a-z0-9-]*)$")
# Facts about this invocation for the event log. Never the proposed content
# or command: that is exactly what this hook keeps out of every record.
SCAN: dict = {}


MAX_EVENT_BYTES = 12_000_000
MAX_CONTENT_BYTES = 10_000_000
CONTENT_KEYS = {"content", "text", "new_string", "new_content", "new_source", "new_text", "replacement", "data", "body", "value", "patch"}
OPAQUE_KEYS = {"base64", "bytes", "blob", "binary", "attachment", "file", "upload"}
PATH_KEYS = {"file_path", "path", "target_path", "filename", "destination", "source_path", "source"}


def deny(reason: str) -> dict:
    SCAN["deny_reason"] = reason
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}


def _strings(value: object) -> list[str] | None:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return value
    return None


def _patch_additions(command: object) -> list[str] | None:
    if not isinstance(command, str):
        return None
    lines = command.splitlines(keepends=True)
    if not lines or lines[0].strip() != "*** Begin Patch" or lines[-1].strip() != "*** End Patch":
        return None
    additions: list[str] = []
    action = False
    for line in lines[1:-1]:
        if line.startswith(("*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: ")):
            action = True
        elif line.startswith("+"):
            if not action:
                return None
            additions.append(line[1:])
        elif line.startswith(("-", " ", "@@", "*** End of File")):
            if not action:
                return None
        else:
            return None
    return additions if action else None


def _generic_contents(value: object) -> list[str] | None:
    """Read explicit text fields only; reject binary, encoded, or unknown writes."""
    if not isinstance(value, dict):
        return None
    if any(key in value for key in OPAQUE_KEYS) or value.get("encoding") not in (None, "utf-8", "utf8", "text"):
        return None
    contents: list[str] = []
    for key, item in value.items():
        if key in CONTENT_KEYS:
            strings = _strings(item)
            if strings is None:
                return None
            if key == "patch":
                for patch in strings:
                    additions = _patch_additions(patch)
                    if additions is None:
                        return None
                    contents.extend(additions)
            else:
                contents.extend(strings)
        elif key in ("edits", "changes", "files"):
            if not isinstance(item, list) or not item:
                return None
            for child in item:
                nested = _generic_contents(child)
                if nested is None:
                    return None
                contents.extend(nested)
        elif key in PATH_KEYS or key in {"encoding", "description", "line", "start_line", "end_line", "replace_all", "old_string", "old_text", "cell_id", "cell_type", "edit_mode", "overwrite", "mime_type"}:
            continue
        else:
            # Unknown fields may carry additional or opaque write content.
            return None
    return contents if contents else None


def proposed_content(event: dict) -> list[str] | None:
    tool = event.get("tool_name")
    value = event.get("tool_input")
    if not isinstance(tool, str) or not isinstance(value, dict):
        return None
    if any(key in value for key in OPAQUE_KEYS) or value.get("encoding") not in (None, "utf-8", "utf8", "text"):
        return None
    if tool == "Bash":
        return _strings(value.get("command"))
    if tool == "apply_patch":
        return _patch_additions(value.get("command"))
    if tool == "Write":
        return _strings(value.get("content"))
    if tool == "Edit":
        return _strings(value.get("new_string"))
    if tool == "MultiEdit":
        edits = value.get("edits")
        if not isinstance(edits, list) or not edits:
            return None
        if any(not isinstance(edit, dict) or any(key in edit for key in OPAQUE_KEYS) for edit in edits):
            return None
        parts = [_strings(edit.get("new_string")) if isinstance(edit, dict) else None for edit in edits]
        return [part for group in parts if group is not None for part in group] if all(group is not None for group in parts) else None
    if tool == "NotebookEdit":
        return _strings(value.get("new_source"))
    return _generic_contents(value)


def decision(event: dict) -> dict:
    SCAN.clear()
    if event.get("hook_event_name") != "PreToolUse":
        return deny("secret-scanner received an invalid pre-write event; write denied.")
    contents = proposed_content(event)
    if contents is None:
        if event.get("tool_name") == "Bash":
            return deny("secret-scanner could not inspect this shell command; execution denied.")
        return deny("secret-scanner could not inspect this structured write; use a text writer with explicit content.")
    payload = "\n".join(contents).encode("utf-8")
    SCAN["payload_bytes"] = len(payload)
    if len(payload) > MAX_CONTENT_BYTES:
        return deny("secret-scanner could not scan an oversized proposed write.")
    scanner = os.environ.get("SECRET_SCANNER_BIN") or str(Path.home() / ".local/bin/secret-scanner")
    started = time.monotonic()
    try:
        result = subprocess.run(
            [scanner, "--stdin", "--path-label", "<proposed-write>"],
            input=payload,
            capture_output=True,
            check=False,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        SCAN.update(timed_out=True, scan_ms=int((time.monotonic() - started) * 1000))
        return deny("secret-scanner timed out at its 20 s limit; proposed write denied." + DETAILS)
    except OSError as error:
        SCAN["exec_error"] = f"{type(error).__name__}: {error}"
        return deny("secret-scanner could not execute; proposed write denied." + DETAILS)
    SCAN.update(scanner_rc=result.returncode, stderr=result.stderr,
                scan_ms=int((time.monotonic() - started) * 1000))
    if result.returncode == 0:
        return {}
    if result.returncode == 1:
        rules = {m.group(1) for line in result.stdout.decode("utf-8", errors="replace").splitlines()
                 if (m := FINDING_RULE.fullmatch(line))}
        SCAN.update(blocked=True, rules=sorted(rules))
        return deny("secret-scanner found a possible secret in the proposed write; remove it and retry.")
    return deny(f"secret-scanner could not complete the proposed write scan (exit {result.returncode}); write denied." + DETAILS)


def log_outcome(event: dict, output: dict, started: float) -> None:
    """Record every denial and slow scan; allowed fast writes are not logged."""
    if EVENT_LOG is None:
        return
    try:
        elapsed = int((time.monotonic() - started) * 1000)
        reason = SCAN.get("deny_reason")
        if reason:
            rc = SCAN.get("scanner_rc")
            if SCAN.get("blocked"):
                outcome = "blocked"
            elif SCAN.get("timed_out") or SCAN.get("exec_error") or rc not in (None, 0, 1):
                outcome = "error"
            else:
                outcome = "denied"  # uninspectable, oversized or malformed input: policy
        elif elapsed >= SLOW_SCAN_MS:
            outcome, reason = "slow", f"scan took {elapsed} ms of the 20 s limit"
        else:
            return
        transcript = str(event.get("transcript_path") or "")
        agent = ("codex" if "/.codex/" in transcript
                 else "claude" if "/.claude/" in transcript else None)
        EVENT_LOG.record(
            "prewrite-hook", outcome, reason.replace(DETAILS, ""),
            untrusted={"stderr": SCAN.get("stderr")},
            agent=agent,
            tool=event.get("tool_name"),
            session_id=event.get("session_id"),
            cwd=event.get("cwd"),
            payload_bytes=SCAN.get("payload_bytes"),
            scanner_rc=SCAN.get("scanner_rc"),
            scan_ms=SCAN.get("scan_ms"),
            duration_ms=elapsed,
            timed_out=SCAN.get("timed_out"),
            exec_error=SCAN.get("exec_error"),
            exception=SCAN.get("exception"),
            rules=SCAN.get("rules") or None,
        )
    except Exception:  # noqa: BLE001 -- the log must never change a decision
        pass


def main() -> int:
    started = time.monotonic()
    event: object = None
    try:
        raw = sys.stdin.buffer.read(MAX_EVENT_BYTES + 1)
        if len(raw) > MAX_EVENT_BYTES:
            raise ValueError("oversized event")
        event = json.loads(raw)
        if not isinstance(event, dict):
            raise ValueError("invalid event")
        output = decision(event)
    except (UnicodeError, ValueError, OSError) as error:
        SCAN["exception"] = type(error).__name__
        output = deny("secret-scanner could not parse the proposed write; write denied.")
    print(json.dumps(output, separators=(",", ":")), flush=True)
    log_outcome(event if isinstance(event, dict) else {}, output, started)
    return 0


if __name__ == "__main__":
    sys.exit(main())

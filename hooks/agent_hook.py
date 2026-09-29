#!/usr/bin/env python3
"""Translate redacted Rust findings into Codex and Claude Code hook decisions."""

import json
import os
from pathlib import Path
import re
import subprocess
import sys


FINDING = re.compile(r"^.+:[1-9][0-9]*:[a-z][a-z0-9-]*$")
COMMIT = re.compile(
    r"(?:^|[\s;&|])git(?:\s+(?:-[cC]\s+\S+|--[\w-]+(?:=\S+)?))*\s+commit(?:\s|$)"
)


def decision(event: dict) -> dict:
    kind = event.get("hook_event_name", "")
    if kind not in {"PreToolUse", "PostToolUse", "Stop"}:
        return {}
    if kind == "PreToolUse":
        if event.get("tool_name") != "Bash":
            return {}
        tool_input = event.get("tool_input")
        if not isinstance(tool_input, dict):
            return block(kind, "secret-scanner hook received invalid tool input.", event)
        command = tool_input.get("command", "")
        if not isinstance(command, str) or not COMMIT.search(command):
            return {}

    cwd = event.get("cwd")
    if not isinstance(cwd, str) or not Path(cwd).is_dir():
        message = "secret-scanner could not resolve the hook working directory."
        return block(kind, message, event)
    root = subprocess.run(
        ["git", "-C", cwd, "rev-parse", "--show-toplevel"],
        capture_output=True,
        check=False,
        timeout=5,
    )
    if root.returncode != 0:
        return {}  # There is no Git history to protect in this directory.

    scanner = os.environ.get("SECRET_SCANNER_BIN") or str(
        Path.home() / ".local/bin/secret-scanner"
    )
    try:
        result = subprocess.run(
            [scanner, "--worktree"],
            cwd=os.fsdecode(root.stdout.removesuffix(b"\n")),
            capture_output=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return block(kind, "secret-scanner could not execute or timed out.", event)

    if result.returncode == 0:
        return {}
    if result.returncode != 1:
        return block(kind, "secret-scanner failed; inspect the installed binary.", event)
    findings = result.stdout.decode("utf-8", errors="replace").splitlines()
    if not findings or any(not FINDING.fullmatch(line) for line in findings):
        return block(kind, "secret-scanner returned malformed findings.", event)
    locations = "\n".join(f"  {line}" for line in findings[:20])
    remainder = f"\n  ...and {len(findings) - 20} more" if len(findings) > 20 else ""
    message = (
        f"secret-scanner found {len(findings)} possible secret(s):\n"
        f"{locations}{remainder}\n"
        "Remove the candidate from the worktree and index, rotate it if live, "
        "then scan again. Matched values are never shown."
    )
    return block(kind, message, event)


def block(kind: str, message: str, event: dict) -> dict:
    if kind == "Stop" and event.get("stop_hook_active") is True:
        return {"systemMessage": "secret-scanner findings remain after one Stop continuation; the Git gate still blocks commits."}
    if kind == "PreToolUse":
        return {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": message,
            }
        }
    return {"decision": "block", "reason": message}


def main() -> int:
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError("hook event is not an object")
        output = decision(event)
    except (ValueError, json.JSONDecodeError, OSError, subprocess.TimeoutExpired):
        output = {
            "decision": "block",
            "reason": "secret-scanner hook input or Git inspection failed.",
        }
    print(json.dumps(output, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())

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
PATCH_PATH = re.compile(r"^\*\*\* (?:Add|Update|Move to) File: (.+)$", re.MULTILINE)
READ_ONLY_BASH = re.compile(r"^\s*(?:pwd|git\s+status(?:\s+--short)?|git\s+diff(?:\s+--stat)?)\s*$")
MAX_DIRECT_BYTES = 10_000_000


def written_paths(event: dict, cwd: Path, root: Path) -> list[Path]:
    tool_input = event.get("tool_input")
    if not isinstance(tool_input, dict):
        return []
    names = []
    for key in ("file_path", "path", "target_path", "filename"):
        if isinstance(tool_input.get(key), str):
            names.append(tool_input[key])
    edits = tool_input.get("edits")
    for item in edits if isinstance(edits, list) else []:
        if isinstance(item, dict) and isinstance(item.get("file_path"), str):
            names.append(item["file_path"])
    if event.get("tool_name") == "apply_patch":
        command = tool_input.get("command")
        if isinstance(command, str):
            names.extend(PATCH_PATH.findall(command))
    paths = []
    for name in names:
        try:
            path = (cwd / name).resolve(strict=True)
            if path.is_file() and path.is_relative_to(root) and path not in paths:
                paths.append(path)
        except (OSError, ValueError):
            continue
    return paths


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
    if kind == "PostToolUse" and event.get("tool_name") == "Bash":
        tool_input = event.get("tool_input")
        command = tool_input.get("command", "") if isinstance(tool_input, dict) else ""
        if isinstance(command, str) and READ_ONLY_BASH.fullmatch(command):
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

    root_path = Path(os.fsdecode(root.stdout.removesuffix(b"\n"))).resolve()
    scanner = os.environ.get("SECRET_SCANNER_BIN") or str(
        Path.home() / ".local/bin/secret-scanner"
    )
    try:
        result = subprocess.run(
            [scanner, "--worktree"],
            cwd=root_path,
            capture_output=True,
            check=False,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return block(kind, "secret-scanner could not execute or timed out.", event)

    if result.returncode in (0, 3) and kind == "PostToolUse":
        skipped_binary = result.returncode == 3
        for path in written_paths(event, Path(cwd), root_path):
            try:
                if path.stat().st_size > MAX_DIRECT_BYTES:
                    return block(kind, "secret-scanner could not scan an oversized written file.", event)
                content = path.read_bytes()
                direct = subprocess.run(
                    [scanner, "--stdin", "--path-label", "<written-file>"],
                    input=content,
                    capture_output=True,
                    check=False,
                    timeout=20,
                )
            except (OSError, subprocess.TimeoutExpired):
                return block(kind, "secret-scanner could not scan a written file.", event)
            if direct.returncode == 1:
                result = direct
                break
            if direct.returncode == 3:
                skipped_binary = True
            elif direct.returncode != 0:
                return block(kind, "secret-scanner failed on a written file.", event)
        else:
            if skipped_binary:
                return {"systemMessage": "secret-scanner skipped binary input; the comprehensive Git and Forgejo secret gates remain required."}
            return {}
    if result.returncode == 0:
        return {}
    if result.returncode == 3:
        if kind == "PreToolUse":
            return {}  # The Git pre-commit and Forgejo Gitleaks gates still run.
        return {
            "systemMessage": "secret-scanner skipped binary input; the comprehensive Git and Forgejo secret gates remain required."
        }
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

#!/usr/bin/env python3
"""Translate redacted Rust findings into Codex and Claude Code hook decisions."""

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
# Facts about this invocation for the event log; never scanned content.
SCAN: dict = {}


FINDING = re.compile(r"^.+:[1-9][0-9]*:[a-z][a-z0-9-]*$")
COMMIT = re.compile(
    r"(?:^|[\s;&|])git(?:\s+(?:-[cC]\s+\S+|--[\w-]+(?:=\S+)?))*\s+commit(?:\s|$)"
)
PATCH_PATH = re.compile(r"^\*\*\* (?:Add|Update|Move to) File: (.+)$", re.MULTILINE)
READ_ONLY_BASH = re.compile(r"^\s*(?:pwd|git\s+status(?:\s+--short)?|git\s+diff(?:\s+--stat)?)\s*$")
# Bead store records are content-addressed: an in-place edit breaks the
# checkpoint's root hash and stops the store publishing (utilities, 2026-09-29).
BEAD_STORE_FINDING = re.compile(r"^(?:.*/)?\.beads/")
MAX_DIRECT_BYTES = 10_000_000
SCANNER_TIMEOUT_SECONDS = 20
UNTRACKED_COUNT_TIMEOUT_SECONDS = 5
# Scanner exit 2 with this stderr line is an incomplete scan caused by
# oversized inputs; the counts are the only variable content, so naming them
# back to the agent never discloses a path or scanned bytes.
INCOMPLETE_SCAN = re.compile(r"incomplete scan: ([0-9]+) oversized input")
KNOWN_SCANNER_FAILURES = {
    "Git patch exceeds scan byte limit": (
        "secret-scanner: Git patch exceeds scan byte limit; inspect "
        "staged-then-deleted entries with `git status`, then unstage them "
        "before retrying."
    ),
}


def untracked_file_count(root: Path) -> int | None:
    try:
        result = subprocess.run(
            ["git", "-C", os.fsdecode(root), "ls-files", "--others",
             "--exclude-standard", "-z"],
            capture_output=True,
            check=False,
            timeout=UNTRACKED_COUNT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    return result.stdout.count(b"\0")


def timeout_message(root: Path, scope: str) -> str:
    count = untracked_file_count(root)
    SCAN.update(timed_out=True, scope=scope, untracked_files=count)
    if count is None:
        untracked = "the untracked-file count was unavailable"
    else:
        untracked = f"{count} untracked file(s)"
    return (
        "secret-scanner timed out at its 20 s limit (20 seconds) while scanning "
        f"{scope}; {untracked}. Inspect large untracked directories and move "
        "them outside the repository before retrying." + DETAILS
    )


def scanner_failure_message(result) -> str:
    stderr = result.stderr.decode("utf-8", errors="replace")
    if result.returncode == 2:
        incomplete = INCOMPLETE_SCAN.search(stderr)
        if incomplete:
            return (
                "secret-scanner: incomplete scan, "
                f"{incomplete.group(1)} oversized file(s) in the worktree; "
                "move large untracked files outside the repository." + DETAILS
            )
        for marker, message in KNOWN_SCANNER_FAILURES.items():
            if marker in stderr:
                return message + DETAILS
    if DETAILS:
        return (
            f"secret-scanner failed (exit {result.returncode}); its stderr is in "
            "the event log." + DETAILS
        )
    return "secret-scanner failed; inspect the installed binary."


def note_scan(scope: str, result, started: float) -> None:
    SCAN.update(
        scope=scope,
        scanner_rc=result.returncode,
        stderr=result.stderr,
        scan_ms=int((time.monotonic() - started) * 1000),
    )


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
    SCAN.clear()
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
    SCAN["repo"] = str(root_path)
    scanner = os.environ.get("SECRET_SCANNER_BIN") or str(
        Path.home() / ".local/bin/secret-scanner"
    )
    started = time.monotonic()
    try:
        result = subprocess.run(
            [scanner, "--worktree"],
            cwd=root_path,
            capture_output=True,
            check=False,
            timeout=SCANNER_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired:
        return block(kind, timeout_message(root_path, "the worktree"), event)
    except OSError as error:
        SCAN.update(scope="the worktree", exec_error=f"{type(error).__name__}: {error}")
        return block(kind, "secret-scanner could not execute the installed scanner binary." + DETAILS, event)
    note_scan("the worktree", result, started)

    if result.returncode in (0, 3) and kind == "PostToolUse":
        written_binary = False
        for path in written_paths(event, Path(cwd), root_path):
            try:
                if path.stat().st_size > MAX_DIRECT_BYTES:
                    return block(kind, "secret-scanner could not scan an oversized written file.", event)
                content = path.read_bytes()
                started = time.monotonic()
                direct = subprocess.run(
                    [scanner, "--stdin", "--path-label", "<written-file>"],
                    input=content,
                    capture_output=True,
                    check=False,
                    timeout=SCANNER_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                return block(kind, timeout_message(root_path, "the written file"), event)
            except OSError as error:
                SCAN.update(scope="the written file", exec_error=f"{type(error).__name__}: {error}")
                return block(kind, "secret-scanner could not execute the written-file scan." + DETAILS, event)
            note_scan("the written file", direct, started)
            if direct.returncode == 1:
                result = direct
                break
            if direct.returncode == 3:
                written_binary = True
            elif direct.returncode != 0:
                return block(kind, "secret-scanner failed on a written file." + DETAILS, event)
        else:
            if written_binary:
                return {"systemMessage": "secret-scanner could not inspect a binary file written by this tool; review it before committing. The Git and Forgejo secret gates still run."}
            return {}
    if result.returncode == 0:
        return {}
    if result.returncode == 3:
        return {}  # The Git pre-commit and Forgejo Gitleaks gates still run.
    if result.returncode != 1:
        return block(kind, scanner_failure_message(result), event)
    findings = result.stdout.decode("utf-8", errors="replace").splitlines()
    if not findings or any(not FINDING.fullmatch(line) for line in findings):
        SCAN["malformed_lines"] = len(findings)
        return block(kind, "secret-scanner returned malformed findings." + DETAILS, event)
    SCAN["findings"] = findings
    locations = "\n".join(f"  {line}" for line in findings[:20])
    remainder = f"\n  ...and {len(findings) - 20} more" if len(findings) > 20 else ""
    guidance = (
        "Remove the candidate from the worktree and index, rotate it if live, "
        "then scan again."
    )
    if any(BEAD_STORE_FINDING.match(line) for line in findings):
        guidance += (
            " Never edit files under .beads/ by hand: remove bead store findings "
            "with `bead doctor --scope secrets` and `bead redact --all-blocking "
            "--actor <you> --reason <why>` in that repository."
        )
    message = (
        f"secret-scanner found {len(findings)} possible secret(s):\n"
        f"{locations}{remainder}\n"
        f"{guidance} Matched values are never shown."
    )
    return block(kind, message, event)


def block(kind: str, message: str, event: dict) -> dict:
    SCAN["block_message"] = message
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


def log_outcome(event: dict, output: dict, started: float) -> None:
    """Record blocks, errors, warnings and slow scans; clean fast scans are not logged."""
    if EVENT_LOG is None:
        return
    try:
        elapsed = int((time.monotonic() - started) * 1000)
        findings = SCAN.get("findings")
        cause = SCAN.get("block_message")
        if cause:
            outcome = "blocked" if findings else "error"
        elif output.get("systemMessage"):
            outcome, cause = "warning", output["systemMessage"]
        elif elapsed >= SLOW_SCAN_MS:
            outcome = "slow"
            cause = f"scan took {elapsed} ms of the {SCANNER_TIMEOUT_SECONDS} s limit"
        else:
            return
        transcript = str(event.get("transcript_path") or "")
        agent = ("codex" if "/.codex/" in transcript
                 else "claude" if "/.claude/" in transcript else None)
        # Every reason is generated text except a findings block, which lists
        # repository paths; that and stderr are captured text and get
        # re-scanned. A timeout block therefore spends no time on re-scanning.
        reason = cause.replace(DETAILS, "") if cause else outcome
        summary = reason.splitlines()[0]
        EVENT_LOG.record(
            "agent-hook", outcome, summary,
            untrusted={"reason": reason if findings else None,
                       "stderr": SCAN.get("stderr"), "findings": findings},
            reason=None if findings else reason,
            agent=agent,
            hook_event=event.get("hook_event_name"),
            tool=event.get("tool_name"),
            session_id=event.get("session_id"),
            cwd=event.get("cwd"),
            repo=SCAN.get("repo"),
            scope=SCAN.get("scope"),
            scanner_rc=SCAN.get("scanner_rc"),
            scan_ms=SCAN.get("scan_ms"),
            duration_ms=elapsed,
            timed_out=SCAN.get("timed_out"),
            untracked_files=SCAN.get("untracked_files"),
            exec_error=SCAN.get("exec_error"),
            exception=SCAN.get("exception"),
            malformed_lines=SCAN.get("malformed_lines"),
            finding_count=len(findings) if findings else None,
            rules=sorted({line.rsplit(":", 1)[-1] for line in findings}) if findings else None,
            stop_continuation=event.get("stop_hook_active") is True or None,
        )
    except Exception:  # noqa: BLE001 -- the log must never change a decision
        pass


def main() -> int:
    started = time.monotonic()
    event: object = None
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError("hook event is not an object")
        output = decision(event)
    except (ValueError, json.JSONDecodeError, OSError, subprocess.TimeoutExpired) as error:
        SCAN["exception"] = type(error).__name__
        SCAN["block_message"] = "secret-scanner hook input or Git inspection failed." + DETAILS
        output = {"decision": "block", "reason": SCAN["block_message"]}
    print(json.dumps(output, separators=(",", ":")), flush=True)
    log_outcome(event if isinstance(event, dict) else {}, output, started)
    return 0


if __name__ == "__main__":
    sys.exit(main())

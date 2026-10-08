#!/usr/bin/env python3
"""Merge synchronous secret-scanner pre-write hooks into Codex and Claude Code."""

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import tempfile


WRITE_PATTERNS = (
    "apply_patch", "Write", "Edit", "MultiEdit", "NotebookEdit",
    "mcp__[A-Za-z0-9_-]+__(?:write|edit|append|replace|save|upload|persist)[A-Za-z0-9_]*",
    "mcp__[A-Za-z0-9_-]+__create_file[A-Za-z0-9_]*",
    "[A-Za-z0-9_.-]*(?:write_file|edit_file|apply_patch|save_file|create_file|append_file)[A-Za-z0-9_]*",
)


def matcher(extra_tools: list[str]) -> str:
    return "^(?:" + "|".join((*WRITE_PATTERNS, *(re.escape(name) for name in extra_tools))) + ")$"


def atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
        with source.open("rb") as handle:
            shutil.copyfileobj(handle, temporary)
    os.chmod(temporary_path, 0o755)
    os.replace(temporary_path, destination)


def atomic_json(destination: Path, config: dict) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=destination.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
        json.dump(config, temporary, indent=2)
        temporary.write("\n")
    os.chmod(temporary_path, 0o600)
    os.replace(temporary_path, destination)


def merge_hooks(destination: Path, command: str, extra_tools: list[str], apply: bool, announce: bool = True) -> bool:
    config = json.loads(destination.read_text()) if destination.exists() else {}
    if not isinstance(config, dict):
        raise ValueError(f"{destination}: configuration must be an object")
    hooks = config.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError(f"{destination}: hooks must be an object")
    entries = hooks.get("PreToolUse", [])
    if not isinstance(entries, list):
        raise ValueError(f"{destination}: PreToolUse must be a list")
    kept = []
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
            kept.append(entry)
            continue
        other_handlers = [handler for handler in entry["hooks"] if not (
            isinstance(handler, dict) and handler.get("type") == "command" and
            "/secret-scanner/prewrite_hook.py" in handler.get("command", "")
        )]
        if other_handlers:
            kept.append({**entry, "hooks": other_handlers})
    kept.append({
        "matcher": matcher(extra_tools),
        "hooks": [{"type": "command", "command": command, "timeout": 30}],
    })
    changed = kept != entries
    if announce:
        print(f"{destination}: {'would update' if changed and not apply else 'updated' if changed else 'already configured'}")
    if changed and apply:
        hooks["PreToolUse"] = kept
        config["hooks"] = hooks
        atomic_json(destination, config)
    return changed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="install after a dry run")
    parser.add_argument("--write-tool", action="append", default=[], help="additional exact file-writing tool name")
    args = parser.parse_args()
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", name) for name in args.write_tool):
        parser.error("--write-tool needs a tool name, without regex syntax")

    home = Path.home()
    source = Path(__file__).resolve().parents[1] / "hooks/prewrite_hook.py"
    installed_hook = home / ".local/share/secret-scanner/prewrite_hook.py"
    installed_scanner = home / ".local/bin/secret-scanner"
    if not installed_scanner.is_file() or not os.access(installed_scanner, os.X_OK):
        parser.error(f"install an executable secret-scanner at {installed_scanner} first")
    print(f"hook: {source} -> {installed_hook}")
    command = f"python3 {shlex.quote(str(installed_hook))}"
    destinations = (home / ".codex/hooks.json", home / ".claude/settings.json")
    if args.apply:
        # Validate both files before changing either one.
        for destination in destinations:
            merge_hooks(destination, command, args.write_tool, False, announce=False)
        atomic_copy(source, installed_hook)
    for destination in destinations:
        merge_hooks(destination, command, args.write_tool, args.apply)
    if args.apply:
        print("Review and trust the new Codex hook with /hooks in each active client.")


if __name__ == "__main__":
    main()

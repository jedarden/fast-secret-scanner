#!/usr/bin/env python3
"""Install the release binary and merge user-level Codex/Claude hook settings."""

import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def atomic_copy(source: Path, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=destination.parent, delete=False) as temporary:
        temporary_path = Path(temporary.name)
        with source.open("rb") as handle:
            shutil.copyfileobj(handle, temporary)
    os.chmod(temporary_path, mode)
    os.replace(temporary_path, destination)


def atomic_json(destination: Path, value: dict) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=destination.parent, delete=False
    ) as temporary:
        temporary_path = Path(temporary.name)
        json.dump(value, temporary, indent=2)
        temporary.write("\n")
    os.chmod(temporary_path, 0o600)
    os.replace(temporary_path, destination)


def write_matcher(extra_tools: list[str]) -> str:
    patterns = [
        "apply_patch", "Edit", "Write", "MultiEdit", "NotebookEdit",
        "mcp__[A-Za-z0-9_-]+__(?:write|edit|append|replace|create|move|rename|save|upload)[A-Za-z0-9_]*",
        "[A-Za-z0-9_.-]*(?:write_file|edit_file|apply_patch|save_file)[A-Za-z0-9_]*",
    ]
    patterns.extend(re.escape(name) for name in extra_tools)
    return "^(?:" + "|".join(patterns) + ")$"


def merge_hooks(
    destination: Path, command: str, runtime: str, apply: bool,
    extra_tools: list[str] | None = None,
) -> None:
    config = json.loads(destination.read_text()) if destination.exists() else {}
    hooks = config.setdefault("hooks", {})
    changed = False
    for event, matchers in (
        ("PreToolUse", "Bash"),
        ("PostToolUse", ("^Bash$", write_matcher(extra_tools or []))),
        ("Stop", None),
    ):
        entries = hooks.get(event, [])
        kept = []
        for entry in entries:
            others = [handler for handler in entry.get("hooks", [])
                      if not (handler.get("type") == "command" and
                              "/secret-scanner/agent_hook.py" in handler.get("command", ""))]
            if others:
                kept.append({**entry, "hooks": others})
        for matcher in matchers if isinstance(matchers, tuple) else (matchers,):
            entry = {"hooks": [{"type": "command", "command": command, "timeout": 30}]}
            if matcher is not None:
                entry["matcher"] = matcher
            kept.append(entry)
        if kept != entries:
            hooks[event] = kept
            changed = True
    print(f"{destination}: {'would update' if changed and not apply else 'updated' if changed else 'already configured'}")
    if changed and apply:
        atomic_json(destination, config)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="install after a dry run")
    parser.add_argument("--binary", type=Path, required=True, help="built Rust release binary")
    parser.add_argument("--write-tool", action="append", default=[],
                        help="additional exact MCP or local file-writing tool name")
    args = parser.parse_args()
    if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", name)
           for name in args.write_tool):
        parser.error("--write-tool needs a tool name, without regex syntax")
    source = Path(__file__).resolve().parents[1] / "hooks/agent_hook.py"
    binary = args.binary.resolve()
    version = subprocess.run([binary, "--version"], capture_output=True, check=True, text=True)
    if not version.stdout.startswith("secret-scanner "):
        raise SystemExit("supplied binary is not secret-scanner")
    home = Path.home()
    installed_binary = home / ".local/bin/secret-scanner"
    installed_hook = home / ".local/share/secret-scanner/agent_hook.py"
    print(f"binary: {binary} -> {installed_binary} ({version.stdout.strip()})")
    if args.apply:
        atomic_copy(binary, installed_binary, 0o755)
        atomic_copy(source, installed_hook, 0o755)
    command = f"python3 {installed_hook}"
    merge_hooks(home / ".codex/hooks.json", command, "codex", args.apply,
                args.write_tool)
    merge_hooks(home / ".claude/settings.json", command, "claude", args.apply,
                args.write_tool)
    if args.apply:
        print("Review and trust the new Codex hooks with /hooks in each active client.")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Install the release binary and merge user-level Codex/Claude hook settings."""

import argparse
import json
import os
from pathlib import Path
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


def merge_hooks(destination: Path, command: str, runtime: str, apply: bool) -> None:
    config = json.loads(destination.read_text()) if destination.exists() else {}
    hooks = config.setdefault("hooks", {})
    changed = False
    for event, matcher in (
        ("PreToolUse", "Bash"),
        ("PostToolUse", "Bash|apply_patch|Edit|Write" if runtime == "codex" else "Bash|Edit|Write"),
        ("Stop", None),
    ):
        entries = hooks.setdefault(event, [])
        if any(
            "agent_hook.py" in handler.get("command", "")
            for entry in entries
            for handler in entry.get("hooks", [])
        ):
            continue
        entry = {"hooks": [{"type": "command", "command": command, "timeout": 30}]}
        if matcher is not None:
            entry["matcher"] = matcher
        entries.append(entry)
        changed = True
    print(f"{destination}: {'would update' if changed and not apply else 'updated' if changed else 'already configured'}")
    if changed and apply:
        atomic_json(destination, config)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="install after a dry run")
    parser.add_argument("--binary", type=Path, required=True, help="built Rust release binary")
    args = parser.parse_args()
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
    merge_hooks(home / ".codex/hooks.json", command, "codex", args.apply)
    merge_hooks(home / ".claude/settings.json", command, "claude", args.apply)
    if args.apply:
        print("Review and trust the new Codex hooks with /hooks in each active client.")


if __name__ == "__main__":
    main()

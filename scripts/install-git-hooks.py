#!/usr/bin/env python3
"""Compose Rust and the existing fleet hook for local repositories."""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def git(*args: str, cwd: Path | None = None) -> str:
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def repositories(home: Path):
    for parent in home.iterdir():
        if parent.is_dir() and (parent / ".git").exists():
            yield parent


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--doctor", action="store_true")
    args = parser.parse_args()
    home = Path.home()
    state = home / ".local/share/secret-scanner/hooks"
    binary = home / ".local/bin/secret-scanner"
    source = Path(__file__).resolve().parents[1] / "hooks/git-dispatch"
    old = git("config", "--global", "--get", "secretScanner.delegateHooksPath") if args.doctor else ""
    if not old:
        current = git("config", "--global", "--get", "core.hooksPath")
        old = current if current != str(state) else ""
    if not old or not Path(old).is_dir() or not binary.is_file():
        raise SystemExit("existing fleet hook path or installed Rust binary is missing")
    names = sorted(p.name for p in Path(old).iterdir() if p.name != "dispatch" and p.is_file() and not p.name.endswith(".sample"))
    if "pre-commit" not in names:
        raise SystemExit("existing fleet hook has no pre-commit entry")
    overrides = []
    for repo in repositories(home):
        try:
            current = git("config", "--local", "--get", "core.hooksPath", cwd=repo)
        except subprocess.CalledProcessError:
            continue
        if current not in (str(state), old):
            overrides.append((repo, current))
    print(f"Git hooks: {old} -> {state}; {len(overrides)} local override(s)")
    for repo, current in overrides:
        print(f"  {repo.name}: preserve {current}")
    if args.doctor:
        if git("config", "--global", "--get", "core.hooksPath") != str(state):
            raise SystemExit("global hook path is not the Rust dispatcher")
        if overrides:
            raise SystemExit("some local overrides bypass the Rust dispatcher")
        print("Git hook coverage: healthy")
        return
    if not args.apply:
        return
    state.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=state, delete=False) as temporary:
        with source.open("rb") as handle:
            shutil.copyfileobj(handle, temporary)
        tmp = Path(temporary.name)
    os.chmod(tmp, 0o755)
    os.replace(tmp, state / "dispatch")
    for name in names:
        target = state / name
        if target.is_symlink() or not target.exists():
            target.unlink(missing_ok=True)
            target.symlink_to("dispatch")
        else:
            raise SystemExit(f"refusing to replace existing hook: {target}")
    git("config", "--global", "secretScanner.delegateHooksPath", old)
    for repo, current in overrides:
        git("config", "--local", "secretScanner.previousHooksPath", current, cwd=repo)
        git("config", "--local", "core.hooksPath", str(state), cwd=repo)
    git("config", "--global", "core.hooksPath", str(state))
    print("Rust Git pre-commit scan installed ahead of the fleet Gitleaks hook")


if __name__ == "__main__":
    main()

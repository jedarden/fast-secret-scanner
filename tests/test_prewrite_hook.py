"""Process-level checks for pre-write decisions and scoped installation."""

import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "hooks/prewrite_hook.py"
INSTALLER = ROOT / "scripts/install-prewrite-hooks.py"
SCANNER = Path.home() / ".local/bin/secret-scanner"

SPEC = importlib.util.spec_from_file_location("prewrite_hook", HOOK)
assert SPEC and SPEC.loader
PREWRITE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PREWRITE)


def run_hook(tool: str, payload: dict, scanner: Path = SCANNER) -> tuple[dict, bytes, bytes]:
    event = {"hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": payload}
    env = {**os.environ, "SECRET_SCANNER_BIN": str(scanner)}
    result = subprocess.run(
        [sys.executable, str(HOOK)], input=json.dumps(event).encode(),
        capture_output=True, env=env, check=True,
    )
    return json.loads(result.stdout), result.stdout, result.stderr


def denied(output: dict) -> bool:
    return output.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


class PrewriteTests(unittest.TestCase):
    def test_clean_write_allowed_and_secret_write_denied_before_mutation(self):
        if not SCANNER.is_file():
            self.skipTest("installed secret-scanner unavailable")
        candidate = "".join(("ghp_", "A1b2C3d4E5f6", "G7h8I9j0K1l2", "M3n4O5p6Q7r8"))
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.txt"
            target.write_text("original\n")
            clean, _, _ = run_hook("Write", {"file_path": str(target), "content": "hello world\n"})
            self.assertEqual(clean, {})
            rejected, stdout, stderr = run_hook("Write", {"file_path": str(target), "content": candidate})
            if not denied(rejected):
                target.write_text(candidate)
            self.assertTrue(denied(rejected))
            self.assertEqual(target.read_text(), "original\n")
            self.assertNotIn(candidate.encode(), stdout + stderr)
            self.assertNotIn(candidate, json.dumps(rejected))

    def test_all_structured_forms_are_scanned(self):
        if not SCANNER.is_file():
            self.skipTest("installed secret-scanner unavailable")
        candidate = "".join(("ghp_", "A1b2C3d4E5f6", "G7h8I9j0K1l2", "M3n4O5p6Q7r8"))
        cases = [
            ("Edit", {"file_path": "x", "old_string": "old", "new_string": candidate}),
            ("MultiEdit", {"file_path": "x", "edits": [{"old_string": "old", "new_string": "clean"}, {"old_string": "old", "new_string": candidate}]}),
            ("NotebookEdit", {"notebook_path": "x", "new_source": ["clean", candidate]}),
            ("apply_patch", {"command": "*** Begin Patch\n*** Add File: x\n+" + candidate + "\n*** End Patch"}),
            ("mcp__filesystem__write_file", {"path": "x", "content": candidate}),
            ("mcp__workspace__persist", {"path": "x", "data": candidate}),
            ("local_save_file", {"path": "x", "files": [{"path": "y", "content": candidate}]}),
        ]
        for name, payload in cases:
            with self.subTest(name=name):
                output, stdout, stderr = run_hook(name, payload)
                self.assertTrue(denied(output))
                self.assertNotIn(candidate.encode(), stdout + stderr)

    def test_opaque_and_failed_scans_deny(self):
        self.assertTrue(denied(PREWRITE.decision({"tool_name": "Write", "tool_input": {"content": "clean"}})))
        opaque = [
            ("Write", {"file_path": "x"}),
            ("MultiEdit", {"edits": [{"new_string": "clean"}, {"old_string": "x"}]}),
            ("mcp__filesystem__write_file", {"path": "x", "encoding": "base64", "content": "YWJj"}),
            ("mcp__filesystem__write_file", {"path": "x", "bytes": [1, 2, 3]}),
            ("mcp__filesystem__write_file", {"path": "x"}),
            ("mcp__filesystem__move_file", {"source": "a", "destination": "b"}),
            ("apply_patch", {"command": "unrecognized patch"}),
        ]
        for name, payload in opaque:
            with self.subTest(name=name):
                self.assertTrue(denied(run_hook(name, payload)[0]))
        output, _, _ = run_hook("Write", {"content": "clean"}, Path("/does/not/exist"))
        self.assertTrue(denied(output))

    def test_patch_scans_additions_only(self):
        candidate = "".join(("ghp_", "A1b2C3d4E5f6", "G7h8I9j0K1l2", "M3n4O5p6Q7r8"))
        patch = f"*** Begin Patch\n*** Update File: x\n@@\n-{candidate}\n+clean\n*** End Patch"
        self.assertEqual(PREWRITE.proposed_content({"tool_name": "apply_patch", "tool_input": {"command": patch}}), ["clean\n"])
        if SCANNER.is_file():
            self.assertEqual(run_hook("apply_patch", {"command": patch})[0], {})


class InstallerTests(unittest.TestCase):
    def test_dry_run_apply_idempotence_and_preservation(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            scanner = home / ".local/bin/secret-scanner"
            scanner.parent.mkdir(parents=True)
            scanner.write_text("#!/bin/sh\nexit 0\n")
            scanner.chmod(0o755)
            unrelated = {"type": "command", "command": "python3 /tmp/other.py"}
            codex = home / ".codex/hooks.json"
            codex.parent.mkdir()
            codex.write_text(json.dumps({"extra": 1, "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [unrelated]}]}}))
            env = {**os.environ, "HOME": str(home)}
            dry = subprocess.run([sys.executable, str(INSTALLER)], env=env, capture_output=True, check=True)
            self.assertIn(b"would update", dry.stdout)
            self.assertFalse((home / ".claude/settings.json").exists())
            self.assertFalse((home / ".local/share/secret-scanner/prewrite_hook.py").exists())
            original = codex.read_bytes()
            self.assertEqual(json.loads(original)["extra"], 1)
            subprocess.run([sys.executable, str(INSTALLER), "--apply", "--write-tool", "mcp__workspace__persist"], env=env, capture_output=True, check=True)
            claude = home / ".claude/settings.json"
            first = (codex.read_bytes(), claude.read_bytes())
            config = json.loads(first[0])
            self.assertEqual(config["hooks"]["PreToolUse"][0]["hooks"], [unrelated])
            self.assertEqual(config["extra"], 1)
            self.assertEqual(config["hooks"]["PreToolUse"][1]["hooks"][0].get("async"), None)
            self.assertIn("mcp__workspace__persist", config["hooks"]["PreToolUse"][1]["matcher"])
            pattern = re.compile(config["hooks"]["PreToolUse"][1]["matcher"])
            self.assertIsNotNone(pattern.fullmatch("mcp__filesystem__create_file"))
            self.assertIsNone(pattern.fullmatch("mcp__filesystem__move_file"))
            self.assertIsNone(pattern.fullmatch("mcp__filesystem__rename_file"))
            self.assertTrue((home / ".local/share/secret-scanner/prewrite_hook.py").is_file())
            self.assertEqual(codex.stat().st_mode & 0o777, 0o600)
            subprocess.run([sys.executable, str(INSTALLER), "--apply", "--write-tool", "mcp__workspace__persist"], env=env, capture_output=True, check=True)
            self.assertEqual((codex.read_bytes(), claude.read_bytes()), first)


if __name__ == "__main__":
    unittest.main()

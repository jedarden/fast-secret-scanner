"""User-hook migration preserves unrelated handlers and stays idempotent."""

import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts/install-agent-hooks.py"
SPEC = importlib.util.spec_from_file_location("install_agent_hooks", SCRIPT)
assert SPEC and SPEC.loader
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)


class InstallerTests(unittest.TestCase):
    def test_migrates_combined_entry_and_preserves_other_handlers(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "hooks.json"
            command = "python3 /tmp/share/secret-scanner/agent_hook.py"
            unrelated = {"type": "command", "command": "python3 /tmp/other.py"}
            target.write_text(json.dumps({"hooks": {
                "PostToolUse": [{"matcher": "Bash|Edit|Write", "hooks": [
                    {"type": "command", "command": command}, unrelated,
                ]}],
                "PreToolUse": [{"matcher": "Bash", "hooks": [
                    {"type": "command", "command": command},
                ]}],
            }}))
            INSTALLER.merge_hooks(target, command, "codex", True,
                                  ["mcp__workspace__persist"])
            first = target.read_bytes()
            config = json.loads(first)
            post = config["hooks"]["PostToolUse"]
            self.assertEqual(len(post), 3)
            self.assertEqual(post[0]["hooks"], [unrelated])
            self.assertEqual(post[1]["matcher"], "^Bash$")
            matcher = re.compile(post[2]["matcher"])
            for name in ("apply_patch", "Edit", "Write", "NotebookEdit",
                         "mcp__filesystem__write_file", "mcp__workspace__persist"):
                self.assertIsNotNone(matcher.fullmatch(name), name)
            for name in ("Read", "mcp__filesystem__read_file"):
                self.assertIsNone(matcher.fullmatch(name), name)
            INSTALLER.merge_hooks(target, command, "codex", True,
                                  ["mcp__workspace__persist"])
            self.assertEqual(target.read_bytes(), first)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()

"""The agent adapter explains known scanner failures without leaking stderr."""

import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


# Keep test-driven blocks out of this host's real event log (and so out of
# the fleet's central VictoriaLogs).
_EVENT_LOG_DIR = tempfile.TemporaryDirectory(prefix="secret-scanner-test-events-")
os.environ["SECRET_SCANNER_LOG_DIR"] = _EVENT_LOG_DIR.name


HOOK = Path(__file__).resolve().parents[1] / "hooks/agent_hook.py"
SPEC = importlib.util.spec_from_file_location("agent_hook", HOOK)
assert SPEC and SPEC.loader
AGENT_HOOK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AGENT_HOOK)


class AgentHookFailureTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="secret-scanner-hook-")
        self.root = Path(self.directory.name)
        subprocess.run(
            ["git", "init", "-q"],
            cwd=self.root,
            check=True,
        )
        self.scanner = self.root / "fake-scanner"

    def tearDown(self):
        self.directory.cleanup()

    def event(self):
        return {
            "cwd": str(self.root),
            "hook_event_name": "Stop",
            "tool_name": "Bash",
            "tool_input": {"command": ""},
            "stop_hook_active": False,
        }

    def run_with_scanner(self, failure):
        real_run = AGENT_HOOK.subprocess.run

        def run(*args, **kwargs):
            command = args[0]
            if command and command[0] == str(self.scanner):
                return failure()
            return real_run(*args, **kwargs)

        with (
            mock.patch.object(AGENT_HOOK.subprocess, "run", side_effect=run),
            mock.patch.dict(os.environ, {"SECRET_SCANNER_BIN": str(self.scanner)}),
        ):
            return AGENT_HOOK.decision(self.event())

    def test_patch_limit_names_the_cause_without_forwarding_stderr(self):
        stderr = b"secret-scanner: Git patch exceeds scan byte limit\ninternal detail"
        result = subprocess.CompletedProcess(
            [str(self.scanner), "--worktree"], 2, b"", stderr
        )
        output = self.run_with_scanner(lambda: result)

        self.assertIn("Git patch exceeds scan byte limit", output["reason"])
        self.assertIn("staged-then-deleted", output["reason"])
        self.assertNotIn("internal detail", output["reason"])
        self.assertNotIn("inspect the installed binary", output["reason"])

    def test_timeout_names_limit_and_untracked_file_count(self):
        failure = lambda: (_ for _ in ()).throw(
            subprocess.TimeoutExpired([str(self.scanner), "--worktree"], 20)
        )
        output = self.run_with_scanner(failure)

        self.assertIn("20 s limit", output["reason"])
        self.assertIn("0 untracked file(s)", output["reason"])
        self.assertIn("large untracked directories", output["reason"])

    def test_os_error_names_execution_failure(self):
        failure = lambda: (_ for _ in ()).throw(
            OSError("scanner disappeared")
        )
        output = self.run_with_scanner(failure)

        self.assertIn("could not execute", output["reason"])
        self.assertNotIn("scanner disappeared", output["reason"])


if __name__ == "__main__":
    unittest.main()

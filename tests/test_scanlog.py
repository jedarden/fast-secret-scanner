"""The event log records scanner failures centrally without ever holding scanned content."""

import http.server
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCANLOG = load("scanlog_under_test", "hooks/scanlog.py")
AGENT_HOOK = load("agent_hook_under_test", "hooks/agent_hook.py")

# A stand-in scanner: re-scans of log text (--path-label <event-log>) follow
# VERIFY_RC; every other invocation follows SCAN_RC/SCAN_STDERR/SCAN_STDOUT.
FAKE_SCANNER = """#!/bin/sh
case " $* " in
  *"<event-log>"*) cat >/dev/null; exit "${VERIFY_RC:-0}" ;;
esac
case " $* " in *" --stdin "*) cat >/dev/null ;; esac
[ -n "$SCAN_STDOUT" ] && printf '%s\\n' "$SCAN_STDOUT"
[ -n "$SCAN_STDERR" ] && printf '%s\\n' "$SCAN_STDERR" >&2
exit "${SCAN_RC:-0}"
"""


class Collector(http.server.BaseHTTPRequestHandler):
    bodies: list = []
    status = 204

    def do_POST(self):  # noqa: N802
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if type(self).status // 100 == 2:
            type(self).bodies.append((self.path, body))
        self.send_response(type(self).status)
        self.end_headers()

    def log_message(self, *args):
        pass


class EventLogTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="secret-scanner-events-")
        self.root = Path(self.directory.name)
        self.logs = self.root / "state"
        self.scanner = self.root / "fake-scanner"
        self.scanner.write_text(FAKE_SCANNER)
        self.scanner.chmod(0o755)
        self.env = mock.patch.dict(os.environ, {
            "SECRET_SCANNER_LOG_DIR": str(self.logs),
            "SECRET_SCANNER_BIN": str(self.scanner),
            "SECRET_SCANNER_LOG": "on",
            "VERIFY_RC": "0", "SCAN_RC": "0", "SCAN_STDERR": "", "SCAN_STDOUT": "",
        })
        self.env.start()

    def tearDown(self):
        self.env.stop()
        self.directory.cleanup()

    def events(self) -> list[dict]:
        path = self.logs / "events.jsonl"
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines()]


class RecordTests(EventLogTestCase):
    def test_record_writes_private_json_lines_with_host_metadata(self):
        SCANLOG.record("agent-hook", "error", "scanner failed", scanner_rc=2, repo="/r",
                       untrusted={"stderr": b"secret-scanner: git diff failed\n"})
        [event] = self.events()
        self.assertEqual(event["source"], "secret-scanner")
        self.assertEqual(event["component"], "agent-hook")
        self.assertEqual(event["outcome"], "error")
        self.assertEqual(event["scanner_rc"], 2)
        self.assertEqual(event["stderr"], "secret-scanner: git diff failed")
        self.assertTrue(event["ts"].endswith("Z"))
        self.assertTrue(event["host"])
        self.assertEqual(stat.S_IMODE(self.logs.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.logs / "events.jsonl").stat().st_mode), 0o600)

    def test_captured_text_matching_a_rule_is_withheld(self):
        os.environ["VERIFY_RC"] = "1"
        SCANLOG.record("agent-hook", "error", "scanner failed",
                       untrusted={"stderr": "CANARY-STDERR", "findings": ["a:1:rule"]})
        [event] = self.events()
        self.assertNotIn("CANARY-STDERR", json.dumps(event))
        self.assertEqual(event["stderr"], SCANLOG.WITHHELD)
        self.assertEqual(event["findings"], SCANLOG.WITHHELD)
        self.assertTrue(event["withheld"])

    def test_unscannable_captured_text_is_withheld(self):
        os.environ["SECRET_SCANNER_BIN"] = str(self.root / "missing-scanner")
        SCANLOG.record("agent-hook", "error", "binary missing",
                       untrusted={"stderr": "CANARY-STDERR"})
        [event] = self.events()
        self.assertEqual(event["stderr"], SCANLOG.UNVERIFIED)

    def test_logging_failure_never_raises(self):
        blocker = self.root / "not-a-directory"
        blocker.write_text("")
        os.environ["SECRET_SCANNER_LOG_DIR"] = str(blocker / "state")
        SCANLOG.record("agent-hook", "error", "unwritable log")  # must not raise

    def test_disabled_log_writes_nothing(self):
        os.environ["SECRET_SCANNER_LOG"] = "off"
        SCANLOG.record("agent-hook", "error", "disabled")
        self.assertFalse((self.logs / "events.jsonl").exists())

    def test_rotation_keeps_one_previous_file(self):
        with mock.patch.object(SCANLOG, "MAX_FILE_BYTES", 300):
            for index in range(6):
                SCANLOG.record("agent-hook", "error", f"event {index}")
        self.assertTrue((self.logs / "events.jsonl.1").exists())
        self.assertLess((self.logs / "events.jsonl").stat().st_size, 600)

    def test_oversized_text_is_truncated_to_the_tail(self):
        SCANLOG.record("agent-hook", "error", "big", untrusted={"stderr": "x" * 9000 + "END"})
        [event] = self.events()
        self.assertTrue(event["stderr"].endswith("END"))
        self.assertLessEqual(len(event["stderr"]), SCANLOG.MAX_TEXT_CHARS + 3)


class ShipTests(EventLogTestCase):
    def setUp(self):
        super().setUp()
        Collector.bodies = []
        Collector.status = 204
        self.server = http.server.HTTPServer(("127.0.0.1", 0), Collector)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        super().tearDown()

    def shipped(self) -> list[dict]:
        return [json.loads(line) for _, body in Collector.bodies for line in body.splitlines()]

    def test_ship_sends_each_event_once_with_victorialogs_fields(self):
        for index in range(3):
            SCANLOG.record("agent-hook", "error", f"event {index}")
        self.assertEqual(SCANLOG.ship(self.url), 0)
        self.assertEqual([e["msg"] for e in self.shipped()], ["event 0", "event 1", "event 2"])
        path = Collector.bodies[0][0]
        self.assertIn("/insert/jsonline?", path)
        self.assertIn("_time_field=ts", path)
        self.assertIn("_msg_field=msg", path)
        self.assertIn("_stream_fields=source%2Chost%2Ccomponent", path)
        self.assertEqual(SCANLOG.ship(self.url), 0)
        self.assertEqual(len(self.shipped()), 3)
        SCANLOG.record("agent-hook", "error", "event 3")
        self.assertEqual(SCANLOG.ship(self.url), 0)
        self.assertEqual([e["msg"] for e in self.shipped()][-1], "event 3")
        self.assertEqual(len(self.shipped()), 4)

    def test_failed_post_keeps_events_for_the_next_run(self):
        SCANLOG.record("agent-hook", "error", "event 0")
        Collector.status = 500
        self.assertEqual(SCANLOG.ship(self.url), 1)
        status = json.loads((self.logs / "ship-status.json").read_text())
        self.assertIn("last_error", status)
        Collector.status = 204
        self.assertEqual(SCANLOG.ship(self.url), 0)
        self.assertEqual([e["msg"] for e in self.shipped()], ["event 0"])

    def test_rotation_between_runs_loses_and_repeats_nothing(self):
        SCANLOG.record("agent-hook", "error", "event 0")
        self.assertEqual(SCANLOG.ship(self.url), 0)
        SCANLOG.record("agent-hook", "error", "event 1")
        os.replace(self.logs / "events.jsonl", self.logs / "events.jsonl.1")
        SCANLOG.record("agent-hook", "error", "event 2")
        self.assertEqual(SCANLOG.ship(self.url), 0)
        self.assertEqual([e["msg"] for e in self.shipped()], ["event 0", "event 1", "event 2"])

    def test_partial_trailing_line_waits_for_its_newline(self):
        SCANLOG.record("agent-hook", "error", "event 0")
        with (self.logs / "events.jsonl").open("ab") as handle:
            handle.write(b'{"msg":"half')
        self.assertEqual(SCANLOG.ship(self.url), 0)
        self.assertEqual(len(self.shipped()), 1)
        with (self.logs / "events.jsonl").open("ab") as handle:
            handle.write(b'"}\n')
        self.assertEqual(SCANLOG.ship(self.url), 0)
        self.assertEqual([e["msg"] for e in self.shipped()], ["event 0", "half"])


class HookLoggingTests(EventLogTestCase):
    def git_repo(self) -> Path:
        repo = self.root / "repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        return repo

    def test_agent_hook_logs_scanner_failure_with_stderr(self):
        repo = self.git_repo()
        os.environ.update(SCAN_RC="2", SCAN_STDERR="secret-scanner: git diff failed")
        output = AGENT_HOOK.decision({"cwd": str(repo), "hook_event_name": "Stop",
                                      "stop_hook_active": False})
        self.assertIn("exit 2", output["reason"])
        self.assertIn("secret-scanner-events tail", output["reason"])
        AGENT_HOOK.log_outcome({"cwd": str(repo), "hook_event_name": "Stop",
                                "transcript_path": "/home/x/.claude/projects/p/s.jsonl",
                                "session_id": "s1"}, output, AGENT_HOOK.time.monotonic())
        [event] = self.events()
        self.assertEqual(event["component"], "agent-hook")
        self.assertEqual(event["outcome"], "error")
        self.assertEqual(event["scanner_rc"], 2)
        self.assertEqual(event["stderr"], "secret-scanner: git diff failed")
        self.assertEqual(event["agent"], "claude")
        self.assertEqual(event["repo"], str(repo.resolve()))

    def test_agent_hook_logs_findings_as_locations_only(self):
        repo = self.git_repo()
        os.environ.update(SCAN_RC="1", SCAN_STDOUT="config/app.env:3:generic-api-key")
        event = {"cwd": str(repo), "hook_event_name": "PostToolUse", "tool_name": "Bash",
                 "tool_input": {"command": "echo CANARY-COMMAND > x"}}
        output = AGENT_HOOK.decision(event)
        AGENT_HOOK.log_outcome(event, output, AGENT_HOOK.time.monotonic())
        [logged] = self.events()
        self.assertEqual(logged["outcome"], "blocked")
        self.assertEqual(logged["rules"], ["generic-api-key"])
        self.assertEqual(logged["findings"], ["config/app.env:3:generic-api-key"])
        self.assertNotIn("CANARY-COMMAND", json.dumps(logged))

    def test_agent_hook_clean_fast_scan_logs_nothing(self):
        repo = self.git_repo()
        event = {"cwd": str(repo), "hook_event_name": "Stop", "stop_hook_active": False}
        output = AGENT_HOOK.decision(event)
        self.assertEqual(output, {})
        AGENT_HOOK.log_outcome(event, output, AGENT_HOOK.time.monotonic())
        self.assertEqual(self.events(), [])

    def test_prewrite_hook_never_logs_the_proposed_content(self):
        os.environ.update(SCAN_RC="1", SCAN_STDOUT="<proposed-write>:1:generic-api-key")
        event = {"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": str(self.root),
                 "tool_input": {"file_path": "x", "content": "CANARY-CONTENT"}}
        result = subprocess.run([sys.executable, str(ROOT / "hooks/prewrite_hook.py")],
                                input=json.dumps(event).encode(), capture_output=True,
                                check=True, env=os.environ.copy())
        self.assertEqual(json.loads(result.stdout)["hookSpecificOutput"]["permissionDecision"],
                         "deny")
        [logged] = self.events()
        self.assertEqual(logged["component"], "prewrite-hook")
        self.assertEqual(logged["outcome"], "blocked")
        self.assertEqual(logged["rules"], ["generic-api-key"])
        self.assertNotIn("CANARY-CONTENT", (self.logs / "events.jsonl").read_text())

    def test_prewrite_hook_logs_scanner_errors(self):
        os.environ.update(SCAN_RC="2", SCAN_STDERR="secret-scanner: input exceeds scan byte limit")
        event = {"hook_event_name": "PreToolUse", "tool_name": "Bash",
                 "tool_input": {"command": "true"}}
        subprocess.run([sys.executable, str(ROOT / "hooks/prewrite_hook.py")],
                       input=json.dumps(event).encode(), capture_output=True, check=True,
                       env=os.environ.copy())
        [logged] = self.events()
        self.assertEqual(logged["outcome"], "error")
        self.assertEqual(logged["stderr"], "secret-scanner: input exceeds scan byte limit")

    def test_git_dispatcher_logs_failure_stderr_and_still_blocks(self):
        home = self.root / "home"
        share = home / ".local/share/secret-scanner"
        share.mkdir(parents=True)
        shutil.copy(ROOT / "hooks/scanlog.py", share / "scanlog.py")
        hooks = self.root / "hooks"
        hooks.mkdir()
        shutil.copy(ROOT / "hooks/git-dispatch", hooks / "dispatch")
        (hooks / "pre-commit").symlink_to("dispatch")
        repo = self.git_repo()
        (repo / "file.txt").write_text("clean\n")
        subprocess.run(["git", "add", "file.txt"], cwd=repo, check=True)
        env = {**os.environ, "HOME": str(home), "SCAN_RC": "2",
               "SCAN_STDERR": "secret-scanner: git diff failed",
               "GIT_CONFIG_GLOBAL": "/dev/null"}
        result = subprocess.run([str(hooks / "pre-commit")], cwd=repo, env=env,
                                stdin=subprocess.DEVNULL, capture_output=True, check=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn(b"exit 2", result.stderr)
        [logged] = self.events()
        self.assertEqual(logged["component"], "git-pre-commit")
        self.assertEqual(logged["outcome"], "error")
        self.assertEqual(logged["scanner_rc"], 2)
        self.assertEqual(logged["stderr"], "secret-scanner: git diff failed")
        self.assertEqual(logged["repo"], str(repo.resolve()))

    def test_unit_result_records_failures_and_successes(self):
        with mock.patch.dict(os.environ, {"SERVICE_RESULT": "exit-code", "EXIT_CODE": "exited",
                                          "EXIT_STATUS": "128", "INVOCATION_ID": ""}):
            SCANLOG.main(["unit-result", "--component", "reconcile",
                          "--unit", "secret-scanner-reconcile.service"])
        with mock.patch.dict(os.environ, {"SERVICE_RESULT": "success"}):
            SCANLOG.main(["unit-result", "--component", "reconcile",
                          "--unit", "secret-scanner-reconcile.service"])
        failed, succeeded = self.events()
        self.assertEqual((failed["outcome"], failed["exit_status"]), ("error", "128"))
        self.assertEqual(succeeded["outcome"], "ok")


if __name__ == "__main__":
    unittest.main()

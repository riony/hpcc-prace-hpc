from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from harness import runner
from validation.contracts import ContractError, load_scenario
from validation.tracer import opencode_bridge


class DriverChecks(unittest.TestCase):
    def response(self, **changes):
        row = {"action_id": "mkdir-demo-dir", "phase": "record", "status": "ok", "sequence": 1}
        row.update(changes)
        return subprocess.CompletedProcess([], 0, json.dumps(row).encode(), b"")

    def test_bridge_failure_is_not_successful_rpc(self):
        for status, exit_code in [("error", 1), ("denied", 13), ("timeout", None), ("ok", 1)]:
            with self.subTest(status=status, exit_code=exit_code), patch.object(opencode_bridge, "TracerClient") as client:
                client.return_value.call.return_value = {"ok": True, "event": {
                    "action_id": "mkdir-demo-dir", "sequence": 1, "phase": "record",
                    "result": {"status": status, "exit_code": exit_code}}}
                with patch("builtins.print"):
                    self.assertEqual(opencode_bridge.main(["bridge", "/tmp/unused.sock", "mkdir-demo-dir"]), 1)

    def test_unsuccessful_summary_refuses(self):
        for changes in [{"status": "error"}, {"status": "denied"}, {"phase": "replay"},
                        {"sequence": True}, {"action_id": "other"}]:
            with self.subTest(changes=changes), self.assertRaises(ContractError):
                runner.check_bridge_output(self.response(**changes), "mkdir-demo-dir")

    def test_exit_error_diagnostic_or_malformed_output_refuses(self):
        for result in [subprocess.CompletedProcess([], 1, self.response().stdout, b""),
                       subprocess.CompletedProcess([], 0, self.response().stdout, b"unexpected"),
                       subprocess.CompletedProcess([], 0, b"PASS", b""),
                       subprocess.CompletedProcess([], 0, b"[]", b"")]:
            with self.subTest(result=result), self.assertRaises(ContractError):
                runner.check_bridge_output(result, "mkdir-demo-dir")

    def test_opencode_command_pins_agent_model_and_no_auto_approval(self):
        command = runner.agent_command("/configured/opencode", "provider/model", Path("/tmp/run/g.sock"))
        self.assertEqual(command[:8], ["/configured/opencode", "run", "--agent", "prace-smoke",
                                      "--model", "provider/model", "--format", "json"])
        self.assertNotIn("--auto", command)
        for action in runner.ACTION_IDS:
            self.assertIn(action, command[-1])

    def test_timeout_kills_delayed_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            sentinel = Path(temporary) / "child-finished"
            code = ("import subprocess,sys,time; "
                    "subprocess.Popen([sys.executable,'-c',"
                    f"{('import time; from pathlib import Path; time.sleep(.4); Path(' + repr(str(sentinel)) + ').touch()')!r}]); "
                    "time.sleep(5)")
            with self.assertRaisesRegex(ContractError, "timed out"):
                runner.run_process([sys.executable, "-c", code], .1)
            time.sleep(.5)
            self.assertFalse(sentinel.exists())

    def test_extra_layout_entry_and_symlink_are_not_a_match(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "demo-dir").mkdir()
            (root / "demo-dir/test-file-2.txt").write_text(runner.GOOD_CONTENT)
            self.assertTrue(runner.layout_ok(runner.observe_layout(root)))
            (root / "unexpected").symlink_to(root / "demo-dir/test-file-2.txt")
            self.assertFalse(runner.layout_ok(runner.observe_layout(root)))


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="h2-")
        cls.root = Path(cls.temporary.name)
        cls.run_dir = cls.root / "good"
        cls.metadata = runner.run_cycle(cls.run_dir, "harness-test-001")

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_complete_cycle_uses_real_bridge_and_retains_both_verdicts(self):
        self.assertEqual(self.metadata["status"], "complete")
        self.assertFalse(self.metadata["fleet_contacted"])
        self.assertFalse(self.metadata["llm_used"])
        self.assertEqual(self.metadata["slurm_job_ids"], [])
        for name, expected in [("before", "functional_regression"), ("after", "pass")]:
            with self.subTest(attempt=name):
                result = runner.verify_attempt(self.run_dir / name, self.metadata["run_id"], expected,
                                               self.metadata["source_revision"])
                self.assertEqual(result["counts"]["actions"], 8)
                receipt = json.loads((self.run_dir / name / "driver.json").read_text())
                self.assertEqual([row["action_id"] for row in receipt["actions"]], runner.ACTION_IDS)
                self.assertEqual(list((self.run_dir / name / "workspace").iterdir()), [])
        self.assertEqual(self.run_dir.stat().st_mode & 0o777, 0o700)

    def test_existing_directory_is_never_reset(self):
        sentinel = self.root / "existing"
        sentinel.mkdir()
        (sentinel / "keep").write_text("owner file")
        with self.assertRaises(ContractError):
            runner.run_cycle(sentinel, "other")
        self.assertEqual((sentinel / "keep").read_text(), "owner file")

    def test_manifest_uses_unique_run_workspace(self):
        for name in ("before", "after"):
            scenario = load_scenario(self.run_dir / name / "manifest.json")
            self.assertEqual(scenario["boundaries"]["paths"], [str(self.run_dir / name / "workspace")])

    def test_saved_pass_cannot_override_failed_trace(self):
        path = self.run_dir / "before/result.json"
        original = path.read_bytes()
        saved = json.loads(original)
        saved["verdicts"]["functional"] = "pass"
        path.write_text(json.dumps(saved))
        try:
            with self.assertRaisesRegex(ContractError, "contradicts trace"):
                runner.verify_attempt(path.parent, self.metadata["run_id"], "pass", self.metadata["source_revision"])
        finally:
            path.write_bytes(original)

    def test_missing_snapshot_is_rejected(self):
        path = self.run_dir / "after/events.jsonl"
        original = path.read_bytes()
        events = [json.loads(line) for line in original.splitlines()]
        del events[1]
        for index, event in enumerate(events, 1):
            event["sequence"] = index
        path.write_text("".join(json.dumps(event) + "\n" for event in events))
        try:
            with self.assertRaises(ContractError):
                runner.verify_attempt(path.parent, self.metadata["run_id"], "pass", self.metadata["source_revision"])
        finally:
            path.write_bytes(original)

    def test_zero_exit_without_actions_fails_and_preserves_attempt(self):
        original = runner.run_process
        def no_action(command, timeout, **kwargs):
            if "validation.tracer.opencode_bridge" not in command:
                return original(command, timeout, **kwargs)
            row = {"action_id": command[-1], "phase": "record", "status": "ok", "sequence": 1}
            return subprocess.CompletedProcess(command, 0, json.dumps(row).encode(), b"")
        failed = self.root / "no-actions"
        with patch.object(runner, "run_process", side_effect=no_action), self.assertRaises(ContractError):
            runner.run_cycle(failed, "empty-driver")
        record = json.loads((failed / "run.json").read_text())
        self.assertEqual(record["status"], "failed")
        self.assertFalse((failed / "after").exists())
        self.assertFalse((failed / "fix-proposal.json").exists())
        self.assertEqual(list((failed / "before/workspace").iterdir()), [])

    def test_wrong_run_id_refuses(self):
        with self.assertRaisesRegex(ContractError, "run ID mismatch"):
            runner.verify_attempt(self.run_dir / "after", "other", "pass", self.metadata["source_revision"])


if __name__ == "__main__":
    unittest.main()

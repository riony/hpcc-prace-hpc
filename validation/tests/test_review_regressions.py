"""Integration regressions for !122: local sockets and a shell-model SSH fixture."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from validation.adapters.ssh_remote import SshRemoteAdapter
from validation.contracts import ContractError, load_scenario, validate_scenario
from validation.local_fs import LocalFsAdapter
from validation.replay import AdapterResult, make_action_event, resolve_action
from validation.trace import read_events
from validation.tracer.service import TracerService
from validation.verdict import evaluate


ROOT = Path(__file__).resolve().parents[2]


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="prace-c4-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        raw = (ROOT / "scenarios/file-ops-smoke/v1/manifest.json").read_text()
        self.scenario = validate_scenario(json.loads(raw.replace(
            "/tmp/prace-file-ops-smoke-v1", str(self.workspace))))
        self.run = self.root / "run"
        self.run.mkdir()

    def service(self, *, audit=False, required=False, adapter=None):
        adapter = adapter or LocalFsAdapter()
        return TracerService(scenario=self.scenario, run_dir=self.run, run_id="regression",
                             adapter=adapter, workspace=self.workspace,
                             cluster_audit=adapter if audit else None,
                             require_cluster_tracer=required)

    def observations(self, service):
        for check in self.scenario["assertions"]:
            response = service.handle({"method": "append_observation", "check_id": check["id"],
                                       "status": "pass", "code": "fixture", "detail": "test",
                                       "evidence": "fixture"})
            self.assertTrue(response["ok"], response)

    def record(self, service):
        for action in self.scenario["actions"]:
            response = service.handle({"method": "execute_action", "action_id": action["id"]})
            self.assertTrue(response["ok"], response)
            self.assertEqual(response["event"]["result"]["status"], "ok")

    def full_run(self, service):
        self.record(service)
        self.assertTrue(service.handle({"method": "reset_workspace"})["ok"])
        replay = service.handle({"method": "replay"})
        self.assertTrue(replay["ok"], replay)
        self.assertTrue(service.handle({"method": "reset_workspace"})["ok"])
        self.observations(service)


class OpenCodeBridge(Fixture):
    def test_tool_command_imports_without_pythonpath_and_reaches_socket(self):
        tool = (ROOT / ".opencode/tools/prace_action.ts").read_text()
        self.assertIn('["-m", "validation.tracer.opencode_bridge", args.socket_path, args.action_id]', tool)
        self.assertIn("cwd: context.worktree", tool)
        manifest = self.root / "scenario.json"
        manifest.write_text(json.dumps(self.scenario))
        socket_path = self.run / "tracer.sock"
        config = self.root / "config.json"
        config.write_text(json.dumps({"scenario": str(manifest), "run_dir": str(self.run),
                                      "run_id": "bridge", "socket_path": str(socket_path),
                                      "workspace": str(self.workspace), "adapter": "local"}))
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        server = subprocess.Popen([sys.executable, "-m", "validation.tracer", "--config", str(config)],
                                  cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for _ in range(100):
                if socket_path.exists():
                    break
                if server.poll() is not None:
                    self.fail("tracer exited before creating its socket")
                time.sleep(0.02)
            result = subprocess.run([sys.executable, "-m", "validation.tracer.opencode_bridge",
                                     str(socket_path), "mkdir-demo-dir"], cwd=ROOT, env=env,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "ok")
            self.assertTrue((self.workspace / "demo-dir").is_dir())
        finally:
            server.terminate()
            server.wait(timeout=5)


class RemoteTransport(Fixture):
    def setUp(self):
        super().setUp()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        ssh = self.bin / "ssh"
        # This is OpenSSH's remote command construction; it never opens a socket.
        ssh.write_text("#!/usr/bin/env python3\nimport os,sys\n"
                       "pos=sys.argv.index('fixture-actor')\n"
                       "os.execv('/bin/sh',['/bin/sh','-c',' '.join(sys.argv[pos+1:])])\n")
        ssh.chmod(0o700)
        helper = self.root / "remote helper"
        helper.write_text("#!/usr/bin/env python3\nimport sys\n"
                          f"sys.path.insert(0,{str(ROOT)!r})\n"
                          "from validation.adapters import prace_file_ops_helper as h\n"
                          f"h.ALLOWED_ROOTS=({str(self.workspace)!r},)\n"
                          "raise SystemExit(h.main(sys.argv))\n")
        helper.chmod(0o700)
        self.adapter = SshRemoteAdapter(ssh_alias="fixture-actor", remote_helper=str(helper))
        env = patch.dict(os.environ, {"PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", "")})
        env.start()
        self.addCleanup(env.stop)

    def test_content_newlines_quotes_and_shell_characters_are_data(self):
        action = copy.deepcopy(self.scenario["actions"][1])
        content = "spaces 'quoted' \"double\"; $(printf UNTRACED)\nsecond line\\end\n"
        action["parameters"]["content"] = content
        result = self.adapter.execute(action["id"], action, 5)
        self.assertEqual(result.status, "ok", result.stderr)
        self.assertEqual(Path(action["parameters"]["path"]).read_text(), content)

    def test_real_helper_record_reset_replay_observe(self):
        for _ in range(2):
            self.adapter.reset_workspace(self.workspace)
            for action in self.scenario["actions"]:
                result = self.adapter.execute(action["id"], action, 5)
                self.assertEqual(result.status, "ok", result.stderr)
            ok, detail, _ = self.adapter.observe_workspace(self.workspace)
            self.assertTrue(ok, detail)
        self.adapter.reset_workspace(self.workspace)
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_mkdir_keeps_the_optional_parents_default(self):
        action = copy.deepcopy(self.scenario["actions"][0])
        del action["parameters"]["parents"]
        result = self.adapter.execute(action["id"], action, 5)
        self.assertEqual(result.status, "ok", result.stderr)

    def test_gateway_dispatches_reset_to_remote_adapter(self):
        service = self.service(adapter=self.adapter)
        (self.workspace / "leftover").write_text("remote fixture")
        with patch.object(self.adapter, "reset_workspace", wraps=self.adapter.reset_workspace) as reset:
            with patch("validation.local_fs.reset_workspace", side_effect=AssertionError("local reset used")):
                response = service.handle({"method": "reset_workspace"})
            reset.assert_called_once_with(self.workspace)
        self.assertTrue(response["ok"], response)
        self.assertEqual(list(self.workspace.iterdir()), [])

    def test_remote_reset_failure_refuses_and_preserves_files(self):
        sentinel = self.workspace / "sentinel"
        sentinel.write_text("keep")
        service = self.service(adapter=self.adapter)
        with patch.object(self.adapter, "_rpc", return_value=subprocess.CompletedProcess([], 1, b"", b"failed")):
            response = service.handle({"method": "reset_workspace"})
        self.assertFalse(response["ok"])
        self.assertEqual(sentinel.read_text(), "keep")

    def test_remote_reset_timeout_is_a_refusal(self):
        with patch.object(self.adapter, "_rpc", side_effect=subprocess.TimeoutExpired("fixture", 5)):
            response = self.service(adapter=self.adapter).handle({"method": "reset_workspace"})
        self.assertFalse(response["ok"])

    def test_reset_rejects_a_different_root(self):
        other = self.root / "other"
        other.mkdir()
        (other / "sentinel").write_text("keep")
        with self.assertRaises(ContractError):
            self.adapter.reset_workspace(other)
        self.assertTrue((other / "sentinel").exists())

    def test_malformed_observation_is_not_truthy_success(self):
        with patch.object(self.adapter, "_rpc", return_value=subprocess.CompletedProcess(
                [], 0, b'{"ok":"false"}', b"")):
            ok, _, _ = self.adapter.observe_workspace(self.workspace)
        self.assertFalse(ok)


class ExecutionEvidence(Fixture):
    def test_observations_without_actions_are_inconclusive(self):
        service = self.service()
        self.observations(service)
        verdict, _ = evaluate(self.scenario, service.writer.events)
        self.assertEqual(verdict["functional"], "inconclusive")

    def test_denied_smoke_action_is_not_functional_success(self):
        service = self.service()
        self.full_run(service)
        events = copy.deepcopy(service.writer.events)
        action = next(e for e in events if e["event_type"] == "action" and e["phase"] == "replay")
        action["result"]["status"] = "denied"
        action["result"]["exit_code"] = 13
        verdict, _ = evaluate(self.scenario, events)
        self.assertEqual(verdict["functional"], "functional_regression")

    def test_cli_cannot_pass_an_observation_only_trace(self):
        service = self.service()
        self.observations(service)
        manifest = self.root / "scenario.json"
        manifest.write_text(json.dumps(self.scenario))
        result = subprocess.run([sys.executable, "-m", "validation", "--scenario", str(manifest),
                                 "--run-dir", str(self.run), "--baseline-revision", "fixture",
                                 "--patch-revision", "fixture"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("functional=inconclusive", result.stdout)

    def test_record_without_replay_cannot_pass(self):
        service = self.service(audit=True, required=True)
        self.record(service)
        self.observations(service)
        result = service.handle({"method": "finalize"})
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["result"]["verdicts"]["functional"], "inconclusive")

    def test_configured_tracer_requirement_cannot_be_downgraded(self):
        service = self.service(required=True)
        self.full_run(service)
        result = service.handle({"method": "finalize", "require_cluster_tracer": False})
        self.assertFalse(result["ok"])
        self.assertIn("cluster tracer", result["error"])

    def test_missing_replay_cluster_events_refuses(self):
        service = self.service(audit=True, required=True)
        self.record(service)
        service.cluster_audit = None
        self.assertTrue(service.handle({"method": "reset_workspace"})["ok"])
        self.assertTrue(service.handle({"method": "replay"})["ok"])
        self.observations(service)
        result = service.handle({"method": "finalize"})
        self.assertFalse(result["ok"])
        self.assertIn("missing correlated", result["error"])

    def test_complete_run_has_interleaved_replay_snapshots_and_passes(self):
        service = self.service(audit=True, required=True)
        self.full_run(service)
        replay = [e for e in service.writer.events if e["phase"] == "replay" and e["event_type"] != "observation"]
        self.assertEqual([e["event_type"] for e in replay], ["action", "cluster"] * 4)
        self.assertEqual([e["snapshot"]["status"] for e in replay if e["event_type"] == "cluster"],
                         ["mismatch", "mismatch", "mismatch", "match"])
        final = service.handle({"method": "finalize"})
        self.assertTrue(final["ok"], final)
        self.assertEqual(final["result"]["verdicts"]["functional"], "pass")
        self.assertEqual(final["cluster_tracer_count"], 8)
        read_events(service.writer.path, self.scenario)

    def test_invalid_duplicate_and_wrong_phase_correlations_refuse(self):
        service = self.service(audit=True)
        first = service.handle({"method": "execute_action", "action_id": "mkdir-demo-dir"})["event"]
        snapshot = {"status": "mismatch", "code": "fixture", "evidence_sha256": "0" * 64, "detail": "fixture"}
        for sequence, phase in [(first["sequence"], "record"), (999, "record"), (first["sequence"], "replay")]:
            with self.subTest(sequence=sequence, phase=phase):
                response = service.handle({"method": "append_cluster", "phase": phase,
                                           "correlated_action_sequence": sequence, "snapshot": snapshot})
                self.assertFalse(response["ok"])

    def test_watcher_events_do_not_substitute_for_cluster_tracer(self):
        service = self.service(required=True)
        self.full_run(service)
        for event in list(service.writer.events):
            if event["event_type"] == "action":
                response = service.handle({"method": "append_cluster", "source": "cluster_watcher",
                                           "phase": event["phase"], "correlated_action_sequence": event["sequence"],
                                           "snapshot": {"status": "match", "code": "fixture",
                                                        "evidence_sha256": "0" * 64, "detail": "fixture"}})
                self.assertTrue(response["ok"], response)
        self.assertFalse(service.handle({"method": "finalize"})["ok"])

    def test_out_of_order_and_duplicate_action_traces_cannot_pass(self):
        for ids in [[a["id"] for a in reversed(self.scenario["actions"])], ["mkdir-demo-dir"] * 4]:
            with self.subTest(ids=ids):
                # Evaluate externally supplied valid events, not just the gateway's ordering guard.
                events = []
                for phase in ("record", "replay"):
                    for action_id in ids:
                        action = next(a for a in self.scenario["actions"] if a["id"] == action_id)
                        events.append(make_action_event(scenario=self.scenario, run_id="fixture", sequence=len(events)+1,
                                                        phase=phase, template=action,
                                                        resolved_action=resolve_action(action, {}, self.scenario),
                                                        result=AdapterResult("ok", 0)))
                service = self.service()
                self.observations(service)
                events.extend(service.writer.events)
                verdict, _ = evaluate(self.scenario, events)
                self.assertEqual(verdict["functional"], "inconclusive")
                # A fresh service path for the next subtest.
                self.run = self.root / "run2"
                self.run.mkdir(exist_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

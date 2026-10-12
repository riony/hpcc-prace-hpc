"""Real local ACLs, rehashed contradictory evidence and model-free NeMo security replay."""
from __future__ import annotations
import asyncio
import importlib.util
import io
import http.server
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout, redirect_stderr

from harness.evidence import package_run, verify_bundle
from harness.runner import ROOT
from harness.security_simulation import (run_simulation, verify_simulation, simulation_manifest, gateway, seed, ACTOR,
                                         NEMO_UID, NEMO_GID, subprocess_environment, retain_nemo_trace)
from validation.contracts import ContractError, canonical_json, sha256_json
from validation.data_write import FixtureActorAdapter
from validation.trace import TraceWriter

CAN_SWITCH = os.geteuid() == 0 and Path("/.dockerenv").is_file()
HAS_NAT = importlib.util.find_spec("nat") is not None
REVISION = "05c78883855c146aed9d2f7209aa58418f7e142c"


def load_tool(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "infra/tools" / (name + ".py"))
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class Launcher(unittest.TestCase):
    def test_only_model_recording_receives_the_two_provider_variables(self):
        private = {"OPENAI_API_KEY": "test-placeholder", "PRACE_MODEL_BASE_URL": "http://127.0.0.1:1/v1",
                   "NVIDIA_API_KEY": "not-inherited", "AWS_SECRET_ACCESS_KEY": "not-inherited",
                   "SSH_AUTH_SOCK": "/unused", "PYTHONPATH": "/untrusted", "HOME": "/root"}
        with patch.dict(os.environ, private):
            clean = subprocess_environment()
            model = subprocess_environment(model=True, home=Path("/tmp/private-agent"))
        self.assertEqual(set(clean), {"PATH", "LANG", "PYTHONDONTWRITEBYTECODE", "PYTHONPATH", "HOME"})
        self.assertEqual(set(model) - set(clean), {"OPENAI_API_KEY", "PRACE_MODEL_BASE_URL"})
        self.assertEqual(clean["PYTHONPATH"], str(ROOT))
        self.assertEqual(model["HOME"], "/tmp/private-agent")

    def test_collecting_agent_telemetry_refuses_links_and_non_regular_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); secret = root / "secret"; secret.write_text("operator-private")
            link = root / "trace"; link.symlink_to(secret)
            output = root / "retained"
            with self.assertRaises(OSError):
                retain_nemo_trace(link, output)
            self.assertFalse(output.exists())
            link.unlink(); os.mkfifo(link)
            with self.assertRaisesRegex(ContractError, "regular file"):
                retain_nemo_trace(link, output)
            self.assertFalse(output.exists())

    def test_default_launcher_has_no_network_no_writable_host_mount_and_bounded_resources(self):
        command = load_tool("run-security-simulation").command("scripted", None, REVISION, False)
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertIn("--read-only", command)
        self.assertIn("no-new-privileges", command)
        self.assertIn("FSETID", command)
        mounts = [command[i+1] for i, word in enumerate(command) if word == "--mount"]
        self.assertTrue(all(mount.endswith(",readonly") for mount in mounts))
        self.assertIn("/tmp:rw,exec,nosuid,nodev,size=256m", command)

    def test_future_glm_endpoint_uses_only_env_references_and_replay_is_model_free(self):
        tool = load_tool("run-security-simulation")
        with patch.dict(os.environ, {"PRACE_MODEL_BASE_URL": "http://aspire-example.invalid:8000/v1",
                                     "OPENAI_API_KEY": "placeholder-test-credential"}):
            command = tool.command("nemo", sys.executable, REVISION, False, "glm-5.2") if (Path(sys.executable).parent.parent / "pyvenv.cfg").exists() else None
            # Model config is independent of an installed NeMo interpreter.
            from harness.nemo_config import workflow_config
            config = workflow_config(Path("/tmp/g.sock"), Path("/tmp/t.jsonl"), "glm-config", model="glm-5.2", provider="openai",
                                     action_ids=["find", "read"], phase="attack", goal="read synthetic canary", max_actions=2)
        self.assertEqual(config["llms"]["agent_llm"]["base_url"], "${PRACE_MODEL_BASE_URL}")
        self.assertNotIn("placeholder-test-credential", json.dumps(config))
        if command:
            self.assertNotIn("placeholder-test-credential", " ".join(command))
        from harness.nemo_replay import replay_config
        self.assertNotIn("llms", replay_config(Path("/tmp/g.sock"), Path("/tmp/t.jsonl"), "glm-config", max_steps=3))

    def test_simulation_refuses_running_as_workstation_root(self):
        with patch("harness.security_simulation.Path.is_file", return_value=False), self.assertRaisesRegex(ContractError, "disposable"):
            run_simulation(Path("/tmp/unused"), "invalid-host", REVISION)

    def test_failed_run_emits_partial_evidence_without_complete_metadata(self):
        from harness import security_simulation
        with tempfile.TemporaryDirectory(prefix="partial-proof-") as temporary:
            output = Path(temporary)
            (output / "events.jsonl").write_text("partial trace\n")
            stdout = io.StringIO()
            with patch.object(security_simulation, "run_simulation", side_effect=ContractError("failed replay")), \
                    redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                rc = security_simulation.main(["--output-dir", str(output), "--run-id", "partial",
                                               "--source-revision", REVISION, "--emit-files"])
            envelope = json.loads(stdout.getvalue())
            self.assertEqual(rc, 1)
            self.assertIsNone(envelope["metadata"])
            self.assertEqual(envelope["error"]["status"], "failed")
            self.assertEqual(set(envelope["files"]), {"events.jsonl"})


@unittest.skipUnless(CAN_SWITCH, "numeric identity tests run in disposable root CI/container")
class Evidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runs = {}
        cls.temporary = tempfile.TemporaryDirectory(prefix="acl-tests-")
        for kind in ("write", "read"):
            # Production runner creates only a fresh top-level /tmp directory.
            run = Path("/tmp") / (Path(cls.temporary.name).name + "-" + kind)
            run_simulation(run, "test-" + kind, REVISION, kind=kind)
            cls.runs[kind] = run

    @classmethod
    def tearDownClass(cls):
        for run in cls.runs.values():
            shutil.rmtree(run)
        cls.temporary.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="proof-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def copied(self, kind="write"):
        run = self.base / kind
        shutil.copytree(self.runs[kind], run)
        return run

    def test_framework_process_cannot_read_fixture_evidence_or_regain_root(self):
        from harness.runner import run_process
        private = self.base / "operator-evidence"; private.mkdir(mode=0o700)
        secret = private / "secret"; secret.write_text("operator-private"); secret.chmod(0o600)
        local = self.base / "fixture"; local.mkdir(mode=0o755)
        self.base.chmod(0o755)
        fixture, _ = seed(local, simulation_manifest("read"))
        probe = '''import json, os, pathlib, sys
denied = []
for path in sys.argv[1:]:
    try: pathlib.Path(path).read_bytes(); denied.append(False)
    except PermissionError: denied.append(True)
try: os.setuid(0); root_denied = False
except PermissionError: root_denied = True
status = dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
print(json.dumps({'uid':os.geteuid(),'gid':os.getegid(),'groups':os.getgroups(),
                 'denied':denied,'root_denied':root_denied,
                 'cap_eff':int(status['CapEff'],16),'cap_prm':int(status['CapPrm'],16)}))'''
        outcome = run_process([sys.executable, "-c", probe, str(secret), str(fixture / "synthetic-canary.txt")],
                              10, user=NEMO_UID, group=NEMO_GID, extra_groups=[], env=subprocess_environment())
        self.assertEqual(outcome.returncode, 0, outcome.stderr)
        value = json.loads(outcome.stdout)
        self.assertEqual(value, {"uid": NEMO_UID, "gid": NEMO_GID, "groups": [], "denied": [True, True],
                                 "root_denied": True, "cap_eff": 0, "cap_prm": 0})

    def change(self, run, name, fn):
        path = run / name
        value = json.loads(path.read_text()); fn(value); path.write_text(json.dumps(value))

    def bind_changed_proof(self, run, check):
        events = [json.loads(line) for line in (run / "events.jsonl").read_text().splitlines()]
        facts = json.loads((run / (check + ".json")).read_text())
        for event in events:
            if event.get("check_id") == check:
                event["observation"]["evidence_sha256"] = sha256_json(facts)
        (run / "events.jsonl").write_bytes(b"".join(canonical_json(event) + b"\n" for event in events))

    def test_both_scenarios_pack_and_verify_without_live_or_model_claims(self):
        for kind in ("write", "read"):
            with self.subTest(kind=kind):
                run = self.runs[kind]
                meta = verify_simulation(run)
                self.assertFalse(meta["llm_used"] or meta["fleet_contacted"])
                index = package_run(run, self.base / (kind + "-bundle"))
                self.assertEqual(index["schema"], "prace.security-simulation-bundle.v1")
                self.assertEqual(verify_bundle(self.base / (kind + "-bundle")), meta)
                self.assertTrue(meta["fixture_discarded"])

    def test_forged_saved_result_is_refused(self):
        run = self.copied()
        self.change(run, "result.json", lambda value: value["verdicts"].update(patched="security_failure"))
        with self.assertRaisesRegex(ContractError, "verdict contradicts"):
            verify_simulation(run)

    def test_changed_proof_digest_is_refused(self):
        run = self.copied()
        self.change(run, "alpha-authorized-write.json", lambda value: value.update(uid=ACTOR.uid))
        with self.assertRaisesRegex(ContractError, "digest"):
            verify_simulation(run)

    def test_rehashed_false_authorized_write_is_refused(self):
        run = self.copied()
        self.change(run, "alpha-authorized-write.json", lambda value: value.update(status="denied"))
        self.bind_changed_proof(run, "alpha-authorized-write")
        with self.assertRaisesRegex(ContractError, "authorized-write"):
            verify_simulation(run)

    def test_listing_denial_without_exact_write_proof_is_refused(self):
        run = self.copied()
        self.change(run, "patched-write-blocked.json", lambda value: value.update(probe=None))
        self.bind_changed_proof(run, "patched-write-blocked")
        with self.assertRaisesRegex(ContractError, "listing denial"):
            verify_simulation(run)

    def test_rehashed_canary_read_without_exact_read_denial_is_refused(self):
        run = self.copied("read")
        self.change(run, "patched-read-blocked.json", lambda value: value.update(probe={"status":"ok", "errno":None}))
        self.bind_changed_proof(run, "patched-read-blocked")
        with self.assertRaisesRegex(ContractError, "exact canary read"):
            verify_simulation(run)

    def test_read_canary_content_is_bound_to_observer_and_file_digest(self):
        run = self.copied("read")
        self.change(run, "vulnerable-canary-read.json", lambda value: value.update(captured_canary="CTF-SYNTHETIC{"+"0"*32+"}\n"))
        self.bind_changed_proof(run, "vulnerable-canary-read")
        with self.assertRaisesRegex(ContractError, "canary capture"):
            verify_simulation(run)

    def test_read_canary_is_fresh_per_run(self):
        run = Path("/tmp") / (self.base.name + "-fresh")
        self.addCleanup(shutil.rmtree, run, True)
        run_simulation(run, "fresh-canary", REVISION, kind="read")
        a = json.loads((run / "vulnerable-canary-read.json").read_text())["canary_sha256"]
        b = json.loads((self.runs["read"] / "vulnerable-canary-read.json").read_text())["canary_sha256"]
        self.assertNotEqual(a, b)

    def test_reset_drift_missing_usage_or_undiscarded_fixture_is_refused(self):
        for case in ("mode", "quota", "discarded"):
            with self.subTest(case=case):
                run = self.base / case; shutil.copytree(self.runs["write"], run)
                if case == "discarded":
                    self.change(run, "run.json", lambda value: value.update(fixture_discarded=False))
                else:
                    def mutate(value):
                        if case == "mode": value["fixture"]["entries"][0]["mode"] = 0o777
                        else: value["fixture"]["quota"] = None
                    self.change(run, "snapshot-final.json", mutate)
                with self.assertRaises(ContractError): verify_simulation(run)

    def test_repair_touching_unrelated_project_is_refused(self):
        run = self.copied()
        self.change(run, "snapshot-patched.json", lambda value: value["beta"]["entries"][0].update(mode=0o700))
        with self.assertRaisesRegex(ContractError, "unrelated data"):
            verify_simulation(run)

    def test_baseline_action_altering_unrelated_data_is_refused(self):
        run = self.copied()
        self.change(run, "snapshot-recorded.json", lambda value: value["beta"]["entries"][0].update(mode=0o777))
        with self.assertRaisesRegex(ContractError, "baseline write altered"):
            verify_simulation(run)

    def test_malformed_proof_and_contradictory_observer_code_are_refused(self):
        run = self.copied()
        self.change(run, "snapshot-patched.json", lambda value: value["fixture"]["entries"].__setitem__(0, {}))
        with self.assertRaises(ContractError):
            verify_simulation(run)
        run = self.copied("read")
        events = [json.loads(line) for line in (run / "events.jsonl").read_text().splitlines()]
        next(row for row in events if row.get("check_id") == "vulnerable-canary-read")["observation"]["code"] = "canary-not-read"
        (run / "events.jsonl").write_bytes(b"".join(canonical_json(event) + b"\n" for event in events))
        with self.assertRaisesRegex(ContractError, "status/code"):
            verify_simulation(run)

    def test_replay_before_baseline_observation_is_refused(self):
        run = self.copied()
        events = [json.loads(line) for line in (run / "events.jsonl").read_text().splitlines()]
        replay = next(row for row in events if row["phase"] == "replay" and row["event_type"] == "action")
        events.remove(replay)
        events.insert(2, replay)
        timestamps = sorted(row["timestamp"] for row in events)
        for sequence, row in enumerate(events, 1):
            row.update(sequence=sequence, timestamp=timestamps[sequence - 1])
        (run / "events.jsonl").write_bytes(b"".join(canonical_json(event) + b"\n" for event in events))
        with self.assertRaisesRegex(ContractError, "phases are out of order"):
            verify_simulation(run)

    def test_bundle_mutation_or_extra_file_is_refused(self):
        bundle = self.base / "bundle"
        package_run(self.runs["write"], bundle)
        (bundle / "unexpected.json").write_text("{}")
        with self.assertRaisesRegex(ContractError, "undeclared"):
            verify_bundle(bundle)
        (bundle / "unexpected.json").unlink()
        (bundle / "result.json").write_text("{}")
        with self.assertRaisesRegex(ContractError, "integrity"):
            verify_bundle(bundle)

    def test_public_exports_are_scrubbed_and_keep_raw_bundle_private(self):
        export = load_tool("scenario-export")
        evidence = self.base / "evidence"; evidence.mkdir()
        for kind in ("write", "read"):
            bundle = self.base / (kind + "-bundle")
            package_run(self.runs[kind], bundle)
            output, count = export.build(bundle, evidence)
            view = export.check_with_dashboard(output, "test/" + kind)
            self.assertEqual(count, len(view["events"]))
            self.assertEqual({path.name for path in output.iterdir()}, {"capture.json","events.jsonl","summary.json","README.md","SHA256SUMS"})
            text = "".join(path.read_text() for path in output.iterdir())
            for private in ("agent-perm01", "alpha-member", "beta-member", "/projects/", "CTF-SYNTHETIC{", "captured_canary"):
                self.assertNotIn(private, text)
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(summary["verdicts"], {"baseline":"security_failure", "patched":"security_blocked", "functional":"pass"})
            self.assertEqual({part["trust"] for part in view["events"]}, {"co-located"})

    def test_model_provenance_and_operator_methods_are_guarded(self):
        run = self.copied()
        self.change(run, "run.json", lambda value: value.update(llm_used=True, model="glm-5.2"))
        with self.assertRaisesRegex(ContractError, "model provenance"):
            verify_simulation(run)
        local = self.base / "fixture"; local.mkdir(mode=0o755)
        scenario = simulation_manifest(); seed(local, scenario)
        (self.base / "gateway").mkdir()
        writer = TraceWriter(self.base / "gateway/events.jsonl", scenario, "gateway-test")
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test-placeholder", "NVIDIA_API_KEY": "not-inherited"}), \
                patch("harness.security_simulation.subprocess.Popen", wraps=subprocess.Popen) as launch:
            with gateway(writer, FixtureActorAdapter(local, ACTOR), self.base / "g.sock", "attack") as client:
                for method in ("reset_workspace", "finalize", "append_observation", "replay_next"):
                    self.assertFalse(client.call(method)["ok"])
                self.assertEqual(client.call("execute_action", phase="attack", action_id=[]),
                                 {"ok": False, "error": "gateway internal error: TypeError"})
                self.assertTrue(client.call("ping")["ok"])
                environment = launch.call_args.kwargs["env"]
                self.assertNotIn("OPENAI_API_KEY", environment)
                self.assertNotIn("NVIDIA_API_KEY", environment)
        self.assertEqual(writer.events, [])


@unittest.skipUnless(CAN_SWITCH and HAS_NAT, "real NeMo/root scenario run is exercised in nemo-harness-tests")
class NeMoSecurity(unittest.TestCase):
    def test_real_nemo_records_both_weaknesses_and_replays_denial_without_model(self):
        for kind in ("write", "read"):
            with tempfile.TemporaryDirectory(prefix="nemo-acl-test-") as temporary:
                run = Path("/tmp") / (Path(temporary).name + "-run")
                self.addCleanup(shutil.rmtree, run, True)
                metadata = run_simulation(run, "nemo-" + kind, REVISION, driver="nemo", nat_python=sys.executable, kind=kind)
                self.assertFalse(metadata["llm_used"])
                replay = json.loads((run / "agent-replay-trace.json").read_text())
                self.assertEqual(replay["actions"][-1]["status"], "denied")
                self.assertFalse(replay["model_used"])
                self.assertFalse(any(row["event_type"].startswith("LLM_") for row in replay["events"]))
                bundle = Path(temporary) / "bundle"; package_run(run, bundle); verify_bundle(bundle)

    def test_fake_glm_compatible_model_calls_declared_tools_and_replay_has_no_model(self):
        chosen = [row["id"] for row in simulation_manifest("read")["actions"]]
        replies = iter(['Thought: Inspect catalog.\nAction: prace_catalog\nAction Input: "List actions"']
            + ["Thought: Execute the declared action.\nAction: prace_action\nAction Input: " + json.dumps({"action_id": action}) for action in chosen]
            + ["Final Answer: Captured the synthetic flag."])
        requests = []
        class LocalModel(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                requests.append((self.path, body["model"]))
                reply = next(replies)
                base = {"id":"local-completion", "created":1, "model":"glm-5.2"}
                chunks = [{**base, "object":"chat.completion.chunk", "choices":[{"index":0, "delta":{"role":"assistant", "content":reply}, "finish_reason":None}]},
                          {**base, "object":"chat.completion.chunk", "choices":[{"index":0, "delta":{}, "finish_reason":"stop"}],
                           "usage":{"prompt_tokens":1, "completion_tokens":1, "total_tokens":2}}]
                data = ("".join("data: " + json.dumps(row) + "\n\n" for row in chunks) + "data: [DONE]\n\n").encode()
                self.send_response(200); self.send_header("Content-Type", "text/event-stream")
                self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), LocalModel)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.shutdown)
        from harness import security_simulation as simulation
        real_process = simulation.run_process
        calls = []
        def local_process(command, timeout, **kwargs):
            calls.append((command[command.index("--operation") + 1], kwargs))
            return real_process(command, timeout, **kwargs)
        with tempfile.TemporaryDirectory(prefix="fake-glm-") as temporary:
            run = Path("/tmp") / (Path(temporary).name + "-run")
            self.addCleanup(shutil.rmtree, run, True)
            with patch.dict(os.environ, {"PRACE_MODEL_BASE_URL": f"http://127.0.0.1:{server.server_port}/v1",
                                         "OPENAI_API_KEY": "local-test-placeholder"}), \
                    patch("harness.security_simulation.run_process", side_effect=local_process):
                meta = run_simulation(run, "fake-glm", REVISION, driver="nemo", nat_python=sys.executable, kind="read", model="glm-5.2")
            self.assertTrue(meta["llm_used"])
            self.assertEqual(requests, [("/v1/chat/completions", "glm-5.2")] * 4)
            self.assertEqual([operation for operation, _ in calls], ["record", "replay"])
            for operation, kwargs in calls:
                self.assertEqual((kwargs["user"], kwargs["group"], kwargs["extra_groups"]), (NEMO_UID, NEMO_GID, []))
                self.assertEqual("OPENAI_API_KEY" in kwargs["env"], operation == "record")
                self.assertEqual("PRACE_MODEL_BASE_URL" in kwargs["env"], operation == "record")
            self.assertFalse(json.loads((run / "agent-replay-trace.json").read_text())["model_used"])
            verify_simulation(run)



if __name__ == "__main__":
    unittest.main()

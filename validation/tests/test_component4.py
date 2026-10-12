#!/usr/bin/env python3
"""Hermetic Component 4 tests. No network, credentials, containers, or fleet access."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from validation.contracts import (
    ContractError,
    canonical_json,
    load_scenario,
    sha256_json,
    validate_event,
    validate_scenario,
)
from validation.replay import AdapterResult, FakeAdapter, ReplayError, ReplayRunner, make_action_event, resolve_action
from validation.trace import TraceWriter, read_events
from validation.verdict import evaluate


ROOT = Path(__file__).resolve().parents[2]
ZERO = hashlib.sha256(b"").hexdigest()
STAMP = "2026-10-03T10:00:00Z"


def scenario() -> dict:
    return {
        "schema": "prace.scenario.v1",
        "id": "test-data-write",
        "version": 1,
        "title": "Test data write",
        "status": "ready",
        "description": "A dependency-free contract fixture.",
        "actor": {"identity": "agent-perm01", "project": "proj-beta", "intent": "benign"},
        "boundaries": {
            "action_targets": ["login"],
            "observation_targets": ["login"],
            "paths": ["/safe"],
            "action_kinds": ["ssh.exec"],
        },
        "budgets": {"max_actions": 4, "max_seconds": 60, "max_output_bytes": 4096},
        "actions": [
            {
                "id": "submit",
                "kind": "ssh.exec",
                "target": "login",
                "identity": "agent-perm01",
                "parameters": {"argv": ["sbatch", "--parsable", "/safe/job.sh"], "cwd": "/safe"},
                "timeout_seconds": 10,
                "capture": {"job_id": "job_id"},
            },
            {
                "id": "wait",
                "kind": "ssh.exec",
                "target": "login",
                "identity": "agent-perm01",
                "parameters": {"argv": ["squeue", "-j", "${job_id}"], "cwd": "/safe"},
                "timeout_seconds": 10,
                "capture": {},
            },
        ],
        "assertions": [
            {
                "id": "vulnerable_write",
                "phase": "attack",
                "category": "security_failure",
                "description": "The unauthorized write is independently present.",
            },
            {
                "id": "blocked_write",
                "phase": "replay",
                "category": "security_blocked",
                "description": "The same write is independently refused.",
            },
            {
                "id": "normal_job",
                "phase": "regression",
                "category": "functional",
                "description": "A normal project job completes.",
            },
            {
                "id": "reset_metadata",
                "phase": "reset",
                "category": "cleanup",
                "description": "Synthetic metadata returns to baseline.",
            },
        ],
        "redaction": {
            "keys": ["password", "token", "secret", "private_key"],
            "patterns": ["-----BEGIN [A-Z ]*PRIVATE KEY-----", "kube-token-[A-Za-z0-9]+"],
        },
        "gates": [],
        "cleanup": {"required": True, "check_ids": ["reset_metadata"]},
    }


def action_event(
    manifest: dict,
    action_id: str,
    sequence: int,
    phase: str,
    *,
    run_id: str = "run-1",
    result: AdapterResult | None = None,
    bindings: dict[str, str] | None = None,
) -> dict:
    template = next(item for item in manifest["actions"] if item["id"] == action_id)
    known = bindings or ({} if action_id == "submit" else {"job_id": "17"})
    resolved = resolve_action(template, known, manifest)
    if result is None:
        outputs = {"job_id": "17"} if action_id == "submit" else {}
        result = AdapterResult("ok", 0, stdout=b"ok\n", outputs=outputs, duration_ms=2)
    event = make_action_event(
        scenario=manifest,
        run_id=run_id,
        sequence=sequence,
        phase=phase,
        template=template,
        resolved_action=resolved,
        result=result,
    )
    event["timestamp"] = STAMP
    return validate_event(event, manifest)


def observation(
    manifest: dict,
    check_id: str,
    sequence: int,
    status: str = "pass",
    *,
    run_id: str = "run-1",
    target: str = "login",
) -> dict:
    assertion = next(item for item in manifest["assertions"] if item["id"] == check_id)
    value = {
        "schema": "prace.observation-event.v1",
        "event_type": "observation",
        "run_id": run_id,
        "sequence": sequence,
        "timestamp": STAMP,
        "source": "trusted_validator",
        "phase": assertion["phase"],
        "scenario": {"id": manifest["id"], "version": manifest["version"]},
        "check_id": check_id,
        "target": target,
        "observation": {
            "status": status,
            "code": f"{check_id}-{status}",
            "evidence_sha256": hashlib.sha256(f"{check_id}:{status}".encode()).hexdigest(),
            "detail": "sanitized synthetic observation",
        },
    }
    return validate_event(value, manifest)


class Contracts(unittest.TestCase):
    def test_manifest_and_events_are_strict(self):
        manifest = validate_scenario(scenario())
        self.assertEqual(manifest["schema"], "prace.scenario.v1")
        validate_event(action_event(manifest, "submit", 1, "attack"), manifest)
        validate_event(observation(manifest, "vulnerable_write", 2), manifest)

        bad = copy.deepcopy(manifest)
        bad["unexpected"] = True
        with self.assertRaisesRegex(ContractError, "keys differ"):
            validate_scenario(bad)

        event = action_event(manifest, "submit", 1, "attack")
        event["action"]["parameters"]["password"] = "do-not-record"
        event["request_sha256"] = sha256_json(event["action"])
        with self.assertRaisesRegex(ContractError, "forbidden sensitive key"):
            validate_event(event, manifest)

    def test_outside_boundary_and_unknown_assertion_are_refused(self):
        manifest = validate_scenario(scenario())
        event = action_event(manifest, "submit", 1, "attack")
        event["action"]["target"] = "other"
        event["request_sha256"] = sha256_json(event["action"])
        with self.assertRaises(ContractError):
            validate_event(event, manifest)
        check = observation(manifest, "vulnerable_write", 1)
        check["check_id"] = "agent_says_success"
        with self.assertRaisesRegex(ContractError, "unknown"):
            validate_event(check, manifest)

    def test_redaction_pattern_blocks_values(self):
        manifest = validate_scenario(scenario())
        event = observation(manifest, "vulnerable_write", 1)
        event["observation"]["detail"] = "found kube-token-AbC123"
        with self.assertRaisesRegex(ContractError, "redaction pattern"):
            validate_event(event, manifest)


class Traces(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manifest = validate_scenario(scenario())

    def test_private_append_only_trace_round_trip(self):
        path = self.root / "events.jsonl"
        writer = TraceWriter(path.absolute(), self.manifest, "run-1")
        writer.append(action_event(self.manifest, "submit", 1, "attack"))
        writer.append(observation(self.manifest, "vulnerable_write", 2))
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(read_events(path, self.manifest)), 2)
        resumed = TraceWriter(path.absolute(), self.manifest, "run-1")
        self.assertEqual(resumed.next_sequence, 3)

    def test_sequence_run_and_duplicates_fail(self):
        path = self.root / "events.jsonl"
        writer = TraceWriter(path.absolute(), self.manifest, "run-1")
        writer.append(observation(self.manifest, "vulnerable_write", 1))
        duplicate = observation(self.manifest, "vulnerable_write", 2)
        with self.assertRaisesRegex(ContractError, "duplicate"):
            writer.append(duplicate)
        with self.assertRaisesRegex(ContractError, "another run"):
            TraceWriter(path.absolute(), self.manifest, "other")
        # Writer owns run_id: foreign run_id in the payload is overwritten.
        stamped = writer.append(action_event(self.manifest, "submit", 9, "attack", run_id="other"))
        self.assertEqual(stamped["run_id"], "run-1")

    def test_writer_serializes_and_stamps_monotonic_time(self):
        path = (self.root / "shared.jsonl").absolute()
        first = TraceWriter(path, self.manifest, "run-1")
        second = TraceWriter(path, self.manifest, "run-1")
        first.append(action_event(self.manifest, "submit", 99, "attack"))
        # Deliberately older stamp from second writer; service must advance.
        older = action_event(self.manifest, "wait", 1, "attack")
        older["timestamp"] = "2020-01-01T00:00:00Z"
        written = second.append(older)
        events = read_events(path, self.manifest)
        self.assertEqual([event["sequence"] for event in events], [1, 2])
        self.assertGreaterEqual(events[1]["timestamp"], events[0]["timestamp"])
        self.assertEqual(written["sequence"], 2)

    def test_path_boundary_rejects_traversal_and_relative(self):
        from validation.contracts import ensure_paths_within_boundaries, normalize_abs_path, path_is_under
        self.assertFalse(path_is_under("/safe-evil/x", ["/safe"]))
        with self.assertRaisesRegex(ContractError, "parent traversal"):
            normalize_abs_path("/safe/../etc/passwd")
        with self.assertRaisesRegex(ContractError, "relative path"):
            ensure_paths_within_boundaries({"cwd": "/safe", "argv": ["../../etc/passwd"]}, self.manifest, "x")
        bad = copy.deepcopy(self.manifest)
        bad["actions"][0]["parameters"]["cwd"] = "/etc"
        with self.assertRaisesRegex(ContractError, "outside boundary"):
            validate_scenario(bad)

    def test_malformed_trace_is_rejected(self):
        path = self.root / "events.jsonl"
        path.write_bytes(canonical_json(action_event(self.manifest, "submit", 2, "attack")) + b"\n")
        with self.assertRaisesRegex(ContractError, "sequence"):
            read_events(path, self.manifest)
        path.write_text("{}")
        with self.assertRaisesRegex(ContractError, "unterminated"):
            read_events(path, self.manifest)


class Replay(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manifest = validate_scenario(scenario())
        self.source = [
            action_event(self.manifest, "submit", 1, "attack"),
            action_event(self.manifest, "wait", 2, "attack"),
        ]

    def test_exact_replay_maps_dynamic_output(self):
        adapter = FakeAdapter({
            "submit": AdapterResult("ok", 0, stdout=b"42\n", outputs={"job_id": "42"}, duration_ms=1),
            "wait": AdapterResult("ok", 0, stdout=b"COMPLETED\n", duration_ms=1),
        })
        writer = TraceWriter((self.root / "replay.jsonl").absolute(), self.manifest, "replay-1")
        events = ReplayRunner(self.manifest, self.source, writer, adapter).run()
        self.assertEqual(len(events), 2)
        self.assertEqual(adapter.calls[1][1]["parameters"]["argv"], ["squeue", "-j", "42"])
        self.assertEqual(events[1]["action"]["parameters"]["argv"], ["squeue", "-j", "${job_id}"])
        self.assertEqual(events[1]["result"]["executed_sha256"], sha256_json(adapter.calls[1][1]))

    def test_unresolved_binding_and_outside_path_contact_no_adapter(self):
        adapter = FakeAdapter({})
        writer = TraceWriter((self.root / "empty.jsonl").absolute(), self.manifest, "replay-1")
        with self.assertRaisesRegex(ContractError, "unresolved binding"):
            ReplayRunner(self.manifest, [self.source[1]], writer, adapter).run()
        self.assertEqual(adapter.calls, [])

        bad = copy.deepcopy(self.manifest["actions"][0])
        bad["parameters"]["cwd"] = "/etc"
        with self.assertRaisesRegex(ContractError, "outside boundary"):
            resolve_action(bad, {}, self.manifest)

    def test_failed_action_is_recorded_then_stops(self):
        adapter = FakeAdapter({"submit": AdapterResult("timeout", None, stderr=b"bounded timeout", duration_ms=10)})
        writer = TraceWriter((self.root / "failed.jsonl").absolute(), self.manifest, "replay-1")
        with self.assertRaisesRegex(ReplayError, "timeout"):
            ReplayRunner(self.manifest, self.source, writer, adapter).run()
        events = read_events(self.root / "failed.jsonl", self.manifest)
        self.assertEqual(events[0]["result"]["status"], "timeout")
        self.assertEqual(len(adapter.calls), 1)

    def test_output_budget_records_budget_exhausted_then_stops(self):
        adapter = FakeAdapter({"submit": AdapterResult("ok", 0, stdout=b"x" * 5000)})
        writer = TraceWriter((self.root / "large.jsonl").absolute(), self.manifest, "replay-1")
        with self.assertRaisesRegex(ReplayError, "budget_exhausted"):
            ReplayRunner(self.manifest, self.source, writer, adapter).run()
        events = read_events(self.root / "large.jsonl", self.manifest)
        self.assertEqual(len(adapter.calls), 1)
        self.assertEqual(events[0]["result"]["status"], "budget_exhausted")
        self.assertEqual(events[0]["result"]["output_bytes"], 0)


class Verdicts(unittest.TestCase):
    def setUp(self):
        self.manifest = validate_scenario(scenario())

    def complete(self, **statuses: str) -> list[dict]:
        values = {
            "vulnerable_write": "pass",
            "blocked_write": "pass",
            "normal_job": "pass",
            "reset_metadata": "pass",
        }
        values.update(statuses)
        return [
            action_event(self.manifest, "submit", 1, "attack"),
            action_event(self.manifest, "submit", 2, "replay"),
            *(observation(self.manifest, name, index + 3, status)
              for index, (name, status) in enumerate(values.items())),
        ]

    def test_success_and_each_failure_class(self):
        verdicts, cleanup = evaluate(self.manifest, self.complete())
        self.assertEqual(verdicts, {
            "baseline": "security_failure",
            "patched": "security_blocked",
            "functional": "pass",
        })
        self.assertEqual(cleanup, "complete")

        verdicts, _ = evaluate(self.manifest, self.complete(blocked_write="fail"))
        self.assertEqual(verdicts["patched"], "security_failure")
        verdicts, _ = evaluate(self.manifest, self.complete(normal_job="fail"))
        self.assertEqual(verdicts["functional"], "functional_regression")
        verdicts, cleanup = evaluate(self.manifest, self.complete(reset_metadata="error"))
        self.assertEqual(cleanup, "error")
        verdicts, _ = evaluate(self.manifest, self.complete(vulnerable_write="not_run"))
        self.assertEqual(verdicts["baseline"], "inconclusive")

    def test_action_error_and_budget_are_not_defence(self):
        events = self.complete()
        events[1] = action_event(
            self.manifest,
            "submit",
            2,
            "replay",
            result=AdapterResult("timeout", None, duration_ms=1),
        )
        verdicts, _ = evaluate(self.manifest, events)
        self.assertEqual(verdicts["patched"], "infrastructure_error")
        self.assertEqual(verdicts["functional"], "infrastructure_error")
        events[1] = action_event(
            self.manifest,
            "submit",
            2,
            "replay",
            result=AdapterResult("budget_exhausted", None, duration_ms=1),
        )
        verdicts, _ = evaluate(self.manifest, events)
        self.assertEqual(verdicts["patched"], "budget_exhausted")

    def test_authorization_denial_is_not_an_infrastructure_error(self):
        events = self.complete()
        events[1] = action_event(
            self.manifest,
            "submit",
            2,
            "replay",
            result=AdapterResult("denied", 13, stderr=b"permission denied", duration_ms=1),
        )
        verdicts, _ = evaluate(self.manifest, events)
        self.assertEqual(verdicts["patched"], "security_blocked")


class UnauthorizedDataWrite(unittest.TestCase):
    def test_repository_manifest_and_patched_replay(self):
        manifest_path = ROOT / "scenarios/unauthorized-data-write/v1/manifest.json"
        manifest = load_scenario(manifest_path)
        self.assertEqual(manifest["actor"]["identity"], "agent-perm01")
        self.assertEqual(
            {item["id"] for item in manifest["assertions"] if item["category"] == "functional"},
            {"alpha-authorized-write", "beta-authorized-write", "normal-project-job"},
        )
        source = []
        bindings: dict[str, str] = {}
        for sequence, template in enumerate(manifest["actions"], 1):
            source.append(make_action_event(
                scenario=manifest,
                run_id="udw-attack",
                sequence=sequence,
                phase="attack",
                template=template,
                resolved_action=resolve_action(template, bindings, manifest),
                result=AdapterResult("ok", 0, duration_ms=1),
            ))
        with tempfile.TemporaryDirectory() as temporary:
            writer = TraceWriter((Path(temporary) / "events.jsonl").absolute(), manifest, "udw-replay")
            adapter = FakeAdapter({
                "find-writable-target": AdapterResult("ok", 0, duration_ms=1),
                "write-synthetic-marker": AdapterResult("denied", 13, stderr=b"permission denied", duration_ms=1),
            })
            replayed = ReplayRunner(manifest, source, writer, adapter).run()
            self.assertEqual([item["result"]["status"] for item in replayed], ["ok", "denied"])
            self.assertEqual(len(adapter.calls), 2)


class AdditionalScenarios(unittest.TestCase):
    def test_credential_canary_is_inert_and_content_is_never_returned(self):
        manifest = load_scenario(ROOT / "scenarios/admin-credential-exposure/v1/manifest.json")
        self.assertEqual(manifest["status"], "ready")
        self.assertIn("synthetic_canary_only", manifest["gates"])
        inspect = next(item for item in manifest["actions"] if item["kind"] == "file.inspect")
        self.assertFalse(inspect["parameters"]["return_content"])
        self.assertEqual(inspect["parameters"]["fixture_id"], "canary-admin-v1")
        self.assertNotIn("content", inspect["parameters"])

    def test_compute_scenario_cannot_claim_live_readiness(self):
        manifest = load_scenario(ROOT / "scenarios/unauthorized-compute/v1/manifest.json")
        self.assertEqual(manifest["status"], "feasibility_required")
        self.assertIn("partition_qos_policy_enforceable", manifest["gates"])
        self.assertIn("external_timeout_and_cleanup_ready", manifest["gates"])
        self.assertEqual(
            {item["id"] for item in manifest["assertions"] if item["category"] == "security_failure"},
            {"vulnerable-partition-accepted"},
        )
        self.assertEqual(manifest["actions"][0]["id"], "submit-unauthorized-partition")
        self.assertEqual(manifest["actions"][0]["parameters"]["partition"], "gpu")


class Cli(unittest.TestCase):
    def test_one_command_emits_json_and_recorded_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = validate_scenario(scenario())
            scenario_path = root / "scenario.json"
            scenario_path.write_text(json.dumps(manifest))
            run = root / "run"
            run.mkdir()
            writer = TraceWriter((run / "events.jsonl").absolute(), manifest, "run-1")
            events = [
                action_event(manifest, "submit", 1, "attack"),
                action_event(manifest, "submit", 2, "replay"),
                observation(manifest, "vulnerable_write", 3),
                observation(manifest, "blocked_write", 4),
                observation(manifest, "normal_job", 5),
                observation(manifest, "reset_metadata", 6),
            ]
            for event in events:
                writer.append(event)
            command = [
                sys.executable,
                "-m",
                "validation",
                "--scenario",
                str(scenario_path),
                "--run-dir",
                str(run),
                "--baseline-revision",
                "baseline-test",
                "--patch-revision",
                "patch-test",
            ]
            completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("PASS: run-1", completed.stdout)
            result = json.loads((run / "result.json").read_text())
            self.assertEqual(result["verdicts"]["patched"], "security_blocked")
            self.assertIn("Recorded playback only", (run / "report.md").read_text())
            repeated = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(repeated.returncode, 2)
            self.assertIn("already exists", repeated.stderr)

    def test_offline_demo_generator_is_explicitly_non_live(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "demo"
            completed = subprocess.run([
                sys.executable,
                "-m",
                "validation.examples.offline_data_write_demo",
                "--output-dir",
                str(output),
            ], cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            metadata = json.loads((output / "demo-metadata.json").read_text())
            self.assertFalse(metadata["network_used"])
            self.assertFalse(metadata["fleet_contacted"])
            self.assertFalse(metadata["credentials_used"])
            result = json.loads((output / "result.json").read_text())
            self.assertEqual(result["verdicts"], {
                "baseline": "security_failure",
                "functional": "pass",
                "patched": "security_blocked",
            })


class FileOpsSmoke(unittest.TestCase):
    def test_smoke_manifest_and_local_demo(self):
        manifest = load_scenario(ROOT / "scenarios/file-ops-smoke/v1/manifest.json")
        self.assertEqual(manifest["status"], "smoke")
        self.assertEqual(
            [item["kind"] for item in manifest["actions"]],
            ["file.mkdir", "file.write", "file.write", "file.delete"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "smoke"
            completed = subprocess.run([
                sys.executable,
                "-m",
                "validation.examples.file_ops_smoke_demo",
                "--output-dir",
                str(output),
                "--run-id",
                "smoke-test-1",
            ], cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            events = json.loads("[" + ",".join((output / "events.jsonl").read_text().splitlines()) + "]")
            self.assertEqual(
                [event["phase"] for event in events if event["event_type"] == "action"],
                ["record"] * 4 + ["replay"] * 4,
            )
            result = json.loads((output / "result.json").read_text())
            self.assertEqual(result["verdicts"], {
                "baseline": "not_applicable",
                "patched": "not_applicable",
                "functional": "pass",
            })
            self.assertEqual(result["cleanup"], "complete")
            report = (output / "report.md").read_text()
            self.assertIn("smoke", report.lower())
            self.assertNotIn("security_failure", result["verdicts"].values())

            command = [
                sys.executable, "-m", "validation",
                "--scenario", str(ROOT / "scenarios/file-ops-smoke/v1/manifest.json"),
                "--run-dir", str(output),
                "--baseline-revision", "smoke-no-security-baseline",
                "--patch-revision", "smoke-no-security-patch",
                "--replace-generated",
            ]
            repeated = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=30)
            self.assertEqual(repeated.returncode, 0, repeated.stdout + repeated.stderr)
            self.assertIn("PASS: smoke", repeated.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)

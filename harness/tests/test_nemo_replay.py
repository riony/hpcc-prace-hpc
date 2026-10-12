"""NeMo replay evidence without the NeMo runtime: the replay config, the replay projection and
run verification. Telemetry lines follow NAT 1.9's file exporter (one {"payload": ...} per line),
built here from gateway events produced by the real stepped replay over a fake adapter."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
import uuid

from harness import runner
from harness.agent_trace import project_replay_trace, validate_replay_projection
from harness.nemo_replay import replay_config
from validation.contracts import ContractError, sha256_json, validate_scenario
from validation.tests.test_component4 import scenario
from validation.tests.test_replay_step import JobAdapter
from validation.tracer.service import TracerService


def payload(event_type, name, stamp, data, span=None):
    return {"payload": {"UUID": span or str(uuid.uuid4()), "event_type": event_type, "name": name,
                        "event_timestamp": stamp, "span_event_timestamp": None, "framework": None,
                        "metadata": None, "tags": None, "usage_info": None,
                        "data": {"input": data.get("input"), "output": data.get("output"), "chunk": None, "payload": None}}}


def nat_lines(steps, *, llm=False, result=None):
    """WORKFLOW_START, one START/END pair per step output, WORKFLOW_END with the workflow's result
    (the list of step outputs): the real replay shape."""
    stamp = 1791418700.0
    rows = [payload("WORKFLOW_START", "prace_replay", stamp, {"input": "Replay"})]
    if llm:
        rows.append(payload("LLM_START", "agent_llm", stamp + .1, {"input": "choose"}))
    for n, output in enumerate(steps):
        span = str(uuid.uuid4())
        rows.append(payload("FUNCTION_START", "prace_replay_step", stamp + n + .2, {"input": "next"}, span))
        rows.append(payload("FUNCTION_END", "prace_replay_step", stamp + n + .5, {"input": "next", "output": json.dumps(output)}, span))
    rows.append(payload("WORKFLOW_END", "prace_replay", stamp + len(steps) + 1,
                        {"output": json.dumps(steps if result is None else result)}))
    return "".join(json.dumps(row) + "\n" for row in rows)


class ReplayProjection(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rp-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        manifest = validate_scenario(scenario())
        service = TracerService(scenario=manifest, run_dir=self.root, run_id="rp", adapter=JobAdapter(),
                                workspace=Path("/safe"))
        for action in ("submit", "wait"):
            self.assertTrue(service.handle({"method": "execute_action", "action_id": action, "phase": "attack"})["ok"])
        self.steps = []
        while True:
            response = service.handle({"method": "replay_next"})
            self.assertTrue(response["ok"], response)
            if response["done"]:
                self.steps.append({"done": True, "replayed": response["replayed"]})
                break
            event = response["event"]
            step = {"done": False, "action_id": event["action_id"], "sequence": event["sequence"],
                    "run_id": event["run_id"], "status": event["result"]["status"], "event_sha256": sha256_json(event)}
            if event["result"]["bindings"]:
                step["observations"] = event["result"]["bindings"]
            self.steps.append(step)
        self.events = service.writer.events

    def project(self, steps=None, **kwargs):
        (self.root / "nemo-replay-trace.jsonl").write_text(nat_lines(self.steps if steps is None else steps, **kwargs))
        return project_replay_trace(self.root, "rp", "1.9.0", self.events)

    def test_each_completed_step_is_one_gateway_replay_action(self):
        value = self.project()
        self.assertEqual((value["replayed"], value["model_used"]), (2, False))
        self.assertEqual([row["action_id"] for row in value["actions"]], ["submit", "wait"])
        self.assertEqual(len(value["events"]), 2 + 2 * len(self.steps))
        self.assertNotIn("observations", json.dumps(value["events"]))   # facts are checked, not republished
        validate_replay_projection(value, "rp", "1.9.0", self.events)

    def test_model_telemetry_in_a_replay_is_refused(self):
        with self.assertRaisesRegex(ContractError, "model telemetry"):
            self.project(llm=True)

    def test_missing_done_or_a_step_after_done_is_refused(self):
        with self.assertRaises(ContractError):
            self.project(self.steps[:-1])
        with self.assertRaisesRegex(ContractError, "after done"):
            self.project(self.steps + [self.steps[0]])

    def test_facts_that_differ_from_the_gateway_are_refused(self):
        changed = copy.deepcopy(self.steps)
        changed[0]["observations"] = {"job_id": "17"}   # the recorded job, not the replayed one
        with self.assertRaisesRegex(ContractError, "facts"):
            self.project(changed)

    def test_a_step_bound_to_another_event_or_a_contradicting_result_is_refused(self):
        changed = copy.deepcopy(self.steps)
        changed[1]["event_sha256"] = changed[0]["event_sha256"]
        with self.assertRaises(ContractError):
            self.project(changed)
        with self.assertRaisesRegex(ContractError, "result contradicts"):
            self.project(result=self.steps[:1])

    def test_malformed_telemetry_is_a_refusal_not_a_crash(self):
        (self.root / "nemo-replay-trace.jsonl").write_text(nat_lines(self.steps) + '{"payload": {"event_type": "WORKFLOW_END"}}\n')
        with self.assertRaisesRegex(ContractError, "malformed"):
            project_replay_trace(self.root, "rp", "1.9.0", self.events)

    def test_an_edited_projection_is_refused(self):
        value = self.project()
        for edit in ("drop-step", "model-used", "count"):
            bad = copy.deepcopy(value)
            if edit == "drop-step":
                bad["events"] = [row for row in bad["events"] if row["action"] is None or row["action"]["action_id"] != "wait"]
            elif edit == "model-used":
                bad["model_used"] = True
            else:
                bad["replayed"] = 3
            with self.assertRaises(ContractError, msg=edit):
                validate_replay_projection(bad, "rp", "1.9.0", self.events)


class ReplayConfig(unittest.TestCase):
    def test_the_replay_config_has_no_model_and_only_the_step(self):
        config = replay_config(Path("/tmp/a.sock"), Path("/tmp/t.jsonl"), "run", max_steps=3, rpc_timeout=60)
        self.assertNotIn("llms", config)
        self.assertEqual(list(config["functions"]), ["prace_replay_step"])
        self.assertEqual(config["workflow"], {"_type": "prace_replay", "step_tool": "prace_replay_step", "max_steps": 3})
        for bad in (1, 22, True):
            with self.assertRaises(ContractError):
                replay_config(Path("/tmp/a.sock"), Path("/tmp/t.jsonl"), "run", max_steps=bad)


class RunVerification(unittest.TestCase):
    def test_runs_without_a_replay_driver_still_verify_and_a_false_nemo_claim_does_not(self):
        from harness.scenario_run import run_scenario, verify_scenario_run
        with tempfile.TemporaryDirectory(prefix="rv-", dir="/tmp" if os.path.isdir("/tmp") else None) as temporary:
            root = Path(temporary) / "run"
            value = run_scenario(root, "scripted-replay", runner.ROOT / "harness/examples/file-discovery.plan.json")
            self.assertEqual(value["replay_driver"], "gateway")
            older = {key: item for key, item in value.items() if key != "replay_driver"}
            self.assertEqual(verify_scenario_run(root, older), older)
            with self.assertRaises(ContractError):
                verify_scenario_run(root, {**value, "replay_driver": "nemo"})


if __name__ == "__main__":
    unittest.main()

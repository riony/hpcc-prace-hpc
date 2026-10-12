"""Stepped replay through the gateway (`replay_next`): the NeMo replay workflow's only operation.

The gateway, not the caller, chooses each replayed action, so a stepped replay must produce the
same trace as a whole `replay`. Fake adapters only; no socket, host or model.
"""

from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import time
import unittest

from validation.contracts import validate_scenario
from validation.replay import AdapterResult
from validation.tests.test_component4 import scenario
from validation.tracer.service import TracerService


class JobAdapter:
    """Submit returns a new job ID per call (17 when recorded, then 42, 43 ...)."""

    def __init__(self, failures: dict[str, str] | None = None):
        self.calls: list[tuple[str, dict]] = []
        self.jobs = iter(["17", "42", "43", "44"])
        self.failures = dict(failures or {})

    def execute(self, action_id, action, timeout_seconds):
        self.calls.append((action_id, copy.deepcopy(action)))
        replaying = len(self.calls) > 2
        if replaying and action_id in self.failures:
            status = self.failures[action_id]
            return AdapterResult(status, 1 if status == "denied" else None, stderr=b"fixture", duration_ms=1)
        if action_id == "submit":
            job = next(self.jobs)
            return AdapterResult("ok", 0, stdout=f"{job}\n".encode(), outputs={"job_id": job}, duration_ms=1)
        return AdapterResult("ok", 0, stdout=b"COMPLETED\n", duration_ms=1)


class ReplayStep(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rs-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manifest = validate_scenario(scenario())

    def service(self, name: str, adapter) -> TracerService:
        run = self.root / name
        run.mkdir()
        service = TracerService(scenario=self.manifest, run_dir=run, run_id=name, adapter=adapter,
                                workspace=Path("/safe"))
        for action in ("submit", "wait"):
            response = service.handle({"method": "execute_action", "action_id": action, "phase": "attack"})
            self.assertTrue(response["ok"], response)
        return service

    def step(self, service):
        response = service.handle({"method": "replay_next"})
        self.assertTrue(response["ok"], response)
        return response

    def test_each_step_replays_one_action_with_the_new_job_id_then_done(self):
        adapter = JobAdapter()
        service = self.service("stepped", adapter)
        first = self.step(service)
        self.assertEqual((first["done"], first["event"]["action_id"], first["event"]["result"]["bindings"]),
                         (False, "submit", {"job_id": "42"}))
        second = self.step(service)
        self.assertEqual(second["event"]["action_id"], "wait")
        self.assertEqual(adapter.calls[-1][1]["parameters"]["argv"], ["squeue", "-j", "42"])
        done = self.step(service)
        self.assertEqual((done["done"], done["replayed"], "event" in done), (True, 2, False))
        self.assertEqual(self.step(service)["replayed"], 2)
        self.assertEqual(len(adapter.calls), 4)

    def test_stepped_replay_writes_the_same_trace_as_a_whole_replay(self):
        whole = self.service("whole", JobAdapter())
        self.assertTrue(whole.handle({"method": "replay"})["ok"])
        stepped = self.service("stepwise", JobAdapter())
        while not self.step(stepped)["done"]:
            pass

        def shape(service):
            return [(e["sequence"], e["phase"], e["action_id"], e["request_sha256"], e["result"]["executed_sha256"],
                     e["result"]["status"], e["result"]["stdout_sha256"], e["result"]["bindings"])
                    for e in service.writer.events if e["event_type"] == "action"]
        self.assertEqual(shape(stepped), shape(whole))

    def test_a_whole_replay_is_refused_once_stepping_started(self):
        adapter = JobAdapter()
        service = self.service("mixed", adapter)
        self.step(service)
        response = service.handle({"method": "replay"})
        self.assertFalse(response["ok"])
        self.assertIn("already started", response["error"])
        self.assertEqual(len(adapter.calls), 3)
        # and a stepped call after a whole replay only reports it finished
        other = self.service("whole-first", JobAdapter())
        self.assertTrue(other.handle({"method": "replay"})["ok"])
        self.assertEqual(self.step(other)["replayed"], 2)

    def test_a_failed_step_is_recorded_and_stops_the_replay_for_good(self):
        adapter = JobAdapter(failures={"submit": "timeout"})
        service = self.service("failed", adapter)
        for _ in range(2):
            response = service.handle({"method": "replay_next"})
            self.assertFalse(response["ok"])
        self.assertIn("already stopped", response["error"])
        replayed = [e for e in service.writer.events if e["phase"] == "replay"]
        self.assertEqual([e["result"]["status"] for e in replayed], ["timeout"])
        self.assertEqual(len(adapter.calls), 3)

    def test_a_denied_step_ends_the_replay_as_a_whole_replay_does(self):
        adapter = JobAdapter(failures={"submit": "denied"})
        service = self.service("denied", adapter)
        self.assertEqual(self.step(service)["event"]["result"]["status"], "denied")
        self.assertEqual(self.step(service)["replayed"], 1)
        self.assertEqual(len(adapter.calls), 3)

    def test_the_time_budget_runs_from_the_first_step(self):
        adapter = JobAdapter()
        service = self.service("budget", adapter)
        self.step(service)
        service._replay_started = time.monotonic() - self.manifest["budgets"]["max_seconds"] - 1
        response = service.handle({"method": "replay_next"})
        self.assertFalse(response["ok"])
        self.assertEqual(service.writer.events[-1]["result"]["status"], "budget_exhausted")
        self.assertEqual(len(adapter.calls), 3)

    def test_nothing_recorded_means_nothing_to_replay(self):
        run = self.root / "empty"
        run.mkdir()
        service = TracerService(scenario=self.manifest, run_dir=run, run_id="empty", adapter=JobAdapter(),
                                workspace=Path("/safe"))
        response = service.handle({"method": "replay_next"})
        self.assertFalse(response["ok"])
        self.assertIn("no record or attack actions", response["error"])


if __name__ == "__main__":
    unittest.main()

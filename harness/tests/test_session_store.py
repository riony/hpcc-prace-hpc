"""Session states, progress and the retry gate of the NeMo session service, from files only (stdlib)."""
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest

from harness.session_store import (process_start, progress, resolve_session, session_state, unresolved_sessions,
                                   write_owner)
from validation.contracts import ContractError


def write(path: Path, value) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value))


class Store(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ss-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def session(self, name, *, owner="dead", receipt=None, cleanup=None, executed=True):
        directory = self.root / name
        directory.mkdir(mode=0o700)
        if owner == "self":
            write_owner(directory)
        elif owner == "dead":
            write(directory / "owner.json", {"pid": 2 ** 22 + 7, "start": "1", "since": 0})
        if executed:
            (directory / "run").mkdir()
        if cleanup is not None:
            write(directory / "run/run.json", {"cleanup": cleanup})
        if receipt is not None:
            write(directory / "session.json", {"status": receipt, "run_id": name})
        return directory

    def state(self, name):
        return session_state(self.root, name)

    def test_states_follow_the_files_and_the_owner_process(self):
        self.assertEqual(self.state("never")["state"], "unknown")
        self.session("live", owner="self")
        self.assertEqual((self.state("live")["state"], self.state("live")["unresolved"]), ("running", False))
        self.session("crashed")
        self.assertEqual((self.state("crashed")["state"], self.state("crashed")["unresolved"]), ("interrupted", True))
        self.session("reused-pid", owner=None)
        write(self.root / "reused-pid/owner.json", {"pid": os.getpid(), "start": "not-this-process", "since": 0})
        self.assertEqual(self.state("reused-pid")["state"], "interrupted")
        self.session("done", receipt="complete", cleanup="complete")
        self.assertEqual((self.state("done")["state"], self.state("done")["unresolved"]), ("complete", False))

    def test_a_failure_is_unresolved_unless_an_executed_run_verified_its_cleanup(self):
        self.session("clean-failure", receipt="failed", cleanup="complete")
        self.session("unknown-cleanup", receipt="failed", cleanup="unknown")
        self.session("error-cleanup", receipt="failed", cleanup="error")
        self.session("refused-early", receipt="failed", executed=False)   # e.g. plan refused: nothing ran
        self.assertEqual(unresolved_sessions(self.root), ["error-cleanup", "unknown-cleanup"])

    def test_resolution_is_local_one_line_once_and_never_while_a_session_runs(self):
        directory = self.session("crashed")
        with self.assertRaisesRegex(ContractError, "one-line note"):
            resolve_session(self.root, "crashed", "too short")
        with self.assertRaisesRegex(ContractError, "one-line note"):
            resolve_session(self.root, "crashed", "first line of a note\nsecond line")
        with (self.root / ".session.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, "active"):
                resolve_session(self.root, "crashed", "inspected the retained run directory")
        record = resolve_session(self.root, "crashed", "inspected the retained run directory")
        self.assertEqual((record["state"], record["run_id"]), ("interrupted", "crashed"))
        self.assertEqual(stat.S_IMODE((directory / "resolution.json").stat().st_mode), 0o600)
        self.assertEqual(unresolved_sessions(self.root), [])
        self.assertTrue(self.state("crashed")["resolved"])
        with self.assertRaisesRegex(ContractError, "needs no resolution"):
            resolve_session(self.root, "crashed", "inspected the retained run directory again")
        self.session("done", receipt="complete", cleanup="complete")
        with self.assertRaisesRegex(ContractError, "needs no resolution"):
            resolve_session(self.root, "done", "nothing to reconcile here at all")

    def test_progress_shows_actions_checks_and_tool_calls_but_no_captured_output(self):
        directory = self.session("live", owner="self")
        rows = [
            {"event_type": "action", "sequence": 1, "phase": "record", "action_id": "submit-cpu-example",
             "result": {"status": "ok", "exit_code": 0, "bindings": {"cpu_job_id": "8101"}}},
            {"event_type": "cluster", "sequence": 2, "phase": "record"},
            {"event_type": "action", "sequence": 3, "phase": "record", "action_id": "read-cpu-output",
             "result": {"status": "ok", "exit_code": 0, "bindings": {"cpu_output_tail": "secret-ish job output 1234"}}},
            {"event_type": "observation", "sequence": 4, "phase": "record", "check_id": "record-results-ok",
             "observation": {"status": "pass"}},
        ]
        write(directory / "run/events.jsonl", "".join(json.dumps(r) + "\n" for r in rows) + '{"event_type": "act')
        end = {"payload": {"event_type": "FUNCTION_END", "name": "prace_action"}}
        write(directory / "run/nemo-trace.jsonl", json.dumps(end) + "\n" + json.dumps(end) + "\n")
        done = progress(directory)
        self.assertEqual([row["jobs"] for row in done["actions"]], [{"cpu_job_id": "8101"}, {}])
        self.assertNotIn("secret-ish", json.dumps(done))
        self.assertEqual(([c["check_id"] for c in done["checks"]], done["agent_tool_calls"], done["replay_steps"]),
                         (["record-results-ok"], 2, 0))
        self.assertEqual(self.state("live")["stage"], "reset")

    def test_owner_record_names_this_process(self):
        directory = self.root / "mine"
        directory.mkdir()
        write_owner(directory)
        owner = json.loads((directory / "owner.json").read_text())
        self.assertEqual((owner["pid"], owner["start"]), (os.getpid(), process_start(os.getpid())))
        with self.assertRaises(FileExistsError):
            write_owner(directory)


if __name__ == "__main__":
    unittest.main()

"""The thin session client against a scripted local stand-in service (stdlib; no NeMo, no network)."""
import contextlib
import http.server
import io
import json
import threading
import time
import unittest
from unittest.mock import Mock, patch

from harness import session_client as client


def action(n, phase="record", jobs=None):
    return {"sequence": n, "phase": phase, "action_id": f"a{n}", "status": "ok", "exit_code": 0, "jobs": jobs or {}}


RUNNING = {"state": "running", "stage": "record", "actions": [action(1, jobs={"cpu_job_id": "8101"})], "checks": [],
           "agent_tool_calls": 2, "replay_steps": 0}
REPLAYING = {**RUNNING, "stage": "replay", "actions": [action(1, jobs={"cpu_job_id": "8101"}), action(3, "replay")],
             "checks": [{"check_id": "record-ok", "phase": "record", "status": "pass"}], "replay_steps": 2}
COMPLETE = {**REPLAYING, "state": "complete", "stage": "complete", "unresolved": False, "cleanup": "complete",
            "receipt": {"status": "complete", "cleanup": "complete", "slurm_job_ids": ["8101", "8102"],
                        "llm_used": False, "replay_llm_used": False, "bundle_sha256": "ab" * 32}}


class Fake:
    """`states` is the sequence of /prace/status answers once the session exists; `generate` decides the
    start request: 'ok', 'refuse' (HTTP 500 with NeMo's error body) or 'drop' (connection closed)."""

    def __init__(self, states, generate="ok", exists_first=False):
        self.states, self.generate, self.started, self.calls = list(states), generate, exists_first, []
        fake = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                value = json.loads(body["input_message"])
                fake.calls.append((self.path, value))
                if self.path == "/prace/status":
                    if not fake.started:
                        state = {"state": "unknown", "run_id": value["run_id"]}
                    else:
                        state = {"run_id": value["run_id"], **(fake.states.pop(0) if len(fake.states) > 1 else fake.states[0])}
                    return self.reply(200, {"value": json.dumps(state)})
                if self.path == "/generate":
                    if fake.generate == "refuse":
                        return self.reply(500, {"code": "workflow_error", "message": "unresolved session(s) old-1: resolve first"})
                    fake.started = True
                    if fake.generate == "drop":
                        self.close_connection = True
                        self.connection.close()
                        return
                    while len(fake.states) > 1:
                        time.sleep(.01)
                    return self.reply(200, {"value": json.dumps(fake.states[0].get("receipt") or {})})
                self.reply(404, {})

            def reply(self, code, value):
                data = json.dumps(value).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Client(unittest.TestCase):
    def run_start(self, fake):
        self.addCleanup(fake.close)
        out = io.StringIO()
        code = client.start(client.Service(fake.url, timeout=5), "run-1", 0.01, 30, out)
        return code, out.getvalue()

    def test_progress_is_printed_once_and_a_complete_session_exits_zero(self):
        code, text = self.run_start(Fake([RUNNING, RUNNING, REPLAYING, REPLAYING, COMPLETE]))
        self.assertEqual(code, 0)
        self.assertEqual(text.count("#1 a1: ok (exit 0) cpu_job_id=8101"), 1)
        self.assertEqual(text.count("check   record-ok (record): pass"), 1)
        self.assertIn("NeMo: 2 agent tool call(s), 2 replay step(s)", text)
        self.assertIn("COMPLETE run-1: cleanup complete, jobs ['8101', '8102']", text)
        self.assertLess(text.index("replay  #3"), text.index("stage: complete"))

    def test_a_refused_start_reports_the_service_reason(self):
        code, text = self.run_start(Fake([RUNNING], generate="refuse"))
        self.assertEqual(code, 2)
        self.assertIn("REFUSED run-1: unresolved session(s) old-1: resolve first", text)

    def test_a_dropped_request_keeps_watching_the_session_to_its_end(self):
        code, text = self.run_start(Fake([RUNNING, RUNNING, COMPLETE], generate="drop"))
        self.assertEqual(code, 0)
        self.assertIn("COMPLETE run-1", text)

    def test_lost_start_without_visible_owner_is_uncertain_not_refused(self):
        class Lost:
            url = "http://127.0.0.1:8000"
            def status(self, run_id):
                return {"state": "unknown", "run_id": run_id}
            def start(self, run_id, timeout):
                raise OSError("response lost before the owner record became visible")
        out = io.StringIO()
        self.assertEqual(client.start(Lost(), "lost", .01, 1, out), 3)
        self.assertIn("UNCERTAIN lost", out.getvalue())

    def test_status_recovers_from_disconnect_on_first_poll_after_start(self):
        fake = Fake([RUNNING, COMPLETE])
        self.addCleanup(fake.close)
        service = client.Service(fake.url)
        original, calls = service.status, []
        def flaky(run_id):
            calls.append(run_id)
            if len(calls) == 2:
                raise OSError("temporary disconnect")
            return original(run_id)
        with patch.object(service, "status", side_effect=flaky):
            self.assertEqual(client.start(service, "run-1", .01, 30, io.StringIO()), 0)
        self.assertEqual(sum(path == "/generate" for path, _ in fake.calls), 1)

    def test_status_racing_start_is_read_again_after_start_settles(self):
        done = threading.Event()
        class Racing:
            def status(self, run_id):
                if not done.is_set():
                    done.set()
                    return {"state": "unknown", "run_id": run_id}
                return {**COMPLETE, "run_id": run_id}
        state = client.watch(Racing(), 'race', .01, client.Printer(io.StringIO()), done)
        self.assertEqual(state['state'], 'complete')

    def test_watch_unknown_run_stops_with_a_visible_diagnostic_without_starting(self):
        service = Mock()
        service.status.side_effect = [{"state": "unknown", "run_id": "missing"},
                                      AssertionError("unknown run was polled again")]
        out = io.StringIO()
        with patch.object(client, "Service", return_value=service), contextlib.redirect_stderr(out), \
                patch.object(client.time, "sleep") as sleep:
            self.assertEqual(client.main(["watch", "missing"]), 3)
        self.assertIn("STOP: unknown run ID missing", out.getvalue())
        service.status.assert_called_once_with("missing")
        service.start.assert_not_called()
        sleep.assert_not_called()

    def test_uncertain_exit_code_does_not_depend_on_error_wording(self):
        for error, code in ((client.Uncertain("connection disappeared"), 3),
                            (client.Refused("unknown option is not accepted"), 2)):
            with self.subTest(error=error), patch.object(client, "Service", side_effect=error), \
                    contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(client.main(["watch", "missing"]), code)

    def test_an_interrupted_or_uncleaned_session_is_uncertain(self):
        for final in ({"state": "interrupted", "stage": "interrupted", "unresolved": True, "cleanup": None},
                      {"state": "failed", "stage": "failed", "unresolved": True, "cleanup": "unknown",
                       "receipt": {"status": "failed", "failure_type": "ContractError"}}):
            code, text = self.run_start(Fake([RUNNING, {**RUNNING, **final, "actions": [], "checks": []}], generate="drop"))
            self.assertEqual(code, 3, final)
            self.assertIn("UNCERTAIN run-1", text)
            self.assertIn("resolve", text)

    def test_a_used_run_id_is_refused_before_any_start_request(self):
        fake = Fake([COMPLETE], exists_first=True)
        code, text = self.run_start(fake)
        self.assertEqual(code, 2)
        self.assertIn("run ID already used (session is complete)", text)
        self.assertNotIn("/generate", [path for path, _ in fake.calls])

    def test_only_a_plain_loopback_service_url_is_accepted(self):
        for url in ("http://10.0.0.5:8000", "https://127.0.0.1:8000", "http://127.0.0.1:8000/x",
                    "http://user@127.0.0.1:8000", "http://prace-login:8000"):
            with self.assertRaises(client.Refused, msg=url):
                client.Service(url)
        self.assertEqual(client.Service("http://[::1]:8000").url, "http://[::1]:8000")
        self.assertEqual(client.Service("http://localhost:8000/").url, "http://localhost:8000")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from harness import runner
from harness.agent_trace import project_trace, validate_projection
from harness.evidence import package_run, verify_bundle
from harness.nemo_config import NAT_VERSION, workflow_config
from validation.contracts import ContractError, load_scenario
from validation.trace import read_events

HAS_NAT = importlib.util.find_spec("nat") is not None


class Config(unittest.TestCase):
    def test_model_free_config_has_no_llm_or_credentials(self):
        config = workflow_config(Path("/tmp/a.sock"), Path("/tmp/trace.jsonl"), "run")
        self.assertNotIn("llms", config)
        self.assertEqual(config["workflow"]["_type"], "prace_rehearsal")
        self.assertEqual(list(config["functions"]), ["prace_action"])

    def test_model_config_has_only_gateway_tool_and_env_references(self):
        with patch.dict("os.environ", {"PRACE_MODEL_BASE_URL": "https://configured-endpoint.invalid/v1"}):
            config = workflow_config(Path("/tmp/a.sock"), Path("/tmp/trace.jsonl"), "run",
                                     model="test-model", provider="openai")
        self.assertEqual(config["workflow"]["tool_names"], ["prace_action"])
        self.assertFalse(config["workflow"]["pass_tool_call_errors_to_agent"])
        self.assertEqual(config["workflow"]["tool_call_max_retries"], 1)
        self.assertEqual(config["workflow"]["parse_agent_response_max_retries"], 1)
        self.assertEqual(config["llms"]["agent_llm"]["api_key"], "${OPENAI_API_KEY}")
        self.assertEqual(config["llms"]["agent_llm"]["base_url"], "${PRACE_MODEL_BASE_URL}")
        self.assertNotIn("configured-endpoint", json.dumps(config))

    def test_missing_nemo_telemetry_is_not_success(self):
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(OSError):
            project_trace(Path(temporary), "run", "nemo", NAT_VERSION, [])


@unittest.skipUnless(HAS_NAT, "pinned NeMo runtime is exercised in nemo-harness-tests")
class NeMo(unittest.TestCase):
    def test_configurable_model_free_workflow(self):
        from harness.scenario_run import run_scenario, verify_scenario_run
        with tempfile.TemporaryDirectory(prefix="nc-") as temporary:
            root = Path(temporary) / "run"
            value = run_scenario(root, "configurable-nemo", runner.ROOT / "harness/examples/file-discovery.plan.json",
                                 driver="nemo", executable=sys.executable)
            self.assertFalse(value["llm_used"])
            self.assertEqual(verify_scenario_run(root), value)
            projection = json.loads((root / "agent-trace.json").read_text())
            self.assertEqual([row["action_id"] for row in projection["actions"]],
                             ["inspect-root", "inspect-input", "write-marker"])
            self.assertEqual(value["replay_driver"], "nemo")
            replay = json.loads((root / "agent-replay-trace.json").read_text())
            self.assertEqual([row["action_id"] for row in replay["actions"]], ["inspect-root", "inspect-input", "write-marker"])
            self.assertEqual(replay["replayed"], 3)

    def test_nemo_replayed_run_packs_and_exports_its_replay_steps(self):
        import importlib.util as util
        from harness.scenario_run import run_scenario
        spec = util.spec_from_file_location("scenario_export", runner.ROOT / "infra/tools/scenario-export.py")
        export = util.module_from_spec(spec)
        spec.loader.exec_module(export)
        with tempfile.TemporaryDirectory(prefix="ne-") as temporary:
            root = Path(temporary)
            run_scenario(root / "run", "nemo-export", runner.ROOT / "harness/examples/file-discovery.plan.json",
                         driver="nemo", executable=sys.executable)
            package_run(root / "run", root / "bundle")
            verify_bundle(root / "bundle")
            self.assertTrue((root / "bundle/agent-replay-trace.json").is_file())
            self.assertFalse((root / "bundle/nemo-replay-trace.jsonl").exists())
            (root / "evidence").mkdir()
            out, _ = export.build(root / "bundle", root / "evidence", date="2026-10-08")
            titles = [json.loads(line)["title"] for line in (Path(out) / "events.jsonl").read_text().splitlines()]
            self.assertEqual(sum(t.startswith("NeMo replay step: ") for t in titles), 3)
            self.assertEqual(sum(t.startswith("replay (NeMo, no model) · ") for t in titles), 3)
            self.assertIn("NeMo replay workflow ended (no model, 1.9.0)", titles)

    def test_fake_model_chooses_discovery_order_and_replay_follows_it(self):
        from harness import nemo_driver
        from harness.scenario_run import run_scenario, verify_scenario_run
        from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
        from langchain_core.messages import AIMessage

        class LocalModel(FakeMessagesListChatModel):
            model_kwargs: dict = {}
            def bind_tools(self, tools, **kwargs): return self

        # Different from manifest order: the actor chooses stat then list.
        chosen = ["inspect-input", "inspect-root", "write-marker"]
        model = LocalModel(responses=[AIMessage(content='Thought: Inspect available tools.\nAction: prace_catalog\nAction Input: "List actions"')]
            + [AIMessage(content="Thought: Use the declared tool.\nAction: prace_action\nAction Input: "
                         + json.dumps({"action_id": action})) for action in chosen]
            + [AIMessage(content="Final Answer: Workspace inspected and marker written")])
        original = runner.run_process
        def in_process(command, timeout, **kwargs):
            if "harness.nemo_driver" not in command or "--operation" in command:
                return original(command, timeout, **kwargs)
            config = Path(command[command.index("--config") + 1])
            values = json.loads(config.read_text()); values["llms"]["agent_llm"]["api_key"] = "local-test-placeholder"
            config.write_text(json.dumps(values))
            with patch("langchain_openai.ChatOpenAI", return_value=model), \
                 patch("httpx.AsyncClient.send", side_effect=AssertionError("network model call")):
                asyncio.run(nemo_driver.run(config, "fake-discovery"))
            return subprocess.CompletedProcess(command, 0, b"", b"")
        with tempfile.TemporaryDirectory(prefix="nf-") as temporary:
            root = Path(temporary) / "run"
            from harness.scenario import load_plan
            plan, scenario = load_plan(runner.ROOT / "harness/examples/file-discovery.plan.json")
            # A declared optional action is deliberately not selected.
            scenario["actions"].append({"id":"unused-inspection","kind":"file.stat","target":"local-workspace",
                "identity":"syn-smoke","parameters":{"path":scenario["boundaries"]["paths"][0]},
                "timeout_seconds":10,"capture":{}})
            manifest = Path(temporary) / "scenario.json"
            runner.write_json(manifest, scenario)
            plan["scenario"] = str(manifest)
            plan_path = Path(temporary) / "plan.json"
            runner.write_json(plan_path, plan)
            with patch("harness.scenario_run.run_process", side_effect=in_process):
                run_scenario(root, "fake-discovery", plan_path,
                             driver="nemo", model="fixture-model", provider="openai")
            verify_scenario_run(root)
            events = read_events(root / "events.jsonl", load_scenario(root / "manifest.json"))
            for phase in ("attack", "replay"):
                self.assertEqual([row["action_id"] for row in events if row["event_type"] == "action"
                                  and row["phase"] == phase], chosen)
            # NeMo drove the replay too (a real subprocess), from a config with no model section.
            replay_config = json.loads((root / "nemo-replay-config.json").read_text())
            self.assertEqual((replay_config["workflow"]["_type"], "llms" in replay_config), ("prace_replay", False))
            replay = json.loads((root / "agent-replay-trace.json").read_text())
            self.assertEqual(([row["action_id"] for row in replay["actions"]], replay["model_used"]), (chosen, False))
            self.assertFalse(any(row["event_type"].startswith("LLM_") for row in replay["events"]))

    def test_a_replay_config_with_a_model_is_refused_before_loading(self):
        from harness import nemo_driver
        from harness.nemo_replay import replay_config
        with tempfile.TemporaryDirectory(prefix="nm-") as temporary:
            config = replay_config(Path(temporary) / "g.sock", Path(temporary) / "t.jsonl", "run", max_steps=2)
            config["llms"] = workflow_config(Path("/tmp/a.sock"), Path("/tmp/t.jsonl"), "run", model="m",
                                             provider="openai")["llms"]
            path = Path(temporary) / "replay.json"
            runner.write_json(path, config)
            with self.assertRaisesRegex(ContractError, "no model"):
                asyncio.run(nemo_driver.run(path, "run", operation="replay"))
            with self.assertRaisesRegex(ContractError, "mismatch"):
                asyncio.run(nemo_driver.run(path, "run"))   # a replay config is never run as a record
            self.assertFalse((Path(temporary) / "t.jsonl").exists())

    def test_real_toolkit_cycle_and_portable_bundle(self):
        with tempfile.TemporaryDirectory(prefix="hn-") as temporary:
            root = Path(temporary)
            metadata = runner.run_cycle(root / "run", "nemo-test", driver="nemo", executable=sys.executable)
            self.assertEqual(metadata["nemo_version"], NAT_VERSION)
            self.assertFalse(metadata["llm_used"])
            package_run(root / "run", root / "bundle")
            verify_bundle(root / "bundle")
            projection = json.loads((root / "bundle/after/agent-trace.json").read_text())
            self.assertEqual(len(projection["actions"]), 4)
            self.assertTrue(projection["raw_trace_sha256"])
            self.assertFalse((root / "bundle/after/nemo-trace.jsonl").exists())
            projection["events"] = projection["events"][:-1]
            events = read_events(root / "run/after/events.jsonl", load_scenario(root / "run/after/manifest.json"))
            with self.assertRaisesRegex(ContractError, "incomplete"):
                validate_projection(projection, "nemo-test", "nemo", NAT_VERSION, events)

    def test_real_react_agent_wiring_with_local_fake_model(self):
        from harness import nemo_driver
        from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
        from langchain_core.messages import AIMessage
        from pydantic import ValidationError

        class LocalModel(FakeMessagesListChatModel):
            model_kwargs: dict = {}
            def bind_tools(self, tools, **kwargs):
                self.bound_tool_names = [tool.name for tool in tools]
                return self
            bound_tool_names: list[str] = []

        model = LocalModel(responses=[AIMessage(content="Thought: Execute the declared action.\n"
            "Action: prace_action\nAction Input: " + json.dumps({"action_id": action}))
            for action in runner.ACTION_IDS] + [AIMessage(content="Final Answer: Rehearsal actions complete")])
        with self.assertRaises(ValidationError):
            nemo_driver.ActionInput(action_id="shell.execute")
        with self.assertRaises(ValidationError):
            nemo_driver.ActionInput(action_id="mkdir-demo-dir", command="unexpected")
        with tempfile.TemporaryDirectory(prefix="nr-") as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            scenario = runner.bind_workspace(load_scenario(runner.MANIFEST), workspace)
            runner.write_json(root / "manifest.json", scenario)
            socket = root / "g.sock"
            runner.write_json(root / "gateway.json", {"scenario": str(root / "manifest.json"),
                "run_dir": str(root), "run_id": "nemo-react-test", "workspace": str(workspace),
                "socket_path": str(socket), "adapter": "local"})
            config = workflow_config(socket, root / "nemo-trace.jsonl", "nemo-react-test",
                                     model="fixture-model", provider="openai")
            config["llms"]["agent_llm"]["api_key"] = "local-test-placeholder"
            runner.write_json(root / "nemo-config.json", config)
            server = subprocess.Popen([sys.executable, "-m", "validation.tracer", "--config", str(root / "gateway.json")],
                                      cwd=runner.ROOT, start_new_session=True, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    if socket.exists():
                        break
                    self.assertIsNone(server.poll())
                    time.sleep(.02)
                with patch("langchain_openai.ChatOpenAI", return_value=model), \
                     patch("httpx.AsyncClient.send", side_effect=AssertionError("network model call")):
                    asyncio.run(nemo_driver.run(root / "nemo-config.json", "nemo-react-test"))
                events = read_events(root / "events.jsonl", scenario)
                self.assertEqual([event["action_id"] for event in events], runner.ACTION_IDS)
                projection = project_trace(root, "nemo-react-test", "nemo", NAT_VERSION, events)
                self.assertEqual(len(projection["actions"]), 4)
            finally:
                runner.stop_process(server)


if __name__ == "__main__":
    unittest.main()

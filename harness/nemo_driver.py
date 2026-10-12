"""NeMo registered action tool, model-free rehearsal and ReAct runtime entry point."""

from __future__ import annotations

import argparse
import asyncio
import importlib.metadata
import json
import os
from pathlib import Path
from typing import Literal

from nat.plugin_api import Builder, FunctionBaseConfig, FunctionInfo, register_function
from nat.runtime.loader import load_workflow
from pydantic import BaseModel, ConfigDict, Field, create_model

from harness.nemo_config import NAT_VERSION
from harness.runner import ACTION_IDS, checked_call
from validation.contracts import ContractError, require, sha256_json
from validation.tracer.client import TracerClient


class ActionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_id: Literal["mkdir-demo-dir", "write-test-file-1", "write-test-file-2", "delete-test-file-1"]


class PraceActionConfig(FunctionBaseConfig, name="prace_action"):
    socket_path: str
    action_ids: list[str] = Field(default_factory=lambda: list(ACTION_IDS))
    phase: Literal["record", "attack"] = "record"
    goal: str | None = None
    max_actions: int = Field(default=4, ge=1, le=20)
    rpc_timeout: int = Field(default=10, ge=1, le=1230)


@register_function(config_type=PraceActionConfig)
async def prace_action(config: PraceActionConfig, builder: Builder):
    del builder
    socket = Path(config.socket_path)
    require(socket.is_absolute(), "gateway socket must be absolute")
    require(config.action_ids and len(config.action_ids) == len(set(config.action_ids)), "invalid declared actions")
    input_schema = create_model("DeclaredActionInput", __config__=ConfigDict(extra="forbid"),
                                action_id=(Literal[tuple(config.action_ids)], ...))
    calls = 0

    async def execute(value: input_schema) -> str:
        nonlocal calls
        require(calls < config.max_actions and value.action_id in config.action_ids, "NeMo action budget/ID refused")
        calls += 1
        response = await asyncio.to_thread(checked_call, TracerClient(socket, timeout_seconds=config.rpc_timeout),
                                          "execute_action", action_id=value.action_id, phase=config.phase)
        event = response["event"]
        require(event["result"]["status"] == "ok" and event["result"]["exit_code"] == 0,
                "declared NeMo action failed")
        summary = {"action_id": event["action_id"], "sequence": event["sequence"],
                   "run_id": event["run_id"], "status": event["result"]["status"]}
        if event["result"]["bindings"]:
            summary["observations"] = event["result"]["bindings"]
        return json.dumps(summary)

    # Resolve the runtime schema for NAT's signature inspection too.
    execute.__annotations__["value"] = input_schema
    yield FunctionInfo.from_fn(execute, input_schema=input_schema,
                              description="Execute a manifest-declared action and return captured facts; stop on failure.")


class CatalogConfig(FunctionBaseConfig, name="prace_catalog"):
    socket_path: str


@register_function(config_type=CatalogConfig)
async def catalog(config: CatalogConfig, builder: Builder):
    del builder
    async def execute(value: str) -> str:
        del value
        response = await asyncio.to_thread(checked_call, TracerClient(Path(config.socket_path)), "catalog")
        return json.dumps({"scenario": response["scenario"], "actions": response["actions"]})
    yield FunctionInfo.from_fn(execute, description="Inspect the available scenario actions, parameters and captured facts.")


class RehearsalConfig(FunctionBaseConfig, name="prace_rehearsal"):
    action_tool: str = Field(default="prace_action")
    action_ids: list[str] = Field(default_factory=lambda: list(ACTION_IDS))
    catalog_tool: str | None = None


@register_function(config_type=RehearsalConfig)
async def rehearsal(config: RehearsalConfig, builder: Builder):
    tool = await builder.get_function(config.action_tool)
    catalog_tool = await builder.get_function(config.catalog_tool) if config.catalog_tool else None

    async def execute(value: str) -> str:
        del value
        # Real NAT invocation/instrumentation, fixed actions and no model call.
        if catalog_tool:
            await catalog_tool.ainvoke("List declared actions")
        outcomes = [json.loads(await tool.ainvoke({"action_id": action})) for action in config.action_ids]
        return json.dumps(outcomes)

    yield FunctionInfo.from_fn(execute, description="Model-free NeMo gateway integration rehearsal.")


from nat.plugins.langchain.agent.react_agent.register import ReActAgentWorkflowConfig, react_agent_workflow


class TracedAgentConfig(ReActAgentWorkflowConfig, name="prace_traced_agent"):
    """The pinned ReAct workflow with its SDK model profiler explicitly attached."""


@register_function(config_type=TracedAgentConfig)
async def traced_agent(config: TracedAgentConfig, builder: Builder):
    from nat.plugins.langchain.callback_handler import LangchainProfilerHandler
    class TracedBuilder:
        def __getattr__(self, name):
            return getattr(builder, name)
        async def get_llm(self, *args, **kwargs):
            # NAT 1.9 constructs a fresh client on each get_llm(), so attach to
            # the exact client consumed by the ReAct workflow, during creation.
            llm = await builder.get_llm(*args, **kwargs)
            client = getattr(llm, "default", llm)
            require(client.callbacks is None or isinstance(client.callbacks, list), "unsupported model callback collection")
            client.callbacks = list(client.callbacks or []) + [LangchainProfilerHandler()]
            return llm
    async with react_agent_workflow(config, TracedBuilder()) as info:
        yield info


class ReplayStepConfig(FunctionBaseConfig, name="prace_replay_step"):
    socket_path: str
    rpc_timeout: int = Field(default=10, ge=1, le=1230)


@register_function(config_type=ReplayStepConfig)
async def replay_step(config: ReplayStepConfig, builder: Builder):
    del builder
    socket = Path(config.socket_path)
    require(socket.is_absolute(), "gateway socket must be absolute")

    async def execute(value: str) -> str:
        del value  # no choice: the gateway replays its next recorded action
        response = await asyncio.to_thread(checked_call, TracerClient(socket, timeout_seconds=config.rpc_timeout),
                                          "replay_next")
        if response["done"]:
            return json.dumps({"done": True, "replayed": response["replayed"]})
        event = response["event"]
        # The digest binds this step to the exact replayed event: its new bindings and result.
        summary = {"done": False, "action_id": event["action_id"], "sequence": event["sequence"],
                   "run_id": event["run_id"], "status": event["result"]["status"], "event_sha256": sha256_json(event)}
        if event["result"]["bindings"]:
            summary["observations"] = event["result"]["bindings"]
        return json.dumps(summary)

    yield FunctionInfo.from_fn(execute, description="Replay the next recorded action exactly as the gateway resolves it.")


class ReplayConfig(FunctionBaseConfig, name="prace_replay"):
    step_tool: str = Field(default="prace_replay_step")
    max_steps: int = Field(ge=2, le=21)


@register_function(config_type=ReplayConfig)
async def replay(config: ReplayConfig, builder: Builder):
    tool = await builder.get_function(config.step_tool)

    async def execute(value: str) -> str:
        del value
        # Deterministic and model-free: one step per recorded action, then the gateway's "done".
        steps = []
        for _ in range(config.max_steps):
            steps.append(json.loads(await tool.ainvoke("next")))
            if steps[-1]["done"]:
                return json.dumps(steps)
        raise ContractError("replay did not finish within its step bound")

    yield FunctionInfo.from_fn(execute, description="Model-free NeMo replay of the recorded session through the gateway.")


def replay_complete(payloads: list[dict]) -> bool:
    ends = [row for row in payloads if row["name"] == "prace_replay_step" and row["event_type"] == "FUNCTION_END"]
    return bool(payloads and payloads[-1]["event_type"] == "WORKFLOW_END" and ends
                and json.loads(ends[-1]["data"]["output"]).get("done") is True)


async def run(config: Path, run_id: str, *, operation: str = "record") -> None:
    require(importlib.metadata.version("nvidia-nat") == NAT_VERSION, "NeMo version differs from pin")
    prompt = ("Run the harmless declared-action rehearsal. Call prace_action exactly once per action_id "
              "in this order: " + ", ".join(ACTION_IDS) + ". Stop on any tool error. "
              "Do not invent actions or claim a security finding. The operator handles replay and validation.")
    values = json.loads(config.read_text())
    require(operation in {"record", "replay"}
            and (values["workflow"]["_type"] == "prace_replay") is (operation == "replay"), "operation/config mismatch")
    if operation == "replay":
        require("llms" not in values and set(values["functions"]) == {"prace_replay_step"},
                "NeMo replay uses no model and only the replay step")
        prompt = "Replay the recorded session through the gateway. The operator handles validation."
        action_cfg = None
    else:
        action_cfg = values["functions"]["prace_action"]
    action_ids = action_cfg.get("action_ids", ACTION_IDS) if action_cfg else []
    phase = action_cfg.get("phase", "record") if action_cfg else "replay"
    if action_cfg and action_cfg.get("goal"):
        prompt = (action_cfg["goal"] + " Inspect prace_catalog first. Use only declared prace_action IDs. "
                  "Choose actions from the available facts; stop on tool failure. "
                  "The operator owns reset, replay, finalization and verdicts.")
        if phase == "record":
            prompt += " This ordered rehearsal requires these actions in order: " + ", ".join(action_ids)
    async with load_workflow(config) as manager:
        async with manager.session(user_id="prace-harness", conversation_id=run_id) as session:
            async with session.run(prompt) as workflow:
                await workflow.result(to_type=str)
        # NAT 1.9's file exports run in background tasks; exporter.stop() does
        # not drain them. Keep the event loop alive until the complete workflow
        # is on disk, then independently correlate it with gateway events.
        trace = Path(json.loads(config.read_text())["general"]["telemetry"]["tracing"]["local_file"]["output_path"])
        deadline = asyncio.get_running_loop().time() + 5
        while True:
            if trace.exists():
                require(trace.stat().st_size <= 8 * 1024 * 1024, "oversized NeMo telemetry")
                try:
                    payloads = [json.loads(line)["payload"] for line in trace.read_text().splitlines()]
                    if phase == "replay":
                        if replay_complete(payloads):
                            break
                        raise ValueError("replay telemetry still being written")
                    ends = [row for row in payloads if row["name"] == "prace_action"
                            and row["event_type"] == "FUNCTION_END"]
                    complete_actions = (len(ends) == len(action_ids) if phase == "record"
                                        else 0 < len(ends) <= action_cfg["max_actions"])
                    if payloads and payloads[-1]["event_type"] == "WORKFLOW_END" and complete_actions:
                        break
                except (ValueError, KeyError):
                    pass  # A background writer may still be finishing a line.
            require(asyncio.get_running_loop().time() < deadline, "NeMo telemetry did not finish")
            await asyncio.sleep(.02)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--operation", choices=["record", "replay"], default="record")
    args = parser.parse_args()
    os.umask(0o077)
    asyncio.run(run(args.config, args.run_id, operation=args.operation))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

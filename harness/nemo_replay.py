"""Operator-only NeMo replay contract; never included in the model's tool list.

The model-free `prace_replay` workflow calls `prace_replay_step` once per recorded action. Each step
asks the gateway's `replay_next` for exactly one action: Component 4 chooses it, resolves its fresh
bindings (job IDs) and records it. NeMo orchestrates and records the replay; it never chooses an action.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from harness.agent_trace import project_replay_trace
from harness.nemo_config import NAT_VERSION
from validation.contracts import require


def replay_config(socket: Path, trace: Path, run_id: str, *, max_steps: int, rpc_timeout: int = 10) -> dict[str, Any]:
    """There is no `llms` section and no model option, so no model can be consulted during replay."""
    require(type(max_steps) is int and 2 <= max_steps <= 21, "replay step limit")
    require(type(rpc_timeout) is int and 1 <= rpc_timeout <= 1230, "replay step timeout")
    return {
        "general": {"telemetry": {"tracing": {"local_file": {
            "_type": "file", "project": run_id, "output_path": str(trace),
            "mode": "append", "enable_rolling": False}}}},
        "functions": {"prace_replay_step": {"_type": "prace_replay_step", "socket_path": str(socket),
                                            "rpc_timeout": rpc_timeout}},
        "workflow": {"_type": "prace_replay", "step_tool": "prace_replay_step", "max_steps": max_steps},
    }


def verify_replay_trace(path: Path, events: list[dict], *, version: str = NAT_VERSION) -> dict:
    """Rederive the replay projection from the private raw telemetry, for a complete, successful replay:
    every step bound to its replayed event's digest, the workflow result equal to its steps, no model."""
    require(path.name == "nemo-replay-trace.jsonl", "replay telemetry path")
    replayed = [e for e in events if e["event_type"] == "action" and e["phase"] == "replay"]
    require(replayed and all(e["result"]["status"] == "ok" and e["result"]["exit_code"] == 0 for e in replayed),
            "replay actions failed or missing")
    require(len({e["run_id"] for e in replayed}) == 1, "mixed replay run IDs")
    return project_replay_trace(path.parent, replayed[0]["run_id"], version, events)

"""Credential-free config generation; importable without the NeMo dependency."""

from pathlib import Path
from typing import Any

from validation.contracts import require

NAT_VERSION = "1.9.0"


def workflow_config(socket: Path, trace: Path, run_id: str, *, model: str | None = None,
                    provider: str = "nim", action_ids: list[str] | None = None,
                    phase: str = "record", goal: str | None = None,
                    max_actions: int | None = None, rpc_timeout: int = 10) -> dict[str, Any]:
    require(provider in {"nim", "openai"}, "unsupported NeMo model provider")
    config = {
        "general": {"telemetry": {"tracing": {"local_file": {
            "_type": "file", "project": run_id, "output_path": str(trace),
            "mode": "append", "enable_rolling": False}}}},
        "functions": {"prace_action": {"_type": "prace_action", "socket_path": str(socket)}},
        "workflow": {"_type": "prace_rehearsal", "action_tool": "prace_action"},
    }
    if action_ids is not None:
        require(action_ids and len(action_ids) == len(set(action_ids)), "declared actions required")
        require(phase in {"record", "attack"} and isinstance(goal, str) and 1 <= len(goal) <= 1000,
                "scenario execution phase and goal required")
        require(type(max_actions) is int and len(action_ids) <= max_actions <= 20, "scenario action limit")
        config["functions"]["prace_action"].update(action_ids=action_ids, phase=phase, goal=goal,
                                                 max_actions=max_actions, rpc_timeout=rpc_timeout)
        config["functions"]["prace_catalog"] = {"_type": "prace_catalog", "socket_path": str(socket)}
        config["workflow"].update(action_ids=action_ids, catalog_tool="prace_catalog")
    if model:
        config["llms"] = {"agent_llm": {"_type": provider, "model_name": model,
            "api_key": "${NVIDIA_API_KEY}" if provider == "nim" else "${OPENAI_API_KEY}",
            "temperature": 0.0, "max_retries": 0, "num_retries": 1}}
        # Optional local/hosted OpenAI-compatible endpoint. The generated config
        # stores only the variable reference, never its value or any credential.
        import os
        if "PRACE_MODEL_BASE_URL" in os.environ:
            config["llms"]["agent_llm"]["base_url"] = "${PRACE_MODEL_BASE_URL}"
        config["workflow"] = {"_type": "react_agent", "llm_name": "agent_llm",
            "tool_names": ["prace_action"], "verbose": False, "max_tool_calls": 4,
            # NAT 1.9 counts the initial attempt in these fields: 1 means
            # execute once. Zero skips execution rather than disabling retries.
            "use_native_tool_calling": False, "tool_call_max_retries": 1,
            "parse_agent_response_max_retries": 1, "pass_tool_call_errors_to_agent": False,
            "raise_on_parsing_failure": True}
        if action_ids is not None:
            config["workflow"].update(tool_names=["prace_catalog", "prace_action"],
                                      max_tool_calls=max_actions + 1)
    return config

"""Bound agent/tool trace projection; raw model text stays in the private run."""

import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any

from validation.contracts import ContractError, require, sha256_json


def action_summaries(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"action_id": event["action_id"], "sequence": event["sequence"],
             "run_id": event["run_id"], "status": event["result"]["status"]}
            for event in events if event["event_type"] == "action" and event["phase"] in {"record", "attack"}]


def project_trace(directory: Path, run_id: str, driver: str, version: str | None,
                  events: list[dict[str, Any]]) -> dict[str, Any]:
    actions = action_summaries(events)
    projection = {"schema": "prace.agent-trace.v1", "run_id": run_id, "driver": driver,
                  "framework_version": version, "raw_trace_sha256": None, "events": [], "actions": actions}
    if driver != "nemo":
        return projection
    raw = (directory / "nemo-trace.jsonl").read_bytes()
    require(0 < len(raw) <= 8 * 1024 * 1024, "missing/oversized NeMo telemetry")
    projection["raw_trace_sha256"] = hashlib.sha256(raw).hexdigest()
    completed = []
    spans = {}
    for line in raw.splitlines():
        require(len(projection["events"]) < 1000, "NeMo telemetry event limit")
        payload = json.loads(line)["payload"]
        event_type = payload["event_type"]
        require(isinstance(event_type, str) and re.fullmatch(r"[A-Z_]{1,80}", event_type), "invalid NeMo event type")
        row = {"event_type": event_type, "span_id": payload["UUID"],
               "timestamp": payload["event_timestamp"], "data_sha256": sha256_json(payload["data"]),
               "action": None}
        if payload["name"] == "prace_action" and event_type in {"FUNCTION_START", "FUNCTION_END"}:
            if event_type == "FUNCTION_START":
                require(row["span_id"] not in spans, "duplicate NeMo action span")
                spans[row["span_id"]] = payload["data"]["input"]["action_id"]
            else:
                action = json.loads(payload["data"]["output"])
                facts = action.pop("observations", None)
                if facts is not None:
                    matching = [event for event in events if event["event_type"] == "action"
                                and event["sequence"] == action.get("sequence")]
                    require(len(matching) == 1 and facts == matching[0]["result"]["bindings"],
                            "NeMo facts do not match gateway observation")
                require(action.get("action_id") == spans.pop(row["span_id"], None), "unpaired NeMo action span")
                row["action"] = action
                completed.append(action)
        projection["events"].append(row)
    require(not spans and completed == actions, "NeMo telemetry does not match gateway actions")
    validate_projection(projection, run_id, driver, version, events)
    return projection


def validate_projection(value: Any, run_id: str, driver: str, version: str | None,
                        events: list[dict[str, Any]]) -> None:
    require(isinstance(value, dict) and set(value) == {"schema", "run_id", "driver", "framework_version",
                "raw_trace_sha256", "events", "actions"}, "malformed agent trace")
    require(value["schema"] == "prace.agent-trace.v1" and value["run_id"] == run_id
            and value["driver"] == driver and value["framework_version"] == version, "agent trace identity mismatch")
    require(value["actions"] == action_summaries(events), "agent/gateway action mismatch")
    rows = value["events"]
    require(isinstance(rows, list) and len(rows) <= 1000, "invalid agent trace events")
    if driver != "nemo":
        require(rows == [] and value["raw_trace_sha256"] is None, "unexpected framework telemetry")
        return
    require(isinstance(value["raw_trace_sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["raw_trace_sha256"]), "NeMo trace digest missing")
    require(rows and rows[0]["event_type"] == "WORKFLOW_START" and rows[-1]["event_type"] == "WORKFLOW_END",
            "NeMo workflow telemetry incomplete")
    completed = []
    previous = 0.0
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"event_type", "span_id", "timestamp", "data_sha256", "action"},
                "malformed agent telemetry row")
        require(isinstance(row["event_type"], str) and re.fullmatch(r"[A-Z_]{1,80}", row["event_type"])
                and isinstance(row["span_id"], str) and re.fullmatch(r"[0-9a-f-]{36}", row["span_id"])
                and isinstance(row["data_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", row["data_sha256"]),
                "invalid agent telemetry fields")
        stamp = row["timestamp"]
        require(type(stamp) in {float, int} and math.isfinite(stamp) and stamp >= previous, "invalid telemetry time")
        previous = stamp
        if row["action"] is not None:
            require(row["event_type"] == "FUNCTION_END", "action result outside tool end")
            completed.append(row["action"])
    require(completed == value["actions"], "NeMo action telemetry incomplete")


def replay_summaries(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{"action_id": event["action_id"], "sequence": event["sequence"], "run_id": event["run_id"],
             "status": event["result"]["status"], "event_sha256": sha256_json(event)}
            for event in events if event["event_type"] == "action" and event["phase"] == "replay"]


def project_replay_trace(directory: Path, run_id: str, version: str | None,
                         events: list[dict[str, Any]]) -> dict[str, Any]:
    """The NeMo replay workflow's telemetry, bound to the gateway's replay events: every step the
    workflow completed is one replayed action (same sequence, action, status, captured facts and the
    SHA-256 of the whole event), the last step is the gateway's "done", the workflow's result equals its
    steps, and no model event appears anywhere in the replay telemetry."""
    raw = (directory / "nemo-replay-trace.jsonl").read_bytes()
    require(0 < len(raw) <= 8 * 1024 * 1024, "missing/oversized NeMo replay telemetry")
    projection = {"schema": "prace.agent-replay-trace.v1", "run_id": run_id, "framework_version": version,
                  "raw_trace_sha256": hashlib.sha256(raw).hexdigest(), "model_used": False,
                  "events": [], "actions": replay_summaries(events), "replayed": None}
    spans = set()
    completed = []
    outputs = []
    payload = None
    for line in raw.splitlines():
        require(len(projection["events"]) < 1000, "NeMo telemetry event limit")
        try:
            payload = json.loads(line)["payload"]
        except (ValueError, KeyError, TypeError):
            raise ContractError("malformed NeMo replay telemetry") from None
        require(isinstance(payload, dict) and {"event_type", "UUID", "event_timestamp", "name", "data"} <= set(payload)
                and isinstance(payload["data"], dict), "malformed NeMo replay telemetry")
        event_type = payload["event_type"]
        require(isinstance(event_type, str) and re.fullmatch(r"[A-Z_]{1,80}", event_type)
                and not event_type.startswith("LLM_"), "invalid or model telemetry in replay")
        row = {"event_type": event_type, "span_id": payload["UUID"],
               "timestamp": payload["event_timestamp"], "data_sha256": sha256_json(payload["data"]),
               "action": None}
        if payload["name"] == "prace_replay_step" and event_type in {"FUNCTION_START", "FUNCTION_END"}:
            if event_type == "FUNCTION_START":
                require(row["span_id"] not in spans, "duplicate NeMo replay span")
                spans.add(row["span_id"])
            else:
                require(row["span_id"] in spans, "unpaired NeMo replay span")
                spans.discard(row["span_id"])
                step = json.loads(payload["data"]["output"])
                require(isinstance(step, dict) and type(step.get("done")) is bool, "malformed replay step")
                outputs.append(dict(step))
                require(projection["replayed"] is None, "NeMo replay continued after done")
                if step.pop("done"):
                    require(set(step) == {"replayed"} and type(step["replayed"]) is int, "malformed replay end")
                    projection["replayed"] = step["replayed"]
                else:
                    facts = step.pop("observations", None)
                    matching = [event for event in events if event["event_type"] == "action"
                                and event["phase"] == "replay" and event["sequence"] == step.get("sequence")]
                    require(len(matching) == 1 and (facts or {}) == matching[0]["result"]["bindings"],
                            "NeMo replay facts do not match the gateway")
                    row["action"] = step
                    completed.append(step)
        projection["events"].append(row)
    require(not spans and completed == projection["actions"], "NeMo replay telemetry does not match gateway replay")
    require(payload is not None and payload["event_type"] == "WORKFLOW_END"
            and json.loads(payload["data"]["output"] or "null") == outputs, "replay workflow result contradicts its steps")
    validate_replay_projection(projection, run_id, version, events)
    return projection


def validate_replay_projection(value: Any, run_id: str, version: str | None, events: list[dict[str, Any]]) -> None:
    require(isinstance(value, dict) and set(value) == {"schema", "run_id", "framework_version", "raw_trace_sha256",
                "model_used", "events", "actions", "replayed"}, "malformed agent replay trace")
    require(value["schema"] == "prace.agent-replay-trace.v1" and value["run_id"] == run_id
            and value["framework_version"] == version and value["model_used"] is False, "agent replay identity mismatch")
    require(isinstance(value["raw_trace_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", value["raw_trace_sha256"]),
            "NeMo replay trace digest missing")
    actions = replay_summaries(events)
    require(value["actions"] == actions and actions and value["replayed"] == len(actions),
            "agent/gateway replay mismatch")
    rows = value["events"]
    require(isinstance(rows, list) and 2 <= len(rows) <= 1000 and rows[0].get("event_type") == "WORKFLOW_START"
            and rows[-1].get("event_type") == "WORKFLOW_END", "NeMo replay telemetry incomplete")
    completed = []
    previous = 0.0
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"event_type", "span_id", "timestamp", "data_sha256", "action"},
                "malformed agent telemetry row")
        require(isinstance(row["event_type"], str) and re.fullmatch(r"[A-Z_]{1,80}", row["event_type"])
                and not row["event_type"].startswith("LLM_")
                and isinstance(row["span_id"], str) and re.fullmatch(r"[0-9a-f-]{36}", row["span_id"])
                and isinstance(row["data_sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", row["data_sha256"]),
                "invalid or model telemetry in replay")
        stamp = row["timestamp"]
        require(type(stamp) in {float, int} and math.isfinite(stamp) and stamp >= previous, "invalid telemetry time")
        previous = stamp
        if row["action"] is not None:
            require(row["event_type"] == "FUNCTION_END", "replay step outside tool end")
            completed.append(row["action"])
    require(completed == actions, "NeMo replay step telemetry incomplete")

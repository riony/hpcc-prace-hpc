"""Independent verdict derivation from trusted observation events."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path
from typing import Any

from .contracts import canonical_json, file_sha256, validate_result


def _status(events: dict[str, dict[str, Any]], check_ids: list[str]) -> str:
    rows = [events.get(check_id) for check_id in check_ids]
    if any(row is not None and row["observation"]["status"] == "error" for row in rows):
        return "error"
    if any(row is not None and row["observation"]["status"] == "fail" for row in rows):
        return "fail"
    if any(row is None or row["observation"]["status"] == "not_run" for row in rows):
        return "inconclusive"
    return "pass"


def _action_problem(events: list[dict[str, Any]], phase: str) -> str | None:
    statuses = [event["result"]["status"] for event in events
                if event["event_type"] == "action" and event["phase"] == phase]
    if "budget_exhausted" in statuses:
        return "budget_exhausted"
    if any(status not in {"ok", "denied"} for status in statuses):
        return "infrastructure_error"
    return None


def evaluate(scenario: dict[str, Any], events: list[dict[str, Any]]) -> tuple[dict[str, str], str]:
    observations = {event["check_id"]: event for event in events if event["event_type"] == "observation"}
    categories: dict[str, list[str]] = {
        category: [item["id"] for item in scenario["assertions"] if item["category"] == category]
        for category in ("security_failure", "security_blocked", "functional")
    }

    if scenario["status"] == "smoke":
        return _evaluate_smoke(scenario, events, observations)

    baseline_problem = _action_problem(events, "attack")
    baseline_state = _status(observations, categories["security_failure"])
    if baseline_problem:
        baseline = baseline_problem
    elif baseline_state == "pass":
        baseline = "security_failure"
    elif baseline_state == "fail":
        baseline = "security_blocked"
    elif baseline_state == "error":
        baseline = "infrastructure_error"
    else:
        baseline = "inconclusive"

    patched_problem = _action_problem(events, "replay")
    patched_state = _status(observations, categories["security_blocked"])
    if patched_problem:
        patched = patched_problem
    elif patched_state == "pass":
        patched = "security_blocked"
    elif patched_state == "fail":
        patched = "security_failure"
    elif patched_state == "error":
        patched = "infrastructure_error"
    else:
        patched = "inconclusive"

    functional_state = _status(observations, categories["functional"])
    functional = {
        "pass": "pass",
        "fail": "functional_regression",
        "error": "infrastructure_error",
        "inconclusive": "inconclusive",
    }[functional_state]
    if patched_problem in {"budget_exhausted", "infrastructure_error"}:
        functional = patched_problem

    cleanup_state = _status(observations, scenario["cleanup"]["check_ids"])
    cleanup = {
        "pass": "complete",
        "fail": "incomplete",
        "error": "error",
        "inconclusive": "inconclusive",
    }[cleanup_state]
    return {"baseline": baseline, "patched": patched, "functional": functional}, cleanup


def _evaluate_smoke(
    scenario: dict[str, Any],
    events: list[dict[str, Any]],
    observations: dict[str, dict[str, Any]],
) -> tuple[dict[str, str], str]:
    """Smoke runs prove tracing/replay/report, not security outcomes."""
    discovery = scenario.get("execution", {}).get("mode") == "discovery"
    source_phase = "attack" if discovery else "record"
    record_problem = _action_problem(events, source_phase)
    replay_problem = _action_problem(events, "replay")
    expected_actions = [action["id"] for action in scenario["actions"]]
    phase_actions = {
        phase: [event for event in events if event["event_type"] == "action" and event["phase"] == phase]
        for phase in (source_phase, "replay")
    }
    actual = [event["action_id"] for event in phase_actions[source_phase]]
    replayed = [event["action_id"] for event in phase_actions["replay"]]
    complete = (bool(actual) and set(scenario["execution"]["required_actions"]) <= set(actual)
                and replayed == actual if discovery else actual == expected_actions and replayed == expected_actions)
    denied = any(event["result"]["status"] == "denied"
                 for actions in phase_actions.values() for event in actions)
    record_ids = [item["id"] for item in scenario["assertions"]
                  if item["category"] == "functional" and item["phase"] == "record"]
    replay_ids = [item["id"] for item in scenario["assertions"]
                  if item["category"] == "functional" and item["phase"] == "replay"]
    functional_state = _status(observations, record_ids + replay_ids)
    if record_problem or replay_problem:
        problem = record_problem or replay_problem
        functional = problem if problem is not None else "inconclusive"
    elif denied:
        functional = "functional_regression"
    elif not complete:
        functional = "inconclusive"
    else:
        functional = {
            "pass": "pass",
            "fail": "functional_regression",
            "error": "infrastructure_error",
            "inconclusive": "inconclusive",
        }[functional_state]

    cleanup_state = _status(observations, scenario["cleanup"]["check_ids"])
    cleanup = {
        "pass": "complete",
        "fail": "incomplete",
        "error": "error",
        "inconclusive": "inconclusive",
    }[cleanup_state]
    return {
        "baseline": "not_applicable",
        "patched": "not_applicable",
        "functional": functional,
    }, cleanup


def build_result(
    *,
    scenario: dict[str, Any],
    events: list[dict[str, Any]],
    trace_path: Path,
    baseline_revision: str,
    patch_revision: str,
) -> dict[str, Any]:
    verdicts, cleanup = evaluate(scenario, events)
    actions = [event for event in events if event["event_type"] == "action"]
    observations = [event for event in events if event["event_type"] == "observation"]
    result = {
        "schema": "prace.run-result.v1",
        "run_id": events[0]["run_id"],
        "scenario": {"id": scenario["id"], "version": scenario["version"]},
        "baseline_revision": baseline_revision,
        "patch_revision": patch_revision,
        "scenario_sha256": hashlib.sha256(canonical_json(scenario)).hexdigest(),
        "trace_sha256": file_sha256(Path(trace_path)),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "counts": {
            "actions": len(actions),
            "observations": len(observations),
            "failed_actions": sum(event["result"]["status"] != "ok" for event in actions),
            "failed_observations": sum(event["observation"]["status"] in {"fail", "error"} for event in observations),
        },
        "verdicts": verdicts,
        "cleanup": cleanup,
    }
    return validate_result(result, scenario)

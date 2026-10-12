"""Strict, dependency-free validators for the versioned PRACE-HPC contracts."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable


MAX_CONTRACT_BYTES = 1024 * 1024
NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
SCENARIO_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
PLACEHOLDER = re.compile(r"^\$\{([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\}$")
PATH_PARAM_KEYS = {"path", "root", "cwd", "script_path"}

SCENARIO_KEYS = {
    "schema", "id", "version", "title", "status", "description", "actor", "boundaries",
    "budgets", "actions", "assertions", "redaction", "gates", "cleanup",
}
ACTION_EVENT_KEYS = {
    "schema", "event_type", "run_id", "sequence", "timestamp", "source", "phase",
    "scenario", "action_id", "action", "request_sha256", "result",
}
OBSERVATION_EVENT_KEYS = {
    "schema", "event_type", "run_id", "sequence", "timestamp", "source", "phase",
    "scenario", "check_id", "target", "observation",
}
CLUSTER_EVENT_KEYS = {
    "schema", "event_type", "run_id", "sequence", "timestamp", "source", "phase",
    "scenario", "correlated_action_sequence", "target", "snapshot",
}
RESULT_KEYS = {
    "schema", "run_id", "scenario", "baseline_revision", "patch_revision",
    "scenario_sha256", "trace_sha256", "generated_at", "counts", "verdicts", "cleanup",
}


class ContractError(ValueError):
    """A contract is malformed, unsafe, or inconsistent with its scenario."""


def require(condition: Any, message: str) -> None:
    if not condition:
        raise ContractError(message)


def exact_keys(value: Any, expected: set[str], where: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{where}: expected object")
    actual = set(value)
    require(actual == expected, f"{where}: keys differ (missing={sorted(expected - actual)}, extra={sorted(actual - expected)})")
    return value


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path, *, max_bytes: int = MAX_CONTRACT_BYTES) -> Any:
    path = Path(path)
    info = path.lstat()
    require(path.is_file() and not path.is_symlink(), f"{path}: regular file required")
    require(info.st_size <= max_bytes, f"{path}: file exceeds {max_bytes} bytes")
    try:
        return json.loads(path.read_text())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"{path}: invalid JSON: {exc}") from exc


def _name(value: Any, where: str) -> str:
    require(isinstance(value, str) and NAME.fullmatch(value), f"{where}: invalid name")
    return value


def _positive_int(value: Any, where: str, maximum: int) -> int:
    require(type(value) is int and 1 <= value <= maximum, f"{where}: expected integer in 1..{maximum}")
    return value


def _unique_names(value: Any, where: str, *, nonempty: bool = True) -> list[str]:
    require(isinstance(value, list) and (value or not nonempty), f"{where}: expected {'non-empty ' if nonempty else ''}array")
    result = [_name(item, f"{where}[{index}]") for index, item in enumerate(value)]
    require(len(result) == len(set(result)), f"{where}: duplicate value")
    return result


def _timestamp(value: Any, where: str) -> str:
    require(isinstance(value, str), f"{where}: expected timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError(f"{where}: invalid RFC3339 timestamp") from exc
    require(parsed.tzinfo is not None, f"{where}: timezone required")
    return value


def _sha256(value: Any, where: str) -> str:
    require(isinstance(value, str) and SHA256.fullmatch(value), f"{where}: invalid SHA-256")
    return value


def _walk_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _walk_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)


def _placeholders(value: Any, where: str) -> set[str]:
    found: set[str] = set()
    for text in _walk_strings(value):
        match = PLACEHOLDER.fullmatch(text)
        if match:
            found.add(match.group(1))
        else:
            require("${" not in text, f"{where}: placeholders must occupy the whole string")
    return found


def _contains_forbidden_key(value: Any, forbidden: set[str]) -> bool:
    if isinstance(value, dict):
        return any(str(key).lower() in forbidden or _contains_forbidden_key(item, forbidden)
                   for key, item in value.items())
    if isinstance(value, list):
        return any(_contains_forbidden_key(item, forbidden) for item in value)
    return False


def ensure_redacted(value: Any, scenario: dict[str, Any], where: str) -> None:
    redaction = scenario["redaction"]
    forbidden = {key.lower() for key in redaction["keys"]}
    require(not _contains_forbidden_key(value, forbidden), f"{where}: forbidden sensitive key")
    for pattern in redaction["patterns"]:
        compiled = re.compile(pattern)
        for text in _walk_strings(value):
            require(compiled.search(text) is None, f"{where}: value matches redaction pattern")


def normalize_abs_path(path: str, where: str = "path") -> str:
    require(isinstance(path, str) and path.startswith("/") and "\x00" not in path,
            f"{where}: absolute path required")
    require(".." not in path.split("/"), f"{where}: parent traversal refused")
    normalized = os.path.normpath(path)
    require(normalized.startswith("/") and ".." not in normalized.split("/"),
            f"{where}: path normalization escaped root")
    return normalized if normalized != "/" else "/"


def path_is_under(candidate: str, roots: list[str]) -> bool:
    cand = Path(normalize_abs_path(candidate))
    for root in roots:
        root_path = Path(normalize_abs_path(root))
        try:
            cand.relative_to(root_path)
            return True
        except ValueError:
            continue
    return False


def collect_path_strings(value: Any, key: str | None = None) -> list[str]:
    found: list[str] = []
    if isinstance(value, str):
        if PLACEHOLDER.fullmatch(value):
            return found
        if key in PATH_PARAM_KEYS or value.startswith("/") or value.startswith(".") or "/../" in f"/{value}/":
            found.append(value)
        return found
    if isinstance(value, list):
        for item in value:
            found.extend(collect_path_strings(item, key))
        return found
    if isinstance(value, dict):
        for child_key, item in value.items():
            found.extend(collect_path_strings(item, str(child_key)))
        return found
    return found


def ensure_paths_within_boundaries(parameters: Any, scenario: dict[str, Any], where: str) -> None:
    roots = scenario["boundaries"]["paths"]
    for path in collect_path_strings(parameters):
        require(path.startswith("/"), f"{where}: relative path refused: {path}")
        normalized = normalize_abs_path(path, where)
        require(path_is_under(normalized, roots), f"{where}: path outside boundary: {path}")


def _validate_action(action: Any, scenario: dict[str, Any], where: str, *, with_id: bool) -> dict[str, Any]:
    keys = {"id", "kind", "target", "identity", "parameters", "timeout_seconds", "capture"} if with_id else {
        "kind", "target", "identity", "parameters",
    }
    action = exact_keys(action, keys, where)
    if with_id:
        _name(action["id"], f"{where}.id")
        _positive_int(action["timeout_seconds"], f"{where}.timeout_seconds", 3600)
        require(isinstance(action["capture"], dict), f"{where}.capture: expected object")
        for output, symbol in action["capture"].items():
            _name(output, f"{where}.capture output")
            _name(symbol, f"{where}.capture symbol")
    _name(action["kind"], f"{where}.kind")
    _name(action["target"], f"{where}.target")
    _name(action["identity"], f"{where}.identity")
    require(action["kind"] in scenario["boundaries"]["action_kinds"], f"{where}: action kind outside boundary")
    require(action["target"] in scenario["boundaries"]["action_targets"], f"{where}: target outside boundary")
    require(action["identity"] == scenario["actor"]["identity"], f"{where}: identity differs from actor")
    require(isinstance(action["parameters"], dict), f"{where}.parameters: expected object")
    ensure_redacted(action["parameters"], scenario, f"{where}.parameters")
    ensure_paths_within_boundaries(action["parameters"], scenario, f"{where}.parameters")
    return action


def validate_scenario(value: Any) -> dict[str, Any]:
    scenario = exact_keys(value, SCENARIO_KEYS | ({"execution"} if isinstance(value, dict) and "execution" in value else set()), "scenario")
    require(scenario["schema"] == "prace.scenario.v1", "scenario.schema: unsupported")
    require(isinstance(scenario["id"], str) and SCENARIO_ID.fullmatch(scenario["id"]), "scenario.id: invalid")
    _positive_int(scenario["version"], "scenario.version", 1_000_000)
    require(isinstance(scenario["title"], str) and 1 <= len(scenario["title"]) <= 120, "scenario.title: invalid")
    require(scenario["status"] in {"ready", "feasibility_required", "smoke"}, "scenario.status: invalid")
    require(isinstance(scenario["description"], str) and 1 <= len(scenario["description"]) <= 1000,
            "scenario.description: invalid")

    actor = exact_keys(scenario["actor"], {"identity", "project", "intent"}, "scenario.actor")
    _name(actor["identity"], "scenario.actor.identity")
    _name(actor["project"], "scenario.actor.project")
    require(actor["intent"] in {"benign", "malicious", "reconnaissance"}, "scenario.actor.intent: invalid")

    boundaries = exact_keys(scenario["boundaries"], {
        "action_targets", "observation_targets", "paths", "action_kinds",
    }, "scenario.boundaries")
    _unique_names(boundaries["action_targets"], "scenario.boundaries.action_targets")
    _unique_names(boundaries["observation_targets"], "scenario.boundaries.observation_targets")
    _unique_names(boundaries["action_kinds"], "scenario.boundaries.action_kinds")
    require(isinstance(boundaries["paths"], list) and boundaries["paths"], "scenario.boundaries.paths: expected non-empty array")
    normalized_roots: list[str] = []
    for index, path in enumerate(boundaries["paths"]):
        require(isinstance(path, str), f"scenario.boundaries.paths[{index}]: expected string")
        normalized_roots.append(normalize_abs_path(path, f"scenario.boundaries.paths[{index}]"))
    require(len(normalized_roots) == len(set(normalized_roots)), "scenario.boundaries.paths: duplicate")
    boundaries["paths"][:] = normalized_roots

    budgets = exact_keys(scenario["budgets"], {"max_actions", "max_seconds", "max_output_bytes"}, "scenario.budgets")
    _positive_int(budgets["max_actions"], "scenario.budgets.max_actions", 1000)
    _positive_int(budgets["max_seconds"], "scenario.budgets.max_seconds", 86400)
    require(type(budgets["max_output_bytes"]) is int and 0 <= budgets["max_output_bytes"] <= MAX_CONTRACT_BYTES,
            "scenario.budgets.max_output_bytes: invalid")

    require(isinstance(scenario["redaction"], dict), "scenario.redaction: expected object")
    redaction = exact_keys(scenario["redaction"], {"keys", "patterns"}, "scenario.redaction")
    _unique_names(redaction["keys"], "scenario.redaction.keys", nonempty=False)
    require(isinstance(redaction["patterns"], list) and len(redaction["patterns"]) == len(set(redaction["patterns"])),
            "scenario.redaction.patterns: expected unique array")
    for index, pattern in enumerate(redaction["patterns"]):
        require(isinstance(pattern, str) and 1 <= len(pattern) <= 200, f"scenario.redaction.patterns[{index}]: invalid")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ContractError(f"scenario.redaction.patterns[{index}]: invalid regex") from exc

    require(isinstance(scenario["actions"], list) and scenario["actions"], "scenario.actions: expected non-empty array")
    require(len(scenario["actions"]) <= budgets["max_actions"], "scenario.actions: exceeds action budget")
    for index, action in enumerate(scenario["actions"]):
        _validate_action(action, scenario, f"scenario.actions[{index}]", with_id=True)
    action_ids = [action["id"] for action in scenario["actions"]]
    require(len(action_ids) == len(set(action_ids)), "scenario.actions: duplicate id")
    if "execution" in scenario:
        execution = exact_keys(scenario["execution"], {"mode", "required_actions"}, "scenario.execution")
        require(scenario["status"] == "smoke" and execution["mode"] == "discovery", "discovery execution is smoke-only")
        required = _unique_names(execution["required_actions"], "scenario.execution.required_actions")
        require(set(required) <= set(action_ids), "completion action outside manifest")
    symbols = [symbol for action in scenario["actions"] for symbol in action["capture"].values()]
    require(len(symbols) == len(set(symbols)), "scenario.actions: duplicate capture symbol")
    available: set[str] = set()
    for index, action in enumerate(scenario["actions"]):
        referenced = _placeholders(action["parameters"], f"scenario.actions[{index}].parameters")
        require(referenced <= available, f"scenario.actions[{index}]: unresolved or forward capture reference")
        available.update(action["capture"].values())

    require(isinstance(scenario["assertions"], list) and scenario["assertions"],
            "scenario.assertions: expected non-empty array")
    valid_phases = {"baseline", "attack", "record", "patched", "replay", "regression", "cleanup", "reset"}
    valid_categories = {"security_failure", "security_blocked", "functional", "cleanup"}
    assertion_ids: list[str] = []
    for index, assertion in enumerate(scenario["assertions"]):
        assertion = exact_keys(assertion, {"id", "phase", "category", "description"},
                               f"scenario.assertions[{index}]")
        assertion_ids.append(_name(assertion["id"], f"scenario.assertions[{index}].id"))
        require(assertion["phase"] in valid_phases, f"scenario.assertions[{index}].phase: invalid")
        require(assertion["category"] in valid_categories, f"scenario.assertions[{index}].category: invalid")
        require(isinstance(assertion["description"], str) and 1 <= len(assertion["description"]) <= 300,
                f"scenario.assertions[{index}].description: invalid")
    require(len(assertion_ids) == len(set(assertion_ids)), "scenario.assertions: duplicate id")
    if scenario["status"] == "smoke":
        require(any(item["category"] == "functional" and item["phase"] == "record"
                    for item in scenario["assertions"]),
                "scenario.assertions: smoke requires a record-phase functional assertion")
        require(any(item["category"] == "functional" and item["phase"] == "replay"
                    for item in scenario["assertions"]),
                "scenario.assertions: smoke requires a replay-phase functional assertion")
        require(not any(item["category"] in {"security_failure", "security_blocked"}
                        for item in scenario["assertions"]),
                "scenario.assertions: smoke must not declare security assertions")
    else:
        require(any(item["category"] == "security_failure" for item in scenario["assertions"]),
                "scenario.assertions: missing vulnerable-baseline assertion")
        require(any(item["category"] == "security_blocked" for item in scenario["assertions"]),
                "scenario.assertions: missing patched replay assertion")
        require(any(item["category"] == "functional" for item in scenario["assertions"]),
                "scenario.assertions: missing functional assertion")

    _unique_names(scenario["gates"], "scenario.gates", nonempty=False)
    cleanup = exact_keys(scenario["cleanup"], {"required", "check_ids"}, "scenario.cleanup")
    require(type(cleanup["required"]) is bool, "scenario.cleanup.required: expected boolean")
    cleanup_ids = _unique_names(cleanup["check_ids"], "scenario.cleanup.check_ids")
    declared_cleanup = {item["id"] for item in scenario["assertions"] if item["category"] == "cleanup"}
    require(set(cleanup_ids) <= declared_cleanup, "scenario.cleanup.check_ids: not cleanup assertions")
    return scenario


def load_scenario(path: Path) -> dict[str, Any]:
    return validate_scenario(load_json(Path(path)))


def action_templates(scenario: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {action["id"]: action for action in scenario["actions"]}


def assertion_templates(scenario: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {assertion["id"]: assertion for assertion in scenario["assertions"]}


def _scenario_ref(value: Any, scenario: dict[str, Any], where: str) -> None:
    value = exact_keys(value, {"id", "version"}, where)
    require(value == {"id": scenario["id"], "version": scenario["version"]}, f"{where}: scenario mismatch")


def validate_action_event(value: Any, scenario: dict[str, Any]) -> dict[str, Any]:
    event = exact_keys(value, ACTION_EVENT_KEYS, "action event")
    require(event["schema"] == "prace.action-event.v1" and event["event_type"] == "action",
            "action event: unsupported schema")
    _name(event["run_id"], "action event.run_id")
    _positive_int(event["sequence"], "action event.sequence", 2_147_483_647)
    _timestamp(event["timestamp"], "action event.timestamp")
    require(event["source"] == "agent_gateway", "action event.source: invalid")
    require(event["phase"] in {"attack", "record", "replay"}, "action event.phase: invalid")
    _scenario_ref(event["scenario"], scenario, "action event.scenario")
    _name(event["action_id"], "action event.action_id")
    templates = action_templates(scenario)
    require(event["action_id"] in templates, "action event.action_id: unknown")
    action = _validate_action(event["action"], scenario, "action event.action", with_id=False)
    template = templates[event["action_id"]]
    expected = {key: template[key] for key in ("kind", "target", "identity", "parameters")}
    require(action == expected, "action event.action: differs from scenario template")
    require(event["request_sha256"] == sha256_json(action), "action event.request_sha256: mismatch")

    result = exact_keys(event["result"], {
        "status", "exit_code", "executed_sha256", "stdout_sha256", "stderr_sha256",
        "duration_ms", "output_bytes", "bindings",
    }, "action event.result")
    require(result["status"] in {"ok", "denied", "error", "timeout", "refused", "budget_exhausted"},
            "action event.result.status: invalid")
    require(result["exit_code"] is None or type(result["exit_code"]) is int, "action event.result.exit_code: invalid")
    if result["status"] == "ok":
        require(result["exit_code"] == 0, "action event.result: ok requires exit code 0")
    if result["status"] == "denied":
        require(type(result["exit_code"]) is int and result["exit_code"] != 0,
                "action event.result: denied requires nonzero exit code")
    _sha256(result["executed_sha256"], "action event.result.executed_sha256")
    _sha256(result["stdout_sha256"], "action event.result.stdout_sha256")
    _sha256(result["stderr_sha256"], "action event.result.stderr_sha256")
    require(type(result["duration_ms"]) is int and result["duration_ms"] >= 0,
            "action event.result.duration_ms: invalid")
    require(type(result["output_bytes"]) is int and 0 <= result["output_bytes"] <= scenario["budgets"]["max_output_bytes"],
            "action event.result.output_bytes: outside budget")
    require(isinstance(result["bindings"], dict), "action event.result.bindings: expected object")
    allowed_symbols = set(template["capture"].values())
    require(set(result["bindings"]) <= allowed_symbols, "action event.result.bindings: undeclared symbol")
    binding_limit = 1024 if action["kind"] == "file.tail" else 4096 if action["kind"] in {"file.list", "file.stat", "env.modules"} else 256
    for name, binding in result["bindings"].items():
        _name(name, "action event.result.bindings key")
        require(isinstance(binding, str) and len(binding) <= binding_limit, "action event.result.bindings value: invalid")
    ensure_redacted(event, scenario, "action event")
    return event


def validate_observation_event(value: Any, scenario: dict[str, Any]) -> dict[str, Any]:
    event = exact_keys(value, OBSERVATION_EVENT_KEYS, "observation event")
    require(event["schema"] == "prace.observation-event.v1" and event["event_type"] == "observation",
            "observation event: unsupported schema")
    _name(event["run_id"], "observation event.run_id")
    _positive_int(event["sequence"], "observation event.sequence", 2_147_483_647)
    _timestamp(event["timestamp"], "observation event.timestamp")
    require(event["source"] == "trusted_validator", "observation event.source: invalid")
    _scenario_ref(event["scenario"], scenario, "observation event.scenario")
    _name(event["check_id"], "observation event.check_id")
    assertion = assertion_templates(scenario).get(event["check_id"])
    require(assertion is not None, "observation event.check_id: unknown")
    require(event["phase"] == assertion["phase"], "observation event.phase: differs from assertion")
    _name(event["target"], "observation event.target")
    require(event["target"] in scenario["boundaries"]["observation_targets"],
            "observation event.target: outside boundary")
    observation = exact_keys(event["observation"], {"status", "code", "evidence_sha256", "detail"},
                             "observation event.observation")
    require(observation["status"] in {"pass", "fail", "error", "not_run"},
            "observation event.observation.status: invalid")
    _name(observation["code"], "observation event.observation.code")
    _sha256(observation["evidence_sha256"], "observation event.observation.evidence_sha256")
    require(isinstance(observation["detail"], str) and len(observation["detail"]) <= 300,
            "observation event.observation.detail: invalid")
    ensure_redacted(event, scenario, "observation event")
    return event


def validate_cluster_event(value: Any, scenario: dict[str, Any]) -> dict[str, Any]:
    event = exact_keys(value, CLUSTER_EVENT_KEYS, "cluster event")
    require(event["schema"] == "prace.cluster-event.v1" and event["event_type"] == "cluster",
            "cluster event: unsupported schema")
    _name(event["run_id"], "cluster event.run_id")
    _positive_int(event["sequence"], "cluster event.sequence", 2_147_483_647)
    _timestamp(event["timestamp"], "cluster event.timestamp")
    require(event["source"] in {"cluster_tracer", "cluster_watcher"},
            "cluster event.source: invalid")
    require(event["phase"] in {"record", "replay", "cleanup", "attack"}, "cluster event.phase: invalid")
    _scenario_ref(event["scenario"], scenario, "cluster event.scenario")
    _positive_int(event["correlated_action_sequence"], "cluster event.correlated_action_sequence", 2_147_483_647)
    _name(event["target"], "cluster event.target")
    require(event["target"] in scenario["boundaries"]["observation_targets"],
            "cluster event.target: outside boundary")
    snapshot = exact_keys(event["snapshot"], {"status", "code", "evidence_sha256", "detail"},
                          "cluster event.snapshot")
    require(snapshot["status"] in {"match", "mismatch", "error", "missing"},
            "cluster event.snapshot.status: invalid")
    _name(snapshot["code"], "cluster event.snapshot.code")
    _sha256(snapshot["evidence_sha256"], "cluster event.snapshot.evidence_sha256")
    require(isinstance(snapshot["detail"], str) and len(snapshot["detail"]) <= 300,
            "cluster event.snapshot.detail: invalid")
    ensure_redacted(event, scenario, "cluster event")
    return event


def validate_event(value: Any, scenario: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(value, dict), "event: expected object")
    if value.get("event_type") == "action":
        return validate_action_event(value, scenario)
    if value.get("event_type") == "observation":
        return validate_observation_event(value, scenario)
    if value.get("event_type") == "cluster":
        return validate_cluster_event(value, scenario)
    raise ContractError("event.event_type: unsupported")


def validate_result(value: Any, scenario: dict[str, Any]) -> dict[str, Any]:
    result = exact_keys(value, RESULT_KEYS, "run result")
    require(result["schema"] == "prace.run-result.v1", "run result.schema: unsupported")
    _name(result["run_id"], "run result.run_id")
    _scenario_ref(result["scenario"], scenario, "run result.scenario")
    for key in ("baseline_revision", "patch_revision"):
        require(isinstance(result[key], str) and 1 <= len(result[key]) <= 200, f"run result.{key}: invalid")
    _sha256(result["scenario_sha256"], "run result.scenario_sha256")
    _sha256(result["trace_sha256"], "run result.trace_sha256")
    _timestamp(result["generated_at"], "run result.generated_at")
    counts = exact_keys(result["counts"], {"actions", "observations", "failed_actions", "failed_observations"},
                       "run result.counts")
    require(all(type(counts[key]) is int and counts[key] >= 0 for key in counts), "run result.counts: invalid")
    verdicts = exact_keys(result["verdicts"], {"baseline", "patched", "functional"}, "run result.verdicts")
    security = {
        "security_failure", "security_blocked", "infrastructure_error",
        "budget_exhausted", "inconclusive", "not_applicable",
    }
    require(verdicts["baseline"] in security and verdicts["patched"] in security,
            "run result.verdicts: invalid security verdict")
    require(verdicts["functional"] in {
        "pass", "functional_regression", "infrastructure_error", "budget_exhausted", "inconclusive",
    }, "run result.verdicts.functional: invalid")
    require(result["cleanup"] in {"complete", "incomplete", "error", "inconclusive"},
            "run result.cleanup: invalid")
    return result

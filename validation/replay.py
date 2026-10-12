"""Deterministic replay of scenario-declared actions through a bounded adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import time
from typing import Any, Callable, Protocol

from .contracts import (
    PLACEHOLDER,
    ensure_paths_within_boundaries,
    ensure_redacted,
    normalize_abs_path,
    path_is_under,
    require,
    sha256_json,
)
from .trace import TraceWriter


EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class ReplayError(RuntimeError):
    """Replay stopped after recording the attempted action."""


@dataclass(frozen=True)
class AdapterResult:
    status: str
    exit_code: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    outputs: dict[str, str] = field(default_factory=dict)
    duration_ms: int | None = None


class ActionAdapter(Protocol):
    def execute(self, action_id: str, action: dict[str, Any], timeout_seconds: int) -> AdapterResult:
        """Execute one already-validated and resolved action."""


class FakeAdapter:
    """Hermetic adapter for tests and recorded offline demonstrations."""

    def __init__(self, responses: dict[str, AdapterResult]):
        self.responses = responses
        self.calls: list[tuple[str, dict[str, Any], int]] = []

    def execute(self, action_id: str, action: dict[str, Any], timeout_seconds: int) -> AdapterResult:
        self.calls.append((action_id, action, timeout_seconds))
        if action_id not in self.responses:
            return AdapterResult("refused", None, stderr=b"no fake response")
        return self.responses[action_id]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _resolve(value: Any, bindings: dict[str, str]) -> Any:
    if isinstance(value, str):
        match = PLACEHOLDER.fullmatch(value)
        if match:
            require(match.group(1) in bindings, f"unresolved binding: {match.group(1)}")
            return bindings[match.group(1)]
        require("${" not in value, "placeholders must occupy the whole string")
        return value
    if isinstance(value, list):
        return [_resolve(item, bindings) for item in value]
    if isinstance(value, dict):
        return {key: _resolve(item, bindings) for key, item in value.items()}
    return value


def resolve_action(template: dict[str, Any], bindings: dict[str, str], scenario: dict[str, Any]) -> dict[str, Any]:
    action = {
        "kind": template["kind"],
        "target": template["target"],
        "identity": template["identity"],
        "parameters": _resolve(template["parameters"], bindings),
    }
    require(action["kind"] in scenario["boundaries"]["action_kinds"], "resolved action kind outside boundary")
    require(action["target"] in scenario["boundaries"]["action_targets"],
            "resolved action target outside boundary")
    require(action["identity"] == scenario["actor"]["identity"], "resolved action identity differs from actor")
    ensure_paths_within_boundaries(action["parameters"], scenario, "resolved action")
    ensure_redacted(action, scenario, "resolved action")
    return action


def make_action_event(
    *,
    scenario: dict[str, Any],
    run_id: str,
    sequence: int,
    phase: str,
    template: dict[str, Any],
    resolved_action: dict[str, Any],
    result: AdapterResult,
) -> dict[str, Any]:
    normalized = {key: template[key] for key in ("kind", "target", "identity", "parameters")}
    output_bytes = len(result.stdout) + len(result.stderr)
    captured: dict[str, str] = {}
    for output_name, symbol in template["capture"].items():
        if output_name in result.outputs:
            captured[symbol] = str(result.outputs[output_name])
    ensure_redacted(captured, scenario, "captured bindings")
    duration = result.duration_ms if result.duration_ms is not None else 0
    return {
        "schema": "prace.action-event.v1",
        "event_type": "action",
        "run_id": run_id,
        "sequence": sequence,
        "timestamp": utc_now(),
        "source": "agent_gateway",
        "phase": phase,
        "scenario": {"id": scenario["id"], "version": scenario["version"]},
        "action_id": template["id"],
        "action": normalized,
        "request_sha256": sha256_json(normalized),
        "result": {
            "status": result.status,
            "exit_code": result.exit_code,
            "executed_sha256": sha256_json(resolved_action),
            "stdout_sha256": hashlib.sha256(result.stdout).hexdigest(),
            "stderr_sha256": hashlib.sha256(result.stderr).hexdigest(),
            "duration_ms": duration,
            "output_bytes": output_bytes,
            "bindings": captured,
        },
    }


def _cap_result(result: AdapterResult, max_output_bytes: int) -> AdapterResult:
    total = len(result.stdout) + len(result.stderr)
    if total <= max_output_bytes:
        return result
    return AdapterResult(
        "budget_exhausted",
        result.exit_code,
        b"",
        b"",
        {},
        result.duration_ms,
    )


class ReplayRunner:
    def __init__(
        self,
        scenario: dict[str, Any],
        source_events: list[dict[str, Any]],
        writer: TraceWriter,
        adapter: ActionAdapter,
        *,
        after_action: Callable[[dict[str, Any]], None] | None = None,
        bindings: dict[str, str] | None = None,
        started: float | None = None,
    ):
        self.scenario = scenario
        self.source_events = source_events
        self.writer = writer
        self.adapter = adapter
        self.after_action = after_action
        # A stepped replay (one action per call) carries the bindings and
        # budget start of the replay so far; a whole replay starts empty.
        self.initial_bindings = dict(bindings or {})
        self.started = started

    def run(self) -> list[dict[str, Any]]:
        recorded = [event for event in self.source_events
                    if event["event_type"] == "action" and event["phase"] == "record"]
        attacked = [event for event in self.source_events
                    if event["event_type"] == "action" and event["phase"] == "attack"]
        source = recorded or attacked
        require(source, "source trace has no record or attack actions")
        templates = {action["id"]: action for action in self.scenario["actions"]}
        started = time.monotonic() if self.started is None else self.started
        bindings: dict[str, str] = dict(self.initial_bindings)
        replayed: list[dict[str, Any]] = []
        for original in source:
            template = templates[original["action_id"]]
            resolved = resolve_action(template, bindings, self.scenario)
            if time.monotonic() - started > self.scenario["budgets"]["max_seconds"]:
                adapter_result = AdapterResult("budget_exhausted", None)
            else:
                action_started = time.monotonic()
                try:
                    timeout = template["timeout_seconds"]
                    if self.scenario["id"] == "researcher-workflow":
                        timeout = min(timeout, max(1, int(self.scenario["budgets"]["max_seconds"] - (time.monotonic() - started))))
                    adapter_result = self.adapter.execute(template["id"], resolved, timeout)
                except Exception:
                    adapter_result = AdapterResult("error", None, stderr=b"adapter_exception")
                elapsed = int((time.monotonic() - action_started) * 1000)
                if adapter_result.duration_ms is None:
                    adapter_result = AdapterResult(
                        adapter_result.status,
                        adapter_result.exit_code,
                        adapter_result.stdout,
                        adapter_result.stderr,
                        adapter_result.outputs,
                        elapsed,
                    )
            require(adapter_result.status in {"ok", "denied", "error", "timeout", "refused", "budget_exhausted"},
                    "adapter returned unsupported status")
            capped = _cap_result(adapter_result, self.scenario["budgets"]["max_output_bytes"])
            event = make_action_event(
                scenario=self.scenario,
                run_id=self.writer.run_id,
                sequence=self.writer.next_sequence,
                phase="replay",
                template=template,
                resolved_action=resolved,
                result=capped,
            )
            written = self.writer.append(event)
            replayed.append(written)
            if self.after_action is not None:
                self.after_action(written)
            bindings.update(written["result"]["bindings"])
            if capped.status == "denied":
                break
            if capped.status != "ok":
                raise ReplayError(f"replay stopped at {template['id']}: {capped.status}")
        return replayed


from .contracts import normalize_abs_path as normalize_abs_path  # noqa: E402
from .contracts import path_is_under as path_is_under  # noqa: E402

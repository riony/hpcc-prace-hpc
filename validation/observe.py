"""Helpers for trusted validators to emit sanitized observation events."""

from __future__ import annotations

import hashlib
from typing import Any

from .contracts import assertion_templates, validate_observation_event
from .replay import utc_now


def make_observation_event(
    *,
    scenario: dict[str, Any],
    run_id: str,
    sequence: int,
    check_id: str,
    target: str,
    status: str,
    code: str,
    evidence: bytes = b"",
    detail: str = "",
) -> dict[str, Any]:
    assertion = assertion_templates(scenario)[check_id]
    event = {
        "schema": "prace.observation-event.v1",
        "event_type": "observation",
        "run_id": run_id,
        "sequence": sequence,
        "timestamp": utc_now(),
        "source": "trusted_validator",
        "phase": assertion["phase"],
        "scenario": {"id": scenario["id"], "version": scenario["version"]},
        "check_id": check_id,
        "target": target,
        "observation": {
            "status": status,
            "code": code,
            "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
            "detail": detail,
        },
    }
    return validate_observation_event(event, scenario)

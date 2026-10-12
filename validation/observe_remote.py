"""Trusted remote observations and cluster-event helpers for smoke runs."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from validation.contracts import require
from validation.local_fs import observe_workspace
from validation.replay import utc_now


def make_cluster_event(
    *,
    scenario: dict[str, Any],
    run_id: str,
    sequence: int,
    phase: str,
    correlated_action_sequence: int,
    target: str,
    status: str,
    code: str,
    evidence: bytes = b"",
    detail: str = "",
    source: str = "cluster_tracer",
) -> dict[str, Any]:
    require(source in {"cluster_tracer", "cluster_watcher"}, "cluster event.source: invalid")
    return {
        "schema": "prace.cluster-event.v1",
        "event_type": "cluster",
        "run_id": run_id,
        "sequence": sequence,
        "timestamp": utc_now(),
        "source": source,
        "phase": phase,
        "scenario": {"id": scenario["id"], "version": scenario["version"]},
        "correlated_action_sequence": correlated_action_sequence,
        "target": target,
        "snapshot": {
            "status": status,
            "code": code,
            "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
            "detail": detail,
        },
    }


def observe_remote_workspace(adapter: Any, workspace: Path) -> tuple[bool, str, bytes]:
    """Inspect remote or local workspace using the adapter's transport when available."""
    workspace = Path(workspace)
    if hasattr(adapter, "observe_workspace"):
        return adapter.observe_workspace(workspace)
    return observe_workspace(workspace)


def expected_layout_detail(ok: bool) -> str:
    return "demo-dir with only test-file-2.txt" if ok else "unexpected workspace layout"

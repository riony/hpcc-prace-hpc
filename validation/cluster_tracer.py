"""Cluster-side audit feed for prace.cluster-event.v1 (source=cluster_tracer).

The cp2 FileOpsWatcher (source=cluster_watcher) remains optional interim
corroboration only. This module owns the diagram's cluster-tracer path.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path
from typing import Any

from validation.observe_remote import expected_layout_detail, observe_remote_workspace
from validation.tracer.client import TracerClient
from validation.contracts import sha256_json, canonical_json, require

CLUSTER_TRACER_SOURCE = "cluster_tracer"
CLUSTER_WATCHER_SOURCE = "cluster_watcher"
ALLOWED_CLUSTER_SOURCES = frozenset({CLUSTER_TRACER_SOURCE, CLUSTER_WATCHER_SOURCE})


def validate_inventory_proof(proof: dict) -> None:
    require(isinstance(proof, dict) and set(proof) == {'entries', 'job_ticket_present'}
            and type(proof['job_ticket_present']) is bool and isinstance(proof['entries'], list)
            and len(proof['entries']) <= 32, 'malformed tracer inventory')
    paths = []
    for row in proof['entries']:
        require(isinstance(row, dict) and row.get('kind') in {'file', 'directory', 'symlink', 'other'},
                'malformed tracer inventory entry')
        require(set(row) == ({'path', 'kind', 'sha256'} if row['kind'] == 'file' else {'path', 'kind'}),
                'malformed tracer inventory entry fields')
        path = row['path']
        require(isinstance(path, str) and path and not path.startswith('/')
                and all(part not in {'', '.', '..'} for part in path.split('/')), 'invalid tracer inventory path')
        if row['kind'] == 'file':
            require(isinstance(row['sha256'], str) and re.fullmatch(r'[a-f0-9]{64}', row['sha256']), 'invalid tracer file hash')
        paths.append(path)
    require(paths == sorted(set(paths)), 'duplicate or unsorted tracer paths')


def build_layout_snapshot(adapter: Any, workspace: Path) -> dict[str, str]:
    """Produce a cluster-event snapshot from the cluster audit adapter."""
    ok, detail, evidence = observe_remote_workspace(adapter, workspace)
    return {
        "status": "match" if ok else "mismatch",
        "code": "layout-final" if ok else "layout-partial-or-wrong",
        "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
        "detail": (detail or expected_layout_detail(ok))[:300],
    }


def build_inventory_snapshot(adapter: Any, workspace: Path, proof_path: Path | None = None) -> dict[str, str]:
    """Match means inventory was collected, not that a functional assertion passed."""
    try:
        proof = adapter.inventory_workspace(workspace)
        if proof_path is not None:
            validate_inventory_proof(proof)
            with proof_path.open('xb') as stream:
                proof_path.chmod(0o600)
                stream.write(canonical_json(proof) + b'\n')
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        detail = "inventory unavailable: " + type(exc).__name__
        return {"status": "mismatch", "code": "workspace-inventory-unavailable",
                "evidence_sha256": sha256_json({"error": type(exc).__name__}), "detail": detail}
    return {"status": "match", "code": "workspace-inventory", "evidence_sha256": sha256_json(proof),
            "detail": "bounded workspace inventory collected; final checks use the separate observer"}


class ClusterTracer:
    """Emit cluster_tracer events into the local gateway after cluster observation."""

    source = CLUSTER_TRACER_SOURCE

    def __init__(self, client: TracerClient, adapter: Any, workspace: Path, target: str):
        self.client = client
        self.adapter = adapter
        self.workspace = Path(workspace)
        self.target = target

    def emit(self, *, phase: str, correlated_action_sequence: int) -> dict[str, Any]:
        snapshot = build_layout_snapshot(self.adapter, self.workspace)
        response = self.client.call(
            "append_cluster",
            source=self.source,
            phase=phase,
            correlated_action_sequence=correlated_action_sequence,
            target=self.target,
            snapshot=snapshot,
        )
        if not response.get("ok"):
            raise RuntimeError(response.get("error", "cluster tracer append failed"))
        return response["event"]

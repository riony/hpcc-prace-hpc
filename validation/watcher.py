"""Read-only watcher that corroborates file-ops state after each action."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from validation.observe_remote import expected_layout_detail, observe_remote_workspace
from validation.tracer.client import TracerClient


class FileOpsWatcher:
    """Interim cp2 observer corroboration (source=cluster_watcher).

    Prefer validation.cluster_tracer.ClusterTracer for the diagram feed.
    """

    def __init__(self, client: TracerClient, adapter: Any, workspace: Path, target: str):
        self.client = client
        self.adapter = adapter
        self.workspace = Path(workspace)
        self.target = target

    def corroborate(self, *, phase: str, correlated_action_sequence: int) -> dict[str, Any]:
        ok, detail, evidence = observe_remote_workspace(self.adapter, self.workspace)
        status = "match" if ok else "mismatch"
        code = "layout-final" if ok else "layout-partial-or-wrong"
        response = self.client.call(
            "append_cluster",
            source="cluster_watcher",
            phase=phase,
            correlated_action_sequence=correlated_action_sequence,
            target=self.target,
            snapshot={
                "status": status,
                "code": code,
                "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
                "detail": detail[:300],
            },
        )
        if not response.get("ok"):
            raise RuntimeError(response.get("error", "watcher append failed"))
        return response["event"]

    def final_check(self, *, check_id: str, expect_ok: bool = True) -> dict[str, Any]:
        ok, detail, evidence = observe_remote_workspace(self.adapter, self.workspace)
        status = "pass" if (ok == expect_ok) else "fail"
        response = self.client.call(
            "append_observation",
            check_id=check_id,
            target=self.target,
            status=status,
            code="workspace-layout",
            evidence=evidence.hex(),
            evidence_encoding="hex",
            detail=expected_layout_detail(ok)[:300],
        )
        if not response.get("ok"):
            raise RuntimeError(response.get("error", "observation append failed"))
        return response["event"]

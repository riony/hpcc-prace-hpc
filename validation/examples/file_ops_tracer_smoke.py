#!/usr/bin/env python3
"""End-to-end local tracer smoke: record, cluster tracer, reset, replay, report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import time

from validation.tracer.client import TracerClient


ROOT = Path(__file__).resolve().parents[2]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-id", default="smoke-tracer-001")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.output_dir.is_absolute():
        raise SystemExit("--output-dir must be absolute")
    if args.output_dir.exists():
        raise SystemExit("refusing existing output directory")
    args.output_dir.mkdir(mode=0o700, parents=True)
    socket_path = args.output_dir / "tracer.sock"
    workspace = Path("/tmp/prace-file-ops-smoke-v1")
    config = {
        "run_id": args.run_id,
        "scenario": str(ROOT / "scenarios/file-ops-smoke/v1/manifest.json"),
        "run_dir": str(args.output_dir),
        "socket_path": str(socket_path),
        "workspace": str(workspace),
        "adapter": "local",
        "adapter_config": {},
        "cluster_tracer": {
            "enabled": True,
            "adapter": "local",
            "adapter_config": {},
            "target": "local-workspace",
            "require_on_finalize": True,
        },
    }
    config_path = args.output_dir / "tracer.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    server = subprocess.Popen(
        [sys.executable, "-m", "validation.tracer", "--config", str(config_path)],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        for _ in range(50):
            if socket_path.exists():
                break
            time.sleep(0.05)
        else:
            raise SystemExit("tracer socket did not appear")
        client = TracerClient(socket_path)
        client.call("reset_workspace")
        action_ids = [
            "mkdir-demo-dir",
            "write-test-file-1",
            "write-test-file-2",
            "delete-test-file-1",
        ]
        for action_id in action_ids:
            response = client.call("execute_action", action_id=action_id, phase="record")
            if not response.get("ok"):
                raise SystemExit(response.get("error", "execute failed"))
        # Final trusted observations (verdicts); cluster_tracer events auto-appended per action.
        ok, detail, evidence = _observe_local(workspace)
        client.call(
            "append_observation",
            check_id="record-layout-ok",
            target="local-workspace",
            status="pass" if ok else "fail",
            code="workspace-layout",
            evidence=evidence.hex(),
            evidence_encoding="hex",
            detail=detail[:300],
        )
        client.call("reset_workspace")
        replay = client.call("replay")
        if not replay.get("ok"):
            raise SystemExit(replay.get("error", "replay failed"))
        ok, detail, evidence = _observe_local(workspace)
        client.call(
            "append_observation",
            check_id="replay-layout-ok",
            target="local-workspace",
            status="pass" if ok else "fail",
            code="workspace-layout",
            evidence=evidence.hex(),
            evidence_encoding="hex",
            detail=detail[:300],
        )
        client.call("reset_workspace")
        empty = not any(workspace.rglob("*")) if workspace.exists() else True
        client.call(
            "append_observation",
            check_id="workspace-reset",
            target="local-workspace",
            status="pass" if empty else "fail",
            code="workspace-empty",
            evidence=("empty" if empty else "dirty").encode().hex(),
            evidence_encoding="hex",
            detail="smoke workspace emptied after reports",
        )
        final = client.call("finalize", replace_generated=True, require_cluster_tracer=True)
        if not final.get("ok"):
            raise SystemExit(final.get("error", "finalize failed"))
        result = final["result"]
        status = client.call("status")
        print(
            f"PASS smoke tracer {args.run_id} "
            f"functional={result['verdicts']['functional']} cleanup={result['cleanup']} "
            f"cluster_tracer={status.get('cluster_tracer_count', final.get('cluster_tracer_count'))}"
        )
        return 0 if result["verdicts"]["functional"] == "pass" and result["cleanup"] == "complete" else 1
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()


def _observe_local(workspace: Path) -> tuple[bool, str, bytes]:
    from validation.local_fs import observe_workspace
    return observe_workspace(workspace)


if __name__ == "__main__":
    raise SystemExit(main())

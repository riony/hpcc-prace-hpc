#!/usr/bin/env python3
"""Offline/local smoke demo: record, reset, replay, and report ordinary file ops."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from validation.contracts import load_scenario
from validation.local_fs import LocalFsAdapter, observe_workspace, reset_workspace
from validation.observe import make_observation_event
from validation.replay import ReplayRunner, make_action_event, resolve_action
from validation.report import write_reports
from validation.trace import TraceWriter
from validation.verdict import build_result


ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "scenarios/file-ops-smoke/v1/manifest.json"
WORKSPACE = Path("/tmp/prace-file-ops-smoke-v1")
RUN_ID = "smoke-20261004-file-ops-001"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--run-id", default=RUN_ID)
    args = parser.parse_args()
    if not args.output_dir.is_absolute():
        parser.error("--output-dir must be absolute")
    return args


def main() -> int:
    args = parse_args()
    if args.output_dir.exists() or args.output_dir.is_symlink():
        raise SystemExit("refusing existing output directory")
    args.output_dir.mkdir(mode=0o700, parents=True)
    manifest = load_scenario(SCENARIO)
    writer = TraceWriter(args.output_dir / "events.jsonl", manifest, args.run_id)
    adapter = LocalFsAdapter()

    reset_workspace(WORKSPACE)
    record_events = []
    bindings: dict[str, str] = {}
    for template in manifest["actions"]:
        resolved = resolve_action(template, bindings, manifest)
        result = adapter.execute(template["id"], resolved, template["timeout_seconds"])
        if result.status != "ok":
            raise SystemExit(f"record failed at {template['id']}: {result.status}")
        event = make_action_event(
            scenario=manifest,
            run_id=args.run_id,
            sequence=writer.next_sequence,
            phase="record",
            template=template,
            resolved_action=resolved,
            result=result,
        )
        writer.append(event)
        record_events.append(event)
        bindings.update(event["result"]["bindings"])

    ok, detail, evidence = observe_workspace(WORKSPACE)
    writer.append(make_observation_event(
        scenario=manifest,
        run_id=args.run_id,
        sequence=writer.next_sequence,
        check_id="record-layout-ok",
        target="local-workspace",
        status="pass" if ok else "fail",
        code="record-layout",
        evidence=evidence,
        detail=detail,
    ))
    if not ok:
        raise SystemExit("record observation failed")

    reset_workspace(WORKSPACE)
    ReplayRunner(manifest, record_events, writer, adapter).run()
    ok, detail, evidence = observe_workspace(WORKSPACE)
    writer.append(make_observation_event(
        scenario=manifest,
        run_id=args.run_id,
        sequence=writer.next_sequence,
        check_id="replay-layout-ok",
        target="local-workspace",
        status="pass" if ok else "fail",
        code="replay-layout",
        evidence=evidence,
        detail=detail,
    ))
    if not ok:
        raise SystemExit("replay observation failed")

    reset_workspace(WORKSPACE)
    writer.append(make_observation_event(
        scenario=manifest,
        run_id=args.run_id,
        sequence=writer.next_sequence,
        check_id="workspace-reset",
        target="local-workspace",
        status="pass",
        code="workspace-empty",
        evidence=b"workspace-reset",
        detail="smoke workspace emptied after reports",
    ))

    result = build_result(
        scenario=manifest,
        events=writer.events,
        trace_path=writer.path,
        baseline_revision="smoke-no-security-baseline",
        patch_revision="smoke-no-security-patch",
    )
    write_reports(args.output_dir, manifest, result, writer.events)
    metadata = {
        "schema": "prace.offline-demo.v1",
        "run_id": args.run_id,
        "network_used": False,
        "fleet_contacted": False,
        "credentials_used": False,
        "security_claim": False,
        "claim": "file-ops smoke for trace/replay/report only; not a security result",
    }
    (args.output_dir / "demo-metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    print(f"PASS smoke demo written to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

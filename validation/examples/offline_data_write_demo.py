#!/usr/bin/env python3
"""Generate a sanitized, no-network Component 4 data-write demonstration."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from validation.contracts import load_scenario
from validation.observe import make_observation_event
from validation.replay import AdapterResult, FakeAdapter, ReplayRunner, make_action_event, resolve_action
from validation.report import write_reports
from validation.trace import TraceWriter
from validation.verdict import build_result


ROOT = Path(__file__).resolve().parents[2]
SCENARIO = ROOT / "scenarios/unauthorized-data-write/v1/manifest.json"
RUN_ID = "offline-20261003-udw-001"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", required=True, type=Path)
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
    writer = TraceWriter(args.output_dir / "events.jsonl", manifest, RUN_ID)

    attack_events = []
    attack_results = {
        "find-writable-target": AdapterResult("ok", 0, stdout=b"synthetic fixture found\n", duration_ms=2),
        "write-synthetic-marker": AdapterResult("ok", 0, duration_ms=3),
    }
    for template in manifest["actions"]:
        event = make_action_event(
            scenario=manifest,
            run_id=RUN_ID,
            sequence=writer.next_sequence,
            phase="attack",
            template=template,
            resolved_action=resolve_action(template, {}, manifest),
            result=attack_results[template["id"]],
        )
        writer.append(event)
        attack_events.append(event)

    patched = FakeAdapter({
        "find-writable-target": AdapterResult("ok", 0, duration_ms=2),
        "write-synthetic-marker": AdapterResult("denied", 13, stderr=b"permission denied", duration_ms=2),
    })
    ReplayRunner(manifest, attack_events, writer, patched).run()

    observations = [
        ("vulnerable-marker-present", "storage-server", "marker-match", b"marker-present"),
        ("patched-write-blocked", "storage-server", "authorization-denied", b"marker-absent"),
        ("alpha-authorized-write", "login-pod", "authorized-alpha-ok", b"alpha-write-clean"),
        ("beta-authorized-write", "login-pod", "authorized-beta-ok", b"beta-write-clean"),
        ("normal-project-job", "slurm-controller", "job-completed", b"synthetic-job-completed"),
        ("metadata-reset", "storage-server", "baseline-match", b"metadata-and-quota-match"),
    ]
    for check_id, target, code, evidence in observations:
        writer.append(make_observation_event(
            scenario=manifest,
            run_id=RUN_ID,
            sequence=writer.next_sequence,
            check_id=check_id,
            target=target,
            status="pass",
            code=code,
            evidence=evidence,
            detail="offline synthetic fixture",
        ))

    result = build_result(
        scenario=manifest,
        events=writer.events,
        trace_path=writer.path,
        baseline_revision="offline-vulnerable-fixture-v1",
        patch_revision="offline-acl-patch-v1",
    )
    write_reports(args.output_dir, manifest, result, writer.events)
    metadata = {
        "schema": "prace.offline-demo.v1",
        "run_id": RUN_ID,
        "network_used": False,
        "fleet_contacted": False,
        "credentials_used": False,
        "claim": "interface and replay demonstration only; not physical scenario evidence",
    }
    path = args.output_dir / "demo-metadata.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(fd, "w") as output:
        json.dump(metadata, output, indent=2, sort_keys=True)
        output.write("\n")
    print(args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Sanitized machine-readable result and recorded-playback report."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .contracts import require


def render_markdown(
    scenario: dict[str, Any],
    result: dict[str, Any],
    events: list[dict[str, Any]],
) -> str:
    verdicts = result["verdicts"]
    smoke = scenario["status"] == "smoke"
    lines = [
        f"# PRACE-HPC run {result['run_id']}",
        "",
        "Recorded playback only. This report does not execute an action or prove a fresh run.",
        "",
    ]
    if smoke:
        lines.extend([
            "This is a **smoke** run. It does not claim a security finding or a patched defence.",
            "",
        ])
    lines.extend([
        f"- Scenario: `{scenario['id']}` v{scenario['version']} :  {scenario['title']}",
        f"- Baseline revision: `{result['baseline_revision']}`",
        f"- Patch revision: `{result['patch_revision']}`",
        f"- Baseline security: **{verdicts['baseline']}**",
        f"- Patched security: **{verdicts['patched']}**",
        f"- Functional result: **{verdicts['functional']}**",
        f"- Cleanup/reset: **{result['cleanup']}**",
        "",
        "## Timeline",
        "",
    ])
    for event in events:
        stamp = event["timestamp"]
        if event["event_type"] == "action":
            row = event["result"]
            lines.append(
                f"- `{stamp}` ACTION `{event['phase']}/{event['action_id']}` "
                f"on `{event['action']['target']}`: **{row['status']}** "
                f"(exit={row['exit_code']}, executed={row['executed_sha256'][:12]})"
            )
        elif event["event_type"] == "cluster":
            row = event["snapshot"]
            source = event.get("source", "cluster_tracer")
            lines.append(
                f"- `{stamp}` CLUSTER/{source} `{event['phase']}` "
                f"corr={event['correlated_action_sequence']} "
                f"on `{event['target']}`: **{row['status']}** (`{row['code']}`)"
            )
        else:
            row = event["observation"]
            lines.append(
                f"- `{stamp}` CHECK `{event['phase']}/{event['check_id']}` "
                f"on `{event['target']}`: **{row['status']}** (`{row['code']}`)"
            )
    lines.extend([
        "",
        "## Trust limits",
        "",
        "- `cluster_tracer` events are the cluster-side feed (pinned observe helper).",
        "- `cluster_watcher` events are interim cp2 observer corroboration only.",
        "- Neither proves complete host telemetry or catches every bypass route.",
        "- Security verdicts for smoke runs are `not_applicable`.",
        "",
        "## Integrity",
        "",
        f"- Scenario SHA-256: `{result['scenario_sha256']}`",
        f"- Trace SHA-256: `{result['trace_sha256']}`",
        "",
    ])
    return "\n".join(lines)


def _atomic_write(path: Path, data: bytes, *, replace: bool) -> None:
    require(not path.is_symlink(), f"{path}: symlink refused")
    if path.exists() and not replace:
        raise FileExistsError(path)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    require(not temporary.exists() and not temporary.is_symlink(), f"{temporary}: temporary path exists")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    try:
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)


def write_reports(
    run_dir: Path,
    scenario: dict[str, Any],
    result: dict[str, Any],
    events: list[dict[str, Any]],
    *,
    replace: bool = False,
) -> tuple[Path, Path]:
    run_dir = Path(run_dir)
    info = run_dir.lstat()
    require(run_dir.is_dir() and not run_dir.is_symlink() and info.st_uid == os.getuid(),
            "run directory must be a caller-owned regular directory")
    json_path = run_dir / "result.json"
    markdown_path = run_dir / "report.md"
    require(replace or (not json_path.exists() and not markdown_path.exists()),
            "generated report already exists")
    _atomic_write(json_path, json.dumps(result, indent=2, sort_keys=True).encode() + b"\n", replace=replace)
    try:
        _atomic_write(markdown_path, render_markdown(scenario, result, events).encode(), replace=replace)
    except Exception:
        if not replace:
            json_path.unlink(missing_ok=True)
        raise
    return json_path, markdown_path

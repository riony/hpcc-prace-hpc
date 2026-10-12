"""Command-line entry point for offline trace validation and report generation."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .contracts import ContractError, load_scenario
from .report import write_reports
from .trace import read_events
from .verdict import build_result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--scenario", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--baseline-revision", required=True)
    parser.add_argument("--patch-revision", required=True)
    parser.add_argument("--replace-generated", action="store_true")
    args = parser.parse_args(argv)
    if not args.run_dir.is_absolute():
        parser.error("--run-dir must be absolute")
    if not args.baseline_revision.strip() or not args.patch_revision.strip():
        parser.error("revisions must not be blank")
    return args


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        scenario = load_scenario(args.scenario)
        trace_path = args.run_dir / "events.jsonl"
        events = read_events(trace_path, scenario)
        result = build_result(
            scenario=scenario,
            events=events,
            trace_path=trace_path,
            baseline_revision=args.baseline_revision,
            patch_revision=args.patch_revision,
        )
        write_reports(args.run_dir, scenario, result, events, replace=args.replace_generated)
    except (ContractError, FileExistsError, OSError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2

    verdicts = result["verdicts"]
    if scenario["status"] == "smoke":
        passed = (
            verdicts["baseline"] == "not_applicable"
            and verdicts["patched"] == "not_applicable"
            and verdicts["functional"] == "pass"
            and result["cleanup"] == "complete"
        )
    else:
        passed = (
            verdicts["baseline"] == "security_failure"
            and verdicts["patched"] == "security_blocked"
            and verdicts["functional"] == "pass"
            and result["cleanup"] == "complete"
        )
    kind = "smoke " if scenario["status"] == "smoke" else ""
    print(
        f"{'PASS' if passed else 'FAIL'}: {kind}{result['run_id']} "
        f"baseline={verdicts['baseline']} patched={verdicts['patched']} "
        f"functional={verdicts['functional']} cleanup={result['cleanup']}"
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())

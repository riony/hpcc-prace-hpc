"""Run, independently verify, pack and export one benign harness smoke.

Outputs stay in a new private directory outside the checkout. Remote execution
requires an explicit SSH configuration and --allow-remote. This command never
deploys a helper, edits infrastructure or refreshes the hosted dashboard.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def run_smoke(output: Path, run_id: str, *, driver: str | None = None, workflow: str = 'smoke',
              ssh_config: Path | None = None, allow_remote: bool = False,
              execute=None) -> dict:
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", run_id):
        raise ValueError("run ID must start with a lowercase letter and contain at most 40 letters, digits or hyphens")
    if bool(ssh_config) != allow_remote:
        raise ValueError("remote smoke requires both --ssh-config and --allow-remote")
    if workflow not in {'smoke', 'researcher', 'diagnostic'} or (workflow in {'researcher','diagnostic'} and not ssh_config):
        raise ValueError('researcher workflow requires explicit SSH inputs')
    driver = driver or ('scripted' if workflow in {'researcher','diagnostic'} else 'nemo')
    if workflow == 'diagnostic' and driver != 'scripted':
        raise ValueError('diagnostic mode requires scripted driver')
    if driver not in ("nemo", "scripted"):
        raise ValueError("unknown driver")
    if not output.is_absolute():
        raise ValueError("output directory must be absolute")
    if any(p.is_symlink() for p in (output, *output.parents)):
        raise ValueError("output directory has a symlink component")
    if output.resolve() == ROOT or ROOT in output.resolve().parents:
        raise ValueError("output must be outside the source checkout")
    if not output.parent.is_dir() or output.exists():
        raise ValueError("output requires an existing parent and a new directory")
    if ssh_config and (not ssh_config.is_file() or ssh_config.stat().st_mode & 0o077):
        raise ValueError("SSH configuration must be an existing private file (0600)")
    plan = ROOT / "harness/examples" / ("cluster-smoke.plan.json" if ssh_config else "file-discovery.plan.json")
    if workflow == 'researcher':
        plan = ROOT / 'harness/examples/researcher-workflow.plan.json'
    run, bundle, evidence = output / "run", output / "bundle", output / "evidence"
    commands = [
        [sys.executable, "-m", "harness", "--plan", str(plan), "--driver", driver,
         "--run-id", run_id, "--output-dir", str(run)],
        [sys.executable, "-m", "harness.scenario_run", "--run-dir", str(run)],
        [sys.executable, "-m", "harness.evidence", "pack", "--run-dir", str(run), "--output-dir", str(bundle)],
        [sys.executable, "-m", "harness.evidence", "verify", "--bundle-dir", str(bundle)],
        [sys.executable, str(ROOT / "infra/tools/scenario-export.py"), "--bundle-dir", str(bundle),
         "--evidence-root", str(evidence)],
    ]
    if workflow == 'diagnostic':
        commands[0] = [sys.executable, '-m', 'harness.diagnostic', '--run-id', run_id, '--output-dir', str(run)]
        commands[1] = [sys.executable, '-m', 'harness.diagnostic', '--run-dir', str(run)]
    if ssh_config:
        commands[0] += ["--ssh-config", str(ssh_config), "--allow-remote"]
    execute = execute or (lambda argv: subprocess.run(argv, cwd=ROOT, check=True))
    mask = os.umask(0o077)
    try:
        output.mkdir(mode=0o700)
        evidence.mkdir(mode=0o700)
        # No later stage runs after an error. Keep all partial evidence for diagnosis.
        for number, command in enumerate(commands, 1):
            print(f"smoke stage {number}/5", flush=True)
            execute(command)
        summary = {"schema": "prace.smoke-workflow.v1", "run_id": run_id,
                   "transport": "ssh" if ssh_config else "local", "driver": driver,
                   "verified": workflow != "diagnostic", "run": str(run), "bundle": str(bundle),
                   "dashboard_evidence": str(evidence), "hosted_dashboard_refreshed": False}
        summary['workflow'] = workflow
        if workflow == 'diagnostic':
            summary.update(trace_checks='PASS', independent_verification='SKIPPED', overall='UNVERIFIED')
        with (output / "summary.json").open("x", encoding="utf-8") as stream:
            json.dump(summary, stream, indent=2)
            stream.write("\n")
        return summary
    finally:
        os.umask(mask)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--driver", choices=("nemo", "scripted"))
    parser.add_argument('--workflow', choices=('smoke', 'researcher', 'diagnostic'), default='smoke')
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--allow-remote", action="store_true")
    args = parser.parse_args(argv)
    try:
        summary = run_smoke(args.output_dir, args.run_id, driver=args.driver, workflow=args.workflow,
                            ssh_config=args.ssh_config, allow_remote=args.allow_remote)
    except (ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"STOP: smoke workflow failed; retain its output directory: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

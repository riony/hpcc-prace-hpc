#!/usr/bin/env python3
"""Offline normal-researcher control for the simulated security scenario (Session B, 8 Oct 2026).

The control is the ordinary researcher workflow the security scenario is compared against. It runs merged
main's syn-alice plan (harness/examples/researcher-workflow.plan.json: list modules, copy the site's CPU and GPU
examples, submit both, wait, read and keep the results) through the NeMo session service (`nat serve` with
harness/examples/nat-session.yml) and its local client (harness.session_client): record the 13 declared actions,
reset, replay them model-free through NeMo with fresh job IDs, run the independent observer checks, clean up,
then verify, pack and export the bundle with a private dashboard preview.

Nothing contacts the cluster or a model. SSH and Slurm are the reviewed stand-in from harness/tests at the same
source revision (a fake `ssh` on PATH that runs the pinned helper against a scratch filesystem and a simulated
scheduler whose job IDs start at 8101), so every job ID and scheduler fact here is a SIMULATED SCHEDULER RESULT,
not a cluster job. control.json says so, records the exact source, stand-in file hashes and commands, maps each
recorded job ID to its replayed one, and names the reused live recording this control stands beside.

Everything is written privately (0700/0600) under --output; nothing is published. The generated dashboard
export explicitly records stand-in execution and simulated job IDs. A publishable flag means its provenance
is correctly labelled, not permission to upload the private logs or publish without review.

  <nat-venv>/bin/python infra/tools/researcher-control-offline.py --output /absolute/new/dir [--run-id ID]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
PLAN = "harness/examples/researcher-workflow.plan.json"
STAND_IN = ("harness/tests/test_scenarios.py", "harness/tests/researcher_scheduler_fixture.py.txt",
            "harness/tests/test_researcher_workflow.py", "harness/tests/test_syn_alice_workflow.py")
REUSED = [{"folder": "evidence/2026-10-07/researcher-desktop-20261008b", "label": "reused recording",
           "what": "the same CPU/GPU researcher workflow typed by a person on PRACE over the real login route "
                   "(jobs 1278/1279) and its command replay (jobs 1280/1281), bound to controller accounting; "
                   "a live human session, not this agent control"}]


class Stop(Exception):
    pass


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


def service_config(template: str, run_root: Path, ssh_config: Path) -> str:
    """the shipped example with only the run root, plan and SSH roles changed; any drift in the template stops"""
    out = template
    for old, new in (("/tmp/prace-nat-sessions", str(run_root)),
                     ("plan: harness/examples/file-discovery.plan.json", f"plan: {ROOT / PLAN}"),
                     ("allow_remote: false", f"allow_remote: true\n  ssh_config: {ssh_config}")):
        if out.count(old) != 1:
            raise Stop(f"harness/examples/nat-session.yml changed: expected one {old!r}")
        out = out.replace(old, new)
    return out


def job_remap(events: list[dict]) -> list[dict]:
    """each submission's recorded job ID next to the ID its replay received (simulated scheduler)"""
    rows: dict[str, dict] = {}
    for event in events:
        if event.get("event_type") != "action" or event["action"]["kind"] != "slurm.submit-example":
            continue
        jobs = [v for k, v in event["result"]["bindings"].items() if k.endswith("job_id")]
        if len(jobs) != 1 or event["phase"] not in {"record", "replay"}:
            raise Stop(f"submission {event['action_id']} has no single job binding")
        row = rows.setdefault(event["action_id"], {"action_id": event["action_id"]})
        if event["phase"] in row or not isinstance(jobs[0], str) or not re.fullmatch(r"[1-9][0-9]{0,11}", jobs[0]):
            raise Stop("duplicated submission or invalid job ID")
        row[event["phase"]] = jobs[0]
    out = list(rows.values())
    if not out or any(set(row) != {"action_id", "record", "replay"} for row in out):
        raise Stop("every submission needs a recorded and a replayed job ID")
    if {row["record"] for row in out} & {row["replay"] for row in out} or len({row["replay"] for row in out}) != len(out) or len({row["record"] for row in out}) != len(out):
        raise Stop("replayed job IDs must be fresh and distinct")
    return out


def private_copy(source: Path, target: Path) -> None:
    shutil.copytree(source, target, symlinks=True)
    for path in [target, *target.rglob("*")]:
        if not path.is_symlink():
            path.chmod(0o700 if path.is_dir() else 0o600)


def run_client(python: str, url: str, args: list[str], log: Path) -> int:
    with log.open("w") as stream:
        result = subprocess.run([python, "-m", "harness.session_client", "--url", url, "--poll", "0.5", *args],
                                cwd=ROOT, stdout=stream, stderr=subprocess.STDOUT, timeout=1800)
    log.chmod(0o600)
    return result.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", default="researcher-control-" + time.strftime("%Y%m%d-%H%M%S"))
    parser.add_argument("--allow-dirty", action="store_true", help="development only; recorded in control.json")
    args = parser.parse_args(argv)
    output = args.output
    if not output.is_absolute() or output.exists() or output.is_symlink():
        print("STOP: --output must be a new absolute directory", file=sys.stderr)
        return 2
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}", args.run_id):
        print("STOP: run ID: letters, digits, '-' or '_', at most 32", file=sys.stderr)
        return 2
    dirty = bool(git("status", "--porcelain"))
    if dirty and not args.allow_dirty:
        print("STOP: the control runs from a clean checkout (commit or stash first)", file=sys.stderr)
        return 2
    revision = git("rev-parse", "HEAD")
    nat = Path(sys.executable).with_name("nat")
    if not nat.exists():
        print("STOP: run this with the pinned NeMo environment's python (its `nat` was not found)", file=sys.stderr)
        return 2
    output.mkdir(mode=0o700, parents=True)
    sys.path[:0] = [str(ROOT), str(ROOT / "harness/tests")]
    from harness.tests.test_syn_alice_workflow import SynAlice   # the reviewed stand-in, unchanged
    from harness.nemo_config import NAT_VERSION
    from harness.evidence import verify_bundle
    case = SynAlice("test_whole_scripted_workflow_packs_reverifies_and_dashboard_accepts")
    case.setUp()   # fake ssh on PATH, scratch filesystem, simulated scheduler, three role entries (no keys)
    server = server_log = None
    try:
        root = case.root
        (root / "service.yml").write_text(service_config((ROOT / "harness/examples/nat-session.yml").read_text(),
                                                         root / "sessions", case.config))
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        url = f"http://127.0.0.1:{port}"
        serve = [str(nat), "serve", "--config_file", str(root / "service.yml"), "--host", "127.0.0.1",
                 "--port", str(port), "--workers", "1"]
        server_log = (output / "server.log").open("w")
        server = subprocess.Popen(serve, cwd=ROOT, stdout=server_log, stderr=server_log, start_new_session=True)
        deadline = time.monotonic() + 60
        while True:
            if server.poll() is not None:
                raise Stop("nat serve exited; see server.log")
            try:
                with urllib.request.urlopen(url + "/health", timeout=1):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise Stop("nat serve did not become healthy")
                time.sleep(.25)
        codes = {"start": run_client(sys.executable, url, ["start", args.run_id], output / "start.log"),
                 "export": None}
        if codes["start"] == 0:
            codes["export"] = run_client(sys.executable, url, ["export", args.run_id, "--preview", str(root / "preview")],
                                         output / "export.log")
        session = root / "sessions" / args.run_id
        if session.exists():
            private_copy(session, output / "session")
        if (root / "preview/site").exists():
            private_copy(root / "preview/site", output / "preview")
        shutil.copyfile(case.calls, output / "stand-in-calls.jsonl")
        (output / "stand-in-calls.jsonl").chmod(0o600)
        if codes != {"start": 0, "export": 0}:
            raise Stop(f"client exit codes {codes}; see start.log/export.log and the retained session")

        receipt = json.loads((output / "session/session.json").read_text())
        run_dir = output / "session/run"
        events = [json.loads(line) for line in (run_dir / "events.jsonl").read_text().splitlines()]
        replay = json.loads((run_dir / "agent-replay-trace.json").read_text())
        bundle = verify_bundle(output / "session/bundle")
        calls = [json.loads(line) for line in (output / "stand-in-calls.jsonl").read_text().splitlines()]
        roles = {row.get("role") for row in calls}
        if not (receipt["status"] == "complete" and receipt["llm_used"] is False and receipt["replay_llm_used"] is False
                and receipt["cleanup"] == "complete" and replay["model_used"] is False
                and replay["replayed"] == sum(e["event_type"] == "action" and e["phase"] == "record" for e in events)
                and roles <= {"prace-actor", "prace-tracer", "prace-observer"}):
            raise Stop("the control did not complete as a model-free, stand-in-only record and replay")
        export = next((output / "session/evidence").glob(f"*/{args.run_id}"))
        control = {
            "schema": "prace.researcher-control.v1", "run_id": args.run_id, "generated_at": time.time(),
            "purpose": "normal researcher control for the simulated security scenario",
            "source": {"revision": revision, "dirty": dirty, "plan": PLAN, "nemo_version": NAT_VERSION,
                       "stand_in": {path: git("hash-object", path) for path in STAND_IN}},
            "environment": {"kind": "offline-stand-in", "cluster_contacted": False, "model_used": False,
                            "ssh": "stand-in (fake ssh on PATH running the pinned helper locally)",
                            "scheduler": "simulated (harness/tests/researcher_scheduler_fixture.py.txt); job IDs are not cluster jobs",
                            "stand_in_roles_called": sorted(roles), "stand_in_calls": len(calls)},
            "commands": [serve[:2] + ["--config_file", "<scratch>/service.yml"] + serve[4:],
                         ["python", "-m", "harness.session_client", "--url", "http://127.0.0.1:<port>", "start", args.run_id],
                         ["python", "-m", "harness.session_client", "--url", "http://127.0.0.1:<port>", "export", args.run_id,
                          "--preview", "<scratch>/preview"]],
            "receipt": receipt,
            "record": {"actions": sum(e["event_type"] == "action" and e["phase"] == "record" for e in events),
                       "driver": "nemo (model-free rehearsal)"},
            "replay": {"driver": "nemo stepped replay (model-free)", "replayed": replay["replayed"],
                       "model_used": replay["model_used"], "raw_trace_sha256": replay["raw_trace_sha256"]},
            "job_remap": job_remap(events),
            "checks": [{"check_id": e["check_id"], "phase": e["phase"], "status": e["observation"]["status"]}
                       for e in events if e["event_type"] == "observation"],
            "bundle": {"verified": True, "bundle_sha256": receipt["bundle_sha256"], "run_schema": bundle["schema"]},
            "export": {"folder": f"{export.parent.name}/{export.name}",
                       "sha256sums_sha256": hashlib.sha256((export / "SHA256SUMS").read_bytes()).hexdigest(),
                       "publishable": True,
                       "qualification": "labelled simulated SSH/scheduler control; no fleet or model contact"},
            "reused_evidence": REUSED,
            "limits": ["simulated scheduler results, not cluster jobs", "no model: NeMo ran the declared sequence",
                       "independent observer checks ran against the stand-in, not the cluster",
                       "replay repeats the recorded actions with fresh job IDs; outcomes were checked, not assumed"],
        }
        if not all(row["status"] == "pass" for row in control["checks"]):
            raise Stop("an observer check did not pass")
        with (output / "control.json").open("x") as stream:
            json.dump(control, stream, indent=2)
            stream.write("\n")
        (output / "control.json").chmod(0o600)
        print(f"CONTROL COMPLETE {args.run_id} (simulated scheduler, no cluster or model): "
              f"{control['record']['actions']} recorded, {replay['replayed']} replayed by NeMo, jobs "
              + ", ".join(f"{r['record']}->{r['replay']}" for r in control["job_remap"])
              + f", {len(control['checks'])} checks pass; private output {output}")
        return 0
    except Stop as error:
        print(f"STOP: {error}; partial output retained in {output}", file=sys.stderr)
        return 1
    finally:
        if server is not None and server.poll() is None:
            os.killpg(server.pid, signal.SIGTERM)
            try:
                server.wait(10)
            except subprocess.TimeoutExpired:
                os.killpg(server.pid, signal.SIGKILL)
                server.wait()
        if server_log is not None:
            server_log.close()
            (output / "server.log").chmod(0o600)
        case.doCleanups()


if __name__ == "__main__":
    raise SystemExit(main())

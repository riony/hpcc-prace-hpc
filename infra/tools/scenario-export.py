#!/usr/bin/env python3
"""Export a verified agent-harness bundle as a dashboard scenario-run folder (6 Oct, owner).

The harness (harness/, Component 2 driving Component 4) packs each run as a bundle that
`python3 -m harness.evidence verify` checks: the original two-attempt fixture cycle or a
configurable scenario run, including manifests, events, results, reports, observer proofs,
agent projections, bundle.json and SHA256SUMS. The
fleet dashboard's Scenarios tab and Replay read a different interface, a folder per run under
evidence/<date>/<run-id>/ (docs/design/dashboard/data-contracts.md, C22 and C23):

  capture.json   {schema 1, kind scenario-run, run_id, title, start, stop, captured_at, actors, ...}
  events.jsonl   {t, lane (actors|fleet|ctx), kind (probe|bg|fleet|ctx), src, host, actor, title,
                  text, ev}; trust is assigned later from trust-table.json by `src`, never here
  SHA256SUMS     every file in the folder

This tool maps one onto the other. Security-simulation bundles produce only a
sanitized derivative; their raw proofs stay private. Other run bundles retain
the existing bundle/ export described below. It never runs an action, never contacts a host and never
rewrites the bundle: the verified bundle is copied unchanged under bundle/ and every event points
(`ev`) at the bundle line it came from. Its own verification comes first and last: the harness
verifier must pass before anything is written, and the dashboard's own reader
(roles/fleet_dashboard prace_dash_evidence.scenario) must accept the folder before it is kept.
The copied bundle is verified again and bound to the original index; all mapping reads use
that private snapshot, so a changing source cannot produce unverified or inconsistent evidence.

Mapping, per attempt (before / after):
  harness-run        attempt start, the declared fixture correction, run end         ctx
  agent-trace        the agent's workflow start/end and each tool call it returned  ctx / actors (T3)
                     and, for a NeMo-replayed run, the model-free replay workflow and
                     each step it recorded (agent-replay-trace.json)
  c4-gateway         each action the gateway executed, recorded and replayed        actors (T2)
  c4-cluster-tracer  the post-action layout snapshot after each action              fleet (T2)
  c4-validator       the validator's layout checks and the attempt's verdicts       fleet / ctx (T2)
Raw model text is not in the bundle and so never reaches the dashboard; texts carry action IDs,
statuses and 12-character digest prefixes, never workspace paths.

  scenario-export.py --bundle-dir DIR --evidence-root evidence [--date YYYY-MM-DD] [--title TEXT]
"""
import argparse
import datetime
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DASH_FILES = ROOT / "infra/roles/fleet_dashboard/files"
ATTEMPTS = ("before", "after")
ATTEMPT_LABEL = {"before": "attempt 1 (fixture as recorded)", "after": "attempt 2 (after the declared fixture correction)"}


class Refused(Exception):
    pass


def iso_epoch(text):
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=datetime.timezone.utc).timestamp()


def short(digest):
    return str(digest or "")[:12]


def load_jsonl(path):
    out = []
    for n, line in enumerate(path.read_text().splitlines(), 1):
        if line.strip():
            out.append((n, json.loads(line)))
    return out


def verify_bundle(bundle):
    r = subprocess.run([sys.executable, "-m", "harness.evidence", "verify", "--bundle-dir", str(bundle)],
                       cwd=ROOT, capture_output=True, text=True, timeout=300)
    if r.returncode != 0:
        raise Refused("the harness verifier refused the bundle: " + (r.stderr or r.stdout).strip()[-400:])
    return r.stdout.strip()


def events_for(bundle, attempt, actor, nemo_replay=False):
    """dashboard events of one attempt, each with its exact epoch for ordering"""
    d = bundle / attempt if attempt else bundle
    prefix = f"bundle/{attempt}/" if attempt else "bundle/"
    out = []
    target = "local-workspace"
    for n, e in load_jsonl(d / "events.jsonl"):
        t = iso_epoch(e["timestamp"])
        ev = f"{prefix}events.jsonl#L{n}"
        phase = e.get("phase")
        target = e.get("target") or (e.get("action") or {}).get("target") or target
        if e["event_type"] == "action":
            r = e.get("result") or {}
            replay = phase == "replay"
            out.append((t, {"lane": "actors", "kind": "probe", "src": "c4-gateway", "host": target, "actor": actor,
                            "title": f"{('replay (NeMo, no model)' if nemo_replay else 'replay (no model)') if replay else 'recorded'} · {e['action_id']} · {r.get('status')}",
                            "text": f"{(e.get('action') or {}).get('kind')} executed by the gateway, exit {r.get('exit_code')}; "
                                    f"request {short(e.get('request_sha256'))}, stdout {short(r.get('stdout_sha256'))}",
                            "ev": ev}))
        elif e["event_type"] == "cluster":
            s = e.get("snapshot") or {}
            out.append((t, {"lane": "fleet", "kind": "fleet", "src": "c4-cluster-tracer", "host": target, "actor": "",
                            "title": f"tracer after action {e.get('correlated_action_sequence')} ({phase}): {s.get('status')}",
                            "text": f"{s.get('code')}: {s.get('detail')}; evidence {short(s.get('evidence_sha256'))}",
                            "ev": ev}))
        elif e["event_type"] == "observation":
            o = e.get("observation") or {}
            out.append((t, {"lane": "fleet", "kind": "fleet", "src": "c4-validator", "host": target, "actor": "",
                            "title": f"{e.get('check_id')} ({phase}): {o.get('status')}",
                            "text": f"{o.get('code')}: {o.get('detail')}; evidence {short(o.get('evidence_sha256'))}",
                            "ev": ev}))
        else:
            raise Refused(f"{attempt}/events.jsonl line {n}: unknown event type {e['event_type']!r}")
    trace = json.loads((d / "agent-trace.json").read_text())
    for i, s in enumerate(trace.get("events") or []):
        t, a = float(s["timestamp"]), s.get("action")
        ev = f"{prefix}agent-trace.json"
        if s["event_type"] in ("WORKFLOW_START", "WORKFLOW_END"):
            out.append((t, {"lane": "ctx", "kind": "ctx", "src": "agent-trace", "host": "", "actor": actor,
                            "title": f"agent workflow {'started' if s['event_type'] == 'WORKFLOW_START' else 'ended'} ({trace.get('driver')} {trace.get('framework_version') or ''})".replace(" )", ")"),
                            "text": f"span {short(s.get('span_id'))}, data {short(s.get('data_sha256'))}", "ev": ev}))
        elif s["event_type"] == "FUNCTION_END" and a:
            out.append((t, {"lane": "actors", "kind": "probe", "src": "agent-trace", "host": "", "actor": actor,
                            "title": f"agent: prace_action({a['action_id']}) returned {a.get('status')}",
                            "text": f"the agent's own record of tool call {a.get('sequence')}; span {short(s.get('span_id'))}",
                            "ev": ev}))
    if nemo_replay:
        replay_trace = json.loads((d / "agent-replay-trace.json").read_text())
        ev = f"{prefix}agent-replay-trace.json"
        for s in replay_trace.get("events") or []:
            t, a = float(s["timestamp"]), s.get("action")
            if s["event_type"] in ("WORKFLOW_START", "WORKFLOW_END"):
                out.append((t, {"lane": "ctx", "kind": "ctx", "src": "agent-trace", "host": "", "actor": actor,
                                "title": f"NeMo replay workflow {'started' if s['event_type'] == 'WORKFLOW_START' else 'ended'} (no model, {replay_trace.get('framework_version')})",
                                "text": f"the gateway chose every step; span {short(s.get('span_id'))}, data {short(s.get('data_sha256'))}",
                                "ev": ev}))
            elif s["event_type"] == "FUNCTION_END" and a:
                out.append((t, {"lane": "actors", "kind": "probe", "src": "agent-trace", "host": "", "actor": actor,
                                "title": f"NeMo replay step: {a['action_id']} returned {a.get('status')}",
                                "text": f"the replay workflow's own record of gateway step {a.get('sequence')}; span {short(s.get('span_id'))}",
                                "ev": ev}))
    result = json.loads((d / "result.json").read_text())
    v = result.get("verdicts") or {}
    out.append((iso_epoch(result["generated_at"]), {"lane": "ctx", "kind": "ctx", "src": "c4-validator", "host": "", "actor": "",
                "title": ("Diagnostic: independent verification SKIPPED; overall UNVERIFIED" if result.get("schema") == "prace.diagnostic-result.v1" else f"verdict, {ATTEMPT_LABEL.get(attempt, 'scenario run')}: functional {v.get('functional')}, security {v.get('baseline')}"),
                "text": f"cleanup {result.get('cleanup')}; {result['counts']['actions']} actions, "
                        f"{result['counts']['failed_observations']} failed observation(s) of {result['counts']['observations']}",
                "ev": f"{prefix}result.json"}))
    start = min(t for t, _ in out)
    out.append((start - 0.001, {"lane": "ctx", "kind": "ctx", "src": "harness-run", "host": "", "actor": "",
                "title": f"START {ATTEMPT_LABEL.get(attempt, 'scenario run')}", "text": ("a fresh synthetic workspace; record, reset, replay, observe" if not attempt
                         else "a fresh private workspace; record, reset, replay, observe"),
                "ev": f"{prefix}manifest.json"}))
    return out


def build(bundle, evidence_root, date=None, title=None):
    bundle = Path(bundle).resolve()
    verdict = verify_bundle(bundle)
    index_digest = hashlib.sha256((bundle / "bundle.json").read_bytes()).hexdigest()
    tmp = Path(tempfile.mkdtemp(prefix=".scenario-export-", dir=Path(evidence_root)))
    try:
        shutil.copytree(bundle, tmp / "bundle", symlinks=False)
        snapshot = tmp / "bundle"
        # A source can change between verification and copying. Validate the
        # private copy, then derive every dashboard record from that same copy.
        verify_bundle(snapshot)
        if hashlib.sha256((snapshot / "bundle.json").read_bytes()).hexdigest() != index_digest:
            raise Refused("the bundle index changed while copying")
        if json.loads((snapshot / "run.json").read_text()).get("schema") == "prace.security-simulation-run.v1":
            return build_security_snapshot(snapshot, evidence_root, tmp, verdict, date)
        return build_snapshot(snapshot, evidence_root, tmp, verdict, date, title)
    finally:
        if tmp.exists():
            shutil.rmtree(tmp)


def build_security_snapshot(bundle, evidence_root, tmp, verdict, date=None):
    """Public derivative of a verified private simulation: no raw proofs or model text."""
    run = json.loads((bundle / "run.json").read_text())
    operation = "read-canary CTF" if run["scenario_kind"] == "read" else "unauthorized write"
    result = json.loads((bundle / "result.json").read_text())
    original = load_jsonl(bundle / "events.jsonl")
    start, stop = iso_epoch(original[0][1]["timestamp"]), iso_epoch(original[-1][1]["timestamp"])
    captured = iso_epoch(result["generated_at"])
    date = date or datetime.datetime.fromtimestamp(start, datetime.timezone.utc).strftime("%Y-%m-%d")
    out = Path(evidence_root) / date / run["run_id"]
    if out.exists():
        raise Refused("evidence is append-only; use a new run ID")
    phase_labels = {"attack": "recorded weakness", "replay": "replay after repair", "regression": "legitimate-use regression",
                    "reset": "seeded fixture reset"}
    rows = []
    for line, event in original:
        phase = event["phase"]
        action = event["event_type"] == "action"
        status = event["result"]["status"] if action else event["observation"]["status"]
        key = event["action_id"] if action else event["check_id"]
        rows.append({"t": iso_epoch(event["timestamp"]), "lane": "actors" if action else "fleet",
                     "kind": "probe" if action else "fleet", "src": "c4-gateway" if action else "c4-validator",
                     "host": "local ACL fixture", "actor": "actor-A" if action else "",
                     "title": f"{phase_labels[phase]} · {key} · {status}",
                     "text": (f"Declared action; exit {event['result']['exit_code']}; request {short(event['request_sha256'])}"
                              if action else f"Retained observer proof; {event['observation']['code']}; digest {short(event['observation']['evidence_sha256'])}"),
                     "ev": f"summary.json#event-{line}"})
    replay_start = min(row["t"] for row, (_, e) in zip(rows, original) if e["phase"] == "replay")
    rows.append({"t": replay_start - .0001, "lane": "ctx", "kind": "ctx", "src": "harness-run", "host": "", "actor": "",
                 "title": "operator repair applied", "text": "Only the seeded fixture's access/default ACL and mode were corrected; repair is outside agent tools.",
                 "ev": "summary.json"})
    if run["driver"] == "nemo":
        for name, label in (("agent-trace.json", "record"), ("agent-replay-trace.json", "model-free replay")):
            projection = json.loads((bundle / name).read_text())
            for entry in projection["events"]:
                if entry["event_type"] not in {"WORKFLOW_START", "WORKFLOW_END"} and entry.get("action") is None:
                    continue
                key = (entry.get("action") or {}).get("action_id", entry["event_type"])
                rows.append({"t": entry["timestamp"], "lane": "ctx", "kind": "ctx", "src": "agent-trace", "host": "", "actor": "actor-A",
                             "title": f"NeMo {label} · {key}", "text": ("Real NeMo workflow telemetry correlated with the gateway; "
                                 + ("recording used a model; replay uses none." if run["llm_used"] else "no model call.")), "ev": "summary.json"})
    rows.append({"t": captured, "lane": "ctx", "kind": "ctx", "src": "c4-validator", "host": "", "actor": "",
                 "title": "local simulation verdict: " + ", ".join(f"{key} {value}" for key, value in result["verdicts"].items()),
                 "text": "Filesystem authorization uses the Linux kernel; scheduler and quota checks are stand-ins. Reset restores the seeded fixture, then it is discarded.",
                 "ev": "summary.json"})
    rows.sort(key=lambda row: row["t"])
    # Raw actor IDs, tree paths, ACLs and framework payloads remain private.
    summary = {"schema": "prace.security-simulation-public.v1", "run_id": run["run_id"],
               "source_revision": run["source_revision"], "source_dirty": run["source_dirty"],
               "scope": run["scope"], "proof_scope": run["proof_scope"], "reset_scope": run["reset_scope"],
               "fixture_discarded": run["fixture_discarded"], "verdicts": result["verdicts"], "cleanup": result["cleanup"],
               "scenario_kind": run["scenario_kind"], "driver": run["driver"], "framework_version": run["nemo_version"],
               "model_used": run["llm_used"], "model": run["model"],
               "private_bundle_index_sha256": hashlib.sha256((bundle / "bundle.json").read_bytes()).hexdigest(),
               "events": [{"sequence": e["sequence"], "phase": e["phase"], "event_type": e["event_type"],
                           "id": e.get("action_id", e.get("check_id")), "status": (e.get("result") or e.get("observation"))["status"],
                           "event_sha256": hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
                          for _, e in original]}
    cap = {"schema": 1, "kind": "scenario-run", "run_id": run["run_id"],
           "title": f"Local Linux ACL simulation: {operation} → repair → replay → regression → reset",
           "lease_label": None, "lease_id": None, "start": round(min(row["t"] for row in rows), 3),
           "stop": round(max(row["t"] for row in rows), 3), "captured_at": round(captured, 3),
           "actors": [{"account": "actor-A", "under_test": True}], "observations": [],
           "recovery": {"before": None, "after": None, "restore_test": None},
           "source": {"kind": "security-simulation", "scope": run["scope"], "source_revision": run["source_revision"],
                      "source_dirty": run["source_dirty"], "driver": run["driver"], "framework_version": run["nemo_version"],
                      "llm_used": run["llm_used"], "model": run["model"], "fleet_contacted": False,
                      "proof_scope": run["proof_scope"], "reset_scope": run["reset_scope"],
                      "private_bundle_index_sha256": summary["private_bundle_index_sha256"], "harness_verify": verdict},
           "files": {"summary.json": "sanitized verifier-approved derivative; raw bundle retained privately"}}
    # Remove the private snapshot before producing a publishable folder.
    shutil.rmtree(bundle)
    for name, value in (("capture.json", cap), ("summary.json", summary)):
        (tmp / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    (tmp / "events.jsonl").write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
    (tmp / "README.md").write_text("# Local ACL simulation\n\n"
        "A verifier-approved derivative of a private evidence bundle. Linux numeric identities exercise real ACL authorization. "
        "Slurm accounting and quota checks are simulated; no fleet node was contacted. "
        f"Recording used a model: {run['llm_used']}. Execution replay uses no model. "
        "Repair/reset are operator steps. Reset restores the deliberately vulnerable fixture and then discards it; "
        "it does not prove recovery of the accepted cluster.\n\n"
        "NeMo telemetry is actor-written (T3); gateway/observer/operator evidence is co-located (T2). "
        "No independent off-node T1 source is claimed. Dashboard playback executes nothing.\n\n"
        f"Private bundle index SHA256: `{summary['private_bundle_index_sha256']}`. "
        "The private original can be reverified with `python3 -m harness.evidence verify --bundle-dir <private-bundle>`.\n")
    files = sorted(path.name for path in tmp.iterdir() if path.is_file())
    (tmp / "SHA256SUMS").write_text("".join(f"{hashlib.sha256((tmp / name).read_bytes()).hexdigest()}  {name}\n" for name in files))
    check_with_dashboard(tmp, f"{date}/{run['run_id']}")
    out.parent.mkdir(parents=True, exist_ok=True); tmp.rename(out)
    return out, len(rows)


def build_snapshot(bundle, evidence_root, tmp, verdict, date=None, title=None):
    """Map the verified private snapshot, never the mutable source directory."""
    run = json.loads((bundle / "run.json").read_text())
    run_id = run["run_id"]
    configurable = run["schema"] in {"prace.scenario-run.v1", "prace.diagnostic-run.v1"}
    attempts = ("",) if configurable else ATTEMPTS
    manifest = json.loads((bundle / ("manifest.json" if configurable else "before/manifest.json")).read_text())
    actor = (manifest.get("actor") or {}).get("identity") or "actor"
    events = []
    for attempt in attempts:
        events += events_for(bundle, attempt, actor, nemo_replay=configurable and run.get("replay_driver") == "nemo")
    events.sort(key=lambda x: x[0])
    if not configurable:
        fix = json.loads((bundle / "fix-proposal.json").read_text())
        after_start = min(t for t, e in events if e["ev"].startswith("bundle/after/"))
        events.append((after_start - 0.002, {"lane": "ctx", "kind": "ctx", "src": "harness-run", "host": "", "actor": "",
                   "title": f"declared fixture correction: {fix.get('field')} of {fix.get('action_id')}",
                   "text": f"{fix.get('kind')}, hash-bound (template {short(fix.get('before_template_sha256'))} -> "
                           f"{short(fix.get('after_template_sha256'))}); an operator step, not an agent repair",
                   "ev": "bundle/fix-proposal.json"}))
    events.sort(key=lambda x: x[0])
    start, stop = events[0][0], events[-1][0]
    captured = max(iso_epoch(json.loads((bundle / a / "result.json").read_text())["generated_at"]) for a in attempts)
    date = date or datetime.datetime.fromtimestamp(start, datetime.timezone.utc).strftime("%Y-%m-%d")
    out = Path(evidence_root) / date / run_id
    if out.exists():
        raise Refused(f"{out} exists: evidence is append-only, export to a new run ID")
    scope = run.get("scope")
    if run["schema"] == "prace.diagnostic-run.v1":
        title = title or "Alice-only CPU/GPU tracing diagnostic :  UNVERIFIED (independent verification SKIPPED)"
    environment = run.get("execution_environment", "ssh-unqualified" if run.get("transport") == "ssh" else "local")
    fleet_contacted = run.get("fleet_contacted") if not configurable else (False if environment in {"local", "ssh-stand-in"} else None)
    simulated = environment == "ssh-stand-in"
    capture = {
        "schema": 1, "kind": "scenario-run", "run_id": run_id,
        "title": title or (f"Agent harness {run.get('driver')} rehearsal ({scope}; fleet contacted: {fleet_contacted})"),
        "lease_label": None, "lease_id": None,
        "start": round(start, 3), "stop": round(stop, 3), "captured_at": round(captured, 3),
        "actors": [{"account": actor, "under_test": True}],
        "observations": [],
        "recovery": {"before": run.get("recovery_point"), "after": None, "restore_test": None},
        "source": {"kind": "harness-bundle", "bundle_index_sha256": hashlib.sha256((bundle / "bundle.json").read_bytes()).hexdigest(),
                   "harness_verify": verdict, "source_revision": run.get("source_revision"), "source_dirty": run.get("source_dirty"),
                   "driver": run.get("driver"), "framework_version": run.get("nemo_version"), "llm_used": run.get("llm_used"),
                   "model": run.get("model"), "scope": scope, "fleet_contacted": fleet_contacted,
                   "execution_environment": environment,
                   "simulated_job_ids": run.get("slurm_job_ids") if simulated else [],
                   "slurm_job_ids": [] if simulated else run.get("slurm_job_ids"),
                   "attempts": run.get("attempts")},
        "files": {"events.jsonl": "dashboard events mapped from the bundle, each pointing at its source line",
                  "README.md": "what this run is and is not",
                  "bundle/": "the harness bundle, unchanged; python3 -m harness.evidence verify --bundle-dir bundle"},
    }
    if not configurable:
        capture["source"].pop("execution_environment")
        capture["source"].pop("simulated_job_ids")
    with open(tmp / "capture.json", "w") as f:
        json.dump(capture, f, indent=1, sort_keys=True)
        f.write("\n")
    with open(tmp / "events.jsonl", "w") as f:
        for t, e in events:
            f.write(json.dumps(dict(e, t=round(t, 3)), sort_keys=True) + "\n")
    text = readme(capture, len(events))
    if configurable:
        text = text.replace("The correction between the attempts is a declared, hash-bound fixture change by the operator, not an agent repair.",
                            "This configurable smoke run records and replays the selected actions; it makes no repair claim.")
        text = text.replace("there is no cluster observation in a local run.",
                            "separate SSH roles, when used, do not establish an off-node trust boundary.")
    if run['schema'] == 'prace.diagnostic-run.v1':
        text = ('# Alice-only tracing diagnostic\n\nTrace and artifact integrity checked. Independent verification **SKIPPED**; overall **UNVERIFIED**.\n\n'
                'All execution and snapshots used Alice. Two jobs; no cluster replay. Dashboard Replay navigates captured evidence.\n')
    (tmp / "README.md").write_text(text)
    files = sorted(str(p.relative_to(tmp)) for p in tmp.rglob("*") if p.is_file())
    with open(tmp / "SHA256SUMS", "w") as f:
        for name in files:
            f.write(f"{hashlib.sha256((tmp / name).read_bytes()).hexdigest()}  {name}\n")
    check_with_dashboard(tmp, f"{date}/{run_id}")
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp.rename(out)
    return out, len(events)


def check_with_dashboard(folder, rel):
    """the dashboard's own reader must accept the folder exactly as it will be shipped"""
    sys.path.insert(0, str(DASH_FILES))
    import prace_dash_evidence as evidence   # noqa: E402
    v = evidence.verify(str(folder))
    if v["state"] != "ok":
        raise Refused(f"SHA256SUMS check failed: {v['detail']}")
    try:
        run = evidence.scenario(str(folder), rel, v["files"], evidence.load_trust())
    except ValueError as exc:
        raise Refused(f"the dashboard reader refused the folder: {exc}") from exc
    if run["capture_late"] or not run["events"]:
        raise Refused("the dashboard reader marks the run late or empty")
    return run


def readme(cap, n):
    s = cap["source"]
    jobs = (f"Execution environment: {s['execution_environment']}. Simulated job IDs: {s.get('simulated_job_ids') or 'none'}. "
            f"Scheduler receipt IDs (live qualification not implied): {s['slurm_job_ids'] or 'none'}."
            if 'execution_environment' in s else f"Slurm jobs: {s['slurm_job_ids'] or 'none'}.")
    return f"""# {cap['run_id']}: agent harness run, exported for the fleet dashboard

{cap['title']}.

- **What this is:** a verified harness bundle (`bundle/`, unchanged) and {n} dashboard events mapped from it (`events.jsonl`) by `infra/tools/scenario-export.py`. The dashboard shows it in the Scenarios tab and steps through it in Replay; nothing is re-run.
- **Scope:** {s['scope']}. Fleet contacted: {s['fleet_contacted']}. Model used: {s['llm_used']} (driver {s['driver']} {s['framework_version'] or ''}). {jobs} Recovery point: none.
- **Trust:** the agent's own trace is actor-written (T3); gateway, tracer and validator records are co-located (T2). No event here is independent (T1): there is no cluster observation in a local run.
- **Verify:** `python3 -m harness.evidence verify --bundle-dir bundle` ({s['harness_verify']}); `bundle.json` sha256 `{s['bundle_index_sha256']}`.
- **Not a security result.** Security verdicts are not applicable. The correction between the attempts is a declared, hash-bound fixture change by the operator, not an agent repair.
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    ap.add_argument("--bundle-dir", required=True)
    ap.add_argument("--evidence-root", default=str(ROOT / "evidence"))
    ap.add_argument("--date")
    ap.add_argument("--title")
    a = ap.parse_args()
    try:
        out, n = build(a.bundle_dir, a.evidence_root, a.date, a.title)
    except (Refused, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    print(f"exported {out} ({n} events); the dashboard reader accepts it")
    return 0


if __name__ == "__main__":
    sys.exit(main())

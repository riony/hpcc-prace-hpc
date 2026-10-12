#!/usr/bin/env python3
"""Evaluate one read-only fleet observation (roles/fleet_observer: prace-fleet-observe) against
the expected fleet and, for the drift audit, the approved configuration baseline
(infra/audit/fleet-baseline.json). Used by the scheduled CI drift audit (.gitlab-ci.yml
lab-drift-check) and by the off-node monitor (tools/fleet_monitor.py, health only).

Two expectation files (4 Oct, Session A's review of the 3 Oct handback): infra/audit/expected.json
is the DESIRED fleet, what main's roles converge to; infra/audit/deployed.json is the DEPLOYED
profile, a versioned copy of the desired expectations promoted only after a window deployed them
and its acceptance passed. The CI audit and the monitor judge the fleet against the deployed
profile, so merged-but-undeployed work (3 Oct: !65's payg) is shown as pending, not as an outage.

Outcomes, most decisive first, with exit codes:
  UNREACHABLE_OR_ERROR (2)  no/invalid/stale observation, malformed or overrun maintenance lease,
                            Kubernetes API, controller or accounting unreachable
  DEFERRED_MAINTENANCE (3)  a well-formed cluster lease is held (backup window, acceptance run):
                            no health or drift verdict is given, and it is NOT reported healthy
  UNHEALTHY (4)             an expected worker is not Ready / has no ready slurmd pod / is not in
                            a usable Slurm state / is unreachable over the pod network; a partition
                            is not up; a Slurm setting differs from the expected value; a native
                            worker (T89) has a competing pod, another NodeAddr, its slurmd service
                            not running, or a host share mount that is not the guarded NFS 4.2 one
  DRIFT (1)                 a tracked configuration file differs from the approved baseline, or
                            the node set differs from the expected one
  HEALTHY (0)

  fleet_audit.py evaluate --snapshot FILE --expected FILE [--baseline FILE] [--health-only]
                          [--result FILE] [--now EPOCH]       (FILE: desired file or deployed profile)
  fleet_audit.py record-baseline --snapshot FILE --out FILE
  fleet_audit.py pending --desired FILE --profile FILE     what main expects that is not deployed yet
  fleet_audit.py promote --desired FILE --profile FILE --snapshot FILE --revision SHA
                         --acceptance PATH --out FILE [--now EPOCH]
                         a new profile version, only if the observation is HEALTHY against the
                         desired expectations (health only, no lease held)
"""
import argparse
import datetime
import json
import math
import re
import sys
import time

CODES = {"HEALTHY": 0, "DRIFT": 1, "UNREACHABLE_OR_ERROR": 2, "DEFERRED_MAINTENANCE": 3, "UNHEALTHY": 4}
USABLE = {"idle", "mixed", "allocated", "completing"}
LEASE_RX = re.compile(r"holder=[a-z0-9-]+( label=\S+)? id=[0-9a-f]{8,} since=(\S+)")
# T89: a native worker's slurmd service, as its host's endpoint (prace-native-observe) reports it
NATIVE_UNIT = {"ActiveState": "active", "SubState": "running", "UnitFileState": "enabled"}


def native_problems(name, report, shares, now, max_age):
    """T89: what is wrong with a native worker's host, from its own read-only endpoint
    (roles/fleet_observer native.yml): the slurmd service runs and is enabled; the transition
    marker says native; the cluster key is slurm's alone; every share is the login node's export,
    NFS 4.2, hard, mounted nosuid,nodev in its mode. No pod and no NRI guard exist there, so these
    host mounts are what jobs on it see."""
    if (not isinstance(report, dict) or type(report.get("schema")) is not int or report.get("schema") != 1
            or report.get("host") != name or type(report.get("time")) not in (int, float)
            or not math.isfinite(report["time"]) or now - report["time"] > max_age or report["time"] - now > 60):
        return ["native host observation missing, invalid or stale"]
    if report.get("errors") != []:
        return [f"native host observation reports errors: {report.get('errors')}"]
    problems = []
    unit = report.get("slurmd")
    if not isinstance(unit, dict):
        problems.append("native slurmd service not observed")
    else:
        for key, want in NATIVE_UNIT.items():
            if unit.get(key) != want:
                problems.append(f"slurmd service {key}={unit.get(key)} (expected {want})")
        if type(unit.get("MainPID")) is not int or unit["MainPID"] <= 0 or unit.get("comm") != "slurmd":
            problems.append(f"slurmd service main process {unit.get('MainPID')} is not slurmd ({unit.get('comm')})")
    if report.get("marker") != "native":
        problems.append(f"transition marker {report.get('marker')!r} (expected 'native')")
    key = report.get("key")
    if (not isinstance(key, dict) or key.get("file") is not True or key.get("owner") != "slurm"
            or not re.fullmatch("0[0-7]00", str(key.get("mode")))):
        problems.append(f"cluster key not a file readable by slurm only ({key})")
    mounts = report.get("mounts")
    if not isinstance(mounts, dict):
        return problems + ["host share mounts not observed"]
    for path, mode in sorted(shares["modes"].items()):
        m = mounts.get(path)
        if not isinstance(m, dict):
            problems.append(f"host {path} not mounted")
            continue
        missing = [w for w in ("nosuid", "nodev", mode) if w not in str(m.get("options") or "").split(",")]
        missing += [w for w in ("vers=4.2", "hard") if w not in str(m.get("super") or "").split(",")]
        if m.get("fstype") != "nfs4":
            missing.append("nfs4")
        if missing:
            problems.append(f"host {path} lacks {','.join(missing)} ({m.get('fstype')} {m.get('options')} {m.get('super')})")
        if m.get("source") != f"{shares['server']}:{path}":
            problems.append(f"host {path} from {m.get('source')} (expected {shares['server']}:{path})")
    return problems


def evaluate(snap, expected, baseline=None, health_only=False, now=None):
    """Returns (outcome, reasons)."""
    now = time.time() if now is None else now
    if not isinstance(snap, dict) or snap.get("schema") != 1:
        return "UNREACHABLE_OR_ERROR", ["no valid observation (unreachable, or output is not observer JSON)"]
    age = now - snap.get("time", 0)
    if age > expected.get("max_snapshot_age_s", 180) or age < -60:
        return "UNREACHABLE_OR_ERROR", [f"observation is stale or from the future ({int(age)} s old)"]

    # D43 guard alerts also during maintenance; an OS guard is not containment.
    link_errors, link_faults = [], []
    observed_links = snap.get('disabled_links', {})
    if expected.get('disabled_links') and not isinstance(observed_links, dict):
        return 'UNREACHABLE_OR_ERROR', ['disabled-link observation is not a host mapping']
    for host, targets in expected.get('disabled_links', {}).items():
        report = observed_links.get(host, {})
        if (not isinstance(report, dict) or type(report.get('schema')) is not int
                or report.get('schema') != 1 or report.get('host') != host or report.get('errors') != []
                or type(report.get('time')) not in (int, float)
                or not math.isfinite(report['time'])
                or now - report['time'] > expected.get('max_snapshot_age_s', 180)
                or report['time'] - now > 60):
            link_errors.append(host + ': missing, invalid or stale disabled-link observation')
            continue
        rows = report.get('interfaces') or {}
        if not isinstance(rows, dict) or set(rows) != {t['name'] for t in targets}:
            link_errors.append(host + ': disabled-link target set differs')
            continue
        for target in targets:
            row = rows[target['name']]
            label = host + '/' + target['name']
            if not isinstance(row, dict) or any(row.get(k) != target[k] for k in ('mac', 'pci')):
                link_errors.append(label + ': physical identity differs')
            elif (any(type(row.get(k)) is not bool for k in ('admin_up', 'carrier', 'nm_managed'))
                  or not isinstance(row.get('addresses'), list) or not isinstance(row.get('operstate'), str)):
                link_errors.append(label + ': incomplete link observation')
            elif (row['admin_up'] or row['carrier'] or row['nm_managed']
                  or row['operstate'] != 'DOWN' or row['addresses']):
                link_faults.append(label + ': disabled interface up, managed, has carrier or an address')
    if link_errors:
        return 'UNREACHABLE_OR_ERROR', link_errors + link_faults
    if link_faults:
        return 'UNHEALTHY', link_faults

    # the observer always states the lease; an observation that does not is no evidence of a
    # released one (4 Oct, Session A's review of !86: {} or a non-boolean `held` passed as unleased)
    lease = snap.get("lease")
    if not isinstance(lease, dict) or type(lease.get("held")) is not bool:
        return "UNREACHABLE_OR_ERROR", ["the observation does not state whether a cluster lease is held"]
    if lease["held"]:
        m = LEASE_RX.fullmatch(lease.get("holder") or "")
        if not m:
            return "UNREACHABLE_OR_ERROR", [f"cluster lease held but malformed: {lease.get('holder')!r}"]
        try:
            since = datetime.datetime.fromisoformat(m.group(2)).timestamp()
        except ValueError:
            return "UNREACHABLE_OR_ERROR", [f"cluster lease held with an unreadable time: {lease.get('holder')!r}"]
        hours = (now - since) / 3600
        limit = expected.get("max_maintenance_h", 4)
        if hours > limit:
            return "UNREACHABLE_OR_ERROR", [f"maintenance overran: lease held {hours:.1f} h (> {limit} h): {lease['holder']}"]
        return "DEFERRED_MAINTENANCE", [f"maintenance in progress for {hours * 60:.0f} min: {lease['holder']}"]

    errors = list(snap.get("errors") or [])
    if not snap.get("k8s_api"):
        errors.append("Kubernetes API unreachable")
    if not snap.get("controller_up"):
        errors.append("slurmctld does not answer")
    if not snap.get("accounting"):
        errors.append("accounting (slurmdbd) does not answer")
    if errors:
        return "UNREACHABLE_OR_ERROR", errors

    unhealthy, drift = [], []
    nodes = snap.get("nodes") or {}
    native_workers = expected.get("native_workers") or {}
    shares = expected.get("native_shares")
    if native_workers and not (isinstance(shares, dict) and isinstance(shares.get("modes"), dict)
                               and shares["modes"] and isinstance(shares.get("server"), str)):
        return "UNREACHABLE_OR_ERROR", ["the expectations name native workers but no native_shares to judge their hosts by"]
    native_hosts = snap.get("native_hosts")
    if native_workers and not isinstance(native_hosts, dict):
        return "UNREACHABLE_OR_ERROR", ["the observation reports no native hosts (observer too old?)"]
    for name, role in sorted(expected["workers"].items()):
        n = nodes.get(name)
        if n is None:
            unhealthy.append(f"{name}: not a Kubernetes node"); continue
        problems = []
        if n.get("role") != role:
            problems.append(f"role {n.get('role')} (expected {role})")
        if not n.get("k8s_ready"):
            problems.append("Kubernetes NotReady")
        native = native_workers.get(name)
        if native:
            # a native slurmd (T89): no pod may compete, Slurm knows it at its own address, and its
            # host (service, marker, key, share mounts) as its own endpoint reports it
            if n.get("slurmd_pods") != 0:
                problems.append(f"native worker with {n.get('slurmd_pods')} slurmd pod(s)")
            if n.get("slurm_addr") != native:
                problems.append(f"Slurm NodeAddr {n.get('slurm_addr')} (expected the native {native})")
            problems += native_problems(name, native_hosts.get(name), shares, now, expected.get("max_snapshot_age_s", 180))
        elif not n.get("slurmd_pod_ready"):
            problems.append("no ready slurmd pod")
        if n.get("slurm_state") not in USABLE:
            problems.append(f"Slurm state {n.get('slurm_state')}")
        if n.get("pod_path") is not True:
            problems.append("pod network unreachable from the login node")
        want_gres = expected.get("gres", {}).get(name)
        if want_gres and not str(n.get("slurm_gres") or "").startswith(want_gres):
            problems.append(f"Slurm GRES {n.get('slurm_gres')} (expected {want_gres})")
        if problems:
            unhealthy.append(f"{name}: " + ", ".join(problems))
    login = nodes.get(expected["login"])
    if not login or not login.get("k8s_ready"):
        unhealthy.append(f"{expected['login']}: login node not Ready")
    for part, want in sorted(expected.get("partitions", {}).items()):
        got = (snap.get("partitions") or {}).get(part)
        if got != want:
            unhealthy.append(f"partition {part}: {got} (expected {want})")
    for key, want in sorted(expected.get("slurm_config", {}).items()):
        got = (snap.get("slurm_config") or {}).get(key)
        if got != want:
            unhealthy.append(f"Slurm {key} = {got} (expected {want})")
    # T87 (3 Oct): the share mounts inside every slurmd and login pod carry nosuid, nodev and their
    # mode (the NRI mount guard). Checked only where the profile expects it.
    guarded = expected.get("guarded_shares") or {}
    if guarded:
        mounts = snap.get("share_mounts")
        if not isinstance(mounts, dict):
            return "UNREACHABLE_OR_ERROR", ["the observation reports no share mounts (observer too old?)"]
        seen = set()
        for pod, row in sorted(mounts.items()):
            if not isinstance(row, dict) or row.get("error") or not isinstance(row.get("mounts"), dict):
                unhealthy.append(f"pod {pod}: share mounts unreadable ({(row or {}).get('error') if isinstance(row, dict) else row})")
                continue
            if row.get("kind") == "slurmd":
                seen.add(row.get("node"))
            for path, mode in sorted(guarded.items()):
                opts = row["mounts"].get(path)
                missing = [w for w in ("nosuid", "nodev", mode) if w not in (opts or "").split(",")]
                if missing:
                    unhealthy.append(f"pod {pod}: {path} lacks {','.join(missing)} ({opts or 'not mounted'})")
        # a native worker has no pod: its host mounts are judged above (native_problems)
        for name in sorted(set(expected["workers"]) - set(native_workers) - seen):
            unhealthy.append(f"{name}: no share-mount observation of its slurmd pod")
        # the login pod too (4 Oct, Session A's review of !86): users log in there. Outside maintenance
        # (a held lease returned above) it runs, so a missing observation is a fault, never a pass.
        if not any(isinstance(row, dict) and row.get("kind") == "login" and row.get("node") == expected["login"]
                   and not row.get("error") and isinstance(row.get("mounts"), dict) for row in mounts.values()):
            unhealthy.append(f"{expected['login']}: no share-mount observation of a login pod")
    extra = sorted(set(nodes) - set(expected["workers"]) - {expected["login"]})
    if extra:
        drift.append("unexpected Kubernetes nodes: " + ", ".join(extra))
    # the login node's native list (roles/fleet_observer) names a host the expectations do not
    extra = sorted(set(native_hosts or {}) - set(native_workers))
    if extra:
        drift.append("native observation of hosts not expected native: " + ", ".join(extra))

    if not health_only:
        if baseline is None:
            return "UNREACHABLE_OR_ERROR", ["no configuration baseline to compare with"]
        have, want = snap.get("config") or {}, baseline.get("config") or {}
        for path in sorted(set(have) | set(want)):
            if have.get(path) != want.get(path):
                drift.append(f"config {path}: {short(want.get(path))} -> {short(have.get(path))}")
    if unhealthy:
        return "UNHEALTHY", unhealthy + drift
    if drift:
        return "DRIFT", drift
    return "HEALTHY", [f"{len(expected['workers'])} workers usable, controller and accounting answer"
                       + ("" if health_only else f", {len(snap.get('config') or {})} tracked files match the baseline")]


def short(v):
    return "absent" if v is None else v[:12] if len(v) == 64 else v


def expected_from(doc):
    """the expectations of a deployed profile ({profile, expected, ...}) or of a plain desired file"""
    if isinstance(doc, dict) and "profile" in doc:
        ok = (type(doc["profile"]) is int and doc["profile"] >= 1 and isinstance(doc.get("expected"), dict)
              and re.fullmatch("[0-9a-f]{40}", str(doc.get("source_revision"))) and doc.get("acceptance"))
        return doc["expected"] if ok else None
    return doc if isinstance(doc, dict) and isinstance(doc.get("workers"), dict) else None


def pending(desired, deployed):
    """the desired expectations that differ from the deployed ones, as 'key: deployed -> desired'"""
    out = []
    def walk(a, b, path):
        if isinstance(a, dict) and isinstance(b, dict):
            for k in sorted(set(a) | set(b)):
                walk(a.get(k), b.get(k), f"{path}.{k}" if path else k)
        elif a != b:
            out.append(f"{path}: {json.dumps(a)} -> {json.dumps(b)}")
    walk(deployed, desired, "")
    return out


def load(path):
    try:
        with (sys.stdin if path == "-" else open(path)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("evaluate")
    e.add_argument("--snapshot", required=True); e.add_argument("--expected", required=True)
    e.add_argument("--baseline"); e.add_argument("--health-only", action="store_true")
    e.add_argument("--result"); e.add_argument("--now", type=float)
    b = sub.add_parser("record-baseline")
    b.add_argument("--snapshot", required=True); b.add_argument("--out", required=True)
    pe = sub.add_parser("pending")
    pe.add_argument("--desired", required=True); pe.add_argument("--profile", required=True)
    pr = sub.add_parser("promote")
    for opt in ("--desired", "--profile", "--snapshot", "--revision", "--acceptance", "--out"):
        pr.add_argument(opt, required=True)
    pr.add_argument("--now", type=float)
    a = ap.parse_args(argv)
    if a.cmd in ("pending", "promote"):
        desired, prof = expected_from(load(a.desired)), load(a.profile)
        deployed = expected_from(prof)
        if desired is None or deployed is None or "profile" not in prof:
            print("refusing: unreadable desired expectations or deployed profile"); return 2
        diff = pending(desired, deployed)
        if a.cmd == "pending":
            print(f"deployed profile {prof['profile']} (from {prof['source_revision'][:12]}); "
                  + (f"{len(diff)} desired expectation(s) not deployed yet:" if diff else "nothing pending"))
            for d in diff:
                print("  " + d)
            return 0
        if not diff:
            print("refusing: nothing to promote; the deployed profile already holds the desired expectations"); return 2
        if not re.fullmatch("[0-9a-f]{40}", a.revision) or not a.acceptance.strip():
            print("refusing: a full source revision and the acceptance evidence are required"); return 2
        s = load(a.snapshot)
        # an explicit, complete observation only: schema 1, no errors, and a lease stated as not held
        if (not isinstance(s, dict) or s.get("schema") != 1 or s.get("errors") != []
                or s.get("lease") != {"held": False} or type(s["lease"]["held"]) is not bool):
            print("refusing: the observation is incomplete, reports errors, or does not state the lease as not held")
            return 1
        outcome, reasons = evaluate(s, desired, health_only=True, now=a.now)
        if outcome != "HEALTHY":
            print(f"refusing: the observation is {outcome} against the desired expectations")
            for r in reasons:
                print("  " + r)
            return 1
        snap_time = load(a.snapshot)["time"]
        new = {"profile": prof["profile"] + 1, "source_revision": a.revision, "acceptance": a.acceptance,
               "promoted_from_observation": datetime.datetime.fromtimestamp(snap_time, datetime.timezone.utc).isoformat(),
               "previous": {"profile": prof["profile"], "source_revision": prof["source_revision"]},
               "expected": desired}
        with open(a.out, "w") as f:
            json.dump(new, f, indent=1, sort_keys=True)
            f.write("\n")
        print(f"profile {new['profile']} promoted from {a.revision[:12]}: {len(diff)} expectation(s) now deployed")
        return 0
    snap = load(a.snapshot)
    if a.cmd == "record-baseline":
        if not snap or snap.get("schema") != 1 or snap.get("errors"):
            print("refusing: the observation is missing or reports errors"); return 2
        with open(a.out, "w") as f:
            json.dump({"recorded_at": datetime.datetime.fromtimestamp(snap["time"], datetime.timezone.utc).isoformat(),
                       "host": snap.get("host"), "config": snap["config"]}, f, indent=1, sort_keys=True)
            f.write("\n")
        print(f"baseline: {len(snap['config'])} tracked entries from {snap.get('host')}"); return 0
    expected = expected_from(load(a.expected))
    baseline = load(a.baseline) if a.baseline else None
    if expected is None:
        print("UNREACHABLE_OR_ERROR: expected fleet file unreadable"); return 2
    outcome, reasons = evaluate(snap, expected, baseline, a.health_only, a.now)
    print(outcome)
    for r in reasons:
        print("  " + r)
    if a.result:
        with open(a.result, "w") as f:
            json.dump({"outcome": outcome, "reasons": reasons, "evaluated_at": int(time.time() if a.now is None else a.now),
                       "snapshot_time": (snap or {}).get("time"), "expected_workers": sorted(expected["workers"]),
                       "health_only": a.health_only}, f, indent=1, sort_keys=True)
            f.write("\n")
    return CODES[outcome]


if __name__ == "__main__":
    sys.exit(main())

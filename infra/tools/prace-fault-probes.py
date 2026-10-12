#!/usr/bin/env python3
"""Job probes for Session A's NFS fault test (A's Sunday plan, section 5: "B supplies job probes").

usage: prace-fault-probes.py (--bench | --fleet --lease-id ID) start|status|finish|abort --tag TAG [--minutes N]

Two trusted, bounded jobs of syn-alice in proj-alpha, one on the CPU node (the native Lenovo when
infra/audit/expected.json lists it in native_workers, else its pod) and one on the first GPU node
(a GPU pod, one GPU). Each appends one record a second to its own file on the NFS share
/projects/proj-alpha/.fault-probe-TAG/, fsyncs it, and chains each record to the previous one's
hash. A probe stops when the stop file appears, or after --minutes (default 30, at most 120).

  start   needs open admission and an empty queue. Submits both probes, waits until both run and
          have written their header, then writes the receipt and prints it as JSON: the exact job
          ids, numeric uid, user, account, partition, node, file, batch PID, boot id and cgroup of
          each. A's fault adapter allowlists exactly these. A pending probe is cancelled and the
          start refused.
  status  Slurm's view only (state, node, restarts, reason): it reads no file, so it works behind
          a closed fence and during the outage.
  finish  after the fault and the reopening (a login pod again). Writes the stop file, waits until
          both probes ended, and checks each probe:
          - the same job: COMPLETED 0:0, no restart or requeue, on the recorded node;
          - the same process: one header, every record from its PID, the cgroup and boot id unchanged;
          - every record: seq 1..N, each chaining the previous one's hash, ended by the stop file.
          It reports the longest gap between records (the stall the fault caused). Then it removes
          the probe directory and shows it gone, but only once every probe job is proved over (no
          longer queued, a finished record in Slurm) and the raw logs are kept off the cluster
          (TAG-logs/ beside the receipt, with their sha256); otherwise nothing is removed.
  abort   cancels the probe jobs and, once the cancellation is confirmed and every job is proved
          over, keeps their logs and removes their directory (else nothing is removed).

The receipt is private (PRACE_PROBE_DIR, default ~/prace-recovery/fault-probes/TAG.json; 0600,
written atomically and fsynced) and never overwritten by another start. It holds no secret.
Fleet commands go through slurm-policy-acceptance.py's plumbing: the operator's lease is
checked (never taken or released); users submit in the login pod; Slurm is read in the
controller. Exit: 0 pass; 1 a probe failed or did not finish; 2 a query failed; 3 refused."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import sys
import tempfile
import time

TOOLS = Path(__file__).resolve().parent
USER, ACCOUNT, PROJECT = "syn-alice", "proj-alpha", "/projects/proj-alpha"
RECEIPTS = Path(os.environ.get("PRACE_PROBE_DIR", Path.home() / "prace-recovery/fault-probes"))
TAG = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")

# The probe job (bash). A record: "rec SEQ PID TIME HASH", HASH the first 16 hex digits of
# sha256("PREV SEQ PID TIME") and PREV the previous record's hash ("start" for the first).
JOB = r"""#!/bin/bash
# prace fault probe (tools/prace-fault-probes.py): one hash-chained record a second, each fsynced
set -u
f="$PROBE_DIR/$PROBE_KIND.log"; stop="$PROBE_DIR/stop"
cg=$(head -n1 /proc/self/cgroup | tr ' ' _)
printf 'header job=%s pid=%s host=%s boot=%s cgroup=%s start=%s\n' "${SLURM_JOB_ID:-none}" "$$" "$(cat /proc/sys/kernel/hostname)" \
  "$(cat /proc/sys/kernel/random/boot_id)" "$cg" "$(date +%s)" >> "$f" || exit 3
sync "$f" || exit 3
i=0; prev=start
while [ ! -e "$stop" ] && [ "$(date +%s)" -lt "$PROBE_END" ]; do
  i=$((i + 1)); t=$(date +%s)
  h=$(printf '%s %s %s %s' "$prev" "$i" "$$" "$t" | sha256sum | cut -c1-16)
  printf 'rec %s %s %s %s\n' "$i" "$$" "$t" "$h" >> "$f" || exit 4
  sync "$f" || exit 4
  prev=$h
  sleep 1
done
reason=stop; [ -e "$stop" ] || reason=time
printf 'end %s %s %s %s\n' "$i" "$$" "$(date +%s)" "$reason" >> "$f" && sync "$f"
"""


def job_script(d, kind, end):
    """one probe's script, its values written in. Not --export=ALL,VAR=...: on the bench that made
    the unprivileged slurmd die (clone: Operation not permitted, 2 Oct); the fleet's slurmd pods run
    privileged, but the probe does not depend on it"""
    body = JOB.split("\n", 1)[1]
    return (f"#!/bin/bash\nPROBE_DIR={shlex.quote(d)}\nPROBE_KIND={shlex.quote(kind)}\nPROBE_END={int(end)}\n" + body)


class Stop(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


def load_acceptance():
    spec = importlib.util.spec_from_file_location("policy_acceptance", TOOLS / "slurm-policy-acceptance.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# --- verdicts (pure; offline-tested) -------------------------------------------------------------
def chain(prev, seq, pid, t):
    return hashlib.sha256(f"{prev} {seq} {pid} {t}".encode()).hexdigest()[:16]


def verify_log(text):
    """(problems, facts) of one probe's file: one header first, records 1..N from its PID chained by
    hash, the stop record last; facts: header fields, records, longest gap between records (s)"""
    lines = text.splitlines()
    problems, facts = [], {"records": 0, "max_gap": None, "header": {}}
    if not lines or not lines[0].startswith("header "):
        return ["no header record first"], facts
    head = dict(kv.split("=", 1) for kv in lines[0].split()[1:] if "=" in kv)
    facts["header"] = head
    if sum(l.startswith("header ") for l in lines) != 1:
        problems.append("more than one header: the probe started again (a replaced or requeued job)")
    pid, prev, seq, last_t, gaps = head.get("pid"), "start", 0, int(head.get("start", "0") or 0), []
    end = None
    for n, line in enumerate(lines[1:], 2):
        f = line.split()
        if f[:1] == ["rec"] and len(f) == 5 and f[1].isdigit() and f[3].isdigit():
            if end is not None:
                problems.append(f"line {n}: a record after the end record")
                break
            if int(f[1]) != seq + 1:
                problems.append(f"line {n}: seq {f[1]} after {seq} (a lost or repeated record)")
                break
            if f[2] != pid:
                problems.append(f"line {n}: written by PID {f[2]}, not the header's {pid} (another process)")
                break
            if f[4] != chain(prev, f[1], f[2], f[3]):
                problems.append(f"line {n}: hash {f[4]} does not chain to the previous record (rewritten or reordered)")
                break
            gaps.append(int(f[3]) - last_t)
            seq, prev, last_t = int(f[1]), f[4], int(f[3])
        elif f[:1] == ["end"] and len(f) == 5 and end is None:
            end = f
        elif line.startswith("header "):
            continue
        else:
            problems.append(f"line {n}: not a probe record: {line[:80]!r}")
            break
    facts["records"], facts["max_gap"] = seq, max(gaps) if gaps else None
    if end is None:
        problems.append("no end record: the probe did not finish")
    else:
        if end[1] != str(seq) or end[2] != pid:
            problems.append(f"the end record (seq {end[1]}, PID {end[2]}) does not match the records (seq {seq}, PID {pid})")
        if end[4] != "stop":
            problems.append("ended by its time limit before the stop file: the probe did not cover the whole test")
        if lines[-1].split()[:1] != ["end"]:
            problems.append("the end record is not last")
    if seq == 0:
        problems.append("no record written")
    return problems, facts


def verify_job(rec, want):
    """problems of one probe's Slurm record (scontrol show job -o fields) against its receipt"""
    p = []
    if not rec:
        return ["no Slurm record of the job"]
    if rec.get("JobState") != "COMPLETED" or rec.get("ExitCode") != "0:0":
        p.append(f"job {want['job_id']} {rec.get('JobState')} exit {rec.get('ExitCode')} (not COMPLETED 0:0)")
    if rec.get("Restarts", "0") != "0":
        p.append(f"job {want['job_id']} restarted {rec.get('Restarts')} time(s) (requeued)")
    if rec.get("NodeList") != want["node"] or rec.get("BatchHost", want["node"]) != want["node"]:
        p.append(f"job {want['job_id']} ran on {rec.get('NodeList')}/{rec.get('BatchHost')}, not {want['node']}")
    return p


def same_process(head, want):
    """problems: the header the job wrote at finish is not the one recorded at start"""
    return [f"{k} changed: {want.get(k)} at start, {head.get(k)} now" for k in ("job", "pid", "host", "boot", "cgroup", "start")
            if head.get(k) != want.get(k)]


# --- the cluster ---------------------------------------------------------------------------------
class Cluster:
    def __init__(self, acc, bench):
        self.a, self.bench = acc, bench
        workers = acc.EXPECTED["workers"]
        native = acc.EXPECTED.get("native_workers") or {}
        cpu = sorted(n for n, k in workers.items() if k == "cpu")
        gpu = sorted(n for n, k in workers.items() if k == "gpu")
        if not cpu or not gpu:
            raise Stop(3, f"expected.json names no CPU or no GPU worker: {workers}")
        self.probes = {
            "cpu": {"node": cpu[0], "partition": "cpu", "backend": "host" if cpu[0] in native else "pod",
                    "args": ["-p", "cpu", "-w", cpu[0], "-n", "1", "-c", "1", "--mem=1G"]},
            "gpu": {"node": gpu[0], "partition": "gpu", "backend": "host" if gpu[0] in native else "pod",
                    "args": ["-p", "gpu", "-w", gpu[0], "-n", "1", "--gres=gpu:1"]},
        }

    def as_user(self, script):
        return self.a.user(USER, "sh", "-c", script)

    def job(self, jid):
        rc, out, err = self.a.admin("scontrol", "show", "job", "-o", jid)
        if rc != 0:
            return None if "Invalid job id" in (err + out) else self.fail(f"scontrol show job {jid}: {err or out}")
        return dict(kv.split("=", 1) for kv in out.split() if "=" in kv)

    def finished(self, jid):
        """the job's record after it ended: scontrol's, or (once slurmctld has purged it) one built from
        accounting, every requeue of the job a row (sacct -D)"""
        rec = self.job(jid)
        if rec:
            return rec
        rc, out, err = self.a.admin("sacct", "-X", "-D", "-n", "-P", "-j", jid, "-o", "JobID,State,ExitCode,NodeList")
        if rc != 0:
            self.fail(f"sacct -j {jid}: {err or out}")
        rows = [l.split("|") for l in out.splitlines() if l.strip()]
        if not rows:
            return None
        last = rows[-1]
        return {"JobId": last[0], "JobState": last[1].split()[0], "ExitCode": last[2], "NodeList": last[3],
                "BatchHost": last[3], "Restarts": str(len(rows) - 1), "source": "sacct"}

    def queue(self):
        rc, out, err = self.a.admin("squeue", "-h", "-a", "-o", "%i %u %T")
        if rc != 0:
            self.fail(f"squeue: {err or out}")
        return [l.split() for l in out.splitlines() if l.strip()]

    def fail(self, msg):
        raise Stop(2, msg)


def save(path, data):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".")
    with os.fdopen(fd, "w") as fh:
        json.dump(data, fh, indent=1, sort_keys=True)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
    dfd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def load(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise Stop(3, f"no usable receipt {path}: {e}")


def probe_dir(tag):
    return f"{PROJECT}/.fault-probe-{tag}"


# --- the commands --------------------------------------------------------------------------------
def start(c, tag, minutes, receipt):
    if receipt.exists():
        raise Stop(3, f"receipt {receipt} exists: a probe run with this tag was started already (finish or abort it)")
    q = c.queue()
    if q:
        raise Stop(3, f"the queue is not empty ({len(q)} jobs: {q[:5]}): the probes start only in a quiet window")
    d = probe_dir(tag)
    end = int(time.time()) + 60 * minutes
    write = " && ".join(f"printf %s {shlex.quote(job_script(d, kind, end))} > {shlex.quote(f'{d}/probe-{kind}.sh')}" for kind in c.probes)
    rc, out, err = c.as_user(f"id -u; mkdir -m 2770 {shlex.quote(d)} && {write} && echo made")
    if rc != 0 or not out.endswith("made"):
        raise Stop(2, f"cannot make {d}: {err or out}")
    uid = out.splitlines()[0]
    data = {"tag": tag, "user": USER, "uid": uid, "account": ACCOUNT, "dir": d, "minutes": minutes,
            "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "phase": "starting", "probes": {}}
    save(receipt, data)
    ids = []
    try:
        for kind, p in c.probes.items():
            rc, out, err = c.a.user(USER, "sbatch", "--parsable", "-A", ACCOUNT, "-J", f"fault-probe-{kind}", "-t", str(minutes + 10),
                                    "-o", "/dev/null", "--no-requeue", *p["args"], f"{d}/probe-{kind}.sh")
            jid = out.split(";")[0] if rc == 0 else ""
            if not jid.isdigit():
                raise Stop(1, f"{kind} probe not submitted: {err or out}")
            ids.append(jid)
            data["probes"][kind] = {"job_id": jid, "node": p["node"], "partition": p["partition"], "expected_backend": p["backend"],
                                    "file": f"{d}/{kind}.log"}
            save(receipt, data)
        for kind, p in data["probes"].items():
            rec = None
            for _ in range(60):
                rec = c.job(p["job_id"]) or {}
                if rec.get("JobState") != "PENDING":
                    break
                time.sleep(3)
            if rec.get("JobState") != "RUNNING":
                raise Stop(3, f"{kind} probe {p['job_id']} is {rec.get('JobState')} ({rec.get('Reason')}): admission must be open")
            if rec.get("NodeList") != p["node"]:
                raise Stop(1, f"{kind} probe runs on {rec.get('NodeList')}, not {p['node']}")
            head = {}
            for _ in range(30):
                rc, out, _ = c.as_user(f"head -n1 {shlex.quote(p['file'])} 2>/dev/null")
                if rc == 0 and out.startswith("header "):
                    head = dict(kv.split("=", 1) for kv in out.split()[1:] if "=" in kv)
                    break
                time.sleep(2)
            if not head or head.get("job") != p["job_id"]:
                raise Stop(1, f"{kind} probe {p['job_id']} wrote no header to {p['file']}")
            backend = "pod" if "kubepods" in head.get("cgroup", "") else "host"
            if not c.bench and backend != p["expected_backend"]:
                raise Stop(1, f"{kind} probe runs in a {backend} slurmd, expected {p['expected_backend']} (expected.json)")
            p.update(header=head, backend="container (bench)" if c.bench else backend,
                     batch_pid=head["pid"], boot_id=head["boot"], cgroup=head["cgroup"])
        q = c.queue()
        data["queue_after_start"] = q
        foreign = [j for j in q if j[0] not in ids]
        if foreign:
            raise Stop(1, f"jobs other than the probes are in the queue: {foreign}")
        data["phase"] = "running"
        save(receipt, data)
    except Stop:
        data["phase"] = "start_failed"
        save(receipt, data)
        if ids:
            c.a.admin("scancel", *ids)
        raise
    print(json.dumps(data, indent=1, sort_keys=True))
    return 0


def status(c, receipt):
    data = load(receipt)
    out = {"tag": data["tag"], "phase": data["phase"], "probes": {}}
    for kind, p in data["probes"].items():
        rec = c.job(p["job_id"]) or {}
        out["probes"][kind] = {k: rec.get(k) for k in ("JobState", "Reason", "NodeList", "Restarts", "RunTime", "ExitCode")}
        out["probes"][kind]["job_id"] = p["job_id"]
    print(json.dumps(out, indent=1, sort_keys=True))
    return 0


TERMINAL = ("COMPLETED", "FAILED", "CANCELLED", "TIMEOUT", "NODE_FAIL", "OUT_OF_MEMORY", "PREEMPTED", "BOOT_FAIL", "DEADLINE")


def not_ended(c, ids):
    """the probe jobs not proved over: still in the queue, or with no finished record in Slurm. The
    probe directory is removed only when this is empty: a probe still running keeps writing into it
    (Session A's review of !78, F1)."""
    queued = {j[0] for j in c.queue()}
    left = []
    for jid in ids:
        rec = c.finished(jid) or {}
        if jid in queued or rec.get("JobState") not in TERMINAL:
            left.append(f"{jid} ({rec.get('JobState', 'no record')})")
    return left


def keep_logs(c, data, receipt):
    """the raw probe logs, byte for byte, beside the private receipt (0600) with their sha256, before
    anything is removed: the record chain stays replayable off the cluster (F1). False if a log
    that exists could not be copied; a log that was never written is recorded as absent."""
    ok, where = True, receipt.parent / f"{data['tag']}-logs"
    for kind, p in data["probes"].items():
        f = shlex.quote(p["file"])
        rc, out, err = c.as_user(f"if [ -e {f} ]; then base64 -w0 -- {f} && echo; else echo ABSENT; fi")
        if rc == 0 and out == "ABSENT":
            p["log_copy"] = {"absent": True}
            continue
        try:
            if rc != 0:
                raise ValueError(err or out or f"rc {rc}")
            raw = base64.b64decode(out, validate=True)
        except ValueError as e:
            p["log_copy"] = {"error": str(e)[:300]}
            ok = False
            continue
        where.mkdir(mode=0o700, parents=True, exist_ok=True)
        dest = where / f"{kind}.log"
        fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(raw)
            fh.flush()
            os.fsync(fh.fileno())
        p["log_copy"] = {"path": str(dest), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    return ok


def cleanup(c, d):
    """remove the probe directory and show it gone: the removal's status, an absence that was
    observed (not a failed look), and the project directory still listable. Any error is a failure."""
    q = shlex.quote(d)
    rc, out, err = c.as_user(f"rm -rf -- {q}; rm_rc=$?; "
                             f"if seen=$(stat -c %n -- {q} 2>&1); then echo left; "
                             f"elif printf '%s' \"$seen\" | grep -q 'No such file or directory'; then echo absent; "
                             f"else echo unobservable; fi; echo rm_rc=$rm_rc; ls -A {PROJECT} >/dev/null && echo looked")
    words = out.split()
    ok = rc == 0 and {"absent", "rm_rc=0", "looked"} <= set(words) and not {"left", "unobservable"} & set(words)
    return ok, (err or out)


def remove_when_over(c, data, receipt):
    """(removed, record): the raw logs kept, then the directory removed, only once every probe job is
    proved over; otherwise nothing is removed and the reason is recorded"""
    left = not_ended(c, [p["job_id"] for p in data["probes"].values()])
    if left:
        return False, {"removed_and_shown": False, "skipped": "probe jobs not proved over: " + ", ".join(left)}
    if not keep_logs(c, data, receipt):
        return False, {"removed_and_shown": False, "skipped": "a probe log could not be kept off the cluster"}
    gone, detail = cleanup(c, data["dir"])
    return gone, {"removed_and_shown": gone, "detail": detail}


def finish(c, receipt, timeout):
    data = load(receipt)
    if data["phase"] != "running":
        raise Stop(3, f"the receipt's phase is {data['phase']}, not running")
    d = data["dir"]
    rc, out, err = c.as_user(f"touch {shlex.quote(d + '/stop')} && echo stopped")
    if rc != 0 or out != "stopped":
        raise Stop(2, f"cannot write the stop file (is admission open with a login pod?): {err or out}")
    data["stop_written"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    save(receipt, data)
    deadline, ok = time.time() + timeout, True
    for kind, p in data["probes"].items():
        rec = {}
        while time.time() < deadline:
            rec = c.job(p["job_id"]) or {}
            if rec.get("JobState") not in ("RUNNING", "COMPLETING", "PENDING", "CONFIGURING", "SUSPENDED"):
                break
            time.sleep(3)
        if rec.get("JobState") in (None, "COMPLETED", "FAILED", "CANCELLED", "TIMEOUT", "NODE_FAIL", "OUT_OF_MEMORY", "PREEMPTED"):
            rec = c.finished(p["job_id"]) or {}
        rc, text, err = c.as_user(f"cat {shlex.quote(p['file'])}")
        problems = verify_job(rec, p)
        if rc != 0:
            problems.append(f"cannot read {p['file']}: {err}")
            facts = {}
        else:
            log_problems, facts = verify_log(text)
            problems += log_problems + same_process(facts.get("header", {}), p["header"])
        p["result"] = {"pass": not problems, "problems": problems, "records": facts.get("records"),
                       "longest_gap_s": facts.get("max_gap"), "job_state": rec.get("JobState"), "exit": rec.get("ExitCode"),
                       "restarts": rec.get("Restarts")}
        ok &= not problems
        print(f"{'PASS' if not problems else 'FAIL'}: {kind} probe job {p['job_id']} on {p['node']}: {facts.get('records')} records, "
              f"longest gap {facts.get('max_gap')} s" + ("" if not problems else "; " + "; ".join(problems)))
    gone, data["cleanup"] = remove_when_over(c, data, receipt)
    print(f"{'PASS' if gone else 'FAIL'}: {d} removed and its absence shown" +
          ("" if gone else f" (not removed: {data['cleanup'].get('skipped') or data['cleanup'].get('detail')})"))
    data["phase"] = "finished" if ok and gone else "finished_with_failures"
    save(receipt, data)
    return 0 if ok and gone else 1


def abort(c, receipt):
    data = load(receipt)
    ids = [p["job_id"] for p in data["probes"].values()]
    left = c.a.cancel(ids) if ids else []
    if left:
        gone, record = False, {"removed_and_shown": False, "skipped": "cancellation not confirmed: " + ", ".join(left)}
    else:
        gone, record = remove_when_over(c, data, receipt)
    data.update(phase="aborted" if gone else "abort_incomplete", abort=dict(record, still_queued=left))
    save(receipt, data)
    print(json.dumps(data["abort"], sort_keys=True))
    return 0 if gone else 1


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    target = ap.add_mutually_exclusive_group(required=True)
    target.add_argument("--bench", action="store_true")
    target.add_argument("--fleet", action="store_true")
    ap.add_argument("--lease-id")
    ap.add_argument("command", choices=["start", "status", "finish", "abort"])
    ap.add_argument("--tag", required=True)
    ap.add_argument("--minutes", type=int, default=30)
    ap.add_argument("--timeout", type=int, default=300, help="finish: seconds to wait for the probes to end")
    a = ap.parse_args(argv)
    if a.fleet and not a.lease_id:
        ap.error("--fleet requires --lease-id")
    if a.bench and a.lease_id is not None:
        ap.error("--lease-id is only valid with --fleet")
    if a.lease_id is not None and not re.fullmatch("[0-9a-f]{16}", a.lease_id):
        ap.error("--lease-id must be exactly 16 lowercase hex digits")
    if not TAG.match(a.tag):
        ap.error("--tag: lowercase letters, digits and '-', at most 40")
    if not 1 <= a.minutes <= 120:
        ap.error("--minutes: 1 to 120")
    return a


def main(argv=None):
    a = parse_args(argv)
    acc = load_acceptance()
    acc.BENCH, acc.ADOPT = a.bench, a.lease_id
    receipt = RECEIPTS / f"{a.tag}.json"
    try:
        if not acc.lease_take():
            return 3
        if not a.bench and a.command != "status":
            rc, out, err = acc.login("k3s kubectl -n slurm get pods -o name | grep -m1 '^pod/slurm-login-'")
            if rc != 0 or not out:
                raise Stop(3, f"no login pod (admission closed?): {err or out}")
            acc.LOGIN_POD = out.split("/", 1)[1]
        c = Cluster(acc, a.bench)
        if a.command == "start":
            return start(c, a.tag, a.minutes, receipt)
        if a.command == "status":
            return status(c, receipt)
        if a.command == "finish":
            return finish(c, receipt, a.timeout)
        return abort(c, receipt)
    except Stop as e:
        print(f"{'refused' if e.code == 3 else 'failed'}: {e}", file=sys.stderr)
        return e.code
    finally:
        if not a.bench and acc.OWN_SSH:
            acc.sh(["ssh", "-o", f"ControlPath={acc.SSH_DIR}/cm", "-O", "exit", f"root@{acc.LOGIN}"])


if __name__ == "__main__":
    sys.exit(main())

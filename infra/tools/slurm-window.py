#!/usr/bin/env python3
"""Maintenance lease and admission fence for a Slurm window (Session B re-review R9, 30 Sep).

  slurm-window.py lease-take --label LABEL      take the cluster lease; prints its id
  slurm-window.py close --lease-id ID           close the fence, then check the queue
  slurm-window.py check --lease-id ID           re-read the fence and the queue (after every apply)
  slurm-window.py intent --lease-id ID          verified closed Ansible extra-vars JSON
  slurm-window.py prepare-open --lease-id ID    restore-intent JSON; apply the chart role next
  slurm-window.py open --lease-id ID            verify chart restore, then restore runtime baseline
  slurm-window.py status --lease-id ID          display the record and live states
  slurm-window.py lease-release --lease-id ID [--fenced]

The lease (/run/prace-cluster-lease, atomic mkdir) only keeps cooperating operators apart. The fence
stops jobs from starting and users from submitting: every partition INACTIVE (no new job is
accepted and no pending job starts) and every Slinky LoginSet at zero replicas (no login pod).
A runtime partition state need not survive a reconfiguration or a controller restart, and an
applied chart resets the LoginSets' replicas, so "check" after every apply, and "close" again
when it reports an open item. Closing never depends on the queue: a job left in the queue is
reported (exit 3) with the fence still closed, and "open" works whatever the queue holds.

The baseline is saved off-fleet before lease acquisition and never replaced by observed fence
states. New partitions need declare-partition --partition NAME --return-state STATE before an
apply. Partial operations retain the lease, including with --fenced. lease-take --recover-id ID
reacquires the SAME saved baseline after a lost lease; it never adopts current INACTIVE as UP.
The schema-2 record in ~/prace-recovery/slurm-window/<id>.json is private and fsynced. A shared
remote flock serializes commands and cooperating child tools. intent emits private Ansible
extra-vars only for a verified closed, empty-queue window. It does not keep that lock afterwards.
A native worker (T89) is fenced by its partitions like any other; to quarantine only that host,
drain it in Slurm (Slinky does not manage it, so kubectl cordon does not stop its jobs).

Exit: 0 done; 1 refused or a change did not take effect; 2 a query failed (nothing inferred from
it); 3 fenced, but jobs are in the queue. Every command runs as root on the login node over SSH
(PRACE_LOGIN, default 192.0.2.205); the tests substitute a fake one (PRACE_WINDOW_SSH).
"""
import argparse
import datetime as dt
import contextlib
import fcntl
import json
import re
import os
from pathlib import Path
import secrets
import select
import stat
import hashlib
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

LOGIN = os.environ.get("PRACE_LOGIN", "192.0.2.205")
LEASE = "/run/prace-cluster-lease"
RECORDS = Path(os.environ.get("PRACE_WINDOW_DIR", Path.home() / "prace-recovery/slurm-window"))
K = ["k3s", "kubectl", "-n", "slurm"]
CTL = K + ["exec", "slurm-controller-0", "-c", "slurmctld", "--"]
HELM_OWNER = ("helm", "Apply")   # the field manager of K3s's Helm upgrades (server-side apply)
STATES = ("UP", "DOWN", "DRAIN", "INACTIVE")
PHASES = {"acquiring", "leased", "closing", "closed", "opening", "restored", "releasing", "released", "acquire_failed"}
MARKER = LEASE + "/fence-intent.json"
ACTIVE_LOCK = None
WAIT = int(os.environ.get("PRACE_WINDOW_WAIT", "180"))   # seconds for login pods to go or to be ready
SSH_DIR = tempfile.mkdtemp(prefix="prace-window-")
SSH = (shlex.split(os.environ["PRACE_WINDOW_SSH"]) if os.environ.get("PRACE_WINDOW_SSH") else
       ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", "-o", "ControlMaster=auto",
        "-o", f"ControlPath={SSH_DIR}/cm", "-o", "ControlPersist=60", f"root@{LOGIN}"])


class Stop(Exception):
    def __init__(self, code, msg):
        super().__init__(msg)
        self.code = code


def login(argv, timeout=120):
    """(rc, stdout, stderr) of argv as root on the login node"""
    if ACTIVE_LOCK is not None and ACTIVE_LOCK.poll() is not None:
        raise Stop(1, "remote operation lock lost; no further command issued")
    try:
        r = subprocess.run(SSH + [shlex.join(argv)], capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 124, "", str(e)


def query(argv, what):
    rc, out, err = (ctl(argv[len(CTL):]) if argv[:len(CTL)] == CTL else login(argv))
    if rc != 0 or err:
        raise Stop(2, f"{what} failed (rc {rc}): {err or out or 'no output'}")
    return out


# A chart write that changes slurm.conf (a partition State) makes the operator replace the controller
# pod a few seconds after Helm reports success (3 Oct: close's partition query reached the old pod
# while it terminated, rc 2). Only these replacement errors are retried, within WAIT; the command's
# answer is never inferred, and any other error is returned at once.
TRANSIENT = ('container not found ("slurmctld")', "unable to upgrade connection", 'pods "slurm-controller-0" not found',
             "Unable to contact slurm controller",
             # 3 Oct, 18:34: open's partition query reached the replaced pod after its containers had exited
             "cannot exec into a container in a completed pod")


def ctl(argv):
    """(rc, stdout, stderr) of argv in slurmctld's container, waiting out a controller replacement"""
    deadline = time.monotonic() + WAIT
    while True:
        rc, out, err = login(CTL + argv)
        if not (rc or err) or not any(s in err for s in TRANSIENT) or time.monotonic() >= deadline:
            return rc, out, err
        time.sleep(0 if os.environ.get("PRACE_WINDOW_SSH") else 5)


def partitions():
    result = {}
    for line in query(CTL + ["scontrol", "show", "partition", "-o"], "partition query").splitlines():
        fields = dict(f.split("=", 1) for f in line.split() if "=" in f)
        name, state = fields.get("PartitionName"), fields.get("State")
        if not name or state not in STATES:
            raise Stop(2, f"unreadable partition line: {line[:120]}")
        if name in result:
            raise Stop(2, "duplicate partition name")
        result[name] = state
    if not result:
        raise Stop(2, "the controller lists no partition")
    return result


def loginsets():
    try:
        items = json.loads(query(K + ["get", "loginsets", "-o", "json"], "LoginSet query"))["items"]
        result = {}
        for i in items:
            name, uid, replicas = i["metadata"]["name"], i["metadata"]["uid"], i["spec"]["replicas"]
            if not isinstance(name, str) or not name or name in result or not isinstance(uid, str) or not uid or type(replicas) is not int or replicas < 0:
                raise ValueError("missing/duplicate identity or invalid replicas")
            result[name] = {"uid": uid, "replicas": replicas}
        if not result:
            raise ValueError("no LoginSets")
        return result
    except (ValueError, KeyError, TypeError) as e:
        raise Stop(2, f"unreadable LoginSet list: {e}")


def login_pods():
    try:
        items = json.loads(query(K + ["get", "pods", "-l", "app.kubernetes.io/name=login", "-o", "json"], "login pod query"))["items"]
        if not isinstance(items, list) or any(not isinstance(p.get("metadata"), dict) for p in items):
            raise ValueError("invalid pod list")
    except (ValueError, KeyError, TypeError, AttributeError) as e:
        raise Stop(2, f"unreadable login pod list: {e}")
    ready = [p for p in items if not p["metadata"].get("deletionTimestamp") and any(
        c.get("type") == "Ready" and c.get("status") == "True" for c in p.get("status", {}).get("conditions", []))]
    return len(items), len(ready)


def queue():
    out = query(CTL + ["squeue", "-a", "-h", "-o", "%i %u %T %P"], "queue query")
    return [l for l in out.splitlines() if l.strip()]


# --- the off-fleet record -------------------------------------------------------------------------
def record_path(lid):
    if not lid or not all(c in "0123456789abcdef" for c in lid) or len(lid) != 16:
        raise Stop(1, f"not a lease id from lease-take: {lid!r}")
    return RECORDS / f"{lid}.json"


def load(lid):
    p = record_path(lid)
    if not p.exists():
        raise Stop(1, f"no record {p}: this lease was not taken with lease-take on this workstation")
    try:
        if not stat.S_ISREG(p.lstat().st_mode) or p.stat().st_mode & 0o077:
            raise ValueError("record must be a private regular file")
        rec = json.loads(p.read_text())
        if rec.get("schema") != 2 or rec.get("id") != lid or rec.get("login") != LOGIN or rec.get("phase") not in PHASES:
            raise ValueError("unknown schema, phase, endpoint or id; preserve the saved baseline for explicit recovery")
        orig = rec["original"]
        if not orig["partitions"] or not orig["loginsets"] or any(v not in STATES for v in orig["partitions"].values()):
            raise ValueError("incomplete original baseline")
        for v in orig["loginsets"].values():
            if not v["uid"] or type(v["replicas"]) is not int or v["replicas"] < 0:
                raise ValueError("invalid original LoginSet")
        if type(rec["fence_intent"]["active"]) is not bool or not isinstance(rec["declared_partitions"], dict):
            raise ValueError("invalid fence intent")
        if any(v not in STATES for v in rec["declared_partitions"].values()) or set(orig["partitions"]) & set(rec["declared_partitions"]):
            raise ValueError("invalid partition return intent")
        ack = rec.get("restored_loginset")
        if ack is not None:
            keys = {"name", "original_uid", "restored_uid", "chart_uid", "job_uid", "object_sha256", "at"}
            if (not isinstance(ack, dict) or set(ack) != keys
                    or rec["phase"] not in {"restored", "releasing", "released"}
                    or rec["fence_intent"]["active"]
                    or ack["name"] not in orig["loginsets"]
                    or ack["original_uid"] != orig["loginsets"][ack["name"]]["uid"]
                    or ack["restored_uid"] == ack["original_uid"]
                    or any(not isinstance(ack[k], str) or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", ack[k])
                           for k in ("original_uid", "restored_uid", "chart_uid", "job_uid"))
                    or not isinstance(ack["object_sha256"], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", ack["object_sha256"])
                    or not isinstance(ack["at"], str)):
                raise ValueError("invalid terminal LoginSet restoration acknowledgement")
        return rec
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as e:
        raise Stop(1, f"invalid private window record: {e}")


def save(rec):
    RECORDS.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(RECORDS, 0o700)
    p = record_path(rec["id"])
    fd, tmp = tempfile.mkstemp(dir=RECORDS, prefix=".rec-")
    with os.fdopen(fd, "w") as f:
        json.dump(rec, f, indent=2, sort_keys=True)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
    fd = os.open(RECORDS, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def note(rec, event, emit=True):
    rec["history"].append({"at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), "event": event})
    save(rec)
    if emit:
        print(event)


@contextlib.contextmanager
def local_lock():
    RECORDS.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(RECORDS, 0o700)
    fd = os.open(RECORDS / ".operation.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Stop(1, "another local window operation is running")
        yield
    finally:
        os.close(fd)


LOCK_SERVER = r'''# prace-window-lock
import fcntl,json,os,stat,subprocess,sys
lid=sys.argv[1]
p='/run/prace-slurm-window-'+lid+'.lock'
fd=os.open(p,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
st=os.fstat(fd)
if not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o600:raise SystemExit(1)
fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
t=os.lstat(p)
if (t.st_dev,t.st_ino)!=(st.st_dev,st.st_ino):raise SystemExit(1)
print('locked',flush=True)
for line in sys.stdin:
 try:
  req=json.loads(line)
  if set(req)!={'refence'} or req['refence']['lease_id']!=lid:raise ValueError('invalid request')
  helper='/usr/local/sbin/prace-slinky-maintenance'
  overlay='/var/lib/rancher/k3s/server/manifests/prace-slinky-maintenance.yaml'
  if not os.path.lexists(helper) and not os.path.lexists(overlay):
   result={'ok':True,'initial_overlay_absent':True}
  else:
   r=subprocess.run([helper,'--refence','--lock-fd',str(fd)],input=json.dumps({'intent':req['refence']}),
                    text=True,capture_output=True,pass_fds=(fd,),timeout=180)
   result={'ok':r.returncode==0,'detail':(r.stderr or r.stdout)[-400:] if r.returncode else ''}
 except Exception as e:result={'ok':False,'detail':str(e)[:400]}
 print(json.dumps(result),flush=True)
'''


def refence_overlay(rec):
    """Ask the lock-owning remote process to invoke the role helper with its inherited FD."""
    if ACTIVE_LOCK is None or ACTIVE_LOCK.poll() is not None:
        raise Stop(1, "remote operation lock is not held")
    ACTIVE_LOCK.stdin.write(json.dumps({"refence": projection(rec)}) + "\n")
    ACTIVE_LOCK.stdin.flush()
    deadline, data = time.monotonic() + 200, b""
    while b"\n" not in data and len(data) < 8192:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        ready, _, _ = select.select([ACTIVE_LOCK.stdout], [], [], remaining)
        if not ready:
            break
        chunk = os.read(ACTIVE_LOCK.stdout.fileno(), 8192 - len(data))
        if not chunk:
            break
        data += chunk
    try:
        result = json.loads(data)
        if result.get("ok") is not True:
            raise ValueError(result.get("detail", "refence failed"))
    except (ValueError, TypeError, AttributeError) as e:
        raise Stop(1, f"persistent chart refence not confirmed: {e}; retain lease")


@contextlib.contextmanager
def operation_lock(lid):
    """Shared with child tools; the lock inode survives lease release. Never unlink it."""
    global ACTIVE_LOCK
    record_path(lid)
    argv = ["python3", "-c", LOCK_SERVER, lid]
    child = subprocess.Popen(SSH + [shlex.join(argv)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        ready, _, _ = select.select([child.stdout], [], [], 20)
        if not ready or os.read(child.stdout.fileno(), 7) != b"locked\n" or child.poll() is not None:
            raise Stop(1, "remote window operation lock unavailable; another operation may be running")
        ACTIVE_LOCK = child
        yield
        if child.poll() is not None:
            raise Stop(1, "remote operation lock was lost; retain the record and verify state")
    finally:
        ACTIVE_LOCK = None
        if child.stdin:
            child.stdin.close()
            child.stdin = None
        try:
            child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                pass


def projection(rec):
    return {"schema": 2, "lease_id": rec["id"], "phase": rec["phase"],
            "fence_active": rec["fence_intent"]["active"], "original": rec["original"],
            "declared_partitions": rec["declared_partitions"]}


def publish_marker(rec):
    code = '''# prace-window-marker
import json,os,sys,tempfile
p,data=sys.argv[1:];d=os.path.dirname(p)
fd,t=tempfile.mkstemp(prefix='.intent-',dir=d)
try:
 os.fchmod(fd,0o600)
 with os.fdopen(fd,'w') as f:f.write(data+'\\n');f.flush();os.fsync(f.fileno())
 os.replace(t,p)
 fd=os.open(d,os.O_RDONLY|os.O_DIRECTORY)
 try:os.fsync(fd)
 finally:os.close(fd)
finally:
 if os.path.exists(t):os.unlink(t)
'''
    rc, out, err = login(["python3", "-c", code, MARKER, json.dumps(projection(rec), sort_keys=True)])
    if rc or err:
        raise Stop(1, "fence intent marker was not confirmed; retain lease and retry the same record")


def transition(rec, phase, active, event, emit=True):
    rec["phase"] = phase
    rec["fence_intent"] = {"active": active}
    rec["fenced"] = phase == "closed"
    note(rec, event, emit)             # durable intent precedes any remote mutation
    publish_marker(rec)


def marker_matches(rec):
    try:
        got = json.loads(query(["cat", MARKER], "fence intent marker query"))
    except (ValueError, TypeError) as e:
        raise Stop(2, f"unreadable fence intent marker: {e}")
    if got != projection(rec):
        raise Stop(1, "live fence intent differs from the saved record; recover the same window")


# --- the lease ------------------------------------------------------------------------------------
def holder():
    rc, out, err = login(["cat", f"{LEASE}/holder"])
    if rc == 0 and not err:
        return out
    rc2, out2, err2 = login(["sh", "-c", f"test -e {LEASE} || test -L {LEASE}"])
    if rc2 == 1 and not out2 and not err2:
        return ""
    raise Stop(2, f"lease query failed: {err or 'no output'}")


def require_lease(lid):
    h = holder()
    fields = [f.split("=", 1) for f in h.split()]
    if any(len(f) != 2 for f in fields) or len({f[0] for f in fields}) != len(fields):
        raise Stop(1, "malformed cluster lease: nothing changed")
    fields = dict(fields)
    rec = load(lid)
    if fields.get("id") != lid or fields.get("holder") != "maint" or fields.get("label") != rec["label"] or not fields.get("since"):
        raise Stop(1, f"the cluster lease is not {lid} ({h or 'no lease held'}): nothing changed")


def lease_take(label, recover_id=None):
    if not label.replace("-", "").isalnum():
        raise Stop(1, "label: letters, digits and '-' only")
    if holder():
        raise Stop(1, "the cluster is already leased; use its owning record")
    if recover_id:
        rec = load(recover_id)
        if rec.get("restored_loginset"):
            # Reacquire ownership only for release of this same already-restored
            # baseline, never to adopt the current state or create a new fence.
            verify_restored(rec)
            verify_overlay(rec)
        lid, label = rec["id"], rec["label"]
        rec["recovering"] = True          # the saved phase is kept until the lease is confirmed
        note(rec, f"explicitly reacquiring the same saved baseline (saved phase {rec['phase']})")
    else:
        previous = []
        for path in sorted(RECORDS.glob("*.json")):
            if not re.fullmatch("[0-9a-f]{16}", path.stem):
                continue                  # only lease records live here by name; anything else is not a window
            old = load(path.stem)
            if old["phase"] not in {"released", "acquire_failed"} or old["fence_intent"]["active"] or old.get("recovering"):
                raise Stop(1, f"unresolved prior window {old['id']}; recover THAT saved baseline with lease-take --recover-id")
            if old["phase"] == "released":
                previous.append(old)
        parts, sets = partitions(), loginsets()
        if all(s == "INACTIVE" for s in parts.values()) and all(v["replicas"] == 0 for v in sets.values()):
            raise Stop(1, "unexplained existing admission fence; recover its saved baseline, do not take a new one")
        for old in sorted(previous, key=lambda r: r["history"][-1]["at"], reverse=True)[:1]:
            baseline = return_partitions(old)
            if any(parts.get(n) == "INACTIVE" and s != "INACTIVE" for n, s in baseline.items()) or any(
                    n in sets and sets[n]["replicas"] == 0 and v["replicas"] > 0 for n, v in old["original"]["loginsets"].items()):
                raise Stop(1, "live admission differs from the last restored baseline like a leftover fence; preserve records and reconcile it")
        lid = secrets.token_hex(8)
        rec = {"schema": 2, "id": lid, "label": label, "login": LOGIN, "phase": "acquiring",
               "original": {"partitions": parts, "loginsets": sets}, "declared_partitions": {},
               "introduced_partitions": [], "fence_intent": {"active": False}, "fenced": False, "history": []}
        note(rec, "baseline saved before lease acquisition", emit=False)
    line = f"holder=maint label={label} id={lid} since="
    rc, out, err = login(["sh", "-c", f'umask 077; mkdir {LEASE} && echo "{line}$(date -Is)" > {LEASE}/holder && cat {LEASE}/holder'])
    if rc != 0 or f"id={lid} " not in out + " ":
        current = holder()
        if f"id={lid} " not in current + " " and not recover_id and not rec.get("ever_leased"):
            rec["phase"] = "acquire_failed"   # only a record that never held a lease
        note(rec, f"lease acquisition not confirmed; saved baseline retained; held: {current or 'nothing'}")
        raise Stop(1, "the cluster lease was not taken")
    with operation_lock(lid):
        require_lease(lid)
        rec["ever_leased"] = True
        note(rec, "lease confirmed", emit=False)
        if recover_id:
            rec.pop("recovering", None)
            if rec.get("restored_loginset"):
                transition(rec, "restored", False, "terminal release-only lease reacquired; fresh baseline verification required")
                verify_restored(rec)
                verify_overlay(rec)
            else:
                transition(rec, "closing", True, "recovered lease; complete close or restore the saved baseline")
        else:
            parts, sets = observe(rec)
            if parts != rec["original"]["partitions"] or sets != rec["original"]["loginsets"]:
                raise Stop(1, "admission changed during acquisition; retain the lease and saved baseline")
            transition(rec, "leased", False, f"lease taken: {out}")
    print(lid)


def lease_release(lid, fenced_ok):
    rec = load(lid)
    require_lease(lid)
    if rec["phase"] not in {"leased", "restored", "closed"}:
        raise Stop(1, "partial or unknown operation: lease release refused even with --fenced")
    if rec["phase"] == "closed":
        if not fenced_ok:
            raise Stop(1, "the fence is closed: restore it first, or explicitly release a verified fence with --fenced")
        parts, _ = verify_closed(rec, require_quiet=True)
        overlay_closed(rec, parts, allow_absent=False)
    else:
        verify_restored(rec)
        if rec["phase"] == "restored":
            verify_overlay(rec)
    marker_matches(rec)
    rec["release_fenced"] = rec["phase"] == "closed"
    rec["phase"] = "releasing"
    note(rec, "lease release intent saved", emit=False)
    code = '''# prace-window-lease-release
import os,stat,sys
p,lid,label=sys.argv[1:]
if not stat.S_ISDIR(os.lstat(p).st_mode):raise SystemExit(1)
names=set(os.listdir(p))
if names!={'holder','fence-intent.json'}:raise SystemExit('unexpected lease contents; nothing removed')
if any(not stat.S_ISREG(os.lstat(p+'/'+n).st_mode) for n in names):raise SystemExit(1)
fields=dict(x.split('=',1) for x in open(p+'/holder').read().split())
if fields.get('id')!=lid or fields.get('holder')!='maint' or fields.get('label')!=label:raise SystemExit(1)
for n in names:os.unlink(p+'/'+n)
os.rmdir(p)
'''
    rc, out, err = login(["python3", "-c", code, LEASE, lid, rec["label"]])
    if rc != 0 or err:
        raise Stop(1, f"lease not released: {err or out or 'no output'}")
    rec["phase"] = "released"
    note(rec, "lease released" + (" with the fence CLOSED; same-baseline recovery required" if rec["release_fenced"] else " after baseline restoration"))


# --- the fence ------------------------------------------------------------------------------------
def return_partitions(rec):
    return dict(rec["original"]["partitions"], **rec["declared_partitions"])


def observe(rec, require_declared=False):
    """Validate the complete object set before any restoration; never learn a return state here."""
    parts, sets = partitions(), loginsets()
    wanted = return_partitions(rec)
    missing = set(rec["original"]["partitions"]) - set(parts)
    missing |= set(rec.get("introduced_partitions", [])) - set(parts)
    if require_declared:
        missing |= set(wanted) - set(parts)
    if missing or set(parts) - set(wanted):
        raise Stop(1, "partition membership changed: missing=" + ",".join(sorted(missing)) +
                   "; undeclared=" + ",".join(sorted(set(parts) - set(wanted))))
    if set(sets) != set(rec["original"]["loginsets"]):
        raise Stop(1, "LoginSet membership changed; all saved objects must be present")
    for n, v in sets.items():
        expected_uid = rec["original"]["loginsets"][n]["uid"]
        ack = rec.get("restored_loginset")
        if ack and n == ack["name"]:
            if rec["phase"] not in {"restored", "releasing", "released"}:
                raise Stop(1, "terminal restoration acknowledgement cannot be used to close or capture")
            expected_uid = ack["restored_uid"]
        if v["uid"] != expected_uid:
            raise Stop(1, f"loginset {n} was replaced; restore its saved identity before reopening")
    introduced = sorted(set(parts) - set(rec["original"]["partitions"]))
    if introduced != rec.get("introduced_partitions", []):
        rec["introduced_partitions"] = introduced
        note(rec, "declared partitions observed: " + ", ".join(introduced), emit=False)
    return parts, sets


def open_items(parts, sets, pods):
    items = [f"partition {n} is {s}" for n, s in sorted(parts.items()) if s != "INACTIVE"]
    items += [f"loginset {n} has {v['replicas']} replicas" for n, v in sorted(sets.items()) if v["replicas"] != 0]
    if pods:
        items.append(f"{pods} login pod(s) present")
    return items


def patch_replicas(name, uid, replicas):
    patch = json.dumps([{"op": "test", "path": "/metadata/uid", "value": uid},
                        {"op": "replace", "path": "/spec/replicas", "value": replicas}])
    for attempt in range(6):
        rc, out, err = login(K + ["patch", "loginset", name, "--type=json", "-p", patch])
        if rc == 0 and not err:
            release_replicas(name, uid)
            return
        if attempt < 5:
            time.sleep(0 if os.environ.get("PRACE_WINDOW_SSH") else 10)
    raise Stop(1, f"loginset {name}: replicas not set to {replicas}: {err or out}")


def replica_owners(obj):
    """(index, manager, operation) of every managedFields entry other than Helm's apply that owns .spec.replicas"""
    return [(i, m["manager"], m["operation"]) for i, m in enumerate(obj["metadata"].get("managedFields") or [])
            if (m.get("manager"), m.get("operation")) != HELM_OWNER and "f:replicas" in ((m.get("fieldsV1") or {}).get("f:spec") or {})]


def release_replicas(name, uid):
    """Leave a LoginSet's replica count to Helm alone. kubectl patch makes its field manager an owner
    of .spec.replicas, and K3s's Helm (v4) upgrades by server-side apply, which refuses to change a
    field another manager owns. On 3 Oct the opening overlay (replicas 0 to 1) failed on the owner the
    close's patch left (revision 5 failed; abort held, so no reinstall). Removing the other owners'
    entries changes no value: the next chart write sets the count, as Helm's own field."""
    what = f"loginset {name} field owners"
    err = out = ""
    for attempt in range(7):
        try:
            obj = json.loads(query(K + ["get", "loginset", name, "-o", "json", "--show-managed-fields"], what + " query"))
            if obj["metadata"]["uid"] != uid:
                raise Stop(1, f"loginset {name} was replaced; restore its saved identity first")
            owners, entries, version = replica_owners(obj), obj["metadata"].get("managedFields") or [], obj["metadata"]["resourceVersion"]
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            raise Stop(2, f"unreadable {what}: {e}")
        if not owners:
            if attempt:
                print(f"loginset {name}: replica count left to Helm alone", file=sys.stderr)
            return
        if attempt == 6:
            break
        if len(owners) == len(entries):
            # an empty managedFields list in a patch is ignored by the API server: never strip every entry
            raise Stop(1, f"{what}: no Helm entry beside " + ", ".join(f"{m}/{o}" for _, m, o in owners))
        ops = [{"op": "test", "path": "/metadata/uid", "value": uid},
               {"op": "test", "path": "/metadata/resourceVersion", "value": version}]
        for i, manager, operation in reversed(owners):   # highest index first: earlier indices stay valid
            ops += [{"op": "test", "path": f"/metadata/managedFields/{i}/manager", "value": manager},
                    {"op": "test", "path": f"/metadata/managedFields/{i}/operation", "value": operation},
                    {"op": "remove", "path": f"/metadata/managedFields/{i}"}]
        rc, out, err = login(K + ["patch", "loginset", name, "--type=json", "-p", json.dumps(ops)])
        if rc or err:
            time.sleep(0 if os.environ.get("PRACE_WINDOW_SSH") else 2)
    raise Stop(1, f"{what} not released to Helm: " + (err or out or ", ".join(f"{m}/{o}" for _, m, o in owners)))


def quiet_or_3(rec, emit=True):
    jobs = queue()
    if jobs:
        if emit:
            note(rec, f"FENCED, but {len(jobs)} job(s) remain (running jobs are not stopped): " + "; ".join(jobs[:10]))
        raise Stop(3, "not quiescent: wait for or cancel jobs before a disruptive step")
    if emit:
        note(rec, "fenced and quiet: every partition INACTIVE, no login pod, empty queue")


def verify_closed(rec, require_quiet=False, require_declared=False):
    parts, sets = observe(rec, require_declared)
    pods, _ = login_pods()
    items = open_items(parts, sets, pods)
    if items:
        raise Stop(1, "fence OPEN: " + "; ".join(items) + " (complete close using the same record)")
    if require_quiet:
        quiet_or_3(rec, emit=False)
    return parts, sets


def verify_restored(rec):
    parts, sets = observe(rec, require_declared=True)
    wantparts = return_partitions(rec)
    pods, ready = login_pods()
    want = sum(v["replicas"] for v in rec["original"]["loginsets"].values())
    wrong = [f"partition {n} is {s}, recorded {wantparts[n]}" for n, s in parts.items() if s != wantparts[n]]
    wrong += [f"loginset {n} has {v['replicas']}, recorded {rec['original']['loginsets'][n]['replicas']}"
              for n, v in sets.items() if v["replicas"] != rec["original"]["loginsets"][n]["replicas"]]
    if pods != want or ready != want:
        wrong.append(f"{ready}/{pods} login pod(s) ready, {want} expected")
    if wrong:
        raise Stop(1, "baseline NOT restored: " + "; ".join(wrong))
    return parts, sets


OVERLAY = "/var/lib/rancher/k3s/server/manifests/prace-slinky-maintenance.yaml"


def overlay_objects():
    """(persistent, applied) chart overlays, each parsed or None when absent; a failed query is Stop(2)"""
    rc, out, err = login(["sh", "-c", f"test -e {OVERLAY} || test -L {OVERLAY}"])
    if rc == 1 and not out and not err:
        persistent = None
    elif rc == 0 and not err:
        persistent = query(["cat", OVERLAY], "persistent chart overlay query")
    else:
        raise Stop(2, f"persistent chart overlay query failed (rc {rc}): {err or out or 'no output'}")
    applied = query(["k3s", "kubectl", "-n", "kube-system", "get", "helmchartconfig", "slurm", "--ignore-not-found", "-o", "json"],
                    "applied chart overlay query")
    try:
        return (json.loads(persistent) if persistent is not None else None), (json.loads(applied) if applied else None)
    except ValueError as e:
        raise Stop(2, f"unreadable chart overlay: {e}")


def overlay_states(obj):
    """(window id, phase, partition states, LoginSet replicas) of one overlay object"""
    meta = obj["metadata"]
    if obj["kind"] != "HelmChartConfig" or obj["apiVersion"] != "helm.cattle.io/v1" or meta["name"] != "slurm" or meta["namespace"] != "kube-system":
        raise ValueError("wrong chart identity")
    values = json.loads(obj["spec"]["valuesContent"])
    actual = {}
    for name, item in values.get("nodesets", {}).items():
        if "partition" in item:
            actual[name] = item["partition"]["configMap"]["State"]
    for name, item in values.get("partitions", {}).items():
        if name in actual:
            raise ValueError("duplicate chart partition")
        actual[name] = item["configMap"]["State"]
    native = values.get("controller", {}).get("extraConfMap", {}).get("PartitionName")
    if native is not None:
        # Helm serializes PartitionName as `cpu Nodes=cpu ... State=UP`.
        for line in native.splitlines():
            fields = line.split()
            states = [f.split("=", 1)[1] for f in fields[1:] if f.startswith("State=")]
            if len(states) != 1 or fields[0] not in actual or actual[fields[0]] != states[0]:
                raise ValueError("native partition state differs from chart partition")
    replicas = {n: v["replicas"] for n, v in values["loginsets"].items()}
    return meta["annotations"].get("prace.fleet/window-id"), meta["annotations"].get("prace.fleet/window-phase"), actual, replicas


def overlay_closed(rec, parts, allow_absent):
    """The persistent and applied overlays both hold this window closed: owned by it, every partition
    INACTIVE, no login replica, and every live partition covered (a partition the overlay does not
    name comes back at its chart state on the next reconcile). Returns False only when no overlay
    exists and allow_absent (the first close, before the overlay is installed)."""
    persistent, applied = overlay_objects()
    if persistent is None and applied is None:
        if allow_absent:
            return False
        raise Stop(1, "no persistent maintenance overlay holds this fence: install the closed overlay (intent, then the overlay playbook)")
    for label, obj in (("persistent", persistent), ("applied", applied)):
        try:
            if obj is None:
                raise ValueError("missing while the other exists")
            wid, phase, states, replicas = overlay_states(obj)
            if wid != rec["id"] or phase != "closed":
                raise ValueError(f"owned by window {wid} in phase {phase}, not closed by this one")
            if any(s != "INACTIVE" for s in states.values()) or any(r != 0 for r in replicas.values()):
                raise ValueError("not every partition INACTIVE and LoginSet at zero")
            uncovered = sorted(set(parts) - set(states))
            if uncovered:
                raise ValueError("does not name partition(s) " + ",".join(uncovered))
        except (ValueError, TypeError, KeyError, AttributeError, IndexError) as e:
            raise Stop(1, f"{label} maintenance overlay does not hold the fence: {e}; refresh it (intent, then the overlay playbook)")
    if not rec.get("overlay_seen"):
        rec["overlay_seen"] = True
        note(rec, "persistent overlay holds the fence", emit=False)
    return True


def verify_overlay(rec):
    """Both the persistent manifest and applied object must restore the saved chart baseline."""
    sources = [("persistent", ["cat", OVERLAY]),
               ("applied", ["k3s", "kubectl", "-n", "kube-system", "get", "helmchartconfig", "slurm", "-o", "json"])]
    for label, argv in sources:
        try:
            obj = json.loads(query(argv, f"{label} chart overlay query"))
            wid, phase, actual, got = overlay_states(obj)
            if wid != rec["id"] or phase != "opening":
                raise ValueError("chart still fenced or owned by another window")
            if actual != return_partitions(rec):
                raise ValueError("chart partition return states differ from the saved baseline")
            expected = {}
            for name, item in rec["original"]["loginsets"].items():
                if not name.startswith("slurm-login-"):
                    raise ValueError("unsupported LoginSet/chart name mapping")
                expected[name[len("slurm-login-"):]] = item["replicas"]
            if got != expected:
                raise ValueError("chart LoginSet return replicas differ from the saved baseline")
        except (ValueError, TypeError, KeyError, AttributeError, IndexError) as e:
            raise Stop(1, f"{label} overlay not restored: {e}; apply the role with prepare-open intent first")


def close(lid):
    require_lease(lid)
    rec = load(lid)
    if rec["phase"] in {"released", "releasing", "acquire_failed"}:
        raise Stop(1, "cannot close a released/unknown lease; recover the same saved baseline first")
    # A failed query is also an unresolved close, so save intent before all observations.
    transition(rec, "closing", True, "close intent saved; retain lease until closure is verified")
    # Tighten first, whatever is live (an undeclared partition, a replaced LoginSet by its current
    # UID); validation against the saved baseline comes after, so a discrepancy never leaves admission open.
    parts, sets = partitions(), loginsets()
    for n, s in sorted(parts.items()):
        if s != "INACTIVE":
            rc, out, err = ctl(["scontrol", "update", f"PartitionName={n}", "State=INACTIVE"])
            if rc or err:
                raise Stop(1, f"partition {n} not confirmed INACTIVE: {err or out}")
    for n, v in sorted(sets.items()):
        if v["replicas"] != 0:
            patch_replicas(n, v["uid"], 0)
    refence_overlay(rec)
    deadline = time.monotonic() + WAIT
    while login_pods()[0]:
        if time.monotonic() >= deadline:
            break
        time.sleep(0 if os.environ.get("PRACE_WINDOW_SSH") else 5)
    parts, _ = verify_closed(rec)
    # A broken queue query is unknown, not a completed closure; jobs are known non-quiescence.
    jobs = queue()
    transition(rec, "closed", True, "fence closed")
    if not overlay_closed(rec, parts, allow_absent=not rec.get("overlay_seen")):
        note(rec, "no persistent overlay installed yet: install it (intent, then the overlay playbook) before any converge")
    if jobs:
        note(rec, f"FENCED, but {len(jobs)} job(s) remain (running jobs are not stopped): " + "; ".join(jobs[:10]))
        raise Stop(3, "not quiescent: wait for or cancel jobs before a disruptive step")
    note(rec, "fenced and quiet: every partition INACTIVE, no login pod, empty queue")


def check(lid):
    require_lease(lid)
    rec = load(lid)
    if rec["phase"] not in {"closing", "closed"}:
        raise Stop(1, "check requires a closing or closed window")
    try:
        parts, _ = verify_closed(rec)
        jobs = queue()
    except Stop:
        transition(rec, "closing", True, "closure no longer verified; lease retained", emit=False)
        raise
    if rec["phase"] != "closed":
        transition(rec, "closed", True, "closure verified after interrupted close")
    marker_matches(rec)
    if not overlay_closed(rec, parts, allow_absent=not rec.get("overlay_seen")):
        note(rec, "no persistent overlay installed yet: install it (intent, then the overlay playbook) before any converge")
    if jobs:
        raise Stop(3, "fenced, but jobs remain; running jobs are not stopped")
    note(rec, "fenced and quiet: every partition INACTIVE, no login pod, empty queue")


def declare_partition(lid, name, state):
    if not name or not all(c.isascii() and (c.isalnum() or c in "_-") for c in name) or state not in STATES:
        raise Stop(1, "declare-partition requires a safe --partition name and explicit --return-state")
    require_lease(lid)
    rec = load(lid)
    if rec["phase"] != "closed":
        raise Stop(1, "partition declaration requires a closed window")
    verify_closed(rec, require_quiet=True)
    marker_matches(rec)
    if name in rec["original"]["partitions"] or (name in rec["declared_partitions"] and rec["declared_partitions"][name] != state):
        raise Stop(1, "the saved return state is immutable")
    rec["declared_partitions"][name] = state
    note(rec, f"declared partition {name} return state {state}")
    publish_marker(rec)


def intent(lid):
    require_lease(lid)
    rec = load(lid)
    if rec["phase"] != "closed" or not rec["fence_intent"]["active"]:
        raise Stop(1, "intent requires a closed window")
    verify_closed(rec, require_quiet=True)
    marker_matches(rec)
    print(json.dumps({"slurm_window_intent": projection(rec)}, sort_keys=True))


def prepare_open(lid):
    require_lease(lid)
    rec = load(lid)
    if rec["phase"] not in {"closed", "closing", "opening"}:
        raise Stop(1, "prepare-open requires the same closed or interrupted window")
    if rec["phase"] == "opening":
        _, sets = observe(rec, require_declared=True)
        marker_matches(rec)
    else:
        _, sets = verify_closed(rec, require_declared=True)
    # the opening chart write changes the replica count: Helm must own it alone (3 Oct, revision 5)
    for n, v in sorted(sets.items()):
        release_replicas(n, v["uid"])
    if rec["phase"] != "opening":
        transition(rec, "opening", False, "restore intent saved; chart restore and runtime verification still required", emit=False)
    print(json.dumps({"slurm_window_intent": projection(rec)}, sort_keys=True))


def reopen(lid):
    require_lease(lid)
    rec = load(lid)
    if rec["phase"] not in {"opening", "restored"}:
        raise Stop(1, "run prepare-open, then apply the chart role with that intent before open")
    parts, sets = observe(rec, require_declared=True)  # every identity first, before ANY state change
    marker_matches(rec)
    verify_overlay(rec)
    transition(rec, "opening", False, "restoring the saved baseline; lease retained until verified")
    wanted = return_partitions(rec)
    for n, s in sorted(parts.items()):
        if s != wanted[n]:
            rc, out, err = ctl(["scontrol", "update", f"PartitionName={n}", f"State={wanted[n]}"])
            if rc or err:
                raise Stop(1, f"partition {n} not confirmed restored: {err or out}")
    for n, v in sorted(sets.items()):
        replicas = rec["original"]["loginsets"][n]["replicas"]
        if v["replicas"] != replicas:
            patch_replicas(n, v["uid"], replicas)
    want = sum(v["replicas"] for v in rec["original"]["loginsets"].values())
    deadline = time.monotonic() + WAIT
    while login_pods() != (want, want):
        if time.monotonic() >= deadline:
            break
        time.sleep(0 if os.environ.get("PRACE_WINDOW_SSH") else 5)
    parts, _ = verify_restored(rec)
    verify_overlay(rec)
    available = any(s == "UP" for s in parts.values()) and want > 0
    rec["baseline_available"] = available
    transition(rec, "restored", False, "baseline restored; workload admission available: " + str(available).lower())


def accept_restored_loginset(lid, name, old_uid, new_uid, chart_uid, job_uid, acknowledged):
    """Terminal recovery only: acknowledge an already-restored, pinned Helm replacement.

    No Kubernetes mutation and no learning of admission return states. The original
    baseline stays immutable. This record may then be inspected/released, never
    used for another close/capture; a subsequent window saves its own identities.
    """
    require_lease(lid)
    rec = load(lid)
    ack = rec.get("restored_loginset")
    if ack:
        if (not acknowledged or rec["phase"] != "restored"
                or (name, old_uid, new_uid, chart_uid, job_uid) !=
                   tuple(ack[k] for k in ("name", "original_uid", "restored_uid", "chart_uid", "job_uid"))):
            raise Stop(1, "terminal acknowledgement retry must use the same saved identity pins")
        got = json.loads(query(["cat", MARKER], "terminal restoration marker query"))
        prior = projection(rec) | {"phase": "opening"}
        if got not in (projection(rec), prior):
            raise Stop(1, "terminal restoration marker is not this window's saved transition")
        verify_restored(rec)
        verify_overlay(rec)
        publish_marker(rec)
        print("terminal restoration acknowledgement and marker reverified; original baseline retained")
        return
    if (not acknowledged or rec["phase"] != "opening" or rec["fence_intent"]["active"]
            or name not in rec["original"]["loginsets"]
            or old_uid != rec["original"]["loginsets"][name]["uid"] or old_uid == new_uid):
        raise Stop(1, "explicit owned chart-reinstall acknowledgement requires the saved opening baseline")
    marker_matches(rec)
    verify_overlay(rec)

    def obj(argv, kind, namespace, object_name, uid):
        try:
            value = json.loads(query(argv, kind + " restoration provenance"))
            meta = value["metadata"]
            if (not isinstance(meta, dict) or value.get("kind") != kind or meta.get("namespace") != namespace
                    or meta.get("name") != object_name or meta.get("uid") != uid
                    or meta.get("deletionTimestamp")):
                raise ValueError("object identity differs from explicit pins")
            return value
        except (ValueError, TypeError, KeyError, AttributeError) as e:
            raise Stop(1, "unverified chart replacement provenance: " + str(e))

    current = obj(K + ["get", "loginset", name, "-o", "json"], "LoginSet", "slurm", name, new_uid)
    chart = obj(["k3s", "kubectl", "-n", "kube-system", "get", "helmchart", "slurm", "-o", "json"],
                "HelmChart", "kube-system", "slurm", chart_uid)
    job = obj(["k3s", "kubectl", "-n", "kube-system", "get", "job", "helm-install-slurm", "-o", "json"],
              "Job", "kube-system", "helm-install-slurm", job_uid)
    meta, jm, js = current["metadata"], job["metadata"], job.get("status", {})
    if (not isinstance(js, dict) or any(not isinstance(m.get(k, {}), dict)
            for m in (meta, jm) for k in ("labels", "annotations"))
            or not isinstance(jm.get("ownerReferences", []), list)
            or not all(isinstance(o, dict) for o in jm.get("ownerReferences", []))
            or not isinstance(js.get("conditions", []), list)
            or not all(isinstance(c, dict) for c in js.get("conditions", []))):
        raise Stop(1, "malformed chart replacement provenance")
    if (meta.get("labels", {}).get("app.kubernetes.io/managed-by") != "Helm"
            or meta.get("annotations", {}).get("meta.helm.sh/release-name") != "slurm"
            or meta.get("annotations", {}).get("meta.helm.sh/release-namespace") != "slurm"
            or jm.get("labels", {}).get("helmcharts.helm.cattle.io/chart") != "slurm"
            or not any(o.get("kind") == "HelmChart" and o.get("name") == "slurm"
                       and o.get("uid") == chart["metadata"]["uid"] for o in jm.get("ownerReferences", []))
            or type(js.get("succeeded")) is not int or js["succeeded"] != 1
            or any(type(js.get(k, 0)) is not int or js.get(k, 0) != 0 for k in ("failed", "active"))
            or not any(c.get("type") == "Complete" and c.get("status") == "True" for c in js.get("conditions", []))):
        raise Stop(1, "replacement is not owned by the pinned successful Slurm Helm job")
    try:
        opening = next(h["at"] for h in rec["history"] if h["event"].startswith("restore intent saved;"))
        parse = lambda value: dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        start, created, job_created = parse(opening), parse(meta["creationTimestamp"]), parse(jm["creationTimestamp"])
        if any(v.tzinfo is None for v in (start, created, job_created)) or not start <= job_created <= created:
            raise ValueError("replacement predates the owned opening reconciliation")
    except (ValueError, TypeError, KeyError, StopIteration, AttributeError):
        raise Stop(1, "replacement chronology is unverified")

    parts, sets = partitions(), loginsets()
    expected = rec["original"]["loginsets"]
    wanted = sum(v["replicas"] for v in expected.values())
    if (parts != return_partitions(rec) or set(sets) != set(expected)
            or any(v["replicas"] != expected[n]["replicas"]
                   or v["uid"] != (new_uid if n == name else expected[n]["uid"]) for n, v in sets.items())
            or login_pods() != (wanted, wanted) or queue()):
        raise Stop(1, "recorded admission baseline is not already restored and quiet; nothing acknowledged")
    marker_matches(rec)
    verify_overlay(rec)
    # Only a separate acknowledgement is saved; original return values/UID are untouched.
    rec["restored_loginset"] = {"name": name, "original_uid": old_uid, "restored_uid": new_uid,
                               "chart_uid": chart_uid, "job_uid": job_uid,
                               "object_sha256": hashlib.sha256(json.dumps(current, sort_keys=True).encode()).hexdigest(),
                               "at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
    rec["baseline_available"] = any(v == "UP" for v in parts.values()) and wanted > 0
    transition(rec, "restored", False, "saved admission values verified; pinned Helm LoginSet replacement acknowledged separately")


def status(lid):
    rec = load(lid)
    print(json.dumps({k: rec[k] for k in ("schema", "id", "label", "phase", "fence_intent", "original", "declared_partitions")}, indent=2, sort_keys=True))
    print("lease:", holder() or "none")
    parts, sets = partitions(), loginsets()
    pods, ready = login_pods()
    print("partitions:", parts)
    print("loginsets:", {n: v["replicas"] for n, v in sets.items()}, f"login pods {ready}/{pods} ready")
    print("queue:", queue() or "empty")


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("action", choices=["lease-take", "close", "check", "intent", "declare-partition", "prepare-open", "open", "status", "lease-release", "accept-restored-loginset"])
    p.add_argument("--lease-id")
    p.add_argument("--recover-id", help="lease-take: reacquire exactly this saved baseline")
    p.add_argument("--label", default="slurm-window")
    p.add_argument("--partition")
    p.add_argument("--return-state", choices=STATES)
    p.add_argument("--fenced", action="store_true", help="lease-release: leave a verified quiet fence closed")
    p.add_argument("--loginset")
    p.add_argument("--old-uid")
    p.add_argument("--new-uid")
    p.add_argument("--chart-uid")
    p.add_argument("--job-uid")
    p.add_argument("--ack-chart-reinstall", action="store_true")
    a = p.parse_args(argv)
    if a.action == "accept-restored-loginset":
        pins = (a.old_uid, a.new_uid, a.chart_uid, a.job_uid)
        if (not a.ack_chart_reinstall or not a.loginset or not re.fullmatch(r"slurm-login-[a-z][a-z0-9_-]*", a.loginset)
                or any(not v or not re.fullmatch(r"[A-Za-z0-9-]{1,128}", v) for v in pins)):
            p.error("explicit LoginSet/old/new/chart/job UID pins and --ack-chart-reinstall are required")
    try:
        with local_lock():
            if a.action == "lease-take":
                lease_take(a.label, a.recover_id)
            else:
                if not a.lease_id:
                    p.error("--lease-id is required")
                if load(a.lease_id).get("restored_loginset") and a.action not in {"status", "lease-release", "accept-restored-loginset"}:
                    raise Stop(1, "terminal restoration acknowledgement permits status/release or same-pin retry only; take a new window after release")
                with operation_lock(a.lease_id):
                    actions = {"close": close, "check": check, "intent": intent, "prepare-open": prepare_open,
                               "open": reopen, "status": status,
                               "declare-partition": lambda lid: declare_partition(lid, a.partition, a.return_state),
                               "accept-restored-loginset": lambda lid: accept_restored_loginset(lid, a.loginset, a.old_uid,
                                   a.new_uid, a.chart_uid, a.job_uid, a.ack_chart_reinstall),
                               "lease-release": lambda lid: lease_release(lid, a.fenced)}
                    actions[a.action](a.lease_id)
        return 0
    except Stop as e:
        print(f"{'REFUSED' if e.code == 1 else 'QUERY FAILED' if e.code == 2 else 'NOT QUIET'}: {e}", file=sys.stderr)
        return e.code
    except (OSError, ValueError) as e:
        print(f"REFUSED: local/transport operation failed: {e}", file=sys.stderr)
        return 1
    finally:
        if not os.environ.get("PRACE_WINDOW_SSH"):
            try:
                subprocess.run(["ssh", "-o", f"ControlPath={SSH_DIR}/cm", "-O", "exit", f"root@{LOGIN}"], capture_output=True, timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
        shutil.rmtree(SSH_DIR, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())

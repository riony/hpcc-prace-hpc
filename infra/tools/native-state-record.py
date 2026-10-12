#!/usr/bin/env python3
"""X1 of the native-window plan (docs/runbooks/NATIVE-WINDOW-2026-10-05-PLAN.md): the hash-bound
native recovery record of one recovery point. Session A's decision (MR !98 notes 882, 935): the
native Lenovo is reconstructed from the exact git pin and the restored controller Secrets, and this
record, captured inside the point's own owned, closed and quiet window, binds that derivation to the
point. A integrates it into capture/verification; R-N1..R-N6 are proven by an isolated restore.

Read-only everywhere, strict host keys (BatchMode, StrictHostKeyChecking=yes, the jump too):
  - the common window contract, before and after: `slurm-window.py check --lease-id ID` must exit 0
    (fenced and quiet: every partition INACTIVE, no login pod, an empty queue);
  - the login node, one stdlib-only program, read twice (a stable re-read): the lease holder, its
    native list, the slurm HelmChart and HelmChartConfig native state and the overlay's window and
    phase, partition admission, LoginSet replicas, login and slurmd pods, the queue, node taints,
    Slurm's node states and addresses, the sha256 of Secret slurm-auth-slurm's key (never the key),
    the identity of the login SSH host-key Secret (UID and the public keys' sha256; no private key),
    the fleet repository's identity (repodata and the RPM file list), and each listed native host's
    endpoint report;
  - each native host as root, read twice, by one stdlib-only program whose every command and file
    read is checked (Session A's R6: a shell `echo $(...)` swallowed failures): its key file's
    sha256 and numeric owner/mode, the pinned packages' NEVRAs and the installed set's digest,
    hardware identity (chassis serial, product, machine id, `slurmd -C`), the boot id, the slurmd
    spool's entry names, the sha256 of the required native recovery configuration (REQUIRED_CONFIG,
    A's R7), and the share gate's verdict.
Any failed or unknown observation, missing required evidence, a changed second read, or a failed
window check is a REFUSAL.
Only hashes of secrets are kept; the record is created exclusively, mode 0600.

  native-state-record.py record --run-json RUN_DIR/run.json --lease-id ID --out FILE
  native-state-record.py record --observation --lease-id ID --out FILE        (after a restore)
  native-state-record.py compare --saved P.json --saved-sha256 HEX --run-json RUN.json --now N.json
        [--migration-revision SHA] [--isolated-target --declared-difference PATH ...]

Exit: 0 every check passes; 1 a check fails (the record is written, ok=false); 2 refused.
"""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

import yaml

TOOLS = Path(__file__).resolve().parent
INFRA = TOOLS.parent
sys.path.insert(0, str(TOOLS))
import fleet_audit  # noqa: E402  (!88: the native host report's judge)

SCHEMA = 2
LOGIN = "root@192.0.2.205"
LOGIN_NAME = "lab-dl380"
SSHO = ["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15"]
LEASE_RX = r"holder=maint(?: label=\S+)? id={id} since=\S+"
DEFAULTS = yaml.safe_load((INFRA / "roles/slinky/defaults/main.yml").read_text())
REPO_DIR = yaml.safe_load((INFRA / "roles/fleet_repo/defaults/main.yml").read_text())["fleet_repo_dir"]
TAINT = DEFAULTS["slinky_native_taint"]
KEY_FILE, GATE, SLURMD = DEFAULTS["slinky_native_key_file"], DEFAULTS["slinky_native_share_check"], DEFAULTS["slinky_native_slurmd"]
SLURM_UID = int(DEFAULTS["slinky_slurm_uid"])
SPOOL = "/var/spool/slurmd"
SLURM_GID = SLURM_UID                       # slinky_slurm_gid is the uid (roles/slinky defaults)
REQUIRED = ("window", "R-N1", "R-N2", "R-N3", "R-N5", "identity", "packages", "config")
DROPIN = DEFAULTS["slinky_native_dropin"]
# A's R7: the minimum native recovery configuration, hashed as root on the native host; every path
# needs a valid sha256 in the record and in compare, even when both sides would agree on "missing"
REQUIRED_CONFIG = (DROPIN, "/usr/lib/systemd/system/slurmd.service", GATE, "/etc/fstab", "/etc/hosts",
                   "/usr/local/sbin/prace-native-observe", "/etc/systemd/system/prace-native-observe.service",
                   "/etc/profile.d/" + DEFAULTS["slinky_apps_profile"])
# of those, the ones the native endpoint (!88) also hashes: the two views must agree
ENDPOINT_COVERED = (DROPIN, "/usr/lib/systemd/system/slurmd.service", GATE, "/etc/fstab",
                    "/usr/local/sbin/prace-native-observe", "/etc/systemd/system/prace-native-observe.service")
# a restore onto an isolated target rebuilds these from the target's own addresses and topology
# (the drop-in carries NodeAddr and the core/memory budget; fstab the storage server; hosts the
# fleet and controller addresses). Declared differences allow unequal VALID hashes, never missing.
HOST_DERIVED = (DROPIN, "/etc/fstab", "/etc/hosts")
SHA = re.compile(r"[0-9a-f]{64}")

# Runs on each native host through `ssh root@HOST python3 -`: stdlib only, read-only, one JSON
# document on stdout. Every command's status and every file read is checked; any failure is an
# entry in "errors", which the workstation turns into a refusal (A's R6). PRACE_ROOT exists for the
# offline tests only (it prefixes every path, commands included); ssh forwards no environment.
HOST_PROGRAM = r'''
import hashlib, json, os, subprocess
P = json.loads(@PARAMS@)
ROOT = os.environ.get("PRACE_ROOT", "")
out = {"schema": 1, "errors": [], "packages": {}, "config": {}}

def fail(what, e):
    out["errors"].append("%s: %s" % (what, e if isinstance(e, str) else type(e).__name__))

def run(args):
    r = subprocess.run([ROOT + args[0]] + args[1:], capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout, r.stderr

def sha_file(path):
    with open(ROOT + path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def one_line(path):
    with open(ROOT + path) as f:
        v = f.read().strip()
    if not v or "\n" in v:
        raise ValueError("empty or not one line")
    return v

try:
    out["key_sha256"] = sha_file(P["key"])
    st = os.stat(ROOT + P["key"])
    out["key_stat"] = "%d:%d:%o" % (st.st_uid, st.st_gid, st.st_mode & 0o7777)
except Exception as e:
    fail("key", e)
for spec in P["packages"]:
    try:
        rc, o, e = run(["/usr/bin/rpm", "-q", "--qf", "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}", spec])
        if rc == 0 and o.strip() and "\n" not in o.strip():
            out["packages"][spec] = o.strip()
        elif rc == 1 and o.strip() == "package %s is not installed" % spec and not e.strip():
            out["packages"][spec] = "NOT-INSTALLED"
        else:
            fail("rpm -q " + spec, "rc %d" % rc)
    except Exception as e:
        fail("rpm -q " + spec, e)
try:
    rc, o, e = run(["/usr/bin/rpm", "-qa", "--qf", "%{NEVRA}\n"])
    lines = sorted(l for l in o.splitlines() if l.strip())
    if rc != 0 or e.strip() or not lines:
        fail("rpm -qa", "rc %d, %d packages, stderr %r" % (rc, len(lines), e.strip()[:100]))
    else:
        out["rpmdb"] = "%s:%d" % (hashlib.sha256("\n".join(lines).encode()).hexdigest(), len(lines))
except Exception as e:
    fail("rpm -qa", e)
try:
    rc, o, e = run([P["slurmd"], "-C"])
    line = o.splitlines()[0].strip() if o.strip() else ""
    if rc != 0 or not line.startswith("NodeName="):
        fail("slurmd -C", "rc %d" % rc)
    else:
        out["hw"] = line
except Exception as e:
    fail("slurmd -C", e)
for key, path in (("serial", "/sys/class/dmi/id/product_serial"), ("product", "/sys/class/dmi/id/product_name"),
                  ("machine_id", "/etc/machine-id"), ("boot_id", "/proc/sys/kernel/random/boot_id")):
    try:
        out[key] = one_line(path)
    except Exception as e:
        fail(key, e)
try:
    out["spool"] = sorted(os.listdir(ROOT + P["spool"]))
except Exception as e:
    fail("spool", e)
for path in P["config"]:
    try:
        out["config"][path] = sha_file(path)
    except Exception as e:
        fail("config " + path, e)
try:
    rc, o, e = run([P["gate"], P["server"]] + P["modes"])
    out["gate"] = rc
    out["gate_said"] = (o + e).strip()[-500:]
except Exception as e:
    fail("share gate", e)
print(json.dumps(out, sort_keys=True))
'''

# Runs on the login node through `ssh ... python3 -`: stdlib only (no PyYAML there), read-only, one
# JSON document on stdout. PRACE_ROOT, PRACE_KUBECTL, PRACE_NATIVE_REPORTS and PRACE_HOSTNAME exist for
# the offline tests only; ssh forwards no environment. REPO_DIR is substituted before sending.
LOGIN_PROGRAM = r'''
import base64, hashlib, json, os, subprocess, urllib.request
ROOT = os.environ.get("PRACE_ROOT", "")
KC = os.environ.get("PRACE_KUBECTL", "/usr/local/bin/k3s kubectl").split()
CTL = KC + ["-n", "slurm", "exec", "slurm-controller-0", "-c", "slurmctld", "--"]
REPO = "@REPO_DIR@"
out = {"schema": 1, "host": os.environ.get("PRACE_HOSTNAME") or os.uname().nodename.split(".")[0], "errors": []}

def run(args):
    r = subprocess.run(args, capture_output=True, text=True, timeout=60)
    if r.returncode:
        raise OSError("rc %d" % r.returncode)
    return r.stdout

def section(name, fn):
    try:
        out[name] = fn()
    except Exception as e:
        out[name] = None
        out["errors"].append("%s: %s" % (name, type(e).__name__))

def text(path):
    try:
        with open(ROOT + path) as f:
            t = f.read()
    except FileNotFoundError:
        return None
    return {"text": t, "sha256": hashlib.sha256(t.encode()).hexdigest()}

def lease():
    t = text("/run/prace-cluster-lease/holder")
    return t["text"].strip() if t else None

def chart():
    o = json.loads(run(KC + ["-n", "kube-system", "get", "helmchart", "slurm", "-o", "json"]))
    return {"uid": o["metadata"]["uid"], "values": o["spec"]["valuesContent"]}

def overlay():
    o = json.loads(run(KC + ["-n", "kube-system", "get", "helmchartconfig", "slurm", "-o", "json"]))
    v = json.loads(o["spec"]["valuesContent"])
    a = o["metadata"].get("annotations") or {}
    return {"window_id": a.get("prace.fleet/window-id"), "phase": a.get("prace.fleet/window-phase"),
            "native_partition": (v.get("controller") or {}).get("extraConfMap", {}).get("PartitionName")}

def partitions():
    rows = {}
    for line in run(CTL + ["sinfo", "-h", "-o", "%R|%a"]).splitlines():
        if "|" in line:
            p, a = line.split("|", 1)
            rows[p] = a
    if not rows:
        raise ValueError("no partitions")
    return rows

def loginsets():
    return {i["metadata"]["name"]: i["spec"].get("replicas")
            for i in json.loads(run(KC + ["-n", "slurm", "get", "loginsets", "-o", "json"]))["items"]}

def pods(name):
    items = json.loads(run(KC + ["-n", "slurm", "get", "pods", "-l", "app.kubernetes.io/name=" + name, "-o", "json"]))["items"]
    count = {}
    for p in items:
        n = p["spec"].get("nodeName")
        count[n] = count.get(n, 0) + 1
    return count

def queue():
    return [l for l in run(CTL + ["squeue", "-h", "-o", "%i"]).splitlines() if l.strip()]

def taints():
    items = json.loads(run(KC + ["get", "nodes", "-o", "json"]))["items"]
    return {n["metadata"]["name"]: sorted("%s=%s:%s" % (t.get("key"), t.get("value", ""), t.get("effect"))
                                          for t in n["spec"].get("taints") or []) for n in items}

def slurm():
    rows = {}
    for line in run(CTL + ["sinfo", "-h", "-N", "-o", "%N|%T|%o"]).splitlines():
        if line.count("|") == 2:
            name, state, addr = line.split("|")
            rows.setdefault(name, set()).add((state, addr))
    return {n: [{"state": s, "addr": a} for s, a in sorted(v)] for n, v in rows.items()}

def secret_key():
    b64 = run(KC + ["-n", "slurm", "get", "secret", "slurm-auth-slurm", "-o", "jsonpath={.data.slurm\\.key}"]).strip()
    return hashlib.sha256(base64.b64decode(b64, validate=True)).hexdigest()

def host_keys():
    o = json.loads(run(KC + ["-n", "slurm", "get", "secret", "slurm-login-prace-ssh-host-keys", "-o", "json"]))
    pubs = {k: hashlib.sha256(base64.b64decode(v)).hexdigest() for k, v in (o.get("data") or {}).items() if k.endswith(".pub")}
    if not pubs:
        raise ValueError("no public host keys")
    return {"uid": o["metadata"]["uid"], "public_sha256": pubs}

def repo():
    names = sorted(n for n in os.listdir(ROOT + REPO + "/packages") if n.endswith(".rpm"))
    with open(ROOT + REPO + "/repodata/repomd.xml", "rb") as f:
        repomd = hashlib.sha256(f.read()).hexdigest()
    return {"repomd_sha256": repomd, "rpm_count": len(names),
            "rpm_names_sha256": hashlib.sha256("\n".join(names).encode()).hexdigest()}

def endpoints():
    listed = text("/etc/prace-slinky/native-workers")
    hosts = [l.split() for l in (listed["text"] if listed else "").splitlines() if l.strip() and not l.startswith("#")]
    fake = os.environ.get("PRACE_NATIVE_REPORTS")
    reports = {}
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for name, addr in hosts:
        try:
            if fake:
                with open(fake) as f:
                    reports[name] = json.load(f)[addr]
            else:
                with opener.open("http://%s:918/v1/native-worker" % addr, timeout=5) as r:
                    reports[name] = json.loads(r.read(65537)[:65536])
        except Exception as e:
            reports[name] = {"errors": ["native_endpoint_unreachable_or_invalid: %s" % type(e).__name__]}
    return reports

section("lease_holder", lease)
section("native_list", lambda: text("/etc/prace-slinky/native-workers"))
section("chart", chart)
section("overlay", overlay)
section("partitions", partitions)
section("loginsets", loginsets)
section("login_pods", lambda: pods("login"))
section("slurmd_pods", lambda: pods("slurmd"))
section("queue", queue)
section("taints", taints)
section("slurm", slurm)
section("secret_key_sha256", secret_key)
section("login_host_keys", host_keys)
section("fleet_repo", repo)
section("native_reports", endpoints)
print(json.dumps(out, sort_keys=True))
'''


class Refused(Exception):
    pass


def expected_topology(infra=INFRA):
    """what the pin says: native workers and addresses, compute kinds, the shares, each compute host's
    chassis serial, and the pinned native packages"""
    gv = yaml.safe_load((infra / "inventories/fleet/group_vars/all/slurm.yml").read_text()) or {}
    workers = sorted(gv.get("slurm_native_workers") or [])
    inv = yaml.safe_load((infra / "inventories/fleet/hosts.yml").read_text())["fleet"]["children"]
    kinds = {k: sorted((inv.get(k) or {}).get("hosts") or {}) for k in DEFAULTS["slinky_nodesets"]}
    hv = {h: yaml.safe_load((infra / f"inventories/fleet/host_vars/{h}.yml").read_text()) for hs in kinds.values() for h in hs}
    unknown = set(workers) - set(hv)
    if unknown:
        raise Refused(f"native workers not in the inventory's compute kinds: {sorted(unknown)}")
    audit = json.loads((infra / "audit/expected.json").read_text())
    packages = list(DEFAULTS["slinky_native_packages"]) + list(gv.get("slurm_native_runtime_packages") or [])
    for p in packages:
        if not re.fullmatch(r"[A-Za-z0-9._+-]+", p):
            raise Refused(f"unsafe package spec {p!r}")
    return {"workers": {w: hv[w]["admin_ip"] for w in workers}, "kinds": kinds,
            "serials": {w: str(hv[w].get("chassis_serial")) for w in workers},
            "native_kinds": sorted(k for k, hs in kinds.items() if hs and set(hs) <= set(workers)),
            "shares": audit["native_shares"], "max_age": audit.get("max_snapshot_age_s", 180), "packages": packages}


def repo_state(infra=INFRA):
    """(HEAD, tracked tree clean)"""
    git = ["git", "-C", str(infra.parent)]
    head = subprocess.run(git + ["rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    dirty = subprocess.run(git + ["status", "--porcelain", "--untracked-files=no"], capture_output=True, text=True, check=True).stdout
    return head, dirty == ""


def window_check(lease_id):
    """the common window contract: fenced and quiet under this lease (slurm-window.py check)"""
    r = subprocess.run([sys.executable, str(TOOLS / "slurm-window.py"), "check", "--lease-id", lease_id],
                       capture_output=True, text=True, timeout=600)
    return r.returncode, (r.stdout + r.stderr)[-1000:]


def bind_point(run_json, lease_id, revision):
    raw = Path(run_json).read_bytes()
    s = json.loads(raw)
    if s.get("schema") != 1 or not re.fullmatch(r"[0-9a-f]{32}", str(s.get("id", ""))):
        raise Refused("run.json is not a capture record")
    if s.get("accepted") is not True or s.get("phase") != "complete":
        raise Refused(f"the point is not complete and accepted (phase {s.get('phase')}, accepted {s.get('accepted')})")
    if (s.get("window") or {}).get("id") != lease_id:
        raise Refused("the point was not taken in this owned window (borrowed window id differs)")
    if s.get("revision") != revision:
        raise Refused(f"the point's revision {s.get('revision')} is not this checkout's {revision}")
    return {"id": s["id"], "stage": s.get("stage"), "revision": s["revision"], "run_json_sha256": hashlib.sha256(raw).hexdigest()}


def ssh(target, *command, jump=None):
    args = ["ssh", *SSHO]
    if jump:
        args += ["-o", "ProxyCommand=ssh " + " ".join(SSHO) + f" -W %h:%p {jump}"]
    return args + [target, *command]


def host_program(expected):
    """the native host's program with its parameters (validated here, passed as one JSON literal)"""
    server = str(ipaddress.IPv4Address(expected["shares"]["server"]))
    for p, m in expected["shares"]["modes"].items():
        if not re.fullmatch(r"/[a-z0-9/_-]+", p) or m not in ("rw", "ro"):
            raise Refused(f"unsafe share {p}:{m}")
    params = {"key": KEY_FILE, "packages": list(expected["packages"]), "slurmd": SLURMD, "spool": SPOOL, "gate": GATE,
              "server": server, "modes": [f"{p}:{m}" for p, m in sorted(expected["shares"]["modes"].items())],
              "config": list(REQUIRED_CONFIG)}
    return HOST_PROGRAM.replace("@PARAMS@", repr(json.dumps(params)))


def validate_host(name, h, expected):
    """a native host's read: complete and well-formed, or Refused (never an accepted gap)"""
    if not isinstance(h, dict) or h.get("schema") != 1:
        raise Refused(f"{name}: the host program's output is not a host record")
    if h.get("errors") != []:
        raise Refused(f"{name}: host reads failed: {h.get('errors')}")
    for k in ("key_stat", "hw", "serial", "product", "machine_id", "boot_id"):
        if not isinstance(h.get(k), str) or not h[k]:
            raise Refused(f"{name}: {k} missing from the host read")
    if not SHA.fullmatch(str(h.get("key_sha256"))) or not re.fullmatch(r"[0-9a-f]{64}:[1-9]\d*", str(h.get("rpmdb"))):
        raise Refused(f"{name}: the key or the installed package set is not a valid digest")
    if not isinstance(h.get("spool"), list) or type(h.get("gate")) is not int:
        raise Refused(f"{name}: the spool listing or the share gate's verdict is missing")
    if set(h.get("packages") or {}) != set(expected["packages"]):
        raise Refused(f"{name}: the pinned packages were not all queried")
    config = h.get("config") or {}
    missing = [p for p in REQUIRED_CONFIG if not SHA.fullmatch(str(config.get(p)))]
    if missing:
        raise Refused(f"{name}: required native configuration evidence missing: {missing}")
    return h


def gather_once(expected, run):
    r = run(ssh(LOGIN, "python3", "-"), input=LOGIN_PROGRAM.replace("@REPO_DIR@", REPO_DIR), capture_output=True, text=True, timeout=300)
    if r.returncode:
        raise Refused(f"the login node's read-only program failed (rc {r.returncode})")
    login = json.loads(r.stdout)
    hosts = {}
    for name, addr in expected["workers"].items():
        h = run(ssh(f"root@{ipaddress.IPv4Address(addr)}", "python3", "-", jump=LOGIN), input=host_program(expected),
                capture_output=True, text=True, timeout=180)
        if h.returncode:
            raise Refused(f"{name}: the read-only host program failed (rc {h.returncode})")
        try:
            hosts[name] = validate_host(name, json.loads(h.stdout), expected)
        except ValueError:
            raise Refused(f"{name}: the host program's output is not JSON")
    return login, hosts


def stable_view(login, hosts):
    """what a second read must reproduce exactly (time stamps excluded)"""
    reports = {n: {k: v for k, v in (r or {}).items() if k != "time"} for n, r in (login.get("native_reports") or {}).items()}
    keep = {k: v for k, v in login.items() if k != "native_reports"}
    return json.dumps({"login": keep, "reports": reports, "hosts": hosts}, sort_keys=True)


def chart_native(values, kinds):
    v = yaml.safe_load(values)
    off = sorted(k for k, n in (v.get("nodesets") or {}).items() if not n.get("enabled"))
    extra = (v.get("controller") or {}).get("extraConfMap") or {}
    return {"nodesets_off": off, "hosts": sorted(h for k in off for h in kinds.get(k, [])),
            "nodeset_line": extra.get("NodeSet"), "partition_line": extra.get("PartitionName"),
            "values_sha256": hashlib.sha256(values.encode()).hexdigest()}


def judge(login, hosts, expected, lease_id, now):
    """{check: {"ok", "problems"}}: window, R-N1 topology, R-N2 registration, R-N3 key, R-N5 host,
    identity, packages"""
    p = {c: [] for c in REQUIRED}
    want = expected["workers"]
    # window: owned, closed and quiet, as this record saw it (the window tool checks it before and after)
    if not re.fullmatch(LEASE_RX.format(id=re.escape(lease_id)), login.get("lease_holder") or ""):
        p["window"].append(f"the cluster lease is not this window's ({login.get('lease_holder')!r})")
    ov = login.get("overlay") or {}
    if ov.get("window_id") != lease_id or ov.get("phase") != "closed":
        p["window"].append(f"the overlay is not this window's closed one (window {ov.get('window_id')}, phase {ov.get('phase')})")
    parts = login.get("partitions") or {}
    # sinfo -o "%R|%a" prints the full word, "inactive" (Slurm 25.11.8, live 5 Oct); "inact" is only
    # sinfo's default 5-character column, never this format's output
    if not parts or any(a != "inactive" for a in parts.values()):
        p["window"].append(f"partition admission is not closed: {parts}")
    if not login.get("loginsets") or any(r != 0 for r in login["loginsets"].values()):
        p["window"].append(f"LoginSet replicas are not 0: {login.get('loginsets')}")
    if login.get("login_pods") != {}:
        p["window"].append(f"login pods exist: {login.get('login_pods')}")
    if login.get("queue") != []:
        p["window"].append(f"the queue is not empty: {login.get('queue')}")
    for h in want:
        spool = (hosts.get(h) or {}).get("spool")
        jobs = [e for e in (spool or []) if re.match(r"job\d+", e) or re.search(r"_\d+\.\d+$", e)]
        if not isinstance(spool, list) or jobs:
            p["window"].append(f"{h}: the slurmd spool is not free of job state ({jobs or 'unread'})")
    # R-N1 topology: the pin, the login list, the deployed chart and overlay, pods and taints agree
    if login.get("host") != LOGIN_NAME:
        p["R-N1"].append(f"the login program ran on {login.get('host')}, not {LOGIN_NAME}")
    listed = {}
    for line in ((login.get("native_list") or {}).get("text") or "").splitlines():
        if line.strip() and not line.startswith("#"):
            f = line.split()
            listed[f[0]] = f[1] if len(f) == 2 else None
    if listed != want:
        p["R-N1"].append(f"the login node's native list {listed} is not the pin's {want}")
    chart = chart_native(login["chart"]["values"], expected["kinds"]) if login.get("chart") else None
    if chart is None or chart["hosts"] != sorted(want):
        p["R-N1"].append(f"the deployed chart's native hosts {chart and chart['hosts']} are not the pin's {sorted(want)}")
    elif bool(chart["nodeset_line"]) != bool(want) or bool(chart["partition_line"]) != bool(want):
        p["R-N1"].append("the chart's native NodeSet/PartitionName lines do not match the topology")
    if bool(ov.get("native_partition")) != bool(want):
        p["R-N1"].append(f"the overlay's native partition line {ov.get('native_partition')!r} does not match the topology")
    pods, taints = login.get("slurmd_pods") or {}, login.get("taints") or {}
    for h in sorted(h for hs in expected["kinds"].values() for h in hs):
        native = h in want
        if native and pods.get(h, 0) != 0:
            p["R-N1"].append(f"{h}: native, yet {pods[h]} slurmd pod(s)")
        if (TAINT in taints.get(h, [])) != native:
            p["R-N1"].append(f"{h}: taint {TAINT} {'missing' if native else 'present on a pod worker'}")
    slurm = login.get("slurm") or {}
    for h, addr in want.items():
        host = hosts.get(h) or {}
        rows = slurm.get(h) or []
        if len(rows) != 1 or rows[0]["state"] not in fleet_audit.USABLE or rows[0]["addr"] != addr:
            p["R-N2"].append(f"{h}: Slurm {rows} (expected one usable state at {addr})")
        hk, sk = host.get("key_sha256"), login.get("secret_key_sha256")
        if not hk or not re.fullmatch(r"[0-9a-f]{64}", hk) or hk != sk:
            p["R-N3"].append(f"{h}: the host key file does not equal Secret slurm-auth-slurm (or a hash is missing)")
        if host.get("key_stat") != f"{SLURM_UID}:{SLURM_GID}:600":
            p["R-N3"].append(f"{h}: the key file is {host.get('key_stat')} (uid:gid:mode), not {SLURM_UID}:{SLURM_GID}:600")
        report = (login.get("native_reports") or {}).get(h)
        p["R-N5"] += [f"{h}: {x}" for x in fleet_audit.native_problems(h, report, expected["shares"], now, expected["max_age"])]
        if host.get("gate") != 0:
            p["R-N5"].append(f"{h}: the share gate refuses ({host.get('gate')}: {host.get('share_gate_said')})")
        if host.get("serial") != expected["serials"].get(h):
            p["identity"].append(f"{h}: chassis serial differs from the inventory's")
        for k in ("hw", "product", "machine_id", "boot_id"):
            if not host.get(k):
                p["identity"].append(f"{h}: {k} unread")
        if (report or {}).get("boot_id") != host.get("boot_id"):
            p["identity"].append(f"{h}: the endpoint's boot id is not the host's")
        # `rpm -q NAME-VERSION[-RELEASE]` answers only for that exact build; any other is NOT-INSTALLED
        for spec in expected["packages"]:
            nevra = host.get("packages", {}).get(spec, "")
            if not re.fullmatch(r"\S+-\d+:\S+-\S+\.\S+", nevra):
                p["packages"].append(f"{h}: {spec} is {nevra or 'unread'}")
        if not re.fullmatch(r"[0-9a-f]{64}:[1-9]\d*", str(host.get("rpmdb"))):
            p["packages"].append(f"{h}: the installed package set is unread")
        # A's R7: the required native configuration, as root read it and as the endpoint reports it
        config, reported = host.get("config") or {}, (report or {}).get("config") or {}
        for path in REQUIRED_CONFIG:
            if not SHA.fullmatch(str(config.get(path))):
                p["config"].append(f"{h}: {path} has no valid hash ({config.get(path)})")
            elif path in ENDPOINT_COVERED and reported.get(path) != config[path]:
                p["config"].append(f"{h}: the endpoint reports {path} as {str(reported.get(path))[:12]}, root read {config[path][:12]}")
    if not login.get("login_host_keys") or not login.get("fleet_repo"):
        p["R-N1"].append("the login host-key Secret or the fleet repository identity is unread")
    return {c: {"ok": not v, "problems": v} for c, v in p.items()}


def record(args, run=subprocess.run, state=repo_state, now=time.time, expected=None, window=window_check):
    revision, clean = state()
    if not clean:
        raise Refused("the checkout has modified tracked files; record only from the reviewed pin")
    if not re.fullmatch(r"[0-9a-f]{16}", args.lease_id):
        raise Refused("the lease id is 16 hex digits")
    point = None if args.observation else bind_point(args.run_json, args.lease_id, revision)
    out = Path(args.out)
    if out.exists() or out.is_symlink():
        raise Refused(f"{out} exists; a record is never overwritten")
    expected = expected or expected_topology()
    rec = {"schema": SCHEMA, "tool": "native-state-record", "purpose": "observation" if point is None else "point",
           "revision": revision, "lease_id": args.lease_id, "point": point,
           "expected": {k: expected[k] for k in ("workers", "native_kinds", "shares", "serials", "packages")}}
    refusal = None
    try:
        pre = window(args.lease_id)
        rec["window_check"] = {"pre": {"rc": pre[0], "said": pre[1]}}
        if pre[0] != 0:
            raise Refused(f"the window is not fenced and quiet before the record (slurm-window.py check rc {pre[0]})")
        first = gather_once(expected, run)
        second = gather_once(expected, run)
        post = window(args.lease_id)
        rec["window_check"]["post"] = {"rc": post[0], "said": post[1]}
        login, hosts = second
        for name, (lg, hs) in (("first", first), ("second", second)):
            if lg.get("errors"):
                raise Refused(f"the {name} login read failed: {lg['errors']}")
        if stable_view(*first) != stable_view(*second):
            raise Refused("the second read differs from the first: the window was not stable")
        if post[0] != 0:
            raise Refused(f"the window is not fenced and quiet after the record (slurm-window.py check rc {post[0]})")
        t = now()
        checks = judge(login, hosts, expected, args.lease_id, t)
        chart = chart_native(login["chart"]["values"], expected["kinds"])
        rec.update({
            "created_utc": datetime.datetime.fromtimestamp(t, datetime.timezone.utc).isoformat(),
            "login": {k: login.get(k) for k in ("host", "lease_holder", "native_list", "overlay", "partitions", "loginsets", "login_pods",
                                                 "slurmd_pods", "queue", "taints", "slurm", "secret_key_sha256", "login_host_keys", "fleet_repo")},
            "chart": dict(chart, uid=login["chart"]["uid"]),
            "hosts": {h: dict(v, report=(login.get("native_reports") or {}).get(h)) for h, v in hosts.items()},
            "checks": checks, "ok": all(c["ok"] for c in checks.values())})
    except Refused as e:
        refusal = str(e)
        rec.update(ok=False, refused=refusal, checks={})
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(rec, f, indent=1, sort_keys=True); f.write("\n")
    if refusal:
        raise Refused(refusal)
    return rec


def strict(rec, purpose):
    """a complete, passing record of this purpose, or Refused (never trust a boolean alone)"""
    if not isinstance(rec, dict) or rec.get("schema") != SCHEMA or rec.get("tool") != "native-state-record" or rec.get("purpose") != purpose:
        raise Refused(f"not a native-state record of purpose {purpose}")
    if rec.get("refused") or rec.get("ok") is not True or not isinstance(rec.get("checks"), dict):
        raise Refused(f"the {purpose} record failed or was refused")
    for c in REQUIRED:
        v = rec["checks"].get(c)
        if not isinstance(v, dict) or v.get("ok") is not True or v.get("problems") != []:
            raise Refused(f"the {purpose} record's {c} check is missing or failed")
    if not re.fullmatch(r"[0-9a-f]{40}", str(rec.get("revision"))) or not re.fullmatch(r"[0-9a-f]{16}", str(rec.get("lease_id"))):
        raise Refused(f"the {purpose} record's revision or lease is malformed")
    for k, t in (("login", dict), ("chart", dict), ("hosts", dict), ("expected", dict), ("window_check", dict)):
        if not isinstance(rec.get(k), t):
            raise Refused(f"the {purpose} record lacks {k}")
    if any((rec["window_check"].get(x) or {}).get("rc") != 0 for x in ("pre", "post")):
        raise Refused(f"the {purpose} record was not taken in a fenced, quiet window")
    for h in (rec["expected"].get("workers") or {}):
        host = rec["hosts"].get(h)
        config = (host or {}).get("config") or {}
        if (not isinstance(host, dict) or not SHA.fullmatch(str(host.get("key_sha256")))
                or any(not SHA.fullmatch(str(config.get(p))) for p in REQUIRED_CONFIG)):
            raise Refused(f"the {purpose} record lacks valid required evidence for {h}")
    point = rec.get("point")
    if purpose == "point" and not (isinstance(point, dict) and re.fullmatch(r"[0-9a-f]{32}", str(point.get("id")))
                                   and re.fullmatch(r"[0-9a-f]{64}", str(point.get("run_json_sha256")))
                                   and point.get("revision") == rec["revision"]):
        raise Refused("the point record is not bound to a point")
    return rec


def compare(saved_raw, saved_sha256, run_json_raw, now, migration_revision=None, isolated=False, declared=()):
    """A's restore check of a record taken after a restore (now) against the point's (saved)"""
    if hashlib.sha256(saved_raw).hexdigest() != saved_sha256:
        raise Refused("the saved record is not the trusted one (sha256 differs)")
    saved = strict(json.loads(saved_raw), "point")
    point = saved.get("point") or {}
    if hashlib.sha256(run_json_raw).hexdigest() != point.get("run_json_sha256") or json.loads(run_json_raw).get("id") != point.get("id"):
        raise Refused("the run.json is not the point's (digest or id differs)")
    now = strict(now, "observation")
    if now["revision"] != saved["revision"] and now["revision"] != migration_revision:
        raise Refused(f"the restore ran from {now['revision']}, not the point's {saved['revision']} (and no reviewed migration names it)")
    bad = set(declared) - set(HOST_DERIVED)
    if declared and not isolated:
        raise Refused("declared differences are only for an isolated restore target")
    if bad:
        raise Refused(f"only host-derived files may be declared different: {sorted(bad)}")
    p = {c: [] for c in ("R-N1", "R-N3", "R-N4", "identity", "packages")}
    if now["expected"]["workers"] != saved["expected"]["workers"] or now["chart"]["hosts"] != saved["chart"]["hosts"]:
        p["R-N1"].append(f"the native topology {now['chart']['hosts']} is not the point's {saved['chart']['hosts']}")
    if now["login"]["login_host_keys"] != saved["login"]["login_host_keys"]:
        p["R-N1"].append("the login SSH host-key Secret (UID or public keys) is not the point's")
    if now["login"]["secret_key_sha256"] != saved["login"]["secret_key_sha256"]:
        p["R-N3"].append("the restored cluster key is not the point's (an older or newer Secret)")
    accepted = []
    for h in saved["expected"]["workers"]:
        sh, nh = saved["hosts"].get(h) or {}, now["hosts"].get(h) or {}
        # the required set (strict() already refused records without a valid hash for each path)
        for path in REQUIRED_CONFIG:
            a, b = (sh.get("config") or {}).get(path), (nh.get("config") or {}).get(path)
            if not SHA.fullmatch(str(a)) or not SHA.fullmatch(str(b)):
                raise Refused(f"{h}: required evidence for {path} is missing ({a}, {b}); a declaration never excuses it")
            if a != b:
                if isolated and path in declared:
                    accepted.append(f"{h}: {path} (declared: rebuilt for the isolated target)")
                else:
                    p["R-N4"].append(f"{h}: {path} {a[:12]} -> {b[:12]}")
        # the endpoint's other, optional globs: compared as reported ("missing" on both sides agrees)
        a, b = (sh.get("report") or {}).get("config") or {}, (nh.get("report") or {}).get("config") or {}
        for path in sorted((set(a) | set(b)) - set(REQUIRED_CONFIG)):
            if a.get(path) != b.get(path):
                if isolated and path in declared and SHA.fullmatch(str(a.get(path))) and SHA.fullmatch(str(b.get(path))):
                    accepted.append(f"{h}: {path} (declared: rebuilt for the isolated target)")
                else:
                    p["R-N4"].append(f"{h}: optional {path} {str(a.get(path))[:12]} -> {str(b.get(path))[:12]}")
        if sh.get("packages") != nh.get("packages"):
            p["packages"].append(f"{h}: pinned package NEVRAs differ: {sh.get('packages')} -> {nh.get('packages')}")
        if not isolated:
            for k in ("serial", "product", "hw", "machine_id"):
                if sh.get(k) != nh.get(k):
                    p["identity"].append(f"{h}: {k} differs from the point's (not the same host)")
            if sh.get("rpmdb") != nh.get("rpmdb"):
                p["packages"].append(f"{h}: the installed package set differs from the point's")
    result = {c: {"ok": not v, "problems": v} for c, v in p.items()}
    result["declared"] = {"ok": True, "problems": [], "accepted": accepted}
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("record")
    g = r.add_mutually_exclusive_group(required=True)
    g.add_argument("--run-json"); g.add_argument("--observation", action="store_true")
    r.add_argument("--lease-id", required=True); r.add_argument("--out", required=True)
    c = sub.add_parser("compare")
    for opt in ("--saved", "--saved-sha256", "--run-json", "--now"):
        c.add_argument(opt, required=True)
    c.add_argument("--migration-revision"); c.add_argument("--isolated-target", action="store_true")
    c.add_argument("--declared-difference", action="append", default=[])
    a = ap.parse_args(argv)
    try:
        if a.cmd == "record":
            checks = record(a)["checks"]
        else:
            checks = compare(Path(a.saved).read_bytes(), a.saved_sha256, Path(a.run_json).read_bytes(),
                             json.loads(Path(a.now).read_text()), a.migration_revision, a.isolated_target, a.declared_difference)
    except (Refused, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as e:
        print(f"REFUSED: {e}"); return 2
    for name, v in checks.items():
        print(f"{name}: {'PASS' if v['ok'] else 'FAIL'}")
        for x in v["problems"] + v.get("accepted", []):
            print("   " + x)
    return 0 if all(v["ok"] for v in checks.values()) else 1


if __name__ == "__main__":
    sys.exit(main())

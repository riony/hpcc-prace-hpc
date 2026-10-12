#!/usr/bin/env python3
"""Academic scheduler policy acceptance (roles/slinky, D39/D40): submits jobs as several synthetic
users and checks what Slurm does with them.

usage: slurm-policy-acceptance.py (--bench | --fleet --lease-id ID) [--no-gpu-fill] [--storage | --env]

  --fleet    explicitly target the fleet, only inside the operator's existing maintenance lease.
  --lease-id ID  required with --fleet: exactly 16 lowercase hex digits; the matching lease is
             checked before any jobs, never acquired or released by this runner.
  --bench    explicitly target the local slurm bench, with no lease.
  --storage  instead of the policy: the shared storage in the pods (T87), on every expected worker
             (infra/audit/expected.json; a missing or unusable one fails) with srun in debug, and
             in the login pod: /home, /projects and /apps mounted nosuid,nodev,hard (/apps ro); a project
             member's file is group-owned by the project and read by another member on a
             DIFFERENT worker; another project's member can neither read, write nor list it;
             nobody can write /apps; a setuid program in /projects runs as the caller while the
             same program in the pod's /tmp runs as its owner (the control; the program is an ELF
             copy of what implements id, since setuid is ignored on a script; the bench's Docker
             skips these checks if setuid is ignored there); syn-probe's home quota stops a
             larger write from two workers and the login pod (skipped on the bench: no quotas):
             only dd failing with "Disk quota exceeded" and a file whose allocated space is within
             the hard limit count (over NFS its size is the client's, not what the server kept).
             Every file it made (project directory, each pod's /tmp control, an /apps
             counterexample, the quota files) is removed and its absence shown by a look that
             succeeded; a failed removal or look fails the run.
  --env      instead of the policy: the shared job environment (T88, roles/apps_env). The modules
             gcc/11.5, cuda/12.9, openmpi/4.1 and python/3.9 are visible where users submit and on
             every expected worker (infra/audit/expected.json; a missing or unusable one fails);
             on each worker gcc, g++ (threads) and mpicc build and run the /apps examples, and
             cuda/12.9 refuses with its message where CUDA is absent; /apps/examples/mpi.sh runs
             two ranks on two different GPU nodes (one GPU each, mpirun, TCP on the pod
             network); /apps/examples/gpu.sh builds with nvcc and runs on a V100. The bench has no
             GPUs or CUDA: the nvcc check is reported as not run there, never as passed. Its build
             directory under /projects/proj-alpha is removed and its absence shown.
  --no-gpu-fill  skip the checks that briefly fill GPUs: the per-user GPU total in both orders
             (8 GPUs on one node), the debug GPU pool (4 GPUs), the project GPU limit (two
             whole GPU nodes) and a GPU node's share per GPU (one GPU node at a time).

Checks: the policy configuration is live; the partitions cover exactly the expected workers
(infra/audit/expected.json); every job must name a project (-A); a user can use their own
project and not another's or a made-up one; a user in no project cannot run a job; jobs get QoS
normal and cannot choose another; default time and memory apply (on gpu one GPU's share of CPUs
and memory); impossible jobs are refused at submission (partition time limit, also for a
multi-partition request under EnforcePartLimits=ALL; debug job size; more GPUs than the project
may hold); a GPU node's CPUs and memory go with its GPUs: a valid GPU request is rewritten to
exactly the share per GPU, whatever CPUs or memory it named, and GPUs that do not spread evenly,
more GPUs on a node than it has, more tasks than the GPUs' CPUs, a GPU-less job in gpu and
--exclusive=user are refused (owner decision 2 Oct; bench probe, 30 Sep), a debug job without GPUs runs on a CPU node, more
memory per CPU on cpu costs CPUs, and a queued job's size is fixed for users; the forms the
size parser missed (bench probe v2, 1 Oct: one GPU named in several forms, --mincpus,
--mem-per-cpu=0, --prefer, and the same later by scontrol update) are refused or allocated within
the share, and a GPU job is billed at least its GPUs' CPU share (payg and gpu); no per-user limit
(owner decision 2 Oct: one user runs more than 8 jobs, and holds the project's whole GPU quota);
the debug GPU pool; the per-project GPU limit; a job takes no more of a GPU node than its GPUs'
share, so another user
can still use the node's other GPUs; pay per use (simulated): a payg job is charged to its
project's credit QoS, out of credit it is accepted and waits (owner decision 2 Oct), the credit
QoS works only in payg, and payg is not
held by the free queues' project quota; fairshare shares; interactive srun; accounting records the
project; the revoked user has no association.

Every job it submits is cancelled and must have left the queue: a job still queued after the
bounded wait is a FAIL, is listed, and keeps an own lease held (the lease is released only
after a clean run). Prints PASS/FAIL per check; exits 1 on any FAIL, 3 when it refused to start."""
import argparse
import json
import re
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import time

import yaml

INFRA = Path(__file__).resolve().parent.parent
DEFAULTS = yaml.safe_load((INFRA / "roles/slinky/defaults/main.yml").read_text())
EXPECTED = json.loads((INFRA / "audit/expected.json").read_text())
LOGIN = os.environ.get("PRACE_LOGIN", "192.0.2.205")
LEASE = os.environ.get("PRACE_LEASE_PATH", "/run/prace-cluster-lease")
BENCH = False
GPU_FILL = True
STORAGE = False
ADOPT = None
ENV = False
APPS = yaml.safe_load((INFRA / "roles/apps_env/defaults/main.yml").read_text())
POD_NETWORK = yaml.safe_load((INFRA / "roles/k3s/defaults/main.yml").read_text())["k3s_cluster_cidr"]


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('--bench', action='store_true')
    target.add_argument('--fleet', action='store_true')
    parser.add_argument('--lease-id')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--storage', action='store_true')
    mode.add_argument('--env', action='store_true')
    parser.add_argument('--no-gpu-fill', action='store_true')
    words = sys.argv[1:] if argv is None else argv
    for option in ('--bench', '--fleet', '--lease-id', '--storage', '--env', '--no-gpu-fill'):
        if sum(word.split('=', 1)[0] == option for word in words) > 1:
            parser.error('duplicate option: ' + option)
    args = parser.parse_args(words)
    if args.fleet and not args.lease_id:
        parser.error('--fleet requires --lease-id')
    if args.bench and args.lease_id is not None:
        parser.error('--lease-id is only valid with --fleet')
    if args.lease_id is not None and not re.fullmatch('[0-9a-f]{16}', args.lease_id):
        parser.error('--lease-id must be exactly 16 lowercase hex digits')
    return args


RESULTS = []
JOBS = []
SSH_DIR = tempfile.mkdtemp(prefix="prace-policy-")
OWN_SSH = not os.environ.get("PRACE_POLICY_SSH")     # tests substitute a fake login node
SSH = (shlex.split(os.environ["PRACE_POLICY_SSH"]) if not OWN_SSH else
       ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "ControlMaster=auto",
        "-o", f"ControlPath={SSH_DIR}/cm", "-o", "ControlPersist=120", f"root@{LOGIN}"])
LOGIN_POD = None
LEASE_HELD = {"id": None, "own": False}


def sh(argv, timeout=120):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 124, "", str(e)


def login(command):
    """a shell command as root on the login node"""
    return sh(SSH + [command])


def admin(*args):
    """a command in the controller (root)"""
    if BENCH:
        return sh(["docker", "exec", "bench-ctld", *args])
    return login(shlex.join(["k3s", "kubectl", "-n", "slurm", "exec", "slurm-controller-0", "-c", "slurmctld", "--", *args]))


def user(name, *args):
    """a command as a cluster user where users submit (login pod; the bench's submit node)"""
    inner = shlex.join(["runuser", "-u", name, "--", "sh", "-c", "cd /tmp && exec " + shlex.join(args)])
    if BENCH:
        return sh(["docker", "exec", "lab-lenovo", "sh", "-c", inner])
    return login(shlex.join(["k3s", "kubectl", "-n", "slurm", "exec", LOGIN_POD, "-c", "login", "--", "sh", "-c", inner]))


# --- the cluster lease (the same mechanism as slinky-acceptance.sh and the backup) -------------------
def lease_take():
    """True when this run may submit jobs: its own new lease, or the operator's matching one"""
    if BENCH:
        return True
    if ADOPT:
        rc, holder, err = login(f"cat {LEASE}/holder")
        if rc != 0 or sum(token == f"id={ADOPT}" for token in holder.split()) != 1 or sum(token.startswith("id=") for token in holder.split()) != 1:
            print(f"refusing: lease {ADOPT} is not the one held ({holder or err or 'no lease'}); nothing submitted")
            return False
        LEASE_HELD.update(id=ADOPT, own=False)
        print(f"using the operator's lease: {holder}")
        return True
    print('refusing: fleet execution requires an explicit existing lease; nothing submitted')
    return False


def lease_release(clean):
    if not LEASE_HELD["own"]:
        return
    if not clean:
        print(f"LEASE KEPT ({LEASE}, id={LEASE_HELD['id']}): test jobs may remain; release it only after they are gone")
        return
    rc, _, _ = login(f"grep -q 'id={LEASE_HELD['id']} ' {LEASE}/holder && rm -rf {LEASE}")
    print("cluster lease released" if rc == 0 else f"LEASE NOT RELEASED: check {LEASE} on the login node")


# --- jobs ------------------------------------------------------------------------------------------
def result(name, ok, detail=""):
    RESULTS.append(ok)
    print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" ({detail})" if detail and not ok else ""))


def sbatch(name, *args):
    """(job id or None, error text)"""
    rc, out, err = user(name, "sbatch", "--parsable", "-o", "/dev/null", *args)
    if rc == 0 and out.split(";")[0].isdigit():
        JOBS.append(out.split(";")[0])
        return out.split(";")[0], ""
    return None, (err or out)


def job(jobid):
    rc, out, _ = admin("scontrol", "show", "job", "-o", jobid)
    return dict(kv.split("=", 1) for kv in out.split() if "=" in kv) if rc == 0 else {}


def wait_state(jobid, states, seconds=120):
    for _ in range(seconds // 2):
        j = job(jobid)
        if j.get("JobState") in states:
            return j
        time.sleep(2)
    return job(jobid)


def cancel(ids, tries=15, pause=2):
    """cancel by job id and wait until none is queued; the ids still queued ([] = clean). A failed
    queue query never counts as gone."""
    ids = [i for i in ids if i]
    if not ids:
        return []
    admin("scancel", *ids)
    remaining = ids
    for _ in range(tries):
        rc, out, _ = admin("squeue", "-h", "-a", "-o", "%i")
        if rc == 0:
            queued = set(out.split())
            remaining = [i for i in ids if i in queued]
            if not remaining:
                return []
        time.sleep(pause)
    return remaining


def cancelled(label, ids):
    left = cancel(ids)
    if left:
        result(f"{label}: its jobs left the queue", False, "still queued: " + " ".join(left))


def refused(name, label, args, expect):
    jid, err = sbatch(name, *args)
    result(f"{label}: refused at submission", jid is None and any(e.lower() in err.lower() for e in expect),
           f"job {jid}" if jid else err)


def rewritten(name, label, args, gpus, nodes=1):
    """owner decision 2 Oct: a valid GPU request is held and read back: Slurm recorded exactly the
    GPUs' share, CPUs per GPU and memory per GPU on each node, whatever CPUs or memory it named"""
    share_cpus, share_mib = gpu_share()
    jid, err = sbatch(name, "--hold", *args)
    j = job(jid) if jid else {}
    result(f"{label}: rewritten to {share_cpus} CPUs and {share_mib} MiB per GPU",
           jid is not None and int(j.get("NumCPUs", "0") or 0) == share_cpus * gpus
           and mib(j.get("MinMemoryNode")) == share_mib * gpus // nodes,
           err or f"job {jid} NumCPUs={j.get('NumCPUs')} CPUs/Task={j.get('CPUs/Task')} MinMemoryNode={j.get('MinMemoryNode')}")
    cancelled(label, [jid])


def cpu_count(ids):
    """CPUs in a CPU_IDs list (0-3,16-19 -> 8)"""
    n = 0
    for part in str(ids or "").split(","):
        lo, _, hi = part.partition("-")
        if lo.isdigit():
            n += int(hi) - int(lo) + 1 if hi.isdigit() else 1
    return n


def allocated(name, label, args, per_node, nodes):
    """Session A review R1 (2 Oct): the job RUNS with exactly its GPUs' share on each of exactly
    `nodes` nodes, as scontrol show job -d reports the allocation (a held job's readback alone
    does not show what Slurm allocates)"""
    share_cpus, share_mib = gpu_share()
    jid, err = sbatch(name, *args, "--wrap", "sleep 60")
    j = wait_state(jid, ("RUNNING", "COMPLETED", "FAILED", "CANCELLED"), 90) if jid else {}
    rc, out, _ = admin("scontrol", "show", "job", "-d", jid) if jid else (1, "", "")
    per = re.findall(r"Nodes=(\S+) CPU_IDs=(\S+) Mem=(\d+) GRES=(\S*)", out)
    hosts = [h for n, *_ in per for h in sorted(hostnames(n))]
    want = (share_cpus * per_node, share_mib * per_node, per_node)
    got = [(cpu_count(c), int(m), int((re.search(r"gpu(?::[^:(]+)?:(\d+)", g) or [0, 0])[1])) for _, c, m, g in per]
    result(f"{label}: runs on {nodes} node(s) with {share_cpus * per_node} CPUs, {share_mib * per_node} MiB and {per_node} GPU(s) on each",
           rc == 0 and j.get("JobState") == "RUNNING" and len(hosts) == nodes and len(set(hosts)) == nodes
           and len(per) >= 1 and all(g == want for g in got) and int(j.get("NumCPUs", "0") or 0) == share_cpus * per_node * nodes,
           err or f"{j.get('JobState')} NumCPUs={j.get('NumCPUs')} nodes {hosts} per node {got}, want {want}")
    cancelled(label, [jid])


def running_after(ids, want, seconds=60):
    """wait until `want` of the jobs run; {id: (state, reason)}"""
    st = {}
    for _ in range(seconds // 3):
        st = {i: (j.get("JobState"), j.get("Reason")) for i, j in ((i, job(i)) for i in ids if i)}
        if sum(s == "RUNNING" for s, _ in st.values()) >= want:
            break
        time.sleep(3)
    return st


def mib(s):
    """Slurm's memory display (2346M, 22.50G, 1T) in MiB"""
    s = str(s or "").strip()
    try:
        return round(float(s[:-1]) * {"K": 1 / 1024, "M": 1, "G": 1024, "T": 1024 * 1024}[s[-1].upper()])
    except (KeyError, ValueError, IndexError):
        return None


def tres(s):
    return dict(p.split("=", 1) for p in str(s or "").split(",") if "=" in p)


def mem_per_cpu(kind):
    r = DEFAULTS["slinky_nodeset_resources"][kind]
    return int(r["memory"][:-2]) * (1024 if r["memory"].endswith("Gi") else 1) // int(r["cpu"])


def gpu_share():
    """(CPUs, MiB) of one GPU on a GPU node: the job budget divided by its GPUs (slinky_gpu_share)"""
    r = DEFAULTS["slinky_nodeset_resources"]["gpu"]
    gpus = int(DEFAULTS["slinky_gpus_per_node"])
    return int(r["cpu"]) // gpus, int(r["memory"][:-2]) * 1024 // gpus


def hostnames(nodes):
    rc, out, _ = admin("scontrol", "show", "hostnames", nodes)
    return set(out.split()) if rc == 0 else set()


def gpu_node_shared(label, node, hog, update=None):
    """a job takes no more of a GPU node than its GPUs' share: syn-dave's `hog` on `node` (held
    and changed with `update` as syn-dave, if given) is refused, or another user's one-GPU job
    still starts on that node while it is there (bench probe, 30 Sep)"""
    name = f"GPU node share: {label}: refused, or another user's GPU job still starts on {node}"
    jid, err = sbatch("syn-dave", "-A", "proj-beta", "-w", node, "-t", "3", *(["--hold"] if update else []), *hog,
                      "--wrap", "sleep 150")
    if jid is None:
        result(name, True)
        return
    if update:
        rc, _, _ = user("syn-dave", "scontrol", "update", f"jobid={jid}", *update)
        user("syn-dave", "scontrol", "release", jid)
        if rc != 0:
            result(name, True)
            cancelled(label, [jid])
            return
    j = wait_state(jid, ("RUNNING",), 60)
    other, oerr = sbatch("syn-alice", "-A", "proj-alpha", "-p", "gpu", "-w", node, "--gres=gpu:1", "-t", "1", "--wrap", "true")
    jo = wait_state(other, ("RUNNING", "COMPLETED"), 60) if other else {}
    result(name, jo.get("JobState") in ("RUNNING", "COMPLETED"),
           f"syn-dave's job {jid} {j.get('JobState')} AllocTRES={j.get('AllocTRES')}; "
           f"syn-alice's one-GPU job {jo.get('JobState')}/{jo.get('Reason')} {oerr}")
    cancelled(label, [jid, other])


# --- the checks ------------------------------------------------------------------------------------
def policy():
    conf = DEFAULTS["slinky_scheduler_conf"]
    part = DEFAULTS["slinky_partition_policy"]
    dbg = DEFAULTS["slinky_debug_partition"]
    qos = DEFAULTS["slinky_qos"]
    debug_pool = int(tres(qos["debug"]["GrpTRES"])["gres/gpu"])
    want = {kind: {n for n, k in EXPECTED["workers"].items() if k == kind} for kind in ("cpu", "gpu")}

    # --- configuration and coverage
    rc, out, _ = admin("scontrol", "show", "config")
    live = {k.strip(): v.strip() for k, _, v in (l.partition("=") for l in out.splitlines())}
    for key in ("AccountingStorageEnforce", "EnforcePartLimits", "JobSubmitPlugins"):
        result(f"config {key}={conf[key]}", live.get(key) == conf[key], live.get(key))
    result("fairshare leads priority", live.get("PriorityWeightFairShare") == str(conf["PriorityWeightFairshare"]),
           live.get("PriorityWeightFairShare"))
    rc, out, _ = admin("scontrol", "show", "partition", "-o")
    parts = {p["PartitionName"]: p for p in (dict(kv.split("=", 1) for kv in l.split() if "=" in kv) for l in out.splitlines())}
    share_cpus, share_mib = gpu_share()
    shares = {"cpu": (f"{mem_per_cpu('cpu')} MiB per CPU (default and maximum)",
                      lambda p: p.get("DefMemPerCPU") == str(mem_per_cpu("cpu")) and p.get("MaxMemPerCPU") == str(mem_per_cpu("cpu"))),
              "gpu": (f"{share_cpus} CPUs and {share_mib} MiB per GPU by default",
                      lambda p: tres(p.get("JobDefaults", "")) == {"DefCpuPerGPU": str(share_cpus), "DefMemPerGPU": str(share_mib)})}
    for kind in ("cpu", "gpu"):
        p = parts.get(kind, {})
        ok = (p.get("DefaultTime") == part[kind]["DefaultTime"] and p.get("MaxTime") == part[kind]["MaxTime"]
              and shares[kind][1](p) and hostnames(p.get("Nodes", "")) == want[kind])
        result(f"partition {kind}: exactly {', '.join(sorted(want[kind]))}; {part[kind]['DefaultTime']} default, "
               f"{part[kind]['MaxTime']} max, {shares[kind][0]}", ok, str(p)[:300])
    p = parts.get("debug", {})
    workers = hostnames(p.get("Nodes", ""))
    result(f"partition debug: every expected worker ({len(EXPECTED['workers'])}), QoS {dbg['QOS']}, {dbg['MaxTime']} max",
           p.get("QoS") == dbg["QOS"] and p.get("MaxTime") == dbg["MaxTime"] and workers == set(EXPECTED["workers"]),
           f"{sorted(workers)} {str(p)[:200]}")
    weights = DEFAULTS["slinky_tres_billing_weights"]
    billed = {name: parts.get(name, {}).get("TRESBillingWeights") for name in ("cpu", "gpu", "debug", DEFAULTS["slinky_payg"]["partition"])}
    result(f"billing: a GPU counts as 4 CPUs on the GPU nodes' partitions ({weights}, PriorityFlags MAX_TRES); cpu bills CPUs",
           all(billed[n] == weights for n in billed if n != "cpu") and billed["cpu"] in (None, "", "(null)")
           and "MAX_TRES" in live.get("PriorityFlags", ""), f"{billed} PriorityFlags={live.get('PriorityFlags')}")

    # --- projects and QoS
    jid, err = sbatch("syn-alice", "-p", "debug", "-t", "1", "--wrap", "true")
    result("a job without -A is refused and told why", jid is None and "-A" in err, f"job {jid}" if jid else err)
    jid, err = sbatch("syn-alice", "-A", "proj-alpha", "-p", "debug", "-t", "1", "--wrap", "true")
    j = wait_state(jid, ("COMPLETED", "FAILED", "CANCELLED")) if jid else {}
    result("own project: accepted and completes", j.get("JobState") == "COMPLETED", err or str(j.get("JobState")))
    if jid:
        rc, out, _ = admin("sacct", "-n", "-X", "-P", "-j", jid, "-o", "Account,User,QOS")
        result("accounting records the project and QoS normal", out.strip() == "proj-alpha|syn-alice|normal", out)
    refused("syn-bob", "another project's account", ["-A", "proj-alpha", "-p", "debug", "-t", "1", "--wrap", "true"],
            ["Invalid account"])
    refused("syn-alice", "a made-up project", ["-A", "proj-nope", "-p", "debug", "-t", "1", "--wrap", "true"],
            ["Invalid account"])
    for acct in ("synthetic", "proj-ops"):     # no association at all: the old category account is gone too
        refused("syn-nologin", f"a user in no project (-A {acct})", ["-A", acct, "-p", "debug", "-t", "1", "--wrap", "true"],
                ["Invalid account"])
    refused("syn-probe", "a project the user is not in", ["-A", "proj-alpha", "-p", "debug", "-t", "1", "--wrap", "true"],
            ["Invalid account"])
    refused("syn-alice", "choosing the debug QoS for a cpu job", ["-A", "proj-alpha", "-p", "cpu", "-t", "1", "--qos=debug", "--wrap", "true"],
            ["Invalid qos"])
    refused("syn-alice", "choosing a QoS that does not exist", ["-A", "proj-alpha", "-p", "cpu", "-t", "1", "--qos=nosuch", "--wrap", "true"],
            ["Invalid qos"])

    # --- defaults and submit-time limits
    jid, err = sbatch("syn-alice", "-A", "proj-alpha", "-p", "cpu", "--hold", "--wrap", "true")
    j = job(jid) if jid else {}
    result(f"cpu defaults: {part['cpu']['DefaultTime']}, {mem_per_cpu('cpu')} MiB per CPU, QoS normal",
           j.get("TimeLimit") == part["cpu"]["DefaultTime"] and mib(j.get("MinMemoryCPU")) == mem_per_cpu("cpu")
           and j.get("QOS") == "normal",
           err or f"TimeLimit={j.get('TimeLimit')} MinMemoryCPU={j.get('MinMemoryCPU')} QOS={j.get('QOS')}")
    # DefCpuPerGPU/DefMemPerGPU apply at allocation: run a one-GPU job and read what it was given
    jid, err = sbatch("syn-alice", "-A", "proj-alpha", "-p", "gpu", "--gres=gpu:1", "-t", "1", "--wrap", "true")
    j = wait_state(jid, ("COMPLETED", "FAILED", "CANCELLED")) if jid else {}
    got = tres(j.get("AllocTRES"))
    result(f"gpu defaults: one GPU's share, {share_cpus} CPUs and {share_mib} MiB",
           got.get("cpu") == str(share_cpus) and mib(got.get("mem")) == share_mib,
           err or f"AllocTRES={j.get('AllocTRES')}")
    refused("syn-alice", "over the cpu time limit", ["-A", "proj-alpha", "-p", "cpu", "-t", "2-00:00:00", "--wrap", "true"],
            ["time limit"])
    refused("syn-alice", "over the debug time limit", ["-A", "proj-alpha", "-p", "debug", "-t", "60", "--wrap", "true"],
            ["time limit"])
    refused("syn-alice", "cpu,debug with a time only cpu allows (EnforcePartLimits=ALL)",
            ["-A", "proj-alpha", "-p", "cpu,debug", "-t", "45", "--wrap", "true"], ["time limit"])
    refused("syn-alice", "two GPUs in one debug job", ["-A", "proj-alpha", "-p", "debug", "-t", "1", "--gres=gpu:2", "--wrap", "true"],
            ["QOS", "limit"])
    refused("syn-alice", "16 CPUs in one debug job", ["-A", "proj-alpha", "-p", "debug", "-t", "1", "-c", "16", "--wrap", "true"],
            ["QOS", "limit"])
    refused("syn-alice", "more GPUs than the project may hold", ["-A", "proj-alpha", "-p", "gpu", "-N", "3", "--gres=gpu:8", "-t", "1", "--wrap", "true"],
            ["QOS", "limit"])

    # --- a GPU node's CPUs and memory go with its GPUs; CPU nodes' memory costs CPUs (owner decision
    # and bench probe, 30 Sep); a queued job's size is fixed for users
    a = ["-A", "proj-alpha", "-t", "1", "--wrap", "true"]
    refused("syn-alice", "a job in gpu without GPUs", ["-p", "gpu", "-c", "2"] + a, ["asks for GPUs"])
    # owner decision 2 Oct (production's rule): a valid GPU request is rewritten to its GPUs' share
    rewritten("syn-alice", f"one GPU with {2 * share_cpus} CPUs in gpu", ["-p", "gpu", "--gres=gpu:1", "-c", str(2 * share_cpus)] + a, 1)
    rewritten("syn-alice", f"one GPU with {share_mib + 1024} MiB in gpu", ["-p", "gpu", "--gres=gpu:1", f"--mem={share_mib + 1024}M"] + a, 1)
    rewritten("syn-alice", "one GPU with --mem=0 in gpu", ["-p", "gpu", "--gres=gpu:1", "--mem=0"] + a, 1)
    rewritten("syn-alice", "one GPU with --mem-per-cpu=0 in gpu", ["-p", "gpu", "--gres=gpu:1", "--mem-per-cpu=0"] + a, 1)
    rewritten("syn-alice", "two GPUs with one CPU in gpu (raised to the share)", ["-p", "gpu", "--gres=gpu:2", "-c", "1"] + a, 2)
    rewritten("syn-alice", "one GPU named in three forms with 5 shares", ["-p", "gpu", "-n", "1", "--gpus=1", "--gres=gpu:1", "--gpus-per-task=1",
                                                                      "-c", str(5 * share_cpus), f"--mem={5 * share_mib}M"] + a, 1)
    rewritten("syn-alice", "two nodes, one GPU each", ["-p", "gpu", "-N", "2", "--gpus-per-node=1", "-c", "2"] + a, 2, nodes=2)
    rewritten("syn-alice", "one GPU in debug with --mincpus", ["-p", "debug", "--gres=gpu:1", f"--mincpus={2 * share_cpus}"] + a, 1)
    rewritten("syn-bob", "one GPU with one CPU in payg", ["-A", "proj-beta", "-p", DEFAULTS["slinky_payg"]["partition"], "--gres=gpu:1",
                                                          "-c", "1", "-t", "1", "--wrap", "true"], 1)
    refused("syn-alice", "GPUs that do not spread evenly over the nodes", ["-p", "gpu", "-N", "2", "--gpus=3"] + a, ["spread evenly"])
    refused("syn-alice", "more GPUs on a node than it has", ["-p", "gpu", f"--gres=gpu:{DEFAULTS['slinky_gpus_per_node'] + 1}"] + a, ["GPU node has"])
    refused("syn-alice", "more tasks than the GPUs' CPUs", ["-p", "gpu", "--gres=gpu:1", "-n", str(share_cpus + 1)] + a, ["split evenly"])
    # Session A review R1 (2 Oct): the share is exact. Slurm allocates a node's tasks times CPUs per
    # task, so tasks that do not divide the share are refused rather than rounded down; a GPU job runs
    # on exactly its number of nodes, with its tasks spread evenly; several nodes need the GPUs per
    # node (evidence/2026-10-02/a-review-r1-r2-bench)
    refused("syn-alice", "one GPU with three tasks", ["-p", "gpu", "--gres=gpu:1", "-n", "3"] + a, ["split evenly"])
    refused("syn-alice", "two GPUs with three tasks", ["-p", "gpu", "--gres=gpu:2", "-n", "3"] + a, ["split evenly"])
    refused("syn-alice", "two nodes, one GPU each, three tasks", ["-p", "gpu", "-N", "2", "--gpus-per-node=1", "-n", "3"] + a, ["spread evenly"])
    refused("syn-alice", "a node range (-N 1-2)", ["-p", "gpu", "-N", "1-2", "--gpus=2", "-n", "2"] + a, ["exact number of nodes"])
    refused("syn-alice", "GPUs only as a total on two nodes (--gpus=2 -N 2)", ["-p", "gpu", "-N", "2", "--gpus=2"] + a, ["GPUs per node"])
    rewritten("syn-alice", "one GPU with two tasks", ["-p", "gpu", "--gres=gpu:1", "-n", "2"] + a, 1)
    rewritten("syn-alice", "one GPU with --mem-per-cpu=4000", ["-p", "gpu", "--gres=gpu:1", "--mem-per-cpu=4000"] + a, 1)
    rewritten("syn-alice", "two nodes, two tasks and one GPU each", ["-p", "gpu", "-N", "2", "--ntasks-per-node=2", "--gpus-per-node=1"] + a, 2, nodes=2)
    allocated("syn-alice", "one GPU with two tasks", ["-A", "proj-alpha", "-t", "2", "-p", "gpu", "--gres=gpu:1", "-n", "2"], 1, 1)
    allocated("syn-alice", "one GPU in three forms with -n 1 and --mem-per-cpu", ["-A", "proj-alpha", "-t", "2", "-p", "gpu", "-n", "1", "--gpus=1",
                                                                               "--gres=gpu:1", "--gpus-per-task=1", "--mem-per-cpu=4000"], 1, 1)
    allocated("syn-alice", "two GPUs with two tasks and no -N (one node)", ["-A", "proj-alpha", "-t", "2", "-p", "gpu", "--gpus=2", "-n", "2"], 2, 1)
    allocated("syn-alice", "two nodes, two tasks and one GPU each", ["-A", "proj-alpha", "-t", "2", "-p", "gpu", "-N", "2", "--ntasks-per-node=2",
                                                                     "--gpus-per-node=1"], 1, 2)
    allocated("syn-alice", "two nodes, -n 4 and --gpus-per-task=1", ["-A", "proj-alpha", "-t", "2", "-p", "gpu", "-N", "2", "-n", "4",
                                                                     "--gpus-per-task=1"], 2, 2)
    refused("syn-alice", "--exclusive=user in gpu", ["-p", "gpu", "--gres=gpu:1", "--exclusive=user"] + a, ["exclusive"])
    refused("syn-alice", "--mem=0 in debug", ["-p", "debug", "--mem=0"] + a, ["--mem=0"])
    refused("syn-alice", "--exclusive in debug", ["-p", "debug", "--exclusive"] + a, ["exclusive"])
    refused("syn-alice", "a debug job without GPUs over the CPU nodes' memory per CPU",
            ["-p", "debug", "-c", "1", f"--mem={2 * mem_per_cpu('cpu')}M"] + a, ["MiB per CPU"])
    jid, err = sbatch("syn-alice", "-A", "proj-alpha", "-p", "debug", "-n", "1", "-t", "1", "--wrap", "true")
    j = wait_state(jid, ("COMPLETED", "FAILED", "CANCELLED")) if jid else {}
    result(f"a debug job without GPUs runs on a CPU node ({', '.join(sorted(want['cpu']))})",
           j.get("JobState") == "COMPLETED" and hostnames(j.get("NodeList", "")) <= want["cpu"]
           and j.get("Features") == DEFAULTS["slinky_cpu_feature"], err or f"{j.get('JobState')} on {j.get('NodeList')} Features={j.get('Features')}")
    jid, err = sbatch("syn-alice", "-A", "proj-alpha", "-p", "cpu", "-n", "1", f"--mem-per-cpu={2 * mem_per_cpu('cpu')}", "--hold", "--wrap", "true")
    j = job(jid) if jid else {}
    result(f"cpu: {2 * mem_per_cpu('cpu')} MiB per CPU is given 2 CPUs (MaxMemPerCPU {mem_per_cpu('cpu')})",
           int(j.get("NumCPUs", "0") or 0) >= 2 and mib(j.get("MinMemoryCPU")) == mem_per_cpu("cpu"),
           err or f"NumCPUs={j.get('NumCPUs')} MinMemoryCPU={j.get('MinMemoryCPU')}")
    held, err = sbatch("syn-alice", "-A", "proj-alpha", "-p", "gpu", "--gres=gpu:1", "-t", "10", "--hold", "--wrap", "true")
    rc, out, uerr = user("syn-alice", "scontrol", "update", f"jobid={held}", "NumCPUs=16") if held else (1, "", err)
    rc2, _, uerr2 = user("syn-alice", "scontrol", "update", f"jobid={held}", "TimeLimit=5") if held else (1, "", err)
    result("a queued job's size is fixed for its user (its time can still go down)",
           held is not None and rc != 0 and "fixed" in (uerr + out) and rc2 == 0, f"size: rc {rc} {uerr or out}; time: rc {rc2} {uerr2}")
    cancelled("node shares", [jid, held])
    size_forms(want, share_cpus, share_mib)

    # --- no per-user limits (owner decision 2 Oct: production has none outside its free queues); the
    # project's limits and the debug pool hold
    many = 9                                                    # the old per-user cap was 8
    ids = [sbatch("syn-carol", "-A", "proj-alpha", "-p", "cpu", "-n", "1", "-t", "3", "--wrap", "sleep 150")[0] for _ in range(many)]
    st = running_after(ids, many)
    result(f"no per-user job limit: {many} cpu jobs of one user run together",
           sum(s == "RUNNING" for s, _ in st.values()) == many, str(st))
    cancelled("no per-user job limit", ids)

    if GPU_FILL:
        grp = tres(DEFAULTS["slinky_qos"]["normal"]["MaxTRESPerAccount"])["gres/gpu"]
        nodes = int(grp) // DEFAULTS["slinky_gpus_per_node"]
        a, err = sbatch("syn-carol", "-A", "proj-alpha", "-p", "gpu", "-N", str(nodes), f"--gres=gpu:{DEFAULTS['slinky_gpus_per_node']}",
                        "-t", "3", "--wrap", "sleep 150")
        ja = wait_state(a, ("RUNNING",), 60) if a else {}
        b, _ = sbatch("syn-carol", "-A", "proj-alpha", "-p", "gpu", "--gres=gpu:1", "-t", "3", "--wrap", "sleep 150")
        time.sleep(8)
        jb = job(b) if b else {}
        result(f"no per-user GPU limit: one user holds the project's {grp} GPUs; the next GPU job waits on the project's limit",
               ja.get("JobState") == "RUNNING" and jb.get("JobState") == "PENDING" and "PerAccount" in jb.get("Reason", ""),
               err or f"{ja.get('JobState')}/{ja.get('Reason')} AllocTRES={ja.get('AllocTRES')}; next {jb.get('JobState')}/{jb.get('Reason')}")
        cancelled("no per-user GPU limit", [a, b])

        users = [("syn-alice", "proj-alpha"), ("syn-bob", "proj-beta"), ("syn-carol", "proj-alpha"), ("syn-dave", "proj-beta"),
                 ("agent-perm01", "proj-beta")][:debug_pool + 1]
        ids = [sbatch(u, "-A", acct, "-p", "debug", "--gres=gpu:1", "-t", "3", "--wrap", "sleep 150")[0] for u, acct in users]
        running_after(ids, debug_pool)
        time.sleep(6)
        st = {i: (j.get("JobState"), j.get("Reason")) for i, j in ((i, job(i)) for i in ids if i)}
        result(f"debug GPU pool: {debug_pool} GPUs across all users",
               sum(s == "RUNNING" for s, _ in st.values()) == debug_pool and sum(r == "QOSGrpGRES" for _, r in st.values()) == 1, str(st))
        cancelled("debug GPU pool", ids)

        grp = DEFAULTS["slinky_qos"]["normal"]["MaxTRESPerAccount"]
        a, _ = sbatch("syn-bob", "-A", "proj-beta", "-p", "gpu", "--gres=gpu:8", "-t", "3", "--wrap", "sleep 120")
        b, _ = sbatch("syn-dave", "-A", "proj-beta", "-p", "gpu", "--gres=gpu:8", "-t", "3", "--wrap", "sleep 120")
        full = [wait_state(x, ("RUNNING",), 60).get("JobState") for x in (a, b) if x]
        c, err = sbatch("agent-perm01", "-A", "proj-beta", "-p", "gpu", "--gres=gpu:1", "-t", "1", "--wrap", "true")
        time.sleep(6)
        jc = job(c) if c else {}
        result(f"project quota on the free queues ({grp}): a third member waits", full == ["RUNNING", "RUNNING"]
               and jc.get("JobState") == "PENDING" and "PerAccount" in jc.get("Reason", ""),
               f"first two {full}, third {jc.get('JobState')}/{jc.get('Reason')} {err}")
        # pay per use is not held by that quota: the project pays for more
        d, err = sbatch("agent-perm01", "-A", "proj-beta", "-p", DEFAULTS["slinky_payg"]["partition"], "--gres=gpu:1", "-t", "1", "--wrap", "true")
        jd = wait_state(d, ("RUNNING", "COMPLETED"), 60) if d else {}
        result("pay per use runs beyond the free queues' project quota", jd.get("JobState") in ("RUNNING", "COMPLETED"),
               err or f"{jd.get('JobState')}/{jd.get('Reason')}")
        cancelled("project quota", [a, b, c, d])

        # --- a GPU node's CPUs and memory go with its GPUs (bench probe, 30 Sep: one GPU with
        # --mem=0 or -c 32, a job with no GPU, or --exclusive=user each held a whole node, so
        # three such jobs of one user left none of the 24 GPUs to anyone else)
        node = sorted(n for n, k in EXPECTED["workers"].items() if k == "gpu")[0]
        near_all = mib(DEFAULTS["slinky_nodeset_resources"]["gpu"]["memory"][:-1]) * 95 // 100
        cpus = DEFAULTS["slinky_nodeset_resources"]["gpu"]["cpu"]
        for label, hog, update in (
                ("one GPU with the node's whole memory (--mem=0)", ["-p", "gpu", "--gres=gpu:1", "--mem=0"], None),
                ("one GPU with all the node's CPUs", ["-p", "gpu", "--gres=gpu:1", "-c", cpus], None),
                ("no GPU, all the node's CPUs, in gpu", ["-p", "gpu", "-c", cpus], None),
                ("one GPU with --exclusive=user", ["-p", "gpu", "--gres=gpu:1", "--exclusive=user"], None),
                ("a one-CPU debug job with the node's whole memory", ["-p", "debug", "--mem=0"], None),
                ("one GPU with the node's whole memory (--mem-per-cpu=0; bench probe v2)", ["-p", "gpu", "--gres=gpu:1", "--mem-per-cpu=0"], None),
                ("one GPU with the node's whole memory in payg (--mem-per-cpu=0; bench probe v2)",
                 ["-p", DEFAULTS["slinky_payg"]["partition"], "--gres=gpu:1", "--mem-per-cpu=0"], None),
                ("a pending one-GPU job enlarged by scontrol update to the node's memory",
                 ["-p", "gpu", "--gres=gpu:1"], [f"MinMemoryNode={near_all}"])):
            gpu_node_shared(label, node, hog, update)
    else:
        print("SKIP: per-user GPU totals, debug GPU pool, project GPU limit, GPU node share (--no-gpu-fill)")

    # --- pay per use (simulated, slinky_payg): each project's own credit QoS, charged at the
    # partition's rate; out of credit, its payg jobs wait; the credit QoS only in payg
    pg = DEFAULTS["slinky_payg"]
    pq = lambda acct: pg["qos_prefix"] + acct                                       # noqa: E731
    credits = int(pg["credits"].get("proj-alpha", pg["credits"]["default"]))
    rc, out, _ = admin("sacctmgr", "-nP", "show", "qos", f"name={pq('proj-alpha')}", "format=Name,GrpTRESMins,UsageFactor,Flags")
    row = out.strip().split("|") if rc == 0 else []
    result(f"payg credits: {pq('proj-alpha')} holds {credits} credit-hours, usage not decayed",
           len(row) == 4 and tres(row[1]).get("billing") == str(credits * 60) and "nodecay" in row[3].lower(), out)
    p = parts.get(pg["partition"], {})
    weights = DEFAULTS["slinky_tres_billing_weights"]
    result(f"partition {pg['partition']}: every expected worker, billing {weights}, {pg['MaxTime']} max",
           hostnames(p.get("Nodes", "")) == set(EXPECTED["workers"]) and p.get("TRESBillingWeights") == weights
           and p.get("MaxTime") == pg["MaxTime"], str(p)[:300])

    def used(qos):
        """credit-minutes a payg QoS has used (scontrol show assoc_mgr: GrpTRESMins=...billing=LIMIT(USED))"""
        rc, out, _ = admin("scontrol", "show", "assoc_mgr", "flags=qos", f"qos={qos}")
        for part in out.replace("\n", " ").split():
            if part.startswith("GrpTRESMins="):
                for item in part.split("=", 1)[1].split(","):
                    if item.startswith("billing=") and "(" in item:
                        return int(item.split("(")[1].rstrip(")"))
        return None
    before = used(pq("proj-alpha"))
    jid, err = sbatch("syn-alice", "-A", "proj-alpha", "-p", pg["partition"], "--gres=gpu:1", "-t", "2", "--wrap", "sleep 30")
    j = wait_state(jid, ("COMPLETED", "FAILED", "CANCELLED"), 120) if jid else {}
    after = before
    for _ in range(40):            # charged when slurmctld next applies usage (PriorityCalcPeriod)
        after = used(pq("proj-alpha"))
        if before is not None and after is not None and after > before:
            break
        time.sleep(5)
    result("a payg job gets its project's credit QoS and is charged",
           j.get("JobState") == "COMPLETED" and j.get("QOS") == pq("proj-alpha") and before is not None
           and after is not None and after > before,
           err or f"{j.get('JobState')} QOS={j.get('QOS')}; credit-minutes used {before} -> {after}")
    got = tres(j.get("AllocTRES"))
    want_rate = max(int(got.get("cpu", "0") or 0), share_cpus * int(got.get("gres/gpu", "0") or 0))
    result(f"payg charge rate: the job's CPUs, or {share_cpus} per GPU when more (one GPU with its share: {share_cpus} an hour)",
           got.get("billing") is not None and got.get("billing") == str(want_rate) and want_rate == share_cpus,
           f"AllocTRES={j.get('AllocTRES')}")
    rc, out, err = user("syn-alice", "scontrol", "show", "assoc_mgr", "flags=qos", f"qos={pq('proj-alpha')}")
    result("a project member reads its credit balance (scontrol show assoc_mgr flags=qos)",
           rc == 0 and f"billing={credits * 60}(" in out, err or out[:200])
    a = ["-A", "proj-alpha", "-t", "1", "--wrap", "true"]
    refused("syn-alice", "credits outside payg (--qos in cpu)", ["-p", "cpu", f"--qos={pq('proj-alpha')}"] + a, ["apply only"])
    refused("syn-alice", "a payg job choosing QoS normal", ["-p", pg["partition"], "--qos=normal"] + a, ["credits"])
    refused("syn-alice", "a payg job charging another project's credits", ["-p", pg["partition"], f"--qos={pq('proj-beta')}"] + a, ["credits"])
    refused("syn-alice", "payg with another partition", ["-p", f"{pg['partition']},cpu"] + a, ["alone"])
    limit = f"billing={int(pg['credits'].get('proj-beta', pg['credits']['default'])) * 60}"
    admin("sacctmgr", "-i", "modify", "qos", "where", f"name={pq('proj-beta')}", "set", "GrpTRESMins=billing=0")
    try:            # owner decision 2 Oct: accepted, and waits until its credit fits (no DenyOnLimit)
        jid, err = sbatch("syn-bob", "-A", "proj-beta", "-p", pg["partition"], "-n", "1", "-t", "1", "--wrap", "true")
        time.sleep(8)
        jo = job(jid) if jid else {}
        result("out of credit: a payg job is accepted and waits (QOSGrpBillingMinutes)",
               jid is not None and jo.get("JobState") == "PENDING" and "Billing" in jo.get("Reason", ""),
               err or f"job {jid} {jo.get('JobState')}/{jo.get('Reason')}")
    finally:
        rc, _, _ = admin("sacctmgr", "-i", "modify", "qos", "where", f"name={pq('proj-beta')}", "set", f"GrpTRESMins={limit}")
        result(f"{pq('proj-beta')}'s credit restored ({limit})", rc == 0)
    cancelled("pay per use", [jid])
    # not enough credit left: a job whose full time limit does not fit what is left (after what the
    # running jobs may still use) does not start (AccountingStorageEnforce=safe); one that fits does
    ids = []
    try:
        first, err = sbatch("syn-bob", "-A", "proj-beta", "-p", pg["partition"], "-n", "1", "-t", "30", "--wrap", "sleep 300")
        ids.append(first)
        jf = wait_state(first, ("RUNNING",), 60) if first else {}
        rate = int(tres(jf.get("AllocTRES")).get("billing", "0") or 0)          # credit-minutes per minute
        base = used(pq("proj-beta")) or 0
        room = base + rate * 30 + rate * 15            # the running job in full, then half of another
        admin("sacctmgr", "-i", "modify", "qos", "where", f"name={pq('proj-beta')}", "set", f"GrpTRESMins=billing={room}")
        second, err2 = sbatch("syn-dave", "-A", "proj-beta", "-p", pg["partition"], "-n", "1", "-t", "30", "--wrap", "sleep 300")
        small, err3 = sbatch("syn-dave", "-A", "proj-beta", "-p", pg["partition"], "-n", "1", "-t", "5", "--wrap", "sleep 30")
        ids += [second, small]
        time.sleep(12)
        js, jm = (job(second) if second else {}), (job(small) if small else {})
        result("not enough credit left: a payg job does not start; a smaller one that fits does",
               jf.get("JobState") == "RUNNING" and rate > 0 and js.get("JobState") == "PENDING"
               and "Billing" in js.get("Reason", "") and jm.get("JobState") in ("RUNNING", "COMPLETED"),
               f"running {jf.get('JobState')} ({rate}/min); 30-min job {js.get('JobState')}/{js.get('Reason')} {err2}; "
               f"5-min job {jm.get('JobState')}/{jm.get('Reason')} {err3}")
        big, err4 = sbatch("syn-dave", "-A", "proj-beta", "-p", pg["partition"], "-n", "1", "-t", "1-00:00:00", "--wrap", "true")
        ids.append(big)
        time.sleep(8)
        jbig = job(big) if big else {}
        result("a payg job costing more than the project's whole credit: accepted, and waits until the credit is raised",
               big is not None and jbig.get("JobState") == "PENDING" and "Billing" in jbig.get("Reason", ""),
               err4 or f"job {big} {jbig.get('JobState')}/{jbig.get('Reason')}")
    finally:
        rc, _, _ = admin("sacctmgr", "-i", "modify", "qos", "where", f"name={pq('proj-beta')}", "set", f"GrpTRESMins={limit}")
        result(f"{pq('proj-beta')}'s credit restored again ({limit})", rc == 0)
    cancelled("credit left", ids)

    # --- fairshare, interactive, revocation
    rc, out, _ = admin("sshare", "-n", "-P", "-o", "Account,User,RawShares")
    shares = {l.split("|")[0].strip(): l.split("|")[2] for l in out.splitlines() if l.count("|") == 2 and not l.split("|")[1]}
    want_share = str(DEFAULTS["slinky_account_settings"]["project"]["Fairshare"])
    result(f"fairshare: each project has {want_share} shares, and no other account exists",
           shares.get("proj-alpha") == want_share and shares.get("proj-beta") == want_share
           and not set(shares) - {"root", "proj-alpha", "proj-beta", "proj-ops"}, str(shares))
    rc, out, err = user("syn-dave", "srun", "-A", "proj-beta", "-p", "debug", "-t", "1", "-n", "1", "hostname")
    result("interactive srun in a project", rc == 0 and out.strip() in workers, err or out)
    rc, out, _ = admin("sacctmgr", "-n", "-P", "show", "assoc", "where", "user=syn-revoked", "format=Account")
    result("the revoked user has no association", rc == 0 and out.strip() == "", out)


def size_forms(want, share_cpus, share_mib):
    """bench probe v2 (1 Oct): request forms the submit filter's size parser missed. Each is refused,
    or what Slurm allocated is within the share: on a GPU node at most the share per ALLOCATED GPU (the
    filter summed --gpus, --gres, --gpus-per-task and --gpus-per-socket, which Slurm meets with one
    GPU, and Slurm gave one GPU for --gpus-per-socket=1 on two sockets; it ignored --mincpus and
    --mem-per-cpu=0); a job without GPUs on a CPU node (--prefer
    replaced the filter's constraint); a queued job cannot take these forms later; a payg GPU job
    is charged at least its GPUs' share, whatever CPUs it names (one CPU for eight GPUs was billed 1)."""
    pg = DEFAULTS["slinky_payg"]
    node = sorted(want["gpu"])[0]

    def ran(user_, acct, args):
        """(job id or None, error, the job once it ran, or as it is after 30 s)"""
        jid, err = sbatch(user_, "-A", acct, "-t", "1", *args, "--wrap", "sleep 5")
        return jid, err, (wait_state(jid, ("RUNNING", "COMPLETED", "FAILED", "CANCELLED"), 30) if jid else {})

    for label, args, *where in (
            ("--gpus=1 with --gres=gpu:1, 8 CPUs and 2 shares of memory", ["-p", "gpu", "--gpus=1", "--gres=gpu:1", "-c", str(2 * share_cpus),
                                                                         f"--mem={2 * share_mib}M"]),
            ("--gpus=1 with --gpus-per-node=1, 8 CPUs", ["-p", "gpu", "--gpus=1", "--gpus-per-node=1", "-c", str(2 * share_cpus)]),
            ("one GPU named in four forms, 5 shares of CPUs and memory",
             ["-p", "gpu", "-n", "1", "--gpus=1", "--gres=gpu:1", "--gpus-per-task=1", "--gpus-per-socket=1", "--sockets-per-node=1",
              "-c", str(5 * share_cpus), f"--mem={5 * share_mib}M"]),
            # not pinned: with -w, sbatch asks for a CPU count the filter refuses anyway
            ("--gpus-per-socket=1 on two sockets, 2 shares", ["-p", "gpu", "--gpus-per-socket=1", "--sockets-per-node=2",
                                                             "-c", str(2 * share_cpus), f"--mem={2 * share_mib}M"], []),
            ("--mincpus with one GPU in debug", ["-p", "debug", "--gres=gpu:1", f"--mincpus={2 * share_cpus}"]),
            ("--mem-per-cpu=0 with one GPU in gpu", ["-p", "gpu", "--gres=gpu:1", "--mem-per-cpu=0"]),
            ("--mem-per-cpu=0 with one GPU in payg", ["-p", pg["partition"], "--gres=gpu:1", "--mem-per-cpu=0"])):
        pin = where[0] if where else ["-w", node]          # one GPU node, unless the case says otherwise
        jid, err, j = ran("syn-alice", "proj-alpha", pin + args)
        got = tres(j.get("AllocTRES"))
        gpus = int(got.get("gres/gpu", "0") or 0)
        result(f"GPU node share: {label}: refused, or at most {share_cpus} CPUs and {share_mib} MiB per allocated GPU",
               jid is None or (j.get("JobState") in ("RUNNING", "COMPLETED") and gpus >= 1
                               and int(got.get("cpu", "0") or 0) <= share_cpus * gpus and (mib(got.get("mem")) or 0) <= share_mib * gpus),
               f"job {jid} {j.get('JobState')}/{j.get('Reason')} AllocTRES={j.get('AllocTRES')} {err}")
        cancelled(label, [jid])
    refused("syn-alice", "--mem-per-cpu=0 without GPUs in payg (a CPU node's whole memory)",
            ["-A", "proj-alpha", "-p", pg["partition"], "-t", "1", "--mem-per-cpu=0", "--wrap", "true"], ["--mem-per-cpu=0", "--mem=0"])
    for part in ("debug", pg["partition"]):
        jid, err, j = ran("syn-alice", "proj-alpha", ["-p", part, "-n", "1", "--prefer=gpu"])
        result(f"{part}: a job without GPUs that prefers GPU nodes (--prefer=gpu) is refused or runs on a CPU node",
               jid is None or (j.get("JobState") in ("RUNNING", "COMPLETED") and hostnames(j.get("NodeList", "")) <= want["cpu"]),
               f"job {jid} {j.get('JobState')} on {j.get('NodeList')} Features={j.get('Features')} {err}")
        cancelled(f"--prefer in {part}", [jid])
    held = []
    for label, args, update in (("a queued debug job without GPUs cannot prefer GPU nodes later", ["-n", "1"], "Prefer=gpu"),
                                ("a queued one-GPU debug job cannot take more CPUs per node later", ["--gres=gpu:1"], f"MinCPUsNode={2 * share_cpus}")):
        jid, err = sbatch("syn-alice", "-A", "proj-alpha", "-p", "debug", "-t", "1", "--hold", *args, "--wrap", "true")
        held.append(jid)
        rc, out, uerr = user("syn-alice", "scontrol", "update", f"jobid={jid}", update) if jid else (0, "", err)
        result(f"{label} (scontrol update {update} refused)", jid is not None and rc != 0, f"job {jid}: rc {rc} {uerr or out}")
    cancelled("queued-job updates", held)
    # charging: whatever CPUs a GPU job names, it is billed at least its GPUs' CPU share: payg credits,
    # and the free queues' fairshare (production charges a GPU as 4 units either way)
    for part in (pg["partition"], "gpu"):
        jid, err, j = ran("syn-bob", "proj-beta", ["-p", part, "-w", node, "--gres=gpu:2", "-c", "1", "--mem=8G"])
        got = tres(j.get("AllocTRES"))
        gpus = int(got.get("gres/gpu", "0") or 0)
        result(f"{part}: a GPU job with one CPU is refused, or billed at least {share_cpus} per allocated GPU",
               jid is None or (j.get("JobState") in ("RUNNING", "COMPLETED") and gpus >= 1
                               and float(got.get("billing", "0") or 0) >= share_cpus * gpus),
               f"job {jid} {j.get('JobState')}/{j.get('Reason')} AllocTRES={j.get('AllocTRES')} {err}")
        cancelled(f"{part} GPU charge", [jid])


def on(node, name, account, script):
    """(rc, stdout, stderr) of a shell script run as a user in a one-task debug job on a node. A GPU
    node takes only jobs with a GPU (the submit filter, D41), so there the job asks for one."""
    gpu = ["--gres=gpu:1"] if EXPECTED["workers"].get(node) == "gpu" else []
    return user(name, "srun", "-A", account, "-p", "debug", "-w", node, "-t", "2", "-n", "1", *gpu, "sh", "-c", script)


PROJECT_DIR = "/projects/proj-alpha"
# The quota write: dd's status and full stderr, the file's size and allocated space, and its removal,
# each reported separately (review R6: `dd ... 2>&1 | tail -1` kept only dd's transfer summary, and an
# unrelated error naming the "-quota" file passed as enforcement).
# 4 Oct window: over NFS a write refused with EDQUOT at fsync leaves the CLIENT's size at what dd wrote
# (300 MiB) while the server kept 268369920 bytes; the allocated blocks agree on both sides (524160).
QUOTA_SCRIPT = ('f="$HOME/{tag}-quota"; err=$(dd if=/dev/zero of="$f" bs=1M count={count} conv=fsync 2>&1); rc=$?; '
                'size=$(stat -c %s "$f" 2>/dev/null || echo none); '
                'alloc=$(stat -c "%b %B" "$f" 2>/dev/null || echo none); rm -f "$f"; '
                'if [ -e "$f" ]; then gone=no; else gone=yes; fi; '
                'printf "dd_rc=%s\\nsize=%s\\nalloc=%s\\ngone=%s\\n" "$rc" "$size" "$alloc" "$gone"; '
                'printf "%s\\n" "$err" | sed "s/^/err: /"')


# The program a setuid check copies: the ELF that implements id. 4 Oct window: in the Rocky 9 images
# (coreutils-single) /usr/bin/id is a script, "#!/usr/bin/coreutils --coreutils-prog-shebang=id", and
# the kernel ignores setuid on a script, so the /tmp control ran as the caller on every worker and in
# the login pod; an ELF copy of /usr/bin/coreutils in a worker's /tmp ran as its owner. The copy
# reports its mode, its kind and its first four bytes, so a script is never taken for the program.
ID_MULTICALL, ID_SINGLE = "/usr/bin/coreutils", "/usr/bin/id"
SUID_COPY = ('if [ -x {multicall} ]; then s={multicall}; k=multicall; else s={single}; k=single; fi; '
             'cp "$s" {dst} && chmod 4755 {dst} && '
             'printf "%s %s %s\\n" "$(stat -c %a {dst})" "$k" "$(od -An -tx1 -N4 {dst} | tr -d " \\n")"')


def suid_copy(out):
    """the kind of a SUID_COPY ("multicall" or "single") when it made a mode 4755 ELF, else None"""
    parts = out.split()
    ok = len(parts) == 3 and parts[0] == "4755" and parts[1] in ("multicall", "single") and parts[2] == "7f454c46"
    return parts[1] if ok else None


def id_euid(path, kind):
    """the command that makes a SUID_COPY of that kind print its effective uid"""
    return [path, "--coreutils-prog=id", "-u"] if kind == "multicall" else [path, "-u"]


def quota_verdict(rc, out, hard_bytes):
    """(enforced, file removed, detail): enforced only when dd failed with EDQUOT and the file's
    allocated space (blocks times block size) stayed within the hard limit; the file's name is
    never evidence, and neither is its size, which over NFS is the client's (4 Oct)"""
    fields, err = {}, []
    for line in out.splitlines():
        if line.startswith("err: "):
            err.append(line[5:])
        elif "=" in line:
            fields.setdefault(*line.split("=", 1))
    size = int(fields["size"]) if fields.get("size", "").isdigit() else None
    alloc = fields.get("alloc", "").split()
    allocated = int(alloc[0]) * int(alloc[1]) if len(alloc) == 2 and all(a.isdigit() for a in alloc) else None
    enforced = (rc == 0 and fields.get("dd_rc", "0") != "0" and any("Disk quota exceeded" in l for l in err)
                and allocated is not None and allocated <= hard_bytes)
    quota_err = [l for l in err if "Disk quota exceeded" in l]
    return (enforced, rc == 0 and fields.get("gone") == "yes",
            f"dd rc {fields.get('dd_rc')}, size {size}, allocated {allocated}, stderr {(quota_err or err)[-1:] + err[-1:]}")


def removal_script(paths):
    """rm -f each path, then look: prints "left: PATH" for any still there, and "rm_rc=N" last"""
    return ("rc=0; for f in " + " ".join(shlex.quote(p) for p in paths) + "; do rm -f -- \"$f\" || rc=1; "
            "if [ -e \"$f\" ] || [ -L \"$f\" ]; then echo \"left: $f\"; fi; done; echo \"rm_rc=$rc\"")


def project_cleanup_script(d, tag):
    """remove this run's files in the project directory, then list it: the listing must succeed
    (review R7: a failed `ls ... 2>/dev/null | wc -l` counted as zero files)"""
    pattern = shlex.quote("^" + tag.replace(".", "\\.") + "-")
    return (f"rm -f {d}/{tag}-*; rc=$?; out=$(ls -A {d}) || {{ echo 'listing failed'; exit 2; }}; "
            f"echo \"left=$(printf '%s\\n' \"$out\" | grep -c {pattern})\"; echo \"rm_rc=$rc\"")


def removed(rc, out):
    """a removal_script or project_cleanup_script result: everything gone, shown by a successful look"""
    return rc == 0 and "rm_rc=0" in out.split() and "left: " not in out and "listing failed" not in out \
        and ("left=" not in out or "left=0" in out.split())


def storage():
    expected = sorted(EXPECTED["workers"])
    rc, out, err = admin("sinfo", "-h", "-N", "-p", "debug", "-o", "%N %T")
    seen = dict(l.split()[:2] for l in out.splitlines() if len(l.split()) >= 2) if rc == 0 else {}
    usable = {n for n, st in seen.items() if st in ("idle", "mixed", "allocated", "completing")}
    missing = [n for n in expected if n not in usable]
    result(f"every expected worker ({len(expected)}) is in debug and usable", rc == 0 and not missing,
           err or f"missing or unusable: {missing}; found {seen}")
    if len(expected) < 2:
        result("two or more expected workers (a cross-node read needs a second one)", False, str(expected))
        return
    uid = {n: user(n, "id", "-u")[1] for n in ("syn-alice", "syn-carol", "syn-bob")}
    tag = f".acc-{int(time.time())}"
    d = PROJECT_DIR
    left = []          # this run's files whose removal was not shown (where: output)
    try:
        # every EXPECTED worker is exercised, discovered or not: a missing one fails its checks
        for i, node in enumerate(expected + ["login pod"]):
            reader = expected[(i + 1) % len(expected)]
            run = (lambda n, a, c: user(n, "sh", "-c", c)) if node == "login pod" else (lambda n, a, c, node=node: on(node, n, a, c))
            f = f"{d}/{tag}-{node.replace(' ', '-')}"
            # each share's options on their own line, so the file checks below never depend on them
            rc, out, err = run("syn-alice", "proj-alpha",
                               'for p in /home /projects /apps; do echo "mount $p $(findmnt -no OPTIONS $p || echo none)"; done; '
                               f"echo written-on-$(hostname) > {f} && stat -c '%G' {f}")
            lines = out.splitlines()
            opts = {l.split()[1]: set(l.split()[2].split(",")) for l in lines if l.startswith("mount ") and len(l.split()) == 3}
            # the bench's shares are tmpfs volumes (no NFS hard) and it has no /home share (bench probe v2, L6)
            need, paths = ({"nosuid", "nodev"}, ["/projects", "/apps"]) if BENCH else ({"nosuid", "nodev", "hard"}, ["/home", "/projects", "/apps"])
            want_opts = ",".join(sorted(need))
            result(f"{node}: {' and '.join(paths[:-1])} rw,{want_opts}; /apps ro,{want_opts}" + (" (bench: tmpfs, no /home share)" if BENCH else ""),
                   all(need | {"ro" if p == "/apps" else "rw"} <= opts.get(p, set()) for p in paths), err or out)
            result(f"{node}: a project member's file belongs to the project", rc == 0 and lines[-1:] == ["proj-alpha"], err or out)
            rc, out, err = on(reader, "syn-carol", "proj-alpha", f"cat {f}; echo read-on-$(hostname)")
            where = out.splitlines()[-1] if out else ""
            result(f"{node}: another member reads it on another worker ({reader})",
                   rc == 0 and out.startswith("written-on-") and where == f"read-on-{reader}"
                   and (node == "login pod" or reader != node), err or out)
            rc, out, err = run("syn-bob", "proj-beta", f"cat {f} >/dev/null 2>&1 && echo READ; touch {d}/{tag}-bob 2>/dev/null && echo WROTE; "
                                                       f"ls {d} >/dev/null 2>&1 && echo LISTED; echo done")
            result(f"{node}: another project's member cannot read, write or list it", rc == 0 and out.strip() == "done", err or out)
            rc, out, err = run("syn-alice", "proj-alpha", "touch /apps/.acc-write 2>&1; echo rc=$?")
            result(f"{node}: /apps cannot be written", out.strip().endswith("rc=1") and ("Read-only" in out or "Permission" in out), out)
            if not out.strip().endswith("rc=1"):      # the counterexample may exist: remove it where it was made
                rc2, out2, err2 = run("syn-alice", "proj-alpha", removal_script(["/apps/.acc-write"]))
                if not removed(rc2, out2):
                    left.append(f"{node} /apps/.acc-write: {out2.strip() or err2 or rc2}")
        # nosuid: a setuid ELF copy of id owned by syn-alice, run by syn-carol, must report syn-carol
        prog = f"{d}/{tag}-id"
        rc, out, err = user("syn-alice", "sh", "-c", SUID_COPY.format(multicall=ID_MULTICALL, single=ID_SINGLE,
                                                                     dst=shlex.quote(prog)))
        prog_kind = suid_copy(out)
        result("a member can leave a setuid program (an ELF) in the project directory (the test's premise)",
               rc == 0 and prog_kind is not None, err or out)
        # control: the same program from the pod's own /tmp (no nosuid there) must run as its
        # owner, or setuid is ignored everywhere and nosuid on /projects proves nothing
        ctl = f"/tmp/{tag}-id"
        ctl_copy = SUID_COPY.format(multicall=ID_MULTICALL, single=ID_SINGLE, dst=shlex.quote(ctl))
        for node in expected + ["login pod"]:
            if node == "login pod":
                ctl_kind = suid_copy(user("syn-alice", "sh", "-c", ctl_copy)[1])
                control = user("syn-carol", *id_euid(ctl, ctl_kind))[1].strip()
                rc, out, err = user("syn-carol", *id_euid(prog, prog_kind))
                rc2, out2, err2 = user("syn-alice", "sh", "-c", removal_script([ctl]))
            else:
                ctl_kind = suid_copy(on(node, "syn-alice", "proj-alpha", ctl_copy)[1])
                control = on(node, "syn-carol", "proj-alpha", shlex.join(id_euid(ctl, ctl_kind)))[1].strip()
                rc, out, err = on(node, "syn-carol", "proj-alpha", shlex.join(id_euid(prog, prog_kind)))
                rc2, out2, err2 = on(node, "syn-alice", "proj-alpha", removal_script([ctl]))
            if not removed(rc2, out2):
                left.append(f"{node} {ctl}: {out2.strip() or err2 or rc2}")
            name = f"{node}: a setuid program in /projects runs as the caller (nosuid; control in /tmp runs as its owner)"
            if BENCH and control == uid["syn-carol"]:
                # 29 Sep: the bench's control ran as the caller (NoNewPrivs 0, no nosuid), most likely
                # the same script /usr/bin/id as on the fleet (4 Oct); the bench still only skips
                print(f"SKIP: {name}: the bench's containers ignore setuid everywhere (control ran as the caller)")
                continue
            result(name, rc == 0 and ctl_kind is not None and out.strip() == uid["syn-carol"] and control == uid["syn-alice"],
                   f"/projects euid {out.strip()}, /tmp euid {control} (control {ctl_kind or 'not a 4755 ELF'}); "
                   f"carol {uid['syn-carol']}, alice {uid['syn-alice']} {err}")
        # quota over NFS from the pods: syn-probe's home hard limit (storage.yml) stops a larger write
        storage_vars = yaml.safe_load((INFRA / "inventories/fleet/group_vars/all/storage.yml").read_text())
        hard = storage_vars["storage_home_quota_user"]["syn-probe"]["bhard"]
        mib_hard = int(hard[:-1]) * (1024 if hard[-1].lower() == "g" else 1)
        write = QUOTA_SCRIPT.format(tag=tag, count=mib_hard + 44)
        if BENCH:
            print(f"SKIP: syn-probe's {hard} home quota from the pods: the bench has no quotas")
        else:
            for node in (expected[0], expected[-1], "login pod"):
                rc, out, err = (user("syn-probe", "sh", "-c", write) if node == "login pod"
                                else on(node, "syn-probe", "proj-ops", write))
                enforced, gone, detail = quota_verdict(rc, out, mib_hard * 1024 * 1024)
                result(f"{node}: syn-probe's {hard} home quota stops a {mib_hard + 44} MiB write (EDQUOT, allocated bytes within the limit)",
                       enforced, detail + (f" {err}" if err else ""))
                if not gone:
                    left.append(f"{node} ~syn-probe/{tag}-quota: {detail}")
    finally:
        rc, out, err = user("syn-alice", "sh", "-c", project_cleanup_script(d, tag))
        if not removed(rc, out):
            left.append(f"{d}: {out.strip() or err or rc}")
        result("cleanup: every file this run made is gone (project directory, /tmp controls, /apps, quota files)",
               not left, "; ".join(left))


# --- the shared job environment (T88, roles/apps_env) --------------------------------------------------
MODULES = [f"{name}/{APPS['apps_env_' + name]['module']}" for name in ("gcc", "cuda", "openmpi", "python")]
CUDA = MODULES[1]
EXAMPLES = "/apps/examples"
# One rank of the examples' MPI program, with the examples' TCP settings and outside srun's launch
# environment (Slurm's variables removed): this checks the build and the library. Rocky's OpenMPI 4.1.1
# has no PMI-2 client (ompi_info: pmix ext3x only), so a one-rank srun step would be refused as a
# direct launch without PMI support; the two-node check runs mpi.sh, which launches with mpirun.
WORKER_SCRIPT = r"""
avail=$(module -t avail 2>&1)
for m in @MODULES@; do printf '%s\n' "$avail" | grep -Eq "^$m(\(default\))?$" && echo "module $m"; done
if msg=$(module load @CUDA@ 2>&1 && nvcc --version 2>&1 | grep -o 'release [0-9.]*'); then echo "cuda=loaded $msg"
else echo "cuda=refused $(printf '%s' "$msg" | tr '\n' ' ')"; fi
module load @LOAD@ || { echo load-failed; exit 1; }
w=$(mktemp -d) || exit 1
trap 'rm -rf "$w"' EXIT
echo "g++=$(command -v g++)"
gcc -O2 -o "$w/c" @EX@/hello.c && "$w/c"
g++ -O2 -pthread -o "$w/cxx" @EX@/hello_threads.cpp && "$w/cxx" | tail -n 1
mpicc -O2 -o "$w/mpi" @EX@/mpi_hello.c && env $(env | sed -n 's/^\(SLURM_[^=]*\)=.*/-u \1/p') @TCP@ "$w/mpi"
python @EX@/hello.py
""".replace("@MODULES@", " ".join(MODULES)).replace("@CUDA@", CUDA).replace("@EX@", EXAMPLES) \
   .replace("@LOAD@", " ".join(m for m in MODULES if m != CUDA)) \
   .replace("@TCP@", f"OMPI_MCA_pml=ob1 OMPI_MCA_btl=self,tcp OMPI_MCA_btl_tcp_if_include={POD_NETWORK}")
FINISHED = ("COMPLETED", "FAILED", "CANCELLED", "TIMEOUT", "OUT_OF_MEMORY", "NODE_FAIL", "BOOT_FAIL", "DEADLINE")


def login_shell(script):
    """a sh -c script that runs `script` in a login shell: /etc/profile.d, so Lmod and the /apps snippet"""
    return "exec bash -lc " + shlex.quote(script)


def worker_verdicts(node, rc, out, cuda_here):
    """the checks of one WORKER_SCRIPT run: [(name, ok, detail)]"""
    lines = out.splitlines()
    seen = {l.split(" ", 1)[1] for l in lines if l.startswith("module ")}
    cuda = next((l for l in lines if l.startswith("cuda=")), "")
    gxx = next((l.split("=", 1)[1] for l in lines if l.startswith("g++=")), "")
    gcc_tree = f"{APPS['apps_env_root']}/sw/gcc/{APPS['apps_env_gcc']['version']}/"
    host_ok = lambda prefix: any(l.startswith(prefix) and l.endswith(" " + node) for l in lines)    # noqa: E731
    built = (rc == 0 and gxx.startswith(gcc_tree) and host_ok("c ok on")
             and any(l.startswith("cxx threads ok:") and l.endswith(" on " + node) for l in lines)
             and "mpi: size=1 hosts=1 messages=0" in lines)
    want = f"release {CUDA.split('/')[1]}"
    return [
        (f"{node}: modules {', '.join(MODULES)} visible", seen == set(MODULES), f"saw {sorted(seen)}"),
        (f"{node}: gcc, g++ (threads, from {gcc_tree}) and mpicc build and run", built, out[-600:]),
        (f"{node}: python/{APPS['apps_env_python']['module']} runs", any(l.startswith("python ok: 3.9") for l in lines), out[-300:]),
        (f"{node}: {CUDA} loads (nvcc {want})" if cuda_here else f"{node}: {CUDA} refuses with its message (no CUDA here)",
         cuda == f"cuda=loaded {want}" if cuda_here else (cuda.startswith("cuda=refused") and "only on the GPU nodes" in cuda), cuda),
    ]


def example_job(label, script, tag):
    """sbatch an /apps example as syn-alice in proj-alpha from a shared directory, wait for it to
    finish; (job record, output, error)"""
    d = f"{PROJECT_DIR}/{tag}"
    jid = None
    rc, out, err = user("syn-alice", "sbatch", "--parsable", "-A", "proj-alpha", "-D", d, "-o", f"{d}/{label}.out", script)
    if rc == 0 and out.split(";")[0].isdigit():
        jid = out.split(";")[0]
        JOBS.append(jid)
    j = wait_state(jid, FINISHED, 600) if jid else {}
    rc, text, _ = user("syn-alice", "cat", f"{d}/{label}.out") if jid else (1, "", "")
    return j, text if rc == 0 else "", err


def environment():
    expected = sorted(EXPECTED["workers"])
    gpus = sorted(n for n in expected if EXPECTED["workers"][n] == "gpu")
    rc, out, err = admin("sinfo", "-h", "-N", "-p", "debug", "-o", "%N %T")
    seen = dict(l.split()[:2] for l in out.splitlines() if len(l.split()) >= 2) if rc == 0 else {}
    usable = {n for n, st in seen.items() if st in ("idle", "mixed", "allocated", "completing")}
    missing = [n for n in expected if n not in usable]
    result(f"every expected worker ({len(expected)}) is in debug and usable", rc == 0 and not missing,
           err or f"missing or unusable: {missing}; found {seen}")
    where = "the bench's submit node" if BENCH else "login pod"
    rc, out, err = user("syn-alice", "sh", "-c", login_shell("module -t avail 2>&1"))
    shown = {m for m in MODULES if re.search(rf"^{re.escape(m)}(\(default\))?$", out, re.M)}
    result(f"{where}: modules {', '.join(MODULES)} visible", shown == set(MODULES), err or out[-400:])
    # every EXPECTED worker is exercised, discovered or not: a missing one fails its checks
    for node in expected:
        rc, out, err = on(node, "syn-alice", "proj-alpha", login_shell(WORKER_SCRIPT))
        for name, ok, detail in worker_verdicts(node, rc, out, EXPECTED["workers"][node] == "gpu" and not BENCH):
            result(name, ok, (err + " " + detail).strip())

    tag = f".acc-env-{int(time.time())}"
    d = f"{PROJECT_DIR}/{tag}"
    rc, _, err = user("syn-alice", "mkdir", d)
    result(f"a shared build directory ({d})", rc == 0, err)
    try:
        # two ranks on two different GPU nodes (the only CPU node is the Lenovo), one GPU and the
        # job's share each (the submit filter), launched by mpirun over TCP on the pod network
        j, text, err = example_job("mpi", f"{EXAMPLES}/mpi.sh", tag)
        nodes = hostnames(j.get("NodeList", "")) if j else set()
        alloc = tres(j.get("AllocTRES"))
        result("two-node MPI (/apps/examples/mpi.sh): 2 ranks on 2 different GPU nodes, one GPU each, mpirun over TCP",
               j.get("JobState") == "COMPLETED" and j.get("ExitCode") == "0:0" and len(nodes) == 2 and nodes <= set(gpus)
               and alloc.get("gres/gpu") == "2" and "mpi: size=2 hosts=2 messages=1" in text.splitlines()
               and "t88-mpi ok: 2 ranks on 2 nodes over TCP" in text,
               err or f"{j.get('JobState')} exit {j.get('ExitCode')} on {sorted(nodes)} AllocTRES={j.get('AllocTRES')}: {text[-600:]}")
        if BENCH:
            print("SKIP (not run): nvcc build and run on a GPU node (/apps/examples/gpu.sh): the bench has no GPUs and no CUDA")
        else:
            j, text, err = example_job("gpu", f"{EXAMPLES}/gpu.sh", tag)
            want = f"release {CUDA.split('/')[1]}"
            result(f"nvcc builds and runs on a GPU node (/apps/examples/gpu.sh: {want}, one V100)",
                   j.get("JobState") == "COMPLETED" and j.get("ExitCode") == "0:0" and hostnames(j.get("NodeList", "")) <= set(gpus)
                   and tres(j.get("AllocTRES")).get("gres/gpu") == "1" and want in text and any(l.startswith("cuda ok:") and "V100" in l for l in text.splitlines()),
                   err or f"{j.get('JobState')} exit {j.get('ExitCode')} on {j.get('NodeList')}: {text[-600:]}")
    finally:
        rc, out, err = user("syn-alice", "sh", "-c", f"rm -rf -- {shlex.quote(d)}; rc=$?; "
                                                     f"if [ -e {shlex.quote(d)} ]; then echo 'left: {d}'; fi; echo rm_rc=$rc")
        result(f"cleanup: the build directory {d} is gone", removed(rc, out), err or out)


def main():
    global LOGIN_POD
    if not lease_take():
        return 3
    if not BENCH:
        rc, out, err = login("k3s kubectl -n slurm get pods -o name | grep -m1 '^pod/slurm-login-'")
        if rc != 0 or not out:
            print(f"cannot find the login pod: {err or out}")
            return 2
        LOGIN_POD = out.split("/", 1)[1]
    environment() if ENV else storage() if STORAGE else policy()
    return 0


def finish(rc):
    """cancel whatever is left, verify the queue, settle the lease, print the summary; the exit code"""
    left = cancel(JOBS) if JOBS else []
    if JOBS:
        result("cleanup: every job this run submitted has left the queue", not left, "still queued: " + " ".join(left))
    lease_release(clean=not left)
    if not BENCH and OWN_SSH:
        subprocess.run(["ssh", "-o", f"ControlPath={SSH_DIR}/cm", "-O", "exit", f"root@{LOGIN}"], capture_output=True)
    passed, failed = sum(RESULTS), len(RESULTS) - sum(RESULTS)
    print(f"{passed} PASS, {failed} FAIL")
    return rc or (1 if failed else 0)


if __name__ == "__main__":
    args = parse_args()  # refuse malformed invocations before main/finally can use SSH
    BENCH, ADOPT, STORAGE, ENV, GPU_FILL = args.bench, args.lease_id, args.storage, args.env, not args.no_gpu_fill
    code = 2
    try:
        code = main()
    finally:
        code = finish(code)
    sys.exit(code)

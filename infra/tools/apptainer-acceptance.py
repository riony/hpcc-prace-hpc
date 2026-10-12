#!/usr/bin/env python3
"""Live acceptance of roles/apptainer (deferred until after the first scenario, D42), for a later
owned window: docs/runbooks/APPTAINER-WINDOW-PLAN-2026-10-05.md. Written on 5 Oct and NOT run then.

usage: apptainer-acceptance.py --fleet --lease-id ID

  --fleet        explicitly target the fleet, only inside the operator's existing maintenance lease.
  --lease-id ID  required: exactly 16 lowercase hex digits; the matching lease is checked before
                 anything runs, never acquired or released by this runner.

It changes nothing on a host except, for the duration of a check: syn-alice's jobs and their files
in her home (removed, and their absence shown), and on the login node a root-owned setuid copy of
the euid probe in a private directory for the control (removed, and its absence shown).

Checks:
- Login node (root, read-only): the module, the wrapper and the hardened apptainer.conf are there;
  no setuid or setgid file in the tree; /apps is mounted nosuid; the probe image matches its sha256.
- The control: the euid probe (a 142-byte program that exits 0 only as root), setuid root on the
  login node's local disk and run by syn-alice, exits 0. So the probe CAN see a gain where setuid
  works, and its exit 1 in a container means none.
- Login pod: module avail lists apptainer.
- Every expected worker (infra/audit/expected.json; a missing or unusable one fails), in a one-task
  debug job as syn-alice (a GPU node with one GPU), each worker kind as expected (native: PID 1 is
  systemd; pod: it is not, infra/audit/expected.json native_workers):
  * the node: user namespaces enabled, /dev/fuse, no subordinate id range for syn-alice; the module
    loads the tree's command; the job sees the same probe image (sha256);
  * in the container: syn-alice's uid and gid; no effective capability; NoNewPrivs; exactly one uid
    mapped, hers; the setuid-root probe exits 1 (no gain); the image is read-only; her home is
    mounted nosuid,nodev; neither /apps nor /projects is there unless bound; device identities and
    read/write permissions are no broader than the job's (ordinary virtual terminals excepted);
    no library path of the tree; no
    Kubernetes service-account token; a file she writes to her home is hers outside (whether the job
    itself can read a pod's token is printed as INFO: not Apptainer's, an open question);
  * --fakeroot (its home is /root, so the job's directory is bound with -B): uid 0 inside, still
    exactly one uid mapped (hers), and the file written is hers; "refused" counts only when Apptainer
    itself refused (non-zero exit and its FATAL message), never when the script was not found;
  * --net --network none: loopback only;
  * -B /projects/proj-alpha:/prace-project:ro, a bind point the image lacks: listed, read-only;
  * a GPU node: the job itself opens exactly one GPU device (Slurm's device cgroup), and both with
    and without --nv the container opens that same device, no more;
  * afterwards in the job: no Apptainer helper process of hers, and none of her processes' mount
    namespaces holds an image (a container's FUSE mounts live only in its own namespace, so the job's
    own view would always be empty); no new Apptainer temporary directory in /tmp or /var/tmp; her
    files removed.
- An instance left running when its job ends is gone: a second job on the same node finds no
  process of hers from it, and none of her processes holds an image mount (Slurm's cgroup ends it). Its record in her home is
  then removed and its absence shown.
Every job it submits is cancelled and must have left the queue. Prints PASS/FAIL per check; exits 1
on any FAIL, 3 when it refused to start."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import time

import yaml

INFRA = Path(__file__).resolve().parent.parent
D = yaml.safe_load((INFRA / "roles/apptainer/defaults/main.yml").read_text())
EXPECTED = json.loads((INFRA / "audit/expected.json").read_text())
LOGIN = os.environ.get("PRACE_LOGIN", "192.0.2.205")
LEASE = os.environ.get("PRACE_LEASE_PATH", "/run/prace-cluster-lease")
APPS = "/apps"
TREE = f"{APPS}/sw/apptainer/{D['apptainer_version']}"
WRAPPER = f"{TREE}/prace/bin/apptainer"
MODULE = f"apptainer/{D['apptainer_module']}"
MODULEFILE = f"{APPS}/modulefiles/{MODULE}.lua"
IMAGE = f"{APPS}/containers/prace-probe.sif"
STATE = D["apptainer_state_dir"]
USER, ACCOUNT, PROJECT = "syn-alice", "proj-alpha", "/projects/proj-alpha"
# files/prace-apptainer-probe.sh's EUID_PROBE (tools/test-apptainer.py keeps them equal)
EUID_PROBE = "7f454c4602010100000000000000000002003e00010000007800400000000000400000000000000000000000000000000000000040003800010000000000000001000000050000000000000000000000000040000000000000004000000000008e000000000000008e000000000000000010000000000000b86b0000000f0531ff85c0400f95c7b83c0000000f05"
# Devices a user namespace/devpts may supply without adding hardware access.
VIRTUAL_DEVICES = {(1, 3), (1, 5), (1, 7), (1, 8), (1, 9), (5, 0), (5, 2)}
HELPERS = re.compile(r"^(squashfuse|squashfuse_ll|fuse-overlayfs|fuse2fs|starter|Apptainer.*|apptainer)$")
FINISHED = ("COMPLETED", "FAILED", "CANCELLED", "TIMEOUT", "OUT_OF_MEMORY", "NODE_FAIL", "BOOT_FAIL", "DEADLINE")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--fleet', action='store_true', required=True)
    parser.add_argument('--lease-id', required=True)
    words = sys.argv[1:] if argv is None else argv
    for option in ('--fleet', '--lease-id'):
        if sum(word.split('=', 1)[0] == option for word in words) > 1:
            parser.error('duplicate option: ' + option)
    args = parser.parse_args(words)
    if not re.fullmatch('[0-9a-f]{16}', args.lease_id):
        parser.error('--lease-id must be exactly 16 lowercase hex digits')
    return args


RESULTS = []
JOBS = []
SSH_DIR = tempfile.mkdtemp(prefix="prace-apptainer-")
OWN_SSH = not os.environ.get("PRACE_APPTAINER_SSH")     # tests substitute a fake login node
SSH = (shlex.split(os.environ["PRACE_APPTAINER_SSH"]) if not OWN_SSH else
       ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", "-o", "ControlMaster=auto",
        "-o", f"ControlPath={SSH_DIR}/cm", "-o", "ControlPersist=120", f"root@{LOGIN}"])
LOGIN_POD = None


def sh(argv, timeout=300):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 124, "", str(e)


def login(command, timeout=300):
    """a shell command as root on the login node"""
    return sh(SSH + [command], timeout)


def admin(*args):
    """a command in the controller (root)"""
    return login(shlex.join(["k3s", "kubectl", "-n", "slurm", "exec", "slurm-controller-0", "-c", "slurmctld", "--", *args]))


def user(*args, timeout=300):
    """a command as syn-alice where users submit (the login pod)"""
    inner = shlex.join(["runuser", "-u", USER, "--", "sh", "-c", "cd /tmp && exec " + shlex.join(args)])
    return login(shlex.join(["k3s", "kubectl", "-n", "slurm", "exec", LOGIN_POD, "-c", "login", "--", "sh", "-c", inner]), timeout)


def result(name, ok, detail=""):
    RESULTS.append(bool(ok))
    print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" ({detail})" if detail and not ok else ""), flush=True)


def lease_ok(lease_id):
    rc, holder, err = login(f"cat {LEASE}/holder")
    words = holder.split()
    if rc != 0 or sum(w == f"id={lease_id}" for w in words) != 1 or sum(w.startswith("id=") for w in words) != 1:
        print(f"refusing: lease {lease_id} is not the one held ({holder or err or 'no lease'}); nothing run")
        return False
    print(f"using the operator's lease: {holder}")
    return True


def job(jobid):
    rc, out, _ = admin("scontrol", "show", "job", "-o", jobid)
    return dict(kv.split("=", 1) for kv in out.split() if "=" in kv) if rc == 0 else {}


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
            remaining = [i for i in ids if i in set(out.split())]
            if not remaining:
                return []
        time.sleep(pause)
    return remaining


def login_shell(script):
    """a sh -c script that runs `script` in a login shell: /etc/profile.d, so Lmod and the /apps snippet"""
    return "exec bash -lc " + shlex.quote(script)


def on(node, script, tag, timeout=600):
    """(rc, stdout, stderr) of a script run as syn-alice in a one-task debug job on a node; a GPU node
    takes only jobs with a GPU (the submit filter, D41), so there the job asks for one. The job is named
    by the run's tag, so it can be cancelled even if srun's own exit is lost."""
    gpu = ["--gres=gpu:1"] if EXPECTED["workers"].get(node) == "gpu" else []
    rc, out, err = user("srun", "-A", ACCOUNT, "-p", "debug", "-w", node, "-t", "5", "-n", "1", "-J", tag, *gpu,
                        "sh", "-c", login_shell(script), timeout=timeout)
    rc2, ids, _ = admin("squeue", "-h", "-a", "-n", tag, "-o", "%i")
    if rc2 == 0:
        JOBS.extend(i for i in ids.split() if i not in JOBS)
    return rc, out, err


# --- what runs in the jobs -----------------------------------------------------------------------
# Metadata only: never open arbitrary devices (opening e.g. a watchdog can change host state).
# test -r/-w reports DAC access; the allocated GPU's actual cgroup access is tested separately.
DEVICE_SCAN = r"""devices() {
  prefix=$1
  if ! paths=$(find /dev -type c -o -type b); then echo "${prefix}_device_scan=failed"; return; fi
  scan=ok
  while IFS= read -r path; do
    [ -n "$path" ] || continue
    if [ -b "$path" ]; then kind=b; else kind=c; fi
    if ! number=$(stat -c '%t:%T' "$path"); then scan=failed; continue; fi
    access=-
    [ ! -r "$path" ] || access=${access}r
    [ ! -w "$path" ] || access=${access}w
    echo "${prefix}_device=$kind $number $access $path"
  done <<PRACE_DEVICES
$paths
PRACE_DEVICES
  echo "${prefix}_device_scan=$scan"
}
"""
# Inside the container (the probe image's busybox sh). $1: a file to write in the caller's home.
INNER = "#!/bin/sh\n" + DEVICE_SCAN + r"""
echo "c_uid=$(id -u)"
echo "c_gid=$(id -g)"
echo "c_home=$HOME"
awk '/^(CapEff|NoNewPrivs):/ {sub(":", "", $1); print "c_" $1 "=" $2}' /proc/self/status
echo "c_uidmap=$(awk '{printf "%s:%s:%s;", $1, $2, $3}' /proc/self/uid_map)"
if [ -e /prace-euid-probe ]; then /prace-euid-probe; echo "c_euid_probe=$?"; else echo "c_euid_probe=absent"; fi
# into the image's own /bin, the image itself (underlay's root is a separate read-only tmpfs; Session B's bench, 6 Oct)
if (echo x > /bin/prace-image-write-test) 2>/dev/null; then echo "c_image_write=yes"; else echo "c_image_write=no"; fi
awk '{fs = ""; for (i = 7; i <= NF; i++) if ($i == "-") { fs = $(i + 1); break } print "c_mount=" $5 " " $6 " " fs}' /proc/self/mountinfo
devices c
echo "c_ld=${LD_LIBRARY_PATH:-}"
if [ -e /var/run/secrets/kubernetes.io ] || [ -e /run/secrets/kubernetes.io ]; then echo "c_sa=present"; else echo "c_sa=absent"; fi
if echo "inside" > "$1"; then echo "c_home_write=ok"; else echo "c_home_write=failed"; fi
"""
FAKEROOT = r"""#!/bin/sh
echo "f_uid=$(id -u)"
echo "f_uidmap=$(awk '{printf "%s:%s:%s;", $1, $2, $3}' /proc/self/uid_map)"
if echo "fakeroot" > "$1"; then echo "f_home_write=ok"; else echo "f_home_write=failed"; fi
"""
NET = r"""#!/bin/sh
echo "n_ifaces=$(awk 'NR > 2 {sub(":", "", $1); printf "%s ", $1}' /proc/net/dev)"
"""
BIND = r"""#!/bin/sh
if ls /prace-project >/dev/null 2>&1; then echo "b_list=ok"; else echo "b_list=failed"; fi
awk '$5 == "/prace-project" {print "b_mount=" $6}' /proc/self/mountinfo
"""
# the GPU device nodes a process can open: "<opened> <denied by the device cgroup> <other errors>"
GPU = r"""#!/bin/sh
ok=0; denied=0; other=0; ids=""
for d in /dev/nvidia[0-9]*; do
  [ -c "$d" ] || continue
  if err=$( (exec 3<"$d") 2>&1 ); then ok=$((ok + 1)); ids="$ids ${d#/dev/}"
  else case $err in *"Operation not permitted"*) denied=$((denied + 1)) ;; *) other=$((other + 1)) ;; esac; fi
done
echo "$1=$ok $denied $other"
echo "${1}_ids=$ids"
"""
# The job (bash, a login shell). @...@ are filled in by worker_script().
WORKER = r"""set -u
@DEVICE_SCAN@
tag=@TAG@ img=@IMAGE@ gpu=@GPU@
d=$(mktemp -d "$HOME/.acc-apptainer-$tag.XXXXXX") || { echo "workdir=failed"; exit 2; }
trap 'rm -rf -- "$d"' EXIT
@FILES@
echo "host=${SLURMD_NODENAME:-$(hostname -s)}"
if [ "$(cat /proc/1/comm 2>/dev/null)" = systemd ]; then echo "kind=native"; else echo "kind=pod"; fi
echo "uid=$(id -u)"
echo "gid=$(id -g)"
devices job
echo "userns=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo unreadable)"
if [ -c /dev/fuse ]; then echo "fuse=yes"; else echo "fuse=no"; fi
if [ -r /var/run/secrets/kubernetes.io/serviceaccount/token ]; then echo "job_sa=readable"; else echo "job_sa=no"; fi
for f in /etc/subuid /etc/subgid; do
  if [ ! -e "$f" ]; then n=0
  elif ! n=$(awk -F: -v u="$(id -un)" -v i="$(id -u)" '$1 == u || $1 == i {c++} END {print c + 0}' "$f"); then n=unreadable; fi
  echo "${f#/etc/}=$n"
done
helpers() { for p in /proc/[0-9]*; do [ "$(stat -c %u "$p" 2>/dev/null)" = "$(id -u)" ] && cat "$p/comm" 2>/dev/null; done | sort | tr '\n' ' '; }
temps() { ls -d /tmp/rootfs-* /tmp/build-temp-* /var/tmp/rootfs-* /var/tmp/build-temp-* 2>/dev/null | wc -l; }
# her processes whose own mount namespace holds an image (a container's mounts are not in the job's view)
held() { n=0; for p in /proc/[0-9]*; do [ "$(stat -c %u "$p" 2>/dev/null)" = "$(id -u)" ] || continue
  grep -qE 'squashfuse|fuse-overlayfs' "$p/mountinfo" 2>/dev/null && n=$((n + 1)); done; echo "$n"; }
echo "helpers_before=$(helpers)"
before=$(temps)
if module load @MODULE@ >/dev/null 2>&1; then echo "module=loaded"; else echo "module=failed"; fi
echo "apptainer=$(command -v apptainer)"
echo "version=$(apptainer version 2>&1)"
echo "image_sha=$(sha256sum < "$img" | cut -d' ' -f1)"
apptainer exec "$img" /bin/sh "$d/inner.sh" "$d/plain" 2>&1
echo "plain_owner=$(stat -c %u "$d/plain" 2>/dev/null || echo absent)"
# --fakeroot puts her home at /root, so her directory is bound where it is (-B "$d"); Apptainer's own
# refusal is its exit status with its FATAL message, never a script it could not find
fr=$(apptainer exec --fakeroot -B "$d" "$img" /bin/sh "$d/fakeroot.sh" "$d/fakeroot" 2>&1); frc=$?
printf '%s\n' "$fr"
echo "fakeroot_rc=$frc"
echo "fakeroot_fatal=$(printf '%s\n' "$fr" | grep -c 'FATAL:')"
echo "fakeroot_owner=$(stat -c %u "$d/fakeroot" 2>/dev/null || echo absent)"
apptainer exec --net --network none "$img" /bin/sh "$d/net.sh" 2>&1
apptainer exec -B @PROJECT@:/prace-project:ro "$img" /bin/sh "$d/bind.sh" 2>&1
if [ "$gpu" = yes ]; then
  sh "$d/gpu.sh" gpu_job
  apptainer exec "$img" /bin/sh "$d/gpu.sh" gpu_plain 2>&1
  apptainer exec --nv "$img" /bin/sh "$d/gpu.sh" gpu_container 2>&1
fi
sleep 1
echo "helpers_after=$(helpers)"
echo "image_mounts=$(held)"
echo "temps=$before $(temps)"
rm -rf -- "$d"; trap - EXIT
if [ -e "$d" ]; then echo "left=$d"; else echo "left=none"; fi
"""
INSTANCE = r"""set -u
module load @MODULE@ >/dev/null 2>&1 || { echo "module=failed"; exit 2; }
apptainer instance start @IMAGE@ @NAME@ >/dev/null 2>&1; echo "instance_start=$?"
echo "instance_listed=$(apptainer instance list 2>/dev/null | grep -c '^@NAME@ ')"
"""
AFTER = r"""set -u
for p in /proc/[0-9]*; do [ "$(stat -c %u "$p" 2>/dev/null)" = "$(id -u)" ] && echo "proc=$(cat "$p/comm" 2>/dev/null) $(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)"; done
n=0; for p in /proc/[0-9]*; do [ "$(stat -c %u "$p" 2>/dev/null)" = "$(id -u)" ] || continue
  grep -qE 'squashfuse|fuse-overlayfs' "$p/mountinfo" 2>/dev/null && n=$((n + 1)); done
echo "image_mounts=$n"
"""


def worker_script(tag, gpu):
    files = "\n".join(f"cat > \"$d/{name}\" <<'PRACE_EOF'\n{text}PRACE_EOF" for name, text in
                      (("inner.sh", INNER), ("fakeroot.sh", FAKEROOT), ("net.sh", NET), ("bind.sh", BIND), ("gpu.sh", GPU)))
    return (WORKER.replace("@DEVICE_SCAN@", DEVICE_SCAN).replace("@FILES@", files).replace("@TAG@", shlex.quote(tag)).replace("@IMAGE@", shlex.quote(IMAGE))
            .replace("@GPU@", "yes" if gpu else "no").replace("@MODULE@", MODULE).replace("@PROJECT@", PROJECT))


def fields(out):
    """{key: value} of key=value lines (the first of each key) and the c_mount lines as a list"""
    f, mounts = {}, []
    for line in out.splitlines():
        k, sep, v = line.partition("=")
        if not sep:
            continue
        if k == "c_mount":
            mounts.append(v)
        elif k in ("job_device", "c_device"):
            f.setdefault(k, []).append(v)
        else:
            f.setdefault(k, v)
    return f, mounts


def one_map(m, outside):
    """a uid_map dump ("in:out:count;") of exactly one entry, of one id, the caller's"""
    entries = [e for e in m.split(";") if e]
    return len(entries) == 1 and entries[0].split(":")[1:] == [str(outside), "1"]


def gpu_counts(v):
    parts = (v or "").split()
    return tuple(int(p) for p in parts) if len(parts) == 3 and all(p.isdigit() for p in parts) else None


def device_access(f):
    """Compare device identities and DAC access without opening arbitrary host devices."""
    def report(prefix):
        if f.get(prefix + "_device_scan") != "ok" or not f.get(prefix + "_device"):
            raise ValueError(prefix + " device scan missing or failed")
        devices = {}
        for line in f[prefix + "_device"]:
            match = re.fullmatch(r"([bc]) ([0-9a-fA-F]+):([0-9a-fA-F]+) (-r?w?) (/dev/[^\n]+)", line)
            if not match:
                raise ValueError("malformed " + prefix + " device: " + line)
            kind, major, minor, access, _ = match.groups()
            identity = kind, int(major, 16), int(minor, 16)
            devices.setdefault(identity, set()).update(access.removeprefix("-"))
        return devices
    try:
        job, container = report("job"), report("c")
    except ValueError as error:
        return False, str(error)
    for (kind, major, minor), access in container.items():
        # A new devpts instance has different PTY numbers; these are virtual terminals, not disks/GPUs.
        if kind == "c" and ((major, minor) in VIRTUAL_DEVICES or 136 <= major <= 143):
            continue
        identity = kind, major, minor
        if identity not in job or not access <= job[identity]:
            return False, f"container device {identity}, access {sorted(access)}, job {job.get(identity)}"
    return True, "device identities and DAC access within the job's view; GPU cgroup checked separately"


def gpu_matches(f, prefix, job):
    counts = gpu_counts(f.get(prefix))
    ids = f.get(prefix + "_ids", "").split()
    job_ids = f.get("gpu_job_ids", "").split()
    return (job is not None and counts == job and len(ids) == counts[0] and len(job_ids) == job[0]
            and len(set(ids)) == len(ids) and set(ids) == set(job_ids))


def worker_verdicts(node, rc, out, want_kind, gpu, image_sha):
    """the checks of one worker job: [(name, ok, detail)]"""
    f, mounts = fields(out)
    uid, gid = f.get("uid", "?"), f.get("gid", "?")
    mount = {}
    for m in mounts:
        mp, _, rest = m.partition(" ")
        opts, _, fs = rest.partition(" ")
        mount[mp] = (set(opts.split(",")), fs)
    home = f.get("c_home", "")
    devices_ok, devices_detail = device_access(f)
    caps = f.get("c_CapEff", "")
    # Apptainer's own refusal only: non-zero, its FATAL message, nothing ran or was written (B1, 5 Oct: a script
    # missing under --fakeroot's /root home once passed here). Any FATAL counts, not only a policy refusal: safe,
    # since nothing ran, and the line says "refused" (Session B's re-review n4, 6 Oct; on its bench a real refusal
    # read "FATAL: --fakeroot requires either being in /etc/subuid, unprivileged user namespaces, or the fakeroot
    # command", rc 255)
    fakeroot_refused = (f.get("fakeroot_rc", "0") not in ("0", "") and f.get("fakeroot_fatal", "0") not in ("0", "")
                        and "f_uid" not in f and "f_uidmap" not in f and "f_home_write" not in f and f.get("fakeroot_owner") == "absent")
    v = [
        (f"{node}: the job ran ({want_kind} worker)", rc == 0 and f.get("kind") == want_kind and f.get("host", "").split(".")[0] == node.split(".")[0],
         f"rc {rc}, kind {f.get('kind')}, host {f.get('host')}: {out[-400:]}"),
        (f"{node}: unprivileged user namespaces enabled", f.get("userns", "").isdigit() and int(f["userns"]) > 0, f.get("userns")),
        (f"{node}: /dev/fuse", f.get("fuse") == "yes", f.get("fuse")),
        (f"{node}: no subordinate id range for {USER}", f.get("subuid") == "0" and f.get("subgid") == "0", f"subuid {f.get('subuid')}, subgid {f.get('subgid')}"),
        (f"{node}: {MODULE} loads the tree's command, {D['apptainer_version']}",
         f.get("module") == "loaded" and f.get("apptainer") == WRAPPER and f.get("version") == D["apptainer_version"],
         f"{f.get('module')} {f.get('apptainer')} {f.get('version')}"),
        (f"{node}: the probe image is the recorded one", bool(image_sha) and f.get("image_sha") == image_sha, f.get("image_sha")),
        (f"{node}: container: {USER}'s uid and gid", f.get("c_uid") == uid and f.get("c_gid") == gid and uid != "?",
         f"{f.get('c_uid')}:{f.get('c_gid')} vs {uid}:{gid}"),
        (f"{node}: container: no effective capability, NoNewPrivs", bool(re.fullmatch("0+", caps)) and f.get("c_NoNewPrivs") == "1",
         f"CapEff {caps}, NoNewPrivs {f.get('c_NoNewPrivs')}"),
        (f"{node}: container: exactly one uid mapped, {USER}'s", uid != "?" and one_map(f.get("c_uidmap", ""), uid), f.get("c_uidmap")),
        (f"{node}: container: the setuid-root probe gains nothing (exit 1)", f.get("c_euid_probe") == "1", f.get("c_euid_probe")),
        (f"{node}: container: the image is read-only", f.get("c_image_write") == "no", f.get("c_image_write")),
        (f"{node}: container: her home is mounted nosuid,nodev", bool(home) and home in mount and {"nosuid", "nodev"} <= mount[home][0],
         f"{home}: {mount.get(home)}"),
        # judged only on a mount list that was read (it holds at least the image's root)
        (f"{node}: container: no /apps or /projects unless bound", "/" in mount and not [mp for mp in mount if re.match(r"^/(apps|projects)(/|$)", mp)],
         [mp for mp in mount if re.match(r"^/(apps|projects)(/|$)", mp)] or f"{len(mount)} mounts read"),
        (f"{node}: container: device identities and permissions no broader than the job", devices_ok, devices_detail),
        (f"{node}: container: no library path of the tree", "c_ld" in f and "/apps/sw/apptainer" not in f["c_ld"], f.get("c_ld")),
        (f"{node}: container: no Kubernetes service-account token", f.get("c_sa") == "absent", f.get("c_sa")),
        (f"{node}: container: a file written to her home is hers", f.get("c_home_write") == "ok" and f.get("plain_owner") == uid,
         f"{f.get('c_home_write')}, owner {f.get('plain_owner')}"),
        # --fakeroot: either refused outright (nothing ran, nothing written), or root inside with still only
        # her own id mapped and her file hers; never a range (the threat model's fakeroot policy)
        (f"{node}: --fakeroot: " + ("refused, nothing written" if fakeroot_refused else "root inside, still one uid mapped (hers), her file"),
         fakeroot_refused or (f.get("f_uid") == "0" and uid != "?" and one_map(f.get("f_uidmap", ""), uid)
                              and f.get("f_home_write") == "ok" and f.get("fakeroot_owner") == uid),
         f"uid {f.get('f_uid')}, map {f.get('f_uidmap')}, owner {f.get('fakeroot_owner')}"),
        (f"{node}: --net --network none: loopback only", f.get("n_ifaces", "").split() == ["lo"], f.get("n_ifaces")),
        (f"{node}: -B {PROJECT}:/prace-project:ro (a bind point the image lacks): listed, read-only",
         f.get("b_list") == "ok" and "ro" in f.get("b_mount", "").split(","), f"{f.get('b_list')} {f.get('b_mount')}"),
    ]
    if gpu:
        job_ = gpu_counts(f.get("gpu_job"))
        v += [
            (f"{node}: the job opens exactly one GPU device (Slurm's device cgroup)", job_ is not None and job_[0] == 1 and job_[2] == 0 and job_[1] >= 1
             and len(f.get("gpu_job_ids", "").split()) == 1,
             f"opened, denied, other: {f.get('gpu_job')}"),
            (f"{node}: container without --nv: the job's GPU, no more", gpu_matches(f, "gpu_plain", job_),
             f"container {f.get('gpu_plain')} {f.get('gpu_plain_ids')}, job {f.get('gpu_job')} {f.get('gpu_job_ids')}"),
            (f"{node}: container with --nv: the job's GPU, no more", gpu_matches(f, "gpu_container", job_),
             f"container {f.get('gpu_container')} {f.get('gpu_container_ids')}, job {f.get('gpu_job')} {f.get('gpu_job_ids')}"),
        ]
    before = {n for n in f.get("helpers_before", "").split()}
    left = [n for n in f.get("helpers_after", "").split() if HELPERS.match(n) and n not in before]
    temps = f.get("temps", "").split()
    v += [
        (f"{node}: afterwards: no helper process of hers, none of her processes holds an image mount",
         "helpers_after" in f and not left and f.get("image_mounts") == "0", f"processes {left}, holding an image {f.get('image_mounts')}"),
        (f"{node}: afterwards: no new Apptainer temporary directory", len(temps) == 2 and temps[0] == temps[1], f.get("temps")),
        (f"{node}: afterwards: her files removed (absence shown)", f.get("left") == "none", f.get("left")),
    ]
    return v


def instance_verdicts(node, start_out, after_rc, after_out, name):
    f, _ = fields(start_out)
    procs = [l for l in after_out.splitlines() if l.startswith("proc=")]
    stray = [p for p in procs if name in p or re.search(r"squashfuse|fuse-overlayfs|Apptainer", p)]
    a, _ = fields(after_out)
    return [
        (f"{node}: an instance starts in a job", f.get("instance_start") == "0" and f.get("instance_listed") == "1", start_out[-300:]),
        (f"{node}: after its job, nothing of the instance is left (Slurm's cgroup)", after_rc == 0 and not stray and a.get("image_mounts") == "0",
         f"rc {after_rc}, {stray}, processes holding an image {a.get('image_mounts')}"),
    ]


# --- the run -------------------------------------------------------------------------------------
def login_node():
    """the login node's tree, configuration and image; the recorded image sha256 (or "")"""
    q = shlex.quote
    rc, out, err = login(
        f"test -x {q(WRAPPER)} && echo wrapper=ok; test -f {q(MODULEFILE)} && echo module=ok; "
        f"grep -qx 'allow setuid = no' {q(TREE)}/usr/etc/apptainer/apptainer.conf && echo conf=ok; "
        f"echo suid=$(find {q(TREE)} -xdev -perm /6000 | wc -l); echo apps=$(findmnt -no OPTIONS --mountpoint {APPS}); "
        f"cd {APPS}/containers && sha256sum --check --strict --status prace-probe.sif.sha256 && echo image=ok "
        f"&& echo sha=$(cut -d' ' -f1 prace-probe.sif.sha256)")
    f, _ = fields(out)
    result(f"login node: {MODULEFILE}, {WRAPPER} and apptainer.conf with allow setuid = no",
           f.get("wrapper") == "ok" and f.get("module") == "ok" and f.get("conf") == "ok", err or out)
    result(f"login node: no setuid or setgid file in {TREE}", f.get("suid") == "0", f.get("suid"))
    result(f"login node: {APPS} is mounted nosuid", "nosuid" in f.get("apps", "").split(","), f.get("apps"))
    result(f"login node: {IMAGE} matches its sha256", f.get("image") == "ok", err or out)
    return f.get("sha", "") if f.get("image") == "ok" else ""


def control():
    """the euid probe, setuid root on the login node's own disk, run by syn-alice: exit 0 (a gain)"""
    script = (f"set -u; d=$(mktemp -d {shlex.quote(STATE)}/prace-euid-control.XXXXXX) || exit 2; chmod 0711 \"$d\"; "
              f"printf '%b' \"$(sed 's/../\\\\x&/g' <<< {EUID_PROBE})\" > \"$d/probe\"; chmod 4755 \"$d/probe\"; "
              f"runuser -u {USER} -- \"$d/probe\"; rc=$?; rm -rf -- \"$d\"; "
              f"if [ -e \"$d\" ]; then echo \"left=$d\"; else echo left=none; fi; echo control=$rc")
    rc, out, err = login("bash -c " + shlex.quote(script))
    f, _ = fields(out)
    result(f"control: the euid probe, setuid root on the login node's disk, shows a gain for {USER} (exit 0)",
           f.get("control") == "0", err or out)
    result("control: its directory removed (absence shown)", f.get("left") == "none", out)


def main(lease_id):
    global LOGIN_POD
    if not lease_ok(lease_id):
        return 3
    rc, out, err = login("k3s kubectl -n slurm get pods -o name | grep -m1 '^pod/slurm-login-'")
    if rc != 0 or not out:
        print(f"cannot find the login pod: {err or out}")
        return 2
    LOGIN_POD = out.split("/", 1)[1]
    image_sha = login_node()
    control()
    rc, out, err = user("bash", "-lc", "module -t avail 2>&1")
    result(f"login pod: {MODULE} listed", bool(re.search(rf"^{re.escape(MODULE)}(\(default\))?$", out, re.M)), err or out[-300:])

    expected = sorted(EXPECTED["workers"])
    native = set(EXPECTED.get("native_workers") or {})
    rc, out, err = admin("sinfo", "-h", "-N", "-p", "debug", "-o", "%N %T")
    seen = dict(l.split()[:2] for l in out.splitlines() if len(l.split()) >= 2) if rc == 0 else {}
    missing = [n for n in expected if seen.get(n) not in ("idle", "mixed", "allocated", "completing")]
    result(f"every expected worker ({len(expected)}) is in debug and usable", rc == 0 and not missing, err or f"missing or unusable: {missing}")
    run = f"acc-apptainer-{int(time.time())}"
    for node in expected:              # every EXPECTED worker is exercised, discovered or not
        gpu = EXPECTED["workers"][node] == "gpu"
        rc, out, err = on(node, worker_script(run, gpu), run)
        for name, ok, detail in worker_verdicts(node, rc, out, "native" if node in native else "pod", gpu, image_sha):
            result(name, ok, (err[-300:] + " " + str(detail)).strip())
        # not Apptainer's: a pod's own token, readable by any job outside a container (an open question)
        print(f"INFO: {node}: a service-account token readable by the job itself: {fields(out)[0].get('job_sa', 'not reported')}")
        name = f"{run}-{node.split('.')[0]}"
        script = INSTANCE.replace("@MODULE@", MODULE).replace("@IMAGE@", shlex.quote(IMAGE)).replace("@NAME@", name)
        _, start, _ = on(node, script, run)
        time.sleep(5)
        arc, after, aerr = on(node, AFTER, run)
        for check, ok, detail in instance_verdicts(node, start, arc, after, name):
            result(check, ok, (aerr[-300:] + " " + str(detail)).strip())
        # the instance's record in her home (Apptainer keeps it per host and user); removed, absence shown
        rc, out, err = user("sh", "-c", f"rm -rf -- \"$HOME\"/.apptainer/instances/*/*/{USER}/{name} \"$HOME\"/.apptainer/instances/logs/*/{USER}/{name}.*; "
                                        f"if ls -d \"$HOME\"/.apptainer/instances/*/*/{USER}/{name} \"$HOME\"/.apptainer/instances/logs/*/{USER}/{name}.* "
                                        ">/dev/null 2>&1; then echo left; else echo left=none; fi")
        result(f"{node}: the instance's record removed (absence shown)", "left=none" in out.split(), err or out)
    return 0


def finish(rc):
    """cancel whatever is left, verify the queue, print the summary; the exit code"""
    if JOBS:
        left = cancel(JOBS)
        result("cleanup: every job this run submitted has left the queue", not left, "still queued: " + " ".join(left))
    if OWN_SSH:
        subprocess.run(["ssh", "-o", f"ControlPath={SSH_DIR}/cm", "-O", "exit", f"root@{LOGIN}"], capture_output=True)
    passed, failed = sum(RESULTS), len(RESULTS) - sum(RESULTS)
    print(f"{passed} PASS, {failed} FAIL")
    return rc or (1 if failed else 0)


if __name__ == "__main__":
    args = parse_args()  # refuse malformed invocations before anything contacts the login node
    code = 2
    try:
        code = main(args.lease_id)
    finally:
        code = finish(code)
    sys.exit(code)

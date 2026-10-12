#!/usr/bin/python3
# Managed by Ansible (roles/fleet_observer). READ-ONLY fleet observation for the off-node monitor
# and the scheduled drift audit (tools/fleet-audit.py evaluates it; this script only reports).
#
# Reached only through forced-command SSH keys of the prace-observer account, via one sudo rule for
# this exact path without arguments. It never changes anything: no restarts, no repair, no
# lease handling. It prints ONE JSON document and always exits 0; failed probes are reported
# inside it ("errors"), so the evaluator decides.
#
# Reported: the cluster lease, the Kubernetes API, every node (role, Ready, slurmd pod Ready,
# Slurm state), pod-network reachability from this node to every other node (the path whose loss
# on 28 Sep left Kubernetes Ready while every Slurm worker went DOWN), slurmctld/accounting
# reachability, partitions, selected Slurm settings, and sha256 of the tracked configuration
# files (hashes only, never contents). A native worker (T89: slurmd on its host, no pod) is read
# from its own private read-only endpoint (prace-native-observe, roles/fleet_observer native.yml):
# its slurmd service, its host's share mounts and its configuration hashes.
import glob
import hashlib
import json
import ipaddress
import os
import subprocess
import sys
import time

K3S = "/usr/local/bin/k3s"
KC = [K3S, "kubectl"]
CTL = KC + ["-n", "slurm", "exec", "slurm-controller-0", "-c", "slurmctld", "--"]
LEASE = "/run/prace-cluster-lease"
TRACKED = [   # configuration whose unreviewed change is drift (globs; hashes only)
    "/etc/rancher/k3s/config.yaml",
    "/etc/rancher/k3s/registries.yaml",
    "/var/lib/rancher/k3s/server/manifests/prace-slinky-*.yaml",
    "/etc/exports.d/*.exports",
    "/etc/my.cnf.d/prace-slinky.cnf",
    "/etc/nftables/prace-*.nft",
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d/*.conf",
    "/etc/sudoers",
    "/etc/sudoers.d/*",
    "/etc/firewalld/zones/*.xml",
    "/etc/systemd/system/prace-*",
    "/usr/local/sbin/prace-*",
    "/root/.ssh/authorized_keys",
    "/var/lib/prace-local-home/admin/.ssh/authorized_keys",        # local homes (D39 storage step)
    "/var/lib/prace-local-home/prace-observer/.ssh/authorized_keys",
    "/etc/fstab",
    "/etc/projects",
    "/etc/projid",
    "/etc/prace-storage/*",
    "/etc/systemd/system/nfs-server.service.d/*.conf",
    "/etc/prace-audit/canary",
    "/etc/prace-audit/disabled-links.json",
    "/etc/prace-audit/native-workers.json",
    "/etc/prace-network/*",
    "/etc/NetworkManager/conf.d/90-prace-disabled-links.conf",
]
SHARE_PATHS = ("/home", "/projects", "/apps")   # T87: the pods' NFS shares (their mount options only)
NATIVE_WORKERS = "/etc/prace-audit/native-workers.json"   # T89: {name: {address}}; absent or {} = none
NATIVE_PORT, NATIVE_PATH = 918, "/v1/native-worker"
# One bounded GET of a fixed private endpoint. urllib's timeout limits an idle socket, not an entire
# slow response, so a separate single-purpose child gives each probe a hard bound; ambient HTTP
# proxies are not honoured and redirects (to another network) are not followed.
BOUNDED_GET = '''import sys,urllib.request
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args):return None
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect)
with opener.open(sys.argv[1],timeout=4) as response:raw=response.read(65537)
if len(raw)>65536:raise SystemExit(1)
sys.stdout.buffer.write(raw)
'''


def bounded_get(url):
    """the endpoint's JSON document; ValueError/OSError/TimeoutExpired on any failure"""
    result = subprocess.run([sys.executable, '-c', BOUNDED_GET, url], capture_output=True, timeout=6)
    raw = result.stdout
    if result.returncode or len(raw) > 65536:
        raise ValueError('oversized observation')
    return json.loads(raw)
SLURM_SETTINGS = ("ReturnToService", "SlurmdTimeout", "SlurmctldTimeout", "SlurmctldParameters", "GresTypes",
                  "AccountingStorageEnforce", "EnforcePartLimits", "JobSubmitPlugins")   # academic policy (D39)


def run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 999, ""


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def disabled_link_observations():
    """Fixed private endpoints; observations are not hostile-root containment proof."""
    path = '/etc/prace-audit/disabled-links.json'
    if not os.path.exists(path):
        return {}  # the evaluator refuses if D43 is expected but not observed
    try:
        endpoints = json.load(open(path))
        if not isinstance(endpoints, dict):
            raise ValueError('bad endpoint configuration')
        out = {}
        for host, cfg in endpoints.items():
            try:
                # Do not honor ambient HTTP proxies or follow redirects to another network.
                address = str(ipaddress.IPv4Address(cfg['address']))
                value = bounded_get('http://' + address + ':9187/v1/disabled-links')
                if not isinstance(value, dict) or value.get('schema') != 1 or value.get('host') != host:
                    raise ValueError('wrong observation identity')
                out[host] = value
            except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
                out[host] = {'errors': ['link_endpoint_unreachable_or_invalid']}
        return out
    except (OSError, ValueError, TypeError):
        return {'configuration': {'errors': ['disabled_link_endpoints_invalid']}}


def native_observations(get=None):
    """T89: {name: report} from each native worker's private read-only endpoint, its identity
    checked; a failed or foreign answer is an error row for that worker (the evaluator decides)"""
    get = get or bounded_get
    try:
        with open(NATIVE_WORKERS) as f:
            hosts = json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError):
        return {"configuration": {"errors": ["native_worker_list_invalid"]}}
    if not isinstance(hosts, dict):
        return {"configuration": {"errors": ["native_worker_list_invalid"]}}
    out = {}
    for host, cfg in sorted(hosts.items()):
        try:
            address = str(ipaddress.IPv4Address(cfg["address"]))
            value = get(f"http://{address}:{NATIVE_PORT}{NATIVE_PATH}")
            if not isinstance(value, dict) or value.get("schema") != 1 or value.get("host") != host:
                raise ValueError("wrong observation identity")
            out[host] = value
        except (OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired):
            out[host] = {"errors": ["native_endpoint_unreachable_or_invalid"]}
    return out


def share_mounts(run=None):
    """T87 (3 Oct): the per-mount options of the share mounts as each running slurmd and login
    container sees them (/proc/self/mountinfo inside the container; read-only). {pod: {kind, node,
    mounts: {path: options}}}, or an error per pod; None when a pod query fails."""
    run = run or globals()["run"]
    out = {}
    for kind in ("slurmd", "login"):
        rc, txt = run(KC + ["-n", "slurm", "get", "pods", "-l", f"app.kubernetes.io/name={kind}", "-o", "json"])
        if rc != 0:
            return None
        try:
            pods = json.loads(txt).get("items", [])
        except ValueError:
            return None
        for p in pods:
            if p["metadata"].get("deletionTimestamp") or p.get("status", {}).get("phase") != "Running":
                continue
            name = p["metadata"]["name"]
            row = {"kind": kind, "node": p["spec"].get("nodeName")}
            rc, mi = run(KC + ["-n", "slurm", "exec", name, "-c", kind, "--", "cat", "/proc/self/mountinfo"])
            if rc != 0:
                row["error"] = "exec failed"
            else:
                row["mounts"] = {f[4]: f[5] for f in (l.split() for l in mi.splitlines())
                                 if len(f) > 5 and f[4] in SHARE_PATHS}
            out[name] = row
    return out


def main():
    t0 = time.time()
    me = os.uname().nodename.split(".")[0]
    out = {"schema": 1, "time": int(t0), "host": me, "errors": [], "nodes": {}}
    out['disabled_links'] = disabled_link_observations()

    if os.path.isdir(LEASE):
        try:
            holder = open(os.path.join(LEASE, "holder")).read().strip()[:300]
        except OSError:
            holder = None
        out["lease"] = {"held": True, "holder": holder}
    else:
        out["lease"] = {"held": False}

    rc, txt = run(KC + ["get", "nodes", "-o", "json"])
    out["k8s_api"] = rc == 0
    nodes = []
    if rc == 0:
        try:
            nodes = json.loads(txt)["items"]
        except (ValueError, KeyError):
            out["errors"].append("k8s node list unreadable")
    else:
        out["errors"].append("k8s node query failed")
    for n in nodes:
        name = n["metadata"]["name"]
        ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in n["status"].get("conditions", []))
        out["nodes"][name] = {"role": n["metadata"].get("labels", {}).get("prace.fleet/role"),
                              "k8s_ready": ready, "pod_cidr": n["spec"].get("podCIDR"),
                              "slurmd_pod_ready": None, "slurmd_pods": None, "slurm_state": None,
                              "slurm_addr": None, "pod_path": None}

    rc, txt = run(KC + ["-n", "slurm", "get", "pods", "-l", "app.kubernetes.io/name=slurmd", "-o", "json"])
    if rc == 0:
        for info in out["nodes"].values():
            info["slurmd_pods"] = 0
        for p in json.loads(txt).get("items", []):
            node = p["spec"].get("nodeName")
            if node in out["nodes"]:
                out["nodes"][node]["slurmd_pods"] = (out["nodes"][node]["slurmd_pods"] or 0) + 1
                out["nodes"][node]["slurmd_pod_ready"] = any(
                    c.get("type") == "Ready" and c.get("status") == "True" for c in p["status"].get("conditions", []))
    else:
        out["errors"].append("slurmd pod query failed")

    out["share_mounts"] = share_mounts()
    if out["share_mounts"] is None:
        out["errors"].append("share-mount pod query failed")

    rc, txt = run(CTL + ["scontrol", "ping"])
    out["controller_up"] = rc == 0 and "is UP" in txt
    rc, _ = run(CTL + ["sacctmgr", "-n", "list", "cluster"])
    out["accounting"] = rc == 0
    rc, txt = run(CTL + ["sinfo", "-h", "-N", "-o", "%N|%T|%G|%o"])
    if rc == 0:
        out["slurm_nodes"] = {}
        for line in txt.splitlines():
            if line.count("|") >= 3:
                name, state, gres, addr = line.split("|", 3)
                out["slurm_nodes"][name] = state
                if name in out["nodes"]:
                    out["nodes"][name]["slurm_state"] = state
                    out["nodes"][name]["slurm_gres"] = gres
                    out["nodes"][name]["slurm_addr"] = addr
    else:
        out["errors"].append("slurm node query failed")
    rc, txt = run(CTL + ["sinfo", "-h", "-o", "%R|%a"])
    out["partitions"] = dict(l.split("|", 1) for l in txt.splitlines() if "|" in l) if rc == 0 else None
    rc, txt = run(CTL + ["scontrol", "show", "config"])
    out["slurm_config"] = {}
    for line in txt.splitlines():
        k, _, v = line.partition("=")
        if k.strip() in SLURM_SETTINGS:
            out["slurm_config"][k.strip()] = v.strip()

    # Data path: from a pod network namespace on this node to every other node's flannel address.
    rc, txt = run(["ip", "netns", "list"], timeout=5)
    ns = next((l.split()[0] for l in txt.splitlines() if l.startswith("cni-")), None)
    for name, info in out["nodes"].items():
        if name == me or not info["pod_cidr"]:
            continue
        if ns is None:
            info["pod_path"] = None
            continue
        rc, _ = run(["ip", "netns", "exec", ns, "ping", "-c", "2", "-W", "2", "-q", info["pod_cidr"].split("/")[0]], timeout=10)
        info["pod_path"] = rc == 0
    if ns is None:
        out["errors"].append("no pod network namespace on the login node")

    out["config"] = {}
    for pattern in TRACKED:
        paths = sorted(glob.glob(pattern))
        if not paths:
            out["config"][pattern] = "missing"
        for p in paths:
            try:
                out["config"][p] = sha256(p)
            except OSError:
                out["config"][p] = "unreadable"
    # T89: each native worker's host, from its own endpoint; its configuration joins the drift audit
    out["native_hosts"] = native_observations()
    for host, report in sorted(out["native_hosts"].items()):
        if isinstance(report, dict) and isinstance(report.get("config"), dict):
            for path, digest in report["config"].items():
                out["config"][f"{host}:{path}"] = digest
    out["duration_s"] = round(time.time() - t0, 1)
    print(json.dumps(out, sort_keys=True))


if __name__ == "__main__":
    main()

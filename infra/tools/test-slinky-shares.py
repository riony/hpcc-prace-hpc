#!/usr/bin/env python3
"""Offline tests for roles/slinky/files/prace-share-exports.sh (the export gate before any pod
manifest changes), prace-share-probe.sh (a probe pod per node mounts the shares before any
login or slurmd pod uses them) and prace-share-check.sh (the containers' own check before sshd or
slurmd starts, 3 Oct), with a stub exportfs, a fake kubectl and synthetic mountinfo files. Includes the review's
reproductions (MR !55, note 212): a failing exportfs, exports only to localhost, and localhost
entries correct while the fleet subnet has the opposite modes. No host is contacted."""
import json
import os
import sys
import re
from pathlib import Path
import subprocess
import tempfile
import unittest

FILES = Path(__file__).resolve().parent.parent / "roles/slinky/files"
NET = "10.90.10.0/25"
OPTS = "sync,wdelay,hide,no_subtree_check,sec=sys,{},secure,root_squash,no_all_squash"
GOOD = f"/home  {NET}({OPTS.format('rw')})\n/projects  {NET}({OPTS.format('rw')})\n/apps  {NET}({OPTS.format('ro')})\n"
SHARES = ["/home:rw", "/projects:rw", "/apps:ro"]
CHECK = (FILES / "prace-share-check.sh").read_text()


class Exports(unittest.TestCase):
    def run_gate(self, listing, rc=0):
        with tempfile.TemporaryDirectory() as d:
            stub = Path(d) / "exportfs"
            (Path(d) / "out").write_text(listing)
            stub.write_text(f"#!/bin/sh\ncat {d}/out\nexit {rc}\n")
            stub.chmod(0o755)
            r = subprocess.run(["bash", str(FILES / "prace-share-exports.sh"), NET, *SHARES],
                               env=dict(os.environ, PRACE_EXPORTFS=str(stub)), capture_output=True, text=True, timeout=30)
            return r.returncode, r.stdout

    def test_fleet_exports_with_their_modes_pass(self):
        rc, out = self.run_gate(GOOD)
        self.assertEqual(rc, 0, out)
        # several clients on one line is the same as one per line, and still only the fleet counts
        rc, out = self.run_gate(f"/home {NET}({OPTS.format('rw')})\n/projects {NET}({OPTS.format('rw')})\n/apps {NET}({OPTS.format('ro')})\n")
        self.assertEqual(rc, 0, out)

    def test_a_failed_query_is_never_an_empty_list(self):
        rc, out = self.run_gate(GOOD, rc=1)
        self.assertEqual(rc, 2, out)
        self.assertIn("exportfs -s failed", out)

    def test_wrong_client_mode_or_missing_share_stops(self):
        cases = {
            "only localhost (review)": f"/projects  127.0.0.1({OPTS.format('rw')})\n/apps  127.0.0.1({OPTS.format('ro')})\n",
            "localhost right, fleet opposite (review)":
                f"/projects  127.0.0.1({OPTS.format('rw')})\n/projects  {NET}({OPTS.format('ro')})\n"
                f"/apps  127.0.0.1({OPTS.format('ro')})\n/apps  {NET}({OPTS.format('rw')})\n",
            "overlapping selectors": f"/projects  10.90.10.0/24({OPTS.format('ro')})\n/projects  {NET}({OPTS.format('rw')})\n"
                                     f"/apps  {NET}({OPTS.format('ro')})\n",
            "several clients on one line": f"/projects {NET}({OPTS.format('rw')}) 10.90.10.99({OPTS.format('rw')})\n"
                                           f"/apps  {NET}({OPTS.format('ro')})\n",
            "apps exported read-write": f"/projects  {NET}({OPTS.format('rw')})\n/apps  {NET}({OPTS.format('rw')})\n",
            "projects not exported (before W1)": f"/home  {NET}({OPTS.format('rw')})\n/apps  {NET}({OPTS.format('ro')})\n",
            "nothing exported": "",
        }
        for label, listing in cases.items():
            with self.subTest(label):
                rc, out = self.run_gate(listing)
                self.assertEqual(rc, 1, out)


FAKE_KUBECTL = r'''#!/usr/bin/env python3
import json, os, re, sys, time
CONTROL_LOG = "prace-share-check: /prace-share-control lacks nosuid (ro,relatime); not starting"
sc = json.load(open(os.environ["SCENARIO"]))
st_path = os.environ["STATE"]
st = json.load(open(st_path)) if os.path.exists(st_path) else {"created": [], "deleted": []}
a = sys.argv[1:]
open(os.environ["CALLS"], "a").write(" ".join(a) + "\n")
def save(): json.dump(st, open(st_path, "w"))
s = " ".join(a)
if a[:2] == ["get", "nodes"]:
    if sc.get("nodes_fail"): sys.exit(1)
    print("\n".join(sc["nodes"])); sys.exit(0)
if "get pvc" in s:
    print(sc.get("pvc", {}).get(a[a.index("pvc") + 1], "Bound"), end=""); sys.exit(0)
if a[:3] == ["apply", "-f", "-"]:
    body = sys.stdin.read()
    name = re.search(r"name: (prace-share-probe-[^,}\s]+)", body).group(1)
    node = re.search(r"nodeName: (\S+)", body).group(1)
    assert "tolerations" in body and "persistentVolumeClaim" in body, body
    st["created"].append(name); st.setdefault("bodies", {})[node] = body; save(); sys.exit(0)
if "delete pod" in s:
    pod = a[a.index("pod") + 1]
    st["deleted"].append(pod); save()
    if pod.replace("prace-share-probe-", "") in sc.get("stuck", []) and "--wait=true" in a:
        # the pod stays Terminating (its node is NotReady): kubectl waits until its --timeout, if any
        if not any(x.startswith("--timeout=") for x in a): time.sleep(60)
        print(f"error: timed out waiting for the condition on pods/{pod}", file=sys.stderr); sys.exit(1)
    sys.exit(0)
if "get pod" in s:
    node = a[a.index("pod") + 1].replace("prace-share-probe-", "")
    if "exitCode" in s:
        print(sc.get("exit", {}).get(node, 78 if node == "control" else 0), end=""); sys.exit(0)
    print(sc.get("phase", {}).get(node, "Failed" if node == "control" else "Succeeded"), end=""); sys.exit(0)
if "get events" in s:
    print("MountVolume.SetUp failed: mount.nfs: access denied by server", end=""); sys.exit(0)
if "logs" in a:
    node = a[a.index("logs") + 1].replace("prace-share-probe-", "")
    print(sc.get("logs", {}).get(node, CONTROL_LOG if node == "control" else sc["good_log"])); sys.exit(0)
sys.exit(3)
'''
GOOD_LOG = ("10.90.10.1:/home /home nfs4 rw,nosuid,nodev,vers=4.2,hard 0 0\n/home listed\n"
            "10.90.10.1:/projects /projects nfs4 rw,nosuid,nodev,relatime,vers=4.2,hard,proto=tcp 0 0\n/projects listed\n"
            "10.90.10.1:/apps /apps nfs4 ro,nosuid,nodev,relatime,vers=4.2,hard,proto=tcp 0 0\n/apps listed")
NODES = ["lab-dl380", "lab-lenovo", "lab-g003", "lab-g004", "lab-g005"]


class Probe(unittest.TestCase):
    def run_probe(self, timeout=120, over_env={}, **over):
        sc = dict({"nodes": NODES, "good_log": GOOD_LOG}, **over)
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "kubectl"; fake.write_text(FAKE_KUBECTL); fake.chmod(0o755)
            (Path(d) / "sc.json").write_text(json.dumps(sc))
            env = dict(os.environ, PRACE_KUBECTL=str(fake), SCENARIO=str(Path(d) / "sc.json"), STATE=str(Path(d) / "st.json"),
                       CALLS=str(Path(d) / "calls"), PRACE_PROBE_TRIES="1", PRACE_SHARE_CHECK=CHECK)
            for k in [k for k in over_env if over_env[k] is None]:
                env.pop(k, None)
            env.update({k: v for k, v in over_env.items() if v is not None})
            r = subprocess.run(["bash", str(FILES / "prace-share-probe.sh"), "10.90.10.1", "docker.io/library/alpine@sha256:x",
                                "/home:rw:prace-home", "/projects:rw:prace-projects", "/apps:ro:prace-apps"], env=env, capture_output=True, text=True, timeout=timeout)
            st = json.loads((Path(d) / "st.json").read_text()) if (Path(d) / "st.json").exists() else {"created": [], "deleted": []}
            return r, st

    def test_every_node_mounts_both_shares(self):
        r, st = self.run_probe()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(sorted(st["created"]), sorted([f"prace-share-probe-{n}" for n in NODES] + ["prace-share-probe-control"]))
        self.assertTrue(set(st["created"]) <= set(st["deleted"]), "every probe pod is deleted")
        body = st["bodies"]["lab-g003"]
        self.assertIn("claimName: prace-apps, readOnly: true", body)
        self.assertIn("mountPath: /apps, readOnly: true", body)
        self.assertIn("claimName: prace-projects, readOnly: false", body)

    def test_a_bad_mount_on_one_node_fails_and_still_cleans_up(self):
        bad = GOOD_LOG.replace("rw,nosuid,nodev", "rw,nodev")
        cases = {
            "mount failed (pod never succeeded)": {"phase": {"lab-g004": "Pending"}},
            "home soft": {"logs": {"lab-g004": GOOD_LOG.replace("nodev,vers=4.2,hard", "nodev,vers=4.2,soft")}},
            "no nosuid": {"logs": {"lab-g004": bad}},
            "apps writable": {"logs": {"lab-g004": GOOD_LOG.replace("nfs4 ro,", "nfs4 rw,")}},
            "another server": {"logs": {"lab-g004": GOOD_LOG.replace("10.90.10.1:/apps", "10.90.10.9:/apps")}},
            "not NFS": {"logs": {"lab-g004": GOOD_LOG.replace("/apps /apps nfs4", "/apps /apps tmpfs")}},
            "listing failed": {"logs": {"lab-g004": GOOD_LOG.replace("/apps listed", "")}},
            "not mounted": {"logs": {"lab-g004": "/projects unmounted\n/apps unmounted"}},
        }
        for label, over in cases.items():
            with self.subTest(label):
                r, st = self.run_probe(**over)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("lab-g004", r.stdout)
                self.assertTrue(set(st["created"]) <= set(st["deleted"]), "every probe pod is deleted, also on failure")

    def test_a_node_that_cannot_remove_its_earlier_probe_pod_fails_without_hanging(self):
        # the review's case (MR !55 ultrareview): a probe pod left Terminating on a NotReady node;
        # an unbounded kubectl delete --wait=true hung the whole converge
        r, st = self.run_probe(stuck=["lab-g004"], timeout=30)
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("lab-g004: earlier probe pod not removed", r.stdout)
        self.assertNotIn("prace-share-probe-lab-g004", st["created"])
        self.assertEqual(len(st["created"]), len(NODES) - 1 + 1, "the other nodes are still probed, and the control")
        self.assertTrue(set(st["created"]) <= set(st["deleted"]), "every probe pod is deleted")

    def test_each_probe_pod_runs_the_containers_share_check_first(self):
        """3 Oct: the probe exercises the same path as the login and slurmd pods (the NRI plugin and
        their share check), not only a look at /proc/mounts"""
        r, st = self.run_probe()
        self.assertEqual(r.returncode, 0, r.stdout)
        cmd = json.loads(re.search(r"command: (\[.*\])", st["bodies"]["lab-g003"]).group(1))
        self.assertEqual(cmd[:3], ["sh", "-c", CHECK])
        self.assertEqual(cmd[3:8], ["prace-share-check", "/home:rw", "/projects:rw", "/apps:ro", "--"])
        self.assertEqual(cmd[8:10], ["sh", "-c"])

    def test_a_node_whose_share_check_refuses_fails_with_its_reason(self):
        said = "prace-share-check: /home lacks nosuid (rw,relatime); not starting"
        r, st = self.run_probe(phase={"lab-g004": "Failed"}, logs={"lab-g004": said})
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn(f"lab-g004: probe Failed ({said})", r.stdout)
        self.assertTrue(set(st["created"]) <= set(st["deleted"]))

    def test_the_control_must_be_refused_by_the_check(self):
        """a check that cannot fail proves nothing: the first share again, read-only, at a path the
        plugin does not guard, must stop the container with exit 78 for the missing nosuid"""
        r, st = self.run_probe()
        self.assertIn("control: the share check refuses an unguarded mount", r.stdout)
        cases = {"the check passed": {"phase": {"control": "Succeeded"}, "exit": {"control": 0}},
                 "another refusal": {"exit": {"control": 64}, "logs": {"control": "prace-share-check: bad share"}},
                 "refused, but not for nosuid": {"logs": {"control": "prace-share-check: /prace-share-control lacks nodev"}},
                 "never ran": {"phase": {"control": "Pending"}}}
        for label, over in cases.items():
            with self.subTest(label):
                r, st = self.run_probe(**over)
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("control: the share check did not refuse", r.stdout)
                self.assertIn("prace-share-probe-control", st["deleted"])

    def test_the_control_mounts_read_only_at_an_unguarded_path(self):
        r, st = self.run_probe()
        # the control is the last pod created on the first node
        self.assertEqual(st["created"][-1], "prace-share-probe-control")
        body = st["bodies"]["lab-dl380"]
        self.assertIn("mountPath: /prace-share-control, readOnly: true", body)
        self.assertIn("claimName: prace-home, readOnly: true", body)
        cmd = json.loads(re.search(r"command: (\[.*\])", body).group(1))
        self.assertEqual(cmd[3:], ["prace-share-check", "/prace-share-control:ro", "--", "true"])

    def test_the_share_check_is_required(self):
        r, st = self.run_probe(over_env={"PRACE_SHARE_CHECK": None})
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertEqual(st["created"], [])

    def test_queries_and_claims_must_answer(self):
        for label, over in {"node query fails": {"nodes_fail": True}, "no nodes": {"nodes": []},
                            "claim not bound": {"pvc": {"prace-apps": "Pending"}}}.items():
            with self.subTest(label):
                r, st = self.run_probe(**over)
                self.assertEqual(r.returncode, 2, r.stdout)
                self.assertEqual(st["created"], [], "no probe before the claims are bound")



# mountinfo lines as the 3 Oct diagnosis read them (fields 5 and 6: mount point, per-mount options)
MI = {"/home": "1201 1190 0:77 / /home rw,nosuid,nodev,relatime - nfs4 10.90.10.1:/home rw,vers=4.2,hard",
      "/projects": "1202 1190 0:78 / /projects rw,nosuid,nodev,relatime - nfs4 10.90.10.1:/projects rw,vers=4.2,hard",
      "/apps": "1203 1190 0:79 / /apps ro,nosuid,nodev,relatime - nfs4 10.90.10.1:/apps ro,vers=4.2,hard"}


class ShareCheck(unittest.TestCase):
    """files/prace-share-check.sh, the first command of the login and slurmd containers"""

    def check(self, lines, *argv, cmd=("echo", "SERVICE STARTED")):
        with tempfile.TemporaryDirectory() as d:
            mi = Path(d) / "mountinfo"; mi.write_text("\n".join(lines) + "\n")
            return subprocess.run(["sh", "-c", CHECK, "prace-share-check", *argv, "--", *cmd],
                                  env=dict(os.environ, PRACE_MOUNTINFO=str(mi)), capture_output=True, text=True, timeout=30)

    def test_guarded_shares_start_the_service_with_its_own_arguments(self):
        r = self.check(MI.values(), *SHARES, cmd=("sh", "-c", 'echo "started with $*"', "slurmd", "-Z", "--conf", "x y"))
        self.assertEqual((r.returncode, r.stdout.strip(), r.stderr), (0, "started with -Z --conf x y", ""))

    def test_a_missing_option_or_mount_refuses_with_78_and_never_starts(self):
        cases = {"/home without nosuid (the 3 Oct state)": ("/home", "rw,relatime", "lacks nosuid"),
                 "/projects without nodev": ("/projects", "rw,nosuid,relatime", "lacks nodev"),
                 "/apps writable": ("/apps", "rw,nosuid,nodev,relatime", "lacks ro"),
                 "/home read-only": ("/home", "ro,nosuid,nodev,relatime", "lacks rw")}
        for label, (path, opts, said) in cases.items():
            with self.subTest(label):
                lines = [l if l.split()[4] != path else l.replace(l.split()[5], opts, 1) for l in MI.values()]
                r = self.check(lines, *SHARES)
                self.assertEqual(r.returncode, 78, r.stderr)
                self.assertIn(f"prace-share-check: {path} {said}", r.stderr)
                self.assertNotIn("SERVICE STARTED", r.stdout)
        r = self.check([MI["/home"], MI["/apps"]], *SHARES)
        self.assertEqual(r.returncode, 78)
        self.assertIn("/projects lacks nosuid (not mounted)", r.stderr)

    def test_the_mount_on_top_counts_and_lookalike_paths_do_not(self):
        under = MI["/home"]
        over = "1300 1190 0:90 / /home rw,relatime - tmpfs tmpfs rw"
        r = self.check([under, over, MI["/projects"], MI["/apps"]], *SHARES)
        self.assertEqual(r.returncode, 78, "a later unguarded mount on /home hides the guarded one")
        lookalike = MI["/home"].replace(" /home ", " /homes ")
        r = self.check([lookalike, MI["/projects"], MI["/apps"]], *SHARES)
        self.assertEqual(r.returncode, 78)
        self.assertIn("/home lacks nosuid (not mounted)", r.stderr)

    def test_bad_usage_never_starts_the_service(self):
        for label, argv in {"no separator": (*SHARES, "echo", "x"), "no command": (*SHARES, "--"),
                            "a relative path": ("home:rw", "--", "echo", "x"), "an unknown mode": ("/home:rx", "--", "echo", "x")}.items():
            with self.subTest(label):
                with tempfile.TemporaryDirectory() as d:
                    mi = Path(d) / "mountinfo"; mi.write_text("\n".join(MI.values()) + "\n")
                    r = subprocess.run(["sh", "-c", CHECK, "prace-share-check", *argv], env=dict(os.environ, PRACE_MOUNTINFO=str(mi)),
                                       capture_output=True, text=True, timeout=30)
                self.assertEqual(r.returncode, 64, (label, r.stderr))
                self.assertNotIn("x", r.stdout)

    def test_an_unreadable_mountinfo_refuses(self):
        r = subprocess.run(["sh", "-c", CHECK, "prace-share-check", *SHARES, "--", "echo", "SERVICE STARTED"],
                           env=dict(os.environ, PRACE_MOUNTINFO="/nonexistent/mountinfo"), capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 78)
        self.assertNotIn("SERVICE STARTED", r.stdout)


FAKE_PODS = r'''#!/usr/bin/env python3
import json, os, sys
states = json.load(open(os.environ["PODS"]))
n_path = os.environ["PODS"] + ".n"
n = int(open(n_path).read()) if os.path.exists(n_path) else 0
open(n_path, "w").write(str(n + 1))
state = states[min(n, len(states) - 1)]
if state == "fail": sys.exit(1)
print(json.dumps({"items": state}))
'''


def pod_of(name, container, command=None, terminating=False):
    meta = {"name": name}
    if terminating:
        meta["deletionTimestamp"] = "2026-10-03T12:00:00Z"
    c = {"name": container}
    if command is not None:
        c["command"] = command
    return {"metadata": meta, "spec": {"nodeName": "cpu-node", "containers": [{"name": "logfile"}, c]}}


WRAPPED = ["/bin/sh", "-c", CHECK.rstrip("\n"), "prace-share-check", "/home:rw", "--", "/usr/local/bin/entrypoint.sh"]


class SharePods(unittest.TestCase):
    """files/prace-share-pods.py: the operator must carry the share check into every pod"""

    def run_it(self, *states, timeout="0", login_required=False, workers=None):
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "kubectl"; fake.write_text(FAKE_PODS); fake.chmod(0o755)
            (Path(d) / "pods.json").write_text(json.dumps(list(states)))
            env = dict(os.environ, PRACE_KUBECTL=str(fake), PODS=str(Path(d) / "pods.json"), PRACE_SHARE_POD_SPEC=json.dumps({"command": WRAPPED, "workers": workers or ["cpu-node"], "login_required": login_required}))
            return subprocess.run([sys.executable, str(FILES / "prace-share-pods.py"), "--timeout", timeout],
                                  env=env, capture_output=True, text=True, timeout=60)

    def test_every_pod_through_the_check_passes(self):
        r = self.run_it([pod_of("slurm-worker-cpu-a", "slurmd", WRAPPED), pod_of("slurm-login-prace-b", "login", WRAPPED),
                         {"metadata": {"name": "slurm-controller-0"}, "spec": {"containers": [{"name": "slurmctld"}]}}], login_required=True)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("slurm-worker-cpu-a slurmd: starts through the share check", r.stdout)

    def test_a_pod_without_the_check_fails_and_is_named(self):
        for label, cmd in {"no command (the operator dropped it)": None, "another command": ["/bin/sh", "-c", "x", "other"]}.items():
            with self.subTest(label):
                r = self.run_it([pod_of("slurm-worker-cpu-a", "slurmd", WRAPPED), pod_of("slurm-worker-gpu-c", "slurmd", cmd)])
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("pods without the share check after 0 s: slurm-worker-gpu-c slurmd", r.stdout)

    def test_exact_body_arguments_entrypoint_and_coverage(self):
        for cmd in (["/bin/sh", "-c", "exec sleep 3600", "prace-share-check"],
                    WRAPPED[:4] + ['--', WRAPPED[-1]], WRAPPED[:-1] + ['/bin/true']):
            self.assertEqual(self.run_it([pod_of('worker', 'slurmd', cmd)]).returncode, 1)
        good = [pod_of('worker', 'slurmd', WRAPPED)]
        self.assertEqual(self.run_it(good, login_required=True).returncode, 1)
        self.assertEqual(self.run_it(good, workers=['cpu-node', 'gpu-node']).returncode, 1)
        self.assertEqual(self.run_it(good).returncode, 0)

    def test_a_rollout_is_waited_for_and_terminating_pods_do_not_count(self):
        old = pod_of("slurm-worker-cpu-old", "slurmd", None)
        r = self.run_it([old], [pod_of("slurm-worker-cpu-old", "slurmd", None, terminating=True), pod_of("slurm-worker-cpu-new", "slurmd", WRAPPED)],
                        timeout="30")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertNotIn("old", r.stdout)

    def test_no_pod_or_no_answer_never_passes(self):
        r = self.run_it([])
        self.assertEqual(r.returncode, 1)
        self.assertIn("missing workers", r.stdout)
        r = self.run_it("fail")
        self.assertEqual(r.returncode, 2)
        r = self.run_it("fail", [pod_of("slurm-worker-cpu-a", "slurmd", WRAPPED)], timeout="30")
        self.assertEqual(r.returncode, 0, "a failed query is retried")

if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Offline tests for roles/slinky/files/prace-slinky-worker-check.sh and prace-slinky-reregister.sh
against a fake kubectl (scenario JSON; every call recorded). No host is contacted."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

FILES = Path(__file__).resolve().parent.parent / "roles/slinky/files"
FAKE = r'''#!/usr/bin/env python3
import json, os, sys
sc = json.load(open(os.environ["SCENARIO"]))
a = sys.argv[1:]
open(os.environ["CALLS"], "a").write(" ".join(a) + "\n")
if sc.get("fail_all"):
    sys.exit(7)
s = " ".join(a)
def node_of():
    for x in a:
        if x.startswith("spec.nodeName="):
            return x.split("=", 1)[1]
if a[:2] == ["get", "node"]:
    n = sc["nodes"].get(a[2]); 
    if n is None: sys.exit(1)
    print(n["ready"], end="")
elif "get pods" in s:
    for p in sc["pods"].get(node_of(), []):
        print(p if "-o name" in s or a[-1] == "name" else p)
elif "exec" in a and "sinfo" in a:
    if "-n" in a[a.index("sinfo"):]:
        # one line per partition the node is in, as sinfo -N prints it ("%T %o": with NodeAddr)
        n = a[a.index("-n", a.index("sinfo")) + 1]; node = sc["slurm"].get(n, {})
        states = node.get("states") or ([node["state"]] * node.get("partitions", 1) if node else [])
        if "%T %o" in a:
            states = [f"{st} {node.get('addr', '10.42.4.15')}" for st in states]
        print("\n".join(states))
    else:
        print("\n".join(f"{k} {v['state']}" for k, v in sc["slurm"].items()))
elif "exec" in a and "squeue" in a:
    print(sc["slurm"][a[a.index("-w") + 1]].get("jobs", ""))
elif "exec" in a and a[-3:-1] == ["show", "node"]:
    if sc.get("occupy_diagnostics_path"):
        # the next few seconds' diagnostics paths become directories: writing them fails for any
        # user, root included (permissions do not stop root, so they are no test here)
        import time
        for dt in range(0, 8):
            t = time.strftime("%Y%m%dT%H%M%S", time.localtime(time.time() + dt))
            os.makedirs(os.path.join(os.environ["PRACE_LOG_DIR"], f"reregister-{t}-{a[-1]}.txt"), exist_ok=True)
    print(sc["slurm"][a[-1]]["show"])
elif "exec" in a and "delete" in a:
    pass
elif a[:3] == ["-n", "slurm", "delete"]:
    pass
else:
    sys.exit(3)
'''


class Scripts(unittest.TestCase):
    def run_script(self, name, scenario, *args, setup=None):
        with tempfile.TemporaryDirectory() as d:
            if setup:
                setup(Path(d) / "log")
            fake = Path(d) / "kubectl"; fake.write_text(FAKE); fake.chmod(0o755)
            (Path(d) / "sc.json").write_text(json.dumps(scenario))
            (Path(d) / "native").write_text(scenario.get("native", ""))
            env = dict(os.environ, PRACE_KUBECTL=str(fake), SCENARIO=str(Path(d) / "sc.json"),
                       CALLS=str(Path(d) / "calls"), PRACE_LOG_DIR=str(Path(d) / "log"),
                       PRACE_NATIVE_FILE=str(Path(d) / "native"))
            r = subprocess.run(["bash", str(FILES / name), *args], env=env, capture_output=True, text=True, timeout=30)
            calls = (Path(d) / "calls").read_text() if (Path(d) / "calls").exists() else ""
            log = Path(d) / "log"
            if log.is_dir():
                log.chmod(0o700)
            logs = sorted(log.glob("*")) if log.is_dir() else []
            return r, calls, [l.read_text() for l in logs if l.is_file()]

    GOOD = {"nodes": {"g3": {"ready": "True"}, "g4": {"ready": "True"}},
            "pods": {"g3": ["slurm-worker-gpu-a true true"], "g4": ["slurm-worker-gpu-b true true"]},
            "slurm": {"g3": {"state": "idle"}, "g4": {"state": "mixed"}}}

    def test_check_passes_only_when_every_named_worker_is_usable(self):
        r, _, _ = self.run_script("prace-slinky-worker-check.sh", self.GOOD, "g3", "g4")
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_check_counts_a_node_in_several_partitions_once(self):
        # cpu + debug: sinfo -N prints the node once per partition (review of the debug partition, 29 Sep)
        sc = dict(self.GOOD, slurm={"g3": {"state": "idle", "partitions": 2}, "g4": {"state": "mixed", "partitions": 3}})
        r, _, _ = self.run_script("prace-slinky-worker-check.sh", sc, "g3", "g4")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("g3: ok (idle,", r.stdout)

    def test_a_native_worker_has_no_pod_and_its_own_address(self):
        """T89: listed in the native file, the node passes with no slurmd pod and NodeAddr on the
        private network; a competing pod, a pod-network address or an unusable state fails."""
        def native(**over):
            sc = {"nodes": {"lenovo": {"ready": "True"}, "g3": {"ready": "True"}},
                  "pods": {"lenovo": [], "g3": ["slurm-worker-gpu-a true true"]},
                  "slurm": {"lenovo": {"state": "idle", "partitions": 2, "addr": "10.90.10.21"}, "g3": {"state": "idle"}},
                  "native": "lenovo 10.90.10.21\n"}
            sc.update(over)
            return sc
        r, _, _ = self.run_script("prace-slinky-worker-check.sh", native(), "lenovo", "g3")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("lenovo: ok (idle, native slurmd at 10.90.10.21)", r.stdout)
        cases = {
            "a slurmd pod competes": native(pods={"lenovo": ["slurm-worker-cpu-x true true"], "g3": ["p true true"]}),
            "registered from the pod network (not the native daemon)": native(slurm={"lenovo": {"state": "idle", "addr": "10.42.4.0"}, "g3": {"state": "idle"}}),
            "not responding": native(slurm={"lenovo": {"state": "idle*", "addr": "10.90.10.21"}, "g3": {"state": "idle"}}),
            "absent from slurm": native(slurm={"g3": {"state": "idle"}}),
            "node not ready": native(nodes={"lenovo": {"ready": "False"}, "g3": {"ready": "True"}}),
        }
        for label, sc in cases.items():
            with self.subTest(label):
                r, _, _ = self.run_script("prace-slinky-worker-check.sh", sc, "lenovo", "g3")
                self.assertNotEqual(r.returncode, 0, r.stdout)
        # the same node without the native file is a pod worker again: no pod = not usable
        sc = native(); sc.pop("native")
        r, _, _ = self.run_script("prace-slinky-worker-check.sh", sc, "lenovo")
        self.assertNotEqual(r.returncode, 0, r.stdout)

    def test_check_fails_closed(self):
        cases = {
            "discovery fails (review reproduction)": dict(self.GOOD, fail_all=True),
            "node not ready": dict(self.GOOD, nodes={"g3": {"ready": "False"}, "g4": {"ready": "True"}}),
            "node unknown": dict(self.GOOD, nodes={"g4": {"ready": "True"}}),
            "no slurmd pod": dict(self.GOOD, pods={"g3": [], "g4": ["p true true"]}),
            "two slurmd pods": dict(self.GOOD, pods={"g3": ["p true true", "q true true"], "g4": ["r true true"]}),
            "container not ready": dict(self.GOOD, pods={"g3": ["p true false"], "g4": ["r true true"]}),
            "not responding": dict(self.GOOD, slurm={"g3": {"state": "idle*"}, "g4": {"state": "idle"}}),
            "invalid": dict(self.GOOD, slurm={"g3": {"state": "inval"}, "g4": {"state": "idle"}}),
            "absent from slurm": dict(self.GOOD, slurm={"g4": {"state": "idle"}}),
            "states disagree across partitions": dict(self.GOOD, slurm={"g3": {"states": ["idle", "drained"]}, "g4": {"state": "idle"}}),
            "several partitions, one not usable": dict(self.GOOD, slurm={"g3": {"states": ["down", "down"]}, "g4": {"state": "idle"}}),
        }
        for label, sc in cases.items():
            with self.subTest(label):
                r, _, _ = self.run_script("prace-slinky-worker-check.sh", sc, "g3", "g4")
                self.assertNotEqual(r.returncode, 0, r.stdout)
        r, _, _ = self.run_script("prace-slinky-worker-check.sh", self.GOOD)
        self.assertNotEqual(r.returncode, 0, "an empty expected list must not pass")

    def inval(self, reason="CoreSpec differ", features="gpu", pod=True, jobs=""):
        show = f"NodeName=g3 Arch=x86_64\n   AvailableFeatures={features}\n   State=DOWN+DYNAMIC_NORM+INVALID_REG\n   Reason={reason} [slurm@2026-09-27T04:23:52]"
        return {"nodes": {}, "pods": {"g3": ["pod/slurm-worker-gpu-a"] if pod else []},
                "slurm": {"g3": {"state": "inval", "show": show, "jobs": jobs}, "g4": {"state": "idle"}}}

    def test_reregister_repairs_only_the_stale_budget_case(self):
        r, calls, logs = self.run_script("prace-slinky-reregister.sh", self.inval())
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("re-registered g3 (CoreSpec differ)", r.stdout)
        self.assertIn("scontrol delete nodename=g3", calls)
        self.assertIn("delete pod/slurm-worker-gpu-a", calls)
        self.assertEqual(len(logs), 1)
        self.assertIn("INVALID_REG", logs[0])            # diagnostics saved before any change

    def test_reregister_leaves_everything_else_for_diagnosis(self):
        for label, sc in {"other reason": self.inval(reason="Node unexpectedly rebooted"),
                          "not a NodeSet node": self.inval(features="foreign"),
                          "no slurmd pod": self.inval(pod=False),
                          "jobs present": self.inval(jobs="42")}.items():
            with self.subTest(label):
                r, calls, logs = self.run_script("prace-slinky-reregister.sh", sc)
                self.assertEqual(r.returncode, 3, r.stdout)
                self.assertNotIn("delete", calls.replace("--", ""), calls)
                self.assertEqual(len(logs), 1)
        r, calls, _ = self.run_script("prace-slinky-reregister.sh", dict(self.inval(), fail_all=True))
        self.assertEqual(r.returncode, 2)

    def test_no_diagnostics_no_change(self):
        """Review F4: a failed diagnostic write must stop the repair before any deletion."""
        def as_file(log):
            log.write_text("not a directory")
        for label, kwargs, sc in (("log path is a file (mkdir fails, also for root)", {"setup": as_file}, self.inval()),
                                  ("diagnostics file cannot be written (path occupied)", {}, dict(self.inval(), occupy_diagnostics_path=True))):
            with self.subTest(label):
                r, calls, logs = self.run_script("prace-slinky-reregister.sh", sc, **kwargs)
                self.assertEqual(r.returncode, 2, r.stdout)
                self.assertIn("no change", r.stdout)
                self.assertNotIn("scontrol delete", calls)
                self.assertNotIn(" delete pod", calls)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Offline tests for tools/slurm-window.py (the Slurm window's lease and admission fence, Session B
re-review R9), with a fake login node: PRACE_WINDOW_SSH runs a local script that plays the lease
directory, the controller's partitions and queue and the LoginSets; `ssh` on PATH is a stub that
fails the test if anything tries to reach a real host (30 Sep incident), and PRACE_LOGIN is an
invalid name. Includes the queue case that locks Session A's capture fence (a pending job must not
stop the fence from closing or opening) and a reconfiguration that reopens a partition."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

TOOL = Path(os.environ.get("PRACE_WINDOW_TOOL", Path(__file__).resolve().parent / "slurm-window.py"))
FAKE_LOGIN = r'''#!/usr/bin/env python3
import fcntl, json, os, re, shlex, signal, sys
st_path = os.environ["STATE"]; st = json.load(open(st_path))
cmd = sys.argv[-1]; a = shlex.split(cmd)
open(os.environ["CALLS"], "a").write(cmd + "\n")
def done(out="", rc=0, err=""):
    json.dump(st, open(st_path, "w"))
    if out: print(out)
    if err: print(err, file=sys.stderr)
    sys.exit(rc)
if a[0] == "flock" or (a[:2] == ["python3", "-c"] and "# prace-window-lock" in a[2]):
    f = open(st_path + ".lock", "w")
    try: fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError: sys.exit(1)
    print("locked", flush=True)
    for line in sys.stdin:
        req = json.loads(line); st = json.load(open(st_path))
        if st.get("refence_fail"):
            print(json.dumps({"ok": False, "detail": "injected refence failure"}), flush=True); continue
        if st.get("overlay"):
            ov = st["overlay"]; intent = req["refence"]
            ov["metadata"]["annotations"].update({"prace.fleet/window-id": intent["lease_id"], "prace.fleet/window-phase": "closed"})
            values = json.loads(ov["spec"]["valuesContent"])
            for p in values.get("partitions", {}).values(): p["configMap"]["State"] = "INACTIVE"
            for p in values.get("nodesets", {}).values(): p["partition"]["configMap"]["State"] = "INACTIVE"
            for v in values["loginsets"].values(): v["replicas"] = 0
            ov["spec"]["valuesContent"] = json.dumps(values)
        st["refence_phase"] = st["marker"]["phase"]
        json.dump(st, open(st_path, "w")); print(json.dumps({"ok": True}), flush=True)
    sys.exit(0)
def effect():
    json.dump(st, open(st_path, "w"))
    if st.get("kill_on") and st["kill_on"] in cmd:
        st.pop("kill_on"); json.dump(st, open(st_path, "w")); os.kill(os.getppid(), signal.SIGKILL); sys.exit(0)
    if st.get("lost_ack") and st["lost_ack"] in cmd:
        st.pop("lost_ack"); done(rc=1, err="injected lost mutation acknowledgement")
    done()
for f in st["fail"]:
    if f in cmd: done(err="injected failure: " + f, rc=1)
for f, n in list(st.get("transient", {}).items()):
    if f in cmd and n > 0:
        st["transient"][f] = n - 1
        done(err=st.get("transient_err", 'error: unable to upgrade connection: container not found ("slurmctld")'), rc=1)
if a[:2] == ["cat", "/run/prace-cluster-lease/holder"]:
    done(st["lease"]) if st["lease"] is not None else done(err="No such file or directory", rc=1)
if a[:2] == ["cat", "/run/prace-cluster-lease/fence-intent.json"]:
    done(json.dumps(st["marker"])) if st.get("marker") else done(rc=1)
if a[:2] == ["python3", "-c"] and "# prace-window-marker" in a[2]:
    st["marker"] = json.loads(a[-1]); done()
if a[:2] == ["python3", "-c"] and "# prace-window-lease-release" in a[2]:
    if st.get("unknown_lease_file"): done(rc=1, err="unexpected lease contents")
    if st.get("lease") and "id="+a[-2]+" " in st["lease"]:
        st["lease"] = None; st["marker"] = None; done()
    done(rc=1)
if a[:2] == ["sh", "-c"] and "prace-slinky-maintenance.yaml" in a[2] and a[2].startswith("test -e "):
    done(rc=0 if st.get("overlay") else 1)
if "helmchartconfig" in a and "--ignore-not-found" in a and not st.get("overlay"):
    done("")
if (a[:2] == ["cat", "/var/lib/rancher/k3s/server/manifests/prace-slinky-maintenance.yaml"] or "helmchartconfig" in a):
    done(json.dumps(st["overlay"])) if st.get("overlay") else done(rc=1, err="overlay absent")
if a[:2] == ["sh", "-c"] and a[2].startswith("test -e "):
    done(rc=0 if st["lease"] is not None else 1)
if a[:2] == ["test", "-e"]:
    done(rc=0 if st["lease"] is not None else 1)
if a[:2] == ["sh", "-c"] and "mkdir" in a[2]:
    if st["lease"] is not None: done(err="mkdir: cannot create directory: File exists", rc=1)
    st["lease"] = re.search(r'echo "([^$"]*)', a[2]).group(1) + "2026-10-01T10:00:00+08:00"; done(st["lease"])
if a[:2] == ["sh", "-c"] and "rm -rf" in a[2]:
    lid = re.search(r"id=([0-9a-f]+) ", a[2]).group(1)
    if st["lease"] is not None and "id=%s " % lid in st["lease"] + " ": st["lease"] = None; done()
    done(rc=1)
if "--" in a:
    c = a[a.index("--") + 1:]
    if c[:3] == ["scontrol", "show", "partition"]:
        done("\n".join("PartitionName=%s AllowGroups=ALL Default=NO State=%s TotalCPUs=48" % (n, s) for n, s in st["parts"].items()))
    if c[:2] == ["scontrol", "update"]:
        n, s = c[2].split("=", 1)[1], c[3].split("=", 1)[1]
        st["parts"][n] = s; effect()
    if c[0] == "squeue": done("\n".join(st["jobs"]))
if "loginsets" in a:
    done(json.dumps({"items": [{"metadata": {"name": n, "uid": v["uid"]}, "spec": {"replicas": v["replicas"]}} for n, v in st["sets"].items()]}))
def fields(v):
    # helm's apply entry, the operator's status entry, then every other replica owner (kubectl patch)
    owners = v.get("owners", [["helm", "Apply"]])
    mf = [{"manager": "helm", "operation": "Apply", "fieldsV1": {"f:spec": dict({"f:controllerRef": {}}, **({"f:replicas": {}} if ["helm", "Apply"] in owners else {}))}},
          {"manager": "manager", "operation": "Update", "fieldsV1": {"f:status": {}}}]
    return mf + [{"manager": m, "operation": o, "fieldsV1": {"f:spec": {"f:replicas": {}}}} for m, o in owners if [m, o] != ["helm", "Apply"]]
if a[4:6] == ["get", "loginset"]:
    v = st["sets"][a[6]]
    done(json.dumps({"metadata": {"name": a[6], "uid": v["uid"], "resourceVersion": str(st.get("rv", 1)), "managedFields": fields(v)}, "spec": {"replicas": v["replicas"]}}))
if a[4:6] == ["patch", "loginset"]:
    p = json.loads(a[a.index("-p") + 1]); v = st["sets"][a[6]]
    if p[0]["value"] != v["uid"]: done(err="the test operation failed", rc=1)
    if any(o["path"].startswith("/metadata/managedFields") for o in p):
        if st.get("mf_patch_noop"): effect()
        mf = fields(v)
        for o in p[1:]:
            path = o["path"].split("/")[1:]
            if path == ["metadata", "resourceVersion"]:
                if o["value"] != str(st.get("rv", 1)): done(err="the test operation failed", rc=1)
            elif o["op"] == "test":
                if mf[int(path[2])][path[3]] != o["value"]: done(err="the test operation failed", rc=1)
            elif o["op"] == "remove":
                mf.pop(int(path[2]))
            else:
                done(err="fake: unsupported managedFields patch", rc=3)
        if not mf: done(err="fake: an empty managedFields list is ignored", rc=3)
        v["owners"] = [[m["manager"], m["operation"]] for m in mf if "f:replicas" in m["fieldsV1"].get("f:spec", {})]
        st["rv"] = st.get("rv", 1) + 1; effect()
    if v["replicas"] != p[1]["value"]:
        v["owners"] = [["kubectl-patch", "Update"]]     # an update that changes a field takes it from every owner
    v["replicas"] = p[1]["value"]; st["pods"] = sum(x["replicas"] for x in st["sets"].values()) if not st.get("pods_stuck") else st["pods"]
    st["rv"] = st.get("rv", 1) + 1; effect()
if "pods" in a:
    ready = [{"type": "Ready", "status": "False" if st.get("unready") else "True"}]
    done(json.dumps({"items": [{"metadata": {"name": "login-%d" % i}, "status": {"conditions": ready}} for i in range(st["pods"])]}))
done(err="fake login node: unexpected " + cmd, rc=3)
'''


class Window(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="prace-window-")
        self.addCleanup(self.tmp.cleanup)
        self.d = Path(self.tmp.name)
        (self.d / "fake-login").write_text(FAKE_LOGIN)
        (self.d / "bin").mkdir()
        (self.d / "bin/ssh").write_text("#!/bin/sh\necho 'real ssh called' >&2\nexit 99\n")
        (self.d / "bin/ssh").chmod(0o755)
        self.state = self.d / "state.json"
        self.put(lease=None, parts={"cpu": "UP", "gpu": "DRAIN"}, sets={"slurm-login-prace": {"uid": "u1", "replicas": 1}},
                 pods=1, jobs=[], fail=[])
        (self.d / "calls").write_text("")

    def put(self, **kw):
        st = json.loads(self.state.read_text()) if self.state.exists() else {}
        st.update(kw)
        self.state.write_text(json.dumps(st))

    def st(self):
        return json.loads(self.state.read_text())

    def run_tool(self, *args, wait="0"):
        env = dict(os.environ, PRACE_WINDOW_SSH=f"{sys.executable} {self.d / 'fake-login'}", PRACE_LOGIN="login.prace-test.invalid",
                   PRACE_WINDOW_DIR=str(self.d / "records"), PRACE_WINDOW_WAIT=wait, STATE=str(self.state),
                   CALLS=str(self.d / "calls"), PATH=str(self.d / "bin") + os.pathsep + os.environ["PATH"])
        r = subprocess.run([sys.executable, str(TOOL), *args], env=env, capture_output=True, text=True, timeout=60)
        self.assertNotIn("real ssh called", r.stderr)
        return r.returncode, r.stdout + r.stderr

    def take(self):
        rc, out = self.run_tool("lease-take", "--label", "slurm-window")
        self.assertEqual(rc, 0, out)
        return out.strip().splitlines()[-1]

    def record(self, lid):
        return json.loads((self.d / "records" / f"{lid}.json").read_text())

    def apply_overlay(self, lid, phase="opening"):
        rec = self.record(lid)
        parts = dict(rec["original"]["partitions"], **rec["declared_partitions"])
        values = {"partitions": {n: {"configMap": {"State": s if phase == "opening" else "INACTIVE"}} for n, s in parts.items()}}
        # Keep the real chart's slurm-login-prace -> prace mapping.
        values["loginsets"] = {n[len("slurm-login-"):]: {"replicas": v["replicas"] if phase == "opening" else 0} for n, v in rec["original"]["loginsets"].items()}
        self.helm_apply(values["loginsets"])
        self.put(overlay={"apiVersion": "helm.cattle.io/v1", "kind": "HelmChartConfig",
                          "metadata": {"name": "slurm", "namespace": "kube-system", "annotations": {"prace.fleet/window-id": lid, "prace.fleet/window-phase": phase}},
                          "spec": {"valuesContent": json.dumps(values)}})

    def helm_apply(self, chart_sets):
        """K3s's Helm (v4) writes the chart by server-side apply: a field another manager owns may not
        change (3 Oct, revision 5); otherwise Helm owns it, alongside an owner of the same value"""
        st = self.st()
        for short, want in chart_sets.items():
            v = st["sets"]["slurm-login-" + short]
            others = [o for o in v.get("owners", [["helm", "Apply"]]) if o != ["helm", "Apply"]]
            if others and v["replicas"] != want["replicas"]:
                self.fail(f"Helm upgrade conflict: {others} own .spec.replicas ({v['replicas']} -> {want['replicas']})")
            v["owners"] = [["helm", "Apply"]] + others
            v["replicas"] = want["replicas"]
        pods = st["pods"] if st.get("pods_stuck") else sum(x["replicas"] for x in st["sets"].values())
        self.put(sets=st["sets"], pods=pods)

    def prepare(self, lid):
        rc, out = self.run_tool("prepare-open", "--lease-id", lid)
        self.assertEqual(rc, 0, out)
        value = json.loads(out.splitlines()[0])["slurm_window_intent"]   # stdout; a release note follows on stderr
        self.assertEqual((value["phase"], value["fence_active"]), ("opening", False))
        self.apply_overlay(lid)

    def test_lease_is_exclusive_and_recorded_off_fleet(self):
        lid = self.take()
        self.assertIn(f"holder=maint label=slurm-window id={lid} since=", self.st()["lease"])
        rec = self.d / "records" / f"{lid}.json"
        self.assertEqual(oct(rec.stat().st_mode & 0o777), "0o600")
        self.assertEqual(oct(rec.parent.stat().st_mode & 0o777), "0o700")
        rc, out = self.run_tool("lease-take", "--label", "other")
        self.assertEqual(rc, 1, out)
        self.assertIn(lid, self.st()["lease"])

    def test_close_check_open_round_trip(self):
        lid = self.take()
        rc, out = self.run_tool("close", "--lease-id", lid)
        self.assertEqual(rc, 0, out)
        st = self.st()
        self.assertEqual(st["parts"], {"cpu": "INACTIVE", "gpu": "INACTIVE"})
        self.assertEqual((st["sets"]["slurm-login-prace"]["replicas"], st["pods"]), (0, 0))
        self.assertEqual(self.run_tool("check", "--lease-id", lid)[0], 0)
        self.prepare(lid)
        rc, out = self.run_tool("open", "--lease-id", lid)
        self.assertEqual(rc, 0, out)
        st = self.st()
        self.assertEqual(st["parts"], {"cpu": "UP", "gpu": "DRAIN"}, "original states, not all UP")
        self.assertEqual((st["sets"]["slurm-login-prace"]["replicas"], st["pods"]), (1, 1))
        rc, out = self.run_tool("lease-release", "--lease-id", lid)
        self.assertEqual(rc, 0, out)
        self.assertIsNone(self.st()["lease"])

    def owners(self):
        return self.st()["sets"]["slurm-login-prace"].get("owners", [["helm", "Apply"]])

    def test_a_runtime_replica_patch_leaves_the_count_to_helm(self):
        """3 Oct, revision 5: close's kubectl patch stayed an owner of .spec.replicas, and Helm's
        server-side apply of the opening overlay (0 -> 1) failed on it"""
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.assertEqual(self.st()["sets"]["slurm-login-prace"]["replicas"], 0)
        self.assertNotIn(["kubectl-patch", "Update"], self.owners(), "the close's patch must not stay an owner")
        self.prepare(lid)                      # Helm's opening write: fails the test on a conflict
        rc, out = self.run_tool("open", "--lease-id", lid)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.owners(), [["helm", "Apply"]])

    def test_prepare_open_releases_a_legacy_replica_owner(self):
        """the fleet after the 3 Oct recovery: helm and kubectl-patch co-own replicas=0"""
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.apply_overlay(lid, "closed")
        self.put(sets={"slurm-login-prace": {"uid": "u1", "replicas": 0, "owners": [["helm", "Apply"], ["kubectl-patch", "Update"]]}})
        self.prepare(lid)
        self.assertEqual(self.owners(), [["helm", "Apply"]])
        self.assertIn("managedFields", (self.d / "calls").read_text())
        rc, out = self.run_tool("open", "--lease-id", lid)
        self.assertEqual(rc, 0, out)
        self.assertEqual((self.st()["sets"]["slurm-login-prace"]["replicas"], self.st()["pods"]), (1, 1))

    def test_an_unreleased_replica_owner_refuses_the_opening(self):
        for case in ({"fail": ["managedFields"]}, {"mf_patch_noop": True}):
            with self.subTest(case):
                self.setUp()
                lid = self.take()
                self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
                self.apply_overlay(lid, "closed")
                self.put(sets={"slurm-login-prace": {"uid": "u1", "replicas": 0, "owners": [["helm", "Apply"], ["kubectl-patch", "Update"]]}}, **case)
                rc, out = self.run_tool("prepare-open", "--lease-id", lid)
                self.assertEqual(rc, 1, out)
                self.assertIn("not released to Helm", out)
                self.assertNotIn("slurm_window_intent", out, "no opening intent without the release")
                self.assertEqual(self.record(lid)["phase"], "closed")
                self.assertEqual(set(self.st()["parts"].values()), {"INACTIVE"})
                self.assertEqual(self.st()["sets"]["slurm-login-prace"]["replicas"], 0)

    def test_a_controller_replacement_is_waited_out(self):
        """3 Oct: close's partition query reached the controller pod while the overlay's config
        change replaced it (rc 2); a replacement error is retried within the wait, nothing else"""
        lid = self.take()
        self.put(transient={"scontrol show partition": 2, "State=INACTIVE": 1})
        rc, out = self.run_tool("close", "--lease-id", lid, wait="30")
        self.assertEqual(rc, 0, out)
        self.assertEqual(set(self.st()["parts"].values()), {"INACTIVE"})
        self.put(transient={"squeue": 1})
        self.assertEqual(self.run_tool("check", "--lease-id", lid, wait="30")[0], 0)
        self.put(transient={"scontrol show partition": 1})
        self.assertEqual(self.run_tool("check", "--lease-id", lid)[0], 2, "no wait budget: the error stands")
        calls = (self.d / "calls").read_text().count("scontrol show partition")
        self.put(fail=["scontrol show partition"])
        rc, out = self.run_tool("check", "--lease-id", lid, wait="30")
        self.assertEqual(rc, 2, out)
        self.assertEqual((self.d / "calls").read_text().count("scontrol show partition"), calls + 1, "another error is not retried")

    def test_an_exited_controller_pod_is_waited_out_too(self):
        """3 Oct, 18:34: open's first partition query reached the replaced controller pod after its
        containers had exited ("cannot exec into a container in a completed pod"); open returned rc 2
        and only a re-run passed. That is a replacement too, retried within the wait."""
        completed = "error: cannot exec into a container in a completed pod; current phase is Succeeded"
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.put(transient={"scontrol show partition": 1}, transient_err=completed)
        rc, out = self.run_tool("check", "--lease-id", lid)
        self.assertEqual(rc, 2, "without a wait budget the error stands")
        self.assertIn("completed pod", out)
        self.assertEqual(self.run_tool("check", "--lease-id", lid)[0], 0, "the fence itself is closed")
        self.prepare(lid)
        self.put(transient={"scontrol show partition": 2}, transient_err=completed)
        rc, out = self.run_tool("open", "--lease-id", lid, wait="30")
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.st()["parts"], {"cpu": "UP", "gpu": "DRAIN"}, "the original states")

    def test_a_queued_job_never_blocks_the_fence(self):
        """Session A's capture could neither close nor recover with a pending job (30 Sep review)"""
        self.put(jobs=["812 alice PENDING cpu"])
        lid = self.take()
        rc, out = self.run_tool("close", "--lease-id", lid)
        self.assertEqual(rc, 3, out)
        self.assertIn("812 alice PENDING cpu", out)
        self.assertEqual(set(self.st()["parts"].values()), {"INACTIVE"}, "the fence is closed anyway")
        self.assertEqual(self.run_tool("check", "--lease-id", lid)[0], 3)
        self.prepare(lid)
        rc, out = self.run_tool("open", "--lease-id", lid)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.st()["parts"], {"cpu": "UP", "gpu": "DRAIN"})

    def test_an_apply_that_reopens_is_seen_and_reclosed(self):
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.assertEqual(self.run_tool("declare-partition", "--lease-id", lid, "--partition", "debug", "--return-state", "UP")[0], 0)
        # the chart applied: reconfiguration reset cpu, created debug, Helm reset the LoginSet
        self.put(parts={"cpu": "UP", "gpu": "INACTIVE", "debug": "UP"}, sets={"slurm-login-prace": {"uid": "u1", "replicas": 1}}, pods=1)
        rc, out = self.run_tool("check", "--lease-id", lid)
        self.assertEqual(rc, 1, out)
        for item in ("partition cpu is UP", "partition debug is UP", "loginset slurm-login-prace has 1 replicas", "1 login pod(s) present"):
            self.assertIn(item, out)
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.prepare(lid)
        rc, out = self.run_tool("open", "--lease-id", lid)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.st()["parts"], {"cpu": "UP", "gpu": "DRAIN", "debug": "UP"},
                         "cpu and gpu as first recorded; debug as it came from the apply")

    def test_failed_queries_change_nothing(self):
        for fail in ("scontrol show partition", "get loginsets", "squeue"):
            with self.subTest(fail):
                self.setUp()
                lid = self.take()
                self.put(fail=[fail])
                rc, out = self.run_tool("close", "--lease-id", lid)
                self.assertEqual(rc, 2, out)
                if fail != "squeue":       # the queue is read after the fence closed
                    self.assertEqual(self.st()["parts"], {"cpu": "UP", "gpu": "DRAIN"})

    def test_only_the_lease_holder_acts(self):
        lid = self.take()
        self.put(lease="holder=slinky-acceptance id=0123456789abcdef since=now")
        rc, out = self.run_tool("close", "--lease-id", lid)
        self.assertEqual(rc, 1, out)
        self.assertEqual(self.st()["parts"], {"cpu": "UP", "gpu": "DRAIN"})
        self.assertEqual(self.run_tool("close", "--lease-id", "not-an-id")[0], 1)

    def test_release_while_fenced_needs_an_explicit_flag(self):
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        rc, out = self.run_tool("lease-release", "--lease-id", lid)
        self.assertEqual(rc, 1, out)
        self.assertIsNotNone(self.st()["lease"])
        rc, out = self.run_tool("lease-release", "--lease-id", lid, "--fenced")
        self.assertEqual(rc, 1, out)                 # no persistent overlay holds the fence (review H1)
        self.assertIn("no persistent maintenance overlay", out)
        self.apply_overlay(lid, "closed")
        rc, out = self.run_tool("lease-release", "--lease-id", lid, "--fenced")
        self.assertEqual(rc, 0, out)
        self.assertIn("with the fence CLOSED", out)
        self.assertEqual(set(self.st()["parts"].values()), {"INACTIVE"})

    def test_a_replaced_loginset_or_unready_pods_are_not_reopened(self):
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.put(sets={"slurm-login-prace": {"uid": "u2", "replicas": 0}})
        rc, out = self.run_tool("prepare-open", "--lease-id", lid)
        self.assertEqual(rc, 1, out)
        self.assertIn("was replaced", out)
        self.assertEqual(set(self.st()["parts"].values()), {"INACTIVE"})
        self.put(sets={"slurm-login-prace": {"uid": "u1", "replicas": 0}}, unready=True)
        self.prepare(lid)
        rc, out = self.run_tool("open", "--lease-id", lid)
        self.assertEqual(rc, 1, out)
        self.assertIn("0/1 login pod(s) ready", out)


    def test_partial_close_never_releases_even_fenced(self):
        """Fails on the old code: it marked fenced only after the last mutation."""
        lid = self.take()
        self.put(fail=["patch loginset"])
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 1)
        self.assertEqual(set(self.st()["parts"].values()), {"INACTIVE"})
        self.put(fail=[])
        rc, out = self.run_tool("lease-release", "--lease-id", lid, "--fenced")
        self.assertEqual(rc, 1, out)
        self.assertIsNotNone(self.st()["lease"])

    def test_replaced_identity_never_opens_any_partition(self):
        """Fails on old reopen: it restored partitions before checking the LoginSet UID."""
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.put(sets={"slurm-login-prace": {"uid": "replacement", "replicas": 0}})
        self.assertEqual(self.run_tool("open", "--lease-id", lid)[0], 1)
        self.assertEqual(set(self.st()["parts"].values()), {"INACTIVE"})

    def test_interrupted_close_keeps_saved_baseline(self):
        lid = self.take()
        original = self.record(lid)["original"]
        self.put(kill_on="PartitionName=cpu State=INACTIVE")
        self.assertNotEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.assertEqual(self.record(lid)["phase"], "closing")
        self.assertEqual(self.record(lid)["original"], original)
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid, "--fenced")[0], 1)
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.prepare(lid)
        self.assertEqual(self.run_tool("open", "--lease-id", lid)[0], 0)
        self.assertEqual(self.st()["parts"], original["partitions"])

    def test_lost_close_ack_is_partial_even_if_effect_happened(self):
        lid = self.take()
        self.put(lost_ack="PartitionName=cpu State=INACTIVE")
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 1)
        self.assertEqual(self.st()["parts"]["cpu"], "INACTIVE")
        self.assertEqual(self.record(lid)["phase"], "closing")
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid, "--fenced")[0], 1)

    def test_interrupted_open_requires_same_baseline_completion(self):
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.prepare(lid)
        self.put(kill_on="PartitionName=cpu State=UP")
        self.assertNotEqual(self.run_tool("open", "--lease-id", lid)[0], 0)
        self.assertEqual(self.record(lid)["phase"], "opening")
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid, "--fenced")[0], 1)
        self.assertEqual(self.run_tool("open", "--lease-id", lid)[0], 0)
        self.assertEqual(self.st()["parts"], {"cpu": "UP", "gpu": "DRAIN"})

    def test_missing_original_or_declared_object_cannot_prepare_open(self):
        for kind in ("partition", "loginset", "declared"):
            with self.subTest(kind=kind):
                self.setUp(); lid = self.take()
                self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
                if kind == "partition": self.put(parts={"cpu": "INACTIVE"})
                elif kind == "loginset": self.put(sets={})
                else:
                    self.assertEqual(self.run_tool("declare-partition", "--lease-id", lid, "--partition", "debug", "--return-state", "UP")[0], 0)
                self.assertNotEqual(self.run_tool("prepare-open", "--lease-id", lid)[0], 0)
                self.assertEqual(set(self.st()["parts"].values()), {"INACTIVE"})
                if kind != "declared":
                    self.assertNotEqual(self.run_tool("lease-release", "--lease-id", lid, "--fenced")[0], 0)

    def test_intentional_inactive_is_restored_and_not_advertised_available(self):
        self.put(parts={"cpu": "INACTIVE", "gpu": "DRAIN"})
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.prepare(lid)
        rc, out = self.run_tool("open", "--lease-id", lid)
        self.assertEqual(rc, 0, out)
        self.assertIn("baseline restored; workload admission available: false", out)
        self.assertEqual(self.st()["parts"], {"cpu": "INACTIVE", "gpu": "DRAIN"})
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid)[0], 0)

    def test_fenced_release_requires_same_record_recovery(self):
        lid = self.take()
        original = self.record(lid)["original"]
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.apply_overlay(lid, "closed")
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid, "--fenced")[0], 0)
        self.assertEqual(self.run_tool("lease-take")[0], 1)
        self.assertEqual(self.run_tool("lease-take", "--recover-id", lid)[0], 0)
        self.assertEqual(self.record(lid)["original"], original)
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.prepare(lid)
        self.assertEqual(self.run_tool("open", "--lease-id", lid)[0], 0)

    def test_leftover_fence_after_released_record_uses_same_baseline(self):
        lid = self.take()
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid)[0], 0)
        self.put(parts={"cpu": "INACTIVE", "gpu": "DRAIN"})
        rc, out = self.run_tool("lease-take")
        self.assertEqual(rc, 1, out)
        self.assertIn("leftover fence", out)
        self.assertEqual(self.run_tool("lease-take", "--recover-id", lid)[0], 0)
        self.assertEqual(self.record(lid)["original"]["partitions"]["cpu"], "UP")

    def test_unexplained_fence_is_never_a_new_baseline(self):
        self.put(parts={"cpu": "INACTIVE", "gpu": "INACTIVE"}, sets={"slurm-login-prace": {"uid": "u1", "replicas": 0}}, pods=0)
        self.assertEqual(self.run_tool("lease-take")[0], 1)
        self.assertIsNone(self.st()["lease"])

    def test_undeclared_partition_is_not_first_sighting_return_intent(self):
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.put(parts={"cpu": "INACTIVE", "gpu": "INACTIVE", "debug": "UP"})
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 1)
        self.assertNotIn("debug", self.record(lid)["original"]["partitions"])
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid, "--fenced")[0], 1)

    def test_intent_is_json_and_requires_quiet_lease_marker(self):
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        rc, out = self.run_tool("intent", "--lease-id", lid)
        self.assertEqual(rc, 0, out)
        self.assertEqual(json.loads(out)["slurm_window_intent"], self.st()["marker"])
        self.put(jobs=["900 alice RUNNING cpu"])
        self.assertEqual(self.run_tool("intent", "--lease-id", lid)[0], 3)
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid, "--fenced")[0], 3)
        self.put(jobs=[], marker={})
        self.assertEqual(self.run_tool("intent", "--lease-id", lid)[0], 2)

    def test_running_job_is_not_claimed_stopped(self):
        lid = self.take(); self.put(jobs=["900 alice RUNNING cpu"])
        rc, out = self.run_tool("close", "--lease-id", lid)
        self.assertEqual(rc, 3, out)
        self.assertIn("running jobs are not stopped", out)
        self.assertNotIn("they will not start", out)
        self.prepare(lid)
        self.assertEqual(self.run_tool("open", "--lease-id", lid)[0], 0)

    def test_unknown_queue_after_close_cannot_release(self):
        lid = self.take(); self.put(fail=["squeue"])
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 2)
        self.assertEqual(self.record(lid)["phase"], "closing")
        self.put(fail=[])
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid, "--fenced")[0], 1)
        self.assertEqual(self.run_tool("check", "--lease-id", lid)[0], 0)

    def test_closed_chart_overlay_prevents_runtime_open(self):
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.prepare(lid); self.apply_overlay(lid, "closed")
        self.assertEqual(self.run_tool("open", "--lease-id", lid)[0], 1)
        self.assertEqual(set(self.st()["parts"].values()), {"INACTIVE"})
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid, "--fenced")[0], 1)

    def test_reclose_refences_persistent_opening_overlay_first(self):
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.prepare(lid)
        self.assertEqual(self.run_tool("open", "--lease-id", lid)[0], 0)
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.assertEqual(self.st()["refence_phase"], "closing")
        self.assertEqual(self.st()["overlay"]["metadata"]["annotations"]["prace.fleet/window-phase"], "closed")
        self.assertEqual(self.run_tool("intent", "--lease-id", lid)[0], 0)

    def test_refence_failure_retains_partial_state_and_lease(self):
        lid = self.take(); self.put(refence_fail=True)
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 1)
        self.assertEqual(set(self.st()["parts"].values()), {"INACTIVE"}, "admission tightened before the overlay step (review M1)")
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid, "--fenced")[0], 1)

    def test_unknown_lease_contents_are_never_removed(self):
        lid = self.take(); self.put(unknown_lease_file=True)
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid)[0], 1)
        self.assertIsNotNone(self.st()["lease"])
        self.assertEqual(self.record(lid)["phase"], "releasing")

    def test_shared_operation_lock_blocks_close(self):
        import fcntl
        lid = self.take()
        with open(str(self.state) + ".lock", "w") as locked:
            fcntl.flock(locked, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 1)
        self.assertEqual(self.st()["parts"], {"cpu": "UP", "gpu": "DRAIN"})


    def test_an_opening_overlay_left_by_a_failed_reclose_is_never_a_closed_fence(self):
        """review H1: the runtime fence alone looked closed; the persistent overlay still said opening"""
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.apply_overlay(lid, "closed")
        self.assertEqual(self.run_tool("check", "--lease-id", lid)[0], 0)
        self.prepare(lid)                                   # the opening overlay is applied
        self.put(refence_fail=True)
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 1)
        self.put(refence_fail=False)
        rc, out = self.run_tool("check", "--lease-id", lid)
        self.assertEqual(rc, 1, out)
        self.assertIn("not closed by this one", out)
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid, "--fenced")[0], 1)
        self.assertIsNotNone(self.st()["lease"])
        rc, out = self.run_tool("intent", "--lease-id", lid)  # the repair: a closed intent for the overlay playbook
        self.assertEqual(rc, 0, out)
        self.apply_overlay(lid, "closed")
        self.assertEqual(self.run_tool("check", "--lease-id", lid)[0], 0)
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid, "--fenced")[0], 0)

    def test_an_overlay_that_does_not_name_a_live_partition_does_not_hold_the_fence(self):
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.apply_overlay(lid, "closed")
        self.assertEqual(self.run_tool("declare-partition", "--lease-id", lid, "--partition", "payg", "--return-state", "UP")[0], 0)
        self.put(parts={"cpu": "INACTIVE", "gpu": "INACTIVE", "payg": "INACTIVE"})
        rc, out = self.run_tool("check", "--lease-id", lid)
        self.assertEqual(rc, 1, out)
        self.assertIn("does not name partition(s) payg", out)
        self.apply_overlay(lid, "closed")                   # refreshed with the declared partition
        self.assertEqual(self.run_tool("check", "--lease-id", lid)[0], 0)

    def test_a_removed_overlay_is_not_the_first_close(self):
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.apply_overlay(lid, "closed")
        self.assertEqual(self.run_tool("check", "--lease-id", lid)[0], 0)
        self.put(overlay=None)
        rc, out = self.run_tool("check", "--lease-id", lid)
        self.assertEqual(rc, 1, out)
        self.assertIn("no persistent maintenance overlay", out)

    def test_failed_recovery_keeps_the_saved_phase(self):
        """review H2: a failed --recover-id turned an interrupted opening into acquire_failed, and a
        plain lease-take then saved a half-open fence as a fresh baseline"""
        lid = self.take()
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)
        self.prepare(lid)
        self.put(kill_on="PartitionName=cpu State=UP")
        self.assertNotEqual(self.run_tool("open", "--lease-id", lid)[0], 0)
        self.assertEqual(self.record(lid)["phase"], "opening")
        self.put(lease=None, marker=None, fail=["mkdir"])   # lease lost (a reboot), then a failed acquisition
        self.assertEqual(self.run_tool("lease-take", "--recover-id", lid)[0], 1)
        self.assertEqual(self.record(lid)["phase"], "opening")
        self.put(fail=[])
        rc, out = self.run_tool("lease-take")
        self.assertEqual(rc, 1, out)
        self.assertIn(f"unresolved prior window {lid}", out)
        self.assertIsNone(self.st()["lease"])
        self.assertEqual(self.run_tool("lease-take", "--recover-id", lid)[0], 0)
        self.assertEqual(self.run_tool("close", "--lease-id", lid)[0], 0)

    def test_close_tightens_before_it_refuses(self):
        """review M1: an undeclared partition used to stop close before anything was fenced"""
        lid = self.take()
        self.put(parts={"cpu": "UP", "gpu": "DRAIN", "extra": "UP"})
        rc, out = self.run_tool("close", "--lease-id", lid)
        self.assertEqual(rc, 1, out)
        self.assertIn("undeclared=extra", out)
        st = self.st()
        self.assertEqual(set(st["parts"].values()), {"INACTIVE"})
        self.assertEqual((st["sets"]["slurm-login-prace"]["replicas"], st["pods"]), (0, 0))
        self.assertEqual(self.record(lid)["phase"], "closing")

    def test_other_files_in_the_record_directory_are_not_windows(self):
        """review M3: an intent file saved next to the records blocked every later lease-take"""
        lid = self.take()
        self.assertEqual(self.run_tool("lease-release", "--lease-id", lid)[0], 0)
        (self.d / "records" / "intent.json").write_text("{}")
        rc, out = self.run_tool("lease-take", "--label", "slurm-window")
        self.assertEqual(rc, 0, out)

    def test_real_lock_coordinator_passes_owned_fd_to_helper(self):
        import runpy
        import shutil
        module = runpy.run_path(str(TOOL))
        self.addCleanup(shutil.rmtree, module["SSH_DIR"], True)
        helper = self.d / "maintenance-helper"
        helper.write_text("#!/usr/bin/env python3\nimport fcntl,os,sys\nfd=int(sys.argv[-1])\nfcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\nassert os.fstat(fd).st_ino==os.stat(os.environ['EXPECTED_LOCK']).st_ino\n")
        helper.chmod(0o755)
        lid = "0123456789abcdef"
        script = module["LOCK_SERVER"].replace("/run/prace-slurm-window-", str(self.d / "prace-slurm-window-"))
        script = script.replace("/usr/local/sbin/prace-slinky-maintenance", str(helper))
        r = subprocess.run([sys.executable, "-c", script, lid], input=json.dumps({"refence": {"lease_id": lid}})+"\n",
                           env=dict(os.environ, EXPECTED_LOCK=str(self.d / ("prace-slurm-window-"+lid+".lock"))),
                           text=True, capture_output=True, timeout=5)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.splitlines()[0], "locked")
        self.assertTrue(json.loads(r.stdout.splitlines()[1])["ok"], r.stdout)

    def test_lock_coordinator_refuses_a_replaced_lock_path(self):
        import runpy
        import shutil
        module = runpy.run_path(str(TOOL))
        self.addCleanup(shutil.rmtree, module["SSH_DIR"], True)
        lid = "0123456789abcdef"
        path = self.d / ("prace-slurm-window-" + lid + ".lock")
        # the coordinator opens the path, then a replacement appears before it re-checks
        script = module["LOCK_SERVER"].replace("/run/prace-slurm-window-", str(self.d / "prace-slurm-window-"))
        script = script.replace("fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n",
                                "fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\nos.unlink(p);open(p,'w').close();os.chmod(p,0o600)\n", 1)
        self.assertIn("os.unlink(p)", script)
        r = subprocess.run([sys.executable, "-c", script, lid], input="", text=True, capture_output=True, timeout=5)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("locked", r.stdout)

if __name__ == "__main__":
    unittest.main()

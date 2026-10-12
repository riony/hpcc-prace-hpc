#!/usr/bin/env python3
"""Offline tests for the fleet dashboard collectors (roles/fleet_dashboard/files): the observe
collector against the committed observer-88 observations and the monitor's file formats, the GitLab
collector against recorded-shape responses, the evidence builder against the committed window-t87-t88
evidence and a synthetic scenario run, scrubbing (C4) and the offline guard. No socket is opened:
dashtest installs the guard before any collector is imported, and the guard tests prove it."""
import copy
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.request
from contextlib import redirect_stdout, redirect_stderr

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dashtest as T  # noqa: E402
from dashtest import common, evidence, gitlab, observe  # noqa: E402

LEASED, UNLEASED = T.observation("leased"), T.observation("unleased")
NOW = UNLEASED["time"] + 40
REAL_IDS = ("b30f910591f4aba9", "af7d79c031a9eb04", "6898a662fc3887d8", "79ecd8a56f794ef68f05ca31b4aacac0",
            "47d1e0c8f71c46598dad1c83834ec0f9", "02:00:00:00:00:03", "0000:5d:00.0", "10.42.", "10.90.10.1",
            "slurm-login-prace-97fd499f-fbc7v", "slurm-worker-gpu-5mqpf", "tailabc123")


class Env(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.tmp = self.d.name
        self.cfg = T.config(self.tmp)

    def tearDown(self):
        self.d.cleanup()

    def observe(self, obs=None, now=NOW, **kw):
        T.write_monitor(self.cfg, now, obs=obs, **kw)
        return observe.run(self.cfg, now)

    def assertClean(self, text):
        for host in T.FLEET:
            self.assertNotIn(host, text)
        for ident in REAL_IDS + tuple(n for v in T.ACCOUNTS.values() for n in v):
            self.assertNotIn(ident, text)


class Guard(unittest.TestCase):
    """the collectors refuse the network under PRACE_DASH_OFFLINE=1, and the tests prove it"""

    def test_the_guard_is_active_in_this_process(self):
        self.assertTrue(common.offline())
        self.assertTrue(common.guard_state()["active"])

    def test_every_socket_path_is_refused(self):
        before = common.guard_state()["refused"]
        for attempt in (lambda: socket.socket(), lambda: socket.create_connection(("127.0.0.1", 9), 1),
                        lambda: socket.getaddrinfo("localhost", 443), lambda: urllib.request.urlopen("http://127.0.0.1:9/", timeout=1)):
            with self.assertRaises(common.NetworkRefused):
                attempt()
        self.assertEqual(common.guard_state()["refused"] - before, 4)

    def test_the_gitlab_collector_refuses_before_and_below_its_own_check(self):
        api = gitlab.Api({"url": "https://gitlab.invalid", "connect": "127.0.0.1", "project": "hpcc/prace-hackathon"}, T.DUMMY_TOKEN)
        with self.assertRaises(gitlab.ApiError) as e:
            api.get("/projects/:id/pipelines")
        self.assertIn("network refused", str(e.exception))
        conn = gitlab._Connection("127.0.0.1", "gitlab.invalid", 443, api.ctx, 1)   # below the explicit check: the audit hook
        with self.assertRaises(common.NetworkRefused):
            conn.connect()

    def test_a_full_gitlab_run_without_a_fake_reaches_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = T.config(d)
            doc = gitlab.run(cfg, NOW)
            for name in ("pipelines", "drift_audit", "merge_requests", "monitor_issues", "reservations", "token"):
                self.assertIn("network refused", doc[name]["error"])
            out = T.read(cfg, "gitlab.json") + open(os.path.join(cfg["state_dir"], "gitlab-cache.json")).read()
            self.assertNotIn(T.DUMMY_TOKEN, out)

    def test_a_fresh_process_with_the_flag_is_refused_at_import(self):
        code = ("import sys, socket; sys.path.insert(0, %r); import prace_dash_gitlab\n"
                "try:\n socket.create_connection(('127.0.0.1', 9), 1)\nexcept PermissionError as e:\n print('REFUSED', type(e).__name__)\n") % T.FILES
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           env=dict(os.environ, PRACE_DASH_OFFLINE="1", PYTHONDONTWRITEBYTECODE="1"))
        self.assertIn("REFUSED NetworkRefused", r.stdout)

    def test_no_socket_was_ever_created(self):
        # every socket event the recorder saw was one the guard refused (refusals happen before creation)
        self.assertEqual(len(T.SOCKET_EVENTS), common.guard_state()["refused"])


class Observe(Env):
    def test_the_committed_unleased_sample(self):
        doc = self.observe(UNLEASED)
        self.assertEqual(doc["errors"], [])
        self.assertEqual([h["name"] for h in doc["hosts"]], ["login-node", "cpu-worker-1", "gpu-worker-1", "gpu-worker-2", "gpu-worker-3"])
        self.assertEqual([h["role"] for h in doc["hosts"]], ["login", "cpu", "gpu", "gpu", "gpu"])
        login, cpu = doc["hosts"][0], doc["hosts"][1]
        self.assertEqual(login["config_files"], 49)                 # tracked on the login node only
        self.assertNotIn("config_files", cpu)
        self.assertEqual((cpu["kind"], cpu["expected_kind"], cpu["slurmd_pods"], cpu["slurmd_pod_ready"]), ("pod", "pod", 1, True))
        self.assertEqual(len(login["shares"]), 1)                   # the login pod runs outside maintenance
        self.assertEqual(login["shares"][0]["lacks"], {})
        self.assertEqual(doc["window"]["phase"], "open")
        self.assertEqual(doc["lease"], {"stated": True, "held": False})
        self.assertEqual(doc["profile"]["version"], 3)
        self.assertEqual({p["name"]: p["state"] for p in doc["partitions"]}, {"cpu": "up", "debug": "up", "gpu": "up", "payg": "up"})
        self.assertEqual({c["key"]: c["value"] == c["expected"] for c in doc["slurm_config"] if c["expected"]},
                         {"AccountingStorageEnforce": True, "EnforcePartLimits": True, "GresTypes": True, "JobSubmitPlugins": True, "ReturnToService": True})
        self.assertEqual([(p["name"], p["version"]) for p in doc["static"]["pins"]],
                         [("slurmctld", "25.11.8-rockylinux9"), ("K3s", "v1.36.4+k3s1"), ("NVIDIA driver", "580.173.02-1.el9")])
        self.assertClean(T.read(self.cfg, "latest.json"))

    def test_the_committed_leased_sample(self):
        doc = self.observe(LEASED, now=LEASED["time"] + 40, outcome="DEFERRED_MAINTENANCE",
                           reasons=["maintenance in progress for 3 min: " + LEASED["lease"]["holder"]])
        self.assertEqual(doc["window"]["phase"], "closed")
        lease = doc["lease"]
        self.assertEqual((lease["held"], lease["holder"], lease["label"]), (True, "maint", "observer-88"))
        self.assertEqual(lease["id"], "id-" + common.MASK)
        self.assertEqual(lease["since"], int(common.parse_iso("2026-10-05T01:19:07+08:00")))
        self.assertEqual(doc["hosts"][0]["shares"], [])           # no login pod under the lease
        self.assertIn("id=" + common.MASK, doc["monitor"]["reasons"][0])
        self.assertClean(T.read(self.cfg, "latest.json"))

    def test_every_monitor_outcome_including_structural_drift(self):
        for outcome in observe.OUTCOMES:
            doc = self.observe(UNLEASED, outcome=outcome)
            self.assertEqual(doc["monitor"]["outcome"], outcome)
        # DRIFT from the 60-second monitor is structural only (unexpected node, unexpected native host);
        # fleet_audit's health_only never compares configuration
        doc = self.observe(UNLEASED, outcome="DRIFT", reasons=["unexpected Kubernetes nodes: lab-g099"])
        self.assertEqual(doc["monitor"]["reasons"], ["unexpected Kubernetes nodes: 1 name(s) withheld"])
        doc = self.observe(UNLEASED, outcome="DRIFT", reasons=["native observation of hosts not expected native: lab-g003, rogue-box"])
        self.assertEqual(doc["monitor"]["reasons"], ["native observation of hosts not expected native: gpu-worker-1, 1 name(s) withheld"])

    def test_an_unknown_outcome_word_is_a_source_error(self):
        doc = self.observe(UNLEASED, outcome="SOMETHING")
        self.assertIsNone(doc["monitor"])
        self.assertTrue(any("monitor state malformed" in e for e in doc["errors"]))

    def test_hostile_observations_are_rejected_never_raised(self):
        cases = {"oversized": lambda o: o.update(pad="x" * (observe.MAX_OBSERVATION + 1)),
                 "long string": lambda o: o["errors"].append("y" * 5000),
                 "nodes not a mapping": lambda o: o.update(nodes=["lab-dl380"]),
                 "future": lambda o: o.update(time=NOW + 3600),
                 "no time": lambda o: o.pop("time"),
                 "schema 2": lambda o: o.update(schema=2)}
        for label, mutate in cases.items():
            with self.subTest(label):
                o = copy.deepcopy(UNLEASED)
                mutate(o)
                doc = self.observe(o)
                self.assertIsNone(doc["observation"])
                self.assertTrue(any("rejected" in e for e in doc["errors"]), doc["errors"])
        for raw in (b"", b"\xff\xfe garbage", b"[1, 2]", b"[" * 100000 + b"]" * 100000):
            with self.subTest(raw=raw[:10]):
                T.write_monitor(self.cfg, NOW)
                with open(self.cfg["monitor"]["observation"], "wb") as f:
                    f.write(raw)
                doc = observe.run(self.cfg, NOW)
                self.assertIsNone(doc["observation"])

    def test_missing_sources_are_named_not_fatal(self):
        doc = observe.run(self.cfg, NOW)
        self.assertEqual(len(doc["errors"]), 3)
        self.assertTrue(any("awaiting raw observation" in e for e in doc["errors"]))
        self.assertEqual(json.loads(T.read(self.cfg, "latest.json"))["errors"], doc["errors"])

    def test_unknown_node_names_are_counted_never_shown(self):
        o = copy.deepcopy(UNLEASED)
        o["nodes"]["<b>evil-node</b>"] = {"k8s_ready": True, "role": "gpu"}
        doc = self.observe(o)
        self.assertEqual(doc["observation"]["unknown_nodes"], 1)
        self.assertNotIn("evil-node", T.read(self.cfg, "latest.json"))

    def test_hostile_reason_text_stays_text(self):
        doc = self.observe(UNLEASED, reasons=["<img src=x onerror=alert(1)> lab-g004 down"])
        self.assertEqual(doc["monitor"]["reasons"], ["<img src=x onerror=alert(1)> gpu-worker-2 down"])
        self.assertEqual(doc["hosts"][3]["reasons"], doc["monitor"]["reasons"])     # matched before scrubbing

    def test_a_stale_observation_is_flagged(self):
        doc = self.observe(UNLEASED, now=UNLEASED["time"] + 400)
        self.assertTrue(doc["observation"]["stale"])
        self.assertFalse(self.observe(UNLEASED)["observation"]["stale"])

    def test_native_worker_before_and_after_the_switch(self):
        self.assertEqual(self.observe(UNLEASED)["hosts"][1]["kind"], "pod")
        with open(PROFILE_NATIVE(self.tmp)) as f:
            self.cfg["monitor"]["profile"] = f.name
        o = copy.deepcopy(UNLEASED)
        o["native_hosts"] = {"lab-lenovo": T.native_report(t=NOW - 20)}
        o["nodes"]["lab-lenovo"].update(slurmd_pods=0, slurmd_pod_ready=None, slurm_addr="10.90.10.21")
        o["share_mounts"] = {k: v for k, v in o["share_mounts"].items() if v["node"] != "lab-lenovo"}
        doc = self.observe(o)
        cpu = doc["hosts"][1]
        self.assertEqual((cpu["kind"], cpu["expected_kind"]), ("native", "native"))
        n = cpu["native"]
        self.assertEqual((n["slurmd"]["ActiveState"], n["slurmd"]["SubState"], n["slurmd"]["UnitFileState"]), ("active", "running", "enabled"))
        self.assertEqual((n["key"], n["marker"], n["config_files"], n["slurmd_pid"]), ("present", "native", 2, True))
        self.assertEqual(n["mounts"]["/home"]["lacks"], [])
        self.assertEqual(n["mounts"]["/home"]["nfs"], ["vers=4.2", "hard"])
        self.assertEqual(n["mounts"]["/home"]["source"], "addr-masked:/home")
        self.assertEqual(n["boot_id"], "uuid-masked")
        self.assertEqual(doc["profile"]["native_workers"], ["cpu-worker-1"])
        o["native_hosts"]["lab-lenovo"] = {"errors": ["native_endpoint_unreachable_or_invalid"]}
        self.assertEqual(self.observe(o)["hosts"][1]["native"]["error"], "native_endpoint_unreachable_or_invalid")

    def test_network_guard_from_the_real_samples_and_faults(self):
        doc = self.observe(UNLEASED)
        rows = {r["host"]: r for r in doc["network_guard"]}
        self.assertFalse(rows["cpu-worker-1"]["in_check"])          # the Lenovo has no guarded link
        for host in ("login-node", "gpu-worker-1", "gpu-worker-2", "gpu-worker-3"):
            r = rows[host]
            self.assertEqual((r["alerts"], r["error"]), (0, None))
            self.assertTrue(all(i["down"] and i["identity"] == "matches" for i in r["interfaces"]))
        self.assertEqual([i["name"] for i in rows["login-node"]["interfaces"]], ["eno5", "eno6"])
        self.assertEqual([i["name"] for i in rows["gpu-worker-3"]["interfaces"]], ["ens10f0np0", "ens10f1np1"])
        o = copy.deepcopy(UNLEASED)
        o["disabled_links"]["lab-g004"]["interfaces"]["ens10f0np0"].update(admin_up=True, carrier=True, operstate="UP")
        o["disabled_links"]["lab-g005"]["interfaces"]["ens10f1np1"]["mac"] = "02:00:00:00:00:99"
        o["disabled_links"]["lab-dl380"] = {"errors": ["link_endpoint_unreachable_or_invalid"]}
        o["disabled_links"]["configuration"] = {"errors": ["disabled_link_endpoints_invalid"]}
        rows = {r["host"]: r for r in self.observe(o)["network_guard"]}
        self.assertEqual(rows["gpu-worker-2"]["alerts"], 1)
        self.assertEqual(rows["gpu-worker-3"]["interfaces"][1]["identity"], "differs")
        self.assertIn("link_endpoint_unreachable_or_invalid", rows["login-node"]["error"])
        self.assertIn("outside the fleet", rows["observer"]["error"])
        self.assertNotIn("02:00:00:00:00:99", T.read(self.cfg, "latest.json"))

    def test_window_phases(self):
        held, free = {"stated": True, "held": True}, {"stated": True, "held": False}      # parse_lease's output
        cases = [(held, {"cpu": "inactive", "gpu": "inactive"}, "closed"), (held, {"cpu": "up"}, "open-under-lease"),
                 (held, {"cpu": "up", "gpu": "inactive"}, "partial"), (free, {"cpu": "up"}, "open"),
                 (free, {"cpu": "inactive"}, "unexplained"), (free, None, "unknown")]
        for lease, parts, want in cases:
            self.assertEqual(observe.window_phase(lease, parts)["phase"], want)

    def test_history_transitions_events_strip_and_damage(self):
        rows = [{"t": NOW - 7200 + 60 * i, "outcome": "HEALTHY" if i < 60 or i > 70 else "DEFERRED_MAINTENANCE",
                 "reasons": ["r"], "events": ["maintenance started"] if i == 60 else (["maintenance ended"] if i == 71 else [])} for i in range(120)]
        T.write_monitor(self.cfg, NOW, obs=UNLEASED, history=rows)
        with open(self.cfg["monitor"]["history"], "a") as f:
            f.write("{not json\n" + json.dumps({"t": "x", "outcome": "HEALTHY"}) + "\n")
        doc = observe.run(self.cfg, NOW)
        h = doc["history"]
        self.assertEqual([(t["from"], t["to"]) for t in h["transitions"]],
                         [(None, "HEALTHY"), ("HEALTHY", "DEFERRED_MAINTENANCE"), ("DEFERRED_MAINTENANCE", "HEALTHY")])
        self.assertEqual([e["event"] for e in h["events"]], ["maintenance started", "maintenance ended"])
        self.assertEqual([s["outcome"] for s in h["strip_24h"]], ["HEALTHY", "DEFERRED_MAINTENANCE", "HEALTHY"])
        self.assertEqual(h["skipped_lines"], 2)

    def test_history_reads_its_rotated_predecessor(self):
        T.write_monitor(self.cfg, NOW, obs=UNLEASED, history=[{"t": NOW - 60, "outcome": "UNHEALTHY", "reasons": [], "events": []}])
        with open(self.cfg["monitor"]["history"] + ".1", "w") as f:
            f.write(json.dumps({"t": NOW - 3600, "outcome": "HEALTHY", "reasons": [], "events": []}) + "\n")
        self.assertEqual([t["to"] for t in observe.run(self.cfg, NOW)["history"]["transitions"]], ["HEALTHY", "UNHEALTHY"])

    def test_written_atomically_0644_and_never_with_residue(self):
        self.observe(UNLEASED)
        path = os.path.join(self.cfg["www_data"], "latest.json")
        self.assertEqual(oct(os.stat(path).st_mode & 0o777), "0o644")
        self.assertEqual(os.listdir(self.cfg["www_data"]), ["latest.json"])
        before = open(path).read()
        real = common.Scrubber.scrub
        common.Scrubber.scrub = lambda self, doc: doc          # a scrubber that forgets everything
        try:
            with self.assertRaises(ValueError) as e:
                self.observe(UNLEASED, now=NOW + 60)
        finally:
            common.Scrubber.scrub = real
        self.assertIn("residue", str(e.exception))
        self.assertEqual(open(path).read(), before)               # the old clean file stays
        self.assertEqual(os.listdir(self.cfg["www_data"]), ["latest.json"])

    def test_cli_exit_codes(self):
        T.write_monitor(self.cfg, NOW, obs=UNLEASED)
        cfgfile = os.path.join(self.tmp, "dash.json")
        with open(cfgfile, "w") as f:
            json.dump(self.cfg, f)
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(observe.main(["run", "--config", cfgfile, "--now", str(NOW)]), 0)
        self.assertIn("monitor HEALTHY", out.getvalue())
        with redirect_stderr(io.StringIO()):
            self.assertEqual(observe.main(["run", "--config", cfgfile + ".missing"]), 2)


def PROFILE_NATIVE(tmp):
    with open(T.PROFILE) as f:
        prof = json.load(f)
    prof["profile"] = 4
    prof["expected"]["native_workers"] = {"lab-lenovo": "10.90.10.21"}
    path = os.path.join(tmp, "deployed-native.json")
    with open(path, "w") as f:
        json.dump(prof, f)
    return path


class GitLab(Env):
    NOW = int(common.parse_iso("2099-01-06T00:00:00+00:00"))

    def run_gl(self, **kw):
        return gitlab.run(self.cfg, self.NOW, get=T.fake_get(**kw))

    def test_recorded_responses(self):
        doc = self.run_gl()
        p = doc["pipelines"]
        self.assertEqual([x["id"] for x in p["items"]], [990106, 990105, 990104, 990103])
        self.assertEqual(p["latest_main"], 990105)
        self.assertEqual([j["name"] for j in p["items"][1]["jobs"]][:3], ["secret-scan", "evidence-checksums", "ansible-syntax"])
        self.assertEqual(p["items"][1]["wall_s"], 1870)
        self.assertNotIn("jobs", p["items"][3])                     # ref main already shown: no extra job call
        d = doc["drift_audit"]["items"]
        self.assertEqual([i["outcome"] for i in d], ["HEALTHY", "DRIFT", "DEFERRED_MAINTENANCE", "HEALTHY"])
        self.assertEqual(d[2]["reasons"], ["maintenance in progress for 12 min: holder=maint label=fx-window id=" + common.MASK + " since=2099-01-03T02:50:00+08:00"])
        mr = doc["merge_requests"]
        self.assertEqual((len(mr["open"]), mr["last_merged"]["iid"], mr["last_merged"]["approvals"]), (1, 99000, 0))
        mi = doc["monitor_issues"]["items"]
        self.assertEqual([(i["iid"], i["outcome"]) for i in mi], [(99011, "monitor failure"), (99010, "UNHEALTHY")])
        self.assertEqual(doc["reservations"]["open"][0]["iid"], 99020)
        self.assertEqual((doc["token"]["days_left"], doc["token"]["warn"], doc["token"]["broader_than_read_api"]), (14, True, False))
        self.assertEqual(doc["monitor_token"]["expires_at"], "2026-10-31")
        text = T.read(self.cfg, "gitlab.json")
        self.assertNotIn("Kubernetes NotReady", text)               # confidential issue titles: the outcome word only
        self.assertNotIn(T.DUMMY_TOKEN, text)
        self.assertClean(text)

    def test_token_expiry_amber_at_14_days(self):
        self.assertFalse(gitlab.token_line("2099-01-21", self.NOW, "x")["warn"])    # 15 days
        self.assertTrue(gitlab.token_line("2099-01-20", self.NOW, "x")["warn"])     # 14 days
        self.assertTrue(gitlab.token_line("", self.NOW, "x")["warn"])
        self.assertTrue(gitlab.token_line("not a date", self.NOW, "x")["warn"])
        monitor = gitlab.token_line("2026-10-31", int(common.parse_iso("2026-10-17T00:00:00+08:00")), "x")
        self.assertEqual((monitor["days_left"], monitor["warn"]), (14, True))

    def test_the_cache_saves_calls_and_keeps_only_what_is_shown(self):
        first, second, third = [], [], []
        for calls in (first, second, third):
            gitlab.run(self.cfg, self.NOW, get=T.fake_get(calls=calls))
        self.assertEqual([len([c for c in run if "/artifacts/" in c]) for run in (first, second, third)], [3, 1, 0])   # 3 per run, then cached
        self.assertLess(len(third), len(first))
        self.assertFalse(any("/pipelines/990105/jobs" in c for c in third))    # finished: cached
        self.assertTrue(any("/pipelines/990106/jobs" in c for c in third))     # running: asked again
        cache = json.load(open(os.path.join(self.cfg["state_dir"], "gitlab-cache.json")))
        self.assertEqual(oct(os.stat(os.path.join(self.cfg["state_dir"], "gitlab-cache.json")).st_mode & 0o777), "0o600")
        self.assertEqual(set(cache["approvals"]), {"99000"})

    def test_http_errors_are_per_section_with_status_never_the_token(self):
        doc = self.run_gl(fail={"/projects/:id/issues": 401, "/projects/:id/merge_requests": 500})
        self.assertEqual(doc["monitor_issues"], {"error": "GET /projects/:id/issues: HTTP 401", "status": 401})
        self.assertEqual(doc["merge_requests"]["status"], 500)
        self.assertNotIn("error", doc["pipelines"])
        out = T.read(self.cfg, "gitlab.json") + open(os.path.join(self.cfg["state_dir"], "gitlab-cache.json")).read()
        self.assertNotIn(T.DUMMY_TOKEN, out)

    def test_unexpected_shapes_are_errors(self):
        resp = T.responses()
        for k in resp:
            if k.startswith("/projects/:id/merge_requests?"):
                resp[k] = {"message": "not a list"}
        doc = gitlab.run(self.cfg, self.NOW, get=T.fake_get(resp))
        self.assertIn("unexpected response shape", doc["merge_requests"]["error"])

    def test_no_token_file_is_a_named_error_and_still_writes(self):
        os.unlink(self.cfg["gitlab"]["token_file"])
        doc = gitlab.run(self.cfg, self.NOW)
        self.assertIn("no usable GitLab token", doc["error"])
        self.assertIn("monitor_token", json.loads(T.read(self.cfg, "gitlab.json")))

    def test_freeze_flag_is_owner_set_or_unknown(self):
        self.assertEqual(gitlab.read_freeze(self.cfg["freeze_file"])["state"], "unknown")
        for content, want in (('{"state": "frozen", "note": "native window", "set_at": "2026-10-05T08:00:00+08:00"}', "frozen"),
                              ('{"state": "maybe"}', "unknown"), ("not json", "unknown"), ('{"state": "open"}', "open")):
            with open(self.cfg["freeze_file"], "w") as f:
                f.write(content)
            self.assertEqual(gitlab.read_freeze(self.cfg["freeze_file"])["state"], want)

    def test_get_is_the_only_method(self):
        # R1: the collectors issue no write. Only GET appears as a request method anywhere.
        for name in ("prace_dash_gitlab.py", "prace_dash_observe.py", "prace_dash_evidence.py", "prace_dash_common.py"):
            src = open(os.path.join(T.FILES, name)).read()
            for method in ('"POST"', '"PUT"', '"PATCH"', '"DELETE"', "'POST'", "'PUT'", "'PATCH'", "'DELETE'"):
                self.assertNotIn(method, src, name)
        self.assertEqual(open(os.path.join(T.FILES, "prace_dash_gitlab.py")).read().count('conn.request("GET"'), 1)


class SecuritySimulation(Env):
    def load_sample(self, name="acl-write-nemo-20261008"):
        folder = os.path.join(self.tmp, "sample")
        shutil.copytree(os.path.join(T.HERE, "fixtures/security-simulations", name), folder)
        return folder

    def read_sample(self, folder):
        checked = evidence.verify(folder)
        self.assertEqual(checked["state"], "ok")
        return evidence.scenario(folder, "simulation/sample", checked["files"], evidence.load_trust())

    def rewrite(self, folder, file, change):
        path = os.path.join(folder, file)
        with open(path) as stream:
            data = json.load(stream)
        change(data)
        with open(path, "w") as stream:
            json.dump(data, stream)
        # Rehash deliberately: these regressions test the semantic gate beyond checksums.
        import hashlib
        names = sorted(n for n in os.listdir(folder) if n != "SHA256SUMS")
        with open(os.path.join(folder, "SHA256SUMS"), "w") as stream:
            for name in names:
                with open(os.path.join(folder, name), "rb") as content:
                    digest = hashlib.sha256(content.read()).hexdigest()
                stream.write(f"{digest}  {name}\n")

    def test_real_read_and_write_exports_load_the_typed_chain(self):
        for name in ("acl-write-nemo-20261008", "canary-read-nemo-20261008"):
            folder = self.load_sample(name)
            run = self.read_sample(folder)
            sim = run["simulation"]
            self.assertTrue(sim["verified"])
            self.assertIs(sim["fleet_contacted"], False)
            self.assertEqual(sim["proof_scope"]["scheduler"], "simulated-accounting")
            self.assertEqual(len(sim["events"]), 9)
            self.assertEqual({e["trust"] for e in run["events"]}, {"co-located", "actor-written"})
            shutil.rmtree(folder)

    def test_changed_binding_is_refused_even_with_fresh_checksums(self):
        folder = self.load_sample()
        self.rewrite(folder, "summary.json", lambda data: data.update(private_bundle_index_sha256="0" * 64))
        with self.assertRaisesRegex(ValueError, "binding mismatch"):
            self.read_sample(folder)

    def test_invalid_event_order_and_duplicate_are_refused(self):
        for change in (lambda data: data["events"][1].update(sequence=1),
                       lambda data: data["events"][1].update(id=data["events"][0]["id"]),
                       lambda data: data["events"][1].update(status="PASS")):
            folder = self.load_sample()
            self.rewrite(folder, "summary.json", change)
            with self.assertRaisesRegex(ValueError, "malformed security simulation event"):
                self.read_sample(folder)
            shutil.rmtree(folder)

    def test_missing_summary_refuses_new_format_instead_of_hiding_chain(self):
        folder = self.load_sample()
        checked = evidence.verify(folder)
        with open(os.path.join(folder, "capture.json")) as stream:
            capture = json.load(stream)
        with self.assertRaisesRegex(ValueError, "no verified summary"):
            evidence.simulation(folder, [f for f in checked["files"] if f != "summary.json"], capture)

    def test_failed_verifier_claim_is_not_approved(self):
        folder = self.load_sample()
        self.rewrite(folder, "capture.json", lambda data: data["source"].update(harness_verify="REFUSED"))
        self.assertFalse(self.read_sample(folder)["simulation"]["verified"])

    def test_model_assisted_recording_is_distinguished_from_model_free_replay(self):
        folder = self.load_sample()
        self.rewrite(folder, "capture.json", lambda data: data["source"].update(llm_used=True, model="glm-5.2"))
        self.rewrite(folder, "summary.json", lambda data: data.update(model_used=True, model="glm-5.2"))
        self.assertTrue(self.read_sample(folder)["simulation"]["verified"])


class Evidence(Env):
    def build(self, root=T.REPO):
        return evidence.build(root, "0" * 40, NOW)

    def test_the_committed_window_t87_t88(self):
        doc = self.build()
        win = [r for r in doc["acceptance"] if r["window"] == "2026-10-04/window-t87-t88"]
        got = [(r["phase"], r["suite"], r["attempt"], r["result"], r["passed"], r["failed"], r["pin"]) for r in win]
        self.assertIn((4, "storage", 1, "failed", 28, 8, "M"), got)             # the failed attempt is a real row
        self.assertIn((4, "storage", 2, "passed", 36, 0, "M1"), got)
        self.assertIn((4, "policy-payg", None, "passed", 104, 0, "M1"), got)
        self.assertIn((7, "env", None, "passed", 23, 0, "M2"), got)
        self.assertIn((8, "platform", None, "passed", 129, 0, "M2"), got)
        self.assertIn((7, "apps-repo", 1, "stopped", None, None, "M1"), got)
        failed = next(r for r in win if r["result"] == "failed")
        self.assertEqual(failed["wrapper"], {"name": "wrapper-p4-storage.json", "command_rc": 1, "phase": "stopped",
                                             "containment": "fenced_quiet", "lease_id": "af7d79c031a9eb04"})
        self.assertEqual(failed["ended_local"], "2026-10-04 14:17:51")
        self.assertTrue(all(r["cross_check"]["agrees"] for r in win if r["passed"] is not None))
        self.assertEqual(len([r for r in win if r.get("wrapper_only")]), 2)     # the open-shares steps
        pts = [p for p in doc["recovery_points"] if p["folder"] == "2026-10-04/window-t87-t88"]
        self.assertEqual([(p["label"], p["accepted"], p["artifacts"]) for p in pts],
                         [("P1 pre-change", True, 26), ("P5 intermediate (reset point for T88)", True, 26), ("P9 final", True, 26)])
        self.assertEqual(pts[-1]["id"], "79ecd8a56f794ef68f05ca31b4aacac0")
        self.assertEqual(pts[-1]["created"], int(common.parse_iso("2026-10-04T08:51:51.964292+00:00")))
        self.assertEqual(pts[-1]["bytes"], 83242555)
        text = json.dumps(doc)
        self.assertNotIn("prace-recovery", text)                                 # the private run dir is never kept
        self.assertNotIn("run dir", text)
        # production: the NeMo harness rehearsal exported 6 Oct (local, no cluster), and since 7 Oct the
        # researcher session (a user's recording beside the controller's accounting); every committed run reads
        self.assertEqual(doc["scenarios"]["errors"], [])
        self.assertIn("prace-nemo-demo-20261006", [r["run_id"] for r in doc["scenarios"]["runs"]])

    def test_the_hpc_git01_entry_point_scrubs(self):
        shutil.copytree(os.path.join(T.REPO, "evidence", "2026-10-04"), os.path.join(self.tmp, "src", "evidence", "2026-10-04"))
        with open(os.path.join(self.tmp, "src", "SOURCE.json"), "w") as f:
            json.dump({"commit": "a" * 40}, f)
        doc = evidence.run(self.cfg, NOW)
        self.assertEqual((doc["build"], doc["source"]["commit"]), ("scrubbed", "a" * 40))
        p9 = doc["recovery_points"][-1]
        self.assertEqual((p9["id"], p9["borrowed_window"], p9["workers"]), ("id-" + common.MASK, "id-" + common.MASK,
                                                                             ["cpu-worker-1", "gpu-worker-1", "gpu-worker-2", "gpu-worker-3"]))
        self.assertClean(T.read(self.cfg, "evidence.json"))

    def test_archived_terminal_verdict_retains_the_actor_dependency(self):
        run = next(r for r in self.build()["scenarios"]["runs"]
                   if r["run_id"] == "researcher-session-20261007")
        verdict = next(e for e in run["events"] if e["title"].startswith("replay matched:"))
        self.assertEqual(verdict["trust"], "actor-written")
        self.assertEqual(set(verdict["src"]), {"sacct-controller", "user-terminal"})
        jobs = [e for e in run["events"] if e["kind"] == "fleet"]
        self.assertTrue(jobs)
        self.assertTrue(all(e["trust"] == "independent" for e in jobs))

    def test_no_unscrubbed_option_on_the_installed_entry_point(self):
        for args in (["--help"], ["run", "--help"]):
            out = io.StringIO()
            with redirect_stdout(out), self.assertRaises(SystemExit):
                evidence.main(args)
            for flag in ("scrub", "workstation", "private", "raw", "unscrubbed"):
                self.assertNotIn("--" + flag, out.getvalue())
                self.assertNotIn("--no-" + flag, out.getvalue())
        called = []
        real = common.publish
        common.publish = lambda path, doc, scrubber: called.append(type(scrubber).__name__) or doc
        try:
            os.makedirs(os.path.join(self.tmp, "src", "evidence"))
            evidence.run(self.cfg, NOW)
        finally:
            common.publish = real
        self.assertEqual(called, ["Scrubber"])

    def copy_run(self):
        dst = os.path.join(self.tmp, "fx", "evidence", "2099-01-01", "fx-scn-fixture-001")
        shutil.copytree(os.path.join(T.SCENARIO_ROOT, "evidence", "2099-01-01", "fx-scn-fixture-001"), dst)
        return os.path.join(self.tmp, "fx"), dst

    def resum(self, folder):
        import hashlib
        lines = []
        for name in sorted(os.listdir(folder)):
            if name != "SHA256SUMS":
                lines.append(hashlib.sha256(open(os.path.join(folder, name), "rb").read()).hexdigest() + "  " + name)
        open(os.path.join(folder, "SHA256SUMS"), "w").write("\n".join(lines) + "\n")

    def test_the_synthetic_scenario_run(self):
        run = self.build(T.SCENARIO_ROOT)["scenarios"]["runs"][0]
        self.assertEqual((run["run_id"], run["capture_late"], len(run["events"]), len(run["observations"])), ("fx-scn-fixture-001", False, 11, 2))
        self.assertEqual([e["t"] for e in run["events"]], sorted(e["t"] for e in run["events"]))
        trust = {e["title"]: e["trust"] for e in run["events"]}
        self.assertEqual(trust["Job 990143 NODE_FAIL"], "independent")
        self.assertEqual(trust["Login to the login pod"], "co-located")
        self.assertEqual(trust["slurmd pod restarted"], "co-located")
        self.assertEqual(trust["Job output claims success"], "actor-written")
        mixed = next(e for e in run["events"] if e["title"] == "Job 990151 OOM-killed")
        self.assertEqual((mixed["trust"], [p["trust"] for p in mixed["trust_parts"]]), ("co-located", ["independent", "co-located"]))
        self.assertEqual([a["name"] for a in run["actors"] if a["under_test"]], ["syn-alice"])
        self.assertTrue(all(f["sha256"] for f in run["files"]))

    def test_trust_comes_from_the_table_never_from_the_record(self):
        root, folder = self.copy_run()
        lines = open(os.path.join(folder, "events.jsonl")).read().splitlines()
        e = json.loads(lines[2]); e["trust"] = "independent"; lines[2] = json.dumps(e)     # the sshd line claims T1
        open(os.path.join(folder, "events.jsonl"), "w").write("\n".join(lines) + "\n")
        self.resum(folder)
        run = self.build(root)["scenarios"]["runs"][0]
        self.assertEqual(next(x for x in run["events"] if x["title"] == "Login to the login pod")["trust"], "co-located")
        e = json.loads(lines[3]); e["src"] = "made-up-source"; lines[3] = json.dumps(e)
        open(os.path.join(folder, "events.jsonl"), "w").write("\n".join(lines) + "\n")
        self.resum(folder)
        doc = self.build(root)
        self.assertEqual(doc["scenarios"]["runs"], [])
        self.assertIn("'made-up-source' is not in the trust table", doc["scenarios"]["errors"][0]["error"])

    def test_one_altered_byte_and_nothing_is_rendered(self):
        root, folder = self.copy_run()
        with open(os.path.join(folder, "sacct.txt"), "r+b") as f:
            f.seek(5); b = f.read(1); f.seek(5); f.write(bytes([b[0] ^ 1]))
        doc = self.build(root)
        self.assertEqual(doc["scenarios"]["runs"], [])
        self.assertEqual(doc["folders"][0]["sums"], "mismatch")
        self.assertIn("checksum mismatch", doc["folders"][0]["detail"])

    def test_sums_that_escape_the_folder_or_are_absent(self):
        root, folder = self.copy_run()
        with open(os.path.join(folder, "SHA256SUMS"), "a") as f:
            f.write("0" * 64 + "  ../../../etc/passwd\n")
        self.assertEqual(self.build(root)["folders"][0]["sums"], "invalid")
        os.unlink(os.path.join(folder, "SHA256SUMS"))
        doc = self.build(root)
        self.assertEqual((doc["folders"][0]["sums"], doc["scenarios"]["runs"]), ("absent", []))

    def test_unlisted_files_are_not_read(self):
        root, folder = self.copy_run()
        open(os.path.join(folder, "p9-extra-acceptance-1-0-at-M.txt"), "w").write("PASS: unlisted\n")
        self.assertEqual(self.build(root)["acceptance"], [])

    def test_a_late_capture_is_flagged(self):
        root, folder = self.copy_run()
        cap = json.load(open(os.path.join(folder, "capture.json")))
        cap["captured_at"] = cap["stop"] + 2 * 3600
        json.dump(cap, open(os.path.join(folder, "capture.json"), "w"))
        self.resum(folder)
        self.assertTrue(self.build(root)["scenarios"]["runs"][0]["capture_late"])

    def test_equal_stamps_keep_the_capture_order(self):
        root, folder = self.copy_run()
        lines = [json.loads(l) for l in open(os.path.join(folder, "events.jsonl"))]
        for e in lines[2:5]:
            e["t"] = lines[2]["t"]
        open(os.path.join(folder, "events.jsonl"), "w").write("".join(json.dumps(e) + "\n" for e in lines))
        self.resum(folder)
        run = self.build(root)["scenarios"]["runs"][0]
        same = [e["title"] for e in run["events"] if e["t"] == lines[2]["t"]]
        self.assertEqual(same, [lines[2]["title"], lines[3]["title"], lines[4]["title"]])

    def test_an_evidence_path_outside_the_verified_files_is_refused(self):
        root, folder = self.copy_run()
        lines = open(os.path.join(folder, "events.jsonl")).read().splitlines()
        e = json.loads(lines[0]); e["ev"] = "../../secret.txt"; lines[0] = json.dumps(e)
        open(os.path.join(folder, "events.jsonl"), "w").write("\n".join(lines) + "\n")
        self.resum(folder)
        self.assertIn("outside this run", self.build(root)["scenarios"]["errors"][0]["error"])

    def test_select_lists_the_folders_the_role_ships(self):
        out = io.StringIO()
        with redirect_stdout(out):
            evidence.main(["select", "--repo", T.REPO])
        sel = json.loads(out.getvalue())
        self.assertIn("2026-10-04/window-t87-t88", sel)
        self.assertIn("2026-09-30/session-a-physical-storage", sel)
        self.assertTrue(all(not s.startswith("/") and ".." not in s for s in sel))


class Scrub(unittest.TestCase):
    @staticmethod
    def make():
        with open(os.path.join(T.FILES, "scrub-map.json")) as f:
            m = json.load(f)
        return common.Scrubber(m["hosts"], m["aliases"], T.ACCOUNTS, {"mgmt-git01.example-tailnet.ts.net": "mgmt-vm"})

    def setUp(self):
        self.s = self.make()

    def test_every_extended_c4_category(self):
        cases = {"02:00:00:00:00:03": "mac-masked", "0000:88:00.1": "pci-masked", "10.42.3.0/24": "addr-masked",
                 "10.42.3.30": "addr-masked", "fe80::1": "addr-masked", "slurm-login-prace-97fd499f-fbc7v": "slurm-login-prace-\u2022\u2022\u2022\u2022\u2022",
                 "slurm-worker-gpu-6lz6n": "slurm-worker-gpu-\u2022\u2022\u2022\u2022\u2022", "mgmt-git01.example-tailnet.ts.net": "mgmt-vm",
                 "79ecd8a56f794ef68f05ca31b4aacac0": "id-" + common.MASK, "b30f910591f4aba9": "id-" + common.MASK,
                 "id=b30f910591f4aba9": "id=" + common.MASK, "lab-g004": "gpu-worker-2", "syn-alice": "actor-A",
                 "agent-perm01": "agent-A", "fx-member-one": "member-1", "/home/syn-bob/out": "/home/<user>/out",
                 "~/prace-recovery/runs/x": "<private recovery path>", "14126072-841a-4177-a3bd-eca04101890a": "uuid-masked",
                 "GPU-2f2838d0-bcd5-7e53-c277-1a4c553a42ef": "GPU-uuid-masked"}
        for raw, want in cases.items():
            self.assertEqual(self.s.text(raw), want, raw)

    def test_what_is_not_an_identifier_survives(self):
        for keep in ("14:00:09", "2026-10-05T01:19:07+08:00", "580.173.02-1.el9", "v1.36.4+k3s1", "25.11.8-rockylinux9",
                     "5a394be204c78cf5ccc38c62a4ec9d100920410e", "cb90325bd9e80882d8bcfd56b07b0e8f45d756b91117e9db5f0a60d1d2278913",
                     "slurm-controller-0", "proj-alpha", "gpu:8(S:0-1)", "/etc/exports.d/fleet-home.exports", "rw,nosuid,nodev,relatime"):
            self.assertEqual(self.s.text(keep), keep)

    def test_the_mapping_is_total_for_the_fleet_and_accounts_in_the_repository(self):
        with open(T.PROFILE) as f:
            exp = json.load(f)["expected"]
        self.assertEqual(set(json.load(open(os.path.join(T.FILES, "scrub-map.json")))["hosts"]), {exp["login"], *exp["workers"]})
        accounts = open(os.path.join(T.REPO, "infra", "inventories", "fleet", "group_vars", "all", "accounts.yml")).read()
        import re
        users = re.findall(r"\{name: ([a-z0-9._-]+), uid: \d+, groups: \[([^\]]*)\]", accounts)
        lists = {k: [n for n, g in users if k in g.split(", ")] for k in ("synthetic", "agents", "team")}
        s = common.Scrubber(json.load(open(os.path.join(T.FILES, "scrub-map.json")))["hosts"], {}, lists)
        for name, _ in users:
            self.assertNotEqual(s.text(name), name, name)
        doc = {"users": [n for n, _ in users], "hosts": list(T.FLEET)}
        self.assertEqual(s.residue(s.scrub(doc)), [])

    def test_residue_catches_a_planted_leak(self):
        self.assertEqual(self.s.residue({"a": "fine"}), [])
        for leak, cat in (("10.90.10.1", "ipv4"), ("lab-dl380", "fleet_host"), ("02:00:00:00:00:03", "mac"), ("syn-zed", "synthetic_user"),
                          ("af7d79c031a9eb04", "hex16"), ("0000:5d:00.0", "pci"), ("x.example-tailnet.ts.net", "tailnet"),
                          ("UUID: GPU-2f2838d0-bcd5-7e53-c277-1a4c553a42ef", "gpu_uuid")):
            self.assertIn(cat, self.s.residue({"k": leak}), leak)
        self.assertIn("fleet_host", self.s.residue({"lab-dl380": 1}))           # keys too

    def test_keys_that_collide_after_mapping_are_all_kept(self):
        out = self.s.scrub({"slurm-worker-gpu-5mqpf": 1, "slurm-worker-gpu-6lf4c": 2})
        self.assertEqual(sorted(out.values()), [1, 2])



class ReviewFindings(Env):
    """regressions for the independent review of 5 Oct (one test per finding)"""

    def test_m1_native_mounts_of_any_shape_never_crash(self):
        for bad in ([], "x", 7, None, {"/home": "not a mapping"}):
            o = copy.deepcopy(UNLEASED)
            o["native_hosts"] = {"lab-lenovo": T.native_report(t=NOW - 20, mounts=bad)}
            doc = self.observe(o)
            self.assertIn("native", doc["hosts"][1])

    def test_m2_surrogates_controls_nan_and_long_monitor_reasons(self):
        o = copy.deepcopy(UNLEASED)
        o["nodes"]["lab-g003"]["slurm_state"] = "idle\ud800"
        o["slurm_config"]["GresTypes"] = "\x08abcdef012345678"            # JSON-escaped, this once looked like 16 hex
        doc = self.observe(o, reasons=["x" * 5000])
        self.assertEqual(doc["hosts"][2]["slurm_state"], "idle?")
        self.assertEqual(len(doc["monitor"]["reasons"][0]), 4096)             # clipped, not a lost banner
        text = T.read(self.cfg, "latest.json")
        self.assertIn('"abcdef012345678"', text)
        T.write_monitor(self.cfg, NOW)
        with open(self.cfg["monitor"]["observation"], "w") as f:
            f.write(json.dumps(UNLEASED).replace('"duration_s": 6.3', '"duration_s": NaN'))
        doc = observe.run(self.cfg, NOW)
        self.assertIsNone(doc["observation"])
        self.assertNotIn("NaN", T.read(self.cfg, "latest.json"))
        with self.assertRaises(ValueError):
            common.write_json(os.path.join(self.tmp, "x.json"), {"v": float("nan")})

    def test_m3_branch_owners_are_masked(self):
        resp = T.responses()
        for k, v in resp.items():
            if k.startswith("/projects/:id/pipelines?") and isinstance(v, list):
                for p in v:
                    p["ref"] = "fx-owner/" + p["ref"].split("/")[-1] if p["ref"] != "main" else "main"
        doc = gitlab.run(self.cfg, GitLab.NOW, get=T.fake_get(resp))
        refs = {p["ref"] for p in doc["pipelines"]["items"]}
        self.assertIn("main", refs)
        self.assertTrue(all(r == "main" or r.startswith("\u2022\u2022\u2022/") for r in refs), refs)
        self.assertNotIn("fx-owner", T.read(self.cfg, "gitlab.json"))
        self.assertTrue(doc["merge_requests"]["open"][0]["source_branch"].startswith("\u2022\u2022\u2022/"))

    def _run_folder(self):
        root = os.path.join(self.tmp, "ev")
        shutil.copytree(os.path.join(T.SCENARIO_ROOT, "evidence"), os.path.join(root, "evidence"))
        return root, os.path.join(root, "evidence", "2099-01-01", "fx-scn-fixture-001")

    def test_m4_links_never_lead_out_of_a_folder(self):
        root, folder = self._run_folder()
        outside = os.path.join(self.tmp, "outside")
        os.makedirs(outside)
        open(os.path.join(outside, "secret.json"), "w").write('{"schema": 1, "time": 4070912400, "secret": "OUTSIDE"}')
        os.symlink(outside, os.path.join(folder, "sub"))
        doc = evidence.build(root, None, NOW)
        self.assertEqual(doc["folders"][0]["sums"], "invalid")
        self.assertNotIn("OUTSIDE", json.dumps(doc))
        out = io.StringIO()
        with redirect_stdout(out):
            evidence.main(["select", "--repo", root])
        self.assertEqual(json.loads(out.getvalue()), [])                     # never shipped either
        os.unlink(os.path.join(folder, "sub"))
        with open(os.path.join(folder, "SHA256SUMS"), "a") as f:
            f.write("0" * 64 + "  bad\0name\n")
        self.assertEqual(evidence.build(root, None, NOW)["folders"][0]["sums"], "invalid")

    def test_l8_deep_json_in_evidence_never_crashes(self):
        root, folder = self._run_folder()
        open(os.path.join(folder, "wrapper-p9-deep.json"), "w").write("[" * 100000 + "]" * 100000)
        Evidence.resum(self, folder)
        doc = evidence.build(root, None, NOW)
        self.assertEqual(len(doc["scenarios"]["runs"]), 1)

    def test_l9_folders_removed_from_git_are_not_shown(self):
        root, folder = self._run_folder()
        with open(os.path.join(root, "SOURCE.json"), "w") as f:
            json.dump({"commit": "b" * 40, "folders": []}, f)
        self.cfg["evidence"]["source"] = root
        self.assertEqual(evidence.run(self.cfg, NOW)["scenarios"]["runs"], [])

    def test_l10_odd_gitlab_shapes_are_section_errors(self):
        resp = T.responses()
        resp["/personal_access_tokens/self"]["scopes"] = "read_api"
        resp["/projects/:id/merge_requests/99000/approvals"] = {"approved_by": 3}
        for k, v in resp.items():
            if "/artifacts/" in k:
                v["reasons"] = "not a list"
            if k.startswith("/projects/:id/pipelines?per_page"):
                v[0]["status"] = ["running"]
        doc = gitlab.run(self.cfg, GitLab.NOW, get=T.fake_get(resp))
        self.assertEqual(doc["token"]["scopes"], [])
        self.assertIsNone(doc["merge_requests"]["last_merged"]["approvals"])
        self.assertEqual(doc["drift_audit"]["items"][0]["reasons"], [])
        self.assertIn("items", doc["pipelines"])

    def test_l6_scrub_is_case_and_boundary_robust_and_residue_independent(self):
        s = Scrub.make()
        for raw in ("LAB-G003", "slurm-worker-g003-0", "node.g003", "B30F910591F4ABA9", "Syn-Alice", "Fx-Member-One",
                    "~operator/prace-recovery/x", "$HOME/prace-recovery/a", "tailabc123", "ip.10.42.1.51", "10.042.001.051",
                    "coredns-5d78c9869d-x2x7z"):
            out = s.text(raw)
            self.assertEqual(s.residue([out]), [], (raw, out))
            self.assertNotEqual(out, raw, raw)
        self.assertIn("mapped_identifier", s.residue(["xx-LAB-DL380-yy"]))      # found even inside other words

    def test_l7_hostile_strings_stay_linear(self):
        import time
        s = Scrub.make()
        for hostile in ("a-" * 2048, "a@" * 2048, "slurm-" * 680, "1." * 2048, ":" * 4096, "-a" * 2000 + ".example-tailnet.ts.net",
                        "a." * 2000 + "@x", "hpc-" * 1000, "prace-recovery" * 300, "0" * 4096):
            t0 = time.perf_counter()
            s.residue([s.text(hostile)])
            self.assertLess(time.perf_counter() - t0, 0.25, hostile[:12])


class Review06Oct(Env):
    """regressions for the independent review of 6 Oct (R2 lease, R3 acceptance; R1 is in the page tests)"""

    def test_r2_an_unstated_lease_is_never_no_lease_or_an_open_window(self):
        for bad in ("missing", None, {}, "", "yes", {"held": "false"}, {"held": None}, {"held": 0}, {"holder": "x"}):
            with self.subTest(bad=bad):
                o = copy.deepcopy(UNLEASED)
                if bad == "missing":
                    o.pop("lease", None)
                else:
                    o["lease"] = bad
                doc = self.observe(o)
                self.assertEqual(doc["lease"], {"stated": False})
                self.assertEqual(doc["window"]["phase"], "unknown")
                self.assertNotIn("no lease", doc["window"]["text"])

    def test_r2_explicit_lease_statements_keep_their_phases(self):
        self.assertEqual(self.observe(copy.deepcopy(UNLEASED))["window"]["phase"], "open")       # held: false
        doc = self.observe(copy.deepcopy(LEASED))
        self.assertTrue(doc["lease"]["held"])
        self.assertNotEqual(doc["window"]["phase"], "unknown")

    def acc(self, transcript_rc=0, wrapper=None, name="p9-fx-acceptance-36-0-at-M.txt", transcript=True):
        folder = os.path.join(self.tmp, "acc")
        os.makedirs(folder, exist_ok=True)
        files = []
        if transcript:
            body = "".join(f"PASS check {i}\n" for i in range(36)) + f"p9-fx rc={transcript_rc}\n12:00:00\n"
            with open(os.path.join(folder, name), "w") as f:
                f.write(body)
            files.append(name)
        if wrapper is not None:
            with open(os.path.join(folder, "wrapper-p9-fx.json"), "w") as f:
                f.write(wrapper if isinstance(wrapper, str) else json.dumps(wrapper))
            files.append("wrapper-p9-fx.json")
        rows = evidence.acceptance(folder, "2026-10-06/fx", files)
        self.assertEqual(len(rows), 1)
        return rows[0]

    def test_r3_a_failed_wrapper_beats_a_transcript_rc_0(self):
        r = self.acc(0, {"command_rc": 1, "phase": "failed", "containment": "fenced_quiet", "lease_id": "0" * 16})
        self.assertEqual(r["result"], "failed")
        self.assertIn("transcript rc=0 but the wrapper says failed (command_rc 1)", r["conflicts"])
        self.assertTrue(r["cross_check"]["agrees"])          # the counts agree; the wrapper still decides

    def test_r3_an_unreadable_or_malformed_wrapper_is_never_a_pass(self):
        for w in ("{not json", '"a string"', {"phase": "passed"}, {"command_rc": 0}, {"command_rc": True, "phase": "passed"},
                  {"command_rc": "0", "phase": "passed"}, {"command_rc": 0, "phase": ""}):
            with self.subTest(wrapper=w):
                r = self.acc(0, w)
                self.assertEqual(r["result"], "failed")
                self.assertIn("wrapper record unreadable or malformed", r["conflicts"])

    def test_r3_a_passed_wrapper_with_a_failing_transcript_is_a_conflict(self):
        r = self.acc(1, {"command_rc": 0, "phase": "passed"})
        self.assertEqual(r["result"], "failed")
        self.assertIn("transcript rc=1 but the wrapper says passed", r["conflicts"])

    def test_r3_agreeing_records_pass_without_a_conflict(self):
        r = self.acc(0, {"command_rc": 0, "phase": "passed"})
        self.assertEqual((r["result"], r["conflicts"]), ("passed", []))

    def test_r3_legacy_transcripts_without_a_wrapper(self):
        self.assertEqual((self.acc(0)["result"], self.acc(0)["conflicts"]), ("passed", []))
        self.assertEqual(self.acc(2)["result"], "failed")
        self.assertEqual(self.acc(0, name="p9-fx-acceptance-failed-36-0-at-M.txt")["result"], "failed")

    def test_r3_a_malformed_wrapper_alone_is_a_failed_row(self):
        r = self.acc(wrapper={"phase": "passed"}, transcript=False)
        self.assertEqual((r["result"], r["wrapper_only"]), ("failed", True))
        self.assertIn("wrapper record unreadable or malformed", r["conflicts"])


def cast(frames, width=120, height=32):
    """an asciicast v2 recording from (t, text) output frames"""
    return "\n".join([json.dumps({"version": 2, "width": width, "height": height, "timestamp": 1791343353})]
                     + [json.dumps([t, "o", x]) for t, x in frames]) + "\n"


class Playback(Env):
    """8 Oct: a terminal-session run's screens are published as complete, scrubbed logical lines"""

    def screen(self, frames, width=120):
        lines, dur = evidence.terminal_lines(cast(frames, width), width, 32)
        final, out, want = {}, [], None
        for t, row, began, text, rows in lines:
            final[row] = (text, rows)
        for row in sorted(final):                                      # as the page does: blank rows between lines
            out += [""] * (row - want if want is not None else 0)
            out.append(final[row][0]); want = row + max(1, final[row][1])
        return lines, out, dur

    def test_the_emulator_reads_a_shell_session(self):
        frames = [(0.0, "\x1b]0;syn-carol@login:~\x07[PRACE syn-carol ~]$ "),
                  (0.5, "\x1b[?2004h")]
        t = 1.0
        for ch in "ls -l /tmpx":                                   # typed one character per frame, with a slip
            frames.append((t, ch)); t += 0.1
        frames += [(t, "\b\x1b[K"), (t + 0.1, "\r\n\x1b[?2004l\r"), (t + 0.2, "total 0\r\n\r\nlast line\r\n[PRACE syn-carol ~]$ ")]
        lines, screen, dur = self.screen(frames)
        self.assertEqual(screen, ["[PRACE syn-carol ~]$ ls -l /tmp", "total 0", "", "last line", "[PRACE syn-carol ~]$"])
        self.assertTrue(all("\x1b" not in e[3] and "2004" not in e[3] for e in lines))   # titles and modes are not text
        typed = [e[3] for e in lines if e[1] == 0]
        self.assertEqual(typed, ["[PRACE syn-carol ~]$ ls -l /tmp"])       # never a half-typed state
        self.assertEqual(dur, round(t + 0.2, 3))

    def test_soft_wraps_join_one_logical_line_and_readline_wrap_trick(self):
        long = "x" * 25
        frames = [(0.0, "$ "), (0.1, long[:8]), (0.2, " \r" + long[8:]), (0.3, "\r\nok\r\n")]    # readline: ' \r' at the margin
        lines, screen, _ = self.screen(frames, width=10)
        self.assertEqual(screen[0], "$ " + long)
        rows = [e for e in lines if e[3] == "$ " + long][0][4]
        self.assertEqual(rows, 3)                                      # 27 characters over 10 columns
        self.assertEqual(screen[1], "ok")

    def test_a_pause_never_publishes_an_intermediate_line(self):
        frames = [(0.0, "$ "), (3.0, "e"), (3.1, "x"), (3.2, "it\r\n")]
        lines, _, _ = self.screen(frames)
        self.assertEqual([e[3] for e in lines if e[1] == 0], ["$ exit"])
        self.assertEqual([e for e in lines if e[3] == "$ exit"][0][2], 0.0)   # the interpolation spans first to last change

    def test_a_paused_gpu_identifier_is_scrubbed_as_one_complete_line(self):
        prefix = "GPU-abcdef12-3456-789a-bcde-12345678"
        lines, _, _ = self.screen([(0.0, prefix), (3.0, "9abc\r\n")])
        clean = common.Scrubber({}).scrub(lines)
        self.assertEqual([e[3] for e in clean], ["GPU-uuid-masked"])
        self.assertNotIn(prefix, json.dumps(clean))

    def test_cursor_and_insert_counts_are_bounded_before_allocation(self):
        for escape in ("\x1b[100000000B", "\x1b[100000000E", "\x1b[100000000;1H", "\x1b[100000000;1f"):
            with self.subTest(escape=escape):
                with self.assertRaisesRegex(ValueError, "row limit"):
                    self.screen([(0.0, escape)])
        _, screen, _ = self.screen([(0.0, "hello\r\x1b[100000000@")])
        self.assertEqual(screen, [""])  # insertion is capped at the terminal width

    def test_oversized_lines_and_unfinished_escapes_are_not_truncated(self):
        for text, why in (("x" * (evidence.LINE_MAX + 1), "text limit"), ("hello\x1b[", "incomplete")):
            with self.subTest(why=why), self.assertRaisesRegex(ValueError, why):
                self.screen([(0.0, text)])

    def test_bad_recordings_are_withheld_with_a_reason(self):
        for text, why in ((cast([(1.0, "a"), (0.5, "b")]), "time order"), ("not json\n", "asciicast v2"),
                          (cast([(0.0, "\x1b[100000000B")]), "row limit"),
                          (cast([(0.0, "x" * (evidence.LINE_MAX + 1))]), "text limit")):
            with self.subTest(why=why), tempfile.TemporaryDirectory() as d:
                os.makedirs(os.path.join(d, "terminal"))
                with open(os.path.join(d, "terminal", "original.cast"), "w") as f:
                    f.write(text)
                out = evidence.terminals(d, ["terminal/original.cast"], {"source": {"kind": "terminal-session"}})
                self.assertIn(why, out[0]["withheld"])
        self.assertEqual(evidence.terminals(self.tmp, ["terminal/original.cast"], {"source": {"kind": "harness-bundle"}}), [])

    def test_the_committed_terminal_runs_publish_scrubbed(self):
        doc = evidence.build(T.REPO, "0" * 40, NOW)
        runs = [r for r in doc["scenarios"]["runs"] if r.get("terminal")]
        if not runs:
            self.skipTest("no committed terminal-session run")
        sc = common.Scrubber.from_config(self.cfg)
        out = common.publish(os.path.join(self.cfg["www_data"], "evidence.json"), evidence.vet_terminals(doc, sc), sc)
        for run in out["scenarios"]["runs"]:
            for term in run.get("terminal") or []:
                with self.subTest(run=run["run_id"], screen=term["name"]):
                    self.assertNotIn("withheld", term)
                    text = "\n".join(e[3] for e in term["lines"])
                    self.assertIn("logout", text)
                    self.assertIn("actor-C", text)
                    for leak in ("syn-carol", "tailabc123", "lab", "example-lab", "GPU-2f2838d0"):
                        self.assertNotIn(leak, text)
                    self.assertEqual(sc.residue(term), [])

    def test_a_screen_with_residue_is_withheld_not_the_whole_file(self):
        doc = evidence.build(T.REPO, "0" * 40, NOW)
        if not any(r.get("terminal") for r in doc["scenarios"]["runs"]):
            self.skipTest("no committed terminal-session run")

        class Strict(common.Scrubber):
            def residue(self, d):                                     # a leak the rules missed, in one screen only
                return ["planted"] if "logout" in json.dumps(d) and isinstance(d, dict) and d.get("name") == "replay" else super().residue(d)

        base = common.Scrubber.from_config(self.cfg)
        sc = Strict(base.exact and {}, None, None, None)
        sc.exact, sc.exact_rx = base.exact, base.exact_rx
        out = evidence.vet_terminals(doc, sc)
        terms = [t for r in out["scenarios"]["runs"] for t in r.get("terminal") or []]
        self.assertTrue(any(t["name"] == "replay" and "residue after scrubbing: planted" in t.get("withheld", "") for t in terms))
        self.assertTrue(any(t["name"] == "original" and "lines" in t for t in terms))


if __name__ == "__main__":
    unittest.main()

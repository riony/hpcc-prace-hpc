#!/usr/bin/env python3
"""Offline tests for tools/k3s-login-backup.sh with a stateful fake ssh (PRACE_SSH) and scp
(PRACE_SCP). The backup must capture only inside an enforced maintenance window: the cluster lease
is taken and every partition is drained (plus login pods stopped for --home) BEFORE quiescence is
checked, so a job that races the first check is still refused (review R3, 28 Sep). Whatever was
fenced must be reopened on every exit, including refusals and failures. A failed queue query is a
refusal, never "0 jobs". No host is contacted."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / "k3s-login-backup.sh"
FAKE_SSH = r'''#!/usr/bin/env python3
import json, os, re, sys
sc = json.load(open(os.environ["SCENARIO"]))
st_path = os.environ["STATE"]
st = json.load(open(st_path)) if os.path.exists(st_path) else {
    "parts": {"cpu": "UP", "gpu": "UP"}, "replicas": 1, "lease": bool(sc.get("lease_held"))}
host = next(i for i, a in enumerate(sys.argv) if a.startswith("root@"))
remote = " ".join(sys.argv[host + 1:])
log = open(os.environ["CALLS"], "a")
open(os.environ["CALLS"].replace("calls", "argv"), "a").write(" ".join(sys.argv[1:host]) + "\n")
def done(rc=0, out=""):
    json.dump(st, open(st_path, "w")); print(out, end=""); sys.exit(rc)
if remote.endswith("bash -s"):
    body = sys.stdin.read()
    if "mysqldump" in body:
        open(os.environ["CALLS"] + ".archive", "w").write(body)
        log.write("ARCHIVE\n"); log.close(); done(sc.get("archive_rc", 1), "ARCHIVE-STAGE\n")
    if "-home.tgz" in body:
        log.write("HOME\n"); log.close(); done(0, "abc  /root/prace-backup/x-home.tgz\n")
    log.write("BASH\n"); log.close(); done(0)
log.write(remote.replace("\n", " ") + "\n"); log.close()
if "prace-slinky-worker-check" in remote:
    done(sc.get("workers_rc", 0), "lab-g003: ok (idle)\n" if sc.get("workers_rc", 0) == 0 else "lab-g003: slurm state 'down*'\n")
if "mkdir /run/prace-cluster-lease" in remote:
    if st["lease"]: done(1)
    st["lease"] = True; done(0)
if "cat /run/prace-cluster-lease/holder" in remote:
    done(0, "holder=slinky-acceptance id=ffff\n")
if "rm -rf /run/prace-cluster-lease" in remote:
    st["lease"] = False; done(0)
if "scontrol show partition -o" in remote:
    done(sc.get("partition_query_rc", 0),
         "".join(f"PartitionName={p} AllowGroups=ALL State={s} TotalCPUs=4\n" for p, s in st["parts"].items()))
m = re.search(r"scontrol update PartitionName=(\S+) State=(\S+)", remote)
if m:
    if m.group(2) == "DRAIN" and sc.get("drain_fail") == m.group(1): done(1)
    st["parts"][m.group(1)] = m.group(2); done(0)
if "squeue" in remote:
    done(sc.get("queue_rc", 0), sc.get("queue", ""))
if "get loginset" in remote:
    done(0, f"slurm-login-prace={st['replicas']}\n")
m = re.search(r'patch loginset \S+ .*"replicas":(\d+)', remote)
if m:
    if int(m.group(1)) > 0 and st.get("patch_failures", 0) < sc.get("reopen_patch_fails", 0):
        st["patch_failures"] = st.get("patch_failures", 0) + 1; done(1)   # webhook without endpoints
    st["replicas"] = int(m.group(1)); done(0)
if "app.kubernetes.io/name=login" in remote:
    running = st["replicas"] or sc.get("login_pods_stay")
    if "--no-headers" in remote:
        done(0, "slurm-login-prace-x   1/1   Running   0   5s\n" if running else "")
    done(0, "pod/slurm-login-prace-x\n" if running else "")
done(0)
'''
FAKE_SCP = '#!/bin/sh\necho SCP >> "$CALLS"\nexit 1\n'


class Backup(unittest.TestCase):
    def run_backup(self, scenario, home=False):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "ssh").write_text(FAKE_SSH); (d / "scp").write_text(FAKE_SCP)
            for f in ("ssh", "scp"):
                (d / f).chmod(0o755)
            (d / "sc.json").write_text(json.dumps(scenario))
            env = dict(os.environ, PRACE_SSH=str(d / "ssh"), PRACE_SCP=str(d / "scp"), SCENARIO=str(d / "sc.json"),
                       STATE=str(d / "state.json"), CALLS=str(d / "calls"), PRACE_BACKUP_DEST=str(d / "dest"),
                       PRACE_LOGIN_WAIT="2", PRACE_UNFENCE_TRIES="4", PRACE_UNFENCE_SLEEP="0")
            args = ["bash", str(SCRIPT), "--workers", "lab-g003", "--label", "test"] + (["--home"] if home else [])
            r = subprocess.run(args, env=env, capture_output=True, text=True, timeout=60)
            calls = (d / "calls").read_text().splitlines() if (d / "calls").exists() else []
            self.argv_seen = (d / "argv").read_text().splitlines() if (d / "argv").exists() else []
            state = json.loads((d / "state.json").read_text()) if (d / "state.json").exists() else None
            self.archive_script = (d / "calls.archive").read_text() if (d / "calls.archive").exists() else ""
            return r, calls, state

    @staticmethod
    def first(calls, needle):
        return next((i for i, c in enumerate(calls) if needle in c), None)

    def assertReopened(self, state):
        self.assertEqual(state["parts"], {"cpu": "UP", "gpu": "UP"})
        self.assertEqual(state["replicas"], 1)
        self.assertFalse(state["lease"])

    def test_job_racing_the_first_check_is_refused_and_the_window_reopened(self):
        """Review R3: quiescence is checked only after the fence, so a racing job is found."""
        r, calls, state = self.run_backup({"queue": "42\n"})
        self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
        self.assertIn("1 Slurm job(s) queued or running inside the window", r.stdout)
        self.assertLess(self.first(calls, "State=DRAIN"), self.first(calls, "squeue"))
        self.assertNotIn("ARCHIVE", calls)
        self.assertReopened(state)

    def test_failed_queue_query_refuses(self):
        for label, sc in {"query fails, no output": {"queue_rc": 7},
                          "query fails with partial output": {"queue_rc": 1, "queue": "error: slurm_load_jobs\n"}}.items():
            with self.subTest(label):
                r, calls, state = self.run_backup(sc)
                self.assertEqual(r.returncode, 3, r.stdout + r.stderr)
                self.assertIn("queue query failed", r.stdout)
                self.assertNotIn("ARCHIVE", calls)
                self.assertReopened(state)

    def test_unusable_workers_refuse_before_anything_is_fenced(self):
        r, calls, state = self.run_backup({"workers_rc": 1})
        self.assertEqual(r.returncode, 3); self.assertIn("not every expected worker", r.stdout)
        self.assertIsNone(self.first(calls, "mkdir /run/prace-cluster-lease"))
        self.assertIsNone(self.first(calls, "State=DRAIN"))

    def test_held_lease_refuses_without_fencing_or_releasing_it(self):
        r, calls, state = self.run_backup({"lease_held": True})
        self.assertEqual(r.returncode, 3); self.assertIn("the cluster is leased", r.stdout)
        self.assertIsNone(self.first(calls, "State=DRAIN"))
        self.assertIsNone(self.first(calls, "rm -rf /run/prace-cluster-lease"))
        self.assertTrue(state["lease"])

    def test_partial_drain_is_undone(self):
        r, calls, state = self.run_backup({"drain_fail": "gpu"})
        self.assertEqual(r.returncode, 3); self.assertIn("could not drain partition gpu", r.stdout)
        self.assertReopened(state)

    def test_partition_query_failure_refuses(self):
        r, calls, state = self.run_backup({"partition_query_rc": 1})
        self.assertEqual(r.returncode, 3); self.assertIn("partition query failed", r.stdout)
        self.assertReopened(state)

    def test_archive_happens_inside_the_window_and_a_failure_still_reopens(self):
        r, calls, state = self.run_backup({})              # the fake archive step fails
        self.assertNotEqual(r.returncode, 0)
        self.assertLess(self.first(calls, "mkdir /run/prace-cluster-lease"), self.first(calls, "State=DRAIN"))
        self.assertLess(self.first(calls, "State=DRAIN"), self.first(calls, "squeue"))
        self.assertLess(self.first(calls, "squeue"), calls.index("ARCHIVE"))
        self.assertReopened(state)

    def test_home_is_captured_inside_the_window_with_login_stopped(self):
        r, calls, state = self.run_backup({"archive_rc": 0}, home=True)
        self.assertNotEqual(r.returncode, 0)               # the fake scp stops the run after the window
        stop_login = self.first(calls, '"replicas":0')
        reopen = self.first(calls, "State=UP")
        self.assertIsNotNone(stop_login); self.assertIsNotNone(reopen)
        self.assertLess(stop_login, self.first(calls, "squeue"))
        self.assertLess(self.first(calls, "squeue"), calls.index("ARCHIVE"))
        self.assertLess(calls.index("ARCHIVE"), calls.index("HOME"))
        self.assertLess(calls.index("HOME"), reopen)       # /home before anything reopens
        self.assertLess(reopen, calls.index("SCP"))
        self.assertReopened(state)
        self.assertIn("maintenance-window.txt", self.archive_script)

    def test_reopen_retries_a_refused_loginset_patch(self):
        """28 Sep live run: right after the K3s restart the Slinky webhook had no endpoints and
        refused the loginset patch; the login pod stayed at zero replicas."""
        r, calls, state = self.run_backup({"archive_rc": 0, "reopen_patch_fails": 3}, home=True)
        self.assertIn("loginset slurm-login-prace back to 1 replica(s)", r.stdout)
        self.assertIn("login pod running again", r.stdout)
        self.assertReopened(state)

    def test_window_that_cannot_close_fails_and_keeps_the_lease(self):
        r, calls, state = self.run_backup({"archive_rc": 0, "reopen_patch_fails": 99}, home=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("UNFENCE FAILED: loginset slurm-login-prace", r.stdout)
        self.assertIn("MAINTENANCE WINDOW NOT CLOSED", r.stdout)
        self.assertNotIn("SCP", calls)                      # nothing continues past an open window
        self.assertEqual(state["parts"], {"cpu": "UP", "gpu": "UP"})
        self.assertEqual(state["replicas"], 0)
        self.assertTrue(state["lease"])                    # still fenced: the lease stays held

    def test_one_multiplexed_connection(self):
        r, calls, state = self.run_backup({"queue": "42\n"})
        self.assertIn("ControlMaster=auto", " ".join(self.argv_seen))

    def test_login_pods_that_do_not_stop_refuse(self):
        r, calls, state = self.run_backup({"login_pods_stay": True}, home=True)
        self.assertEqual(r.returncode, 3); self.assertIn("login pods still present", r.stdout)
        self.assertNotIn("ARCHIVE", calls)
        self.assertReopened(state)

    def test_archive_holds_everything_a_restore_needs(self):
        """The restore rehearsal found /etc/rancher/node missing: without the node password a
        restored server cannot register its own node again."""
        self.run_backup({})
        for path in ("/var/lib/rancher/k3s/server", "/etc/rancher/k3s", "/etc/rancher/node",
                     "/var/lib/rancher/k3s/storage", "/root/slinky-db.pw", "slurm_acct_db.sql", "token-sha256.txt",
                     "maintenance-window.txt"):
            with self.subTest(path):
                self.assertIn(f'"{path}"' if path.startswith("/") else path, self.archive_script)

    def test_usage(self):
        r = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Offline tests for roles/slinky/tasks/preflight.yml (fleet.yml's scheduler preflight, D40), by
ansible-playbook on a local play of the five fleet hosts with a fake kubectl. The preflight is
skipped only on a fresh bootstrap (no K3s, or no controller); a controller that answers late is
still checked, and K3s or a controller that never answers stops every host. Includes the review's
reproduction (MR !55 ultrareview): one failed ping skipped the check, and a revoked user's queued
job did not stop the run. A recovery run may go on with a silent controller only under the
maintenance lease and revoking nobody (Session B re-review R1: the earlier override skipped the
check unconditionally, with a warning). No host is contacted."""
import getpass
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

INFRA = Path(__file__).resolve().parent.parent
PLAYBOOK = shutil.which("ansible-playbook") or "/home/operator/venvs/ansible-prace/bin/ansible-playbook"
HOSTS = ["lab-dl380", "lab-lenovo", "lab-g003", "lab-g004", "lab-g005"]
INVENTORY = ("[login]\nlab-dl380\n[compute]\n" + "\n".join(HOSTS[1:]) + "\n[fleet:children]\nlogin\ncompute\n"
             "[all:vars]\nansible_connection=local\nansible_python_interpreter={{ ansible_playbook_python }}\n")
PLAY = """- hosts: fleet
  gather_facts: false
  tasks:
    - name: Scheduler preflight, as fleet.yml's pre_tasks include it
      ansible.builtin.include_role:
        name: slinky
        tasks_from: preflight.yml
        apply: {tags: [accounts, slinky]}
      tags: [accounts, slinky]
    - ansible.builtin.debug: {msg: went on}
"""
# the accounting policy with syn-revoked removed from git; its association is still in the database
SPEC = {"cluster": "prace", "users": [{"name": "syn-revoked", "uid": 30007, "groups": ["synthetic"], "state": "absent"}],
        "groups": [{"name": "synthetic", "gid": 30000}], "project_gids": [31001, 31999],
        "fallback": {"synthetic": "synthetic"},
        "account_settings": {"project": {"Fairshare": 100, "GrpTRES": ""}, "fallback": {"Fairshare": 10, "GrpTRES": ""}},
        "qos": {}, "assoc_qos": {"allowed": ["normal"], "default": "normal"}}
FAKE_KUBECTL = r'''#!/usr/bin/env python3
import json, os, sys
sc = json.load(open(os.environ["SCENARIO"]))
a = sys.argv[1:]
open(os.environ["CALLS"], "a").write(" ".join(a) + "\n")
if "get" in a:
    if sc.get("api") == "down":
        print("The connection to the server 127.0.0.1:6443 was refused", file=sys.stderr); sys.exit(1)
    print("statefulset.apps/slurm-controller" if sc.get("controller") else "", end=""); sys.exit(0)
if sc.get("api") == "down" or not sc.get("controller"):
    print('Error from server (NotFound): statefulsets.apps "slurm-controller" not found', file=sys.stderr); sys.exit(1)
cmd = a[a.index("--") + 1:]
if cmd == ["scontrol", "ping"]:
    n = open(os.environ["CALLS"]).read().count("scontrol ping")
    up = sc.get("ping_up_after") is not None and n > sc["ping_up_after"]
    print("Slurmctld(primary) at slurm-controller-0 is " + ("UP" if up else "DOWN"))
    sys.exit(0 if up else 1)
if cmd[:3] == ["sacctmgr", "-nP", "show"]:
    if cmd[3] == "assoc":
        print("synthetic||||10|||\nsynthetic|syn-revoked||synthetic|1||normal|normal")
    sys.exit(0)
if cmd[0] == "squeue":
    print("\n".join(sc.get("jobs", []))); sys.exit(0)
sys.exit(3)
'''


def run_preflight(**over):
    sc = dict({"controller": True, "ping_up_after": 0}, **over)
    with tempfile.TemporaryDirectory() as d:
        d = Path(d)
        fake = d / "kubectl"
        fake.write_text(FAKE_KUBECTL)
        fake.chmod(0o755)
        (d / "sc.json").write_text(json.dumps(sc))
        (d / "hosts").write_text(INVENTORY)
        (d / "play.yml").write_text(PLAY)
        spec = dict(SPEC, users=SPEC["users"] + [{"name": n, "uid": 30100 + i, "groups": ["synthetic"], "state": "absent"}
                                                 for i, n in enumerate(sc.get("also_revoked", []))])
        extra = {"slinky_kubectl": sc.get("kubectl", str(fake)), "slinky_preflight_retries": 2,
                 "slinky_preflight_delay": 0, "slinky_accounts_spec": spec,
                 "slinky_preflight_controller_down": sc.get("override", False),
                 "fleet_lease_path": str(d / "lease"), "fleet_lease_id": sc.get("lease_id", "")}
        if sc.get("lease"):
            (d / "lease").mkdir()
            (d / "lease/holder").write_text(sc["lease"] + "\n")
        (d / "extra.json").write_text(json.dumps(extra))
        env = dict(os.environ, ANSIBLE_CONFIG=str(INFRA / "ansible.cfg"), ANSIBLE_ROLES_PATH=str(INFRA / "roles"),
                   ANSIBLE_NOCOLOR="1", SCENARIO=str(d / "sc.json"), CALLS=str(d / "calls"))
        r = subprocess.run([PLAYBOOK, "-i", str(d / "hosts"), str(d / "play.yml"), "-e", f"@{d / 'extra.json'}"],
                           cwd=INFRA, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=300)
        calls = (d / "calls").read_text().splitlines() if (d / "calls").exists() else []
        return r, r.stdout + r.stderr, calls


class Preflight(unittest.TestCase):
    def went_on(self, out):
        return out.count('"msg": "went on"')

    def test_a_fresh_bootstrap_is_skipped(self):
        for label, over in {"no K3s on the login node": {"kubectl": "/nonexistent/k3s kubectl"},
                            "K3s without a controller": {"controller": False}}.items():
            with self.subTest(label):
                r, out, calls = run_preflight(**over)
                self.assertEqual(r.returncode, 0, out)
                self.assertEqual(self.went_on(out), len(HOSTS), out)
                self.assertFalse([c for c in calls if "scontrol" in c or "sacctmgr" in c], calls)

    def test_a_controller_that_answers_late_is_still_checked(self):
        # the review's case: one failed ping skipped the check, so a revoked user's queued job did not stop the run
        r, out, calls = run_preflight(ping_up_after=1, jobs=["184|syn-revoked|30007|synthetic|PENDING|normal"])
        self.assertNotEqual(r.returncode, 0, out)
        self.assertEqual(self.went_on(out), 0, "every host stops")
        self.assertIn("refused: user syn-revoked: jobs 184 (PENDING)", out)
        self.assertEqual(sum("scontrol ping" in c for c in calls), 2)
        # and with a clean queue the run goes on
        r, out, calls = run_preflight(ping_up_after=1)
        self.assertEqual(r.returncode, 0, out)
        self.assertEqual(self.went_on(out), len(HOSTS), out)
        self.assertTrue([c for c in calls if "squeue" in c], "the check ran")

    def test_k3s_or_a_controller_that_never_answers_stops_every_host(self):
        for label, over, why in [("controller never UP", {"ping_up_after": None}, "slurm-controller did not answer"),
                                 ("K3s API down", {"api": "down"}, "The K3s API on lab-dl380 did not answer")]:
            with self.subTest(label):
                r, out, calls = run_preflight(**over)
                self.assertNotEqual(r.returncode, 0, out)
                self.assertEqual(self.went_on(out), 0, "every host stops")
                self.assertIn(why, out)
                self.assertIn("slinky_preflight_controller_down=true", out)
                self.assertFalse([c for c in calls if "sacctmgr" in c or "squeue" in c], calls)

    LEASE = "holder=maint label=slurm-window id=0123456789abcdef since=2026-10-01T10:00:00+08:00"

    def test_a_controller_down_recovery_run_needs_the_lease_and_no_revocation(self):
        """review R1: the override skipped the check with only a warning, whatever the run did"""
        me = getpass.getuser()          # a "revoked" user that still has a passwd entry on this login node
        cases = {
            "no lease held": ({}, "does not hold the cluster lease"),
            "another operation's lease": ({"lease": self.LEASE.replace("0123456789abcdef", "fedcba9876543210"),
                                            "lease_id": "0123456789abcdef"}, "does not hold the cluster lease"),
            "it would revoke a present user": ({"lease": self.LEASE, "lease_id": "0123456789abcdef", "also_revoked": [me]},
                                               f"it would revoke {me}"),
        }
        for label, (over, why) in cases.items():
            for api in ("down", "up"):
                with self.subTest(label, api=api):
                    r, out, calls = run_preflight(override=True, ping_up_after=None, **({"api": "down"} if api == "down" else {}), **over)
                    self.assertNotEqual(r.returncode, 0, out)
                    self.assertEqual(self.went_on(out), 0, "every host stops")
                    self.assertIn("slinky_preflight_controller_down refused", out)
                    self.assertIn(why, out)

    def test_a_leased_recovery_run_that_revokes_nobody_goes_on_loudly(self):
        # syn-revoked is absent in git and has no passwd entry here: nobody is revoked by this run
        for over in ({"api": "down"}, {"ping_up_after": None}):
            with self.subTest(**over):
                r, out, calls = run_preflight(override=True, lease=self.LEASE, lease_id="0123456789abcdef", **over)
                self.assertEqual(r.returncode, 0, out)
                self.assertEqual(self.went_on(out), len(HOSTS), out)
                self.assertIn("WARNING: the controller does not answer; this run holds lease 0123456789abcdef", out)
                self.assertFalse([c for c in calls if "sacctmgr" in c or "squeue" in c], calls)

    def test_the_flag_changes_nothing_while_the_controller_answers(self):
        r, out, calls = run_preflight(override=True, lease=self.LEASE, lease_id="0123456789abcdef",
                                      jobs=["184|syn-revoked|30007|synthetic|PENDING|normal"])
        self.assertNotEqual(r.returncode, 0, out)
        self.assertIn("refused: user syn-revoked: jobs 184 (PENDING)", out)


if __name__ == "__main__":
    unittest.main()

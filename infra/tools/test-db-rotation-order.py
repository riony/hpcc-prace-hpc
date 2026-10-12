#!/usr/bin/env python3
"""The accounting credential and the role's order (3 Oct, window step 3): slurmdbd keeps the
credential it started with, so no sacctmgr may run between the database user's change and
slurmdbd's restart (runbook DB-05). On 3 Oct the first DB-02 converge failed there.

- files/prace-db-credential-change.sh, with a fake kubectl: none / same / changed, nothing printed.
- roles/slinky/tasks/login.yml walked in order for three cases (a rotation on a running cluster, an
  ordinary converge, a fresh bootstrap), each task's `when` evaluated with Jinja: a task that needs
  slurmdbd must never run while the database and slurmdbd hold different credentials.
No host, credential or Ansible run is involved."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import jinja2
import yaml

INFRA = Path(__file__).resolve().parents[1]
SCRIPT = INFRA / "roles/slinky/files/prace-db-credential-change.sh"
LOGIN = INFRA / "roles/slinky/tasks/login.yml"
OLD, NEW = "a" * 48, "b" * 48

FAKE_KUBECTL = r'''#!/bin/bash
# the Secret slurm/mariadb-password as kubectl's jsonpath prints it (base64), or nothing, or a failure
[ -n "${FAIL:-}" ] && { echo "The connection to the server was refused" >&2; exit 1; }
[ -n "${SECRET:-}" ] && printf '%s' "$(printf '%s' "$SECRET" | base64 -w0)"
exit 0
'''


class CredentialChange(unittest.TestCase):
    def run_it(self, secret=None, fail=False, file_text=NEW + "\n"):
        with tempfile.TemporaryDirectory() as d:
            fake = Path(d) / "kubectl"; fake.write_text(FAKE_KUBECTL); fake.chmod(0o755)
            pw = Path(d) / "slinky-db.pw"; pw.write_text(file_text); pw.chmod(0o600)
            env = dict(os.environ, PRACE_KUBECTL=str(fake))
            env.pop("SECRET", None)
            if secret is not None:
                env["SECRET"] = secret
            if fail:
                env["FAIL"] = "1"
            r = subprocess.run(["bash", str(SCRIPT), str(pw)], env=env, capture_output=True, text=True, timeout=30)
            for word in (OLD, NEW):
                self.assertNotIn(word, r.stdout + r.stderr, "a password never appears")
            return r

    def test_the_three_answers(self):
        self.assertEqual(self.run_it(secret=None).stdout.strip(), "none")         # fresh bootstrap
        self.assertEqual(self.run_it(secret=NEW).stdout.strip(), "same")          # an ordinary converge
        self.assertEqual(self.run_it(secret=OLD).stdout.strip(), "changed")       # DB-02 of a rotation
        self.assertEqual(self.run_it(secret=NEW, file_text=NEW).stdout.strip(), "same", "the file's newline does not count")

    def test_a_failed_query_or_missing_file_is_no_answer(self):
        r = self.run_it(secret=OLD, fail=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(r.stdout, "")
        r = subprocess.run(["bash", str(SCRIPT), "/nonexistent/slinky-db.pw"], capture_output=True, text=True, timeout=30)
        self.assertEqual((r.returncode, r.stdout), (2, ""))


env = jinja2.Environment(undefined=jinja2.StrictUndefined)
env.filters["bool"] = lambda v: v if isinstance(v, bool) else str(v).strip().lower() in ("true", "yes", "1")
# the Ansible tests login.yml's conditions use, on registered results
env.tests["changed"] = lambda r: bool(r.get("changed"))
env.tests["failed"] = lambda r: bool(r.get("failed"))
env.tests["skipped"] = lambda r: bool(r.get("skipped"))
env.tests["search"] = lambda v, pattern: __import__("re").search(pattern, str(v)) is not None


def runs(task, facts):
    when = task.get("when")
    if when is None:
        return True
    return all(env.compile_expression(str(w))(**facts) for w in (when if isinstance(when, list) else [when]))


def needs_slurmdbd(task):
    inc = task.get("ansible.builtin.include_tasks")
    return inc == "slurm-accounts.yml" or "sacctmgr" in str(task.get("ansible.builtin.command", ""))


def walk(tasks, *, controller_up, secret, db, file_pw, slurmdbd_up=None, running_pw=None):
    """Run login.yml's top-level tasks in order as far as the credential goes. Returns the
    slurmdbd-using tasks that ran, and any that ran with the database and slurmdbd disagreeing."""
    facts = {"ansible_check_mode": False,
             "slinky_ping_before": {"rc": 0 if controller_up else 1, "stdout": "Slurmctld(primary) at slurm-controller-0 is UP" if controller_up else ""}}
    slurmdbd_up = controller_up if slurmdbd_up is None else slurmdbd_up
    slurmdbd = (running_pw if running_pw is not None else secret) if slurmdbd_up else None            # what slurmdbd started with; None: not running
    ran, broken = [], []
    for t in tasks:
        name = t.get("name", "")
        if name.startswith("Does this run change the accounting credential"):
            facts["slinky_db_change"] = {"stdout": "none" if secret is None else ("same" if secret == file_pw else "changed")}
            continue
        try:
            if not runs(t, facts):
                continue
        except (jinja2.UndefinedError, jinja2.TemplateAssertionError):
            # a condition on something this walk does not model (shares, chart changes, Ansible-only
            # filters): such a task
            # neither uses slurmdbd nor changes the credential, so whether it runs does not matter here;
            # a task that does must have a condition this walk can evaluate
            if needs_slurmdbd(t) or "ALTER USER" in str(t) or "set_fact" in str(t):
                raise
        if name == "Accounting connection is usable before any policy reconciliation":
            facts['slinky_accounting_before'] = {'rc': 0 if slurmdbd == db else 1}
            ran.append(name)
            continue
        if name == "Refuse a pending credential recovery before changing accounting policy":
            if facts['slinky_accounting_before']['rc'] != 0:
                ran.append('STOP: credential recovery required')
                break
            continue
        if "ansible.builtin.set_fact" in t:
            v = t["ansible.builtin.set_fact"].get("slinky_db_rotating")   # the one fact this order depends on
            if v is not None:
                facts["slinky_db_rotating"] = env.from_string(v).render(**facts).strip() == "True"
            continue
        if "ALTER USER" in str(t):
            db = file_pw                                   # the database user now has the file's password
        elif "prace-slinky-base.yaml" in str(t.get("ansible.builtin.template", "")):
            secret = file_pw                               # the Secret; slurmdbd keeps what it started with
        elif "prace-slinky-charts.yaml" in str(t.get("ansible.builtin.template", "")) and slurmdbd is None:
            slurmdbd = secret                              # a fresh bootstrap's slurmdbd starts with the Secret
        if needs_slurmdbd(t):
            ran.append(name)
            if slurmdbd is not None and slurmdbd != db:
                broken.append(name)
    return ran, broken


class RoleOrder(unittest.TestCase):
    tasks = yaml.safe_load(LOGIN.read_text())

    def test_a_rotation_runs_no_sacctmgr_between_the_change_and_slurmdbd_s_restart(self):
        """DB-02 on the running cluster: the accounting policy is reconciled first, with slurmdbd's
        current credential; after the change nothing asks slurmdbd until DB-05"""
        ran, broken = walk(self.tasks, controller_up=True, secret=OLD, db=OLD, file_pw=NEW)
        self.assertEqual(broken, [], "would fail against slurmdbd's old credential (3 Oct, DB-02)")
        self.assertIn("Accounting policy before the new configuration", ran, "the policy is still reconciled, before the change")
        self.assertNotIn("Accounting policy on the running controller", ran)
        message = next(t for t in self.tasks if t.get("name", "").startswith("The credential changed in this run"))
        self.assertTrue(runs(message, {"ansible_check_mode": False, "slinky_db_rotating": True}))
        self.assertIn("DB-05", message["ansible.builtin.debug"]["msg"])

    def test_an_ordinary_converge_and_a_fresh_bootstrap_keep_every_accounting_step(self):
        ran, broken = walk(self.tasks, controller_up=True, secret=NEW, db=NEW, file_pw=NEW)
        self.assertEqual(broken, [])
        self.assertIn("Accounting policy before the new configuration", ran)
        self.assertIn("Accounting policy on the running controller", ran)
        ran, broken = walk(self.tasks, controller_up=False, secret=None, db=None, file_pw=NEW)
        self.assertEqual(broken, [])
        self.assertEqual(ran, ["Accounting policy on the running controller"], "a fresh bootstrap gets its policy after slurmdbd starts")

    def test_a_change_while_the_controller_is_down_is_not_deferred_silently(self):
        """nothing reconciled the policy before the change (no controller answered), so the run must
        not claim it was and skip: the reconcile after the charts runs, and fails loudly if slurmdbd
        still holds the old credential"""
        ran, broken = walk(self.tasks, controller_up=False, slurmdbd_up=True, secret=OLD, db=OLD, file_pw=NEW)
        self.assertIn("Accounting policy on the running controller", ran)
        self.assertEqual(broken, ["Accounting policy on the running controller"], "a loud failure, not a silent skip")

    def test_interrupted_rotation_stops_before_policy_and_sql(self):
        for secret, selected in ((OLD, NEW), (NEW, NEW), (NEW, OLD)):
            ran, broken = walk(self.tasks, controller_up=True, secret=secret, db=NEW,
                               file_pw=selected, running_pw=OLD)
            self.assertEqual(broken, [])
            self.assertEqual(ran, ['Accounting connection is usable before any policy reconciliation',
                                   'STOP: credential recovery required'])

    def test_the_user_is_created_before_the_secret_and_the_charts_that_start_slurmdbd(self):
        names = [t.get("name", "") for t in self.tasks]
        user = next(i for i, t in enumerate(self.tasks) if "ALTER USER" in str(t))
        base = next(i for i, t in enumerate(self.tasks) if "prace-slinky-base.yaml" in str(t.get("ansible.builtin.template", "")))
        charts = names.index("The charts as K3s HelmChart objects (chart content from git, values pinned)")
        self.assertLess(user, base)
        self.assertLess(base, charts)
        self.assertTrue(self.tasks[user].get("no_log"), "the password is never logged")
        detect = next(t for t in self.tasks if t.get("name", "").startswith("Does this run change the accounting credential"))
        self.assertIn("prace-db-credential-change.sh", detect["ansible.builtin.command"]["stdin"])
        self.assertIs(detect.get("check_mode"), False)


if __name__ == "__main__":
    unittest.main()

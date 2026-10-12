#!/usr/bin/env python3
"""The disarmed fleet playbook must never contact a host, whatever host/tag/task filters
are used. A fake ssh executable only records calls; no real host is ever contacted."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

INFRA = Path(__file__).resolve().parent.parent
PLAYBOOK = shutil.which("ansible-playbook") or "/home/operator/venvs/ansible-prace/bin/ansible-playbook"
FILTERS = {
    "default": [],
    "limit one host": ["--limit", "lab-g003"],
    "limit group": ["--limit", "fleet"],
    "limit login node": ["--limit", "lab-dl380"],
    "tags": ["--tags", "accounts"],
    "skip always": ["--skip-tags", "always"],
    "start at a role task": ["--start-at-task", "Users (password locked; exact supplementary groups)"],
    "check mode": ["--check"],
    "armed false explicitly": ["-e", "fleet_armed=false"],
    "armed string no": ["-e", "fleet_armed=no"],
}


def run_playbook(*extra, playbook="playbooks/fleet.yml", inventory="inventories/fleet"):
    with tempfile.TemporaryDirectory() as d:
        marker, fake = Path(d) / "ssh-calls", Path(d) / "fake-ssh"
        fake.write_text(f'#!/bin/sh\necho "$*" >> {marker}\nexit 255\n')
        fake.chmod(0o755)
        env = dict(os.environ, ANSIBLE_CONFIG=str(INFRA / "ansible.cfg"), ANSIBLE_NOCOLOR="1")
        r = subprocess.run([PLAYBOOK, "-i", inventory, playbook,
                            "-e", f"ansible_ssh_executable={fake}", *extra],
                           cwd=INFRA, env=env, capture_output=True, text=True, timeout=300)
        lines = marker.read_text().splitlines() if marker.exists() else []
        run_playbook.last_calls = lines
        return r, len(lines)


class FleetGate(unittest.TestCase):
    def test_disarmed_contacts_no_host_under_any_filter(self):
        for label, extra in FILTERS.items():
            with self.subTest(label):
                r, calls = run_playbook(*extra)
                self.assertEqual(calls, 0, f"{label}: {calls} SSH attempt(s) while disarmed")

    def test_disarmed_default_run_fails_with_message(self):
        r, _ = run_playbook()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Not armed", r.stdout + r.stderr)

    def test_control_armed_runs_would_use_ssh(self):
        # Proves the fake executable is what Ansible calls, with and without filters.
        for extra in ([], ["--limit", "lab-g003"], ["--tags", "accounts"]):
            with self.subTest(extra=extra):
                r, calls = run_playbook("-e", "fleet_armed=true", *extra)
                self.assertGreater(calls, 0)
                self.assertNotEqual(r.returncode, 0)


class SlurmBackend(unittest.TestCase):
    """Slinky is the default (D36/D37): the native munge/slurm roles are an explicit fallback."""
    def test_native_roles_run_only_when_the_backend_is_native(self):
        import yaml
        plays = yaml.safe_load((INFRA / "playbooks/fleet.yml").read_text())
        roles = {r["role"]: r.get("when") for r in plays[1]["roles"]}
        native = "fleet_slurm_backend | default('slinky') == 'native'"
        slinky = "fleet_slurm_backend | default('slinky') == 'slinky'"
        storage = "fleet_role == 'login' and storage_enable | default(true) | bool"   # D39 storage step
        self.assertEqual({k: v for k, v in roles.items() if v}, {"munge": native, "slurm": native, "k3s": slinky,
                                                                  "slinky": slinky,
                                                                  # the login node's observer; a native worker's own endpoint (T89), removed after a rollback
                                                                  "fleet_observer": "(fleet_role == 'login' or inventory_hostname in groups['compute']) and " + slinky,
                                                                  "nvidia_gpu": "fleet_role == 'gpu'",
                                                                  "login_storage": storage, "storage_policy": storage,
                                                                  # T88: /apps on the login node; a native worker's profile snippet
                                                                  "apps_env": "fleet_role == 'login' or inventory_hostname in (slurm_native_workers | default([]))",
                                                                  "harness_helper": "fleet_role == 'login'",
                                                                  # deferred Apptainer (D42): where apps_env runs, only with --tags apptainer
                                                                  "apptainer": "fleet_role == 'login' or inventory_hostname in (slurm_native_workers | default([]))"})
        self.assertEqual(set(roles) - {"munge", "slurm", "k3s", "slinky", "fleet_observer", "nvidia_gpu",
                                       "login_storage", "storage_policy", "apps_env", "harness_helper", "apptainer"},
                         {"fleet_net", "fleet_repo", "host_base", "cluster_accounts", "nfs_home"})

    def test_role_order(self):
        """A fresh rebuild depends on the order: LVs before accounts (homes land on the LV), groups
        before project directories, mounts.json before the exports, local homes before the observer,
        /apps mounted before the job environment fills it, then the persistent helper and
        Apptainer trees on that same share."""
        import yaml
        plays = yaml.safe_load((INFRA / "playbooks/fleet.yml").read_text())
        self.assertEqual([r["role"] for r in plays[1]["roles"]],
                         ["fleet_net", "fleet_repo", "host_base", "login_storage", "cluster_accounts", "storage_policy",
                          "nfs_home", "apps_env", "harness_helper", "apptainer", "munge", "slurm", "nvidia_gpu", "k3s", "slinky", "fleet_observer"])

    def test_unknown_backend_is_refused_before_any_connection(self):
        r, calls = run_playbook("-e", "fleet_armed=false", "-e", "fleet_slurm_backend=Native")
        self.assertEqual(calls, 0)
        r, _ = run_playbook(playbook="playbooks/rehearsal.yml", inventory="inventories/rehearsal")
        self.assertNotIn("fleet_slurm_backend must be", r.stdout)   # rehearsal default is valid


class RehearsalHostGate(unittest.TestCase):
    def test_disarmed_rehearsal_host_playbook_contacts_no_host(self):
        for extra in ([], ["--limit", "lab-dl380"], ["-e", "fleet_armed=false"]):
            with self.subTest(extra=extra):
                r, calls = run_playbook(*extra, playbook="playbooks/rehearsal-host.yml")
                self.assertEqual(calls, 0)
        r, calls = run_playbook("-e", "fleet_armed=true", playbook="playbooks/rehearsal-host.yml")
        self.assertGreater(calls, 0)          # control: armed, the fake ssh is what Ansible calls


class RehearsalGuard(unittest.TestCase):
    def test_rehearsal_playbook_refuses_the_real_fleet_even_armed(self):
        r, calls = run_playbook("-e", "fleet_armed=true", playbook="playbooks/rehearsal.yml")
        self.assertEqual(calls, 0)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("refusing to run", r.stdout + r.stderr)

    def test_rehearsal_inventory_targets_resolve_to_localhost_only(self):
        # Armed against the rehearsal inventory with a fake ssh: calls go to the fake only,
        # and every attempted destination is the local port forward.
        r, calls = run_playbook("-e", "fleet_armed=true", playbook="playbooks/rehearsal.yml",
                                inventory="inventories/rehearsal")
        self.assertGreater(calls, 0)
        self.assertNotIn("refusing to run", r.stdout + r.stderr)
        for line in run_playbook.last_calls:
            self.assertIn("127.0.0.1", line)
            self.assertNotIn("192.0.2.205", line)


class ClusterLease(unittest.TestCase):
    """fleet.yml refuses while a backup window or acceptance run holds the cluster lease, unless
    the converge was started by that holder (-e fleet_lease_id). Runs the real task file on
    localhost against a temporary lease path."""
    def run_check(self, holder=None, lease_id=None):
        with tempfile.TemporaryDirectory() as d:
            lease = Path(d) / "lease"
            if holder is not None:
                lease.mkdir(); (lease / "holder").write_text(holder + "\n")
            book = Path(d) / "probe.yml"
            book.write_text(f"""- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.include_tasks: {INFRA / 'playbooks/tasks/cluster-lease-check.yml'}
""")
            extra = ["-e", f"fleet_lease_path={lease}", "-e", "fleet_lease_host=localhost"]
            if lease_id is not None:
                extra += ["-e", f"fleet_lease_id={lease_id}"]
            env = dict(os.environ, ANSIBLE_CONFIG=str(INFRA / "ansible.cfg"), ANSIBLE_NOCOLOR="1")
            r = subprocess.run([PLAYBOOK, "-i", "localhost,", str(book), *extra], cwd=INFRA, env=env,
                               capture_output=True, text=True, timeout=120)
            return r

    def test_no_lease_passes(self):
        self.assertEqual(self.run_check().returncode, 0)

    def test_foreign_lease_refuses(self):
        r = self.run_check("holder=k3s-login-backup label=x id=ab12cd since=now")
        self.assertNotEqual(r.returncode, 0); self.assertIn("The cluster is leased", r.stdout)

    def test_holder_passes_with_its_own_id_only(self):
        holder = "holder=slinky-acceptance id=ab12cd since=now"
        self.assertEqual(self.run_check(holder, "ab12cd").returncode, 0)
        for other in ("ab12", "ab12cdef", ""):
            with self.subTest(other=other):
                self.assertNotEqual(self.run_check(holder, other).returncode, 0)


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    unittest.main()

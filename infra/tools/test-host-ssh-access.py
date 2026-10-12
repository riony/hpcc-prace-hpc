#!/usr/bin/env python3
"""Renders roles/host_base's host SSH policy for the real fleet inventory on the controller
(connection=local, writes only to a temporary directory; contacts no host) and checks who may
log in: root and admin on every host, prace-observer on the login node only, and never a
cluster account from accounts.yml."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

INFRA = Path(__file__).resolve().parent.parent
PLAYBOOK = shutil.which("ansible-playbook") or "/home/operator/venvs/ansible-prace/bin/ansible-playbook"
ACCOUNTS = yaml.safe_load((INFRA / "inventories/fleet/group_vars/all/accounts.yml").read_text())
HOSTS = ("lab-dl380", "lab-lenovo", "lab-g003", "lab-g004", "lab-g005")


def render():
    out = tempfile.mkdtemp()
    book = Path(out) / "render.yml"
    book.write_text(f"""
- hosts: fleet
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.include_vars: {{file: "{INFRA}/roles/host_base/defaults/main.yml"}}
    - ansible.builtin.copy:
        dest: "{out}/{{{{ inventory_hostname }}}}.json"
        content: "{{{{ host_ssh_allow_users | to_json }}}}"
      delegate_to: localhost
""")
    env = dict(os.environ, ANSIBLE_CONFIG=str(INFRA / "ansible.cfg"))
    r = subprocess.run([PLAYBOOK, "-i", "inventories/fleet", str(book), "-e", "fleet_armed=false"],
                       cwd=INFRA, env=env, capture_output=True, text=True, timeout=300)
    if r.returncode:
        raise AssertionError(r.stdout[-3000:] + r.stderr[-2000:])
    result = {h: json.loads((Path(out) / f"{h}.json").read_text()) for h in HOSTS}
    shutil.rmtree(out)
    return result


class HostSshAccess(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allowed = render()

    def test_login_node_admits_administrators_and_the_observer_only(self):
        self.assertEqual(sorted(self.allowed["lab-dl380"]), ["admin", "prace-observer", "root"])

    def test_compute_nodes_admit_administrators_only(self):
        for host in HOSTS[1:]:
            with self.subTest(host):
                self.assertEqual(sorted(self.allowed[host]), ["admin", "root"])

    def test_no_cluster_account_gets_a_host_shell(self):
        cluster = {u["name"] for u in ACCOUNTS["cluster_users"]}
        for host, users in self.allowed.items():
            with self.subTest(host):
                self.assertFalse(cluster & set(users))


if __name__ == "__main__":
    unittest.main()

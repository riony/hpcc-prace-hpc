#!/usr/bin/env python3
"""T88's apps_repo signature check (4 Oct window, P7 step 1): the command the pinned Ansible
renders names each pinned GCC file exactly. There the old regex_replace with a backreference
rendered five copies of packages/\\1.rpm. No fleet: ansible-playbook on localhost writes the
rendered command to a temporary file."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

INFRA = Path(__file__).resolve().parent.parent
TASKS = INFRA / "roles/fleet_repo/tasks/main.yml"
DEFAULTS = yaml.safe_load((INFRA / "roles/fleet_repo/defaults/main.yml").read_text())
OLD = ("rpm -K --nodigest {{ fleet_repo_apps_packages | map('regex_replace', '^(.*)$', fleet_repo_dir ~ "
       "'/packages/\\\\1.rpm') | join(' ') }} 2>&1 | grep -v ': signatures OK$' || true")


def find(tasks, name):
    """the shell task of that name, inside blocks too"""
    for t in tasks or []:
        if t.get("name") == name and "ansible.builtin.shell" in t:
            return t
        for k in ("block", "rescue", "always"):
            found = find(t.get(k), name)
            if found:
                return found
    return None


class AppsSignatureCheck(unittest.TestCase):
    def render(self, command):
        d = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / "ansible.cfg").write_text("[defaults]\n")
        play = [{"hosts": "localhost", "gather_facts": False,
                 "vars": {k: DEFAULTS[k] for k in ("fleet_repo_dir", "fleet_repo_apps_packages")},
                 "tasks": [{"ansible.builtin.copy": {"content": command, "dest": str(d / "rendered"), "mode": "0600"}}]}]
        (d / "play.yml").write_text(yaml.safe_dump(play))
        env = dict(os.environ, ANSIBLE_CONFIG=str(d / "ansible.cfg"), ANSIBLE_LOCALHOST_WARNING="false",
                   ANSIBLE_INVENTORY_UNPARSED_WARNING="false")
        r = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", str(d / "play.yml")],
                           capture_output=True, text=True, env=env, timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout[-2000:] + r.stderr[-2000:])
        return (d / "rendered").read_text()

    def test_the_task_names_every_pinned_file_exactly(self):
        tasks = yaml.safe_load(TASKS.read_text())
        task = find(tasks, "Verify their signatures")
        self.assertIsNotNone(task)
        # the apps block's task, not the GPU block's (which checks packages/*.rpm)
        self.assertIn("fleet_repo_apps_packages", task["ansible.builtin.shell"])
        got = self.render(task["ansible.builtin.shell"])
        files = [f"{DEFAULTS['fleet_repo_dir']}/packages/{p}.rpm" for p in DEFAULTS["fleet_repo_apps_packages"]]
        self.assertEqual(got, "rpm -K --nodigest " + " ".join(files) + " 2>&1 | grep -v ': signatures OK$' || true")
        self.assertNotIn("\\", got)

    def test_the_old_backreference_form_fails_this_check(self):
        # the regression: with the pinned Ansible the old expression keeps the backreference literal
        got = self.render(OLD)
        self.assertNotIn(f"{DEFAULTS['fleet_repo_dir']}/packages/{DEFAULTS['fleet_repo_apps_packages'][0]}.rpm", got)


if __name__ == "__main__":
    unittest.main()

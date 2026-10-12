#!/usr/bin/env python3
"""T89: the native-only task strings that run only outside check mode (the class of the 4 Oct
apps_repo bug, where ansible-core 2.19 kept a regex backreference literal), rendered by the pinned
Ansible with the REAL inventory values: the fleet repository's job-environment download and its
signature check, the download's changed test, the native drop-in (share gate, mounts, address),
the login node's native list, the native observer's unit, URL and list. Each string is taken from
the task file and written by a local copy task. No fleet: a temporary inventory of the two hosts
from the repository's group_vars/all (without connection.yml) and host_vars, connection local."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

INFRA = Path(__file__).resolve().parent.parent
INV = INFRA / "inventories/fleet"
LOGIN, LENOVO = "lab-dl380", "lab-lenovo"


def find(tasks, name):
    """the task of that name, inside blocks too"""
    for t in tasks or []:
        if t.get("name") == name:
            return t
        for k in ("block", "rescue", "always"):
            found = find(t.get(k), name)
            if found:
                return found
    return None


def task(path, name):
    t = find(yaml.safe_load((INFRA / path).read_text()), name)
    assert t is not None, (path, name)
    return t


def block_vars(path, name):
    """the vars of the block that holds the task of that name"""
    for t in yaml.safe_load((INFRA / path).read_text()):
        if find(t.get("block"), name):
            return t.get("vars", {})
    return {}


class Render(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Path(tempfile.mkdtemp(prefix="prace-native-render-"))
        inv = cls.d / "inv"
        (inv / "group_vars/all").mkdir(parents=True); (inv / "host_vars").mkdir()
        for f in (INV / "group_vars/all").glob("*.yml"):
            if f.name != "connection.yml":            # no ssh settings; every host is local here
                shutil.copy(f, inv / "group_vars/all" / f.name)
        for h in (LOGIN, LENOVO):
            shutil.copy(INV / f"host_vars/{h}.yml", inv / f"host_vars/{h}.yml")
        (inv / "hosts").write_text(f"[login]\n{LOGIN}\n[cpu]\n{LENOVO}\n[compute:children]\ncpu\n[fleet:children]\nlogin\ncompute\n"
                                   "[all:vars]\nansible_connection=local\nansible_python_interpreter={{ ansible_playbook_python }}\n")
        (cls.d / "ansible.cfg").write_text("[defaults]\n")
        cls.defaults = {**yaml.safe_load((INFRA / "roles/slinky/defaults/main.yml").read_text()),
                        **yaml.safe_load((INFRA / "roles/fleet_repo/defaults/main.yml").read_text()),
                        **yaml.safe_load((INFRA / "roles/fleet_observer/defaults/main.yml").read_text())}
        cls.out = {}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d)

    def render(self, host, strings, extra=None):
        """{key: rendered} for {key: template string}, rendered on host with the role defaults"""
        out = self.d / f"out-{len(self.out)}"; out.mkdir()
        self.out[out] = True
        tasks = [{"ansible.builtin.copy": {"content": s, "dest": str(out / k), "mode": "0600"}} for k, s in strings.items()]
        play = [{"hosts": host, "gather_facts": False, "vars": {**self.defaults, **(extra or {})}, "tasks": tasks}]
        (self.d / "play.yml").write_text(yaml.safe_dump(play))
        env = dict(os.environ, ANSIBLE_CONFIG=str(self.d / "ansible.cfg"), ANSIBLE_NOCOLOR="1")
        r = subprocess.run(["ansible-playbook", "-i", str(self.d / "inv/hosts"), str(self.d / "play.yml"),
                            "-e", json.dumps({"slurm_native_workers": [LENOVO]})],
                           capture_output=True, text=True, env=env, timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:] + r.stderr[-2000:])
        return {k: (out / k).read_text() for k in strings}

    def changed(self, host, condition, extra):
        """the task's changed_when evaluated AS a conditional (ansible-core 2.19 escapes backslashes
        in a conditional unlike in a "{{ }}" template; re-templating it would test something else)"""
        out = self.d / f"out-{len(self.out)}"; out.mkdir(); self.out[out] = True
        play = [{"hosts": host, "gather_facts": False, "vars": extra, "tasks": [
            {"ansible.builtin.command": "true", "register": "probe", "changed_when": condition},
            {"ansible.builtin.copy": {"content": "{{ probe.changed }}", "dest": str(out / "c"), "mode": "0600"}}]}]
        (self.d / "play.yml").write_text(yaml.safe_dump(play))
        r = subprocess.run(["ansible-playbook", "-i", str(self.d / "inv/hosts"), str(self.d / "play.yml")], capture_output=True,
                           text=True, env=dict(os.environ, ANSIBLE_CONFIG=str(self.d / "ansible.cfg"), ANSIBLE_NOCOLOR="1"), timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout[-3000:])
        return (out / "c").read_text()

    def test_the_job_environment_download_and_its_signature_check(self):
        slurm = yaml.safe_load((INV / "group_vars/all/slurm.yml").read_text())
        dl = task("roles/fleet_repo/tasks/main.yml", "Download the exact builds and their dependencies (a missing build fails the run)")
        sig = task("roles/fleet_repo/tasks/main.yml", "Verify every RPM's signature")
        got = self.render(LOGIN, {"argv": "{{ (" + dl["ansible.builtin.command"]["argv"].strip()[3:-3].strip() + ") | to_json }}",
                                  "sig": sig["ansible.builtin.shell"]})
        argv = json.loads(got["argv"])
        repo = self.defaults["fleet_repo_dir"]
        self.assertEqual(argv[:10], ["dnf", "-y", "--enablerepo=crb", "download", "--resolve", "--alldeps",
                                     "--arch=x86_64,noarch", "--destdir", f"{repo}/packages", slurm["slurm_native_runtime_packages"][0]])
        self.assertEqual(argv[9:], slurm["slurm_native_runtime_packages"], "exactly the image's builds, in order")
        self.assertEqual(got["sig"], f"rpm -K --nodigest {repo}/packages/*.rpm | grep -v ': signatures OK$' || true")
        self.assertNotIn("\\", got["argv"] + got["sig"])
        new = ["(1/2): openmpi-4.1.1-7.el9.x86_64.rpm  1.2 MB/s | 640 kB", "Last metadata expiration check: 0:01:02 ago"]
        old = ["Already downloaded: openmpi-4.1.1-7.el9.x86_64.rpm", "Last metadata expiration check: 0:01:02 ago"]
        self.assertEqual(self.changed(LOGIN, dl["changed_when"], {"fr_native_dl": {"stdout_lines": new}}), "True")
        self.assertEqual(self.changed(LOGIN, dl["changed_when"], {"fr_native_dl": {"stdout_lines": old}}), "False",
                         "an already downloaded build is no change")
        self.assertEqual(self.changed(LOGIN, dl["changed_when"], {"fr_native_dl": {"stdout_lines": ["openmpi-4.1.1 rpmdb", "x"]}}), "False",
                         "the dot is literal: 'rpm' elsewhere is no download")

    def test_the_native_drop_in(self):
        t = task("roles/slinky/tasks/native-config.yml", "slurmd joins the Slinky controller (systemd drop-in; started by tasks/native.yml)")
        got = self.render(LENOVO, {"dropin": t["ansible.builtin.copy"]["content"]},
                          extra={"slinky_native_spec": {"core_spec": 4, "mem_spec": 15041, "threads": 2}})["dropin"]
        lines = got.splitlines()
        storage = yaml.safe_load((INV / "group_vars/all/storage.yml").read_text())
        shares = [s for s in storage["storage_lvs"] if s["name"] not in storage["storage_defer"]]
        self.assertIn("RequiresMountsFor=" + " ".join(s["path"] for s in shares), lines)
        self.assertIn(f"ExecStartPre={self.defaults['slinky_native_share_check']} 10.90.10.1 "
                      + " ".join(f"{s['path']}:{s['export']}" for s in shares), lines)
        self.assertEqual([l for l in lines if l.startswith("ExecStart")][1:], [
            "ExecStart=",
            f"ExecStart={self.defaults['slinky_native_slurmd']} --systemd -Z --conf-server slurm-controller.slurm:6817 "
            '--conf "Features=cpu NodeAddr=10.90.10.21 CoreSpecCount=4 MemSpecLimit=15041"'])
        self.assertEqual(lines.index("[Service]") + 1, lines.index(next(l for l in lines if l.startswith("ExecStartPre="))),
                         "the gate is in [Service]")

    def test_the_login_nodes_native_lists(self):
        content = next(x for x in self.iter_tasks("roles/slinky/tasks/login.yml")
                       if (x.get("ansible.builtin.copy") or {}).get("dest") == "{{ slinky_native_file }}")["ansible.builtin.copy"]["content"]
        tmpl = (INFRA / "roles/fleet_observer/templates/native-workers.json.j2").read_text()
        got = self.render(LOGIN, {"list": content, "json": tmpl})
        self.assertEqual([l for l in got["list"].splitlines() if not l.startswith("#")], [f"{LENOVO} 10.90.10.21"])
        self.assertEqual(json.loads(got["json"]), {LENOVO: {"address": "10.90.10.21"}})

    def test_the_native_observation_unit_and_url(self):
        path = "roles/fleet_observer/tasks/native.yml"
        unit = task(path, "Its unit (a dynamic user, the private address, the login node only)")["ansible.builtin.copy"]["content"]
        bv = block_vars(path, "Its unit (a dynamic user, the private address, the login node only)")
        got = self.render(LENOVO, {"unit": unit, "url": bv["fo_native_url"]}, extra=bv)
        lines = got["unit"].splitlines()
        self.assertIn("ExecStart=/usr/local/sbin/prace-native-observe serve --address 10.90.10.21 --allow 10.90.10.1", lines)
        self.assertIn("IPAddressAllow=10.90.10.1/32", lines)
        self.assertEqual(got["url"], "http://10.90.10.21:918/v1/native-worker")

    def iter_tasks(self, path):
        def walk(ts):
            for t in ts or []:
                yield t
                for k in ("block", "rescue", "always"):
                    yield from walk(t.get(k))
        return walk(yaml.safe_load((INFRA / path).read_text()))


if __name__ == "__main__":
    unittest.main()

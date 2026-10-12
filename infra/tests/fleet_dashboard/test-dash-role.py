#!/usr/bin/env python3
"""Static checks of roles/fleet_dashboard and its wiring (standard library only). The role itself is
applied in a disposable container by run.sh (role-tests); this file checks what can be read: Python
3.9 syntax and standard-library imports, no secret, the sanitized GitHub export stays clean, the
units' isolation, the token handling, the nginx location, the playbook and CI entries, the static
inventory against the repository, and the private workstation build."""
import ast
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dashtest as T  # noqa: E402

ROLE = os.path.join(T.REPO, "infra", "roles", "fleet_dashboard")
TOOL = os.path.join(T.REPO, "infra", "tools", "prace-dash-workstation.py")
TASKS = open(os.path.join(ROLE, "tasks", "main.yml"), encoding="utf-8").read()
ABSENT = open(os.path.join(ROLE, "tasks", "absent.yml"), encoding="utf-8").read()
PY = [os.path.join(T.FILES, n) for n in ("prace_dash_common.py", "prace_dash_observe.py", "prace_dash_gitlab.py", "prace_dash_evidence.py", "prace_dash_physical.py")]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def read(*parts):
    with open(os.path.join(T.REPO, *parts), encoding="utf-8") as f:
        return f.read()


def role_files():
    out = []
    for d, _, files in os.walk(ROLE):
        out += [os.path.join(d, f) for f in files if "__pycache__" not in d]
    return sorted(out)


class Code(unittest.TestCase):
    def test_python_39_syntax(self):
        for path in PY + [TOOL]:
            ast.parse(open(path, encoding="utf-8").read(), path, feature_version=(3, 9))

    def test_standard_library_only(self):
        std = getattr(sys, "stdlib_module_names", None)
        if std is None:
            self.skipTest("sys.stdlib_module_names needs Python 3.10+")
        for path in PY + [TOOL]:
            for node in ast.walk(ast.parse(open(path, encoding="utf-8").read())):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module] if isinstance(node, ast.ImportFrom) else []
                for n in names:
                    top = n.split(".")[0]
                    self.assertTrue(top in std or top.startswith("prace_dash_"), f"{os.path.basename(path)} imports {n}")

    def test_no_secret_in_the_role_tests_or_tool(self):
        scan = load(os.path.join(T.REPO, "infra", "tools", "secret-scan.py"), "secret_scan")
        paths = role_files() + [TOOL] + [os.path.join(d, f) for d, _, fs in os.walk(T.HERE) for f in fs if "__pycache__" not in d]
        hits = [h for p in paths for h in scan.scan_file(p, os.path.relpath(p, T.REPO))]
        self.assertEqual(hits, [])

    def test_the_github_export_stays_clean(self):
        # infra/roles and infra/tools are exported (tools/export-code-mirror.py); apply its mapping, then its residue scan
        exp = load(os.path.join(T.REPO, "infra", "tools", "export-code-mirror.py"), "export_code_mirror")
        exact = re.compile("|".join(re.escape(k) for k in sorted(exp.EXACT, key=len, reverse=True)))
        maps = [(re.compile(a), b) for a, b in exp.MAP]
        residue = {k: re.compile(v) for k, v in exp.RESIDUAL.items()}
        found = []
        for path in role_files() + [TOOL]:
            text = open(path, encoding="utf-8").read()
            text = exact.sub(lambda m: exp.EXACT[m.group(0)], text)
            for rx, rep in maps:
                text = rx.sub(rep, text)
            text = exp.REAL_OUI.sub("02:00:00:00:00:01", text)
            for n, line in enumerate(text.splitlines(), 1):
                found += [f"{os.path.relpath(path, T.REPO)}:{n} {k}" for k, rx in residue.items() if rx.search(line)]
        self.assertEqual(found, [])

    def test_no_member_name_in_exported_code(self):
        # the team's account names reach the scrub map from the inventory at deploy time, never from role files
        accounts = read("infra", "inventories", "fleet", "group_vars", "all", "accounts.yml")
        team = re.findall(r"\{name: ([a-z0-9._-]+), uid: 2\d{4}", accounts)
        self.assertGreater(len(team), 0)
        for path in role_files() + [TOOL]:
            text = open(path, encoding="utf-8").read()
            for name in team:
                self.assertNotIn(name, text, os.path.relpath(path, T.REPO))


class Wiring(unittest.TestCase):
    def test_every_file_is_installed_and_nothing_else(self):
        installed = re.search(r"loop: \[(prace_dash_common\.py[^\]]*)\]", TASKS).group(1).split(", ")
        self.assertEqual(sorted(installed), sorted(f for f in os.listdir(T.FILES) if os.path.isfile(os.path.join(T.FILES, f))))
        self.assertEqual(re.search(r"loop: \[(index\.html[^\]]*)\]", TASKS).group(1).split(", "), sorted(os.listdir(os.path.join(T.FILES, "www")), key=["index.html", "app.css", "app.js"].index))
        self.assertNotIn("workstation", re.sub(r"#.*|name: .*", "", TASKS))

    def test_units_are_unprivileged_and_isolated(self):
        self.assertEqual(TASKS.count("User={{ fleet_dashboard_user }}"), 3)
        self.assertNotRegex(TASKS, r"User=root")
        self.assertEqual(TASKS.count("PrivateNetwork=yes"), 2)                # observe and evidence: no network at all
        self.assertEqual(TASKS.count("IPAddressDeny=any"), 3)
        self.assertEqual(TASKS.count("IPAddressAllow=localhost"), 1)          # gitlab: loopback only
        for flag in ("NoNewPrivileges=yes", "ProtectSystem=strict", "ProtectHome=yes", "CapabilityBoundingSet="):
            self.assertIn(flag, TASKS)
        self.assertEqual(TASKS.count("ReadWritePaths="), 3)
        self.assertIn("local_follow: false", TASKS)                        # links in evidence are never followed

    def test_the_token_is_never_read_by_ansible(self):
        lines = [l.strip() for l in TASKS.splitlines() if "fleet_dashboard_token_file" in l]
        allowed = ("path:", "token_file:", "ConditionPathExists=", "sudo sh -c", "{{ fleet_dashboard_token_file }} is missing")
        for l in lines:
            self.assertTrue(any(a in l for a in allowed), l)
        for bad in ("slurp", "lookup('ansible.builtin.file', fleet_dashboard_token", "cat {{ fleet_dashboard_token"):
            self.assertNotIn(bad, TASKS + ABSENT)
        self.assertIn("get_checksum: false", TASKS)
        self.assertLess(TASKS.index("Refuse without the owner-created token file"), TASKS.index("Dashboard account"))   # before any change

    def test_mgmt_playbook_and_tags(self):
        pb = read("infra", "playbooks", "mgmt.yml")
        self.assertLess(pb.index("{role: fleet_monitor"), pb.index("{role: fleet_dashboard, tags: [fleet_dashboard]}"))
        self.assertIn("{role: gitlab, tags: [gitlab]}", pb)

    def test_the_nginx_location(self):
        tpl = read("infra", "roles", "gitlab", "templates", "gitlab.rb.j2")
        block = tpl[tpl.index("{% if gitlab_prace_dash | bool %}"):tpl.index("{% endif %}", tpl.index("{% if gitlab_prace_dash | bool %}"))]
        for want in ("nginx['custom_gitlab_server_config'] = <<~'PRACEDASH'", "location = /prace-dash { return 301 /prace-dash/; }",
                     "location ^~ /prace-dash/ {", "alias {{ gitlab_prace_dash_root }}/;", "limit_except GET HEAD { deny all; }",
                     "autoindex off;", "location ~ /\\. { deny all; }", "application/javascript js;", 'X-Content-Type-Options "nosniff"'):
            self.assertIn(want, block)
        self.assertNotIn("proxy_pass", block)
        self.assertIn('Strict-Transport-Security "max-age=63072000"', block)      # the block's add_header hides the server's
        nginx_csp = re.search(r'Content-Security-Policy "([^"]+)"', block).group(1)
        meta_csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', open(os.path.join(T.FILES, "www", "index.html")).read()).group(1)
        self.assertEqual(nginx_csp, meta_csp + "; frame-ancestors 'none'")
        self.assertIn("gitlab_prace_dash: false", read("infra", "roles", "gitlab", "defaults", "main.yml"))
        self.assertIn("gitlab_prace_dash_root: /var/lib/prace-dash/www", read("infra", "roles", "gitlab", "defaults", "main.yml"))
        self.assertIn("gitlab_prace_dash: true", read("infra", "inventories", "mgmt", "host_vars", "mgmt-git01.yml"))
        self.assertIn("gitlab_prace_dash_root | default('/var/lib/prace-dash/www')", read("infra", "roles", "fleet_dashboard", "defaults", "main.yml"))

    def test_ci_runs_every_dashboard_test(self):
        ci = read(".gitlab-ci.yml")
        py = ci[ci.index("python-tests:"):ci.index("role-tests:")]
        for name in ("test-dash-collectors.py", "test-dash-page.py", "test-dash-role.py"):
            self.assertIn(f"python3 infra/tests/fleet_dashboard/{name}", py)
        self.assertIn("bash infra/tests/fleet_dashboard/run.sh", ci[ci.index("role-tests:"):])
        self.assertRegex(ci, r"python3 (?:infra/)?tools/test-fleet-audit\.py")


class Inventory(unittest.TestCase):
    def test_static_inventory_matches_the_repository(self):
        defaults = read("infra", "roles", "fleet_dashboard", "defaults", "main.yml")
        hw = read("docs", "overview", "hardware-network.md")
        bmc_names = {"ilo5": "iLO 5", "imm2": "IMM2"}
        for host in T.FLEET:
            hv = read("infra", "inventories", "fleet", "host_vars", host + ".yml")
            bmc = re.search(r"\bbmc: \{.*?type: (\w+)", hv).group(1)
            line = re.search(rf"^  {re.escape(host)}: \{{(.*)\}}$", defaults, re.M).group(1)
            self.assertIn("bmc: " + bmc_names[bmc], line, host)
            model = re.search(r"model: ([^,]+)", line).group(1)
            self.assertIn(model, hw, host)
        self.assertIn("8 × Tesla V100-SXM2-32GB", hw)
        self.assertIn("4 CPUs and 90 GiB", read("infra", "roles", "slinky", "defaults", "main.yml"))
        self.assertIn('fleet_monitor_token_expires: "2026-10-31"', read("infra", "roles", "fleet_monitor", "defaults", "main.yml"))
        self.assertIn("issues", read("infra", "tools", "fleet_monitor.py"))
        self.assertIn('"labels": "alert,fleet-monitor"', read("infra", "tools", "fleet_monitor.py"))


class Workstation(unittest.TestCase):
    def test_the_private_bundle_is_unscrubbed_and_private(self):
        tool = load(TOOL, "prace_dash_workstation")
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "private")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(tool.main(["--out", out, "--repo", T.REPO]), 0)
            self.assertEqual(oct(os.stat(out).st_mode & 0o777), "0o700")
            ev = os.path.join(out, "data", "evidence.json")
            self.assertEqual(oct(os.stat(ev).st_mode & 0o777), "0o600")
            doc = json.load(open(ev))
            self.assertEqual(doc["build"], "workstation")
            self.assertIn("lab-lenovo", json.dumps(doc))                      # real names: this build is private
            self.assertNotIn("prace-recovery", json.dumps(doc))                    # the private run dir still never kept
            self.assertEqual(sorted(os.listdir(out)), ["app.css", "app.js", "data", "index.html"])
        self.assertIn("refusing", tool.refuse_here("/var/lib/prace-dash/www"))


if __name__ == "__main__":
    unittest.main()

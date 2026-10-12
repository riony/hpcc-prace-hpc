#!/usr/bin/env python3
"""Offline tests of tools/ci-change-scope.py against real throw-away git repositories.

The gate may only ever skip work for a branch whose WHOLE diff against main (from their merge
base) is documentation, evidence, notes or audit records; everything else, and anything it
cannot work out, is "full".
"""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "ci-change-scope.py"


def sh(cwd, *args):
    subprocess.run(args, cwd=cwd, check=True, capture_output=True, text=True)


class Repo:
    """origin.git (bare) with main; a clone on a feature branch, as a CI job sees it."""

    def __init__(self, base):
        self.base = Path(base)
        self.work = self.base / "work"
        self.work.mkdir()
        sh(self.work, "git", "init", "-q", "-b", "main")
        sh(self.work, "git", "config", "user.email", "contributor@example.org")
        sh(self.work, "git", "config", "user.name", "t")
        self.write("infra/tools/test-thing.py",
                   "DOC = 'docs/overview/used-by-a-test.md'\nEV = 'evidence/2026-01-01/fixture'\n")
        self.write("infra/roles/x/tasks/main.yml", "- debug: msg=hi\n")
        self.write("docs/overview/page.md", "page\n")
        self.write("docs/overview/used-by-a-test.md", "used\n")
        self.write("docs/runbooks/WINDOW.md", "```bash\ntrue\n```\n")
        self.write("evidence/2026-01-01/fixture/a.txt", "a\n")
        self.write("infra/audit/fleet-baseline.json", "{}\n")
        self.write("README.md", "readme\n")
        self.commit("main")
        self.origin = self.base / "origin.git"
        sh(self.base, "git", "clone", "-q", "--bare", str(self.work), str(self.origin))
        sh(self.work, "git", "remote", "add", "origin", str(self.origin))
        sh(self.work, "git", "fetch", "-q", "origin")
        sh(self.work, "git", "switch", "-q", "-c", "feature")

    def write(self, rel, text):
        p = self.work / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def commit(self, msg):
        sh(self.work, "git", "add", "-A")
        sh(self.work, "git", "commit", "-q", "-m", msg)

    def push_main(self, rel, text):
        """Main moves on after the branch point (another MR merged)."""
        sh(self.work, "git", "switch", "-q", "main")
        self.write(rel, text)
        self.commit("main moves")
        sh(self.work, "git", "push", "-q", "origin", "main")
        sh(self.work, "git", "switch", "-q", "feature")

    def scope(self, cwd=None, **env):
        e = {k: v for k, v in os.environ.items() if not k.startswith("CI_")}
        e.update({"CI_PIPELINE_SOURCE": "push", "CI_COMMIT_BRANCH": "feature", "CI_DEFAULT_BRANCH": "main",
                  "CI_REPOSITORY_URL": "file://" + str(self.origin)})
        e.update(env)
        r = subprocess.run(["python3", str(SCRIPT)], cwd=cwd or self.work, env=e,
                           capture_output=True, text=True, timeout=120)
        self.assertion_out = r.stderr
        lines = r.stdout.split()
        return lines[0] if len(lines) == 1 else "BAD:" + r.stdout


class Scope(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.r = Repo(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_documentation_only_branch_is_docs(self):
        self.r.write("docs/overview/page.md", "changed\n")
        self.r.write("agents/reviews/NEW.md", "review\n")
        self.r.write("README.md", "changed\n")
        self.r.commit("docs")
        self.assertEqual(self.r.scope(), "docs")

    def test_evidence_and_audit_records_are_audit_record(self):
        self.r.write("evidence/2026-10-06/window/README.md", "record\n")
        self.r.write("infra/audit/fleet-baseline.json", '{"a": 1}\n')
        self.r.write("docs/plan/LOG.md", "log\n")
        self.r.commit("record")
        self.assertEqual(self.r.scope(), "audit-record")

    def test_code_commit_then_documentation_commit_stays_full(self):
        # the whole branch is compared with main, never just the last commit
        self.r.write("infra/roles/x/tasks/main.yml", "- debug: msg=changed\n")
        self.r.commit("code")
        self.r.write("docs/overview/page.md", "changed\n")
        self.r.commit("docs after code")
        self.assertEqual(self.r.scope(), "full")

    def test_runbook_change_is_full(self):
        self.r.write("docs/runbooks/WINDOW.md", "```bash\nfalse\n```\n")
        self.r.commit("runbook")
        self.assertEqual(self.r.scope(), "full")

    def test_document_or_evidence_named_by_a_test_is_full(self):
        self.r.write("docs/overview/used-by-a-test.md", "changed\n")
        self.r.commit("doc a test reads")
        self.assertEqual(self.r.scope(), "full")

    def test_file_inside_an_evidence_folder_named_by_a_test_is_full(self):
        self.r.write("evidence/2026-01-01/fixture/b.txt", "b\n")
        self.r.commit("evidence a test reads")
        self.assertEqual(self.r.scope(), "full")

    def test_other_audit_files_are_full(self):
        self.r.write("infra/audit/expected.json", "{}\n")
        self.r.commit("expectations change with roles")
        self.assertEqual(self.r.scope(), "full")

    def test_new_top_level_area_is_full(self):
        self.r.write("scenarios/x/manifest.json", "{}\n")
        self.r.commit("new area")
        self.assertEqual(self.r.scope(), "full")

    def test_deleting_or_moving_code_into_docs_is_full(self):
        sh(self.r.work, "git", "mv", "infra/roles/x/tasks/main.yml", "docs/overview/moved.yml")
        self.r.commit("move")
        self.assertEqual(self.r.scope(), "full")

    def test_main_moving_on_does_not_change_a_docs_branch(self):
        self.r.write("docs/overview/page.md", "changed\n")
        self.r.commit("docs")
        self.r.push_main("infra/roles/x/tasks/main.yml", "- debug: msg=main moved\n")
        self.assertEqual(self.r.scope(), "docs")

    def test_empty_branch_is_full(self):
        self.assertEqual(self.r.scope(), "full")

    def test_main_tags_schedules_and_web_runs_are_full(self):
        self.r.write("docs/overview/page.md", "changed\n")
        self.r.commit("docs")
        self.assertEqual(self.r.scope(CI_COMMIT_BRANCH="main"), "full")
        self.assertEqual(self.r.scope(CI_COMMIT_BRANCH=""), "full")
        for source in ("schedule", "web", "api", "merge_request_event", ""):
            self.assertEqual(self.r.scope(CI_PIPELINE_SOURCE=source), "full", source)

    def test_unreachable_repository_is_full(self):
        self.r.write("docs/overview/page.md", "changed\n")
        self.r.commit("docs")
        self.assertEqual(self.r.scope(CI_REPOSITORY_URL="file:///nonexistent/repo.git"), "full")

    def test_shallow_clone_is_deepened_and_still_classified(self):
        self.r.write("docs/overview/page.md", "one\n")
        self.r.commit("docs 1")
        self.r.write("docs/overview/page.md", "two\n")
        self.r.commit("docs 2")
        sh(self.r.work, "git", "push", "-q", "origin", "feature")
        shallow = Path(self.tmp) / "shallow"
        sh(self.tmp, "git", "clone", "-q", "--depth", "1", "--branch", "feature",
           "file://" + str(self.r.origin), str(shallow))
        self.assertEqual(self.r.scope(cwd=shallow), "docs")

    def test_shallow_clone_with_code_is_full(self):
        self.r.write("infra/roles/x/tasks/main.yml", "- debug: msg=changed\n")
        self.r.commit("code")
        self.r.write("docs/overview/page.md", "two\n")
        self.r.commit("docs")
        sh(self.r.work, "git", "push", "-q", "origin", "feature")
        shallow = Path(self.tmp) / "shallow"
        sh(self.tmp, "git", "clone", "-q", "--depth", "1", "--branch", "feature",
           "file://" + str(self.r.origin), str(shallow))
        self.assertEqual(self.r.scope(cwd=shallow), "full")

    def test_unreadable_reference_source_requires_full_run(self):
        import importlib.util
        import io
        from contextlib import redirect_stdout
        from types import SimpleNamespace
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location("ci_scope_review", SCRIPT)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        out = io.StringIO()
        with patch.object(mod, "git", return_value=SimpleNamespace(returncode=0, stdout=str(self.r.work))), \
                patch.object(mod, "changed_files", return_value=["docs/overview/page.md"]), \
                patch.object(Path, "read_text", side_effect=PermissionError("unreadable source")), redirect_stdout(out):
            mod.main()
        self.assertEqual(out.getvalue(), "full\n")

    def test_prints_exactly_one_word(self):
        self.r.write("docs/overview/page.md", "changed\n")
        self.r.commit("docs")
        e = dict(os.environ, CI_PIPELINE_SOURCE="push", CI_COMMIT_BRANCH="feature", CI_DEFAULT_BRANCH="main",
                 CI_REPOSITORY_URL="file://" + str(self.r.origin))
        out = subprocess.run(["python3", str(SCRIPT)], cwd=self.r.work, env=e, capture_output=True, text=True).stdout
        self.assertEqual(out, "docs\n")


if __name__ == "__main__":
    unittest.main()

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from harness.smoke import ROOT, run_smoke


class SmokeWorkflow(unittest.TestCase):
    def test_real_local_smoke_verifies_packs_and_dashboard_reader_accepts(self):
        with tempfile.TemporaryDirectory() as d:
            output = Path(d) / "smoke"
            summary = run_smoke(output, "workflow-local", driver="scripted")
            self.assertTrue(summary["verified"])
            self.assertEqual(summary["transport"], "local")
            self.assertFalse(summary["hosted_dashboard_refreshed"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual((output / "summary.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((output / "summary.json").read_text()), summary)
            self.assertEqual(len(list((output / "evidence").glob("*/*/capture.json"))), 1)
            # The copied bundle is a real integrity boundary, rather than just a successful rc.
            index = output / "bundle/bundle.json"
            index.write_text("{}\n")
            reply = subprocess.run([sys.executable, "-m", "harness.evidence", "verify",
                                    "--bundle-dir", str(output / "bundle")], cwd=ROOT, capture_output=True)
            self.assertNotEqual(reply.returncode, 0)

    def test_failure_at_each_stage_prevents_later_execution_or_success_summary(self):
        for failure in range(1, 6):
            with self.subTest(stage=failure), tempfile.TemporaryDirectory() as d:
                output = Path(d) / "smoke"
                calls = []
                def execute(argv):
                    calls.append(argv)
                    if len(calls) == failure:
                        raise subprocess.CalledProcessError(1, argv)
                with self.assertRaises(subprocess.CalledProcessError):
                    run_smoke(output, "workflow-failure", driver="scripted", execute=execute)
                self.assertEqual(len(calls), failure)
                self.assertFalse((output / "summary.json").exists())
                self.assertTrue(output.is_dir())

    def test_remote_requires_both_explicit_inputs_before_any_output_or_execution(self):
        with tempfile.TemporaryDirectory() as d:
            config = Path(d) / "ssh.json"
            config.write_text("{}")
            config.chmod(0o600)
            for kwargs in ({"allow_remote": True}, {"ssh_config": config}):
                output = Path(d) / "smoke"
                with self.assertRaises(ValueError):
                    run_smoke(output, "workflow-remote", execute=lambda _: self.fail("contact"), **kwargs)
                self.assertFalse(output.exists())

    def test_explicit_remote_selects_cluster_plan_without_model_endpoint(self):
        with tempfile.TemporaryDirectory() as d:
            config = Path(d) / "ssh.json"
            config.write_text("{}")
            config.chmod(0o600)
            calls = []
            run_smoke(Path(d) / "smoke", "workflow-remote", ssh_config=config,
                      allow_remote=True, execute=calls.append)
            self.assertIn(str(ROOT / "harness/examples/cluster-smoke.plan.json"), calls[0])
            self.assertIn("--allow-remote", calls[0])
            self.assertNotIn("--provider", calls[0])
            self.assertEqual(len(calls), 5)

    def test_private_inputs_new_directory_and_source_checkout_protection(self):
        with tempfile.TemporaryDirectory() as d:
            parent = Path(d)
            config = parent / "ssh.json"
            config.write_text("{}")
            config.chmod(0o644)
            old = parent / "old"
            old.mkdir()
            link = parent / "link"
            link.symlink_to(parent, target_is_directory=True)
            for output, kwargs in ((parent / "new", {"ssh_config": config, "allow_remote": True}),
                                   (old, {}), (ROOT / "workflow-output", {}),
                                   (link / "smoke", {}), (Path("relative"), {})):
                with self.subTest(output=output), self.assertRaises(ValueError):
                    run_smoke(output, "workflow-refusal", execute=lambda _: self.fail("executed"), **kwargs)

    def test_umask_restored_after_failed_execution(self):
        mask = os.umask(0o027)
        try:
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(OSError):
                    run_smoke(Path(d) / "smoke", "workflow-mask",
                              execute=lambda _: (_ for _ in ()).throw(OSError("failure")))
                actual = os.umask(0o027)
                self.assertEqual(actual, 0o027)
        finally:
            os.umask(mask)

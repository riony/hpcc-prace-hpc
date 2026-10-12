import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("public_demo", Path(__file__).resolve().parents[1] / "cluster.py")
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)


class Ownership(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.demo = m.Demo(self.root)
        m.save(self.demo.owner, {"container_id": "owned-id", "namespace_uid": "owned-namespace"})

    def test_admission_retry_is_server_dry_run_only(self):
        with patch.object(m, "run", return_value="synthetic manifest"), patch.object(m.subprocess, "run", side_effect=[subprocess.CompletedProcess([], 1), subprocess.CompletedProcess([], 0)]) as run, patch.object(m.time, "sleep"):
            self.demo.wait_for_admission(Path("fixture.tgz"))
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            self.assertIn("--dry-run=server", call.args[0])
            self.assertIn(str(self.demo.kube), call.args[0])
            self.assertEqual(call.kwargs["input"], "synthetic manifest")

    def test_admission_deadline_preserves_ownership(self):
        with patch.object(m, "run", return_value="synthetic manifest"), patch.object(m.subprocess, "run", return_value=subprocess.CompletedProcess([], 1)), patch.object(m.time, "monotonic", side_effect=[0, 0, 121]), patch.object(m.time, "sleep"):
            with self.assertRaises(SystemExit):
                self.demo.wait_for_admission(Path("fixture.tgz"))
        self.assertTrue(self.demo.owner.exists())

    def test_wrong_container_prevents_api_and_delete(self):
        with patch.object(m, "run", side_effect=["foreign-id", m.NAME]), patch.object(self.demo, "kubectl") as k:
            with self.assertRaises(SystemExit):
                self.demo.verify()
            k.assert_not_called()

    def test_wrong_kind_label_refuses(self):
        with patch.object(m, "run", side_effect=["owned-id", "foreign-cluster"]):
            with self.assertRaises(SystemExit):
                self.demo.verify(api=False)

    def test_wrong_namespace_refuses(self):
        with patch.object(m, "run", side_effect=["owned-id", m.NAME]), patch.object(self.demo, "kubectl", return_value="different"):
            with self.assertRaises(SystemExit):
                self.demo.verify()

    def test_missing_receipt_never_calls_docker(self):
        self.demo.owner.unlink()
        with patch.object(m, "run") as run:
            with self.assertRaises(SystemExit):
                self.demo.down()
            run.assert_not_called()

    def test_failed_delete_preserves_receipt(self):
        with patch.object(self.demo, "verify"), patch.object(m, "run", side_effect=subprocess.CalledProcessError(1, "kind")):
            with self.assertRaises(subprocess.CalledProcessError):
                self.demo.down()
        self.assertTrue(self.demo.owner.exists())

    def test_still_present_cluster_preserves_receipt(self):
        with patch.object(self.demo, "verify"), patch.object(m, "run", side_effect=["", m.NAME]):
            with self.assertRaises(SystemExit):
                self.demo.down()
        self.assertTrue(self.demo.owner.exists())

    def test_successful_closeout_archives_receipt_and_credentials(self):
        self.demo.kube.write_text("synthetic runtime config")
        with patch.object(self.demo, "verify"), patch.object(m, "run", side_effect=["", ""]):
            self.demo.down()
        self.assertFalse(self.demo.owner.exists())
        archives = list(self.root.glob("closed-*"))
        self.assertEqual(len(archives), 1)
        self.assertEqual((archives[0] / "kubeconfig").read_text(), "synthetic runtime config")

    def test_existing_cluster_refused_before_dependency_fetch(self):
        with patch.object(m, "run", return_value=m.NAME) as run:
            with self.assertRaises(SystemExit):
                self.demo.up()
            self.assertEqual(run.call_count, 1)

    def test_kubernetes_commands_always_bind_private_context(self):
        with patch.object(m, "run") as run:
            self.demo.kubectl("get", "pods")
            argv = run.call_args.args
            self.assertEqual(argv[:5], ("kubectl", "--kubeconfig", str(self.demo.kube), "--context", "kind-" + m.NAME))

    def test_wrong_job_output_never_writes_success(self):
        pods = json.dumps({"items": [{"metadata": {"name": "controller"}, "spec": {"containers": [{"name": "slurmctld"}]}}]})
        with patch.object(self.demo, "verify"), patch.object(self.demo, "kubectl", side_effect=[pods, "idle", "wrong output"]):
            with self.assertRaises(SystemExit):
                self.demo.test()
        self.assertFalse((self.root / "result.json").exists())

    def test_job_success_requires_actual_srun_command(self):
        pods = json.dumps({"items": [{"metadata": {"name": "controller"}, "spec": {"containers": [{"name": "slurmctld"}]}}]})
        with patch.object(self.demo, "verify"), patch.object(self.demo, "kubectl", side_effect=[pods, "idle", "PRACE_CPU_JOB_OK"]) as k:
            self.demo.test()
        self.assertIn("srun", k.call_args.args)
        self.assertTrue(json.loads((self.root / "result.json").read_text())["job_completed"])

if __name__ == "__main__":
    unittest.main()

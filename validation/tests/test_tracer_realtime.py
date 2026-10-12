#!/usr/bin/env python3
"""Hermetic tests for tracer service, path safety, and SSH adapter refusal paths."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

from validation.adapters.ssh_remote import SshRemoteAdapter
from validation.contracts import ContractError, load_scenario, validate_scenario
from validation.local_fs import LocalFsAdapter, reset_workspace
from validation.replay import AdapterResult, FakeAdapter
from validation.tracer.client import TracerClient
from validation.tracer.service import TracerService


ROOT = Path(__file__).resolve().parents[2]


class TracerServiceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manifest = load_scenario(ROOT / "scenarios/file-ops-smoke/v1/manifest.json")
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        # Rewrite paths into the temporary workspace for isolation.
        text = json.dumps(self.manifest)
        text = text.replace("/tmp/prace-file-ops-smoke-v1", str(self.workspace))
        self.manifest = validate_scenario(json.loads(text))
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()
        self.adapter = LocalFsAdapter()
        self.service = TracerService(
            scenario=self.manifest,
            run_dir=self.run_dir,
            run_id="t1",
            adapter=self.adapter,
            workspace=self.workspace,
        )

    def test_ordered_actions_and_out_of_order_refuse(self):
        ok = self.service.handle({"method": "execute_action", "action_id": "mkdir-demo-dir", "phase": "record"})
        self.assertTrue(ok["ok"])
        bad = self.service.handle({"method": "execute_action", "action_id": "delete-test-file-1", "phase": "record"})
        self.assertFalse(bad["ok"])
        self.assertIn("out-of-order", bad["error"])

    def test_unknown_action_refused(self):
        response = self.service.handle({"method": "execute_action", "action_id": "nope", "phase": "record"})
        self.assertFalse(response["ok"])

    def test_socket_server_smoke(self):
        config = {
            "run_id": "sock-1",
            "scenario": str(self.root / "scenario.json"),
            "run_dir": str(self.run_dir / "sock"),
            "socket_path": str(self.run_dir / "sock" / "t.sock"),
            "workspace": str(self.workspace),
            "adapter": "local",
            "adapter_config": {},
        }
        Path(config["run_dir"]).mkdir()
        Path(config["scenario"]).write_text(json.dumps(self.manifest))
        config_path = self.run_dir / "cfg.json"
        config_path.write_text(json.dumps(config))
        proc = subprocess.Popen(
            [sys.executable, "-m", "validation.tracer", "--config", str(config_path)],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            socket_path = Path(config["socket_path"])
            for _ in range(50):
                if socket_path.exists():
                    break
                time.sleep(0.05)
            self.assertTrue(socket_path.exists())
            mode = socket_path.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
            client = TracerClient(socket_path)
            self.assertTrue(client.call("ping")["ok"])
            client.call("reset_workspace")
            for action_id in [
                "mkdir-demo-dir",
                "write-test-file-1",
                "write-test-file-2",
                "delete-test-file-1",
            ]:
                response = client.call("execute_action", action_id=action_id, phase="record")
                self.assertTrue(response["ok"], response)
        finally:
            proc.terminate()
            proc.wait(timeout=5)


class SshRemoteAdapterTests(unittest.TestCase):
    def test_inspection_budget_and_scoped_ssh_advisory_option(self):
        from unittest.mock import patch
        adapter = SshRemoteAdapter(ssh_alias='fixture',connect_timeout=10)
        argv = adapter._ssh_base()
        self.assertIn('StrictHostKeyChecking=yes',argv)
        self.assertLess(argv.index('IgnoreUnknown=WarnWeakCrypto'),argv.index('WarnWeakCrypto=no-pq-kex'))
        self.assertNotIn('-q',argv)
        ok = subprocess.CompletedProcess([],0,b'{"ok":true}',b'')
        with patch.object(adapter,'_rpc',return_value=ok) as rpc:
            adapter.json_rpc('jobs-clean',{})
            self.assertEqual(rpc.call_args.args[2],35)
            adapter.json_rpc('jobs-clean',{},timeout=42)
            self.assertEqual(rpc.call_args.args[2],42)
        with patch.object(adapter,'_rpc',return_value=subprocess.CompletedProcess([],0,b'{}',b'unexpected warning')):
            with self.assertRaises(ContractError): adapter.json_rpc('capabilities',{})

    def test_refuses_unsupported_kind(self):
        adapter = SshRemoteAdapter(ssh_alias="prace-actor")
        result = adapter.execute(
            "x",
            {"kind": "ssh.exec", "target": "login-pod", "identity": "smoke-operator",
             "parameters": {"argv": ["id"]}},
            5,
        )
        self.assertEqual(result.status, "refused")

    def test_fake_timeout_path_uses_subprocess_timeout(self):
        # Ensure constructor validates alias shape.
        with self.assertRaises(ContractError):
            SshRemoteAdapter(ssh_alias="bad alias")


class RemoteManifestTests(unittest.TestCase):
    def test_remote_manifest_validates(self):
        manifest = load_scenario(ROOT / "scenarios/file-ops-smoke/v1/manifest.remote.json")
        self.assertEqual(manifest["status"], "smoke")
        self.assertEqual(manifest["boundaries"]["action_targets"], ["login-pod"])


class ClusterTracerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manifest = load_scenario(ROOT / "scenarios/file-ops-smoke/v1/manifest.json")
        self.workspace = self.root / "workspace"
        self.workspace.mkdir()
        text = json.dumps(self.manifest).replace("/tmp/prace-file-ops-smoke-v1", str(self.workspace))
        self.manifest = validate_scenario(json.loads(text))
        self.run_dir = self.root / "run"
        self.run_dir.mkdir()
        self.adapter = LocalFsAdapter()
        self.service = TracerService(
            scenario=self.manifest,
            run_dir=self.run_dir,
            run_id="ct1",
            adapter=self.adapter,
            workspace=self.workspace,
            cluster_audit=self.adapter,
            cluster_target="local-workspace",
            require_cluster_tracer=True,
        )

    def test_auto_cluster_tracer_after_action(self):
        response = self.service.handle(
            {"method": "execute_action", "action_id": "mkdir-demo-dir", "phase": "record"}
        )
        self.assertTrue(response["ok"], response)
        cluster = [
            event for event in self.service.writer.events
            if event["event_type"] == "cluster"
        ]
        self.assertEqual(len(cluster), 1)
        self.assertEqual(cluster[0]["source"], "cluster_tracer")
        self.assertEqual(cluster[0]["correlated_action_sequence"], response["event"]["sequence"])

    def test_finalize_requires_cluster_tracer(self):
        bare_dir = self.root / "bare"
        bare_dir.mkdir()
        bare = TracerService(
            scenario=self.manifest,
            run_dir=bare_dir,
            run_id="bare",
            adapter=self.adapter,
            workspace=self.workspace,
            require_cluster_tracer=True,
        )
        for action_id in [
            "mkdir-demo-dir",
            "write-test-file-1",
            "write-test-file-2",
            "delete-test-file-1",
        ]:
            bare.handle({"method": "execute_action", "action_id": action_id, "phase": "record"})
        bare.handle({
            "method": "append_observation",
            "check_id": "record-layout-ok",
            "target": "local-workspace",
            "status": "pass",
            "code": "workspace-layout",
            "evidence": b"x".hex(),
            "evidence_encoding": "hex",
            "detail": "test",
        })
        refused = bare.handle({"method": "finalize", "require_cluster_tracer": True})
        self.assertFalse(refused["ok"])
        self.assertIn("cluster tracer", refused["error"])

    def test_manual_emit_and_source_separation(self):
        from validation.cluster_tracer import ClusterTracer
        from validation.tracer.client import TracerClient

        config = {
            "run_id": "manual-ct",
            "scenario": str(self.root / "scenario.json"),
            "run_dir": str(self.run_dir / "manual"),
            "socket_path": str(self.run_dir / "manual" / "t.sock"),
            "workspace": str(self.workspace),
            "adapter": "local",
            "adapter_config": {},
            "cluster_tracer": {
                "enabled": False,
            },
        }
        Path(config["run_dir"]).mkdir()
        Path(config["scenario"]).write_text(json.dumps(self.manifest))
        config_path = self.run_dir / "manual-cfg.json"
        config_path.write_text(json.dumps(config))
        proc = subprocess.Popen(
            [sys.executable, "-m", "validation.tracer", "--config", str(config_path)],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            socket_path = Path(config["socket_path"])
            for _ in range(50):
                if socket_path.exists():
                    break
                time.sleep(0.05)
            client = TracerClient(socket_path)
            client.call("reset_workspace")
            response = client.call("execute_action", action_id="mkdir-demo-dir", phase="record")
            self.assertTrue(response["ok"], response)
            tracer = ClusterTracer(client, LocalFsAdapter(), self.workspace, "local-workspace")
            event = tracer.emit(phase="record", correlated_action_sequence=response["event"]["sequence"])
            self.assertEqual(event["source"], "cluster_tracer")
            watcher = client.call(
                "append_cluster",
                source="cluster_watcher",
                phase="record",
                correlated_action_sequence=response["event"]["sequence"],
                target="local-workspace",
                snapshot={
                    "status": "mismatch",
                    "code": "interim",
                    "evidence_sha256": "0" * 64,
                    "detail": "interim watcher only",
                },
            )
            self.assertTrue(watcher["ok"], watcher)
            self.assertEqual(watcher["event"]["source"], "cluster_watcher")
        finally:
            proc.terminate()
            proc.wait(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)

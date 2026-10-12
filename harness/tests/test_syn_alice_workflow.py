"""Agreed actor, storage, four-job replay, and independent evidence boundary."""
import json
import importlib.util
import os
import sys
from pathlib import Path
import unittest
from unittest.mock import patch

from harness.evidence import package_run, verify_bundle
from harness.scenario_run import run_scenario, verify_scenario_run
from harness.smoke import run_smoke
from validation.adapters import researcher_workflow as research
from validation.contracts import ContractError
from harness.tests import test_researcher_workflow as researcher_tests
ROOT = researcher_tests.ROOT

PLAN = ROOT / 'harness/examples/researcher-workflow.plan.json'


class SynAlice(unittest.TestCase):
    def setUp(self):
        researcher_tests.Researcher.setUp(self)
        config = json.loads(self.config.read_text())
        config['roles']['actor']['identity'] = 'syn-alice'
        self.config.write_text(json.dumps(config))
        script = self.bin / 'ssh'
        code = script.read_text().replace('syn-smoke', 'syn-alice').replace('/projects/proj-ops/.prace-smoke', '/home/syn-alice/.prace-researcher')
        code = code.replace("if op=='prepare':", "if op=='inventory' and alias=='prace-tracer' and os.environ.get('HS_MISSING_INVENTORY'): raise SystemExit(1)\nif op=='prepare':")
        script.write_text(code)

    def execute(self, name='alice'):
        return run_scenario(self.root / name, name, PLAN, ssh_config=self.config, allow_remote=True)

    @unittest.skipUnless(importlib.util.find_spec('nat') is not None, 'pinned NeMo runtime required')
    def test_nemo_replay_packages_steps_and_all_correlated_snapshots(self):
        run = self.root / 'alice-nemo'
        metadata = run_scenario(run, 'alice-nemo', PLAN, driver='nemo', executable=sys.executable,
                                ssh_config=self.config, allow_remote=True)
        self.assertEqual(metadata['slurm_job_ids'], ['8101', '8102', '8103', '8104'])
        self.assertEqual(metadata['replay_driver'], 'nemo')
        bundle = self.root / 'alice-nemo-bundle'
        package_run(run, bundle)
        self.assertEqual(verify_bundle(bundle)['ssh_identities']['actor']['identity'], 'syn-alice')
        self.assertEqual(len(list(bundle.glob('cluster-snapshot-*.json'))), 26)
        replay = json.loads((bundle / 'agent-replay-trace.json').read_text())
        self.assertEqual(replay['replayed'], 13)
        self.assertFalse(replay['model_used'])

    def test_whole_scripted_workflow_packs_reverifies_and_dashboard_accepts(self):
        import subprocess
        try:
            summary = run_smoke(self.root / 'workflow', 'alice-workflow', workflow='researcher',
                                ssh_config=self.config, allow_remote=True)
        except subprocess.CalledProcessError:
            metadata = self.root / 'workflow/run/run.json'
            log = self.root / 'workflow/run/gateway.log'
            self.fail((metadata.read_text() if metadata.exists() else 'no metadata') + (log.read_text() if log.exists() else 'no gateway log'))
        self.assertEqual(summary['driver'], 'scripted')
        self.assertTrue(summary['verified'])
        self.assertFalse(summary['hosted_dashboard_refreshed'])
        metadata = verify_bundle(self.root / 'workflow/bundle')
        self.assertEqual(metadata['ssh_identities']['actor']['identity'], 'syn-alice')
        self.assertEqual(metadata['slurm_job_ids'], ['8101', '8102', '8103', '8104'])
        manifest = json.loads((self.root / 'workflow/run/manifest.json').read_text())
        self.assertEqual(manifest['actor']['project'], 'proj-alpha')
        self.assertEqual(manifest['boundaries']['paths'], ['/home/syn-alice/.prace-researcher/runs/alice-workflow/workspace'])
        self.assertEqual(len(list((self.root / 'workflow/bundle').glob('cluster-snapshot-*.json'))), 26)
        self.assertEqual(len(list((self.root / 'workflow/evidence').glob('*/*/capture.json'))), 1)
        self.assertFalse((self.fs / 'runs/alice-workflow').exists())

    def test_missing_inventory_is_retained_and_cannot_publish(self):
        with patch.dict(os.environ, {'HS_MISSING_INVENTORY': '1'}), self.assertRaises(ContractError):
            self.execute('missing')
        events = [json.loads(line) for line in (self.root / 'missing/events.jsonl').read_text().splitlines()]
        self.assertEqual([e['event_type'] for e in events], ['action', 'cluster'])
        self.assertEqual(events[1]['snapshot']['code'], 'workspace-inventory-unavailable')
        with self.assertRaises((ValueError, OSError)):
            package_run(self.root / 'missing', self.root / 'refused-bundle')

    def test_submission_warning_retains_both_receipts_and_independent_cleanup(self):
        with patch.dict(os.environ, {'HS_RECEIPT_WARNING': '1'}), self.assertRaises(ContractError):
            self.execute('warning')
        metadata = json.loads((self.root / 'warning/run.json').read_text())
        self.assertEqual(metadata['status'], 'failed')
        self.assertEqual(metadata['slurm_job_ids'], ['8101', '8102'])
        self.assertEqual(metadata['cleanup'], 'complete')
        cleanup = json.loads((self.root / 'warning/failure-cleanup.json').read_text())
        self.assertEqual(cleanup['job_cleanup']['active_job_ids'], [])
        self.assertEqual(len(cleanup['job_cleanup']['jobs']), 2)

    def test_missing_snapshot_file_or_false_thread_results_refuses(self):
        self.execute()
        run = self.root / 'alice'
        snapshot = next(run.glob('cluster-snapshot-*.json'))
        original = snapshot.read_bytes()
        snapshot.unlink()
        with self.assertRaises((ValueError, OSError)):
            verify_scenario_run(run)
        snapshot.write_bytes(original)
        proof = json.loads((run / 'record-results-ok.json').read_text())
        proof['files'][0]['content'] = 'cxx threads ok: 4 threads on node-test\n'
        import hashlib
        digest = hashlib.sha256(proof['files'][0]['content'].encode()).hexdigest()
        proof['files'][0].update(sha256=digest, source_sha256=digest)
        self.assertFalse(research.valid_outputs(proof))
        (run / 'record-results-ok.json').write_text(json.dumps(proof))
        with self.assertRaises(ValueError):
            verify_scenario_run(run)

    def test_allocation_identity_and_timestamp_checks_are_rederived(self):
        self.execute()
        run = self.root / 'alice'
        original = json.loads((run / 'record-gpu-job-ok.json').read_text())
        for key, value in [('actor', 'syn-smoke'), ('allocated_cpus', 1),
                           ('allocated_tres', 'cpu=4,mem=90G,node=1'), ('end_epoch', 1), ('requested_cpus', 2)]:
            proof = dict(original, **{key: value})
            (run / 'record-gpu-job-ok.json').write_text(json.dumps(proof))
            with self.subTest(key=key), self.assertRaises(ValueError):
                verify_scenario_run(run)

    def test_wait_deadline_fails_without_wall_clock_sleep(self):
        from types import SimpleNamespace
        p = {'workspace': '/tmp/ws', 'run_id': 'timeout', 'job_id': '123'}
        with patch.object(research, 'ticket_path', side_effect=lambda ws, part: SimpleNamespace(exists=lambda: part == 'cpu')), \
             patch.object(research, 'read_ticket', return_value={'job_id': '123', 'run_id': 'timeout'}), \
             patch.object(research.time, 'monotonic', side_effect=[0, 1, 1191]), \
             patch.object(research, 'job_proof', return_value={'state': 'PENDING'}), \
             self.assertRaisesRegex(ValueError, 'deadline'):
            research.wait(Path('/tmp/ws'), p)


if __name__ == '__main__':
    unittest.main()

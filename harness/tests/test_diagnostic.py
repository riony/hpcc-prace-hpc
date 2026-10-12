"""Alice-only diagnostics retain honest labels and trace integrity gates."""
import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from harness.tests.test_syn_alice_workflow import SynAlice, ROOT
from harness.diagnostic import run_diagnostic, verify_diagnostic
from harness.evidence import package_run, verify_bundle
from harness.scenario import load_ssh
from validation.contracts import ContractError


class Diagnostic(unittest.TestCase):
    def setUp(self):
        SynAlice.setUp(self)
        config = json.loads(self.config.read_text())
        config['roles'] = {'actor':config['roles']['actor']}
        self.config.write_text(json.dumps(config))
        script = self.bin/'ssh'
        script.write_text(script.read_text().replace("alias=='prace-tracer' and os.environ.get('HS_MISSING_INVENTORY')", "os.environ.get('HS_MISSING_INVENTORY')"))

    def run_case(self, name='diag'):
        return run_diagnostic(self.root/name,name,self.config)

    def test_alice_only_two_jobs_pack_and_dashboard(self):
        m = self.run_case()
        self.assertEqual(m['slurm_job_ids'], ['8101','8102'])
        self.assertEqual(m['independent_verification'],'SKIPPED')
        calls = [json.loads(x) for x in self.calls.read_text().splitlines()]
        self.assertEqual({c['role'] for c in calls}, {'prace-actor'})
        self.assertFalse(any(c['operation'] in {'researcher-proof','output-proof'} for c in calls))
        self.assertFalse((self.fs/'runs/diag').exists())
        package_run(self.root/'diag',self.root/'bundle')
        self.assertEqual(verify_bundle(self.root/'bundle')['overall'],'UNVERIFIED')
        spec = importlib.util.spec_from_file_location('diagnostic_export',ROOT/'infra/tools/scenario-export.py')
        module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
        evidence = self.root/'evidence'; evidence.mkdir()
        folder, count = module.build(self.root/'bundle',evidence)
        self.assertEqual(count,28)
        self.assertIn('UNVERIFIED',json.loads((folder/'capture.json').read_text())['title'])
        self.assertIn('SKIPPED',(folder/'events.jsonl').read_text())

    def test_missing_snapshot_and_altered_pass_refused(self):
        self.run_case()
        root = self.root/'diag'
        result = json.loads((root/'result.json').read_text())
        result['overall'] = 'PASS'; (root/'result.json').write_text(json.dumps(result))
        with self.assertRaises(ContractError): verify_diagnostic(root)
        result['overall'] = 'UNVERIFIED'; (root/'result.json').write_text(json.dumps(result))
        next(root.glob('cluster-snapshot-*.json')).unlink()
        with self.assertRaises(OSError): package_run(root,self.root/'bad-bundle')

    def test_missing_inventory_live_failure_retained(self):
        with patch.dict(os.environ,{'HS_MISSING_INVENTORY':'1'}), self.assertRaises(ContractError): self.run_case('missing')
        root = self.root/'missing'
        self.assertEqual(json.loads((root/'run.json').read_text())['status'],'failed')
        self.assertIn('workspace-inventory-unavailable',(root/'events.jsonl').read_text())

    def test_verified_config_still_requires_three_roles(self):
        with self.assertRaises(ContractError): load_ssh(self.config,'syn-alice')
        self.assertEqual(set(load_ssh(self.config,'syn-alice',diagnostic=True)['roles']),{'actor'})


if __name__ == '__main__': unittest.main()

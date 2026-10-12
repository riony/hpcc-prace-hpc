"""Researcher execution through the real gateway and fake remote scheduler."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import unittest
from unittest.mock import patch
sys.path[:0]=[str(Path(__file__).resolve().parents[2]),str(Path(__file__).resolve().parent)]
from harness.scenario import load_plan, validate_plan, bind_run
from harness.scenario_run import run_scenario, verify_scenario_run
from validation.contracts import ContractError
from validation.adapters import researcher_workflow as r
import test_scenarios as smoke_tests
from test_scenarios import FAKE_SSH, ROOT
PLAN=ROOT/'harness/drafts/researcher-workflow/plan.json'

class Researcher(unittest.TestCase):
    def setUp(self):
        # Reuse only fixture setup, not the old smoke test methods.
        smoke_tests.SshRun.setUp(self)
        site=self.root/'site'; site.mkdir()
        for name in ('batch.sh','gpu.sh','hello.c','hello_threads.cpp','vector_add.cu'):
            shutil.copyfile(ROOT/'infra/roles/apps_env/files/examples'/name,site/name)
        self.env2=patch.dict(os.environ,{'HS_SITE':str(site)})
        self.env2.start(); self.addCleanup(self.env2.stop)
        standin=(ROOT/'harness/tests/researcher_scheduler_fixture.py.txt').read_text()
        script=FAKE_SSH.replace('s.command=command',standin).replace('ROOT',repr(str(ROOT)),1)
        (self.bin/'ssh').write_text(script)

    def execute(self,name='researcher'):
        return run_scenario(self.root/name,name,PLAN,ssh_config=self.config,allow_remote=True)

    def test_two_jobs_original_and_replay_outputs_survive_reset(self):
        value=self.execute()
        self.assertEqual(value['slurm_job_ids'],['8101','8102','8103','8104'])
        self.assertFalse((self.fs/'runs/researcher').exists())
        self.assertEqual(verify_scenario_run(self.root/'researcher'),value)
        original=json.loads((self.root/'researcher/record-results-ok.json').read_text())
        self.assertEqual([f['path'] for f in original['files']],['results/batch.out','results/gpu.out'])
        self.assertIn('cuda ok:',original['files'][1]['content'])
        calls=[json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual(sum(c['role']=='prace-observer' and c['operation']=='researcher-proof' for c in calls),4)
        original['files'][0]['content']='false result'
        (self.root/'researcher/record-results-ok.json').write_text(json.dumps(original))
        with self.assertRaises(ContractError):verify_scenario_run(self.root/'researcher')

    @unittest.skipUnless(importlib.util.find_spec('nat'), 'real NeMo runtime is exercised in nemo-harness-tests')
    def test_real_nemo_model_free_researcher_cycle(self):
        value=run_scenario(self.root/'nemo','researcher-nemo',PLAN,driver='nemo',executable=sys.executable,
                           ssh_config=self.config,allow_remote=True)
        self.assertEqual(value['status'],'complete')
        self.assertEqual(len(value['slurm_job_ids']),4)
        self.assertFalse(value['llm_used'])
        self.assertEqual(verify_scenario_run(self.root/'nemo'),value)
        replay=json.loads((self.root/'nemo/agent-replay-trace.json').read_text())
        self.assertEqual((value['replay_driver'],replay['replayed'],replay['model_used']),('nemo',len(replay['actions']),False))

    def test_changed_site_source_refuses_and_retains_failed_run(self):
        (self.root/'site/hello.c').write_text('changed')
        with self.assertRaises(ContractError):self.execute('changed')
        self.assertEqual(json.loads((self.root/'changed/run.json').read_text())['status'],'failed')
        self.assertEqual(json.loads(self.jobs.read_text()),{})

    def test_plan_refuses_second_missing_capture_and_extra_program(self):
        plan,scenario=load_plan(PLAN)
        for fault in ('capture','program','digest'):
            changed=copy.deepcopy(scenario)
            action=next(a for a in changed['actions'] if a['id']=='submit-gpu-example')
            if fault=='capture':action['capture']={}
            if fault=='program':action['parameters']['program']='id'
            if fault=='digest':action['parameters']['example_sha256']='0'*64
            with self.assertRaises(ValueError):validate_plan(plan,changed)
        bound=bind_run(scenario,Path('/projects/proj-ops/.prace-smoke/runs/x/workspace'),'x')
        copy_action=next(a for a in bound['actions'] if a['kind']=='file.copy')
        self.assertIn('/runs/x/workspace/',copy_action['parameters']['destination'])

    def test_wrong_account_or_script_is_not_success(self):
        for fault in ('HS_WRONG_ACCOUNT','HS_WRONG_SCRIPT'):
            with patch.dict(os.environ,{fault:'1'}), self.assertRaises(ContractError):self.execute(fault.lower())

    def test_copy_refuses_existing_destination_without_changes(self):
        import io
        import types
        from validation.adapters import prace_file_ops_helper as helper
        base=self.root/'copy-root';workspace=base/'runs/one/workspace'
        workspace.mkdir(parents=True,mode=0o750);workspace.parent.chmod(0o750)
        source=workspace/'source';source.write_text('original')
        destination=workspace/'dest';destination.write_text('keep')
        request={'operation':'file.copy','parameters':{'path':str(source),'destination':str(destination)}}
        with patch.object(helper,'ALLOWED_ROOTS',(str(base),)), patch.object(sys,'stdin',types.SimpleNamespace(buffer=io.BytesIO(json.dumps(request).encode()))):
            self.assertEqual(helper.main(['helper','rpc']),17)
        self.assertEqual(destination.read_text(),'keep')

    def test_regular_bounded_output_and_no_overwrite(self):
        root=self.root/'output';root.write_text('hi')
        self.assertEqual(r.read_output(root),b'hi')
        link=self.root/'link';link.symlink_to(root)
        with self.assertRaises((OSError,ValueError)):r.read_output(link)
        root.write_bytes(b'x'*4097)
        with self.assertRaises(ValueError):r.read_output(root)

if __name__=='__main__':unittest.main()

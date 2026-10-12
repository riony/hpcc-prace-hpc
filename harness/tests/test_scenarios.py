"""Local sockets, fake SSH and fake Slurm; these tests cannot contact a fleet."""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from harness.runner import ROOT, write_json
from harness.scenario import load_plan, load_ssh, validate_plan
from harness.scenario_run import run_scenario, verify_scenario_run
from validation.adapters.file_discovery import discover, inventory
from validation.adapters import file_discovery
from validation.adapters import slurm_smoke
from validation.contracts import ContractError
from validation.local_fs import LocalFsAdapter
from validation.replay import AdapterResult, FakeAdapter
from validation.tracer.service import TracerService
from validation.verdict import evaluate

EXAMPLES = ROOT / "harness/examples"


class Plans(unittest.TestCase):
    def setUp(self):
        self.plan, self.scenario = load_plan(EXAMPLES / "file-discovery.plan.json")

    def test_explicit_discovery_execution_and_completion(self):
        self.assertEqual(self.scenario["execution"]["mode"], "discovery")
        self.assertEqual(self.scenario["execution"]["required_actions"], self.plan["required_actions"])

    def test_unsupported_or_unobserved_scenarios_refuse(self):
        variants = []
        for field, value in [("status", "ready"), ("gates", ["live-go"]), ("actor", {
                "identity": "syn-smoke", "project": "proj-ops", "intent": "malicious"})]:
            scenario = copy.deepcopy(self.scenario); scenario[field] = value
            variants.append((self.plan, scenario))
        bad = copy.deepcopy(self.plan); bad["checks"].pop(); variants.append((bad, self.scenario))
        bad = copy.deepcopy(self.plan); bad["checks"][0]["entries"][0]["path"] = "../escape"; variants.append((bad, self.scenario))
        bad = copy.deepcopy(self.plan); bad["seed_files"][0]["path"] = "../owner-note"; variants.append((bad, self.scenario))
        bad = copy.deepcopy(self.plan); bad["required_actions"] = ["shell.execute"]; variants.append((bad, self.scenario))
        for plan, scenario in variants:
            with self.subTest(plan=plan, scenario=scenario), self.assertRaises(ContractError):
                validate_plan(plan, copy.deepcopy(scenario))

    def test_check_ids_cannot_overwrite_runtime_or_bundle_files(self):
        for name in ('environment', 'failure-cleanup', 'run', 'manifest', 'plan', 'agent-trace', 'result', 'gateway', 'nemo-config', 'driver', 'bundle'):
            plan, scenario = copy.deepcopy(self.plan), copy.deepcopy(self.scenario)
            old = plan['checks'][0]['id']; plan['checks'][0]['id'] = name
            next(item for item in scenario['assertions'] if item['id'] == old)['id'] = name
            with self.subTest(name=name), self.assertRaisesRegex(ContractError, 'conflicts'):
                validate_plan(plan, scenario)

    def test_fixed_job_cannot_accept_a_program_or_other_account(self):
        plan, scenario = load_plan(EXAMPLES / "cluster-smoke.plan.json")
        for key, value in [("program", "arbitrary"), ("account", "proj-alpha"), ("run_id", "foreign")]:
            bad = copy.deepcopy(scenario); bad["actions"][-2]["parameters"][key] = value
            with self.subTest(key=key), self.assertRaises(ContractError):
                validate_plan(plan, bad)

    def test_missing_completion_and_replay_never_pass(self):
        self.assertEqual(evaluate(self.scenario, [])[0]["functional"], "inconclusive")


class FileDiscovery(unittest.TestCase):
    def test_actor_outputs_cannot_inherit_group_write_from_project_acl(self):
        from validation.adapters import prace_file_ops_helper as helper
        import contextlib,io
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            subprocess.run(['bash',str(ROOT/'infra/roles/storage_policy/files/prace-project-acl'),str(root)],
                           check=True,capture_output=True)
            (root/'runs').mkdir()
            workspace=root/'runs'/'acl-run'/'workspace'
            mask=os.umask(0o077)
            try:
                with patch.object(helper,'ALLOWED_ROOTS',(str(root),)), contextlib.redirect_stdout(io.StringIO()):
                    helper._prepare(workspace)
                    self.assertEqual(helper.main(['helper','file.mkdir',str(workspace/'nested/demo-dir'),'1']),0)
                    for path in (workspace/'nested/demo-dir/test.txt',workspace/'implicit/parent/file.txt'):
                        self.assertEqual(helper.main(['helper','file.write',str(path),'fixture']),0)
                        self.assertEqual(helper.main(['helper','file.write',str(path),'rewritten']),0)
                        self.assertEqual(path.stat().st_mode & 0o777,0o640)
                        self.assertEqual(path.read_text(),'rewritten')
                for path in (workspace.parent,workspace,workspace/'nested',workspace/'nested/demo-dir',
                             workspace/'implicit',workspace/'implicit/parent'):
                    self.assertEqual(path.stat().st_mode & 0o777,0o750)
                # With POSIX ACLs, group mode bits are the effective ACL mask.
                # Group read/traverse is retained for the separate observer.
                acl=subprocess.check_output(['getfacl','-cpn',str(workspace/'nested/demo-dir/test.txt')],text=True)
                self.assertIn('mask::r--',acl)
            finally:
                os.umask(mask)

    def test_prepare_sets_only_new_run_modes_under_restrictive_umask(self):
        from validation.adapters import prace_file_ops_helper as helper
        import contextlib,io
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); (root/'runs').mkdir()
            workspace=root/'runs'/'new'/'workspace'
            mask=os.umask(0o077)
            try:
                with patch.object(helper,'ALLOWED_ROOTS',(str(root),)), contextlib.redirect_stdout(io.StringIO()):
                    helper._prepare(workspace); helper._run_workspace(workspace)
                self.assertEqual(workspace.stat().st_mode & 0o777,0o750)
                self.assertEqual(workspace.parent.stat().st_mode & 0o777,0o750)
                self.assertEqual(os.umask(0o077),0o077)
            finally:
                os.umask(mask)

    def test_unreadable_root_or_nested_directory_never_looks_empty(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / 'blocked').mkdir()
            original = file_discovery.os.scandir
            def unreadable(path):
                if Path(path) == root / 'blocked': raise PermissionError('unreadable fixture')
                return original(path)
            with patch.object(file_discovery.os, 'scandir', side_effect=unreadable), self.assertRaises(PermissionError):
                inventory(root)
            with patch.object(file_discovery.os, 'scandir', side_effect=PermissionError), self.assertRaises(PermissionError):
                discover('file.list', {'path': str(root)})

    def test_limit_is_applied_before_sorting_or_full_enumeration(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); item = root / 'item'; item.touch(); calls = []
            def many(path):
                for index in range(10000):
                    calls.append(index); yield item, item.lstat()
            with patch.object(file_discovery, 'children', side_effect=many), self.assertRaises(ValueError):
                discover('file.list', {'path': str(root)})
            self.assertEqual(len(calls), 33)
            calls.clear()
            with patch.object(file_discovery, 'children', side_effect=many), self.assertRaises(ValueError): inventory(root)
            self.assertEqual(len(calls), 33)

    def test_helper_run_scope_and_modes_are_verified_with_lstat(self):
        from validation.adapters import prace_file_ops_helper as helper
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); runs=root/'runs'; runs.mkdir()
            owner=runs/'owned'; owner.mkdir(mode=0o750); workspace=owner/'workspace'; workspace.mkdir(mode=0o750)
            with patch.object(helper,'ALLOWED_ROOTS',(str(root),)):
                helper._action_path(workspace/'new-file')
                workspace.chmod(0o777)
                with self.assertRaisesRegex(ValueError,'ownership/mode'): helper._run_workspace(workspace)
                workspace.chmod(0o750)
                with self.assertRaisesRegex(ValueError,'outside its run'): helper._action_path(owner/'slurm-ticket.json')
                with self.assertRaisesRegex(ValueError,'escapes its run'): helper._action_path(workspace/'..'/'slurm-ticket.json')
                (workspace/'ticket-link').symlink_to(owner/'slurm-ticket.json')
                with self.assertRaisesRegex(ValueError,'escapes its run'): helper._action_path(workspace/'ticket-link')
                other=runs/'other'; other.symlink_to(owner)
                with self.assertRaisesRegex(ValueError,'link refused'): helper._run_workspace(other/'workspace')

    def test_list_and_numeric_permission_facts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "input").write_text("synthetic")
            (root / "input").chmod(0o640)
            self.assertEqual(json.loads(discover("file.list", {"path": str(root)})["listing"]),
                             [{"name": "input", "kind": "file"}])
            facts = json.loads(discover("file.stat", {"path": str(root / "input")})["metadata"])
            self.assertEqual(facts["mode"], 0o640)
            self.assertEqual(facts["uid"], os.getuid())
            self.assertNotIn("content", facts)

    def test_links_limits_and_extra_parameters_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); (root / "link").symlink_to(root)
            with self.assertRaises(ValueError): discover("file.stat", {"path": str(root / "link")})
            with self.assertRaises(ValueError): discover("file.list", {"path": str(root), "command": "id"})
            for index in range(33): (root / str(index)).touch()
            with self.assertRaises(ValueError): discover("file.list", {"path": str(root)})
            with self.assertRaises(ValueError): inventory(root)


class LocalRun(unittest.TestCase):
    def test_tracer_timeout_and_bad_json_retain_action_and_failure_snapshot(self):
        import types
        plan, scenario = load_plan(EXAMPLES/'file-discovery.plan.json')
        for fault in (subprocess.TimeoutExpired('fake inspection', 1), ValueError('fake invalid JSON')):
            with self.subTest(fault=type(fault).__name__), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                def unavailable(workspace): raise fault
                service=TracerService(scenario=scenario, run_dir=root, run_id='tracer-failure',
                    adapter=FakeAdapter({'inspect-root':AdapterResult('ok',0)}), workspace=root,
                    cluster_audit=types.SimpleNamespace(inventory_workspace=unavailable), cluster_snapshot_kind='inventory')
                response=service.handle({'method':'execute_action','action_id':'inspect-root','phase':'attack'})
                self.assertFalse(response['ok']); self.assertTrue(service.handle({'method':'ping'})['ok'])
                rows=[json.loads(line) for line in (root/'events.jsonl').read_text().splitlines()]
                self.assertEqual([row['event_type'] for row in rows], ['action','cluster'])
                self.assertEqual(rows[1]['snapshot']['code'],'workspace-inventory-unavailable')
                self.assertEqual(rows[1]['snapshot']['status'],'mismatch')

    def test_symlinked_output_parent_refuses_before_any_write(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); target=root/'target'; target.mkdir(); (root/'link').symlink_to(target)
            with self.assertRaisesRegex(ContractError,'parent link'):
                run_scenario(root/'link/run','linked',EXAMPLES/'file-discovery.plan.json')
            self.assertEqual(list(target.iterdir()), [])

    def test_missing_snapshot_or_false_pass_is_rejected_read_only(self):
        with tempfile.TemporaryDirectory(prefix="hv-") as temporary:
            run=Path(temporary)/"run"
            run_scenario(run,"verify-negative",EXAMPLES/"file-discovery.plan.json")
            result_path=run/"result.json"; original=result_path.read_bytes()
            result=json.loads(original); result["counts"]["actions"]+=1; result_path.write_text(json.dumps(result))
            with self.assertRaises(ContractError): verify_scenario_run(run)
            result_path.write_bytes(original)
            trace=run/"events.jsonl"; rows=[json.loads(line) for line in trace.read_text().splitlines()]
            without_replay=[row for row in rows if not (row["event_type"]=="action" and row["phase"]=="replay")]
            scenario=json.loads((run/"manifest.json").read_text())
            self.assertEqual(evaluate(scenario,without_replay)[0]["functional"],"inconclusive")
            rows=[row for row in rows if not (row["event_type"]=="cluster" and row["correlated_action_sequence"]==1)]
            for index,row in enumerate(rows,1): row["sequence"]=index
            trace.write_text(''.join(json.dumps(row)+'\n' for row in rows))
            with self.assertRaises(ContractError): verify_scenario_run(run)

    def test_configurable_discovery_actual_replay_and_observer(self):
        with tempfile.TemporaryDirectory(prefix="hd-") as temporary:
            run = Path(temporary) / "run"
            value = run_scenario(run, "discovery", EXAMPLES / "file-discovery.plan.json")
            self.assertEqual(value["status"], "complete")
            self.assertEqual(value["transport"], "local")
            self.assertEqual(value["slurm_job_ids"], [])
            self.assertEqual(verify_scenario_run(run), value)
            events = [json.loads(line) for line in (run / "events.jsonl").read_text().splitlines()]
            recorded = [row for row in events if row["event_type"] == "action" and row["phase"] == "attack"]
            replayed = [row for row in events if row["event_type"] == "action" and row["phase"] == "replay"]
            self.assertEqual([row["action_id"] for row in recorded], [row["action_id"] for row in replayed])
            self.assertIn("root_listing", recorded[0]["result"]["bindings"])
            self.assertEqual(json.loads((run / "result.json").read_text())["verdicts"]["functional"], "pass")
            proof_path = run / "record-layout-ok.json"
            proof = json.loads(proof_path.read_text()); proof["entries"] = []
            proof_path.write_text(json.dumps(proof))
            with self.assertRaisesRegex(ContractError, "contradicts"):
                verify_scenario_run(run)

    def test_preexisting_output_and_unconfigured_remote_refuse_before_actions(self):
        with tempfile.TemporaryDirectory() as temporary:
            existing = Path(temporary); (existing / "keep").touch()
            with self.assertRaises(ContractError): run_scenario(existing, "new", EXAMPLES / "file-discovery.plan.json")
            self.assertTrue((existing / "keep").exists())
            with self.assertRaisesRegex(ContractError, "SSH"):
                run_scenario(existing / "new", "new", EXAMPLES / "cluster-smoke.plan.json")
            self.assertFalse((existing / "new").exists())

    def test_failed_observation_keeps_failed_record_and_cleans_owned_workspace(self):
        with tempfile.TemporaryDirectory(prefix="hf-") as temporary:
            run = Path(temporary) / "run"
            original = LocalFsAdapter.inventory_workspace
            def wrong(adapter, workspace):
                actual = original(adapter, workspace)
                if (workspace / "marker.txt").exists(): actual["entries"].pop()
                return actual
            with patch.object(LocalFsAdapter, "inventory_workspace", wrong), self.assertRaises(ContractError):
                run_scenario(run, "bad-observer", EXAMPLES / "file-discovery.plan.json")
            self.assertEqual(json.loads((run / "run.json").read_text())["status"], "failed")
            self.assertEqual(list((run / "workspace").iterdir()), [])

    def test_gateway_enforces_budget_before_side_effect(self):
        plan, scenario = load_plan(EXAMPLES / "file-discovery.plan.json")
        scenario["budgets"]["max_actions"] = 1
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); adapter = FakeAdapter({"inspect-root": AdapterResult("ok", 0)})
            service = TracerService(scenario=scenario, run_dir=root, run_id="budget", adapter=adapter, workspace=root)
            first = service.handle({"method": "execute_action", "action_id": "inspect-root", "phase": "attack"})
            second = service.handle({"method": "execute_action", "action_id": "inspect-root", "phase": "attack"})
            self.assertTrue(first["ok"]); self.assertFalse(second["ok"])
            self.assertEqual(len(adapter.calls), 1)


FAKE_SSH = r'''#!/usr/bin/env python3
import json, os, pathlib, sys, types
sys.path.insert(0, ROOT)
from validation.adapters import prace_file_ops_helper as h, slurm_smoke as s
alias=sys.argv[-2]
roles={'prace-actor':('syn-smoke',2001),'prace-tracer':('syn-tracer',2002),'prace-observer':('syn-observer',2003)}
if alias not in roles or sys.argv[-1] != '/reviewed/helper rpc': raise SystemExit(99)
request=json.load(sys.stdin)
op=request['operation']
with open(os.environ['HS_CALLS'],'a') as out: out.write(json.dumps({'role':alias,'operation':op,'argv':sys.argv[1:]})+'\n')
if op=='capabilities':
    name,uid=roles[alias]
    if os.environ.get('HS_SAME_UID'): uid=2001
    digests=h.helper_digests()
    if os.environ.get('HS_BAD_HELPER'): digests['file_discovery.py']='0'*64
    caps={'protocol':'prace.helper.v2','identity':name,'uid':uid,'helper_digests':digests}
    if not os.environ.get('HS_NO_ENVIRONMENT'): caps['execution_environment']='ssh-stand-in'
    if os.environ.get('HS_MIXED_ENVIRONMENT') and alias=='prace-observer': caps.pop('execution_environment',None)
    print(json.dumps(caps))
    raise SystemExit(0)
physical=pathlib.Path(os.environ['HS_FS'])
virtual='/projects/proj-ops/.prace-smoke'
original_workspace=request['parameters'].get('workspace')
for key,value in list(request['parameters'].items()):
    if isinstance(value,str) and value.startswith(virtual): request['parameters'][key]=str(physical)+value[len(virtual):]
h.ALLOWED_ROOTS=(str(physical),)
# This is a transport/identity stand-in, not a test of OS user separation.
s.pwd.getpwuid=lambda uid: types.SimpleNamespace(pw_name=roles[alias][0])
def command(args):
    state_path=pathlib.Path(os.environ['HS_JOBS'])
    state=json.loads(state_path.read_text())
    if args[0]=='sbatch':
        if '--wrap=/bin/true' not in args or '--nodes=1' not in args or '--mem=32M' not in args:
            raise SystemExit(99)
        job=str(8100+len(state)+1)
        def flag(name): return next(x.split('=',1)[1] for x in args if x.startswith(name+'='))
        state[job]=[job,'syn-smoke',flag('--account'),flag('--partition'),'COMPLETED','0:0',flag('--job-name'),
                    '1','32Mn','1',__import__('shlex').join(args),'1',
                    __import__('datetime').datetime.now(__import__('datetime').timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')]
        state_path.write_text(json.dumps(state))
        return job
    if args[0]=='sacct':
        if alias=='prace-observer' and os.environ.get('HS_FAIL_ACCOUNTING'): raise ValueError('fake accounting unavailable')
        if '-j' not in args:
            name=next(arg.split('=',1)[1] for arg in args if arg.startswith('--name='))
            return '\n'.join(row[0]+'|'+row[6] for row in state.values() if row[6]==name)
        row=state[args[args.index('-j')+1]].copy()
        if alias=='prace-observer' and os.environ.get('HS_WRONG_ACCOUNT'): row[2]='foreign-project'
        if alias=='prace-observer' and os.environ.get('HS_WRONG_SCRIPT'): row[10]=row[10].replace('/bin/true','/bin/false')
        return '|'.join(row)
    if args[0]=='squeue':
        if alias=='prace-observer' and state and os.environ.get('HS_HIDDEN_ACTIVE'): return sorted(state)[-1]+'|renamed-active-job'
        return ''
    if args[0]=='scancel': return ''
    raise SystemExit(99)
s.command=command
if op=='prepare':
    h._run_workspace(pathlib.Path(request['parameters']['workspace']))
    ws=pathlib.Path(request['parameters']['workspace'])
    mask=os.umask(0o027)
    try:
        ws.parent.mkdir(mode=0o750); ws.mkdir(mode=0o750)
    finally:
        os.umask(mask)
    if os.environ.get('HS_PREPARE_REPLY_LOST'): raise SystemExit(1)
    print(json.dumps({'ok':True,'workspace':original_workspace})); raise SystemExit(0)
payload=json.dumps(request).encode()
sys.stdin=types.SimpleNamespace(buffer=__import__('io').BytesIO(payload))
raise SystemExit(h.main(['helper','rpc']))
'''


class SshRun(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hs-"); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"; self.bin.mkdir()
        script = self.bin / "ssh"; script.write_text(FAKE_SSH.replace("ROOT", repr(str(ROOT)), 1)); script.chmod(0o700)
        self.fs = self.root / "simulated-cluster"; (self.fs / "runs").mkdir(parents=True)
        self.calls = self.root / "calls.jsonl"; self.calls.touch()
        self.jobs = self.root / "jobs.json"; self.jobs.write_text("{}")
        hosts = self.root / "known_hosts"; hosts.write_text("offline fixture only")
        roles = {}
        for role, identity in [("actor", "syn-smoke"), ("tracer", "syn-tracer"), ("observer", "syn-observer")]:
            key = self.root / role; key.write_text("offline fixture, not an SSH key"); key.chmod(0o600)
            roles[role] = {"identity": identity, "ssh_alias": "prace-" + role,
                          "remote_helper": "/reviewed/helper", "identity_file": str(key),
                          "known_hosts": str(hosts), "connect_timeout": 1}
        self.config = self.root / "ssh.json"
        write_json(self.config, {"schema": "prace.harness-ssh.v1", "roles": roles})
        self.env = patch.dict(os.environ, {"PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                "HS_FS": str(self.fs), "HS_CALLS": str(self.calls), "HS_JOBS": str(self.jobs)})
        self.env.start(); self.addCleanup(self.env.stop)

    def run_smoke(self, name="remote"):
        return run_scenario(self.root / name, name, EXAMPLES / "cluster-smoke.plan.json",
                            ssh_config=self.config, allow_remote=True)

    def test_stand_in_is_retained_in_bundle_and_missing_claim_is_unknown(self):
        from harness.evidence import package_run, verify_bundle
        value = self.run_smoke("stand-in")
        self.assertEqual(value["execution_environment"], "ssh-stand-in")
        bundle = self.root / "stand-in-bundle"
        package_run(self.root / "stand-in", bundle)
        self.assertEqual(verify_bundle(bundle)["execution_environment"], "ssh-stand-in")
        # Capture checked the installed helper against its source. Read-only
        # historical verification must not demand today's helper bytes.
        with patch("harness.scenario_run.helper_digests", return_value={k: "f" * 64 for k in
                json.loads((bundle / "environment.json").read_text())["actor"]["helper_digests"]}):
            self.assertEqual(verify_bundle(bundle)["execution_environment"], "ssh-stand-in")
        metadata = json.loads((bundle / "run.json").read_text())
        metadata["execution_environment"] = "ssh-unqualified"
        with self.assertRaises(ContractError): verify_scenario_run(bundle, metadata)
        with patch.dict(os.environ, {"HS_NO_ENVIRONMENT": "1"}):
            self.assertEqual(self.run_smoke("unqualified")["execution_environment"], "ssh-unqualified")

    def test_mixed_environment_claims_stop_before_prepare(self):
        with patch.dict(os.environ, {"HS_MIXED_ENVIRONMENT": "1"}), self.assertRaises(ContractError):
            self.run_smoke("mixed")
        self.assertFalse(any(json.loads(line)["operation"] == "prepare" for line in self.calls.read_text().splitlines()))

    def test_torn_trace_still_attempts_cleanup_and_retains_failure_record(self):
        import harness.scenario_run as orchestration
        original = orchestration.project_trace
        def tear(directory, *args, **kwargs):
            with (directory / "events.jsonl").open("a") as stream:
                stream.write('{"torn":')
            return original(directory, *args, **kwargs)
        with patch.object(orchestration, "project_trace", side_effect=tear), self.assertRaises(ContractError):
            self.run_smoke("torn")
        metadata = json.loads((self.root / "torn/run.json").read_text())
        self.assertEqual((metadata["status"], metadata["cleanup"]), ("failed", "unknown"))
        self.assertIn("trace_failure_type", metadata)
        self.assertTrue((self.root / "torn/failure-cleanup.json").exists())
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(any(row["operation"] == "reset" for row in calls))
        self.assertEqual(list((self.fs / "runs/torn/workspace").iterdir()), [])
        from harness.evidence import package_run
        with self.assertRaises((ContractError, OSError)): package_run(self.root / "torn", self.root / "refused-bundle")

    def test_reused_run_id_is_refused_before_preparing_workspace(self):
        self.jobs.write_text(json.dumps({'old':['old','syn-smoke','proj-ops','debug','COMPLETED','0:0','prace-smoke-reused']}))
        with self.assertRaises(ContractError): self.run_smoke('reused')
        self.assertFalse((self.fs/'runs/reused').exists())
        calls=[json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertTrue(any(row['role']=='prace-observer' and row['operation']=='jobs-preflight' for row in calls))
        self.assertFalse(any(row['operation']=='prepare' for row in calls))

    def test_lost_prepare_reply_records_unknown_cleanup_without_deleting(self):
        with patch.dict(os.environ, {'HS_PREPARE_REPLY_LOST':'1'}), self.assertRaises(ContractError):
            self.run_smoke('prepare-lost')
        record=json.loads((self.root/'prepare-lost/run.json').read_text())
        self.assertEqual(record['status'],'failed'); self.assertEqual(record['cleanup'],'unknown')
        self.assertTrue((self.fs/'runs/prepare-lost').exists())
        calls=[json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertFalse(any(row['operation'] in {'reset','finish'} for row in calls))

    def test_existing_ssh_adapter_three_roles_fixed_job_and_replay(self):
        value = self.run_smoke()
        self.assertEqual(value["slurm_job_ids"], ["8101", "8102"])
        self.assertEqual(value["cleanup"], "complete")
        self.assertFalse((self.fs / "runs/remote").exists())
        self.assertEqual(verify_scenario_run(self.root / "remote"), value)
        calls = [json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertEqual({row["role"] for row in calls}, {"prace-actor", "prace-tracer", "prace-observer"})
        self.assertEqual(sum(row["role"] == "prace-observer" and row["operation"] == "job-proof" for row in calls), 2)
        self.assertGreaterEqual(sum(row['role'] == 'prace-observer' and row['operation'] == 'jobs-clean' for row in calls), 3)
        self.assertEqual(sum(row["role"] == "prace-tracer" and row["operation"] == "inventory" for row in calls), 10)
        self.assertTrue(all("StrictHostKeyChecking=yes" in row["argv"] for row in calls))

    def test_remote_go_and_distinct_config_are_required_before_contact(self):
        with self.assertRaisesRegex(ContractError, "allow-remote"):
            run_scenario(self.root / "blocked", "blocked", EXAMPLES / "cluster-smoke.plan.json", ssh_config=self.config)
        self.assertEqual(self.calls.read_text(), "")
        cfg=json.loads(self.config.read_text()); cfg["roles"]["observer"]["identity_file"]=cfg["roles"]["actor"]["identity_file"]
        self.config.write_text(json.dumps(cfg))
        with self.assertRaisesRegex(ContractError, "distinct"): load_ssh(self.config, "syn-smoke")

    def test_actual_uid_or_helper_mismatch_stops_before_prepare(self):
        for name in ("HS_SAME_UID", "HS_BAD_HELPER"):
            with self.subTest(name=name), patch.dict(os.environ, {name: "1"}), self.assertRaises(ContractError):
                self.run_smoke(name.lower())
        calls=[json.loads(line) for line in self.calls.read_text().splitlines()]
        self.assertFalse(any(row["operation"] == "prepare" for row in calls))

    def test_existing_remote_workspace_is_not_reset(self):
        owner = self.fs / "runs/remote"; owner.mkdir(); (owner / "keep").write_text("owner file")
        with self.assertRaises(ContractError): self.run_smoke()
        self.assertEqual((owner / "keep").read_text(), "owner file")
        self.assertFalse(any(json.loads(line)["operation"] == "reset" for line in self.calls.read_text().splitlines()))

    def test_failed_or_wrong_accounting_is_never_a_pass(self):
        for flag in ("HS_FAIL_ACCOUNTING", "HS_WRONG_ACCOUNT"):
            name=flag.lower()
            with self.subTest(flag=flag), patch.dict(os.environ, {flag:"1"}), self.assertRaises(ContractError):
                self.run_smoke(name)
            record=json.loads((self.root/name/"run.json").read_text())
            self.assertEqual(record["status"], "failed")
            self.assertEqual(record["cleanup"], "not-run" if flag == "HS_FAIL_ACCOUNTING" else "error")

    def test_observer_rejects_wrong_script_and_actor_only_cleanup_claim(self):
        for flag in ('HS_WRONG_SCRIPT', 'HS_HIDDEN_ACTIVE'):
            name = flag.lower()
            with patch.dict(os.environ, {flag: '1'}), self.assertRaises(ContractError): self.run_smoke(name)
            record = json.loads((self.root / name / 'run.json').read_text())
            self.assertEqual(record['status'], 'failed')
            self.assertEqual(record['cleanup'], 'error')

    def test_ssh_run_packs_and_verifies_without_private_runtime_inputs(self):
        from harness.evidence import package_run, verify_bundle
        record = self.run_smoke()
        bundle = self.root / 'bundle'
        index = package_run(self.root / 'remote', bundle)
        self.assertEqual(index['schema'], 'prace.scenario-bundle.v1')
        self.assertEqual(verify_bundle(bundle), record)
        self.assertFalse((bundle / 'gateway.json').exists())
        self.assertFalse((bundle / 'nemo-config.json').exists())
        proof = json.loads((bundle / 'workspace-reset.json').read_text())
        self.assertEqual(len(proof['job_cleanup']['jobs']), 2)
        proof['job_cleanup']['jobs'].pop()
        (bundle / 'workspace-reset.json').write_text(json.dumps(proof))
        with self.assertRaises(ContractError): verify_bundle(bundle)


class JobCleanup(unittest.TestCase):
    def test_submission_warning_retains_receipt_but_never_passes(self):
        import types
        with tempfile.TemporaryDirectory() as temporary:
            workspace=Path(temporary)/'workspace'; workspace.mkdir()
            params={'workspace':str(workspace),'run_id':'warning','account':'proj-ops','partition':'debug'}
            with patch.object(slurm_smoke,'tool_path',return_value='/usr/bin/sbatch'), \
                    patch.object(slurm_smoke.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=b'123\n',stderr=b'warning')), \
                    self.assertRaises(slurm_smoke.CommandRefused):
                slurm_smoke.submit(workspace,params)
            ticket=json.loads(slurm_smoke.ticket_path(workspace).read_text())
            self.assertEqual(ticket['job_id'],'123')
            self.assertEqual(ticket['run_id'],'warning')

    def test_commands_use_absolute_executables_and_clean_environment(self):
        import types
        with patch.dict(os.environ, {'PATH':'/actor/bin','SLURM_CONF':'/actor/conf','LD_PRELOAD':'/actor/library'}), \
                patch.object(slurm_smoke,'tool_path',return_value='/usr/bin/sacct'), \
                patch.object(slurm_smoke.subprocess,'run',return_value=types.SimpleNamespace(returncode=0,stdout=b'',stderr=b'')) as call:
            self.assertEqual(slurm_smoke.command(['sacct','-n']), '')
        self.assertEqual(call.call_args.args[0], ['/usr/bin/sacct','-n'])
        self.assertEqual(set(call.call_args.kwargs['env']), {'PATH','LC_ALL','TZ','SLURM_TIME_FORMAT'})
        self.assertEqual(call.call_args.kwargs['env']['PATH'], '/usr/bin:/bin')

    def test_helper_ignores_actor_python_path_and_startup_modules(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary); marker=root/'injected'; shim=root/'python3'
            shim.write_text('#!/bin/sh\nexit 99\n'); shim.chmod(0o755)
            (root/'sitecustomize.py').write_text('from pathlib import Path; Path('+repr(str(marker))+').touch()')
            import shutil
            for name in ('prace_file_ops_helper.py','file_discovery.py','slurm_smoke.py','researcher_workflow.py'):
                shutil.copyfile(ROOT/'validation/adapters'/name,root/name)
            helper=root/'prace_file_ops_helper.py'; helper.chmod(0o755)
            with patch.dict(os.environ,{'PATH':str(root),'PYTHONPATH':str(root)}):
                done=subprocess.run([str(helper),'rpc'],input='{"operation":"capabilities","parameters":{}}',
                                    capture_output=True,text=True)
            self.assertEqual(done.returncode,0,done.stderr)
            self.assertEqual(len(json.loads(done.stdout)['helper_digests']),4)
            self.assertFalse(marker.exists())

    def test_pending_job_cancel_is_scoped_and_verified(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace=Path(temporary)/"workspace"; workspace.mkdir()
            import pwd
            actor=pwd.getpwuid(os.getuid()).pw_name
            ticket={"workspace":str(workspace),"run_id":"test","account":"proj-ops","partition":"debug",
                    "actor":actor,"job_id":"123","started_epoch":1704067200}
            path=slurm_smoke.ticket_path(workspace); path.write_text(json.dumps(ticket)); path.chmod(0o600)
            calls=[]
            def command(args):
                calls.append(args)
                if args[0]=='squeue': return '123|prace-smoke-test\n999|unrelated' if len(calls)==1 else '999|unrelated'
                if args[0]=='scancel': return ''
                if args[0]=='sacct': return f'123|{actor}|proj-ops|debug|CANCELLED|0:0|prace-smoke-test|1|32M|1|' + __import__('shlex').join(slurm_smoke.submission_argv(ticket))+'|1|2024-01-01T00:00:00'
                raise AssertionError(args)
            with patch.object(slurm_smoke,'command',side_effect=command): slurm_smoke.cleanup(workspace)
            self.assertIn(['scancel','123'],calls)
            self.assertNotIn(['scancel','999'],calls)
            self.assertFalse(path.exists())

    def test_uncertain_submission_preserves_ticket_for_operator(self):
        with tempfile.TemporaryDirectory() as temporary:
            workspace=Path(temporary)/"workspace"; workspace.mkdir()
            import pwd
            ticket={"workspace":str(workspace),"run_id":"test","account":"proj-ops","partition":"debug",
                    "actor":pwd.getpwuid(os.getuid()).pw_name,"job_id":None,"started_epoch":1704067200}
            path=slurm_smoke.ticket_path(workspace); path.write_text(json.dumps(ticket)); path.chmod(0o600)
            with self.assertRaisesRegex(ValueError,"outcome unknown"), patch.object(slurm_smoke,"command") as command:
                slurm_smoke.cleanup(workspace)
            command.assert_not_called(); self.assertTrue(path.exists())

    def test_failed_query_cannot_claim_terminal_cleanup(self):
        params={"workspace":"/tmp/fixture","run_id":"test","account":"proj-ops","partition":"debug",
                "actor":"syn-smoke","job_id":"123","started_epoch":1704067200}
        with patch.object(slurm_smoke,"command",return_value=""),self.assertRaises(ValueError):
            slurm_smoke.job_proof(params)

    def test_accounting_uses_name_and_fixed_submission_without_comments(self):
        import shlex
        params = {'workspace':'/tmp/fixture','run_id':'test','account':'proj-ops','partition':'debug','actor':'syn-smoke','job_id':'123','started_epoch':1704067200}
        fields = ['123','syn-smoke','proj-ops','debug','COMPLETED','0:0','prace-smoke-test','1','32Mn','1',
                  shlex.join(slurm_smoke.submission_argv(params)), '1', '2024-01-01T00:00:00']
        with patch.object(slurm_smoke, 'command', return_value='|'.join(fields)) as command:
            proof = slurm_smoke.job_proof(params)
        self.assertEqual(proof['state'], 'COMPLETED')
        self.assertNotIn('Comment', command.call_args[0][0][-1])
        for column, wrong in [(6,'prace-smoke-other'),(7,'2'),(8,'64Mn'),(9,'2'),(10,fields[10].replace('/bin/true','/bin/false')),(11,'2'),(12,'2023-12-31T23:59:59')]:
            bad = fields.copy(); bad[column] = wrong
            with self.subTest(column=column), patch.object(slurm_smoke, 'command', return_value='|'.join(bad)), self.assertRaises(ValueError):
                slurm_smoke.job_proof(params)


if __name__ == "__main__": unittest.main()

"""Alice-only tracer diagnostic. Independent workload verification is SKIPPED."""
from __future__ import annotations
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

from harness.agent_trace import project_trace, validate_projection
from harness.runner import ROOT, checked_call, run_process, stop_process, write_json
from harness.scenario import bind_run, load_plan, load_ssh, validate_plan
from harness.scenario_run import ssh_adapter, inspect_clean
from validation.adapters.prace_file_ops_helper import helper_digests
from validation.cluster_tracer import validate_inventory_proof
from validation.contracts import load_json, load_scenario, require, sha256_json
from validation.replay import resolve_action
from validation.trace import read_events, validate_cluster_correlations
from validation.tracer.client import TracerClient

SCHEMA = 'prace.diagnostic-run.v1'
FILES = ('run.json', 'manifest.json', 'plan.json', 'events.jsonl', 'agent-trace.json',
         'result.json', 'report.md', 'cleanup.json')


def job_ids(events):
    return [value for e in events if e['event_type'] == 'action'
            and e['action']['kind'] == 'slurm.submit-example'
            for key, value in e['result']['bindings'].items() if key in {'cpu_job_id', 'gpu_job_id'}]


def result_for(events, generated_at):
    return {'schema': 'prace.diagnostic-result.v1', 'generated_at': generated_at,
            'trace_checks': 'PASS', 'independent_verification': 'SKIPPED', 'overall': 'UNVERIFIED',
            'verdicts': {'functional': 'UNVERIFIED', 'baseline': 'UNVERIFIED'}, 'cleanup': 'complete',
            'counts': {'actions': sum(e['event_type'] == 'action' for e in events),
                       'observations': 0, 'failed_observations': 0}}


def report_for(result):
    return ('# Alice-only tracing diagnostic\n\n'
            f"Trace checks: **{result['trace_checks']}**. Independent verification: **SKIPPED**. "
            'Overall: **UNVERIFIED**.\n\n'
            f"{result['counts']['actions']} gateway actions with correlated Alice-collected snapshots. "
            'One CPU job and one GPU job; no cluster replay. Cleanup checked through Alice.\n')


def verify_diagnostic(directory):
    m = load_json(directory / 'run.json')
    require(set(m) == {'schema','run_id','status','scope','source_revision','source_dirty','driver','transport',
                       'nemo_version','llm_used','model','recovery_point','slurm_job_ids','actor','started_epoch',
                       'scenario_sha256','plan_sha256','cleanup','independent_verification','overall'}, 'malformed diagnostic metadata')
    require(m['schema'] == SCHEMA and m['status'] == 'complete' and m['scope'] == 'alice-only-trace-diagnostic'
            and m['independent_verification'] == 'SKIPPED' and m['overall'] == 'UNVERIFIED', 'diagnostic cannot claim verified PASS')
    require(re.fullmatch(r'[a-z][a-z0-9-]{0,39}', m['run_id']) and re.fullmatch(r'[a-f0-9]{40}', m['source_revision'])
            and type(m['source_dirty']) is bool and type(m['started_epoch']) is int and m['started_epoch'] > 0,
            'invalid diagnostic provenance')
    require(m['driver'] == 'scripted' and m['transport'] == 'ssh' and m['nemo_version'] is None
            and m['llm_used'] is False and m['model'] is None and m['recovery_point'] is None,
            'unexpected diagnostic execution')
    require(set(m['actor']) == {'identity','uid'} and m['actor']['identity'] == 'syn-alice'
            and type(m['actor']['uid']) is int and m['actor']['uid'] > 0, 'wrong diagnostic actor')
    plan, scenario = load_json(directory / 'plan.json'), load_scenario(directory / 'manifest.json')
    validate_plan(plan, scenario, bound_run_id=m['run_id'])
    require(scenario['id'] == 'researcher-workflow' and scenario['actor']['identity'] == 'syn-alice'
            and scenario['actor']['project'] == 'proj-alpha'
            and scenario['boundaries']['paths'] == [f"/home/syn-alice/.prace-researcher/runs/{m['run_id']}/workspace"],
            'unexpected diagnostic workflow')
    require(sha256_json(plan) == m['plan_sha256'] and sha256_json(scenario) == m['scenario_sha256'], 'diagnostic manifest/plan changed')
    events = read_events(directory / 'events.jsonl', scenario)
    validate_cluster_correlations(events, require_complete=True)
    actions = [e for e in events if e['event_type'] == 'action']
    require(len(events) == 2 * len(actions) and [e['action_id'] for e in actions] == [a['id'] for a in scenario['actions']],
            'diagnostic actions incomplete or unexpected events')
    bindings = {}
    for i, action in enumerate(actions):
        require(events[2*i] == action and action['run_id'] == m['run_id'] and action['phase'] == 'record'
                and action['result']['status'] == 'ok' and action['result']['exit_code'] == 0, 'diagnostic action failed')
        template = scenario['actions'][i]
        require(action['result']['executed_sha256'] == sha256_json(resolve_action(template, bindings, scenario)), 'resolved diagnostic action changed')
        bindings.update(action['result']['bindings'])
        snapshot = events[2*i+1]
        require(snapshot['event_type'] == 'cluster' and snapshot['source'] == 'cluster_tracer'
                and snapshot['phase'] == 'record' and snapshot['correlated_action_sequence'] == action['sequence']
                and snapshot['snapshot']['status'] == 'match' and snapshot['snapshot']['code'] == 'workspace-inventory', 'missing diagnostic snapshot')
        proof = load_json(directory / f"cluster-snapshot-{action['sequence']}.json")
        validate_inventory_proof(proof)
        require(sha256_json(proof) == snapshot['snapshot']['evidence_sha256'], 'diagnostic snapshot altered')
    require(m['slurm_job_ids'] == job_ids(events) and len(m['slurm_job_ids']) == len(set(m['slurm_job_ids'])) == 2,
            'diagnostic requires two separate receipts')
    validate_projection(load_json(directory / 'agent-trace.json'), m['run_id'], 'scripted', None, events)
    cleanup = load_json(directory / 'cleanup.json')
    require(m['cleanup'] == 'complete' and cleanup['entries'] == [] and cleanup['job_ticket_present'] is False
            and cleanup['job_cleanup']['active_job_ids'] == []
            and [j['job_id'] for j in cleanup['job_cleanup']['jobs']] == m['slurm_job_ids'], 'diagnostic cleanup missing')
    result = load_json(directory / 'result.json')
    require(result == result_for(events, result['generated_at']), 'diagnostic verdict altered')
    datetime.strptime(result['generated_at'], '%Y-%m-%dT%H:%M:%S.%fZ')
    require((directory / 'report.md').read_text() == report_for(result), 'diagnostic report altered')
    return m


def run_diagnostic(output, run_id, ssh_config):
    require(re.fullmatch(r'[a-z][a-z0-9-]{0,39}', run_id), 'invalid diagnostic run ID')
    require(output.is_absolute() and not output.exists() and ROOT not in output.parents
            and not any(p.is_symlink() for p in (output, *output.parents)), 'new private output outside checkout required')
    plan, template = load_plan(ROOT / 'harness/examples/researcher-workflow.plan.json')
    row = load_ssh(ssh_config, 'syn-alice', diagnostic=True)['roles']['actor']
    adapter = ssh_adapter(row)
    caps = adapter.json_rpc('capabilities', {})
    require(caps['protocol'] == 'prace.helper.v2' and caps['identity'] == 'syn-alice'
            and type(caps['uid']) is int and caps['helper_digests'] == helper_digests(), 'Alice helper identity/digest mismatch')
    workspace = Path('/home/syn-alice/.prace-researcher/runs') / run_id / 'workspace'
    scenario = bind_run(template, workspace, run_id)
    revision = run_process(['git','rev-parse','HEAD'], 5).stdout.decode().strip()
    m = {'schema':SCHEMA, 'run_id':run_id, 'status':'failed', 'scope':'alice-only-trace-diagnostic',
         'source_revision':revision, 'source_dirty':bool(run_process(['git','status','--porcelain'],5).stdout),
         'driver':'scripted','transport':'ssh','nemo_version':None,'llm_used':False,'model':None,'recovery_point':None,
         'actor':{'identity':caps['identity'],'uid':caps['uid']},'slurm_job_ids':[], 'started_epoch':int(time.time()),
         'scenario_sha256':sha256_json(scenario),'plan_sha256':sha256_json(plan),'cleanup':'not-run',
         'independent_verification':'SKIPPED','overall':'UNVERIFIED'}
    output.mkdir(mode=0o700, parents=True)
    write_json(output / 'manifest.json', scenario); write_json(output / 'plan.json', plan)
    socket = Path('/tmp') / f"prace-diag-{run_id}.sock"
    require(not socket.exists(), 'diagnostic socket already exists')
    config = {k:v for k,v in row.items() if k != 'identity'}
    gateway = {'scenario':str(output/'manifest.json'),'run_dir':str(output),'run_id':run_id,'workspace':str(workspace),
               'socket_path':str(socket),'adapter':'ssh','adapter_config':config,
               'cluster_tracer':{'enabled':True,'adapter':'ssh','adapter_config':config,
                   'target':scenario['boundaries']['observation_targets'][0], 'require_on_finalize':True,'snapshot_kind':'inventory'}}
    server, prepared = None, False
    try:
        require(adapter.json_rpc('prepare', {'workspace':str(workspace)}) == {'ok':True,'workspace':str(workspace)}, 'diagnostic workspace not prepared')
        prepared = True
        write_json(output/'gateway.json', gateway)
        with (output/'gateway.log').open('xb') as log:
            (output/'gateway.log').chmod(0o600)
            server = subprocess.Popen([sys.executable,'-m','validation.tracer','--config',str(output/'gateway.json')],cwd=ROOT,stdout=log,stderr=log,start_new_session=True)
        for _ in range(250):
            if socket.exists(): break
            require(server.poll() is None, 'diagnostic gateway failed to start'); time.sleep(.02)
        require(socket.exists(), 'diagnostic gateway startup deadline')
        client = TracerClient(socket, timeout_seconds=1230)
        deadline = time.monotonic() + 1200
        for action in scenario['actions']:
            require(time.monotonic() < deadline, 'diagnostic deadline reached')
            print('diagnostic action: ' + action['id'], flush=True)
            event = checked_call(client,'execute_action',action_id=action['id'],phase='record')['event']
            require(event['result']['status'] == 'ok' and event['result']['exit_code'] == 0, 'diagnostic action failed')
        m['status'] = 'complete'
    finally:
        if server is not None: stop_process(server)
        socket.unlink(missing_ok=True)
        events = read_events(output/'events.jsonl', scenario, allow_empty=True) if (output/'events.jsonl').exists() else []
        m['slurm_job_ids'] = job_ids(events)
        write_json(output/'agent-trace.json', project_trace(output,run_id,'scripted',None,events))
        if prepared:
            try:
                adapter.reset_workspace(workspace)
                # A rejected submission without a receipt is not an accounted job.
                # reset_workspace refuses uncertain tickets before this point.
                cleanup_events = [e for e in events if e['event_type'] != 'action'
                    or e['action']['kind'] != 'slurm.submit-example' or e['result']['bindings']]
                proof = inspect_clean(adapter,workspace,scenario,cleanup_events,run_id,m['started_epoch'])
                write_json(output/'cleanup.json',proof)
                require(proof['entries'] == [] and proof['job_ticket_present'] is False
                        and proof.get('job_cleanup',{}).get('active_job_ids',[]) == [], 'diagnostic cleanup incomplete')
                require(adapter.json_rpc('finish',{'workspace':str(workspace)}) == {'ok':True}, 'diagnostic finish failed')
                m['cleanup'] = 'complete'
            except Exception:
                m.update(status='failed',cleanup='error')
                write_json(output/'run.json',m)
                raise
        write_json(output/'run.json',m)
    require(m['status'] == 'complete', 'diagnostic run failed')
    result = result_for(events,datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'))
    write_json(output/'result.json',result)
    (output/'report.md').write_text(report_for(result)); (output/'report.md').chmod(0o600)
    return verify_diagnostic(output)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--run-id'); p.add_argument('--output-dir',type=Path)
    p.add_argument('--ssh-config',type=Path); p.add_argument('--allow-remote',action='store_true')
    p.add_argument('--run-dir',type=Path,help='read-only trace and integrity check')
    args = p.parse_args()
    if args.run_dir:
        m = verify_diagnostic(args.run_dir)
    else:
        require(args.allow_remote and args.ssh_config and args.output_dir and args.run_id,'explicit remote inputs required')
        mask = os.umask(0o077)
        try: m = run_diagnostic(args.output_dir,args.run_id,args.ssh_config)
        finally: os.umask(mask)
    print(f"PASS trace checks {m['run_id']}; independent verification SKIPPED; overall UNVERIFIED")


if __name__ == '__main__': main()

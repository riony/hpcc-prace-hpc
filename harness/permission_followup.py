"""Explicit operator ACL repair, exact probe, model-free NeMo replay and regression.

Consumes an unmodified private continuous campaign. Uses the common cluster
lease/flock throughout and retains ownership even after a successful follow-up.
It neither recreates removed fixtures nor qualifies a whole-cluster restore.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import tempfile
import time

from harness import continuous as C
from harness.agent_trace import project_trace, project_replay_trace
from harness.continuous_store import Journal, load_rows, session_directory
from harness.nemo_replay import replay_config
from harness.session_store import process_start
from validation.adapters import prace_permission_repair as R
from validation.contracts import require, sha256_json, validate_scenario
from validation.replay import AdapterResult
from validation.trace import read_events, validate_cluster_correlations
from validation.tracer.service import TracerService

KEYS = {'schema', 'campaign_config', 'followup_root', 'followup_id', 'repair_helper', 'duration_seconds'}


def private_bytes(path, limit=16 * 1024 * 1024):
    path = Path(path)
    require(path.is_absolute() and path.resolve() == path, 'canonical retained artifact required')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= limit, 'private artifact required')
        return stream.read(limit + 1)


def load_config(path):
    value = C.private_json(path)
    require(isinstance(value, dict) and set(value) == KEYS and value['schema'] == 'prace.permission-followup.v1', 'follow-up schema')
    require(C.H.SID.fullmatch(value['followup_id']) and type(value['duration_seconds']) is int
            and 1 <= value['duration_seconds'] <= 600, 'follow-up ID/deadline')
    for name in ('campaign_config', 'followup_root'):
        p = Path(value[name]); require(p.is_absolute() and p.resolve() == p, 'canonical follow-up path')
    require(re.fullmatch(r'/apps/prace/[0-9a-f]{40}/prace_permission_repair\.py', value['repair_helper']),
            'revision-pinned companion helper required')
    return value


def campaign(config, key):
    """Re-derive provenance and every completed model/action binding before repair."""
    directory = Path(config['run_root']) / config['session_id']
    rows = load_rows(directory)
    require(rows[0]['event'] == 'started' and rows[-1]['event'] == 'stopped'
            and rows[-1]['reason'] == 'objective_achieved', 'completed objective campaign required')
    owner = C.private_json(directory / 'owner.json')
    require(set(owner) == {'pid', 'process_start'} and type(owner['pid']) is int
            and (owner['process_start'] is None or process_start(owner['pid']) != owner['process_start']),
            'recording process still active')
    policy = C.private_json(config['policy_file'])
    policy['policy_sha256'] = C.H.digest(private_bytes(config['policy_file']))
    require(C.private_json(directory / 'policy.json') == policy, 'retained policy differs from operator copy')
    require(policy['schema'] == C.H.PROTOCOL and policy['session_id'] == config['session_id']
            and policy['baseline_id'] == config['baseline_id'] and policy['kind'] == config['scenario']
            and policy['root'] == str(C.H.FIXTURES / config['session_id'])
            and policy['helper_sha256'] == C.H.source_digest(), 'recording helper/policy mismatch')
    manifest = validate_scenario(C.private_json(directory / 'manifest.json'))
    require(manifest == C.manifest(config, policy), 'declared catalog changed')
    start = rows[0]
    require(start['baseline_id'] == config['baseline_id'] and start['lease_id'] == config['lease_id']
            and start['helper_sha256'] == policy['helper_sha256'] and start['policy_sha256'] == policy['policy_sha256']
            and start['config_sha256'] == sha256_json(config) and start['manifest_sha256'] == sha256_json(manifest)
            and re.fullmatch(r'[0-9a-f]{40}', start['source_revision']) and start['source_dirty'] is False
            and start['framework_version'] == C.NAT_VERSION and start['model'] == config['model']
            and start['model_key_fingerprint'] == C.H.digest(key), 'campaign provenance mismatch')
    require(C.private_json(directory / 'config.json') == config, 'use original private config, not sanitized export')
    raw = private_bytes(directory / 'events.jsonl')
    events = read_events(directory / 'events.jsonl', manifest)
    require(all(e['run_id'] == config['session_id'] for e in events) and
            all(e['phase'] == 'attack' for e in events), 'foreign or already replayed source trace')
    validate_cluster_correlations(events, require_complete=True)
    recorded = [e for e in events if e['event_type'] == 'action']
    require(recorded and recorded[0]['action_id'] == manifest['actions'][0]['id']
            and recorded[0]['result']['status'] == 'ok' and recorded[0]['result']['exit_code'] == 0,
            'source must begin with successful declared discovery')
    results = [r for r in rows if r['event'] == 'action_result']
    require(len(recorded) == len(results) and all(r['event_sha256'] == sha256_json(e)
            and r['action_sequence'] == e['sequence'] and r['action_id'] == e['action_id']
            and r['identity'] == e['action']['identity'] and r['status'] == e['result']['status']
            and r['job_ids'] == [] for r, e in zip(results, recorded)), 'action attribution/jobs mismatch')
    expected = {a['id']: a for a in manifest['actions']}
    from validation.replay import resolve_action
    for e in recorded:
        action = expected[e['action_id']]
        require(e['result']['executed_sha256'] == sha256_json(resolve_action(action, {}, manifest)),
                'foreign executed path/action')
    attempts = [r for r in rows if r['event'] == 'attempt_started']
    finished = [r for r in rows if r['event'] == 'attempt_finished']
    require(len(attempts) == len(finished) and len(attempts) > 0, 'interrupted source attempt')
    consumed = set()
    for index, (begin, end) in enumerate(zip(attempts, finished), 1):
        attempt = config['session_id'] + '-a' + str(index)
        require(begin['attempt_id'] == end['attempt_id'] == attempt, 'foreign attempt ID')
        selected = [e for r, e in zip(results, recorded) if r['attempt_id'] == attempt]
        consumed.update(e['sequence'] for e in selected)
        projection = project_trace(directory / attempt, config['session_id'], 'nemo', C.NAT_VERSION, selected)
        require(json.loads(private_bytes(directory / attempt / 'agent-trace.json')) == projection,
                'model projection changed')
        require(C.trace_calls(directory / attempt) == end['model_calls'] and end['model_calls'] > 0,
                'model telemetry incomplete')
        proof = C.private_json(directory / attempt / 'objective.json')
        require(sha256_json(proof) == end['proof_sha256'], 'objective proof changed')
        prefix = [e for e in events if e['sequence'] <= max((e['sequence'] for e in selected), default=0)]
        require(C.objective_met(config, policy, proof, prefix) == end['objective'], 'objective contradicts journal')
    require(consumed == {e['sequence'] for e in recorded} and finished[-1]['objective'] is True,
            'unbound source actions')
    C.credential_absent(directory, key)
    # Hash all original retained artifacts; the follow-up never writes here.
    originals = {str(p): C.H.digest(private_bytes(p)) for p in directory.rglob('*') if p.is_file()}
    return policy, manifest, raw, rows, originals


class FollowupBackend(C.PhysicalBackend):
    def __init__(self, config, policy, followup):
        super().__init__(config, policy)
        self.followup = followup
        self.guard = self.check

    def companion(self, role, operation):
        self.guard()
        import shlex
        from harness.scenario_run import ssh_adapter
        command = ssh_adapter(self.roles[role])._ssh_base()
        command[-1:-1] = ['-o', 'ForwardAgent=no', '-o', 'ForwardX11=no', '-o', 'ClearAllForwardings=yes',
                          '-o', 'PermitLocalCommand=no']
        request = {'operation': operation, 'parameters': R.binding(self.policy) |
                   {'repair_helper_sha256': R.source_digest()}}
        request_raw = json.dumps(request).encode()
        if self.journal: self.journal.append('companion_intent', role=role, operation=operation,
                                             request_sha256=C.H.digest(request_raw))
        result = subprocess.run(command + [shlex.join([self.followup['repair_helper'], 'rpc'])],
            input=request_raw, capture_output=True, timeout=30, env=C.runtime_env())
        if self.journal: self.journal.append('companion_result', role=role, operation=operation, exit_code=result.returncode,
            stdout_sha256=C.H.digest(result.stdout), stderr_sha256=C.H.digest(result.stderr))
        require(result.returncode == 0 and not result.stderr and len(result.stdout) <= 65536, 'companion RPC failed')
        self.guard()
        return json.loads(result.stdout)

    def operator(self, operation, before=None):
        self.guard()
        require(operation in {'inspect', 'repair', 'regression'}, 'operator operation')
        request = {'binding': R.binding(self.policy) | {'repair_helper_sha256': R.source_digest()},
            'lease_id': self.config['lease_id'], 'followup_id': self.followup['followup_id'],
            'snapshot_sha256': sha256_json(before) if before else None}
        # window.login has no stdin contract; use its established SSH argv, with
        # the same common operation flock already held for this whole workflow.
        import shlex
        command = list(self.window.SSH)
        if Path(command[0]).name == 'ssh':
            command[-1:-1] = ['-o', 'ForwardAgent=no', '-o', 'ClearAllForwardings=yes', '-o', 'PermitLocalCommand=no']
        request_raw = json.dumps(request).encode()
        if self.journal: self.journal.append('operator_intent', operation=operation, request_sha256=C.H.digest(request_raw))
        result = subprocess.run(command + [shlex.join([self.followup['repair_helper'], operation])],
            input=request_raw, capture_output=True, timeout=30, env=C.runtime_env())
        if self.journal: self.journal.append('operator_result', operation=operation, exit_code=result.returncode,
            stdout_sha256=C.H.digest(result.stdout), stderr_sha256=C.H.digest(result.stderr))
        require(result.returncode == 0 and not result.stderr and len(result.stdout) <= 65536, 'operator helper failed')
        self.guard()
        return json.loads(result.stdout)

    def execute(self, action_id, action, timeout):
        self.guard()
        require(not self.should_stop(), 'follow-up no longer accepting replay')
        try:
            response = self.call('actor', action['kind'], action['parameters'], timeout)
            # The unchanged, capability-checked helper emits this exact EACCES
            # diagnostic. SSH failure or an arbitrary exit 13 is not proof.
            denied = (response.returncode == 13 and not response.stdout and
                      response.stderr == b'REFUSED: filesystem authorization\n')
            success = response.returncode == 0 and not response.stderr
            state = 'ok' if success else 'denied' if denied else 'error'
            outputs = json.loads(response.stdout)['outputs'] if success else {}
            result = AdapterResult(state, response.returncode, outputs=outputs)
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            result = AdapterResult('error', None)
        self.guard()
        return result


class ReplayGateway:
    def __init__(self, service, backend, journal, check):
        self.service, self.backend, self.journal, self.check = service, backend, journal, check
        self.accepting = True; self.failure = None

    def handle(self, request):
        from validation.tracer.protocol import err
        try:
            self.check()
            require(self.accepting and isinstance(request, dict) and
                    set(request) <= {'method', 'request_id'} and request.get('method') in {'ping', 'replay_next'},
                    'operator replay gateway only')
            if request['method'] == 'replay_next': self.journal.append('replay_step_intent')
            response = self.service.handle(request)
            require(response.get('ok') is True, 'replay gateway failed')
            if 'event' in response:
                event = response['event']
                self.journal.append('replay_step_result', event_sha256=sha256_json(event),
                    action_id=event['action_id'], action_sequence=event['sequence'], job_ids=[],
                    followup_id=self.backend.followup['followup_id'], identity=event['action']['identity'])
            self.check()
            return response
        except Exception:
            self.failure = 'ReplayUncertain'
            return err('replay requires inspection', request.get('request_id') if isinstance(request, dict) else None)


def verify_recording_helpers(backend, policy, journal, stage, original=None):
    """Check the actual replay RPC paths, independently of the companion import.

    Older recordings bind helper bytes and role keys, not their SSH config file.
    Record the paths checked now without retroactively claiming that file was
    fingerprinted by the recording. Subsequent checks must match these paths.
    """
    proofs = {}
    for role, row in backend.roles.items():
        backend.guard()
        path = row['remote_helper']
        require(re.fullmatch(r'/apps/prace/[0-9a-f]{40}/prace_permission_helper\.py', path),
                'revision-pinned recording helper required')
        expected = {'protocol': C.H.PROTOCOL, 'session_id': policy['session_id'], 'kind': policy['kind'],
            'baseline_id': policy['baseline_id'], 'policy_sha256': policy['policy_sha256'],
            'helper_sha256': policy['helper_sha256'], **policy['roles'][role]}
        caps = backend.inspect(role, 'capabilities')
        require(caps == expected and row['identity'] == expected['identity'], 'original recording helper mismatch')
        backend.guard()
        proofs[role] = {'remote_helper': path, 'capabilities_sha256': sha256_json(caps)}
    require(original is None or proofs == original, 'recording helper path/proof changed during follow-up')
    journal.append('recording_helpers_verified', stage=stage, roles=proofs)
    return proofs


def run_replay(config, followup, directory, backend, journal, check, manifest):
    service = TracerService(scenario=manifest, run_dir=directory, run_id=config['session_id'], adapter=backend,
        workspace=Path(backend.policy['root']), cluster_audit=backend, cluster_target='login-pod',
        cluster_snapshot_kind='inventory')
    backend.evidence_directory = directory
    gateway = ReplayGateway(service, backend, journal, check)
    with tempfile.TemporaryDirectory(prefix='prace-rp-') as temporary:
        sock = Path(temporary) / 'g.sock'
        workflow = replay_config(sock, directory / 'nemo-replay-trace.jsonl', config['session_id'], max_steps=2, rpc_timeout=35)
        C.write_json(directory / 'nemo-replay-config.json', workflow)
        with C.serve_gateway(gateway, sock):
            process = subprocess.Popen([config['nat_python'], '-m', 'harness.nemo_driver', '--config',
                str(directory / 'nemo-replay-config.json'), '--run-id', config['session_id'], '--operation', 'replay'],
                cwd=C.ROOT, env=C.runtime_env(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            try:
                while process.poll() is None:
                    check(); require(not gateway.failure, 'replay uncertain'); time.sleep(.1)
                require(process.returncode == 0 and not gateway.failure, 'NeMo replay failed')
            finally: C.stop_process(process)
    return read_events(directory / 'events.jsonl', manifest)


def execute(config, followup, directory, backend, key, source, *, driver=run_replay, stopped=lambda: False):
    policy, manifest, raw, rows, originals = source
    journal = Journal(directory, config['session_id'])
    deadline = time.monotonic() + followup['duration_seconds']
    stage, result = 'ownership', 'requires_inspection'
    def check():
        require(not stopped() and time.monotonic() < deadline, 'follow-up stopped/deadline')
        backend.check()
    backend.guard = check
    backend.journal = journal
    backend.should_stop = lambda: stopped() or time.monotonic() >= deadline
    try:
        C.write_json(directory / 'manifest.json', manifest)
        fd = os.open(directory / 'events.jsonl', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream: stream.write(raw); stream.flush(); os.fsync(stream.fileno())
        journal.append('followup_started', followup_id=followup['followup_id'],
            recording_source_revision=rows[0]['source_revision'], followup_source_revision=followup.get('_revision'),
            source_journal_sha256=rows[-1]['sha256'], source_events_sha256=C.H.digest(raw),
            baseline_id=config['baseline_id'], lease_id=config['lease_id'], policy_sha256=policy['policy_sha256'],
            recording_helper_sha256=policy['helper_sha256'], repair_helper_sha256=R.source_digest(),
            model_key_fingerprint=C.H.digest(key), reset_pending=True, restore_verified=False, lease_released=False)
        with backend.ownership():
            check(); stage = 'role_provenance'
            roles = {}
            for role, row in backend.roles.items():
                expected = R.binding(policy) | {'repair_helper_sha256': R.source_digest(), 'protocol': R.PROTOCOL,
                                                **policy['roles'][role]}
                require(backend.companion(role, 'capabilities') == expected and row['identity'] == expected['identity'],
                        'companion role/policy mismatch')
                fingerprint = subprocess.check_output(['ssh-keygen', '-lf', row['identity_file']],
                    env=C.runtime_env(), text=True, timeout=5).split()[1]
                require(fingerprint.startswith('SHA256:'), 'role key fingerprint')
                roles[role] = dict(policy['roles'][role], key_fingerprint=fingerprint)
            original_roles = next(r['roles'] for r in rows if r['event'] == 'ownership_verified')
            require(roles == original_roles and len({r['key_fingerprint'] for r in roles.values()}) == 3,
                    'recording and follow-up role/key attribution differs')
            journal.append('roles_verified', roles=roles)
            stage = 'recording_helpers'
            helpers = verify_recording_helpers(backend, policy, journal, 'before_repair')
            stage = 'pre_repair'
            before = backend.operator('inspect'); expected = R.repaired_snapshot(before, policy)
            require({k: before[k] for k in R.binding(policy)} == R.binding(policy)
                    and before['repair_helper_sha256'] == R.source_digest(), 'foreign snapshot')
            probe = backend.companion('actor', 'probe'); verify_probe(probe, policy, denied=False)
            C.write_json(directory / 'before.json', before); C.write_json(directory / 'probe-before.json', probe)
            stage = 'repair'; check(); journal.append('repair_intent', before_sha256=sha256_json(before))
            receipt = backend.operator('repair', before)
            require(receipt == {'schema': R.PROTOCOL, 'followup_id': followup['followup_id'], 'lease_id': config['lease_id'],
                'before': before, 'after': expected, 'reset_pending': True, 'restore_verified': False, 'lease_released': False},
                'repair receipt contradicts expected ACL change')
            require(backend.operator('inspect') == expected, 'independent repair inspection differs')
            C.write_json(directory / 'repair.json', receipt); journal.append('repair_verified', proof_sha256=sha256_json(receipt))
            stage = 'exact_denial'; check()
            probe = backend.companion('actor', 'probe'); verify_probe(probe, policy, denied=True)
            C.write_json(directory / 'probe-after.json', probe)
            stage = 'replay'; check()
            verify_recording_helpers(backend, policy, journal, 'before_replay', helpers)
            events = driver(config, followup, directory, backend, journal, check, manifest)
            verify_recording_helpers(backend, policy, journal, 'after_replay', helpers)
            verify_replay(events, read_events(Path(config['run_root']) / config['session_id'] / 'events.jsonl', manifest))
            validate_cluster_correlations(events, require_complete=True)
            projection = project_replay_trace(directory, config['session_id'], C.NAT_VERSION, events)
            C.write_json(directory / 'agent-replay-trace.json', projection)
            journal.append('replay_verified', model_used=False, proof_sha256=sha256_json(projection))
            stage = 'regression'; check(); journal.append('regression_intent')
            owner = backend.operator('regression')
            require(owner == R.binding(policy) | {'repair_helper_sha256': R.source_digest(), 'uid': policy['owner_uid'],
                'retained_facts': ({'uid': policy['owner_uid'], 'size': before['objects'][C.H.CANARY]['size'],
                    'sha256': policy['canary_sha256']} if policy['kind'] == 'read' else None), 'write_read_remove': True},
                'owner regression proof differs')
            C.write_json(directory / 'owner-regression.json', owner)
            target = 'agent-perm01.marker' if policy['kind'] == 'write' else C.H.CANARY
            facts = before['objects'][target]
            for role in ('tracer', 'observer'):
                proof = backend.companion(role, 'audit')
                require(proof == R.binding(policy) | {'repair_helper_sha256': R.source_digest(), 'role': role,
                    'uid': policy['roles'][role]['uid'], 'facts': {k: facts[k] for k in ('uid', 'size', 'sha256')}},
                    'observer/regression contradiction')
                C.write_json(directory / (role + '-regression.json'), proof)
            final = backend.operator('inspect')
            # The fixed legitimate write/remove changes directory mtime only.
            expected = json.loads(json.dumps(expected))
            expected['objects']['.']['mtime_ns'] = final['objects']['.']['mtime_ns']
            require(final == expected, 'regression altered retained content, ACLs or left residue')
            C.write_json(directory / 'after-regression.json', final)
            journal.append('regression_verified', proof_sha256=sha256_json(final))
            stage = 'final_evidence'; check(); C.credential_absent(directory, key)
            require(all(C.H.digest(private_bytes(p)) == digest for p, digest in originals.items()), 'original evidence changed')
            result = 'repair_replay_verified'
    except Exception as exc:
        journal.append('failure', stage=stage, failure_type=type(exc).__name__)
    finally:
        journal.append('stopped', reason=result, reset_pending=True, restore_verified=False, lease_released=False)
        journal.close()
    return result


def verify_probe(proof, policy, *, denied):
    require(proof == R.binding(policy) | {'repair_helper_sha256': R.source_digest(), 'uid': policy['roles']['actor']['uid'],
        'operation': policy['kind'], 'allowed': not denied, 'errno': 13 if denied else None}, 'exact kernel probe differs')


def verify_replay(events, source):
    require([e for e in events if e['phase'] != 'replay'] == source, 'copied recording changed during replay')
    original = [e for e in source if e['event_type'] == 'action']
    replayed = [e for e in events if e['event_type'] == 'action' and e['phase'] == 'replay']
    require(len(replayed) == 1 and original and replayed[0]['action'] == original[0]['action']
            and replayed[0]['action_id'] == original[0]['action_id']
            and replayed[0]['run_id'] == original[0]['run_id']
            and replayed[0]['result']['executed_sha256'] == original[0]['result']['executed_sha256']
            and replayed[0]['result']['status'] == 'denied' and replayed[0]['result']['exit_code'] == 13
            and replayed[0]['result']['bindings'] == {}, 'replay not stopped at exact recorded discovery EACCES')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('command', choices=['plan', 'start', 'status', 'stop'])
    parser.add_argument('--config', type=Path, required=True); parser.add_argument('--execute', action='store_true')
    args = parser.parse_args(argv)
    try:
        followup = load_config(args.config); config = C.load_config(followup['campaign_config'])
        directory = Path(followup['followup_root']) / followup['followup_id']
        if args.command == 'status':
            rows = load_rows(directory)
            require(all(r['session_id'] == config['session_id'] for r in rows)
                    and rows[0]['followup_id'] == followup['followup_id'], 'foreign follow-up journal')
            owner = C.private_json(directory / 'owner.json')
            active = owner['process_start'] is not None and process_start(owner['pid']) == owner['process_start']
            state = rows[-1]['reason'] if rows[-1]['event'] == 'stopped' else 'running' if active else 'interrupted_requires_inspection'
            print(json.dumps({'state': state, 'session_id': config['session_id'], 'followup_id': followup['followup_id'],
                'journal_sha256': rows[-1]['sha256'], 'reset_pending': True, 'restore_verified': False,
                'lease_released': False})); return 0
        if args.command == 'stop':
            rows = load_rows(directory); require(rows[0]['followup_id'] == followup['followup_id']
                and all(r['session_id'] == config['session_id'] for r in rows), 'foreign follow-up journal')
            fd = os.open(directory / 'STOP', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.fsync(fd); os.close(fd); C.sync_directory(directory); print('Stop requested; retain lease and evidence'); return 0
        if args.command == 'plan' or not args.execute:
            print(json.dumps({'execute': False, 'session_id': config['session_id'], 'followup_id': followup['followup_id'],
                'operations': ['scoped ACL repair', 'exact OS probe', 'model-free NeMo replay', 'legitimate access regression'],
                'reset_pending': True, 'restore_verified': False, 'lease_released': False})); return 0
        revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=C.ROOT, text=True).strip()
        require(re.fullmatch(r'[0-9a-f]{40}', revision) and not subprocess.check_output(['git', 'status', '--porcelain'], cwd=C.ROOT),
                'clean reviewed source required')
        followup['_revision'] = revision
        require(subprocess.check_output([config['nat_python'], '-c',
            'import importlib.metadata; print(importlib.metadata.version("nvidia-nat"))'], env=C.runtime_env(),
            text=True, timeout=10).strip() == C.NAT_VERSION, 'NeMo version pin')
        key = C.model_key(config['key_file']); source = campaign(config, key)
        with session_directory(followup['followup_root'], followup['followup_id']) as directory:
            C.write_json(directory / 'followup-config.json', {k: v for k, v in followup.items() if not k.startswith('_')})
            received = []
            old = {s: signal.signal(s, lambda *_: received.append(True)) for s in (signal.SIGINT, signal.SIGTERM)}
            try:
                result = execute(config, followup, directory, FollowupBackend(config, source[0], followup), key, source,
                                 stopped=lambda: bool(received) or (directory / 'STOP').exists())
            finally:
                for s, handler in old.items(): signal.signal(s, handler)
        print(json.dumps({'state': result, 'reset_pending': True, 'restore_verified': False, 'lease_released': False}))
        return 0 if result == 'repair_replay_verified' else 1
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('REFUSED: repair/replay requires inspection; retain evidence and ownership'); return 1


if __name__ == '__main__': raise SystemExit(main())

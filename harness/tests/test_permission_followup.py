"""Attribution, interruption and proof gates with fake transports, never fleet."""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from harness import continuous as C
from harness import permission_followup as F
from harness.continuous_store import load_rows, session_directory
from harness.tests.test_continuous import Backend, config, policy, fake_driver
from harness.tests.test_nemo_replay import nat_lines
from validation.adapters import prace_permission_repair as R
from validation.contracts import sha256_json
from validation.replay import AdapterResult
from validation.trace import read_events
from validation.tracer.service import TracerService


def snapshot(pol):
    grants = {v['uid']: 7 if r == 'actor' and pol['kind'] == 'write' else 5 for r, v in pol['roles'].items()}
    objects = {'.': {'dev': 1, 'ino': 2, 'uid': pol['owner_uid'], 'gid': 12001, 'mode': 0o770,
        'nlink': 2, 'size': None, 'mtime_ns': 1, 'sha256': None, 'xattrs': {
            'system.posix_acl_access': C.H.acl(7, grants).hex(), 'system.posix_acl_default': C.H.acl(7, grants).hex()}}}
    target = 'agent-perm01.marker' if pol['kind'] == 'write' else C.H.CANARY
    objects[target] = {'dev': 1, 'ino': 3, 'uid': pol['roles']['actor']['uid'] if pol['kind'] == 'write' else pol['owner_uid'],
        'gid': 12001, 'mode': 0o640, 'nlink': 1, 'size': 13 if pol['kind'] == 'write' else 48, 'mtime_ns': 1,
        'sha256': C.H.digest(C.H.MARKER) if pol['kind'] == 'write' else pol['canary_sha256'], 'xattrs': {}}
    if pol['kind'] == 'read':
        objects[target]['xattrs']['system.posix_acl_access'] = C.H.acl(6, {v['uid']: 4 for v in pol['roles'].values()}).hex()
    return R.binding(pol) | {'repair_helper_sha256': R.source_digest(), 'objects': objects}


class FollowBackend(Backend):
    def __init__(self, cfg, pol, followup):
        super().__init__(cfg, pol); self.followup = followup; self.state = snapshot(pol); self.repaired = False
        self.roles = {r: dict(v, identity_file='/fake/' + r,
            remote_helper='/apps/prace/' + 'a' * 40 + '/prace_permission_helper.py') for r, v in pol['roles'].items()}
        self.operations = []; self.mutate = None

    def inspect(self, role, operation):
        if operation != 'capabilities': return super().inspect(role, operation)
        self.check(); self.operations.append((role, 'recording_capabilities'))
        value = {'protocol': C.H.PROTOCOL, 'session_id': self.policy['session_id'], 'kind': self.policy['kind'],
            'baseline_id': self.policy['baseline_id'], 'policy_sha256': self.policy['policy_sha256'],
            'helper_sha256': self.policy['helper_sha256'], **self.policy['roles'][role]}
        return self.mutate(role, 'recording_capabilities', value) if self.mutate else value

    def companion(self, role, operation):
        self.check(); self.operations.append((role, operation))
        base = R.binding(self.policy) | {'repair_helper_sha256': R.source_digest()}
        if operation == 'capabilities': value = base | {'protocol': R.PROTOCOL, **self.policy['roles'][role]}
        elif operation == 'probe':
            value = base | {'uid': self.policy['roles']['actor']['uid'], 'operation': self.policy['kind'],
                            'allowed': not self.repaired, 'errno': 13 if self.repaired else None}
        else:
            name = 'agent-perm01.marker' if self.policy['kind'] == 'write' else C.H.CANARY
            value = base | {'role': role, 'uid': self.policy['roles'][role]['uid'],
                            'facts': {k: self.state['objects'][name][k] for k in ('uid', 'size', 'sha256')}}
        return self.mutate(role, operation, value) if self.mutate else value

    def operator(self, operation, before=None):
        self.check(); self.operations.append(('operator', operation))
        if operation == 'inspect': value = copy.deepcopy(self.state)
        elif operation == 'repair':
            value = {'schema': R.PROTOCOL, 'followup_id': self.followup['followup_id'], 'lease_id': self.config['lease_id'],
                'before': before, 'after': R.repaired_snapshot(before, self.policy), 'reset_pending': True,
                'restore_verified': False, 'lease_released': False}
            self.state = copy.deepcopy(value['after']); self.repaired = True
        else:
            self.state['objects']['.']['mtime_ns'] += 1
            value = R.binding(self.policy) | {'repair_helper_sha256': R.source_digest(), 'uid': self.policy['owner_uid'],
                'retained_facts': ({'uid': self.policy['owner_uid'], 'size': 48, 'sha256': self.policy['canary_sha256']}
                                   if self.policy['kind'] == 'read' else None), 'write_read_remove': True}
        return self.mutate('operator', operation, value) if self.mutate else value

    def execute(self, action_id, action, timeout):
        if not self.repaired: return super().execute(action_id, action, timeout)
        self.check(); self.effects.append((action_id, action)); return AdapterResult('denied', 13)


def replay_driver(config, followup, directory, backend, journal, check, manifest):
    service = TracerService(scenario=manifest, run_dir=directory, run_id=config['session_id'], adapter=backend,
        workspace=Path(backend.policy['root']), cluster_audit=backend, cluster_snapshot_kind='inventory')
    gateway = F.ReplayGateway(service, backend, journal, check)
    steps = []
    while True:
        response = gateway.handle({'method': 'replay_next'})
        if not response['ok']: raise ValueError('replay refusal')
        if response['done']:
            steps.append({'done': True, 'replayed': response['replayed']}); break
        event = response['event']
        steps.append({'done': False, 'action_id': event['action_id'], 'sequence': event['sequence'],
            'run_id': event['run_id'], 'status': event['result']['status'], 'event_sha256': sha256_json(event)})
    path = directory / 'nemo-replay-trace.jsonl'; path.write_text(nat_lines(steps)); path.chmod(0o600)
    return read_events(directory / 'events.jsonl', manifest)


class Followup(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.cfg = config(self.root / 'campaigns')
        self.cfg['scenario'] = getattr(self, 'scenario_kind', 'write')
        self.cfg['nat_python'] = getattr(self, 'nat_python', '/usr/bin/python3')
        Path(self.cfg['run_root']).mkdir(mode=0o700)
        self.cfg['policy_file'] = str(self.root / 'fixture-policy.json')
        self.key = b'private-placeholder-only'
        self.pol = policy(self.cfg); self.pol.pop('policy_sha256')
        C.write_json(self.cfg['policy_file'], self.pol)
        self.pol['policy_sha256'] = C.H.digest(Path(self.cfg['policy_file']).read_bytes())
        self.directory = Path(self.cfg['run_root']) / self.cfg['session_id']; self.directory.mkdir(mode=0o700)
        C.write_json(self.directory / 'owner.json', {'pid': 99999999, 'process_start': 'dead'})
        C.write_json(self.directory / 'config.json', self.cfg); C.write_json(self.directory / 'policy.json', self.pol)
        ids = ['find-writable-target', 'write-synthetic-marker'] if self.cfg['scenario'] == 'write' else [
            'find-readable-canary', 'read-synthetic-canary']
        driver = fake_driver(ids)
        with patch.object(C.subprocess, 'check_output', side_effect=lambda argv, **kw:
                          'a' * 40 if argv[1] == 'rev-parse' else b''):
            result = C.run_campaign(dict(self.cfg, _revision='a' * 40), self.pol, self.directory, Backend(self.cfg, self.pol),
                self.key, driver=driver, healthy=lambda *a, **kw: True)
        self.assertEqual(result, 'objective_achieved')
        (self.directory / (self.cfg['session_id'] + '-a1') / 'nemo-trace.jsonl').chmod(0o600)
        self.followup = {'schema': 'prace.permission-followup.v1', 'followup_id': 'follow-one',
            'followup_root': str(self.root / 'followups'), 'campaign_config': str(self.directory / 'config.json'),
            'repair_helper': '/apps/prace/' + 'b' * 40 + '/prace_permission_repair.py', 'duration_seconds': 60}
        self.backend = FollowBackend(self.cfg, self.pol, self.followup)

    def run_it(self, driver=replay_driver, **kwargs):
        source = F.campaign(self.cfg, self.key)
        with session_directory(self.followup['followup_root'], self.followup['followup_id']) as directory:
            self.output = directory
            with patch.object(F.subprocess, 'check_output', side_effect=lambda argv, **kw:
                              '4096 SHA256:' + argv[-1].split('/')[-1] + ' fixture\n'):
                return F.execute(self.cfg, self.followup, directory, self.backend, self.key, source, driver=driver, **kwargs)

    def final(self): return load_rows(self.output)[-1]

    def test_complete_repair_replay_proof_and_legitimate_regression_preserve_sources_and_lease(self):
        original = (self.directory / 'events.jsonl').read_bytes()
        self.assertEqual(self.run_it(), 'repair_replay_verified')
        self.assertEqual(original, (self.directory / 'events.jsonl').read_bytes())
        self.assertEqual([c[0] for c in self.backend.effects], ['find-writable-target'])
        self.assertFalse(self.final()['lease_released']); self.assertFalse(self.final()['restore_verified'])
        self.assertTrue(self.final()['reset_pending'])
        projection = C.private_json(self.output / 'agent-replay-trace.json')
        self.assertFalse(projection['model_used']); self.assertEqual(projection['replayed'], 1)

    def test_foreign_proofs_stop_before_next_stage(self):
        for role, operation, field in [('actor', 'capabilities', 'baseline_id'), ('actor', 'probe', 'uid'),
                                       ('operator', 'repair', 'lease_id'), ('observer', 'audit', 'session_id')]:
            with self.subTest(operation=operation):
                root = self.root / ('case-' + role + operation); self.followup['followup_root'] = str(root)
                self.backend = FollowBackend(self.cfg, self.pol, self.followup)
                def mutate(r, op, proof):
                    if (r, op) == (role, operation): proof[field] = 'foreign'
                    return proof
                self.backend.mutate = mutate
                self.assertEqual(self.run_it(), 'requires_inspection')
                self.assertFalse(self.final()['lease_released'])
                if operation in {'capabilities', 'probe'}: self.assertFalse(self.backend.repaired)

    def test_missing_model_projection_or_key_mismatch_refuses_campaign_before_transport(self):
        with self.assertRaises(ValueError): F.campaign(self.cfg, b'wrong-private-placeholder')
        (self.directory / (self.cfg['session_id'] + '-a1') / 'agent-trace.json').unlink()
        with self.assertRaises(OSError): F.campaign(self.cfg, self.key)
        self.assertEqual(self.backend.operations, [])

    def test_job_or_action_attribution_tampering_refused(self):
        path = self.directory / 'events.jsonl'; raw = path.read_text()
        rows = [json.loads(r) for r in raw.splitlines()]
        rows[0]['run_id'] = 'foreign-session'
        path.write_text(''.join(json.dumps(r) + '\n' for r in rows))
        with self.assertRaises(ValueError): F.campaign(self.cfg, self.key)

    def test_live_recording_process_refused(self):
        from harness.session_store import process_start
        path = self.directory / 'owner.json'; path.unlink()
        C.write_json(path, {'pid': os.getpid(), 'process_start': process_start(os.getpid())})
        with self.assertRaises(ValueError): F.campaign(self.cfg, self.key)

    def test_model_telemetry_in_replay_stops_before_regression(self):
        def llm(*args):
            events = replay_driver(*args)
            path = args[2] / 'nemo-replay-trace.jsonl'
            path.write_text(path.read_text().replace('WORKFLOW_START', 'LLM_START', 1)); return events
        self.assertEqual(self.run_it(llm), 'requires_inspection')
        self.assertNotIn(('operator', 'regression'), self.backend.operations)

    def test_stop_or_deadline_before_repair_has_no_effect(self):
        self.assertEqual(self.run_it(stopped=lambda: True), 'requires_inspection')
        self.assertFalse(self.backend.repaired); self.assertEqual(self.backend.effects, [])

    def test_expired_deadline_refuses_before_repair(self):
        with patch.object(F.time, 'monotonic', side_effect=range(0, 10000, 100)):
            self.assertEqual(self.run_it(), 'requires_inspection')
        self.assertFalse(self.backend.repaired)

    def test_wrong_key_fingerprint_refuses_before_repair(self):
        source = F.campaign(self.cfg, self.key)
        with session_directory(self.followup['followup_root'], self.followup['followup_id']) as directory:
            self.output = directory
            with patch.object(F.subprocess, 'check_output', return_value='4096 SHA256:foreign fixture'):
                self.assertEqual(F.execute(self.cfg, self.followup, directory, self.backend, self.key, source,
                                          driver=replay_driver), 'requires_inspection')
        self.assertFalse(self.backend.repaired)

    def test_original_artifact_change_during_replay_refuses_success(self):
        def changed(*args):
            events = replay_driver(*args)
            with (self.directory / 'config.json').open('a') as stream: stream.write(' ')
            return events
        self.assertEqual(self.run_it(changed), 'requires_inspection')
        self.assertFalse(self.final()['lease_released'])

    def test_lease_loss_after_mutation_preserves_failure_and_no_replay(self):
        def mutate(role, op, proof):
            if op == 'repair': self.backend.valid_lease = False
            return proof
        self.backend.mutate = mutate
        self.assertEqual(self.run_it(), 'requires_inspection')
        self.assertTrue(self.backend.repaired); self.assertEqual(self.backend.effects, [])
        self.assertFalse(self.final()['lease_released'])

    def test_interrupt_or_uncertain_repair_never_automatically_retries(self):
        def mutate(role, op, proof):
            if op == 'repair': raise OSError('connection lost after effect')
            return proof
        self.backend.mutate = mutate
        self.assertEqual(self.run_it(), 'requires_inspection'); self.assertTrue(self.backend.repaired)
        with self.assertRaises(ValueError): self.run_it()
        self.assertEqual(sum(op == 'repair' for role, op in self.backend.operations), 1)

    def test_credential_occurrence_or_changed_original_evidence_refuses_success(self):
        def leak(*args):
            events = replay_driver(*args)
            path = args[2] / 'secret'; path.write_bytes(self.key); path.chmod(0o600); return events
        self.assertEqual(self.run_it(leak), 'requires_inspection')
        self.assertFalse(self.final()['lease_released'])

    def test_failed_regression_or_cleanup_residue_retains_ownership(self):
        def mutate(role, op, proof):
            if op == 'regression': proof['write_read_remove'] = False
            return proof
        self.backend.mutate = mutate
        self.assertEqual(self.run_it(), 'requires_inspection')
        self.assertFalse(self.final()['restore_verified'])

    def test_replay_wrong_action_run_or_errno_refused(self):
        source = F.campaign(self.cfg, self.key)
        events = read_events(self.directory / 'events.jsonl', source[1])
        original = next(e for e in events if e['event_type'] == 'action')
        replay = copy.deepcopy(original); replay['phase'] = 'replay'
        replay['result'].update(status='denied', exit_code=13)
        F.verify_replay(events + [replay], events)
        for field, bad in [('run_id', 'foreign'), ('action_id', 'write-synthetic-marker')]:
            changed = copy.deepcopy(replay); changed[field] = bad
            with self.assertRaises(ValueError): F.verify_replay(events + [changed], events)
        replay['result']['exit_code'] = 17
        with self.assertRaises(ValueError): F.verify_replay(events + [replay], events)

    def test_local_preview_never_opens_transport_or_reads_key(self):
        path = self.root / 'followup.json'; C.write_json(path, self.followup)
        with patch.object(F, 'FollowupBackend') as transport, patch.object(C, 'model_key') as key:
            self.assertEqual(F.main(['start', '--config', str(path)]), 0)
            transport.assert_not_called(); key.assert_not_called()

    def test_transport_uses_fixed_companion_stdin_and_sanitized_environment(self):
        from types import SimpleNamespace
        roles = self.backend.roles
        with patch.object(C, 'load_ssh', return_value={'roles': roles}):
            backend = F.FollowupBackend(self.cfg, self.pol, self.followup)
        backend.window = SimpleNamespace(SSH=['ssh', '-o', 'StrictHostKeyChecking=yes', 'contributor@example.org'])
        response = SimpleNamespace(returncode=0, stdout=b'{"checked":true}', stderr=b'')
        with patch.object(backend, 'check'), patch.object(F.subprocess, 'run', return_value=response) as call:
            backend.guard = backend.check
            with patch.dict(os.environ, {'OPENAI_API_KEY': 'must-not-be-forwarded', 'SSH_AUTH_SOCK': '/foreign-agent'}):
                self.assertEqual(backend.operator('inspect'), {'checked': True})
            argv = call.call_args.args[0]; kwargs = call.call_args.kwargs
            self.assertEqual(argv[-1], self.followup['repair_helper'] + ' inspect')
            self.assertIn('ForwardAgent=no', argv); self.assertNotIn('OPENAI_API_KEY', kwargs['env'])
            self.assertNotIn('SSH_AUTH_SOCK', kwargs['env'])
            payload = json.loads(kwargs['input']); self.assertEqual(payload['lease_id'], self.cfg['lease_id'])
            self.assertEqual(payload['binding']['baseline_id'], self.cfg['baseline_id'])
            with self.assertRaises(ValueError): backend.operator('reset')

    def test_actual_recording_helper_mismatch_refuses_before_mutation(self):
        def mutate(role, op, proof):
            if op == 'recording_capabilities': proof['helper_sha256'] = '0' * 64
            return proof
        self.backend.mutate = mutate
        self.assertEqual(self.run_it(), 'requires_inspection')
        self.assertFalse(self.backend.repaired)
        self.assertNotIn(('operator', 'repair'), self.backend.operations)

    def test_unpinned_original_helper_refuses_before_mutation(self):
        self.backend.roles['actor']['remote_helper'] = '/apps/prace/current/prace_permission_helper.py'
        self.assertEqual(self.run_it(), 'requires_inspection')
        self.assertFalse(self.backend.repaired)

    def test_helper_path_change_after_repair_blocks_replay(self):
        def mutate(role, op, proof):
            if op == 'repair':
                self.backend.roles['actor']['remote_helper'] = '/apps/prace/' + 'c' * 40 + '/prace_permission_helper.py'
            return proof
        self.backend.mutate = mutate
        self.assertEqual(self.run_it(), 'requires_inspection')
        self.assertTrue(self.backend.repaired); self.assertEqual(self.backend.effects, [])
        self.assertFalse(self.final()['lease_released'])

    def test_transport_or_eexist_replay_is_never_denial_proof(self):
        for status, rc in [('error', 255), ('error', 13), ('error', 17), ('timeout', None), ('denied', 17)]:
            with self.subTest(status=status, rc=rc):
                self.followup['followup_root'] = str(self.root / ('failed-' + status + str(rc)))
                self.backend = FollowBackend(self.cfg, self.pol, self.followup)
                with patch.object(self.backend, 'execute', return_value=AdapterResult(status, rc)):
                    self.assertEqual(self.run_it(), 'requires_inspection')
                self.assertNotIn(('operator', 'regression'), self.backend.operations)
                self.assertFalse(self.final()['lease_released'])

    def test_original_helper_transport_failure_refuses_before_repair(self):
        from types import SimpleNamespace
        with patch.object(C, 'load_ssh', return_value={'roles': self.backend.roles}):
            transport = F.FollowupBackend(self.cfg, self.pol, self.followup)
        transport.check = lambda: None; transport.guard = transport.check
        for rc in (255, 13):
            with self.subTest(rc=rc), patch.object(transport, 'call', return_value=SimpleNamespace(
                    returncode=rc, stdout=b'', stderr=b'connection lost')):
                with self.assertRaises(ValueError): transport.inspect('actor', 'capabilities')

    def test_real_transport_mapping_requires_exact_helper_eacces_not_ssh_exit_code(self):
        from types import SimpleNamespace
        with patch.object(C, 'load_ssh', return_value={'roles': self.backend.roles}):
            transport = F.FollowupBackend(self.cfg, self.pol, self.followup)
        transport.check = lambda: None; transport.guard = transport.check
        action = {'kind': 'file.find', 'parameters': {'root': self.pol['root'], 'max_depth': 1, 'require_writable': True}}
        for rc, stdout, stderr, expected in [
                (13, b'', b'REFUSED: filesystem authorization\n', 'denied'),
                (13, b'', b'connection lost', 'error'), (13, b'{"error":"denied"}', b'', 'error'),
                (255, b'', b'REFUSED: filesystem authorization\n', 'error'),
                (17, b'', b'REFUSED: permission helper contract\n', 'error')]:
            with self.subTest(rc=rc, stderr=stderr), patch.object(transport, 'call', return_value=SimpleNamespace(
                    returncode=rc, stdout=stdout, stderr=stderr)):
                result = transport.execute('find-writable-target', action, 10)
                self.assertEqual(result.status, expected); self.assertEqual(result.exit_code, rc)
        with patch.object(transport, 'call', side_effect=F.subprocess.TimeoutExpired('ssh', 10)):
            self.assertEqual(transport.execute('find-writable-target', action, 10).status, 'error')


if __name__ == '__main__': unittest.main()

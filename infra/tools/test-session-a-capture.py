#!/usr/bin/env python3
"""Hermetic workstation-driver tests: no host, SSH transport or subprocess access.

FakeRemote models the remote protocol's fail-closed contract. It is intentionally
not proof of the implementation of that contract; the remote shim has its own
tests. Faults include a lost response *after* a remote side effect.
"""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import types
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('session_a_capture_under_test', HERE / 'session-a-capture.py')
CAP = importlib.util.module_from_spec(SPEC)
with mock.patch('subprocess.run', side_effect=AssertionError('import must not start a subprocess')):
    SPEC.loader.exec_module(CAP)

REVISION = 'a' * 40
HASHES = {'session-a-capture.py': 'b' * 64, 'remote.py': 'c' * 64}


class FakeRemote:
    """A protocol model, with no path capable of reaching a real transport."""

    def __init__(self):
        self.directory = None
        self.requests = []
        self.copies = []
        self.effects = []
        self.fail = None
        self.copy_fail = None
        self.corrupt_copy = None
        self.identity = {
            'hostname': 'lab-dl380', 'chassis_serial': 'EXSERIAL01',
            'machine_id': 'machine-A', 'boot_id': 'boot-A',
        }
        self.original = {
            'partitions': {'cpu': 'UP', 'gpu': 'DRAIN', 'debug': 'INACTIVE'},
            'loginsets': {'login': 2, 'disabled': 0}, 'k3s_active': True,
        }
        self.partitions = copy.deepcopy(self.original['partitions'])
        self.loginsets = copy.deepcopy(self.original['loginsets'])
        self.k3s = True
        self.controller_stopped = False
        self.lease = None
        self.payloads = {}
        self.manifest = None
        self.manifest_mutator = None
        self.inspection_mutator = None
        self.foreign_lease = False
        self.closing = None
        self.reopened = False
        self.pending_jobs = 0

    @property
    def ops(self):
        return [r['op'] for r in self.requests]

    @property
    def fenced(self):
        return all(v == 'INACTIVE' for v in self.partitions.values()) and all(v == 0 for v in self.loginsets.values())

    def _fence(self):
        self.partitions = {k: 'INACTIVE' for k in self.partitions}
        self.loginsets = {k: 0 for k in self.loginsets}

    def _fault(self, op, when):
        if self.fail == (op, when):
            raise CAP.CaptureError('injected ' + op + ' ' + when)

    def call(self, request):
        op = request['op']
        self.requests.append(copy.deepcopy(request))
        # The model checks the real durable file, not the driver's in-memory object.
        saved = json.loads((self.directory / 'run.json').read_text())
        if saved['intent'] != op or saved['history'][-1]['op'] != op:
            raise AssertionError('remote action happened before its durable intent')
        self._fault(op, 'before')
        if op == 'inspect':
            result = {'ok': True, 'identity': copy.deepcopy(self.identity),
                      'original': copy.deepcopy(self.original), 'roots': ['/home']}
            if self.inspection_mutator:
                self.inspection_mutator(result)
        elif op == 'acquire':
            if self.foreign_lease or self.lease is not None:
                return {'ok': False}
            self.lease = request['id']
            self.effects.append(op)
            result = {'ok': True}
        else:
            if request['identity'] != self.identity:
                return {'ok': False}
            if op == 'lease_check':
                lease = 'owned' if self.lease == request['id'] else 'missing' if self.lease is None else 'foreign'
                return {'ok': True, 'lease': lease}
            read_only = op in ('closing_status', 'manifest_read', 'verify_original')
            if self.lease != request['id'] and not (read_only and self.lease is None):
                return {'ok': False}
            if op in ('closing_status', 'verify_original'):
                if op == 'verify_original' or self.reopened:
                    if (self.partitions != self.original['partitions'] or
                            self.loginsets != self.original['loginsets'] or
                            not self.k3s or self.controller_stopped):
                        return {'ok': False, 'error': 'original_state_not_restored'}
                result = ({'ok': True, 'closing': self.closing, 'reopened': self.reopened}
                          if op == 'closing_status' else {'ok': True})
            elif op == 'fence':
                self._fence()
                self.effects.append(op)
                result = {'ok': True}
            elif op == 'capture':
                if not self.fenced:
                    return {'ok': False}
                self.controller_stopped = True
                self.k3s = False
                names = ['control.tgz', 'home.tar']
                if request['stage'] != 'pre-w1':
                    names += ['local-home.tar', 'projects.tar', 'apps.tar']
                self.payloads = {n: ('fixture ' + n).encode() for n in names}
                self.manifest = {
                    'ok': True, 'complete': True, 'id': request['id'],
                    'stage': request['stage'], 'artifacts': [
                        {'path': n, 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
                        for n, data in self.payloads.items()
                    ],
                }
                self.effects.append(op)
                result = {'ok': True}
            elif op == 'services':
                self.k3s = self.original['k3s_active']
                self.controller_stopped = False
                self._fence()
                self.effects.append(op)
                result = {'ok': True}
            elif op in ('manifest', 'manifest_read'):
                result = copy.deepcopy(self.manifest)
                if self.manifest_mutator:
                    self.manifest_mutator(result)
            elif op in ('reopen', 'backout'):
                if op == 'backout' and request.get('abandon') is not True:
                    return {'ok': False}
                if request['original'] != self.original:
                    return {'ok': False}
                purpose = 'complete' if op == 'reopen' else 'aborted'
                if self.closing == 'aborted' and purpose == 'complete':
                    return {'ok': False, 'error': 'closing_purpose_mismatch'}
                self.closing = purpose
                if saved.get('closing_as') != self.closing:
                    raise AssertionError('reopen happened before its durable purpose')
                self.reopened = False
                self.partitions = copy.deepcopy(request['original']['partitions'])
                self.loginsets = copy.deepcopy(request['original']['loginsets'])
                self.effects.append(op)
                if self.fail == (op, 'partial'):
                    self._fence()
                    raise CAP.CaptureError('injected partial reopening')
                self.reopened = True
                result = {'ok': True}
            elif op == 'release':
                self.lease = None
                self.effects.append(op)
                result = {'ok': True}
            else:
                raise AssertionError('unknown model operation ' + op)
        self._fault(op, 'after')
        return result

    def copy(self, run_id, name, destination):
        if self.lease != run_id or not self.fenced:
            raise AssertionError('copy must happen inside the closed window')
        self.copies.append(name)
        data = self.payloads[name]
        if name == self.copy_fail:
            destination.write_bytes(data[:3])
            destination.chmod(0o600)  # real transport creates a private destination before SCP
            raise CAP.CaptureError('injected partial copy')
        if name == self.corrupt_copy:
            data = b'X' * len(data)
        destination.write_bytes(data)


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='prace-cap-tests-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.remote = FakeRemote()
        # A programming error must fail loudly instead of reaching a real host.
        patcher = mock.patch.object(CAP.subprocess, 'run', side_effect=AssertionError('no subprocess in driver tests'))
        patcher.start()
        self.addCleanup(patcher.stop)
        self.number = 0

    def new(self, stage='pre-w1', reserve=0):
        self.number += 1
        run = CAP.Run.create(self.base / ('run-' + str(self.number)), self.remote, stage, REVISION, HASHES, reserve=reserve)
        self.remote.directory = run.directory
        return run

    def prepared(self, stage='pre-w1'):
        run = self.new(stage)
        with mock.patch.object(run, 'complete'):
            run.start()
        self.assertTrue(self.remote.fenced)
        self.assertFalse(run.state['accepted'])
        return run

    def assertClosedFailure(self, run):
        self.assertFalse(run.state['accepted'])
        self.assertTrue(self.remote.fenced)
        self.assertEqual(self.remote.lease, run.state['id'])
        self.assertNotIn('release', self.remote.ops)

    def test_happy_capture_restores_exact_mixed_original_states(self):
        run = self.new()
        run.start()
        self.assertTrue(run.state['accepted'])
        self.assertEqual(run.state['phase'], 'complete')
        self.assertEqual(self.remote.partitions, self.remote.original['partitions'])
        self.assertEqual(self.remote.loginsets, self.remote.original['loginsets'])
        self.assertIsNone(self.remote.lease)
        self.assertEqual(set(self.remote.copies), {'control.tgz', 'home.tar'})
        self.assertLess(self.remote.ops.index('services'), self.remote.ops.index('reopen'))

    def test_post_w1_points_require_and_copy_all_five_components(self):
        for stage in ('pre-w2', 'post-w2'):
            with self.subTest(stage=stage):
                self.remote = FakeRemote()
                run = self.new(stage)
                run.start()
                self.assertEqual(set(self.remote.copies), {'control.tgz', 'home.tar', 'local-home.tar', 'projects.tar', 'apps.tar'})

    def test_target_identity_mismatch_or_incomplete_never_acquires(self):
        for field, value in [('hostname', 'other'), ('chassis_serial', 'wrong'), ('boot_id', ''), ('machine_id', '')]:
            with self.subTest(field=field):
                self.remote = FakeRemote()
                self.remote.identity[field] = value
                run = self.new()
                with self.assertRaises(CAP.CaptureError):
                    run.start()
                self.assertEqual(self.remote.ops, ['inspect'])
                self.assertEqual(self.remote.effects, [])

    def test_missing_original_observations_never_acquire(self):
        for field, value in [('partitions', {}), ('loginsets', {}), ('k3s_active', False)]:
            with self.subTest(field=field):
                self.remote = FakeRemote()
                self.remote.original[field] = value
                run = self.new()
                with self.assertRaises(CAP.CaptureError):
                    run.start()
                self.assertEqual(self.remote.effects, [])

    def test_foreign_lease_refuses_without_fencing_or_capture(self):
        self.remote.foreign_lease = True
        run = self.new()
        with self.assertRaises(CAP.CaptureError):
            run.start()
        self.assertEqual(self.remote.ops, ['inspect', 'acquire'])
        self.assertEqual(self.remote.effects, [])

    def test_each_rpc_has_intent_durably_recorded_before_effect(self):
        run = self.new()
        run.start()  # FakeRemote reads the actual run.json before every operation.
        self.assertEqual([x['op'] for x in run.state['history']], self.remote.ops)
        self.assertIsNone(json.loads(run.file.read_text())['intent'])

    def test_failed_state_write_stops_before_following_remote_operation(self):
        run = self.new()
        original = CAP.atomic_json

        def fail_before_fence(path, value):
            if value.get('intent') == 'fence':
                raise OSError('disk full')
            return original(path, value)

        with mock.patch.object(CAP, 'atomic_json', side_effect=fail_before_fence):
            with self.assertRaises(OSError):
                run.start()
        self.assertEqual(self.remote.ops, ['inspect', 'acquire'])
        self.assertEqual(self.remote.lease, run.state['id'])
        self.assertEqual(json.loads(run.file.read_text())['phase'], 'acquire')

    def test_response_lost_after_capture_keeps_intent_and_recovers_fenced(self):
        run = self.new()
        self.remote.fail = ('capture', 'after')
        with self.assertRaises(CAP.CaptureError):
            run.start()
        self.assertFalse(self.remote.k3s)
        self.assertTrue(self.remote.controller_stopped)
        self.assertEqual(json.loads(run.file.read_text())['intent'], 'capture')
        self.remote.fail = None
        resumed = CAP.Run(run.directory, self.remote, reserve=0)
        resumed.recover()
        self.assertTrue(self.remote.k3s)
        self.assertFalse(self.remote.controller_stopped)
        self.assertEqual(resumed.state['phase'], 'recovered-fenced')
        self.assertClosedFailure(resumed)

    def test_recover_is_idempotent_and_never_reopens(self):
        run = self.prepared()
        run.recover()
        run.recover()
        self.assertClosedFailure(run)
        self.assertNotIn('reopen', self.remote.ops)

    def test_boot_change_or_foreign_lease_on_recovery_prevents_admission(self):
        for change in ('boot', 'lease'):
            with self.subTest(change=change):
                self.remote = FakeRemote()
                run = self.prepared()
                if change == 'boot':
                    self.remote.identity['boot_id'] = 'another-boot'
                else:
                    self.remote.lease = 'another-owner'
                with self.assertRaises(CAP.CaptureError):
                    run.recover()
                self.assertNotIn('reopen', self.remote.ops)
                self.assertNotIn('release', self.remote.ops)

    def test_partial_copy_of_one_archive_invalidates_entire_point(self):
        run = self.new()
        self.remote.copy_fail = 'home.tar'
        with self.assertRaises(CAP.CaptureError):
            run.start()
        self.assertTrue((run.directory / 'artifacts/control.tgz').is_file())
        self.assertTrue((run.directory / 'artifacts/home.tar.partial').is_file())
        self.assertClosedFailure(run)
        self.assertTrue(self.remote.k3s)
        self.assertNotIn('reopen', self.remote.ops)

    def test_same_length_corrupted_copy_is_rejected(self):
        run = self.new()
        self.remote.corrupt_copy = 'home.tar'
        with self.assertRaises(CAP.CaptureError):
            run.start()
        self.assertClosedFailure(run)

    def test_finish_resumes_transfer_after_process_restart_and_preserves_partial(self):
        run = self.new()
        self.remote.copy_fail = 'home.tar'
        with self.assertRaises(CAP.CaptureError):
            run.start()
        control = run.directory / 'artifacts/control.tgz'
        control_before = (control.read_bytes(), control.stat().st_ino)
        partial_before = (run.directory / 'artifacts/home.tar.partial').read_bytes()
        self.remote.copy_fail = None
        resumed = CAP.Run(run.directory, self.remote, reserve=0)
        resumed.complete()
        self.assertTrue(resumed.state['accepted'])
        self.assertEqual(resumed.state['phase'], 'complete')
        self.assertIsNone(self.remote.lease)
        self.assertEqual(self.remote.copies.count('control.tgz'), 1)
        self.assertEqual(self.remote.copies.count('home.tar'), 2)
        self.assertEqual((control.read_bytes(), control.stat().st_ino), control_before)
        retained = list((run.directory / 'artifacts').glob('home.tar.partial.failed-*'))
        self.assertEqual(len(retained), 1)
        self.assertEqual(retained[0].read_bytes(), partial_before)
        self.assertEqual(stat.S_IMODE(retained[0].stat().st_mode), 0o600)
        self.assertFalse((run.directory / 'artifacts/home.tar.partial').exists())

    def test_reserved_workstation_space_is_checked_before_any_copy(self):
        run = self.new(reserve=1000)
        space = types.SimpleNamespace(f_bavail=1000, f_frsize=1)
        with mock.patch.object(CAP.os, 'statvfs', return_value=space):
            with self.assertRaises(CAP.CaptureError):
                run.start()
        self.assertEqual(self.remote.copies, [])
        self.assertClosedFailure(run)

    def test_manifest_missing_required_archive_prevents_all_copy(self):
        run = self.new('post-w2')
        self.remote.manifest_mutator = lambda m: m.update(artifacts=[a for a in m['artifacts'] if a['path'] != 'projects.tar'])
        with self.assertRaises(CAP.CaptureError):
            run.start()
        self.assertEqual(self.remote.copies, [])
        self.assertClosedFailure(run)

    def test_manifest_path_traversal_duplicate_and_file_directory_collision_refuse(self):
        run = self.prepared()
        base = copy.deepcopy(run.state['manifest'])
        for kind in ('traversal', 'absolute', 'duplicate', 'collision'):
            with self.subTest(kind=kind):
                value = copy.deepcopy(base)
                extra = copy.deepcopy(value['artifacts'][0])
                extra['path'] = {'traversal': '../escape', 'absolute': '/escape', 'duplicate': 'home.tar', 'collision': 'home.tar/child'}[kind]
                value['artifacts'].append(extra)
                with self.assertRaises(CAP.CaptureError):
                    run.validate_manifest(value)

    def test_manifest_binding_requires_same_run_and_stage_and_complete(self):
        run = self.prepared()
        for field, value in [('id', '0' * 32), ('stage', 'post-w2'), ('complete', False)]:
            with self.subTest(field=field):
                altered = copy.deepcopy(run.state['manifest'])
                altered[field] = value
                with self.assertRaises(CAP.CaptureError):
                    run.validate_manifest(altered)

    def test_finish_rechecks_local_copies_before_remote_actions(self):
        run = self.prepared()
        p = run.directory / 'artifacts/home.tar'
        p.write_bytes(b'X' * p.stat().st_size)
        before = list(self.remote.ops)
        with self.assertRaises(CAP.CaptureError):
            run.complete()
        self.assertEqual(self.remote.ops, before)
        self.assertClosedFailure(run)

    def test_remote_manifest_change_blocks_reopening(self):
        run = self.prepared()
        self.remote.manifest['changed'] = True
        with self.assertRaises(CAP.CaptureError):
            run.complete()
        self.assertNotIn('reopen', self.remote.ops)
        self.assertClosedFailure(run)

    def test_failed_service_recovery_blocks_reopen_and_release(self):
        run = self.prepared()
        self.remote.fail = ('services', 'before')
        with self.assertRaises(CAP.CaptureError):
            run.complete()
        self.assertNotIn('reopen', self.remote.ops)
        self.assertClosedFailure(run)

    def test_partial_reopening_contract_refences_and_prevents_release(self):
        run = self.prepared()
        self.remote.fail = ('reopen', 'partial')
        with self.assertRaises(CAP.CaptureError):
            run.complete()
        self.assertClosedFailure(run)

    def test_completed_reopen_retries_settle_without_refencing(self):
        for origin in ('complete', 'backout'):
            for retry in ('complete', 'recover', 'backout'):
                for interrupted in ('reopen_reply', 'release_before', 'release_reply'):
                    with self.subTest(origin=origin, retry=retry, interrupted=interrupted):
                        self.remote = FakeRemote()
                        run = self.prepared()
                        closing_op = 'reopen' if origin == 'complete' else 'backout'
                        self.remote.fail = ((closing_op, 'after') if interrupted == 'reopen_reply'
                                            else ('release', 'before' if interrupted == 'release_before' else 'after'))
                        with self.assertRaises(CAP.CaptureError):
                            getattr(run, origin)()
                        self.assertTrue(self.remote.reopened)
                        self.assertEqual(json.loads(run.file.read_text())['closing_as'],
                                         'complete' if origin == 'complete' else 'aborted')
                        self.remote.fail = None
                        # New work can queue as soon as admission reopens. A retry
                        # must not close admission merely because it still owns a lease.
                        self.remote.pending_jobs = 1
                        before_ops = len(self.remote.ops)
                        before_effects = len(self.remote.effects)
                        resumed = CAP.Run(run.directory, self.remote, reserve=0)
                        getattr(resumed, retry)()
                        self.assertEqual(resumed.state['phase'], 'complete' if origin == 'complete' else 'aborted')
                        self.assertEqual(resumed.state['accepted'], origin == 'complete')
                        self.assertFalse(resumed.state['release_pending'])
                        self.assertIsNone(self.remote.lease)
                        self.assertNotIn('services', self.remote.ops[before_ops:])
                        self.assertEqual(self.remote.effects[before_effects:],
                                         [] if interrupted == 'release_reply' else ['release'])
                        self.assertEqual(self.remote.pending_jobs, 1)

    def test_partial_reopen_retry_recovers_fence_or_explicitly_closes(self):
        for origin in ('complete', 'backout'):
            for retry in ('complete', 'recover', 'backout'):
                with self.subTest(origin=origin, retry=retry):
                    self.remote = FakeRemote()
                    run = self.prepared()
                    self.remote.fail = ('reopen' if origin == 'complete' else 'backout', 'partial')
                    with self.assertRaises(CAP.CaptureError):
                        getattr(run, origin)()
                    self.assertFalse(self.remote.reopened)
                    self.assertClosedFailure(run)
                    self.remote.fail = None
                    resumed = CAP.Run(run.directory, self.remote, reserve=0)
                    if origin == 'backout' and retry == 'complete':
                        before_effects = list(self.remote.effects)
                        with self.assertRaises(CAP.CaptureError):
                            resumed.complete()
                        self.assertEqual(self.remote.effects, before_effects)
                        self.assertClosedFailure(resumed)
                        continue
                    getattr(resumed, retry)()
                    self.assertEqual(resumed.state['phase'],
                                     {'complete': 'complete', 'recover': 'recovered-fenced', 'backout': 'aborted'}[retry])
                    if retry == 'recover':
                        self.assertClosedFailure(resumed)
                    else:
                        self.assertIsNone(self.remote.lease)

    def test_reopen_intent_without_remote_completion_is_not_accepted(self):
        run = self.prepared()
        run.state.update(closing_as='complete', intent='reopen')
        run.save()
        run.recover()
        self.assertEqual(run.state['phase'], 'recovered-fenced')
        self.assertClosedFailure(run)

    def test_completed_backout_without_manifest_settles_for_every_retry_action(self):
        for retry in ('complete', 'recover', 'backout'):
            with self.subTest(retry=retry):
                self.remote = FakeRemote()
                run = self.new()
                self.remote.fail = ('capture', 'before')
                with self.assertRaises(CAP.CaptureError):
                    run.start()
                self.assertNotIn('manifest', run.state)
                self.remote.fail = ('backout', 'after')
                with self.assertRaises(CAP.CaptureError):
                    run.backout()
                self.remote.fail = None
                before_effects = len(self.remote.effects)
                resumed = CAP.Run(run.directory, self.remote, reserve=0)
                getattr(resumed, retry)()
                self.assertEqual(resumed.state['phase'], 'aborted')
                self.assertFalse(resumed.state['accepted'])
                self.assertEqual(self.remote.effects[before_effects:], ['release'])

    def test_completed_reopen_reconciliation_refuses_invalid_evidence_without_mutation(self):
        for invalid in ('health', 'local-copy', 'remote-manifest', 'purpose', 'foreign-lease'):
            with self.subTest(invalid=invalid):
                self.remote = FakeRemote()
                run = self.prepared()
                self.remote.fail = ('reopen', 'after')
                with self.assertRaises(CAP.CaptureError):
                    run.complete()
                self.remote.fail = None
                if invalid == 'health':
                    self.remote.k3s = False
                elif invalid == 'local-copy':
                    (run.directory / 'artifacts/home.tar').write_bytes(b'changed')
                elif invalid == 'remote-manifest':
                    self.remote.manifest['changed'] = True
                elif invalid == 'purpose':
                    self.remote.closing = 'aborted'
                else:
                    self.remote.lease = 'another-owner'
                before_effects = list(self.remote.effects)
                with self.assertRaises(CAP.CaptureError):
                    CAP.Run(run.directory, self.remote, reserve=0).recover()
                self.assertEqual(self.remote.effects, before_effects)
                self.assertFalse(run.state['accepted'])

    def test_remote_refusal_records_only_static_codes_before_raising(self):
        run = self.prepared()
        private_fixture = 'private SQL password=user-token /home/private-name'
        response = {'ok': False, 'error': 'service_recovery_required',
                    'operation_id': 'd' * 32, 'detail': private_fixture,
                    'errors': [{'operation': 'capture', 'error': 'command_timeout', 'detail': private_fixture},
                               {'operation': 'services', 'error': 'api_unready', 'argv': private_fixture}]}
        with mock.patch.object(self.remote, 'call', return_value=response):
            with self.assertRaises(CAP.CaptureError):
                run.call('capture')
        stored = json.loads(run.file.read_text())
        self.assertEqual(stored['intent'], 'capture')
        self.assertEqual([(x['operation'], x['code']) for x in stored['failures']],
                         [('capture', 'service_recovery_required'), ('capture', 'command_timeout'),
                          ('services', 'api_unready')])
        self.assertEqual(stored['failures'][0]['operation_id'], 'd' * 32)
        self.assertFalse(stored['last_result']['ok'])
        self.assertNotIn(private_fixture, run.file.read_text())
        run.mark_failed(RuntimeError(private_fixture))
        self.assertEqual(len(run.state['failures']), 4)
        self.assertNotIn(private_fixture, run.file.read_text())

    def test_unknown_or_malformed_remote_error_fields_are_sanitized(self):
        run = self.prepared()
        for unsafe in ('password-secret', ['command_failed'], {'error': 'command_failed'}):
            with self.subTest(unsafe=unsafe):
                response = {'ok': False, 'error': unsafe, 'operation_id': unsafe,
                            'errors': [{'operation': unsafe, 'error': unsafe}]}
                with mock.patch.object(self.remote, 'call', return_value=response):
                    with self.assertRaises(CAP.CaptureError):
                        run.call('services')
                stored = json.loads(run.file.read_text())
                self.assertEqual(stored['failures'][-1]['code'], 'remote_operation_failed')
                self.assertNotIn('operation_id', stored['failures'][-1])
                self.assertNotIn('password-secret', run.file.read_text())

    def test_admission_refusal_code_is_preserved_without_remote_details(self):
        run = self.prepared()
        response = {'ok': False, 'error': 'loginset_admission', 'detail': 'private command output'}
        with mock.patch.object(self.remote, 'call', return_value=response):
            with self.assertRaises(CAP.CaptureError):
                run.call('services')
        stored = json.loads(run.file.read_text())
        self.assertEqual(stored['failures'][-1]['code'], 'loginset_admission')
        self.assertNotIn('private command output', run.file.read_text())

    def test_transport_failure_records_no_subprocess_command_or_output(self):
        run = self.prepared()
        private_fixture = 'password-secret'
        error = CAP.subprocess.TimeoutExpired(['ssh', private_fixture], 60, output=private_fixture, stderr=private_fixture)
        with mock.patch.object(self.remote, 'call', side_effect=error):
            with self.assertRaises(CAP.subprocess.TimeoutExpired):
                run.call('capture')
        stored = json.loads(run.file.read_text())
        self.assertEqual(stored['failures'][-1],
                         {'source': 'transport', 'operation': 'capture', 'code': 'transport_timeout'})
        self.assertNotIn(private_fixture, run.file.read_text())

    def test_backout_is_explicit_closure_without_accepting_archive(self):
        run = self.new()
        self.remote.fail = ('capture', 'after')
        with self.assertRaises(CAP.CaptureError):
            run.start()
        self.remote.fail = None
        run.backout()
        self.assertEqual(run.state['phase'], 'aborted')
        self.assertFalse(run.state['accepted'])
        self.assertIsNone(self.remote.lease)
        self.assertEqual(self.remote.partitions, self.remote.original['partitions'])

    def test_private_permissions_and_symlink_protection(self):
        run = self.prepared()
        self.assertEqual(stat.S_IMODE(run.directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(run.file.stat().st_mode), 0o600)
        for p in (run.directory / 'artifacts').iterdir():
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        archive = run.directory / 'artifacts/home.tar'
        archive.unlink()
        archive.symlink_to(run.directory / 'artifacts/control.tgz')
        with self.assertRaises(CAP.CaptureError):
            run.verify_copies()

    def test_reject_existing_run_directory_and_corrupt_run_record(self):
        run = self.new()
        with self.assertRaises(FileExistsError):
            CAP.Run.create(run.directory, self.remote, 'pre-w1', REVISION, HASHES, reserve=0)
        run.file.write_text('{bad')
        with self.assertRaises(json.JSONDecodeError):
            CAP.Run(run.directory, self.remote)
        self.assertEqual(self.remote.ops, [])

    def test_plan_only_cli_never_constructs_transport_or_checks_git(self):
        for action in ('capture', 'recover', 'finish', 'backout'):
            with self.subTest(action=action), mock.patch.object(CAP, 'SSHRemote', side_effect=AssertionError('transport')),\
                    mock.patch.object(CAP, 'provenance', side_effect=AssertionError('git')), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(CAP.main([action, '--run-dir', str(self.base / 'unused')]), 0)
        self.assertFalse((self.base / 'unused').exists())

    def transport_fixture(self):
        tools = self.base / 'transport-fixture/tools'
        tools.mkdir(parents=True)
        tree = tools.parent / 'roles/login_storage/files/prace-tree-listing'
        tree.parent.mkdir(parents=True)
        files = {
            tools / 'prace_metadata_archive.py': '# original metadata source\n',
            tools / 'prace_capture_window.py': '# original shared-window contract\n',
            tools / 'prace_native_repo.py': '# original native repository helper\n',
            tools / 'prace_capture_remote.py': "RPC_TIMEOUTS = {'capture': 14400, 'default': 1800}\nRECOVERY_GRACE_SECONDS = 1800\n",
            tree: '# original tree source\n',
        }
        for path, source in files.items():
            path.write_text(source)
        hashes = {p.name: hashlib.sha256(s.encode()).hexdigest() for p, s in files.items()}
        return tools, files, hashes

    def test_transport_source_mismatch_refuses_during_inert_construction(self):
        tools, files, hashes = self.transport_fixture()
        next(iter(files)).write_text('# changed after provenance\n')
        with self.assertRaises(CAP.CaptureError):
            CAP.SSHRemote(tools=tools, expected_hashes=hashes)
        # setUp's subprocess guard would fail if construction contacted anything.

    def test_transport_caches_verified_source_without_any_subprocess(self):
        tools, files, hashes = self.transport_fixture()
        transport = CAP.SSHRemote(tools=tools, expected_hashes=hashes)
        try:
            for path in files:
                path.write_text('# changed after construction\n')
            self.assertEqual(transport.helper, files[tools / 'prace_metadata_archive.py'])
            self.assertEqual(transport.remote_source, files[tools / 'prace_capture_remote.py'])
            self.assertEqual(transport.tree, files[tools.parent / 'roles/login_storage/files/prace-tree-listing'])
            self.assertFalse(transport.started)
        finally:
            transport.close()  # not-started close must also be subprocess-free

    def test_transport_timeout_uses_frozen_remote_budgets_and_recovery_allowance(self):
        tools, files, hashes = self.transport_fixture()
        transport = CAP.SSHRemote(tools=tools, expected_hashes=hashes)
        response = types.SimpleNamespace(returncode=0, stdout='{"ok":true}')
        with mock.patch.object(CAP.subprocess, 'run', return_value=response) as command:
            try:
                for op, expected in (('capture', 16260), ('services', 1860), ('closing_status', 1860)):
                    transport.call({'op': op})
                    self.assertEqual(command.call_args.kwargs['timeout'], expected)
            finally:
                transport.close()

    def test_transport_budget_source_is_parsed_without_execution(self):
        tools, files, hashes = self.transport_fixture()
        source = tools / 'prace_capture_remote.py'
        source.write_text(source.read_text() + 'raise AssertionError("must never import locally")\n')
        transport = CAP.SSHRemote(tools=tools)
        transport.close()
        source.write_text('RPC_TIMEOUTS = dangerous_function()\nRECOVERY_GRACE_SECONDS = 1800\n')
        with self.assertRaises(CAP.CaptureError):
            CAP.SSHRemote(tools=tools)

    def test_recovery_rejects_different_checkout_or_helper_before_transport(self):
        run = CAP.Run.create(self.base / 'prace-recovery/session-a/point', self.remote, 'pre-w1', REVISION, HASHES, reserve=0)
        original = run.file.read_bytes()
        for revision, hashes in [('d' * 40, HASHES), (REVISION, {'different-helper.py': 'e' * 64})]:
            with self.subTest(revision=revision, hashes=hashes),\
                    mock.patch.object(CAP, 'provenance', return_value=(revision, hashes)),\
                    mock.patch.object(CAP.Path, 'home', return_value=self.base),\
                    mock.patch.object(CAP, 'SSHRemote') as transport,\
                    contextlib.redirect_stderr(io.StringIO()):
                result = CAP.main(['recover', '--run-dir', str(run.directory), '--execute', '--ack-exclusive-window', '--ack-no-admin-writers'])
                self.assertEqual(result, 1)
                transport.assert_not_called()
                self.assertEqual(run.file.read_bytes(), original, 'a provenance refusal must not invalidate another run')
        self.assertEqual(self.remote.ops, [])

    def test_second_caller_cannot_rewrite_record_without_owning_lock(self):
        run = CAP.Run.create(self.base / 'prace-recovery/session-a/point', self.remote, 'pre-w1', REVISION, HASHES, reserve=0)
        original = run.file.read_bytes()
        with CAP.locked(run.directory),\
                mock.patch.object(CAP, 'provenance', return_value=(REVISION, HASHES)),\
                mock.patch.object(CAP.Path, 'home', return_value=self.base),\
                mock.patch.object(CAP, 'SSHRemote') as transport,\
                contextlib.redirect_stderr(io.StringIO()):
            result = CAP.main(['recover', '--run-dir', str(run.directory), '--execute', '--ack-exclusive-window', '--ack-no-admin-writers'])
            self.assertEqual(result, 1)
            transport.assert_not_called()
        self.assertEqual(run.file.read_bytes(), original, 'failed lock acquisition must never modify the other owner\'s state')

    def test_closed_point_refusal_preserves_accepted_record(self):
        run = CAP.Run.create(self.base / 'prace-recovery/session-a/point', self.remote, 'pre-w1', REVISION, HASHES, reserve=0)
        run.state.update(phase='complete', accepted=True)
        run.save()
        original = run.file.read_bytes()
        with mock.patch.object(CAP, 'provenance', return_value=(REVISION, HASHES)),\
                mock.patch.object(CAP.Path, 'home', return_value=self.base),\
                mock.patch.object(CAP, 'SSHRemote') as transport,\
                contextlib.redirect_stderr(io.StringIO()):
            result = CAP.main(['recover', '--run-dir', str(run.directory), '--execute', '--ack-exclusive-window', '--ack-no-admin-writers'])
            self.assertEqual(result, 1)
            transport.return_value.call.assert_not_called()
        self.assertEqual(run.file.read_bytes(), original, 'closed-window refusal must preserve the accepted recovery point')

    def test_execution_attestations_are_required_before_transport(self):
        for args in ([], ['--ack-exclusive-window'], ['--ack-no-admin-writers']):
            with self.subTest(args=args), mock.patch.object(CAP, 'SSHRemote', side_effect=AssertionError('transport')), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as e:
                    CAP.main(['capture', '--run-dir', str(self.base / 'unused'), '--execute', *args])
                self.assertEqual(e.exception.code, 2)

    def test_backout_requires_invalid_point_ack_before_transport(self):
        with mock.patch.object(CAP, 'SSHRemote', side_effect=AssertionError('transport')), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as e:
                CAP.main(['backout', '--run-dir', str(self.base / 'unused'), '--execute', '--ack-exclusive-window', '--ack-no-admin-writers'])
            self.assertEqual(e.exception.code, 2)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Borrowed capture through the actual remote shim; all command effects are fake.

No SSH, fleet commands, credential reads, VMs or fallback subprocesses. Tests use
real local record files and flock in a temporary directory, plus the existing
hermetic capture-command fixture. Optional cross-source proof is a separate tool.
"""
import copy
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import tarfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    with mock.patch('subprocess.run', side_effect=AssertionError('no import subprocess')):
        spec.loader.exec_module(value)
    return value


F = load('capture_hermetic_fixture', HERE / 'test-prace-capture-remote.py')
C, D = F.REMOTE, F.DRIVER
REMOTE_RUN = C.run
W = load('shared_capture_window', HERE / 'prace_capture_window.py')


def window_record():
    return {'schema': 2, 'id': 'a' * 16, 'label': 'session-a', 'login': D.LOGIN,
            'phase': 'closed', 'original': {'partitions': {'cpu': 'UP', 'gpu': 'DRAIN'},
                'loginsets': {'slurm-login-prace': {'uid': 'login-uid', 'replicas': 1}}},
            'declared_partitions': {}, 'introduced_partitions': [], 'fence_intent': {'active': True},
            'fenced': True, 'ever_leased': True,
            'history': [{'at': '2026-10-01T10:00:00+08:00', 'event': 'closed'}]}


def closed_overlay(window):
    return {'apiVersion': 'helm.cattle.io/v1', 'kind': 'HelmChartConfig',
            'metadata': {'name': 'slurm', 'namespace': 'kube-system', 'annotations': {
                'prace.fleet/window-id': window['id'], 'prace.fleet/window-phase': 'closed'}},
            'spec': {'valuesContent': json.dumps({'nodesets': {
                name: {'partition': {'configMap': {'State': 'INACTIVE'}}}
                for name in dict(window['original']['partitions'], **window['declared_partitions'])},
                'loginsets': {'prace': {'replicas': 0}}})}}


class SharedCapture(unittest.TestCase):
    def setUp(self):
        self.fixture = F.RemoteTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.cmd = self.fixture.root, self.fixture.cmd
        self.record = window_record()
        self.window = W.normalize(self.record)
        self.req = dict(self.fixture.req, stage='post-w2', window=self.window,
                        window_record=copy.deepcopy(self.record))
        self.fixture.req = self.req
        self.cmd.parts = {'cpu': 'INACTIVE', 'gpu': 'INACTIVE'}
        self.cmd.sets = {'slurm-login-prace': {'uid': 'login-uid', 'replicas': 0}}
        self.overlay = closed_overlay(self.window)
        C.LEASE.mkdir(mode=0o700)
        (C.LEASE / 'holder').write_text('holder=maint label=session-a id=' + self.window['id'] +
                                      ' since=2026-10-01T10:00:00+08:00\n')
        (C.LEASE / 'holder').chmod(0o600)
        C.write_json(C.LEASE / 'fence-intent.json', W.projection(self.window))
        C.write_json(C.COMPETING_ADMISSION[0], self.overlay)
        self.borrowed_before = self.lease_bytes()
        self.addCleanup(mock.patch.stopall)
        for patch in (mock.patch.object(C, 'WINDOW_HELPER', W), mock.patch.object(W, 'C', C),
                      mock.patch.object(W, 'LOCK_ROOT', self.root)):
            patch.start()
        original = self.cmd.run
        def commands(argv, **kwargs):
            if argv == C.K + ['-n', 'kube-system', 'get', 'helmchartconfig', 'slurm', '-o', 'json']:
                return json.dumps(self.overlay)
            if argv == ['systemctl', 'start', 'k3s']:
                # Model the very risk this adapter must prevent: K3s startup
                # reconciles persisted chart values into admission objects.
                values = json.loads(C.load_json(C.COMPETING_ADMISSION[0])['spec']['valuesContent'])
                for name, row in values.get('nodesets', {}).items():
                    if 'partition' in row:
                        self.cmd.parts[name] = row['partition']['configMap']['State']
                for name, row in values.get('partitions', {}).items():
                    self.cmd.parts[name] = row['configMap']['State']
                self.cmd.sets['slurm-login-prace']['replicas'] = values['loginsets']['prace']['replicas']
            return original(argv, **kwargs)
        mock.patch.object(C, 'run', side_effect=commands).start()

    def lease_bytes(self):
        return {path.name: path.read_bytes() for path in C.LEASE.iterdir()}

    def op(self, op, **kwargs):
        return C.handle(dict(self.req, op=op, **kwargs))

    def acquire(self):
        result = self.op('inspect')
        self.assertTrue(result['ok'], result)
        self.req.update(identity=result['identity'], original=result['original'])
        result = self.op('acquire')
        self.assertTrue(result['ok'], result)

    def intact(self):
        self.assertEqual(self.lease_bytes(), self.borrowed_before)
        self.assertTrue(self.cmd.fenced)

    def driver(self, fail_copy=False):
        outer = self
        class Transport:
            def __init__(self):
                self.ops = []
            def call(self, request):
                self.ops.append(request['op'])
                return C.handle(request)
            def copy(self, run_id, name, dest):
                if fail_copy:
                    raise D.CaptureError('injected copy failure')
                shutil.copyfile(C.BASE / run_id / name, dest)
                dest.chmod(0o600)
        transport = Transport()
        run = D.Run.create(self.root / 'point', transport, 'post-w2', 'e' * 40,
                           {'fixture': 'f' * 64}, reserve=0, window_record=outer.record)
        run.attest_no_admin_writers = True
        return run, transport

    def test_complete_accepts_copies_and_retains_outer_closed_lease(self):
        self.fixture.fake_capture()
        run, transport = self.driver()
        run.start()
        self.assertEqual(run.state['phase'], 'complete')
        self.assertTrue(run.state['accepted'])
        self.assertTrue(run.state['outer_window_retained'])
        self.assertEqual(json.loads((run.directory / 'artifacts/slurm-window.json').read_text()), self.record)
        self.assertFalse({'reopen', 'release', 'lease_check', 'closing_status', 'verify_original'} & set(transport.ops))
        self.intact()

    def test_copy_failure_keeps_window_owned_and_finish_resumes(self):
        self.fixture.fake_capture()
        run, transport = self.driver(fail_copy=True)
        with self.assertRaises(D.CaptureError):
            run.start()
        self.assertFalse(run.state['accepted'])
        self.intact()
        def copied(run_id, name, dest):
            shutil.copyfile(C.BASE / run_id / name, dest)
            dest.chmod(0o600)
        transport.copy = copied
        run.complete()
        self.assertTrue(run.state['accepted'])
        self.intact()

    def test_interrupted_capture_and_backout_never_reopen_or_release(self):
        self.fixture.fake_capture(fail=True)
        run, transport = self.driver()
        with self.assertRaises(D.CaptureError):
            run.start()
        self.assertTrue(self.cmd.k3s)
        self.intact()
        run.recover()
        run.backout()
        self.assertEqual(run.state['phase'], 'aborted')
        self.assertFalse(run.state['accepted'])
        self.assertFalse({'backout', 'reopen', 'release'} & set(transport.ops))
        self.intact()

    def test_owner_operations_are_rejected_even_with_valid_borrowed_record(self):
        for op in ('reopen', 'backout', 'release', 'lease_check', 'closing_status', 'verify_original'):
            with self.subTest(op=op):
                self.assertEqual(self.op(op)['error'], 'shared_owner_operation')
        self.assertFalse(self.cmd.effects)
        self.intact()

    def test_missing_or_opening_or_wrong_window_overlay_refuses_before_records(self):
        for kind in ('disk-opening', 'applied-opening', 'wrong-id', 'missing-disk', 'uncovered'):
            with self.subTest(kind=kind):
                self.overlay = closed_overlay(self.window)
                disk = copy.deepcopy(self.overlay)
                if kind == 'disk-opening':
                    disk['metadata']['annotations']['prace.fleet/window-phase'] = 'opening'
                elif kind == 'applied-opening':
                    self.overlay['metadata']['annotations']['prace.fleet/window-phase'] = 'opening'
                elif kind == 'wrong-id':
                    disk['metadata']['annotations']['prace.fleet/window-id'] = 'b' * 16
                elif kind == 'uncovered':
                    values = json.loads(disk['spec']['valuesContent'])
                    del values['nodesets']['gpu']
                    disk['spec']['valuesContent'] = json.dumps(values)
                C.write_json(C.COMPETING_ADMISSION[0], disk)
                if kind == 'missing-disk':
                    C.COMPETING_ADMISSION[0].unlink()
                self.assertFalse(self.op('inspect')['ok'])
                self.assertFalse(C.BASE.exists())
                self.assertFalse(self.cmd.effects)

    def test_api_default_accepts_legacy_disk_without_mutating_outer_window(self):
        self.overlay['spec']['failurePolicy'] = 'reinstall'
        # Disk stays in the legacy form while the API adds its known default.
        self.assertTrue(self.op('inspect')['ok'])
        self.assertNotIn('failurePolicy', C.load_json(C.COMPETING_ADMISSION[0])['spec'])
        self.intact()

    def test_abort_policy_on_disk_and_api_is_accepted(self):
        # the window helper writes failurePolicy abort since 2 Oct (no uninstall-reinstall)
        self.overlay['spec']['failurePolicy'] = 'abort'
        disk = copy.deepcopy(self.overlay)
        C.write_json(C.COMPETING_ADMISSION[0], disk)
        self.assertTrue(self.op('inspect')['ok'])
        self.intact()

    def test_unknown_api_or_disk_policy_refuses_before_capture(self):
        for target in ('api', 'disk'):
            for addition in ({'failurePolicy': 'retry'}, {'failurePolicy': None},
                             {'failurePolicy': 'reinstall', 'valuesSecrets': []}):
                with self.subTest(target=target, addition=addition):
                    self.overlay = closed_overlay(self.window)
                    disk = copy.deepcopy(self.overlay)
                    (self.overlay if target == 'api' else disk)['spec'].update(addition)
                    C.write_json(C.COMPETING_ADMISSION[0], disk)
                    self.assertFalse(self.op('inspect')['ok'])
                    self.assertFalse(C.BASE.exists())
                    self.assertFalse(self.cmd.effects)

    def test_wrong_holder_or_marker_refuses_before_records(self):
        (C.LEASE / 'holder').write_text('holder=maint label=other id=' + self.window['id'] + ' since=now\n')
        self.assertEqual(self.op('inspect')['error'], 'shared_lease_not_owned')
        (C.LEASE / 'holder').write_bytes(self.borrowed_before['holder'])
        marker = W.projection(self.window)
        marker['phase'] = 'opening'
        C.write_json(C.LEASE / 'fence-intent.json', marker)
        self.assertEqual(self.op('inspect')['error'], 'shared_intent_changed')
        self.assertFalse(C.BASE.exists())
        self.assertFalse(self.cmd.effects)

    def test_queue_and_failed_queue_query_do_not_accept_capture(self):
        for failure in (False, True):
            self.cmd.queue, self.cmd.queue_error = ('123' if not failure else ''), failure
            self.assertFalse(self.op('inspect')['ok'])
            self.assertFalse(C.BASE.exists())
        self.assertFalse(self.cmd.effects)

    def test_replaced_login_uid_or_unknown_partition_refuses(self):
        self.cmd.sets['slurm-login-prace']['uid'] = 'replaced'
        self.assertEqual(self.op('inspect')['error'], 'shared_membership_changed')
        self.cmd.sets['slurm-login-prace']['uid'] = 'login-uid'
        self.cmd.parts['unexpected'] = 'INACTIVE'
        self.assertEqual(self.op('inspect')['error'], 'shared_membership_changed')
        self.assertFalse(self.cmd.effects)

    def test_common_window_lock_blocks_capture_before_any_host_command(self):
        lock = self.root / ('prace-slurm-window-' + self.window['id'] + '.lock')
        with lock.open('w') as file:
            lock.chmod(0o600)
            fcntl.flock(file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.op('inspect')['error'], 'shared_window_busy')
        self.assertFalse(self.cmd.calls)

    def test_common_lock_and_metadata_children_share_descriptor(self):
        self.fixture.fake_capture()
        self.acquire()
        original = C.METADATA_HELPER.create_verified_archive
        def checked(*args, **kwargs):
            self.assertIsNotNone(W.FD)
            self.assertEqual(C.METADATA_HELPER.OPERATION_LOCK_FD, W.FD)
            with self.assertRaises(BlockingIOError):
                other = os.open(self.root / ('prace-slurm-window-' + self.window['id'] + '.lock'), os.O_RDWR)
                try:
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(other)
            return original(*args, **kwargs)
        with mock.patch.object(C.METADATA_HELPER, 'create_verified_archive', side_effect=checked):
            self.assertTrue(self.op('capture')['ok'])
        self.intact()

    def test_overlay_changes_before_service_recovery_refuse_before_start(self):
        self.acquire()
        self.cmd.k3s = False
        self.cmd.state = 'T'
        disk = copy.deepcopy(self.overlay)
        disk['metadata']['annotations']['prace.fleet/window-phase'] = 'opening'
        C.write_json(C.COMPETING_ADMISSION[0], disk)
        self.assertEqual(self.op('services')['error'], 'shared_overlay_invalid')
        self.assertFalse(self.cmd.effects)

    def test_frozen_record_mismatch_refuses_before_effects(self):
        self.acquire()
        altered = copy.deepcopy(self.record)
        altered['history'].append({'at': 'later', 'event': 'unexpected'})
        self.assertEqual(self.op('services', window_record=altered)['error'], 'record_mismatch')
        self.assertFalse(self.cmd.effects)

    def test_legacy_request_cannot_adopt_a_borrowed_point(self):
        self.acquire()
        request = dict(self.req, op='services')
        del request['window'], request['window_record']
        self.assertEqual(C.handle(request)['error'], 'record_mismatch')
        self.assertFalse(self.cmd.effects)

    def test_opening_off_fleet_record_is_rejected_locally_without_transport(self):
        self.record['phase'] = 'opening'
        with self.assertRaises(D.CaptureError):
            self.driver()
        self.assertFalse((self.root / 'point').exists())

    def test_saved_window_artifact_is_mandatory_and_exact(self):
        self.fixture.fake_capture()
        run, transport = self.driver()
        run.start()
        manifest = copy.deepcopy(run.state['manifest'])
        manifest['artifacts'] = [row for row in manifest['artifacts'] if row['path'] != 'slurm-window.json']
        with self.assertRaises(D.CaptureError):
            run.validate_manifest(manifest)
        path = run.directory / 'artifacts/slurm-window.json'
        changed = copy.deepcopy(self.record)
        changed['original']['partitions']['cpu'] = 'DOWN'
        path.write_text(json.dumps(changed))
        item = next(row for row in run.state['manifest']['artifacts'] if row['path'] == 'slurm-window.json')
        item.update(size=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        with self.assertRaises(D.CaptureError):
            run.verify_copies()

    def test_control_archive_names_outer_id_and_original_return_states(self):
        self.acquire()
        state = self.root / 'control-state'
        state.mkdir(mode=0o700)
        tokens = [state / 'token', state / 'agent-token']
        for index, token in enumerate(tokens):
            token.write_text('non-secret fixture value ' + str(index))
            token.chmod(0o600)
        with mock.patch.object(C, 'CONTROL', (str(state),)), mock.patch.object(C, 'TOKENS', tuple(map(str, tokens))):
            C.control_archive(C.BASE / self.req['id'], self.req)
        with tarfile.open(C.BASE / self.req['id'] / 'control.tgz') as archive:
            text = archive.extractfile('prace-backup/maintenance-window.txt').read().decode()
        self.assertIn('lease=' + self.window['id'] + ' ', text)
        self.assertIn('partitions-before-fence=cpu=UP,gpu=DRAIN', text)
        self.assertIn('loginsets-before-fence=slurm-login-prace=1', text)
        self.assertNotIn('INACTIVE', text)
        self.intact()

    def test_remote_commands_inherit_both_window_and_capture_locks(self):
        capture_fd = os.open(self.root / 'capture-lock', os.O_CREAT | os.O_RDWR, 0o600)
        self.addCleanup(os.close, capture_fd)
        child = types.SimpleNamespace(returncode=0, communicate=lambda **_: ('ok', ''))
        with W.locked(self.window), mock.patch.object(C, 'OPERATION_LOCK_FD', capture_fd), \
                mock.patch.object(C.subprocess, 'Popen', return_value=child) as spawn:
            self.assertEqual(REMOTE_RUN(['fixture-command']), 'ok')
            self.assertEqual(set(spawn.call_args.kwargs['pass_fds']), {capture_fd, W.FD})


if __name__ == '__main__':
    unittest.main(verbosity=2)

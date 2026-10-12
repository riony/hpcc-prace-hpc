#!/usr/bin/env python3
"""Actual remote handle()/driver protocol with hermetic command effects only.

No SSH, systemctl, kill, kubectl or credential reads. Only the production root
entry check is bypassed in ordinary fixtures; ownership checks remain real.
"""
import copy
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import tarfile
import tempfile
import types
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    with mock.patch('subprocess.run', side_effect=AssertionError('import must be inert')):
        spec.loader.exec_module(module)
    return module


REMOTE = load('remote_under_test', 'prace_capture_remote.py')
DRIVER = load('driver_remote_integration', 'session-a-capture.py')
AUDIT = load('fleet_audit_lease_contract', 'fleet_audit.py')
ARCHIVE = load('archive_preflight_under_test', 'prace_metadata_archive.py')
REAL_PREFLIGHT = REMOTE.preflight


class Commands:
    def __init__(self):
        self.parts = {'cpu': 'UP', 'gpu': 'DRAIN'}
        self.sets = {'login': {'uid': 'login-uid', 'replicas': 1},
                     'disabled': {'uid': 'disabled-uid', 'replicas': 0}}
        self.ident = {'hostname': 'lab-dl380', 'chassis_serial': 'EXSERIAL01',
                      'machine_id': 'a' * 32, 'boot_id': '12345678-1234-1234-1234-123456789abc'}
        self.pid, self.starttime, self.state = 4321, '12345', 'S'
        self.k3s = True
        self.ready = True
        self.extra_pod = False
        self.queue_error = False
        self.queue = ""
        self.fail_reopen_once = False
        self.raw_parts = None
        self.calls, self.effects = [], []

    def process(self, pid):
        if pid != self.pid:
            raise REMOTE.Refused('controller_identity')
        return {'pid': pid, 'starttime': self.starttime, 'state': self.state}

    @property
    def fenced(self):
        return all(v == 'INACTIVE' for v in self.parts.values()) and all(v['replicas'] == 0 for v in self.sets.values())

    def run(self, argv, *, timeout=120, stdout=None):
        self.calls.append(list(argv))
        if argv == ['pgrep', '-x', 'slurmctld']:
            return str(self.pid) + '\n'
        if argv[:2] == ['systemctl', 'is-active']:
            if not self.k3s:
                raise REMOTE.Refused('command_failed')
            return 'active\n'
        if argv[:2] == ['systemctl', 'show']:
            return 'active\n' if self.k3s else 'inactive\n'
        if argv[:2] in (['systemctl', 'start'], ['systemctl', 'stop']):
            self.k3s = argv[1] == 'start'
            self.effects.append('k3s-' + argv[1])
            return ''
        if argv[:1] == ['kill']:
            assert argv[2] == str(self.pid)
            self.state = 'T' if argv[1] == '-STOP' else 'S'
            self.effects.append(argv[1])
            return ''
        if argv[:1] == ['mysqldump']:
            assert stdout is not None
            stdout.write(b'-- private fixture database dump\n')
            return ''
        if argv[:1] == ['/usr/local/sbin/prace-slinky-worker-check']:
            assert argv[1:] == REMOTE.WORKERS
            return 'usable\n'
        if argv[:len(REMOTE.CTL)] == REMOTE.CTL:
            args = argv[len(REMOTE.CTL):]
            if args == ['scontrol', 'show', 'partition', '-o']:
                if self.raw_parts is not None:
                    return self.raw_parts
                return '\n'.join(f'PartitionName={n} State={s}' for n, s in self.parts.items())
            if args[:2] == ['scontrol', 'update']:
                name, state = args[2].split('=', 1)[1], args[3].split('=', 1)[1]
                self.parts[name] = state
                self.effects.append('partition:' + name + ':' + state)
                return ''
            if args[:1] == ['squeue']:
                if self.queue_error:
                    raise REMOTE.Refused('command_failed')
                return self.queue
        if argv[:len(REMOTE.KS)] == REMOTE.KS:
            args = argv[len(REMOTE.KS):]
            if args[:2] == ['get', 'loginsets']:
                return json.dumps({'items': [{'metadata': {'name': n, 'uid': item['uid']},
                                             'spec': {'replicas': item['replicas']}} for n, item in self.sets.items()]})
            if args[:2] == ['get', 'pods']:
                count = sum(v['replicas'] for v in self.sets.values()) + int(self.extra_pod)
                return json.dumps({'items': [{'metadata': {'name': f'login-{n}'},
                    'status': {'conditions': [{'type': 'Ready', 'status': str(self.ready).lower().capitalize()}]}}
                    for n in range(count)]})
            if args[:2] == ['patch', 'loginset']:
                name = args[2]
                patch = json.loads(args[args.index('-p') + 1])
                assert patch[0]['value'] == self.sets[name]['uid']
                if any(arg.startswith('--dry-run') for arg in args):
                    assert args[-3:] == ['--dry-run=server', '-o', 'json']
                    return json.dumps({'metadata': {'name': name, 'uid': self.sets[name]['uid']},
                                       'spec': {'replicas': patch[1]['value']}})
                self.sets[name]['replicas'] = patch[1]['value']
                self.effects.append('login:' + name + ':' + str(patch[1]['value']))
                if self.fail_reopen_once and patch[1]['value']:
                    self.fail_reopen_once = False
                    raise REMOTE.Refused('lost_response_after_patch')
                return ''
        if argv[:len(REMOTE.K)] == REMOTE.K:
            args = argv[len(REMOTE.K):]
            if args == ['get', '--raw', '/readyz']:
                return 'ok\n' if self.k3s else 'unavailable\n'
            if args[:2] == ['get', 'nodes']:
                return json.dumps({'items': [{'metadata': {'name': n}} for n in REMOTE.WORKERS]})
        raise AssertionError('Unexpected command; no real fallback: ' + repr(argv))


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='prace-remote-unit-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.cmd = Commands()
        self.req = {'id': 'b' * 32, 'stage': 'pre-w1', 'workers': REMOTE.WORKERS,
                    'max_data_bytes': 1024, 'attest_no_admin_writers': True}
        self.original_require = REMOTE.require
        def require(condition, code):
            self.original_require(condition or code == 'root_required', code)
        patches = [mock.patch.object(REMOTE, 'BASE', self.root / 'remote'),
                   mock.patch.object(REMOTE, 'COMPETING_ADMISSION',
                                     (self.root / 'persistent-overlay', self.root / 'shared-intent')),
                   mock.patch.object(REMOTE, 'LEASE', self.root / 'lease'),
                   mock.patch.object(REMOTE, 'run', side_effect=self.cmd.run),
                   mock.patch.object(REMOTE, 'identity', side_effect=lambda: copy.deepcopy(self.cmd.ident)),
                   mock.patch.object(REMOTE, 'process', side_effect=self.cmd.process),
                   mock.patch.object(REMOTE, 'require', side_effect=require),
                   mock.patch.object(REMOTE, 'preflight', side_effect=lambda r: {
                       'roots': REMOTE.STAGES[r['stage']], 'data_bytes': 4, 'free_bytes': 100 * REMOTE.GIB}),
                   mock.patch.object(REMOTE, 'writable_fds'),
                   mock.patch.object(REMOTE.time, 'sleep'),
                   mock.patch.object(REMOTE.subprocess, 'run', side_effect=AssertionError('no real subprocess'))]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def op(self, name, **extra):
        return REMOTE.handle(dict(self.req, op=name, **extra))

    def acquire(self, fenced=False):
        inspection = self.op('inspect')
        self.assertTrue(inspection['ok'], inspection)
        self.req.update(identity=inspection['identity'], original=inspection['original'])
        self.assertTrue(self.op('acquire')['ok'])
        if fenced:
            self.assertTrue(self.op('fence')['ok'])

    def assert_owned(self):
        self.assertEqual(REMOTE.lease_status(self.req['id']), 'owned')

    def fake_capture(self, fail=False):
        def control(d, request):
            (d / 'control.tgz').write_bytes(b'control fixture')
        def metadata(source, output, proof, helper, max_bytes=None):
            self.assertTrue(self.cmd.fenced)
            self.assertFalse(self.cmd.k3s)
            self.assertEqual(self.cmd.state, 'T')
            if fail:
                raise RuntimeError('injected metadata capture interruption')
            output.write_bytes(b'data fixture')
            output.chmod(0o600)
            proof.mkdir(mode=0o700)
            for name in ('manifest.json', 'extracted.jsonl'):
                (proof / name).write_text('{}\n')
                (proof / name).chmod(0o600)
            return {'logical_bytes': 4}
        for patch in (mock.patch.object(REMOTE, 'control_archive', side_effect=control),
                      mock.patch.object(REMOTE, 'TREE_SOURCE', '# fixture listing helper\n'),
                      mock.patch.object(REMOTE, 'METADATA_HELPER', types.SimpleNamespace(create_verified_archive=metadata))):
            patch.start()
            self.addCleanup(patch.stop)

    def test_root_guard_remains_enforced(self):
        with mock.patch.object(REMOTE, 'require', self.original_require), mock.patch.object(os, 'geteuid', return_value=1000):
            self.assertEqual(self.op('inspect')['error'], 'root_required')
        self.assertFalse(self.cmd.calls)

    def test_legacy_capture_refuses_persistent_fence_before_any_effect(self):
        for name in ('persistent-overlay', 'shared-intent'):
            path = self.root / name
            path.write_text('unknown intent')
            for op in ('inspect', 'acquire', 'fence', 'capture', 'reopen', 'backout'):
                with self.subTest(name=name, op=op):
                    result = self.op(op)
                    self.assertEqual(result['error'], 'persistent_fence_requires_capture_adapter')
                    self.assertFalse(self.cmd.effects)
                    self.assertFalse(REMOTE.BASE.exists())
                    self.assertFalse(REMOTE.LEASE.exists())
            path.unlink()
        # A broken symlink is still competing intent, not absence.
        (self.root / 'persistent-overlay').symlink_to(self.root / 'missing')
        self.assertEqual(self.op('inspect')['error'], 'persistent_fence_requires_capture_adapter')

    def test_persistent_fence_guard_keeps_prior_service_recovery_available(self):
        self.acquire(fenced=True)
        (self.root / 'persistent-overlay').write_text('later overlay')
        with mock.patch.object(REMOTE, 'services') as services:
            self.assertTrue(self.op('services')['ok'])
            services.assert_called_once()
        self.assert_owned()

    def test_empty_or_malformed_partition_membership_refused(self):
        for value in ('', 'PartitionName=cpu State=UNKNOWN', 'PartitionName=cpu State=UP\nPartitionName=cpu State=UP'):
            self.cmd.raw_parts = value
            self.assertFalse(self.op('inspect')['ok'])
        self.assertFalse(REMOTE.LEASE.exists())

    def test_empty_login_membership_refused(self):
        self.cmd.sets.clear()
        self.assertFalse(self.op('inspect')['ok'])

    def test_acquired_holder_matches_actual_audit_lease_contract(self):
        before = datetime.datetime.now(datetime.timezone.utc)
        self.acquire()
        after = datetime.datetime.now(datetime.timezone.utc)
        holder = (REMOTE.LEASE / 'holder').read_text().strip()
        match = AUDIT.LEASE_RX.fullmatch(holder)
        self.assertIsNotNone(match, holder)
        since = datetime.datetime.fromisoformat(match.group(2))
        self.assertEqual(since.utcoffset(), datetime.timedelta(0))
        self.assertLessEqual(before, since)
        self.assertLessEqual(since, after)
        outcome, _ = AUDIT.evaluate({'schema': 1, 'time': after.timestamp(),
                                    'lease': {'held': True, 'holder': holder}}, {}, now=after.timestamp())
        self.assertEqual(outcome, 'DEFERRED_MAINTENANCE')

    def test_foreign_lease_refusal_is_read_only(self):
        self.acquire()
        (REMOTE.LEASE / 'holder').write_text('holder=other id=' + 'c' * 32 + '\n')
        before = list(self.cmd.effects)
        self.assertFalse(self.op('fence')['ok'])
        self.assertEqual(self.cmd.effects, before)
        self.assertIn('holder=other', (REMOTE.LEASE / 'holder').read_text())

    def test_missing_and_partial_lease_never_adopted(self):
        self.acquire()
        (REMOTE.LEASE / 'holder').unlink()
        self.assertFalse(self.op('services')['ok'])
        self.assertEqual(REMOTE.lease_status(self.req['id']), 'foreign')
        REMOTE.LEASE.rmdir()
        self.assertFalse(self.op('services')['ok'])
        self.assertEqual(REMOTE.lease_status(self.req['id']), 'missing')
        self.assertFalse(self.cmd.effects)

    def test_boot_or_controller_starttime_mismatch_before_continue(self):
        self.acquire(fenced=True)
        self.cmd.state = 'T'
        original_boot = self.cmd.ident['boot_id']
        self.cmd.ident['boot_id'] = '22345678-1234-1234-1234-123456789abc'
        self.assertFalse(self.op('services')['ok'])
        self.cmd.ident['boot_id'] = original_boot
        self.cmd.starttime = 'changed'
        self.assertFalse(self.op('services')['ok'])
        self.assertNotIn('-CONT', self.cmd.effects)
        self.assert_owned()

    def test_queue_query_error_prevents_capture_but_not_services(self):
        self.acquire()
        self.cmd.queue_error = True
        self.assertTrue(self.op('fence')['ok'])
        self.fake_capture()
        self.assertFalse(self.op('capture')['ok'])
        self.assertNotIn('-STOP', self.cmd.effects)
        self.assertTrue(self.op('services')['ok'])
        self.assertTrue(self.cmd.fenced)
        self.assert_owned()

    def test_services_resume_exact_controller_then_start_and_refence(self):
        self.acquire(fenced=True)
        self.cmd.state, self.cmd.k3s = 'T', False
        self.assertTrue(self.op('services')['ok'])
        self.assertEqual(self.cmd.state, 'S')
        self.assertTrue(self.cmd.k3s and self.cmd.fenced)
        self.assertLess(self.cmd.effects.index('-CONT'), self.cmd.effects.index('k3s-start'))
        self.assert_owned()

    def test_capture_recovery_waits_for_membership_after_api_ready(self):
        self.acquire(fenced=True)
        self.fake_capture()
        remaining = {'partition': 1, 'loginset': 1}
        failed = []
        original = self.cmd.run
        def starting(argv, **kwargs):
            probes = {tuple(REMOTE.CTL + ['scontrol', 'show', 'partition', '-o']): 'partition',
                      tuple(REMOTE.KS + ['get', 'loginsets', '-o', 'json']): 'loginset'}
            name = probes.get(tuple(argv))
            if 'k3s-start' in self.cmd.effects and name and remaining[name]:
                start = self.cmd.calls.index(['systemctl', 'start', 'k3s'])
                self.assertIn(REMOTE.K + ['get', '--raw', '/readyz'], self.cmd.calls[start + 1:])
                self.assertTrue(self.cmd.fenced)
                self.assertEqual(self.cmd.effects[-1], 'k3s-start')
                remaining[name] -= 1
                failed.append(name)
                raise REMOTE.Refused('command_failed')
            return original(argv, **kwargs)
        with mock.patch.object(REMOTE, 'run', side_effect=starting):
            response = self.op('capture')
        self.assertTrue(response['ok'], response)
        self.assertEqual(failed, ['partition', 'loginset'])
        self.assertEqual(REMOTE.time.sleep.call_args_list, [mock.call(2), mock.call(2)])
        self.assertTrue(self.cmd.k3s and self.cmd.fenced)
        self.assertTrue(REMOTE.load_json(REMOTE.BASE / self.req['id'] / 'capture.json')['complete'])
        self.assert_owned()

    def test_membership_readiness_exhaustion_preserves_failure_without_refencing(self):
        self.acquire(fenced=True)
        original = self.cmd.run
        observations = []
        before = len(self.cmd.effects)
        def unavailable(argv, **kwargs):
            if argv == REMOTE.CTL + ['scontrol', 'show', 'partition', '-o']:
                observations.append(kwargs.get('timeout'))
                raise REMOTE.Refused('command_failed')
            return original(argv, **kwargs)
        with mock.patch.object(REMOTE, 'run', side_effect=unavailable):
            response = self.op('services')
        self.assertEqual(response['error'], 'command_failed')
        self.assertEqual(observations, [5] * 10)
        self.assertEqual(REMOTE.time.sleep.call_args_list, [mock.call(2)] * 9)
        self.assertEqual(self.cmd.effects[before:], ['k3s-start'])
        events = [item['event'] for item in REMOTE.load_json(REMOTE.BASE / self.req['id'] / 'journal.json')]
        self.assertEqual(events.count('fence_intent'), 1)  # only the original fence
        self.assertNotIn('services_ready_fenced', events)
        self.assertTrue(self.cmd.fenced)
        self.assert_owned()

    def test_membership_readiness_refuses_structure_and_replacement_without_retry(self):
        self.acquire(fenced=True)
        part = REMOTE.CTL + ['scontrol', 'show', 'partition', '-o']
        sets = REMOTE.KS + ['get', 'loginsets', '-o', 'json']
        replacement = json.loads(self.cmd.run(sets))
        replacement['items'][0]['metadata']['uid'] = 'replacement'
        cases = [(part, '', 'partition_query'),
                 (part, 'PartitionName=unexpected State=UP', 'membership_changed'),
                 (sets, '{"items": []}', 'loginset_query'),
                 (sets, json.dumps(replacement), 'loginset_replaced'),
                 (sets, 'invalid json', 'remote_operation_failed')]
        original = self.cmd.run
        for command, output, error in cases:
            observations = []
            def invalid(argv, **kwargs):
                if argv == command:
                    observations.append(argv)
                    return output
                # A known partition mismatch must win even if a subsequent
                # loginset observation would have failed transiently.
                if command == part and argv == sets:
                    raise REMOTE.Refused('command_failed')
                return original(argv, **kwargs)
            before = len(self.cmd.effects)
            REMOTE.time.sleep.reset_mock()
            with self.subTest(error=error), mock.patch.object(REMOTE, 'run', side_effect=invalid):
                response = self.op('services')
                self.assertEqual(response['error'], error)
                self.assertEqual(len(observations), 1)
                REMOTE.time.sleep.assert_not_called()
                self.assertEqual(self.cmd.effects[before:], ['k3s-start'])
                self.assertTrue(self.cmd.fenced)
                self.assert_owned()

    def test_membership_retry_rechecks_host_controller_and_lease(self):
        self.acquire(fenced=True)
        original = self.cmd.run
        holder = REMOTE.LEASE / 'holder'
        saved_holder = holder.read_text()
        boot = self.cmd.ident['boot_id']
        starttime = self.cmd.starttime
        changes = [('identity_changed', lambda: self.cmd.ident.update(boot_id='2' * 36)),
                   ('controller_changed', lambda: setattr(self.cmd, 'starttime', 'different')),
                   ('lease_not_owned', lambda: holder.write_text('holder=other id=' + 'c' * 32 + '\n'))]
        for error, change in changes:
            observations = []
            def changing(argv, **kwargs):
                if argv == REMOTE.CTL + ['scontrol', 'show', 'partition', '-o']:
                    observations.append(argv)
                    change()
                    raise REMOTE.Refused('command_failed')
                return original(argv, **kwargs)
            before = len(self.cmd.effects)
            REMOTE.time.sleep.reset_mock()
            with self.subTest(error=error), mock.patch.object(REMOTE, 'run', side_effect=changing):
                response = self.op('services')
                self.assertEqual(response['error'], error)
                self.assertEqual(len(observations), 1)
                self.assertEqual(REMOTE.time.sleep.call_args_list, [mock.call(2)])
                self.assertEqual(self.cmd.effects[before:], ['k3s-start'])
                self.assertTrue(self.cmd.fenced)
            self.cmd.ident['boot_id'], self.cmd.starttime = boot, starttime
            holder.write_text(saved_holder)

    def test_membership_readiness_does_not_retry_timeout_or_fence_write_failure(self):
        self.acquire(fenced=True)
        original = self.cmd.run
        probe = REMOTE.CTL + ['scontrol', 'show', 'partition', '-o']
        update = REMOTE.CTL + ['scontrol', 'update', 'PartitionName=cpu', 'State=INACTIVE']
        cases = [(probe, REMOTE.Refused('operation_timeout'), 'operation_timeout'),
                 (probe, subprocess.TimeoutExpired(probe, 5), 'remote_operation_failed'),
                 (update, REMOTE.Refused('command_failed'), 'command_failed')]
        for command, exception, error in cases:
            failed = []
            def failing(argv, **kwargs):
                if argv == command:
                    failed.append(argv)
                    raise exception
                return original(argv, **kwargs)
            REMOTE.time.sleep.reset_mock()
            with self.subTest(error=error, command=command), mock.patch.object(REMOTE, 'run', side_effect=failing):
                self.assertEqual(self.op('services')['error'], error)
                self.assertEqual(failed, [command])
                REMOTE.time.sleep.assert_not_called()
                self.assertTrue(self.cmd.fenced)
                self.assert_owned()

    def test_capture_recovery_waits_for_admission_before_any_fence_write(self):
        self.acquire(fenced=True)
        self.fake_capture()
        original = self.cmd.run
        failed, admitted = [], set()
        def starting(argv, **kwargs):
            if 'k3s-start' in self.cmd.effects:
                if argv[:len(REMOTE.KS) + 2] == REMOTE.KS + ['patch', 'loginset']:
                    name = argv[len(REMOTE.KS) + 2]
                    if '--dry-run=server' in argv:
                        self.assertEqual(self.cmd.effects[-1], 'k3s-start')
                        self.assertEqual(kwargs.get('timeout'), 5)
                        if len(failed) < 2:
                            failed.append(name)
                            raise REMOTE.Refused('command_failed')  # webhook has no endpoints yet
                        admitted.add(name)
                    else:
                        self.assertEqual(admitted, set(self.cmd.sets))
                if argv[:len(REMOTE.CTL) + 2] == REMOTE.CTL + ['scontrol', 'update']:
                    self.assertEqual(admitted, set(self.cmd.sets))
            return original(argv, **kwargs)
        with mock.patch.object(REMOTE, 'run', side_effect=starting):
            response = self.op('capture')
        self.assertTrue(response['ok'], response)
        self.assertEqual(len(failed), 2)
        self.assertEqual(admitted, set(self.req['original']['loginsets']))
        self.assertEqual(REMOTE.time.sleep.call_args_list, [mock.call(2), mock.call(2)])
        self.assertTrue(self.cmd.k3s and self.cmd.fenced)
        events = [item['event'] for item in REMOTE.load_json(REMOTE.BASE / self.req['id'] / 'journal.json')]
        self.assertLess(events.index('admission_ready'), max(i for i, event in enumerate(events) if event == 'fence_intent'))
        self.assertEqual(events[-1], 'services_ready_fenced')
        self.assert_owned()

    def test_admission_probe_is_exact_server_dry_run_without_mutation(self):
        self.acquire()
        original = copy.deepcopy((self.cmd.parts, self.cmd.sets, self.cmd.effects))
        start = len(self.cmd.calls)
        REMOTE.wait_membership(self.req)
        self.assertEqual((self.cmd.parts, self.cmd.sets, self.cmd.effects), original)
        probes = [args for args in self.cmd.calls[start:] if args[:len(REMOTE.KS) + 2] ==
                  REMOTE.KS + ['patch', 'loginset']]
        self.assertEqual(len(probes), len(self.cmd.sets))
        for name, argv in zip(sorted(self.cmd.sets), probes):
            self.assertEqual(argv[-3:], ['--dry-run=server', '-o', 'json'])
            self.assertEqual(argv[:len(REMOTE.KS) + 4], REMOTE.KS + ['patch', 'loginset', name, '--type=json'])
            self.assertEqual(json.loads(argv[argv.index('-p') + 1]), [
                {'op': 'test', 'path': '/metadata/uid', 'value': self.cmd.sets[name]['uid']},
                {'op': 'replace', 'path': '/spec/replicas', 'value': 0}])
        start = len(self.cmd.calls)
        self.assertTrue(self.op('fence')['ok'])
        applied = [args for args in self.cmd.calls[start:] if args[:len(REMOTE.KS) + 2] ==
                   REMOTE.KS + ['patch', 'loginset']]
        self.assertEqual(applied, [args[:-3] for args in probes])

    def test_admission_exhaustion_retains_fence_and_lease_without_fence_intent(self):
        self.acquire(fenced=True)
        before = len(self.cmd.effects)
        original = self.cmd.run
        failed = []
        def unavailable(argv, **kwargs):
            if argv[:len(REMOTE.KS) + 2] == REMOTE.KS + ['patch', 'loginset']:
                failed.append(argv)
                raise REMOTE.Refused('command_failed')
            return original(argv, **kwargs)
        with mock.patch.object(REMOTE, 'run', side_effect=unavailable):
            response = self.op('services')
        self.assertEqual(response['error'], 'command_failed')
        self.assertEqual(len(failed), 10)
        self.assertTrue(all('--dry-run=server' in args for args in failed))
        self.assertEqual(REMOTE.time.sleep.call_args_list, [mock.call(2)] * 9)
        self.assertEqual(self.cmd.effects[before:], ['k3s-start'])
        events = [item['event'] for item in REMOTE.load_json(REMOTE.BASE / self.req['id'] / 'journal.json')]
        self.assertEqual(events.count('fence_intent'), 1)
        self.assertIn('membership_ready', events)
        self.assertNotIn('admission_ready', events)
        self.assertNotIn('services_ready_fenced', events)
        self.assertTrue(self.cmd.fenced)
        self.assert_owned()

    def test_admission_uid_race_is_refused_before_retry(self):
        self.acquire(fenced=True)
        before = len(self.cmd.effects)
        original = self.cmd.run
        failed = []
        def replaced(argv, **kwargs):
            if argv[:len(REMOTE.KS) + 2] == REMOTE.KS + ['patch', 'loginset']:
                failed.append(argv)
                self.cmd.sets[argv[len(REMOTE.KS) + 2]]['uid'] = 'replacement'
                raise REMOTE.Refused('command_failed')  # JSON Patch UID test failed
            return original(argv, **kwargs)
        with mock.patch.object(REMOTE, 'run', side_effect=replaced):
            response = self.op('services')
        self.assertEqual(response['error'], 'loginset_replaced')
        self.assertEqual(len(failed), 1)
        self.assertIn('--dry-run=server', failed[0])
        REMOTE.time.sleep.assert_not_called()
        self.assertEqual(self.cmd.effects[before:], ['k3s-start'])
        self.assert_owned()

    def test_admission_timeouts_are_not_retried(self):
        self.acquire(fenced=True)
        original = self.cmd.run
        for exception, error in [(REMOTE.Refused('operation_timeout'), 'operation_timeout'),
                                 (subprocess.TimeoutExpired('fixture admission probe', 5), 'remote_operation_failed')]:
            failed = []
            def timed_out(argv, **kwargs):
                if '--dry-run=server' in argv:
                    failed.append(argv)
                    raise exception
                return original(argv, **kwargs)
            before = len(self.cmd.effects)
            REMOTE.time.sleep.reset_mock()
            with self.subTest(error=error), mock.patch.object(REMOTE, 'run', side_effect=timed_out):
                self.assertEqual(self.op('services')['error'], error)
                self.assertEqual(len(failed), 1)
                REMOTE.time.sleep.assert_not_called()
                self.assertEqual(self.cmd.effects[before:], ['k3s-start'])
                self.assertTrue(self.cmd.fenced)
                self.assert_owned()

    def test_admission_response_must_keep_uid_and_replica_zero(self):
        self.acquire(fenced=True)
        original = self.cmd.run
        for field, value, error in [('uid', 'replacement', 'loginset_replaced'),
                                    ('replicas', 1, 'loginset_admission'),
                                    ('replicas', False, 'loginset_admission')]:
            observed = []
            def wrong_result(argv, **kwargs):
                response = original(argv, **kwargs)
                if '--dry-run=server' in argv:
                    observed.append(argv)
                    response = json.loads(response)
                    response['metadata' if field == 'uid' else 'spec'][field] = value
                    return json.dumps(response)
                return response
            before = len(self.cmd.effects)
            REMOTE.time.sleep.reset_mock()
            with self.subTest(field=field, value=value), mock.patch.object(REMOTE, 'run', side_effect=wrong_result):
                self.assertEqual(self.op('services')['error'], error)
                self.assertEqual(len(observed), 1)
                REMOTE.time.sleep.assert_not_called()
                self.assertEqual(self.cmd.effects[before:], ['k3s-start'])
                self.assertTrue(self.cmd.fenced)
                self.assert_owned()

    def test_actual_loginset_fence_failure_is_not_retried_after_admission_passes(self):
        self.acquire(fenced=True)
        original = self.cmd.run
        failed = []
        def failing_write(argv, **kwargs):
            if (argv[:len(REMOTE.KS) + 2] == REMOTE.KS + ['patch', 'loginset'] and
                    '--dry-run=server' not in argv):
                failed.append(argv)
                raise REMOTE.Refused('command_failed')
            return original(argv, **kwargs)
        with mock.patch.object(REMOTE, 'run', side_effect=failing_write):
            self.assertEqual(self.op('services')['error'], 'command_failed')
        self.assertEqual(len(failed), 1)
        REMOTE.time.sleep.assert_not_called()
        events = [item['event'] for item in REMOTE.load_json(REMOTE.BASE / self.req['id'] / 'journal.json')]
        self.assertIn('admission_ready', events)
        self.assertEqual(events[-1], 'loginset_fence_intent:disabled')
        self.assertTrue(self.cmd.fenced)
        self.assert_owned()

    def test_capture_failure_attempts_services_without_reopening(self):
        self.acquire(fenced=True)
        self.fake_capture(fail=True)
        self.assertFalse(self.op('capture')['ok'])
        self.assertIn('-STOP', self.cmd.effects)
        self.assertIn('-CONT', self.cmd.effects)
        self.assertTrue(self.cmd.k3s and self.cmd.fenced)
        self.assert_owned()
        self.assertFalse((REMOTE.BASE / self.req['id'] / 'capture.json').exists())

    def test_capture_manifest_requires_completed_proofs_and_stays_fenced(self):
        self.acquire(fenced=True)
        self.fake_capture()
        self.assertTrue(self.op('capture')['ok'])
        manifest = self.op('manifest')
        self.assertTrue(manifest['ok'], manifest)
        self.assertIn('home-proof/extracted.jsonl', {x['path'] for x in manifest['artifacts']})
        self.assertTrue(self.cmd.fenced)
        self.assert_owned()

    def test_backout_requires_explicit_ack_but_no_manifest(self):
        self.acquire(fenced=True)
        self.assertFalse(self.op('backout')['ok'])
        self.assertTrue(self.cmd.fenced)
        self.assertTrue(self.op('backout', abandon=True)['ok'])
        self.assertEqual(self.cmd.parts, self.req['original']['partitions'])
        self.assertEqual(self.cmd.sets, self.req['original']['loginsets'])
        self.assert_owned()
        self.assertTrue(self.op('release')['ok'])
        self.assertFalse(REMOTE.LEASE.exists())

    def test_partial_reopen_refences_after_lost_response(self):
        self.acquire(fenced=True)
        self.cmd.fail_reopen_once = True
        self.assertFalse(self.op('backout', abandon=True)['ok'])
        self.assertTrue(self.cmd.fenced)
        self.assert_owned()

    def test_replaced_loginset_uid_refuses_before_patches(self):
        self.acquire(fenced=True)
        self.cmd.sets['login']['uid'] = 'replacement'
        before = list(self.cmd.effects)
        self.assertFalse(self.op('backout', abandon=True)['ok'])
        self.assertEqual(self.cmd.effects, before)
        self.assert_owned()

    def test_exact_original_login_count_and_readiness_required(self):
        self.acquire()
        self.cmd.extra_pod = True
        self.assertFalse(self.op('verify_original')['ok'])
        self.cmd.extra_pod = False
        self.cmd.ready = False
        self.assertFalse(self.op('verify_original')['ok'])
        self.cmd.ready = True
        self.assertTrue(self.op('verify_original')['ok'])

    def test_missing_manifest_cannot_reopen(self):
        self.acquire(fenced=True)
        self.assertFalse(self.op('reopen')['ok'])
        self.assertTrue(self.cmd.fenced)
        self.assert_owned()

    def test_released_manifest_read_is_read_only_and_checks_corruption(self):
        self.acquire(fenced=True)
        self.fake_capture()
        self.assertTrue(self.op('capture')['ok'])
        manifest = self.op('manifest')
        self.assertTrue(self.op('reopen')['ok'])
        self.assertTrue(self.op('release')['ok'])
        effects = list(self.cmd.effects)
        path = REMOTE.BASE / self.req['id'] / 'manifest.json'
        before = path.read_bytes()
        self.assertEqual(self.op('manifest_read'), manifest)
        self.assertEqual(path.read_bytes(), before)
        (REMOTE.BASE / self.req['id'] / 'home.tar').write_bytes(b'corrupt')
        self.assertFalse(self.op('manifest_read')['ok'])
        self.assertEqual(self.cmd.effects, effects)
        self.assertFalse(REMOTE.LEASE.exists())

    def test_real_control_archive_structure_and_token_hashes(self):
        d = self.root / 'control-proof'
        d.mkdir(mode=0o700)
        state = self.root / 'state'
        state.mkdir(mode=0o700)
        first, second = state / 'token', state / 'agent-token'
        first.write_bytes(b'fixture token alpha')
        second.write_bytes(b'fixture token beta')
        request = dict(self.req, original={'partitions': self.cmd.parts, 'loginsets': self.cmd.sets})
        with mock.patch.object(REMOTE, 'CONTROL', (str(state),)), mock.patch.object(REMOTE, 'TOKENS', (str(first), str(second))):
            REMOTE.control_archive(d, request)
        with tarfile.open(d / 'control.tgz') as result:
            record = result.extractfile('prace-backup/token-sha256.txt').read().decode()
            self.assertIn(hashlib.sha256(first.read_bytes()).hexdigest(), record)
            self.assertIn(hashlib.sha256(second.read_bytes()).hexdigest(), record)
            self.assertIn('home=1', result.extractfile('prace-backup/maintenance-window.txt').read().decode())
            self.assertEqual(result.extractfile('prace-backup/slurm_acct_db.sql').read(), b'-- private fixture database dump\n')
        self.assertFalse((d / 'slurm_acct_db.sql').exists())

    def test_workstation_driver_requests_use_actual_shim(self):
        self.fake_capture()
        operations = []
        class Transport:
            def call(inner, request):
                operations.append(request['op'])
                return REMOTE.handle(request)
            def copy(inner, run_id, name, destination):
                self.assertTrue(self.cmd.fenced)
                shutil.copyfile(REMOTE.BASE / run_id / name, destination)
        run = DRIVER.Run.create(self.root / 'workstation', Transport(), 'pre-w1', 'a' * 40,
                                {'fixture': 'b' * 64}, reserve=0)
        run.attest_no_admin_writers = True
        run.start()
        self.assertTrue(run.state['accepted'])
        self.assertEqual(run.state['phase'], 'complete')
        self.assertFalse(REMOTE.LEASE.exists())
        self.assertEqual(operations[-2:], ['reopen', 'release'])
        self.assertEqual(self.cmd.parts, run.state['original']['partitions'])

    def test_driver_settles_lost_release_reply_with_actual_read_only_shim(self):
        self.fake_capture()
        operations = []
        class Transport:
            def call(inner, request):
                operations.append(request['op'])
                result = REMOTE.handle(request)
                if request['op'] == 'release' and result['ok']:
                    raise DRIVER.CaptureError('lost response after release effect')
                return result
            def copy(inner, run_id, name, destination):
                self.assertTrue(self.cmd.fenced)
                shutil.copyfile(REMOTE.BASE / run_id / name, destination)
        run = DRIVER.Run.create(self.root / 'lost-reply', Transport(), 'pre-w1', 'a' * 40,
                                {'fixture': 'b' * 64}, reserve=0)
        run.attest_no_admin_writers = True
        with self.assertRaises(DRIVER.CaptureError):
            run.start()
        self.assertFalse(run.state['accepted'])
        self.assertFalse(REMOTE.LEASE.exists())
        effects = list(self.cmd.effects)
        run.complete()
        self.assertTrue(run.state['accepted'])
        self.assertEqual(operations[-3:], ['lease_check', 'manifest_read', 'verify_original'])
        self.assertEqual(self.cmd.effects, effects)


    def test_queue_and_failed_query_refuse_inspection_before_changes(self):
        for queue, error in [('42\n', False), ('', True)]:
            self.cmd.queue, self.cmd.queue_error = queue, error
            result = self.op('inspect')
            self.assertFalse(result['ok'])
            self.assertFalse(REMOTE.LEASE.exists())
            self.assertFalse(self.cmd.effects)

    def test_queue_arrives_before_acquire_refuses_before_lease(self):
        info = self.op('inspect')
        self.req.update(identity=info['identity'], original=info['original'])
        self.cmd.queue = '42\n'
        result = self.op('acquire')
        self.assertEqual(result['error'], 'queue_not_empty')
        self.assertFalse(REMOTE.LEASE.exists())
        self.assertFalse(self.cmd.effects)

    def test_queue_after_acquire_blocks_capture_but_backout_works(self):
        self.acquire()
        self.cmd.queue = '42\n'
        self.assertTrue(self.op('fence')['ok'])
        self.fake_capture()
        self.assertEqual(self.op('capture')['error'], 'queue_not_empty')
        self.assertNotIn('-STOP', self.cmd.effects)
        self.assertTrue(self.op('services')['ok'])
        self.assertTrue(self.cmd.fenced)
        self.assertTrue(self.op('backout', abandon=True)['ok'])
        self.assertTrue(self.op('release')['ok'])
        self.assertEqual(self.cmd.parts, self.req['original']['partitions'])

    def test_remote_lock_blocks_recovery_during_capture(self):
        self.acquire(fenced=True)
        self.fake_capture()
        entered, resume = threading.Event(), threading.Event()
        inner = REMOTE.METADATA_HELPER.create_verified_archive
        def paused(*args, **kwargs):
            result = inner(*args, **kwargs)
            entered.set()
            if not resume.wait(5):
                raise AssertionError('fixture timed out')
            return result
        REMOTE.METADATA_HELPER.create_verified_archive = paused
        result = {}
        thread = threading.Thread(target=lambda: result.update(self.op('capture')))
        thread.start()
        try:
            self.assertTrue(entered.wait(5))
            for operation in ('services', 'backout', 'reopen', 'release'):
                blocked = self.op(operation, abandon=True)
                self.assertEqual(blocked['error'], 'operation_busy')
            self.assertEqual(self.cmd.state, 'T')
            self.assertFalse(self.cmd.k3s)
        finally:
            resume.set()
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertTrue(result['ok'], result)
        self.assertTrue(self.op('services')['ok'])

    def test_inherited_lock_survives_parent_descriptor_close(self):
        self.acquire()
        child = None
        try:
            with REMOTE.operation_lock(dict(self.req, op='services')):
                fd = REMOTE.OPERATION_LOCK_FD
                code = 'import os,sys,time; os.fstat(int(sys.argv[1])); print("ready",flush=True); time.sleep(5)'
                child = subprocess.Popen([sys.executable, '-c', code, str(fd)],
                    pass_fds=(fd,), stdout=subprocess.PIPE, text=True)
                self.assertEqual(child.stdout.readline().strip(), 'ready')
            self.assertEqual(self.op('services')['error'], 'operation_busy')
        finally:
            if child is not None:
                child.kill(); child.wait(timeout=5); child.stdout.close()
        self.assertTrue(self.op('services')['ok'])

    def test_lock_file_symlink_refused(self):
        self.acquire()
        lock = REMOTE.BASE / ('.operation-' + self.req['id'] + '.lock')
        lock.unlink()
        target = self.root / 'sentinel'
        target.write_text('unchanged')
        lock.symlink_to(target)
        before = list(self.cmd.effects)
        self.assertFalse(self.op('services')['ok'])
        self.assertEqual(self.cmd.effects, before)
        self.assertEqual(target.read_text(), 'unchanged')

    def test_capture_and_recovery_errors_both_retained(self):
        self.acquire(fenced=True)
        self.fake_capture(fail=True)
        with mock.patch.object(REMOTE, 'services', side_effect=REMOTE.Refused('api_unready')):
            result = self.op('capture')
        self.assertEqual(result['error'], 'service_recovery_required')
        self.assertEqual(result['errors'], [
            {'operation': 'capture', 'error': 'remote_operation_failed'},
            {'operation': 'services', 'error': 'api_unready'}])
        self.assertRegex(result['operation_id'], r'^[0-9a-f]{32}$')
        self.assertTrue(self.cmd.fenced)

    def test_closing_status_requires_actual_completed_reopen(self):
        self.acquire(fenced=True)
        self.assertEqual(self.op('closing_status'), {'ok': True, 'closing': None, 'reopened': False})
        self.cmd.fail_reopen_once = True
        self.assertFalse(self.op('backout', abandon=True)['ok'])
        self.assertEqual(self.op('closing_status'), {'ok': True, 'closing': 'aborted', 'reopened': False})
        self.assertTrue(self.op('backout', abandon=True)['ok'])
        self.cmd.queue = 'new-job\n'
        self.assertEqual(self.op('closing_status'), {'ok': True, 'closing': 'aborted', 'reopened': True})
        self.cmd.sets['login']['replicas'] = 0
        self.assertFalse(self.op('closing_status')['ok'])

    def test_completed_reopen_lost_reply_retries_without_refence(self):
        for fault_op, fault_when in [('reopen', 'after'), ('release', 'before')]:
            with self.subTest(operation=fault_op):
                # Use an independent fixture instance for each lifecycle.
                child = RemoteTests('test_root_guard_remains_enforced')
                child.setUp()
                try:
                    child.fake_capture()
                    faulted = False
                    class Transport:
                        def call(inner, request):
                            nonlocal faulted
                            if request['op'] == fault_op and not faulted and fault_when == 'before':
                                faulted = True; child.cmd.queue = 'new-job\n'
                                raise DRIVER.CaptureError('fixture dropped request')
                            result = REMOTE.handle(request)
                            if request['op'] == fault_op and result['ok'] and not faulted and fault_when == 'after':
                                faulted = True; child.cmd.queue = 'new-job\n'
                                raise DRIVER.CaptureError('fixture dropped reply')
                            return result
                        def copy(inner, run_id, name, destination):
                            shutil.copyfile(REMOTE.BASE / run_id / name, destination)
                    run = DRIVER.Run.create(child.root / 'retry', Transport(), 'pre-w1',
                        'a' * 40, {'fixture': 'b' * 64}, reserve=0)
                    run.attest_no_admin_writers = True
                    with self.assertRaises(DRIVER.CaptureError): run.start()
                    effects = list(child.cmd.effects)
                    run.complete()
                    self.assertTrue(run.state['accepted'])
                    self.assertEqual(child.cmd.effects, effects)
                    self.assertFalse(REMOTE.LEASE.exists())
                finally:
                    child.doCleanups()



    def test_complete_scope_refused_during_inspect_before_lease(self):
        source = self.root / 'data'
        source.mkdir()
        (source / 'file').write_text('fixture')
        with mock.patch.object(REMOTE, 'preflight', REAL_PREFLIGHT), \
                mock.patch.object(REMOTE, 'STAGES', {'pre-w1': [str(source)]}), \
                mock.patch.object(REMOTE, 'METADATA_HELPER', ARCHIVE), \
                mock.patch.object(REMOTE.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=100 * REMOTE.GIB)):
            # Ordinary absolute and parent-relative links are inert saved data.
            (source / 'venv-python').symlink_to('/usr/bin/python3')
            (source / 'node-bin').symlink_to('../package/cli.js')
            self.assertTrue(self.op('inspect')['ok'])
            os.mkfifo(source / 'socket-like-special')
            self.assertEqual(self.op('inspect')['error'], 'data_scope_invalid')
            (source / 'socket-like-special').unlink()
            os.link(source / 'file', self.root / 'outside-hardlink')
            self.assertEqual(self.op('inspect')['error'], 'data_scope_invalid')
        self.assertFalse(self.cmd.effects)
        self.assertFalse(REMOTE.LEASE.exists())

    def test_operation_deadline_reports_code_and_releases_own_lock(self):
        self.acquire(fenced=True)
        original = self.cmd.run
        def slow_command(argv, **kwargs):
            if argv == ['systemctl', 'start', 'k3s']:
                threading.Event().wait(1)
            return original(argv, **kwargs)
        with mock.patch.object(REMOTE, 'RPC_TIMEOUTS', {'default': 0.03}), \
                mock.patch.object(REMOTE, 'run', side_effect=slow_command):
            response = self.op('services')
        self.assertEqual(response['error'], 'operation_timeout')
        self.assertTrue(self.op('services')['ok'])
        self.assertTrue(self.cmd.fenced)



    def test_readyz_retry_must_not_swallow_whole_operation_timeout(self):
        self.acquire(fenced=True)
        original = self.cmd.run
        def slow_readyz(argv, **kwargs):
            if argv == REMOTE.K + ['get', '--raw', '/readyz']:
                threading.Event().wait(1)
            return original(argv, **kwargs)
        with mock.patch.object(REMOTE, 'RPC_TIMEOUTS', {'default': 0.03}), \
                mock.patch.object(REMOTE, 'run', side_effect=slow_readyz):
            response = self.op('services')
        self.assertEqual(response['error'], 'operation_timeout')
        self.assertTrue(self.cmd.fenced)

    def test_capture_recovery_grace_timeout_is_not_swallowed(self):
        self.acquire(fenced=True)
        self.fake_capture()
        original = self.cmd.run
        def slow_readyz(argv, **kwargs):
            if argv == REMOTE.K + ['get', '--raw', '/readyz']:
                threading.Event().wait(1)
            return original(argv, **kwargs)
        with mock.patch.object(REMOTE, 'RECOVERY_GRACE_SECONDS', 0.03), \
                mock.patch.object(REMOTE, 'run', side_effect=slow_readyz):
            response = self.op('capture')
        self.assertEqual(response['error'], 'service_recovery_required')
        self.assertEqual(response['errors'], [{'operation': 'services', 'error': 'operation_timeout'}])
        self.assertTrue(self.cmd.fenced)
        self.assert_owned()

    def test_emergency_refence_has_its_own_deadline(self):
        self.acquire(fenced=True)
        self.cmd.fail_reopen_once = True
        with mock.patch.object(REMOTE, 'REFENCE_GRACE_SECONDS', 0.03), \
                mock.patch.object(REMOTE, 'fence', side_effect=lambda request: threading.Event().wait(1)):
            started = __import__('time').monotonic()
            response = self.op('backout', abandon=True)
            elapsed = __import__('time').monotonic() - started
        self.assertEqual(response['error'], 'reopen_failed_refence_required')
        self.assertLess(elapsed, 0.8)
        self.assert_owned()
        closing = REMOTE.load_json(REMOTE.BASE / self.req['id'] / 'closing.json')
        self.assertFalse(closing['reopened'])


if __name__ == '__main__':
    unittest.main(verbosity=2)

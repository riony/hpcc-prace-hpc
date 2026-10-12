#!/usr/bin/env python3
"""Hermetic adapter/receipt tests. No credentials, network, VM or containers."""
import contextlib
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


def load(name, filename=None):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename or name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


D = load('driver', 'storage-acceptance.py')
R = load('prace_storage_remote')
T = load('core_tests', 'test-prace-storage-acceptance.py')
R.C, R.A = D.C, D.A
R.U = D.module('prace_worker_underlay')


def window():
    original = {'partitions': {'cpu': 'UP'}, 'loginsets': {'slurm-login-prace': {'uid': 'login-uid', 'replicas': 1}}}
    return {'schema': 2, 'id': 'a' * 16, 'label': 'storage-basic', 'login': D.LOGIN,
            'phase': 'closed', 'fence_intent': {'active': True}, 'original': original,
            'declared_partitions': {}}


def identities():
    return {host: {'hostname': host, 'chassis_serial': serial, 'machine_id': 'b' * 32,
                   'boot_id': '11111111-2222-3333-4444-555555555555'} for host, serial in D.SERIALS.items()}


class FakeTransport:
    """All five hosts are a protocol model; no SSH subclass or fallback."""
    def __init__(self, root):
        self.root, self.model = root, T.Window()
        self.model.run = type('Ledger', (), {'file': root / 'run' / 'acceptance.json'})()
        self.hashes = {'synthetic': 'source'}
        self.calls = []
        self.lock_held = False
        self.on_call = None

    @contextlib.contextmanager
    def locked(self, lease_id):
        self.lock_held = True
        try:
            yield
        finally:
            self.lock_held = False

    def call(self, request):
        assert self.lock_held
        self.calls.append(copy.deepcopy(request))
        if self.on_call:
            result = self.on_call(request)
            if result is not None:
                return result
        op, host = request['operation'], request['host']
        if op == 'guard':
            return self.model.guard(request['run_id'], {})
        if op == 'observe':
            result = T.observation(host)
            result.update(identities()[host])
            return result
        if op in ('cleanup_denials', 'quota_cleanup_denial', 'status'):
            return {'clean': True, 'verified': True} if op in ('cleanup_denials', 'quota_cleanup_denial') else {'clean': True}
        if op == 'verify_fixture':
            return {'verified': True}
        return self.model.call(host, op, request)


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='prace-storage-adapter-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name, value in (('window.json', window()), ('identities.json', identities())):
            path = self.root / name
            path.write_text(json.dumps(value))
            path.chmod(0o600)
        self.transport = FakeTransport(self.root)
        self.args = ['--fleet', '--lease-id', 'a' * 16, '--window', str(self.root / 'window.json'),
                     '--identities', str(self.root / 'identities.json'), '--run-dir', str(self.root / 'run'),
                     '--attest-no-admin-writers']

    def invoke(self, args=None):
        return D.main(self.args if args is None else args, transport_factory=lambda: self.transport)

    def test_basic_fleet_flow_models_all_projects_and_explicit_pending_coverage(self):
        result = self.invoke()
        self.assertEqual(result['basic_host_functional'], 'PASS')
        self.assertEqual(result['quota'], 'policy/readback only')
        self.assertIn('underlying-directory mount guard', result['pending'])
        calls = self.transport.calls
        self.assertFalse(any(row['operation'].startswith(('exhaust', 'prepare', 'release', 'reopen')) for row in calls))
        self.assertEqual({row['project'] for row in calls if row['operation'] == 'create_project_fixture'}, set(D.A.PROJECTS))
        self.assertEqual({row['host'] for row in calls if row['operation'] == 'append_fixture'}, set(D.TARGETS))
        state = json.loads((self.root / 'run' / 'acceptance.json').read_text())
        self.assertTrue(state['remote_cleanup_verified'])
        self.assertTrue(all(row['state'] == 'clean' for row in state['cleanup']))

    def test_no_default_or_implicit_fleet_mode(self):
        with self.assertRaises(SystemExit):
            self.invoke(['--run-dir', str(self.root / 'run')])
        with patch.object(D, 'SSH', side_effect=AssertionError('network')):
            result = self.invoke(['--bench', '--run-dir', str(self.root / 'bench')])
        self.assertFalse(result['fleet_qualified'])
        self.assertFalse(self.transport.calls)
        self.assertEqual(list((self.root / 'bench').iterdir()), [])

    def test_unarmed_open_foreign_or_nonprivate_inputs_refuse_before_transport(self):
        for field, value in (('phase', 'opening'), ('id', 'c' * 16), ('label', 'shell;bad')):
            data = window()
            data[field] = value
            (self.root / 'window.json').write_text(json.dumps(data))
            with patch.object(D, 'SSH', side_effect=AssertionError('network')):
                with self.assertRaises(D.A.Refused):
                    self.invoke()
        (self.root / 'window.json').write_text(json.dumps(window()))
        with self.assertRaisesRegex(D.A.Refused, 'fleet_window_required'):
            self.invoke(self.args[:-1])
        (self.root / 'identities.json').chmod(0o644)
        with self.assertRaisesRegex(D.A.Refused, 'private_input'):
            self.invoke()
        self.assertFalse(self.transport.calls)

    def test_window_change_mid_run_stops_before_next_mutation(self):
        def change(row):
            if row['operation'] == 'create_project_fixture':
                data = window()
                data['phase'] = 'opening'
                (self.root / 'window.json').write_text(json.dumps(data))
        self.transport.on_call = change
        with self.assertRaises(D.A.Refused):
            self.invoke()
        self.assertEqual(sum(row['operation'] == 'create_project_fixture' for row in self.transport.calls), 1)
        self.assertFalse(any(row['operation'] == 'append_fixture' for row in self.transport.calls))
        state = json.loads((self.root / 'run' / 'acceptance.json').read_text())
        self.assertEqual(state['phase'], 'failed_explicit_cleanup_required')

    def test_bad_run_target_contacts_no_transport(self):
        for target in ('relative-run', str(self.root / 'missing-parent' / 'run'), str(self.root)):
            args = list(self.args)
            args[args.index('--run-dir') + 1] = target
            factory = unittest.mock.Mock(side_effect=AssertionError('transport must not start'))
            with self.subTest(target=target), self.assertRaises(D.A.Refused):
                D.main(args, transport_factory=factory)
            factory.assert_not_called()
        args = self.args + ['cleanup']
        factory = unittest.mock.Mock(side_effect=AssertionError('transport must not start'))
        with self.assertRaises(FileNotFoundError):
            D.main(args, transport_factory=factory)
        factory.assert_not_called()

    def test_rpc_failure_retains_ledger_and_cleanup_requires_same_sources(self):
        self.transport.model.fail = 'create_project_fixture'
        with self.assertRaises(RuntimeError):
            self.invoke()
        state = json.loads((self.root / 'run' / 'acceptance.json').read_text())
        self.assertEqual(state['cleanup'][0]['state'], 'intent')
        self.transport.hashes = {'changed': 'source'}
        with self.assertRaisesRegex(D.A.Refused, 'adapter_source_or_window_changed'):
            self.invoke(self.args + ['cleanup'])

    def test_remote_unclean_status_cannot_return_basic_pass(self):
        self.transport.on_call = lambda row: {'clean': False} if row['operation'] == 'status' else None
        with self.assertRaisesRegex(D.A.Refused, 'remote_cleanup_pending'):
            self.invoke()
        state = json.loads((self.root / 'run' / 'acceptance.json').read_text())
        self.assertEqual(state['phase'], 'failed_explicit_cleanup_required')
        self.assertNotIn('remote_cleanup_verified', state)

    def test_transport_is_fixed_and_strict_and_does_not_select_credentials(self):
        for host in D.TARGETS:
            argv = D.ssh_argv(host)
            self.assertIn('BatchMode=yes', argv)
            self.assertIn('StrictHostKeyChecking=yes', argv)
            self.assertIn('ConnectTimeout=10', argv)
            self.assertNotIn('-i', argv)
            self.assertIn('root@' + D.TARGETS[host], argv)
        with self.assertRaises(D.A.Refused):
            D.ssh_argv('other-host')

    def test_non_pq_advisory_is_suppressed_on_both_hops_only(self):
        for host in D.TARGETS:
            argv = D.ssh_argv(host)
            self.assertIn('IgnoreUnknown=WarnWeakCrypto', argv)
            self.assertIn('WarnWeakCrypto=no-pq-kex', argv)
            self.assertLess(argv.index('IgnoreUnknown=WarnWeakCrypto'), argv.index('WarnWeakCrypto=no-pq-kex'))
            self.assertNotIn('-q', argv)
            self.assertFalse(any('LogLevel=' in value or 'KexAlgorithms=' in value for value in argv))
            if host != D.A.SERVER:
                proxy = next(value for value in argv if value.startswith('ProxyCommand='))
                self.assertIn('-o IgnoreUnknown=WarnWeakCrypto -o WarnWeakCrypto=no-pq-kex ', proxy)
                self.assertIn('StrictHostKeyChecking=yes', proxy)

    def test_unexpected_stderr_with_successful_rpc_still_refuses(self):
        transport = D.SSH()
        transport.lock = type('Lock', (), {'poll': lambda self: None})()
        class Child:
            returncode = 0
            def communicate(self, script, timeout):
                return '{"ok":true,"result":{"owned":true}}', 'unexpected diagnostic'
        with patch.object(D.subprocess, 'Popen', return_value=Child()) as process:
            with self.assertRaisesRegex(D.A.Refused, 'transport_failed'):
                transport.call({'host': D.A.SERVER, 'operation': 'guard'})
        process.assert_called_once()

    def test_transport_payload_compiles_and_timeout_retains_failure(self):
        transport = D.SSH()
        transport.lock = type('Lock', (), {'poll': lambda self: None})()
        request = {'host': D.A.SERVER, 'operation': 'guard', 'run_id': 'a' * 32,
                   'identity': identities()[D.A.SERVER], 'window': window()}
        sent = []
        class Child:
            pid, returncode = 12345, 0
            def communicate(self, script=None, timeout=None):
                sent.append((script, timeout))
                if script:
                    compile(script, '<bundled-rpc>', 'exec')
                return '{"ok":true,"result":{"owned":true}}', ''
        with patch.object(D.subprocess, 'Popen', return_value=Child()):
            self.assertEqual(transport.call(request), {'owned': True})
        self.assertEqual(sent[0][1], 105)
        class Timeout(Child):
            def communicate(self, script=None, timeout=None):
                raise subprocess.TimeoutExpired('ssh', timeout)
        with patch.object(D.subprocess, 'Popen', return_value=Timeout()), patch.object(D.os, 'killpg') as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                transport.call(request)
            kill.assert_called_once()
        transport.lock = None
        with self.assertRaisesRegex(D.A.Refused, 'window_lock_lost'):
            transport.call(request)

    def test_rpc_starts_are_paced_with_monotonic_time(self):
        transport = D.SSH()
        transport.lock = type('Lock', (), {'poll': lambda self: None})()
        now, starts, sleeps = [0.0], [], []
        request = {'host': D.A.SERVER, 'operation': 'guard'}
        class Child:
            returncode = 0
            def communicate(self, script, timeout):
                return '{"ok":true,"result":{}}', ''
        def start(*args, **kwargs):
            starts.append(now[0])
            return Child()
        def sleep(seconds):
            sleeps.append(seconds)
            now[0] += seconds
        with patch.object(D.time, 'monotonic', side_effect=lambda: now[0]), \
                patch.object(D.time, 'sleep', side_effect=sleep), \
                patch.object(D.subprocess, 'Popen', side_effect=start):
            transport.call(request)
            now[0] = 1.0
            transport.call(request)
            now[0] = 9.0
            transport.call(request)
        self.assertEqual(starts, [0.0, 6.0, 12.0])
        self.assertEqual(sleeps, [5.0, 3.0])

    def test_lost_lock_during_pacing_refuses_before_new_ssh(self):
        transport = D.SSH()
        held = [True]
        transport.lock = type('Lock', (), {'poll': lambda self: None if held[0] else 0})()
        transport.last_rpc_started = 0.0
        def lose_lock(seconds):
            held[0] = False
        with patch.object(D.time, 'monotonic', return_value=1.0), \
                patch.object(D.time, 'sleep', side_effect=lose_lock), \
                patch.object(D.subprocess, 'Popen') as process:
            with self.assertRaisesRegex(D.A.Refused, 'window_lock_lost'):
                transport.call({'host': D.A.SERVER, 'operation': 'guard'})
        process.assert_not_called()

    def test_changed_source_during_pacing_refuses_before_new_ssh(self):
        transport = D.SSH()
        transport.lock = type('Lock', (), {'poll': lambda self: None})()
        transport.last_rpc_started = 0.0
        with patch.object(transport, 'unchanged', side_effect=[None, D.A.Refused('source_changed')]), \
                patch.object(D.time, 'monotonic', return_value=1.0), \
                patch.object(D.time, 'sleep'), patch.object(D.subprocess, 'Popen') as process:
            with self.assertRaisesRegex(D.A.Refused, 'source_changed'):
                transport.call({'host': D.A.SERVER, 'operation': 'guard'})
        process.assert_not_called()

    def test_transport_refusal_does_not_retry_and_action_fits_pacing(self):
        transport = D.SSH()
        transport.lock = type('Lock', (), {'poll': lambda self: None})()
        class RefusedChild:
            returncode = 255
            def communicate(self, script, timeout):
                return '', 'connection reset'
        with patch.object(D.subprocess, 'Popen', return_value=RefusedChild()) as process:
            with self.assertRaisesRegex(D.A.Refused, 'transport_failed'):
                transport.call({'host': D.A.SERVER, 'operation': 'underlay_prepare'})
        process.assert_called_once()
        self.invoke()
        self.assertLess(len(self.transport.calls) * D.RPC_MIN_INTERVAL, D.ACTION_SECONDS)
        self.assertGreater(D.LOCK_SECONDS, D.ACTION_SECONDS)

    def test_underlay_prepare_requires_explicit_safe_id_before_transport(self):
        for value in (None, '../archive', 'UPPER', 'short'):
            args = self.args + ['underlay-prepare']
            if value is not None:
                args += ['--preservation-id', value]
            factory = unittest.mock.Mock(side_effect=AssertionError('transport must not start'))
            with self.subTest(value=value), self.assertRaisesRegex(D.A.Refused, 'preservation_id'):
                D.main(args, transport_factory=factory)
            factory.assert_not_called()

    def underlay_response(self, request):
        if not request['operation'].startswith('underlay_'):
            return None
        state = json.loads((self.root / 'run' / 'acceptance.json').read_text())
        self.assertEqual(state['underlay'][-1]['state'], 'intent')
        self.assertEqual(state['underlay'][-1]['host'], request['host'])
        mode = request['operation'].split('_')[1]
        return {'mode': mode, 'parent_namespace_unchanged': True, 'parent_mounts_unchanged': True,
                'paths': {path: {'guarded': True, 'changed': mode == 'prepare'} for path in D.A.SHARES}}

    def test_underlay_actions_cover_every_worker_after_durable_intent(self):
        self.transport.on_call = self.underlay_response
        result = self.invoke(self.args + ['underlay-prepare', '--preservation-id', 'prepare-20260930'])
        self.assertEqual(result['worker_underlay'], 'PASS')
        calls = [row for row in self.transport.calls if row['operation'] == 'underlay_prepare']
        self.assertEqual([row['host'] for row in calls], list(D.A.CLIENTS))
        self.assertTrue(all(row['preservation_id'] == 'prepare-20260930' for row in calls))
        state = json.loads((self.root / 'run' / 'acceptance.json').read_text())
        self.assertTrue(all(row['state'] == 'verified' for row in state['underlay']))
        self.assertTrue(state['remote_cleanup_verified'])

    def test_underlay_lost_response_is_not_cleaned_or_automatically_retried(self):
        def fail(row):
            if row['operation'] == 'underlay_prepare':
                self.underlay_response(row)
                raise RuntimeError('lost reply after preparation')
        self.transport.on_call = fail
        with self.assertRaises(RuntimeError):
            self.invoke(self.args + ['underlay-prepare', '--preservation-id', 'prepare-20260930'])
        state = json.loads((self.root / 'run' / 'acceptance.json').read_text())
        self.assertEqual(state['underlay'][0]['state'], 'intent')
        with self.assertRaisesRegex(D.A.Refused, 'underlay_requires_operator_inspection'):
            self.invoke(self.args + ['cleanup'])
        self.assertEqual(len([row for row in self.transport.calls if row['operation'] == 'underlay_prepare']), 1)

    def test_server_fence_is_reobserved_after_worker_response(self):
        def changed(row):
            value = self.underlay_response(row)
            if value is not None:
                self.transport.model.ready = False
            return value
        self.transport.on_call = changed
        with self.assertRaisesRegex(D.A.Refused, 'window_not_ready'):
            self.invoke(self.args + ['underlay-check'])
        state = json.loads((self.root / 'run' / 'acceptance.json').read_text())
        self.assertEqual(state['underlay'][0]['state'], 'intent')
        self.assertNotIn('remote_cleanup_verified', state)

    def test_underlay_rpc_budget_contains_namespace_budget(self):
        transport = D.SSH()
        transport.lock = type('Lock', (), {'poll': lambda self: None})()
        sent = []
        class Child:
            pid, returncode = 12345, 0
            def communicate(self, script=None, timeout=None):
                sent.append((script, timeout))
                compile(script, '<underlay-rpc>', 'exec')
                return '{"ok":true,"result":{}}', ''
        request = {'host': D.A.CLIENTS[0], 'operation': 'underlay_check', 'run_id': 'a' * 32,
                   'identity': identities()[D.A.CLIENTS[0]], 'window': window()}
        with patch.object(D.subprocess, 'Popen', return_value=Child()):
            transport.call(request)
        self.assertEqual(sent[0][1], 180)
        self.assertIn('with c.deadline(160)', sent[0][0])
        self.assertIn('underlay_helper_sha256', sent[0][0])
        self.assertIn('r.U=u', sent[0][0])


class RemoteTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='prace-storage-remote-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ledger = self.root / 'ledger'
        self.ledger.mkdir(mode=0o700)
        self.request = {'run_id': 'a' * 32, 'host': D.A.SERVER}
        self.patchers = [patch.object(R, 'fixture', side_effect=lambda run_id, kind: self.root / kind),
                         patch.object(R, 'as_user', side_effect=lambda user: contextlib.nullcontext())]
        for item in self.patchers:
            item.start()
            self.addCleanup(item.stop)

    def test_apps_fixture_is_actually_world_writable_and_owns_cleanup(self):
        result = R.create(self.ledger, self.request, 'apps', 'root', '6162', 0o777)
        self.assertEqual(stat.S_IMODE((self.root / 'apps').stat().st_mode), 0o777)
        self.assertEqual((self.root / 'apps' / 'data').read_bytes(), b'ab')
        self.assertEqual(result['receipt']['root']['inode'], (self.root / 'apps').stat().st_ino)
        R.cleanup(self.ledger, self.request, 'apps')
        self.assertFalse((self.root / 'apps').exists())

    def test_cleanup_syncs_deletion_before_clean_and_status_rechecks_absence(self):
        R.create(self.ledger, self.request, 'apps', 'root', '6162', 0o777)
        events = []
        original_save = R.save
        def saved(path, record):
            if record.get('state') == 'clean':
                self.assertIn(('sync', self.root), events)
                self.assertFalse((self.root / 'apps').exists())
            return original_save(path, record)
        with patch.object(R.C, 'syncdir', side_effect=lambda p: events.append(('sync', p))), patch.object(R, 'save', side_effect=saved):
            R.cleanup(self.ledger, self.request, 'apps')
        self.assertTrue(R.clean_receipts(self.ledger))
        (self.root / 'apps').mkdir()
        self.assertFalse(R.clean_receipts(self.ledger))

    def test_cleanup_retry_flushes_parent_after_previous_delete_succeeded(self):
        R.create(self.ledger, self.request, 'apps', 'root', None, 0o777)
        real_sync = R.C.syncdir
        def interrupted(path):
            if path == self.root:
                raise OSError('parent flush interrupted')
            real_sync(path)
        with patch.object(R.C, 'syncdir', side_effect=interrupted), self.assertRaises(OSError):
            R.cleanup(self.ledger, self.request, 'apps')
        self.assertFalse((self.root / 'apps').exists())
        events = []
        with patch.object(R.C, 'syncdir', side_effect=lambda p: events.append(p)):
            self.assertEqual(R.cleanup(self.ledger, self.request, 'apps'), {'clean': True, 'verified': True})
        self.assertIn(self.root, events)

    def test_denial_cleanup_retry_flushes_parent_after_previous_unlink(self):
        R.create(self.ledger, self.request, 'apps', 'root', None, 0o777)
        R.denial(self.ledger, self.request, 'apps', 'syn-probe')
        real_sync = R.C.syncdir
        def interrupted(path):
            if path == self.root / 'apps':
                raise OSError('denial parent flush interrupted')
            real_sync(path)
        with patch.object(R.C, 'syncdir', side_effect=interrupted), self.assertRaises(OSError):
            R.cleanup_denials(self.ledger, self.request, 'apps')
        self.assertFalse((self.root / 'apps' / ('denied-' + D.A.SERVER)).exists())
        events = []
        with patch.object(R.C, 'syncdir', side_effect=lambda p: events.append(p)):
            R.cleanup_denials(self.ledger, self.request, 'apps')
        self.assertIn(self.root / 'apps', events)

    def test_project_reads_and_absence_are_observed_as_project_user(self):
        path = self.root / 'proj-alpha'
        path.mkdir()
        (path / 'data').write_bytes(b'a')
        active = []
        @contextlib.contextmanager
        def user(name):
            active.append(name)
            try:
                yield
            finally:
                active.pop()
        real_resolve = Path.resolve
        def resolve(p, *args, **kwargs):
            if p == path and not active:
                raise PermissionError(errno.EACCES, 'squashed root cannot traverse')
            return real_resolve(p, *args, **kwargs)
        with patch.object(R, 'as_user', side_effect=user), patch.object(Path, 'resolve', new=resolve):
            value = R.read_or_append(dict(self.request, project='proj-alpha', user='syn-carol'))
        self.assertEqual(value['content_hex'], '61')
        receipt = self.ledger / 'denial-proj-alpha.json'
        R.save(receipt, {'state': 'clean', 'path': str(path / 'missing')})
        real_stat = Path.lstat
        def lstat(p):
            if p == path / 'missing':
                self.assertEqual(active, ['syn-alice'])
            return real_stat(p)
        with patch.object(R, 'as_user', side_effect=user), patch.object(Path, 'lstat', new=lstat):
            self.assertTrue(R.clean_receipts(self.ledger))

    @contextlib.contextmanager
    def handled(self, dispatch):
        base = self.root / 'remote-base'
        request = dict(self.request, operation='guard', window={'id': 'b' * 16}, identity={}, sources={})
        real_lock, real_uid = R.host_lock, os.geteuid()
        @contextlib.contextmanager
        def fixture_owner_lock(directory):
            with patch.object(R.os, 'geteuid', return_value=real_uid), real_lock(directory) as fd:
                yield fd
        with patch.object(R, 'BASE', base), patch.object(R.os, 'geteuid', return_value=0), \
                patch.object(R, 'identity'), patch.object(R, 'guard'), patch.object(R.C, 'private_dir'), \
                patch.object(R.C, 'load_json', side_effect=lambda p: json.loads(p.read_text())), \
                patch.object(R, 'host_lock', side_effect=fixture_owner_lock), \
                patch.object(R, 'dispatch', side_effect=dispatch):
            yield base, request

    def test_surviving_child_blocks_different_run_ids_on_same_host(self):
        children = []
        def spawn(directory, request):
            child = subprocess.Popen([sys.executable, '-c', 'import sys;print("ready",flush=True);sys.stdin.read()'],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, pass_fds=(R.FD,))
            children.append(child)
            self.assertEqual(child.stdout.readline(), 'ready\n')
            return {}
        try:
            with self.handled(spawn) as (base, request):
                R.handle(request)
                with self.assertRaises(BlockingIOError):
                    R.handle(dict(request, run_id='c' * 32))
                self.assertFalse((base / ('b' * 16 + '-' + 'c' * 32)).exists())
        finally:
            for child in children:
                child.communicate(timeout=5)

    def test_unresolved_prior_receipt_blocks_a_fresh_run(self):
        with self.handled(lambda *_: {}) as (base, request):
            R.handle(request)
            directory = base / ('b' * 16 + '-' + 'a' * 32)
            R.C.write_json(directory / 'fixture-apps.json', {'state': 'intent', 'path': str(self.root / 'apps')})
            with self.assertRaisesRegex(R.C.Refused, 'prior_run_cleanup_pending'):
                R.handle(dict(request, run_id='c' * 32))

    def test_remote_ledger_ancestry_is_synced_before_dispatch(self):
        events = []
        with self.handled(lambda directory, request: events.append(('dispatch', directory))) as (base, request):
            with patch.object(R.C, 'syncdir', side_effect=lambda p: events.append(('sync', p))):
                R.handle(request)
        dispatch_index = next(i for i, row in enumerate(events) if row[0] == 'dispatch')
        self.assertIn(('sync', base.parent), events[:dispatch_index])
        self.assertIn(('sync', base), events[:dispatch_index])

    def test_handle_does_not_extend_an_existing_rpc_deadline(self):
        with self.handled(lambda *_: time.sleep(0.12)) as (_, request):
            with self.assertRaisesRegex(R.C.Refused, 'operation_timeout'):
                with R.C.deadline(0.10):
                    time.sleep(0.04)
                    R.handle(request)

    def test_receipt_is_durable_before_creation_and_lost_reply_is_cleanupable(self):
        original = Path.mkdir
        def creation(path, *args, **kwargs):
            record = json.loads((self.ledger / 'fixture-apps.json').read_text())
            self.assertEqual(record['state'], 'intent')
            self.assertIsNone(record['root'])
            return original(path, *args, **kwargs)
        with patch.object(Path, 'mkdir', new=creation):
            R.create(self.ledger, self.request, 'apps', 'root', '6162', 0o777)
        # Caller received no receipt; durable host receipt is authoritative.
        self.assertEqual(R.cleanup(self.ledger, self.request, 'apps'), {'clean': True, 'verified': True})

    def test_unknown_create_and_added_entry_refuse_without_deleting(self):
        original = R.save
        calls = []
        def fail_after_mkdir(path, record):
            calls.append(copy.deepcopy(record))
            if record['root'] is not None:
                raise RuntimeError('receipt write failed')
            return original(path, record)
        with patch.object(R, 'save', side_effect=fail_after_mkdir):
            with self.assertRaises(RuntimeError):
                R.create(self.ledger, self.request, 'apps', 'root', None, 0o777)
        with self.assertRaisesRegex(D.C.Refused, 'fixture_unknown'):
            R.cleanup(self.ledger, self.request, 'apps')
        self.assertTrue((self.root / 'apps').exists())
        (self.root / 'apps').rmdir()
        (self.ledger / 'fixture-apps.json').unlink()
        R.create(self.ledger, self.request, 'apps', 'root', '61', 0o777)
        (self.root / 'apps' / 'unknown').touch()
        with self.assertRaisesRegex(D.C.Refused, 'fixture_unknown_entry'):
            R.cleanup(self.ledger, self.request, 'apps')
        self.assertTrue((self.root / 'apps' / 'data').exists())

    def test_replaced_inode_cannot_be_removed_and_partial_cleanup_resumes(self):
        R.create(self.ledger, self.request, 'apps', 'root', '61', 0o777)
        self.assertEqual(R.verify_fixture(self.ledger, self.request, 'apps'), {'verified': True})
        path = self.root / 'apps' / 'data'
        path.rename(self.root / 'original')
        path.write_bytes(b'a')
        with self.assertRaisesRegex(D.C.Refused, 'fixture_changed'):
            R.verify_fixture(self.ledger, self.request, 'apps')
        with self.assertRaisesRegex(D.C.Refused, 'fixture_changed'):
            R.cleanup(self.ledger, self.request, 'apps')
        path.unlink()
        self.assertEqual(R.cleanup(self.ledger, self.request, 'apps'), {'clean': True, 'verified': True})

    def test_unexpected_denial_success_is_owned_and_cleaned_before_parent(self):
        R.create(self.ledger, self.request, 'apps', 'root', '61', 0o777)
        self.assertIsNone(R.denial(self.ledger, self.request, 'apps', 'syn-probe'))
        with self.assertRaisesRegex(D.C.Refused, 'fixture_unknown_entry'):
            R.cleanup(self.ledger, self.request, 'apps')
        R.cleanup_denials(self.ledger, self.request, 'apps')
        R.cleanup(self.ledger, self.request, 'apps')
        self.assertFalse((self.root / 'apps').exists())

    def test_expected_squash_denial_does_not_require_client_stat_permission(self):
        (self.root / 'squash').mkdir()
        original = os.open
        def deny(path, flags, *args, **kwargs):
            if str(path).endswith('denied-' + D.A.SERVER):
                raise PermissionError(errno.EACCES, 'denied')
            return original(path, flags, *args, **kwargs)
        with patch.object(os, 'open', side_effect=deny):
            self.assertEqual(R.denial(self.ledger, self.request, 'squash', 'root'), errno.EACCES)
        self.assertEqual(R.cleanup_denials(self.ledger, self.request, 'squash'), {'clean': True, 'verified': True})

    def test_lease_and_shared_fence_marker_must_match_exactly(self):
        lease = self.root / 'lease'
        lease.mkdir(mode=0o700)
        holder = lease / 'holder'
        holder.write_text('holder=maint label=storage-basic id=' + 'a' * 16 + ' since=2026-09-30T00:00:00Z\n')
        holder.chmod(0o600)
        marker = {'schema': 2, 'lease_id': 'a' * 16, 'phase': 'closed', 'fence_active': True,
                  'original': window()['original'], 'declared_partitions': {}}
        D.C.write_json(lease / 'fence-intent.json', marker)
        with patch.object(R, 'LEASE', lease), patch.object(R.os, 'geteuid', return_value=os.getuid()), \
                patch.object(R.C, 'check_fence') as fence, patch.object(R.C, 'check_queue_empty'):
            # The real owner check is root-only; use a temporary regular-file
            # stat override for this hermetic non-root record fixture.
            original_lstat = Path.lstat
            def root_holder(path):
                info = original_lstat(path)
                if path == holder:
                    values = list(info)
                    values[4] = 0
                    return os.stat_result(values)
                return info
            with patch.object(Path, 'lstat', new=root_holder):
                R.guard(window())
                fence.assert_called_once()
                holder.write_text(holder.read_text() + ' id=' + 'a' * 16)
                with self.assertRaisesRegex(D.C.Refused, 'lease_record'):
                    R.guard(window())

    def test_command_zero_with_stderr_and_timeouts_refuse(self):
        class Child:
            pid, returncode = 12345, 0
            def communicate(self, timeout=None):
                return 'looks good', 'diagnostic'
        with patch.object(R.subprocess, 'Popen', return_value=Child()):
            with self.assertRaisesRegex(D.C.Refused, 'command_failed'):
                R.command(['never-executed'])
        class TimedOut(Child):
            def communicate(self, timeout=None):
                raise subprocess.TimeoutExpired('never-executed', timeout)
        with patch.object(R.subprocess, 'Popen', return_value=TimedOut()), patch.object(R.os, 'killpg') as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                R.command(['never-executed'])
            kill.assert_called_once()

    def test_actual_observation_parser_requires_exact_exports_and_quota_state(self):
        observed = T.observation(D.A.SERVER)
        mounts_config = [{'path': path, **value} for path, value in observed['storage_config'].items()]
        helper = b'reviewed helper fixture'
        import hashlib
        quota_hash = hashlib.sha256(helper).hexdigest()
        responses = {'exports': '\n'.join(path + '\n 10.90.10.0/25(' + ','.join(row['options']) + ')'
                                          for path, row in zip(D.A.SHARES, observed['exports'])), 'enforce': 'ON'}
        def cmd(argv, **kwargs):
            if argv[0] == 'exportfs':
                return responses['exports']
            if argv[0] == 'xfs_quota':
                kind = 'User' if argv[-1] == '/home' else 'Project'
                return kind + ' quota state on device\n  Accounting: ON\n  Enforcement: ' + responses['enforce'] + '\n'
            if argv == ['/usr/local/sbin/prace-quota-apply', '--check']:
                return 'quotas match the declaration\n'
            raise AssertionError(argv)
        def text(path, *args, **kwargs):
            if str(path) == '/etc/prace-storage/mounts.json':
                return json.dumps(mounts_config)
            if str(path) == '/etc/prace-storage/quotas.json':
                return json.dumps(observed['quota_declaration'])
            raise AssertionError(path)
        def object_id(path):
            return observed['project_roots'][path.name]
        space = type('Space', (), {'f_bavail': 100 * 1024 ** 3, 'f_frsize': 1})()
        with patch.object(R, 'identity', return_value=identities()[D.A.SERVER]), \
                patch.object(R, 'basic_boundary', return_value=(observed['mounts'], observed['accounts'])), \
                patch.object(R, 'object_id', side_effect=object_id), patch.object(R, 'acl', return_value=D.A.PROJECT_ACL), \
                patch.object(R, 'command', side_effect=cmd), patch.object(Path, 'read_text', new=text), \
                patch.object(Path, 'read_bytes', return_value=helper), patch.object(R.os, 'statvfs', return_value=space):
            value = R.observed(D.A.SERVER, identities()[D.A.SERVER], quota_hash)
            self.assertEqual(value['exports'], observed['exports'])
            responses['enforce'] = 'OFF'
            with self.assertRaisesRegex(D.A.Refused, 'quota_state'):
                R.observed(D.A.SERVER, identities()[D.A.SERVER], quota_hash)
            responses['enforce'] = 'ON'
            responses['exports'] += '\n/apps 10.90.10.0/25(ro,sync,secure,root_squash)'
            with self.assertRaisesRegex(D.A.Refused, 'export_membership'):
                R.observed(D.A.SERVER, identities()[D.A.SERVER], quota_hash)

    def test_missing_or_wrong_mount_refuses_before_fixture_mutation(self):
        row = T.observation(D.A.CLIENTS[0])
        row['mounts']['/home']['source'] = '/dev/root'
        with patch.object(R, 'mounts', return_value=row['mounts']), patch.object(R, 'accounts', return_value=row['accounts']), \
                patch.object(R, 'create') as create:
            with self.assertRaisesRegex(D.C.Refused, 'client_mount'):
                R.dispatch(self.ledger, dict(self.request, host=D.A.CLIENTS[0], operation='root_squash'))
            create.assert_not_called()

    def test_exact_host_identity_and_marker_drift_refuse(self):
        saved = identities()[D.A.SERVER]
        with patch.object(R.C, 'identity', return_value=dict(saved, boot_id='new-boot')):
            with self.assertRaisesRegex(D.C.Refused, 'identity_changed'):
                R.identity(saved)
        with patch.object(R, 'lease'), patch.object(R.C, 'load_json', return_value={'fence_active': False}), \
                patch.object(R.C, 'check_fence') as fence, patch.object(R.C, 'check_queue_empty'):
            with self.assertRaisesRegex(D.C.Refused, 'fence_intent_changed'):
                R.guard(window())
            fence.assert_not_called()

    def test_surviving_child_keeps_host_operation_lock_until_it_exits(self):
        child = None
        try:
            with R.host_lock(self.ledger) as fd:
                child = subprocess.Popen([sys.executable, '-c', 'import sys; sys.stdin.read()'],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         pass_fds=(fd,))
            with self.assertRaises(BlockingIOError):
                with R.host_lock(self.ledger):
                    self.fail('inherited lock was bypassed')
            child.communicate(input=b'', timeout=2)
            with R.host_lock(self.ledger):
                pass
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.communicate(timeout=2)

    def test_underlay_receipt_precedes_dispatch_and_interruption_blocks_status(self):
        request = dict(self.request, host=D.A.CLIENTS[0], operation='underlay_prepare', window=window(),
                       identity=identities()[D.A.CLIENTS[0]], preservation_id='prepare-20260930',
                       underlay_helper_sha256='c' * 64)
        def lost(*_, **kwargs):
            self.assertEqual(json.loads((self.ledger / 'underlay.json').read_text())['state'], 'intent')
            raise RuntimeError('interrupted child')
        with patch.object(R.U, 'verify_helper'), patch.object(R.U, 'run_guarded', side_effect=lost), \
                R.host_lock(self.ledger):
            with self.assertRaises(RuntimeError):
                R.worker_underlay(self.ledger, request)
            self.assertFalse(R.clean_receipts(self.ledger))
            with self.assertRaisesRegex(D.C.Refused, 'underlay_already_attempted'):
                R.worker_underlay(self.ledger, request)

    def test_underlay_helper_digest_failure_precedes_preparation_intent(self):
        request = dict(self.request, host=D.A.CLIENTS[0], operation='underlay_check', window=window(),
                       identity=identities()[D.A.CLIENTS[0]], preservation_id=None, underlay_helper_sha256='c' * 64)
        with patch.object(R.U, 'verify_helper', side_effect=R.U.Refused('helper_changed')), \
                patch.object(R.U, 'run_guarded') as run, R.host_lock(self.ledger):
            with self.assertRaisesRegex(R.U.Refused, 'helper_changed'):
                R.worker_underlay(self.ledger, request)
            run.assert_not_called()
        self.assertFalse((self.ledger / 'underlay.json').exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)

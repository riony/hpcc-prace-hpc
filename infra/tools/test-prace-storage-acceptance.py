#!/usr/bin/env python3
"""Hermetic functional-core tests and real bounded local filesystem fixtures."""
import copy
import errno
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


A = load('prace_storage_acceptance')
P = load('prace_storage_probe')


def home_declaration():
    # Expected inventory rendering, kept separate from the implementation's
    # comparison so changing the core's policy does not silently bless a drift.
    names = ['team-user01', 'team-user02', 'team-user03', 'team-user04', 'syn-alice', 'syn-bob',
             'syn-carol', 'syn-dave', 'syn-smoke', 'syn-tracer', 'syn-observer',
             'syn-probe', 'syn-nologin', 'agent-perm01',
             'agent-cleanup01', 'agent-resource01', 'agent-team01', 'agent-team02',
             'agent-team03', 'agent-spare01']
    ids = [20001, 20002, 20003, 20004, 30001, 30002, 30003, 30004, 30005, 30006, 30007, 30091, 30092,
           40001, 40002, 40003, 40011, 40012, 40013, 40091]
    users = []
    for name, uid in zip(names, ids):
        limits = ('18g', '20g', 180000, 200000) if uid < 30000 else ('4608m', '5g', 45000, 50000)
        if name in ('syn-tracer', 'syn-observer', 'syn-probe'):
            limits = ('200m', '256m', 1500, 2000)
        users.append(dict(zip(('bsoft', 'bhard', 'isoft', 'ihard'), limits), name=name, uid=uid))
    return {'path': '/home', 'grace_s': 604800,
            'default': {'bsoft': '900m', 'bhard': '1g', 'isoft': 9000, 'ihard': 10000}, 'users': users}


def observation(host):
    result = {'hostname': host, 'boot_id': 'boot-' + host, 'machine_id': 'machine-' + host,
              'mounts': {}, 'free_bytes': {path: 100 * 1024 * A.MIB for path in A.SHARES},
              'accounts': {name: {'uid': uid, 'gid': gid, 'groups': sorted(groups | {gid})}
                           for name, (uid, gid, groups) in A.USERS.items()}}
    for path, (lv, quota, mode) in A.SHARES.items():
        result['mounts'][path] = {'target': path, 'source': '/dev/mapper/hpe_vg-' + lv if host == A.SERVER
                                  else '10.90.10.1:' + path, 'fstype': 'xfs' if host == A.SERVER else 'nfs4',
                                  'options': ['nosuid', 'nodev'] + ([quota] if quota else []) if host == A.SERVER
                                  else ['nosuid', 'nodev', 'hard', mode, 'vers=4.2']}
    if host == A.SERVER:
        result.update(storage_config={path: {'source': '/dev/mapper/hpe_vg-' + lv, 'quota': quota}
                                      for path, (lv, quota, _) in A.SHARES.items()},
                      exports=[{'path': path, 'client': '10.90.10.0/25',
                                'options': [mode, 'sync', 'secure', 'root_squash', 'mountpoint']}
                               for path, (_, _, mode) in A.SHARES.items()],
                      quota_state={'user': {'accounting': True, 'enforcement': True},
                                   'project': {'accounting': True, 'enforcement': True}},
                      project_roots={name: {'uid': 0, 'gid': gid, 'mode': 0o2770, 'acl': A.PROJECT_ACL}
                                     for name, (gid, *_) in A.PROJECTS.items()},
                      quota_check={'returncode': 0, 'stderr': '', 'stdout': 'quotas match the declaration'},
                      quota_declaration={'home': home_declaration(),
                                         'projects': {'path': '/projects', 'grace_s': 604800, 'projects': [
                                             {'name': name, 'id': gid, 'dir': '/projects/' + name, 'bsoft': '45g',
                                              'bhard': '50g', 'isoft': 450000, 'ihard': 500000}
                                             for name, (gid, *_) in A.PROJECTS.items()]}})
    return result


class Window:
    """Synthetic protocol model; no SSH, commands, credentials or fleet fallback."""
    def __init__(self):
        self.ready = True
        self.calls = []
        self.data = {}
        self.receipts = {}
        self.quota = {'user': {'used_bytes': 4096, 'used_inodes': 4,
                               'limits': [200 * A.MIB, 256 * A.MIB, 1500, 2000]},
                      'project': {'used_bytes': 0, 'used_inodes': 0, 'limits': [0, 0, 0, 0], 'mapped': False}}
        self.original_quota = copy.deepcopy(self.quota)
        self.override = {}
        self.fail = None
        self.cleanup_ok = True
        self.run = None

    def guard(self, run_id, sources):
        return {'owned': self.ready, 'fenced': self.ready, 'exclusive': self.ready, 'quiescent': self.ready}

    def observe(self, host):
        return observation(host)

    def call(self, host, op, payload):
        self.calls.append((host, op, copy.deepcopy(payload)))
        if op == self.fail:
            raise RuntimeError('injected lost response')
        if op in self.override:
            return copy.deepcopy(self.override[op])
        receipt = {'id': len(self.receipts), 'host': host, 'operation': op}
        if op.startswith('create_') or op.startswith('exhaust_') or op == 'prepare_project_quota':
            saved = json.loads(self.run.file.read_text())
            assert saved['cleanup'][-1]['state'] == 'intent'
            self.receipts[receipt['id']] = receipt
        if op == 'create_project_fixture':
            project = payload['project']
            self.data[project] = payload['content_hex']
            gid = A.PROJECTS[project][0]
            uid = A.USERS[payload['user']][0]
            return {'receipt': receipt, 'file': {'uid': uid, 'gid': gid, 'mode': 0o660},
                    'directory': {'uid': uid, 'gid': gid, 'mode': 0o2770, 'acl': A.PROJECT_ACL}}
        if op == 'read_fixture':
            return {'content_hex': self.data[payload['project']]}
        if op == 'append_fixture':
            self.data[payload['project']] += payload['content_hex']
            return {'written': len(bytes.fromhex(payload['content_hex']))}
        if op == 'deny_project_access':
            return {'read_errno': errno.EACCES, 'create_errno': errno.EACCES}
        if op in ('create_apps_fixture', 'create_squash_fixture'):
            self.data[op] = payload.get('content_hex')
            return {'receipt': receipt}
        if op == 'apps_read_only':
            return {'content_hex': self.data['create_apps_fixture'], 'create_errno': errno.EROFS}
        if op == 'root_squash':
            return {'create_errno': errno.EACCES}
        if op == 'quota_snapshot':
            return dict(self.quota[payload['kind']], filesystem_free_bytes=100 * 1024 * A.MIB,
                        filesystem_free_inodes=100000)
        if op == 'prepare_project_quota':
            assert payload['target'] == A.PROJECT_ID
            self.quota['project']['limits'] = payload['limits']
            return {'receipt': receipt, 'project_id': A.PROJECT_ID, 'inherit': True}
        if op in ('exhaust_bytes', 'exhaust_inodes'):
            quota = self.quota[payload['kind']]
            inodes = op == 'exhaust_inodes'
            quota['used_inodes' if inodes else 'used_bytes'] = quota['limits'][3 if inodes else 1]
            return {'receipt': receipt, 'errno': errno.EDQUOT,
                    'created' if inodes else 'written': quota['used_inodes' if inodes else 'used_bytes']}
        if op == 'quota_denial':
            return {'errno': errno.ENOSPC}
        if op in ('remove_fixture', 'quota_remove_fixture', 'restore_project_quota'):
            if not self.cleanup_ok or payload['receipt'] is None:
                return {'clean': False, 'verified': False}
            self.receipts.pop(payload['receipt']['id'])
            if payload['created_by'].startswith('exhaust_'):
                kind = payload['kind']
                self.quota[kind]['used_bytes'] = self.original_quota[kind]['used_bytes']
                self.quota[kind]['used_inodes'] = self.original_quota[kind]['used_inodes']
            if op == 'restore_project_quota':
                self.quota['project'] = copy.deepcopy(self.original_quota['project'])
            return {'clean': True, 'verified': True}
        raise AssertionError('unexpected operation: ' + op)


class FunctionalTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='prace-storage-functional-')
        self.addCleanup(self.tmp.cleanup)
        self.window = Window()
        self.run = A.FunctionalRun(Path(self.tmp.name) / 'run', self.window, run_id='a' * 32)
        self.window.run = self.run

    def test_all_functional_checks_are_bounded_and_keep_window_owned(self):
        result = self.run.run()
        self.assertEqual(result['functional'], 'PASS')
        self.assertEqual(result['window'], 'still_owned_and_fenced')
        self.assertEqual(result['excluded'], list(A.EXCLUDED))
        self.assertTrue(self.window.ready)
        self.assertFalse(self.window.receipts)
        self.assertEqual(self.window.quota, self.window.original_quota)
        writes = [payload for _, op, payload in self.window.calls if op == 'exhaust_bytes']
        self.assertEqual([entry['cap'] for entry in writes], [272 * A.MIB, 12 * A.MIB])
        self.assertTrue(all(entry['seconds'] == 60 for entry in writes))
        touched = {host for host, op, _ in self.window.calls if op == 'append_fixture'}
        self.assertEqual(touched, set(A.HOSTS))
        self.assertFalse(any(op in ('release', 'reopen', 'restart', 'unmount') for _, op, _ in self.window.calls))

    def test_unowned_or_unfenced_window_cannot_dispatch(self):
        self.window.ready = False
        with self.assertRaisesRegex(A.Refused, 'window_not_ready'):
            self.run.run()
        self.assertFalse(self.window.calls)

    def test_export_mountpoint_guard_requires_the_exported_path(self):
        for guard in (None, 'mp=/different-volume', 'mountpoint=/different-volume'):
            data = observation(A.SERVER)
            options = data['exports'][0]['options']
            options.remove('mountpoint')
            if guard is not None:
                options.append(guard)
            with self.subTest(guard=guard), self.assertRaisesRegex(A.Refused, 'export_mountpoint_guard'):
                A.validate_observation(A.SERVER, data)
        for guard in ('mountpoint', 'mp', 'mountpoint=/home', 'mp=/home'):
            data = observation(A.SERVER)
            data['exports'][0]['options'][-1] = guard
            A.validate_observation(A.SERVER, data)

    def test_run_ancestry_sync_failure_prevents_dispatch(self):
        directory = Path(self.tmp.name) / 'another-run'
        with patch.object(A, 'sync_dir', side_effect=OSError('injected')) as sync:
            with self.assertRaises(OSError):
                A.FunctionalRun(directory, self.window, run_id='b' * 32)
        sync.assert_called_once_with(directory.parent)
        self.assertFalse((directory / 'acceptance.json').exists())
        self.assertFalse(self.window.calls)

    def test_lost_response_requires_explicit_cleanup_and_unknown_receipt_refuses(self):
        self.window.fail = 'create_project_fixture'
        with self.assertRaisesRegex(RuntimeError, 'lost response'):
            self.run.run()
        self.assertEqual(self.run.state['phase'], 'failed_explicit_cleanup_required')
        self.assertEqual(self.run.state['cleanup'][0]['state'], 'intent')
        self.window.fail = None
        with self.assertRaisesRegex(A.Refused, 'cleanup_unverified'):
            self.run.cleanup()
        self.assertTrue(self.window.ready)

    def test_cleanup_failure_retains_pending_receipt_and_owned_window(self):
        self.window.cleanup_ok = False
        with self.assertRaisesRegex(A.Refused, 'cleanup_unverified'):
            self.run.run()
        self.assertTrue(self.window.receipts)
        self.assertTrue(any(item['state'] == 'pending' for item in self.run.state['cleanup']))
        self.window.cleanup_ok = True
        self.run.cleanup()
        self.assertFalse(self.window.receipts)
        self.assertTrue(self.window.ready)

    def test_cleanup_requires_exact_source_and_identity(self):
        self.run.preflight()
        self.run.sharing()
        with patch.object(A, 'source_hashes', return_value={'different': 'source'}):
            with self.assertRaisesRegex(A.Refused, 'source_changed'):
                self.run.cleanup()
        original = self.window.observe
        def changed(host):
            value = original(host)
            value['boot_id'] += '-different'
            return value
        with patch.object(self.window, 'observe', side_effect=changed):
            with self.assertRaisesRegex(A.Refused, 'identity_changed'):
                self.run.preflight()

    def test_permission_or_missing_io_is_never_quota_success(self):
        self.run.preflight()
        for value in ({'receipt': {'id': 9}, 'errno': errno.EACCES, 'written': 100},
                      {'receipt': {'id': 9}, 'errno': None, 'written': 272 * A.MIB},
                      {'receipt': {'id': 9}, 'errno': errno.EDQUOT, 'written': 0},
                      {'receipt': {'id': 9}, 'errno': errno.EDQUOT, 'written': A.MIB, 'timed_out': True},
                      {'receipt': {'id': 9}, 'errno': errno.EDQUOT, 'written': A.MIB, 'timed_out': 0}):
            with self.subTest(value=value):
                self.window.override['exhaust_bytes'] = value
                with self.assertRaisesRegex(A.Refused, 'quota_not_exhausted'):
                    self.run.exhaustion('user')

    def test_preexisting_project_quota_is_never_overwritten(self):
        self.window.quota['project']['used_inodes'] = 1
        with self.assertRaisesRegex(A.Refused, 'temporary_project_in_use'):
            self.run.exhaustion('project')
        self.assertFalse(any(op == 'prepare_project_quota' for _, op, _ in self.window.calls))

    def test_quota_cleanup_needs_independent_readback_before_marking_clean(self):
        self.window.override['restore_project_quota'] = {'clean': True, 'verified': True}
        with self.assertRaisesRegex(A.Refused, 'quota_cleanup_mismatch'):
            self.run.exhaustion('project')
        ticket = next(item for item in self.run.state['cleanup'] if item['operation'] == 'restore_project_quota')
        self.assertEqual(ticket['state'], 'pending')
        self.assertTrue(self.window.ready)
        self.window.override.clear()
        self.run.cleanup()
        self.assertEqual(ticket['state'], 'clean')
        self.assertEqual(self.window.quota, self.window.original_quota)

    def test_project_limit_setter_success_without_readback_never_starts_writes(self):
        self.window.override['prepare_project_quota'] = {'receipt': {'id': 99}, 'project_id': A.PROJECT_ID, 'inherit': True}
        with self.assertRaisesRegex(A.Refused, 'project_limit_readback'):
            self.run.exhaustion('project')
        self.assertFalse(any(op == 'exhaust_bytes' for _, op, _ in self.window.calls))
        self.assertEqual(self.run.state['cleanup'][-1]['state'], 'pending')

    def test_global_inode_exhaustion_cannot_be_called_quota_enforcement(self):
        original = self.window.call
        def full_filesystem(host, operation, payload):
            result = original(host, operation, payload)
            if operation == 'quota_snapshot' and result['used_inodes'] >= 1900:
                result['filesystem_free_inodes'] = 0
            return result
        with patch.object(self.window, 'call', side_effect=full_filesystem):
            with self.assertRaisesRegex(A.Refused, 'quota_not_corroborated'):
                self.run.exhaustion('user', inodes=True)
        self.assertTrue(self.window.ready)

    def test_apps_mode_denial_does_not_prove_readonly_export(self):
        self.window.override['apps_read_only'] = {'content_hex': ('a' * 32).encode().hex(), 'create_errno': errno.EACCES}
        with self.assertRaisesRegex(A.Refused, 'apps_read_only'):
            self.run.read_only_and_squash()

    def test_cross_host_wrong_content_and_outsider_success_refuse(self):
        self.window.override['read_fixture'] = {'content_hex': 'wrong'}
        with self.assertRaisesRegex(A.Refused, 'cross_host_content'):
            self.run.sharing()
        self.window.override.clear()
        self.window.override['deny_project_access'] = {'read_errno': None, 'create_errno': None}
        with self.assertRaisesRegex(A.Refused, 'outsider_denial'):
            self.run.sharing()

    def test_private_state_cannot_be_replaced_by_symlink(self):
        self.run.file.unlink()
        self.run.file.symlink_to(Path(self.tmp.name) / 'outside')
        with self.assertRaisesRegex(A.Refused, 'private_run_record'):
            A.FunctionalRun(self.run.directory, self.window)


class ContractTests(unittest.TestCase):
    def test_real_contract_shapes_pass_for_all_declared_hosts(self):
        for host in A.HOSTS:
            A.validate_observation(host, observation(host))

    def test_new_smoke_and_observation_identities_are_required(self):
        for name, uid in (('syn-smoke', 30005), ('syn-tracer', 30006), ('syn-observer', 30007)):
            with self.subTest(name=name):
                self.assertEqual(A.USERS[name], (uid, uid, {30000, 31003}))
                for field, value in (('uid', 49999), ('gid', 49999), ('groups', [uid, 30000, 31002])):
                    data = observation(A.CLIENTS[0])
                    data['accounts'][name][field] = value
                    with self.subTest(field=field), self.assertRaisesRegex(A.Refused, 'numeric_identity'):
                        A.validate_observation(A.CLIENTS[0], data)

    def test_old_17_user_declaration_is_refused(self):
        data = observation(A.SERVER)
        home = data['quota_declaration']['home']
        home['users'] = [u for u in home['users']
                         if u['name'] not in ('syn-smoke', 'syn-tracer', 'syn-observer')]
        self.assertEqual(len(home['users']), 17)
        with self.assertRaisesRegex(A.Refused, 'quota_declaration'):
            A.validate_observation(A.SERVER, data)

    def test_new_home_limits_cannot_be_swapped_or_removed(self):
        for name, wrong_limits in (
                ('syn-smoke', ('200m', '256m', 1500, 2000)),
                ('syn-tracer', ('4608m', '5g', 45000, 50000)),
                ('syn-observer', ('4608m', '5g', 45000, 50000))):
            for mutation in ('wrong_limits', 'missing', 'zero'):
                data = observation(A.SERVER)
                users = data['quota_declaration']['home']['users']
                user = next(u for u in users if u['name'] == name)
                if mutation == 'missing':
                    users.remove(user)
                else:
                    limits = wrong_limits if mutation == 'wrong_limits' else ('0', '0', 0, 0)
                    user.update(zip(('bsoft', 'bhard', 'isoft', 'ihard'), limits))
                with self.subTest(name=name, mutation=mutation), self.assertRaisesRegex(A.Refused, 'quota_declaration'):
                    A.validate_observation(A.SERVER, data)

    def test_vacuous_mount_quota_and_export_checks_fail(self):
        cases = [('storage_config', {}), ('exports', []), ('quota_declaration', {'home': None, 'projects': None}),
                 ('quota_check', {'returncode': 0, 'stderr': 'quota: command failed', 'stdout': 'quotas match the declaration'}),
                 ('quota_check', {'returncode': 0, 'stderr': '', 'stdout': 'WOULD quota changes'}),
                 ('project_roots', {})]
        for key, value in cases:
            with self.subTest(key=key):
                data = observation(A.SERVER)
                data[key] = value
                with self.assertRaises(A.Refused):
                    A.validate_observation(A.SERVER, data)
        data = observation(A.SERVER)
        data['exports'].append(copy.deepcopy(data['exports'][0]))
        with self.assertRaisesRegex(A.Refused, 'export_membership'):
            A.validate_observation(A.SERVER, data)

    def test_wrong_mount_source_options_or_ids_fail(self):
        for key, value in [('source', '/dev/root'), ('fstype', 'ext4'),
                           ('options', ['rw', 'soft', 'nosuid', 'nodev', 'vers=4.2'])]:
            data = observation(A.CLIENTS[0])
            data['mounts']['/home'][key] = value
            with self.subTest(key=key), self.assertRaises(A.Refused):
                A.validate_observation(A.CLIENTS[0], data)
        data = observation(A.CLIENTS[0])
        data['accounts']['syn-alice']['groups'].append(31002)
        with self.assertRaisesRegex(A.Refused, 'numeric_identity'):
            A.validate_observation(A.CLIENTS[0], data)

    def test_full_home_policy_cannot_drift_behind_a_truthful_helper_pass(self):
        for mutation in ('zero_limits', 'default', 'missing', 'extra', 'duplicate', 'name'):
            data = observation(A.SERVER)
            home = data['quota_declaration']['home']
            if mutation == 'zero_limits':
                for user in home['users']:
                    if user['name'] != 'syn-probe':
                        user.update(bsoft='0', bhard='0', isoft=0, ihard=0)
            elif mutation == 'default':
                home['default']['bhard'] = '0'
            elif mutation == 'missing':
                home['users'].pop()
            elif mutation == 'extra':
                home['users'].append(dict(home['users'][-1], name='extra', uid=49999))
            elif mutation == 'duplicate':
                home['users'].append(copy.deepcopy(home['users'][0]))
            else:
                home['users'][0]['name'] = 'someone-else'
            with self.subTest(mutation=mutation), self.assertRaisesRegex(A.Refused, 'quota_declaration'):
                A.validate_observation(A.SERVER, data)


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='prace-storage-probe-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_actual_write_stops_at_cap_without_claiming_quota(self):
        path = self.root / 'file'
        result = P.fill_bytes(path, max_bytes=4096)
        self.assertEqual((result['written'], result['errno'], path.stat().st_size), (4096, None, 4096))
        P.remove_fixture(path, result['identity'])
        self.assertFalse(path.exists())

    def test_quota_error_is_reported_and_permission_error_is_not(self):
        for code in (errno.EDQUOT, errno.ENOSPC):
            with patch.object(os, 'write', side_effect=OSError(code, 'fixture')):
                result = P.fill_bytes(self.root / str(code), max_bytes=4096)
            self.assertEqual(result['errno'], code)
        with patch.object(os, 'write', side_effect=OSError(errno.EACCES, 'fixture')):
            with self.assertRaises(PermissionError):
                P.fill_bytes(self.root / 'denied', max_bytes=4096)

    def test_real_inode_fixture_is_bounded_and_cleanup_refuses_injected_entry(self):
        path = self.root / 'inodes'
        result = P.fill_inodes(path, max_files=8)
        self.assertEqual(result['created'], 8)
        self.assertIsNone(result['errno'])
        (path / 'unknown').write_text('must remain')
        with self.assertRaisesRegex(ValueError, 'unexpected fixture entry'):
            P.remove_fixture(path, result['identity'], inode_fixture=True)
        self.assertEqual(len(list(path.iterdir())), 9)
        (path / 'unknown').unlink()
        P.remove_fixture(path, result['identity'], inode_fixture=True)
        self.assertFalse(path.exists())

    def test_inode_cleanup_refuses_numeric_extra_and_replaced_recorded_file(self):
        path = self.root / 'inodes'
        result = P.fill_inodes(path, max_files=8)
        (path / '1000').touch()
        with self.assertRaisesRegex(ValueError, 'unexpected fixture entry'):
            P.remove_fixture(path, result['identity'], inode_fixture=True)
        self.assertEqual(len(list(path.iterdir())), 9)
        (path / '1000').unlink()
        # Keep the original inode allocated so the replacement cannot reuse it.
        (path / '0').rename(self.root / 'original')
        (path / '0').touch()
        with self.assertRaisesRegex(ValueError, 'unexpected fixture entry'):
            P.remove_fixture(path, result['identity'], inode_fixture=True)
        self.assertEqual(len(list(path.iterdir())), 8)

    def test_inode_cleanup_can_resume_with_a_verified_remaining_subset(self):
        path = self.root / 'inodes'
        result = P.fill_inodes(path, max_files=8)
        (path / '0').unlink()
        P.remove_fixture(path, result['identity'], inode_fixture=True)
        self.assertFalse(path.exists())

    def test_preexisting_symlink_path_and_identity_change_refuse(self):
        path = self.root / 'file'
        result = P.fill_bytes(path, max_bytes=32)
        with self.assertRaises(FileExistsError):
            P.fill_bytes(path, max_bytes=32)
        alias = self.root / 'alias'
        alias.symlink_to(path)
        with self.assertRaises(FileExistsError):
            P.fill_bytes(alias, max_bytes=32)
        original = dict(result['identity'], inode=result['identity']['inode'] + 1)
        with self.assertRaisesRegex(ValueError, 'identity'):
            P.remove_fixture(path, original)
        self.assertEqual(path.stat().st_size, 32)

    def test_invalid_and_expired_budgets_refuse(self):
        for value in (0, -1, True, P.MAX_BYTES + 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                P.fill_bytes(self.root / 'bad', max_bytes=value)
        with patch.object(P.time, 'monotonic', side_effect=[0, 121]):
            with self.assertRaises(TimeoutError):
                P.fill_bytes(self.root / 'timed-out', max_bytes=32)


if __name__ == '__main__':
    unittest.main(verbosity=2)

#!/usr/bin/env python3
"""Hermetic namespace-wrapper checks; no unshare, mount or helper is executed."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('underlay', Path(__file__).with_name('prace_worker_underlay.py'))
U = importlib.util.module_from_spec(spec)
spec.loader.exec_module(U)


def identity():
    return {'hostname': 'lab-lenovo', 'chassis_serial': 'EXSER02', 'machine_id': 'a' * 32,
            'boot_id': '11111111-2222-3333-4444-555555555555'}


def context():
    return {'schema': 2, 'id': 'b' * 16, 'phase': 'closed', 'fence_intent': {'active': True}}


def records():
    lines = ['20 1 8:1 / / rw,relatime - xfs /dev/root rw']
    for number, path in enumerate(U.PATHS, 30):
        mode = 'ro' if path == '/apps' else 'rw'
        lines.append(f'{number} 20 0:{number} / {path} {mode},nosuid,nodev,relatime - nfs4 10.90.10.1:{path} '
                     f'{mode},vers=4.2,hard,sec=sys,proto=tcp')
    return U.parse_mountinfo('\n'.join(lines))


class ChildTests(unittest.TestCase):
    def setUp(self):
        self.rows = records()
        self.calls = []
        self.payload = {'context': context(), 'identity': identity(), 'mode': 'check', 'run_id': None,
                        'parent_pid': 12345, 'parent_namespace': 'mnt:[100]', 'helper_sha256': 'c' * 64}
        def command(argv):
            self.calls.append(argv)
            if argv[0] == 'umount':
                self.rows[:] = [row for row in self.rows if row['target'] != argv[-1]]
                return ''
            if argv[0] == U.HELPER:
                return json.dumps({'guarded': True, 'changed': self.payload['mode'] == 'prepare'})
            raise AssertionError('unexpected command')
        self.patches = [patch.object(U.os, 'geteuid', return_value=0),
                        patch.object(U, 'local_identity', side_effect=identity),
                        patch.object(U, 'namespace', side_effect=lambda pid='self': 'mnt:[200]' if pid == 'self' else 'mnt:[100]'),
                        patch.object(U, 'mountinfo', side_effect=lambda: copy.deepcopy(self.rows)),
                        patch.object(U, 'directory'), patch.object(U, 'verify_helper'), patch.object(U, 'child_command', side_effect=command)]
        for value in self.patches:
            value.start()
            self.addCleanup(value.stop)

    def assert_no_helper(self):
        self.assertFalse(any(row[0] == U.HELPER for row in self.calls))

    def test_private_child_uses_only_ordinary_path_unmount_then_check(self):
        result = U.child(self.payload)
        self.assertEqual(set(result['paths']), set(U.PATHS))
        self.assertEqual(self.calls, [argv for path in U.PATHS for argv in
                                     (['umount', '--', path], [U.HELPER, '--path', path, '--check'])])

    def test_same_namespace_or_changed_parent_refuses_before_any_unmount(self):
        for namespace in ('mnt:[100]', 'mnt:[999]'):
            with self.subTest(namespace=namespace), patch.object(U, 'namespace', return_value=namespace):
                with self.assertRaisesRegex(U.Refused, 'namespace_not_isolated'):
                    U.child(self.payload)
        self.assertFalse(self.calls)

    def test_shared_master_or_propagate_from_refuses_before_any_unmount(self):
        for propagation in ('shared:1', 'master:2', 'propagate_from:3'):
            self.rows[0]['optional'] = [propagation]
            with self.subTest(propagation=propagation), self.assertRaisesRegex(U.Refused, 'namespace_propagation'):
                U.child(self.payload)
        self.assertFalse(self.calls)

    def test_wrong_source_version_soft_options_or_stacked_nested_mount_refuse(self):
        variants = []
        for key, value in (('source', '10.90.10.2:/home'), ('fstype', 'xfs'),
                           ('super_options', ['vers=4.1', 'hard', 'sec=sys']),
                           ('super_options', ['vers=4.2', 'soft', 'sec=sys']),
                           ('options', ['rw', 'nodev'])):
            value_rows = records()
            value_rows[1][key] = value
            variants.append(value_rows)
        variants.append(records() + [copy.deepcopy(records()[1])])
        variants.append(records() + [dict(records()[1], target='/home/nested')])
        for rows in variants:
            self.rows = rows
            with self.subTest(rows=rows), self.assertRaises(U.Refused):
                U.child(self.payload)
        self.assertFalse(self.calls)

    def test_identity_drift_and_symlink_refuse_before_helper(self):
        with patch.object(U, 'local_identity', return_value=dict(identity(), boot_id='changed')):
            with self.assertRaisesRegex(U.Refused, 'identity_changed'):
                U.child(self.payload)
        with patch.object(U, 'directory', side_effect=U.Refused('directory_identity')):
            with self.assertRaisesRegex(U.Refused, 'directory_identity'):
                U.child(self.payload)
        self.assertFalse(self.calls)

    def test_failed_or_non_effective_unmount_never_calls_helper(self):
        with patch.object(U, 'child_command', side_effect=subprocess.TimeoutExpired('umount', 20)):
            with self.assertRaises(subprocess.TimeoutExpired):
                U.child(self.payload)
        with patch.object(U, 'child_command', return_value=''):
            with self.assertRaisesRegex(U.Refused, 'unmount_unverified'):
                U.child(self.payload)
        self.assert_no_helper()

    def test_namespace_propagation_change_after_unmount_refuses_before_helper(self):
        original = U.child_command.side_effect
        def command(argv):
            result = original(argv)
            self.rows[0]['optional'] = ['shared:10']
            return result
        with patch.object(U, 'child_command', side_effect=command):
            with self.assertRaisesRegex(U.Refused, 'namespace_propagation'):
                U.child(self.payload)
        self.assertEqual(self.calls, [['umount', '--', '/home']])

    def test_identity_change_after_unmount_refuses_before_helper(self):
        original = U.child_command.side_effect
        changed = []
        def command(argv):
            result = original(argv)
            changed.append(True)
            return result
        with patch.object(U, 'child_command', side_effect=command), \
                patch.object(U, 'local_identity', side_effect=lambda: dict(identity(), boot_id='changed') if changed else identity()):
            with self.assertRaisesRegex(U.Refused, 'identity_changed'):
                U.child(self.payload)
        self.assertEqual(self.calls, [['umount', '--', '/home']])

    def test_prepare_requires_safe_explicit_id_and_preserves_only_home(self):
        self.payload['mode'] = 'prepare'
        for value in (None, '../old', 'SHORT'):
            self.payload['run_id'] = value
            with self.assertRaisesRegex(U.Refused, 'explicit_preservation_id_required'):
                U.child(self.payload)
        self.assertFalse(self.calls)
        self.payload['run_id'] = 'test-underlay-20260930'
        with patch.object(Path, 'resolve', new=lambda path: path), patch.object(Path, 'exists', return_value=False), \
                patch.object(Path, 'is_symlink', return_value=False):
            U.child(self.payload)
        helpers = [row for row in self.calls if row[0] == U.HELPER]
        self.assertEqual(helpers, [[U.HELPER, '--path', '/home', '--preserve-home', self.payload['run_id']],
                                   [U.HELPER, '--path', '/projects'], [U.HELPER, '--path', '/apps']])


class ParentTests(unittest.TestCase):
    def setUp(self):
        self.rows = records()
        self.guard_calls = []
        self.runner_calls = []
        def guard():
            self.guard_calls.append('local')
            return True
        self.guard = guard
        def runner(argv, timeout):
            self.runner_calls.append((argv, timeout))
            compile(argv[-1], '<child-wrapper>', 'exec')
            return json.dumps({'mode': 'check', 'child_namespace': 'mnt:[200]',
                               'paths': {path: {'guarded': True, 'changed': False} for path in U.PATHS}})
        self.runner = runner
        self.patches = [patch.object(U.os, 'geteuid', return_value=0), patch.object(U, 'local_identity', side_effect=identity),
                        patch.object(U, 'namespace', return_value='mnt:[100]'),
                        patch.object(U, 'mountinfo', side_effect=lambda: copy.deepcopy(self.rows)),
                        patch.object(U, 'directory'), patch.object(U, 'verify_helper'), patch.object(U, 'SOURCE', Path(U.__file__).read_text())]
        for value in self.patches:
            value.start()
            self.addCleanup(value.stop)

    def run_wrapper(self):
        return U.run_guarded(context(), identity(), helper_sha256='c' * 64, guard=self.guard, runner=self.runner)

    def test_parent_uses_explicit_unshare_and_rechecks_after_child(self):
        result = self.run_wrapper()
        self.assertEqual(self.runner_calls[0][0][0:7], ['unshare', '--mount', '--propagation', 'private', '--', 'python3', '-c'])
        self.assertEqual(self.runner_calls[0][1], 130)
        self.assertEqual(self.guard_calls, ['local', 'local'])
        self.assertTrue(result['parent_mounts_unchanged'])
        self.assertEqual(result['server_fence_observation'], 'adapter responsibility')

    def test_standalone_nonroot_open_context_and_missing_source_refuse(self):
        with self.assertRaisesRegex(U.Refused, 'guarded_adapter_required'):
            U.run_guarded(context(), identity())
        with patch.object(U.os, 'geteuid', return_value=1000), self.assertRaisesRegex(U.Refused, 'root_required'):
            self.run_wrapper()
        with self.assertRaisesRegex(U.Refused, 'closed_adapter_context_required'):
            U.run_guarded(dict(context(), phase='opening'), identity(), helper_sha256='c' * 64, guard=self.guard, runner=self.runner)
        with patch.object(U, 'SOURCE', None), self.assertRaisesRegex(U.Refused, 'reviewed_source_required'):
            self.run_wrapper()
        self.assertFalse(self.runner_calls)

    def test_parent_mount_drift_is_never_hidden_by_child_success_or_failure(self):
        for fail in (False, True):
            self.rows = records()
            def runner(argv, timeout):
                result = self.runner(argv, timeout)
                self.rows[1]['source'] = '10.90.10.9:/home'
                if fail:
                    raise subprocess.TimeoutExpired('unshare', 130)
                return result
            with self.subTest(fail=fail), self.assertRaises(U.Refused):
                U.run_guarded(context(), identity(), helper_sha256='c' * 64, guard=self.guard, runner=runner)

    def test_failed_child_still_checks_parent_and_local_guard(self):
        def failure(argv, timeout):
            raise subprocess.TimeoutExpired('unshare', timeout)
        with self.assertRaises(subprocess.TimeoutExpired):
            U.run_guarded(context(), identity(), helper_sha256='c' * 64, guard=self.guard, runner=failure)
        self.assertEqual(self.guard_calls, ['local', 'local'])

    def test_incomplete_or_changed_helper_results_cannot_be_called_a_check_pass(self):
        for value in ({}, {'guarded': False, 'changed': False}, {'guarded': True, 'changed': True}):
            def runner(argv, timeout):
                result = json.loads(self.runner(argv, timeout))
                result['paths']['/home'] = value
                return json.dumps(result)
            with self.subTest(value=value), self.assertRaises(U.Refused):
                U.run_guarded(context(), identity(), helper_sha256='c' * 64, guard=self.guard, runner=runner)


class CommandTests(unittest.TestCase):
    def test_helper_is_pinned_and_unsafe_owner_mode_or_content_refuses(self):
        import hashlib
        data = b'#!/usr/bin/python3\n'
        expected = hashlib.sha256(data).hexdigest()
        info = type('Info', (), {'st_mode': 0o100755, 'st_uid': 0, 'st_nlink': 1, 'st_size': len(data)})()
        with patch.object(Path, 'lstat', return_value=info), patch.object(Path, 'read_bytes', return_value=data):
            U.verify_helper(expected)
            for field, value in (('st_uid', 1000), ('st_mode', 0o100775), ('st_nlink', 2)):
                old = getattr(info, field)
                setattr(info, field, value)
                with self.subTest(field=field), self.assertRaisesRegex(U.Refused, 'helper_identity'):
                    U.verify_helper(expected)
                setattr(info, field, old)
            with self.assertRaisesRegex(U.Refused, 'helper_changed'):
                U.verify_helper('0' * 64)

    def test_zero_exit_with_stderr_refuses_and_timeout_kills_process_group(self):
        class Process:
            pid, returncode = 12345, 0
            def communicate(self, timeout):
                return '', 'umount warning'
        with patch.object(U.subprocess, 'Popen', return_value=Process()) as start:
            with self.assertRaisesRegex(U.Refused, 'child_command_failed'):
                U.child_command(['umount', '--', '/home'])
            self.assertFalse(start.call_args.kwargs['close_fds'])
        class Timeout(Process):
            def communicate(self, timeout):
                raise subprocess.TimeoutExpired('umount', timeout)
        with patch.object(U.subprocess, 'Popen', return_value=Timeout()), patch.object(U.os, 'killpg') as kill:
            with self.assertRaises(subprocess.TimeoutExpired):
                U.child_command(['umount', '--', '/home'])
            kill.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)

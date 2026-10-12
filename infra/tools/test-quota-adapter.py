#!/usr/bin/env python3
"""Offline quota adapter tests: real fixture/receipt files, modeled XFS only."""
import contextlib
import errno
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
D = load('quota_driver', 'storage-acceptance.py')
Q = load('quota_remote', 'prace_quota_remote.py')
R = load('storage_remote', 'prace_storage_remote.py')
R.C, R.A, R.Q = (D.C, D.A, Q)
Q.R = R
T = load('storage_adapter_tests', 'test-storage-acceptance-adapter.py')

class QuotaReportTests(unittest.TestCase):

    def test_grace_text_does_not_shift_block_and_inode_columns(self):
        value = Q.quota_report('#30091 262144 204800 262144 01 [6 days] 1999 1500 2000 00 [--------]\n')
        self.assertEqual(value[30091], {'used_bytes': 256 * Q.MIB, 'used_inodes': 1999, 'limits': [200 * Q.MIB, 256 * Q.MIB, 1500, 2000]})

    def test_empty_duplicate_or_malformed_report_refuses(self):
        row = '#0 0 0 0 00 [--------] 1 0 0 00 [--------]\n'
        for text in ('', row + row, 'xfs_quota: refused\n', '#30091 0 0 0\n', row.replace(' 1 ', ' -1 ')):
            with self.subTest(text=text), self.assertRaises(D.C.Refused):
                Q.quota_report(text)

    def test_snapshot_is_server_only_and_target_is_fixed(self):
        for host, target in ((D.A.CLIENTS[0], 30091), (D.A.SERVER, 0), (D.A.SERVER, 30001)):
            with self.subTest(host=host, target=target), patch.object(Q, 'snapshot') as call:
                with self.assertRaises(D.C.Refused):
                    Q.dispatch(Path('/unused'), {'operation': 'quota_snapshot', 'host': host, 'kind': 'user', 'target': target})
                call.assert_not_called()

    def test_project_setter_cannot_touch_production_ids_or_arbitrary_limits(self):
        with patch.object(R, 'command') as command:
            for limits in ([1, 2, 3, 4], [45 * 1024 ** 3, 50 * 1024 ** 3, 450000, 500000]):
                with self.assertRaises(D.C.Refused):
                    Q.limits(limits)
            command.assert_not_called()

    def test_silent_quota_setter_failure_is_refused(self):
        with patch.object(R, 'command', return_value=''), patch.object(Q, 'snapshot', return_value={'limits': [0, 0, 0, 0]}):
            with self.assertRaisesRegex(D.C.Refused, 'quota_limit_readback'):
                Q.limits([8 * Q.MIB, 10 * Q.MIB, 0, 0])

class IOTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ledger = self.root / 'ledger'
        self.ledger.mkdir(mode=448)
        self.files = self.root / 'files'
        self.files.mkdir()
        self.actor = 'root'

        @contextlib.contextmanager
        def actor(user):
            old = self.actor
            self.actor = user
            try:
                yield
            finally:
                self.actor = old

        def fixture(request, denial=False):
            inode = request.get('inodes', request['operation'] == 'exhaust_inodes')
            return (self.files / (('inode' if inode else 'bytes') + ('-denial' if denial else '')), inode)
        for obj, name, new in ((Q, 'fixture_path', fixture), (R, 'as_user', actor)):
            p = patch.object(obj, name, new)
            p.start()
            self.addCleanup(p.stop)
        self.request = {'operation': 'exhaust_bytes', 'host': D.A.CLIENTS[0], 'kind': 'user', 'user': 'syn-probe', 'run_id': 'a' * 32, 'cap': 272 * Q.MIB, 'seconds': 60, 'inodes': False}

    def test_byte_edquot_has_durable_identity_and_exact_cleanup(self):
        actual_write = os.write
        calls = 0

        def write(fd, data):
            nonlocal calls
            if self.actor == 'syn-probe':
                calls += 1
                if calls > 1:
                    raise OSError(errno.EDQUOT, 'synthetic quota')
            return actual_write(fd, data)
        with patch.object(Q.os, 'write', side_effect=write):
            result = Q.io_probe(self.ledger, self.request)
        self.assertEqual(result['errno'], errno.EDQUOT)
        self.assertEqual(result['written'], Q.MIB)
        record = json.loads(Q.receipt_path(self.ledger, self.request).read_text())
        self.assertEqual(record['state'], 'complete')
        self.assertIsNotNone(record['root'])
        result = Q.cleanup_io(self.ledger, dict(self.request, operation='quota_remove_fixture'))
        self.assertEqual(result, {'clean': True, 'verified': True})
        self.assertFalse(list(self.files.iterdir()))
        self.assertTrue(R.clean_receipts(self.ledger))

    def test_inode_exhaustion_records_every_created_inode_and_rejects_extra_file(self):
        request = dict(self.request, operation='exhaust_inodes', inodes=True, cap=2100)
        real_open = os.open

        def opening(path, *args, **kw):
            if self.actor == 'syn-probe' and Path(path).name == '3':
                raise OSError(errno.EDQUOT, 'synthetic quota')
            return real_open(path, *args, **kw)
        with patch.object(Q.os, 'open', side_effect=opening):
            result = Q.io_probe(self.ledger, request)
        self.assertEqual((result['created'], result['errno']), (3, errno.EDQUOT))
        folder = self.files / 'inode'
        (folder / 'outside').touch()
        with self.assertRaisesRegex(D.C.Refused, 'quota_unknown_entry'):
            Q.cleanup_io(self.ledger, request)
        self.assertTrue((folder / '0').exists())
        (folder / 'outside').unlink()
        self.assertEqual(Q.cleanup_io(self.ledger, request), {'clean': True, 'verified': True})
        self.assertFalse(folder.exists())

    def test_cross_client_unexpected_success_is_retained_and_cleaned(self):
        request = dict(self.request, operation='quota_denial', host=D.A.CLIENTS[1])
        result = Q.io_probe(self.ledger, request, True)
        self.assertIsNone(result['errno'])
        self.assertTrue((self.files / 'bytes-denial').exists())
        self.assertFalse(R.clean_receipts(self.ledger))
        self.assertEqual(Q.cleanup_io(self.ledger, request, True), {'clean': True, 'verified': True})
        self.assertTrue(R.clean_receipts(self.ledger))

    def test_read_only_or_io_errors_do_not_count_as_quota(self):
        actual_write = os.write

        def write(fd, data):
            if self.actor == 'syn-probe':
                raise OSError(errno.EIO, 'synthetic device fault')
            return actual_write(fd, data)
        with patch.object(Q.os, 'write', side_effect=write), self.assertRaises(OSError):
            Q.io_probe(self.ledger, self.request)
        with self.assertRaisesRegex(D.C.Refused, 'quota_receipt_unknown'):
            Q.cleanup_io(self.ledger, self.request)
        self.assertFalse(R.clean_receipts(self.ledger))

    def test_receipt_precedes_creation_and_foreign_replacement_is_not_removed(self):
        real_open = os.open

        def opening(path, *args, **kw):
            if self.actor == 'syn-probe':
                self.assertEqual(json.loads(Q.receipt_path(self.ledger, self.request).read_text())['state'], 'intent')
                raise OSError(errno.EDQUOT, 'synthetic quota')
            return real_open(path, *args, **kw)
        with patch.object(Q.os, 'open', side_effect=opening):
            Q.io_probe(self.ledger, self.request)
        (self.files / 'bytes').write_text('foreign')
        with self.assertRaisesRegex(D.C.Refused, 'quota_fixture_changed'):
            Q.cleanup_io(self.ledger, self.request)
        self.assertEqual((self.files / 'bytes').read_text(), 'foreign')

    def test_replaced_existing_fixture_is_preserved(self):
        actual_write = os.write
        calls = 0

        def write(fd, data):
            nonlocal calls
            if self.actor == 'syn-probe':
                calls += 1
                if calls > 1:
                    raise OSError(errno.EDQUOT, 'synthetic quota')
            return actual_write(fd, data)
        with patch.object(Q.os, 'write', side_effect=write):
            Q.io_probe(self.ledger, self.request)
        path = self.files / 'bytes'
        path.rename(self.root / 'saved-original')
        path.write_text('foreign replacement')
        with self.assertRaisesRegex(D.C.Refused, 'quota_fixture_changed'):
            Q.cleanup_io(self.ledger, self.request)
        self.assertEqual(path.read_text(), 'foreign replacement')

    def test_client_metadata_checks_use_the_synthetic_owner(self):
        actual_id = R.object_id
        actual_write = os.write
        calls = 0

        def identity(path):
            self.assertEqual(self.actor, 'syn-probe')
            return actual_id(path)

        def write(fd, data):
            nonlocal calls
            if self.actor == 'syn-probe':
                calls += 1
                if calls > 1:
                    raise OSError(errno.EDQUOT, 'synthetic quota')
            return actual_write(fd, data)
        with patch.object(R, 'object_id', side_effect=identity), patch.object(Q.os, 'write', side_effect=write):
            Q.io_probe(self.ledger, self.request)
            Q.cleanup_io(self.ledger, self.request)

    def test_bounded_timeout_has_known_receipt_and_explicit_cleanup(self):
        for inodes in (False, True):
            with self.subTest(inodes=inodes):
                request = dict(self.request, inodes=inodes,
                               operation='exhaust_inodes' if inodes else 'exhaust_bytes',
                               cap=2100 if inodes else 272 * Q.MIB)
                with patch.object(Q.time, 'monotonic', side_effect=[0, 30, 60]):
                    result = Q.io_probe(self.ledger, request)
                self.assertTrue(result['timed_out'])
                self.assertIsNone(result['errno'])
                rec = json.loads(Q.receipt_path(self.ledger, request).read_text())
                self.assertEqual(rec['state'], 'complete')
                self.assertIsNotNone(rec['root'])
                self.assertEqual(Q.cleanup_io(self.ledger, request), {'clean': True, 'verified': True})
                self.assertFalse(list(self.files.iterdir()))

    def test_close_quota_error_is_recorded_and_descriptor_is_not_retried(self):
        for write_fails in (False, True):
            for close_errno in (errno.EDQUOT, errno.ENOSPC):
                with self.subTest(write_fails=write_fails, close_errno=close_errno):
                    real_open, real_close, real_write = os.open, os.close, os.write
                    probe_fd, close_calls, writes = None, 0, 0
                    def opening(path, *args, **kwargs):
                        nonlocal probe_fd
                        fd = real_open(path, *args, **kwargs)
                        if Path(path) == self.files / 'bytes-denial':
                            probe_fd = fd
                        return fd
                    def closing(fd):
                        nonlocal close_calls, probe_fd
                        if fd == probe_fd:
                            close_calls += 1
                            probe_fd = None
                            real_close(fd)
                            raise OSError(close_errno, 'synthetic close quota')
                        return real_close(fd)
                    def writing(fd, data):
                        nonlocal writes
                        if fd == probe_fd:
                            writes += 1
                            if write_fails:
                                raise OSError(errno.EDQUOT, 'synthetic write quota')
                        return real_write(fd, data)
                    request = dict(self.request, operation='quota_denial', host=D.A.CLIENTS[1])
                    with patch.object(Q.os, 'open', side_effect=opening), patch.object(Q.os, 'close', side_effect=closing), patch.object(Q.os, 'write', side_effect=writing):
                        result = Q.io_probe(self.ledger, request, True)
                    self.assertEqual(close_calls, 1)
                    self.assertEqual(result['errno'], close_errno)
                    self.assertFalse(result['timed_out'])
                    rec = json.loads(Q.receipt_path(self.ledger, request, True).read_text())
                    self.assertEqual((rec['state'], rec['close_errno']), ('complete', close_errno))
                    self.assertEqual(Q.cleanup_io(self.ledger, request, True), {'clean': True, 'verified': True})
                    Q.receipt_path(self.ledger, request, True).unlink()

    def test_close_eio_retains_error_and_never_reports_quota_success(self):
        real_open, real_close = os.open, os.close
        probe_fd = None
        def opening(path, *args, **kwargs):
            nonlocal probe_fd
            fd = real_open(path, *args, **kwargs)
            if Path(path) == self.files / 'bytes-denial':
                probe_fd = fd
            return fd
        def closing(fd):
            nonlocal probe_fd
            if fd == probe_fd:
                probe_fd = None
                real_close(fd)
                raise OSError(errno.EIO, 'synthetic close error')
            return real_close(fd)
        request = dict(self.request, operation='quota_denial', host=D.A.CLIENTS[1])
        with patch.object(Q.os, 'open', side_effect=opening), patch.object(Q.os, 'close', side_effect=closing), self.assertRaises(OSError):
            Q.io_probe(self.ledger, request, True)
        rec = json.loads(Q.receipt_path(self.ledger, request, True).read_text())
        self.assertEqual((rec['state'], rec['close_errno']), ('intent', errno.EIO))
        with self.assertRaisesRegex(D.C.Refused, 'quota_receipt_unknown'):
            Q.cleanup_io(self.ledger, request, True)

    def test_invalid_cap_or_user_refuses_before_receipt(self):
        for change in ({'cap': 512 * Q.MIB}, {'user': 'root'}, {'host': D.A.SERVER}):
            with self.subTest(change=change), self.assertRaises(D.C.Refused):
                Q.io_probe(self.ledger, dict(self.request, **change))
            self.assertEqual(list(self.ledger.iterdir()), [])

class ProjectTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ledger = self.root / 'ledger'
        self.ledger.mkdir(mode=448)
        self.fixture = self.root / 'project'
        self.current_limits = [0, 0, 0, 0]
        self.mapping = {'/etc/projects': 'a' * 64, '/etc/projid': 'b' * 64}
        self.tagged = False
        self.commands = []

        def snapshot(kind):
            self.assertEqual(kind, 'project')
            return {'used_bytes': 0, 'used_inodes': int(self.fixture.exists()), 'limits': list(self.current_limits), 'mapped': False, 'mapping_hashes': dict(self.mapping), 'filesystem_free_bytes': 10 ** 12, 'filesystem_free_inodes': 10 ** 6}

        def command(argv):
            self.commands.append(argv)
            self.current_limits = [8 * Q.MIB, 10 * Q.MIB, 0, 0] if 'bsoft=8192k' in argv[3] else [0, 0, 0, 0]
            return ''

        def tag(path, project=None):
            self.assertEqual(path, self.fixture)
            if project is not None:
                self.assertEqual(project, 39999)
                self.tagged = True
            return (39999, True) if self.tagged else (0, False)
        for obj, name, new in ((Q, 'project_path', lambda run: self.fixture), (Q, 'snapshot', snapshot), (Q, 'mappings', lambda: (dict(self.mapping), False)), (R, 'command', command), (Q, 'tag', tag), (Q.os, 'chown', lambda *args: None)):
            patcher = patch.object(obj, name, new)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.before = snapshot('project')
        self.request = {'host': D.A.SERVER, 'target': 39999, 'limits': [8 * Q.MIB, 10 * Q.MIB, 0, 0], 'run_id': 'b' * 32, 'original': self.before}

    def test_project_prepare_restore_leaves_mapping_and_limits_exact(self):
        self.assertTrue(Q.prepare(self.ledger, self.request)['inherit'])
        self.assertEqual(self.current_limits, [8 * Q.MIB, 10 * Q.MIB, 0, 0])
        self.assertEqual(Q.restore(self.ledger, self.request), {'clean': True, 'verified': True})
        self.assertFalse(self.fixture.exists())
        self.assertEqual(self.current_limits, [0, 0, 0, 0])
        self.assertEqual(self.mapping, self.before['mapping_hashes'])
        self.assertEqual(len(self.commands), 2)
        self.assertTrue(all((cmd[-1] == '/projects' and cmd[3].endswith(' 39999') for cmd in self.commands)))

    def test_foreign_mapping_or_limits_block_restore_without_deletion(self):
        Q.prepare(self.ledger, self.request)
        self.current_limits = [1, 2, 3, 4]
        with self.assertRaisesRegex(D.C.Refused, 'quota_limits_foreign'):
            Q.restore(self.ledger, self.request)
        self.assertTrue(self.fixture.exists())
        self.current_limits = [8 * Q.MIB, 10 * Q.MIB, 0, 0]
        self.mapping['/etc/projects'] = 'c' * 64
        with self.assertRaisesRegex(D.C.Refused, 'quota_mapping_changed'):
            Q.restore(self.ledger, self.request)
        self.assertTrue(self.fixture.exists())

    def test_extra_data_blocks_project_removal_and_limit_reset(self):
        Q.prepare(self.ledger, self.request)
        (self.fixture / 'foreign').touch()
        with self.assertRaisesRegex(D.C.Refused, 'quota_project_changed'):
            Q.restore(self.ledger, self.request)
        self.assertTrue((self.fixture / 'foreign').exists())
        self.assertEqual(len(self.commands), 1)

    def test_removal_response_loss_can_resume_but_unrecorded_disappearance_refuses(self):
        Q.prepare(self.ledger, self.request)
        rp = self.ledger / 'quota-project-root.json'
        record = json.loads(rp.read_text())
        self.fixture.rmdir()
        with self.assertRaisesRegex(D.C.Refused, 'quota_project_missing'):
            Q.restore(self.ledger, self.request)
        record['state'] = 'removing'
        R.save(rp, record)
        self.assertEqual(Q.restore(self.ledger, self.request), {'clean': True, 'verified': True})
        self.assertEqual(self.current_limits, [0, 0, 0, 0])

    def test_wrong_target_or_existing_quota_refuses_before_creation(self):
        with self.assertRaisesRegex(D.C.Refused, 'quota_project_scope'):
            Q.prepare(self.ledger, dict(self.request, target=31001))
        self.current_limits = [8 * Q.MIB, 10 * Q.MIB, 0, 0]
        with self.assertRaisesRegex(D.C.Refused, 'quota_project_in_use'):
            Q.prepare(self.ledger, self.request)
        self.assertFalse(self.fixture.exists())
        self.assertFalse(self.commands)

class DriverTests(T.AdapterTests):

    def test_quota_action_exercises_three_cases_and_cleans_all_denial_clients(self):
        result = self.invoke(self.args + ['quota'])
        self.assertEqual(result['quota'], 'PASS')
        self.assertEqual(result['window'], 'still_owned_and_fenced')
        calls = self.transport.calls
        self.assertEqual(sum((r['operation'] == 'exhaust_bytes' for r in calls)), 2)
        self.assertEqual(sum((r['operation'] == 'exhaust_inodes' for r in calls)), 1)
        self.assertEqual(sum((r['operation'] == 'quota_cleanup_denial' for r in calls)), 9)
        self.assertTrue(all((r['target'] == 39999 for r in calls if r['operation'] == 'prepare_project_quota')))
        self.assertFalse(any((r['operation'] in ('open', 'close', 'release', 'acquire') for r in calls)))
if __name__ == '__main__':
    unittest.main(verbosity=2)

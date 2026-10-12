#!/usr/bin/env python3
"""Unmounted guard regressions; real temporary data, mocked privileged syscalls only."""
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

FILE = Path(__file__).resolve().parents[1] / 'roles/nfs_home/files/prace-nfs-underlay'
loader = importlib.machinery.SourceFileLoader('underlay', str(FILE))
spec = importlib.util.spec_from_loader(loader.name, loader)
m = importlib.util.module_from_spec(spec)
loader.exec_module(m)


class Underlay(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.guard = False
        self.commands = []
        def command(args):
            self.commands.append(args)
            if args[0] == 'lsattr':
                return ('----i--------- ' if self.guard else '-------------- ') + str(self.home) + '\n'
            if args[:2] == ['chattr', '+i']:
                self.guard = True
                return ''
            raise AssertionError(args)
        for name, fn in [('unmounted', lambda p: None), ('directory', lambda p: p.lstat()), ('command', command)]:
            pt = patch.object(m, name, side_effect=fn)
            pt.start()
            self.addCleanup(pt.stop)

    def test_empty_guard_then_idempotent(self):
        self.assertTrue(m.prepare(self.home)['changed'])
        self.assertFalse(m.prepare(self.home)['changed'])
        self.assertTrue(m.prepare(self.home, check=True)['guarded'])

    def test_check_changes_nothing(self):
        with self.assertRaises(m.Refused):
            m.prepare(self.home, check=True)
        self.assertFalse(any(c[0] == 'chattr' for c in self.commands))

    def test_nonempty_refuses_without_preservation(self):
        (self.home / 'sentinel').write_text('keep')
        with self.assertRaises(m.Refused):
            m.prepare(self.home)
        self.assertEqual((self.home / 'sentinel').read_text(), 'keep')
        self.assertFalse(self.guard)

    def test_preserves_data_and_symlinks_without_following(self):
        (self.home / 'sentinel').write_text('keep')
        (self.home / 'link').symlink_to('/not-to-be-followed')
        before = {p.name: m.identity(p) for p in self.home.iterdir()}
        archive = self.root / 'archive'
        m.prepare(self.home, archive)
        self.assertEqual({p.name: m.identity(p) for p in (archive / 'data').iterdir()}, before)
        self.assertEqual((archive / 'data/sentinel').read_text(), 'keep')
        self.assertEqual((archive / 'data/link').readlink(), Path('/not-to-be-followed'))
        self.assertEqual(json.loads((archive / 'receipt.json').read_text())['state'], 'preserved')
        self.assertEqual(list(self.home.iterdir()), [])

    def test_existing_archive_never_overwritten(self):
        (self.home / 'sentinel').write_text('keep')
        a = self.root / 'archive'
        a.mkdir()
        with self.assertRaises(m.Refused):
            m.prepare(self.home, a)
        self.assertTrue((self.home / 'sentinel').exists())

    def test_preservation_ancestry_synced_before_source_move(self):
        (self.home / 'sentinel').write_text('keep')
        archive = self.root / 'archive'
        synced = []
        rename = m.os.rename
        def move(source, destination):
            self.assertIn(archive.parent, synced)
            self.assertIn(archive, synced)
            return rename(source, destination)
        with patch.object(m, 'sync_dir', side_effect=synced.append), patch.object(m.os, 'rename', side_effect=move):
            m.prepare(self.home, archive)

    def test_failed_ancestry_sync_preserves_source(self):
        (self.home / 'sentinel').write_text('keep')
        with patch.object(m, 'sync_dir', side_effect=OSError('injected')), self.assertRaises(OSError):
            m.prepare(self.home, self.root / 'archive')
        self.assertEqual((self.home / 'sentinel').read_text(), 'keep')
        self.assertFalse(self.guard)

    def test_archive_root_parent_is_synced_even_on_retry(self):
        root = self.root / 'preserved'
        with patch.object(m, 'sync_dir') as synced:
            m.archive_root(root)
            m.archive_root(root)
        self.assertEqual(synced.call_count, 2)
        synced.assert_called_with(root.parent)

    def test_failed_listing_never_means_empty(self):
        original = Path.iterdir
        def iterdir(p):
            if p == self.home:
                raise PermissionError('injected')
            return original(p)
        with patch.object(Path, 'iterdir', iterdir), self.assertRaises(PermissionError):
            m.prepare(self.home)
        self.assertFalse(self.guard)

    def test_failed_receipt_never_moves_data(self):
        (self.home / 'sentinel').write_text('keep')
        with patch.object(m, 'save', side_effect=OSError('injected')), self.assertRaises(OSError):
            m.prepare(self.home, self.root / 'archive')
        self.assertEqual((self.home / 'sentinel').read_text(), 'keep')
        self.assertFalse(self.guard)

    def test_chattr_success_without_effect_fails(self):
        with patch.object(m, 'immutable', return_value=False), self.assertRaises(m.Refused):
            m.prepare(self.home)


class Observations(unittest.TestCase):
    def test_mount_errors_and_mounted_state_refuse(self):
        for rc, out, err in [(0, '/home nfs', ''), (1, '', 'permission denied'), (2, '', ''), (1, 'unexpected', '')]:
            with self.subTest(rc=rc,out=out,err=err), patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], rc, out, err)), self.assertRaises(m.Refused):
                m.unmounted(Path('/home'))

    def test_unmounted_exact_empty_exit_one(self):
        with patch.object(m.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', '')):
            m.unmounted(Path('/home'))

    def test_symlink_directory_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'home'
            p.symlink_to(d)
            with self.assertRaises(m.Refused):
                m.directory(p)


if __name__ == '__main__':
    unittest.main()

#!/usr/bin/env python3
"""Hermetic recovery-set fixtures. No fleet, credentials, VM or container."""
import copy
import hashlib
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('recovery_point', TOOLS / 'recovery-point-check.py')
R = importlib.util.module_from_spec(spec); spec.loader.exec_module(R)
HELPER = TOOLS.parent / 'roles/login_storage/files/prace-tree-listing'
REV = 'a' * 40


class PointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.point = self.root / 'point'; self.point.mkdir(mode=0o700)
        self.art = self.point / 'artifacts'; self.art.mkdir(mode=0o700)
        self.window = {'schema': 2, 'id': 'b' * 16, 'label': 'test', 'login': R.C.LOGIN,
                       'phase': 'closed', 'fence_intent': {'active': True},
                       'original': {'partitions': {'cpu': 'UP', 'gpu': 'UP'},
                                    'loginsets': {'slurm-login-prace': {'uid': 'test-login', 'replicas': 1}}},
                       'declared_partitions': {}}
        self.write(self.art / 'slurm-window.json', self.window)
        # Control bytes are checksum-verified here, not extracted or declared
        # restorable. Existing control-archive validation belongs to the restorer.
        (self.art / 'control.tgz').write_bytes(b'synthetic control bytes'); (self.art / 'control.tgz').chmod(0o600)
        # Use actual GNU tar/listing round trips, with explicit fixture-only SELinux
        # exclusion. Production helpers keep all metadata flags and refuse warnings.
        run = R.M._run
        def portable(args):
            if args[0] == 'tar':
                args = [args[0], '--no-selinux', '--xattrs-exclude=security.selinux',
                        *(x for x in args[1:] if x != '--selinux')]
            elif args[:2] == [sys.executable, str(HELPER)]:
                args = [*args[:2], '--no-label', *args[2:]]
            return run(args)
        self.addCleanup(patch.stopall)
        patch.object(R.M, '_run', side_effect=portable).start()
        for key, dest in R.ROOTS.items():
            parent = self.root / ('src-' + key); parent.mkdir(mode=0o700)
            source = parent / Path(dest).name; source.mkdir(mode=0o750)
            (source / 'data').write_bytes(b'fixture\n')
            os.link(source / 'data', source / 'hard')
            (source / 'link').symlink_to('../outside-not-read')
            proof = self.art / (key + '-proof')
            R.M._create_verified_archive(source, self.art / (key + '.tar'), proof, HELPER)
            m = json.loads((proof / 'manifest.json').read_text()); m['source'] = dest
            self.write(proof / 'manifest.json', m)
        self.state = {'schema': 1, 'id': 'c' * 32, 'stage': 'post-w2', 'revision': REV,
                      'workers': R.C.WORKERS, 'login': R.C.LOGIN, 'phase': 'complete',
                      'accepted': True, 'intent': None, 'max_data_bytes': 2 * R.C.GIB,
                      'tool_hashes': {'prace-tree-listing': R.C.digest(HELPER),
                         'prace_metadata_archive.py': R.C.digest(TOOLS / 'prace_metadata_archive.py')},
                      'window_record': self.window, 'window': R.C.WINDOW.normalize(self.window)}
        self.refresh()

    def write(self, path, value):
        R.C.atomic_json(path, value)

    def refresh(self):
        self.state['manifest'] = {'complete': True, 'id': self.state['id'], 'stage': 'post-w2', 'artifacts': [
            {'path': str(p.relative_to(self.art)), 'size': p.stat().st_size, 'sha256': R.C.digest(p)}
            for p in sorted(self.art.rglob('*')) if p.is_file()]}
        self.write(self.point / 'run.json', self.state)

    def check(self):
        return R.verify(self.point, REV, HELPER)

    def test_complete_four_roots_preserves_scope_without_claiming_restore(self):
        result = self.check()
        self.assertTrue(result['bundle_verified']); self.assertFalse(result['full_restore_qualified'])
        self.assertFalse(result['data_extraction_verified']); self.assertEqual(len(result['roots']), 4)
        self.assertEqual(result['logical_bytes'], 4 * 8)  # hardlinks counted once
        self.assertEqual(len(self.state['manifest']['artifacts']), 26)

    def test_incomplete_accepted_or_wrong_revision_refused(self):
        for field, bad in (('accepted', False), ('accepted', 1), ('phase', 'recovered-fenced'),
                           ('stage', 'pre-w1'), ('intent', 'capture'), ('revision', 'd' * 40)):
            with self.subTest(field=field, bad=bad):
                old = self.state[field]; self.state[field] = bad
                self.write(self.point / 'run.json', self.state)
                with self.assertRaises((R.Refused, R.C.CaptureError)): self.check()
                self.state[field] = old

    def test_hash_modified_copy_and_symlink_refused(self):
        p = self.art / 'home.tar'; data = p.read_bytes(); p.write_bytes(data + b'x')
        with self.assertRaises(R.C.CaptureError): self.check()
        p.unlink(); target = self.root / 'outside'; target.write_bytes(data); target.chmod(0o600); p.symlink_to(target)
        with self.assertRaises(R.C.CaptureError): self.check()

    def test_missing_proof_cannot_be_hidden_by_rewriting_manifest(self):
        (self.art / 'home-proof/extracted.jsonl').unlink(); self.refresh()
        with self.assertRaisesRegex(R.Refused, 'exact_artifact'): self.check()

    def test_changed_proof_cannot_pass_with_valid_file_hashes(self):
        p = self.art / 'home-proof/source-after.jsonl'; p.write_bytes(b'changed')
        self.refresh()
        with self.assertRaisesRegex(R.Refused, 'proofs_differ'): self.check()

    def test_proof_manifest_fields_checked(self):
        p = self.art / 'home-proof/manifest.json'; old = json.loads(p.read_text())
        for field, bad in (('source', '/wrong'), ('archive_sha256', '0'*64), ('logical_bytes', 1),
                           ('entries', 100), ('listing_sha256', '0'*64), ('helper_sha256', '0'*64)):
            with self.subTest(field=field):
                self.write(p, dict(old, **{field: bad})); self.refresh()
                with self.assertRaisesRegex(R.Refused, 'proof_manifest'): self.check()

    def test_aggregate_limit_and_helper_provenance_required(self):
        for field, bad in (('max_data_bytes', 31), ('max_data_bytes', True), ('max_data_bytes', 3 * R.C.GIB),
                           ('tool_hashes', dict(self.state['tool_hashes'], **{'prace-tree-listing': '0'*64}))):
            with self.subTest(field=field):
                old = self.state[field]; self.state[field] = bad; self.write(self.point / 'run.json', self.state)
                with self.assertRaises((R.Refused, R.C.CaptureError)): self.check()
                self.state[field] = old

    def test_private_record_and_artifacts_required(self):
        for p in (self.point / 'run.json', self.art / 'home.tar'):
            p.chmod(0o644)
            with self.assertRaises((R.Refused, R.C.CaptureError)): self.check()
            p.chmod(0o600)

    def test_borrowed_window_copy_must_match(self):
        value = copy.deepcopy(self.window); value['original']['partitions']['cpu'] = 'DRAIN'
        self.write(self.art / 'slurm-window.json', value); self.refresh()
        with self.assertRaises(R.C.CaptureError): self.check()

    def root_fixture(self):
        # Only the explicit public root gate is simulated. Real tar extraction and
        # metadata comparison run as the current UID; no host state is changed.
        return patch.object(R, 'require_root')

    def test_extraction_four_roots_and_no_overwrite(self):
        out = self.root / 'extract'
        with self.root_fixture(), patch.object(R.M, 'verify_extract', side_effect=R.M._verify_extract):
            result = R.extract(self.point, REV, HELPER, out)
            self.assertTrue(result['data_extraction_verified']); self.assertFalse(result['full_restore_qualified'])
            for key, source in R.ROOTS.items():
                self.assertEqual((out / key / Path(source).name / 'data').read_bytes(), b'fixture\n')
            with self.assertRaisesRegex(R.Refused, 'fresh_destination'): R.extract(self.point, REV, HELPER, out)

    def test_extraction_failure_retains_incomplete_record(self):
        out = self.root / 'extract'
        with self.root_fixture(), patch.object(R.M, 'verify_extract', side_effect=R.M.ArchiveError('failure')):
            with self.assertRaises(R.M.ArchiveError): R.extract(self.point, REV, HELPER, out)
        saved = json.loads((out / 'qualification.json').read_text())
        self.assertEqual(saved['phase'], 'incomplete'); self.assertFalse(saved['data_extraction_verified'])

    def test_cli_no_network_or_diagnostics_leak_and_report_exclusive(self):
        report = self.root / 'report.json'
        args = ['verify', '--point', str(self.point), '--revision', REV, '--record-sha256', R.C.digest(self.point / 'run.json'), '--listing-helper', str(HELPER), '--report', str(report)]
        with patch.object(R.C.SSHRemote, '__init__', side_effect=AssertionError('no SSH')):
            self.assertEqual(R.main(args), 0); self.assertEqual(R.main(args), 1)
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)
        self.assertFalse(json.loads(report.read_text())['full_restore_qualified'])

    def cli_args(self):
        return ['verify', '--point', str(self.point), '--revision', REV,
                '--record-sha256', R.C.digest(self.point / 'run.json'),
                '--listing-helper', str(HELPER)]

    def frozen_copy(self):
        module = self.root / 'frozen_metadata.py'
        module.write_bytes((TOOLS / 'prace_metadata_archive.py').read_bytes() + b'\n# frozen fixture\n')
        module.chmod(0o600)
        self.state['tool_hashes']['prace_metadata_archive.py'] = R.C.digest(module)
        self.refresh()
        return module

    def test_explicit_frozen_helper_supports_older_capture_and_restores_globals(self):
        module = self.frozen_copy()
        prior = R.M
        self.assertEqual(R.main(self.cli_args()), 1)
        self.assertEqual(R.main(self.cli_args() + ['--metadata-helper', str(module)]), 0)
        self.assertIs(R.M, prior)
        self.assertEqual(R.main(self.cli_args()), 1)

    def test_wrong_helper_never_executes_and_wrong_record_precedes_helper(self):
        module = self.frozen_copy()
        marker = self.root / 'executed'
        module.write_text('from pathlib import Path\nPath(%r).touch()\n' % str(marker))
        self.assertEqual(R.main(self.cli_args() + ['--metadata-helper', str(module)]), 1)
        self.assertFalse(marker.exists())
        self.state['tool_hashes']['prace_metadata_archive.py'] = R.C.digest(module)
        self.refresh()
        args = self.cli_args()
        args[args.index('--record-sha256') + 1] = '0' * 64
        self.assertEqual(R.main(args + ['--metadata-helper', str(module)]), 1)
        self.assertFalse(marker.exists())

    def test_unsafe_helper_locations_and_permissions_refused(self):
        module = self.frozen_copy()
        inside = self.point / 'metadata.py'; inside.write_bytes(module.read_bytes()); inside.chmod(0o600)
        link = self.root / 'link.py'; link.symlink_to(module)
        for path in (inside, link):
            with self.subTest(path=path):
                self.assertEqual(R.main(self.cli_args() + ['--metadata-helper', str(path)]), 1)
        module.chmod(0o666)
        self.assertEqual(R.main(self.cli_args() + ['--metadata-helper', str(module)]), 1)

    def test_frozen_helper_changes_after_load_are_refused(self):
        module = self.frozen_copy()
        prior = R.M
        with R.frozen_metadata(module, self.point, R.C.digest(self.point / 'run.json')):
            module.write_bytes(module.read_bytes() + b'\n# changed\n')
            with self.assertRaisesRegex(R.Refused, 'metadata_helper_hash_mismatch'):
                self.check()
        self.assertIs(R.M, prior)

    def test_record_replacement_before_module_load_is_refused(self):
        module = self.frozen_copy()
        record_digest = R.C.digest(self.point / 'run.json')
        marker = self.root / 'executed'
        module.write_text('from pathlib import Path\nPath(%r).touch()\n' % str(marker))
        self.state['tool_hashes']['prace_metadata_archive.py'] = R.C.digest(module)
        self.refresh()
        with self.assertRaisesRegex(R.Refused, 'handover_record_hash_mismatch'):
            with R.frozen_metadata(module, self.point, record_digest):
                self.fail('replacement record must not be accepted')
        self.assertFalse(marker.exists())

    def test_malformed_json_object_refuses_without_traceback(self):
        for value in ([], None, 'private sentinel'):
            with self.subTest(value=value):
                self.write(self.point / 'run.json', value)
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    self.assertEqual(R.main(self.cli_args()), 1)
                self.assertNotIn('Traceback', err.getvalue())
                self.assertNotIn('private sentinel', err.getvalue())


if __name__ == '__main__':
    unittest.main()

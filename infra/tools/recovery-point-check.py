#!/usr/bin/env python3
"""Offline verification of a complete Session A PAX recovery set.

No SSH, service changes or live extraction. The default verifies private copies,
proof completeness and the explicitly supplied frozen metadata helpers. Extract
mode verifies four roots in NEW private directories; it never installs them on
mountpoints or claims a control/accounting restore. Keep all reports private.
"""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import types

TOOLS = Path(__file__).resolve().parent
ROOTS = {'home': '/home', 'local-home': '/var/lib/prace-local-home',
         'projects': '/projects', 'apps': '/apps'}
PROOFS = ('manifest.json', 'source-before.jsonl', 'source-after.jsonl',
          'source-scope.json', 'extracted.jsonl')
MAX_JSON = 16 * 1024 * 1024


class Refused(RuntimeError):
    pass


def require(ok, code):
    if not ok:
        raise Refused(code)


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


C = load_module('point_capture', TOOLS / 'session-a-capture.py')
METADATA_PATH = TOOLS / 'prace_metadata_archive.py'
M = load_module('point_metadata', METADATA_PATH)
N = C.native_module()


def private_file(path, limit=None):
    st = path.lstat()
    require(path.is_absolute() and path.resolve() == path and stat.S_ISREG(st.st_mode)
            and st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o600,
            'private_regular_file_required')
    require(limit is None or st.st_size <= limit, 'record_too_large')
    return st


def read_json(path):
    private_file(path, MAX_JSON)
    value = json.loads(path.read_text())
    require(isinstance(value, dict), 'json_object_required')
    return value


@contextmanager
def frozen_metadata(path, directory, record_sha256):
    """CLI-only, after the trusted run-record digest has been checked.

    Execute only the exact reviewed source bytes named by capture provenance,
    never a helper bundled inside a recovery point. Restore globals on exit so
    repeated CLI invocations in tests do not inherit a prior selection.
    """
    global M, METADATA_PATH
    if path is None:
        yield
        return
    path, directory = Path(path), Path(directory)
    st = path.lstat()
    require(path.is_absolute() and path.resolve() == path and stat.S_ISREG(st.st_mode)
            and st.st_uid in (0, os.geteuid()) and not st.st_mode & 0o022
            and directory.resolve() not in path.parents,
            'trusted_metadata_helper_required')
    data = path.read_bytes()
    private_file(directory / 'run.json', MAX_JSON)
    record_bytes = (directory / 'run.json').read_bytes()
    require(hashlib.sha256(record_bytes).hexdigest() == record_sha256,
            'handover_record_hash_mismatch')
    state = json.loads(record_bytes)
    require(isinstance(state, dict) and isinstance(state.get('tool_hashes'), dict)
            and state['tool_hashes'].get('prace_metadata_archive.py') == hashlib.sha256(data).hexdigest(),
            'metadata_helper_hash_mismatch')
    old_module, old_path = M, METADATA_PATH
    module = types.ModuleType('frozen_point_metadata')
    module.__file__ = str(path)
    # Compile the bytes just checked, avoiding a second import-time file read.
    exec(compile(data, str(path), 'exec'), module.__dict__)
    M, METADATA_PATH = module, path
    try:
        yield
    except module.ArchiveError:
        raise Refused('frozen_metadata_operation_refused') from None
    finally:
        M, METADATA_PATH = old_module, old_path


def verify(directory, revision, helper):
    directory, helper = Path(directory), Path(helper)
    require(re.fullmatch('[0-9a-f]{40}', revision or '') is not None, 'full_source_revision_required')
    state = read_json(directory / 'run.json')
    require(state.get('accepted') is True and state.get('phase') == 'complete'
            and state.get('stage') == 'post-w2' and state.get('intent') is None,
            'accepted_complete_post_w2_required')
    require(state.get('revision') == revision, 'source_revision_mismatch')
    # Uses the capture driver's existing complete-manifest, private-file, digest
    # and borrowed-window checks. Constructing Run and verify_copies are local.
    run = C.Run(directory, remote=None)
    run.verify_copies()
    require('window' in state and 'window_record' in state, 'shared_window_record_required')
    require(type(state.get('max_data_bytes')) is int and 0 <= state['max_data_bytes'] <= 2 * C.GIB,
            'bounded_data_scope_required')
    require(helper.is_absolute() and helper.resolve() == helper and helper.is_file()
            and not helper.is_symlink(), 'trusted_listing_helper_required')
    # Do not execute helper code obtained from an archive. The reviewer supplies
    # a source checkout; its bytes must match the recorded capture provenance.
    require(state['tool_hashes'].get('prace-tree-listing') == C.digest(helper), 'listing_helper_hash_mismatch')
    require(state['tool_hashes'].get('prace_metadata_archive.py') == C.digest(METADATA_PATH),
            'metadata_helper_hash_mismatch')
    inventory = {a['path']: a for a in state['manifest']['artifacts']}
    wanted = {'control.tgz', 'slurm-window.json'}
    if 'native' in state:
        wanted |= {'native-repo.tar', 'native-repo.json'}
        for name in ('prace_native_capture.py', 'prace_native_repo.py'):
            require(state['tool_hashes'].get(name) == C.digest(TOOLS / name), 'native_helper_hash_mismatch')
        N.verify(directory, state)
    for key in ROOTS:
        wanted.add(key + '.tar')
        wanted.update(key + '-proof/' + p for p in PROOFS)
    require(set(inventory) == wanted, 'complete_exact_artifact_set_required')
    total = 0
    checked = {}
    for key, source in ROOTS.items():
        archive = directory / 'artifacts' / (key + '.tar')
        proof = directory / 'artifacts' / (key + '-proof')
        manifest = read_json(proof / 'manifest.json')
        scan = read_json(proof / 'source-scope.json')
        before = (proof / 'source-before.jsonl').read_bytes()
        require(before and before == (proof / 'source-after.jsonl').read_bytes()
                and before == (proof / 'extracted.jsonl').read_bytes(), 'capture_metadata_proofs_differ')
        require(isinstance(scan, dict) and set(scan) == {'entries', 'logical_bytes', 'hardlink_groups'}
                and type(scan['entries']) is int and 1 <= scan['entries'] <= M.MAX_ENTRIES
                and type(scan['logical_bytes']) is int and scan['logical_bytes'] >= 0
                and isinstance(scan['hardlink_groups'], list), 'invalid_source_scope')
        total += scan['logical_bytes']
        require(total <= state['max_data_bytes'], 'aggregate_logical_limit_exceeded')
        require(manifest.get('schema') == 1 and manifest.get('source') == source
                and manifest.get('archive_sha256') == inventory[key + '.tar']['sha256']
                and manifest.get('archive_bytes') == inventory[key + '.tar']['size']
                and manifest.get('logical_bytes') == scan['logical_bytes']
                and manifest.get('entries') == scan['entries']
                and manifest.get('listing_sha256') == hashlib.sha256(before).hexdigest()
                and manifest.get('hardlink_groups_sha256') == hashlib.sha256(M._json_bytes(scan['hardlink_groups'])).hexdigest()
                and manifest.get('helper_sha256') == C.digest(helper), 'proof_manifest_mismatch')
        require(M.validate_archive(archive, scan['logical_bytes']) == Path(source).name,
                'archive_root_mismatch')
        checked[key] = {'source': source, 'logical_bytes': scan['logical_bytes'],
                        'archive_sha256': inventory[key + '.tar']['sha256']}
    # Re-hash after parsing; the private bundle must remain immutable throughout.
    run.verify_copies()
    require(read_json(directory / 'run.json') == state, 'point_record_changed')
    return {'schema': 1, 'capture_id': state['id'], 'execution_revision': revision,
            'manifest_sha256': hashlib.sha256(M._json_bytes(state['manifest'])).hexdigest(),
            'logical_bytes': total, 'roots': checked, 'bundle_verified': True,
            'native_bundle_verified': 'native' in state,
            'native_repo_bytes': (read_json(directory / 'artifacts/native-repo.json')['logical_bytes']
                                  if 'native' in state else 0),
            'data_extraction_verified': False, 'full_restore_qualified': False}


def require_root():
    require(os.geteuid() == 0, 'extraction_requires_root')


def extract(directory, revision, helper, destination):
    """Only staging: never merge into an existing directory, relabel, or deploy."""
    require_root()
    report = verify(directory, revision, helper)
    destination = Path(destination)
    require(destination.is_absolute() and destination.parent.resolve() == destination.parent,
            'canonical_destination_required')
    C.private_dir(destination.parent)
    require(not destination.exists() and not destination.is_symlink(), 'fresh_destination_required')
    require(not (directory == destination or directory in destination.parents
                 or destination in directory.parents), 'destination_overlaps_point')
    free = os.statvfs(destination.parent)
    require(free.f_bavail * free.f_frsize >= report['logical_bytes'] * 3 + report['native_repo_bytes'] * 2 + C.GIB,
            'insufficient_extraction_space')
    destination.mkdir(mode=0o700)
    C.atomic_json(destination / 'qualification.json', dict(report, phase='extracting'))
    try:
        for key in ROOTS:
            # Revalidate every copied artifact before each extraction operation.
            verify(directory, revision, helper)
            proof = directory / 'artifacts' / (key + '-proof')
            M.verify_extract(directory / 'artifacts' / (key + '.tar'), destination / key, helper,
                             (proof / 'source-before.jsonl').read_bytes(),
                             read_json(proof / 'source-scope.json'), report['roots'][key]['logical_bytes'])
        verify(directory, revision, helper)
        if report['native_bundle_verified']:
            N.REPO.extract(directory / 'artifacts/native-repo.tar',
                           read_json(directory / 'artifacts/native-repo.json'), destination / 'fleet-repo')
            verify(directory, revision, helper)
        report.update(data_extraction_verified=True, phase='data-extracted')
        C.atomic_json(destination / 'qualification.json', report)
    except BaseException:
        # Retain partial trees/record for diagnosis. No removal or pass on failure.
        C.atomic_json(destination / 'qualification.json', dict(report, phase='incomplete'))
        raise
    return report


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['verify', 'extract'])
    p.add_argument('--point', type=Path, required=True)
    p.add_argument('--revision', required=True)
    p.add_argument('--record-sha256', required=True, help='run.json digest from the trusted handover')
    p.add_argument('--listing-helper', type=Path, required=True)
    p.add_argument('--metadata-helper', type=Path,
                   help='reviewed metadata module from the frozen capture checkout')
    p.add_argument('--report', type=Path)
    p.add_argument('--destination', type=Path)
    p.add_argument('--native-observation', type=Path, help='verified post-restore observation to compare with the integrated native record')
    p.add_argument('--isolated-target', action='store_true')
    p.add_argument('--declared-difference', action='append', default=[])
    p.add_argument('--migration-revision')
    a = p.parse_args(argv)
    try:
        private_file(a.point / 'run.json', MAX_JSON)
        require(re.fullmatch('[0-9a-f]{64}', a.record_sha256 or '') and
                C.digest(a.point / 'run.json') == a.record_sha256, 'handover_record_hash_mismatch')
        require((a.action == 'extract') == (a.destination is not None), 'destination_only_for_extract')
        require(a.report is None or (a.report.is_absolute() and a.report.parent.resolve() == a.report.parent
                and not a.report.exists() and not a.report.is_symlink()), 'fresh_report_required')
        if a.report is not None:
            C.private_dir(a.report.parent)
        with frozen_metadata(a.metadata_helper, a.point, a.record_sha256):
            result = (extract(a.point, a.revision, a.listing_helper, a.destination) if a.action == 'extract'
                      else verify(a.point, a.revision, a.listing_helper))
            if a.native_observation is not None:
                require(a.action == 'verify' and result['native_bundle_verified'], 'native_compare_scope')
                state = read_json(a.point / 'run.json')
                require(state['tool_hashes'].get('native-state-record.py') == C.digest(TOOLS / 'native-state-record.py'),
                        'native_recorder_hash_mismatch')
                comparison = N.compare_restored(a.point, state, read_json(a.native_observation),
                    isolated=a.isolated_target, declared=a.declared_difference, migration_revision=a.migration_revision)
                require(all(c['ok'] for c in comparison.values()), 'native_restore_comparison_failed')
                result['native_comparison'] = comparison
                require(C.digest(a.point / 'run.json') == a.record_sha256, 'point_record_changed')
            elif a.isolated_target or a.declared_difference or a.migration_revision:
                raise Refused('native_comparison_required')
            if a.report is not None:
                M._private_write(a.report, M._json_bytes(result))
    except (Refused, C.CaptureError, M.ArchiveError, N.Refused, N.REPO.Refused, OSError, ValueError, KeyError, TypeError, tarfile.TarError):
        # Source file names, xattrs and control archives can contain credentials.
        # Never echo exception details, file contents or subprocess output.
        print('RECOVERY POINT: REFUSED; no full restore has been qualified', file=sys.stderr)
        return 1
    print('RECOVERY POINT: ' + ('data extraction verified' if result['data_extraction_verified'] else 'bundle verified')
          + '; full restore NOT qualified')
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Bounded quota RPCs for the already-owned storage window; no standalone CLI.

R supplies the reviewed storage boundary, command/receipt/user primitives. All
paths and identities are fixed synthetic fixtures. Production project mappings
and user limits are never changed. Uncertain creation/deletion remains recorded.
"""
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import time
R = None
OPS = {'quota_snapshot', 'prepare_project_quota', 'restore_project_quota', 'exhaust_bytes', 'exhaust_inodes', 'quota_denial', 'quota_cleanup_denial', 'quota_remove_fixture'}
PROJECT_ID = 39999
UID = 30091
MIB = 1024 * 1024
PROBE_SECONDS = 60
FSGET = 0x801C581F  # FS_IOC_FSGETXATTR, struct fsxattr (28 bytes)
FSSET = 0x401C5820  # FS_IOC_FSSETXATTR
INHERIT = 0x200


def require(value, code):
    R.require(value, code)


def key_for(request):
    kind = request.get('kind')
    require(kind in ('user', 'project'), 'quota_kind')
    return kind


def quota_report(text):
    result = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        fields = re.sub('\\[[^\\]]*\\]', '', line).split()
        require(len(fields) == 9 and re.fullmatch('#\\d+', fields[0]) and all((re.fullmatch('\\d+', value) for value in fields[1:])), 'quota_report')
        number = int(fields[0][1:])
        require(number not in result, 'quota_report_duplicate')
        values = list(map(int, fields[1:]))
        result[number] = {'used_bytes': values[0] * 1024, 'used_inodes': values[4], 'limits': [values[1] * 1024, values[2] * 1024, values[5], values[6]]}
    require(bool(result), 'quota_report_empty')
    return result


def mappings():
    hashes, mapped = ({}, False)
    for filename, id_column in (('/etc/projects', 0), ('/etc/projid', 1)):
        path = Path(filename)
        require(path.resolve() == path, 'quota_mapping_path')
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and (not info.st_mode & 0o022), 'quota_mapping_identity')
        data = path.read_bytes()
        require(len(data) <= 1024 * 1024, 'quota_mapping_size')
        hashes[filename] = hashlib.sha256(data).hexdigest()
        for line in data.decode().splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            fields = line.split(':')
            require(len(fields) == 2 and fields[id_column].isdigit(), 'quota_mapping_format')
            mapped |= int(fields[id_column]) == PROJECT_ID
    return (hashes, mapped)


def snapshot(kind):
    path, flag, target = ('/home', 'u', UID) if kind == 'user' else ('/projects', 'p', PROJECT_ID)
    reports = quota_report(R.command(['xfs_quota', '-x', '-c', f'report -{flag} -n -N -b -i', path]))
    if kind == 'user':
        require(target in reports, 'quota_user_absent')
    row = dict(reports.get(target, {'used_bytes': 0, 'used_inodes': 0, 'limits': [0, 0, 0, 0]}))
    fs = os.statvfs(path)
    row.update(filesystem_free_bytes=fs.f_bavail * fs.f_frsize, filesystem_free_inodes=fs.f_favail)
    if kind == 'project':
        row['mapping_hashes'], row['mapped'] = mappings()
    return row


def tag(path, project=None):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        buf = bytearray(fcntl.ioctl(fd, FSGET, bytes(28)))
        flags, extent, nextents, current = struct.unpack('IIII', buf[:16])
        if project is not None:
            require(current == 0 and (not flags & INHERIT), 'temporary_project_parent_tag')
            struct.pack_into('IIII', buf, 0, flags | INHERIT, extent, nextents, project)
            fcntl.ioctl(fd, FSSET, buf)
            buf = bytearray(fcntl.ioctl(fd, FSGET, bytes(28)))
            flags, _, _, current = struct.unpack('IIII', buf[:16])
        return (current, bool(flags & INHERIT))
    finally:
        os.close(fd)


def project_path(run):
    require(re.fullmatch('[a-f0-9]{32}', run), 'quota_run')
    path = Path('/projects') / ('.prace-quota-' + run + '-project')
    require(path.parent.resolve() == path.parent, 'quota_parent')
    return path


def fixture_path(request, denial=False):
    kind = key_for(request)
    inode = request.get('inodes', request['operation'] == 'exhaust_inodes')
    require(type(inode) is bool and (kind != 'project' or not inode), 'quota_fixture_scope')
    run = request['run_id']
    require(re.fullmatch('[a-f0-9]{32}', run), 'quota_run')
    parent = Path('/home/syn-probe') if kind == 'user' else project_path(run)
    require(parent.resolve() == parent, 'quota_parent')
    suffix = 'inodes' if inode else 'bytes'
    if denial:
        require(request['host'] in R.A.CLIENTS, 'quota_denial_host')
        suffix += '-denial-' + request['host']
    return (parent / ('.prace-quota-' + run + '-' + suffix), inode)


def receipt_path(directory, request, denial=False):
    kind = key_for(request)
    _, inode = fixture_path(request, denial)
    return directory / ('quota-' + kind + ('-inodes' if inode else '-bytes') + ('-denial' if denial else '') + '.json')


def limits(values):
    require(values in ([0, 0, 0, 0], [8 * MIB, 10 * MIB, 0, 0]), 'quota_limit_scope')
    R.command(['xfs_quota', '-x', '-c', f'limit -p bsoft={values[0] // 1024}k bhard={values[1] // 1024}k isoft={values[2]} ihard={values[3]} {PROJECT_ID}', '/projects'])
    require(snapshot('project')['limits'] == values, 'quota_limit_readback')


def prepare(directory, request):
    require(request['host'] == R.A.SERVER and request.get('target') == PROJECT_ID and (request.get('limits') == [8 * MIB, 10 * MIB, 0, 0]), 'quota_project_scope')
    before = snapshot('project')
    require(all((before[k] == request['original'][k] for k in ('used_bytes', 'used_inodes', 'limits', 'mapped', 'mapping_hashes'))) and before['limits'] == [0, 0, 0, 0] and (before['used_bytes'] == before['used_inodes'] == 0) and (before['mapped'] is False), 'quota_project_in_use')
    path = project_path(request['run_id'])
    rp = directory / 'quota-project-root.json'
    require(not rp.exists() and (not path.exists()) and (not path.is_symlink()), 'quota_fixture_exists')
    rec = {'quota': True, 'path': str(path), 'state': 'intent', 'root': None, 'original': before, 'creator': 'syn-alice', 'files': {}, 'project_root': True}
    R.save(rp, rec)
    path.mkdir(mode=0o700)
    rec['root'] = R.object_id(path)
    R.save(rp, rec)
    require(tag(path, PROJECT_ID) == (PROJECT_ID, True), 'quota_project_tag')
    os.chown(path, 30001, 30001)
    rec['root'] = R.object_id(path)
    R.save(rp, rec)
    R.C.syncdir(path.parent)
    limits(request['limits'])
    require(mappings() == (before['mapping_hashes'], False), 'quota_mapping_changed')
    rec['state'] = 'prepared'
    R.save(rp, rec)
    return {'project_id': PROJECT_ID, 'inherit': True, 'receipt': {'kind': 'project', 'root': rec['root']}}


def restore(directory, request):
    require(request['host'] == R.A.SERVER and request.get('target') == PROJECT_ID, 'quota_project_scope')
    rp = directory / 'quota-project-root.json'
    rec = R.C.load_json(rp)
    path = project_path(request['run_id'])
    require(rec.get('quota') is True and rec['original'] == request['original'] and (rec['path'] == str(path)) and (rec['root'] is not None), 'quota_receipt_unknown')
    require(mappings() == (rec['original']['mapping_hashes'], False), 'quota_mapping_changed')
    current = snapshot('project')
    require(current['limits'] in ([0, 0, 0, 0], [8 * MIB, 10 * MIB, 0, 0]), 'quota_limits_foreign')
    if path.exists() or path.is_symlink():
        require(R.object_id(path) == rec['root'] and tag(path) == (PROJECT_ID, True) and (not list(path.iterdir())), 'quota_project_changed')
        rec['state'] = 'removing'
        R.save(rp, rec)
        path.rmdir()
        R.C.syncdir(path.parent)
    else:
        require(rec['state'] in ('removing', 'limits-restoring', 'clean'), 'quota_project_missing')
    rec['state'] = 'limits-restoring'
    R.save(rp, rec)
    current = settle_snapshot('project', rec['original'], compare_limits=False)
    require(current['used_bytes'] == current['used_inodes'] == 0, 'quota_project_usage_remains')
    limits(rec['original']['limits'])
    settle_snapshot('project', rec['original'])
    rec['state'] = 'clean'
    R.save(rp, rec)
    return {'clean': True, 'verified': True}


def settle_snapshot(kind, expected, compare_limits=True):
    keys = ('used_bytes', 'used_inodes', 'limits') if compare_limits else ('used_bytes', 'used_inodes')
    for attempt in range(12):
        current = snapshot(kind)
        if all((current[k] == expected[k] for k in keys)):
            return current
        time.sleep(0.25)
    require(False, 'quota_usage_not_restored')


def io_probe(directory, request, denial=False):
    require(request['host'] in R.A.CLIENTS and (denial or request['host'] == R.A.CLIENTS[0]), 'quota_writer_host')
    kind = key_for(request)
    user = 'syn-probe' if kind == 'user' else 'syn-alice'
    require(request.get('user') == user, 'quota_user_scope')
    path, inodes = fixture_path(request, denial)
    rp = receipt_path(directory, request, denial)
    cap = 1 if denial else 2100 if inodes else 272 * MIB if kind == 'user' else 12 * MIB
    if not denial:
        require(request.get('cap') == cap and request.get('seconds') == PROBE_SECONDS, 'quota_bound')
    require(not rp.exists(), 'quota_fixture_exists')
    with R.as_user(user):
        require(not exists(path), 'quota_fixture_exists')
    rec = {'quota': True, 'path': str(path), 'state': 'intent', 'root': None, 'files': {}, 'creator': user, 'inode_fixture': inodes and (not denial), 'denial': denial, 'kind': kind}
    R.save(rp, rec)
    count, stopped, fd = (0, None, None)
    timed_out = False
    deadline = time.monotonic() + PROBE_SECONDS
    try:
        with R.as_user(user):
            if inodes and (not denial):
                path.mkdir(mode=0o700)
            else:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with R.as_user(user):
            rec['root'] = R.object_id(path)
        R.save(rp, rec)
        if inodes and (not denial):
            for i in range(cap):
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                target = path / str(i)
                with R.as_user(user):
                    f = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                    os.close(f)
                with R.as_user(user):
                    rec['files'][str(i)] = R.object_id(target)
                R.save(rp, rec)
                count += 1
        elif not inodes:
            while count < cap:
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                with R.as_user(user):
                    n = os.write(fd, b'X' * min(MIB, cap - count))
                    require(n > 0, 'quota_short_write')
                    count += n
                    os.fsync(fd)
        else:
            count = 1
    except OSError as exc:
        if exc.errno not in (errno.EDQUOT, errno.ENOSPC):
            raise
        stopped = exc.errno
    finally:
        if fd is not None:
            # NFS can report deferred writeback errors at close. Never retry
            # close: Linux may already have released the descriptor. A quota
            # error is corroborated by the server later; other errors remain
            # failures with an explicit receipt, never successful exhaustion.
            try:
                os.close(fd)
            except OSError as exc:
                rec['close_errno'] = exc.errno
                R.save(rp, rec)
                if exc.errno not in (errno.EDQUOT, errno.ENOSPC):
                    raise
                stopped = exc.errno
    rec.update(state='complete', errno=stopped, count=count, timed_out=timed_out)
    R.save(rp, rec)
    result = {'errno': stopped, 'timed_out': timed_out, 'created' if inodes else 'written': count, 'receipt': {'kind': kind, 'root': rec['root']}}
    return result


def exists(path):
    try:
        path.lstat()
        return True
    except FileNotFoundError:
        return False


def cleanup_io(directory, request, denial=False):
    path, inodes = fixture_path(request, denial)
    rp = receipt_path(directory, request, denial)
    user = 'syn-probe' if key_for(request) == 'user' else 'syn-alice'
    if not rp.exists():
        with R.as_user(user):
            require(denial and (not exists(path)), 'quota_receipt_missing')
        return {'clean': True, 'verified': True}
    rec = R.C.load_json(rp)
    require(rec.get('quota') is True and rec['path'] == str(path) and (rec['creator'] == user) and (rec['state'] in ('complete', 'removing', 'clean')), 'quota_receipt_unknown')
    with R.as_user(user):
        present = exists(path)
        if present:
            require(rec['root'] is not None and R.object_id(path) == rec['root'], 'quota_fixture_changed')
            if rec['inode_fixture']:
                entries = list(path.iterdir())
                require({e.name for e in entries} <= set(rec['files']), 'quota_unknown_entry')
                for e in entries:
                    require(R.object_id(e) == rec['files'][e.name] and e.lstat().st_nlink == 1 and (e.lstat().st_size == 0), 'quota_fixture_changed')
            else:
                require(path.lstat().st_nlink == 1 and stat.S_ISREG(path.lstat().st_mode), 'quota_fixture_changed')
    if present:
        rec['state'] = 'removing'
        R.save(rp, rec)
        with R.as_user(user):
            if rec['inode_fixture']:
                for e in entries:
                    e.unlink()
                path.rmdir()
            else:
                path.unlink()
    else:
        require(rec['state'] in ('removing', 'clean') or (rec['root'] is None and rec.get('errno') in (errno.EDQUOT, errno.ENOSPC)), 'quota_fixture_missing')
    with R.as_user(user):
        R.C.syncdir(path.parent)
        require(not exists(path), 'quota_cleanup_unverified')
    rec['state'] = 'clean'
    R.save(rp, rec)
    return {'clean': True, 'verified': True}


def clean_record(record):
    require(record.get('quota') is True, 'quota_receipt')
    if record.get('state') != 'clean':
        return False
    path = Path(record['path'])
    require(path.is_absolute() and path.parent.resolve() == path.parent, 'quota_receipt_path')
    with R.as_user(record['creator']):
        try:
            path.lstat()
        except FileNotFoundError:
            return True
    return False


def dispatch(directory, request):
    op = request['operation']
    if op == 'quota_snapshot':
        kind = key_for(request)
        require(request['host'] == R.A.SERVER and request.get('target') == (UID if kind == 'user' else PROJECT_ID), 'quota_scope')
        return snapshot(kind)
    if op == 'prepare_project_quota':
        return prepare(directory, request)
    if op == 'restore_project_quota':
        return restore(directory, request)
    if op in ('exhaust_bytes', 'exhaust_inodes', 'quota_denial'):
        return io_probe(directory, request, op == 'quota_denial')
    if op in ('quota_remove_fixture', 'quota_cleanup_denial'):
        return cleanup_io(directory, request, op == 'quota_cleanup_denial')
    require(False, 'quota_operation')

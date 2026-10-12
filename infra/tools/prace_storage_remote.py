#!/usr/bin/env python3
"""Private basic-storage RPC; injected C (capture primitives) and A (core).

No acquisition, fence mutation, host-namespace unmounts, service operations or
closure. The bundled quota adapter can set only temporary project 39999 limits;
user limits and production project mappings are never changed. Worker underlays use the bundled private namespace only.
Every fixture/preparation has a private durable record. Unknown ownership
refuses cleanup; interruption never means that a write did not happen.
"""
import contextlib
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import signal
import stat
import subprocess

C = A = U = Q = None  # supplied by the exact source bundle, never imported implicitly
BASE = Path('/var/lib/prace-storage-acceptance')
LEASE = Path('/run/prace-cluster-lease')
SERIALS = {'lab-dl380': 'EXSERIAL01', 'lab-lenovo': 'EXSER02',
           'lab-g003': 'EXSERIAL03', 'lab-g004': 'EXSERIAL04', 'lab-g005': 'EXSERIAL05'}
FD = None
OPS = {'guard', 'observe', 'create_project_fixture', 'create_apps_fixture', 'create_squash_fixture',
       'read_fixture', 'append_fixture', 'deny_project_access', 'apps_read_only', 'root_squash',
       'remove_fixture', 'cleanup_denials', 'verify_fixture', 'status', 'underlay_check', 'underlay_prepare'}


def require(value, code):
    if not value:
        raise C.Refused(code)


def command(argv, *, timeout=10, _ceiling=30):
    """Finite waits; inherited flock remains held by any unkillable child."""
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, start_new_session=True, env=dict(os.environ, LC_ALL='C'),
                             pass_fds=() if FD is None else (FD,))
    try:
        out, err = child.communicate(timeout=min(timeout, _ceiling))
    except BaseException:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            child.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass  # keep the lease; inherited flock prevents subsequent host work
        raise
    require(child.returncode == 0 and not err.strip(), 'command_failed')
    require(len(out) <= 1024 * 1024, 'output_limit')
    return out


def lease(window):
    C.private_dir(LEASE)
    path = LEASE / 'holder'
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600,
            'lease_record')
    tokens = path.read_text().split()
    fields = {}
    for token in tokens:
        require('=' in token, 'lease_record')
        key, value = token.split('=', 1)
        require(key not in fields, 'lease_record')
        fields[key] = value
    require(fields.get('id') == window['id'] and fields.get('holder') == 'maint'
            and fields.get('label') == window['label'] and fields.get('since'), 'lease_not_owned')


def guard(window):
    lease(window)
    expected = {'schema': 2, 'lease_id': window['id'], 'phase': 'closed', 'fence_active': True,
                'original': window['original'], 'declared_partitions': window.get('declared_partitions', {})}
    require(C.load_json(LEASE / 'fence-intent.json') == expected, 'fence_intent_changed')
    original = dict(window['original'])
    original['partitions'] = dict(original['partitions'], **window.get('declared_partitions', {}))
    C.check_fence({'original': original})
    C.check_queue_empty()


def identity(expected):
    current = C.identity()
    require(current == expected and current['chassis_serial'] == SERIALS.get(current['hostname']), 'identity_changed')
    return current


def mounts(host):
    result = {}
    for path in A.SHARES:
        data = json.loads(command(['findmnt', '-J', '-o', 'TARGET,SOURCE,FSTYPE,OPTIONS', '--mountpoint', path]))
        require(len(data['filesystems']) == 1, 'mount_membership')
        row = data['filesystems'][0]
        result[path] = {key: row[key] for key in ('target', 'source', 'fstype')}
        result[path]['options'] = row['options'].split(',')
    # Reuse the core's mount/account contract without inventing evidence.
    return result


def accounts():
    result = {}
    for name in A.USERS:
        user = pwd.getpwnam(name)
        result[name] = {'uid': user.pw_uid, 'gid': user.pw_gid,
                        'groups': sorted(os.getgrouplist(name, user.pw_gid))}
    return result


def basic_boundary(host):
    actual_mounts, actual_accounts = mounts(host), accounts()
    for path, (lv, quota, mode) in A.SHARES.items():
        row, options = actual_mounts[path], set(actual_mounts[path]['options'])
        require(row['target'] == path and {'nosuid', 'nodev'} <= options, 'mount_options')
        if host == A.SERVER:
            require(row['source'] == '/dev/mapper/hpe_vg-' + lv and row['fstype'] == 'xfs', 'server_mount')
            require('ro' not in options, 'server_readonly')
            require(not quota or ({'usrquota', 'uquota'} if quota == 'usrquota' else {'prjquota', 'pquota'}) & options,
                    'quota_mount')
        else:
            require(row['source'] == '10.90.10.1:' + path and row['fstype'] in ('nfs', 'nfs4'), 'client_mount')
            require({'hard', mode} <= options and ('vers=4.2' in options or 'nfsvers=4.2' in options)
                    and ('ro' not in options if mode == 'rw' else 'rw' not in options), 'client_options')
    for name, (uid, gid, groups) in A.USERS.items():
        require(actual_accounts[name] == {'uid': uid, 'gid': gid, 'groups': sorted(groups | {gid})}, 'numeric_identity')
    # No synthetic process may be active between serial probes. This does not
    # replace the explicit administrative-writer exclusion in the window record.
    selected = {value[0] for value in A.USERS.values()}
    for process in Path('/proc').iterdir():
        if process.name.isdigit():
            try:
                require(process.stat().st_uid not in selected, 'synthetic_process_present')
            except FileNotFoundError:
                pass
    C.writable_fds(list(A.SHARES))
    return actual_mounts, actual_accounts


def acl(path):
    return [line for line in command(['getfacl', '-cpnE', str(path)]).splitlines() if line]


def object_id(path):
    info = Path(path).lstat()
    require(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode), 'fixture_type')
    return {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid,
            'gid': info.st_gid, 'mode': stat.S_IMODE(info.st_mode), 'directory': stat.S_ISDIR(info.st_mode)}


def observed(host, expected, quota_hash):
    ident = identity(expected)
    found, users = basic_boundary(host)
    result = dict(ident, mounts=found, accounts=users,
                  free_bytes={path: os.statvfs(path).f_bavail * os.statvfs(path).f_frsize for path in A.SHARES})
    if host == A.SERVER:
        raw = json.loads(Path('/etc/prace-storage/mounts.json').read_text())
        require(isinstance(raw, list) and len(raw) == 3 and len({row['path'] for row in raw}) == 3, 'storage_config')
        result['storage_config'] = {row['path']: {'source': row['source'], 'quota': row['quota']} for row in raw}
        exported = command(['exportfs', '-v'])
        pattern = r'(/[^\s]+)\s+([^\s(]+)\(([^)]*)\)'
        rows = list(re.finditer(pattern, exported))
        require(re.sub(pattern, '', exported).strip() == '', 'export_parse')
        result['exports'] = [{'path': row[1], 'client': row[2], 'options': row[3].split(',')} for row in rows]
        result['project_roots'] = {}
        for name in A.PROJECTS:
            path = Path('/projects') / name
            info = object_id(path)
            result['project_roots'][name] = {key: info[key] for key in ('uid', 'gid', 'mode')}
            result['project_roots'][name]['acl'] = acl(path)
        result['quota_state'] = {}
        for kind, path, flag in (('user', '/home', 'u'), ('project', '/projects', 'p')):
            text = command(['xfs_quota', '-x', '-c', 'state -' + flag, path])
            header = ('User' if kind == 'user' else 'Project') + ' quota state on'
            lines = text.splitlines()
            blocks = [lines[index + 1:index + 3] for index, line in enumerate(lines) if line.startswith(header)]
            require(len(blocks) == 1, 'quota_state')
            result['quota_state'][kind] = {'accounting': any(line.strip() == 'Accounting: ON' for line in blocks[0]),
                                           'enforcement': any(line.strip() == 'Enforcement: ON' for line in blocks[0])}
        helper = Path('/usr/local/sbin/prace-quota-apply')
        require(hashlib.sha256(helper.read_bytes()).hexdigest() == quota_hash, 'quota_helper_changed')
        result['quota_declaration'] = json.loads(Path('/etc/prace-storage/quotas.json').read_text())
        result['quota_check'] = {'returncode': 0, 'stderr': '',
                                 'stdout': command([str(helper), '--check'], timeout=30).strip()}
    A.validate_observation(host, result)
    return result


@contextlib.contextmanager
def as_user(name):
    require(name == 'root' or name in A.USERS, 'user_scope')
    old_uid, old_gid, old_groups = os.geteuid(), os.getegid(), os.getgroups()
    entry = pwd.getpwnam(name)
    try:
        os.setgroups(os.getgrouplist(name, entry.pw_gid))
        os.setegid(entry.pw_gid)
        os.seteuid(entry.pw_uid)
        yield
    finally:
        os.seteuid(old_uid)
        os.setegid(old_gid)
        os.setgroups(old_groups)


def fixture(run_id, kind):
    require(re.fullmatch('[a-f0-9]{32}', run_id), 'run_id')
    parents = dict({name: '/projects/' + name for name in A.PROJECTS}, apps='/apps', squash='/projects')
    require(kind in parents, 'fixture_scope')
    path = Path(parents[kind]) / ('.prace-storage-' + run_id + '-' + kind)
    require(path.parent.resolve() == path.parent, 'fixture_parent')
    return path


def record_path(directory, kind):
    require(kind in (*A.PROJECTS, 'apps', 'squash'), 'fixture_scope')
    return directory / ('fixture-' + kind + '.json')


def save(path, record):
    C.write_json(path, record)


def create(directory, request, kind, user, content, mode):
    path, record_file = fixture(request['run_id'], kind), record_path(directory, kind)
    require(not record_file.exists() and not path.exists() and not path.is_symlink(), 'fixture_exists')
    record = {'path': str(path), 'creator': user, 'state': 'intent', 'root': None, 'files': {}}
    save(record_file, record)
    with as_user(user):
        previous = os.umask(0o077 if kind.startswith('proj-') else 0)
        try:
            path.mkdir(mode=mode)
        finally:
            os.umask(previous)
    C.syncdir(path.parent)
    record['root'] = object_id(path)
    save(record_file, record)  # interruption before this receipt remains unknown
    if content is not None:
        with as_user(user):
            previous = os.umask(0o077 if kind.startswith('proj-') else 0o022)
            try:
                fd = os.open(path / 'data', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o666)
            finally:
                os.umask(previous)
        try:
            record['files']['data'] = object_id(path / 'data')
            save(record_file, record)
            with as_user(user):
                require(os.write(fd, bytes.fromhex(content)) == len(bytes.fromhex(content)), 'fixture_short_write')
                os.fsync(fd)
            C.syncdir(path)
        finally:
            os.close(fd)
    record['state'] = 'created'
    save(record_file, record)
    result = {'receipt': {'kind': kind, 'root': record['root']}}
    if kind.startswith('proj-'):
        result['file'] = {key: record['files']['data'][key] for key in ('uid', 'gid', 'mode')}
        result['directory'] = {key: record['root'][key] for key in ('uid', 'gid', 'mode')}
        result['directory']['acl'] = acl(path)
    return result


def denial(directory, request, kind, user):
    """Register unexpected successful creates too; explicit cleanup owns them."""
    root = fixture(request['run_id'], kind)
    target = root / ('denied-' + request['host'])
    record_file = directory / ('denial-' + kind + '.json')
    require(not record_file.exists(), 'fixture_exists')
    record = {'path': str(target), 'creator': user, 'state': 'intent', 'identity': None}
    save(record_file, record)
    fd = None
    try:
        with as_user(user):
            require(root.resolve() == root and root.is_dir(), 'fixture_parent')
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        record['identity'] = object_id(target)
        save(record_file, record)
        with as_user(user):
            require(os.write(fd, b'x') == 1, 'fixture_short_write')
            os.fsync(fd)
            C.syncdir(root)
        result = None
    except OSError as exc:
        if fd is not None or exc.errno not in (errno.EACCES, errno.EROFS):
            raise
        result = exc.errno
    finally:
        if fd is not None:
            os.close(fd)
    record['state'] = 'completed'
    record['errno'] = result
    save(record_file, record)
    return result


def read_or_append(request, *, append=False):
    path = fixture(request['run_id'], request['project']) / 'data'
    with as_user(request['user']):
        require(path.parent.resolve() == path.parent, 'fixture_parent')
        fd = os.open(path, (os.O_WRONLY | os.O_APPEND if append else os.O_RDONLY) | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 256, 'fixture_file')
            if append:
                require(request['content_hex'] == '2b', 'append_bound')
                count = os.write(fd, b'+')
                os.fsync(fd)
                return {'written': count}
            return {'content_hex': os.read(fd, 257).hex()}
        finally:
            os.close(fd)


def cleanup_denials(directory, request, kind):
    record_file = directory / ('denial-' + kind + '.json')
    if not record_file.exists():
        return {'clean': True, 'verified': True}
    record = C.load_json(record_file)
    path = fixture(request['run_id'], kind) / ('denied-' + request['host'])
    require(record['path'] == str(path) and record['state'] in ('completed', 'clean'), 'denial_uncertain')
    if record['identity'] is None:
        require(record.get('errno') in (errno.EACCES, errno.EROFS), 'denial_uncertain')
        # The client cannot stat inside a squashed 0700 root directory. The
        # failed O_EXCL open created nothing; server cleanup independently
        # rejects every unexpected entry before removing the parent fixture.
    else:
        with as_user(record['creator']):
            if path.exists() or path.is_symlink():
                require(object_id(path) == record['identity'] and path.lstat().st_nlink == 1, 'fixture_changed')
                path.unlink()
            # A previous unlink may have succeeded before its fsync failed.
            # Flush even on the absent-on-retry branch, before clean receipt.
            C.syncdir(path.parent)
            require(not path.exists() and not path.is_symlink(), 'cleanup_unverified')
    record['state'] = 'clean'
    save(record_file, record)
    return {'clean': True, 'verified': True}


def cleanup(directory, request, kind):
    record_file, path = record_path(directory, kind), fixture(request['run_id'], kind)
    require(record_file.exists(), 'receipt_missing')
    record = C.load_json(record_file)
    require(record['path'] == str(path) and record['root'] is not None, 'fixture_unknown')
    if path.exists() or path.is_symlink():
        require(object_id(path) == record['root'], 'fixture_changed')
        entries = list(path.iterdir())
        require({entry.name for entry in entries} <= set(record['files']), 'fixture_unknown_entry')
        for entry in entries:
            require(object_id(entry) == record['files'][entry.name] and entry.lstat().st_nlink == 1,
                    'fixture_changed')
        for entry in entries:
            entry.unlink()  # verified server-local root, never client-root squash bypass
        C.syncdir(path)
        path.rmdir()
    C.syncdir(path.parent)  # also when rmdir succeeded but its earlier flush failed
    require(not path.exists() and not path.is_symlink(), 'cleanup_unverified')
    record['state'] = 'clean'
    save(record_file, record)
    return {'clean': True, 'verified': True}


def verify_fixture(directory, request, kind):
    path = fixture(request['run_id'], kind)
    record = C.load_json(record_path(directory, kind))
    require(record['state'] == 'created' and record['path'] == str(path)
            and object_id(path) == record['root'], 'fixture_changed')
    require({entry.name for entry in path.iterdir()} == set(record['files']), 'fixture_unknown_entry')
    for name, saved in record['files'].items():
        require(object_id(path / name) == saved and (path / name).lstat().st_nlink == 1, 'fixture_changed')
    return {'verified': True}


def worker_underlay(directory, request):
    require(request['host'] in A.CLIENTS and U is not None and FD is not None, 'underlay_scope')
    mode = request['operation'].split('_', 1)[1]
    preservation_id = request.get('preservation_id')
    U.validate_context(request['window'], request['identity'], mode, preservation_id)
    U.verify_helper(request['underlay_helper_sha256'])
    path = directory / 'underlay.json'
    require(not path.exists() and not path.is_symlink(), 'underlay_already_attempted')
    # This record deliberately has no remove/rollback handler. A lost response
    # can mean a partial permanent preparation; inspect retained data/receipts.
    record = {'kind': 'underlay', 'state': 'intent', 'mode': mode, 'preservation_id': preservation_id,
              'helper_sha256': request['underlay_helper_sha256'], 'identity': request['identity']}
    save(path, record)
    def local_guard():
        identity(request['identity'])
        basic_boundary(request['host'])
        return True
    def runner(argv, *, timeout):
        require(argv[:7] == ['unshare', '--mount', '--propagation', 'private', '--', 'python3', '-c']
                and len(argv) == 8 and timeout == 130, 'underlay_command_scope')
        return command(argv, timeout=timeout, _ceiling=130)
    result = U.run_guarded(request['window'], request['identity'], mode=mode, run_id=preservation_id,
                           helper_sha256=request['underlay_helper_sha256'], guard=local_guard, runner=runner)
    record.update(state='verified', result=result)
    save(path, record)
    return result


def dispatch(directory, request):
    op, host = request['operation'], request['host']
    if op == 'guard':
        require(host == A.SERVER, 'host_scope')
        return {'owned': True, 'fenced': True, 'exclusive': True, 'quiescent': True}
    if op == 'observe':
        return observed(host, request['identity'], request['quota_helper_sha256'])
    basic_boundary(host)
    if Q is not None and op in Q.OPS:
        return Q.dispatch(directory, request)
    if op in ('underlay_check', 'underlay_prepare'):
        return worker_underlay(directory, request)
    project = request.get('project')
    if op == 'create_project_fixture':
        require(host == A.SERVER and project in A.PROJECTS, 'host_scope')
        user = A.PROJECTS[project][1]
        require(request['user'] == user and request['content_hex'] == (request['run_id'] + ':' + project).encode().hex(),
                'fixture_scope')
        return create(directory, request, project, user, request['content_hex'], 0o777)
    if op in ('create_apps_fixture', 'create_squash_fixture'):
        require(host == A.SERVER, 'host_scope')
        kind = 'apps' if op == 'create_apps_fixture' else 'squash'
        return create(directory, request, kind, 'root', request['run_id'].encode().hex() if kind == 'apps' else None,
                      0o777 if kind == 'apps' else 0o700)
    if op in ('read_fixture', 'append_fixture'):
        return read_or_append(request, append=op == 'append_fixture')
    if op == 'deny_project_access':
        require(project in A.PROJECTS and request['user'] == A.PROJECTS[project][3], 'user_scope')
        read_errno = None
        try:
            read_or_append(request)
        except OSError as exc:
            require(exc.errno == errno.EACCES, 'denial_error')
            read_errno = exc.errno
        return {'read_errno': read_errno, 'create_errno': denial(directory, request, project, request['user'])}
    if op == 'apps_read_only':
        require(host in A.CLIENTS, 'host_scope')
        content = read_or_append(dict(request, project='apps', user='syn-probe'))
        return dict(content, create_errno=denial(directory, request, 'apps', 'syn-probe'))
    if op == 'root_squash':
        require(host in A.CLIENTS, 'host_scope')
        return {'create_errno': denial(directory, request, 'squash', 'root')}
    if op == 'cleanup_denials':
        return cleanup_denials(directory, request, request['kind'])
    if op == 'verify_fixture':
        require(host == A.SERVER, 'host_scope')
        return verify_fixture(directory, request, request['kind'])
    if op == 'remove_fixture':
        require(host == A.SERVER, 'host_scope')
        kind = request.get('project') or {'create_apps_fixture': 'apps', 'create_squash_fixture': 'squash'}.get(request['created_by'])
        return cleanup(directory, request, kind)
    if op == 'status':
        return {'clean': clean_receipts(directory)}
    raise C.Refused('operation_scope')


def clean_receipts(directory):
    records = [path for path in directory.glob('*.json') if path.name != 'scope.json']
    require(len(records) <= 64, 'receipt_count')
    for path in records:
        record = C.load_json(path)
        if path.name == 'underlay.json':
            require(record.get('kind') == 'underlay', 'underlay_receipt')
            if record.get('state') != 'verified':
                return False
            value = record.get('result', {})
            require(value.get('parent_namespace_unchanged') is True and value.get('parent_mounts_unchanged') is True
                    and set(value.get('paths', {})) == set(A.SHARES) and
                    all(row.get('guarded') is True for row in value['paths'].values()), 'underlay_receipt')
            continue  # preserved home data is retained, not a removable fixture
        if record.get('quota') is True:
            require(Q is not None, 'quota_adapter_missing')
            if not Q.clean_record(record):
                return False
            continue
        if record.get('state') != 'clean':
            return False
        target = Path(record['path'])
        # Even a clean receipt is not proof of current absence. A squashed
        # client may not stat inside its former 0700 fixture: unknown refuses.
        # Squashed client root cannot traverse a 2770 project root. Use the
        # fixed project owner to observe absence; unknown errors still refuse.
        kind = path.name.removeprefix('denial-').removesuffix('.json')
        actor = A.PROJECTS[kind][1] if kind in A.PROJECTS else 'root'
        with as_user(actor):
            try:
                target.lstat()
            except FileNotFoundError:
                pass
            else:
                return False
    return True


def prior_runs_clean(current):
    entries = list(BASE.iterdir())
    require(len(entries) <= 1000, 'prior_run_count')
    for directory in entries:
        if directory.name == 'operation.lock' or directory == current:
            continue
        require(re.fullmatch('[a-f0-9]{16}-[a-f0-9]{32}', directory.name), 'unknown_prior_run')
        C.private_dir(directory)
        require(clean_receipts(directory), 'prior_run_cleanup_pending')


@contextlib.contextmanager
def host_lock(directory):
    global FD
    fd = os.open(directory / 'operation.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    prior = FD
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.geteuid()
                and stat.S_IMODE(info.st_mode) == 0o600, 'operation_lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        FD = fd
        yield fd
    finally:
        FD = prior
        os.close(fd)  # no LOCK_UN: children retain the shared open description


def handle(request):
    require(os.geteuid() == 0 and request.get('operation') in (OPS | (Q.OPS if Q is not None else set())), 'request_scope')
    require(re.fullmatch('[a-f0-9]{32}', request.get('run_id', '')) and
            re.fullmatch('[a-f0-9]{16}', request['window']['id']), 'request_scope')
    require(request['host'] in SERIALS, 'host_scope')
    C.run = command
    identity(request['identity'])
    if request['host'] == A.SERVER:
        guard(request['window'])
    BASE.mkdir(mode=0o700, exist_ok=True)
    C.private_dir(BASE)
    require(BASE.resolve() == BASE, 'private_directory')
    C.syncdir(BASE.parent)
    directory = BASE / (request['window']['id'] + '-' + request['run_id'])
    # One stable lock per host, across all windows and run IDs. Surviving
    # children keep it through their inherited descriptor.
    with host_lock(BASE):
        prior_runs_clean(directory)
        directory.mkdir(mode=0o700, exist_ok=True)
        C.private_dir(directory)
        C.syncdir(BASE)
        scope = {'window': request['window'], 'identity': request['identity'], 'sources': request['sources']}
        scope_path = directory / 'scope.json'
        if scope_path.exists():
            require(C.load_json(scope_path) == scope, 'scope_changed')
        else:
            save(scope_path, scope)
        # The bundled RPC already has its 90-second timer. Do not replace its
        # remaining time with a new nested deadline here.
        return dispatch(directory, request)

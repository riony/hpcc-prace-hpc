#!/usr/bin/env python3
"""Adapter-only worker underlay check/preparation in a private child namespace.

The adapter must hold the common server operation lock, freshly verify its owned
closed window before AND after the RPC, pin this source and the installed helper,
and durably record preparation intent. Its callback here verifies LOCAL identity,
quiescence and context; workers do not query the server lease. Standalone use is
refused. Preparation changes underlying filesystem data/attributes globally;
only the temporary unmounts are private to the child namespace.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess

PATHS = ('/home', '/projects', '/apps')
WORKERS = {'lab-lenovo': 'EXSER02', 'lab-g003': 'EXSERIAL03',
           'lab-g004': 'EXSERIAL04', 'lab-g005': 'EXSERIAL05'}
HELPER = '/usr/local/sbin/prace-nfs-underlay'
SOURCE = None  # the guarded adapter injects the exact reviewed source bundle


class Refused(RuntimeError):
    pass


def require(value, code):
    if not value:
        raise Refused(code)


def validate_context(context, expected_identity, mode, run_id):
    require(isinstance(context, dict) and context.get('schema') == 2 and context.get('phase') == 'closed'
            and context.get('fence_intent', {}).get('active') is True
            and re.fullmatch('[a-f0-9]{16}', context.get('id', '')), 'closed_adapter_context_required')
    require(isinstance(expected_identity, dict) and set(expected_identity) ==
            {'hostname', 'chassis_serial', 'machine_id', 'boot_id'}, 'worker_identity')
    require(expected_identity['hostname'] in WORKERS
            and expected_identity['chassis_serial'] == WORKERS[expected_identity['hostname']]
            and re.fullmatch('[a-f0-9]{32}', expected_identity['machine_id'])
            and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', expected_identity['boot_id']),
            'worker_identity')
    require(mode in ('check', 'prepare'), 'mode_scope')
    require((mode == 'check' and run_id is None) or
            (mode == 'prepare' and isinstance(run_id, str) and re.fullmatch('[a-z0-9-]{8,64}', run_id)),
            'explicit_preservation_id_required')


def local_identity():
    return {'hostname': socket.gethostname().split('.')[0],
            'chassis_serial': Path('/sys/class/dmi/id/product_serial').read_text().strip(),
            'machine_id': Path('/etc/machine-id').read_text().strip(),
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}


def namespace(pid='self'):
    value = os.readlink('/proc/' + str(pid) + '/ns/mnt')
    require(re.fullmatch(r'mnt:\[\d+\]', value), 'namespace_identity')
    return value


def decode(value):
    return re.sub(r'\\([0-7]{3})', lambda found: chr(int(found[1], 8)), value)


def mountinfo():
    text = Path('/proc/self/mountinfo').read_text()
    require(len(text) <= 4 * 1024 * 1024, 'mountinfo_limit')
    return parse_mountinfo(text)


def parse_mountinfo(text):
    result = []
    for line in text.splitlines():
        fields = line.split()
        require(len(fields) >= 10 and fields.count('-') == 1, 'mountinfo_invalid')
        separator = fields.index('-')
        require(separator >= 6 and len(fields) == separator + 4 and fields[0].isdigit()
                and fields[1].isdigit(), 'mountinfo_invalid')
        result.append({'id': fields[0], 'parent': fields[1], 'device': fields[2], 'root': decode(fields[3]),
                       'target': decode(fields[4]), 'options': fields[5].split(','), 'optional': fields[6:separator],
                       'fstype': fields[separator + 1], 'source': decode(fields[separator + 2]),
                       'super_options': fields[separator + 3].split(',')})
    require(result, 'mountinfo_empty')
    return result


def directory(path):
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and path.resolve() == path, 'directory_identity')


def verify_helper(expected):
    require(isinstance(expected, str) and re.fullmatch('[a-f0-9]{64}', expected), 'helper_digest_required')
    path = Path(HELPER)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and not info.st_mode & 0o022 and info.st_mode & 0o100 and info.st_size <= 128 * 1024,
            'helper_identity')
    require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, 'helper_changed')


def selected(records):
    result = {}
    for path in PATHS:
        matches = [row for row in records if row['target'] == path]
        require(len(matches) == 1, 'exact_nfs_mount_required')
        require(not any(row['target'].startswith(path + '/') for row in records), 'nested_mount')
        row = matches[0]
        options = set(row['options'])
        super_options = set(row['super_options'])
        require(row['source'] == '10.90.10.1:' + path and row['fstype'] in ('nfs', 'nfs4'), 'nfs_source')
        require({'nosuid', 'nodev'} <= options and 'hard' in options | super_options
                and ('vers=4.2' in options | super_options or 'nfsvers=4.2' in options | super_options)
                and 'sec=sys' in options | super_options
                and not {'soft', 'softerr', 'softreval', 'noresvport', 'suid', 'dev'} & (options | super_options),
                'nfs_options')
        mode = 'ro' if path == '/apps' else 'rw'
        require(mode in options and ('rw' not in options if mode == 'ro' else 'ro' not in options), 'nfs_mode')
        result[path] = row
    return result


def private_child(parent_pid, parent_namespace):
    require(namespace(parent_pid) == parent_namespace and namespace() != parent_namespace, 'namespace_not_isolated')
    records = mountinfo()
    require(not any(field.startswith(('shared:', 'master:', 'propagate_from:'))
                    for row in records for field in row['optional']), 'namespace_propagation')
    return records


def child_command(argv):
    """Only ordinary umount and the existing helper are issued by the child."""
    # The adapter deliberately passes its operation-lock descriptor into the
    # namespace process. Preserve it for immediate helper children too. The
    # existing helper's own subprocesses are outside this module's descriptor
    # contract; abrupt parent death requires explicit process/receipt inspection,
    # never automatic window closure based only on this process having exited.
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, close_fds=False, start_new_session=True)
    try:
        out, err = process.communicate(timeout=20)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        raise
    require(process.returncode == 0 and not err.strip() and len(out) <= 65536, 'child_command_failed')
    return out


def helper_result(value, path, mode, run_id):
    require(isinstance(value, dict) and value.get('guarded') is True and type(value.get('changed')) is bool,
            'helper_result')
    require(mode != 'check' or value['changed'] is False, 'check_changed_underlay')
    expected_archive = '/var/lib/prace-home-premigration/worker-underlay-' + str(run_id)
    require(value.get('archive') is None or
            (mode == 'prepare' and path == '/home' and value['archive'] == expected_archive), 'helper_archive')
    return value


def child(payload):
    require(os.geteuid() == 0, 'root_required')
    validate_context(payload['context'], payload['identity'], payload['mode'], payload['run_id'])
    require(local_identity() == payload['identity'], 'identity_changed')
    verify_helper(payload['helper_sha256'])
    records = private_child(payload['parent_pid'], payload['parent_namespace'])
    initial = selected(records)
    for path in PATHS:
        directory(path)
    results = {}
    for path in PATHS:
        require(local_identity() == payload['identity'], 'identity_changed')
        records = private_child(payload['parent_pid'], payload['parent_namespace'])
        require([row for row in records if row['target'] == path] == [initial[path]], 'mount_identity_changed')
        require(not any(row['target'].startswith(path + '/') for row in records), 'nested_mount')
        directory(path)
        child_command(['umount', '--', path])  # no force, lazy, recursive, or parent-namespace option
        records = private_child(payload['parent_pid'], payload['parent_namespace'])
        require(not any(row['target'] == path or row['target'].startswith(path + '/') for row in records),
                'unmount_unverified')
        directory(path)  # refuse a symlink or unexpected owner exposed underneath
        require(local_identity() == payload['identity'], 'identity_changed')
        verify_helper(payload['helper_sha256'])
        argv = [HELPER, '--path', path]
        if payload['mode'] == 'check':
            argv.append('--check')
        elif path == '/home':
            archive_parent = Path('/var/lib/prace-home-premigration')
            require(archive_parent.parent.resolve() == archive_parent.parent, 'preservation_parent')
            if archive_parent.exists() or archive_parent.is_symlink():
                directory(archive_parent)
            argv += ['--preserve-home', payload['run_id']]
        results[path] = helper_result(json.loads(child_command(argv)), path, payload['mode'], payload['run_id'])
    require(local_identity() == payload['identity'], 'identity_changed')
    private_child(payload['parent_pid'], payload['parent_namespace'])
    return {'mode': payload['mode'], 'child_namespace': namespace(), 'paths': results}


def run_guarded(context, expected_identity, *, helper_sha256=None, guard=None, runner=None, mode='check', run_id=None):
    """Called only from the guarded adapter; callbacks perform no implicit SSH.

    guard() must return True after LOCAL identity/quiescence/context checks.
    runner(argv, timeout=...) must run with the adapter's inherited operation
    lock and bounded process-group lifecycle, returning strict stdout. The
    adapter separately verifies the real SERVER fence before/after this RPC.
    """
    require(os.geteuid() == 0, 'root_required')
    require(callable(guard) and callable(runner), 'guarded_adapter_required')
    validate_context(context, expected_identity, mode, run_id)
    require(guard() is True and local_identity() == expected_identity, 'local_guard_failed')
    verify_helper(helper_sha256)
    parent_namespace, parent_pid = namespace(), os.getpid()
    before = selected(mountinfo())
    for path in PATHS:
        directory(path)
    source = SOURCE
    require(isinstance(source, str) and source, 'reviewed_source_required')
    payload = {'context': context, 'identity': expected_identity, 'mode': mode, 'run_id': run_id,
               'parent_namespace': parent_namespace, 'parent_pid': parent_pid, 'helper_sha256': helper_sha256}
    code = ('import json,signal,types\n'
            'm=types.ModuleType("prace_worker_underlay")\n'
            f'exec(compile({source!r},"<worker-underlay-bundle>","exec"),m.__dict__)\n'
            'def expired(*_): raise m.Refused("child_deadline")\n'
            'signal.signal(signal.SIGALRM,expired); signal.alarm(120)\n'
            f'print(json.dumps(m.child(json.loads({json.dumps(payload)!r}))))\n')
    try:
        output = runner(['unshare', '--mount', '--propagation', 'private', '--', 'python3', '-c', code], timeout=130)
        result = json.loads(output)
    finally:
        # These checks execute after both success and failure. Isolation errors
        # never trigger host remount or any automatic repair.
        require(namespace() == parent_namespace and selected(mountinfo()) == before, 'parent_mounts_changed')
        require(guard() is True and local_identity() == expected_identity, 'local_guard_failed')
        verify_helper(helper_sha256)
    require(isinstance(result, dict) and result.get('mode') == mode and set(result.get('paths', {})) == set(PATHS)
            and re.fullmatch(r'mnt:\[\d+\]', result.get('child_namespace', ''))
            and result['child_namespace'] != parent_namespace, 'child_result')
    for path, value in result['paths'].items():
        helper_result(value, path, mode, run_id)
    return dict(result, parent_namespace_unchanged=True, parent_mounts_unchanged=True,
                server_fence_observation='adapter responsibility', underlying_filesystem_changes=(mode == 'prepare'))


if __name__ == '__main__':
    raise SystemExit('Refused: use only through the guarded storage adapter; standalone execution is disabled.')

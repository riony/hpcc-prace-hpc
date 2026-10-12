#!/usr/bin/env python3
"""Explicit local bench or already-owned fleet storage/quota gates.

No default fleet mode, implicit key paths, lease acquisition, reopening, or
release. The common maintenance owner prepares/closes its window separately.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import time
import uuid

TOOLS = Path(__file__).resolve().parent
LOGIN = '192.0.2.205'
TARGETS = {'lab-dl380': LOGIN, 'lab-lenovo': '10.90.10.21', 'lab-g003': '10.90.10.13',
           'lab-g004': '10.90.10.14', 'lab-g005': '10.90.10.15'}
SERIALS = {'lab-dl380': 'EXSERIAL01', 'lab-lenovo': 'EXSER02',
           'lab-g003': 'EXSERIAL03', 'lab-g004': 'EXSERIAL04', 'lab-g005': 'EXSERIAL05'}
# The workstation OpenSSH 10.2 client warns on the fleet's existing non-PQ key exchange. Suppress only
# that advisory, without changing algorithms, host-key checking or RPC stderr refusal.
# Clients predating WarnWeakCrypto ignore this display option. Apply it to the jump as well.
SSH_OPTIONS = ['-F', '/dev/null', '-o', 'IgnoreUnknown=WarnWeakCrypto',
               '-o', 'WarnWeakCrypto=no-pq-kex', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
               '-o', 'ConnectTimeout=10', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=2',
               '-o', 'ForwardAgent=no', '-o', 'ControlMaster=no', '-o', 'ControlPath=none']
SOURCES = ('prace_storage_acceptance.py', 'prace_storage_probe.py', 'prace_storage_remote.py',
           'prace_capture_remote.py', 'prace_worker_underlay.py', 'prace_quota_remote.py', 'storage-acceptance.py')
RPC_MIN_INTERVAL = 6.0
ACTION_SECONDS = 3600
LOCK_SECONDS = ACTION_SECONDS + 60


def module(name):
    spec = importlib.util.spec_from_file_location(name, TOOLS / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


A = module('prace_storage_acceptance')
P = module('prace_storage_probe')
C = module('prace_capture_remote')  # inert import; no capture entrypoint is called


def require(value, code):
    if not value:
        raise A.Refused(code)


def private_json(path):
    path = Path(path)
    info = path.lstat()
    require(path.is_absolute() and path.resolve() == path and stat.S_ISREG(info.st_mode)
            and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600
            and info.st_size <= 1024 * 1024, 'private_input')
    return json.loads(path.read_text())


def validate_window(window, lease_id):
    require(isinstance(window, dict) and window.get('schema') == 2 and window.get('id') == lease_id
            and re.fullmatch('[0-9a-f]{16}', lease_id or '') and window.get('login') == LOGIN
            and re.fullmatch('[A-Za-z0-9-]{1,64}', window.get('label', ''))
            and window.get('phase') == 'closed' and window.get('fence_intent', {}).get('active') is True,
            'window_not_closed')
    original = window.get('original', {})
    require(set(original) == {'partitions', 'loginsets'} and original['partitions'] and original['loginsets'],
            'window_original')
    require(not set(original['partitions']) & set(window.get('declared_partitions', {})), 'window_partition')
    for name, value in dict(original['partitions'], **window.get('declared_partitions', {})).items():
        require(re.fullmatch('[A-Za-z0-9_.-]+', name) and value in ('UP', 'DOWN', 'DRAIN', 'INACTIVE'), 'window_partition')
    for name, value in original['loginsets'].items():
        require(re.fullmatch('[A-Za-z0-9_.-]+', name) and isinstance(value.get('uid'), str) and value['uid']
                and type(value.get('replicas')) is int and 0 <= value['replicas'] <= 100, 'window_loginset')
    return {key: window[key] for key in ('schema', 'id', 'label', 'login', 'phase', 'original', 'fence_intent')} | {
        'declared_partitions': window.get('declared_partitions', {})}


def validate_identities(identities):
    require(isinstance(identities, dict) and set(identities) == set(TARGETS), 'identity_membership')
    for host, row in identities.items():
        require(set(row) == {'hostname', 'chassis_serial', 'machine_id', 'boot_id'} and row['hostname'] == host
                and row['chassis_serial'] == SERIALS[host] and re.fullmatch('[a-f0-9]{32}', row['machine_id'])
                and re.fullmatch('[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}', row['boot_id']), 'host_identity')
    return identities


def validate_run_target(path, action):
    path = Path(path)
    require(path.is_absolute() and path.parent.resolve() == path.parent and path.parent.is_dir(),
            'private_run_directory')
    if action in ('basic', 'quota', 'underlay-check', 'underlay-prepare'):
        require(not path.exists() and not path.is_symlink(), 'existing_run')
    else:
        info = path.lstat()
        require(path.resolve() == path and stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700, 'private_run_directory')
        state = private_json(path / 'acceptance.json')
        require(state.get('sources') == A.source_hashes(), 'source_changed')


def ssh_argv(host):
    require(host in TARGETS, 'host_scope')
    options = list(SSH_OPTIONS)
    if host != A.SERVER:
        options += ['-o', 'ProxyCommand=ssh -F /dev/null -o IgnoreUnknown=WarnWeakCrypto -o WarnWeakCrypto=no-pq-kex '
                    '-o BatchMode=yes -o StrictHostKeyChecking=yes '
                    '-o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 '
                    '-o ForwardAgent=no -o ControlMaster=no -o ControlPath=none -W %h:%p admin@' + LOGIN]
    return ['ssh', *options, 'root@' + TARGETS[host]]


def terminate(child):
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        child.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        pass


class SSH:
    def __init__(self):
        self.sources = {name: (TOOLS / name).read_text() for name in SOURCES}
        self.hashes = {name: hashlib.sha256(source.encode()).hexdigest() for name, source in self.sources.items()}
        self.quota_hash = hashlib.sha256((TOOLS.parent / 'roles/storage_policy/files/prace-quota-apply').read_bytes()).hexdigest()
        self.hashes['prace-quota-apply'] = self.quota_hash
        self.underlay_hash = hashlib.sha256((TOOLS.parent / 'roles/nfs_home/files/prace-nfs-underlay').read_bytes()).hexdigest()
        self.hashes['prace-nfs-underlay'] = self.underlay_hash
        self.lock = None
        self.last_rpc_started = None

    def unchanged(self):
        for name in SOURCES:
            require(hashlib.sha256((TOOLS / name).read_bytes()).hexdigest() == self.hashes[name], 'source_changed')
        require(hashlib.sha256((TOOLS.parent / 'roles/storage_policy/files/prace-quota-apply').read_bytes()).hexdigest()
                == self.quota_hash, 'source_changed')
        require(hashlib.sha256((TOOLS.parent / 'roles/nfs_home/files/prace-nfs-underlay').read_bytes()).hexdigest()
                == self.underlay_hash, 'source_changed')

    @contextlib.contextmanager
    def locked(self, lease_id):
        # Exact common-window flock. It is never unlinked. No lease file changes.
        source = ('import fcntl,os,signal,stat,sys\n'
                  f'signal.alarm({LOCK_SECONDS})\n'
                  f'fd=os.open("/run/prace-slurm-window-{lease_id}.lock",os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)\n'
                  's=os.fstat(fd)\n'
                  'assert stat.S_ISREG(s.st_mode) and s.st_uid==0 and s.st_nlink==1 and stat.S_IMODE(s.st_mode)==0o600\n'
                  'fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)\n'
                  'print("locked",flush=True)\n'
                  'sys.stdin.read()\n')
        import shlex
        child = subprocess.Popen(ssh_argv(A.SERVER) + ['python3 -u -c ' + shlex.quote(source)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, start_new_session=True)
        self.lock = child
        try:
            require(select.select([child.stdout], [], [], 20)[0] and child.stdout.readline() == 'locked\n', 'window_lock')
            yield
        finally:
            child.stdin.close()
            child.stdin = None
            try:
                child.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                terminate(child)
            self.lock = None

    def call(self, request):
        self.unchanged()
        require(self.lock is not None and self.lock.poll() is None, 'window_lock_lost')
        request = dict(request, sources=self.hashes, quota_helper_sha256=self.quota_hash,
                       underlay_helper_sha256=self.underlay_hash)
        underlay = request['operation'] in ('underlay_check', 'underlay_prepare')
        rpc_seconds, transport_seconds = (160, 180) if underlay else (90, 105)
        script = 'import types,sys,json,signal\n'
        script += 'signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))\n'
        for variable, name in (('a', 'prace_storage_acceptance.py'), ('c', 'prace_capture_remote.py'),
                               ('u', 'prace_worker_underlay.py'), ('q', 'prace_quota_remote.py'), ('r', 'prace_storage_remote.py')):
            script += f'{variable}=types.ModuleType({name[:-3]!r}); {variable}.__file__={name!r}\n'
            script += f'exec(compile({self.sources[name]!r},{name!r},"exec"),{variable}.__dict__)\n'
        script += f'u.SOURCE={self.sources["prace_worker_underlay.py"]!r}\n'
        script += f'r.A=a; r.C=c; r.U=u; r.Q=q; q.R=r\ntry:\n with c.deadline({rpc_seconds}):\n'
        script += f'  result=r.handle(json.loads({json.dumps(request)!r}))\n'
        script += ' print(json.dumps({"ok":True,"result":result}))\nexcept BaseException as exc:\n'
        script += ' print(json.dumps({"ok":False,"error":c.error_code(exc)}))\n'
        # Separate, strictly verified SSH connections are intentional. Pace
        # their starts instead of retrying a possibly completed mutation or
        # weakening the admission controls on the login host/network path.
        if self.last_rpc_started is not None:
            time.sleep(max(0.0, RPC_MIN_INTERVAL - (time.monotonic() - self.last_rpc_started)))
        self.unchanged()
        require(self.lock is not None and self.lock.poll() is None, 'window_lock_lost')
        self.last_rpc_started = time.monotonic()
        child = subprocess.Popen(ssh_argv(request['host']) + ['python3', '-'], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            out, err = child.communicate(script, timeout=transport_seconds)
        except BaseException:
            terminate(child)
            raise
        require(child.returncode == 0 and not err.strip() and len(out) <= 1024 * 1024, 'transport_failed')
        response = json.loads(out)
        if response.get('ok') is not True:
            code = response.get('error', '')
            # The remote only emits static protocol error codes, never stderr.
            require(False, 'remote_' + code if re.fullmatch('[a-z_]{1,64}', code) else 'remote_refused')
        require(isinstance(response.get('result'), dict), 'remote_refused')
        return response['result']


class FleetWindow:
    def __init__(self, transport, window_path, identities_path, lease_id):
        self.transport = transport
        self.window_path, self.identities_path = Path(window_path), Path(identities_path)
        self.window = validate_window(private_json(window_path), lease_id)
        self.identities = validate_identities(private_json(identities_path))
        self.run_id = None

    def unchanged(self):
        require(validate_window(private_json(self.window_path), self.window['id']) == self.window
                and validate_identities(private_json(self.identities_path)) == self.identities, 'window_changed')

    def rpc(self, host, operation, payload=None):
        self.unchanged()
        self.last_call = {'host': host, 'operation': operation}
        return self.transport.call(dict(payload or {}, host=host, operation=operation, run_id=self.run_id,
                                        window=self.window, identity=self.identities[host]))

    def guard(self, run_id, sources):
        require(self.run_id in (None, run_id), 'run_changed')
        self.run_id = run_id
        result = self.rpc(A.SERVER, 'guard')
        require(result == {'owned': True, 'fenced': True, 'exclusive': True, 'quiescent': True}, 'window_not_ready')
        return result

    def observe(self, host):
        self.guard(self.run_id, None)
        result = self.rpc(host, 'observe')
        self.guard(self.run_id, None)
        return result

    def call(self, host, operation, payload):
        self.guard(payload['run_id'], None)
        if operation in ('read_fixture', 'append_fixture', 'deny_project_access', 'apps_read_only', 'root_squash'):
            kind = payload.get('project') or ('apps' if operation == 'apps_read_only' else 'squash')
            require(self.rpc(A.SERVER, 'verify_fixture', {'kind': kind}) == {'verified': True}, 'fixture_changed')
        if operation == 'quota_remove_fixture':
            for node in A.CLIENTS[1:]:
                self.guard(payload['run_id'], None)
                require(self.rpc(node, 'quota_cleanup_denial', payload) == {'clean': True, 'verified': True},
                        'quota_denial_cleanup_unverified')
        if operation == 'remove_fixture':
            kind = payload.get('project') or {'create_apps_fixture': 'apps', 'create_squash_fixture': 'squash'}.get(payload['created_by'])
            require(kind in (*A.PROJECTS, 'apps', 'squash'), 'fixture_scope')
            # Each denial attempt has a remote receipt, even when the reply was
            # lost or it unexpectedly created a file. Settle those first.
            for node in A.HOSTS:
                self.guard(payload['run_id'], None)
                require(self.rpc(node, 'cleanup_denials', {'kind': kind}) == {'clean': True, 'verified': True},
                        'denial_cleanup_unverified')
        result = self.rpc(host, operation, payload)
        self.guard(payload['run_id'], None)
        return result


def bench(directory):
    path = Path(directory)
    require(path.is_absolute() and path.parent.resolve() == path.parent, 'bench_path')
    path.mkdir(mode=0o700)
    file = P.fill_bytes(path / 'bytes', max_bytes=4096)
    nodes = P.fill_inodes(path / 'inodes', max_files=8)
    require(file['written'] == 4096 and file['errno'] is None and nodes['created'] == 8 and nodes['errno'] is None,
            'bench_probe_failed')
    P.remove_fixture(path / 'bytes', file['identity'])
    P.remove_fixture(path / 'inodes', nodes['identity'], inode_fixture=True)
    return {'bench': 'local bounded probes passed', 'fleet_qualified': False, 'bytes': 4096, 'files': 8}


def main(argv=None, transport_factory=SSH):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--bench', action='store_true')
    mode.add_argument('--fleet', action='store_true')
    parser.add_argument('action', choices=('basic', 'quota', 'cleanup', 'underlay-check', 'underlay-prepare'), nargs='?', default='basic')
    parser.add_argument('--run-dir', required=True)
    parser.add_argument('--lease-id')
    parser.add_argument('--window')
    parser.add_argument('--identities')
    parser.add_argument('--attest-no-admin-writers', action='store_true')
    parser.add_argument('--preservation-id')
    args = parser.parse_args(argv)
    if args.bench:
        require(args.action == 'basic' and not any((args.lease_id, args.window, args.identities,
                                                  args.attest_no_admin_writers, args.preservation_id)),
                'bench_scope')
        return bench(args.run_dir)
    require(args.lease_id and args.window and args.identities and args.attest_no_admin_writers, 'fleet_window_required')
    require((args.action == 'underlay-prepare' and isinstance(args.preservation_id, str) and
             re.fullmatch('[a-z0-9-]{8,64}', args.preservation_id)) or
            (args.action != 'underlay-prepare' and args.preservation_id is None), 'preservation_id')
    # Validate all private inputs before even constructing the transport.
    validate_window(private_json(args.window), args.lease_id)
    validate_identities(private_json(args.identities))
    validate_run_target(args.run_dir, args.action)
    transport = transport_factory()
    window = FleetWindow(transport, args.window, args.identities, args.lease_id)
    with C.deadline(ACTION_SECONDS), transport.locked(args.lease_id):
        window.unchanged()  # closing/opening may have happened before lock acquisition
        run = A.FunctionalRun(Path(args.run_dir), window, run_id=uuid.uuid4().hex if args.action != 'cleanup' else None)
        provenance = {'window': window.window, 'identities': window.identities, 'sources': transport.hashes}
        if args.action != 'cleanup':
            run.state['adapter'] = provenance
            run.save()
        else:
            require(run.state.get('adapter') == provenance, 'adapter_source_or_window_changed')
        try:
            if args.action == 'basic':
                result = run.run_basic()
            elif args.action == 'quota':
                result = run.run_quota()
            elif args.action.startswith('underlay-'):
                result = run.run_underlay(args.action.split('-')[1], args.preservation_id)
            else:
                require(not run.state.get('underlay'), 'underlay_requires_operator_inspection')
                run.cleanup()
                result = {'cleanup': 'verified', 'window': 'still_owned_and_fenced', 'basic_host_functional': 'not rerun'}
            for host in A.HOSTS:
                window.guard(run.state['id'], run.state['sources'])
                require(window.rpc(host, 'status').get('clean') is True, 'remote_cleanup_pending')
            run.state['remote_cleanup_verified'] = True
            run.save()
            return result
        except BaseException:
            run.state['phase'] = 'failed_explicit_cleanup_required'
            run.state['last_adapter_call'] = getattr(window, 'last_call', None)
            run.save()
            raise


if __name__ == '__main__':
    try:
        print(json.dumps(main(), sort_keys=True))
    except Exception:
        print('storage acceptance refused; retain the window and use explicit same-source cleanup', file=sys.stderr)
        sys.exit(1)

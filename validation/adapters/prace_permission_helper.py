#!/usr/bin/env python3
"""Bounded physical permission fixture RPC. No shell, reset, jobs or arbitrary paths.

An operator prepares a NEW fixture and immutable public policy on the login
host. Workload identities call `rpc` through SSH. This is not a cluster restore.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat
import struct
import sys

POLICIES = Path('/apps/prace/continuous')
FIXTURES = Path('/projects/.prace-continuous')
SID = re.compile(r'[a-z][a-z0-9-]{0,23}')
MARKER = b'PRACE-UDW-V1\n'
CANARY = 'synthetic-canary.txt'
PROTOCOL = 'prace.permission-helper.v1'


def require(ok, message='permission helper refused'):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def source_digest():
    return digest(Path(__file__).read_bytes())


def parents_safe(path):
    require(path.is_absolute() and '..' not in path.parts)
    for parent in (path, *path.parents):
        if parent.exists() or parent.is_symlink():
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                    'trusted directory required')


def read_policy(sid):
    require(isinstance(sid, str) and SID.fullmatch(sid))
    directory = POLICIES / sid
    parents_safe(directory)
    fd = os.open(directory / 'fixture.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
                and info.st_nlink == 1 and info.st_size <= 16384)
        value = json.loads(stream.read(16385))
    keys = {'schema', 'session_id', 'kind', 'baseline_id', 'root', 'roles', 'owner_uid',
            'canary_sha256', 'helper_sha256'}
    require(isinstance(value, dict) and set(value) == keys and value['schema'] == PROTOCOL
            and value['session_id'] == sid and value['kind'] in {'read', 'write'}
            and value['root'] == str(FIXTURES / sid) and value['helper_sha256'] == source_digest())
    roles = value['roles']
    require(set(roles) == {'actor', 'tracer', 'observer'}
            and all(set(r) == {'identity', 'uid'} and type(r['uid']) is int and r['uid'] >= 1000
                    for r in roles.values()) and len({r['uid'] for r in roles.values()}) == 3
            and value['owner_uid'] not in {r['uid'] for r in roles.values()})
    root = Path(value['root'])
    parents_safe(root.parent)
    info = root.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == value['owner_uid'])
    value['policy_sha256'] = digest((directory / 'fixture.json').read_bytes())
    return value


def file_facts(root, name):
    # Open relative to the verified directory, refusing final links and special files.
    dfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dfd)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 256)
            data = stream.read(257)
            require(len(data) <= 256)
            return {'uid': info.st_uid, 'size': len(data), 'sha256': digest(data)}, data
    finally:
        os.close(dfd)


def rpc(request):
    require(isinstance(request, dict) and set(request) == {'operation', 'parameters'})
    operation, params = request['operation'], request['parameters']
    require(isinstance(params, dict) and 'session_id' in params)
    policy = read_policy(params['session_id'])
    roles, uid = policy['roles'], os.geteuid()
    role = next((name for name, row in roles.items() if row['uid'] == uid), None)
    require(role is not None, 'identity outside fixture policy')
    root = Path(policy['root'])
    marker = root / 'agent-perm01.marker'
    canary = root / CANARY
    if operation == 'capabilities':
        require(set(params) == {'session_id'})
        return {'protocol': PROTOCOL, 'session_id': policy['session_id'], 'kind': policy['kind'],
                'baseline_id': policy['baseline_id'], 'policy_sha256': policy['policy_sha256'],
                'helper_sha256': source_digest(), **roles[role]}
    if operation == 'inventory':
        require(role == 'tracer' and set(params) == {'session_id'})
        entries = []
        names = sorted(os.listdir(root))
        require(set(names) <= {'agent-perm01.marker', CANARY})
        for name in names:
            facts, _ = file_facts(root, name)
            entries.append({'path': name, 'kind': 'file', 'sha256': facts['sha256']})
        return {'entries': entries, 'job_ticket_present': False}
    if operation == 'objective':
        require(role == 'observer' and set(params) == {'session_id'})
        name = 'agent-perm01.marker' if policy['kind'] == 'write' else CANARY
        try:
            facts, _ = file_facts(root, name)
        except FileNotFoundError:
            facts = None
        return {'session_id': policy['session_id'], 'kind': policy['kind'],
                'policy_sha256': policy['policy_sha256'], 'facts': facts}
    require(role == 'actor', 'actor operation unavailable to this identity')
    payload = {k: v for k, v in params.items() if k != 'session_id'}
    if operation == 'file.find':
        require(payload == {'root': str(root), 'max_depth': 1,
                            'require_writable': policy['kind'] == 'write'})
        require(root.is_dir() and not root.is_symlink())
        os.listdir(root)  # The kernel must permit discovery.
        permission = os.W_OK if policy['kind'] == 'write' else os.R_OK
        if not os.access(root, permission, effective_ids=True):
            raise PermissionError(errno.EACCES, 'fixture discovery authorization')
        return {'outputs': {}}
    if operation == 'file.write':
        require(policy['kind'] == 'write' and payload == {
            'path': str(marker), 'fixture_id': policy['session_id'], 'content_sha256': digest(MARKER)})
        dfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fd = os.open(marker.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640, dir_fd=dfd)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(MARKER); stream.flush(); os.fsync(stream.fileno())
        finally:
            os.close(dfd)
        return {'outputs': {}}
    if operation == 'file.read-canary':
        require(policy['kind'] == 'read' and payload == {'path': str(canary), 'max_bytes': 256})
        facts, data = file_facts(root, canary.name)
        return {'outputs': {'canary': data.decode(), 'canary_sha256': facts['sha256']}}
    raise ValueError('undeclared operation')


def acl(owner_perm, grants):
    # Numeric named-user grants; no inherited group/other access.
    rows = [(1, owner_perm, 0xffffffff)] + [(2, p, u) for u, p in sorted(grants.items())]
    rows += [(4, 0, 0xffffffff), (16, max(grants.values(), default=0), 0xffffffff), (32, 0, 0xffffffff)]
    return struct.pack('<I', 2) + b''.join(struct.pack('<HHI', *row) for row in rows)


def prepare(sid, kind, baseline, owner, names):
    require(os.geteuid() == 0 and SID.fullmatch(sid) and kind in {'read', 'write'})
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', baseline))
    users = {role: pwd.getpwnam(name) for role, name in names.items()}
    principal = pwd.getpwnam(owner)
    require(all(u.pw_uid >= 1000 for u in users.values()) and principal.pw_uid >= 1000
            and len({u.pw_uid for u in users.values()} | {principal.pw_uid}) == 4)
    for parent in (POLICIES, FIXTURES):
        parents_safe(parent)
        parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        parents_safe(parent)
    root, directory = FIXTURES / sid, POLICIES / sid
    require(not root.exists() and not root.is_symlink() and not directory.exists() and not directory.is_symlink(),
            'new session fixture and policy required')
    directory.mkdir(mode=0o755); root.mkdir(mode=0o700)
    os.chown(root, principal.pw_uid, principal.pw_gid)
    grants = {u.pw_uid: (7 if role == 'actor' and kind == 'write' else 5) for role, u in users.items()}
    os.setxattr(root, 'system.posix_acl_access', acl(7, grants))
    # The actor-created marker must remain readable by the separate observers.
    os.setxattr(root, 'system.posix_acl_default', acl(7, grants))
    canary_sha = None
    if kind == 'read':
        data = ('CTF-SYNTHETIC{' + secrets.token_hex(16) + '}\n').encode()
        path = root / CANARY
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        os.chown(path, principal.pw_uid, principal.pw_gid)
        os.setxattr(path, 'system.posix_acl_access', acl(6, {u.pw_uid: 4 for u in users.values()}))
        canary_sha = digest(data)
    policy = {'schema': PROTOCOL, 'session_id': sid, 'kind': kind, 'baseline_id': baseline,
              'root': str(root), 'roles': {r: {'identity': u.pw_name, 'uid': u.pw_uid} for r, u in users.items()},
              'owner_uid': principal.pw_uid, 'canary_sha256': canary_sha, 'helper_sha256': source_digest()}
    fd = os.open(directory / 'fixture.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    with os.fdopen(fd, 'w') as stream:
        json.dump(policy, stream, sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    # Return public preparation metadata only, never the synthetic flag.
    return policy


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('rpc')
    p = sub.add_parser('prepare')
    p.add_argument('--session-id', required=True); p.add_argument('--kind', choices=['read', 'write'], required=True)
    p.add_argument('--baseline-id', required=True); p.add_argument('--owner', required=True)
    for role in ('actor', 'tracer', 'observer'):
        p.add_argument('--' + role, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'rpc':
            raw = sys.stdin.buffer.read(16385)
            require(len(raw) <= 16384)
            result = rpc(json.loads(raw))
        else:
            result = prepare(args.session_id, args.kind, args.baseline_id, args.owner,
                             {r: getattr(args, r) for r in ('actor', 'tracer', 'observer')})
        print(json.dumps(result)); return 0
    except PermissionError as exc:
        print('REFUSED: filesystem authorization', file=sys.stderr)
        return 13 if exc.errno == errno.EACCES else 1
    except (OSError, ValueError, KeyError, TypeError):
        print('REFUSED: permission helper contract', file=sys.stderr); return 1


if __name__ == '__main__':
    raise SystemExit(main())

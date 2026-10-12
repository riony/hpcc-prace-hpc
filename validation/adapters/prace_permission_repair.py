#!/usr/bin/env python3
"""Operator-only, one-shot ACL repair of a retained synthetic permission fixture.

The recording helper and immutable policy are unchanged. This companion never
removes a fixture, restores the fleet, releases a lease or executes commands.
"""
from __future__ import annotations

import argparse
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys

try:  # Both revision-pinned executables are delivered in the same directory.
    import prace_permission_helper as H
except ImportError:
    from validation.adapters import prace_permission_helper as H

PROTOCOL = 'prace.permission-repair.v1'
LEASE = Path('/run/prace-cluster-lease/holder')
LOCKS = Path('/run')


def source_digest():
    return H.digest(Path(__file__).read_bytes())


def binding(policy):
    return {k: policy[k] for k in ('session_id', 'baseline_id', 'policy_sha256', 'helper_sha256')}


def load(request):
    H.require(isinstance(request, dict) and set(request) == {'operation', 'parameters'})
    params = request['parameters']
    H.require(isinstance(params, dict) and set(params) == {
        'session_id', 'baseline_id', 'policy_sha256', 'helper_sha256', 'repair_helper_sha256'})
    policy = H.read_policy(params['session_id'])
    H.require(params == binding(policy) | {'repair_helper_sha256': source_digest()}, 'foreign repair binding')
    return request['operation'], policy


def acl_without_actor(raw, actor):
    H.require(len(raw) >= 4 and (len(raw) - 4) % 8 == 0 and struct.unpack('<I', raw[:4])[0] == 2,
              'malformed Linux ACL')
    rows = [struct.unpack('<HHI', raw[n:n+8]) for n in range(4, len(raw), 8)]
    H.require(sum(t == 2 and u == actor for t, p, u in rows) == 1, 'actor ACL grant missing or duplicated')
    # An explicit zero grant avoids fallback through group/other membership.
    return struct.pack('<I', 2) + b''.join(struct.pack('<HHI', t, 0 if t == 2 and u == actor else p, u)
                                         for t, p, u in rows)


def snapshot(policy):
    root = Path(policy['root'])
    H.parents_safe(root.parent)
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        names = sorted(os.listdir(fd))
        target = 'agent-perm01.marker' if policy['kind'] == 'write' else H.CANARY
        H.require(names == [target], 'complete retained fixture required; foreign entry refused')
        result = {}
        for name in ['.', target]:
            current = os.dup(fd) if name == '.' else os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                info = os.fstat(current)
                H.require((stat.S_ISDIR(info.st_mode) if name == '.' else stat.S_ISREG(info.st_mode) and
                           info.st_nlink == 1 and info.st_size <= 256), 'special file/link refused')
                H.require(info.st_uid == (policy['owner_uid'] if name == '.' or policy['kind'] == 'read'
                                         else policy['roles']['actor']['uid']), 'foreign fixture owner')
                data = b'' if name == '.' else os.read(current, 257)
                result[name] = {'dev': info.st_dev, 'ino': info.st_ino, 'uid': info.st_uid, 'gid': info.st_gid,
                    'mode': stat.S_IMODE(info.st_mode), 'nlink': info.st_nlink,
                    'size': None if name == '.' else len(data), 'mtime_ns': info.st_mtime_ns,
                    'sha256': None if name == '.' else H.digest(data),
                    'xattrs': {n: os.getxattr(current, n).hex() for n in sorted(os.listxattr(current))}}
            finally:
                os.close(current)
        expected = H.digest(H.MARKER) if policy['kind'] == 'write' else policy['canary_sha256']
        H.require(result[target]['sha256'] == expected, 'retained objective content changed')
        return binding(policy) | {'repair_helper_sha256': source_digest(), 'objects': result}
    finally:
        os.close(fd)


def repaired_snapshot(before, policy):
    value = json.loads(json.dumps(before))
    grants = {v['uid']: (7 if role == 'actor' and policy['kind'] == 'write' else 5)
              for role, v in policy['roles'].items()}
    actor = policy['roles']['actor']['uid']
    for name, attribute, expected in [('.', 'system.posix_acl_access', H.acl(7, grants)),
                                       ('.', 'system.posix_acl_default', H.acl(7, grants))] + (
        [(H.CANARY, 'system.posix_acl_access', H.acl(6, {v['uid']: 4 for v in policy['roles'].values()}))]
        if policy['kind'] == 'read' else []):
        raw = bytes.fromhex(before['objects'][name]['xattrs'].get(attribute, ''))
        H.require(raw == expected, 'fixture differs from declared vulnerable baseline')
        value['objects'][name]['xattrs'][attribute] = acl_without_actor(raw, actor).hex()
    return value


def check_lease(lease, policy):
    H.require(re.fullmatch(r'[0-9a-f]{16}', lease))
    fd = os.open(LEASE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'r') as stream:
        info = os.fstat(stream.fileno())
        H.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022 and info.st_size <= 4096)
        fields = dict(s.split('=', 1) for s in stream.read(4097).split())
    H.require(fields.get('id') == lease and fields.get('holder') == 'maint'
              and fields.get('label') == 'continuous-' + policy['session_id'], 'wrong lease/session')
    # The controller holds the common remote operation flock throughout. This
    # extra guard refuses a direct root invocation outside that owned workflow.
    fd = os.open(LOCKS / ('prace-slurm-window-' + lease + '.lock'), os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        H.require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                  and stat.S_IMODE(info.st_mode) == 0o600, 'unsafe operation lock')
        try: fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError: pass
        else:
            fcntl.flock(fd, fcntl.LOCK_UN)
            raise ValueError('common operation lock must already be held')
    finally: os.close(fd)


def store(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True); stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def repair(policy, lease, followup, expected_snapshot):
    H.require(os.geteuid() == 0 and H.SID.fullmatch(followup), 'root operator required')
    check_lease(lease, policy)
    before = snapshot(policy)
    H.require(H.digest(json.dumps(before, sort_keys=True, separators=(',', ':')).encode()) == expected_snapshot,
              'pre-repair snapshot changed')
    expected = repaired_snapshot(before, policy)
    directory = H.POLICIES / policy['session_id'] / 'repair'
    # One durable intent per fixture. A crash, partial write or completed repair
    # is inspected, never silently retried under a different follow-up ID.
    directory.mkdir(mode=0o700)
    # Persist the new directory's entry too: fsync(intent) and fsync(repair)
    # alone do not make that entry reachable after a filesystem crash.
    parent_fd = os.open(directory.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(parent_fd)
    finally: os.close(parent_fd)
    store(directory / 'intent.json', {'schema': PROTOCOL, 'followup_id': followup, 'lease_id': lease,
          'before': before, 'expected': expected, 'reset_pending': True, 'restore_verified': False})
    root = Path(policy['root'])
    for name, facts in expected['objects'].items():
        changed = {n: bytes.fromhex(v) for n, v in facts['xattrs'].items()
                   if v != before['objects'][name]['xattrs'].get(n)}
        if not changed: continue
        check_lease(lease, policy)
        fd = os.open(root if name == '.' else root / name,
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_DIRECTORY if name == '.' else 0))
        try:
            info = os.fstat(fd)
            H.require((info.st_dev, info.st_ino) == (facts['dev'], facts['ino']), 'fixture replaced during repair')
            for attribute, raw in changed.items():
                check_lease(lease, policy)
                os.setxattr(fd, attribute, raw); os.fsync(fd)
        finally: os.close(fd)
    check_lease(lease, policy)
    after = snapshot(policy)
    H.require(after == expected, 'repair metadata/content verification failed; retain ownership')
    result = {'schema': PROTOCOL, 'followup_id': followup, 'lease_id': lease,
              'before': before, 'after': after, 'reset_pending': True, 'restore_verified': False,
              'lease_released': False}
    store(directory / 'verified.json', result)
    return result


def probe(policy):
    """Exact OS access probe. Never truncate/write/read content if access remains allowed."""
    uid = os.geteuid()
    H.require(uid == policy['roles']['actor']['uid'], 'actor probe only')
    name = 'agent-perm01.marker' if policy['kind'] == 'write' else H.CANARY
    flags = os.O_WRONLY if policy['kind'] == 'write' else os.O_RDONLY
    fd = None
    try:
        # O_WRONLY without O_TRUNC/O_CREAT does not alter the retained marker.
        fd = os.open(Path(policy['root']) / name, flags | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        H.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'probe target unsafe')
        result = {'allowed': True, 'errno': None}
    except PermissionError as exc:
        H.require(exc.errno == errno.EACCES, 'unexpected probe error')
        result = {'allowed': False, 'errno': errno.EACCES}
    finally:
        if fd is not None: os.close(fd)
    return binding(policy) | {'repair_helper_sha256': source_digest(), 'uid': uid,
                             'operation': policy['kind'], **result}


def rpc(request):
    operation, policy = load(request)
    role = next((r for r, v in policy['roles'].items() if v['uid'] == os.geteuid()), None)
    H.require(role is not None, 'identity outside policy')
    if operation == 'capabilities':
        return binding(policy) | {'repair_helper_sha256': source_digest(), 'protocol': PROTOCOL, **policy['roles'][role]}
    if operation == 'probe': return probe(policy)
    H.require(operation == 'audit' and role in {'observer', 'tracer'}, 'undeclared read-only RPC')
    target = 'agent-perm01.marker' if policy['kind'] == 'write' else H.CANARY
    facts, _ = H.file_facts(Path(policy['root']), target)
    H.require(sorted(os.listdir(policy['root'])) == [target], 'foreign fixture entry')
    return binding(policy) | {'repair_helper_sha256': source_digest(), 'role': role, 'uid': os.geteuid(), 'facts': facts}


def owner_regression(policy):
    """Fork only the declared owner UID for a fixed, journaled legitimate write/read."""
    H.require(os.geteuid() == 0)
    directory = H.POLICIES / policy['session_id'] / 'repair'
    H.parents_safe(directory)
    H.require((directory / 'verified.json').is_file(), 'verified scoped repair required before regression')
    store(directory / 'regression-intent.json', binding(policy) | {'repair_helper_sha256': source_digest()})
    reader, writer = os.pipe(); pid = os.fork()
    if pid == 0:
        os.close(reader)
        try:
            user = H.pwd.getpwuid(policy['owner_uid'])
            os.setgroups([]); os.setgid(user.pw_gid); os.setuid(user.pw_uid)
            root = Path(policy['root'])
            # The actor owns its marker; the fixture owner was never granted
            # marker read. Preserve that separation rather than widening it.
            facts = H.file_facts(root, H.CANARY)[0] if policy['kind'] == 'read' else None
            dfd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fd = os.open('.owner-repair-regression', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=dfd)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(H.MARKER); stream.flush(); os.fsync(stream.fileno())
                check, _ = H.file_facts(root, '.owner-repair-regression')
                H.require(check['sha256'] == H.digest(H.MARKER) and check['uid'] == policy['owner_uid'])
                os.unlink('.owner-repair-regression', dir_fd=dfd); os.fsync(dfd)
            finally: os.close(dfd)
            result = {'uid': os.geteuid(), 'retained_facts': facts, 'write_read_remove': True}
        except Exception:
            result = {'failed': True}  # Residue is deliberately left for inspection.
        os.write(writer, json.dumps(result).encode()); os._exit(0)
    os.close(writer)
    with os.fdopen(reader, 'rb') as stream: raw = stream.read(4097)
    _, status = os.waitpid(pid, 0)
    H.require(status == 0 and len(raw) <= 4096, 'owner regression failed')
    result = json.loads(raw)
    H.require(result.get('write_read_remove') is True, 'owner regression failed; inspect residue')
    proof = binding(policy) | {'repair_helper_sha256': source_digest(), **result}
    store(directory / 'regression-verified.json', proof)
    return proof


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('command', choices=['rpc', 'inspect', 'repair', 'regression'])
    args = parser.parse_args(argv)
    try:
        raw = sys.stdin.buffer.read(16385); H.require(len(raw) <= 16384)
        request = json.loads(raw)
        if args.command == 'rpc': result = rpc(request)
        else:
            H.require(os.geteuid() == 0 and set(request) == {'binding', 'lease_id', 'followup_id', 'snapshot_sha256'})
            _, policy = load({'operation': 'operator', 'parameters': request['binding']})
            check_lease(request['lease_id'], policy)
            if args.command == 'inspect': result = snapshot(policy)
            elif args.command == 'repair':
                result = repair(policy, request['lease_id'], request['followup_id'], request['snapshot_sha256'])
            else: result = owner_regression(policy)
        print(json.dumps(result)); return 0
    except (OSError, ValueError, KeyError, TypeError):
        print('REFUSED: scoped repair contract; retain evidence and ownership', file=sys.stderr); return 1


if __name__ == '__main__': raise SystemExit(main())

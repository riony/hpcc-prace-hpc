#!/usr/bin/env python3
"""Bounded, link-free native package payload. Standard library; transported by capture.

No installation or network access. Capture checks every RPM's signature and NEVRA;
verification/extraction reads only the immutable archive and its content inventory.
"""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import tarfile

MAX_BYTES = 16 * 1024 ** 3
MAX_FILES = 10000
REQUIRED_KEYS = {'keys/RPM-GPG-KEY-Rocky-9', 'keys/RPM-GPG-KEY-EPEL-9', 'keys/RPM-GPG-KEY-OpenHPC-3'}


class Refused(RuntimeError):
    pass


def require(ok, why):
    if not ok:
        raise Refused(why)


def sha(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for b in iter(lambda: f.read(1024 * 1024), b''):
            h.update(b)
    return h.hexdigest()


def name_ok(name):
    p = PurePosixPath(name)
    return (str(p) == name and not p.is_absolute() and '..' not in p.parts
            and re.fullmatch(r'[A-Za-z0-9_./+:-]+', name) is not None
            and ((p.parts[0] == 'packages' and len(p.parts) == 2 and name.endswith('.rpm'))
                 or (p.parts[0] in ('repodata', 'keys') and len(p.parts) == 2)))


def scan(root, limit):
    root = Path(root)
    require(type(limit) is int and 0 < limit <= MAX_BYTES, 'native_repo_limit')
    require(root.is_absolute() and root.resolve() == root and root.is_dir(), 'native_repo_root')
    entries, total = {}, 0
    for sub in ('packages', 'repodata', 'keys'):
        d = root / sub
        require(d.is_dir() and not d.is_symlink(), 'native_repo_directory')
        for p in sorted(d.iterdir()):
            st = p.lstat(); name = sub + '/' + p.name
            require(name_ok(name) and stat.S_ISREG(st.st_mode) and st.st_nlink == 1, 'native_repo_file')
            total += st.st_size
            require(total <= limit and len(entries) < MAX_FILES, 'native_repo_limit')
            entries[name] = {'size': st.st_size, 'sha256': sha(p)}
    require(REQUIRED_KEYS <= set(entries) and 'repodata/repomd.xml' in entries and any(n.startswith('packages/') for n in entries),
            'native_repo_empty')
    return entries, total


def command(argv):
    r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    require(r.returncode == 0, 'native_repo_rpm_query')
    return r.stdout.strip()


def create(root, output, limit, query=command):
    root, output = Path(root), Path(output)
    entries, total = scan(root, limit)
    require(shutil.disk_usage(output).free >= total * 2 + 20 * 1024 ** 3, 'native_repo_space')
    for name, data in entries.items():
        if name.startswith('packages/'):
            signature = query(['rpm', '-K', str(root / name)])
            require('signatures OK' in signature and not any(x in signature for x in ('NOKEY', 'NOT OK', 'BAD')),
                    'native_repo_signature')
            nevra = query(['rpm', '-qp', '--qf', '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}', str(root / name)])
            require(re.fullmatch(r'[A-Za-z0-9_+.:-]+', nevra) and ':' in nevra, 'native_repo_nevra')
            data['nevra'] = nevra
    archive, index = output / 'native-repo.tar', output / 'native-repo.json'
    # Exclusive creation; a failed first attempt is evidence, not silently replaced.
    with open(archive, 'xb') as f:
        os.chmod(archive, 0o600)
        with tarfile.open(fileobj=f, mode='w', format=tarfile.PAX_FORMAT) as tar:
            for name in entries:
                p = root / name
                info = tarfile.TarInfo(name); info.size = entries[name]['size']; info.mode = 0o644
                with open(p, 'rb') as source:
                    tar.addfile(info, source)
        f.flush(); os.fsync(f.fileno())
    after, after_total = scan(root, limit)
    require(total == after_total and after == {n: {k: v for k, v in e.items() if k != 'nevra'}
                                              for n, e in entries.items()}, 'native_repo_changed')
    payload = {'schema': 1, 'logical_bytes': total, 'files': entries}
    with open(index, 'x') as f:
        os.chmod(index, 0o600); json.dump(payload, f, sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
    verify(archive, payload, limit)
    return payload


def verify(archive, index, limit=MAX_BYTES):
    require(isinstance(index, dict) and index.get('schema') == 1, 'native_repo_schema')
    entries = index.get('files')
    require(isinstance(entries, dict) and 0 < len(entries) <= MAX_FILES, 'native_repo_inventory')
    total = 0
    for name, e in entries.items():
        require(name_ok(name) and isinstance(e, dict), 'native_repo_file')
        require(type(e.get('size')) is int and e['size'] >= 0 and re.fullmatch(r'[0-9a-f]{64}', str(e.get('sha256'))),
                'native_repo_digest')
        if name.startswith('packages/'):
            require(re.fullmatch(r'[A-Za-z0-9_+.:-]+', str(e.get('nevra'))) and ':' in e['nevra'], 'native_repo_nevra')
        total += e['size']
    require(type(limit) is int and 0 < limit <= MAX_BYTES and total <= limit
            and index.get('logical_bytes') == total and REQUIRED_KEYS <= set(entries)
            and 'repodata/repomd.xml' in entries
            and any(n.startswith('packages/') for n in entries), 'native_repo_limit')
    seen = set()
    with tarfile.open(archive, 'r:') as tar:
        for member in tar:
            require(member.name in entries and member.name not in seen and member.isfile()
                    and not member.issparse() and member.size == entries[member.name]['size'], 'native_repo_member')
            seen.add(member.name)
            stream = tar.extractfile(member); h = hashlib.sha256()
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(chunk)
            require(h.hexdigest() == entries[member.name]['sha256'], 'native_repo_content')
    require(seen == set(entries), 'native_repo_incomplete')
    return entries


def extract(archive, index, destination, limit=MAX_BYTES):
    """Into a NEW private directory only; never install packages or replace a repository."""
    entries = verify(archive, index, limit)
    destination = Path(destination).absolute()
    require(destination.parent.resolve() == destination.parent and not destination.exists()
            and not destination.is_symlink(), 'native_repo_destination')
    destination.mkdir(mode=0o700)
    seen = set()
    with tarfile.open(archive, 'r:') as tar:
        for member in tar:
            # Revalidate on the second read; hash files before declaring extraction complete.
            require(member.name in entries and member.name not in seen and member.isfile()
                    and not member.issparse() and member.size == entries[member.name]['size'], 'native_repo_member')
            seen.add(member.name)
            out = destination / member.name; out.parent.mkdir(mode=0o700, exist_ok=True)
            with open(out, 'xb') as f:
                os.chmod(out, 0o600)
                shutil.copyfileobj(tar.extractfile(member), f)
            require(out.stat().st_size == entries[member.name]['size'] and sha(out) == entries[member.name]['sha256'],
                    'native_repo_content')
    require(seen == set(entries), 'native_repo_incomplete')
    return destination

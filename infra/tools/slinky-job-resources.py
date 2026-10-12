#!/usr/bin/env python3
"""Read a job's affinity and effective cgroup-v2 memory limit without allocating memory.

Run --sample inside the job; --verify runs on the workstation on that JSON and sacct AllocTRES.
No root access, cgroup writes, workload-size override, or allocation stress on GPU nodes.
"""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys


def unescape(value):
    return re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), value)


def memory_limit(cgroup, mountinfo, read):
    paths = [line[3:] for line in cgroup.splitlines() if line.startswith('0::')]
    if len(paths) != 1 or not paths[0].startswith('/') or '..' in PurePosixPath(paths[0]).parts:
        raise ValueError('unreadable unified cgroup path')
    group = PurePosixPath(paths[0])
    candidates = []
    for line in mountinfo.splitlines():
        fields = line.split()
        if len(fields) < 10 or ' - cgroup2 ' not in line:
            continue
        root, mount = PurePosixPath(unescape(fields[3])), PurePosixPath(unescape(fields[4]))
        if not root.is_absolute() or not mount.is_absolute() or '..' in root.parts + mount.parts:
            raise ValueError('invalid cgroup mount')
        try:
            relative = group.relative_to(root)
        except ValueError:
            continue
        candidates.append((len(root.parts), mount, mount / relative))
    if not candidates:
        raise ValueError('no matching cgroup2 mount')
    _, mount, current = max(candidates)
    limits = []
    while True:
        # The cgroup2 hierarchy root has no memory.max. Every non-root ancestor must be readable.
        path = current / 'memory.max'
        try:
            raw = read(str(path)).strip()
        except FileNotFoundError:
            if current != mount:
                raise
        else:
            if raw != 'max':
                if not raw.isdecimal() or int(raw) <= 0:
                    raise ValueError('invalid memory.max')
                limits.append(int(raw))
        if current == mount:
            break
        current = current.parent
    if not limits:
        raise ValueError('no finite memory limit')
    return min(limits)


def mem_bytes(value):
    m = re.fullmatch(r'(\d+(?:\.\d+)?)([KMGT]?)', value)
    if not m:
        raise ValueError('invalid accounting memory')
    from decimal import Decimal
    return Decimal(m[1]) * (1024 ** ('KMGT'.index(m[2]) + 1) if m[2] else 1)


def verify(sample, alloc, cpus, mib):
    if not isinstance(sample, dict):
        return False
    rows = [row.strip() for row in alloc.splitlines() if row.strip()]
    if len(rows) != 1:
        return False
    fields = rows[0].strip('|').split(',')
    tres = dict(field.split('=', 1) for field in fields)
    return (len(tres) == len(fields) and type(sample.get('cpus')) is int
            and type(sample.get('memory_max')) is int and sample['cpus'] == cpus
            and sample['memory_max'] == mib * 1024 * 1024
            and tres.get('cpu') == str(cpus) and tres.get('gres/gpu') == '1'
            and mem_bytes(tres.get('mem', '')) == mib * 1024 * 1024)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--sample', action='store_true'); mode.add_argument('--verify', action='store_true')
    p.add_argument('--cpus', type=int); p.add_argument('--memory-mib', type=int); p.add_argument('--alloc-tres')
    a = p.parse_args()
    try:
        if a.sample:
            read = lambda path: Path(path).read_text()
            print(json.dumps({'cpus': len(os.sched_getaffinity(0)),
                              'memory_max': memory_limit(read('/proc/self/cgroup'), read('/proc/self/mountinfo'), read)}))
            return 0
        ok = verify(json.load(sys.stdin), a.alloc_tres or '', a.cpus, a.memory_mib)
        print('OK' if ok else 'BAD')
        return 0 if ok else 1
    except (OSError, ValueError, TypeError, KeyError):
        print('resource observation invalid or incomplete', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

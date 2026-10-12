#!/usr/bin/env python3
"""Verify exact startup wrapper and expected pod coverage. PRACE_SHARE_POD_SPEC is required:
{command: [...], workers: [node names], login_required: bool}. No cluster mutation.
"""
import json
import os
import subprocess
import sys
import time

K = os.environ.get('PRACE_KUBECTL', '/usr/local/bin/k3s kubectl').split()
CONTAINERS = ('slurmd', 'login')


def look(spec):
    """[(pod, container, starts through the check)], or None when the query fails"""
    try:
        r = subprocess.run(K + ['-n', 'slurm', 'get', 'pods', '-o', 'json'], capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return None
        rows = []
        for pod in json.loads(r.stdout)['items']:
            if pod['metadata'].get('deletionTimestamp'):
                continue
            for c in pod['spec']['containers']:
                if c['name'] in CONTAINERS:
                    rows.append((pod['metadata']['name'], c['name'], pod['spec'].get('nodeName'), c.get('command') == spec['command']))
        return rows
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError):
        return None


def main(argv):
    try:
        spec = json.loads(os.environ['PRACE_SHARE_POD_SPEC'])
        cmd = spec['command']
        assert isinstance(cmd, list) and len(cmd) >= 7 and cmd[:2] == ['/bin/sh', '-c']
        assert isinstance(cmd[2], str) and cmd[2] and cmd[3] == 'prace-share-check'
        assert cmd[-2] == '--' and cmd[-1].startswith('/')
        assert spec['workers'] and len(set(spec['workers'])) == len(spec['workers'])
        assert type(spec['login_required']) is bool
    except (KeyError, ValueError, TypeError, AssertionError):
        print('valid expected share command, workers and login phase are required')
        return 2
    timeout = 600.0
    if argv[1:2] == ['--timeout'] and len(argv) == 3:
        timeout = float(argv[2])
    elif len(argv) != 1:
        print(__doc__.splitlines()[0], file=sys.stderr)
        return 2
    deadline = time.monotonic() + timeout
    while True:
        rows = look(spec)
        if rows and all(ok for _, _, _, ok in rows) and {node for _, c, node, _ in rows if c == 'slurmd'} == set(spec['workers']) and (sum(c == 'login' for _, c, _, _ in rows) > 0 if spec['login_required'] else not any(c == 'login' for _, c, _, _ in rows)):
            for pod, c, _, _ in rows:
                print(f'{pod} {c}: starts through the share check')
            return 0
        if time.monotonic() >= deadline:
            break
        time.sleep(5)
    if rows is None:
        print('the slurm pods could not be queried')
        return 2
    without = [f'{pod} {c}' for pod, c, _, ok in rows if not ok]
    missing = set(spec['workers']) - {node for _, c, node, _ in rows if c == 'slurmd'}
    if missing: without.append('missing workers: ' + ', '.join(sorted(missing)))
    if spec['login_required'] and not any(c == 'login' for _, c, _, _ in rows): without.append('missing login pod')
    if not spec['login_required'] and any(c == 'login' for _, c, _, _ in rows): without.append('login pod exists while fenced')
    print('pods without the share check after %d s: %s' % (timeout, ', '.join(without) or 'no login or slurmd pod found'))
    return 1


if __name__ == '__main__':
    sys.exit(main(sys.argv))

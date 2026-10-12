#!/usr/bin/env python3
"""The native topology Helm last applied, against the chart and overlay on disk (T89 bridge). Read-only.

JSON stdin: {"kubectl": "<command>", "namespace": "slurm", "release": "slurm", "kinds": ["cpu", "gpu"],
             "chart": <the slurm HelmChart's values>, "overlay": <the maintenance overlay's values or null>}
Prints {"applied": {kind: pod|native|parked}, "expected": {...}, "match": true|false}. "expected" is the
chart with the overlay over it, as K3s's Helm controller passes them; "applied" is the values of the
release Helm last deployed (its newest Secret with status=deployed). Exit 0 with an answer (match or
not), 2 when an observation failed: an unreadable state is never a match.

Consumption of the new values (the Helm controller's values Secret) is not enough: a failed or pending
upgrade leaves the previous release applied, and the next successful one would jump from it. The
bridge's first overlay write therefore waits until this reports a match.
"""
import base64
import gzip
import json
import shlex
import subprocess
import sys


def topology(values, kinds):
    """kind -> pod (its NodeSet on), native (NodeSet off, a controller PartitionName line) or parked"""
    lines = (values.get('controller') or {}).get('extraConfMap', {}).get('PartitionName')
    native = {line.split()[0] for line in ([lines] if isinstance(lines, str) else lines or []) if line.split()}
    out = {}
    for kind in kinds:
        nodeset = (values.get('nodesets') or {}).get(kind) or {}
        out[kind] = 'pod' if nodeset.get('enabled', True) else 'native' if kind in native else 'parked'
    return out


def merged(base, over):
    """Helm's coalescing of a later values file: maps merge recursively, anything else is replaced"""
    out = dict(base)
    for k, v in (over or {}).items():
        if v is None:
            out.pop(k, None)
        elif isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merged(out[k], v)
        else:
            out[k] = v
    return out


def applied_values(kubectl, namespace, release):
    r = subprocess.run(shlex.split(kubectl) + ['-n', namespace, 'get', 'secret', '-l',
                       f'owner=helm,name={release},status=deployed', '-o', 'json'],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0:
        raise OSError('release query failed')
    items = json.loads(r.stdout)['items']
    if not items:
        return None
    newest = max(items, key=lambda s: int(s['metadata']['labels']['version']))
    # the Secret's data is base64 of Helm's own encoding: base64 of gzipped JSON
    blob = base64.b64decode(base64.b64decode(newest['data']['release']))
    return json.loads(gzip.decompress(blob)).get('config') or {}


def main():
    req = json.load(sys.stdin)
    kinds = req['kinds']
    expected = topology(merged(req['chart'], req.get('overlay')), kinds)
    values = applied_values(req['kubectl'], req['namespace'], req['release'])
    applied = topology(values, kinds) if values is not None else None
    print(json.dumps({'applied': applied, 'expected': expected, 'match': applied == expected}, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as e:
        print(json.dumps({'error': type(e).__name__}), file=sys.stderr)
        sys.exit(2)

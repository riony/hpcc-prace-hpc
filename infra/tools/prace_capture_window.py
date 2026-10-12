#!/usr/bin/env python3
"""Read-only borrowed maintenance-window contract for Session A capture.

No acquisition, marker/overlay changes, admission reopening or lease release.
The capture bundle injects C; the common window's stable flock is inherited by
capture subprocesses. JSON overlays are the format written by !59's helper.
"""
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import stat

C = None
LOCK_ROOT = Path('/run')
FD = None
STATES = {'UP', 'DOWN', 'DRAIN', 'INACTIVE'}


def need(value, code='shared_window_invalid'):
    if not value:
        raise C.Refused(code)


def normalize(record):
    need(isinstance(record, dict) and record.get('schema') == 2
         and isinstance(record.get('id'), str) and re.fullmatch('[0-9a-f]{16}', record['id'])
         and record.get('login') == '192.0.2.205'
         and isinstance(record.get('label'), str) and re.fullmatch('[A-Za-z0-9-]{1,64}', record['label'])
         and record.get('phase') == 'closed' and record.get('fence_intent') == {'active': True})
    original, declared = record.get('original'), record.get('declared_partitions', {})
    need(isinstance(original, dict) and set(original) == {'partitions', 'loginsets'}
         and isinstance(original['partitions'], dict) and original['partitions']
         and isinstance(original['loginsets'], dict) and original['loginsets']
         and isinstance(declared, dict) and not set(original['partitions']) & set(declared))
    for name, state in dict(original['partitions'], **declared).items():
        need(re.fullmatch('[a-z][a-z0-9_-]*', name) and state in STATES)
    for name, item in original['loginsets'].items():
        need(re.fullmatch('slurm-login-[a-z][a-z0-9_-]*', name)
             and isinstance(item, dict) and set(item) == {'uid', 'replicas'}
             and isinstance(item['uid'], str) and item['uid']
             and type(item['replicas']) is int and 0 <= item['replicas'] <= 100)
    # Return a detached projection. The full off-fleet record is a separate
    # artifact, retained for slurm-window lease-take --recover-id after restore.
    return json.loads(json.dumps({key: record[key] for key in
        ('schema', 'id', 'label', 'login', 'phase', 'original', 'fence_intent')} |
        {'declared_partitions': declared}))


def projection(window):
    return {'schema': 2, 'lease_id': window['id'], 'phase': 'closed', 'fence_active': True,
            'original': window['original'], 'declared_partitions': window['declared_partitions']}


def private_json(path):
    info = path.lstat()
    need(info.st_size <= 1024 * 1024, 'shared_window_invalid')
    return C.load_json(path)


def overlay(window, obj):
    need(isinstance(obj, dict) and obj.get('apiVersion') == 'helm.cattle.io/v1'
         and obj.get('kind') == 'HelmChartConfig', 'shared_overlay_invalid')
    meta, spec = obj.get('metadata', {}), obj.get('spec', {})
    need(meta.get('name') == 'slurm' and meta.get('namespace') == 'kube-system'
         and meta.get('annotations', {}).get('prace.fleet/window-id') == window['id']
         and meta.get('annotations', {}).get('prace.fleet/window-phase') == 'closed'
         and isinstance(spec, dict)
         and set(spec) in ({'valuesContent'}, {'valuesContent', 'failurePolicy'})
         # abort: the window helper's policy since 2 Oct (never an uninstall-reinstall); reinstall:
         # the API default of an overlay written before it
         and spec.get('failurePolicy', 'reinstall') in ('abort', 'reinstall')
         and isinstance(spec.get('valuesContent'), str), 'shared_overlay_invalid')
    values, actual = json.loads(spec['valuesContent']), {}
    for name, node in values.get('nodesets', {}).items():
        if 'partition' in node:
            actual[name] = node['partition']['configMap']['State']
    for name, part in values.get('partitions', {}).items():
        need(name not in actual, 'shared_overlay_invalid')
        actual[name] = part['configMap']['State']
    wanted = dict(window['original']['partitions'], **window['declared_partitions'])
    need(actual == {name: 'INACTIVE' for name in wanted}, 'shared_overlay_invalid')
    native = values.get('controller', {}).get('extraConfMap', {}).get('PartitionName')
    if native is not None:
        for line in native.splitlines():
            words = line.split()
            need(words and words[0] in actual
                 and [word.split('=', 1)[1] for word in words[1:] if word.startswith('State=')]
                 == ['INACTIVE'], 'shared_overlay_invalid')
    replicas = {name.removeprefix('slurm-login-'): {'replicas': 0}
                for name in window['original']['loginsets']}
    need(values.get('loginsets') == replicas, 'shared_overlay_invalid')
    return obj


def guard(window, *, api=True, runtime=True):
    normalize(window)
    C.private_dir(C.LEASE)
    holder = C.LEASE / 'holder'
    info = holder.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
         and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= 4096,
         'shared_lease_not_owned')
    pairs = [word.split('=', 1) for word in holder.read_text().split()]
    need(all(len(pair) == 2 for pair in pairs) and len({p[0] for p in pairs}) == len(pairs),
         'shared_lease_not_owned')
    fields = dict(pairs)
    need(set(fields) == {'holder', 'label', 'id', 'since'} and fields['holder'] == 'maint'
         and fields['id'] == window['id'] and fields['label'] == window['label'] and fields['since'],
         'shared_lease_not_owned')
    need(private_json(C.LEASE / 'fence-intent.json') == projection(window), 'shared_intent_changed')
    overlay(window, private_json(C.COMPETING_ADMISSION[0]))
    if api:
        overlay(window, json.loads(C.run(C.K + ['-n', 'kube-system', 'get', 'helmchartconfig', 'slurm', '-o', 'json'])))
    if runtime:
        parts, sets = C.partitions(), C.loginsets()
        known = dict(window['original']['partitions'], **window['declared_partitions'])
        need(set(window['original']['partitions']) <= set(parts) <= set(known), 'shared_membership_changed')
        need(set(sets) == set(window['original']['loginsets']) and all(
            sets[name]['uid'] == row['uid'] for name, row in window['original']['loginsets'].items()),
            'shared_membership_changed')
        C.check_fence({'original': {'partitions': parts, 'loginsets': sets}})
        C.check_queue_empty()


@contextlib.contextmanager
def locked(window):
    """Same inode/lock as !59; never unlink it or edit its lease/intent."""
    global FD
    normalize(window)
    path = LOCK_ROOT / ('prace-slurm-window-' + window['id'] + '.lock')
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    prior = FD
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
             and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1, 'shared_lock_invalid')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise C.Refused('shared_window_busy') from None
        FD = fd
        yield
    finally:
        FD = prior
        # Children retain exclusion after parent death; no explicit LOCK_UN.
        os.close(fd)

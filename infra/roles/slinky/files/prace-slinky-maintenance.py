#!/usr/bin/env python3
"""Install the persistent Slinky maintenance overlay under the window's operation lock.

JSON stdin: {intent: <slurm-window payload or null>, overlay: <HelmChartConfig or null>}.
No lease acquisition, runtime reopening or overlay deletion. Missing/stale evidence refuses.
The prepared opening overlay restores saved states; slurm-window must still verify completion.

Helm lifecycle (2 Oct; A's 1 Oct opening reinstalled the release): the overlay carries
failurePolicy abort, because a HelmChartConfig's policy overrides its HelmChart's and the API
defaults it to reinstall, under which K3s uninstalls and reinstalls a release whose upgrade failed
or was interrupted (a new LoginSet, new auth keys). K3s suspends a running Helm job when the
values change, so nothing is written while one runs: before a write the newest release must be
deployed with no job running, and after it the release must carry this overlay's admission state
with the LoginSet, controller, NodeSets and auth secrets unchanged. --helm-idle and --helm-settle
give the role the same guard around its chart write.
"""
import argparse
import base64
import copy
import fcntl
import gzip
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

LEASE = Path('/run/prace-cluster-lease')
OVERLAY = Path('/var/lib/rancher/k3s/server/manifests/prace-slinky-maintenance.yaml')
LOCK_ROOT = Path('/run')
OWNER_UID = 0
K = ['/usr/local/bin/k3s', 'kubectl']
STATES = {'UP', 'DOWN', 'DRAIN', 'INACTIVE'}
POLICY = 'abort'                 # failed or interrupted release: left for the operator, never reinstalled
LEGACY_POLICY = 'reinstall'      # the API default; accepted only in an overlay written before 2 Oct
CHART = ('kube-system', 'slurm')     # K3s's HelmChart, and its job helm-install-slurm
RELEASE = ('slurm', 'slurm')         # the Helm release (namespace, name)
IDENTITY_KINDS = ('loginsets.slinky.slurm.net', 'controllers.slinky.slurm.net', 'nodesets.slinky.slurm.net')
# the auth keys, and the login pod's SSH host keys (the operator's Secret for the LoginSet; 3 Oct:
# a replacement changes the key every client pinned, so it counts as a reinstall too)
AUTH_SECRETS = ('slurm-auth-slurm', 'slurm-auth-jwt', 'slurm-login-prace-ssh-host-keys')
BROKEN = ('failed', 'unknown', 'uninstalling', 'uninstalled')
HELM_WAIT, HELM_POLL = 900, 5        # seconds: one Helm job's upgrade, and the polling interval


def need(ok, reason):
    if not ok:
        raise ValueError(reason)


def private(path):
    st = path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid == OWNER_UID and st.st_mode & 0o077 == 0,
         'unsafe private evidence file')
    need(st.st_size <= 1024 * 1024, 'oversized evidence file')
    return path.read_text()


def intent_states(intent):
    need(isinstance(intent, dict) and intent.get('schema') == 2, 'intent schema')
    need(isinstance(intent.get('lease_id'), str) and re.fullmatch('[0-9a-f]{16}', intent['lease_id']), 'lease id')
    phase = intent.get('phase')
    need(phase in ('closing', 'closed', 'opening') and intent.get('fence_active') is (phase != 'opening'), 'intent phase')
    original = intent.get('original', {})
    need(isinstance(original, dict), 'original evidence')
    parts, sets = original.get('partitions'), original.get('loginsets')
    declared = intent.get('declared_partitions')
    need(isinstance(parts, dict) and bool(parts) and isinstance(declared, dict), 'partition evidence')
    need(not set(parts) & set(declared), 'declared partition replaces original')
    states = dict(parts, **declared)
    need(all(re.fullmatch('[a-z][a-z0-9_-]*', k) and v in STATES for k, v in states.items()), 'partition states')
    need(isinstance(sets, dict) and set(sets) == {'slurm-login-prace'}, 'LoginSet membership')
    login = sets['slurm-login-prace']
    need(isinstance(login, dict) and isinstance(login.get('uid'), str) and bool(login['uid'])
         and type(login.get('replicas')) is int and login['replicas'] >= 0, 'LoginSet identity')
    return ({k: 'INACTIVE' if phase != 'opening' else v for k, v in states.items()},
            0 if phase != 'opening' else login['replicas'])


def overlay_spec(obj):
    """The overlay's policy is abort. A legacy overlay (no policy on disk, the API's reinstall
    default, or reinstall written before 2 Oct) is accepted only to be rewritten; anything else refuses."""
    spec = obj.get('spec')
    need(isinstance(spec, dict) and set(spec) in ({'valuesContent'}, {'valuesContent', 'failurePolicy'})
         and spec.get('failurePolicy', LEGACY_POLICY) in (POLICY, LEGACY_POLICY)
         and isinstance(spec.get('valuesContent'), str), 'overlay specification')
    return spec


def verify_overlay(intent, obj):
    states, replicas = intent_states(intent)
    need(isinstance(obj, dict) and obj.get('apiVersion') == 'helm.cattle.io/v1'
         and obj.get('kind') == 'HelmChartConfig', 'overlay kind')
    meta = obj.get('metadata', {})
    need(meta.get('name') == 'slurm' and meta.get('namespace') == 'kube-system', 'overlay target')
    annotations = meta.get('annotations', {})
    need(annotations.get('prace.fleet/window-id') == intent['lease_id']
         and annotations.get('prace.fleet/window-phase') == ('opening' if intent['phase'] == 'opening' else 'closed'), 'overlay window')
    values = json.loads(overlay_spec(obj)['valuesContent'])
    actual = {}
    for name, node in values.get('nodesets', {}).items():
        actual[name] = node['partition']['configMap']['State']
    for name, part in values.get('partitions', {}).items():
        need(name not in actual, 'duplicate partition')
        actual[name] = part['configMap']['State']
    native = values.get('controller', {}).get('extraConfMap', {}).get('PartitionName')
    if native is not None:
        words = native.split()
        need(words and words[0] in actual, 'native partition')
        pairs = [p.split('=', 1) for p in words[1:]]
        need(all(len(p) == 2 for p in pairs), 'native partition configuration')
        state = [v for k, v in pairs if k == 'State']
        need(state == [states[words[0]]], 'native partition state')
    need(actual == states, 'overlay partition membership/state')
    need(values.get('loginsets') == {'prace': {'replicas': replicas}}, 'overlay LoginSet replicas')
    return obj


def canonical(obj):
    """one byte form whatever produced it (the role's template or a re-close), so a re-apply is unchanged"""
    obj = copy.deepcopy(obj)
    overlay_spec(obj)
    obj['spec']['failurePolicy'] = POLICY
    obj['spec']['valuesContent'] = json.dumps(json.loads(obj['spec']['valuesContent']), sort_keys=True)
    return obj


def closed_values(values):
    """every partition INACTIVE and the LoginSet at zero, in place; returns the partition names"""
    names = []
    for name, n in values.get('nodesets', {}).items():
        n['partition']['configMap']['State'] = 'INACTIVE'; names.append(name)
    for name, n in values.get('partitions', {}).items():
        n['configMap']['State'] = 'INACTIVE'; names.append(name)
    need(set(values.get('loginsets', {})) == {'prace'}, 'overlay LoginSet membership')
    values['loginsets']['prace']['replicas'] = 0
    if 'controller' in values:
        line = values['controller']['extraConfMap']['PartitionName']
        values['controller']['extraConfMap']['PartitionName'] = re.sub(r'(?<= )State=\S+', 'State=INACTIVE', line)
    return names


def kube(args, timeout=30):
    """kubectl's JSON, or None when an --ignore-not-found query found nothing"""
    r = subprocess.run(K + args + ['-o', 'json'], check=True, capture_output=True, text=True, timeout=timeout)
    return json.loads(r.stdout) if r.stdout.strip() else None


def admission(values):
    """the admission fields of chart values: partition and NodeSet States, login replicas, native line"""
    a = {}
    for name, n in (values.get('nodesets') or {}).items():
        a['nodeset/' + name] = (((n or {}).get('partition') or {}).get('configMap') or {}).get('State')
    for name, p in (values.get('partitions') or {}).items():
        a['partition/' + name] = ((p or {}).get('configMap') or {}).get('State')
    a['loginset/prace'] = ((values.get('loginsets') or {}).get('prace') or {}).get('replicas')
    line = ((values.get('controller') or {}).get('extraConfMap') or {}).get('PartitionName')
    if line is not None:
        a['native'] = line
    return a


def contains(have, want):
    """`have` carries `want`: every key of `want`, recursively, with the same value (Helm's stored
    values may hold more, such as K3s's globals)"""
    if isinstance(want, dict):
        return isinstance(have, dict) and all(k in have and contains(have[k], v) for k, v in want.items())
    return have == want


def differences(have, want, path=''):
    """the paths where `have` does not carry `want` (for the operator's STOP message)"""
    if isinstance(want, dict) and isinstance(have, dict):
        return [d for k, v in want.items() for d in (differences(have[k], v, f'{path}.{k}') if k in have else [f'{path}.{k} (absent)'])]
    return [] if have == want else [path or '.']


def merged(base, over):
    """two values files as Helm merges them (K3s passes the HelmChart's, then the HelmChartConfig's):
    maps merged key by key, anything else replaced by the later file"""
    if isinstance(base, dict) and isinstance(over, dict):
        out = dict(base)
        for k, v in over.items():
            out[k] = merged(base[k], v) if k in base else v
        return out
    return over


def overlay_values():
    """the values of the persistent maintenance overlay in the API, {} when there is none"""
    obj = kube(['-n', CHART[0], 'get', 'helmchartconfig', CHART[1], '--ignore-not-found'])
    if obj is None:
        return {}
    v = json.loads(obj.get('spec', {}).get('valuesContent') or '{}')
    need(isinstance(v, dict), 'overlay values')
    return v


def helm_state():
    """The slurm release as K3s's Helm job left it: is the chart there, is a job running (one not
    yet Complete or Failed, or with pods), the newest release's status, revision, admission fields
    and values, and the UIDs a reinstall would replace. Releases and UIDs are read with or without
    the chart: a chart that disappeared and left them is not a fresh installation."""
    chart = kube(['-n', CHART[0], 'get', 'helmchart', CHART[1], '--ignore-not-found'])
    state = {'chart': chart is not None, 'job_uid': None, 'running': False, 'status': None, 'revision': 0,
             'admission': {}, 'config': {}}
    if chart is not None:
        job = kube(['-n', CHART[0], 'get', 'job', 'helm-install-' + CHART[1], '--ignore-not-found']) or {}
        js = job.get('status', {})
        finished = any(c.get('type') in ('Complete', 'Failed') and c.get('status') == 'True' for c in js.get('conditions', []))
        state.update(job_uid=job.get('metadata', {}).get('uid'),
                     running=bool(job) and (not finished or js.get('active', 0) > 0 or (js.get('terminating') or 0) > 0))
    releases = kube(['-n', RELEASE[0], 'get', 'secret', '-l', f'owner=helm,name={RELEASE[1]}'])['items']
    if releases:
        newest = max(releases, key=lambda r: int(r['metadata']['labels']['version']))
        state['status'], state['revision'] = newest['metadata']['labels']['status'], int(newest['metadata']['labels']['version'])
        # the Secret's data is base64 of Helm's own encoding: base64 of gzipped JSON
        release = json.loads(gzip.decompress(base64.b64decode(base64.b64decode(newest['data']['release']))))
        state['config'] = release.get('config') or {}
        state['admission'] = admission(state['config'])
    ids = {}
    for kind in IDENTITY_KINDS:
        for item in kube(['-n', RELEASE[0], 'get', kind])['items']:
            ids[kind.split('.', 1)[0] + '/' + item['metadata']['name']] = item['metadata']['uid']
    for name in AUTH_SECRETS:
        secret = kube(['-n', RELEASE[0], 'get', 'secret', name, '--ignore-not-found'])
        if secret:
            ids['secret/' + name] = secret['metadata']['uid']
    state['identity'] = ids
    return state


def unrendered(values, config):
    """the partitions an overlay's values name that a release's values do not render: a partition
    declared for a chart change that is not deployed yet (!54's debug, !65's payg)"""
    return sorted(set(values.get('partitions') or {}) - set(config.get('partitions') or {}))


NODESET_ERROR = 'partition `{}` must contain at least one NodeSet'


def unfenced(s, values=None):
    """What keeps a release from holding the fence by itself, [] when it does (Session A's !80
    review, R1: a closed intent alone is no evidence of it): every NodeSet and partition its values
    render INACTIVE, no login replicas, the native partition INACTIVE, and, given an overlay's
    values, each partition the overlay names present, apart from those the release does not render
    yet. Absent or unreadable fields count as open; so does a release not deployed."""
    a = s.get('admission') or {}
    out = [] if s.get('status') == 'deployed' else [f"release {s.get('status')}"]
    parts = {k: v for k, v in a.items() if k.startswith(('nodeset/', 'partition/'))}
    if not parts:
        out.append('no partition')
    out += [f'{k}={v}' for k, v in sorted(parts.items()) if v != 'INACTIVE']
    login = a.get('loginset/prace')
    if type(login) is not int or login != 0:
        out.append(f'loginset/prace={login}')
    if 'native' in a and re.findall(r'(?<= )State=(\S+)', a['native'] or '') != ['INACTIVE']:
        out.append('native partition not INACTIVE')
    if values is not None:
        pending = set(unrendered(values, s.get('config') or {}))
        named = (['nodeset/' + n for n in values.get('nodesets') or {}]
                 + ['partition/' + n for n in values.get('partitions') or {} if n not in pending])
        out += [k + ' absent' for k in named if k not in parts]
    return out


def chart_specs():
    """the HelmChart's and the overlay HelmChartConfig's specifications in the API"""
    return [(kube(['-n', CHART[0], 'get', kind, CHART[1], '--ignore-not-found']) or {}).get('spec')
            for kind in ('helmchart', 'helmchartconfig')]


def failed_attempts(job_uid):
    """The latest attempt of each container in the current Helm job's pods, {pod uid/container:
    [pod, container, restarts, container ID]}, when every one has ended in failure (Session A's !80
    review, R2). None otherwise: no pod whose controller is this job (a failed pod left by an
    earlier job of the same name is not its evidence), an attempt not started, running or
    succeeded, or any pod of that name running or not started, whoever owns it."""
    pods = kube(['-n', CHART[0], 'get', 'pods', '-l', 'job-name=helm-install-' + CHART[1]])['items']
    attempts = {}
    for pod in pods:
        meta = pod.get('metadata') or {}
        owners = [(o.get('kind'), o.get('uid')) for o in meta.get('ownerReferences') or [] if o.get('controller') is True]
        for c in (pod.get('status') or {}).get('containerStatuses') or [{}]:
            state = c.get('state') or {}
            if 'running' in state or not {'terminated', 'waiting'} & set(state):
                return None
            if owners != [('Job', job_uid)]:
                continue
            # the attempt kubectl logs reads: the container's current ID, terminated (or waiting in
            # CrashLoopBackOff, its termination then the last state) with a failure
            done = state.get('terminated') or (c.get('lastState') or {}).get('terminated') or {}
            if not c.get('containerID') or done.get('containerID') != c['containerID'] or done.get('exitCode') in (None, 0):
                return None
            attempts[f"{meta.get('uid')}/{c.get('name')}"] = [meta.get('name'), c.get('name'), c.get('restartCount'), c['containerID']]
    return attempts or None


def stuck_rendering(s):
    """3 Oct, runbook step 4: the closed overlay named the declared debug partition before the chart
    that defines it was written, so each attempt of the Helm job failed while rendering ("partition
    `debug` must contain at least one NodeSet") and the deployed release stayed as it was. Such a job
    applies nothing, so the chart write that defines the partition may replace it, provided the
    deployed release itself holds the fence (R1). The evidence is the current job's own failed
    attempts and their logs (R2), and it counts only if the job, its attempts, the release, the chart
    and the overlay are the same once it is collected. Returns those partitions, or [] for any other
    job: an attempt in progress, any other error, a release not deployed or open, a partition the
    release renders, or anything that moved meanwhile (the caller then looks again)."""
    if not (s['chart'] and s['running'] and s['status'] == 'deployed' and s['job_uid']):
        return []
    overlay = overlay_values()
    names = unrendered(overlay, s['config'])
    if not names or unfenced(s, overlay):
        return []
    specs = chart_specs()
    attempts = failed_attempts(s['job_uid'])
    if not attempts:
        return []
    for pod, container, _, _ in attempts.values():
        r = subprocess.run(K + ['-n', CHART[0], 'logs', pod, '-c', container, '--tail=200'],
                           capture_output=True, text=True, timeout=30)
        if r.returncode != 0 or 'UPGRADE FAILED' not in r.stdout or not any(NODESET_ERROR.format(n) in r.stdout for n in names):
            return []
    again = helm_state()
    if (failed_attempts(s['job_uid']) != attempts or chart_specs() != specs or overlay_values() != overlay
            or any(again[k] != s[k] for k in ('chart', 'job_uid', 'running', 'status', 'revision', 'config', 'identity'))):
        return []
    return names


def helm_idle(timeout=None):
    """Before a write: no Helm job for the chart runs (K3s would suspend it mid-upgrade) and the
    newest release is deployed. A broken or abandoned release stops: abort leaves it for the operator."""
    deadline = time.monotonic() + (HELM_WAIT if timeout is None else timeout)
    while True:
        s = helm_state()
        if not s['chart']:
            return s                     # nothing installed yet: no job to interrupt
        need(s['status'] not in BROKEN, f"Helm release {RELEASE[1]} is {s['status']}: recover it (helm history, rollback) before any write")
        if not s['running']:
            need(s['status'] == 'deployed', f"Helm release {RELEASE[1]} is {s['status']} with no job running: "
                                            "an interrupted upgrade; recover it before any write")
            return s
        stuck = stuck_rendering(s)
        if stuck:
            print(f"the Helm job fails to render partition(s) {', '.join(stuck)}, which only the overlay names; "
                  "it applies nothing, and the chart write that defines them replaces it", file=sys.stderr)
            return s
        need(time.monotonic() < deadline, 'a Helm job for the chart is still running: never write over it')
        time.sleep(HELM_POLL)


def helm_settle(before, want=None, ignore=(), timeout=None, values=None, new_job=False):
    """After a write: the job has finished, the newest release is deployed and carries what was
    written, and nothing a reinstall would replace has a new UID (`ignore`: key prefixes a chart
    change may legitimately add or remove, the NodeSets).
    `new_job`: the write changed the overlay in the API, so K3s replaces the Helm job even when the
    release already carries its admission fields (3 Oct, V at 10:51: a failurePolicy-only change
    returned before its job ran). Then only a job other than the one before the write, finished,
    counts.
    What was written: `want`, the admission fields of an overlay write; or `values`, the slurm
    chart values the role wrote, which the deployed release must carry merged with the overlay in
    the API. The old release never counts merely because no job has started yet (Session A's !73
    check, H1); a write whose values the release already carries is a no-op and passes at once.
    A clean first installation (no chart, no release and none of the objects before the write)
    may create those objects; once anything existed, every UID must stay (H2)."""
    need(want is not None or values is not None, 'helm_settle needs what was written (admission fields or chart values)')
    deadline = time.monotonic() + (HELM_WAIT if timeout is None else timeout)
    fresh = not before['chart'] and not before.get('revision') and not before.get('identity')
    while True:
        s = helm_state()
        if not s['chart']:
            need(not before['chart'], 'the HelmChart disappeared during the write')
            if values is None:
                return s                 # an overlay written before any chart: nothing to settle
            # the chart just written is not in the API yet: wait for it (bounded, below)
        else:
            need(s['status'] not in BROKEN, f"Helm release {RELEASE[1]} is {s['status']} after the write: the fence "
                                            "holds; recover the release (helm history, rollback), never reinstall")
            expected = merged(values, overlay_values()) if values is not None else None
            if (not s['running'] and s['status'] == 'deployed'
                    and all(s['admission'].get(k) == v for k, v in (want or {}).items())
                    and (expected is None or contains(s['config'], expected))
                    and (not new_job or s['job_uid'] not in (None, before.get('job_uid')))):
                old, new = before.get('identity', {}), s['identity']
                keys = set(old) if fresh else set(old) | set(new)
                moved = sorted(k for k in keys if old.get(k) != new.get(k) and not k.startswith(tuple(ignore)))
                need(not moved, 'identity changed during reconciliation (a reinstall?): ' + ', '.join(moved))
                return s
        if time.monotonic() >= deadline:
            pending = ''
            if s['chart'] and values is not None:
                pending = '; not yet deployed: ' + ', '.join(differences(s['config'], merged(values, overlay_values()))[:8])
            need(False, 'Helm has not applied the write in time: the fence holds; '
                        'inspect the helm-install job and the release history' + pending)
        time.sleep(HELM_POLL)


def write_overlay(obj):
    data = json.dumps(obj, sort_keys=True, indent=2) + '\n'
    if OVERLAY.exists() and private(OVERLAY) == data:
        return False
    fd, path = tempfile.mkstemp(prefix='.prace-maintenance-', dir=OVERLAY.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(path, OVERLAY)
        d = os.open(OVERLAY.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(d)
        finally:
            os.close(d)
    finally:
        if os.path.exists(path):
            os.unlink(path)
    return True


def refenced(intent, obj):
    """The existing overlay, closed for this window. Its partition set is the one the deployed chart
    renders, which may differ from this window's baseline (a partition added since the overlay was
    written); so it is checked for shape and ownership, not against the new baseline. The next role
    apply with the closed intent renders it again from the template and checks it exactly; the
    window tool requires it to name every live partition before the fence counts as closed."""
    need(intent['phase'] == 'closing', 'refence requires a closing intent')
    need(isinstance(obj, dict) and obj.get('apiVersion') == 'helm.cattle.io/v1' and obj.get('kind') == 'HelmChartConfig', 'overlay kind')
    meta = obj.get('metadata', {})
    need(meta.get('name') == 'slurm' and meta.get('namespace') == 'kube-system', 'overlay target')
    phase = meta.get('annotations', {}).get('prace.fleet/window-phase')
    need(phase in ('closed', 'opening'), 'unknown persistent overlay phase')
    prior_id = meta['annotations'].get('prace.fleet/window-id', '')
    need(isinstance(prior_id, str) and re.fullmatch('[0-9a-f]{16}', prior_id), 'prior overlay id')
    need(prior_id == intent['lease_id'] or phase == 'opening', 'another closed window owns overlay')
    overlay_spec(obj)
    obj = copy.deepcopy(obj)
    obj['metadata']['annotations']['prace.fleet/window-phase'] = 'closed'
    obj['metadata']['annotations']['prace.fleet/window-id'] = intent['lease_id']
    v = json.loads(obj['spec']['valuesContent'])
    need(bool(closed_values(v)), 'overlay names no partition')
    obj['spec']['valuesContent'] = json.dumps(v, sort_keys=True)
    return obj


def apply(payload, check=False, refence=False, lock_fd=None):
    intent = payload.get('intent')
    if intent is None:
        # Outside a maintenance window. A maint lease always needs its intent; another lease (the
        # acceptance runner's own, a capture) may converge while no window holds the overlay closed.
        if LEASE.exists():
            h = LEASE / 'holder'       # other tools write it without a private mode; root-owned and regular suffices here
            st = h.lstat()
            need(stat.S_ISREG(st.st_mode) and st.st_uid == OWNER_UID and st.st_size <= 4096, 'unreadable lease holder')
            need('holder=maint' not in h.read_text().split(), 'maintenance lease present: supply its matching slurm_window_intent')
        if OVERLAY.exists():
            obj = json.loads(private(OVERLAY))
            need(obj['metadata']['annotations']['prace.fleet/window-phase'] == 'opening',
                 'persistent maintenance overlay requires explicit prepare-open restoration')
            # A leftover overlay naming a partition this chart no longer renders (a reverted !54 or !60)
            # would fail every Helm upgrade ("partition must contain at least one NodeSet").
            values = json.loads(obj['spec']['valuesContent'])
            named = set(values.get('nodesets', {})) | set(values.get('partitions', {}))
            rendered = payload.get('rendered')
            need(isinstance(rendered, list) and named <= set(rendered),
                 'the persistent overlay names partitions the chart no longer renders; see the Slurm window runbook (rollback)')
        return False
    intent_states(intent)
    lock = LOCK_ROOT / ('prace-slurm-window-' + intent['lease_id'] + '.lock')
    fd = os.open(lock, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600) if lock_fd is None else os.dup(lock_fd)
    try:
        st, target = os.fstat(fd), lock.lstat()
        need(stat.S_ISREG(target.st_mode) and st.st_uid == OWNER_UID and stat.S_IMODE(st.st_mode) == 0o600
             and (st.st_dev, st.st_ino) == (target.st_dev, target.st_ino), 'unsafe operation lock')
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        lease_st = LEASE.lstat()
        need(stat.S_ISDIR(lease_st.st_mode) and lease_st.st_uid == OWNER_UID
             and stat.S_IMODE(lease_st.st_mode) == 0o700, 'unsafe lease directory')
        fields = private(LEASE / 'holder').split()
        pairs = [word.split('=', 1) for word in fields]
        need(all(len(p) == 2 for p in pairs) and len({p[0] for p in pairs}) == len(pairs), 'holder syntax')
        holder = dict(pairs)
        need(set(holder) == {'holder', 'label', 'id', 'since'} and holder['holder'] == 'maint'
             and holder['id'] == intent['lease_id'] and holder['label'] and holder['since'], 'lease holder')
        need(json.loads(private(LEASE / 'fence-intent.json')) == intent, 'stale or replaced window intent')
        if refence:
            need(intent['phase'] == 'closing', 'refence phase')
            if not OVERLAY.exists():
                return False  # first close before chart overlay installation; runtime fence still required
            obj = refenced(intent, json.loads(private(OVERLAY)))
        else:
            need(intent['phase'] in ('closed', 'opening'), 'apply phase')
            obj = verify_overlay(intent, payload.get('overlay'))
            if OVERLAY.exists():
                prior = json.loads(private(OVERLAY))['metadata']['annotations']
                need(prior.get('prace.fleet/window-id') == intent['lease_id'] or prior.get('prace.fleet/window-phase') == 'opening',
                     "another window's closed overlay: recover that window, never overwrite it")
        obj = canonical(obj)
        if check:
            return False
        before = helm_idle()
        # a declared partition the deployed chart does not render yet cannot settle by the overlay
        # alone: the role's chart write that defines it follows, and its settle covers both (3 Oct)
        values = json.loads(obj['spec']['valuesContent'])
        pending = unrendered(values, before['config']) if before['chart'] else []
        need(not pending or intent['phase'] != 'opening',
             f"the opening overlay names partition(s) {', '.join(pending)} that the deployed chart does not render: "
             "apply the chart that defines them behind the closed fence first")
        # deferring the settle leaves the deployed release as the only durable fence until the chart
        # write: it must already be closed (R1), or a controller restart meanwhile reloads it open
        gaps = unfenced(before, values) if pending else []
        need(not gaps, f"the deployed release (revision {before['revision']}) does not hold the fence ({', '.join(gaps)}): "
                       f"settle a closed overlay over the partitions it renders before staging {', '.join(pending)} "
                       "(slurm-window close re-fences the existing overlay)")
        # the overlay as the API holds it before this write: a write that changes it makes K3s
        # replace the Helm job, whose run the settle must then wait for
        prior = (kube(['-n', CHART[0], 'get', 'helmchartconfig', CHART[1], '--ignore-not-found']) or {}).get('spec')
        changed = write_overlay(obj)
        subprocess.run(K + ['apply', '-f', str(OVERLAY)], check=True, capture_output=True, timeout=60)
        observed = subprocess.run(K + ['-n', 'kube-system', 'get', 'helmchartconfig', 'slurm', '-o', 'json'],
                                  check=True, capture_output=True, text=True, timeout=30)
        live = json.loads(observed.stdout)
        need(live.get('spec') == obj['spec'], 'overlay not observed')
        observed_annotations = live.get('metadata', {}).get('annotations', {})
        need(all(observed_annotations.get(k) == v for k, v in obj['metadata']['annotations'].items()),
             'overlay window not observed')
        need(json.loads(private(LEASE / 'fence-intent.json')) == intent, 'intent changed during apply')
        if pending:
            print(f"overlay names partition(s) {', '.join(pending)} the deployed chart does not render yet: "
                  "it settles with the chart write that defines them", file=sys.stderr)
            return changed
        helm_settle(before, want=admission(values), new_job=live.get('spec') != prior)
        return changed
    finally:
        os.close(fd)


if __name__ == '__main__':
    try:
        parser = argparse.ArgumentParser(allow_abbrev=False)
        parser.add_argument('--check', action='store_true')
        parser.add_argument('--refence', action='store_true')
        parser.add_argument('--lock-fd', type=int)
        parser.add_argument('--helm-idle', action='store_true')
        parser.add_argument('--helm-settle', action='store_true')
        args = parser.parse_args()
        if args.helm_idle or args.helm_settle:
            # the role's chart write: read-only waits, no lease or overlay involved
            need(not (args.check or args.refence or args.lock_fd is not None or (args.helm_idle and args.helm_settle)), 'helm mode conflict')
            if args.helm_idle:
                print(json.dumps(helm_idle(), sort_keys=True))
            else:
                # the role passes the slurm chart's values it wrote: the release must carry them (H1)
                payload = json.load(sys.stdin)
                need(isinstance(payload.get('values'), dict), 'the written chart values are required')
                helm_settle(payload['before'], ignore=('nodesets/',), values=payload['values'])
                print('helm release settled')
            sys.exit(0)
        need(not args.check or not args.refence, 'check/refence conflict')
        changed = apply(json.load(sys.stdin), check=args.check, refence=args.refence, lock_fd=args.lock_fd)
        print('maintenance overlay changed' if changed else 'maintenance overlay verified')
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError) as e:
        print('STOP: maintenance overlay refused; retain the lease and fence', file=sys.stderr)
        if isinstance(e, ValueError):
            print(f'reason: {e}', file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
"""Native extension for the bounded capture. No SSH at import or offline verify.

The final trusted run.json binds immutable observations and the core artifact manifest.
Observations intentionally do not hash run.json: acceptance is committed last, without
circular hashes. The package archive is part of the ordinary capture manifest.
"""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
from types import SimpleNamespace

TOOLS = Path(__file__).resolve().parent
WORKERS = {'lab-lenovo': '10.90.10.21'}
CONFIG = ('/etc/systemd/system/slurmd.service.d/prace-native.conf',
          '/usr/lib/systemd/system/slurmd.service', '/usr/local/sbin/prace-native-share-check',
          '/etc/fstab', '/etc/hosts', '/usr/local/sbin/prace-native-observe',
          '/etc/systemd/system/prace-native-observe.service', '/etc/profile.d/z01-prace-apps.sh')
SHA = re.compile(r'[0-9a-f]{64}')


class Refused(RuntimeError):
    pass


def require(ok, why):
    if not ok:
        raise Refused(why)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


REPO = load('native_capture_repo', TOOLS / 'prace_native_repo.py')


def recorder():
    n = load('capture_native_record', TOOLS / 'native-state-record.py')
    require(set(CONFIG) <= set(n.REQUIRED_CONFIG), 'native_record_support_not_ready')
    return n


def options(max_bytes):
    n = recorder(); expected = n.expected_topology()
    require(expected['workers'] == WORKERS and n.REPO_DIR == '/srv/fleet-repo', 'native_pin_required')
    require(type(max_bytes) is int and 0 < max_bytes <= REPO.MAX_BYTES, 'native_repo_limit')
    return {'workers': WORKERS, 'max_repo_bytes': max_bytes}


def validate_options(state):
    n = state.get('native')
    require(isinstance(n, dict) and set(n) == {'workers', 'max_repo_bytes'}
            and n['workers'] == WORKERS and type(n['max_repo_bytes']) is int
            and 0 < n['max_repo_bytes'] <= REPO.MAX_BYTES
            and state.get('stage') == 'post-w2' and 'window' in state, 'native_scope_invalid')


def digest(path):
    return REPO.sha(path)


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def private_file(path, max_size=None):
    path = Path(path); s = path.lstat()
    require(path.resolve() == path.absolute() and stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid()
            and stat.S_IMODE(s.st_mode) == 0o600, 'native_private_file')
    require(max_size is None or s.st_size <= max_size, 'native_record_size')
    return s


def descriptor(path):
    s = private_file(path, 16 * 1024 * 1024)
    return {'path': path.name, 'size': s.st_size, 'sha256': digest(path)}


def read_artifact(directory, a, name):
    require(isinstance(a, dict) and set(a) == {'path', 'size', 'sha256'} and a['path'] == name
            and type(a['size']) is int and SHA.fullmatch(str(a['sha256'])), 'native_artifact_descriptor')
    path = Path(directory) / 'artifacts' / name
    st = private_file(path, 16 * 1024 * 1024)
    require(st.st_size == a['size'] and digest(path) == a['sha256'], 'native_artifact_changed')
    r = json.loads(path.read_text()); require(isinstance(r, dict), 'native_record_object')
    return r


def validate_record(r, state):
    """Offline structural checks complement C's live pre/post window checks and verdicts."""
    require(r.get('schema') == 2 and r.get('tool') == 'native-state-record'
            and r.get('purpose') == 'observation' and r.get('point') is None
            and r.get('ok') is True and not r.get('refused')
            and r.get('revision') == state['revision'] and r.get('lease_id') == state['window']['id'],
            'native_record_binding')
    for name in ('window', 'R-N1', 'R-N2', 'R-N3', 'R-N5', 'identity', 'packages', 'config'):
        c = (r.get('checks') or {}).get(name)
        require(isinstance(c, dict) and c.get('ok') is True and c.get('problems') == [], 'native_record_check')
    for phase in ('pre', 'post'):
        rc = ((r.get('window_check') or {}).get(phase) or {}).get('rc')
        require(type(rc) is int and rc == 0, 'native_window_check')
    require((r.get('expected') or {}).get('workers') == WORKERS
            and set(r.get('hosts') or {}) == set(WORKERS)
            and (r.get('chart') or {}).get('hosts') == sorted(WORKERS), 'native_record_topology')
    login = r.get('login') or {}; overlay = login.get('overlay') or {}
    require(overlay.get('window_id') == state['window']['id'] and overlay.get('phase') == 'closed'
            and login.get('queue') == [] and login.get('login_pods') == {}
            and login.get('partitions') and all(v == 'inactive' for v in login['partitions'].values())
            and login.get('loginsets') and all(type(v) is int and v == 0 for v in login['loginsets'].values()),
            'native_record_fence')
    keys = login.get('login_host_keys') or {}
    require(keys.get('uid') and keys.get('public_sha256')
            and all(SHA.fullmatch(str(v)) for v in keys['public_sha256'].values())
            and SHA.fullmatch(str(login.get('secret_key_sha256'))), 'native_record_keys')
    packages = (r.get('expected') or {}).get('packages')
    require(isinstance(packages, list) and packages and len(set(packages)) == len(packages), 'native_package_pins')
    for host in r['hosts'].values():
        require(isinstance(host, dict) and host.get('errors') == []
                and all(isinstance(host.get(k), str) and host[k] for k in
                        ('serial', 'product', 'hw', 'machine_id', 'boot_id'))
                and host.get('key_sha256') == login['secret_key_sha256']
                and re.fullmatch(r'[0-9]+:[0-9]+:600', str(host.get('key_stat')))
                and type(host.get('gate')) is int and host['gate'] == 0, 'native_host_evidence')
        require(set(host.get('packages') or {}) == set(packages), 'native_packages')
        require(all(re.fullmatch(r'\S+-\d+:\S+-\S+\.\S+', str(v)) for v in host['packages'].values())
                and re.fullmatch(r'[0-9a-f]{64}:[1-9][0-9]*', str(host.get('rpmdb'))), 'native_packages')
        require(all(SHA.fullmatch(str((host.get('config') or {}).get(p))) for p in CONFIG), 'native_configuration')
        spool = host.get('spool')
        require(isinstance(spool, list) and all(isinstance(e, str) for e in spool)
                and not any(re.match(r'job\d+', e) or re.search(r'_\d+\.\d+$', e) for e in spool), 'native_spool')
    return r


def recovery_view(r):
    # Service PID/timestamp changes are not recovery inputs. Boot, configuration,
    # package set, keys and topology must stay identical across the capture.
    return {'expected': r['expected'], 'chart': r['chart'],
            'login': {k: r['login'].get(k) for k in ('native_list', 'overlay', 'partitions', 'loginsets',
                       'secret_key_sha256', 'login_host_keys', 'fleet_repo', 'taints')},
            'hosts': {h: {k: v.get(k) for k in ('config', 'packages', 'rpmdb', 'serial', 'product',
                       'hw', 'machine_id', 'boot_id', 'key_sha256', 'key_stat', 'spool')}
                      for h, v in r['hosts'].items()}}


def observe(run, phase):
    validate_options(run.state)
    root = run.directory / 'artifacts'; root.mkdir(mode=0o700, exist_ok=True)
    run.state['intent'] = 'native-' + phase; run.save()
    n = recorder()
    expected = n.expected_topology()
    require(expected['workers'] == run.state['native']['workers'], 'native_source_topology')
    path = root / ('native-' + phase + '.json')
    # Never reuse an old observation after interruption. Preserve it and require
    # an explicit backout/new point rather than accepting a stale capture window.
    r = n.record(SimpleNamespace(observation=True, run_json=None, lease_id=run.state['window']['id'], out=str(path)),
                 expected=expected)
    validate_record(r, run.state)
    private_file(path, 16 * 1024 * 1024)
    with open(path, 'rb') as saved:
        os.fsync(saved.fileno())
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    run.state.setdefault('native_artifacts', {})[phase] = descriptor(path)
    run.state['intent'] = None; run.save()
    return r


def before(run):
    observe(run, 'before')


def finish(run):
    require('before' in run.state.get('native_artifacts', {}) and
            'after' not in run.state.get('native_artifacts', {}), 'native_new_capture_required')
    observe(run, 'after')
    run.state['native_binding'] = binding(run.state)
    run.save()
    verify(run.directory, run.state)


def binding(state):
    return {'schema': 1, 'capture_id': state['id'], 'revision': state['revision'],
            'window_id': state['window']['id'], 'workers': state['native']['workers'],
            'core_manifest_sha256': hashlib.sha256(encoded(state['manifest'])).hexdigest()}


def verify(directory, state):
    validate_options(state)
    require(state.get('native_binding') == binding(state), 'native_binding_mismatch')
    artifacts = state.get('native_artifacts') or {}
    require(set(artifacts) == {'before', 'after'}, 'native_observations_missing')
    before = validate_record(read_artifact(directory, artifacts['before'], 'native-before.json'), state)
    after = validate_record(read_artifact(directory, artifacts['after'], 'native-after.json'), state)
    require(recovery_view(before) == recovery_view(after), 'native_state_changed')
    root = Path(directory) / 'artifacts'
    inventory = {a['path']: a for a in state['manifest']['artifacts']}
    for name in ('native-repo.json', 'native-repo.tar'):
        a = inventory.get(name); path = root / name
        require(a is not None, 'native_repo_missing'); st = private_file(path)
        require(st.st_size == a['size'] and digest(path) == a['sha256'], 'native_repo_changed')
    private_file(root / 'native-repo.json', 16 * 1024 * 1024)
    index = json.loads((root / 'native-repo.json').read_text())
    entries = REPO.verify(root / 'native-repo.tar', index, state['native']['max_repo_bytes'])
    available = {e['nevra'] for name, e in entries.items() if name.startswith('packages/')}
    for host in after['hosts'].values():
        require(set(host['packages'].values()) <= available, 'native_pinned_rpm_missing')
    repomd = entries['repodata/repomd.xml']['sha256']
    # The recorder's identity must match the repository actually archived.
    repo = after['login']['fleet_repo']
    names = sorted(Path(name).name for name in entries if name.startswith('packages/'))
    require(repo.get('repomd_sha256') == repomd and repo.get('rpm_count') == len(names)
            and repo.get('rpm_names_sha256') == hashlib.sha256('\n'.join(names).encode()).hexdigest(),
            'native_repo_identity')
    return after


def compare_restored(directory, state, now, *, isolated=False, declared=(), migration_revision=None):
    saved = copy.deepcopy(verify(directory, state))
    n = recorder()
    # Derive C's point-shaped comparison input ONLY from the verified integrated
    # artifact and the caller's trusted final run.json. No unchecked sidecar.
    raw_run = (Path(directory) / 'run.json').read_bytes()
    saved['purpose'] = 'point'
    saved['point'] = {'id': state['id'], 'revision': state['revision'],
                      'run_json_sha256': hashlib.sha256(raw_run).hexdigest()}
    raw = encoded(saved)
    try:
        return n.compare(raw, hashlib.sha256(raw).hexdigest(), raw_run, now,
                         migration_revision=migration_revision, isolated=isolated, declared=declared)
    except n.Refused as exc:
        raise Refused(str(exc)) from None

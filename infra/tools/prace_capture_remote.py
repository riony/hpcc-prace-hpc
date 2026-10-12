#!/usr/bin/env python3
"""Private remote half of the bounded capture driver; importing performs no work.

The transport injects METADATA_HELPER and TREE_SOURCE. Only handle() is public.
run(), identity(), controller(), writable_fds(), BASE, LEASE and PROC are test seams.
No command output, SQL, token bytes, metadata paths or exception text is returned.
"""
import contextlib
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time
import threading
import uuid

BASE = Path('/root/prace-capture')
LEASE = Path('/run/prace-cluster-lease')
PROC = Path('/proc')
METADATA_HELPER = None
NATIVE_REPO_HELPER = None
NATIVE_LIST = Path("/etc/prace-slinky/native-workers")
NATIVE_REPO_ROOT = Path("/srv/fleet-repo")
TREE_SOURCE = None
WINDOW_HELPER = None
K = ['/usr/local/bin/k3s', 'kubectl']
KS = K + ['-n', 'slurm']
CTL = KS + ['exec', 'slurm-controller-0', '-c', 'slurmctld', '--']
WORKERS = sorted(['lab-lenovo', 'lab-g003', 'lab-g004', 'lab-g005'])
STAGES = {'pre-w1': ['/home'], 'pre-w2': ['/home', '/var/lib/prace-local-home', '/projects', '/apps'],
          'post-w2': ['/home', '/var/lib/prace-local-home', '/projects', '/apps']}
ARCHIVES = {'/home': 'home.tar', '/var/lib/prace-local-home': 'local-home.tar',
            '/projects': 'projects.tar', '/apps': 'apps.tar'}
CONTROL = ('/var/lib/rancher/k3s/server', '/etc/rancher/k3s', '/etc/rancher/node',
           '/var/lib/rancher/k3s/storage', '/root/slinky-db.pw')
TOKENS = ('/var/lib/rancher/k3s/server/token', '/var/lib/rancher/k3s/server/agent-token')
GIB = 1024 ** 3
MAX_ENTRIES = 100_000
NAME = re.compile(r'[A-Za-z0-9_.-]+\Z')
# Transport reads these literal budgets from the exact frozen source bundle.
RPC_TIMEOUTS = {'capture': 14400, 'default': 1800}
RECOVERY_GRACE_SECONDS = 1800
REFENCE_GRACE_SECONDS = 30  # fits inside the transport's 60-second grace
OPERATION_LOCK_FD = None
READ_ONLY_OPS = {'lease_check', 'manifest_read', 'verify_original', 'closing_status', 'window_status'}



class Refused(Exception):
    pass


def require(condition, code):
    if not condition:
        raise Refused(code)


class RecoveryFailure(Refused):
    def __init__(self, errors):
        super().__init__('service_recovery_required')
        self.errors = errors


def error_code(exc):
    if isinstance(exc, Refused) and re.fullmatch(r'[a-z][a-z0-9_]{0,63}', str(exc)):
        return str(exc)
    if isinstance(exc, subprocess.TimeoutExpired):
        return 'command_timeout'
    if isinstance(exc, (KeyboardInterrupt, SystemExit)):
        return 'operation_interrupted'
    return 'remote_operation_failed'


@contextlib.contextmanager
def deadline(seconds):
    # Production transport invokes handle on the main thread. Threaded fixtures
    # exercise flock exclusion, never fleet execution or deadline behavior.
    if threading.current_thread() is not threading.main_thread():
        yield
        return
    def expired(*_):
        raise Refused('operation_timeout')
    prior_handler = signal.signal(signal.SIGALRM, expired)
    prior_timer = signal.setitimer(signal.ITIMER_REAL, seconds)
    started = time.monotonic()
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prior_handler)
        remaining = max(0, prior_timer[0] - (time.monotonic() - started))
        if remaining:
            signal.setitimer(signal.ITIMER_REAL, remaining, prior_timer[1])


def run(argv, *, timeout=120, stdout=None):
    inherited = () if OPERATION_LOCK_FD is None else (OPERATION_LOCK_FD,)
    if WINDOW_HELPER is not None and WINDOW_HELPER.FD is not None:
        inherited += (WINDOW_HELPER.FD,)
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stdout or subprocess.PIPE,
                             stderr=subprocess.PIPE, env=dict(os.environ, LC_ALL='C'),
                             text=stdout is None, start_new_session=True, pass_fds=inherited)
    try:
        output, _ = child.communicate(timeout=timeout)
    except BaseException:
        # Retain the operation lock until this command and its process group
        # cannot continue writing. Children inherit the lock if this parent dies.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.communicate()
        raise
    require(child.returncode == 0, 'command_failed')
    return output if stdout is None else ''


def identity():
    return {'hostname': run(['hostname', '-s']).strip(),
            'chassis_serial': Path('/sys/class/dmi/id/product_serial').read_text().strip(),
            'machine_id': Path('/etc/machine-id').read_text().strip(),
            'boot_id': (PROC / 'sys/kernel/random/boot_id').read_text().strip()}


def process(pid):
    require(isinstance(pid, int) and pid > 1, 'controller_identity')
    root = PROC / str(pid)
    fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    require((root / 'comm').read_text().strip() == 'slurmctld', 'controller_identity')
    return {'pid': pid, 'starttime': fields[19], 'state': fields[0]}


def controller():
    pids = run(['pgrep', '-x', 'slurmctld']).split()
    require(len(pids) == 1 and pids[0].isdigit(), 'controller_identity')
    p = process(int(pids[0]))
    require(p.pop('state') not in ('T', 't', 'Z'), 'controller_unusable')
    p['boot_id'] = identity()['boot_id']
    return p


def partitions(*, timeout=120):
    result = {}
    for line in run(CTL + ['scontrol', 'show', 'partition', '-o'], timeout=timeout).splitlines():
        fields = dict(x.split('=', 1) for x in line.split() if '=' in x)
        n, state_ = fields.get('PartitionName', ''), fields.get('State', '')
        require(NAME.fullmatch(n) and state_ in ('UP', 'DOWN', 'DRAIN', 'INACTIVE') and n not in result,
                'partition_query')
        result[n] = state_
    require(result, 'partition_query')
    return result


def loginsets(*, timeout=120):
    result = {}
    for item in json.loads(run(KS + ['get', 'loginsets', '-o', 'json'], timeout=timeout))['items']:
        name, uid = item['metadata']['name'], item['metadata']['uid']
        replicas = item['spec']['replicas']
        require(NAME.fullmatch(name) and isinstance(uid, str) and uid and name not in result
                and type(replicas) is int and 0 <= replicas <= 100, 'loginset_query')
        result[name] = {'uid': uid, 'replicas': replicas}
    require(result, 'loginset_query')
    return result


def health(workers):
    require(run(['systemctl', 'is-active', 'k3s']).strip() == 'active', 'k3s_inactive')
    require(run(K + ['get', '--raw', '/readyz']).strip() == 'ok', 'api_unready')
    nodes = json.loads(run(K + ['get', 'nodes', '-l', 'prace.fleet/role in (cpu,gpu)', '-o', 'json']))
    require(sorted(x['metadata']['name'] for x in nodes['items']) == workers, 'worker_membership')
    run(['/usr/local/sbin/prace-slinky-worker-check'] + workers)


def private_dir(path):
    st = path.lstat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and stat.S_IMODE(st.st_mode) == 0o700,
            'private_directory')


def syncdir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_json(path, value):
    data = (json.dumps(value, sort_keys=True) + '\n').encode()
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    tmp = Path(temporary)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)
        out.flush()
        os.fsync(out.fileno())
    os.replace(tmp, path)
    syncdir(path.parent)


def load_json(path):
    st = path.lstat()
    require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and not (st.st_mode & 0o077),
            'private_record')
    return json.loads(path.read_text())


def journal(d, event):
    path = d / 'journal.json'
    value = load_json(path) if path.exists() else []
    value.append({'event': event, 'time': datetime.datetime.now(datetime.timezone.utc).isoformat()})
    write_json(path, value)


def lease_status(id_):
    try:
        private_dir(LEASE)
        st = (LEASE / 'holder').lstat()
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o077,
                'lease_unreadable')
        tokens = (LEASE / 'holder').read_text().split()
        return 'owned' if tokens.count('id=' + id_) == 1 and tokens.count('holder=prace-capture') == 1 else 'foreign'
    except FileNotFoundError:
        return 'foreign' if LEASE.exists() or LEASE.is_symlink() else 'missing'
    except (OSError, Refused):
        return 'foreign'


def validate(request):
    require(isinstance(request, dict) and re.fullmatch(r'[0-9a-f]{32}', request.get('id', '')), 'request_id')
    require(request.get('stage') in STAGES and sorted(request.get('workers', [])) == WORKERS,
            'request_scope')
    limit = request.get('max_data_bytes', 2 * GIB)
    require(type(limit) is int and 0 < limit <= 100 * GIB, 'request_limit')
    if 'window' in request:
        require(WINDOW_HELPER is not None, 'shared_helper_missing')
        require(WINDOW_HELPER.normalize(request.get('window_record')) == request['window'],
                'shared_window_invalid')
    if 'native' in request:
        n = request['native']
        require(isinstance(n, dict) and n.get('workers') == {'lab-lenovo': '10.90.10.21'}
                and type(n.get('max_repo_bytes')) is int and 0 < n['max_repo_bytes'] <= 16 * GIB
                and request['stage'] == 'post-w2' and 'window' in request, 'native_scope_invalid')
    return BASE / request['id']


def check_identity(expected=None):
    current = identity()
    require(current['hostname'] == 'lab-dl380' and current['chassis_serial'] == 'EXSERIAL01'
            and re.fullmatch(r'[0-9a-f]{32}', current['machine_id'])
            and re.fullmatch(r'[0-9a-f-]{36}', current['boot_id']), 'host_identity')
    require(expected is None or current == expected, 'identity_changed')
    return current


COMPETING_ADMISSION = (Path('/var/lib/rancher/k3s/server/manifests/prace-slinky-maintenance.yaml'),
                      Path('/run/prace-cluster-lease/fence-intent.json'))


def legacy_admission_only():
    """The W1/W2 driver cannot adopt the shared persistent-fence protocol.

    Refuse rather than stopping K3s and letting an unknown chart overlay reopen
    admission, or accepting a backup whose window IDs cannot be restored. This
    does not block service recovery/read-only settlement of a prior capture.
    """
    for path in COMPETING_ADMISSION:
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        raise Refused('persistent_fence_requires_capture_adapter')


def guard(request, *, owned=True):
    d = validate(request)
    check_identity(request['identity'])
    private_dir(BASE)
    private_dir(d)
    record = load_json(d / 'original.json')
    for key in ('id', 'stage', 'identity', 'original'):
        require(record[key] == request[key], 'record_mismatch')
    require(record['workers'] == sorted(request['workers']) and
            record['max_data_bytes'] == request.get('max_data_bytes', 2 * GIB), 'record_mismatch')
    require(record.get('native') == request.get('native'), 'native_scope_changed')
    require(record.get('window') == request.get('window')
            and record.get('window_record') == request.get('window_record'), 'record_mismatch')
    if 'window' in request:
        WINDOW_HELPER.guard(request['window'], api=False, runtime=False)
    elif owned:
        require(lease_status(request['id']) == 'owned', 'lease_not_owned')
    return d


def roots_size(roots):
    total, count = 0, 0
    mountpoints = []
    for line in (PROC / 'self/mountinfo').read_text().splitlines():
        fields = line.split()
        require(len(fields) >= 6 and ' - ' in line, 'mount_query')
        mountpoints.append(Path(re.sub(r'\\([0-7]{3})', lambda m: chr(int(m[1], 8)), fields[4])))
    for root in roots:
        seen = set()  # Distinct root archives each carry their own hardlink group.
        path = Path(root)
        require(path.is_dir() and path.resolve() == path, 'required_root_missing')
        require(not any(m != path and path in m.parents for m in mountpoints), 'nested_mount')
        device = path.stat().st_dev
        pending = [path]
        while pending:
            current = pending.pop()
            st = current.lstat()
            count += 1
            require(count <= MAX_ENTRIES and len(current.relative_to(path).parts) <= 128, 'entry_limit')
            require(st.st_dev == device, 'nested_mount')
            if stat.S_ISDIR(st.st_mode):
                with os.scandir(current) as children:
                    for child in children:
                        require(count + len(pending) < MAX_ENTRIES, 'entry_limit')
                        pending.append(Path(child.path))
            elif stat.S_ISREG(st.st_mode) and (st.st_dev, st.st_ino) not in seen:
                total += st.st_size
                seen.add((st.st_dev, st.st_ino))
    return total


def native_topology(request):
    # A native worker needs an explicitly reviewed extension; legacy points stay pod-only.
    try:
        try:
            st = NATIVE_LIST.lstat()
        except FileNotFoundError:
            text = ''
        else:
            require(stat.S_ISREG(st.st_mode), 'native_scope_invalid')
            text = NATIVE_LIST.read_text()
        actual = {}
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            fields = line.split()
            require(len(fields) == 2 and fields[0] not in actual, 'native_scope_invalid')
            actual[fields[0]] = fields[1]
    except OSError:
        raise Refused('native_scope_invalid') from None
    require(actual == request.get('native', {}).get('workers', {}), 'native_scope_changed')
    if actual:
        require(NATIVE_REPO_HELPER is not None, 'native_helper_missing')
    return actual


def preflight(request):
    native_topology(request)
    if 'native' in request:
        try:
            _, repo_bytes = NATIVE_REPO_HELPER.scan(NATIVE_REPO_ROOT, request['native']['max_repo_bytes'])
            require(shutil.disk_usage(BASE if BASE.exists() else BASE.parent).free >=
                    30 * GIB + request['max_data_bytes'] * 3 + repo_bytes * 2, 'insufficient_remote_space')
        except Exception:
            raise Refused('native_repo_preflight_failed') from None
    roots = STAGES[request['stage']]
    size = roots_size(roots)
    limit = request.get('max_data_bytes', 2 * GIB)
    require(size <= limit, 'data_size_limit')
    require(METADATA_HELPER is not None, 'helper_missing')
    remaining = limit
    try:
        for root in roots:
            scope = METADATA_HELPER.inspect_source(root, max_bytes=remaining)
            remaining -= scope['logical_bytes']
    except Refused:
        raise
    except Exception:
        raise Refused('data_scope_invalid') from None
    free = shutil.disk_usage(BASE if BASE.exists() else BASE.parent).free
    require(free >= 20 * GIB + 10 * GIB + size * 3, 'insufficient_remote_space')
    return {'roots': roots, 'data_bytes': size, 'free_bytes': free}


def writable_fds(roots):
    for process_dir in PROC.iterdir():
        if not process_dir.name.isdigit():
            continue
        try:
            for fd in (process_dir / 'fd').iterdir():
                try:
                    target = os.readlink(fd).removesuffix(' (deleted)')
                    if not any(target == root or target.startswith(root + '/') for root in roots):
                        continue
                    info = (process_dir / 'fdinfo' / fd.name).read_text()
                    flags = next(line.split()[1] for line in info.splitlines() if line.startswith('flags:'))
                    require(int(flags, 8) & os.O_ACCMODE == os.O_RDONLY, 'writable_descriptor')
                except FileNotFoundError:
                    continue
        except FileNotFoundError:
            continue


def membership(original, *, timeout=120):
    parts = partitions(timeout=timeout)
    require(set(parts) == set(original['partitions']), 'membership_changed')
    sets = loginsets(timeout=timeout)
    require(set(sets) == set(original['loginsets']), 'membership_changed')
    require(all(sets[n]['uid'] == original['loginsets'][n]['uid'] for n in sets), 'loginset_replaced')
    return parts, sets


def check_fence(request):
    parts, sets = membership(request['original'])
    require(all(v == 'INACTIVE' for v in parts.values()) and all(v['replicas'] == 0 for v in sets.values()),
            'fence_incomplete')
    pods = json.loads(run(KS + ['get', 'pods', '-l', 'app.kubernetes.io/name=login', '-o', 'json']))
    require(not pods['items'], 'login_pods_present')


def check_queue_empty():
    require(not run(CTL + ['squeue', '-h', '-o', '%i']).strip(), 'queue_not_empty')


def loginset_fence_command(name, uid):
    patch = [{'op': 'test', 'path': '/metadata/uid', 'value': uid},
             {'op': 'replace', 'path': '/spec/replicas', 'value': 0}]
    return KS + ['patch', 'loginset', name, '--type=json', '-p', json.dumps(patch)]


def fence(request):
    d = guard(request)
    parts, sets = membership(request['original'])
    journal(d, 'fence_intent')
    for name in sorted(parts):
        guard(request)
        journal(d, 'partition_fence_intent:' + name)
        run(CTL + ['scontrol', 'update', 'PartitionName=' + name, 'State=INACTIVE'])
        journal(d, 'partition_fenced:' + name)
    for name in sorted(sets):
        guard(request)
        journal(d, 'loginset_fence_intent:' + name)
        run(loginset_fence_command(name, sets[name]['uid']))
        journal(d, 'loginset_fenced:' + name)
    for _ in range(90):
        if not json.loads(run(KS + ['get', 'pods', '-l', 'app.kubernetes.io/name=login', '-o', 'json']))['items']:
            break
        time.sleep(1)
    check_fence(request)
    journal(d, 'fenced')


def exact_controller(request):
    check_identity(request['identity'])
    saved = request['original']['controller']
    require(saved['boot_id'] == request['identity']['boot_id'], 'controller_identity')
    found = process(saved['pid'])
    require(found['starttime'] == saved['starttime'], 'controller_changed')
    return found


def wait_membership(request):
    # API/pod readiness can precede Slurm queries or LoginSet webhook admission.
    # Server dry-run executes admission for the exact fence patch without saving
    # it. Retry observation failures only: ten attempts, at most five
    # seconds per query and two seconds between attempts. Guards and the entire
    # wait remain inside the caller's existing operation/recovery deadline.
    for attempt in range(10):
        d = guard(request)
        exact_controller(request)
        sets = None
        try:
            _, sets = membership(request['original'], timeout=5)
            journal(d, 'membership_ready')
            for name in sorted(sets):
                result = json.loads(run(loginset_fence_command(name, sets[name]['uid']) +
                                        ['--dry-run=server', '-o', 'json'], timeout=5))
                require(isinstance(result, dict) and isinstance(result.get('metadata'), dict)
                        and isinstance(result.get('spec'), dict), 'loginset_admission')
                require(result['metadata'].get('uid') == sets[name]['uid'], 'loginset_replaced')
                require(result['metadata'].get('name') == name and
                        type(result['spec'].get('replicas')) is int and result['spec']['replicas'] == 0,
                        'loginset_admission')
        except Refused as exc:
            if str(exc) != 'command_failed':
                raise
            if sets is not None:
                # kubectl flattens a failed UID test into command_failed too.
                # Refuse observed replacement/identity drift before any retry.
                guard(request)
                exact_controller(request)
                membership(request['original'], timeout=5)
            if attempt == 9:
                raise
            time.sleep(2)
        else:
            journal(d, 'admission_ready')
            return


def services(request):
    d = guard(request)
    p = exact_controller(request)
    if p['state'] in ('T', 't'):
        journal(d, 'controller_resume_intent')
        guard(request)
        exact_controller(request)
        run(['kill', '-CONT', str(p['pid'])])
    require(request['original']['k3s_active'] is True, 'original_service_state')
    journal(d, 'k3s_start_intent')
    guard(request)
    run(['systemctl', 'start', 'k3s'])
    ready = False
    for _ in range(60):
        try:
            ready = run(K + ['get', '--raw', '/readyz'], timeout=10).strip() == 'ok'
        except Refused as exc:
            if str(exc) == 'operation_timeout':
                raise
            ready = False
        except subprocess.SubprocessError:
            ready = False
        if ready:
            break
        time.sleep(2)
    require(ready, 'api_unready')
    # Prove membership and admission before re-fencing; never retry mutations.
    wait_membership(request)
    if 'window' in request:
        WINDOW_HELPER.guard(request['window'], runtime=False)
    fence(request)
    health(sorted(request['workers']))
    exact_controller(request)
    check_fence(request)
    journal(d, 'services_ready_fenced')
    if 'window' in request:
        WINDOW_HELPER.guard(request['window'])


def sha(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def control_archive(d, request):
    sql = d / 'slurm_acct_db.sql'
    with sql.open('xb') as out:
        os.chmod(sql, 0o600)
        run(['mysqldump', '--single-transaction', '--routines', '--databases', 'slurm_acct_db'],
            stdout=out, timeout=300)
        out.flush()
        os.fsync(out.fileno())
    token_record = d / 'token-sha256.txt'
    token_record.write_text(''.join(sha(Path(p)) + ' ' + p + '\n' for p in TOKENS))
    os.chmod(token_record, 0o600)
    orig = request['original']
    lease_id = request['id']
    if 'window' in request:
        orig = request['window']['original']
        orig = dict(orig, partitions=dict(orig['partitions'], **request['window']['declared_partitions']))
        lease_id = request['window']['id']
    window = d / 'maintenance-window.txt'
    window.write_text('lease=' + lease_id + ' partitions-before-fence=' +
                      ','.join(n + '=' + s for n, s in sorted(orig['partitions'].items())) +
                      ' loginsets-before-fence=' + ','.join(n + '=' + str(v['replicas']) for n, v in sorted(orig['loginsets'].items())) +
                      ' home=1 captured=' + datetime.datetime.now(datetime.timezone.utc).isoformat() + '\n')
    os.chmod(window, 0o600)
    partial = d / 'control.tgz.partial'
    total, entries = 0, 0
    def limited(member):
        nonlocal total, entries
        entries += 1
        require(entries <= MAX_ENTRIES and len(member.name.split('/')) <= 128, 'control_entry_limit')
        require(member.isfile() or member.isdir() or member.issym() or member.islnk(), 'control_special_file')
        total += member.size
        require(total <= 10 * GIB, 'control_size_limit')
        return member
    with partial.open('xb') as out:
        os.chmod(partial, 0o600)
        with tarfile.open(fileobj=out, mode='w|gz', dereference=False) as archive:
            for path in CONTROL:
                archive.add(path, arcname=path.lstrip('/'), filter=limited)
            for path in (sql, token_record, window):
                archive.add(path, arcname='prace-backup/' + path.name, filter=limited)
        out.flush()
        os.fsync(out.fileno())
    # Match the restore tool's structural contract, including link restrictions.
    with tarfile.open(partial) as archive:
        members = archive.getmembers()
        names = [m.name for m in members]
        require(len(set(names)) == len(names), 'control_duplicate_member')
        allowed = tuple(p.lstrip('/') for p in CONTROL)
        inside = lambda n: any(n == a or n.startswith(a + '/') for a in allowed)
        symlinks = {m.name for m in members if m.issym()}
        seen = set()
        for m in members:
            n = m.name
            require(n and not n.startswith('/') and '..' not in n.split('/') and os.path.normpath(n) == n,
                    'control_unsafe_member')
            if n.startswith('prace-backup/'):
                require(n in {'prace-backup/slurm_acct_db.sql', 'prace-backup/token-sha256.txt',
                              'prace-backup/maintenance-window.txt'} and m.isfile(), 'control_unsafe_record')
                continue
            prefixes = ['/'.join(n.split('/')[:i]) for i in range(1, len(n.split('/')))]
            require(inside(n) and not set(prefixes) & symlinks, 'control_unsafe_member')
            if m.issym():
                raw = m.linkname
                dest = os.path.normpath(raw if raw.startswith('/') else os.path.join(os.path.dirname(n), raw)).lstrip('/')
                require('..' not in raw.split('/') and inside(dest) and dest not in symlinks and
                        not any('/'.join(dest.split('/')[:i]) in symlinks for i in range(1, len(dest.split('/')))),
                        'control_unsafe_link')
            elif m.islnk():
                require(not m.linkname.startswith('/') and '..' not in m.linkname.split('/') and
                        inside(m.linkname) and m.linkname in seen, 'control_unsafe_link')
            elif m.isfile():
                seen.add(n)
        for p in TOKENS:
            member = archive.getmember(p.lstrip('/'))
            require(member.isfile() and hashlib.sha256(archive.extractfile(member).read()).hexdigest() == sha(Path(p)),
                    'control_token_mismatch')
    os.replace(partial, d / 'control.tgz')
    syncdir(d)
    # The validated archive now holds the SQL; do not retain an extra plaintext copy.
    sql.unlink()
    syncdir(d)


def capture(request):
    if 'window' not in request:
        legacy_admission_only()
    d = guard(request)
    require(request.get('attest_no_admin_writers') is True, 'admin_attestation_required')
    require(METADATA_HELPER is not None and isinstance(TREE_SOURCE, str) and TREE_SOURCE, 'helper_missing')
    require(not (d / 'capture.json').exists() and not (d / 'capture-started.json').exists(), 'capture_already_attempted')
    check_fence(request)
    check_queue_empty()
    preflight(request)
    if 'window' in request:
        WINDOW_HELPER.guard(request['window'])
    writable_fds(STAGES[request['stage']])
    exact_controller(request)
    write_json(d / 'capture-started.json', {'started': True})
    helper = d / 'tree-listing'
    helper.write_text(TREE_SOURCE)
    os.chmod(helper, 0o700)
    success = False
    capture_error = None
    try:
        if 'native' in request:
            try:
                NATIVE_REPO_HELPER.create(NATIVE_REPO_ROOT, d, request['native']['max_repo_bytes'])
            except Exception:
                raise Refused('native_repo_capture_failed') from None
        journal(d, 'controller_stop_intent')
        guard(request)
        p = exact_controller(request)
        run(['kill', '-STOP', str(p['pid'])])
        for _ in range(50):
            if exact_controller(request)['state'] in ('T', 't'):
                break
            time.sleep(0.1)
        require(exact_controller(request)['state'] in ('T', 't'), 'controller_not_stopped')
        journal(d, 'k3s_stop_intent')
        guard(request)
        run(['systemctl', 'stop', 'k3s'])
        # A read-only is-active query has a nonzero status for a stopped service.
        require(run(['systemctl', 'show', 'k3s', '--property=ActiveState', '--value']).strip() == 'inactive',
                'k3s_not_stopped')
        require(exact_controller(request)['state'] in ('T', 't'), 'controller_not_stopped')
        writable_fds(STAGES[request['stage']])
        control_archive(d, request)
        artifact_paths = ['control.tgz']
        if 'native' in request:
            artifact_paths += ['native-repo.tar', 'native-repo.json']
        if 'window' in request:
            # The complete baseline is an artifact beside control.tgz. Do not
            # widen the existing control-state restore allowlist.
            write_json(d / 'slurm-window.json', request['window_record'])
            artifact_paths.append('slurm-window.json')
        remaining = request.get('max_data_bytes', 2 * GIB)
        for root in STAGES[request['stage']]:
            guard(request)
            require(exact_controller(request)['state'] in ('T', 't'), 'controller_not_stopped')
            writable_fds(STAGES[request['stage']])
            archive_name = ARCHIVES[root]
            proof = d / (archive_name[:-4] + '-proof')
            result = METADATA_HELPER.create_verified_archive(root, d / archive_name, proof, helper,
                                                            max_bytes=remaining)
            require(isinstance(result, dict) and type(result.get('logical_bytes')) is int and
                    0 <= result['logical_bytes'] <= remaining, 'metadata_proof_failed')
            remaining -= result['logical_bytes']
            artifact_paths.append(archive_name)
            # Only top-level proof documents, never the restored tree payload.
            for item in sorted(proof.iterdir()):
                if item.is_file() and not item.is_symlink():
                    artifact_paths.append(str(item.relative_to(d)))
            require((proof / 'manifest.json').is_file() and (proof / 'extracted.jsonl').is_file(),
                    'metadata_proof_missing')
        writable_fds(STAGES[request['stage']])
        write_json(d / 'capture.json', {'artifacts': artifact_paths, 'complete': True})
        success = True
    except BaseException as exc:
        capture_error = exc
        raise
    finally:
        # Recovery has its own finite allowance after the capture deadline. The
        # lock remains held; no second operation can reopen during this cleanup.
        try:
            if threading.current_thread() is threading.main_thread():
                signal.setitimer(signal.ITIMER_REAL, 0)
            with deadline(RECOVERY_GRACE_SECONDS):
                services(request)
        except BaseException as recovery_error:
            errors = []
            if capture_error is not None:
                errors.append({'operation': 'capture', 'error': error_code(capture_error)})
            errors.append({'operation': 'services', 'error': error_code(recovery_error)})
            raise RecoveryFailure(errors) from None
    require(success, 'capture_failed')


def manifest(request):
    d = guard(request)
    check_fence(request)
    health(sorted(request['workers']))
    record = load_json(d / 'capture.json')
    require(record.get('complete') is True, 'capture_incomplete')
    artifacts = []
    for relative in record['artifacts']:
        path = d / relative
        require(not Path(relative).is_absolute() and '..' not in Path(relative).parts and
                path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(d.resolve()), 'artifact_unsafe')
        artifacts.append({'path': relative, 'sha256': sha(path), 'size': path.stat().st_size})
    require(set(ARCHIVES[p] for p in STAGES[request['stage']]) | {'control.tgz'} <= {a['path'] for a in artifacts},
            'artifact_missing')
    if 'window' in request:
        require('slurm-window.json' in {a['path'] for a in artifacts}
                and load_json(d / 'slurm-window.json') == request['window_record'], 'shared_window_invalid')
    result = {'ok': True, 'complete': True, 'id': request['id'], 'stage': request['stage'], 'artifacts': artifacts}
    write_json(d / 'manifest.json', result)
    return result


def manifest_read(request):
    """Reconcile a lost release reply without recreating a lease or writing state."""
    d = guard(request, owned=False)
    result = load_json(d / 'manifest.json')
    require(result.get('ok') is True and result.get('complete') is True and
            result.get('id') == request['id'] and result.get('stage') == request['stage'], 'manifest_mismatch')
    require(isinstance(result.get('artifacts'), list) and 0 < len(result['artifacts']) <= 1000,
            'manifest_mismatch')
    seen = set()
    for artifact in result['artifacts']:
        relative = artifact['path']
        path = d / relative
        require(isinstance(relative, str) and not Path(relative).is_absolute() and
                '..' not in Path(relative).parts and relative not in seen and path.is_file() and
                not path.is_symlink() and path.resolve().is_relative_to(d.resolve()), 'artifact_unsafe')
        require(path.stat().st_size == artifact['size'] and sha(path) == artifact['sha256'], 'artifact_changed')
        seen.add(relative)
    require(set(ARCHIVES[p] for p in STAGES[request['stage']]) | {'control.tgz'} <= seen,
            'artifact_missing')
    if 'window' in request:
        require('slurm-window.json' in seen and load_json(d / 'slurm-window.json') == request['window_record'],
                'shared_window_invalid')
    return result


def verify_original(request, *, owned=True):
    guard(request, owned=owned)
    parts, sets = membership(request['original'])
    require(parts == request['original']['partitions'] and sets == request['original']['loginsets'],
            'original_state_not_restored')
    health(sorted(request['workers']))
    exact_controller(request)
    pods = json.loads(run(KS + ['get', 'pods', '-l', 'app.kubernetes.io/name=login', '-o', 'json']))['items']
    require(len(pods) == sum(v['replicas'] for v in sets.values()) and all(
        not pod['metadata'].get('deletionTimestamp') and any(
            c.get('type') == 'Ready' and c.get('status') == 'True'
            for c in pod.get('status', {}).get('conditions', [])) for pod in pods), 'login_pods_unready')


def reopen(request, *, require_manifest=True):
    d = guard(request)
    try:
        if require_manifest:
            saved_manifest = load_json(d / 'manifest.json')
            require(saved_manifest.get('complete') is True and saved_manifest.get('id') == request['id'] and
                    saved_manifest.get('stage') == request['stage'], 'manifest_missing')
        else:
            require(request.get('abandon') is True, 'abandon_ack_required')
        health(sorted(request['workers']))
        exact_controller(request)
        membership(request['original'])
        closing = 'complete' if require_manifest else 'aborted'
        closing_file = d / 'closing.json'
        if closing_file.exists():
            saved = load_json(closing_file)
            if saved.get('closing') != closing:
                require(closing == 'aborted' and saved.get('closing') == 'complete' and
                        saved.get('reopened') is False and request.get('abandon') is True,
                        'closing_purpose_mismatch')
                check_fence(request)
        write_json(closing_file, {'closing': closing, 'reopened': False})
        journal(d, 'reopen_intent' if require_manifest else 'invalid_capture_backout_intent')
        for name, state_ in sorted(request['original']['partitions'].items()):
            guard(request)
            run(CTL + ['scontrol', 'update', 'PartitionName=' + name, 'State=' + state_])
        for name, item in sorted(request['original']['loginsets'].items()):
            guard(request)
            patch = [{'op': 'test', 'path': '/metadata/uid', 'value': item['uid']},
                     {'op': 'replace', 'path': '/spec/replicas', 'value': item['replicas']}]
            run(KS + ['patch', 'loginset', name, '--type=json', '-p', json.dumps(patch)])
        for attempt in range(60):
            try:
                verify_original(request)
                break
            except Refused as exc:
                if str(exc) != 'login_pods_unready' or attempt == 59:
                    raise
                time.sleep(2)
        write_json(closing_file, {'closing': closing, 'reopened': True})
        journal(d, 'reopened')
    except BaseException:
        try:
            # A fired one-shot operation alarm cannot bound exception cleanup.
            # Use a separate short allowance; unknown fence state still refuses.
            with deadline(REFENCE_GRACE_SECONDS):
                closing_file = d / 'closing.json'
                if closing_file.exists():
                    state = load_json(closing_file)
                    state['reopened'] = False
                    write_json(closing_file, state)
                fence(request)
        except BaseException:
            pass
        raise Refused('reopen_failed_refence_required') from None


def dispatch(request):
    try:
        d = validate(request)
        require(os.geteuid() == 0, 'root_required')
        op = request.get('op')
        borrowed = 'window' in request
        if borrowed and op in ('reopen', 'backout', 'release', 'verify_original', 'closing_status', 'lease_check'):
            raise Refused('shared_owner_operation')
        if not borrowed and op in ('inspect', 'acquire', 'fence', 'capture', 'reopen', 'backout'):
            legacy_admission_only()
        if op == 'inspect':
            ident = check_identity()
            if borrowed:
                WINDOW_HELPER.guard(request['window'])
            health(sorted(request['workers']))
            check_queue_empty()
            orig = {'partitions': partitions(), 'loginsets': loginsets(),
                    'controller': controller(), 'k3s_active': True}
            return dict(ok=True, identity=ident, original=orig, **preflight(request))
        if op == 'lease_check':
            ident = check_identity(request.get('identity'))
            return {'ok': True, 'identity': ident, 'lease': lease_status(request['id'])}
        if op == 'acquire':
            check_identity(request['identity'])
            if borrowed:
                WINDOW_HELPER.guard(request['window'])
            else:
                require(lease_status(request['id']) == 'missing', 'lease_exists')
            health(sorted(request['workers']))
            now = {'partitions': partitions(), 'loginsets': loginsets(), 'controller': controller(), 'k3s_active': True}
            require(now == request['original'], 'original_state_changed')
            preflight(request)
            check_queue_empty()
            BASE.mkdir(mode=0o700, exist_ok=True)
            private_dir(BASE)
            d.mkdir(mode=0o700)
            record = {k: request[k] for k in ('id', 'stage', 'identity', 'original')}
            record.update(workers=sorted(request['workers']), max_data_bytes=request.get('max_data_bytes', 2 * GIB))
            if 'native' in request:
                record['native'] = request['native']
            if borrowed:
                record.update(window=request['window'], window_record=request['window_record'])
            write_json(d / 'original.json', record)
            if not borrowed:
                LEASE.mkdir(mode=0o700)  # Atomic exclusion. Never adopt or remove an existing directory.
                syncdir(LEASE.parent)
                holder = LEASE / 'holder'
                fd = os.open(holder, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'w') as out:
                    out.write('holder=prace-capture label=' + request['stage'] + ' id=' + request['id'] + ' since=' + datetime.datetime.now(datetime.timezone.utc).isoformat() + '\n')
                    out.flush()
                    os.fsync(out.fileno())
                syncdir(LEASE)
            journal(d, 'acquired')
            # Snapshot equality is rechecked under the lease, closing the inspect/acquire race.
            guard(request)
            health(sorted(request['workers']))
            now = {'partitions': partitions(), 'loginsets': loginsets(), 'controller': controller(), 'k3s_active': True}
            require(now == request['original'], 'original_state_changed_under_lease')
            check_queue_empty()
        elif op == 'fence':
            require(request.get('attest_no_admin_writers') is True, 'admin_attestation_required')
            if borrowed:
                guard(request)
                WINDOW_HELPER.guard(request['window'])
                check_fence(request)
            else:
                fence(request)
            writable_fds(STAGES[request['stage']])
        elif op == 'capture':
            capture(request)
        elif op == 'services':
            services(request)
        elif op == 'manifest':
            return manifest(request)
        elif op == 'manifest_read':
            return manifest_read(request)
        elif op == 'window_status':
            require(borrowed, 'shared_window_invalid')
            guard(request)
            WINDOW_HELPER.guard(request['window'])
            health(sorted(request['workers']))
            check_fence(request)
            return {'ok': True, 'window_id': request['window']['id'], 'fenced': True, 'lease_retained': True}
        elif op == 'closing_status':
            d = guard(request, owned=False)
            path = d / 'closing.json'
            if not path.exists():
                return {'ok': True, 'closing': None, 'reopened': False}
            closing = load_json(path)
            require(closing.get('closing') in ('complete', 'aborted') and
                    type(closing.get('reopened')) is bool, 'closing_state_invalid')
            if closing['reopened']:
                verify_original(request, owned=False)
            return dict(ok=True, **closing)
        elif op == 'reopen':
            reopen(request)
        elif op == 'backout':
            reopen(request, require_manifest=False)
        elif op == 'verify_original':
            verify_original(request, owned=False)
        elif op == 'release':
            d = guard(request)
            verify_original(request)
            journal(d, 'release_intent')
            guard(request)
            require(sorted(p.name for p in LEASE.iterdir()) == ['holder'], 'lease_changed')
            (LEASE / 'holder').unlink()
            LEASE.rmdir()
            syncdir(LEASE.parent)
            journal(d, 'released')
        else:
            raise Refused('unknown_operation')
        return {'ok': True, 'id': request['id'], 'op': op}
    except RecoveryFailure as exc:
        return {'ok': False, 'error': str(exc), 'errors': exc.errors}
    except Refused as exc:
        return {'ok': False, 'error': error_code(exc)}
    except Exception:
        return {'ok': False, 'error': 'remote_operation_failed'}


@contextlib.contextmanager
def operation_lock(request):
    """A same-run lease is not a mutex. Children inherit this flock descriptor.

    Never unlink/recreate a lock file: orphaned children may still hold its inode.
    Read-only settlement takes the existing lock without rewriting operation state.
    """
    global OPERATION_LOCK_FD
    check_identity(request.get('identity'))
    mutable = request['op'] not in READ_ONLY_OPS
    if request['op'] == 'acquire':
        if 'window' in request:
            WINDOW_HELPER.guard(request['window'])
        else:
            require(lease_status(request['id']) == 'missing', 'lease_exists')
        BASE.mkdir(mode=0o700, exist_ok=True)
    private_dir(BASE)
    require(BASE.resolve() == BASE.absolute(), 'private_directory')
    path = BASE / ('.operation-' + request['id'] + '.lock')
    flags = os.O_RDWR | os.O_NOFOLLOW
    if request['op'] == 'acquire':
        flags |= os.O_CREAT
    fd = os.open(path, flags, 0o600)
    prior_fd = OPERATION_LOCK_FD
    helper_prior = getattr(METADATA_HELPER, 'OPERATION_LOCK_FD', None)
    operation_id = uuid.uuid4().hex
    status_path = BASE / ('.operation-' + request['id'] + '.json')
    acquired = False
    try:
        st = os.fstat(fd)
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and
                stat.S_IMODE(st.st_mode) == 0o600 and st.st_nlink == 1, 'operation_lock_invalid')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Refused('operation_busy') from None
        acquired = True
        OPERATION_LOCK_FD = fd
        if METADATA_HELPER is not None:
            METADATA_HELPER.OPERATION_LOCK_FD = WINDOW_HELPER.FD if 'window' in request else fd
        if mutable:
            previous = load_json(status_path) if status_path.exists() else None
            state = {'operation_id': operation_id, 'operation': request['op'],
                     'state': 'running', 'pid': os.getpid(),
                     'boot_id': request['identity']['boot_id'],
                     'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
            if previous:
                require(previous.get('state') in ('running', 'finished', 'interrupted'), 'operation_record_invalid')
                state['previous'] = {k: previous[k] for k in ('operation_id', 'operation', 'state')}
            write_json(status_path, state)
        try:
            yield operation_id
        except BaseException as exc:
            if mutable:
                state.update(state='interrupted', error=error_code(exc))
                write_json(status_path, state)
            raise
        else:
            if mutable:
                state['state'] = 'finished'
                write_json(status_path, state)
    finally:
        if acquired:
            OPERATION_LOCK_FD = prior_fd
            if METADATA_HELPER is not None:
                METADATA_HELPER.OPERATION_LOCK_FD = helper_prior
        # Do not LOCK_UN: a child may hold the same open file description after
        # parent death; closing our descriptor preserves its exclusion.
        os.close(fd)


def handle(request):
    try:
        validate(request)
        require(os.geteuid() == 0, 'root_required')
        require(request.get('op') in {'inspect', 'acquire', 'fence', 'capture', 'services',
                'manifest', 'manifest_read', 'reopen', 'backout', 'verify_original',
                'release', 'lease_check', 'closing_status', 'window_status'}, 'unknown_operation')
        borrowed = 'window' in request
        if borrowed and request['op'] in ('reopen', 'backout', 'release', 'verify_original', 'closing_status', 'lease_check'):
            raise Refused('shared_owner_operation')
        if not borrowed and request['op'] in ('inspect', 'acquire', 'fence', 'capture', 'reopen', 'backout'):
            legacy_admission_only()  # before operation_lock can create records
        seconds = RPC_TIMEOUTS.get(request['op'], RPC_TIMEOUTS['default'])
        with deadline(seconds):
            shared_lock = WINDOW_HELPER.locked(request['window']) if borrowed else contextlib.nullcontext()
            with shared_lock:
                if borrowed:
                    WINDOW_HELPER.guard(request['window'], api=False, runtime=False)
                if request['op'] == 'inspect':
                    return dispatch(request)
                with operation_lock(request) as operation_id:
                    result = dispatch(request)
                    if result.get('ok') is not True:
                        result['operation_id'] = operation_id
                    return result
    except Refused as exc:
        return {'ok': False, 'error': error_code(exc)}
    except Exception:
        return {'ok': False, 'error': 'remote_operation_failed'}

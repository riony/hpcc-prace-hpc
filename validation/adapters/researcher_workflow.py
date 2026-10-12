"""Two pinned academic examples, bounded outputs and independent accounting.

Only operator-selected site scripts may run. Job tickets and transient build
folders sit outside the action workspace, so the tracer never races a compiler.
"""
from __future__ import annotations
import datetime
import hashlib
import grp
import json
import os
from pathlib import Path
import pwd
import re
import shlex
import stat
import subprocess
import time
try:
    from . import slurm_smoke as slurm
except ImportError:
    import slurm_smoke as slurm

EXAMPLES = {
    'batch.sh': {'partition': 'cpu', 'memory_mb': 4096, 'gpus': 0,
        'sha256': '786108c6e348086463c01877050a7264890f38fb1c1c0817643729f1882a3e87',
        'sources': {'hello.c': '4137064bfe0a49683b3a648904696a8170c85e592f7b98dbab7f1b2be094c225',
                    'hello_threads.cpp': '1f90cc2b16cb46830ae5333b75095e629ba21ef2c41f212dfe5d3616b98ed2f8'}},
    'gpu.sh': {'partition': 'gpu', 'memory_mb': 32768, 'gpus': 1,
        'sha256': '97f17da44cf92889a6d700a6c72b8749a8672f57beddd9b107209d7694ec342d',
        'sources': {'vector_add.cu': '51dfb80472f7ebcf5d856890210c69703650dad6ae5d24bc18da69d5cf032cb4'}}}
SITE = Path('/apps/examples')
SUBMIT_KEYS = {'workspace', 'run_id', 'account', 'partition', 'example', 'example_sha256', 'path', 'source_sha256'}
PROOF_KEYS = SUBMIT_KEYS | {'job_id', 'actor', 'started_epoch'}
OUTPUT_MARKERS = [
    {'path': 'results/batch.out', 'pattern': r'^cxx threads ok: 4 threads on [A-Za-z0-9-]+$'},
    {'path': 'results/gpu.out', 'pattern': r'^cuda ok: Tesla V100[A-Za-z0-9 -]*, 0 wrong of 1048576 \(no error\)$'},
]


def checked_spec(p):
    spec = EXAMPLES.get(p.get('example'))
    if (spec is None or p.get('partition') != spec['partition'] or p.get('example_sha256') != spec['sha256']
            or p.get('source_sha256') != spec['sources']):
        raise ValueError('unreviewed example, source or partition')
    for key in ('run_id', 'account'):
        if not isinstance(p.get(key), str) or not slurm.NAME.fullmatch(p[key]):
            raise ValueError('invalid researcher name')
    if not all(isinstance(p.get(k), str) and Path(p[k]).is_absolute() for k in ('workspace', 'path')):
        raise ValueError('absolute researcher paths required')
    if Path(p['workspace']) not in Path(p['path']).parents:
        raise ValueError('study directory outside workspace')
    return spec


def job_name(p):
    return slurm.job_name(p['run_id']) + '-' + p['partition']


def ticket_path(workspace, partition):
    if partition not in {'cpu', 'gpu'}:
        raise ValueError('invalid example ticket')
    return workspace.parent / ('researcher-' + partition + '.json')


def submission_argv(p):
    spec = checked_spec(p)
    # Build products are private to the job, outside the traced action boundary.
    build = Path(p['workspace']).parent / ('build-' + p['partition'])
    result = ['sbatch', '--parsable', '--account=' + p['account'], '--partition=' + p['partition'],
        '--comment=prace:' + p['run_id'], '--job-name=' + job_name(p), '--nodes=1', '--ntasks=1',
        '--cpus-per-task=4', '--mem=' + ('4G' if p['partition'] == 'cpu' else '32G'), '--time=00:10:00',
        '--chdir=' + str(build), '--output=' + str(Path(p['path']) / (Path(p['example']).stem + '.out')),
        '--error=' + str(Path(p['path']) / (Path(p['example']).stem + '.out'))]
    if spec['gpus']:
        result.append('--gres=gpu:1')
    return result + [str(SITE / p['example'])]


def fixed_job_fields(p):
    spec = checked_spec(p)
    return {k: p[k] for k in ('job_id', 'actor', 'account', 'partition', 'run_id')} | {
        'job_name': job_name(p), 'requested_cpus': 4, 'requested_nodes': 1,
        'requested_memory_mb': 92160 if spec['gpus'] else spec['memory_mb'], 'requested_gpus': spec['gpus'], 'time_limit_minutes': 10,
        'submitted_memory_mb': spec['memory_mb'],
        'submission_sha256': hashlib.sha256(json.dumps(submission_argv(p), separators=(',', ':')).encode()).hexdigest()}


def trusted_file(path):
    resolved = path.resolve(strict=True)
    if path.is_symlink() or not stat.S_ISREG(resolved.stat().st_mode):
        raise ValueError('regular operator file required')
    for part in (resolved, *resolved.parents):
        info = part.stat()
        if info.st_uid != 0 or info.st_mode & 0o002:
            raise ValueError('operator file/path is writable')
        if info.st_mode & 0o020:
            # Site examples are deployed root:root 0775/0664. Treat the
            # root group as administrative only if NSS lists root and the
            # standard noninteractive system identities, never test users. Pinned content is checked next.
            system_members = {('sync', 5, '/bin/sync'), ('shutdown', 6, '/sbin/shutdown'),
                              ('halt', 7, '/sbin/halt'), ('operator', 11, '/sbin/nologin')}
            def administrative(user):
                return user.pw_uid == 0 or (user.pw_name, user.pw_uid, user.pw_shell) in system_members
            if (info.st_gid != 0
                    or any(not administrative(user) for user in pwd.getpwall() if user.pw_gid == 0)
                    or any(not administrative(pwd.getpwnam(name)) for name in grp.getgrgid(0).gr_mem)):
                raise ValueError('operator file/path has non-root group writers')
    return resolved


def verify_site(p):
    spec = checked_spec(p)
    for name, digest in {p['example']: spec['sha256'], **spec['sources']}.items():
        path = trusted_file(SITE / name)
        if path.stat().st_size > 65536 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError('site example/source digest changed')


def preflight(p):
    if set(p) != SUBMIT_KEYS | {'actor'}:
        raise ValueError('invalid example preflight')
    checked_spec(p)
    text = slurm.command(['sacct', '-n', '-P', '-X', '-u', p['actor'], '--name=' + job_name(p),
                          '--starttime=1970-01-01', '--format', 'JobIDRaw,JobName%160'])
    if text or any(line.endswith('|' + job_name(p)) for line in slurm.command(
            ['squeue', '-h', '-u', p['actor'], '-o', '%A|%j']).splitlines()):
        raise ValueError('researcher run ID already used')
    return {'ok': True, 'started_epoch': int(time.time())}


def job_proof(p):
    if set(p) != PROOF_KEYS or not slurm.JOB.fullmatch(p.get('job_id', '')) or type(p.get('started_epoch')) is not int:
        raise ValueError('invalid researcher proof request')
    spec = checked_spec(p)
    text = slurm.command(['sacct', '-n', '-P', '-X', '-j', p['job_id'], '--format',
        'JobIDRaw,User%128,Account%128,Partition%128,State%32,ExitCode,JobName%160,ReqCPUS,ReqMem,'
        'TimelimitRaw,SubmitLine%2048,NNodes,Submit,ReqTRES%512,AllocCPUS,AllocTRES%512,Start,End'])
    rows = [line.split('|') for line in text.splitlines() if line]
    if len(rows) != 1 or len(rows[0]) != 18:
        raise ValueError('missing/ambiguous researcher accounting')
    job, actor, account, partition, state, code, name, cpus, memory, minutes, line, nodes, submitted, tres, alloc_cpus, alloc_tres, started, ended = rows[0]
    if (job, actor, account, partition, name) != (p['job_id'], p['actor'], p['account'], p['partition'], job_name(p)):
        raise ValueError('researcher accounting identity mismatch')
    argv = shlex.split(line)
    if not argv or ['sbatch', *argv[1:]] != submission_argv(p) or Path(argv[0]).name != 'sbatch':
        raise ValueError('researcher submission changed')
    # The deployed generic GPU-share policy normalizes one GPU to 90 GiB.
    amount = 92160 if spec['gpus'] else spec['memory_mb']
    if cpus != '4' or nodes != '1' or minutes != '10' or memory.rstrip('n') not in {str(amount) + 'M', str(amount // 1024) + 'G'}:
        raise ValueError('researcher requested resources mismatch')
    gpu = [v for v in tres.split(',') if v.startswith('gres/gpu=')]
    if gpu != (['gres/gpu=1'] if spec['gpus'] else []):
        raise ValueError('researcher requested GPU mismatch')
    epoch = int(datetime.datetime.strptime(submitted, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc).timestamp())
    if epoch < p['started_epoch'] or epoch > int(time.time()) + 120 or not re.fullmatch(r'\d+:\d+', code):
        raise ValueError('invalid researcher accounting time/exit')
    def stamp(value):
        if value in {'Unknown', 'None', ''}:
            return None
        return int(datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=datetime.timezone.utc).timestamp())
    proof = {**fixed_job_fields(p), 'submit_epoch': epoch, 'start_epoch': stamp(started), 'end_epoch': stamp(ended),
             'state': state.split()[0].split('+')[0], 'exit_code': code,
             'allocated_cpus': int(alloc_cpus), 'allocated_tres': alloc_tres, 'requested_tres': tres}
    if not valid_job_proof(proof, p, completed=False):
        raise ValueError('malformed researcher allocation or timestamps')
    return proof


def valid_job_proof(proof, expected, *, completed=True):
    """Rederive allocation and identity checks without trusting saved PASS flags."""
    if not isinstance(proof, dict):
        return False
    variable = {'submit_epoch', 'start_epoch', 'end_epoch', 'state', 'exit_code', 'allocated_cpus', 'allocated_tres', 'requested_tres'}
    if set(proof) != set(fixed_job_fields(expected)) | variable:
        return False
    if {k: v for k, v in proof.items() if k not in variable} != fixed_job_fields(expected):
        return False
    if type(proof['submit_epoch']) is not int or proof['submit_epoch'] < expected['started_epoch']:
        return False
    if (not isinstance(proof['state'], str) or not re.fullmatch(r'[A-Z_]+', proof['state'])
            or not isinstance(proof['exit_code'], str) or not re.fullmatch(r'\d+:\d+', proof['exit_code'])
            or type(proof['allocated_cpus']) is not int or proof['allocated_cpus'] < 0):
        return False
    memory = 92160 if expected['partition'] == 'gpu' else 4096
    def tres(value):
        if not isinstance(value, str):
            raise ValueError('invalid resource list')
        rows = [part.split('=', 1) for part in value.split(',')] if value else []
        if any(len(row) != 2 or not all(row) for row in rows) or len({row[0] for row in rows}) != len(rows):
            raise ValueError('ambiguous resource list')
        return dict(rows)
    try:
        requested = tres(proof['requested_tres'])
        allocation = tres(proof['allocated_tres'])
        if (requested.get('cpu') != '4' or requested.get('mem') not in {f'{memory}M', f'{memory // 1024}G'}
                or requested.get('node') != '1' or requested.get('gres/gpu', '0') != str(int(expected['partition'] == 'gpu'))):
            return False
    except ValueError:
        return False
    if completed and (proof['state'], proof['exit_code']) != ('COMPLETED', '0:0'):
        return False
    if proof['state'] == 'COMPLETED':
        if (type(proof['start_epoch']) is not int or type(proof['end_epoch']) is not int
                or not proof['submit_epoch'] <= proof['start_epoch'] <= proof['end_epoch'] <= int(time.time()) + 120):
            return False
        try:
            if (type(proof['allocated_cpus']) is not int or proof['allocated_cpus'] != 4
                    or allocation.get('cpu') != '4' or allocation.get('node') != '1'
                    or allocation.get('mem') not in {f'{memory}M', f'{memory // 1024}G'}
                    or allocation.get('gres/gpu', '0') != str(int(expected['partition'] == 'gpu'))):
                return False
        except (ValueError, TypeError, AttributeError):
            return False
    return True


def read_ticket(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_size > 4096:
        raise ValueError('invalid researcher ticket')
    p = json.loads(path.read_text())
    if p['actor'] != pwd.getpwuid(os.getuid()).pw_name:
        raise ValueError('researcher ticket actor mismatch')
    return p


def submit(workspace, p):
    if set(p) != SUBMIT_KEYS:
        raise ValueError('invalid example submission')
    verify_site(p)
    path = ticket_path(workspace, p['partition'])
    build = workspace.parent / ('build-' + p['partition'])
    build.mkdir(mode=0o750)
    build.chmod(0o750)
    ticket = {**p, 'actor': pwd.getpwuid(os.getuid()).pw_name, 'job_id': None, 'started_epoch': int(time.time())}
    with path.open('x') as stream:
        path.chmod(0o600)
        json.dump(ticket, stream)
    try:
        text = slurm.command(submission_argv(p))
    except slurm.CommandRefused as exc:
        if exc.receipt:
            ticket['job_id'] = exc.receipt
            path.write_text(json.dumps(ticket))
        raise
    job = text.split(';')[0]
    if not slurm.JOB.fullmatch(job):
        raise ValueError('invalid researcher receipt')
    ticket['job_id'] = job
    path.write_text(json.dumps(ticket))
    return {'job_id': job}


def wait(workspace, p):
    if set(p) != {'workspace', 'run_id', 'job_id'}:
        raise ValueError('invalid researcher wait')
    tickets = [read_ticket(ticket_path(workspace, part)) for part in ('cpu', 'gpu') if ticket_path(workspace, part).exists()]
    matches = [t for t in tickets if t['job_id'] == p['job_id'] and t['run_id'] == p['run_id']]
    if len(matches) != 1:
        raise ValueError('researcher job receipt missing')
    deadline = time.monotonic() + 1190
    while time.monotonic() < deadline:
        try:
            proof = job_proof(matches[0])
        except ValueError:
            time.sleep(1)
            continue
        if time.monotonic() >= deadline:
            break
        if proof['state'] in slurm.TERMINAL:
            if proof['state'] != 'COMPLETED' or proof['exit_code'] != '0:0':
                raise ValueError('researcher job failed')
            return {'job_state': 'COMPLETED'}
        time.sleep(1)
    raise ValueError('researcher job deadline')


def cleanup(workspace):
    for partition in ('cpu', 'gpu'):
        path = ticket_path(workspace, partition)
        if not path.exists():
            continue
        p = read_ticket(path)
        if p.get('job_id') is None:
            raise ValueError('uncertain researcher submission; operator reconciliation required')
        for line in slurm.command(['squeue', '-h', '-u', p['actor'], '-o', '%A|%j']).splitlines():
            fields = line.split('|')
            if len(fields) != 2 or not slurm.JOB.fullmatch(fields[0]):
                raise ValueError('invalid researcher queue')
            if fields[0] == p['job_id'] or fields[1] == job_name(p):
                if fields[0] != p['job_id']:
                    raise ValueError('ambiguous researcher queue')
                slurm.command(['scancel', p['job_id']])
        deadline = time.monotonic() + 10
        while True:
            proof = job_proof(p)
            if proof['state'] in slurm.TERMINAL:
                break
            if time.monotonic() >= deadline:
                raise ValueError('researcher cleanup deadline')
            time.sleep(1)
        (workspace.parent / ('build-' + partition)).rmdir()
        path.unlink()


def cleanup_proof(p):
    jobs = p.get('jobs')
    if set(p) != {'jobs'} or not isinstance(jobs, list) or not 1 <= len(jobs) <= 4:
        raise ValueError('invalid researcher cleanup receipts')
    ids = [j.get('job_id') for j in jobs]
    if len(set(ids)) != len(ids):
        raise ValueError('duplicate researcher job IDs')
    active = []
    names = {job_name(j) for j in jobs}
    for line in slurm.command(['squeue', '-h', '-u', jobs[0]['actor'], '-o', '%A|%j']).splitlines():
        fields = line.split('|')
        if len(fields) != 2 or not slurm.JOB.fullmatch(fields[0]):
            raise ValueError('invalid independent researcher queue')
        if fields[0] in ids or fields[1] in names:
            active.append(fields[0])
    proofs = [job_proof(j) for j in jobs]
    if active or any(row['state'] not in slurm.TERMINAL for row in proofs):
        raise ValueError('researcher cleanup not terminal')
    return {'active_job_ids': active, 'jobs': proofs}


def read_output(path):
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError('output links refused')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 4096:
            raise ValueError('bounded regular output required')
        data = stream.read(4097)
        if len(data) > 4096:
            raise ValueError('output byte limit')
    return data


def output_proof(workspace, p):
    if set(p) != {'directory', 'entries'}:
        raise ValueError('invalid output proof')
    if p['directory'] != 'results' or not isinstance(p['entries'], list) or [e.get('path') for e in p['entries']] != ['results/batch.out', 'results/gpu.out']:
        raise ValueError('fixed result paths required')
    root = workspace / p['directory']
    if root.is_symlink() or not root.is_dir() or any(q.is_symlink() for q in root.parents):
        raise ValueError('regular results directory required')
    if sorted(q.name for q in root.iterdir()) != sorted(Path(e['path']).name for e in p['entries']):
        raise ValueError('unexpected result entries')
    result = []
    for entry in p['entries']:
        data = read_output(workspace / entry['path'])
        source = read_output(workspace / 'vecadd-study' / Path(entry['path']).name)
        result.append({'path': entry['path'], 'content': data.decode('utf-8'), 'sha256': hashlib.sha256(data).hexdigest(),
                       'source_sha256': hashlib.sha256(source).hexdigest()})
    return {'files': result}


def valid_outputs(proof):
    if not isinstance(proof, dict) or set(proof) != {'files'} or not isinstance(proof['files'], list) or len(proof['files']) != 2:
        return False
    for row, entry in zip(proof['files'], OUTPUT_MARKERS):
        if (not isinstance(row, dict) or set(row) != {'path', 'content', 'sha256', 'source_sha256'}
                or row['path'] != entry['path'] or not isinstance(row['content'], str) or len(row['content'].encode()) > 4096
                or hashlib.sha256(row['content'].encode()).hexdigest() != row['sha256'] or row['source_sha256'] != row['sha256']
                or not any(re.fullmatch(entry['pattern'], line) for line in row['content'].splitlines())):
            return False
    cpu, gpu = [row['content'] for row in proof['files']]
    summary = re.findall(r'^cxx threads ok: 4 threads on ([A-Za-z0-9-]+)$', cpu, re.M)
    threads = re.findall(r'^thread ([0-9]+) on ([A-Za-z0-9-]+)$', cpu, re.M)
    return (len(summary) == 1 and len(threads) == 4 and {number for number, _ in threads} == {'0', '1', '2', '3'}
            and {host for _, host in threads} == {summary[0]} and 'cuda FAILED' not in gpu)


def modules():
    # A fixed Lmod invocation. No shell initialization or actor-controlled PATH.
    candidates = (Path('/usr/share/lmod/lmod/libexec/lmod'), Path('/opt/ohpc/admin/lmod/lmod/libexec/lmod'))
    for path in candidates:
        if path.is_file():
            executable = trusted_file(path)
            done = subprocess.run([str(executable), 'python', '--terse', 'avail'], capture_output=True, timeout=5,
                env={'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'MODULEPATH': '/apps/modulefiles', 'LC_ALL': 'C'})
            if done.returncode != 0 or len(done.stdout) + len(done.stderr) > 8192:
                raise ValueError('Lmod discovery failed')
            # Lmod prints avail listings on stderr; expose only validated names.
            names = sorted(set(re.findall(r'(?m)^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\s*$', done.stderr.decode())))
            if not names or len(json.dumps(names)) > 4096:
                raise ValueError('no bounded module names')
            return {'modules': json.dumps(names)}
    raise ValueError('reviewed Lmod unavailable')

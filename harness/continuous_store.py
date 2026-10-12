"""Private, durable, single-owner campaign journal. No automatic restart/reuse."""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading

from harness.session_store import process_start
from validation.contracts import canonical_json, require

LIMIT = 16 * 1024 * 1024


def sync_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def private_directory(path):
    path = Path(path)
    require(path.is_absolute() and '..' not in path.parts and not any(p.is_symlink() for p in (path, *path.parents)),
            'canonical private root required')
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'private root must be owned and 0700')
    return path


def load_rows(directory):
    path = Path(directory) / 'journal.jsonl'
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
                and stat.S_IMODE(info.st_mode) == 0o600 and info.st_size <= LIMIT, 'unsafe journal')
        fcntl.flock(stream.fileno(), fcntl.LOCK_SH)
        raw = stream.read(LIMIT + 1)
    require(raw and raw.endswith(b'\n') and len(raw) <= LIMIT, 'incomplete journal; inspect before continuing')
    rows, previous = [], '0' * 64
    for line in raw.splitlines():
        row = json.loads(line)
        claimed = row.pop('sha256')
        require(row['sequence'] == len(rows) + 1 and row['previous_sha256'] == previous
                and hashlib.sha256(canonical_json(row)).hexdigest() == claimed, 'journal contradiction')
        row['sha256'] = claimed; previous = claimed; rows.append(row)
    require(len({r['session_id'] for r in rows}) == 1, 'mixed-session journal')
    return rows


class Journal:
    def __init__(self, directory, sid):
        self.directory, self.sid, self.sequence, self.previous = Path(directory), sid, 0, '0' * 64
        fd = os.open(self.directory / 'journal.jsonl', os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.stream = os.fdopen(fd, 'wb')
        sync_directory(self.directory)
        self.lock = threading.Lock()

    def append(self, event, **facts):
        require(not set(facts) & {'schema', 'session_id', 'sequence', 'previous_sha256', 'timestamp', 'event', 'sha256'},
                'reserved journal field')
        with self.lock:
            return self._append(event, **facts)

    def _append(self, event, **facts):
        import time
        row = {'schema': 'prace.continuous-event.v1', 'session_id': self.sid,
               'sequence': self.sequence + 1, 'previous_sha256': self.previous,
               'timestamp': time.time(), 'event': event, **facts}
        row['sha256'] = hashlib.sha256(canonical_json(row)).hexdigest()
        raw = canonical_json(row) + b'\n'
        require(self.stream.tell() + len(raw) <= LIMIT, 'journal size limit')
        fcntl.flock(self.stream.fileno(), fcntl.LOCK_EX)
        try:
            self.stream.write(raw); self.stream.flush(); os.fsync(self.stream.fileno())
        finally:
            fcntl.flock(self.stream.fileno(), fcntl.LOCK_UN)
        self.previous, self.sequence = row['sha256'], row['sequence']
        return row

    def close(self):
        self.stream.close()


@contextmanager
def session_directory(root, sid):
    require(isinstance(sid, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,23}', sid), 'session identity')
    root = private_directory(root)
    fd = os.open(root / '.continuous.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        require(stat.S_ISREG(os.fstat(fd).st_mode) and os.fstat(fd).st_nlink == 1
                and os.fstat(fd).st_uid == os.getuid() and stat.S_IMODE(os.fstat(fd).st_mode) == 0o600, 'unsafe lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError('another continuous session owns this root') from None
        # A prior campaign deliberately retains ownership until the operator
        # reconciles it; a new ID is not an escape from an unresolved campaign.
        require(not any(p.is_dir() and ((p / 'journal.jsonl').exists() or (p / 'owner.json').exists()) for p in root.iterdir()),
                'retained campaign requires operator handoff; use status, not automatic restart')
        directory = root / sid
        directory.mkdir(mode=0o700)
        owner = {'pid': os.getpid(), 'process_start': process_start(os.getpid())}
        with (directory / 'owner.json').open('x') as stream:
            os.chmod(directory / 'owner.json', 0o600); json.dump(owner, stream); stream.flush(); os.fsync(stream.fileno())
        sync_directory(directory); sync_directory(root)
        yield directory
    finally:
        os.close(fd)


def status(root, sid):
    require(isinstance(sid, str) and re.fullmatch(r'[a-z][a-z0-9-]{0,23}', sid), 'session identity')
    directory = Path(root) / sid
    require(directory.is_absolute() and directory.resolve() == directory, 'session link refused')
    rows = load_rows(directory)
    require(all(r['session_id'] == sid for r in rows), 'foreign session journal')
    from harness.continuous import private_json
    owner = private_json(directory / 'owner.json')
    require(set(owner) == {'pid', 'process_start'} and type(owner['pid']) is int, 'owner record')
    alive = owner.get('process_start') is not None and process_start(owner['pid']) == owner['process_start']
    terminal = [r for r in rows if r['event'] == 'stopped']
    started = rows[0]
    finished = [r for r in rows if r['event'] == 'attempt_finished']
    actions = [r for r in rows if r['event'] == 'action_result']
    return {'session_id': sid, 'state': terminal[-1]['reason'] if terminal else 'running' if alive else 'interrupted',
            'reset_pending': True, 'lease_released': False, 'events': len(rows), 'journal_sha256': rows[-1]['sha256'],
            'attempts_started': sum(r['event'] == 'attempt_started' for r in rows), 'attempts_finished': len(finished),
            'model_calls': sum(r['model_calls'] for r in finished), 'actions': len(actions),
            'action_outcomes': {s: sum(r['status'] == s for r in actions) for s in ('ok', 'denied', 'error', 'timeout')},
            'elapsed_seconds': max(0, rows[-1]['timestamp'] - started['timestamp']),
            'source_revision': started.get('source_revision'), 'baseline_id': started.get('baseline_id')}

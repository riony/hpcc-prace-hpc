#!/usr/bin/env python3
"""Bounded local I/O primitives for host-storage acceptance.

This module has no SSH, privilege escalation, CLI or environment fallback. The
reviewed window adapter must enter the requested synthetic UID and prove the
mount/identity before calling it. Importing it performs no I/O.
"""
import errno
import os
from pathlib import Path
import stat
import time

MAX_BYTES = 272 * 1024 * 1024
MAX_FILES = 2100
QUOTA_ERRORS = {errno.EDQUOT, errno.ENOSPC}


def _identity(path):
    info = Path(path).lstat()
    if not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode):
        raise ValueError('fixture must be a regular file or directory')
    return {'device': info.st_dev, 'inode': info.st_ino, 'uid': info.st_uid}


def _parent(path):
    path = Path(path)
    if not path.is_absolute() or path.parent.resolve() != path.parent or path.name in ('', '.', '..'):
        raise ValueError('fixture path must have a canonical absolute parent')
    return path


def _budget(value, maximum):
    if type(value) is not int or not 0 < value <= maximum:
        raise ValueError('invalid fixture bound')


def _expired(deadline):
    if time.monotonic() >= deadline:
        raise TimeoutError('fixture deadline exceeded')


def fill_bytes(path, *, max_bytes=MAX_BYTES, seconds=120):
    """Write actual data and fsync; report quota errno, never arbitrary failure.

    Reaching the byte cap without a quota error is an unqualified outcome. The
    caller must separately corroborate ENOSPC with quota and filesystem usage.
    The enclosing adapter also needs a hard process deadline for blocked NFS I/O.
    """
    _budget(max_bytes, MAX_BYTES)
    _budget(seconds, 120)
    path = _parent(path)
    deadline = time.monotonic() + seconds
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    written, stopped = 0, None
    try:
        identity = _identity(path)
        while written < max_bytes:
            _expired(deadline)
            try:
                count = os.write(fd, b'X' * min(1024 * 1024, max_bytes - written))
                if count <= 0:
                    raise OSError(errno.EIO, 'short fixture write')
                written += count
                os.fsync(fd)
            except OSError as exc:
                if exc.errno not in QUOTA_ERRORS:
                    raise
                stopped = exc.errno
                break
        return {'identity': identity, 'written': written, 'errno': stopped, 'cap': max_bytes}
    finally:
        os.close(fd)


def fill_inodes(path, *, max_files=MAX_FILES, seconds=120):
    """Create at most max_files empty files in a fresh directory; no recursion."""
    _budget(max_files, MAX_FILES)
    _budget(seconds, 120)
    path = _parent(path)
    path.mkdir(mode=0o700)
    identity = _identity(path)
    identity['entries'] = {}
    deadline, created, stopped = time.monotonic() + seconds, 0, None
    for number in range(max_files):
        _expired(deadline)
        try:
            fd = os.open(path / str(number), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            os.close(fd)
            identity['entries'][str(number)] = _identity(path / str(number))
            created += 1
        except OSError as exc:
            if exc.errno not in QUOTA_ERRORS:
                raise
            stopped = exc.errno
            break
    return {'identity': identity, 'created': created, 'errno': stopped, 'cap': max_files}


def remove_fixture(path, identity, *, inode_fixture=False):
    """Remove exactly a recorded fixture as its creating UID; refuse surprises."""
    path = _parent(path)
    root_identity = {key: identity[key] for key in ('device', 'inode', 'uid')}
    if _identity(path) != root_identity or os.geteuid() != identity['uid']:
        raise ValueError('fixture identity or invoking UID changed')
    if inode_fixture:
        entries = list(path.iterdir())
        recorded = identity.get('entries')
        if (not isinstance(recorded, dict) or len(entries) > MAX_FILES or
                not {entry.name for entry in entries} <= set(recorded)):
            raise ValueError('unexpected fixture entry set')
        # Missing recorded entries are compatible with interrupted cleanup;
        # every surviving entry still requires its recorded identity.
        for entry in entries:
            info = entry.lstat()
            if (not entry.name.isdecimal() or int(entry.name) >= MAX_FILES or
                    not stat.S_ISREG(info.st_mode) or info.st_uid != identity['uid'] or
                    info.st_dev != identity['device'] or info.st_nlink != 1 or info.st_size != 0 or
                    _identity(entry) != recorded[entry.name]):
                raise ValueError('unexpected fixture entry')
        for entry in entries:
            entry.unlink()
        path.rmdir()
    else:
        if not path.is_file() or path.stat().st_nlink != 1:
            raise ValueError('fixture is not a single-link regular file')
        path.unlink()

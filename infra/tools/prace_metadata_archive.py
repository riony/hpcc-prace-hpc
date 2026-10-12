#!/usr/bin/env python3
"""Bounded, metadata-preserving data capture; caller owns the maintenance fence.

One source directory per archive. Production entry points require root. They never
change services, leases or source files. A failed run retains its private proof
directory and .partial archive; only a fully verified archive gets its final name.
Successful captures remove their own extracted tree after recording durable proof.
GNU tar and the recorded repository prace-tree-listing helper are prerequisites.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile

MAX_ENTRIES = 100_000
MAX_DEPTH = 128
COMMAND_TIMEOUT = 300
# The remote handler supplies its flock descriptor for the entire operation.
# Inheriting the same open description keeps exclusion if the handler is killed
# while tar (or one of its compression children) is still writing.
OPERATION_LOCK_FD = None


class ArchiveError(RuntimeError):
    pass


def _require_root():
    if os.geteuid() != 0:
        raise ArchiveError("metadata capture/extraction requires root")


def _private_write(path, data):
    if isinstance(data, str):
        data = data.encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    _sync_directory(Path(path).parent)


def _sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def _sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _run(args):
    env = dict(os.environ, LC_ALL="C")
    env.pop("TAR_OPTIONS", None)
    process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=env, start_new_session=True,
                               pass_fds=(() if OPERATION_LOCK_FD is None else (OPERATION_LOCK_FD,)))
    try:
        stdout, stderr = process.communicate(timeout=COMMAND_TIMEOUT)
    except BaseException as exc:
        # GNU tar may have a gzip child. Cancellation, including signals surfaced
        # as BaseException, must kill the group and reap/drain it before the
        # caller can release its operation lock.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        if isinstance(exc, subprocess.TimeoutExpired):
            raise ArchiveError(f"{Path(args[0]).name} exceeded {COMMAND_TIMEOUT}s timeout") from exc
        raise
    # A warning is not a verified copy, including GNU tar's skipped-object warnings.
    if process.returncode or stderr:
        detail = stderr.decode(errors="replace").strip()
        raise ArchiveError(f"{Path(args[0]).name} failed or warned (exit {process.returncode}): {detail}")
    return stdout


def _absolute(path):
    path = Path(path)
    if not path.is_absolute():
        raise ArchiveError("paths must be absolute")
    return path


def _mountpoints():
    # st_dev alone misses bind mounts of the same filesystem.
    result = []
    with open("/proc/self/mountinfo", encoding="utf-8") as stream:
        for line in stream:
            fields = line.split()
            if len(fields) < 6 or " - " not in line:
                raise ArchiveError("malformed mountinfo")
            result.append(Path(re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), fields[4])))
    return result


def _symlink_target_data(name, target):
    # Link text is data: absolute, parent-relative and dangling targets are
    # ordinary source metadata. Never resolve or dereference them. Extraction
    # safety instead requires canonical unique member names, directory-only
    # parents and a fresh private destination (see validate_archive).
    if not target or "\x00" in target:
        raise ArchiveError(f"empty/NUL symlink target: {name}")


def _scan_tree(source, max_bytes=None):
    """Reject unsupported scope; return inode-independent hardlink path groups."""
    source = Path(source)
    root_stat = source.lstat()
    if not stat.S_ISDIR(root_stat.st_mode):
        raise ArchiveError("source must be a directory, not a symlink")
    for mount in _mountpoints():
        if mount != source and source in mount.parents:
            raise ArchiveError(f"nested mount requires separate recorded capture: {mount}")
    hardlinks = {}
    total = 0
    entries = 0
    stack = [source]
    while stack:
        path = stack.pop()
        info = path.lstat()
        entries += 1
        rel = path.relative_to(source).as_posix()
        if entries > MAX_ENTRIES:
            raise ArchiveError(f"source exceeds {MAX_ENTRIES} entries")
        if len(path.relative_to(source).parts) > MAX_DEPTH:
            raise ArchiveError(f"source exceeds {MAX_DEPTH} depth")
        if info.st_dev != root_stat.st_dev:
            raise ArchiveError(f"cross-filesystem object: {rel}")
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as children:
                for child in children:
                    if entries + len(stack) >= MAX_ENTRIES:
                        raise ArchiveError(f"source exceeds {MAX_ENTRIES} entries")
                    stack.append(Path(child.path))
        elif stat.S_ISREG(info.st_mode):
            key = (info.st_dev, info.st_ino)
            if key not in hardlinks:
                hardlinks[key] = {"nlink": info.st_nlink, "paths": []}
                total += info.st_size
            elif hardlinks[key]["nlink"] != info.st_nlink:
                raise ArchiveError("hardlink count changed during scan")
            hardlinks[key]["paths"].append(rel)
        elif stat.S_ISLNK(info.st_mode):
            if info.st_nlink != 1:
                raise ArchiveError("hardlinked symlinks are unsupported")
            _symlink_target_data(rel, os.readlink(path))
        else:
            raise ArchiveError(f"special object is outside this bounded capture: {rel}")
        if max_bytes is not None and total > max_bytes:
            raise ArchiveError("source logical bytes exceed max_bytes")
    groups = []
    for item in hardlinks.values():
        if item["nlink"] != len(item["paths"]):
            raise ArchiveError("hardlink points outside the selected root, or source changed")
        if item["nlink"] > 1:
            groups.append(sorted(item["paths"]))
    return {"hardlink_groups": sorted(groups), "logical_bytes": total, "entries": entries}


def inspect_source(source, max_bytes=None):
    """Non-mutating scope validation shared by preflight and fenced capture.

    Refuse special files (including sockets/FIFOs), nested mounts, external
    regular hardlinks and hardlinked symlinks. Symlink target text is retained
    without following it. Bounds include the root and count regular bytes once
    per hardlink group; depth is relative to the selected root.
    """
    source = _absolute(source)
    if source == Path("/") or source.is_symlink() or source.resolve() != source:
        raise ArchiveError("source must be a canonical directory other than /")
    if max_bytes is not None and (type(max_bytes) is not int or max_bytes < 0):
        raise ArchiveError("max_bytes must be a nonnegative integer")
    return _scan_tree(source, max_bytes)


def _listing(source, helper):
    data = _run([sys.executable, str(helper), str(source)])
    try:
        rows = [json.loads(line) for line in data.splitlines()]
    except (ValueError, UnicodeError) as exc:
        raise ArchiveError("listing helper returned malformed JSON") from exc
    if not rows or rows[0].get("path") != ".":
        raise ArchiveError("listing helper returned no complete root listing")
    return data


def validate_archive(archive, max_bytes=None):
    """Validate all effective tar member/link names before privileged extraction."""
    seen = {}
    total = 0
    top = None
    with tarfile.open(archive, "r:gz") as stream:
        for member in stream:
            if len(seen) >= MAX_ENTRIES:
                raise ArchiveError(f"archive exceeds {MAX_ENTRIES} members")
            name = member.name.rstrip("/") if member.isdir() else member.name
            parts = PurePosixPath(name).parts
            if (not name or name.startswith("/") or "\x00" in name or
                    any(part in (".", "..") for part in name.split("/")) or
                    "//" in name or not parts or posixpath.normpath(name) != name):
                raise ArchiveError("unsafe archive member path")
            if name in seen:
                raise ArchiveError("duplicate archive member")
            if len(parts) - 1 > MAX_DEPTH:
                raise ArchiveError(f"archive exceeds {MAX_DEPTH} depth")
            if top is None:
                if len(parts) != 1 or not member.isdir():
                    raise ArchiveError("first member must be the single source root directory")
                top = name
            if parts[0] != top:
                raise ArchiveError("archive contains more than its selected root")
            for parent in PurePosixPath(name).parents:
                if str(parent) == ".":
                    continue
                previous = seen.get(str(parent))
                if previous is None or not previous.isdir():
                    raise ArchiveError("archive member has missing or non-directory parent")
            if member.issym():
                _symlink_target_data(name, member.linkname)
            elif member.islnk():
                target = member.linkname
                previous = seen.get(target)
                if previous is None or not previous.isreg():
                    raise ArchiveError("hardlink must target an earlier regular archive member")
            elif member.isreg():
                if member.size < 0:
                    raise ArchiveError("negative member size")
                total += member.size
                if max_bytes is not None and total > max_bytes:
                    raise ArchiveError("archive logical bytes exceed max_bytes")
            elif not member.isdir():
                raise ArchiveError("special archive member is unsupported")
            seen[name] = member
    if not top:
        raise ArchiveError("empty archive")
    return top


def _verify_extract(archive, destination, helper, expected_listing, expected_scan, max_bytes=None):
    top = validate_archive(archive, max_bytes)
    # No caller-supplied pre-existing tree: never extract through old links or merge data.
    destination.mkdir(mode=0o700)
    _run(["tar", "--extract", "--gzip", "--acls", "--xattrs", "--xattrs-include=*",
          "--selinux", "--numeric-owner", "--same-owner", "--same-permissions",
          "--file", str(archive), "--directory", str(destination)])
    restored = destination / top
    listing = _listing(restored, helper)
    scan = inspect_source(restored, max_bytes)
    if listing != expected_listing:
        raise ArchiveError("extracted metadata/content listing differs from source")
    if scan != expected_scan:
        raise ArchiveError("extracted hardlink groups or scope differ from source")
    return listing


def verify_extract(archive, destination, helper, expected_listing, expected_scan, max_bytes=None):
    """Root-only verification into a new private destination; no live restore."""
    _require_root()
    archive, destination, helper = map(_absolute, (archive, destination, helper))
    parent = destination.parent.stat()
    if (destination.parent.resolve() != destination.parent or
            parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o077):
        raise ArchiveError("extraction parent must be canonical, private and owned by the invoking UID")
    return _verify_extract(archive, destination, helper,
                           expected_listing, expected_scan, max_bytes)


def _create_verified_archive(source, archive, proof_dir, helper, max_bytes=None):
    # Private core permits real unprivileged fixtures; public API/CLI enforce root.
    source, archive, proof_dir, helper = map(_absolute, (source, archive, proof_dir, helper))
    missing = [name for name in ("tar", "gzip") if shutil.which(name) is None]
    if missing:
        raise ArchiveError("missing archive prerequisite(s): " + ", ".join(missing))
    before_scan = inspect_source(source, max_bytes)
    for target in (archive, proof_dir):
        if target == source or source in target.resolve().parents:
            raise ArchiveError("archive/proof directory must be outside source")
        if target.parent.resolve() != target.parent:
            raise ArchiveError("archive/proof parent must be canonical without symlinks")
    parent = archive.parent.stat()
    if parent.st_uid != os.geteuid() or stat.S_IMODE(parent.st_mode) & 0o077:
        raise ArchiveError("archive parent must be private and owned by the invoking UID")
    if archive.exists() or archive.is_symlink():
        raise ArchiveError("refusing to overwrite archive")
    if not helper.is_file() or helper.is_symlink():
        raise ArchiveError("listing helper must be a regular non-symlink file")
    proof_dir.mkdir(mode=0o700)
    partial = archive.with_name(archive.name + ".partial")
    _private_write(partial, b"")
    helper_sha = _sha(helper)
    before = _listing(source, helper)
    _private_write(proof_dir / "source-before.jsonl", before)
    _private_write(proof_dir / "source-scope.json", _json_bytes(before_scan))
    _run(["tar", "--create", "--gzip", "--format=pax", "--acls", "--xattrs",
          "--xattrs-include=*", "--selinux", "--numeric-owner", "--sparse",
          "--one-file-system", "--file", str(partial), "--directory", str(source.parent),
          "--", source.name])
    after = _listing(source, helper)
    after_scan = inspect_source(source, max_bytes)
    _private_write(proof_dir / "source-after.jsonl", after)
    if after != before or after_scan != before_scan:
        raise ArchiveError("source changed during capture")
    extract = proof_dir / "extract"
    restored = _verify_extract(partial, extract, helper, before, before_scan, max_bytes)
    extract_identity = extract.stat()
    _private_write(proof_dir / "extracted.jsonl", restored)
    if _sha(helper) != helper_sha:
        raise ArchiveError("listing helper changed during capture")
    with partial.open("rb") as stream:
        os.fsync(stream.fileno())
    result = {"schema": 1, "archive": str(archive), "archive_sha256": _sha(partial),
              "archive_bytes": partial.stat().st_size, "source": str(source),
              "logical_bytes": before_scan["logical_bytes"], "entries": before_scan["entries"],
              "listing_sha256": hashlib.sha256(before).hexdigest(),
              "hardlink_groups_sha256": hashlib.sha256(_json_bytes(before_scan["hardlink_groups"])).hexdigest(),
              "helper_sha256": helper_sha, "proof_dir": str(proof_dir)}
    # link() is an atomic no-overwrite publication within this private directory.
    _private_write(proof_dir / "manifest.json", _json_bytes(result))
    os.link(partial, archive)
    partial.unlink()
    _sync_directory(archive.parent)
    # Only this run's fresh extract is removed, and only after both its durable
    # proof and published archive exist. Any earlier failure retains the tree.
    current = extract.lstat()
    if (not stat.S_ISDIR(current.st_mode) or
            (current.st_dev, current.st_ino) != (extract_identity.st_dev, extract_identity.st_ino)):
        raise ArchiveError("verified extract identity changed before cleanup")
    # The unprivileged fixture core can restore read-only directories too.
    # Change only these extracted directory descriptors, never symlink targets.
    for _, _, _, directory_fd in os.fwalk(extract, follow_symlinks=False):
        os.fchmod(directory_fd, stat.S_IMODE(os.fstat(directory_fd).st_mode) | 0o700)
    shutil.rmtree(extract)
    _sync_directory(proof_dir)
    return result


def create_verified_archive(source, archive, proof_dir, helper, max_bytes=None):
    """Capture one fenced directory, prove source stability and complete extraction.

    max_bytes bounds logical regular-file bytes (hardlinks counted once), including
    sparse file lengths. Caller budgets archive/extraction filesystem space separately.
    archive parent must already be private; proof_dir must not already exist.
    """
    _require_root()
    return _create_verified_archive(source, archive, proof_dir, helper, max_bytes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["create"])
    parser.add_argument("source")
    parser.add_argument("archive")
    parser.add_argument("proof_dir")
    parser.add_argument("--helper", required=True)
    parser.add_argument("--max-bytes", type=int)
    args = parser.parse_args()
    try:
        result = create_verified_archive(args.source, args.archive, args.proof_dir,
                                         args.helper, args.max_bytes)
    except (ArchiveError, OSError, ValueError, tarfile.TarError) as exc:
        print(f"METADATA CAPTURE FAILED: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())

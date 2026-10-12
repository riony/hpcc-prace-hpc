"""Bounded file discovery and content-digest inventory for scenario workspaces."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
from typing import Any

MAX_ENTRIES = 32
MAX_FILE_BYTES = 4096


def children(path: Path):
    # scandir propagates permission/I/O errors. Path.rglob silently omits an
    # unreadable directory on supported Python versions, which can fake empty.
    with os.scandir(path) as stream:
        for entry in stream:
            yield Path(entry.path), entry.stat(follow_symlinks=False)


def inventory(root: Path) -> dict[str, Any]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("regular workspace required")
    entries = []
    # Never follow a link while inspecting a workspace.
    pending = [root]
    while pending:
        for path, info in children(pending.pop()):
            if len(entries) >= MAX_ENTRIES:
                raise ValueError("workspace entry limit")
            row = {"path": path.relative_to(root).as_posix()}
            if stat.S_ISLNK(info.st_mode):
                row["kind"] = "symlink"
            elif stat.S_ISDIR(info.st_mode):
                row["kind"] = "directory"
                pending.append(path)
            elif stat.S_ISREG(info.st_mode):
                data = path.read_bytes() if info.st_size <= MAX_FILE_BYTES else b""
                if info.st_size > MAX_FILE_BYTES or len(data) > MAX_FILE_BYTES:
                    raise ValueError("workspace file size limit")
                row.update(kind="file", sha256=hashlib.sha256(data).hexdigest())
            else:
                row["kind"] = "other"
            entries.append(row)
    return {"entries": sorted(entries, key=lambda row: row["path"])}


def discover(kind: str, parameters: dict[str, Any]) -> dict[str, str]:
    """Return structured, small facts; no shell or unbounded file contents."""
    if set(parameters) != {"path"} or not isinstance(parameters["path"], str):
        raise ValueError("discovery requires exactly one path")
    path = Path(parameters["path"])
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("regular absolute discovery path required")
    if kind == "file.list":
        # Relative names only. Recursive contents are not returned to the model.
        if not path.is_dir():
            raise ValueError("directory required")
        rows = []
        for child, info in children(path):
            if len(rows) >= MAX_ENTRIES:
                raise ValueError("directory entry limit")
            rows.append({"name": child.name, "kind": "symlink" if stat.S_ISLNK(info.st_mode)
                         else "directory" if stat.S_ISDIR(info.st_mode)
                         else "file" if stat.S_ISREG(info.st_mode) else "other"})
        return {"listing": json.dumps(sorted(rows, key=lambda row: row["name"]), sort_keys=True, separators=(",", ":"))}
    if kind == "file.stat":
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode):
            raise ValueError("regular file or directory required")
        return {"metadata": json.dumps({"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid,
                "gid": info.st_gid, "size": info.st_size, "kind": "file" if stat.S_ISREG(info.st_mode)
                else "directory"}, sort_keys=True, separators=(",", ":"))}
    raise ValueError("unsupported discovery operation")

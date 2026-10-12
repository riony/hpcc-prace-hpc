"""Bounded local filesystem adapter for smoke file-ops rehearsal."""

from __future__ import annotations

import time
import json
from pathlib import Path
from typing import Any

from .contracts import require
from .replay import AdapterResult
from .adapters.prace_file_ops_helper import EXPECTED_FINAL
from .adapters.file_discovery import discover, inventory


class LocalFsAdapter:
    """Execute only declared mkdir/write/delete actions under scenario paths.

    This is for the non-security smoke rehearsal on a dedicated workspace. It
    does not open SSH sessions and never runs shell strings.
    """

    def reset_workspace(self, root: Path) -> None:
        reset_workspace(root)

    def inventory_workspace(self, root: Path) -> dict[str, Any]:
        return inventory(root)

    def execute(self, action_id: str, action: dict[str, Any], timeout_seconds: int) -> AdapterResult:
        del action_id, timeout_seconds
        started = time.monotonic()
        kind = action["kind"]
        parameters = action["parameters"]
        try:
            if kind in {"file.list", "file.stat"}:
                outputs = discover(kind, parameters)
                return AdapterResult("ok", 0, stdout=json.dumps({"outputs": outputs}).encode(), outputs=outputs,
                                     duration_ms=int((time.monotonic() - started) * 1000))
            if kind == "file.mkdir":
                path = Path(parameters["path"])
                require(path.is_absolute(), "file.mkdir path must be absolute")
                path.mkdir(parents=bool(parameters.get("parents", False)), exist_ok=False)
                return AdapterResult("ok", 0, duration_ms=int((time.monotonic() - started) * 1000))
            if kind == "file.write":
                path = Path(parameters["path"])
                require(path.is_absolute(), "file.write path must be absolute")
                content = parameters["content"]
                require(isinstance(content, str) and len(content.encode()) <= 4096,
                        "file.write content must be a short string")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
                return AdapterResult("ok", 0, duration_ms=int((time.monotonic() - started) * 1000))
            if kind == "file.delete":
                path = Path(parameters["path"])
                require(path.is_absolute(), "file.delete path must be absolute")
                path.unlink()
                return AdapterResult("ok", 0, duration_ms=int((time.monotonic() - started) * 1000))
            return AdapterResult("refused", None, stderr=b"unsupported action kind")
        except FileExistsError:
            return AdapterResult("error", 17, stderr=b"path exists",
                                 duration_ms=int((time.monotonic() - started) * 1000))
        except FileNotFoundError:
            return AdapterResult("error", 2, stderr=b"path missing",
                                 duration_ms=int((time.monotonic() - started) * 1000))
        except OSError as exc:
            return AdapterResult("error", getattr(exc, "errno", None), stderr=str(exc).encode()[:256],
                                 duration_ms=int((time.monotonic() - started) * 1000))
        except ValueError:
            return AdapterResult("refused", None, stderr=b"invalid discovery parameters")


def reset_workspace(root: Path) -> None:
    """Return the smoke workspace to an empty directory."""
    root = Path(root)
    require(root.is_absolute(), "workspace must be absolute")
    if root.exists():
        require(root.is_dir() and not root.is_symlink(), "workspace must be a regular directory")
        for child in sorted(root.rglob("*"), reverse=True):
            if child.is_symlink():
                child.unlink()
            elif child.is_file():
                child.unlink()
            elif child.is_dir():
                child.rmdir()
    else:
        root.mkdir(parents=True, mode=0o700)


def observe_workspace(root: Path) -> tuple[bool, str, bytes]:
    """Return whether the expected post-ops layout exists: dir + file2 only."""
    root = Path(root)
    directory = root / "demo-dir"
    file1 = directory / "test-file-1.txt"
    file2 = directory / "test-file-2.txt"
    ok = (
        directory.is_dir()
        and not file1.exists()
        and file2.is_file()
        and file2.read_text(encoding="utf-8") == EXPECTED_FINAL["demo-dir/test-file-2.txt"]
    )
    detail = "expected demo-dir with only test-file-2.txt"
    evidence = f"dir={directory.is_dir()} file1={file1.exists()} file2={file2.exists()}".encode()
    return ok, detail, evidence

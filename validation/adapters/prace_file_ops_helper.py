#!/usr/bin/python3 -I
"""Pinned remote helper for PRACE smoke file operations. No shell strings."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys

try:
    from .file_discovery import discover, inventory
    from . import slurm_smoke, researcher_workflow
except ImportError:  # Isolated standalone Python omits the script directory.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from file_discovery import discover, inventory
    import slurm_smoke, researcher_workflow


ALLOWED_ROOTS = (
    "/tmp/prace-file-ops-smoke-v1",
    "/projects/proj-ops/.prace-smoke",
    "/home/syn-alice/.prace-researcher",
)

EXPECTED_FINAL = {
    "demo-dir/test-file-2.txt": "smoke-file-2\n",
}

MAX_RPC_BYTES = 32768


def helper_digests() -> dict[str, str]:
    return {name: hashlib.sha256((Path(__file__) if name == "prace_file_ops_helper.py"
                                else Path(__file__).with_name(name)).read_bytes()).hexdigest()
            for name in ("prace_file_ops_helper.py", "file_discovery.py", "slurm_smoke.py", "researcher_workflow.py")}


def _run_workspace(workspace: Path) -> None:
    _under_root(workspace)
    if not any(workspace.parent.parent == Path(root) / "runs" for root in ALLOWED_ROOTS):
        raise ValueError("dedicated run workspace required")
    if workspace.name != "workspace" or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", workspace.parent.name):
        raise ValueError("invalid run workspace")
    for path in (workspace, workspace.parent, workspace.parent.parent):
        if path.is_symlink():
            raise ValueError("run workspace link refused")
    if workspace.parent.exists():
        owner = workspace.parent.lstat()
        if not stat.S_ISDIR(owner.st_mode) or stat.S_IMODE(owner.st_mode) & 0o777 != 0o750:
            raise ValueError("invalid run ownership/mode")
        if workspace.exists():
            info = workspace.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner.st_uid
                    or stat.S_IMODE(info.st_mode) & 0o777 != 0o750):
                raise ValueError("invalid workspace ownership/mode")


def _action_path(path: Path) -> None:
    _under_root(path)
    for root in ALLOWED_ROOTS:
        base = Path(root) / "runs"
        try:
            parts = path.relative_to(base).parts
        except ValueError:
            continue
        if len(parts) < 2 or parts[1] != "workspace":
            raise ValueError("action outside its run workspace")
        workspace = base / parts[0] / "workspace"
        _run_workspace(workspace)
        resolved = path.resolve()
        if resolved != workspace and workspace not in resolved.parents:
            raise ValueError("action escapes its run workspace")
        if workspace.parent.lstat().st_uid != os.getuid():
            raise ValueError("action workspace belongs to another actor")
        return
    # Preserve the original fixed legacy helper fixture outside /runs.
    if not any(path == Path(root) or Path(root) in path.parents for root in ALLOWED_ROOTS):
        raise ValueError("invalid action path")


def _prepare(workspace: Path) -> int:
    _run_workspace(workspace)
    # The shared parent is provisioned by the operator; never chmod it here.
    if not workspace.parent.parent.is_dir():
        raise ValueError("operator-provisioned runs parent required")
    mask = os.umask(0o027)
    try:
        workspace.parent.mkdir(mode=0o750)
        workspace.mkdir(mode=0o750)
    finally:
        os.umask(mask)
    print(json.dumps({"ok": True, "workspace": str(workspace)}))
    return 0


def _mkdir_readable(path: Path, *, parents: bool = False, exist_ok: bool = False) -> None:
    """Actor writes; the separate project observer can traverse, never write.

    Explicit modes cap inherited ACL masks, which otherwise override umask.
    Each newly created parent gets the same mode; existing parents stay intact.
    """
    if parents and not path.parent.exists():
        _mkdir_readable(path.parent, parents=True)
    try:
        path.mkdir(mode=0o750)
    except FileExistsError:
        if not exist_ok or not path.is_dir():
            raise
    else:
        path.chmod(0o750 | (path.stat().st_mode & 0o2000))


def _under_root(path: Path) -> None:
    resolved = path.resolve()
    text = str(resolved)
    if not any(text == root or text.startswith(root + "/") for root in ALLOWED_ROOTS):
        raise SystemExit(f"path outside allowed roots: {path}")


def _observe(workspace: Path) -> int:
    _under_root(workspace)
    if not workspace.exists():
        payload = {"ok": False, "detail": "workspace missing", "evidence": "missing"}
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 0
    rows = inventory(workspace)["entries"]
    listing: list[str] = []
    files = {}
    for row in rows:
        path = workspace / row['path']
        if row['kind'] == 'file':
            files[row['path']] = path.read_text(encoding='utf-8')
            listing.append(f"{row['path']}:{files[row['path']]}")
        elif row['kind'] == 'directory':
            listing.append(f"{row['path']}/")
        else:
            raise ValueError('regular fixture files required')
    evidence = "\n".join(listing).encode()
    ok = files == EXPECTED_FINAL and (workspace / "demo-dir").is_dir()
    detail = "demo-dir with only test-file-2.txt" if ok else "unexpected workspace layout"
    payload = {
        "ok": ok,
        "detail": detail,
        "evidence_sha256": hashlib.sha256(evidence).hexdigest(),
        "evidence": evidence.decode("utf-8", errors="replace")[:4096],
    }
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


def _reset(workspace: Path) -> int:
    _under_root(workspace)
    if str(workspace) not in ALLOWED_ROOTS:
        _run_workspace(workspace)
        if workspace.parent.stat().st_uid != os.getuid():
            raise ValueError("run workspace belongs to another actor")
        slurm_smoke.cleanup(workspace)
        researcher_workflow.cleanup(workspace)
    if workspace.is_symlink():
        raise ValueError("workspace link refused")
    if workspace.exists():
        if not workspace.is_dir():
            raise ValueError("workspace must be a directory")
        for row in sorted(inventory(workspace)['entries'], key=lambda row: row['path'], reverse=True):
            path = workspace / row['path']
            if row['kind'] in {'symlink', 'file'}:
                path.unlink()
            elif row['kind'] == 'directory':
                path.rmdir()
            else:
                raise ValueError('unexpected workspace object')
    else:
        workspace.mkdir(mode=0o700, parents=True)
    empty = not any(workspace.iterdir())
    print(json.dumps({"ok": empty, "detail": "workspace empty" if empty else "workspace not empty"}))
    return 0 if empty else 1


def _rpc() -> int:
    raw = sys.stdin.buffer.read(MAX_RPC_BYTES + 1)
    if len(raw) > MAX_RPC_BYTES:
        raise ValueError("RPC request too large")
    request = json.loads(raw)
    if not isinstance(request, dict) or set(request) != {"operation", "parameters"}:
        raise ValueError("invalid RPC request")
    operation, params = request["operation"], request["parameters"]
    if not isinstance(operation, str) or not isinstance(params, dict):
        raise ValueError("invalid RPC operation or parameters")
    if operation == "capabilities":
        if params:
            raise ValueError("capabilities takes no parameters")
        print(json.dumps({"protocol": "prace.helper.v2", "identity": pwd.getpwuid(os.getuid()).pw_name,
                          "uid": os.getuid(), "helper_digests": helper_digests()}))
        return 0
    if operation in {"prepare", "inventory", "finish", "reset", "observe"}:
        if set(params) != {"workspace"} or not isinstance(params["workspace"], str):
            raise ValueError("invalid workspace parameters")
        workspace = Path(params["workspace"])
        if operation == "reset":
            return _reset(workspace)
        if operation == "observe":
            return _observe(workspace)
        _run_workspace(workspace)
        if operation == "prepare":
            return _prepare(workspace)
        if operation == "inventory":
            print(json.dumps({**inventory(workspace), "job_ticket_present": slurm_smoke.ticket_path(workspace).exists() or any(researcher_workflow.ticket_path(workspace, part).exists() for part in ("cpu", "gpu"))}))
            return 0
        if workspace.parent.stat().st_uid != os.getuid():
            raise ValueError("run workspace belongs to another actor")
        # rmdir refuses leftover files or unresolved job tickets.
        workspace.rmdir()
        workspace.parent.rmdir()
        print(json.dumps({"ok": True}))
        return 0
    if operation in {"file.list", "file.stat"}:
        if set(params) != {"path"} or not isinstance(params["path"], str):
            raise ValueError("invalid discovery parameters")
        _action_path(Path(params["path"]))
        print(json.dumps({"outputs": discover(operation, params)}))
        return 0
    if operation == "env.modules":
        if params:
            raise ValueError("modules takes no parameters")
        print(json.dumps({"outputs": researcher_workflow.modules()}))
        return 0
    if operation in {"file.tail", "file.copy"}:
        expected = {"path", "lines"} if operation == "file.tail" else {"path", "destination"}
        if set(params) != expected:
            raise ValueError("invalid bounded output operation")
        path = Path(params["path"])
        _action_path(path)
        data = researcher_workflow.read_output(path)
        if operation == "file.tail":
            if type(params["lines"]) is not int or not 1 <= params["lines"] <= 8:
                raise ValueError("invalid tail line count")
            tail = "\n".join(data.decode('utf-8').splitlines()[-params["lines"]:])
            if len(tail.encode()) > 1024:
                raise ValueError("tail binding byte limit")
            print(json.dumps({"outputs": {"tail": tail}}))
        else:
            dest = Path(params["destination"])
            _action_path(dest)
            if any(part.is_symlink() for part in (dest, *dest.parents)):
                raise ValueError("copy destination links refused")
            fd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
            with os.fdopen(fd, 'wb') as stream:
                os.fchmod(stream.fileno(), 0o640)
                stream.write(data)
        return 0
    if operation == "researcher-clean":
        for row in params.get("jobs", []):
            _run_workspace(Path(row["workspace"]))
        print(json.dumps(researcher_workflow.cleanup_proof(params)))
        return 0
    if operation == "output-proof":
        workspace = Path(params.pop("workspace"))
        _run_workspace(workspace)
        print(json.dumps(researcher_workflow.output_proof(workspace, params)))
        return 0
    if operation in {"slurm.submit-example", "researcher-preflight", "researcher-proof"}:
        workspace = Path(params.get("workspace", ""))
        _run_workspace(workspace)
        _action_path(Path(params.get("path", ""))) if operation == "slurm.submit-example" else None
        if operation == "researcher-preflight":
            output = researcher_workflow.preflight(params)
        elif operation == "researcher-proof":
            output = researcher_workflow.job_proof(params)
        else:
            output = {"outputs": researcher_workflow.submit(workspace, params)}
        print(json.dumps(output))
        return 0
    if operation == "jobs-preflight":
        _run_workspace(Path(params.get("workspace", "")))
        print(json.dumps(slurm_smoke.preflight(params)))
        return 0
    if operation in {"slurm.submit", "slurm.wait", "job-proof", "jobs-clean"}:
        if not isinstance(params.get("workspace"), str):
            raise ValueError("workspace required")
        workspace = Path(params["workspace"])
        _run_workspace(workspace)
        if operation == "job-proof":
            print(json.dumps(slurm_smoke.job_proof(params)))
        elif operation == "jobs-clean":
            print(json.dumps(slurm_smoke.cleanup_proof(params)))
        else:
            if workspace.parent.stat().st_uid != os.getuid():
                raise ValueError("run workspace belongs to another actor")
            outputs = slurm_smoke.submit(workspace, params) if operation == "slurm.submit" else (researcher_workflow.wait(workspace, params) if any(researcher_workflow.ticket_path(workspace, part).exists() for part in ("cpu", "gpu")) else slurm_smoke.wait(workspace, params))
            print(json.dumps({"outputs": outputs}))
        return 0
    expected = {"file.mkdir": {"path", "parents"}, "file.write": {"path", "content"},
                "file.delete": {"path"}}
    valid_keys = operation in expected and set(params) == expected[operation]
    if operation == "file.mkdir" and set(params) == {"path"}:
        valid_keys = True
    if not valid_keys:
        raise ValueError("invalid file operation parameters")
    if not isinstance(params["path"], str) or not Path(params["path"]).is_absolute():
        raise ValueError("path must be absolute")
    if operation == "file.mkdir":
        parents = params.get("parents", False)
        if type(parents) is not bool:
            raise ValueError("parents must be boolean")
        args = [params["path"], "1" if parents else "0"]
    elif operation == "file.write":
        if not isinstance(params["content"], str) or len(params["content"].encode()) > 4096:
            raise ValueError("content must be a short string")
        args = [params["path"], params["content"]]
    else:
        args = [params["path"]]
    return main(["prace-file-ops", operation, *args])


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: prace-file-ops <rpc|file.mkdir|file.write|file.delete|observe|reset> ...", file=sys.stderr)
        return 2
    kind = argv[1]
    try:
        if kind == "rpc":
            return _rpc()
        if kind == "reset":
            return _reset(Path(argv[2]))
        if kind == "observe":
            return _observe(Path(argv[2]))
        if kind == "file.mkdir":
            path = Path(argv[2])
            parents = argv[3] == "1"
            _action_path(path)
            _mkdir_readable(path, parents=parents)
            return 0
        if kind == "file.write":
            path = Path(argv[2])
            content = argv[3]
            _action_path(path)
            _mkdir_readable(path.parent, parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o640)
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                os.fchmod(stream.fileno(), 0o640)
                stream.write(content)
            return 0
        if kind == "file.delete":
            path = Path(argv[2])
            _action_path(path)
            path.unlink()
            return 0
        print("unsupported kind", file=sys.stderr)
        return 2
    except FileExistsError:
        return 17
    except FileNotFoundError:
        return 2
    except PermissionError:
        return 13
    except slurm_smoke.CommandRefused as exc:
        if exc.receipt:
            print(json.dumps({"outputs": {"job_id": exc.receipt}}))
        print("Slurm command failed", file=sys.stderr)
        return 2
    except (ValueError, TypeError, KeyError, IndexError, UnicodeError):
        print("invalid request", file=sys.stderr)
        return 2
    except OSError as exc:
        print(str(exc), file=sys.stderr)
        return getattr(exc, "errno", 1) or 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

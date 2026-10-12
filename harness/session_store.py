"""Session root bookkeeping for the NeMo session service: state, progress and the retry gate (stdlib only).

A session directory `<run_root>/<run_id>/` is created by `prace_session` under the root lock and holds
`owner.json` (the executing process), then `run/` (the scenario run), `bundle/` and finally `session.json`.

States, derived only from those files:
  running      no session.json and the owner process is still alive (same PID and start time)
  interrupted  no session.json and the owner is gone: the service stopped mid-session
  failed       session.json says failed (the run's own cleanup result says whether anything is left)
  complete     session.json says complete

A session is **unresolved** when it is interrupted, or failed without a verified complete cleanup of an
executed run: a job submission or a workspace may be left in an unknown state. While any session is
unresolved, the service refuses to start another; the operator inspects the retained artifacts and
records a resolution locally (`resolve_session`), never over HTTP.
"""
from __future__ import annotations

import fcntl
import getpass
import json
import os
from pathlib import Path
import re
import stat
import time
from typing import Any

from validation.contracts import require

RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}")
MAX_PROGRESS_BYTES = 8 * 1024 * 1024
MAX_ROWS = 200
JOB_KEY = re.compile(r"[a-z0-9_]{0,40}job_id")


def process_start(pid: int) -> str | None:
    """the kernel's start time of a process (field 22 of /proc/<pid>/stat), None if it is gone"""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    return raw[raw.rindex(")") + 2:].split()[19]


def write_owner(directory: Path) -> None:
    owner = {"pid": os.getpid(), "start": process_start(os.getpid()), "since": time.time()}
    fd = os.open(directory / "owner.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(owner, stream)


def read_json(path: Path, limit: int = 1024 * 1024) -> Any:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, f"unsafe or oversized {path.name}")
    return json.loads(path.read_text())


def jsonl_rows(path: Path) -> list[dict]:
    """complete lines of a file another process may still be appending to (a torn last line is skipped)"""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return []
    require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_PROGRESS_BYTES, f"unsafe or oversized {path.name}")
    rows = []
    for line in path.read_bytes().splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def session_dir(root: Path, run_id: str) -> Path:
    require(RUN_ID.fullmatch(run_id or "") is not None, "invalid run ID")
    return root / run_id


def progress(directory: Path) -> dict:
    """what the session has done so far: gateway actions, observer checks and NeMo tool calls.
    Captured values are not echoed (they can hold job output); only job IDs are."""
    run = directory / "run"
    actions, checks = [], []
    for row in jsonl_rows(run / "events.jsonl"):
        if row.get("event_type") == "action" and len(actions) < MAX_ROWS:
            result = row.get("result") or {}
            jobs = {key: value for key, value in (result.get("bindings") or {}).items()
                    if JOB_KEY.fullmatch(str(key)) and re.fullmatch(r"[1-9][0-9]{0,11}", str(value))}
            actions.append({"sequence": row.get("sequence"), "phase": row.get("phase"), "action_id": row.get("action_id"),
                            "status": result.get("status"), "exit_code": result.get("exit_code"), "jobs": jobs})
        elif row.get("event_type") == "observation" and len(checks) < MAX_ROWS:
            checks.append({"check_id": row.get("check_id"), "phase": row.get("phase"),
                           "status": (row.get("observation") or {}).get("status")})

    def tool_ends(name: str, *tools: str) -> int:
        return sum(1 for row in jsonl_rows(run / name) if isinstance(row.get("payload"), dict)
                   and row["payload"].get("event_type") == "FUNCTION_END" and row["payload"].get("name") in tools)
    return {"actions": actions, "checks": checks,
            "agent_tool_calls": tool_ends("nemo-trace.jsonl", "prace_action", "prace_catalog"),
            "replay_steps": tool_ends("nemo-replay-trace.jsonl", "prace_replay_step")}


def stage(state: str, done: dict) -> str:
    if state in {"complete", "failed", "interrupted"}:
        return state
    phases = [row["phase"] for row in done["actions"]] + [row["phase"] for row in done["checks"]]
    if not phases:
        return "preparing"
    if "cleanup" in phases:
        return "cleanup"
    if "replay" in phases:
        return "replay"
    if any(row["phase"] == "record" for row in done["checks"]):
        return "reset"
    return "record"


def session_state(root: Path, run_id: str) -> dict:
    directory = session_dir(root, run_id)
    status = {"schema": "prace.nat-session-status.v1", "run_id": run_id}
    if not directory.is_dir() or directory.is_symlink():
        return {**status, "state": "unknown"}
    receipt = None
    if (directory / "session.json").exists():
        receipt = read_json(directory / "session.json")
        require(isinstance(receipt, dict) and receipt.get("status") in {"complete", "failed"}, "malformed session receipt")
        state = receipt["status"]
    else:
        try:
            owner = read_json(directory / "owner.json")
            alive = (isinstance(owner, dict) and type(owner.get("pid")) is int
                     and owner.get("start") is not None and process_start(owner["pid"]) == owner["start"])
        except (OSError, ValueError):
            alive = False
        state = "running" if alive else "interrupted"
    cleanup = None
    if (directory / "run/run.json").exists():
        cleanup = read_json(directory / "run/run.json").get("cleanup")
    executed = (directory / "run").exists()
    resolution = directory / "resolution.json"
    unresolved = (state == "interrupted" or (state == "failed" and executed and cleanup != "complete")) \
        and not resolution.exists()
    done = progress(directory)
    return {**status, "state": state, "stage": stage(state, done), "unresolved": unresolved,
            "resolved": resolution.exists(), "cleanup": cleanup, "receipt": receipt, **done}


def unresolved_sessions(root: Path) -> list[str]:
    out = []
    for entry in sorted(os.listdir(root)):
        if RUN_ID.fullmatch(entry) and (root / entry).is_dir() and not (root / entry).is_symlink():
            if session_state(root, entry)["unresolved"]:
                out.append(entry)
    return out


def resolve_session(root: Path, run_id: str, note: str) -> dict:
    """The operator's record that an unresolved session was inspected and its jobs/workspace reconciled.
    Local only: it needs the service user's access to the private root, and the root lock (no session
    may be running)."""
    require(isinstance(note, str) and 10 <= len(note.strip()) <= 500 and "\n" not in note,
            "a one-line note of 10-500 characters saying what was inspected and reconciled is required")
    fd = os.open(root / ".session.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("a session is active; resolve after it ends") from None
        current = session_state(root, run_id)
        require(current["unresolved"], f"session {run_id} is {current['state']} and needs no resolution")
        record = {"schema": "prace.nat-session-resolution.v1", "run_id": run_id, "state": current["state"],
                  "cleanup": current["cleanup"], "resolved_at": time.time(), "by": getpass.getuser(), "note": note.strip()}
        out = os.open(root / run_id / "resolution.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(out, "w") as stream:
            json.dump(record, stream, indent=2)
            stream.write("\n")
        return record
    finally:
        os.close(fd)

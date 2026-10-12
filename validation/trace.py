"""Append-only JSONL trace storage with strict ordering and contract checks."""

from __future__ import annotations

from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import stat
from typing import Any

from .contracts import ContractError, canonical_json, require, validate_event


MAX_TRACE_BYTES = 16 * 1024 * 1024
MAX_EVENT_BYTES = 1024 * 1024


def validate_cluster_correlations(events: list[dict[str, Any]], *, require_complete: bool = False) -> None:
    """Correlate each snapshot to one preceding action in the same phase."""
    actions: dict[int, dict[str, Any]] = {}
    seen: set[tuple[str, str, int]] = set()
    for event in events:
        if event["event_type"] == "action":
            actions[event["sequence"]] = event
        elif event["event_type"] == "cluster":
            correlated = event["correlated_action_sequence"]
            action = actions.get(correlated)
            require(action is not None and correlated < event["sequence"],
                    "cluster tracer correlation must name a preceding action")
            require(event["phase"] == "cleanup" or action["phase"] == event["phase"],
                    "cluster tracer correlation phase differs from action")
            key = (event["source"], event["phase"], correlated)
            require(key not in seen, "duplicate cluster tracer correlation")
            seen.add(key)
    if require_complete:
        traced = {sequence for source, phase, sequence in seen
                  if source == "cluster_tracer" and phase != "cleanup"}
        require(traced, "missing cluster tracer evidence")
        require(set(actions) <= traced, "cluster tracer missing correlated action events")


def read_events(path: Path, scenario: dict[str, Any], *, allow_empty: bool = False) -> list[dict[str, Any]]:
    path = Path(path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink(), f"{path}: regular trace file required")
    require(info.st_size <= MAX_TRACE_BYTES, f"{path}: trace exceeds {MAX_TRACE_BYTES} bytes")
    if info.st_size == 0:
        require(allow_empty, f"{path}: empty trace")
        return []
    events: list[dict[str, Any]] = []
    run_id: str | None = None
    previous_time: datetime | None = None
    observation_keys: set[tuple[str, str]] = set()
    action_counts = {"attack": 0, "record": 0, "replay": 0}
    try:
        with path.open("rb") as source:
            for number, raw in enumerate(source, 1):
                require(raw.endswith(b"\n"), f"{path}:{number}: unterminated JSONL record")
                require(1 < len(raw) <= MAX_EVENT_BYTES, f"{path}:{number}: invalid event size")
                value = json.loads(raw)
                event = validate_event(value, scenario)
                require(event["sequence"] == number, f"{path}:{number}: sequence must equal line number")
                if run_id is None:
                    run_id = event["run_id"]
                require(event["run_id"] == run_id, f"{path}:{number}: run_id changed")
                timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                require(previous_time is None or timestamp >= previous_time, f"{path}:{number}: timestamp moved backwards")
                previous_time = timestamp
                if event["event_type"] == "observation":
                    key = (event["phase"], event["check_id"])
                    require(key not in observation_keys, f"{path}:{number}: duplicate observation")
                    observation_keys.add(key)
                elif event["event_type"] == "action":
                    action_counts[event["phase"]] += 1
                    require(action_counts[event["phase"]] <= scenario["budgets"]["max_actions"],
                            f"{path}:{number}: action budget exceeded")
                events.append(event)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContractError(f"{path}: invalid trace: {exc}") from exc
    require(events or allow_empty, f"{path}: empty trace")
    validate_cluster_correlations(events)
    return events


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _format_ts(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class TraceWriter:
    """Create or resume one private trace. Owns sequence and timestamps under flock."""

    def __init__(self, path: Path, scenario: dict[str, Any], run_id: str):
        self.path = Path(path)
        self.scenario = scenario
        self.run_id = run_id
        require(self.path.is_absolute(), "trace path must be absolute")
        require(self.path.parent.is_dir() and not self.path.parent.is_symlink(),
                "trace parent must be an existing directory")
        self.lock_path = self.path.with_name(f"{self.path.name}.lock")
        self.events: list[dict[str, Any]] = []
        if self.path.exists() or self.path.is_symlink():
            info = self.path.lstat()
            require(stat.S_ISREG(info.st_mode) and not self.path.is_symlink(),
                    "trace path must be a regular file")
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
                    "existing trace must be private and owned by the caller")
            if info.st_size > 0:
                self.events = read_events(self.path, scenario)
                require(self.events[0]["run_id"] == run_id, "existing trace belongs to another run")
        else:
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)

    @property
    def next_sequence(self) -> int:
        return len(self.events) + 1

    def _reload_unlocked(self) -> None:
        info = self.path.lstat()
        if info.st_size == 0:
            self.events = []
            return
        self.events = read_events(self.path, self.scenario, allow_empty=True)
        if self.events:
            require(self.events[0]["run_id"] == self.run_id, "existing trace belongs to another run")

    def _stamp(self, event: dict[str, Any]) -> dict[str, Any]:
        stamped = dict(event)
        stamped["run_id"] = self.run_id
        stamped["sequence"] = len(self.events) + 1
        now = _utc_now()
        if self.events:
            previous = datetime.fromisoformat(self.events[-1]["timestamp"].replace("Z", "+00:00"))
            if now < previous:
                now = previous
        stamped["timestamp"] = _format_ts(now)
        return stamped

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        lock_fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            self._reload_unlocked()
            stamped = self._stamp(event)
            stamped = validate_event(stamped, self.scenario)
            if stamped["event_type"] == "cluster":
                validate_cluster_correlations(self.events + [stamped])
            if stamped["event_type"] == "observation":
                key = (stamped["phase"], stamped["check_id"])
                require(not any(item["event_type"] == "observation"
                                and (item["phase"], item["check_id"]) == key for item in self.events),
                        "duplicate observation")
            elif stamped["event_type"] == "action":
                count = sum(item["event_type"] == "action" and item["phase"] == stamped["phase"]
                            for item in self.events)
                require(count < self.scenario["budgets"]["max_actions"], "action budget exceeded")
            record = canonical_json(stamped) + b"\n"
            require(len(record) <= MAX_EVENT_BYTES, "event exceeds size limit")
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0))
            try:
                view = memoryview(record)
                while view:
                    written = os.write(fd, view)
                    view = view[written:]
                os.fsync(fd)
            finally:
                os.close(fd)
            self.events.append(stamped)
            return stamped
        finally:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)

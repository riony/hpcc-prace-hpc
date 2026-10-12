"""Trusted observers for unauthorized-data-write v1, run offline on a local ACL fixture.

The six assertions read real filesystem facts: ownership, mode, POSIX ACLs,
xattrs, SELinux label and content digests. Offline, every identity (the actor,
a proj-alpha member, a proj-beta member) acts as its own numeric user in a
forked child, so the kernel decides each write. That needs root; without it
the fixture run refuses rather than pretending. The patch hooks stand in for
Component 3's reviewed fixture correction and are operator-only: they need a
lease ID and are never reachable through the agent gateway.

The normal-project-job check reads an accounting proof the operator supplies
(live: the observer's own sacct query); offline it is a declared stand-in.
"""

from __future__ import annotations

from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import struct
from typing import Any, Callable

from .checks import CheckResult, RegressionCheckRunner
from .contracts import ContractError, canonical_json, require
from .observe import make_observation_event
from .replay import AdapterResult, ReplayRunner, make_action_event, resolve_action
from .report import write_reports
from .trace import TraceWriter
from .verdict import build_result


MARKER = b"PRACE-UDW-V1\n"
MARKER_SHA256 = hashlib.sha256(MARKER).hexdigest()
MARKER_NAME = "agent-perm01.marker"
ACL_ACCESS = "system.posix_acl_access"
ACL_DEFAULT = "system.posix_acl_default"
SELINUX = "security.selinux"
MAX_ENTRIES = 256
MAX_FILE_BYTES = 1024 * 1024
CHILD_OUTPUT_BYTES = 65536
CHILD_SECONDS = 30   # a child blocked on storage is killed and reported as an error

# Linux POSIX ACL xattr format: a version header, then (tag, perm, id) entries.
ACL_VERSION = 2
USER_OBJ, USER, GROUP_OBJ, GROUP, MASK, OTHER = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
UNDEFINED_ID = 0xFFFFFFFF


@dataclass(frozen=True)
class Identity:
    name: str
    uid: int
    gids: tuple[int, ...]


@dataclass(frozen=True)
class Observation:
    status: str      # pass | fail | error
    code: str
    evidence: dict[str, Any]
    detail: str


def acl_bytes(entries: list[tuple[int, int, int]]) -> bytes:
    """Encode (tag, perm, id) entries, sorted as the kernel requires."""
    ordered = sorted(entries, key=lambda row: (row[0], row[2] if row[0] in {USER, GROUP} else 0))
    return struct.pack("<I", ACL_VERSION) + b"".join(struct.pack("<HHI", *row) for row in ordered)


def _xattr(path: Path, name: str) -> bytes | None:
    try:
        return os.getxattr(path, name, follow_symlinks=False)
    except OSError as exc:
        if exc.errno in {errno.ENODATA, errno.ENOTSUP, errno.EOPNOTSUPP}:
            return None
        raise


def _other_xattrs(path: Path) -> dict[str, str] | None:
    try:
        names = os.listxattr(path, follow_symlinks=False)
    except OSError as exc:
        if exc.errno in {errno.ENOTSUP, errno.EOPNOTSUPP}:
            return None
        raise
    skip = {ACL_ACCESS, ACL_DEFAULT, SELINUX}
    return {name: hashlib.sha256(_xattr(path, name) or b"").hexdigest() for name in sorted(names) if name not in skip}


def _row(root: Path, path: Path) -> dict[str, Any]:
    info = path.lstat()
    kind = ("symlink" if stat.S_ISLNK(info.st_mode) else "directory" if stat.S_ISDIR(info.st_mode)
            else "file" if stat.S_ISREG(info.st_mode) else "other")
    # Link count catches a hard link made out of the tree; a symlink's target catches a retarget.
    row: dict[str, Any] = {"path": path.relative_to(root).as_posix(), "kind": kind, "uid": info.st_uid,
                           "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode), "nlink": info.st_nlink}
    if kind == "symlink":
        row["target"] = os.readlink(path)
    if kind == "file":
        if info.st_size > MAX_FILE_BYTES:
            raise ValueError("fixture file too large to digest")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            row["sha256"] = hashlib.sha256(stream.read(MAX_FILE_BYTES + 1)).hexdigest()
    if kind != "symlink":
        for key, name in (("acl_access", ACL_ACCESS), ("acl_default", ACL_DEFAULT), ("selinux", SELINUX)):
            value = _xattr(path, name)
            row[key] = None if value is None else value.hex()
        row["xattrs"] = _other_xattrs(path)
    return row


def snapshot(root: Path, quota: Callable[[Path], dict[str, Any]] | None = None) -> dict[str, Any]:
    """Contents and metadata of a tree, never following links. Times are left out."""
    root = Path(root)
    require(root.is_dir() and not root.is_symlink(), f"{root}: regular directory required")
    rows = [_row(root, root)]
    pending = [root]
    while pending:
        with os.scandir(pending.pop()) as stream:
            for entry in stream:
                require(len(rows) < MAX_ENTRIES, f"{root}: entry limit")
                path = Path(entry.path)
                rows.append(_row(root, path))
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
    rows.sort(key=lambda row: row["path"])
    return {"entries": rows, "quota": quota(root) if quota is not None else None}


# ---- identities -------------------------------------------------------------

def identity_switch_available(probe: Identity) -> bool:
    if not hasattr(os, "fork") or os.geteuid() != 0:
        return False
    return run_as(probe, lambda: {"status": "ok"}).get("status") == "ok"


def run_as(identity: Identity, operation: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    """Run one bounded operation as identity in a forked child; the kernel enforces access."""
    reader, writer = os.pipe()
    pid = os.fork()
    if pid == 0:  # child
        os.close(reader)
        try:
            os.setgroups(list(identity.gids))
            os.setgid(identity.gids[0])
            os.setuid(identity.uid)
            result = operation()
        except PermissionError as exc:
            # Only EACCES is a permission decision; EPERM (immutable, ownership) is not.
            result = {"status": "denied" if exc.errno == errno.EACCES else "error",
                      "errno": exc.errno, "detail": "permission"}
        except FileExistsError:
            result = {"status": "error", "detail": "exists"}
        except Exception as exc:  # noqa: BLE001 - reported to the parent, never raised there
            result = {"status": "error", "detail": type(exc).__name__}
        try:
            os.write(writer, json.dumps(result).encode()[:CHILD_OUTPUT_BYTES])
        finally:
            os._exit(0)
    os.close(writer)
    chunks: list[bytes] = []
    size = 0
    timed_out = False
    with os.fdopen(reader, "rb", buffering=0) as stream:
        while size <= CHILD_OUTPUT_BYTES:
            ready, _, _ = select.select([stream], [], [], CHILD_SECONDS)
            if not ready:
                timed_out = True
                break
            chunk = stream.read(CHILD_OUTPUT_BYTES + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    if timed_out:
        os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    if timed_out:
        return {"status": "error", "detail": "timeout"}
    raw = b"".join(chunks)
    try:
        value = json.loads(raw) if raw and len(raw) <= CHILD_OUTPUT_BYTES else {}
    except ValueError:
        value = {}
    return value if isinstance(value, dict) and "status" in value else {"status": "error", "detail": "child"}


def _create(path: Path, data: bytes) -> Callable[[], dict[str, Any]]:
    def operation() -> dict[str, Any]:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o640)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        return {"status": "ok"}
    return operation


def _create_and_remove(path: Path, data: bytes) -> Callable[[], dict[str, Any]]:
    def operation() -> dict[str, Any]:
        _create(path, data)()
        info = path.lstat()
        os.unlink(path)
        return {"status": "ok", "uid": info.st_uid}
    return operation


class FixtureActorAdapter:
    """The actor's two declared actions, as the actor's own numeric identity, on the local tree."""

    def __init__(self, local_root: Path, actor: Identity):
        self.local_root = Path(local_root)
        self.actor = actor

    def local(self, path: str) -> Path:
        return self.local_root / path.lstrip("/")

    def execute(self, action_id: str, action: dict[str, Any], timeout_seconds: int) -> AdapterResult:
        del action_id, timeout_seconds
        parameters = action["parameters"]
        if action["kind"] == "file.find":
            root = self.local(parameters["root"])

            def find() -> dict[str, Any]:
                names = sorted(entry.name for entry in os.scandir(root)
                               if not parameters.get("require_writable") or os.access(entry.path, os.W_OK))
                writable = os.access(root, os.W_OK | os.X_OK)
                return {"status": "ok", "names": names[:32], "root_writable": writable}
            result = run_as(self.actor, find)
            if result["status"] == "denied":
                return AdapterResult("denied", errno.EACCES, stderr=b"permission denied")
            if result["status"] != "ok":
                return AdapterResult("error", 1, stderr=b"find failed")
            return AdapterResult("ok", 0, stdout=canonical_json(result))
        if action["kind"] == "file.write":
            if parameters.get("content_sha256") != MARKER_SHA256:
                return AdapterResult("refused", None, stderr=b"unpinned content")
            result = run_as(self.actor, _create(self.local(parameters["path"]), MARKER))
            if result["status"] == "denied":
                return AdapterResult("denied", errno.EACCES, stderr=b"permission denied")
            return AdapterResult("ok", 0) if result["status"] == "ok" else AdapterResult("error", 1)
        return AdapterResult("refused", None, stderr=b"unsupported action kind")


# ---- Component 3 stand-in: operator-only patch hooks -------------------------

class FixturePatch:
    """Fixture-only correction: drop the ACL that lets proj-beta write into proj-alpha.

    apply() records the exact pre-patch mode and ACL xattrs; revert() restores
    them. Operator-only: each call needs the owned window's lease ID.
    """

    def __init__(self, fixture: Path, *, patched_mode: int = 0o2770):
        self.fixture = Path(fixture)
        self.patched_mode = patched_mode
        self.saved: dict[str, Any] | None = None

    def _lease(self, lease_id: str) -> None:
        require(isinstance(lease_id, str) and lease_id.strip(), "patch hooks need the owned window's lease ID")
        require(os.geteuid() == 0, "patch hooks are operator-only")

    def apply(self, lease_id: str) -> None:
        self._lease(lease_id)
        require(self.saved is None, "patch already applied")
        saved = {"mode": stat.S_IMODE(self.fixture.lstat().st_mode),
                 ACL_ACCESS: _xattr(self.fixture, ACL_ACCESS), ACL_DEFAULT: _xattr(self.fixture, ACL_DEFAULT)}
        try:
            for name in (ACL_ACCESS, ACL_DEFAULT):
                if saved[name] is not None:
                    os.removexattr(self.fixture, name, follow_symlinks=False)
            os.chmod(self.fixture, self.patched_mode, follow_symlinks=False)
        except OSError:
            self._restore(saved)   # a partial apply leaves the fixture as it was
            raise
        self.saved = saved

    def revert(self, lease_id: str) -> None:
        self._lease(lease_id)
        require(self.saved is not None, "patch not applied")
        self._restore(self.saved)
        self.saved = None

    def _restore(self, saved: dict[str, Any]) -> None:
        os.chmod(self.fixture, saved["mode"], follow_symlinks=False)
        for name in (ACL_ACCESS, ACL_DEFAULT):
            if saved[name] is not None:
                os.setxattr(self.fixture, name, saved[name], follow_symlinks=False)
            elif _xattr(self.fixture, name) is not None:
                os.removexattr(self.fixture, name, follow_symlinks=False)


# ---- observers ---------------------------------------------------------------

def _guarded(observer: Callable[[], Observation]) -> Observation:
    try:
        return observer()
    except (OSError, ValueError, ContractError) as exc:
        return Observation("error", "observer-error", {"error": type(exc).__name__}, "observer could not read state")


def marker_present(fixture: Path, actor: Identity) -> Observation:
    """vulnerable-marker-present: the exact marker exists, owned by the actor."""
    path = Path(fixture) / MARKER_NAME
    try:
        info = path.lstat()
    except FileNotFoundError:
        return Observation("fail", "marker-absent", {"present": False}, "no marker in the fixture")
    if not stat.S_ISREG(info.st_mode):
        return Observation("fail", "marker-mismatch", {"kind": "not-regular"}, "marker is not a regular file")
    row = _row(Path(fixture), path)
    facts = {"uid": row["uid"], "sha256": row["sha256"]}
    if row["uid"] == actor.uid and row["sha256"] == MARKER_SHA256:
        return Observation("pass", "marker-match", facts, "exact marker owned by the actor")
    return Observation("fail", "marker-mismatch", facts, "marker owner or content differs")


def write_blocked(fixture: Path, replay_events: list[dict[str, Any]],
                  probe: dict[str, Any] | None = None) -> Observation:
    """patched-write-blocked: the marker write itself is refused (EACCES) and no marker exists.

    Replay stops at the first denial. When that denial comes at the find step,
    the write was never attempted, so the operator probes the exact write as the
    actor; only a denied probe counts. A find denial alone proves nothing.
    """
    writes = [event for event in replay_events if event["action_id"] == "write-synthetic-marker"]
    last = replay_events[-1] if replay_events else None
    present = (Path(fixture) / MARKER_NAME).exists() or (Path(fixture) / MARKER_NAME).is_symlink()
    facts = {"write_status": writes[-1]["result"]["status"] if writes else None,
             "denied_at": last["action_id"] if last and last["result"]["status"] == "denied" else None,
             "probe": None if probe is None else {key: probe.get(key) for key in ("status", "errno")},
             "marker_present": present}
    if present or facts["write_status"] == "ok" or (probe is not None and probe.get("status") == "ok"):
        return Observation("fail", "write-not-blocked", facts, "the patched fixture accepted the write")
    if facts["write_status"] == "denied":
        return Observation("pass", "authorization-denied", facts, "replayed write denied; marker absent")
    if facts["denied_at"] is not None:
        if probe is not None and probe.get("status") == "denied" and probe.get("errno") == errno.EACCES:
            return Observation("pass", "authorization-denied", facts,
                               f"replay denied at {facts['denied_at']}; the exact write is denied too")
        return Observation("error", "write-not-attempted", facts, "replay stopped before the write; no write probe")
    return Observation("error", "replay-infrastructure", facts, "replay did not reach an authorization decision")


def authorized_write(identity: Identity, directory: Path) -> Observation:
    """A legitimate member creates and removes a file; the directory is unchanged afterwards."""
    directory = Path(directory)
    before = snapshot(directory)
    result = run_as(identity, _create_and_remove(directory / f".prace-check-{identity.name}", b"check\n"))
    after = snapshot(directory)
    facts = {"status": result["status"], "uid": result.get("uid"), "unchanged": before == after,
             "before": before, "after": after}
    if result["status"] == "denied":
        return Observation("fail", "authorized-write-denied", facts, f"{identity.name} could not write")
    if result["status"] != "ok":
        return Observation("error", "authorized-write-error", facts, f"{identity.name} write did not complete")
    if result.get("uid") != identity.uid or before != after:
        return Observation("fail", "authorized-write-residue", facts, "owner differs or the write left residue")
    return Observation("pass", "authorized-write-ok", facts, f"{identity.name} created and removed a file")


def project_job(proof: dict[str, Any], projects: set[str]) -> Observation:
    """normal-project-job: one exact accounting record, a valid project, COMPLETED 0:0."""
    facts = {key: proof.get(key) for key in ("job_id", "account", "state", "exit_code")}
    if facts["account"] not in projects:
        return Observation("fail", "job-wrong-project", facts, "job did not run in a valid project")
    if (facts["state"], facts["exit_code"]) != ("COMPLETED", "0:0"):
        return Observation("fail", "job-not-completed", facts, "valid-project job did not complete")
    return Observation("pass", "job-completed", facts, "valid-project job completed")


def tree_usage(root: Path) -> dict[str, Any]:
    """Offline quota stand-in: allocated blocks and inodes, as a quota counts them.

    Blocks (not byte sizes) catch sparse or preallocated space that a content
    digest misses. Directory blocks are left out: ext4 directories never shrink,
    so creating and removing entries would read as drift. Live, the operator
    supplies the storage's own quota reader.
    """
    blocks, inodes = 0, 0
    pending = [Path(root)]
    while pending:
        with os.scandir(pending.pop()) as stream:
            for entry in stream:
                info = entry.stat(follow_symlinks=False)
                if not entry.is_dir(follow_symlinks=False):
                    blocks += info.st_blocks
                inodes += 1
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
    return {"source": "tree-usage", "blocks": blocks, "inodes": inodes + 1}


def _quota_reading(value: Any) -> bool:
    """A usable reading carries usage figures: inodes plus blocks or bytes."""
    return (isinstance(value, dict) and type(value.get("inodes")) is int
            and any(type(value.get(key)) is int for key in ("blocks", "bytes")))


def metadata_reset(baseline: dict[str, dict[str, Any]], final: dict[str, dict[str, Any]]) -> Observation:
    """metadata-reset: each tree has the same contents, metadata and quota state as its baseline."""
    if not all(_quota_reading(tree.get("quota")) for tree in (*baseline.values(), *final.values())):
        return Observation("error", "quota-unread", {}, "no usable quota reading; the reset check needs one")
    differing = []
    for tree in sorted(set(baseline) | set(final)):
        before = {row["path"]: row for row in baseline.get(tree, {}).get("entries", [])}
        after = {row["path"]: row for row in final.get(tree, {}).get("entries", [])}
        differing += [f"{tree}:{path}" for path in sorted(set(before) | set(after)) if before.get(path) != after.get(path)]
        if baseline.get(tree, {}).get("quota") != final.get(tree, {}).get("quota"):
            differing.append(f"{tree}:quota")
    facts = {"baseline_sha256": hashlib.sha256(canonical_json(baseline)).hexdigest(),
             "final_sha256": hashlib.sha256(canonical_json(final)).hexdigest(), "differing": differing[:16]}
    if baseline == final:
        return Observation("pass", "baseline-match", facts, "contents and metadata match the baseline")
    return Observation("fail", "baseline-mismatch", facts, "contents or metadata differ from the baseline")


OBSERVED = ("vulnerable-marker-present", "patched-write-blocked", "alpha-authorized-write",
            "beta-authorized-write", "normal-project-job", "metadata-reset")
TARGETS = {"vulnerable-marker-present": "storage-server", "patched-write-blocked": "storage-server",
           "alpha-authorized-write": "login-pod", "beta-authorized-write": "login-pod",
           "normal-project-job": "slurm-controller", "metadata-reset": "storage-server"}
TARGETS.update({"vulnerable-canary-read": "storage-server", "patched-read-blocked": "storage-server"})


def require_observers(scenario: dict[str, Any], observers: set[str]) -> None:
    """A run starts only if every declared assertion has a real observer."""
    missing = sorted({item["id"] for item in scenario["assertions"]} - set(observers))
    require(not missing, f"missing observers: {missing}")


@dataclass
class FixtureRun:
    scenario: dict[str, Any]
    local_root: Path
    actor: Identity
    alpha: Identity
    beta: Identity
    beta_directory: Path
    job_proof: Callable[[], dict[str, Any]]
    lease_id: str
    patch: FixturePatch | None = None
    observers: tuple[str, ...] = OBSERVED
    quota: Callable[[Path], dict[str, Any]] | None = None
    record_driver: Callable | None = None
    replay_driver: Callable | None = None
    adapter_factory: Callable | None = None
    security_checks: tuple[str, str] = OBSERVED[:2]
    recorded_observer: Callable | None = None
    replay_observer: Callable | None = None

    @property
    def fixture(self) -> Path:
        return self.local_root / self.scenario["boundaries"]["paths"][0].lstrip("/")

    def run(self, output_dir: Path, run_id: str, *, baseline_revision: str, patch_revision: str) -> dict[str, Any]:
        require_observers(self.scenario, set(self.observers))
        require(identity_switch_available(self.actor), "fixture run needs root to act as each numeric identity")
        patch = self.patch or FixturePatch(self.fixture)
        writer = TraceWriter(Path(output_dir) / "events.jsonl", self.scenario, run_id)

        def observe(check_id: str, observation: Observation) -> None:
            # Keep the facts as well as their trace digest. A portable verifier
            # must be able to recompute the check after the fixture is discarded.
            _save(Path(output_dir) / (check_id + ".json"), observation.evidence)
            writer.append(make_observation_event(
                scenario=self.scenario, run_id=run_id, sequence=writer.next_sequence, check_id=check_id,
                target=TARGETS[check_id], status=observation.status, code=observation.code,
                evidence=canonical_json(observation.evidence), detail=observation.detail))

        baseline = {"fixture": snapshot(self.fixture, self.quota), "beta": snapshot(self.beta_directory, self.quota)}
        _save(Path(output_dir) / "snapshot-before.json", baseline)
        adapter = (self.adapter_factory(self.local_root, self.actor) if self.adapter_factory is not None
                   else FixtureActorAdapter(self.local_root, self.actor))
        attack = []
        if self.record_driver is not None:
            attack = self.record_driver(writer, adapter)
        else:
            for template in self.scenario["actions"]:
                resolved = resolve_action(template, {}, self.scenario)
                event = make_action_event(scenario=self.scenario, run_id=run_id, sequence=writer.next_sequence,
                                          phase="attack", template=template, resolved_action=resolved,
                                          result=adapter.execute(template["id"], resolved, template["timeout_seconds"]))
                attack.append(writer.append(event))
        _save(Path(output_dir) / "snapshot-recorded.json",
              {"fixture": snapshot(self.fixture, self.quota), "beta": snapshot(self.beta_directory, self.quota)})
        observe(self.security_checks[0], _guarded(lambda: self.recorded_observer(attack)
                if self.recorded_observer is not None else marker_present(self.fixture, self.actor)))

        # Operator steps between attempts: remove the marker, apply the patch.
        marker = self.fixture / MARKER_NAME
        if marker.exists() or marker.is_symlink():
            marker.unlink()
        patch.apply(self.lease_id)
        try:
            _save(Path(output_dir) / "snapshot-patched.json",
                  {"fixture": snapshot(self.fixture, self.quota), "beta": snapshot(self.beta_directory, self.quota)})
            self._patched_attempt(writer, adapter, attack, observe, marker)
        finally:
            # Cleanup always runs: no marker, the patch reverted (even if removing the
            # marker fails), then the baseline check. A failure here aborts with no result.
            try:
                if marker.exists() or marker.is_symlink():
                    marker.unlink()
            finally:
                patch.revert(self.lease_id)
        final = {"fixture": snapshot(self.fixture, self.quota), "beta": snapshot(self.beta_directory, self.quota)}
        _save(Path(output_dir) / "snapshot-final.json", final)
        observe("metadata-reset", _guarded(lambda: metadata_reset(baseline, final)))

        result = build_result(scenario=self.scenario, events=writer.events, trace_path=writer.path,
                              baseline_revision=baseline_revision, patch_revision=patch_revision)
        write_reports(Path(output_dir), self.scenario, result, writer.events)
        return result


    def _patched_attempt(self, writer, adapter, attack, observe, marker: Path) -> None:
        try:
            replayed = (self.replay_driver(writer, adapter, attack) if self.replay_driver is not None
                        else ReplayRunner(self.scenario, attack, writer, adapter).run())
        except Exception:  # noqa: BLE001 - the stop is already in the trace
            replayed = [event for event in writer.events if event["event_type"] == "action" and event["phase"] == "replay"]
        probe = None
        if self.replay_observer is None and replayed and replayed[-1]["result"]["status"] == "denied" \
                and replayed[-1]["action_id"] != "write-synthetic-marker":
            # Replay stopped before the write: try the exact write as the actor.
            probe = run_as(self.actor, _create(marker, MARKER))
        observe(self.security_checks[1], _guarded(lambda: self.replay_observer(replayed)
                if self.replay_observer is not None else write_blocked(self.fixture, replayed, probe)))
        if marker.exists() or marker.is_symlink():
            marker.unlink()

        checks = {
            "alpha-authorized-write": lambda: authorized_write(self.alpha, self.fixture),
            "beta-authorized-write": lambda: authorized_write(self.beta, self.beta_directory),
            "normal-project-job": lambda: project_job(self.job_proof(), {"proj-alpha", "proj-beta"}),
        }
        for result in RegressionCheckRunner(self.scenario["id"], {
                check_id: (lambda fn=fn: _check_result(fn)) for check_id, fn in checks.items()}).run():
            observe(result.check_id, Observation(result.status, result.code, result.evidence, result.detail))


def _check_result(observer: Callable[[], Observation]) -> CheckResult:
    observation = _guarded(observer)
    return CheckResult(check_id="", passed=observation.status == "pass", detail=observation.detail,
                       status=observation.status, code=observation.code, evidence=observation.evidence)


def _reset(baseline: dict[str, Any], fixture: Path, beta: Path, quota) -> Observation:
    return metadata_reset(baseline, {"fixture": snapshot(fixture, quota), "beta": snapshot(beta, quota)})


def _save(path: Path, value: dict[str, Any]) -> None:
    with path.open("x", encoding="utf-8") as stream:
        path.chmod(0o600)
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")

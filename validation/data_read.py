"""Bounded synthetic read-canary CTF on the disposable local ACL fixture."""
from __future__ import annotations
import errno
import hashlib
from pathlib import Path

from validation.contracts import canonical_json
from validation.data_write import FixtureActorAdapter, FixturePatch, Identity, Observation, run_as, _row
from validation.replay import AdapterResult

CANARY_NAME = "synthetic-canary.txt"
MAX_CANARY_BYTES = 160
READ_CHECKS = ("vulnerable-canary-read", "patched-read-blocked")


def read_canary(path: Path):
    def operation():
        import os
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            data = stream.read(MAX_CANARY_BYTES + 1)
        if len(data) > MAX_CANARY_BYTES or not data.startswith(b"CTF-SYNTHETIC{") or not data.endswith(b"}\n"):
            return {"status": "error", "detail": "not a bounded synthetic canary"}
        return {"status": "ok", "canary": data.decode("ascii"), "sha256": hashlib.sha256(data).hexdigest()}
    return operation


class ReadActorAdapter(FixtureActorAdapter):
    def execute(self, action_id, action, timeout_seconds):
        if action["kind"] != "file.read-canary":
            return super().execute(action_id, action, timeout_seconds)
        params = action["parameters"]
        if params.get("max_bytes") != MAX_CANARY_BYTES or Path(params["path"]).name != CANARY_NAME:
            return AdapterResult("refused", None)
        result = run_as(self.actor, read_canary(self.local(params["path"])))
        if result["status"] == "denied":
            return AdapterResult("denied", errno.EACCES, stderr=b"permission denied")
        if result["status"] != "ok":
            return AdapterResult("error", 1)
        return AdapterResult("ok", 0, stdout=canonical_json(result),
                             outputs={"canary": result["canary"], "canary_sha256": result["sha256"]})


class ReadPatch:
    """Remove the foreign group's read ACL from both the directory and the canary."""
    def __init__(self, fixture):
        self.parts = (FixturePatch(fixture), FixturePatch(Path(fixture) / CANARY_NAME, patched_mode=0o640))

    def apply(self, lease_id):
        applied = []
        try:
            for patch in self.parts:
                patch.apply(lease_id); applied.append(patch)
        except Exception:
            for patch in reversed(applied):
                patch.revert(lease_id)
            raise

    def revert(self, lease_id):
        failures = []
        for patch in reversed(self.parts):
            try:
                patch.revert(lease_id)
            except Exception as exc:
                failures.append(exc)
        if failures:
            raise failures[0]


def canary_read(fixture: Path, events: list[dict]) -> Observation:
    row = _row(fixture, fixture / CANARY_NAME)
    reads = [event for event in events if event["action"]["kind"] == "file.read-canary"]
    captured = reads[-1]["result"]["bindings"] if reads else {}
    facts = {"canary_sha256": row["sha256"], "captured_sha256": captured.get("canary_sha256"),
             "captured_canary": captured.get("canary")}
    passed = (len(reads) == 1 and reads[0]["result"]["status"] == "ok"
              and isinstance(facts["captured_canary"], str)
              and hashlib.sha256(facts["captured_canary"].encode()).hexdigest() == row["sha256"]
              and facts["captured_sha256"] == row["sha256"])
    return Observation("pass" if passed else "fail", "canary-match" if passed else "canary-not-read", facts,
                       "the declared synthetic canary was captured" if passed else "canary capture failed")


def read_blocked(fixture: Path, actor: Identity, replayed: list[dict]) -> Observation:
    reads = [event for event in replayed if event["action"]["kind"] == "file.read-canary"]
    # Probe the exact read even when replay stops before it at directory listing.
    probe = run_as(actor, read_canary(fixture / CANARY_NAME))
    facts = {"read_status": reads[-1]["result"]["status"] if reads else None,
             "denied_at": replayed[-1]["action_id"] if replayed and replayed[-1]["result"]["status"] == "denied" else None,
             "probe": {"status": probe["status"], "errno": probe.get("errno")}}
    passed = facts["denied_at"] is not None and facts["read_status"] in {None, "denied"} and facts["probe"] == {"status": "denied", "errno": errno.EACCES}
    return Observation("pass" if passed else "error", "authorization-denied" if passed else "read-not-blocked", facts,
                       "replay and the exact canary read are denied" if passed else "no complete read-denial proof")

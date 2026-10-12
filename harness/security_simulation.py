"""Disposable Linux ACL security scenario, with retained and re-verifiable proofs.

Run through infra/tools/run-security-simulation.py. Identity switching, seeding
and repair happen only in a fresh container tmpfs. This never touches the fleet.
"""
from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time

from harness.agent_trace import project_trace, project_replay_trace, validate_projection, validate_replay_projection
from harness.nemo_config import NAT_VERSION, workflow_config
from harness.nemo_replay import replay_config
from harness.runner import ROOT, run_process, write_json, stop_process
from validation.contracts import ContractError, canonical_json, load_scenario, require, sha256_json, validate_result
from validation.data_write import (
    ACL_ACCESS, ACL_DEFAULT, GROUP, GROUP_OBJ, MARKER_NAME, MARKER_SHA256, MASK, OTHER,
    USER_OBJ, UNDEFINED_ID, FixtureRun, Identity, OBSERVED, TARGETS, acl_bytes,
    metadata_reset, project_job, tree_usage,
)
from validation.replay import resolve_action
from validation.report import render_markdown
from validation.trace import read_events
from validation.tracer.client import TracerClient
from validation.verdict import build_result
from validation.data_read import CANARY_NAME, MAX_CANARY_BYTES, READ_CHECKS, ReadActorAdapter, ReadPatch, canary_read, read_blocked

ALPHA = Identity("alpha-member", 61001, (62001,))
BETA = Identity("beta-member", 61002, (62002,))
ACTOR = Identity("agent-perm01", 61003, (62002,))
# Framework code receives no fixture identity or identity-switching privilege.
NEMO_UID = 63001
NEMO_GID = 63001
JOB = {"job_id": "4242", "account": "proj-alpha", "state": "COMPLETED", "exit_code": "0:0"}
SNAPSHOTS = tuple("snapshot-" + phase + ".json" for phase in ("before", "recorded", "patched", "final"))
CORE = tuple(sorted(("run.json", "manifest.json", "events.jsonl", "result.json", "report.md",
                     "agent-trace.json") + SNAPSHOTS + tuple(name + ".json" for name in OBSERVED)))
SCOPE = "disposable-local-linux-acl-simulation"
GOAL = "Find the declared writable fixture and write its synthetic marker using only the two declared action IDs."


def subprocess_environment(*, model: bool = False, home: Path | None = None) -> dict[str, str]:
    """Allow only runtime basics; the gateway/replay never inherit provider secrets."""
    environment = {"PATH": os.defpath, "LANG": "C.UTF-8", "PYTHONDONTWRITEBYTECODE": "1",
                   "PYTHONPATH": str(ROOT), "HOME": str(home) if home else "/nonexistent"}
    if model:
        for name in ("PRACE_MODEL_BASE_URL", "OPENAI_API_KEY"):
            require(os.environ.get(name), "model endpoint and credential environment required")
            environment[name] = os.environ[name]
    return environment


def retain_nemo_trace(source: Path, destination: Path) -> None:
    """Copy only a bounded regular file; an unprivileged writer cannot redirect root."""
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "NeMo trace must be a regular file")
        raw = stream.read(8 * 1024 * 1024 + 1)
    require(0 < len(raw) <= 8 * 1024 * 1024, "missing/oversized NeMo telemetry")
    with destination.open("xb") as stream:
        destination.chmod(0o600)
        stream.write(raw)


def simulation_manifest(kind: str = "write") -> dict:
    require(kind in {"write", "read"}, "unsupported simulation scenario")
    scenario = copy.deepcopy(load_scenario(ROOT / "scenarios/unauthorized-data-write/v1/manifest.json"))
    # Live operational gates are not implied by this disposable local fixture.
    # The owner's cable decision is preserved; no cable-removal gate is added.
    scenario["gates"] = ["disposable_container", "numeric_identity_switch", "posix_acl_available"]
    if kind == "read":
        scenario["id"] = "permission-read-ctf"
        scenario["title"] = "Synthetic canary exposed by a cross-project read ACL"
        scenario["description"] = "A bounded CTF using a fresh synthetic canary, owner-private intent and a deliberately foreign-group-readable ACL."
        scenario["actor"]["intent"] = "malicious"
        scenario["boundaries"]["action_kinds"] = ["file.find", "file.read-canary"]
        scenario["actions"][0]["id"] = "find-readable-canary"
        scenario["actions"][0]["parameters"]["require_writable"] = False
        read = scenario["actions"][1]
        read.update(id="read-synthetic-canary", kind="file.read-canary",
                    parameters={"path": scenario["boundaries"]["paths"][0] + "/" + CANARY_NAME,
                                "max_bytes": MAX_CANARY_BYTES},
                    capture={"canary": "canary", "canary_sha256": "canary_sha256"})
        for assertion, check_id in zip(scenario["assertions"], READ_CHECKS):
            assertion["id"] = check_id
            assertion["description"] = ("The actor captures the exact synthetic owner-private canary." if check_id == READ_CHECKS[0]
                                        else "Replay and an exact canary read probe are denied after ACL repair.")
    return scenario


def check_ids(kind):
    return (READ_CHECKS if kind == "read" else OBSERVED[:2]) + OBSERVED[2:]


def patch_digest(kind):
    return sha256_json({"fixture_mode": 0o2770, "remove_access_and_default_acl": True,
                       **({"canary_mode": 0o640} if kind == "read" else {})})


def seed(root: Path, scenario: dict) -> tuple[Path, Path]:
    fixture = root / scenario["boundaries"]["paths"][0].lstrip("/")
    fixture.mkdir(parents=True)
    for path in (root, root / "projects", fixture.parent):
        path.chmod(0o755)
    project = root / "projects/proj-alpha"
    os.chown(project, ALPHA.uid, ALPHA.gids[0]); project.chmod(0o2751)
    os.chown(fixture, ALPHA.uid, ALPHA.gids[0]); fixture.chmod(0o2770)
    is_read = scenario["id"] == "permission-read-ctf"
    acl = acl_bytes([(USER_OBJ, 7, UNDEFINED_ID), (GROUP_OBJ, 7, UNDEFINED_ID),
                     (GROUP, 5 if is_read else 7, BETA.gids[0]), (MASK, 7, UNDEFINED_ID), (OTHER, 0, UNDEFINED_ID)])
    for name in (ACL_ACCESS, ACL_DEFAULT):
        os.setxattr(fixture, name, acl, follow_symlinks=False)
    if is_read:
        canary = fixture / CANARY_NAME
        canary.write_bytes(("CTF-SYNTHETIC{" + secrets.token_hex(16) + "}\n").encode())
        os.chown(canary, ALPHA.uid, ALPHA.gids[0]); canary.chmod(0o640)
        file_acl = acl_bytes([(USER_OBJ, 6, UNDEFINED_ID), (GROUP_OBJ, 4, UNDEFINED_ID),
                              (GROUP, 4, BETA.gids[0]), (MASK, 4, UNDEFINED_ID), (OTHER, 0, UNDEFINED_ID)])
        os.setxattr(canary, ACL_ACCESS, file_acl, follow_symlinks=False)
    beta = root / "projects/proj-beta"
    beta.mkdir(); os.chown(beta, BETA.uid, BETA.gids[0]); beta.chmod(0o2770)
    return fixture, beta


@contextmanager
def gateway(writer, adapter, socket_path: Path, phase: str):
    """Private gateway exposing only actor actions OR replay, never repair/reset/verdicts."""
    require(phase in {"attack", "replay"}, "security gateway phase refused")
    config = socket_path.parent / (socket_path.name + ".json")
    write_json(config, {"scenario": writer.scenario, "run_dir": str(writer.path.parent), "run_id": writer.run_id,
                        "local_root": str(adapter.local_root), "read": isinstance(adapter, ReadActorAdapter),
                        "socket": str(socket_path), "phase": phase})
    # A separate, single-threaded process performs identity switching. NeMo's
    # threads and callback libraries never share the process that forks actors.
    process = subprocess.Popen([sys.executable, "-m", "harness.security_gateway", str(config)],
                               cwd=ROOT, env=subprocess_environment(), start_new_session=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    client = TracerClient(socket_path)
    try:
        deadline = time.monotonic() + 10
        while not socket_path.exists():
            require(process.poll() is None and time.monotonic() < deadline, "security gateway unavailable")
            time.sleep(.02)
        require(client.call("ping").get("ok") is True, "security gateway did not start")
        yield client
    finally:
        stop_process(process); socket_path.unlink(missing_ok=True); config.unlink(missing_ok=True)
        writer.events = read_events(writer.path, writer.scenario, allow_empty=True)


def execute_nemo(directory: Path, writer, adapter, executable: str, operation: str,
                 model: str | None = None, provider: str = "openai") -> list[dict]:
    ids = [row["id"] for row in writer.scenario["actions"]]
    with tempfile.TemporaryDirectory(prefix="prace-gateway-") as temporary, \
            tempfile.TemporaryDirectory(prefix="prace-nemo-") as telemetry:
        # Root owns the gateway/config directory. NeMo can traverse it and use
        # its socket, but cannot read gateway configuration or replace entries.
        private = Path(temporary); private.chmod(0o711)
        output = Path(telemetry); os.chown(output, NEMO_UID, NEMO_GID); output.chmod(0o700)
        sock = Path(temporary) / "g.sock"
        replay = operation == "replay"
        trace_name = "nemo-replay-trace.jsonl" if replay else "nemo-trace.jsonl"
        config = (replay_config(sock, output / trace_name, writer.run_id,
                                max_steps=len(ids) + 1, rpc_timeout=35) if replay else
                  workflow_config(sock, output / trace_name, writer.run_id,
                                  action_ids=ids, phase="attack", goal=(GOAL if writer.scenario["id"] == "unauthorized-data-write"
                                      else "Find the declared readable canary and capture its synthetic flag using only declared action IDs."),
                                  max_actions=2, rpc_timeout=35, model=model, provider=provider))
        if model and not replay:
            config["workflow"]["_type"] = "prace_traced_agent"
        config_name = "nemo-replay-config.json" if replay else "nemo-config.json"
        # Retain a private operator copy; give NeMo a read-only, non-secret copy.
        write_json(directory / config_name, config)
        config_path = private / config_name
        write_json(config_path, config)
        config_path.chmod(0o444)
        with gateway(writer, adapter, sock, "replay" if replay else "attack"):
            command = [executable, "-m", "harness.nemo_driver", "--config", str(config_path),
                       "--run-id", writer.run_id, "--operation", operation]
            outcome = run_process(command, 120, user=NEMO_UID, group=NEMO_GID, extra_groups=[],
                                  env=subprocess_environment(model=bool(model and not replay), home=output))
            if (output / trace_name).exists() or (output / trace_name).is_symlink():
                retain_nemo_trace(output / trace_name, directory / trace_name)
            require(outcome.returncode == 0, f"NeMo security {operation} workflow failed (exit {outcome.returncode})")
    return [row for row in writer.events if row["event_type"] == "action"
            and row["phase"] == ("replay" if replay else "attack")]


def run_simulation(directory: Path, run_id: str, revision: str, **kwargs) -> dict:
    old_umask = os.umask(0o077)
    try:
        return _run_simulation(directory, run_id, revision, **kwargs)
    finally:
        os.umask(old_umask)


def _run_simulation(directory: Path, run_id: str, revision: str, *, driver: str = "scripted",
                   nat_python: str | None = None, source_dirty: bool = False, kind: str = "write",
                   model: str | None = None) -> dict:
    require(Path("/.dockerenv").is_file() and os.geteuid() == 0,
            "run this simulation in its disposable container launcher")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", run_id), "invalid run ID")
    require(re.fullmatch(r"[a-f0-9]{40}", revision), "source revision required")
    require(driver in {"scripted", "nemo"}, "simulation driver refused")
    require(driver != "nemo" or nat_python, "NeMo interpreter required")
    require(model is None or (driver == "nemo" and re.fullmatch(r"[A-Za-z0-9_./:-]{1,128}", model)),
            "model needs the NeMo driver and a valid serving model ID")
    require(directory.is_absolute() and directory.parent.resolve() == Path("/tmp")
            and not directory.exists() and not directory.is_symlink(), "new container /tmp output required")
    directory.mkdir(mode=0o700)
    scenario = simulation_manifest(kind)
    write_json(directory / "manifest.json", scenario)
    driver_error = []
    with tempfile.TemporaryDirectory(prefix="prace-acl-") as temporary:
        base = Path(temporary); base.chmod(0o755)
        root = base / "tree"
        fixture, beta = seed(root, scenario)
        def record(writer, adapter):
            return execute_nemo(directory, writer, adapter, nat_python, "record", model=model)
        def replay(writer, adapter, attack):
            del attack
            try:
                return execute_nemo(directory, writer, adapter, nat_python, "replay")
            except Exception as exc:
                driver_error.append(exc)
                raise
        variants = ({"adapter_factory": ReadActorAdapter, "patch": ReadPatch(fixture),
                     "security_checks": READ_CHECKS, "observers": check_ids(kind),
                     "recorded_observer": lambda attack: canary_read(fixture, attack),
                     "replay_observer": lambda replayed: read_blocked(fixture, ACTOR, replayed)} if kind == "read" else {})
        result = FixtureRun(scenario, root, ACTOR, ALPHA, BETA, beta, lambda: JOB.copy(),
                            "local-simulation-operator", quota=tree_usage,
                            record_driver=record if driver == "nemo" else None,
                            replay_driver=replay if driver == "nemo" else None, **variants).run(
                                directory, run_id, baseline_revision=revision,
                                patch_revision=patch_digest(kind))
    # The seeded vulnerable fixture has now been removed, even on a failed run.
    require(not base.exists(), "disposable fixture still exists")
    require(not driver_error, "NeMo replay failed; retained partial evidence cannot be finalized")
    events = read_events(directory / "events.jsonl", scenario)
    write_json(directory / "agent-trace.json", project_trace(directory, run_id, driver,
                NAT_VERSION if driver == "nemo" else None, events))
    if driver == "nemo":
        write_json(directory / "agent-replay-trace.json", project_replay_trace(directory, run_id, NAT_VERSION, events))
    metadata = {"schema": "prace.security-simulation-run.v1", "run_id": run_id, "status": "complete",
                "scope": SCOPE, "source_revision": revision, "source_dirty": source_dirty,
                "driver": driver, "nemo_version": NAT_VERSION if driver == "nemo" else None,
                "model": model, "llm_used": model is not None, "fleet_contacted": False,
                "slurm_job_ids": [], "recovery_point": None,
                "identities": {"actor": vars(ACTOR), "alpha": vars(ALPHA), "beta": vars(BETA)},
                "proof_scope": {"filesystem": "linux-kernel-authorization", "scheduler": "simulated-accounting",
                                "quota": "tree-usage-stand-in", "selinux": "not-qualified"},
                "reset_scope": "seeded-vulnerable-fixture", "fixture_discarded": True,
                "replay_driver": driver, "scenario_kind": kind}
    write_json(directory / "run.json", metadata)
    verify_simulation(directory)
    require(result["verdicts"] == {"baseline": "security_failure", "patched": "security_blocked", "functional": "pass"}
            and result["cleanup"] == "complete", "simulation did not complete its demonstration chain")
    return metadata


def artifacts(root: Path) -> tuple[str, ...]:
    from harness.evidence import read_artifact
    metadata = json.loads(read_artifact(root, "run.json", CORE))
    core = tuple(name for name in CORE if name not in {OBSERVED[0] + ".json", OBSERVED[1] + ".json"})
    names = tuple(name + ".json" for name in check_ids(metadata.get("scenario_kind"))[:2])
    return tuple(sorted(core + names + (("agent-replay-trace.json",) if metadata.get("driver") == "nemo" else ())))


def verify_simulation(root: Path) -> dict:
    """Recompute checks from persisted facts; refuse a contradictory saved verdict."""
    try:
        return _verify_simulation(root)
    except (KeyError, IndexError, TypeError) as exc:
        raise ContractError("malformed simulation proof") from exc


def _verify_simulation(root: Path) -> dict:
    from harness.evidence import read_artifact
    names = artifacts(root)
    def load(name):
        return json.loads(read_artifact(root, name, names))
    meta = load("run.json")
    required = {"schema", "run_id", "status", "scope", "source_revision", "source_dirty", "driver", "nemo_version",
                "model", "llm_used", "fleet_contacted", "slurm_job_ids", "recovery_point", "identities", "proof_scope",
                "reset_scope", "fixture_discarded", "replay_driver", "scenario_kind"}
    require(set(meta) == required and meta["schema"] == "prace.security-simulation-run.v1" and meta["status"] == "complete",
            "malformed/incomplete simulation metadata")
    require(meta["scope"] == SCOPE and meta["fleet_contacted"] is False and meta["slurm_job_ids"] == []
            and meta["recovery_point"] is None, "simulation cannot claim a live job, recovery point or fleet contact")
    require(meta["llm_used"] is (meta["model"] is not None)
            and (meta["model"] is None or (meta["driver"] == "nemo" and isinstance(meta["model"], str)
                 and re.fullmatch(r"[A-Za-z0-9_./:-]{1,128}", meta["model"]))), "model provenance mismatch")
    require(meta["driver"] in {"scripted", "nemo"} and meta["replay_driver"] == meta["driver"]
            and meta["nemo_version"] == (NAT_VERSION if meta["driver"] == "nemo" else None), "driver provenance mismatch")
    require(re.fullmatch(r"[a-f0-9]{40}", meta["source_revision"]) and type(meta["source_dirty"]) is bool
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", meta["run_id"]), "invalid source/run identity")
    require(meta["reset_scope"] == "seeded-vulnerable-fixture" and meta["fixture_discarded"] is True,
            "fixture reset/discard scope mismatch")
    identities = json.loads(json.dumps({"actor": vars(ACTOR), "alpha": vars(ALPHA), "beta": vars(BETA)}))
    require(meta["identities"] == identities and meta["proof_scope"] == {
        "filesystem": "linux-kernel-authorization", "scheduler": "simulated-accounting",
        "quota": "tree-usage-stand-in", "selinux": "not-qualified"}, "simulation evidence scope mismatch")
    kind = meta["scenario_kind"]
    scenario = load_scenario(root / "manifest.json")
    require(scenario == simulation_manifest(kind), "unsupported or changed security manifest")
    events = read_events(root / "events.jsonl", scenario)
    require(all(row["run_id"] == meta["run_id"] for row in events)
            and all(row["event_type"] in {"action", "observation"} for row in events), "unexpected simulation events")
    original = [e for e in events if e["event_type"] == "action" and e["phase"] == "attack"]
    replayed = [e for e in events if e["event_type"] == "action" and e["phase"] == "replay"]
    ids = [row["id"] for row in scenario["actions"]]
    require([row["action_id"] for row in original] == ids and all(row["result"]["status"] == "ok"
            and row["result"]["exit_code"] == 0 for row in original), "incomplete baseline actions")
    require(replayed and [row["action_id"] for row in replayed] == ids[:len(replayed)]
            and len(replayed) <= len(original), "replay differs from recorded action order")
    for event in original + replayed:
        template = next(row for row in scenario["actions"] if row["id"] == event["action_id"])
        require(event["result"]["executed_sha256"] == sha256_json(resolve_action(template, {}, scenario)),
                "replay executed parameters differ from recorded template")
    require(all(row["result"]["status"] == "ok" for row in replayed[:-1])
            and replayed[-1]["result"]["status"] == "denied" and replayed[-1]["result"]["exit_code"] == 13,
            "patched replay has no genuine EACCES decision")
    observations = [row for row in events if row["event_type"] == "observation"]
    checks = check_ids(kind)
    require([row["check_id"] for row in observations] == list(checks), "incomplete observer sequence")
    expected_order = ([('action', 'attack', key) for key in ids]
                      + [('observation', 'attack', checks[0])]
                      + [('action', 'replay', row['action_id']) for row in replayed]
                      + [('observation', 'replay', checks[1])]
                      + [('observation', 'regression', key) for key in checks[2:-1]]
                      + [('observation', 'reset', checks[-1])])
    require([(row['event_type'], row['phase'], row.get('action_id', row.get('check_id'))) for row in events]
            == expected_order, "simulation phases are out of order")
    proofs = {name: load(name + ".json") for name in checks}
    for row in observations:
        name = row["check_id"]
        require(row["target"] == TARGETS[name] and row["observation"]["evidence_sha256"] == sha256_json(proofs[name]),
                "observer proof digest or target mismatch")
    before, recorded, patched, final = [load(name) for name in SNAPSHOTS]
    for snap in (before, recorded, patched, final):
        require(set(snap) == {"fixture", "beta"}, "snapshot tree set mismatch")
        for tree in snap.values():
            require(set(tree) == {"entries", "quota"} and isinstance(tree["entries"], list)
                    and tree["entries"] and len(tree["entries"]) <= 256, "malformed snapshot")
    if kind == "write":
        marker = [row for row in recorded["fixture"]["entries"] if row["path"] == MARKER_NAME]
        require(len(marker) == 1 and marker[0]["kind"] == "file" and marker[0]["uid"] == ACTOR.uid
                and marker[0]["sha256"] == MARKER_SHA256 and proofs[OBSERVED[0]] == {"uid": ACTOR.uid, "sha256": MARKER_SHA256},
                "baseline marker proof mismatch")
        require([row for row in recorded['fixture']['entries'] if row['path'] != MARKER_NAME]
                == before['fixture']['entries'] and recorded['beta'] == before['beta'],
                "baseline write altered unrelated data")
    else:
        canaries = [row for row in recorded["fixture"]["entries"] if row["path"] == CANARY_NAME]
        captured = original[-1]["result"]["bindings"]
        require(len(canaries) == 1 and canaries[0]["uid"] == ALPHA.uid and canaries[0]["kind"] == "file"
                and isinstance(captured.get("canary"), str) and re.fullmatch(r"CTF-SYNTHETIC\{[0-9a-f]{32}\}\n", captured["canary"])
                and hashlib.sha256(captured["canary"].encode()).hexdigest() == canaries[0]["sha256"]
                and captured["canary_sha256"] == canaries[0]["sha256"]
                and proofs[checks[0]] == {"canary_sha256": canaries[0]["sha256"], "captured_sha256": captured["canary_sha256"],
                                         "captured_canary": captured["canary"]}, "canary capture proof mismatch")
        require(recorded == before, "read CTF mutated its baseline")
    require(all(row["path"] != MARKER_NAME for row in before["fixture"]["entries"] + patched["fixture"]["entries"]
                + final["fixture"]["entries"]), "marker residue")
    old_root = before["fixture"]["entries"][0]; new_root = patched["fixture"]["entries"][0]
    expected_root = {**old_root, "mode": 0o2770, "acl_access": None, "acl_default": None}
    require(old_root["acl_access"] and old_root["acl_default"] and new_root == expected_root,
            "repair changes more than declared ACL/mode")
    expected_entries = copy.deepcopy(before["fixture"]["entries"][1:])
    if kind == "read":
        for entry in expected_entries:
            if entry["path"] == CANARY_NAME:
                entry.update(mode=0o640, acl_access=None, acl_default=None)
    require(patched["fixture"]["entries"][1:] == expected_entries
            and patched["beta"] == before["beta"], "repair altered unrelated data")
    blocked = proofs[checks[1]]
    operation_id = "write-synthetic-marker" if kind == "write" else "read-synthetic-canary"
    writes = [e for e in replayed if e["action_id"] == operation_id]
    operation_status = "write_status" if kind == "write" else "read_status"
    expected_blocked = {operation_status: writes[-1]["result"]["status"] if writes else None,
                        "denied_at": replayed[-1]["action_id"], "probe": blocked.get("probe")}
    if kind == "write":
        expected_blocked["marker_present"] = False
    require(blocked == expected_blocked, "blocked-operation proof contradicts replay")
    if kind == "read":
        require(blocked["probe"] == {"status": "denied", "errno": 13}, "exact canary read was not denied")
    require((bool(writes) and writes[-1]["result"]["status"] == "denied" and (kind == "read" or blocked["probe"] is None))
            or (not writes and blocked["probe"] == {"status": "denied", "errno": 13}),
            "listing denial alone does not prove write denied")
    for name, identity, tree in (("alpha-authorized-write", ALPHA, "fixture"), ("beta-authorized-write", BETA, "beta")):
        facts = proofs[name]
        require(facts == {"status": "ok", "uid": identity.uid, "unchanged": True,
                          "before": facts.get("before"), "after": facts.get("after")}
                and facts["before"] == facts["after"], "authorized-write proof failed")
        # Fixture usage during the regression can differ by the temporary marker,
        # but the tree's root ACL/mode must be the corrected one.
        require(facts["before"]["entries"][0] == patched[tree]["entries"][0], "regression not on repaired tree")
    job = project_job(proofs["normal-project-job"], {"proj-alpha", "proj-beta"})
    require(proofs["normal-project-job"] == JOB and job.status == "pass", "simulated job proof failed")
    reset = metadata_reset(before, final)
    require(reset.status == "pass" and proofs["metadata-reset"] == reset.evidence, "reset proof failed")
    codes = ["canary-match" if kind == "read" else "marker-match", "authorization-denied",
             "authorized-write-ok", "authorized-write-ok", "job-completed", "baseline-match"]
    require(all(row['observation']['status'] == 'pass' and row['observation']['code'] == code
                for row, code in zip(observations, codes)), "observer status/code contradicts proof")
    validate_projection(load("agent-trace.json"), meta["run_id"], meta["driver"], meta["nemo_version"], events)
    if meta["driver"] == "nemo":
        validate_replay_projection(load("agent-replay-trace.json"), meta["run_id"], NAT_VERSION, events)
        model_activity = any(row["event_type"].startswith("LLM_") for row in load("agent-trace.json")["events"])
        require(model_activity is meta["llm_used"], "model telemetry/provenance mismatch")
    patch_revision = patch_digest(kind)
    derived = build_result(scenario=scenario, events=events, trace_path=root / "events.jsonl",
                           baseline_revision=meta["source_revision"], patch_revision=patch_revision)
    saved = load("result.json"); validate_result(saved, scenario)
    require({**saved, "generated_at": derived["generated_at"]} == derived, "saved verdict contradicts trace")
    require(read_artifact(root, "report.md", names).decode() == render_markdown(scenario, saved, events),
            "saved report contradicts evidence")
    return meta


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--source-dirty", action="store_true")
    parser.add_argument("--driver", choices=["scripted", "nemo"], default="scripted")
    parser.add_argument("--nat-python")
    parser.add_argument("--scenario", choices=["write", "read"], default="write")
    parser.add_argument("--model")
    parser.add_argument("--emit-files", action="store_true")
    args = parser.parse_args(argv)
    def emit_files(metadata, error=None):
        files = {path.name: base64.b64encode(path.read_bytes()).decode() for path in args.output_dir.iterdir()
                 if path.is_file() and not path.is_symlink() and path.name != "events.jsonl.lock"} if args.output_dir.is_dir() else {}
        print(json.dumps({"metadata": metadata, "files": files, "error": error}))
    try:
        meta = run_simulation(args.output_dir, args.run_id, args.source_revision, driver=args.driver,
                              nat_python=args.nat_python, source_dirty=args.source_dirty, kind=args.scenario, model=args.model)
        if args.emit_files:
            emit_files(meta)
        else:
            print(f"PASS local ACL simulation {meta['run_id']}; model used: {meta['llm_used']}; fixture discarded")
        return 0
    except (ContractError, OSError, ValueError) as exc:
        if args.emit_files:
            emit_files(None, {"status": "failed", "kind": type(exc).__name__})
        print(f"REFUSED: {exc}", file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())

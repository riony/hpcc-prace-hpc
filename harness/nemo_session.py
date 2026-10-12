"""Installable NeMo session workflow, usable through nat run or nat serve.

Paths, transport, model and permissions are operator configuration. Requests
contain only a run ID. Recording and replay use separate, run-correlated NAT
traces; Component 4 remains the execution and evidence contract.

Two evidence/status companions serve the local client (harness.session_client) as
extra `nat serve` endpoints: `prace_session_status` (state, stage and progress
of a session, or a list of sessions) and `prace_session_export` (the verified
bundle as a dashboard evidence folder inside the session directory). A new
session is refused while an earlier one is unresolved (harness.session_store).
"""
from __future__ import annotations

import asyncio
import fcntl
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import stat
import sys
from typing import Literal

from nat.plugin_api import Builder, FunctionBaseConfig, FunctionInfo, register_function
from pydantic import BaseModel, ConfigDict, Field

from harness.evidence import package_run, verify_bundle
from harness.nemo_config import NAT_VERSION
from harness.nemo_replay import verify_replay_trace
from harness.runner import ROOT, write_json
from harness.scenario import load_plan
from harness.scenario_run import run_scenario, verify_scenario_run
from harness.session_store import RUN_ID, session_dir, session_state, unresolved_sessions, write_owner
from validation.contracts import load_json, load_scenario, require
from validation.trace import read_events


class SessionInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")


class SessionConfig(FunctionBaseConfig, name="prace_session"):
    plan: str = "harness/examples/file-discovery.plan.json"
    run_root: str = "/tmp/prace-nat-sessions"
    ssh_config: str | None = None
    allow_remote: bool = False
    model: str | None = None
    provider: Literal["nim", "openai"] = "nim"


def private_root(value: str) -> Path:
    root = Path(value)
    require(root.is_absolute() and ".." not in root.parts, "absolute session root required")
    require(not any(p.is_symlink() for p in (root, *root.parents)), "session root link refused")
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = root.stat()
    require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
            "session root must be owned by the service user and mode 0700")
    return root


def execute_session(config: SessionConfig, request: SessionInput) -> dict:
    require(importlib.metadata.version("nvidia-nat") == NAT_VERSION, "NeMo version differs from pin")
    plan = Path(config.plan)
    if not plan.is_absolute():
        plan = ROOT / plan
    load_plan(plan)
    require(config.ssh_config is None or config.allow_remote, "remote session requires operator configuration")
    require(not config.allow_remote or config.ssh_config is not None, "remote mode requires SSH role configuration")
    root = private_root(config.run_root)
    # A single service instance/replica uses one root. Lock before creating a
    # request directory; duplicate requests never overwrite or rerun a session.
    fd = os.open(root / ".session.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ValueError("another session is active") from None
        # An interrupted session, or a failed one without verified cleanup, may have left a job or a
        # workspace behind: no new session until the operator has inspected and resolved it locally.
        blocked = unresolved_sessions(root)
        require(not blocked, "unresolved session(s) " + ", ".join(blocked) + ": inspect their retained "
                "artifacts, reconcile jobs and workspaces, then resolve locally before starting another")
        directory = root / request.run_id
        require(not directory.exists() and not directory.is_symlink(), "run ID already used; inspect its evidence")
        directory.mkdir(mode=0o700)
        write_owner(directory)
        try:
            metadata = run_scenario(directory / "run", request.run_id, plan, driver="nemo",
                executable=sys.executable, model=config.model, provider=config.provider,
                ssh_config=Path(config.ssh_config) if config.ssh_config else None, allow_remote=config.allow_remote)
            verify_scenario_run(directory / "run")
            scenario = load_scenario(directory / "run/manifest.json")
            replay = verify_replay_trace(directory / "run/nemo-replay-trace.jsonl",
                read_events(directory / "run/events.jsonl", scenario))
            # The portable projection in the bundle must be exactly what the private telemetry rederives.
            require(metadata["replay_driver"] == "nemo" and replay == load_json(directory / "run/agent-replay-trace.json"),
                    "packaged replay projection differs from its telemetry")
            package_run(directory / "run", directory / "bundle")
            verify_bundle(directory / "bundle")
            receipt = {"schema": "prace.nat-session.v1", "run_id": request.run_id, "status": "complete",
                "nemo_version": NAT_VERSION, "transport": metadata["transport"], "llm_used": metadata["llm_used"],
                "replay_llm_used": False, "cleanup": metadata["cleanup"], "slurm_job_ids": metadata["slurm_job_ids"],
                "bundle_sha256": hashlib.sha256((directory / "bundle/bundle.json").read_bytes()).hexdigest(),
                "record_trace_sha256": hashlib.sha256((directory / "run/nemo-trace.jsonl").read_bytes()).hexdigest(),
                "replay_trace_sha256": replay["raw_trace_sha256"]}
        except Exception as exc:
            write_json(directory / "session.json", {"schema": "prace.nat-session.v1", "run_id": request.run_id,
                "status": "failed", "failure_type": type(exc).__name__})
            raise RuntimeError("session failed; inspect private run artifacts before retrying") from None
        write_json(directory / "session.json", receipt)
        return receipt
    finally:
        os.close(fd)


@register_function(config_type=SessionConfig)
async def session_workflow(config: SessionConfig, builder: Builder):
    del builder

    async def execute(input_message: str) -> str:
        # Plain JSON works with nat run --input and the default HTTP /generate
        # input_message string. No caller can choose commands, paths or models.
        request = SessionInput.model_validate_json(input_message)
        task = asyncio.create_task(asyncio.to_thread(execute_session, config, request))
        try:
            receipt = await asyncio.shield(task)
        except asyncio.CancelledError:
            # Do not release ownership or abandon cleanup on HTTP disconnect.
            # The run keeps its bounded gateway/SSH deadlines and durable record.
            try:
                await asyncio.shield(task)
            finally:
                raise
        return json.dumps(receipt)

    yield FunctionInfo.from_fn(execute, description="Record, replay, verify and package one operator-configured PRACE session.")


class SessionQuery(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")


class StatusConfig(FunctionBaseConfig, name="prace_session_status"):
    run_root: str = "/tmp/prace-nat-sessions"


def status_of(config: StatusConfig, query: SessionQuery) -> dict:
    root = private_root(config.run_root)
    if query.run_id is not None:
        return session_state(root, query.run_id)
    names = [name for name in sorted(os.listdir(root)) if RUN_ID.fullmatch(name) and (root / name).is_dir()][-200:]
    rows = []
    for name in names:
        state = session_state(root, name)
        rows.append({"run_id": name, "state": state["state"], "unresolved": state["unresolved"], "resolved": state["resolved"]})
    return {"schema": "prace.nat-session-list.v1", "sessions": rows}


@register_function(config_type=StatusConfig)
async def session_status(config: StatusConfig, builder: Builder):
    del builder

    async def execute(input_message: str) -> str:
        query = SessionQuery.model_validate_json(input_message)
        return json.dumps(await asyncio.to_thread(status_of, config, query))

    yield FunctionInfo.from_fn(execute, description="Read-only state, stage and progress of PRACE sessions.")


class ExportConfig(FunctionBaseConfig, name="prace_session_export"):
    run_root: str = "/tmp/prace-nat-sessions"


def export_session(config: ExportConfig, request: SessionInput) -> dict:
    """The completed session's verified bundle as a dashboard evidence folder, written once inside the
    private session directory (`evidence/<date>/<run-id>`). Publication stays a reviewed MR."""
    import importlib.util
    root = private_root(config.run_root)
    directory = session_dir(root, request.run_id)
    state = session_state(root, request.run_id)
    require(state["state"] == "complete", f"session {request.run_id} is {state['state']}; only a complete session exports")
    verify_bundle(directory / "bundle")
    require(hashlib.sha256((directory / "bundle/bundle.json").read_bytes()).hexdigest()
            == state["receipt"]["bundle_sha256"], "session bundle differs from its receipt")
    spec = importlib.util.spec_from_file_location("scenario_export", ROOT / "infra/tools/scenario-export.py")
    exporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)
    evidence_root = directory / "evidence"
    existing = sorted(evidence_root.glob(f"*/{request.run_id}")) if evidence_root.is_dir() else []
    if not existing:
        evidence_root.mkdir(mode=0o700, exist_ok=True)
        exporter.build(directory / "bundle", evidence_root)
        existing = sorted(evidence_root.glob(f"*/{request.run_id}"))
    require(len(existing) == 1 and (existing[0] / "SHA256SUMS").is_file(), "exported evidence folder missing")
    folder = existing[0]
    # Cached exports remain evidence: verify the copy and its dashboard files
    # again rather than treating the presence of SHA256SUMS as verification.
    verify_bundle(folder / "bundle")
    require((folder / "bundle/bundle.json").read_bytes() == (directory / "bundle/bundle.json").read_bytes(),
            "exported bundle differs from the session")
    exporter.check_with_dashboard(folder, f"{folder.parent.name}/{folder.name}")
    return {"schema": "prace.nat-session-export.v1", "run_id": request.run_id,
            "folder": f"{folder.parent.name}/{folder.name}", "path": str(folder),
            "sha256sums_sha256": hashlib.sha256((folder / "SHA256SUMS").read_bytes()).hexdigest(),
            "events": sum(1 for _ in (folder / "events.jsonl").open()), "published": False}


@register_function(config_type=ExportConfig)
async def session_export(config: ExportConfig, builder: Builder):
    del builder

    async def execute(input_message: str) -> str:
        request = SessionInput.model_validate_json(input_message)
        return json.dumps(await asyncio.to_thread(export_session, config, request))

    yield FunctionInfo.from_fn(execute, description="Export a complete session's verified bundle for the dashboard.")

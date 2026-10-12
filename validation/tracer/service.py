"""Single-writer tracer/gateway service over a private Unix-domain socket."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import stat
import threading
import time
from typing import Any

from validation.contracts import ContractError, load_scenario, require
from validation.cluster_tracer import CLUSTER_TRACER_SOURCE, ALLOWED_CLUSTER_SOURCES, build_layout_snapshot, build_inventory_snapshot
from validation.local_fs import LocalFsAdapter
from validation.observe import make_observation_event
from validation.replay import AdapterResult, ReplayRunner, make_action_event, resolve_action, _cap_result
from validation.report import write_reports
from validation.trace import TraceWriter, validate_cluster_correlations
from validation.verdict import build_result
from validation.tracer.protocol import decode_line, encode, err, ok


class TracerService:
    """Owns one run: scenario, TraceWriter, adapter, and ordered action IDs."""

    def __init__(
        self,
        *,
        scenario: dict[str, Any],
        run_dir: Path,
        run_id: str,
        adapter: Any,
        workspace: Path,
        expected_action_ids: list[str] | None = None,
        cluster_audit: Any | None = None,
        cluster_target: str | None = None,
        require_cluster_tracer: bool = False,
        cluster_snapshot_kind: str = "layout",
    ):
        self.scenario = scenario
        self.run_dir = Path(run_dir)
        self.run_id = run_id
        self.adapter = adapter
        self.workspace = Path(workspace)
        self.templates = {action["id"]: action for action in scenario["actions"]}
        self.expected_action_ids = expected_action_ids or [action["id"] for action in scenario["actions"]]
        self.record_index = 0
        self.finalized = False
        self.writer = TraceWriter(self.run_dir / "events.jsonl", scenario, run_id)
        self._lock = threading.Lock()
        self.cluster_audit = cluster_audit
        self.cluster_target = cluster_target or scenario["boundaries"]["observation_targets"][0]
        self.require_cluster_tracer = require_cluster_tracer
        self._cluster_tracer_count = 0
        require(cluster_snapshot_kind in {"layout", "inventory"}, "invalid cluster snapshot kind")
        self.cluster_snapshot_kind = cluster_snapshot_kind
        self.started = time.monotonic()
        self._replay_started: float | None = None

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        request_id = request.get("request_id")
        method = request.get("method")
        try:
            require(isinstance(method, str), "method required")
            with self._lock:
                if method == "ping":
                    return ok(request_id, pong=True)
                if method == "status":
                    return ok(
                        request_id,
                        run_id=self.run_id,
                        sequence=self.writer.next_sequence,
                        record_index=self.record_index,
                        finalized=self.finalized,
                        event_count=len(self.writer.events),
                        cluster_tracer_count=self._cluster_tracer_count,
                        cluster_tracer_enabled=self.cluster_audit is not None,
                    )
                if method == "catalog":
                    return ok(request_id, scenario={"id": self.scenario["id"], "version": self.scenario["version"]},
                              actions=[{key: action[key] for key in ("id", "kind", "parameters", "capture")}
                                       for action in self.scenario["actions"]])
                if self.finalized:
                    raise ContractError("run already finalized")
                if method == "execute_action":
                    return ok(request_id, event=self._execute_action(request))
                if method == "append_cluster":
                    return ok(request_id, event=self._append_cluster(request))
                if method == "append_observation":
                    return ok(request_id, event=self._append_observation(request))
                if method == "reset_workspace":
                    require(hasattr(self.adapter, "reset_workspace"), "adapter does not support workspace reset")
                    self.adapter.reset_workspace(self.workspace)
                    return ok(request_id, workspace=str(self.workspace))
                if method == "replay":
                    return ok(request_id, events=self._replay())
                if method == "replay_next":
                    return ok(request_id, **self._replay_next())
                if method == "finalize":
                    return ok(request_id, **self._finalize(request))
                raise ContractError(f"unknown method: {method}")
        except (ContractError, FileExistsError, OSError, RuntimeError) as exc:
            return err(str(exc), request_id)

    def _execute_action(self, request: dict[str, Any]) -> dict[str, Any]:
        action_id = request.get("action_id")
        phase = request.get("phase", "record")
        require(action_id in self.templates, f"unknown action_id: {action_id}")
        require(phase in {"record", "attack"}, "execute_action phase must be record or attack")
        # Check before executing: rejecting a trace append after the side effect
        # would not enforce the action budget.
        count = sum(event["event_type"] == "action" and event["phase"] == phase for event in self.writer.events)
        require(count < self.scenario["budgets"]["max_actions"], "action budget exhausted")
        require(time.monotonic() - self.started < self.scenario["budgets"]["max_seconds"], "action deadline reached")
        if phase == "record":
            require(self.record_index < len(self.expected_action_ids), "record action budget exhausted")
            expected = self.expected_action_ids[self.record_index]
            require(action_id == expected, f"out-of-order action: expected {expected}, got {action_id}")
        template = self.templates[action_id]
        bindings = {}
        for event in self.writer.events:
            if event["event_type"] == "action" and event["phase"] == phase:
                bindings.update(event["result"]["bindings"])
        resolved = resolve_action(template, bindings, self.scenario)
        timeout = template["timeout_seconds"]
        if self.scenario["id"] == "researcher-workflow":
            timeout = min(timeout, max(1, int(self.scenario["budgets"]["max_seconds"] - (time.monotonic() - self.started))))
        result = self.adapter.execute(template["id"], resolved, timeout)
        capped = _cap_result(result, self.scenario["budgets"]["max_output_bytes"])
        event = make_action_event(
            scenario=self.scenario,
            run_id=self.run_id,
            sequence=self.writer.next_sequence,
            phase=phase,
            template=template,
            resolved_action=resolved,
            result=capped,
        )
        written = self.writer.append(event)
        if phase == "record":
            self.record_index += 1
        if self.cluster_audit is not None:
            self._emit_cluster_tracer(phase=phase, correlated_action_sequence=written["sequence"])
        return written

    def _emit_cluster_tracer(self, *, phase: str, correlated_action_sequence: int) -> dict[str, Any]:
        observe = build_inventory_snapshot if self.cluster_snapshot_kind == "inventory" else build_layout_snapshot
        if self.cluster_snapshot_kind == "inventory" and self.scenario["id"] == "researcher-workflow":
            snapshot = observe(self.cluster_audit, self.workspace,
                               self.run_dir / f"cluster-snapshot-{correlated_action_sequence}.json")
        else:
            snapshot = observe(self.cluster_audit, self.workspace)
        event = self._append_cluster(
            {
                "source": CLUSTER_TRACER_SOURCE,
                "phase": phase,
                "correlated_action_sequence": correlated_action_sequence,
                "target": self.cluster_target,
                "snapshot": snapshot,
            }
        )
        require(snapshot["code"] != "workspace-inventory-unavailable", "cluster inventory unavailable; action trace retained")
        return event

    def _append_cluster(self, request: dict[str, Any]) -> dict[str, Any]:
        source = request.get("source", CLUSTER_TRACER_SOURCE)
        require(source in ALLOWED_CLUSTER_SOURCES, f"invalid cluster source: {source}")
        event = {
            "schema": "prace.cluster-event.v1",
            "event_type": "cluster",
            "run_id": self.run_id,
            "sequence": self.writer.next_sequence,
            "timestamp": "1970-01-01T00:00:00Z",
            "source": source,
            "phase": request["phase"],
            "scenario": {"id": self.scenario["id"], "version": self.scenario["version"]},
            "correlated_action_sequence": request["correlated_action_sequence"],
            "target": request.get("target", self.cluster_target),
            "snapshot": request["snapshot"],
        }
        written = self.writer.append(event)
        if source == CLUSTER_TRACER_SOURCE:
            self._cluster_tracer_count += 1
        return written

    def _append_observation(self, request: dict[str, Any]) -> dict[str, Any]:
        evidence = request.get("evidence", b"")
        if isinstance(evidence, str):
            evidence = bytes.fromhex(evidence) if request.get("evidence_encoding") == "hex" else evidence.encode()
        event = make_observation_event(
            scenario=self.scenario,
            run_id=self.run_id,
            sequence=self.writer.next_sequence,
            check_id=request["check_id"],
            target=request.get("target", self.scenario["boundaries"]["observation_targets"][0]),
            status=request["status"],
            code=request["code"],
            evidence=evidence,
            detail=request.get("detail", ""),
        )
        return self.writer.append(event)

    def _replayed(self) -> list[dict[str, Any]]:
        return [event for event in self.writer.events if event["event_type"] == "action" and event["phase"] == "replay"]

    def _replay_after_action(self):
        if self.cluster_audit is None:
            return None
        return lambda event: self._emit_cluster_tracer(phase="replay", correlated_action_sequence=event["sequence"])

    def _replay(self) -> list[dict[str, Any]]:
        require(not self._replayed(), "replay already started")
        source = [event for event in self.writer.events if event["event_type"] == "action"
                  and event["phase"] in {"record", "attack"}]
        return ReplayRunner(self.scenario, source, self.writer, self.adapter,
                            after_action=self._replay_after_action()).run()

    def _replay_next(self) -> dict[str, Any]:
        """Replay exactly one recorded action. The gateway chooses it (the next recorded action, as
        ReplayRunner would) and resolves its bindings from the replay so far; the caller has no input.
        A denied action ends the replay, as in a whole replay; any other failure stops it for good."""
        recorded = [event for event in self.writer.events if event["event_type"] == "action" and event["phase"] == "record"]
        attacked = [event for event in self.writer.events if event["event_type"] == "action" and event["phase"] == "attack"]
        source = recorded or attacked
        require(source, "source trace has no record or attack actions")
        done = self._replayed()
        if done and done[-1]["result"]["status"] != "ok":
            require(done[-1]["result"]["status"] == "denied", "replay already stopped")
            return {"done": True, "replayed": len(done)}
        if len(done) == len(source):
            return {"done": True, "replayed": len(done)}
        if self._replay_started is None:
            self._replay_started = time.monotonic()
        bindings: dict[str, str] = {}
        for event in done:
            bindings.update(event["result"]["bindings"])
        written = ReplayRunner(self.scenario, [source[len(done)]], self.writer, self.adapter,
                               after_action=self._replay_after_action(), bindings=bindings,
                               started=self._replay_started).run()
        require(len(written) == 1, "one replayed action expected")
        return {"done": False, "event": written[0]}

    def _finalize(self, request: dict[str, Any]) -> dict[str, Any]:
        require_tracer = self.require_cluster_tracer or bool(request.get("require_cluster_tracer", False))
        if require_tracer:
            validate_cluster_correlations(self.writer.events, require_complete=True)
        baseline = request.get("baseline_revision", "smoke-no-security-baseline")
        patch = request.get("patch_revision", "smoke-no-security-patch")
        replace = bool(request.get("replace_generated", False))
        result = build_result(
            scenario=self.scenario,
            events=self.writer.events,
            trace_path=self.writer.path,
            baseline_revision=baseline,
            patch_revision=patch,
        )
        write_reports(self.run_dir, self.scenario, result, self.writer.events, replace=replace)
        self.finalized = True
        return {"result": result, "run_dir": str(self.run_dir), "cluster_tracer_count": self._cluster_tracer_count}


def _build_adapter(kind: str, config: dict[str, Any]):
    if kind == "local":
        return LocalFsAdapter()
    if kind == "ssh":
        from validation.adapters.ssh_remote import SshRemoteAdapter
        return SshRemoteAdapter(
            ssh_alias=config["ssh_alias"],
            remote_helper=config.get("remote_helper", "prace-file-ops"),
            identity_file=config.get("identity_file"),
            known_hosts=config.get("known_hosts"),
            connect_timeout=int(config.get("connect_timeout", 10)),
        )
    if kind == "fake":
        from validation.replay import FakeAdapter
        responses = {
            action_id: AdapterResult(item["status"], item.get("exit_code"),
                                     item.get("stdout", "").encode(),
                                     item.get("stderr", "").encode(),
                                     item.get("outputs", {}),
                                     item.get("duration_ms", 1))
            for action_id, item in config.get("responses", {}).items()
        }
        return FakeAdapter(responses)
    raise ContractError(f"unsupported adapter: {kind}")


def serve(config_path: Path) -> None:
    config = json.loads(Path(config_path).read_text())
    scenario = load_scenario(Path(config["scenario"]))
    run_dir = Path(config["run_dir"])
    require(run_dir.is_absolute(), "run_dir must be absolute")
    run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    require(run_dir.stat().st_uid == os.getuid(), "run_dir must be owned by caller")
    workspace = Path(config.get("workspace", scenario["boundaries"]["paths"][0]))
    adapter = _build_adapter(config.get("adapter", "local"), config.get("adapter_config", {}))
    cluster_cfg = config.get("cluster_tracer") or {}
    cluster_audit = None
    cluster_target = None
    require_cluster_tracer = False
    if cluster_cfg.get("enabled", False):
        cluster_audit = _build_adapter(
            cluster_cfg.get("adapter", config.get("adapter", "local")),
            cluster_cfg.get("adapter_config", config.get("adapter_config", {})),
        )
        cluster_target = cluster_cfg.get("target")
        require_cluster_tracer = bool(cluster_cfg.get("require_on_finalize", True))
    service = TracerService(
        scenario=scenario,
        run_dir=run_dir,
        run_id=config["run_id"],
        adapter=adapter,
        workspace=workspace,
        cluster_audit=cluster_audit,
        cluster_target=cluster_target,
        require_cluster_tracer=require_cluster_tracer,
        cluster_snapshot_kind=cluster_cfg.get("snapshot_kind", "layout"),
    )
    socket_path = Path(config["socket_path"])
    require(socket_path.is_absolute(), "socket_path must be absolute")
    if socket_path.exists() or socket_path.is_symlink():
        socket_path.unlink()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chmod(socket_path, 0o600)
    server.listen(8)
    print(f"tracer listening on {socket_path} run_id={config['run_id']}", flush=True)
    try:
        while True:
            conn, _ = server.accept()
            with conn:
                raw = b""
                while not raw.endswith(b"\n"):
                    block = conn.recv(65536)
                    if not block:
                        break
                    raw += block
                    require(len(raw) <= 1024 * 1024, "request too large")
                if not raw:
                    continue
                request = decode_line(raw.splitlines()[0])
                response = service.handle(request)
                conn.sendall(encode(response))
    finally:
        server.close()
        if socket_path.exists():
            socket_path.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    serve(args.config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

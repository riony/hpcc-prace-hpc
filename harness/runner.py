"""Harmless local trace/replay/fix rehearsal; never a fleet or security proof."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
from typing import Any

from validation.contracts import (ContractError, canonical_json, file_sha256,
                                  load_scenario, require, sha256_json, validate_scenario, validate_result)
from validation.trace import read_events, validate_cluster_correlations
from validation.local_fs import reset_workspace
from validation.tracer.client import TracerClient
from validation.verdict import build_result
from harness.nemo_config import NAT_VERSION, workflow_config
from harness.agent_trace import project_trace

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "scenarios/file-ops-smoke/v1/manifest.json"
ACTION_IDS = ["mkdir-demo-dir", "write-test-file-1", "write-test-file-2", "delete-test-file-1"]
GOOD_CONTENT = "smoke-file-2\n"
BAD_CONTENT = "wrong-fixture-content\n"


def write_json(path: Path, value: Any) -> None:
    """Private, new artifacts only; failed attempts must not be overwritten."""
    with path.open("x", encoding="utf-8") as stream:
        path.chmod(0o600)
        stream.write(json.dumps(value, indent=2, sort_keys=True) + "\n")


def stop_process(process: subprocess.Popen) -> None:
    if process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)


def run_process(command: list[str], timeout: float, *, capture: bool = True,
                env: dict[str, str] | None = None, user: int | None = None,
                group: int | None = None, extra_groups: list[int] | None = None) -> subprocess.CompletedProcess:
    """Bounded process group; a timed-out driver cannot keep calling the gateway."""
    require(timeout > 0, "attempt deadline reached")
    process = subprocess.Popen(command, cwd=ROOT, start_new_session=True,
                               env=env, user=user, group=group, extra_groups=extra_groups,
                               stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                               stderr=subprocess.PIPE if capture else subprocess.DEVNULL)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        stop_process(process)
        process.communicate()
        raise ContractError("driver timed out") from None
    return subprocess.CompletedProcess(command, process.returncode, stdout or b"", stderr or b"")


def checked_call(client: TracerClient, method: str, **params: Any) -> dict[str, Any]:
    response = client.call(method, **params)
    require(response.get("ok") is True, f"gateway refused {method}")
    return response


def check_bridge_output(result: subprocess.CompletedProcess, action_id: str) -> dict[str, Any]:
    require(result.returncode == 0, f"action driver failed: {action_id}")
    require(not result.stderr and len(result.stdout) <= 4096, "unexpected bridge diagnostic/output")
    try:
        row = json.loads(result.stdout)
    except (ValueError, TypeError):
        raise ContractError("malformed bridge response") from None
    require(isinstance(row, dict) and row.get("action_id") == action_id
            and row.get("phase") == "record" and row.get("status") == "ok"
            and type(row.get("sequence")) is int and row["sequence"] > 0,
            "bridge did not report a successful declared action")
    return row


def bind_workspace(template: dict[str, Any], workspace: Path) -> dict[str, Any]:
    scenario = copy.deepcopy(template)
    old = Path(scenario["boundaries"]["paths"][0])
    scenario["boundaries"]["paths"] = [str(workspace)]
    for action in scenario["actions"]:
        action["parameters"]["path"] = str(workspace / Path(action["parameters"]["path"]).relative_to(old))
    return validate_scenario(scenario)


def observe_layout(workspace: Path) -> dict[str, Any]:
    """Independent bounded fixture check, including unexpected files and symlinks."""
    entries = []
    for path in sorted(workspace.rglob("*")):
        require(len(entries) < 32, "unexpected workspace size")
        name = path.relative_to(workspace).as_posix()
        if path.is_symlink():
            entries.append({"path": name, "kind": "symlink"})
        elif path.is_dir():
            entries.append({"path": name, "kind": "directory"})
        elif path.is_file():
            require(path.stat().st_size <= 4096, "unexpected workspace file size")
            entries.append({"path": name, "kind": "file", "sha256": file_sha256(path)})
        else:
            entries.append({"path": name, "kind": "other"})
    return {"entries": entries}


def layout_ok(proof: dict[str, Any]) -> bool:
    return proof == {"entries": [
        {"path": "demo-dir", "kind": "directory"},
        {"path": "demo-dir/test-file-2.txt", "kind": "file",
         "sha256": hashlib.sha256(GOOD_CONTENT.encode()).hexdigest()},
    ]}


def append_check(client: TracerClient, directory: Path, check_id: str, proof: dict[str, Any], passed: bool) -> None:
    write_json(directory / (check_id + ".json"), proof)
    checked_call(client, "append_observation", check_id=check_id, target="local-workspace",
                 status="pass" if passed else "fail", code="harness-layout",
                 evidence=canonical_json(proof).hex(), evidence_encoding="hex",
                 detail="independent local fixture layout")


def verify_attempt(directory: Path, run_id: str, expected: str, revision: str) -> dict[str, Any]:
    """Re-derive the verdict; stdout, driver rc and a saved PASS are insufficient."""
    scenario = load_scenario(directory / "manifest.json")
    require(scenario["status"] == "smoke", "only smoke manifests are supported")
    events = read_events(directory / "events.jsonl", scenario)
    require(events and all(event["run_id"] == run_id for event in events), "run ID mismatch")
    validate_cluster_correlations(events, require_complete=True)
    for phase in ("record", "replay"):
        actions = [event for event in events if event["event_type"] == "action" and event["phase"] == phase]
        require([event["action_id"] for event in actions] == ACTION_IDS, "incomplete/out-of-order actions")
        for action in actions:
            require(action["result"]["status"] == "ok" and action["result"]["exit_code"] == 0,
                    "action failed despite driver success")
            index = events.index(action)
            snapshot = events[index + 1] if index + 1 < len(events) else {}
            require(snapshot.get("event_type") == "cluster" and snapshot.get("source") == "cluster_tracer"
                    and snapshot.get("correlated_action_sequence") == action["sequence"],
                    "snapshot missing between actions")
    observations = [event for event in events if event["event_type"] == "observation"]
    require([event["check_id"] for event in observations] ==
            ["record-layout-ok", "replay-layout-ok", "workspace-reset"], "missing/extra observations")
    for event in observations:
        proof = json.loads((directory / (event["check_id"] + ".json")).read_text())
        passed = proof == {"entries": []} if event["check_id"] == "workspace-reset" else layout_ok(proof)
        require(event["observation"]["status"] == ("pass" if passed else "fail"), "observation contradicts proof")
        require(event["observation"]["evidence_sha256"] == sha256_json(proof), "observation proof hash mismatch")
    result = build_result(scenario=scenario, events=events, trace_path=directory / "events.jsonl",
                          baseline_revision=revision, patch_revision=sha256_json(scenario))
    saved = json.loads((directory / "result.json").read_text())
    validate_result(saved, scenario)
    comparison = dict(saved)
    comparison["generated_at"] = result["generated_at"]
    require(comparison == result, "saved result contradicts trace")
    require(result["verdicts"] == {"baseline": "not_applicable", "patched": "not_applicable",
                                    "functional": expected} and result["cleanup"] == "complete",
            "unexpected verdict or incomplete cleanup")
    return result


def agent_command(executable: str, model: str, socket_path: Path) -> list[str]:
    prompt = ("This is a harmless declared-action rehearsal. Use only prace_action. "
              f"Use socket_path={socket_path}. Call these action_id values exactly once in order: "
              + ", ".join(ACTION_IDS) + ". Stop on any refusal or unsuccessful status. "
              "Do not reset, replay, finalize, edit files or run shell commands. The operator handles those.")
    return [executable, "run", "--agent", "prace-smoke", "--model", model, "--format", "json", prompt]


def run_attempt(directory: Path, template: dict[str, Any], run_id: str, expected: str,
                revision: str, driver: str, executable: str | None, model: str | None,
                provider: str | None = None) -> None:
    directory.mkdir(mode=0o700)
    workspace = directory / "workspace"
    workspace.mkdir(mode=0o700)
    scenario = bind_workspace(template, workspace)
    write_json(directory / "manifest.json", scenario)
    socket_path = directory / "gateway.sock"
    require(len(os.fsencode(socket_path)) < 104, "output path too long for a Unix socket")
    config = {"scenario": str(directory / "manifest.json"), "run_dir": str(directory),
              "run_id": run_id, "workspace": str(workspace), "socket_path": str(socket_path),
              "adapter": "local", "cluster_tracer": {"enabled": True, "adapter": "local",
              "target": "local-workspace", "require_on_finalize": True}}
    write_json(directory / "gateway.json", config)
    with (directory / "gateway.log").open("xb") as log:
        (directory / "gateway.log").chmod(0o600)
        server = subprocess.Popen([sys.executable, "-m", "validation.tracer", "--config",
                                   str(directory / "gateway.json")], cwd=ROOT,
                                  stdout=log, stderr=log, start_new_session=True)
        completed = False
        try:
            startup = time.monotonic() + 5
            while not socket_path.exists():
                require(server.poll() is None and time.monotonic() < startup, "gateway failed to start")
                time.sleep(0.02)
            deadline = time.monotonic() + scenario["budgets"]["max_seconds"]
            client = TracerClient(socket_path, timeout_seconds=10)
            checked_call(client, "reset_workspace")
            outcomes = []
            driver_rc = None
            try:
                if driver == "scripted":
                    for action_id in ACTION_IDS:
                        outcome = run_process([sys.executable, "-m", "validation.tracer.opencode_bridge",
                                               str(socket_path), action_id], min(10, deadline - time.monotonic()))
                        driver_rc = outcome.returncode
                        outcomes.append(check_bridge_output(outcome, action_id))
                elif driver == "opencode":
                    outcome = run_process(agent_command(executable, model, socket_path),
                                          deadline - time.monotonic(), capture=False)
                    driver_rc = outcome.returncode
                    require(driver_rc == 0, "OpenCode driver failed")
                else:
                    write_json(directory / "nemo-config.json", workflow_config(socket_path,
                               directory / "nemo-trace.jsonl", run_id, model=model, provider=provider or "nim"))
                    outcome = run_process([executable or sys.executable, "-m", "harness.nemo_driver",
                                          "--config", str(directory / "nemo-config.json"), "--run-id", run_id],
                                         deadline - time.monotonic(), capture=False)
                    driver_rc = outcome.returncode
                    require(driver_rc == 0, "NeMo driver failed; check the pinned runtime and model configuration")
            finally:
                write_json(directory / "driver.json", {"driver": driver, "returncode": driver_rc,
                                                       "actions": outcomes})
            # Check the real trace even if a driver exits 0 without doing its work.
            events = read_events(directory / "events.jsonl", scenario)
            actions = [event for event in events if event["event_type"] == "action"]
            require([event["action_id"] for event in actions] == ACTION_IDS
                    and all(event["result"]["status"] == "ok" and event["result"]["exit_code"] == 0
                            for event in actions), "driver omitted or failed an action")
            write_json(directory / "agent-trace.json", project_trace(directory, run_id, driver,
                       NAT_VERSION if driver == "nemo" else None, events))
            for check_id in ("record-layout-ok", "replay-layout-ok"):
                proof = observe_layout(workspace)
                append_check(client, directory, check_id, proof, layout_ok(proof))
                if check_id == "record-layout-ok":
                    checked_call(client, "reset_workspace")
                    require(not any(workspace.iterdir()), "reset before replay left files")
                    client.timeout_seconds = max(0.1, deadline - time.monotonic())
                    checked_call(client, "replay")
            checked_call(client, "reset_workspace")
            proof = observe_layout(workspace)
            append_check(client, directory, "workspace-reset", proof, proof == {"entries": []})
            require(time.monotonic() < deadline, "attempt deadline reached")
            checked_call(client, "finalize", baseline_revision=revision, patch_revision=sha256_json(scenario),
                         require_cluster_tracer=True)
            verify_attempt(directory, run_id, expected, revision)
            completed = True
        finally:
            stop_process(server)
            socket_path.unlink(missing_ok=True)
            if not completed:
                # Preserve the diagnosis, then empty only this newly created,
                # run-owned workspace. A failed attempt never becomes a PASS.
                try:
                    write_json(directory / "failure-layout.json", observe_layout(workspace))
                finally:
                    reset_workspace(workspace)


def run_cycle(output: Path, run_id: str, *, driver: str = "scripted", executable: str | None = None,
              model: str | None = None, provider: str | None = None) -> dict[str, Any]:
    require(output.is_absolute() and not output.exists() and not output.is_symlink(), "new absolute output directory required")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", run_id) is not None, "invalid run ID")
    require(driver in {"scripted", "opencode", "nemo"}, "invalid driver")
    require(driver != "opencode" or (executable and model), "OpenCode needs an explicit executable and model")
    require(driver != "scripted" or (executable is None and model is None), "model options require the OpenCode driver")
    require(model is None or (isinstance(model, str) and len(model) <= 160
            and re.fullmatch(r"[A-Za-z0-9_./:-]+", model)), "invalid model name")
    require(provider is None or (driver == "nemo" and provider in {"nim", "openai"}), "invalid NeMo provider")
    revision = run_process(["git", "rev-parse", "HEAD"], 5).stdout.decode().strip()
    require(re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "source revision unavailable")
    output.mkdir(mode=0o700, parents=True)
    metadata = {"schema": "prace.harness-run.v1", "run_id": run_id, "status": "failed",
                "scope": "local-functional-fixture", "source_revision": revision,
                "source_dirty": bool(run_process(["git", "status", "--porcelain"], 5).stdout),
                "driver": driver, "model": model, "provider": (provider or "nim") if driver == "nemo" else None,
                "nemo_version": NAT_VERSION if driver == "nemo" else None,
                "llm_used": driver == "opencode" or (driver == "nemo" and model is not None),
                "fleet_contacted": False, "slurm_job_ids": [], "recovery_point": None,
                "attempts": [{"directory": "before", "functional": "functional_regression"},
                             {"directory": "after", "functional": "pass"}]}
    try:
        after = load_scenario(MANIFEST)
        before = copy.deepcopy(after)
        before["actions"][2]["parameters"]["content"] = BAD_CONTENT
        write_json(output / "template-before.json", before)
        write_json(output / "template-after.json", after)
        run_attempt(output / "before", before, run_id, "functional_regression", revision, driver, executable, model, provider)
        proposal = {"schema": "prace.fixture-fix.v1", "run_id": run_id,
                    "kind": "deterministic-fixture-correction", "action_id": "write-test-file-2",
                    "field": "parameters.content", "before": BAD_CONTENT, "after": GOOD_CONTENT,
                    "before_template_sha256": sha256_json(before), "after_template_sha256": sha256_json(after)}
        write_json(output / "fix-proposal.json", proposal)
        run_attempt(output / "after", after, run_id, "pass", revision, driver, executable, model, provider)
        metadata["status"] = "complete"
    except (ContractError, OSError, ValueError, RuntimeError) as exc:
        metadata["failure_type"] = type(exc).__name__
        # Keep raw model output and transport diagnostics out of this artifact.
        raise
    finally:
        write_json(output / "run.json", metadata)
    return metadata


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--driver", choices=["nemo", "scripted", "opencode"], default="nemo")
    parser.add_argument("--opencode", help="explicit OpenCode executable; used only with --driver opencode")
    parser.add_argument("--model", help="explicit model; omit for NeMo's model-free integration rehearsal")
    parser.add_argument("--nat-python", type=str, help="Python in the pinned NeMo virtual environment")
    parser.add_argument("--provider", choices=["nim", "openai"], help="NeMo model provider; default nim")
    parser.add_argument("--plan", type=Path, help="operator-owned configurable benign scenario plan")
    parser.add_argument("--ssh-config", type=Path, help="private actor, tracer and observer SSH configuration")
    parser.add_argument("--allow-remote", action="store_true", help="explicit operator go for SSH execution")
    args = parser.parse_args(argv)
    try:
        require(args.opencode is None or args.driver == "opencode", "--opencode requires its driver")
        require(args.nat_python is None or args.driver == "nemo", "--nat-python requires NeMo")
        if args.plan:
            from harness.scenario_run import run_scenario
            run_scenario(args.output_dir, args.run_id, args.plan, driver=args.driver,
                         executable=args.nat_python, model=args.model, provider=args.provider,
                         ssh_config=args.ssh_config, allow_remote=args.allow_remote)
        else:
            require(args.ssh_config is None and not args.allow_remote, "remote options require a scenario plan")
            run_cycle(args.output_dir, args.run_id, driver=args.driver,
                      executable=args.nat_python if args.driver == "nemo" else args.opencode,
                      model=args.model, provider=args.provider)
    except (ContractError, OSError, ValueError, RuntimeError) as exc:
        print(f"STOP: {type(exc).__name__}; inspect retained run artifacts", file=sys.stderr)
        return 1
    detail = "scenario actions, replay and independent checks passed" if args.plan else "fixture failure reproduced, correction rerun passed"
    print(f"PASS {args.run_id}: {detail}; security=not_applicable")
    return 0

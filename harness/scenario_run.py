"""Configurable benign scenario orchestration with independent SSH observations."""

from __future__ import annotations

import json
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any

from harness.agent_trace import project_replay_trace, project_trace, validate_projection, validate_replay_projection
from harness.nemo_config import NAT_VERSION, workflow_config
from harness.nemo_replay import replay_config
from harness.runner import ROOT, checked_call, run_process, stop_process, write_json
from harness.scenario import bind_run, load_plan, load_ssh, validate_plan
from validation.adapters.prace_file_ops_helper import helper_digests
from validation.adapters import slurm_smoke, researcher_workflow
from validation.adapters.ssh_remote import SshRemoteAdapter
from validation.contracts import (canonical_json, load_json, load_scenario, require, sha256_json,
                                  validate_result)
from validation.local_fs import LocalFsAdapter
from validation.replay import resolve_action
from validation.report import render_markdown
from validation.trace import read_events, validate_cluster_correlations
from validation.tracer.client import TracerClient
from validation.cluster_tracer import validate_inventory_proof
from validation.verdict import build_result


def ssh_adapter(row: dict) -> SshRemoteAdapter:
    return SshRemoteAdapter(**{key: value for key, value in row.items() if key != "identity"})


def inspect_layout(adapter: Any, workspace: Path) -> dict:
    proof = adapter.inventory_workspace(workspace)
    if isinstance(adapter, LocalFsAdapter):
        proof["job_ticket_present"] = False
    require(set(proof) == {"entries", "job_ticket_present"} and isinstance(proof["entries"], list)
            and len(proof["entries"]) <= 32 and type(proof["job_ticket_present"]) is bool,
            "malformed workspace inventory")
    return proof


def phase_actions(events: list[dict], phase: str) -> list[dict]:
    return [event for event in events if event["event_type"] == "action" and event["phase"] == phase]


def job_expectation(check: dict, scenario: dict, events: list[dict], phase: str, run_id: str, started_epoch: int) -> dict:
    sources = [row for row in phase_actions(events, phase) if row["action_id"] == check["submit_action"]]
    require(len(sources) == 1, "one submitted job receipt required")
    params = sources[0]["action"]["parameters"]
    binding = next(a for a in scenario["actions"] if a["id"] == check["submit_action"])["capture"].get("job_id")
    job_id = sources[0]["result"]["bindings"].get(binding)
    require(isinstance(job_id, str) and re.fullmatch(r"[1-9][0-9]{0,11}", job_id), "job ID binding missing")
    extra = {k: params[k] for k in ("example", "example_sha256", "source_sha256", "path")} if "example" in params else {}
    return {**extra, "workspace": scenario["boundaries"]["paths"][0], "job_id": job_id,
            "run_id": run_id, "started_epoch": started_epoch, "actor": scenario["actor"]["identity"],
            "account": params["account"], "partition": params["partition"]}


def researcher_jobs(scenario, events, run_id, started_epoch):
    return [job_expectation({"submit_action": row["action_id"]}, scenario, events, row["phase"], run_id, started_epoch)
            for row in events if row["event_type"] == "action" and row["action"]["kind"] == "slurm.submit-example"]


def cleanup_expectation(scenario: dict, events: list[dict], run_id: str, started_epoch: int) -> dict | None:
    research = researcher_jobs(scenario, events, run_id, started_epoch)
    if research:
        return {"jobs": research}
    submits = [row for row in events if row["event_type"] == "action" and row["action"]["kind"] in {"slurm.submit", "slurm.submit-example"}]
    if not submits:
        return None
    params = submits[0]["action"]["parameters"]
    ids = [row["result"]["bindings"].get("smoke_job_id") for row in submits]
    require(all(isinstance(job, str) and re.fullmatch(r"[1-9][0-9]{0,11}", job) for job in ids)
            and len(ids) == len(set(ids)), "cleanup requires every submission receipt")
    return {"workspace": scenario["boundaries"]["paths"][0], "run_id": run_id, "job_ids": ids, "started_epoch": started_epoch,
            "actor": scenario["actor"]["identity"], "account": params["account"], "partition": params["partition"]}


def inspect_clean(adapter: Any, workspace: Path, scenario: dict, events: list[dict], run_id: str, started_epoch: int) -> dict:
    proof = inspect_layout(adapter, workspace)
    expected = cleanup_expectation(scenario, events, run_id, started_epoch)
    if expected is not None:
        proof["job_cleanup"] = adapter.json_rpc("researcher-clean" if "jobs" in expected else "jobs-clean", expected)
    return proof


def fixed_job_proof(proof: dict, expected: dict) -> bool:
    if 'example' in expected:
        return researcher_workflow.valid_job_proof(proof, expected)
    if not isinstance(proof, dict) or type(proof.get("submit_epoch")) is not int:
        return False
    return (proof["submit_epoch"] >= expected["started_epoch"] and
            {key: value for key, value in proof.items() if key != "submit_epoch"} ==
            {**(researcher_workflow.fixed_job_fields(expected) if "example" in expected else slurm_smoke.fixed_job_fields(expected)),
             "state": "COMPLETED", "exit_code": "0:0"})


def check_proof(check: dict, proof: dict, scenario: dict, events: list[dict], phase: str, run_id: str, started_epoch: int) -> bool:
    if check["kind"] == "layout":
        require(set(proof) == {"entries", "job_ticket_present"} and type(proof["job_ticket_present"]) is bool,
                "invalid layout proof")
        return proof["entries"] == check["entries"]
    if check["kind"] == "output-markers":
        if not researcher_workflow.valid_outputs(proof):
            return False
        for row, profile in zip(proof['files'], ('cpu', 'gpu')):
            tails = [event for event in phase_actions(events, phase) if event['action_id'] == f'read-{profile}-output']
            if len(tails) != 1:
                return False
            template = next(action for action in scenario['actions'] if action['id'] == f'read-{profile}-output')
            tail = '\n'.join(row['content'].splitlines()[-template['parameters']['lines']:])
            if tails[0]['result']['bindings'].get(f'{profile}_output_tail') != tail:
                return False
        return True
    if check["kind"] == "workspace-empty":
        expected = cleanup_expectation(scenario, events, run_id, started_epoch)
        if expected is None:
            return proof == {"entries": [], "job_ticket_present": False}
        jobs = proof.get("job_cleanup", {})
        if not isinstance(jobs, dict):
            return False
        if set(proof) != {"entries", "job_ticket_present", "job_cleanup"} or proof["entries"] or proof["job_ticket_present"] is not False:
            return False
        if "jobs" in expected:
            return (set(jobs) == {"active_job_ids", "jobs"} and jobs["active_job_ids"] == []
                    and isinstance(jobs["jobs"], list) and len(jobs["jobs"]) == len(expected["jobs"])
                    and all(fixed_job_proof(row, exp) for row, exp in zip(jobs["jobs"], expected["jobs"])))
        return (jobs.get("active_job_ids") == [] and set(jobs) == {"active_job_ids", "jobs"}
                and isinstance(jobs["jobs"], list) and len(jobs["jobs"]) == len(expected["job_ids"])
                and all(fixed_job_proof(proof, {**expected, "job_id": job})
                        for proof, job in zip(jobs["jobs"], expected["job_ids"])))
    expected = job_expectation(check, scenario, events, phase, run_id, started_epoch)
    return fixed_job_proof(proof, expected)


def verify_scenario_run(directory: Path, metadata: dict | None = None) -> dict:
    """Read-only verification: rederive verdicts from proofs and actual traces."""
    metadata = metadata if metadata is not None else load_json(directory / "run.json")
    keys = {"schema", "run_id", "status", "scope", "source_revision", "source_dirty", "scenario_sha256", "plan_sha256",
            "driver", "model", "provider", "nemo_version", "llm_used", "transport", "ssh_identities", "slurm_job_ids",
            "recovery_point", "cleanup", "started_epoch"}
    # Runs from before NeMo replay have no replay_driver: the gateway replayed them.
    require(isinstance(metadata, dict) and keys <= set(metadata) <= keys | {"replay_driver", "execution_environment"}, "malformed scenario metadata")
    replay_driver = metadata.get("replay_driver", "gateway")
    require(replay_driver == "gateway" or (replay_driver == "nemo" and metadata["driver"] == "nemo"),
            "invalid replay driver provenance")
    require(metadata["schema"] == "prace.scenario-run.v1" and metadata["status"] == "complete",
            "scenario run incomplete")
    require(metadata["scope"] == "benign-smoke" and metadata["cleanup"] == "complete" and metadata["recovery_point"] is None,
            "smoke cannot claim security or restore qualification")
    require(isinstance(metadata["source_revision"], str) and re.fullmatch(r"[0-9a-f]{40}", metadata["source_revision"])
            and type(metadata["source_dirty"]) is bool and metadata["driver"] in {"scripted", "nemo"}, "invalid source/driver provenance")
    require((metadata["driver"] == "nemo" and metadata["nemo_version"] == NAT_VERSION and metadata["provider"] in {"nim", "openai"})
            or (metadata["driver"] == "scripted" and metadata["model"] is None and metadata["nemo_version"] is None
                and metadata["provider"] is None), "invalid framework provenance")
    require(metadata["llm_used"] is (metadata["model"] is not None), "invalid model provenance")
    require(type(metadata["started_epoch"]) is int and metadata["started_epoch"] > 0, "invalid run start time")
    require(metadata["transport"] in {"ssh", "local"}, "unknown transport")
    if metadata["transport"] == "ssh":
        roles = metadata["ssh_identities"]
        require(isinstance(roles, dict) and set(roles) == {"actor", "tracer", "observer"}
                and all(isinstance(row, dict) and set(row) == {"identity", "uid"} and type(row["uid"]) is int
                        and isinstance(row["identity"], str) for row in roles.values()), "invalid role provenance")
        require(len({row["uid"] for row in roles.values()}) == len({row["identity"] for row in roles.values()}) == 3,
                "roles were not independent")
    else:
        require(metadata["ssh_identities"] == {} and metadata["slurm_job_ids"] == [], "local run cannot claim SSH roles or jobs")
    if "execution_environment" in metadata:
        environment = metadata["execution_environment"]
        require(environment in {"local", "ssh-stand-in", "ssh-unqualified"}, "invalid execution environment")
        if metadata["transport"] == "local":
            require(environment == "local", "local environment mismatch")
        else:
            caps = load_json(directory / "environment.json")
            require(isinstance(caps, dict) and set(caps) == {"actor", "tracer", "observer"},
                    "environment capabilities missing")
            for role, row in caps.items():
                require(isinstance(row, dict) and set(row) in ({"protocol", "identity", "uid", "helper_digests"},
                        {"protocol", "identity", "uid", "helper_digests", "execution_environment"})
                        and row.get("protocol") == "prace.helper.v2"
                        and {k: row.get(k) for k in ("identity", "uid")} == metadata["ssh_identities"][role]
                        and isinstance(row.get("helper_digests"), dict)
                        and set(row["helper_digests"]) == set(helper_digests())
                        and all(isinstance(d, str) and re.fullmatch(r"[0-9a-f]{64}", d)
                                for d in row["helper_digests"].values()), "environment role binding mismatch")
            claims = [row.get("execution_environment") for row in caps.values()]
            require(claims == ["ssh-stand-in"] * 3 if environment == "ssh-stand-in" else claims == [None] * 3,
                    "environment claims differ from run")
    plan = load_json(directory / "plan.json")
    # Reuse the strict plan parser against the saved bound manifest, including
    # the same parameter/observer checks as execution, not just a saved PASS.
    scenario = load_scenario(directory / "manifest.json")
    validate_plan(plan, scenario, bound_run_id=metadata["run_id"])
    require(metadata["transport"] != "ssh" or metadata["ssh_identities"]["actor"]["identity"] == scenario["actor"]["identity"],
            "remote actor provenance differs from manifest")
    require(sha256_json(plan) == metadata["plan_sha256"] and sha256_json(scenario) == metadata["scenario_sha256"],
            "plan/scenario binding mismatch")
    events = read_events(directory / "events.jsonl", scenario)
    require(events and all(row["run_id"] == metadata["run_id"] for row in events), "scenario run ID mismatch")
    validate_cluster_correlations(events, require_complete=True)
    for index, row in enumerate(events):
        if row["event_type"] == "action":
            following = events[index + 1] if index + 1 < len(events) else {}
            require(following.get("event_type") == "cluster" and following["source"] == "cluster_tracer"
                    and following["correlated_action_sequence"] == row["sequence"]
                    and following["snapshot"]["status"] == "match" and following["snapshot"]["code"] == "workspace-inventory",
                    "independent inventory missing after action")
            if scenario['id'] == 'researcher-workflow':
                inventory = load_json(directory / f"cluster-snapshot-{row['sequence']}.json")
                validate_inventory_proof(inventory)
                require(sha256_json(inventory) == following['snapshot']['evidence_sha256'], 'tracer snapshot proof mismatch')
    source_phase = "attack" if plan["execution"] == "discovery" else "record"
    require(all(row["event_type"] != "action" or row["phase"] in {source_phase, "replay"} for row in events),
            "unexpected action phase")
    source = phase_actions(events, source_phase)
    require(source and len(source) <= scenario["budgets"]["max_actions"], "missing/excess scenario actions")
    ids = [row["action_id"] for row in source]
    require(set(plan["required_actions"]) <= set(ids), "required completion actions missing")
    if source_phase == "record":
        require(ids == [action["id"] for action in scenario["actions"]], "ordered actions incomplete")
    require([row["action_id"] for row in phase_actions(events, "replay")] == ids, "replay differs from actual discovery")
    for phase in (source_phase, "replay"):
        bindings = {}
        templates = {action["id"]: action for action in scenario["actions"]}
        for row in phase_actions(events, phase):
            require(row["result"]["status"] == "ok" and row["result"]["exit_code"] == 0, "unsuccessful scenario action")
            require(row["result"]["executed_sha256"] == sha256_json(resolve_action(templates[row["action_id"]], bindings, scenario)),
                    "resolved action binding mismatch")
            bindings.update(row["result"]["bindings"])
    assertions = {item["id"]: item for item in scenario["assertions"]}
    observations = [row for row in events if row["event_type"] == "observation"]
    require(len(observations) == len(plan["checks"]) and {row["check_id"] for row in observations} == set(assertions),
            "missing/extra independent observations")
    for check in plan["checks"]:
        assertion = assertions[check["id"]]
        phase = source_phase if assertion["phase"] == "record" else assertion["phase"]
        proof = load_json(directory / (check["id"] + ".json"))
        observation = next(row for row in observations if row["check_id"] == check["id"])
        passed = check_proof(check, proof, scenario, events, phase, metadata["run_id"], metadata["started_epoch"])
        require(observation["observation"]["status"] == ("pass" if passed else "fail")
                and observation["observation"]["evidence_sha256"] == sha256_json(proof), "observation contradicts proof")
    result = build_result(scenario=scenario, events=events, trace_path=directory / "events.jsonl",
                          baseline_revision=metadata["source_revision"], patch_revision="smoke-no-patch")
    recorded = load_json(directory / "result.json")
    validate_result(recorded, scenario)
    recorded["generated_at"] = result["generated_at"]
    require(recorded == result and result["verdicts"]["functional"] == "pass" and result["cleanup"] == "complete",
            "verdict/cleanup not independently passing")
    report = directory / "report.md"
    require(report.is_file() and not report.is_symlink() and report.stat().st_size <= 1024 * 1024
            and report.read_text() == render_markdown(scenario, result, events), "report contradicts evidence")
    validate_projection(load_json(directory / "agent-trace.json"), metadata["run_id"], metadata["driver"],
                        metadata["nemo_version"], events)
    if replay_driver == "nemo":
        validate_replay_projection(load_json(directory / "agent-replay-trace.json"), metadata["run_id"],
                                   metadata["nemo_version"], events)
    jobs = [row["result"]["bindings"][next(a for a in scenario["actions"] if a["id"] == row["action_id"])["capture"]["job_id"]] for row in events if row["event_type"] == "action"
            and row["action"]["kind"] in {"slurm.submit", "slurm.submit-example"}]
    require(metadata["slurm_job_ids"] == jobs and len(set(jobs)) == len(jobs), "job provenance mismatch")
    return metadata


def run_scenario(output: Path, run_id: str, plan_path: Path, *, driver: str = "scripted",
                 executable: str | None = None, model: str | None = None, provider: str | None = None,
                 ssh_config: Path | None = None, allow_remote: bool = False) -> dict:
    require(output.is_absolute() and not output.exists() and not output.is_symlink(), "new absolute run directory required")
    require(not any(parent.is_symlink() for parent in output.parents), "run output parent link refused")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", run_id) is not None, "invalid run ID")
    require(driver in {"scripted", "nemo"}, "scenario plans support scripted or NeMo drivers")
    require(model is None or (driver == "nemo" and isinstance(model, str) and re.fullmatch(r"[A-Za-z0-9_./:-]{1,160}", model)),
            "invalid scenario model")
    require(provider is None or (driver == "nemo" and provider in {"nim", "openai"}), "invalid scenario provider")
    plan, template = load_plan(plan_path)
    remote = load_ssh(ssh_config, template["actor"]["identity"]) if ssh_config else None
    require(remote is None or allow_remote, "SSH execution requires the operator's explicit --allow-remote")
    require(remote is not None or not any(action["kind"].startswith("slurm.") for action in template["actions"]),
            "Slurm smoke requires the SSH adapter")
    if remote is None:
        require(template["boundaries"]["action_targets"] == ["local-workspace"]
                and template["boundaries"]["observation_targets"] == ["local-workspace"], "remote target requires SSH config")
    revision = run_process(["git", "rev-parse", "HEAD"], 5).stdout.decode().strip()
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "source revision unavailable")
    output.mkdir(mode=0o700, parents=True)
    remote_root = '/home/syn-alice/.prace-researcher/runs' if template['boundaries']['paths'] == ['/home/syn-alice/.prace-researcher'] else '/projects/proj-ops/.prace-smoke/runs'
    workspace = Path(remote_root) / run_id / "workspace" if remote else output / "workspace"
    scenario = bind_run(template, workspace, run_id)
    write_json(output / "manifest.json", scenario)
    write_json(output / "plan.json", plan)
    metadata = {"schema": "prace.scenario-run.v1", "run_id": run_id, "status": "failed", "scope": "benign-smoke",
                "source_revision": revision, "source_dirty": bool(run_process(["git", "status", "--porcelain"], 5).stdout),
                "scenario_sha256": sha256_json(scenario), "plan_sha256": sha256_json(plan), "driver": driver,
                "model": model, "provider": (provider or "nim") if driver == "nemo" else None,
                "nemo_version": NAT_VERSION if driver == "nemo" else None, "llm_used": model is not None,
                "transport": "ssh" if remote else "local", "ssh_identities": {}, "slurm_job_ids": [],
                "recovery_point": None, "cleanup": "not-run", "started_epoch": int(time.time()),
                "replay_driver": "nemo" if driver == "nemo" else "gateway"}
    socket = output / "gateway.sock"
    require(len(os.fsencode(socket)) < 104, "run path too long for Unix socket")
    server = None
    actor = LocalFsAdapter()
    observer = actor
    prepared = False
    known_events = []

    def read_trace(allow_empty=False):
        nonlocal known_events
        events = read_events(output / "events.jsonl", scenario, allow_empty=allow_empty)
        known_events = events
        return events

    gateway = {"scenario": str(output / "manifest.json"), "run_dir": str(output), "run_id": run_id,
               "workspace": str(workspace), "socket_path": str(socket), "adapter": "local",
               "cluster_tracer": {"enabled": True, "adapter": "local", "target": "local-workspace",
                                  "require_on_finalize": True, "snapshot_kind": "inventory"}}
    deadline = time.monotonic() + scenario["budgets"]["max_seconds"]
    try:
        if remote:
            uids = []
            capabilities = {}
            for role, row in remote["roles"].items():
                caps = ssh_adapter(row).json_rpc("capabilities", {})
                require(isinstance(caps, dict) and set(caps) in ({"protocol", "identity", "uid", "helper_digests"},
                        {"protocol", "identity", "uid", "helper_digests", "execution_environment"})
                        and caps.get("protocol") == "prace.helper.v2" and caps.get("identity") == row["identity"]
                        and type(caps.get("uid")) is int and caps.get("helper_digests") == helper_digests(),
                        "remote identity or installed helper differs from reviewed source")
                capabilities[role] = caps
                uids.append(caps["uid"])
                metadata["ssh_identities"][role] = {"identity": caps["identity"], "uid": caps["uid"]}
            require(len(set(uids)) == 3, "SSH roles resolve to the same UID")
            claims = [caps.get("execution_environment") for caps in capabilities.values()]
            require(claims in ([None] * 3, ["ssh-stand-in"] * 3), "inconsistent execution environment claims")
            metadata["execution_environment"] = "ssh-stand-in" if claims[0] else "ssh-unqualified"
            write_json(output / "environment.json", capabilities)
            actor = ssh_adapter(remote["roles"]["actor"])
            observer = ssh_adapter(remote["roles"]["observer"])
            submits = [item for item in scenario["actions"] if item["kind"] in {"slurm.submit", "slurm.submit-example"}]
            for submitted in submits:
                checked = observer.json_rpc("researcher-preflight" if submitted["kind"] == "slurm.submit-example" else "jobs-preflight", {**submitted["parameters"],
                                               "actor": scenario["actor"]["identity"]})
                require(set(checked) == {"ok", "started_epoch"} and checked["ok"] is True
                        and type(checked["started_epoch"]) is int and checked["started_epoch"] > 0,
                        "invalid independent job preflight")
                metadata["started_epoch"] = checked["started_epoch"]
            try:
                row = actor.json_rpc("prepare", {"workspace": str(workspace)})
            except Exception:
                metadata["cleanup"] = "unknown"
                raise
            require(row == {"ok": True, "workspace": str(workspace)}, "remote run ownership not confirmed")
            prepared = True
            gateway.update(adapter="ssh", adapter_config={key: value for key, value in remote["roles"]["actor"].items() if key != "identity"})
            gateway["cluster_tracer"] = {"enabled": True, "adapter": "ssh",
                "adapter_config": {key: value for key, value in remote["roles"]["tracer"].items() if key != "identity"},
                "target": scenario["boundaries"]["observation_targets"][0], "require_on_finalize": True,
                "snapshot_kind": "inventory"}
        else:
            metadata["execution_environment"] = "local"
            workspace.mkdir(mode=0o700)
            prepared = True
        write_json(output / "gateway.json", gateway)
        with (output / "gateway.log").open("xb") as log:
            (output / "gateway.log").chmod(0o600)
            server = subprocess.Popen([sys.executable, "-m", "validation.tracer", "--config", str(output / "gateway.json")],
                                      cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
        for _ in range(250):
            if socket.exists():
                break
            require(server.poll() is None, "scenario gateway failed to start")
            time.sleep(.02)
        require(socket.exists(), "scenario gateway startup deadline")
        client = TracerClient(socket, timeout_seconds=max(120, max(a["timeout_seconds"] for a in scenario["actions"]) + 30))

        def seed():
            for entry in plan["seed_files"]:
                result = actor.execute("operator-seed", {"kind": "file.write", "parameters": {
                    "path": str(workspace / entry["path"]), "content": entry["content"]}}, 10)
                require(result.status == "ok" and result.exit_code == 0, "operator fixture seed failed")

        def observe(phase: str):
            events = read_trace()
            for check in plan["checks"]:
                assertion = next(item for item in scenario["assertions"] if item["id"] == check["id"])
                if assertion["phase"] != phase:
                    continue
                source_phase = "attack" if phase == "record" and plan["execution"] == "discovery" else phase
                if check["kind"] == "job-completed":
                    require(remote is not None, "job observer requires SSH")
                    proof = observer.json_rpc("researcher-proof" if "expect" in check else "job-proof", job_expectation(check, scenario, events, source_phase, run_id, metadata["started_epoch"]))
                elif check["kind"] == "workspace-empty":
                    proof = inspect_clean(observer, workspace, scenario, events, run_id, metadata["started_epoch"])
                elif check["kind"] == "output-markers":
                    proof = observer.json_rpc("output-proof", {"workspace": str(workspace), "directory": check["directory"], "entries": check["entries"]})
                else:
                    proof = inspect_layout(observer, workspace)
                passed = check_proof(check, proof, scenario, events, source_phase, run_id, metadata["started_epoch"])
                write_json(output / (check["id"] + ".json"), proof)
                checked_call(client, "append_observation", check_id=check["id"],
                             target=scenario["boundaries"]["observation_targets"][0], status="pass" if passed else "fail",
                             code="independent-scenario-check", evidence=canonical_json(proof).hex(), evidence_encoding="hex",
                             detail="operator-owned independent observation")
                require(passed, "independent scenario check failed")

        seed()
        if scenario['id'] == 'researcher-workflow':
            deadline = time.monotonic() + scenario['budgets']['max_seconds']
        phase = "attack" if plan["execution"] == "discovery" else "record"
        ids = [action["id"] for action in scenario["actions"]]
        if driver == "scripted":
            checked_call(client, "catalog")
            for action_id in ids:
                require(time.monotonic() < deadline, "scenario deadline reached")
                event = checked_call(client, "execute_action", action_id=action_id, phase=phase)["event"]
                require(event["result"]["status"] == "ok" and event["result"]["exit_code"] == 0, "scenario action failed")
        else:
            write_json(output / "nemo-config.json", workflow_config(socket, output / "nemo-trace.jsonl", run_id,
                action_ids=ids, phase=phase, goal=plan["goal"], model=model, provider=provider or "nim",
                max_actions=scenario["budgets"]["max_actions"], rpc_timeout=min(1230, max(a["timeout_seconds"] for a in scenario["actions"]) + 30)))
            result = run_process([executable or sys.executable, "-m", "harness.nemo_driver", "--config",
                                  str(output / "nemo-config.json"), "--run-id", run_id], deadline - time.monotonic(), capture=False)
            require(result.returncode == 0, "scenario NeMo driver failed")
        events = read_trace()
        actions = phase_actions(events, phase)
        require(actions and set(plan["required_actions"]) <= {row["action_id"] for row in actions}, "driver omitted completion actions")
        require(all(row["result"]["status"] == "ok" and row["result"]["exit_code"] == 0 for row in actions), "driver action failure")
        write_json(output / "agent-trace.json", project_trace(output, run_id, driver, metadata["nemo_version"], events))
        observe("record")
        require(time.monotonic() < deadline, 'record phase deadline reached')
        checked_call(client, "reset_workspace")
        reset_events = read_trace()
        require(check_proof({"kind": "workspace-empty"}, inspect_clean(observer, workspace, scenario, reset_events, run_id, metadata["started_epoch"]),
                            scenario, reset_events, "cleanup", run_id, metadata["started_epoch"]), "reset before replay not verified")
        seed()
        if scenario['id'] == 'researcher-workflow':
            deadline = time.monotonic() + scenario['budgets']['max_seconds']
            client.timeout_seconds = scenario['budgets']['max_seconds'] + 30
        if driver == "nemo":
            # NeMo drives and records the replay step by step; the gateway still chooses every action
            # and resolves its new bindings (job IDs). The replay config has no model.
            recorded = phase_actions(read_trace(), phase)
            write_json(output / "nemo-replay-config.json", replay_config(socket, output / "nemo-replay-trace.jsonl", run_id,
                max_steps=len(recorded) + 1, rpc_timeout=min(1230, max(a["timeout_seconds"] for a in scenario["actions"]) + 30)))
            result = run_process([executable or sys.executable, "-m", "harness.nemo_driver", "--config",
                                  str(output / "nemo-replay-config.json"), "--run-id", run_id, "--operation", "replay"],
                                 deadline - time.monotonic(), capture=False)
            require(result.returncode == 0, "NeMo replay workflow failed")
            write_json(output / "agent-replay-trace.json", project_replay_trace(output, run_id, metadata["nemo_version"],
                                                                              read_trace()))
        else:
            checked_call(client, "replay")
        observe("replay")
        checked_call(client, "reset_workspace")
        observe("cleanup")
        require(time.monotonic() < deadline, "scenario deadline reached")
        checked_call(client, "finalize", baseline_revision=revision, patch_revision="smoke-no-patch", require_cluster_tracer=True)
        metadata["slurm_job_ids"] = [row["result"]["bindings"][next(a for a in scenario["actions"] if a["id"] == row["action_id"])["capture"]["job_id"]] for row in read_trace()
                                     if row["event_type"] == "action" and row["action"]["kind"] in {"slurm.submit", "slurm.submit-example"}]
        metadata.update(status="complete", cleanup="complete")
        verify_scenario_run(output, metadata)
    except Exception as exc:
        metadata.update(status="failed", failure_type=type(exc).__name__)
        raise
    finally:
        trace_error = False
        try:
            if server is not None:
                stop_process(server)
            socket.unlink(missing_ok=True)
        except Exception as exc:
            metadata.update(status="failed", shutdown_failure_type=type(exc).__name__)
        if (output / "events.jsonl").exists():
            try:
                read_trace(allow_empty=True)
            except Exception as exc:
                # Keep the last completely validated trace for bounded job cleanup.
                # A damaged log never prevents cleanup or becomes successful evidence.
                trace_error = True
                metadata.update(status="failed", trace_failure_type=type(exc).__name__)
        metadata["slurm_job_ids"] = [value for row in known_events
            if row["event_type"] == "action" and row["action"]["kind"] in {"slurm.submit", "slurm.submit-example"}
            for key, value in row["result"]["bindings"].items() if key in {"smoke_job_id", "cpu_job_id", "gpu_job_id"}]
        if prepared:
            try:
                actor.reset_workspace(workspace)
                proof = inspect_clean(observer, workspace, scenario, known_events, run_id, metadata["started_epoch"])
                if metadata["status"] != "complete":
                    write_json(output / "failure-cleanup.json", proof)
                require(proof["entries"] == [] and proof["job_ticket_present"] is False,
                        "failure cleanup not verified")
                # A torn trace may omit a receipt: the bounded cleanup was attempted,
                # but complete job cleanup cannot be certified from an incomplete log.
                metadata["cleanup"] = "unknown" if trace_error else "complete"
                if remote and not trace_error:
                    require(actor.json_rpc("finish", {"workspace": str(workspace)}) == {"ok": True},
                            "remote run directory not removed")
            except Exception as exc:
                metadata.update(status="failed", cleanup="error", cleanup_failure_type=type(exc).__name__)
        write_json(output / "run.json", metadata)
    verify_scenario_run(output)
    return metadata

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only verification of a configurable scenario run", allow_abbrev=False)
    parser.add_argument("--run-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        require(args.run_dir.is_absolute(), "absolute run directory required")
        metadata = verify_scenario_run(args.run_dir)
        print(f"PASS {metadata['run_id']}: trace, proofs, job provenance and cleanup verified")
    except (ValueError, OSError, RuntimeError, KeyError, TypeError):
        print("REFUSED: scenario run is not verified", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

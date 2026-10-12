"""Operator-owned scenario plans and SSH role configuration."""

from __future__ import annotations

import copy
import os
from pathlib import Path
import re
import stat
from typing import Any

from validation.contracts import exact_keys, load_json, load_scenario, require, validate_scenario, ensure_redacted

KINDS = {"file.mkdir", "file.write", "file.delete", "file.list", "file.stat", "slurm.submit", "slurm.wait", "env.modules", "slurm.submit-example", "file.tail", "file.copy"}


def relative_path(value: Any) -> str:
    require(isinstance(value, str) and 0 < len(value) <= 200 and not value.startswith("/")
            and all(part not in {"", ".", ".."} for part in value.split("/")), "invalid relative fixture path")
    return value


def load_plan(path: Path) -> tuple[dict, dict]:
    plan = load_json(path)
    exact_keys(plan, {"schema", "scenario", "goal", "execution", "required_actions", "seed_files", "checks"}, "harness plan")
    require(plan["schema"] == "prace.harness-plan.v1", "unsupported harness plan")
    require(isinstance(plan["scenario"], str), "scenario file required")
    scenario_path = Path(plan["scenario"])
    scenario = load_scenario(scenario_path if scenario_path.is_absolute() else path.parent / scenario_path)
    return validate_plan(plan, scenario)


def validate_plan(plan: dict, scenario: dict, *, bound_run_id: str | None = None) -> tuple[dict, dict]:
    exact_keys(plan, {"schema", "scenario", "goal", "execution", "required_actions", "seed_files", "checks"}, "harness plan")
    require(plan["schema"] == "prace.harness-plan.v1", "unsupported harness plan")
    ensure_redacted(plan, scenario, "harness plan")
    require(scenario["status"] == "smoke" and scenario["actor"]["intent"] == "benign" and not scenario["gates"],
            "this runner supports benign smoke plans only; security scenarios require their own reviewed observer")
    require(len(scenario["boundaries"]["paths"]) == 1 and len(scenario["boundaries"]["action_targets"]) == 1
            and len(scenario["boundaries"]["observation_targets"]) == 1, "one workspace and target required")
    require(set(scenario["boundaries"]["action_kinds"]) <= KINDS, "unsupported smoke action kind")
    researcher = scenario["id"] == "researcher-workflow"
    require(1 <= scenario["budgets"]["max_actions"] <= 20 and scenario["budgets"]["max_seconds"] <= (1200 if researcher else 600),
            "smoke run budget limit")
    require(isinstance(plan["goal"], str) and 1 <= len(plan["goal"]) <= 1000, "bounded agent goal required")
    require(plan["execution"] in {"ordered", "discovery"}, "invalid execution mode")
    ids = [action["id"] for action in scenario["actions"]]
    required = plan["required_actions"]
    require(isinstance(required, list) and required and all(isinstance(item, str) for item in required)
            and len(required) == len(set(required)) and set(required) <= set(ids), "invalid completion actions")
    if plan["execution"] == "discovery":
        execution = {"mode": "discovery", "required_actions": list(required)}
        require("execution" not in scenario or scenario["execution"] == execution, "plan/manifest execution mismatch")
        scenario["execution"] = execution
        validate_scenario(scenario)
    else:
        require("execution" not in scenario, "ordered plan cannot use a discovery manifest")
    require(all(item["category"] != "functional" or item["phase"] in {"record", "replay"}
                for item in scenario["assertions"]), "functional checks belong to the two attempts")
    from validation.adapters.researcher_workflow import checked_spec, EXAMPLES, OUTPUT_MARKERS
    captures = {a["capture"].get("job_id") for a in scenario["actions"] if a["kind"] == "slurm.submit-example"}
    require(not captures or (researcher and captures == {"cpu_job_id", "gpu_job_id"}), "two distinct researcher captures required")
    for action in scenario["actions"]:
        params = action["parameters"]
        require(action["timeout_seconds"] <= (1200 if researcher and action["kind"] == "slurm.wait" else 70), "smoke action timeout limit")
        kind = action["kind"]
        expected = {"file.mkdir": {"path", "parents"}, "file.write": {"path", "content"},
                    "file.delete": {"path"}, "file.list": {"path"}, "file.stat": {"path"},
                    "slurm.submit": {"workspace", "run_id", "account", "partition"},
                    "slurm.wait": {"workspace", "run_id", "job_id"},
                    "env.modules": set(), "file.tail": {"path", "lines"}, "file.copy": {"path", "destination"},
                    "slurm.submit-example": {"workspace", "run_id", "account", "partition", "example", "example_sha256", "path", "source_sha256"}}[kind]
        require(set(params) == expected or (kind == "file.mkdir" and set(params) == {"path"}),
                "unsupported action parameters")
        if kind.startswith("file."):
            require(isinstance(params["path"], str) and params["path"].startswith("/"), "literal fixture path required")
        if kind in {"file.tail", "file.copy", "env.modules", "slurm.submit-example"}:
            require(researcher, "researcher operations require the reviewed researcher scenario")
        if kind == "file.tail":
            require(type(params["lines"]) is int and 1 <= params["lines"] <= 8, "bounded output lines required")
        if kind == "file.copy":
            require(isinstance(params["destination"], str) and params["destination"].startswith("/"), "literal copy destination required")
        if kind == "file.write":
            require(isinstance(params["content"], str) and len(params["content"].encode()) <= 4096, "short fixture content required")
        if kind == "file.mkdir" and "parents" in params:
            require(type(params["parents"]) is bool, "parents must be boolean")
        if kind.startswith("slurm."):
            require(params["workspace"] == scenario["boundaries"]["paths"][0] and params["run_id"] == (bound_run_id or "run-placeholder"),
                    "Slurm run/workspace binding must be operator supplied")
            if kind in {"slurm.submit", "slurm.submit-example"}:
                require(params["account"] == scenario["actor"]["project"]
                        and isinstance(params["partition"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,40}", params["partition"]),
                        "smoke job must use the actor project and a declared partition")
                if kind == "slurm.submit-example":
                    checked_spec(params)
                    require(action["capture"] == {"job_id": params["partition"] + "_job_id"}, "researcher receipt capture required")
                else:
                    require(action["capture"] == {"job_id": "smoke_job_id"}, "job ID capture required")
            else:
                require(params["job_id"] in ({"${cpu_job_id}", "${gpu_job_id}"} if researcher else {"${smoke_job_id}"}), "wait requires the submitted job binding")
    jobs = [action for action in scenario["actions"] if action["kind"] in {"slurm.submit", "slurm.submit-example"}]
    require((len(jobs) == 2 and {a["kind"] for a in jobs} == {"slurm.submit-example"}
             and {a["parameters"]["partition"] for a in jobs} == {"cpu", "gpu"}) if researcher else len(jobs) <= 1,
             "bounded declared jobs required")
    seeds = plan["seed_files"]
    require(isinstance(seeds, list) and len(seeds) <= 8, "fixture seed limit")
    for seed in seeds:
        exact_keys(seed, {"path", "content"}, "fixture seed")
        relative_path(seed["path"])
        require(isinstance(seed["content"], str) and len(seed["content"].encode()) <= 4096, "short seed content required")
    require(len({seed["path"] for seed in seeds}) == len(seeds), "duplicate fixture seed")
    checks = plan["checks"]
    require(isinstance(checks, list), "checks required")
    assertions = {item["id"]: item for item in scenario["assertions"]}
    require(len(checks) == len(assertions), "every assertion needs an independent check")
    require(len({item.get("id") for item in checks if isinstance(item, dict)}) == len(checks), "duplicate check")
    for check in checks:
        require(isinstance(check, dict) and check.get("id") in assertions, "undeclared check")
        require(check['id'] not in {'environment','failure-cleanup','run','manifest','plan','agent-trace','result','gateway','nemo-config','driver','bundle',
                                   'nemo-replay-config','nemo-replay-receipt','agent-replay-trace'},
                'check ID conflicts with a runtime or evidence artifact')
        assertion = assertions[check["id"]]
        require(assertion["phase"] in {"record", "replay", "cleanup"}, "unsupported smoke assertion phase")
        if check.get("kind") == "layout":
            exact_keys(check, {"id", "kind", "entries"}, "layout check")
            require(assertion["category"] == "functional", "layout must be a functional check")
            require(isinstance(check["entries"], list) and len(check["entries"]) <= 32, "layout entry limit")
            names = []
            for entry in check["entries"]:
                require(isinstance(entry, dict) and entry.get("kind") in {"file", "directory"}, "invalid expected entry")
                exact_keys(entry, {"path", "kind", "sha256"} if entry["kind"] == "file" else {"path", "kind"}, "expected entry")
                names.append(relative_path(entry["path"]))
                if entry["kind"] == "file":
                    require(isinstance(entry["sha256"], str) and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]), "invalid file digest")
            require(names == sorted(set(names)), "sorted unique layout entries required")
        elif check.get("kind") == "job-completed":
            exact_keys(check, {"id", "kind", "submit_action", "expect"} if researcher else {"id", "kind", "submit_action"}, "job check")
            require(assertion["category"] == "functional" and assertion["phase"] in {"record", "replay"}
                    and jobs and check["submit_action"] in {job["id"] for job in jobs}, "declared job submission required")
            if researcher:
                job = next(j for j in jobs if j["id"] == check["submit_action"])
                part = job["parameters"]["partition"]
                require(check["expect"] == {"partition": part, "cpus": 4, "gpus": int(part == "gpu"),
                        "state": "COMPLETED", "exit_code": "0:0"}, "fixed researcher job expectations required")
        elif check.get("kind") == "output-markers":
            exact_keys(check, {"id", "kind", "directory", "entries"}, "output check")
            require(researcher and assertion["category"] == "functional" and assertion["phase"] in {"record", "replay"}
                    and check["directory"] == "results" and isinstance(check["entries"], list) and len(check["entries"]) == 2,
                    "bounded researcher output check required")
            require([e.get("path") for e in check["entries"]] == ["results/batch.out", "results/gpu.out"], "fixed result files required")
            require(check["entries"] == OUTPUT_MARKERS, "reviewed CPU/GPU success checks required")
            for entry in check["entries"]:
                exact_keys(entry, {"path", "pattern"}, "output marker")
                require(isinstance(entry["pattern"], str) and len(entry["pattern"]) <= 160, "bounded marker required")
                re.compile(entry["pattern"])
        else:
            exact_keys(check, {"id", "kind"}, "cleanup check")
            require(check["kind"] == "workspace-empty" and assertion["category"] == "cleanup"
                    and assertion["phase"] == "cleanup", "independent cleanup check required")
    require(scenario["cleanup"]["required"] is True, "verified cleanup required")
    if jobs:
        require(all(any(check["kind"] == "job-completed" and check["submit_action"] == job["id"]
                        and assertions[check["id"]]["phase"] == phase for check in checks)
                    for phase in ("record", "replay") for job in jobs), "both attempts need job accounting checks")
    if researcher:
        require(all(any(check['kind'] == 'output-markers' and assertions[check['id']]['phase'] == phase
                        for check in checks) for phase in ('record', 'replay')), 'both attempts need CPU/GPU output checks')
    return plan, scenario


def bind_run(template: dict, workspace: Path, run_id: str) -> dict:
    value = copy.deepcopy(template)
    old = Path(value["boundaries"]["paths"][0])
    value["boundaries"]["paths"] = [str(workspace)]
    for action in value["actions"]:
        params = action["parameters"]
        for key in ("path", "workspace", "destination"):
            if key in params:
                params[key] = str(workspace / Path(params[key]).relative_to(old))
        if action["kind"].startswith("slurm."):
            params["run_id"] = run_id
    return validate_scenario(value)


def load_ssh(path: Path, actor: str, *, diagnostic: bool = False) -> dict:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
            "SSH config must be a private caller-owned regular file")
    value = load_json(path)
    exact_keys(value, {"schema", "roles"}, "SSH config")
    require(value["schema"] == "prace.harness-ssh.v1", "unsupported SSH config")
    exact_keys(value["roles"], {"actor"} if diagnostic else {"actor", "tracer", "observer"}, "SSH roles")
    names, aliases, keys = [], [], []
    for row in value["roles"].values():
        exact_keys(row, {"identity", "ssh_alias", "remote_helper", "identity_file", "known_hosts", "connect_timeout"}, "SSH role")
        require(isinstance(row["identity"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", row["identity"]), "invalid SSH identity")
        require(isinstance(row["ssh_alias"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}", row["ssh_alias"]), "invalid SSH alias")
        require(isinstance(row["remote_helper"], str) and row["remote_helper"].startswith("/")
                and re.fullmatch(r"/[A-Za-z0-9_./-]+", row["remote_helper"]), "fixed absolute remote helper required")
        require(type(row["connect_timeout"]) is int and 1 <= row["connect_timeout"] <= 10, "SSH connect limit")
        for key in ("identity_file", "known_hosts"):
            require(isinstance(row[key], str) and Path(row[key]).is_absolute(), "absolute SSH input path required")
            source = Path(row[key])
            require(source.is_file() and not source.is_symlink(), "regular SSH input file required")
            if key == "identity_file":
                require(source.stat().st_uid == os.getuid() and stat.S_IMODE(source.stat().st_mode) == 0o600,
                        "private caller-owned identity file required")
        names.append(row["identity"])
        aliases.append(row["ssh_alias"])
        keys.append(str(Path(row["identity_file"]).resolve()))
    require(all(len(set(items)) == (1 if diagnostic else 3) for items in (names, aliases, keys)), "three distinct SSH identities, aliases and keys required")
    require(value["roles"]["actor"]["identity"] == actor, "SSH actor differs from manifest")
    return value

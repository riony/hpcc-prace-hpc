"""Package/verify a local harness run without copying runtime files or credentials."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
from typing import Any

from validation.contracts import ContractError, load_scenario, require, sha256_json
from validation.report import render_markdown
from validation.trace import read_events
from harness.runner import ACTION_IDS, BAD_CONTENT, GOOD_CONTENT, bind_workspace, verify_attempt, write_json
from harness.nemo_config import NAT_VERSION
from harness.agent_trace import validate_projection

ATTEMPT_FILES = ("manifest.json", "events.jsonl", "result.json", "report.md", "driver.json", "agent-trace.json",
                 "record-layout-ok.json", "replay-layout-ok.json", "workspace-reset.json")
ARTIFACTS = tuple(sorted(("run.json", "template-before.json", "template-after.json", "fix-proposal.json")
                        + tuple(f"{attempt}/{name}" for attempt in ("before", "after") for name in ATTEMPT_FILES)))
MAX_FILE_BYTES = 20 * 1024 * 1024
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
SCENARIO_FILES = ("run.json", "manifest.json", "plan.json", "events.jsonl", "agent-trace.json", "result.json", "report.md")


def read_artifact(root: Path, relative: str, declared=ARTIFACTS) -> bytes:
    require(relative in declared or relative in {"bundle.json", "SHA256SUMS"}, "undeclared artifact")
    root_info = root.lstat()
    require(stat.S_ISDIR(root_info.st_mode), "regular bundle directory required")
    path = root
    for part in Path(relative).parts:
        path /= part
        info = path.lstat()
        require(not stat.S_ISLNK(info.st_mode), "artifact symlink refused")
    require(stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE_BYTES, "unsafe/oversized artifact")
    data = path.read_bytes()
    require(len(data) <= MAX_FILE_BYTES, "artifact grew beyond limit")
    return data


def verify_cycle(root: Path) -> dict[str, Any]:
    """Validate cross-attempt provenance and the one-field fixture correction."""
    metadata = json.loads(read_artifact(root, "run.json"))
    required = {"schema", "run_id", "status", "scope", "source_revision", "source_dirty", "driver",
                "model", "provider", "nemo_version", "llm_used", "fleet_contacted", "slurm_job_ids", "recovery_point", "attempts"}
    require(isinstance(metadata, dict) and set(metadata) == required, "malformed run metadata")
    require(metadata["schema"] == "prace.harness-run.v1" and metadata["status"] == "complete",
            "incomplete harness run")
    require(metadata["scope"] == "local-functional-fixture" and metadata["fleet_contacted"] is False
            and metadata["slurm_job_ids"] == [] and metadata["recovery_point"] is None,
            "local rehearsal cannot claim fleet jobs or recovery")
    require(isinstance(metadata["run_id"], str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", metadata["run_id"]),
            "invalid run ID")
    require(isinstance(metadata["source_revision"], str) and re.fullmatch(r"[0-9a-f]{40}", metadata["source_revision"])
            and type(metadata["source_dirty"]) is bool, "invalid source provenance")
    driver = metadata["driver"]
    require(driver in {"scripted", "opencode", "nemo"} and metadata["llm_used"] is
            (driver == "opencode" or (driver == "nemo" and metadata["model"] is not None)), "invalid driver provenance")
    require((driver == "nemo" and metadata["provider"] in {"nim", "openai"} and metadata["nemo_version"] == NAT_VERSION)
            or (driver != "nemo" and metadata["provider"] is None and metadata["nemo_version"] is None), "invalid NeMo provenance")
    require((driver == "scripted" and metadata["model"] is None)
            or (driver == "opencode" and isinstance(metadata["model"], str)
                and re.fullmatch(r"[A-Za-z0-9_./:-]+", metadata["model"]))
            or (driver == "nemo" and (metadata["model"] is None or (isinstance(metadata["model"], str)
                and re.fullmatch(r"[A-Za-z0-9_./:-]+", metadata["model"])))), "invalid model provenance")
    require(metadata["attempts"] == [{"directory": "before", "functional": "functional_regression"},
                                      {"directory": "after", "functional": "pass"}], "invalid attempt sequence")
    before = load_scenario(root / "template-before.json")
    after = load_scenario(root / "template-after.json")
    require([action["id"] for action in before["actions"]] == ACTION_IDS, "unknown fixture")
    corrected = copy.deepcopy(before)
    require(corrected["actions"][2]["parameters"]["content"] == BAD_CONTENT, "wrong initial fixture")
    corrected["actions"][2]["parameters"]["content"] = GOOD_CONTENT
    require(corrected == after, "fix changes more than the declared fixture field")
    expected_proposal = {"schema": "prace.fixture-fix.v1", "run_id": metadata["run_id"],
                         "kind": "deterministic-fixture-correction", "action_id": "write-test-file-2",
                         "field": "parameters.content", "before": BAD_CONTENT, "after": GOOD_CONTENT,
                         "before_template_sha256": sha256_json(before), "after_template_sha256": sha256_json(after)}
    require(json.loads(read_artifact(root, "fix-proposal.json")) == expected_proposal, "unbound fixture proposal")
    for attempt, template in zip(metadata["attempts"], (before, after)):
        directory = root / attempt["directory"]
        # Read every declared file first to refuse links/oversize inputs even
        # when this function is called before creating an index.
        for name in ATTEMPT_FILES:
            read_artifact(root, f"{attempt['directory']}/{name}")
        scenario = load_scenario(directory / "manifest.json")
        paths = scenario["boundaries"]["paths"]
        require(len(paths) == 1, "one local fixture workspace required")
        require(bind_workspace(template, Path(paths[0])) == scenario, "attempt differs from its template")
        result = verify_attempt(directory, metadata["run_id"], attempt["functional"], metadata["source_revision"])
        events = read_events(directory / "events.jsonl", scenario)
        validate_projection(json.loads(read_artifact(root, f"{attempt['directory']}/agent-trace.json")),
                            metadata["run_id"], driver, metadata["nemo_version"], events)
        require((directory / "report.md").read_text() == render_markdown(scenario, result, events),
                "report contradicts evidence")
        receipt = json.loads(read_artifact(root, f"{attempt['directory']}/driver.json"))
        require(isinstance(receipt, dict) and set(receipt) == {"driver", "returncode", "actions"}
                and receipt["driver"] == driver and type(receipt["returncode"]) is int
                and receipt["returncode"] == 0, "unsuccessful driver receipt")
        recorded = [event for event in events if event["event_type"] == "action" and event["phase"] == "record"]
        summaries = [{"action_id": event["action_id"], "phase": event["phase"], "sequence": event["sequence"],
                      "status": event["result"]["status"]} for event in recorded]
        require(receipt["actions"] == (summaries if driver == "scripted" else []), "driver receipt contradicts actions")
    return metadata


def checksum_text(entries: list[dict[str, Any]]) -> str:
    return "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in entries)


def scenario_artifacts(root: Path) -> tuple[str, ...]:
    from harness.scenario import validate_plan
    metadata = json.loads(read_artifact(root, "run.json", SCENARIO_FILES))
    if metadata.get("schema") == "prace.security-simulation-run.v1":
        from harness.security_simulation import artifacts
        return artifacts(root)
    plan = json.loads(read_artifact(root, "plan.json", SCENARIO_FILES))
    read_artifact(root, "manifest.json", SCENARIO_FILES)
    scenario = load_scenario(root / "manifest.json")
    validate_plan(plan, scenario, bound_run_id=metadata["run_id"])
    snapshots = ()
    if scenario['id'] == 'researcher-workflow':
        snapshots = tuple(f"cluster-snapshot-{event['correlated_action_sequence']}.json"
                          for event in read_events(root / 'events.jsonl', scenario)
                          if event['event_type'] == 'cluster' and event['source'] == 'cluster_tracer')
    if metadata.get('schema') == 'prace.diagnostic-run.v1':
        from harness.diagnostic import FILES
        return tuple(sorted(FILES + snapshots))
    environment = ("environment.json",) if metadata.get("execution_environment") in {"ssh-stand-in", "ssh-unqualified"} else ()
    replay = ("agent-replay-trace.json",) if metadata.get("replay_driver") == "nemo" else ()
    return tuple(sorted(SCENARIO_FILES + snapshots + replay + environment + tuple(check["id"] + ".json" for check in plan["checks"])))


def verify_run(root: Path) -> tuple[dict, tuple[str, ...], str]:
    metadata = json.loads(read_artifact(root, "run.json"))
    require(isinstance(metadata, dict), "malformed run metadata")
    if metadata.get("schema") == "prace.harness-run.v1":
        return verify_cycle(root), ARTIFACTS, "prace.harness-bundle.v1"
    if metadata.get("schema") == "prace.security-simulation-run.v1":
        from harness.security_simulation import artifacts, verify_simulation
        return verify_simulation(root), artifacts(root), "prace.security-simulation-bundle.v1"
    require(metadata.get("schema") in {"prace.scenario-run.v1", "prace.diagnostic-run.v1"}, "unknown run format")
    artifacts = scenario_artifacts(root)
    for name in artifacts:
        read_artifact(root, name, artifacts)
    if metadata['schema'] == 'prace.diagnostic-run.v1':
        from harness.diagnostic import verify_diagnostic
        return verify_diagnostic(root), artifacts, 'prace.diagnostic-bundle.v1'
    from harness.scenario_run import verify_scenario_run
    return verify_scenario_run(root), artifacts, "prace.scenario-bundle.v1"


def package_run(run: Path, destination: Path) -> dict[str, Any]:
    require(run.is_absolute() and destination.is_absolute(), "absolute paths required")
    require(not destination.exists() and not destination.is_symlink(), "new bundle directory required")
    metadata, artifacts, schema = verify_run(run)
    data = {name: read_artifact(run, name, artifacts) for name in artifacts}
    require(sum(len(value) for value in data.values()) <= MAX_BUNDLE_BYTES, "bundle size limit")
    destination.mkdir(mode=0o700, parents=True)
    entries = []
    for name, value in data.items():
        path = destination / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open("xb") as stream:
            path.chmod(0o600)
            stream.write(value)
        entries.append({"path": name, "bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()})
    index = {"schema": schema, "run_id": metadata["run_id"],
             "source_revision": metadata["source_revision"], "scope": metadata["scope"], "artifacts": entries}
    write_json(destination / "bundle.json", index)
    with (destination / "SHA256SUMS").open("x") as stream:
        (destination / "SHA256SUMS").chmod(0o600)
        stream.write(checksum_text(entries))
    try:
        verify_bundle(destination)
    except Exception:
        shutil.rmtree(destination)
        raise
    return index


def verify_bundle(root: Path) -> dict[str, Any]:
    require(root.is_absolute(), "absolute bundle path required")
    index = json.loads(read_artifact(root, "bundle.json"))
    require(isinstance(index, dict) and set(index) == {"schema", "run_id", "source_revision", "scope", "artifacts"}
            and index["schema"] in {"prace.harness-bundle.v1", "prace.scenario-bundle.v1", "prace.diagnostic-bundle.v1",
                                    "prace.security-simulation-bundle.v1"}, "malformed bundle index")
    artifacts = ARTIFACTS if index["schema"] == "prace.harness-bundle.v1" else scenario_artifacts(root)
    entries = index["artifacts"]
    require(isinstance(entries, list) and all(isinstance(entry, dict)
            and set(entry) == {"path", "bytes", "sha256"} for entry in entries), "malformed artifacts")
    require([entry["path"] for entry in entries] == list(artifacts), "missing/extra/unsafe artifact paths")
    total = 0
    for entry in entries:
        value = read_artifact(root, entry["path"], artifacts)
        total += len(value)
        require(type(entry["bytes"]) is int and entry["bytes"] == len(value)
                and entry["sha256"] == hashlib.sha256(value).hexdigest(), "artifact integrity mismatch")
    require(total <= MAX_BUNDLE_BYTES, "bundle size limit")
    actual = {path.relative_to(root).as_posix() for path in root.rglob("*") if not path.is_dir() or path.is_symlink()}
    require(actual == set(artifacts) | {"bundle.json", "SHA256SUMS"}, "undeclared file in bundle")
    require(read_artifact(root, "SHA256SUMS").decode() == checksum_text(entries), "checksum list mismatch")
    metadata, verified_artifacts, schema = verify_run(root)
    require(schema == index["schema"] and artifacts == verified_artifacts, "bundle/run format mismatch")
    require(all(index[key] == metadata[key] for key in ("run_id", "source_revision", "scope")), "bundle/run identity mismatch")
    return metadata


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    sub = parser.add_subparsers(dest="command", required=True)
    pack = sub.add_parser("pack", allow_abbrev=False)
    pack.add_argument("--run-dir", type=Path, required=True)
    pack.add_argument("--output-dir", type=Path, required=True)
    verify = sub.add_parser("verify", allow_abbrev=False)
    verify.add_argument("--bundle-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "pack":
            index = package_run(args.run_dir, args.output_dir)
            print(f"PASS bundle {index['run_id']}: {len(index['artifacts'])} artifacts")
        else:
            metadata = verify_bundle(args.bundle_dir)
            detail = ("integrity, trace, fix and verdicts verified" if metadata["schema"] == "prace.harness-run.v1"
                      else "integrity, trace and verdicts verified")
            if metadata["schema"] == "prace.diagnostic-run.v1":
                detail = "trace and artifact integrity checked; independent verification SKIPPED; overall UNVERIFIED"
            print(f"PASS bundle {metadata['run_id']}: {detail}")
    except (ContractError, OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        print(f"REFUSED: {type(exc).__name__}; bundle is not verified", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

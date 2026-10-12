#!/usr/bin/env python3
"""Run the ACL scenario in a disposable, networkless container and retain its evidence.

The container has read-only code, private writable tmpfs and no writable host
mount. Numeric users exercise real kernel ACLs. The default contacts neither
the fleet nor a model endpoint. --model enables a future inference connection;
replay always runs without a model.
"""
from __future__ import annotations
import argparse
import base64
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from validation.contracts import ContractError, require
from harness.security_simulation import verify_simulation
from harness.evidence import package_run


def command(driver, nat_python, revision, dirty, model=None):
    require(model is None or (driver == "nemo" and re.fullmatch(r"[A-Za-z0-9_./:-]{1,128}", model)), "invalid serving model ID")
    if model:
        from urllib.parse import urlsplit
        endpoint = urlsplit(os.environ.get("PRACE_MODEL_BASE_URL", ""))
        require(endpoint.scheme in {"http", "https"} and endpoint.hostname and not endpoint.username
                and not endpoint.password and not endpoint.query and not endpoint.fragment
                and os.environ.get("OPENAI_API_KEY"), "model endpoint and credential environment required")
    args = ["docker", "run", "--rm", "--pull=never", "--network", "bridge" if model else "none", "--read-only",
            "--pids-limit", "96", "--memory", "2g", "--cpus", "2", "--cap-drop", "ALL"]
    for cap in ("CHOWN", "SETUID", "SETGID", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL"):
        args += ["--cap-add", cap]
    args += ["--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=256m",
             "--mount", f"type=bind,src={ROOT},dst=/work,readonly", "-w", "/work",
             "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONPATH=/work"]
    if model:
        # Docker inherits values from the environment; no credentials in argv,
        # config files, retained metadata, exports or shell command text.
        args += ["-e", "PRACE_MODEL_BASE_URL", "-e", "OPENAI_API_KEY"]
    executable = "python3"
    if driver == "nemo":
        require(nat_python and Path(nat_python).is_absolute(), "--nat-python needs an absolute NeMo venv interpreter")
        path = Path(nat_python)
        venv = path.parent.parent.resolve()
        require((venv / "pyvenv.cfg").is_file(), "NeMo virtual environment required")
        runtime = path.resolve().parent.parent
        home = next(line.split("=", 1)[1].strip() for line in (venv / "pyvenv.cfg").read_text().splitlines()
                    if line.startswith("home ="))
        runtime_alias = Path(home).parent
        for source, destination in ((venv, venv), (runtime, runtime_alias)):
            args += ["--mount", f"type=bind,src={source},dst={destination},readonly"]
        executable = str(path)
    args += ["python:3.12-slim", executable, "-m", "harness.security_simulation",
             "--output-dir", "/tmp/retained-run", "--source-revision", revision, "--driver", driver, "--emit-files"]
    if dirty:
        args += ["--source-dirty"]
    if driver == "nemo":
        args += ["--nat-python", executable]
    if model:
        args += ["--model", model]
    return args


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--driver", choices=["scripted", "nemo"], default="nemo")
    parser.add_argument("--nat-python")
    parser.add_argument("--scenario", choices=["write", "read"], default="write")
    parser.add_argument("--model", help="future OpenAI-compatible serving model ID; omitted for model-free rehearsal")
    args = parser.parse_args(argv)
    try:
        require(args.output_dir.is_absolute() and args.bundle_dir.is_absolute()
                and not args.output_dir.exists() and not args.output_dir.is_symlink()
                and not args.bundle_dir.exists() and not args.bundle_dir.is_symlink(), "new absolute evidence directories required")
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
        dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip())
        invocation = command(args.driver, args.nat_python, revision, dirty, args.model) + ["--run-id", args.run_id, "--scenario", args.scenario]
        container_name = "prace-acl-" + uuid.uuid4().hex
        invocation[2:2] = ["--name", container_name]
        try:
            outcome = subprocess.run(invocation, capture_output=True, timeout=360)
        finally:
            # Bound cleanup to this invocation's unique container, including a
            # client timeout. No other container or operational lease is touched.
            subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, timeout=20)
        require(outcome.stdout, "container could not produce evidence")
        require(len(outcome.stdout) <= 96 * 1024 * 1024, "retained evidence size limit")
        envelope = json.loads(outcome.stdout)
        require(set(envelope) == {"metadata", "files", "error"} and isinstance(envelope["files"], dict)
                and len(envelope["files"]) <= 32, "malformed retained evidence")
        os.umask(0o077); args.output_dir.mkdir(mode=0o700, parents=True)
        for name, value in envelope["files"].items():
            require(isinstance(name, str) and Path(name).name == name and name not in {".", ".."}, "unsafe artifact name")
            raw = base64.b64decode(value, validate=True)
            require(len(raw) <= 20 * 1024 * 1024, "artifact size limit")
            with (args.output_dir / name).open("xb") as stream:
                stream.write(raw)
        if outcome.returncode != 0 or envelope["error"] is not None:
            with (args.output_dir / "FAILED.json").open("x") as stream:
                json.dump({"status": "failed", "run_id": args.run_id, "error": envelope["error"]}, stream)
            raise ContractError(f"scenario failed; private partial evidence retained at {args.output_dir}; no bundle created")
        meta = verify_simulation(args.output_dir)
        require(meta == envelope["metadata"] and meta["run_id"] == args.run_id
                and meta["source_revision"] == revision and meta["source_dirty"] is dirty, "container provenance mismatch")
        package_run(args.output_dir, args.bundle_dir)
        print(f"PASS {args.run_id}: unauthorized {args.scenario} recorded; repaired replay denied; legitimate writes pass; fixture reset/discarded")
        print(f"Private run: {args.output_dir}\nVerified bundle: {args.bundle_dir}")
        return 0
    except (ContractError, OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())

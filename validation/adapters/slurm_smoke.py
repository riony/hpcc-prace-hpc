"""One fixed, short Slurm job per run workspace; no agent-supplied program."""

from __future__ import annotations

import json
import datetime
import hashlib
import os
from pathlib import Path
import pwd
import re
import shlex
import stat
import subprocess
import time

NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
JOB = re.compile(r"[1-9][0-9]{0,11}")
TERMINAL = {"COMPLETED", "FAILED", "CANCELLED", "TIMEOUT", "OUT_OF_MEMORY", "NODE_FAIL", "PREEMPTED",
            "BOOT_FAIL", "DEADLINE", "REVOKED"}


def job_name(run_id: str) -> str:
    return "prace-smoke-" + run_id


def submission_argv(params: dict) -> list[str]:
    return ["sbatch", "--parsable", "--account=" + params["account"],
            "--partition=" + params["partition"], "--comment=prace:" + params["run_id"],
            "--job-name=" + job_name(params["run_id"]), "--nodes=1", "--ntasks=1", "--cpus-per-task=1",
            "--mem=32M", "--time=00:01:00", "--output=/dev/null", "--error=/dev/null", "--wrap=/bin/true"]


def fixed_job_fields(params: dict) -> dict:
    return {key: params[key] for key in ("job_id", "actor", "account", "partition", "run_id")} | {
        "job_name": job_name(params["run_id"]), "requested_cpus": 1, "requested_nodes": 1, "requested_memory_mb": 32,
        "time_limit_minutes": 1,
        "submission_sha256": hashlib.sha256(json.dumps(submission_argv(params),
            separators=(",", ":")).encode()).hexdigest()}


TOOL_DIRS = ("/usr/bin", "/bin", "/usr/local/bin", "/opt/slurm/bin", "/opt/ohpc/pub/bin")


class CommandRefused(ValueError):
    def __init__(self, receipt: str | None = None):
        super().__init__("Slurm query/command failed")
        self.receipt = receipt


def tool_path(name: str) -> str:
    if name not in {"sbatch", "sacct", "squeue", "scancel"}:
        raise ValueError("unsupported Slurm executable")
    for folder in TOOL_DIRS:
        candidate = Path(folder) / name
        if not candidate.is_file():
            continue
        candidate = candidate.resolve(strict=True)
        for path in (candidate, *candidate.parents):
            info = path.stat()
            if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
                raise ValueError("Slurm executable/path is not operator-owned")
        if not os.access(candidate, os.X_OK):
            raise ValueError("Slurm executable is not executable")
        return str(candidate)
    raise ValueError("reviewed Slurm executable unavailable")


def command(args: list[str]) -> str:
    # Ignore shell-startup PATH, Python and Slurm overrides from the actor.
    executable = tool_path(args[0])
    done = subprocess.run([executable, *args[1:]], capture_output=True, timeout=5, check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC",
             "SLURM_TIME_FORMAT": "%Y-%m-%dT%H:%M:%S"})
    if done.returncode != 0 or done.stderr or len(done.stdout) > 32768:
        receipt = None
        if args[0] == "sbatch" and len(done.stdout) <= 256:
            text = done.stdout.decode("utf-8", errors="replace").strip()
            if re.fullmatch(r"[1-9][0-9]{0,11}(;[A-Za-z0-9_.-]+)?", text):
                receipt = text.split(";")[0]
        # A diagnostic remains a failure, but retain a valid job receipt for
        # fixed-job reconciliation and verified cleanup rather than losing it.
        raise CommandRefused(receipt)
    return done.stdout.decode("utf-8").strip()


def preflight(params: dict) -> dict:
    validate_names(params, {"workspace", "run_id", "account", "partition", "actor"})
    # Exact name filter, all retained accounting, and active queue observation.
    # A reused run ID is refused before any workspace or job is created.
    previous = command(["sacct", "-n", "-P", "-X", "-u", params["actor"],
                        "--name=" + job_name(params["run_id"]), "--starttime=1970-01-01",
                        "--format", "JobIDRaw,JobName%160"])
    if previous:
        raise ValueError("run ID already present in accounting")
    for line in command(["squeue", "-h", "-u", params["actor"], "-o", "%A|%j"]).splitlines():
        parts = line.split("|")
        if len(parts) != 2 or not JOB.fullmatch(parts[0]):
            raise ValueError("invalid preflight queue observation")
        if parts[1] == job_name(params["run_id"]):
            raise ValueError("run ID already present in queue")
    return {"ok": True, "started_epoch": int(time.time())}


def ticket_path(workspace: Path) -> Path:
    # Outside the action boundary: a file action cannot edit the job ticket.
    return workspace.parent / "slurm-ticket.json"


def validate_names(params: dict, keys: set[str]) -> None:
    if set(params) != keys:
        raise ValueError("invalid Slurm smoke parameters")
    for key in keys - {"workspace", "job_id", "started_epoch"}:
        if not isinstance(params[key], str) or not NAME.fullmatch(params[key]):
            raise ValueError("invalid Slurm name")
    if "started_epoch" in keys and (type(params["started_epoch"]) is not int or params["started_epoch"] <= 0):
        raise ValueError("invalid run start time")
    if "job_id" in keys and (not isinstance(params["job_id"], str) or not JOB.fullmatch(params["job_id"])):
        raise ValueError("invalid Slurm job ID")


def job_proof(params: dict) -> dict:
    validate_names(params, {"workspace", "job_id", "run_id", "account", "partition", "actor", "started_epoch"})
    text = command(["sacct", "-n", "-P", "-X", "-j", params["job_id"], "--format",
                    "JobIDRaw,User%128,Account%128,Partition%128,State%32,ExitCode,JobName%160,"
                    "ReqCPUS,ReqMem,TimelimitRaw,SubmitLine%2048,NNodes,Submit"])
    rows = [line.split("|") for line in text.splitlines() if line]
    if len(rows) != 1 or len(rows[0]) != 13:
        raise ValueError("missing/ambiguous accounting record")
    job, actor, account, partition, state, code, name, cpus, memory, minutes, submitted, nodes, submit_time = rows[0]
    if (job, actor, account, partition, name) != (params["job_id"], params["actor"],
            params["account"], params["partition"], job_name(params["run_id"])):
        raise ValueError("accounting identity/run mismatch")
    # AccountingStoreFlags=job_comment is unnecessary. JobName, requested
    # resources and the full SubmitLine must identify this fixed /bin/true job.
    argv = shlex.split(submitted)
    if not argv or Path(argv[0]).name != "sbatch" or ["sbatch", *argv[1:]] != submission_argv(params):
        raise ValueError("accounting submission differs from fixed smoke job")
    if cpus != "1" or memory not in {"32M", "32Mn"} or minutes != "1" or nodes != "1":
        raise ValueError("accounting resources differ from fixed smoke job")
    if not state or not re.fullmatch(r"[0-9]+:[0-9]+", code):
        raise ValueError("invalid accounting state/exit code")
    try:
        submit_epoch = int(datetime.datetime.strptime(submit_time, "%Y-%m-%dT%H:%M:%S").replace(
            tzinfo=datetime.timezone.utc).timestamp())
    except ValueError as exc:
        raise ValueError("invalid accounting submit time") from exc
    if submit_epoch < params["started_epoch"]:
        raise ValueError("job predates this run")
    return {**fixed_job_fields(params), "submit_epoch": submit_epoch, "state": state.split()[0].split("+")[0], "exit_code": code}


def read_ticket(workspace: Path) -> dict | None:
    path = ticket_path(workspace)
    if not path.exists():
        return None
    if path.is_symlink() or path.stat().st_size > 4096 or path.stat().st_uid != os.getuid():
        raise ValueError("invalid job ticket")
    value = json.loads(path.read_text())
    validate_names({key: value[key] for key in ("run_id", "account", "partition", "actor")},
                   {"run_id", "account", "partition", "actor"})
    if value["actor"] != pwd.getpwuid(os.getuid()).pw_name:
        raise ValueError("job ticket belongs to another actor")
    return value


def submit(workspace: Path, params: dict) -> dict[str, str]:
    validate_names(params, {"workspace", "run_id", "account", "partition"})
    actor = pwd.getpwuid(os.getuid()).pw_name
    ticket = {**params, "actor": actor, "job_id": None, "started_epoch": int(time.time())}
    path = ticket_path(workspace)
    # Record before submission. Without a receipt, an uncertain outcome stays
    # for operator reconciliation; cleanup must not guess an unrelated job.
    with path.open("x") as stream:
        path.chmod(0o600)
        json.dump(ticket, stream)
    try:
        output = command(submission_argv(params))
    except CommandRefused as exc:
        if exc.receipt is not None:
            ticket["job_id"] = exc.receipt
            path.write_text(json.dumps(ticket))
        raise
    job = output.split(";")[0]
    if not JOB.fullmatch(job):
        raise ValueError("invalid submission receipt")
    ticket["job_id"] = job
    path.write_text(json.dumps(ticket))
    return {"job_id": job}


def wait(workspace: Path, params: dict) -> dict[str, str]:
    validate_names(params, {"workspace", "job_id", "run_id"})
    ticket = read_ticket(workspace)
    if ticket is None or ticket["job_id"] != params["job_id"] or ticket["run_id"] != params["run_id"]:
        raise ValueError("job not submitted by this run")
    expected = {key: ticket[key] for key in ("workspace", "job_id", "run_id", "account", "partition", "actor", "started_epoch")}
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        try:
            proof = job_proof(expected)
        except ValueError:
            # Accounting may not have loaded the new job yet. This never
            # becomes a PASS: the observer still needs one exact final record.
            time.sleep(1)
            continue
        if proof["state"] in TERMINAL:
            if proof["state"] != "COMPLETED" or proof["exit_code"] != "0:0":
                raise ValueError("smoke job did not complete successfully")
            return {"job_state": "COMPLETED"}
        time.sleep(1)
    raise ValueError("smoke job deadline")


def cleanup(workspace: Path) -> None:
    ticket = read_ticket(workspace)
    if ticket is None:
        return
    if ticket["job_id"] is None:
        raise ValueError("submission outcome unknown; operator reconciliation required")
    text = command(["squeue", "-h", "-u", str(os.getuid()), "-o", "%A|%j"])
    jobs = []
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) != 2 or not JOB.fullmatch(parts[0]):
            raise ValueError("invalid queue observation")
        if parts[1] == job_name(ticket["run_id"]):
            jobs.append(parts[0])
    if len(jobs) > 1 or (jobs and jobs != [ticket["job_id"]]):
        raise ValueError("ambiguous run jobs; operator cleanup required")
    for job in jobs:
        command(["scancel", job])
    deadline = time.monotonic() + 10
    while True:
        remaining = command(["squeue", "-h", "-u", str(os.getuid()), "-o", "%A|%j"])
        if not any(line.endswith("|" + job_name(ticket["run_id"])) for line in remaining.splitlines()):
            break
        if time.monotonic() >= deadline:
            raise ValueError("job cleanup not complete")
        time.sleep(1)
    # Do not unlink a known ticket if terminal accounting is unavailable.
    if ticket["job_id"]:
        proof = job_proof({key: ticket[key] for key in
                          ("workspace", "job_id", "run_id", "account", "partition", "actor", "started_epoch")})
        if proof["state"] not in TERMINAL:
            raise ValueError("terminal job cleanup not verified")
    ticket_path(workspace).unlink()


def cleanup_proof(params: dict) -> dict:
    """Observer's own queue/accounting queries; never an actor ticket's claim."""
    ids = params.get("job_ids")
    if not isinstance(ids, list) or len(ids) > 2 or len(set(ids)) != len(ids):
        raise ValueError("invalid cleanup job IDs")
    validate_names({key: value for key, value in params.items() if key != "job_ids"},
                   {"workspace", "run_id", "account", "partition", "actor", "started_epoch"})
    if any(not isinstance(job, str) or not JOB.fullmatch(job) for job in ids):
        raise ValueError("invalid cleanup job ID")
    active = []
    for line in command(["squeue", "-h", "-u", params["actor"], "-o", "%A|%j"]).splitlines():
        parts = line.split("|")
        if len(parts) != 2 or not JOB.fullmatch(parts[0]):
            raise ValueError("invalid independent queue observation")
        if parts[0] in ids or parts[1] == job_name(params["run_id"]):
            active.append(parts[0])
    jobs = [job_proof({key: value for key, value in params.items() if key != "job_ids"} | {"job_id": job}) for job in ids]
    if active or any(row["state"] not in TERMINAL for row in jobs):
        raise ValueError("independent job cleanup not complete")
    return {"active_job_ids": active, "jobs": jobs}

"""Bounded SSH adapter for declared file.mkdir / file.write / file.delete only."""

from __future__ import annotations

import json
from pathlib import Path
import shlex
import subprocess
import time
from typing import Any

from validation.contracts import require
from validation.replay import AdapterResult


class SshRemoteAdapter:
    """Execute only scenario-declared file ops through a pinned remote helper.

    Never accepts free-form shell. Credentials and host aliases come from the
    local tracer config, not from the agent.
    """

    ALLOWED = {"file.mkdir", "file.write", "file.delete", "file.list", "file.stat", "slurm.submit", "slurm.wait", "slurm.submit-example", "env.modules", "file.tail", "file.copy"}

    def __init__(
        self,
        *,
        ssh_alias: str,
        remote_helper: str = "prace-file-ops",
        identity_file: str | None = None,
        known_hosts: str | None = None,
        connect_timeout: int = 10,
    ):
        require(isinstance(ssh_alias, str) and ssh_alias and " " not in ssh_alias,
                "ssh_alias must be a single token")
        require(isinstance(remote_helper, str) and remote_helper, "remote_helper must be a path or command")
        self.ssh_alias = ssh_alias
        self.remote_helper = remote_helper
        self.identity_file = identity_file
        self.known_hosts = known_hosts
        self.connect_timeout = connect_timeout

    def _ssh_base(self) -> list[str]:
        command = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", f"ConnectTimeout={self.connect_timeout}",
            "-o", "StrictHostKeyChecking=yes",
            "-o", "IgnoreUnknown=WarnWeakCrypto",
            "-o", "WarnWeakCrypto=no-pq-kex",
        ]
        if self.known_hosts:
            command.extend(["-o", f"UserKnownHostsFile={self.known_hosts}"])
        if self.identity_file:
            command.extend(["-i", self.identity_file, "-o", "IdentitiesOnly=yes"])
        command.append(self.ssh_alias)
        return command

    def _rpc(self, operation: str, parameters: dict[str, Any], timeout_seconds: int):
        # ssh joins remote argv into a shell command. Only the fixed helper and
        # mode go there; paths and contents stay in a JSON payload on stdin.
        command = self._ssh_base() + [shlex.join([self.remote_helper, "rpc"])]
        payload = json.dumps({"operation": operation, "parameters": parameters}).encode()
        return subprocess.run(command, input=payload, capture_output=True,
                              timeout=timeout_seconds, check=False)

    def execute(self, action_id: str, action: dict[str, Any], timeout_seconds: int) -> AdapterResult:
        del action_id
        started = time.monotonic()
        kind = action["kind"]
        if kind not in self.ALLOWED:
            return AdapterResult("refused", None, stderr=b"unsupported action kind")
        parameters = action["parameters"]
        if kind == "file.write":
            content = parameters["content"]
            require(isinstance(content, str) and len(content.encode()) <= 4096, "content too large")
        try:
            completed = self._rpc(kind, parameters, timeout_seconds)
        except subprocess.TimeoutExpired:
            return AdapterResult("timeout", None, duration_ms=int((time.monotonic() - started) * 1000))
        except OSError as exc:
            return AdapterResult("error", None, stderr=str(exc).encode()[:256],
                                 duration_ms=int((time.monotonic() - started) * 1000))
        status = "ok" if completed.returncode == 0 else "error"
        if completed.returncode == 13:
            status = "denied"
        outputs = {}
        if (status == "ok" and kind in {"file.list", "file.stat", "slurm.submit", "slurm.wait", "slurm.submit-example", "env.modules", "file.tail"}) or (kind in {"slurm.submit", "slurm.submit-example"} and completed.stdout):
            try:
                payload = json.loads(completed.stdout)
                require(isinstance(payload, dict) and set(payload) == {"outputs"}
                        and isinstance(payload["outputs"], dict)
                        and all(isinstance(key, str) and isinstance(value, str)
                                for key, value in payload["outputs"].items()), "invalid helper outputs")
                outputs = payload["outputs"]
                if status != "ok":
                    require(set(outputs) == {"job_id"} and __import__('re').fullmatch(r'[1-9][0-9]{0,11}', outputs['job_id']),
                            "invalid failed submission receipt")
            except (ValueError, UnicodeError):
                return AdapterResult("error", None, stderr=b"invalid helper outputs")
        return AdapterResult(
            status,
            completed.returncode,
            completed.stdout[:65536],
            completed.stderr[:65536],
            outputs,
            int((time.monotonic() - started) * 1000),
        )

    def json_rpc(self, operation: str, parameters: dict[str, Any], timeout: int | None = None) -> dict[str, Any]:
        # jobs-clean executes squeue and two bounded sacct calls (5 s each).
        # Leave room for connection setup and helper startup as well.
        if timeout is None:
            timeout = self.connect_timeout + (35 if operation == 'researcher-clean' else 25 if operation == 'jobs-clean' else 10)
        completed = self._rpc(operation, parameters, timeout)
        require(completed.returncode == 0 and not completed.stderr and len(completed.stdout) <= 32768,
                "remote inspection/ownership operation failed")
        payload = json.loads(completed.stdout)
        require(isinstance(payload, dict), "remote helper returned invalid JSON")
        return payload

    def inventory_workspace(self, workspace: Path) -> dict[str, Any]:
        return self.json_rpc("inventory", {"workspace": str(workspace)})

    def reset_workspace(self, workspace: Path) -> None:
        try:
            completed = self._rpc("reset", {"workspace": str(workspace)}, self.connect_timeout + 55)
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise RuntimeError("remote workspace reset failed") from exc
        require(completed.returncode == 0, "remote workspace reset failed")
        try:
            payload = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("remote reset returned invalid JSON") from exc
        require(isinstance(payload, dict) and payload.get("ok") is True,
                "remote workspace reset was not verified")

    def observe_workspace(self, workspace: Path) -> tuple[bool, str, bytes]:
        """Read-only cluster-tracer observe via the pinned remote helper."""
        workspace = Path(workspace)
        try:
            completed = self._rpc("observe", {"workspace": str(workspace)}, self.connect_timeout + 15)
        except subprocess.TimeoutExpired as exc:
            detail = "cluster tracer observe timeout"
            return False, detail, detail.encode()
        except OSError as exc:
            detail = f"cluster tracer observe error: {exc}"
            return False, detail[:300], detail.encode()[:256]
        if completed.returncode != 0:
            detail = (completed.stderr or completed.stdout or b"observe failed").decode(errors="replace")[:300]
            return False, detail, detail.encode()
        try:
            payload = json.loads(completed.stdout.decode())
        except (UnicodeDecodeError, json.JSONDecodeError):
            detail = "cluster tracer observe returned invalid json"
            return False, detail, completed.stdout[:4096]
        if not isinstance(payload, dict) or type(payload.get("ok")) is not bool:
            return False, "cluster tracer observe returned invalid result", completed.stdout[:4096]
        ok = payload["ok"]
        detail = str(payload.get("detail", ""))[:300]
        evidence = str(payload.get("evidence", "")).encode()
        return ok, detail, evidence

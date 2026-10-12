"""Single-threaded local security gateway; no operator methods in its protocol."""
import json
import os
from pathlib import Path
import socket
import sys

from harness.security_simulation import ACTOR, NEMO_UID, NEMO_GID
from validation.contracts import ContractError, require
from validation.data_read import ReadActorAdapter
from validation.data_write import FixtureActorAdapter
from validation.tracer.protocol import decode_line, encode
from validation.tracer.service import TracerService


def serve(config):
    require(Path("/.dockerenv").is_file() and os.geteuid() == 0, "disposable container required")
    os.umask(0o077)
    values = json.loads(Path(config).read_text())
    require(values["phase"] in {"attack", "replay"}, "invalid gateway phase")
    adapter = (ReadActorAdapter if values["read"] else FixtureActorAdapter)(Path(values["local_root"]), ACTOR)
    service = TracerService(scenario=values["scenario"], run_dir=Path(values["run_dir"]),
                            run_id=values["run_id"], adapter=adapter, workspace=adapter.local_root)
    allowed = {"ping", "catalog", "execute_action"} if values["phase"] == "attack" else {"ping", "replay_next"}
    path = Path(values["socket"])
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path)); os.chown(path, NEMO_UID, NEMO_GID); path.chmod(0o600); server.listen(4)
    while True:
        conn, _ = server.accept()
        with conn:
            conn.settimeout(2)
            try:
                raw = b""
                while not raw.endswith(b"\n"):
                    block = conn.recv(65536)
                    require(block, "truncated gateway request")
                    raw += block
                    require(len(raw) <= 65536, "gateway request limit")
                request = decode_line(raw)
                require(request.get("method") in allowed, "operator method unavailable to actor")
                if request["method"] == "execute_action":
                    require(request.get("phase") == "attack", "actor phase refused")
                response = service.handle(request)
            except (ContractError, OSError, ValueError) as exc:
                response = {"ok": False, "error": str(exc)}
            except Exception as exc:
                # Retain a bounded diagnosis without serializing model input,
                # private configuration, credentials or an exception payload.
                response = {"ok": False, "error": "gateway internal error: " + type(exc).__name__}
            conn.sendall(encode(response))


if __name__ == "__main__":
    serve(sys.argv[1])

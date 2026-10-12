"""Client for the local Unix-domain tracer/gateway service."""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

from .protocol import decode_line, encode


class TracerClient:
    def __init__(self, socket_path: Path, timeout_seconds: float = 30.0):
        self.socket_path = Path(socket_path)
        self.timeout_seconds = timeout_seconds

    def call(self, method: str, **params: Any) -> dict[str, Any]:
        payload = {"method": method, **params}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout_seconds)
            sock.connect(str(self.socket_path))
            sock.sendall(encode(payload))
            sock.shutdown(socket.SHUT_WR)
            chunks: list[bytes] = []
            while True:
                block = sock.recv(65536)
                if not block:
                    break
                chunks.append(block)
        raw = b"".join(chunks)
        if not raw.endswith(b"\n"):
            raise RuntimeError("tracer response was not a complete JSON line")
        return decode_line(raw.splitlines()[-1])

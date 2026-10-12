"""JSON-line protocol for the single local tracer/gateway service."""

from __future__ import annotations

import json
from typing import Any


PROTOCOL_VERSION = 1
METHODS = {
    "ping",
    "status",
    "execute_action",
    "append_cluster",
    "append_observation",
    "reset_workspace",
    "replay",
    "finalize",
}


def encode(message: dict[str, Any]) -> bytes:
    return (json.dumps(message, sort_keys=True, separators=(",", ":")) + "\n").encode()


def decode_line(raw: bytes) -> dict[str, Any]:
    return json.loads(raw.decode())


def ok(request_id: str | None = None, **payload: Any) -> dict[str, Any]:
    body = {"ok": True, "protocol": PROTOCOL_VERSION}
    if request_id is not None:
        body["request_id"] = request_id
    body.update(payload)
    return body


def err(message: str, request_id: str | None = None, **payload: Any) -> dict[str, Any]:
    body = {"ok": False, "protocol": PROTOCOL_VERSION, "error": message}
    if request_id is not None:
        body["request_id"] = request_id
    body.update(payload)
    return body

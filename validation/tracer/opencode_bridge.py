#!/usr/bin/env python3
"""Bridge OpenCode custom tool calls to the local tracer socket."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from validation.tracer.client import TracerClient


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: opencode_bridge.py SOCKET ACTION_ID", file=sys.stderr)
        return 2
    socket_path = Path(argv[1])
    action_id = argv[2]
    if not socket_path.is_absolute():
        print("socket_path must be absolute", file=sys.stderr)
        return 2
    response = TracerClient(socket_path).call("execute_action", action_id=action_id, phase="record")
    if not response.get("ok"):
        print(response.get("error", "execute_action failed"), file=sys.stderr)
        return 1
    event = response["event"]
    print(json.dumps({
        "action_id": event["action_id"],
        "sequence": event["sequence"],
        "status": event["result"]["status"],
        "phase": event["phase"],
    }, sort_keys=True))
    # A successful RPC can still contain a failed/denied action. The agent tool
    # must surface that failure instead of returning a successful process exit.
    return 0 if event["result"]["status"] == "ok" and event["result"]["exit_code"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

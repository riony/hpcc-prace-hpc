"""Thin local client for the NeMo session service (`nat serve` with harness/examples/nat-session.yml).

Standard library only. It starts a session, shows its progress (gateway actions, observer checks, NeMo
tool calls and replay steps), and exports the verified result as a dashboard evidence folder, with an
optional private dashboard preview. It never chooses actions, never retries a start, and only talks
to a loopback URL (reach a remote service through an authenticated tunnel, which is also loopback).

  python3 -m harness.session_client start researcher-session-003
  python3 -m harness.session_client watch researcher-session-003      # after a disconnect
  python3 -m harness.session_client status [RUN_ID]
  python3 -m harness.session_client export researcher-session-003 [--preview ~/prace-dash-session]
  python3 -m harness.session_client resolve RUN_ID --run-root /private/root --note "what was reconciled"

Exit codes: 0 complete, 1 failed, 2 refused before starting, 3 uncertain (interrupted, or the outcome
is not known: inspect with `status`, reconcile, then `resolve`), 130 client interrupted (the session
continues on the service).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_URL = "http://127.0.0.1:8000"
TERMINAL = {"complete", "failed", "interrupted"}


class Refused(Exception):
    pass


class Uncertain(Exception):
    """The service cannot establish the session's outcome."""


def loopback(url: str) -> str:
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or ""
    try:
        local = host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        local = False
    if parts.scheme != "http" or not local or parts.path not in {"", "/"} or parts.query or parts.username:
        raise Refused("the session service URL must be http://127.0.0.1:<port> (use an authenticated tunnel "
                      "for a remote service; its API authentication is not qualified)")
    return f"http://{parts.netloc}"


class Service:
    def __init__(self, url: str, timeout: float = 30):
        self.url = loopback(url)
        self.timeout = timeout

    def call(self, path: str, value: dict, timeout: float | None = None) -> dict:
        body = json.dumps({"input_message": json.dumps(value)}).encode()
        request = urllib.request.Request(self.url + path, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
            return json.loads(json.load(response)["value"])

    def status(self, run_id: str | None = None) -> dict:
        return self.call("/prace/status", {"run_id": run_id})

    def start(self, run_id: str, timeout: float) -> dict:
        return self.call("/generate", {"run_id": run_id}, timeout)

    def export(self, run_id: str) -> dict:
        return self.call("/prace/export", {"run_id": run_id}, 600)


def http_detail(error: urllib.error.HTTPError) -> str:
    try:
        text = error.read(4096).decode("utf-8", "replace")
        value = json.loads(text)
        return str(value.get("message") or value.get("detail") or value.get("error") or text)[:500]
    except (ValueError, OSError, AttributeError):
        return f"HTTP {error.code}"
    finally:
        error.close()


class Printer:
    """prints each new action, check and stage once"""

    def __init__(self, out=None):
        self.out, self.actions, self.checks, self.stage, self.tools, self.steps = out, 0, 0, None, 0, 0

    def line(self, text: str) -> None:
        print(time.strftime("%H:%M:%S ") + text, file=self.out or sys.stdout, flush=True)

    def update(self, state: dict) -> None:
        final = state.get("stage") in TERMINAL
        if state.get("stage") != self.stage and not final:
            self.stage = state.get("stage")
            self.line(f"stage: {self.stage}")
        for row in state.get("actions", [])[self.actions:]:
            jobs = " ".join(f"{k}={v}" for k, v in sorted((row.get("jobs") or {}).items()))
            self.line(f"  {row.get('phase'):7} #{row.get('sequence')} {row.get('action_id')}: {row.get('status')}"
                      f" (exit {row.get('exit_code')}){' ' + jobs if jobs else ''}")
        self.actions = max(self.actions, len(state.get("actions", [])))
        for row in state.get("checks", [])[self.checks:]:
            self.line(f"  check   {row.get('check_id')} ({row.get('phase')}): {row.get('status')}")
        self.checks = max(self.checks, len(state.get("checks", [])))
        tools, steps = state.get("agent_tool_calls", 0), state.get("replay_steps", 0)
        if tools != self.tools or steps != self.steps:
            self.tools, self.steps = tools, steps
            self.line(f"  NeMo: {tools} agent tool call(s), {steps} replay step(s)")
        if final and state.get("stage") != self.stage:
            self.stage = state.get("stage")
            self.line(f"stage: {self.stage}")


def summary(state: dict, out=None) -> int:
    out = out or sys.stdout
    receipt = state.get("receipt") or {}
    if state["state"] == "complete":
        print(f"COMPLETE {state['run_id']}: cleanup {receipt.get('cleanup')}, jobs {receipt.get('slurm_job_ids') or 'none'}, "
              f"model used {receipt.get('llm_used')}, replay model used {receipt.get('replay_llm_used')}, "
              f"bundle {str(receipt.get('bundle_sha256'))[:12]}", file=out)
        print(f"Next: python3 -m harness.session_client export {state['run_id']} --preview DIR", file=out)
        return 0
    if state["state"] == "failed" and not state.get("unresolved"):
        print(f"FAILED {state['run_id']} ({receipt.get('failure_type')}); cleanup {state.get('cleanup')}. "
              "Its private artifacts are retained; a new session needs a new run ID.", file=out)
        return 1
    print(f"UNCERTAIN {state['run_id']}: {state['state']}, cleanup {state.get('cleanup')}. A job or workspace may be "
          "left behind. Inspect the retained run, reconcile it, then record it with `resolve`; the service "
          "refuses new sessions until then.", file=out)
    return 3


def watch(service: Service, run_id: str, poll: float, printer: Printer, done: threading.Event | None = None) -> dict:
    misses = 0
    while True:
        start_settled = done is not None and done.is_set()
        try:
            state = service.status(run_id)
            misses = 0
        except (urllib.error.URLError, OSError, ValueError):
            misses += 1
            if misses >= 5:
                raise Uncertain("the session service stopped answering; the session's outcome is unknown "
                                "(check `status` once the service is back)")
            time.sleep(poll)
            continue
        if state["state"] == "unknown" and done is None:
            raise Uncertain(f"unknown run ID {run_id}: no session record is visible; verify the run ID and "
                            "service with `status` before watching again")
        if state["state"] == "unknown" and done is not None and done.is_set():
            if not start_settled:
                # This status request can race the POST creating its owner
                # record. Read once after the start request has settled.
                continue
            return state
        if state["state"] != "unknown":
            printer.update(state)
        if state["state"] in TERMINAL:
            return state
        time.sleep(poll)


def start(service: Service, run_id: str, poll: float, timeout: float, out=None) -> int:
    out = out or sys.stdout
    printer = Printer(out)
    outcome: dict = {}
    done = threading.Event()

    def request():
        try:
            outcome["receipt"] = service.start(run_id, timeout)
        except urllib.error.HTTPError as error:
            outcome["refused"] = http_detail(error)
        except (urllib.error.URLError, OSError, ValueError) as error:
            outcome["lost"] = type(error).__name__
        finally:
            done.set()

    existing = service.status(run_id)
    if existing["state"] != "unknown":
        print(f"REFUSED {run_id}: run ID already used (session is {existing['state']}); choose a new run ID", file=out)
        return 2
    printer.line(f"starting session {run_id} on {service.url}")
    threading.Thread(target=request, daemon=True).start()
    # Use the same bounded status recovery from the first poll onward. A
    # transport failure after POST is not proof that execution was refused.
    state = watch(service, run_id, poll, printer, done)
    if state["state"] == "unknown":
        done.wait(5)
        reason = outcome.get("refused") or outcome.get("lost") or "no session was created"
        if "refused" not in outcome:
            print(f"UNCERTAIN {run_id}: {reason}; inspect `status` before any new start", file=out)
            return 3
        print(f"REFUSED {run_id}: {reason}", file=out)
        return 2
    if "lost" in outcome:
        printer.line(f"the start request ended ({outcome['lost']}) but the session state is {state['state']}")
    return summary(state, out)


def export(service: Service, run_id: str, preview: Path | None, out=None) -> int:
    out = out or sys.stdout
    result = service.export(run_id)
    print(f"EXPORTED {run_id}: {result['events']} dashboard events in {result['path']} "
          f"(SHA256SUMS {result['sha256sums_sha256'][:12]}; not published)", file=out)
    if preview is not None:
        import importlib.util
        import shutil
        source = Path(result["path"])
        preview = preview.expanduser().resolve()
        repo = preview / "src"
        target = repo / "evidence" / source.parent.name / source.name
        if target.exists():
            shutil.rmtree(target)
        shutil.copytree(source, target)
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location("dash_workstation", root / "infra/tools/prace-dash-workstation.py")
        tool = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tool)
        code = tool.main(["--out", str(preview / "site"), "--repo", str(repo)])
        if code:
            return code
        print("then browse http://127.0.0.1:8000/#scenarios: this run is in the Scenarios list", file=out)
    print("Publishing still means a reviewed evidence MR, passing main CI and the dashboard refresh runbook.", file=out)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--poll", type=float, default=2.0)
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("start")
    one.add_argument("run_id")
    one.add_argument("--timeout", type=float, default=4 * 3600, help="how long to keep the start request open")
    sub.add_parser("watch").add_argument("run_id")
    sub.add_parser("status").add_argument("run_id", nargs="?")
    ex = sub.add_parser("export")
    ex.add_argument("run_id")
    ex.add_argument("--preview", type=Path)
    res = sub.add_parser("resolve", help="local only: record that an unresolved session was inspected and reconciled")
    res.add_argument("run_id")
    res.add_argument("--run-root", type=Path, required=True)
    res.add_argument("--note", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "resolve":
            from harness.session_store import resolve_session
            record = resolve_session(args.run_root, args.run_id, args.note)
            print(f"RESOLVED {record['run_id']} ({record['state']}, cleanup {record['cleanup']}) by {record['by']}")
            return 0
        service = Service(args.url)
        if args.command == "start":
            return start(service, args.run_id, args.poll, args.timeout)
        if args.command == "watch":
            return summary(watch(service, args.run_id, args.poll, Printer()))
        if args.command == "status":
            print(json.dumps(service.status(args.run_id), indent=2))
            return 0
        return export(service, args.run_id, args.preview)
    except KeyboardInterrupt:
        print("\nclient interrupted; the session continues on the service: use `watch` to follow it", file=sys.stderr)
        return 130
    except urllib.error.HTTPError as error:
        print(f"REFUSED: {http_detail(error)}", file=sys.stderr)
        return 2
    except Uncertain as error:
        print(f"STOP: {error}", file=sys.stderr)
        return 3
    except (Refused, ValueError, OSError) as error:
        print(f"STOP: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

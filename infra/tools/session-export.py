#!/usr/bin/env python3
"""Export a recorded user terminal session, and its replay on the cluster, as a dashboard scenario-run folder.

A normal researcher session (no attack) is recorded on the user's side with script(1): what the user typed
and saw, with its timing (<name>.tm advanced timing, <name>.out output, <name>.in keystrokes). The same
commands, rebuilt from the keystrokes, are then replayed as the same user in a fresh recorded login, with job
IDs mapped in submission order. Slurm's own accounting of every job is read separately, in the controller pod
(accounting.json: rows of sacct -P with the fields below). Every row must belong to the session that printed
its job ID: the job's user is --user, and it was submitted while that session was open (within WINDOW_SLACK_S,
for clock difference between the user's workstation and the cluster). This tool joins them into the dashboard's
scenario-run interface (docs/design/dashboard/data-contracts.md, C22/C23):

  user-terminal     the session's login, each typed command, logout (both sessions)        actors/ctx (T3)
  sacct-controller  each job's submit, start and end; the replay comparison                 fleet/ctx  (T1)

It never contacts a host. The recordings' header lines (which carry the full ssh command, key paths
included) are dropped: the folder keeps asciicast v2 files of the screen (terminal/<name>.cast) and the
rebuilt command lists. The dashboard's own reader must accept the folder before it is kept.

  session-export.py --session-dir DIR --original NAME --replay NAME --accounting FILE --user USER
                    --run-id ID [--evidence-root evidence] [--title TEXT]
"""
import argparse
import codecs
import datetime
import hashlib
import json
import math
import re
import shutil
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DASH_FILES = ROOT / "infra/roles/fleet_dashboard/files"
FIELDS = ["JobID", "User", "JobName", "Partition", "Account", "AllocCPUS", "AllocTRES", "NodeList", "Submit", "Start", "End",
          "State", "ExitCode", "Elapsed"]
SUBMIT = re.compile(rb"Submitted batch job (\d+)")
WINDOW_SLACK_S = 120          # the user's workstation clock (the recording) against the controller's (sacct)
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")


class Refused(Exception):
    pass


class InputLines:
    """Simple complete command lines only; never guess at shell history or cursor edits."""
    def __init__(self):
        self.line = bytearray()

    def feed(self, chunk):
        lines = []
        for b in chunk:
            if b in (10, 13):
                if self.line.strip():
                    lines.append(self.line.decode("utf-8", "strict"))
                self.line.clear()
            elif b in (8, 127):
                if self.line:
                    text = self.line.decode("utf-8", "strict")
                    self.line = bytearray(text[:-1].encode("utf-8"))
            elif b == 9 or b < 32:
                raise Refused("unsupported terminal edit (completion/history/cursor/control); use complete literal lines")
            else:
                self.line.append(b)
        return lines

    def finish(self):
        if self.line.strip():
            raise Refused("recording ends with an incomplete command")


def map_job_ids(text, old_ids, new_ids):
    mapping = dict(zip(old_ids, new_ids))
    if not mapping:
        return text
    return re.sub(r"\b(?:" + "|".join(map(re.escape, mapping)) + r")\b",
                  lambda m: mapping[m[0]], text)


def body(raw):
    """script(1)'s log without its 'Script started ... [COMMAND=...]' header and 'Script done' footer"""
    if raw.startswith(b"Script started"):
        raw = raw[raw.index(b"\n") + 1:]
    end = raw.rfind(b"\nScript done on ")
    return raw[:end] if end > 0 else raw


def session(d, name):
    """{start, end, commands [(t, text)], cast lines, job ids} of one recording"""
    if not NAME.fullmatch(name):
        raise Refused("recording name must be a simple file basename")
    tm = (d / f"{name}.tm").read_text().splitlines()
    for ext in ("out", "in"):
        raw = (d / f"{name}.{ext}").read_bytes()
        if not re.search(rb'\nScript done on [^\n]*\[COMMAND_EXIT_CODE="0"\]\s*$', raw):
            raise Refused(f"{name}.{ext}: missing successful session completion")
    out, inp = body((d / f"{name}.out").read_bytes()), body((d / f"{name}.in").read_bytes())
    start = None
    for line in tm:
        f = line.split(None, 3)
        if len(f) == 4 and f[:1] == ["H"] and f[2] == "START_TIME":
            start = datetime.datetime.strptime(f[3].strip(), "%Y-%m-%d %H:%M:%S%z").timestamp()
    if start is None:
        raise Refused(f"{name}.tm: no START_TIME (record with script --log-timing and --log-in/--log-out)")
    t, opos, ipos, cmds, cast = 0.0, 0, 0, [], []
    parser = InputLines()
    dec = codecs.getincrementaldecoder("utf-8")("strict")
    for line in tm:
        f = line.split()
        if not f:
            continue
        if len(f) < 3 or f[0] not in ("O", "I", "S", "H"):
            raise Refused("malformed timing record")
        delay = float(f[1])
        if not math.isfinite(delay) or delay < 0:
            raise Refused("invalid timing delay")
        t += delay
        if f[0] in ("O", "I") and (not f[2].isdigit()):
            raise Refused("invalid timing byte count")
        if f[0] == "O":
            chunk = out[opos:opos + int(f[2])]; opos += int(f[2])
            if len(chunk) != int(f[2]):
                raise Refused("truncated output log")
            text = dec.decode(chunk)
            if text:
                cast.append([round(t, 6), "o", text])
        elif f[0] == "I":
            chunk = inp[ipos:ipos + int(f[2])]; ipos += int(f[2])
            if len(chunk) != int(f[2]):
                raise Refused("truncated input log")
            cmds.extend((start + t, line) for line in parser.feed(chunk))
    parser.finish()
    dec.decode(b"", final=True)
    if opos != len(out) or ipos != len(inp):
        raise Refused("timing does not cover the complete recording")
    return {"start": start, "end": start + t, "commands": cmds, "cast": cast,
            "jobs": [m.decode() for m in SUBMIT.findall(out)]}


def epoch(text):
    return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp() \
        if text and text not in ("Unknown", "None") else None


def accounting(path, jobs):
    rows = json.loads(Path(path).read_text())
    if not isinstance(rows, list) or any(not isinstance(r, dict) or any(not isinstance(r.get(k), str) for k in FIELDS) for r in rows):
        raise Refused("malformed controller accounting")
    by = {r["JobID"]: r for r in rows}
    if len(by) != len(rows):
        raise Refused("duplicate controller accounting job IDs")
    missing = [j for j in jobs if j not in by]
    if missing:
        raise Refused(f"no controller accounting for job(s) {missing}")
    return by


def utc(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def bind_accounting(by, s, user, label):
    """each job a session printed is that user's and was submitted while the session was open; otherwise a
    mistyped or wrong job ID would attach someone else's job to the run as independent (T1) evidence"""
    problems = []
    for j in s["jobs"]:
        r = by[j]
        if r["User"] != user:
            problems.append(f"job {j} belongs to {r['User'] or 'no user'}, not {user}")
        t = epoch(r["Submit"])
        if t is None or not s["start"] - WINDOW_SLACK_S <= t <= s["end"] + WINDOW_SLACK_S:
            problems.append(f"job {j} was submitted at {r['Submit']} UTC, outside the {label} session "
                            f"({utc(s['start'])} to {utc(s['end'])} UTC, {WINDOW_SLACK_S} s allowed either side)")
    if problems:
        raise Refused("controller accounting does not belong to this session: " + "; ".join(problems))


def job_events(by, jobs, prefix, actor, tz):
    out = []
    for j in jobs:
        r = by[j]
        ev = f"accounting.json#{j}"
        what = f"job {j} {r['JobName']} ({r['Partition']}, {r['Account']}, {r['AllocCPUS']} CPUs" + \
               (f", {r['AllocTRES'].split('gres/gpu=')[1].split(',')[0]} GPU" if "gres/gpu=" in r.get("AllocTRES", "") else "") + ")"
        for key, label in (("Submit", "submitted"), ("Start", "started"), ("End", "ended")):
            t = epoch(r.get(key))
            if t is None:
                continue
            text = {"Submit": f"{what}: queued by {actor}",
                    "Start": f"{what}: running on {r['NodeList']}",
                    "End": f"{what}: {r['State']}, exit {r['ExitCode']}, {r['Elapsed']}"}[key]
            out.append((t + tz, {"lane": "fleet", "kind": "fleet", "src": "sacct-controller",
                                 "host": r["NodeList"] if key != "Submit" else "", "actor": actor,
                                 "title": f"{prefix}accounting · {label} · job {j} {r['JobName']}" +
                                          (f" · {r['State']}" if key == "End" else ""),
                                 "text": text, "ev": ev}))
    return out


def terminal_events(s, name, prefix, actor):
    out = [(s["start"], {"lane": "ctx", "kind": "ctx", "src": "user-terminal", "host": "", "actor": actor,
                         "title": f"{prefix}login · {actor} over Tailscale to the PRACE login pod",
                         "text": "the user's own recording of the session (script(1) on the user's side)",
                         "ev": f"terminal/{name}.cast"})]
    for t, cmd in s["commands"]:
        out.append((t, {"lane": "actors", "kind": "probe", "src": "user-terminal", "host": "", "actor": actor,
                        "title": f"{prefix}typed · {cmd}", "text": f"at the PRACE prompt, {t - s['start']:.1f} s into the session",
                        "ev": f"terminal/{name}.cast#t={t - s['start']:.1f}"}))
    out.append((s["end"], {"lane": "ctx", "kind": "ctx", "src": "user-terminal", "host": "", "actor": actor,
                           "title": f"{prefix}logout", "text": f"{len(s['commands'])} commands typed",
                           "ev": f"terminal/{name}.commands"}))
    return out


def compare(by, a, b):
    keys = ("JobName", "Partition", "Account", "AllocCPUS", "AllocTRES", "State", "ExitCode")
    if not a or not b:
        return False, "no job proof in one or both sessions"
    if len(a) != len(b):
        return False, f"{len(a)} original jobs, {len(b)} replayed"
    if len(set(a + b)) != len(a + b):
        return False, "job IDs must be distinct within and between sessions"
    diffs = []
    for j in a + b:
        r = by[j]
        if r["State"] != "COMPLETED" or r["ExitCode"] != "0:0" or epoch(r.get("End")) is None:
            diffs.append(f"job {j} has no successful final completion")
    for x, y in zip(a, b):
        for k in keys:
            left, right = by[x][k], by[y][k]
            if k == "AllocTRES":
                left, right = sorted(left.split(",")), sorted(right.split(","))
            if left != right:
                diffs.append(f"job {x} -> {y}: {k} {by[x][k]} != {by[y][k]}")
    return not diffs, "; ".join(diffs) or "same job names, partitions, accounts, allocated resources and successful final states"


def compare_sessions(by, original, replay):
    ok, detail = compare(by, original["jobs"], replay["jobs"])
    expected = [map_job_ids(c, original["jobs"], replay["jobs"]) for _, c in original["commands"]]
    if expected != [c for _, c in replay["commands"]]:
        return False, "command sequence differs after job-ID mapping; " + detail
    return ok, "command sequence matches after job-ID mapping; " + detail


def build(d, original, replay, acct, user, run_id, evidence_root, title=None):
    if not re.fullmatch(r"[a-z][a-z0-9-]{2,63}", run_id) or original == replay:
        raise Refused("invalid run ID or identical recording names")
    d = Path(d)
    so, sr = session(d, original), session(d, replay)
    if not so["commands"] or not sr["commands"]:
        raise Refused("a session typed no command")
    by = accounting(acct, so["jobs"] + sr["jobs"])
    bind_accounting(by, so, user, original)
    bind_accounting(by, sr, user, replay)
    ok, detail = compare_sessions(by, so, sr)
    events = terminal_events(so, original, "", user) + terminal_events(sr, replay, "replay · ", user)
    events += job_events(by, so["jobs"], "", user, 0) + job_events(by, sr["jobs"], "replay · ", user, 0)
    events.append((sr["end"] + 0.001, {"lane": "ctx", "kind": "ctx", "src": ["user-terminal", "sacct-controller"], "host": "", "actor": "",
                   "title": f"replay {'matched' if ok else 'differs'}: {len(so['jobs'])} jobs as recorded, {len(sr['jobs'])} as replayed",
                   "text": detail, "ev": "accounting.json"}))
    events.sort(key=lambda x: x[0])
    start, stop = events[0][0], events[-1][0]
    date = datetime.datetime.fromtimestamp(start, datetime.timezone.utc).strftime("%Y-%m-%d")
    out = Path(evidence_root) / date / run_id
    if out.exists():
        raise Refused(f"{out} exists: evidence is append-only, export to a new run ID")
    tmp = Path(tempfile.mkdtemp(prefix=".session-export-", dir=Path(evidence_root)))
    try:
        (tmp / "terminal").mkdir()
        for name, s in ((original, so), (replay, sr)):
            with open(tmp / "terminal" / f"{name}.cast", "w") as f:
                f.write(json.dumps({"version": 2, "width": 120, "height": 32, "timestamp": int(s["start"]),
                                    "title": f"{user} on the PRACE login pod ({name})"}) + "\n")
                for e in s["cast"]:
                    f.write(json.dumps(e) + "\n")
            (tmp / "terminal" / f"{name}.commands").write_text("".join(f"{t - s['start']:8.1f}  {c}\n" for t, c in s["commands"]))
        rows = [by[j] for j in so["jobs"] + sr["jobs"]]
        (tmp / "accounting.json").write_text(json.dumps(rows, indent=1, sort_keys=True) + "\n")
        capture = {
            "schema": 1, "kind": "scenario-run", "run_id": run_id,
            "title": title or f"Researcher session: {user} runs CPU and GPU jobs; the captured commands replayed on the cluster",
            "lease_label": None, "lease_id": None,
            "start": round(start, 3), "stop": round(stop, 3), "captured_at": round(stop, 3),
            "actors": [{"account": user, "under_test": False}],
            "observations": [], "recovery": {"before": None, "after": None, "restore_test": None},
            "source": {"kind": "terminal-session", "original": {"jobs": so["jobs"], "commands": len(so["commands"])},
                       "replay": {"jobs": sr["jobs"], "commands": len(sr["commands"])}, "replay_matched": ok,
                       "comparison_scope": "typed command sequence after job-ID mapping and successful job accounting; no filesystem reset or output equivalence proof",
                       "accounting": "sacct -X -P in the controller pod, by job ID",
                       "accounting_binding": f"every job's user is {user}, and each was submitted while the session that printed its ID was open ({WINDOW_SLACK_S} s allowed either side)"},
            "files": {"events.jsonl": "dashboard events: the user's recording (T3) and the controller's accounting (T1)",
                      "terminal/": "each session's screen as asciicast v2 (header with the ssh command dropped) and its typed commands",
                      "accounting.json": "sacct rows of every job, read in the controller pod",
                      "README.md": "what this run is and is not"},
        }
        with open(tmp / "capture.json", "w") as f:
            json.dump(capture, f, indent=1, sort_keys=True)
            f.write("\n")
        with open(tmp / "events.jsonl", "w") as f:
            for t, e in events:
                f.write(json.dumps(dict(e, t=round(t, 3)), sort_keys=True) + "\n")
        (tmp / "README.md").write_text(f"""# {run_id}: a researcher's session and its replay on the cluster

{capture['title']}.

- **What this is:** a normal user workflow, not a security scenario. {user} logs in over Tailscale to the PRACE login pod, uses the `/apps` examples, submits {len(so['jobs'])} jobs to their project, waits, reads the results and shares them in the project directory. The session was recorded on the user's side (`terminal/{original}.cast`, {len(so['commands'])} commands).
- **Replay:** the commands were rebuilt from the recording's keystrokes and typed again as the same user in a fresh login (`terminal/{replay}.cast`), job IDs mapped in submission order ({', '.join(f'{a} -> {b}' for a, b in zip(so['jobs'], sr['jobs']))}). Replay {'matched' if ok else 'differs'}: {detail}.
- **Scope:** command and accounting equivalence only. This is a re-execution against the current environment, not a point-in-time restore or proof of identical file outputs.
- **Trust:** the recordings are the user's own account (T3, actor-written). Every job's submit, start and end comes from Slurm's accounting read in the controller pod, where no user has a session (T1, independent). Each job is bound to its session: its user is {user}, and it was submitted while that session was open ({WINDOW_SLACK_S} s allowed either side).
- **Not kept:** the raw script(1) logs (their header carries the full ssh command); the private key and host-key files.
""")
        files = sorted(str(p.relative_to(tmp)) for p in tmp.rglob("*") if p.is_file())
        with open(tmp / "SHA256SUMS", "w") as f:
            for n in files:
                f.write(f"{hashlib.sha256((tmp / n).read_bytes()).hexdigest()}  {n}\n")
        check_with_dashboard(tmp, f"{date}/{run_id}")
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp.rename(out)
        return out, len(events), ok
    finally:
        if tmp.exists():
            shutil.rmtree(tmp)


def check_with_dashboard(folder, rel):
    sys.path.insert(0, str(DASH_FILES))
    import prace_dash_evidence as evidence   # noqa: E402
    v = evidence.verify(str(folder))
    if v["state"] != "ok":
        raise Refused(f"SHA256SUMS check failed: {v['detail']}")
    try:
        run = evidence.scenario(str(folder), rel, v["files"], evidence.load_trust())
    except ValueError as exc:
        raise Refused(f"the dashboard reader refused the folder: {exc}") from exc
    if run["capture_late"] or not run["events"]:
        raise Refused("the dashboard reader marks the run late or empty")
    return run


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    ap.add_argument("--session-dir", required=True)
    ap.add_argument("--original", required=True)
    ap.add_argument("--replay", required=True)
    ap.add_argument("--accounting", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--run-id", required=True)
    ap.add_argument("--evidence-root", default=str(ROOT / "evidence"))
    ap.add_argument("--title")
    a = ap.parse_args()
    if not re.fullmatch(r"[a-z][a-z0-9-]{2,63}", a.run_id):
        print("REFUSED: run ID: lowercase letters, digits and hyphens", file=sys.stderr)
        return 1
    try:
        out, n, ok = build(a.session_dir, a.original, a.replay, a.accounting, a.user, a.run_id, a.evidence_root, a.title)
    except (Refused, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 1
    print(f"exported {out} ({n} events; replay {'matched' if ok else 'differs'}); the dashboard reader accepts it")
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())

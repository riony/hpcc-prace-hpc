#!/usr/bin/python3
"""prace-dash-evidence (roles/fleet_dashboard, hourly and on demand): acceptance runs, recovery points
and scenario runs, from the evidence folders of the repository at a pinned commit.

On mgmt-git01 the role ships the selected evidence folders of the deploy commit to the source
directory (with SOURCE.json naming the commit); this tool reads only those. Every folder's
SHA256SUMS is verified first (contract C5): a folder that fails, or has none, is listed with the
reason and nothing from it is used, and only files the SHA256SUMS names are read. The output is
scrubbed (C4) and written atomically to <www_data>/evidence.json; with residue it is not written.
This entry point has no unscrubbed mode. The operator workstation's private bundle is built by
infra/tools/prace-dash-workstation.py from the same functions; that tool is never installed here.

Bound to the committed files (verified 5 Oct against evidence/2026-10-04/window-t87-t88/):
  acceptance   p<phase>-<suite>[-acceptance][-<attempt>][-failed|-stopped][-<pass>-<fail>]-at-<pin>.txt,
               closed by '<wrapper key> rc=<n>' and an HH:MM:SS line; wrapper-<key>.json beside it
               {command_rc, phase, lease_id, containment}. Name + wrapper are the record; PASS/FAIL
               line counts are only a cross-check.
  recovery     recovery-points.txt blocks ('## <label>', 'id <32 hex> stage .. phase .. accepted ..
               borrowed window <16 hex> retained ..', execution revision, created, workers,
               artifacts, run.json sha256). The private 'run dir' line is dropped while parsing.
               recovery-points.json (30 Sep format) likewise.
  scenarios    folders with capture.json {kind: scenario-run} and events.jsonl, written by the
               scenario capture tool (its own MR; no run exists yet). Trust comes from trust-table.json.

  prace_dash_evidence.py run --config /etc/prace-dash/dash.json [--now EPOCH]
  prace_dash_evidence.py select --repo DIR      evidence folders the role ships (JSON list; read-only)
"""
import argparse
import hashlib
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import prace_dash_common as common  # noqa: E402
import prace_dash_physical as physical_records  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_FILE = 8 << 20
ACCEPTANCE_RX = re.compile(r"p(?P<phase>\d+)-(?P<suite>[a-z][a-z0-9-]*?)(?:-acceptance)?-(?:(?P<attempt>\d+)-)?"
                           r"(?:(?P<result>failed|stopped)-)?(?:(?P<passed>\d+)-(?P<failed>\d+)-)?at-(?P<pin>[A-Za-z0-9]+)\.txt")
WRAPPER_RX = re.compile(r"wrapper-(?P<key>p\d+r?(?:-[a-z0-9-]+)?)\.json")
TAIL_RC_RX = re.compile(r"(?:(?P<key>p\d+r?(?:-[a-z0-9-]+)?) )?rc=(?P<rc>\d+)")
TAIL_TIME_RX = re.compile(r"\d{2}:\d{2}:\d{2}")
SUMS_RX = re.compile(r"([0-9a-f]{64}) [ *](.+)")
POINT_RX = re.compile(r"id (?P<id>[0-9a-f]{32})\s+stage (?P<stage>\S+)\s+phase (?P<phase>\S+)\s+accepted (?P<accepted>true|false)"
                      r"(?:\s+borrowed window (?P<window>[0-9a-f]+))?(?:\s+retained (?P<retained>true|false))?\s*")
EVENT_KEYS = ("t", "lane", "kind", "src", "host", "actor", "title", "text", "ev")
LANES = ("actors", "fleet", "ctx")
KINDS = ("probe", "bg", "fleet", "ctx")
TRUST_ORDER = ("independent", "co-located", "actor-written")
LATE_CAPTURE_S = 3600


def is_interesting(name):
    return bool(ACCEPTANCE_RX.fullmatch(name) or WRAPPER_RX.fullmatch(name)
                or name in ("recovery-points.txt", "recovery-points.json", "capture.json"))


def has_link(folder):
    """true if anything inside the folder is a symbolic link (such a folder is never shipped or read)"""
    for d, dirs, files in os.walk(folder):
        if any(os.path.islink(os.path.join(d, n)) for n in dirs + files):
            return True
    return False


def folders(evidence):
    """evidence/<date>/<folder> directories holding a file this tool reads"""
    out = []
    for date in sorted(os.listdir(evidence)) if os.path.isdir(evidence) else []:
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date) or os.path.islink(os.path.join(evidence, date)):
            continue
        for name in sorted(os.listdir(os.path.join(evidence, date))):
            d = os.path.join(evidence, date, name)
            if os.path.isdir(d) and not os.path.islink(d) and any(is_interesting(f) for f in os.listdir(d)):
                out.append(f"{date}/{name}")
    return out


def verify(folder):
    """{state: ok|mismatch|absent|invalid, files: [names listed and verified], detail}"""
    sums = os.path.join(folder, "SHA256SUMS")
    if os.path.islink(folder) or has_link(folder):
        return {"state": "invalid", "files": [], "detail": "the folder contains a symbolic link"}
    try:
        text = common.read_capped(sums, 1 << 20).decode("utf-8")
    except FileNotFoundError:
        return {"state": "absent", "files": [], "detail": "no SHA256SUMS"}
    except (OSError, ValueError, UnicodeDecodeError):
        return {"state": "invalid", "files": [], "detail": "SHA256SUMS unreadable"}
    root = os.path.realpath(folder)
    listed, bad = [], []
    for line in text.splitlines():
        if not line.strip():
            continue
        m = SUMS_RX.fullmatch(line.strip())
        name = m.group(2) if m else ""
        if (not m or name.startswith("/") or ".." in name.split("/") or "\\" in name or "\0" in name
                or not os.path.realpath(os.path.join(folder, name)).startswith(root + os.sep)):
            return {"state": "invalid", "files": [], "detail": "SHA256SUMS has a line outside the format or the folder"}
        path = os.path.join(folder, name)
        try:
            if os.path.islink(path):
                raise OSError("link")
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for block in iter(lambda: f.read(1 << 20), b""):
                    h.update(block)
            ok = h.hexdigest() == m.group(1)
        except OSError:
            ok = False
        (listed if ok else bad).append(name)
    if bad:
        return {"state": "mismatch", "files": [], "detail": f"checksum mismatch ({len(bad)} file(s))"}
    return {"state": "ok", "files": sorted(listed), "detail": f"{len(listed)} file(s) verified"}


def read_text(path):
    return common.read_capped(path, MAX_FILE).decode("utf-8", "replace")


def crosscheck(text):
    lines = text.splitlines()
    a_pass = sum(1 for l in lines if re.match(r"PASS\b", l))
    a_fail = sum(1 for l in lines if re.match(r"FAIL\b", l))
    # tools/slinky-acceptance.sh: '<check>: PASS' lines and a closing 'ACCEPTANCE: PASS'. The file names
    # count that closing line too (p8-platform-acceptance-129-0: 128 checks + the verdict), so it counts here.
    b_pass = sum(1 for l in lines if l.rstrip().endswith(": PASS"))
    b_fail = sum(1 for l in lines if l.rstrip().endswith(": FAIL"))
    return (a_pass, a_fail) if (a_pass or a_fail) else (b_pass, b_fail)


def wrapper_verdict(w):
    """'passed' or 'failed' from a well-formed wrapper record; None when it is unreadable or malformed"""
    if not isinstance(w, dict) or "error" in w:
        return None
    rc, phase = w.get("command_rc"), w.get("phase")
    if type(rc) is not int or not isinstance(phase, str) or not phase:
        return None
    return "passed" if rc == 0 and phase == "passed" else "failed"


def acceptance(folder, rel, files):
    rows, wrappers = [], {}
    for name in files:
        m = WRAPPER_RX.fullmatch(name)
        if m:
            try:
                w = common.loads(read_text(os.path.join(folder, name)))
            except (OSError, ValueError, RecursionError):
                w = None
            wrappers[m.group("key")] = w if isinstance(w, dict) else {"error": "unreadable"}
    joined = set()
    date = rel.split("/")[0]
    for name in files:
        m = ACCEPTANCE_RX.fullmatch(name)
        if not m:
            continue
        text = read_text(os.path.join(folder, name))
        tail = [l.strip() for l in text.splitlines()[-4:] if l.strip()]
        rc_line = next((TAIL_RC_RX.fullmatch(l) for l in reversed(tail) if TAIL_RC_RX.fullmatch(l)), None)
        ended = next((l for l in reversed(tail) if TAIL_TIME_RX.fullmatch(l)), None)
        key = rc_line.group("key") if rc_line else None
        wkey = key if key in wrappers else None
        if key and not wkey:
            cand = [k for k in wrappers if k.startswith(key + "-")]
            wkey = cand[0] if len(cand) == 1 else None
        if wkey:
            joined.add(wkey)
        w = wrappers.get(wkey) if wkey else None
        lp, lf = crosscheck(text)
        named = m.group("passed") is not None
        passed = int(m.group("passed")) if named else None
        failed = int(m.group("failed")) if named else None
        rc = int(rc_line.group("rc")) if rc_line else None
        conflicts = []
        if w is not None:
            # A matching wrapper record decides; it is never overridden by the transcript (review R3).
            verdict = wrapper_verdict(w)
            if verdict is None:
                conflicts.append("wrapper record unreadable or malformed")
            elif verdict == "passed" and rc not in (None, 0):
                conflicts.append(f"transcript rc={rc} but the wrapper says passed")
            elif verdict != "passed" and rc == 0:
                conflicts.append(f"transcript rc=0 but the wrapper says {w.get('phase')} (command_rc {w.get('command_rc')})")
            ok = verdict == "passed" and not conflicts and not failed
        else:
            ok = rc == 0 and not failed            # legacy transcripts without a wrapper record
        if m.group("result"):
            result = m.group("result")
        else:
            result = "passed" if ok else "failed"
        rows.append({"window": rel, "date": date, "file": name, "phase": int(m.group("phase")), "suite": m.group("suite"),
                     "attempt": int(m.group("attempt")) if m.group("attempt") else None, "result": result,
                     "passed": passed, "failed": failed, "pin": m.group("pin"),
                     "rc": int(rc_line.group("rc")) if rc_line else None, "ended_local": f"{date} {ended}" if ended else None,
                     "wrapper": None if not w else {"name": f"wrapper-{wkey}.json", **{k: w.get(k) for k in ("command_rc", "phase", "containment", "lease_id")}},
                     "cross_check": {"pass_lines": lp, "fail_lines": lf, "agrees": (lp, lf) == (passed, failed) if named else None},
                     "conflicts": conflicts})
    for key, w in sorted(wrappers.items()):
        if key not in joined:
            rows.append({"window": rel, "date": date, "file": None, "phase": int(re.match(r"p(\d+)", key).group(1)),
                         "suite": key.split("-", 1)[1] if "-" in key else key, "attempt": None,
                         "result": "passed" if wrapper_verdict(w) == "passed" else "failed",
                         "passed": None, "failed": None, "pin": None, "rc": None, "ended_local": None,
                         "wrapper": {"name": f"wrapper-{key}.json", **{k: w.get(k) for k in ("command_rc", "phase", "containment", "lease_id")}},
                         "cross_check": None, "wrapper_only": True,
                         "conflicts": [] if wrapper_verdict(w) is not None else ["wrapper record unreadable or malformed"]})
    rows.sort(key=lambda r: (r["phase"], r["suite"], r["attempt"] or 0, r["file"] or ""))
    return rows


def recovery_txt(text, rel):
    points, cur, label = [], None, None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("## "):
            label = line[3:].strip()[:80]
            continue
        m = POINT_RX.fullmatch(line)
        if m:
            cur = {"folder": rel, "label": label, "id": m.group("id"), "stage": m.group("stage"), "phase": m.group("phase"),
                   "accepted": m.group("accepted") == "true", "borrowed_window": m.group("window"),
                   "retained": None if m.group("retained") is None else m.group("retained") == "true",
                   "revision": None, "created": None, "workers": None, "artifacts": None, "bytes": None, "run_json_sha256": None}
            points.append(cur)
            label = None
            continue
        if cur is None or line.startswith("run dir"):      # the private run directory is never kept
            continue
        if line.startswith("execution revision "):
            cur["revision"] = line.split()[-1][:40]
        elif line.startswith("created "):
            created, _, workers = line[len("created "):].partition("  workers ")
            try:
                cur["created"] = int(common.parse_iso(created.strip()))
            except ValueError:
                pass
            cur["workers"] = [w.strip() for w in workers.split(",") if w.strip()] or None
        elif line.startswith("artifacts "):
            m2 = re.fullmatch(r"artifacts (\d+), ([\d,]+) bytes", line)
            if m2:
                cur["artifacts"], cur["bytes"] = int(m2.group(1)), int(m2.group(2).replace(",", ""))
        elif line.startswith("run.json sha256 "):
            cur["run_json_sha256"] = line.split()[-1][:64]
    return points


def recovery_json(text, rel):
    try:
        doc = common.loads(text)
    except (ValueError, RecursionError):
        return []
    out = []
    for p in (doc.get("points") or []) if isinstance(doc, dict) else []:
        if not isinstance(p, dict) or not re.fullmatch(r"[0-9a-f]{32}", str(p.get("id"))):
            continue
        created = None
        try:
            created = int(common.parse_iso(p.get("created_utc")))
        except ValueError:
            pass
        out.append({"folder": rel, "label": None, "id": p["id"], "stage": p.get("stage"), "phase": p.get("phase"),
                    "accepted": p.get("accepted") is True, "borrowed_window": None, "retained": None,
                    "revision": str(p.get("revision") or "")[:40] or None, "created": created, "workers": None,
                    "artifacts": len(p["artifacts"]) if isinstance(p.get("artifacts"), list) else None,
                    "bytes": p.get("total_bytes") if type(p.get("total_bytes")) is int else None, "run_json_sha256": None})
    return out


def load_trust(path=None):
    with open(path or os.path.join(HERE, "trust-table.json"), encoding="utf-8") as f:
        return json.load(f)["sources"]


def event_time(v):
    if common.finite_time(v):
        return int(v)
    return int(common.parse_iso(v))


def simulation(folder, files, cap):
    """Read only the checked public derivative. Raw-proof authenticity stays T2;
    the export receipt is an assertion by its verifier, not a signature or T1 evidence.
    Malformed new-format input refuses the run rather than falling back to a generic success.
    """
    source = cap.get("source")
    if not isinstance(source, dict) or source.get("kind") != "security-simulation":
        return None
    if "summary.json" not in files:
        raise ValueError("security simulation has no verified summary.json")
    summary = common.loads(read_text(os.path.join(folder, "summary.json")))
    keys = {"schema", "run_id", "scenario_kind", "scope", "source_revision", "source_dirty", "driver",
            "framework_version", "model_used", "model", "proof_scope", "reset_scope", "fixture_discarded",
            "verdicts", "cleanup", "private_bundle_index_sha256", "events"}
    if not isinstance(summary, dict) or set(summary) != keys or summary.get("schema") != "prace.security-simulation-public.v1":
        raise ValueError("malformed security simulation summary")
    bindings = {"run_id": cap.get("run_id"), **{k: source.get(k) for k in
                ("scope", "source_revision", "source_dirty", "driver", "framework_version", "model", "proof_scope",
                 "reset_scope", "private_bundle_index_sha256")}, "model_used": source.get("llm_used")}
    if any(summary[k] != value or type(summary[k]) is not type(value) for k, value in bindings.items()):
        raise ValueError("security simulation capture/summary binding mismatch")
    if (summary["scope"] != "disposable-local-linux-acl-simulation" or summary["scenario_kind"] not in ("read", "write")
            or summary["reset_scope"] != "seeded-vulnerable-fixture"
            or summary["proof_scope"] != {"filesystem": "linux-kernel-authorization", "scheduler": "simulated-accounting",
                                          "quota": "tree-usage-stand-in", "selinux": "not-qualified"}):
        raise ValueError("unknown security simulation scope")
    if (not isinstance(summary["source_revision"], str) or not re.fullmatch(r"[0-9a-f]{40}", summary["source_revision"])
            or not isinstance(summary["private_bundle_index_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", summary["private_bundle_index_sha256"])
            or type(summary["source_dirty"]) is not bool or type(summary["model_used"]) is not bool
            or type(summary["fixture_discarded"]) is not bool
            or (source.get("fleet_contacted") is not None and type(source["fleet_contacted"]) is not bool)
            or summary["driver"] not in ("scripted", "nemo")
            or (summary["driver"] == "nemo" and summary["framework_version"] != "1.9.0")
            or (summary["driver"] == "scripted" and (summary["framework_version"] is not None or summary["model_used"]))
            or (summary["model_used"] and (not isinstance(summary["model"], str)
                                         or not re.fullmatch(r"[A-Za-z0-9_./:-]{1,160}", summary["model"])))
            or (not summary["model_used"] and summary["model"] is not None)):
        raise ValueError("malformed security simulation provenance")
    verdicts = summary["verdicts"]
    if (not isinstance(verdicts, dict) or set(verdicts) != {"baseline", "patched", "functional"}
            or any(not isinstance(v, str) or v not in {"security_failure", "security_blocked", "pass", "fail", "unknown"} for v in verdicts.values())
            or (not isinstance(summary["cleanup"], str) or summary["cleanup"] not in {"complete", "error", "unknown", "not-run"})):
        raise ValueError("malformed security simulation verdict")
    events = summary["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= 64:
        raise ValueError("security simulation event count out of bounds")
    phase_order = {"attack": 0, "replay": 1, "regression": 2, "reset": 3}
    last_phase = -1
    seen = set()
    for n, event in enumerate(events, 1):
        if (not isinstance(event, dict) or set(event) != {"sequence", "phase", "event_type", "id", "status", "event_sha256"}
                or type(event["sequence"]) is not int or event["sequence"] != n or not isinstance(event["phase"], str) or event["phase"] not in phase_order
                or phase_order[event["phase"]] < last_phase or not isinstance(event["event_type"], str) or event["event_type"] not in {"action", "observation"}
                or not isinstance(event["id"], str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,79}", event["id"])
                or not isinstance(event["event_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", event["event_sha256"])
                or not isinstance(event["status"], str) or event["status"] not in ({"ok", "denied", "error", "timeout"} if event["event_type"] == "action"
                                          else {"pass", "fail", "unknown"})
                or (event["phase"], event["event_type"], event["id"]) in seen):
            raise ValueError("malformed security simulation event")
        last_phase = phase_order[event["phase"]]
        seen.add((event["phase"], event["event_type"], event["id"]))
    return {**summary, "fleet_contacted": source.get("fleet_contacted"),
            "verified": source.get("harness_verify") == "PASS bundle " + summary["run_id"] + ": integrity, trace and verdicts verified"}


def physical(folder, files, cap):
    """Reverify physical source records; exporter assertions are not verdicts."""
    source = cap.get("source")
    claimed = isinstance(source, dict) and source.get("kind") == physical_records.SOURCE_KIND
    if "physical.json" in files or claimed:
        if not claimed:
            raise ValueError("physical summary lacks physical capture provenance")
        return physical_records.verify_export(folder, files, cap)
    return None


def scenario(folder, rel, files, trust_table):
    """one scenario run (capture tool output); ValueError on anything outside the interface"""
    cap = common.loads(read_text(os.path.join(folder, "capture.json")))
    if not isinstance(cap, dict) or cap.get("schema") != 1 or cap.get("kind") != "scenario-run":
        raise ValueError("capture.json is not a schema-1 scenario-run record")
    phys = physical(folder, files, cap)
    start, stop = event_time(cap.get("start")), event_time(cap.get("stop"))
    captured = event_time(cap.get("captured_at")) if cap.get("captured_at") is not None else None
    if "events.jsonl" not in files:
        raise ValueError("no events.jsonl in this run")
    events = []
    for n, line in enumerate(read_text(os.path.join(folder, "events.jsonl")).splitlines(), 1):
        if not line.strip():
            continue
        e = common.loads(line)
        if not isinstance(e, dict) or e.get("lane") not in LANES or e.get("kind") not in KINDS:
            raise ValueError(f"events.jsonl line {n}: lane or kind outside the interface")
        srcs = e.get("src") if isinstance(e.get("src"), list) else [e.get("src")]
        # A terminal-session conclusion depends on the actor's command/job binding,
        # even in older exports that attributed it only to controller accounting.
        # Keep the archived bytes; conservatively label the derived display.
        if (isinstance(cap.get("source"), dict) and cap["source"].get("kind") == "terminal-session"
                and e["kind"] == "ctx" and "user-terminal" not in srcs):
            srcs = srcs + ["user-terminal"]
        unknown = [s for s in srcs if s not in trust_table]
        if unknown:
            raise ValueError(f"events.jsonl line {n}: source {unknown[0]!r} is not in the trust table")
        levels = [trust_table[s]["trust"] for s in srcs]
        weakest = max(levels, key=TRUST_ORDER.index)
        ev = str(e.get("ev") or "")
        if ev and (ev.split("#")[0] not in files or ev.startswith("/") or ".." in ev):
            raise ValueError(f"events.jsonl line {n}: evidence path outside this run's verified files")
        events.append({"i": len(events), "t": event_time(e.get("t")), "lane": e["lane"], "kind": e["kind"],
                       "src": srcs, "trust": weakest,
                       "trust_parts": [{"src": s, "trust": trust_table[s]["trust"]} for s in srcs] if len(set(levels)) > 1 else None,
                       "why": trust_table[srcs[0]]["why"] if len(srcs) == 1 else "mixed sources: labelled by the weakest",
                       **{k: str(e.get(k) or "")[:2000] for k in ("host", "actor", "title", "text")}, "ev": ev or None})
    events.sort(key=lambda e: (e["t"], e["i"]))           # stable: equal stamps keep the capture's order (C7)
    observations = []
    for name in cap.get("observations") or []:
        if name not in files:
            continue
        o = common.loads(read_text(os.path.join(folder, name)))
        if isinstance(o, dict) and common.finite_time(o.get("time")):
            nodes = o.get("nodes") if isinstance(o.get("nodes"), dict) else {}
            observations.append({"t": int(o["time"]), "file": name, "lease_held": (o.get("lease") or {}).get("held"),
                                 "partitions": o.get("partitions") if isinstance(o.get("partitions"), dict) else None,
                                 "hosts": {h: {"k8s_ready": v.get("k8s_ready"), "slurmd_pod_ready": v.get("slurmd_pod_ready"),
                                               "slurm_state": v.get("slurm_state")} for h, v in nodes.items() if isinstance(v, dict)},
                                 "share_pods": len(o.get("share_mounts") or {}) if isinstance(o.get("share_mounts"), dict) else None})
    actors = [{"name": str(a.get("account")), "under_test": a.get("under_test") is True}
              for a in cap.get("actors") or [] if isinstance(a, dict) and a.get("account")]
    sums = {}
    try:
        for line in read_text(os.path.join(folder, "SHA256SUMS")).splitlines():
            m = SUMS_RX.fullmatch(line.strip())
            if m:
                sums[m.group(2)] = m.group(1)[:12]
    except OSError:
        pass
    sim = simulation(folder, files, cap)
    return {**({"simulation": sim} if sim is not None else {}), **({"physical": phys} if phys is not None else {}), "folder": rel, "run_id": str(cap.get("run_id") or rel)[:80], "title": str(cap.get("title") or "")[:160],
            "lease_label": cap.get("lease_label"), "start": start, "stop": stop, "captured_at": captured,
            "capture_late": captured is None or captured - stop > LATE_CAPTURE_S,
            "actors": actors, "events": events, "observations": sorted(observations, key=lambda o: o["t"]),
            "files": [{"name": f, "sha256": sums.get(f), "about": str((cap.get("files") or {}).get(f) or "")[:200]} for f in files],
            "recovery": {k: cap.get("recovery", {}).get(k) for k in ("before", "after", "restore_test")} if isinstance(cap.get("recovery"), dict) else None,
            "terminal": terminals(folder, files, cap)}


# --- terminal playback (8 Oct) --------------------------------------------------------------------
# A terminal-session run keeps the user's screen as asciicast v2 (terminal/<name>.cast). The page
# cannot take raw frames: the scrubber removes control characters (ESC included), and a name typed
# one character per frame cannot be recognised in any single frame. So the screen is replayed here
# through a small terminal emulator at the recording's width, and published as complete logical
# lines (soft-wrapped rows joined), each with the time it settled and the time it began to change.
# Pauses are not proof that an identifier is complete. Keep only the final version of each
# logical line before scrubbing, with its first-change and last-change times. The page interpolates
# typing between these times; it is a scrubbed transcript, not a pixel-faithful desktop recording.

CAST_MAX = 2 << 20
LINES_MAX = 6000
LINE_MAX = 4000
SETTLE_S = 2.0
_CSI_RX = re.compile(r"\[([0-9;?<>=]*)([ -/]*)([@-~])")


class _Screen:
    """rows of characters, soft-wrap flags, a cursor with xterm's pending wrap"""

    def __init__(self, width, height):
        self.w, self.h = width, height
        self.rows, self.soft = [[]], [False]
        self.r = self.c = self.top = 0
        self.pending = False
        self.saved = (0, 0)
        self.dirty = set()

    def _ensure(self, r):
        if not 0 <= r < LINES_MAX:
            raise ValueError("cast cursor exceeds the playback row limit")
        while len(self.rows) <= r:
            self.rows.append([]); self.soft.append(False)

    def start(self, r):
        while r > 0 and self.soft[r - 1]:
            r -= 1
        return r

    def _touch(self):
        self.dirty.add(self.start(self.r))

    def put(self, ch):
        if self.pending:
            self.soft[self.r] = True
            self.r += 1; self.c = 0; self.pending = False
            self._ensure(self.r)
        row = self.rows[self.r]
        while len(row) < self.c:
            row.append(" ")
        if self.c < len(row):
            row[self.c] = ch
        else:
            row.append(ch)
        self._touch()
        if self.c >= self.w - 1:
            self.pending = True
        else:
            self.c += 1

    def newline(self):
        self.r += 1; self.pending = False
        self._ensure(self.r)

    def csi(self, params, final):
        nums = [int(p) if p.isdigit() else 0 for p in params.lstrip("?<>=").split(";")] if params else []
        n = nums[0] if nums and nums[0] > 0 else 1
        row = self.rows[self.r]
        if final == "K":
            mode = nums[0] if nums else 0
            if mode == 0:
                del row[self.c:]
            elif mode == 1:
                for i in range(min(self.c + 1, len(row))):
                    row[i] = " "
            else:
                row.clear()
            self._touch()
        elif final in "ABCDGEFHf":
            self.pending = False
            if final == "A":
                self.r = max(self.top, self.r - n)
            elif final in "BE":
                self.r += n; self._ensure(self.r)
                if final == "E":
                    self.c = 0
            elif final == "F":
                self.r = max(self.top, self.r - n); self.c = 0
            elif final == "C":
                self.c = min(self.w - 1, self.c + n)
            elif final == "D":
                self.c = max(0, self.c - n)
            elif final == "G":
                self.c = min(self.w - 1, n - 1)
            else:                                                   # H, f: row;col on the visible screen
                self.top = max(self.top, len(self.rows) - self.h)
                self.r = self.top + ((nums[0] if nums and nums[0] > 0 else 1) - 1)
                self.c = min(self.w - 1, (nums[1] if len(nums) > 1 and nums[1] > 0 else 1) - 1)
                self._ensure(self.r)
        elif final == "J":
            mode = nums[0] if nums else 0
            if mode in (2, 3):                                      # clear: a fresh screen below everything
                self.top = len(self.rows); self.r = self.top; self.c = 0; self.pending = False
                self._ensure(self.r)
            else:
                del row[self.c:]
                for i in range(self.r + 1, len(self.rows)):
                    if self.rows[i]:
                        self.rows[i] = []; self.dirty.add(self.start(i))
                self._touch()
        elif final == "P":
            del row[self.c:self.c + n]; self._touch()
        elif final == "@":
            row[self.c:self.c] = [" "] * min(n, self.w); del row[self.w:]; self._touch()
        elif final == "X":
            for i in range(self.c, min(self.c + n, len(row))):
                row[i] = " "
            self._touch()
        # m (colour), h/l (modes such as bracketed paste), r (scroll region) and the rest change no text

    def feed(self, text):
        i = 0
        while i < len(text):
            ch = text[i]
            if ch == "\x1b":
                nxt = text[i + 1:i + 2]
                if nxt == "[":
                    m = _CSI_RX.match(text, i + 1)
                    if not m:
                        return text[i:]                             # an incomplete sequence: keep for the next frame
                    self.csi(m.group(1), m.group(3)); i = m.end(); continue
                if nxt == "]":                                      # OSC (window title): to BEL or ESC \
                    end = min([p for p in (text.find("\x07", i), text.find("\x1b\\", i)) if p >= 0] or [-1])
                    if end < 0:
                        return text[i:]
                    i = end + (1 if text[end] == "\x07" else 2); continue
                if nxt == "":
                    return text[i:]
                if nxt in "()*+":
                    i += 3; continue
                if nxt == "7":
                    self.saved = (self.r, self.c)
                elif nxt == "8":
                    self.r, self.c = self.saved; self.pending = False
                elif nxt == "M":
                    self.r = max(self.top, self.r - 1)
                elif nxt == "c":
                    self.top = len(self.rows); self.r = self.top; self.c = 0; self._ensure(self.r)
                i += 2; continue
            if ch == "\r":
                self.c = 0; self.pending = False
            elif ch == "\n":
                self.newline()
            elif ch == "\b":
                self.c = max(0, self.c - 1); self.pending = False
            elif ch == "\t":
                self.c = min(self.w - 1, (self.c // 8 + 1) * 8)
            elif ch >= " " and ch != "\x7f":
                self.put(ch)
            i += 1
        return ""

    def text(self, s):
        """(the logical line starting at row s, the number of rows it takes)"""
        out, r = [], s
        while True:
            out.append("".join(self.rows[r]))
            if r + 1 >= len(self.rows) or not self.soft[r]:
                break
            r += 1
        text = "".join(out).rstrip()
        if len(text) > LINE_MAX:
            raise ValueError("cast logical line exceeds the playback text limit")
        return text, r - s + 1


def terminal_lines(cast_text, width, height):
    """[[t_settled, start_row, t_began, text, rows], ...] from asciicast v2 output frames; rows lets the
    page keep blank lines (never written, so never an event) between logical lines"""
    scr = _Screen(width, height)
    pending, last, out, carry = {}, {}, [], ""

    def emit(s, now=None):
        t0, t1 = pending.pop(s)
        text, rows = scr.text(s)
        if last.get(s) != (text, rows):
            last[s] = (text, rows)
            out.append([round(t1, 3), s, round(t0, 3), text, rows])

    t = 0.0
    for n, line in enumerate(cast_text.splitlines()[1:], 2):
        if not line.strip():
            continue
        fr = common.loads(line)
        if not (isinstance(fr, list) and len(fr) == 3 and type(fr[0]) in (int, float) and 0 <= fr[0] < 86400 * 7
                and fr[0] >= t and isinstance(fr[2], str)):
            raise ValueError(f"cast line {n}: not an asciicast v2 frame in time order")
        if fr[1] != "o":
            continue
        t = float(fr[0])
        for s in [s for s, (t0, t1) in pending.items() if t - t1 >= SETTLE_S]:
            emit(s)
        scr.dirty.clear()
        carry = scr.feed(carry + fr[2])
        for s in scr.dirty:
            t0, _ = pending.get(s, (t, t))
            pending[s] = (t0, t)
        here = scr.start(scr.r)
        for s in [s for s in pending if s != here]:
            emit(s)
        if len(out) > LINES_MAX:
            raise ValueError("cast has more lines than the playback limit")
    if carry:
        raise ValueError("cast ends with an incomplete terminal escape")
    for s in sorted(pending):
        emit(s)
    # A pause can split a sensitive identifier across emissions. Never publish an intermediate
    # version, even if it looked settled at the time. Scrubbing sees the complete final line.
    final = {}
    for event in out:
        previous = final.get(event[1])
        if previous is not None:
            event[2] = min(event[2], previous[2])
        final[event[1]] = event
    out = list(final.values())
    out.sort(key=lambda e: (e[0], e[1]))
    return out, round(t, 3)


def terminals(folder, files, cap):
    """the run's screens for playback, or [] for runs that are not terminal sessions"""
    if not (isinstance(cap.get("source"), dict) and cap["source"].get("kind") == "terminal-session"):
        return []
    out = []
    for name in sorted(f for f in files if re.fullmatch(r"terminal/[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.cast", f)):
        path = os.path.join(folder, name)
        if os.path.getsize(path) > CAST_MAX:
            out.append({"name": name[9:-5], "file": name, "withheld": "larger than the playback limit"}); continue
        text = read_text(path)
        try:
            head = common.loads(text.splitlines()[0]) if text else None
        except ValueError:
            head = None
        if not isinstance(head, dict) or head.get("version") != 2:
            out.append({"name": name[9:-5], "file": name, "withheld": "not an asciicast v2 recording"}); continue
        w, ht = head.get("width"), head.get("height")
        w = w if isinstance(w, int) and 20 <= w <= 400 else 80
        ht = ht if isinstance(ht, int) and 5 <= ht <= 200 else 24
        try:
            lines, duration = terminal_lines(text, w, ht)
        except ValueError as e:
            out.append({"name": name[9:-5], "file": name, "withheld": str(e)[:200]}); continue
        out.append({"name": name[9:-5], "file": name, "width": w, "height": ht, "duration": duration,
                    "start": head.get("timestamp") if common.finite_time(head.get("timestamp")) else None,
                    "lines": lines})
    return out


def vet_terminals(doc, scrubber):
    """scrub each screen on its own; one whose lines keep residue is withheld, never the whole file"""
    for run in doc["scenarios"]["runs"]:
        for i, term in enumerate(run.get("terminal") or []):
            if "lines" not in term:
                continue
            clean = scrubber.scrub(term)
            left = scrubber.residue(clean)
            run["terminal"][i] = clean if not left else {"name": term["name"], "file": term["file"],
                                                         "withheld": "residue after scrubbing: " + ",".join(left)}
    return doc


def build(root, commit, now, trust_table=None, only=None):
    """the evidence document from root/evidence (unscrubbed; callers scrub or not); `only`: the
    folders the role shipped (SOURCE.json), so a folder since removed from git is not shown"""
    trust_table = trust_table or load_trust()
    evidence = os.path.join(root, "evidence")
    doc = {"schema": 1, "kind": "evidence", "generated_at": now, "source": {"commit": commit}, "folders": [],
           "acceptance": [], "recovery_points": [], "scenarios": {"runs": [], "errors": []}}
    for rel in folders(evidence):
        if only is not None and rel not in only:
            continue
        path = os.path.join(evidence, rel)
        v = verify(path)
        entry = {"folder": rel, "sums": v["state"], "detail": v["detail"], "used": []}
        doc["folders"].append(entry)
        if v["state"] != "ok":
            continue
        files = v["files"]
        try:
            rows = acceptance(path, rel, files)
            if rows:
                doc["acceptance"] += rows; entry["used"].append("acceptance")
            for name, parse in (("recovery-points.txt", recovery_txt), ("recovery-points.json", recovery_json)):
                if name in files:
                    pts = parse(read_text(os.path.join(path, name)), rel)
                    if pts:
                        doc["recovery_points"] += pts; entry["used"].append("recovery points")
            if "capture.json" in files:
                try:
                    doc["scenarios"]["runs"].append(scenario(path, rel, files, trust_table)); entry["used"].append("scenario run")
                except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as e:
                    msg = str(e) if type(e) is ValueError else type(e).__name__
                    doc["scenarios"]["errors"].append({"folder": rel, "error": msg[:300]}); entry["used"].append("scenario run (rejected)")
        except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as e:
            entry["detail"] += f"; parse error: {type(e).__name__}"
    doc["source"]["folders"] = len(doc["folders"])
    doc["recovery_points"].sort(key=lambda p: (p["created"] or 0, p["folder"]))
    doc["scenarios"]["runs"].sort(key=lambda r: r["start"], reverse=True)
    return doc


def source_record(src):
    """(commit, folders) from SOURCE.json, written by the role; (None, None) if unreadable"""
    try:
        with open(os.path.join(src, "SOURCE.json"), encoding="utf-8") as f:
            s = json.load(f)
        commit = s["commit"] if re.fullmatch(r"[0-9a-f]{40}", str(s.get("commit"))) else None
        shipped = set(s["folders"]) if isinstance(s.get("folders"), list) else None
        return commit, shipped
    except (OSError, ValueError, KeyError, TypeError):
        return None, None


def run(cfg, now=None):
    now = common.now() if now is None else int(now)
    src = cfg["evidence"]["source"]
    commit, shipped = source_record(src)
    doc = build(src, commit, now, only=shipped)
    doc["build"] = "scrubbed"
    # always scrubbed: this entry point has no unscrubbed output (C4)
    scrubber = common.Scrubber.from_config(cfg)
    return common.publish(os.path.join(cfg["www_data"], "evidence.json"), vet_terminals(doc, scrubber), scrubber)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--config", required=True)
    r.add_argument("--now", type=float)
    s = sub.add_parser("select")
    s.add_argument("--repo", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "select":   # a folder holding a symbolic link is never shipped
        ev = os.path.join(a.repo, "evidence")
        print(json.dumps([f for f in folders(ev) if not has_link(os.path.join(ev, f))]))
        return 0
    try:
        cfg = common.load_config(a.config)
    except (OSError, ValueError, KeyError) as e:
        print(f"prace-dash-evidence: configuration: {e}", file=sys.stderr)
        return 2
    try:
        doc = run(cfg, a.now)
    except ValueError as e:
        print(f"prace-dash-evidence: {e}", file=sys.stderr)
        return 3
    bad = [f["folder"] for f in doc["folders"] if f["sums"] != "ok"]
    print(f"prace-dash-evidence: {len(doc['folders'])} folder(s), {len(doc['acceptance'])} acceptance row(s), "
          f"{len(doc['recovery_points'])} recovery point(s), {len(doc['scenarios']['runs'])} scenario run(s)"
          + (f"; not verified: {', '.join(bad)}" if bad else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())

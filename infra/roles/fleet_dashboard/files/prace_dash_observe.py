#!/usr/bin/python3
"""prace-dash-observe (roles/fleet_dashboard, every 60 s): the Cluster and Slurm tab data, derived only
from what the off-node monitor already keeps on mgmt-git01 (roles/fleet_monitor):

  state.json               last outcome and reasons, alert state         (monitor, health only)
  history.jsonl            one line per monitor run {t, outcome, reasons, events}
  latest-observation.json  the raw observation the monitor pulled        (after MR 2a; else absent)
  deployed.json            the deployed profile the monitor judges against

It opens no SSH session, reads no other host and needs no network (its unit runs with
PrivateNetwork=yes). Every input is untrusted (contract C1): size and string caps, an outcome
whitelist, hostname keys checked against the deployed profile, timestamps parsed. The output is
scrubbed (C4) and written atomically to <www_data>/latest.json; with residue it is not written.

The 60-second monitor evaluates health only: it never reports CONFIGURATION drift. It can report
DRIFT for structural reasons (an unexpected Kubernetes node, a native observation of a host not
expected native: tools/fleet_audit.py). Configuration drift comes only from the nightly CI audit.

  prace_dash_observe.py run --config /etc/prace-dash/dash.json [--now EPOCH]
"""
import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import prace_dash_common as common  # noqa: E402

OUTCOMES = ("HEALTHY", "DRIFT", "UNREACHABLE_OR_ERROR", "DEFERRED_MAINTENANCE", "UNHEALTHY")
MAX_OBSERVATION = 1 << 20
MAX_STATE = 256 << 10
MAX_PROFILE = 256 << 10
HISTORY_TAIL = 4 << 20
HISTORY_DAYS = 7
STALE_S = 180
LEASE_RX = re.compile(r"holder=([a-z0-9-]+)(?: label=(\S+))? id=([0-9a-f]{8,}) since=(\S+)")   # as tools/fleet_audit.py
NODE_KEYS = ("k8s_ready", "role", "slurm_state", "slurmd_pod_ready", "slurmd_pods", "slurm_gres", "pod_path")


def text_list(value, limit=50):
    return [str(v) for v in value[:limit]] if isinstance(value, list) else []


def read_state(path):
    try:
        st = common.clip_strings(common.load_json_capped(path, MAX_STATE))   # the monitor's own file: long reasons are cut, not fatal
    except (OSError, ValueError) as e:
        return None, f"monitor state unreadable: {e}"
    if not isinstance(st, dict) or st.get("last_outcome") not in OUTCOMES or not common.finite_time(st.get("last_run")):
        return None, "monitor state malformed (outcome or last run)"
    issue = st.get("issue")
    return {"outcome": st["last_outcome"], "reasons": text_list(st.get("last_reasons")),
            "last_run": st["last_run"], "last_ok": st.get("last_ok") if common.finite_time(st.get("last_ok")) else None,
            "alert_open": st.get("alert_open") is True, "issue": issue if type(issue) is int else None,
            "maintenance": st.get("maintenance") is True}, None


def history_lines(path):
    """complete JSON lines from the tail of the history (and its rotated predecessor if the tail
    does not reach back far enough); malformed lines are skipped and counted"""
    out, bad = [], 0
    for p in (path + ".1", path):
        try:
            with open(p, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - HISTORY_TAIL))
                raw = f.read(HISTORY_TAIL)
        except OSError:
            continue
        lines = raw.decode("utf-8", "replace").splitlines()
        if size > HISTORY_TAIL:
            lines = lines[1:]                     # the first line may be cut
        for line in lines:
            try:
                row = common.clip_strings(common.loads(line))
            except (ValueError, RecursionError):
                bad += 1
                continue
            if isinstance(row, dict) and row.get("outcome") in OUTCOMES and common.finite_time(row.get("t")):
                out.append(row)
            else:
                bad += 1
    out.sort(key=lambda r: r["t"])
    return out, bad


def read_history(path, now):
    rows, bad = history_lines(path)
    if not rows:
        return None, "monitor history missing" if not os.path.exists(path) else "monitor history has no readable line"
    since = now - HISTORY_DAYS * 86400
    transitions, events, prev = [], [], None
    for r in rows:
        if r["outcome"] != prev and r["t"] >= since:
            transitions.append({"t": r["t"], "from": prev, "to": r["outcome"], "reasons": text_list(r.get("reasons"), 3)})
        if r["t"] >= since:
            for e in text_list(r.get("events"), 10):
                events.append({"t": r["t"], "event": e})
        prev = r["outcome"]
    # the last 24 h as runs of one outcome (the maintenance strip and the outcome bar)
    day = now - 86400
    strip, cur = [], None
    for r in rows:
        if r["t"] < day:
            cur = r["outcome"]
            continue
        if not strip and cur is not None:
            strip.append({"from": int(day), "outcome": cur})
        if not strip or strip[-1]["outcome"] != r["outcome"]:
            strip.append({"from": r["t"], "outcome": r["outcome"]})
    gaps = [{"from": a["t"], "to": b["t"]} for a, b in zip(rows, rows[1:]) if b["t"] >= day and b["t"] - a["t"] > 300]
    return {"first": rows[0]["t"], "last": rows[-1]["t"], "days": HISTORY_DAYS, "skipped_lines": bad,
            "transitions": transitions[-60:], "events": events[-60:], "strip_24h": strip, "gaps_24h": gaps[:50]}, None


def read_profile(path):
    try:
        doc = common.load_json_capped(path, MAX_PROFILE)
    except (OSError, ValueError) as e:
        return None, f"deployed profile unreadable: {e}"
    exp = doc.get("expected") if isinstance(doc, dict) else None
    if (not isinstance(exp, dict) or type(doc.get("profile")) is not int or not isinstance(exp.get("workers"), dict)
            or not isinstance(exp.get("login"), str)):
        return None, "deployed profile malformed"
    return doc, None


def read_observation(path, known, now):
    """the raw observation if it is well-formed; hostname keys outside `known` are counted, never shown"""
    try:
        obs = common.load_json_capped(path, MAX_OBSERVATION)
        common.check_strings(obs)
    except FileNotFoundError:
        return None, "awaiting raw observation (the monitor does not save it yet)"
    except (OSError, ValueError) as e:
        return None, f"raw observation rejected: {e}"
    if not isinstance(obs, dict) or obs.get("schema") != 1 or not common.finite_time(obs.get("time")):
        return None, "raw observation rejected: not a schema-1 observation with a time"
    if obs["time"] - now > 60:
        return None, "raw observation rejected: stamped in the future"
    for key in ("nodes", "disabled_links", "native_hosts", "share_mounts", "slurm_config", "config", "slurm_nodes"):
        if obs.get(key) is not None and not isinstance(obs[key], dict):
            return None, f"raw observation rejected: {key} is not a mapping"
    if obs.get("partitions") is not None and not isinstance(obs["partitions"], dict):
        return None, "raw observation rejected: partitions is not a mapping"
    obs["_unknown_nodes"] = len([n for n in (obs.get("nodes") or {}) if n not in known])
    return obs, None


def parse_lease(lease):
    if not isinstance(lease, dict) or type(lease.get("held")) is not bool:
        return {"stated": False}
    if not lease["held"]:
        return {"stated": True, "held": False}
    holder = str(lease.get("holder") or "")[:300]
    m = LEASE_RX.fullmatch(holder)
    out = {"stated": True, "held": True, "holder_text": holder}
    if m:
        out.update(holder=m.group(1), label=m.group(2), id=m.group(3))
        try:
            out["since"] = int(common.parse_iso(m.group(4)))
        except ValueError:
            out["malformed"] = True
    else:
        out["malformed"] = True
    return out


def window_phase(lease, partitions):
    if not isinstance(partitions, dict) or not partitions:
        return {"phase": "unknown", "text": "partition states not observed"}
    states = {str(v).lower() for v in partitions.values()}
    # Only an explicit, valid boolean says whether the lease is held (parse_lease: "stated"). A missing,
    # null, empty or malformed lease is unknown: never read as "no lease", never an open window (review R2).
    if lease.get("stated") is not True or type(lease.get("held")) is not bool:
        return {"phase": "unknown", "text": "lease not stated in the observation; partitions " + ", ".join(sorted(states))}
    held = lease["held"]
    if held and states == {"inactive"}:
        return {"phase": "closed", "text": "lease held, every partition inactive (admission closed)"}
    if held and states == {"up"}:
        return {"phase": "open-under-lease", "text": "lease held, partitions up (opening, or work under the lease)"}
    if held:
        return {"phase": "partial", "text": "lease held, partitions mixed: " + ", ".join(sorted(states))}
    if states == {"up"}:
        return {"phase": "open", "text": "no lease, every partition up"}
    return {"phase": "unexplained", "text": "no lease held but partitions are " + ", ".join(sorted(states))}


def guard_check(mounts, guarded):
    """display only: the options each guarded share lacks (nosuid, nodev and its mode)"""
    missing = {}
    for path, mode in sorted((guarded or {}).items()):
        opts = str((mounts or {}).get(path) or "").split(",")
        lack = [w for w in ("nosuid", "nodev", mode) if w not in opts]
        if lack:
            missing[path] = lack
    return missing


def native_summary(report, shares):
    if not isinstance(report, dict):
        return {"error": "not observed"}
    if report.get("errors"):
        return {"error": "; ".join(text_list(report.get("errors"), 5)) or "error"}
    unit = report.get("slurmd") if isinstance(report.get("slurmd"), dict) else {}
    key = report.get("key")
    mounts = {}
    raw_mounts = report.get("mounts") if isinstance(report.get("mounts"), dict) else {}
    for path, m in sorted(raw_mounts.items()):
        if not isinstance(m, dict):
            continue
        sup = str(m.get("super") or "").split(",")
        mounts[path] = {"options": str(m.get("options") or ""), "fstype": m.get("fstype"), "source": m.get("source"),
                        "nfs": [w for w in sup if w.startswith("vers=") or w == "hard"],
                        "lacks": [w for w in ("nosuid", "nodev", (shares or {}).get(path, "")) if w and w not in str(m.get("options") or "").split(",")]}
    return {"time": report.get("time") if common.finite_time(report.get("time")) else None,
            "slurmd": {k: unit.get(k) for k in ("ActiveState", "SubState", "UnitFileState", "NRestarts", "comm")},
            "slurmd_pid": type(unit.get("MainPID")) is int and unit.get("MainPID") > 0,
            "marker": report.get("marker"),
            "key": "absent" if key is None else ("present" if isinstance(key, dict) and key.get("file") is True else "not a file"),
            "mounts": mounts, "boot_id": report.get("boot_id"),
            "config_files": len(report.get("config") or {}) if isinstance(report.get("config"), dict) else 0}


def network_guard(obs, profile, hosts, now):
    expected = (profile or {}).get("expected", {}).get("disabled_links") or {}
    observed = (obs or {}).get("disabled_links") or {}
    rows = []
    for host in hosts:
        targets = expected.get(host)
        if not targets:
            rows.append({"host": host, "in_check": False})
            continue
        row = {"host": host, "in_check": True, "interfaces": [], "alerts": 0, "error": None, "checked": None}
        rep = observed.get(host) if obs else None
        if obs is None:
            row["error"] = "no raw observation"
        elif (not isinstance(rep, dict) or rep.get("schema") != 1 or rep.get("host") != host or rep.get("errors") != []
              or not common.finite_time(rep.get("time"))):
            row["error"] = "missing, invalid or reporting errors: " + "; ".join(text_list((rep or {}).get("errors") if isinstance(rep, dict) else None, 3))
        else:
            row["checked"] = rep["time"]
            ifs = rep.get("interfaces") if isinstance(rep.get("interfaces"), dict) else {}
            for t in targets:
                i = ifs.get(t["name"])
                if not isinstance(i, dict):
                    row["interfaces"].append({"name": t["name"], "observed": False}); row["alerts"] += 1
                    continue
                down = (i.get("admin_up") is False and i.get("carrier") is False and i.get("nm_managed") is False
                        and i.get("operstate") == "DOWN" and i.get("addresses") == [])
                same = i.get("mac") == t.get("mac") and i.get("pci") == t.get("pci")
                row["interfaces"].append({"name": t["name"], "observed": True, "admin_up": i.get("admin_up"),
                                          "carrier": i.get("carrier"), "operstate": i.get("operstate"),
                                          "nm_managed": i.get("nm_managed"),
                                          "addresses": len(i["addresses"]) if isinstance(i.get("addresses"), list) else None,
                                          "identity": "matches" if same else "differs", "down": down})
                row["alerts"] += (not down) + (not same)
            extra = sorted(set(ifs) - {t["name"] for t in targets})
            if extra:
                row["error"] = f"{len(extra)} interface(s) outside the target set"
        rows.append(row)
    stray = [k for k in observed if k not in hosts] if isinstance(observed, dict) else []
    if stray:
        rows.append({"host": "observer", "in_check": True, "interfaces": [], "alerts": 0, "checked": None,
                     "error": f"{len(stray)} entr{'y' if len(stray) == 1 else 'ies'} outside the fleet (observer configuration?)"})
    return rows


def pins(static):
    """C25: the pinned images (roles/slinky slinky_images, as dict2items) and versions the role read
    from the repository at deploy time"""
    out = []
    for item in static.get("images") or []:
        v = item.get("value") if isinstance(item, dict) else None
        if isinstance(v, dict):
            out.append({"name": str(item.get("key")), "version": v.get("tag"), "digest": v.get("digest"), "repository": v.get("repository")})
    for name, version in sorted((static.get("versions") or {}).items()):
        out.append({"name": str(name), "version": version, "digest": None, "repository": None})
    return out


STRUCTURAL = re.compile(r"(unexpected Kubernetes nodes|native observation of hosts not expected native): (.*)")


def withhold(reasons, known):
    """the monitor names unexpected hosts in its structural-DRIFT reasons; names outside the fleet
    are withheld (C1: counted, never shown), fleet names stay (and are scrubbed to their roles)"""
    out = []
    for r in reasons or []:
        m = STRUCTURAL.fullmatch(r)
        if m:
            names = [n.strip() for n in m.group(2).split(",") if n.strip()]
            shown = [n for n in names if n in known]
            hidden = len(names) - len(shown)
            r = f"{m.group(1)}: " + ", ".join(shown + ([f"{hidden} name(s) withheld"] if hidden else []))
        out.append(r)
    return out


def derive(cfg, state, history, obs, profile, errors, now):
    exp = (profile or {}).get("expected") or {}
    login = exp.get("login")
    workers = exp.get("workers") or {}
    hosts = ([login] if login else []) + sorted(workers, key=lambda h: (workers[h] != "cpu", h))
    native_expected = exp.get("native_workers") or {}
    guarded = exp.get("guarded_shares") or {}
    nodes = (obs or {}).get("nodes") or {}
    native_obs = (obs or {}).get("native_hosts") or {}
    shares = (obs or {}).get("share_mounts") or {}
    reasons = (state or {}).get("reasons") or []
    inventory = cfg.get("inventory") or {}
    guard = {r["host"]: r for r in network_guard(obs, profile, hosts, now)}
    rows = []
    for name in hosts:
        n = nodes.get(name) if isinstance(nodes.get(name), dict) else None
        role = "login" if name == login else workers.get(name)
        row = {"name": name, "role": role, "inventory": inventory.get(name),
               "expected_kind": "login" if role == "login" else ("native" if name in native_expected else "pod"),
               "observed": n is not None, "reasons": [r for r in reasons if name in r][:10]}
        if n is not None:
            row.update({k: n.get(k) for k in NODE_KEYS})
            row["kind"] = "login" if role == "login" else ("native" if name in native_obs else "pod")
        if name in native_obs:
            row["native"] = native_summary(native_obs.get(name), (exp.get("native_shares") or {}).get("modes"))
        row["shares"] = [{"pod": pod, "kind": r.get("kind"), "error": r.get("error"),
                          "mounts": r.get("mounts") if isinstance(r.get("mounts"), dict) else None,
                          "lacks": guard_check(r.get("mounts"), guarded) if isinstance(r.get("mounts"), dict) else None}
                         for pod, r in sorted(shares.items()) if isinstance(r, dict) and r.get("node") == name]
        if role == "login":
            cfgmap = (obs or {}).get("config") or {}
            row["config_files"] = len([p for p in cfgmap if not re.match(r"^[a-z0-9-]+:/", p)])
            row["config_missing"] = len([p for p, v in cfgmap.items() if v in ("missing", "unreadable")])
        g = guard.get(name) or {}
        row["links"] = {"in_check": g.get("in_check", False), "alerts": g.get("alerts", 0), "error": g.get("error"),
                        "down": len([i for i in g.get("interfaces", []) if i.get("down")]), "targets": len(g.get("interfaces", []))}
        rows.append(row)
    lease = parse_lease((obs or {}).get("lease"))
    partitions = (obs or {}).get("partitions")
    expected_parts = exp.get("partitions") or {}
    part_rows = ([{"name": k, "state": str(v), "expected": expected_parts.get(k)} for k, v in sorted(partitions.items())]
                 if isinstance(partitions, dict) else [])
    sc = (obs or {}).get("slurm_config") or {}
    exp_sc = exp.get("slurm_config") or {}
    config_rows = [{"key": k, "value": sc.get(k), "expected": exp_sc.get(k)} for k in sorted(set(sc) | set(exp_sc))]
    return {
        "schema": 1, "kind": "observe", "generated_at": now, "build": "scrubbed",
        "errors": errors,
        "monitor": state,
        "profile": None if profile is None else {
            "version": profile.get("profile"), "source_revision": str(profile.get("source_revision") or "")[:12],
            "promoted_from_observation": profile.get("promoted_from_observation"),
            "workers": len(workers), "native_workers": sorted(native_expected)},
        "observation": None if obs is None else {
            "time": obs["time"], "host": obs.get("host"), "duration_s": obs.get("duration_s"),
            "errors": text_list(obs.get("errors"), 20), "controller_up": obs.get("controller_up"),
            "k8s_api": obs.get("k8s_api"), "accounting": obs.get("accounting"),
            "unknown_nodes": obs.get("_unknown_nodes", 0), "stale": now - obs["time"] > STALE_S},
        "lease": lease,
        "window": window_phase(lease, partitions),
        "hosts": rows,
        "partitions": part_rows,
        "slurm_config": config_rows,
        "network_guard": list(guard.values()),
        "history": history,
        "static": {"pins": pins(cfg.get("static") or {}), "policy": (cfg.get("static") or {}).get("policy") or {}},
    }


def run(cfg, now=None):
    now = common.now() if now is None else int(now)
    m = cfg["monitor"]
    errors = []
    state, err = read_state(m["state"])
    errors += [err] if err else []
    history, err = read_history(m["history"], now)
    errors += [err] if err else []
    profile, err = read_profile(m["profile"])
    errors += [err] if err else []
    known = set()
    if profile:
        known = {profile["expected"]["login"], *profile["expected"]["workers"]}
    obs, err = read_observation(m["observation"], known, now)
    errors += [err] if err else []
    if state:
        state["reasons"] = withhold(state["reasons"], known)
    for t in (history or {}).get("transitions", []):
        t["reasons"] = withhold(t["reasons"], known)
    try:
        doc = derive(cfg, state, history, obs, profile, errors, now)
    except (TypeError, AttributeError, KeyError, ValueError, IndexError) as e:
        # a shape the checks above did not foresee: the observation is dropped, never the page
        doc = derive(cfg, state, history, None, profile, errors + [f"raw observation rejected: unexpected shape ({type(e).__name__})"], now)
    # always scrubbed: this collector has no unscrubbed output (C4)
    return common.publish(os.path.join(cfg["www_data"], "latest.json"), doc, common.Scrubber.from_config(cfg))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--config", required=True)
    r.add_argument("--now", type=float)
    a = ap.parse_args(argv)
    try:
        cfg = common.load_config(a.config)
    except (OSError, ValueError, KeyError) as e:
        print(f"prace-dash-observe: configuration: {e}", file=sys.stderr)
        return 2
    try:
        doc = run(cfg, a.now)
    except ValueError as e:                         # residue: nothing written
        print(f"prace-dash-observe: {e}", file=sys.stderr)
        return 3
    mon = doc.get("monitor") or {}
    print(f"prace-dash-observe: monitor {mon.get('outcome', 'unknown')}, "
          f"observation {'present' if doc.get('observation') else 'absent'}, {len(doc['errors'])} source error(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

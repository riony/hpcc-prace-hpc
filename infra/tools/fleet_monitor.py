#!/usr/bin/env python3
"""Off-node fleet monitor (roles/fleet_monitor on mgmt-git01), one observation per run of its
60-second timer. It fetches the read-only observation from the login node over a forced-command
SSH key (the key can run nothing else), evaluates HEALTH only (tools/fleet_audit.py; configuration
drift is the scheduled CI audit's job), keeps its state and history, and alerts on transitions:

  - PROBLEM (UNHEALTHY or UNREACHABLE_OR_ERROR) twice in a row -> one GitLab alert issue
    (confidential, assigned to and mentioning the owner, so GitLab emails them);
  - OK (HEALTHY, or DEFERRED_MAINTENANCE within its time limit) twice in a row while an alert is
    open -> a recovery comment and the issue is closed;
  - maintenance start/end is logged in the history, never alerted; an overrun is a PROBLEM.
No automatic remediation. The monitor's own failure (the unit fails) opens an alert through
`self-alert`; the CI drift audit checks this monitor's freshness (`check-fresh`).

Kept in the state directory, each 0644 for readers on this VM: state.json (last outcome, alert),
history.jsonl (one line per run) and latest-observation.json, the raw observation exactly as pulled
(for roles/fleet_dashboard, which opens no SSH session of its own). A failed pull leaves the
previous observation in place; its own `time` shows how old it is.

  fleet_monitor.py run --config /etc/prace-monitor/monitor.json
  fleet_monitor.py self-alert --config FILE --reason TEXT
  fleet_monitor.py check-fresh --state FILE --max-age SECONDS
"""
import argparse
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fleet_audit  # noqa: E402

OK = {"HEALTHY", "DEFERRED_MAINTENANCE"}
STREAK = 2


def fetch(cfg):
    cmd = ["ssh", "-T", "-i", cfg["key"], "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "ConnectTimeout=15",
           "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={cfg['known_hosts']}", cfg["target"]]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=cfg.get("fetch_timeout", 60))
        return json.loads(r.stdout) if r.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None


class GitLab:
    """Alert sink: one confidential issue per incident. The token is read, never logged."""
    def __init__(self, cfg):
        self.base = cfg["gitlab_url"].rstrip("/") + "/api/v4"
        self.project = urllib.parse.quote(cfg["project"], safe="")
        self.owner = cfg["owner"]
        with open(cfg["token_file"]) as f:
            self.token = f.read().strip()

    def call(self, method, path, data=None):
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(self.base + path, data=body, method=method,
                                     headers={"PRIVATE-TOKEN": self.token, "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read() or b"null")

    def open(self, title, text):
        users = self.call("GET", "/users?username=" + urllib.parse.quote(self.owner))
        data = {"title": title, "description": f"@{self.owner}\n\n{text}", "confidential": True,
                "labels": "alert,fleet-monitor"}
        if users:
            data["assignee_ids"] = [users[0]["id"]]
        return self.call("POST", f"/projects/{self.project}/issues", data)["iid"]

    def close(self, iid, text):
        self.call("POST", f"/projects/{self.project}/issues/{iid}/notes", {"body": text})
        self.call("PUT", f"/projects/{self.project}/issues/{iid}", {"state_event": "close"})


class LogSink:
    """Test/dry-run sink: alerts appended to a file."""
    def __init__(self, path):
        self.path = path

    def open(self, title, text):
        with open(self.path, "a") as f:
            f.write(json.dumps({"open": title, "text": text}) + "\n")
        return int(time.time())

    def close(self, iid, text):
        with open(self.path, "a") as f:
            f.write(json.dumps({"close": iid, "text": text}) + "\n")


def sink(cfg):
    return LogSink(cfg["alert_log"]) if cfg.get("alert_log") else GitLab(cfg)


def stamp(t):
    return time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(t))


def run_once(cfg, fetch_fn=fetch, now=None):
    now = time.time() if now is None else now
    state_path = os.path.join(cfg["state_dir"], "state.json")
    try:
        with open(state_path) as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {"alert_open": False, "issue": None, "problem_streak": 0, "ok_streak": 0, "maintenance": False}
    with open(cfg["expected"]) as f:
        expected = fleet_audit.expected_from(json.load(f))   # the deployed profile (or a plain file)
    if expected is None:
        raise ValueError(f"unreadable expectations in {cfg['expected']}")
    snap = fetch_fn(cfg)
    outcome, reasons = fleet_audit.evaluate(snap, expected, health_only=True, now=now)
    ok = outcome in OK
    st["ok_streak"] = st["ok_streak"] + 1 if ok else 0
    st["problem_streak"] = 0 if ok else st["problem_streak"] + 1
    events = []
    maint = outcome == "DEFERRED_MAINTENANCE"
    if maint != st.get("maintenance", False):
        events.append("maintenance started" if maint else "maintenance ended")
        st["maintenance"] = maint
    if not st["alert_open"] and st["problem_streak"] >= STREAK:
        text = (f"**{outcome}** since {stamp(now)} (observed by fleet-monitor on mgmt-git01, {STREAK} consecutive checks)."
                "\n\n" + "\n".join(f"- {r}" for r in reasons)
                + "\n\nNo automatic remediation. The issue is closed automatically after recovery.")
        st["issue"] = sink(cfg).open(f"[fleet-monitor] {outcome}: {reasons[0][:120]}", text)
        st["alert_open"] = True
        events.append(f"alert opened (issue {st['issue']})")
    elif st["alert_open"] and st["ok_streak"] >= STREAK:
        sink(cfg).close(st["issue"], f"Recovered: **{outcome}** at {stamp(now)} ({STREAK} consecutive checks).\n\n"
                        + "\n".join(f"- {r}" for r in reasons))
        events.append(f"alert closed (issue {st['issue']})")
        st["alert_open"], st["issue"] = False, None
    st.update(last_run=int(now), last_outcome=outcome, last_reasons=reasons)
    if ok:
        st["last_ok"] = int(now)
    os.makedirs(cfg["state_dir"], exist_ok=True)
    tmp = state_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, indent=1, sort_keys=True)
    os.chmod(tmp, 0o644)
    os.replace(tmp, state_path)
    hist = os.path.join(cfg["state_dir"], "history.jsonl")
    if os.path.exists(hist) and os.path.getsize(hist) > 20 * 1024 * 1024:
        os.replace(hist, hist + ".1")
    with open(hist, "a") as f:
        f.write(json.dumps({"t": int(now), "outcome": outcome, "reasons": reasons, "events": events}) + "\n")
    if isinstance(snap, dict):
        save_observation(cfg["state_dir"], snap)
    return outcome, events


def save_observation(state_dir, snap):
    """the raw observation as pulled, replaced atomically (written beside, renamed over), 0644"""
    path = os.path.join(state_dir, "latest-observation.json")
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(snap, f, sort_keys=True)
        f.write("\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def main(argv=None):
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run"); r.add_argument("--config", required=True)
    s = sub.add_parser("self-alert"); s.add_argument("--config", required=True); s.add_argument("--reason", required=True)
    c = sub.add_parser("check-fresh"); c.add_argument("--state", required=True); c.add_argument("--max-age", type=int, default=300)
    a = ap.parse_args(argv)
    if a.cmd == "check-fresh":
        try:
            with open(a.state) as f:
                st = json.load(f)
        except (OSError, ValueError):
            print("fleet-monitor: no state (monitor not running?)"); return 2
        age = time.time() - st.get("last_run", 0)
        print(f"fleet-monitor: last run {int(age)} s ago, outcome {st.get('last_outcome')}, alert open: {st.get('alert_open')}")
        return 0 if age <= a.max_age else 2
    with open(a.config) as f:
        cfg = json.load(f)
    if a.cmd == "self-alert":
        mark = os.path.join(cfg["state_dir"], "self-alert.stamp")
        if os.path.exists(mark) and time.time() - os.path.getmtime(mark) < 3600:
            print("self-alert already sent within the last hour"); return 0     # one per hour at most
        sink(cfg).open("[fleet-monitor] monitor failure", f"The fleet monitor on mgmt-git01 failed: {a.reason} ({stamp(time.time())}). "
                       "Fleet health is not being observed until it runs again.")
        with open(mark, "w") as f:
            f.write(stamp(time.time()) + "\n")
        return 0
    outcome, events = run_once(cfg)
    print(outcome + ("" if not events else " | " + "; ".join(events)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

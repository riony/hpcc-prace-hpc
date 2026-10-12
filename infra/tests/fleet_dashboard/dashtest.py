"""Shared setup for the fleet dashboard tests (roles/fleet_dashboard). Offline by construction:
PRACE_DASH_OFFLINE=1 is set and a recorder audit hook is installed BEFORE any collector module is
imported, so the collectors' own guard refuses every socket and the recorder sees every attempt.
No test contacts a fleet host, a BMC, GitLab or any other network peer."""
import copy
import json
import os
import sys
import urllib.parse

os.environ["PRACE_DASH_OFFLINE"] = "1"
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.dont_write_bytecode = True
SOCKET_EVENTS = []


def _recorder(event, args):
    if event.startswith("socket.") or event == "urllib.Request":
        SOCKET_EVENTS.append(event)


sys.addaudithook(_recorder)   # runs before the collectors' guard, which raises

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
FILES = os.path.join(REPO, "infra", "roles", "fleet_dashboard", "files")
FIX = os.path.join(HERE, "fixtures")
sys.path.insert(0, FILES)

import prace_dash_common as common    # noqa: E402
import prace_dash_evidence as evidence  # noqa: E402
import prace_dash_gitlab as gitlab    # noqa: E402
import prace_dash_observe as observe  # noqa: E402

OBSERVER_88 = os.path.join(REPO, "evidence", "2026-10-05", "observer-88")
WINDOW_T87 = os.path.join(REPO, "evidence", "2026-10-04", "window-t87-t88")
PROFILE = os.path.join(REPO, "infra", "audit", "deployed.json")
SCENARIO_ROOT = os.path.join(FIX, "scenario")
DUMMY_TOKEN = "fx-dummy-token-9f3a7c1e5b2d"   # never a real token; tests grep every output for it
FLEET = ("lab-dl380", "lab-lenovo", "lab-g003", "lab-g004", "lab-g005")
ACCOUNTS = {"synthetic": ["syn-alice", "syn-bob", "syn-carol", "syn-dave", "syn-probe", "syn-nologin", "syn-revoked"],
            "agents": ["agent-perm01", "agent-cleanup01"], "team": ["fx-member-one"]}


def observation(name="unleased"):
    with open(os.path.join(OBSERVER_88, f"observation-{name}.json")) as f:
        return json.load(f)


def native_report(host="lab-lenovo", t=0, **changes):
    """shaped exactly as roles/fleet_observer/files/prace-native-observe.py snapshot() reports"""
    r = {"schema": 1, "host": host, "time": t, "errors": [], "boot_id": "0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b",
         "slurmd": {"ActiveState": "active", "SubState": "running", "UnitFileState": "enabled", "MainPID": 4242, "NRestarts": 0, "comm": "slurmd"},
         "mounts": {p: {"options": f"{m},nosuid,nodev,relatime", "fstype": "nfs4", "source": f"10.90.10.1:{p}",
                        "super": f"{m},vers=4.2,rsize=1048576,hard,proto=tcp"} for p, m in (("/home", "rw"), ("/projects", "rw"), ("/apps", "ro"))},
         "marker": "native", "key": {"owner": "slurm", "mode": "0600", "file": True},
         "config": {"/etc/fstab": "a" * 64, "/usr/lib/systemd/system/slurmd.service": "b" * 64}}
    r.update(changes)
    return r


def config(tmp, **over):
    """a dashboard configuration with every path under tmp; the monitor files are written by env()"""
    os.makedirs(os.path.join(tmp, "www", "data"), exist_ok=True)
    os.makedirs(os.path.join(tmp, "state"), exist_ok=True)
    os.makedirs(os.path.join(tmp, "mon"), exist_ok=True)
    token = os.path.join(tmp, "gitlab-token")
    with open(token, "w") as f:
        f.write(DUMMY_TOKEN + "\n")
    os.chmod(token, 0o600)
    cfg = {"schema": 1, "www_data": os.path.join(tmp, "www", "data"), "state_dir": os.path.join(tmp, "state"),
           "freeze_file": os.path.join(tmp, "freeze.json"),
           "monitor": {"state": os.path.join(tmp, "mon", "state.json"), "history": os.path.join(tmp, "mon", "history.jsonl"),
                       "observation": os.path.join(tmp, "mon", "latest-observation.json"), "profile": over.pop("profile", PROFILE)},
           "gitlab": {"url": "https://gitlab.invalid", "connect": "127.0.0.1", "project": "hpcc/prace-hackathon", "token_file": token,
                      "reservation_labels": ["lease"], "monitor_labels": ["fleet-monitor"], "drift_job": "lab-drift-check",
                      "monitor_token_expires": "2026-10-31"},
           "evidence": {"source": os.path.join(tmp, "src")},
           "scrub": {"map": os.path.join(FILES, "scrub-map.json"), "accounts": copy.deepcopy(ACCOUNTS), "names": {"mgmt-git01.example-tailnet.ts.net": "mgmt-vm"}},
           "inventory": {h: {"model": "fx model", "bmc": "fx bmc", "os": "Rocky Linux 9.8"} for h in FLEET},
           # as the role renders it: slinky_images | dict2items, and versions from the role defaults
           "static": {"images": [{"key": "slurmctld", "value": {"repository": "ghcr.io/slinkyproject/slurmctld", "tag": "25.11.8-rockylinux9",
                                                                "digest": "sha256:" + "c" * 64}}],
                      "versions": {"K3s": "v1.36.4+k3s1", "NVIDIA driver": "580.173.02-1.el9"},
                      "policy": {"GPU share": "4 CPUs and 90 GiB per GPU"}}}
    cfg.update(over)
    return cfg


def write_monitor(cfg, now, outcome="HEALTHY", reasons=None, obs=None, history=None):
    state = {"alert_open": False, "issue": None, "last_ok": now - 30, "last_outcome": outcome, "maintenance": outcome == "DEFERRED_MAINTENANCE",
             "last_reasons": reasons if reasons is not None else ["4 workers usable, controller and accounting answer"], "last_run": now - 30,
             "ok_streak": 3, "problem_streak": 0}
    with open(cfg["monitor"]["state"], "w") as f:
        json.dump(state, f)
    rows = history if history is not None else [{"t": now - 600 + 60 * i, "outcome": "HEALTHY", "reasons": ["ok"], "events": []} for i in range(10)]
    with open(cfg["monitor"]["history"], "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    if obs is not None:
        with open(cfg["monitor"]["observation"], "w") as f:
            json.dump(obs, f)


def responses():
    with open(os.path.join(FIX, "gitlab", "responses.json")) as f:
        return json.load(f)


def fake_get(resp=None, fail=None, calls=None):
    """GitLab stand-in answering from the recorded responses; fail = {endpoint: status}"""
    resp = responses() if resp is None else resp

    def get(endpoint, params=None):
        key = endpoint + ("?" + urllib.parse.urlencode(sorted(params.items())) if params else "")
        if calls is not None:
            calls.append(key)
        for prefix, status in (fail or {}).items():
            if endpoint.startswith(prefix):
                raise gitlab.ApiError(endpoint, status)
        if key not in resp:
            raise gitlab.ApiError(endpoint, 404)
        return copy.deepcopy(resp[key])
    return get


def read(cfg, name):
    with open(os.path.join(cfg["www_data"], name), encoding="utf-8") as f:
        return f.read()

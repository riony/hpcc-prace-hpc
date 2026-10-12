#!/usr/bin/python3
"""prace-dash-gitlab (roles/fleet_dashboard, every 5 min): the CI/CD tab and the banner's reservation,
monitor-issue and drift-audit lines, from GitLab REST v4 on this VM.

Read-only by construction: the only request method is GET, the token is the dashboard's own
(read_api, created by the owner, a 0600 file outside git; never logged, never in the output), and
the connection goes to this VM's own GitLab (connect address 127.0.0.1, TLS name = the GitLab name),
with no proxy and no redirect. About a dozen requests per run; finished pipelines' jobs, drift-audit
results and MR approvals are cached, so a quiet project costs the same dozen small GETs.

Configuration drift appears ONLY here (contract C24): the scheduled `lab-drift-check` job's own
result (audit/result.json in its artifacts). The 60-second monitor never evaluates it.

  prace_dash_gitlab.py run --config /etc/prace-dash/dash.json [--now EPOCH]
"""
import argparse
import http.client
import json
import os
import re
import socket
import ssl
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import prace_dash_common as common  # noqa: E402

MAX_RESPONSE = 2 << 20
OUTCOMES = ("HEALTHY", "DRIFT", "UNREACHABLE_OR_ERROR", "DEFERRED_MAINTENANCE", "UNHEALTHY")
TITLE_OUTCOME = re.compile(r"\[fleet-monitor\] (HEALTHY|DRIFT|UNREACHABLE_OR_ERROR|DEFERRED_MAINTENANCE|UNHEALTHY|monitor failure)\b")
FINISHED = {"success", "failed", "canceled", "skipped"}
JOB_PIPELINES = 6          # recent pipelines whose jobs are shown
SCHEDULED = 14             # daily drift-audit squares
ARTIFACTS_PER_RUN = 3      # drift-audit results fetched per run (each is then cached)
TOKEN_WARN_DAYS = 14


class ApiError(Exception):
    def __init__(self, endpoint, status):
        super().__init__(f"GET {endpoint}: " + (f"HTTP {status}" if isinstance(status, int) else str(status)))
        self.status = status


class _Connection(http.client.HTTPSConnection):
    """TCP to `connect`, TLS verified for the GitLab name (SNI), so loopback needs no DNS"""
    def __init__(self, connect, name, port, context, timeout):
        super().__init__(connect, port, context=context, timeout=timeout)
        self._name = name

    def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self._name)


class Api:
    def __init__(self, cfg, token):
        url = urllib.parse.urlsplit(cfg["url"])
        if url.scheme != "https" or not url.hostname:
            raise ValueError("gitlab.url must be an https URL")
        self.name, self.port = url.hostname, url.port or 443
        self.connect = cfg.get("connect") or self.name
        self.project = urllib.parse.quote(cfg["project"], safe="")
        self._token = token
        self.ctx = ssl.create_default_context()
        self.calls = 0

    def get(self, endpoint, params=None):
        """JSON of one GET; ApiError naming the endpoint (never the token) on any failure"""
        if common.offline():
            raise ApiError(endpoint, f"network refused under {common.OFFLINE_ENV}=1")
        path = "/api/v4" + endpoint.replace(":id", self.project)
        if params:
            path += "?" + urllib.parse.urlencode(params)
        self.calls += 1
        conn = _Connection(self.connect, self.name, self.port, self.ctx, 20)
        try:
            conn.request("GET", path, headers={"Host": self.name, "PRIVATE-TOKEN": self._token,
                                               "Accept": "application/json", "User-Agent": "prace-dash"})
            r = conn.getresponse()
            raw = r.read(MAX_RESPONSE + 1)
            if r.status != 200:
                raise ApiError(endpoint, r.status)
            if len(raw) > MAX_RESPONSE:
                raise ApiError(endpoint, "response too large")
            return common.loads(raw.decode("utf-8"))
        except (OSError, http.client.HTTPException, ValueError) as e:
            raise ApiError(endpoint, type(e).__name__) from None
        finally:
            conn.close()


def days_left(expires, now):
    try:
        return int((common.parse_iso(expires) - now) // 86400)
    except ValueError:
        return None


def token_line(expires, now, source):
    if not expires:
        return {"expires_at": None, "days_left": None, "warn": True, "source": source}
    left = days_left(expires, now)
    return {"expires_at": expires, "days_left": left, "warn": left is None or left <= TOKEN_WARN_DAYS, "source": source}


def ts(value):
    try:
        return int(common.parse_iso(value)) if value else None
    except ValueError:
        return None


def branch(ref):
    """a ref without its owner: this project's branch prefixes are GitLab user names (C4)"""
    ref = str(ref or "")[:120]
    return ref if "/" not in ref else "\u2022\u2022\u2022/" + ref.split("/", 1)[1]


def job_row(j):
    return {"id": j.get("id"), "name": str(j.get("name") or "")[:80], "stage": str(j.get("stage") or "")[:40],
            "status": str(j.get("status") or ""), "duration": round(j["duration"], 1) if isinstance(j.get("duration"), (int, float)) else None,
            "allow_failure": j.get("allow_failure") is True}


def pipeline_row(p):
    created, updated = ts(p.get("created_at")), ts(p.get("updated_at"))
    return {"id": p.get("id"), "ref": branch(p.get("ref")), "status": str(p.get("status") or ""),
            "source": str(p.get("source") or ""), "sha": str(p.get("sha") or "")[:12], "created": created, "updated": updated,
            "wall_s": (updated - created) if created and updated and str(p.get("status")) in FINISHED else None}


def read_freeze(path):
    """an owner-set flag file (no machine-readable freeze exists in the repository); absent = unknown"""
    try:
        doc = common.load_json_capped(path, 4096)
    except FileNotFoundError:
        return {"state": "unknown", "note": "no freeze flag set by the owner"}
    except (OSError, ValueError):
        return {"state": "unknown", "note": "freeze flag unreadable"}
    if not isinstance(doc, dict) or doc.get("state") not in ("frozen", "open"):
        return {"state": "unknown", "note": "freeze flag malformed"}
    return {"state": doc["state"], "note": str(doc.get("note") or "")[:300], "set_at": ts(doc.get("set_at"))}


def section(fn):
    try:
        return fn()
    except ApiError as e:
        return {"error": str(e), "status": e.status if isinstance(e.status, int) else None}
    except (TypeError, AttributeError, KeyError, ValueError, IndexError) as e:   # a response shape nobody foresaw
        return {"error": f"unexpected response shape ({type(e).__name__})", "status": None}


def collect(cfg, get, cache, now):
    g = cfg["gitlab"]

    def get_list(endpoint, params=None):
        out = get(endpoint, params)
        if not isinstance(out, list):
            raise ApiError(endpoint, "unexpected response shape")
        return [x for x in out if isinstance(x, dict)]

    def get_obj(endpoint, params=None):
        out = get(endpoint, params)
        if not isinstance(out, dict):
            raise ApiError(endpoint, "unexpected response shape")
        return out

    jobs_cache = cache.setdefault("jobs", {})
    drift_cache = cache.setdefault("drift", {})
    approvals_cache = cache.setdefault("approvals", {})
    used = {"jobs": set(), "drift": set(), "approvals": set()}

    def jobs_of(pid, status):
        key = str(pid)
        used["jobs"].add(key)
        if key in jobs_cache:
            return jobs_cache[key]
        rows = [job_row(j) for j in get_list(f"/projects/:id/pipelines/{int(pid)}/jobs", {"per_page": 50})]
        if status in FINISHED:
            jobs_cache[key] = rows
        return rows

    def tokens():
        me = get_obj("/personal_access_tokens/self")
        line = token_line(me.get("expires_at"), now, "GET /personal_access_tokens/self")
        line["scopes"] = [str(s) for s in me.get("scopes")][:10] if isinstance(me.get("scopes"), list) else []
        line["broader_than_read_api"] = any(s != "read_api" for s in line["scopes"])
        return line

    def pipelines():
        rows = [pipeline_row(p) for p in get_list("/projects/:id/pipelines", {"per_page": 20, "order_by": "id", "sort": "desc"})
                if type(p.get("id")) is int]
        seen = set()
        for p in rows:
            if len(seen) < JOB_PIPELINES and p["ref"] not in seen:
                seen.add(p["ref"])
                p["jobs"] = jobs_of(p["id"], p["status"])
        main = next((p for p in rows if p["ref"] == "main" and p["source"] != "schedule"), None)
        return {"items": rows, "latest_main": main["id"] if main else None}

    def drift():
        sched = [pipeline_row(p) for p in get_list("/projects/:id/pipelines", {"source": "schedule", "ref": "main",
                                                                                "per_page": SCHEDULED, "order_by": "id", "sort": "desc"})
                 if type(p.get("id")) is int]
        rows, fetched = [], 0
        for p in sched:
            job = next((j for j in jobs_of(p["id"], p["status"]) if j["name"] == g["drift_job"]), None)
            row = {"pipeline": p["id"], "created": p["created"], "status": p["status"], "job": job["id"] if job else None,
                   "job_status": job["status"] if job else None, "outcome": None, "reasons": []}
            if job and job["status"] in ("success", "failed") and type(job["id"]) is int:
                key = str(job["id"])
                used["drift"].add(key)
                if key not in drift_cache and fetched < ARTIFACTS_PER_RUN:   # older results fill in over a few runs
                    fetched += 1
                    try:
                        res = get_obj(f"/projects/:id/jobs/{job['id']}/artifacts/audit/result.json")
                        drift_cache[key] = {"outcome": res.get("outcome") if res.get("outcome") in OUTCOMES else None,
                                            "reasons": [str(r) for r in res.get("reasons")][:5] if isinstance(res.get("reasons"), list) else [],
                                            "evaluated_at": res.get("evaluated_at") if common.finite_time(res.get("evaluated_at")) else None,
                                            "health_only": res.get("health_only") is True}
                    except ApiError as e:
                        drift_cache[key] = {"outcome": None, "reasons": [], "artifact_error": str(e)}
                row.update(drift_cache.get(key) or {})
                if row["outcome"] is None and job["status"] == "success":
                    row["outcome"] = "HEALTHY"                  # exit 0 is HEALTHY (tools/fleet-audit-job.sh)
            rows.append(row)
        return {"job": g["drift_job"], "items": rows}

    def merges():
        opened = get_list("/projects/:id/merge_requests", {"state": "opened", "per_page": 20, "order_by": "updated_at", "sort": "desc"})
        last = get_list("/projects/:id/merge_requests", {"state": "merged", "per_page": 1, "order_by": "updated_at", "sort": "desc"})
        out = {"open": [{"iid": m.get("iid"), "title": str(m.get("title") or "")[:160], "draft": m.get("draft") is True,
                         "source_branch": branch(m.get("source_branch")), "updated": ts(m.get("updated_at"))}
                        for m in opened],
               "open_capped": len(opened) >= 20, "last_merged": None}
        if last and type(last[0].get("iid")) is int:
            m = last[0]
            key = str(m["iid"])
            used["approvals"].add(key)
            if key not in approvals_cache:
                try:
                    by = get_obj(f"/projects/:id/merge_requests/{m['iid']}/approvals").get("approved_by")
                    approvals_cache[key] = len(by) if isinstance(by, list) else None
                except ApiError:
                    approvals_cache[key] = None
            out["last_merged"] = {"iid": m["iid"], "title": str(m.get("title") or "")[:160], "merged": ts(m.get("merged_at")),
                                  "commit": str(m.get("merge_commit_sha") or "")[:12], "approvals": approvals_cache[key]}
        return out

    def monitor_issues():
        items = get_list("/projects/:id/issues", {"labels": ",".join(g["monitor_labels"]), "state": "all", "per_page": 20,
                                              "order_by": "created_at", "sort": "desc"})
        rows = []
        for i in items:
            m = TITLE_OUTCOME.match(str(i.get("title") or ""))      # the title's outcome word only: these issues are confidential
            rows.append({"iid": i.get("iid"), "outcome": m.group(1) if m else None, "state": str(i.get("state") or ""),
                         "created": ts(i.get("created_at")), "closed": ts(i.get("closed_at"))})
        return {"labels": g["monitor_labels"], "items": rows}

    def reservations():
        lab = ",".join(g["reservation_labels"])
        opened = get_list("/projects/:id/issues", {"labels": lab, "state": "opened", "per_page": 10, "order_by": "updated_at", "sort": "desc"})
        closed = get_list("/projects/:id/issues", {"labels": lab, "state": "closed", "per_page": 1, "order_by": "updated_at", "sort": "desc"})
        row = lambda i: {"iid": i.get("iid"), "title": str(i.get("title") or "")[:160], "created": ts(i.get("created_at")),
                         "updated": ts(i.get("updated_at")), "closed": ts(i.get("closed_at"))}
        return {"labels": g["reservation_labels"], "open": [row(i) for i in opened],
                "last_closed": row(closed[0]) if closed else None}

    doc = {"schema": 1, "kind": "gitlab", "generated_at": now, "build": "scrubbed", "project": g["project"],
           "token": section(tokens),
           "monitor_token": token_line(g.get("monitor_token_expires"), now, "roles/fleet_monitor defaults (fleet_monitor_token_expires)"),
           "freeze": read_freeze(cfg["freeze_file"]),
           "pipelines": section(pipelines), "drift_audit": section(drift), "merge_requests": section(merges),
           "monitor_issues": section(monitor_issues), "reservations": section(reservations)}
    # the cache keeps only what is still shown, judged only from sections that were read successfully
    ok = {k: not (isinstance(doc[k], dict) and doc[k].get("error")) for k in ("pipelines", "drift_audit", "merge_requests")}
    for name, sections in (("jobs", ("pipelines", "drift_audit")), ("drift", ("drift_audit",)), ("approvals", ("merge_requests",))):
        if all(ok[s] for s in sections):
            for key in [k for k in cache[name] if k not in used[name]]:
                del cache[name][key]
    return doc


def read_token(path):
    with open(path, encoding="utf-8") as f:
        token = f.read(512).strip()
    if not token or any(c.isspace() for c in token):
        raise ValueError("token file empty or malformed")
    return token


def run(cfg, now=None, get=None):
    now = common.now() if now is None else int(now)
    cache_path = os.path.join(cfg["state_dir"], "gitlab-cache.json")
    try:
        cache = common.load_json_capped(cache_path, 4 << 20)
        cache = cache if isinstance(cache, dict) else {}
    except (OSError, ValueError):
        cache = {}
    calls = None
    if get is None:
        try:
            api = Api(cfg["gitlab"], read_token(cfg["gitlab"]["token_file"]))
        except (OSError, ValueError) as e:
            doc = {"schema": 1, "kind": "gitlab", "generated_at": now, "build": "scrubbed",
                   "error": f"no usable GitLab token ({type(e).__name__})", "freeze": read_freeze(cfg["freeze_file"]),
                   "monitor_token": token_line(cfg["gitlab"].get("monitor_token_expires"), now, "roles/fleet_monitor defaults")}
            return common.publish(os.path.join(cfg["www_data"], "gitlab.json"), doc, common.Scrubber.from_config(cfg))
        get = api.get
    doc = collect(cfg, get, cache, now)
    common.write_json(cache_path, cache, mode=0o600)
    # always scrubbed: this collector has no unscrubbed output (C4)
    return common.publish(os.path.join(cfg["www_data"], "gitlab.json"), doc, common.Scrubber.from_config(cfg))


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
        print(f"prace-dash-gitlab: configuration: {e}", file=sys.stderr)
        return 2
    try:
        doc = run(cfg, a.now)
    except ValueError as e:
        print(f"prace-dash-gitlab: {e}", file=sys.stderr)
        return 3
    failed = [k for k, v in doc.items() if isinstance(v, dict) and v.get("error")] + (["token"] if doc.get("error") else [])
    print("prace-dash-gitlab: " + ("ok" if not failed else "failed sections: " + ", ".join(failed)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

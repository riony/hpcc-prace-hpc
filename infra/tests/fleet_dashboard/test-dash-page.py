#!/usr/bin/env python3
"""Offline tests for the dashboard page (roles/fleet_dashboard/files/www).

Static checks always run (CI's image has no browser): no inline script or style, no markup built
from data, a same-origin CSP, a "JavaScript required" fallback, no external origin anywhere.
The DOM-level render test runs app.js in node against data the real collectors produced from the
committed fixtures (dom-harness.js: a minimal DOM that throws on innerHTML and on any on* or style
attribute). It is skipped where node is not installed, as test-slinky-helm-overlay.py is without helm."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dashtest as T  # noqa: E402
from dashtest import common, evidence, gitlab, observe  # noqa: E402

WWW = os.path.join(T.FILES, "www")
HTML, CSS, JS = (open(os.path.join(WWW, n), encoding="utf-8").read() for n in ("index.html", "app.css", "app.js"))
NODE = shutil.which("node")


class Static(unittest.TestCase):
    def test_index_has_no_inline_script_style_or_handler(self):
        self.assertEqual(re.findall(r"<script\b[^>]*>(.*?)</script>", HTML, re.S), [""])
        self.assertIn('<script src="app.js" defer></script>', HTML)
        self.assertNotRegex(HTML, r"(?i)\son[a-z]+\s*=")
        self.assertNotRegex(HTML, r"(?i)\sstyle\s*=|<style")
        self.assertEqual(re.findall(r'(?:src|href)="([^"]+)"', HTML), ["app.css", "app.js"])

    def test_index_csp_and_the_no_javascript_fallback(self):
        csp = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', HTML).group(1)
        for d in ("default-src 'self'", "script-src 'self'", "style-src 'self'", "object-src 'none'", "base-uri 'none'"):
            self.assertIn(d, csp)
        self.assertNotIn("unsafe", csp)
        self.assertIn("<noscript><p class=\"nojs\">JavaScript required.</p></noscript>", HTML)
        self.assertIn('<div id="app" hidden></div>', HTML)      # nothing else is visible without JavaScript
        self.assertIn('name="viewport"', HTML)

    def test_script_builds_no_markup_from_data(self):
        for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "cssText",
                    "setAttribute('style'", 'setAttribute("style"', "setAttribute('on", "srcdoc", "javascript:"):
            self.assertNotIn(bad, JS, bad)
        self.assertIn("document.createTextNode", JS)
        self.assertIn("attribute not allowed", JS)                # the element builder refuses other attributes

    def test_script_and_style_reach_no_other_origin(self):
        self.assertEqual(re.findall(r"fetch\(([^,]+),", JS), ["'data/' + name + '.json'"])
        for text in (JS, CSS, HTML):
            self.assertNotRegex(text, r"https?://|//[a-z0-9-]+\.")
        self.assertNotRegex(CSS, r"@import|url\(|@font-face")       # system font stacks only (Q9)
        self.assertIn("system-ui", CSS)
        self.assertIn("ui-monospace", CSS)

    def test_links_are_internal_routes_or_same_origin_paths(self):
        self.assertIn("/^#[A-Za-z0-9\\/_.-]*$/", JS)
        self.assertIn("/^\\/[A-Za-z0-9\\/_.-]+$/", JS)

    def test_phone_width_and_both_themes(self):
        self.assertIn("@media (max-width: 760px)", CSS)
        self.assertIn("prefers-color-scheme: light", CSS)
        self.assertIn(':root[data-theme="light"]', CSS)
        self.assertIn("minmax(min(100%, 280px), 1fr)", CSS)      # host cards: one column at 375 px


def build_bundle(d, outcome="HEALTHY", reasons=None, obs="unleased", run_age=30, scenarios=True, gitlab_ok=True, freeze=None,
                 lease="keep"):
    """the real collectors write data/ from the committed samples and fixtures"""
    cfg = T.config(d)
    www = os.path.join(d, "www")
    for n in ("index.html", "app.css", "app.js"):
        shutil.copyfile(os.path.join(WWW, n), os.path.join(www, n))
    o = T.observation(obs)
    if lease == "missing":
        o.pop("lease", None)
    elif lease != "keep":
        o["lease"] = lease
    now = o["time"] + 40
    T.write_monitor(cfg, now, outcome=outcome, reasons=reasons, obs=o)
    with open(cfg["monitor"]["state"]) as f:
        st = json.load(f)
    st["last_run"] = now - run_age
    with open(cfg["monitor"]["state"], "w") as f:
        json.dump(st, f)
    observe.run(cfg, now)
    if gitlab_ok:
        if freeze:
            with open(cfg["freeze_file"], "w") as f:
                json.dump(freeze, f)
        gitlab.run(cfg, now, get=T.fake_get())
    doc = evidence.build(T.REPO, "0" * 40, now)
    if scenarios == "repo":
        pass                                  # the runs committed in the repository, as production ships them
    elif scenarios:
        fx = evidence.build(T.SCENARIO_ROOT, None, now)
        doc["scenarios"], doc["folders"] = fx["scenarios"], doc["folders"] + fx["folders"]
    else:
        doc["scenarios"] = {"runs": [], "errors": []}      # the empty state
    doc["build"] = "scrubbed"
    common.publish(os.path.join(cfg["www_data"], "evidence.json"), doc, common.Scrubber.from_config(cfg))
    return www, now


def scenario_routes(routes):
    """the rendered #scenarios/<n> routes in index order (the harness renders one per committed run)"""
    return sorted((r for r in routes if re.fullmatch(r"#scenarios/\d+", r)), key=lambda r: int(r.split("/")[1]))


def render(www, now):
    r = subprocess.run([NODE, os.path.join(T.HERE, "dom-harness.js"), www, str(now)], capture_output=True, text=True, timeout=60)
    rep = json.loads(r.stdout or "{}")
    if "fatal" in rep or r.returncode:
        raise AssertionError(rep.get("fatal") or r.stderr)
    return rep


def render_clock(www, now, advance, start):
    """the page on <start>, then the clock moves on <advance> s with the data files unchanged"""
    r = subprocess.run([NODE, os.path.join(T.HERE, "dom-harness.js"), www, str(now), str(advance), start],
                       capture_output=True, text=True, timeout=60)
    rep = json.loads(r.stdout or "{}")
    if "fatal" in rep or r.returncode or "clock" not in rep:
        raise AssertionError(rep.get("fatal") or r.stderr or r.stdout)
    return rep["clock"]


@unittest.skipUnless(NODE, "node not installed: DOM-level render test skipped (static checks still ran)")
class Rendered(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.d.cleanup()

    def assertSafe(self, rep):
        for hash_, r in rep["routes"].items():
            self.assertFalse(r["hidden"], hash_)
            self.assertEqual(r["onAttrs"], 0, hash_)
            self.assertNotIn("IMG", r["tags"], hash_)
            self.assertNotIn("SCRIPT", r["tags"], hash_)
            self.assertLessEqual(set(r["styleProps"]), {"width", "left"}, hash_)       # CSSOM geometry only
            for href in r["hrefs"]:
                self.assertRegex(href, r"^(#[A-Za-z0-9/_.-]*|/hpcc/prace-hackathon/-/pipelines/\d+)$")
        self.assertEqual(sorted(set(rep["requests"])), ["data/evidence.json", "data/gitlab.json", "data/latest.json"])

    def test_every_tab_renders_from_real_collector_output(self):
        hostile = "<img src=x onerror=alert(1)> reason text"
        rep = render(*build_bundle(self.d.name, reasons=["4 workers usable, controller and accounting answer", hostile],
                                   freeze={"state": "frozen", "note": "native window"}))
        self.assertSafe(rep)
        c = rep["routes"]["#cluster"]["text"]
        for want in ("HEALTHY", "login-node", "cpu-worker-1", "gpu-worker-3", hostile, "Network guard", "P9 final", "eno5",
                     "ens10f1np1", "not in the check", "InfiniBand is not part of this check", "deployed profile 3", "frozen",
                     "No collector yet.", "later · owner decision", "Last full drift audit (CI)"):
            self.assertIn(want, c)
        self.assertNotIn("STALE", c)
        s = rep["routes"]["#slurm"]["text"]
        for want in ("policy-payg", "28 / 8", "stopped", "lines agree", "AccountingStorageEnforce", "4 CPUs and 90 GiB per GPU", "UP"):
            self.assertIn(want, s)
        sc = rep["routes"]["#scenarios/0"]["text"]
        for want in ("fx-scn-fixture-001", "actor-A · under test", "T2 co-located", "T3 actor-written", "SHA256SUMS verified"):
            self.assertIn(want, sc)
        self.assertIn("<img src=x onerror=alert(1)> all good", rep["pager"]["lastText"])    # a T3 record, as text
        ci = rep["routes"]["#cicd"]["text"]
        for want in ("#990105", "DRIFT", "DEFERRED_MAINTENANCE", "monitor failure", "reviewer: see MR notes", "Dashboard token",
                     "Monitor token", "slurmctld", "v1.36.4+k3s1", "CVE matching"):
            self.assertIn(want, ci)
        self.assertNotIn("Kubernetes NotReady", ci)
        self.assertIn("Cluster", rep["routes"]["#bogus"]["text"])      # an unknown route falls back to Cluster
        self.assertIn("No such run.", rep["routes"]["#replay/9/%"]["text"])      # a malformed link never blanks the page
        self.assertIn("Job 990151 OOM-killed", rep["selected"])
        self.assertIn("sacct-controller: T1 independent", rep["selected"])

    def test_replay_pager_bounds(self):
        rep = render(*build_bundle(self.d.name))
        p = rep["pager"]
        self.assertEqual(p["steps"], 5)
        self.assertEqual(p["first"], {"prev": True, "next": False})
        self.assertEqual(p["last"], {"prev": False, "next": True})
        self.assertEqual(p["current"]["data-key"], "step-4")

    def test_monitor_outcomes_and_dashboard_staleness(self):
        glyph = {"HEALTHY": "✓", "DRIFT": "≠", "UNREACHABLE_OR_ERROR": "✕", "DEFERRED_MAINTENANCE": "◐", "UNHEALTHY": "▲"}
        for outcome, g in glyph.items():
            with self.subTest(outcome), tempfile.TemporaryDirectory() as d:
                c = render(*build_bundle(d, outcome=outcome, obs="leased" if outcome == "DEFERRED_MAINTENANCE" else "unleased"))["routes"]["#cluster"]["text"]
                self.assertIn(g + ("DRIFT (structural)" if outcome == "DRIFT" else outcome), c)
        c = render(*build_bundle(self.d.name, run_age=400))["routes"]["#cluster"]["text"]
        self.assertIn("STALE: the monitor has not run for", c)

    def test_empty_production_states(self):
        rep = render(*build_bundle(self.d.name, scenarios=False, gitlab_ok=False))
        self.assertIn("No scenario runs recorded yet.", rep["routes"]["#scenarios"]["text"])
        self.assertIn("GitLab data unreadable: HTTP 404", rep["routes"]["#cicd"]["text"])
        self.assertIn("GitLab data not loaded", rep["routes"]["#cluster"]["text"])


@unittest.skipUnless(NODE, "node not installed: DOM-level render test skipped (static checks still ran)")
class Review06Oct(unittest.TestCase):
    """regressions for the independent review of 6 Oct"""

    def setUp(self):
        self.d = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.d.cleanup()

    def test_r1_time_alone_makes_the_monitor_and_every_host_stale(self):
        c = render_clock(*build_bundle(self.d.name), 1200, "#cluster")
        self.assertNotIn("STALE", c["before"]["text"])
        self.assertIn("good", c["before"]["banner"].split())
        self.assertTrue(c["before"]["hosts"] and not any("stale" in h.split() for h in c["before"]["hosts"]))
        self.assertGreater(c["refetched"], 0)                    # the same files were fetched again, unchanged
        self.assertIn("STALE: the monitor has not run for", c["after"]["text"])
        self.assertIn("stalec", c["after"]["banner"].split())
        self.assertTrue(all("stale" in h.split() for h in c["after"]["hosts"]), c["after"]["hosts"])

    def test_r1_gitlab_data_goes_stale_without_leaving_the_tab(self):
        c = render_clock(*build_bundle(self.d.name), 1200, "#cicd")
        self.assertNotRegex(c["before"]["text"], r"GitLab data \d+ (s|min) old")
        self.assertRegex(c["after"]["text"], r"GitLab data \d+ min old")

    def test_r1_a_short_wait_changes_no_state(self):
        c = render_clock(*build_bundle(self.d.name), 30, "#cluster")
        self.assertNotIn("STALE", c["after"]["text"])
        self.assertEqual(c["before"]["banner"], c["after"]["banner"])
        self.assertEqual(c["before"]["hosts"], c["after"]["hosts"])

    def test_r2_an_unstated_lease_is_unknown_in_every_view(self):
        for bad in ("missing", None, "", {"held": "false"}, {"held": None}):
            with self.subTest(bad=bad), tempfile.TemporaryDirectory() as d:
                rep = render(*build_bundle(d, lease=bad))
                s, c = rep["routes"]["#slurm"]["text"], rep["routes"]["#cluster"]["text"]
                self.assertIn("Lease?not stated", s)            # "?" is the unknown glyph
                self.assertNotIn("not held", s)
                self.assertNotIn("no lease, every partition up", s)
                self.assertIn("lease not stated in the observation", s)
                self.assertIn("Cluster lease?not stated", c)
                self.assertIn("Window phaseunknown", c)

    def test_r2_an_explicit_unheld_lease_still_reads_not_held(self):
        rep = render(*build_bundle(self.d.name))
        self.assertIn("Leasenot held", rep["routes"]["#slurm"]["text"])         # plain words, as before
        self.assertIn("no lease, every partition up", rep["routes"]["#slurm"]["text"])

    def test_the_committed_harness_run_in_scenarios_and_replay(self):
        www, now = build_bundle(self.d.name, scenarios="repo")
        rep = render(www, now)
        # newest first: the 7 Oct researcher session (when committed) comes before the 6 Oct rehearsal
        sc = next(rep["routes"][r]["text"] for r in scenario_routes(rep["routes"])
                  if "NeMo agent harness rehearsal" in rep["routes"][r]["text"])
        for want in ("prace-nemo-demo-20261006", "NeMo agent harness rehearsal", "T3 actor-written", "T2 co-located",
                     "agent: prace_action(mkdir-demo-dir) returned ok", "verdict, attempt 1", "functional_regression",
                     "declared fixture correction", "verdict, attempt 2"):
            self.assertIn(want, sc)
        self.assertEqual(sc.count("T1 independent"), 1)   # the legend only: a local run has no independent record
        self.assertIn("the agent’s own trace", sc)
        self.assertNotIn("/tmp/", sc)                   # no workspace path reaches the page

    def test_the_committed_researcher_session_in_scenarios(self):
        """7 Oct: a user's own recording (T3) beside the controller's accounting (T1), and the replay"""
        www, now = build_bundle(self.d.name, scenarios="repo")
        routes = render(www, now)["routes"]
        sc = next((routes[r]["text"] for r in scenario_routes(routes) if "researcher-session-20261007 · Researcher session" in routes[r]["text"]), None)
        if sc is None:
            self.skipTest("no committed researcher session")
        for want in ("typed · sbatch -A proj-alpha gpu.sh", "replay · typed · tail -4 slurm-1216.out",
                     "accounting · ended · job 1215 t88-gpu · COMPLETED", "replay matched: 2 jobs as recorded, 2 as replayed",
                     "T3 actor-written", "T1 independent", "actor-C"):
            self.assertIn(want, sc)
        self.assertNotIn("syn-carol", sc)                     # the scrubbed build shows accounts as letters

    def test_terminal_playback_of_the_committed_runs(self):
        """8 Oct: a terminal-session run's screens play in the page, scrubbed, labelled T3; End shows the last screen"""
        www, now = build_bundle(self.d.name, scenarios="repo")
        rep = render(www, now)
        if not rep.get("play"):
            self.skipTest("no committed terminal-session run")
        for key, v in rep["play"].items():
            with self.subTest(screen=key):
                self.assertIn("T3 actor-written", v["text"])
                self.assertIn("Playback executes nothing", v["text"])
                self.assertIn("logout", v["term"])
                self.assertIn("actor-C", v["term"])
                for leak in ("syn-carol", "tailabc123", "lab", "example-lab", "GPU-2f2838d0"):
                    self.assertNotIn(leak, v["text"])
                self.assertEqual(v["onAttrs"], 0)
        self.assertTrue(any("Terminal playback" in v["text"] for k, v in rep["routes"].items() if k.startswith("#scenarios/")))
        self.assertIn("typing is interpolated", next(iter(rep["play"].values()))["text"])

    def test_playback_controls_keep_the_run_when_evidence_is_refreshed(self):
        rep = render(*build_bundle(self.d.name, scenarios="repo"))
        controls = rep.get("controls")
        if not controls:
            self.skipTest("no committed terminal-session run")
        self.assertEqual(controls["one"], "0:01")
        self.assertEqual(controls["two"], "0:03")
        self.assertEqual(controls["paused"], "0:03")
        self.assertEqual(controls["refreshed"]["time"], "0:03")
        self.assertIn("Playback · " + controls["run"] + " ·", controls["refreshed"]["title"])
        self.assertNotIn("new-run-before-the-selected-one", controls["refreshed"]["title"])
        self.assertEqual(controls["restarted"], "0:00")

    def test_the_header_names_the_cluster_hpcc_prace(self):
        text = render(*build_bundle(self.d.name))["routes"]["#cluster"]["text"]
        self.assertTrue(text.startswith("HPCC-PRACEfleet dashboard"), text[:40])     # owner, 6 Oct
        self.assertNotIn("PRACE twin", text)
        self.assertIn("<title>HPCC-PRACE fleet dashboard</title>", HTML)

    def test_r3_a_conflict_is_shown_with_the_failed_result(self):
        www, now = build_bundle(self.d.name)
        path = os.path.join(www, "data", "evidence.json")
        with open(path) as f:
            doc = json.load(f)
        doc["acceptance"][0].update(result="failed", conflicts=["transcript rc=0 but the wrapper says failed (command_rc 1)"])
        with open(path, "w") as f:
            json.dump(doc, f)
        s = render(www, now)["routes"]["#slurm"]["text"]
        self.assertIn("conflict: transcript rc=0 but the wrapper says failed (command_rc 1)", s)



def sim_events(**override):
    """unauthorized-data-write v1 as a sanitized summary lists it: phase, type, id and status per event"""
    rows = [("attack", "action", "find-writable-target", "ok"), ("attack", "action", "write-synthetic-marker", "ok"),
            ("attack", "observation", "vulnerable-marker-present", "pass"),
            ("replay", "action", "find-writable-target", "ok"), ("replay", "action", "write-synthetic-marker", "denied"),
            ("replay", "observation", "patched-write-blocked", "pass"),
            ("regression", "observation", "alpha-authorized-write", "pass"), ("regression", "observation", "beta-authorized-write", "pass"),
            ("regression", "observation", "normal-project-job", "pass"), ("reset", "observation", "metadata-reset", "pass")]
    out = [{"sequence": i + 1, "phase": ph, "event_type": ty, "id": ident, "status": status} for i, (ph, ty, ident, status) in enumerate(rows)]
    for ident, change in override.items():
        for row in out:
            if row["id"] == ident.replace("_", "-") and (change is None or row["phase"] == change.get("phase", row["phase"])):
                row.update(change or {"drop": True})
    return [row for row in out if not row.get("drop")]


GOOD_SIM = {"schema": "prace.security-simulation-public.v1", "verified": True, "source_revision": "eca1139" + "0" * 33,
            "source_dirty": False, "driver": "nemo", "framework_version": "1.9.0", "model_used": False, "model": None, "scenario_kind": "write", "fleet_contacted": False,
            "scope": "local-acl-simulation", "proof_scope": "Linux ACL decisions on a disposable fixture; scheduler and quota stand-ins",
            "reset_scope": "seeded fixture restored, then discarded", "fixture_discarded": True,
            "verdicts": {"baseline": "security_failure", "patched": "security_blocked", "functional": "pass"},
            "cleanup": "complete", "events": sim_events()}


@unittest.skipUnless(NODE, "node not installed: DOM-level render test skipped (static checks still ran)")
class SimulatedScenario(unittest.TestCase):
    """8 Oct: a simulated security scenario as one chain: weakness, repair, replay, legitimate use, reset.
    Each case is one run carrying the collector's proposed `simulation` pass-through."""

    CASES = {
        "good": {},
        "model-record": {"model_used": True, "model": "glm-5.2"},
        "no-denial": {"events": sim_events(write_synthetic_marker={"phase": "replay", "status": "ok"})},
        "missing-functional": {"events": sim_events(normal_project_job=None)},
        "not-discarded": {"fixture_discarded": False},
        "no-reset": {"events": sim_events(metadata_reset=None)},
        "verdict-says-not-blocked": {"verdicts": dict(GOOD_SIM["verdicts"], patched="security_failure")},
        "replay-differs": {"events": sim_events(write_synthetic_marker={"phase": "replay", "id": "write-other-marker"})},
        "cluster-contacted": {"fleet_contacted": True},
        "unverified-dirty": {"verified": False, "source_dirty": True},
        "authorized-write-broken": {"events": sim_events(alpha_authorized_write={"status": "fail"})},
        "cleanup-incomplete": {"cleanup": "error"},
        "empty": None,
        "hostile": {"events": sim_events(find_writable_target={"phase": "attack", "id": "<img src=x onerror=alert(1)>"})},
    }

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.TemporaryDirectory()
        www, now = build_bundle(cls.d.name)
        path = os.path.join(www, "data", "evidence.json")
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        template = doc["scenarios"]["runs"][0]
        runs = []
        for i, (name, change) in enumerate(cls.CASES.items()):
            run = json.loads(json.dumps(template))
            run["run_id"], run["start"] = "udw-" + name, template["start"] - i     # newest first: the index order
            run["simulation"] = {} if change is None else dict(GOOD_SIM, **change)
            runs.append(run)
        runs.append(dict(json.loads(json.dumps(template)), run_id="old-run", start=template["start"] - 99))
        doc["scenarios"]["runs"] = runs
        with open(path, "w", encoding="utf-8") as f:
            json.dump(doc, f)
        rep = render(www, now)
        cls.rep = rep
        cls.text = {}
        for route in scenario_routes(rep["routes"]):
            text = rep["routes"][route]["text"]
            for name in list(cls.CASES) + ["old-run"]:
                # the run list is on every route: match the run's own detail header
                if (("udw-" + name) if name != "old-run" else name) + " · " + template["title"] in text:
                    cls.text[name] = text
        assert sorted(cls.text) == sorted(list(cls.CASES) + ["old-run"]), sorted(cls.text)

    @classmethod
    def tearDownClass(cls):
        cls.d.cleanup()

    def test_a_complete_chain_reads_verified_and_names_its_limits(self):
        t = self.text["good"]
        for want in ("Simulated security scenario", "Chain verified · local simulation", "Local Linux ACL simulation.",
                     "Slurm accounting and quota are stand-ins", "No cluster node was contacted. No model was used.",
                     "Weakness recorded", "Repair applied", "Replay after the repair", "Legitimate use still works", "Fixture reset",
                     "not a cluster recovery", "Original execution", "2 declared action(s), run once against the weak fixture",
                     "Execution replay", "2 of them executed again after the repair, stepped by NeMo, no model",
                     "Browser playback", "they execute nothing", "write-synthetic-marker · denied", "metadata-reset · pass",
                     "eca11390000"):
            self.assertIn(want, t)
        self.assertEqual(t.count("PASS"), 5)
        self.assertNotIn("Not verified", t)
        self.assertIn("· local simulation", self.rep["routes"]["#scenarios"]["text"])

    def test_missing_or_incomplete_evidence_never_reads_as_a_pass(self):
        for name, want in (("no-reset", "Fixture reset: MISSING"), ("cleanup-incomplete", "cleanup is error"),
                           ("empty", "Weakness recorded: MISSING"), ("unverified-dirty", "the verifier did not approve this export"),
                           ("unverified-dirty", "built from an uncommitted source")):
            with self.subTest(case=name):
                self.assertIn("Not verified", self.text[name])
                self.assertNotIn("Chain verified", self.text[name])
                self.assertIn(want, self.text[name])
        self.assertEqual(self.text["empty"].count("MISSING"), 10)        # five steps, each in its badge and its reason

    def test_contradictions_are_named_not_resolved(self):
        for name, want in (("verdict-says-not-blocked", "verdict patched is security_failure but the evidence shows CONTRADICTED"),
                           ("replay-differs", "the replayed actions are not the recorded ones, in order"),
                           ("authorized-write-broken", "verdict functional is pass but the evidence shows FAIL"),
                           ("cluster-contacted", "cluster contact is not ruled out")):
            with self.subTest(case=name):
                self.assertIn(want, self.text[name])
                self.assertNotIn("Chain verified", self.text[name])
        # a repair is only as good as the checked replay: never PASS beside a contradicted replay
        self.assertIn("FAIL Repair applied", self.text["verdict-says-not-blocked"])
        self.assertIn("CONTRADICTED Replay after the repair", self.text["verdict-says-not-blocked"])

    def test_missing_denial_regression_or_discard_never_claims_verified(self):
        for name in ("no-denial", "missing-functional", "not-discarded"):
            self.assertIn("Not verified", self.text[name])
            self.assertNotIn("Chain verified", self.text[name])
        self.assertIn("no final authorization denial", self.text["no-denial"])
        self.assertIn("Recording used model glm-5.2; replay used no model", self.text["model-record"])
        self.assertIn("Chain verified", self.text["model-record"])

    def test_runs_without_a_simulation_are_unchanged_and_hostile_text_stays_text(self):
        self.assertNotIn("Simulated security scenario", self.text["old-run"])
        self.assertIn("<img src=x onerror=alert(1)> · ok", self.text["hostile"])
        for route, r in self.rep["routes"].items():
            self.assertEqual(r["onAttrs"], 0, route)
            self.assertNotIn("IMG", r["tags"], route)

@unittest.skipUnless(NODE, "node not installed: physical card DOM checks skipped")
class PhysicalRecording(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.TemporaryDirectory()
        www, now = build_bundle(cls.d.name)
        path = os.path.join(www, "data", "evidence.json")
        with open(path, encoding="utf-8") as handle:
            doc = json.load(handle)
        source = os.path.join(T.REPO, "evidence/2026-10-09/continuous-physical-read-operator-20261009-01")
        summary, _, _ = evidence.physical_records.derive(evidence.physical_records.read_checked(source))
        summary["verified"] = True
        cases = {"good": {}, "false-objective": {"objective": False},
                 "wrong-actions": {"actions": [{"id": "other-action", "status": "ok"}]},
                 "missing-provenance": {"source_revision": None}, "unverified": {"verified": False},
                 "hostile": {"model": "<img src=x onerror=alert(1)>"},
                 "unsupported-followup": {"repair": "pass", "replay": "pass", "legitimate_use": "pass"}}
        template = doc["scenarios"]["runs"][0]
        runs = []
        for i, (name, change) in enumerate(cases.items()):
            run = json.loads(json.dumps(template))
            run.pop("simulation", None)
            run.update(run_id="physical-" + name, start=template["start"] - i,
                       physical=dict(summary, **change))
            runs.append(run)
        doc["scenarios"]["runs"] = runs
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(doc, handle)
        cls.rep = render(www, now)
        cls.text = {}
        for route in scenario_routes(cls.rep["routes"]):
            text = cls.rep["routes"][route]["text"]
            for name in cases:
                if "physical-" + name + " · " + template["title"] in text:
                    cls.text[name] = text
        assert set(cls.text) == set(cases)

    @classmethod
    def tearDownClass(cls):
        cls.d.cleanup()

    def test_good_recording_has_two_passes_and_unrun_followup(self):
        text = self.text["good"]
        for want in ("Physical security scenario · recording only", "PASS Recording", "PASS Objective",
                     "NOT RUN Repair", "NOT RUN Replay", "NOT RUN Legitimate use", "PENDING Reset",
                     "co-located", "T3", "current lease state are outside this journal"):
            self.assertIn(want.lower(), text.lower())
        self.assertEqual(text.count("PASS"), 2)
        self.assertIn("· physical cluster", self.rep["routes"]["#scenarios"]["text"])

    def test_false_objective_is_not_a_pass(self):
        self.assertIn("FAIL Objective", self.text["false-objective"])
        self.assertNotIn("PASS Objective", self.text["false-objective"])

    def test_wrong_actions_missing_provenance_or_unverified_are_not_passes(self):
        for case in ("wrong-actions", "missing-provenance", "unverified"):
            self.assertIn("NOT VERIFIED Recording", self.text[case])
            self.assertIn("NOT VERIFIED Objective", self.text[case])
            self.assertNotIn("PASS", self.text[case])

    def test_card_never_claims_a_chain_or_unsupported_followup(self):
        for text in self.text.values():
            self.assertNotIn("Chain verified", text)
            self.assertNotIn("PASS Repair", text)
            self.assertNotIn("PASS Replay", text)
            self.assertNotIn("PASS Legitimate use", text)

    def test_hostile_model_text_stays_text(self):
        self.assertIn("<img src=x onerror=alert(1)>", self.text["hostile"])
        for route, report in self.rep["routes"].items():
            self.assertEqual(report["onAttrs"], 0, route)
            self.assertNotIn("IMG", report["tags"], route)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Renders roles/slinky's slurm HelmChart values and maintenance overlay (HelmChartConfig) for the
fleet inventory, as test-slinky-render.py does, and runs the real `helm template` of the pinned
chart with -f chart-values -f overlay-values, the order K3s's Helm controller passes them. Checks
what Helm renders, not the overlay's JSON: the merge, the closed and opening states, the partitions
the chart refuses, and on a native kind (T89) the replaced PartitionName string.

The chart writes no slurm.conf. Partitions are the Controller object's extraConf lines (standalone
partitions and controller.extraConfMap) and each NodeSet object's partition, which the operator
writes as `PartitionName=<nodeset> Nodes=<nodeset> <config>` (not vendored: the bench's form,
evidence/2026-09-29/scheduler-policy-bench). Skipped without helm (PRACE_HELM or PATH) or the fetched
charts (PRACE_SLURM_CHART); CI requires both. Contacts no host."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

import yaml

INFRA = Path(__file__).resolve().parent.parent
PLAYBOOK = shutil.which("ansible-playbook") or "/home/operator/venvs/ansible-prace/bin/ansible-playbook"
HELM = os.environ.get("PRACE_HELM") or shutil.which("helm")
CHART = Path(os.environ.get("PRACE_SLURM_CHART", str(INFRA / "roles/slinky/files/slurm-1.2.2.tgz")))
# The public edition does not vendor the chart archives: tools/fetch-charts.py downloads the
# checksum-pinned copies, and PRACE_SLURM_CHART names the slurm archive among them.
MISSING = [n for n in ("slurm", "slurm-operator", "slurm-operator-crds")
           if not (CHART.parent / f"{n}-1.2.2.tgz").is_file()]
if os.environ.get("CI") and (not HELM or MISSING):
    raise RuntimeError("CI requires real Helm rendering; install the pinned Helm tool and fetch the charts")
SKIP = ("helm not found (set PRACE_HELM or put a Helm 3 on PATH)" if not HELM else
        f"chart archives not found in {CHART.parent} ({', '.join(MISSING)}); run "
        "tools/fetch-charts.py DIR and set PRACE_SLURM_CHART=DIR/slurm-1.2.2.tgz" if MISSING else "")
CHARTS_J2 = (INFRA / "roles/slinky/templates/prace-slinky-charts.yaml.j2").read_text()
NATIVE_LAYER = "slinky_chart_native_workers" in CHARTS_J2      # !57 (T89) and later
LENOVO = ["lab-lenovo"]
# Both topologies explicit (4 Oct night, Session B's real-helm run at the go-live branch): the
# repository's own list is the go-live state from the native window's P3 on, so a pod case that set
# nothing rendered the native chart. The chart reads slinky_chart_native_workers (default: the list),
# the overlay slinky_overlay_native_workers.
POD = {"slurm_native_workers": [], "slinky_chart_native_workers": [], "slinky_overlay_native_workers": []}
NATIVE = {"slurm_native_workers": LENOVO, "slinky_chart_native_workers": LENOVO, "slinky_overlay_native_workers": LENOVO}
ALL = {"cpu", "gpu", "debug", "payg"}


def intent(phase):
    """a window's intent with saved states that differ per partition, so "exactly" is checked"""
    return {"schema": 2, "lease_id": "d" * 16, "phase": phase, "fence_active": phase == "closed",
            "original": {"partitions": {"cpu": "UP", "gpu": "DOWN"},
                         "loginsets": {"slurm-login-prace": {"uid": "uid-test", "replicas": 2}}},
            "declared_partitions": {"debug": "UP", "payg": "INACTIVE"}}


SAVED = {"cpu": "UP", "gpu": "DOWN", "debug": "UP", "payg": "INACTIVE"}


def render(extra=None):
    """the slurm HelmChart's values and the overlay's values (None without an intent)"""
    out = tempfile.mkdtemp()
    # Public releases fetch checksum-pinned archives instead of vendoring them.
    # Keep the real role's helper files and stage the charts only in this fixture.
    role = Path(out) / "role"
    shutil.copytree(INFRA / "roles/slinky/files", role / "files")
    for name in ("slurm", "slurm-operator", "slurm-operator-crds"):
        archive = CHART.parent / f"{name}-1.2.2.tgz"
        shutil.copyfile(archive, role / "files" / archive.name)
    book = Path(out) / "render.yml"
    book.write_text(f"""
- hosts: lab-dl380
  connection: local
  gather_facts: false
  vars:
    ansible_connection: local
    slinky_charts_ondisk: {{skipped: true}}   # no chart deployed yet (maintenance-topology.yml's reading)
  tasks:
    - ansible.builtin.include_vars: {{file: "{INFRA}/roles/slinky/defaults/main.yml"}}
    - ansible.builtin.template: {{src: "{INFRA}/roles/slinky/templates/{{{{ item }}}}.j2", dest: "{out}/{{{{ item }}}}"}}
      vars: {{role_path: "{role}"}}
      loop: [prace-slinky-charts.yaml, prace-slinky-maintenance.json]
""")
    env = dict(os.environ, ANSIBLE_CONFIG=str(INFRA / "ansible.cfg"), ANSIBLE_NOCOLOR="1")
    args = [PLAYBOOK, "-i", "inventories/fleet", str(book)]
    if extra:
        (Path(out) / "extra.json").write_text(json.dumps(extra))
        args += ["-e", "@" + str(Path(out) / "extra.json")]
    r = subprocess.run(args, cwd=INFRA, env=env, capture_output=True, text=True, timeout=300)
    if r.returncode:
        raise AssertionError(r.stdout[-3000:] + r.stderr[-2000:])
    charts = {d["metadata"]["name"]: d for d in yaml.safe_load_all((Path(out) / "prace-slinky-charts.yaml").read_text())}
    doc = json.loads((Path(out) / "prace-slinky-maintenance.json").read_text())
    shutil.rmtree(out)
    overlay = doc["overlay"] and json.loads(doc["overlay"]["spec"]["valuesContent"])
    return yaml.safe_load(charts["slurm"]["spec"]["valuesContent"]), overlay


def helm_template(*values):
    """`helm template` of the pinned chart as K3s installs it (release slurm, namespace slurm),
    each values map a -f file in order: (returncode, rendered objects, stderr)"""
    out = tempfile.mkdtemp()
    args = [HELM, "template", "slurm", str(CHART), "--namespace", "slurm"]
    for i, v in enumerate(values):
        (Path(out) / f"values-{i}.yaml").write_text(yaml.safe_dump(v))
        args += ["-f", str(Path(out) / f"values-{i}.yaml")]
    r = subprocess.run(args, capture_output=True, text=True, timeout=120)
    shutil.rmtree(out)
    return r.returncode, [d for d in yaml.safe_load_all(r.stdout) if d] if r.returncode == 0 else [], r.stderr


def slurm_conf(objects):
    """the partition and NodeSet lines slurm.conf gets from the rendered objects, in order: the
    operator's lines for each NodeSet with a partition, then the Controller's extraConf"""
    lines = []
    for o in objects:
        if o["kind"] == "NodeSet":
            name = o["metadata"]["name"].removeprefix("slurm-worker-")
            lines.append(f"NodeSet={name} Feature={name}")
            if o["spec"].get("partition", {}).get("enabled"):
                lines.append(f"PartitionName={name} Nodes={name} {o['spec']['partition'].get('config', '')}".rstrip())
    for o in objects:
        if o["kind"] == "Controller":
            lines += o["spec"].get("extraConf", "").splitlines()
    return lines


def partitions(objects):
    """partition name -> [its settings, once per PartitionName line]"""
    found = {}
    for line in slurm_conf(objects):
        if line.startswith("PartitionName="):
            words = dict(w.split("=", 1) for w in line.split())
            found.setdefault(words.pop("PartitionName"), []).append(words)
    return found


def login_replicas(objects):
    return {o["metadata"]["name"]: o["spec"]["replicas"] for o in objects if o["kind"] == "LoginSet"}


def nodesets(objects):
    return sorted(o["metadata"]["name"].removeprefix("slurm-worker-") for o in objects if o["kind"] == "NodeSet")


@unittest.skipIf(SKIP, f"{SKIP}; the real-Helm overlay proof is skipped")
class HelmOverlay(unittest.TestCase):
    def template(self, *values):
        rc, objects, err = helm_template(*values)
        self.assertEqual(rc, 0, err)
        return objects

    def topologies(self):
        """the pod topology, and on the !57 layer the native cpu kind with its chart deployed"""
        yield "pod", POD if NATIVE_LAYER else {}
        if NATIVE_LAYER:
            yield "native", NATIVE

    def assert_states(self, objects, want, replicas, name):
        found = partitions(objects)
        self.assertEqual(set(found), ALL, (name, found))
        self.assertTrue(all(len(x) == 1 for x in found.values()), (name, slurm_conf(objects)))
        self.assertEqual({p: x[0].get("State") for p, x in found.items()}, want, (name, slurm_conf(objects)))
        self.assertEqual(login_replicas(objects), {"slurm-login-prace": replicas}, name)

    def test_helm_deep_merges_the_overlay_into_the_chart_values(self):
        """(a) Helm merges the overlay's NodeSet and partition State and the LoginSet replicas into the
        chart's values: closed, every partition INACTIVE and no login replica, over an open chart and a
        closed one; opening, exactly the saved and declared states, also over a chart left closed by
        the last window (the runbook's "between windows"). Without an intent the chart is unchanged."""
        for topo, extra in self.topologies():
            open_chart, _ = render(extra)
            with self.subTest(topology=topo, case="no intent"):
                _, none = render(dict(extra, slurm_window_intent=None))
                self.assertIsNone(none)
                self.assert_states(self.template(open_chart), dict.fromkeys(ALL), 1, "no intent")
            for chart_phase, overlay_phase in ((None, "closed"), ("closed", "closed"), ("closed", "opening"), ("opening", "opening")):
                with self.subTest(topology=topo, chart=chart_phase, overlay=overlay_phase):
                    chart = open_chart if chart_phase is None else render(dict(extra, slurm_window_intent=intent(chart_phase)))[0]
                    _, overlay = render(dict(extra, slurm_window_intent=intent(overlay_phase)))
                    objects = self.template(chart, overlay)
                    if overlay_phase == "closed":
                        self.assert_states(objects, dict.fromkeys(ALL, "INACTIVE"), 0, overlay_phase)
                    else:
                        self.assert_states(objects, SAVED, 2, overlay_phase)
                    # only State and replicas move: every other setting is the chart's
                    plain = partitions(self.template(open_chart))
                    for p, x in partitions(objects).items():
                        self.assertEqual({k: v for k, v in x[0].items() if k != "State"}, plain[p][0], p)

    def test_a_partition_without_nodesets_fails_the_chart_even_disabled(self):
        """(b) slurm.controller.extraConf fails a partition with no NodeSets before it looks at
        `enabled`, so an overlay naming a partition the chart does not render breaks every upgrade;
        the role's overlay names only the chart's partitions, and the declared debug and payg render."""
        chart, overlay = render(dict(POD if NATIVE_LAYER else {}, slurm_window_intent=intent("closed")))
        for name, extra in (("disabled", {"partitions": {"ghost": {"enabled": False}}}),
                            ("enabled", {"partitions": {"ghost": {"enabled": True}}}),
                            ("overlay state only", {"partitions": {"ghost": {"configMap": {"State": "INACTIVE"}}}}),
                            ("empty list", {"partitions": {"ghost": {"enabled": False, "nodesets": []}}})):
            with self.subTest(case=name):
                rc, _, err = helm_template(chart, extra)
                self.assertNotEqual(rc, 0)
                self.assertIn("partition `ghost` must contain at least one NodeSet (or ALL)", err)
        for topo, extra in self.topologies():
            with self.subTest(topology=topo):
                chart, overlay = render(dict(extra, slurm_window_intent=intent("closed")))
                self.assertLessEqual(set(overlay["partitions"]), set(chart["partitions"]))
                self.assertEqual(set(overlay["partitions"]), {"debug", "payg"})
                self.assertEqual(set(partitions(self.template(chart, overlay))), ALL)

    @unittest.skipUnless(NATIVE_LAYER, "this layer has no native kind (T89, !57)")
    def test_the_overlay_replaces_the_native_partition_string(self):
        """(c) with every cpu host native, the overlay's controller.extraConfMap.PartitionName replaces
        the chart's string: one PartitionName=cpu line, the overlay's, beside the chart's NodeSet line;
        no cpu NodeSet object; the rest of extraConfMap is the chart's."""
        native = NATIVE
        for chart_phase, overlay_phase in ((None, "closed"), ("closed", "closed"), ("closed", "opening"), ("opening", "opening")):
            with self.subTest(chart=chart_phase, overlay=overlay_phase):
                chart, _ = render(dict(native, slurm_window_intent=chart_phase and intent(chart_phase)))
                _, overlay = render(dict(native, slurm_window_intent=intent(overlay_phase)))
                self.assertFalse(chart["nodesets"]["cpu"]["enabled"])
                objects = self.template(chart, overlay)
                conf = slurm_conf(objects)
                self.assertEqual(nodesets(objects), ["gpu"])
                cpu = [l for l in conf if l.startswith("PartitionName=cpu ")]
                self.assertEqual(cpu, ["PartitionName=" + overlay["controller"]["extraConfMap"]["PartitionName"]])
                self.assertTrue(cpu[0].endswith(" State=" + ("INACTIVE" if overlay_phase == "closed" else "UP")), cpu)
                self.assertEqual(conf.count("NodeSet=cpu Feature=cpu"), 1)
                extra_conf = next(o for o in objects if o["kind"] == "Controller")["spec"]["extraConf"].splitlines()
                for key, value in chart["controller"]["extraConfMap"].items():
                    if key != "PartitionName":
                        self.assertIn(f"{key}={value}", extra_conf, key)


if __name__ == "__main__":
    unittest.main()

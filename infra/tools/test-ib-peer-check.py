#!/usr/bin/env python3
"""Offline tests for tools/ib-peer-map.sh and tools/ib-peer-check.py (the InfiniBand ring's peers,
for the later window that installs infiniband-diags; D42). The map script runs for real against a
fake sysfs tree and a fake smpquery per node; the check runs on its output with the real fleet
inventory (host_vars ib_ring_ports, network.yml ring_links). A failed, empty, external,
one-sided or miscabled answer never proves a peer. No host is contacted."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import yaml

INFRA = Path(__file__).resolve().parent.parent
MAP = INFRA / "tools/ib-peer-map.sh"
CHECK = INFRA / "tools/ib-peer-check.py"
HV = {h: yaml.safe_load((INFRA / f"inventories/fleet/host_vars/{h}.yml").read_text())["ib_ring_ports"]
      for h in ("lab-g003", "lab-g004", "lab-g005")}
FAKE_SMPQUERY = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]; key = a[a.index("-C") + 1] + "/" + a[a.index("-P") + 1]
peer = json.loads(os.environ["FAKE_PEERS"]).get(key)
if peer is None or peer.get("rc", 0) != 0:
    print("ibwarn: [123] mad_rpc: _do_madrpc failed; dport (DR path slid 0; dlid 0; 0,1)", file=sys.stderr); sys.exit((peer or {}).get("rc", 1) or 1)
print("# Node info: DR path slid 65535; dlid 65535; 0,1")
for k, v in (("BaseVers", "1"), ("NodeType", "Channel Adapter"), ("NumPorts", "1"), ("SystemGuid", peer.get("guid", "")),
             ("Guid", peer.get("guid", "")), ("PortGuid", peer.get("port_guid", "")), ("LocalPort", "1")):
    print(f"{k}:{'.' * (33 - len(k))}{v}")
'''


def dotted(g):
    return "0x" + g.replace(":", "")


def ring(swap=None):
    """the cabling: g003 p0-g004 p0, g004 p1-g005 p0, g005 p1-g003 p1 (port GUID -> peer port GUID)"""
    g3, g4, g5 = (HV[h] for h in ("lab-g003", "lab-g004", "lab-g005"))
    pairs = [(g3[0], g4[0]), (g4[1], g5[0]), (g5[1], g3[1])]
    peers = {}
    for a, b in pairs:
        peers[a["guid"]], peers[b["guid"]] = b["guid"], a["guid"]
    return peers


class Fixture:
    def __init__(self, peers, absent=(), fail=(), empty=(), unlinked=(), smpquery=True):
        self.d = Path(tempfile.mkdtemp(prefix="ib-"))
        self.maps = []
        for host, ports in HV.items():
            root, answers = self.d / host / "sys", {}
            for i, p in enumerate(ports):
                ca = f"mlx5_{i}"
                port = root / ca / "ports/1"
                (port / "gids").mkdir(parents=True)
                (port / "link_layer").write_text("InfiniBand\n")
                (port / "gids/0").write_text("fe80:0000:0000:0000:" + p["guid"] + "\n")
                (port / "state").write_text("2: INIT\n")
                (port / "phys_state").write_text(("3: Disabled" if p["guid"] in unlinked else "5: LinkUp") + "\n")
                dev = self.d / host / "pci" / p["pci"]; dev.mkdir(parents=True)
                (root / ca / "device").symlink_to(dev)
                g = p["guid"]
                if g in fail:
                    answers[f"{ca}/1"] = {"rc": 1}
                elif g in peers and g not in absent:
                    pg = "" if g in empty else dotted(peers[g])
                    answers[f"{ca}/1"] = {"rc": 0, "guid": pg, "port_guid": pg}
            # an outside card that is down: never asked
            port = root / "mlx5_9/ports/1"; (port / "gids").mkdir(parents=True)
            (port / "link_layer").write_text("InfiniBand\n"); (port / "gids/0").write_text("fe80:0000:0000:0000:b883:03ff:ff6f:9999\n")
            (port / "state").write_text("1: DOWN\n"); (port / "phys_state").write_text("3: Disabled\n")
            bindir = self.d / host / "bin"; bindir.mkdir()
            if smpquery:
                (bindir / "smpquery").write_text(FAKE_SMPQUERY.replace("#!/usr/bin/env python3", "#!" + sys.executable, 1)); (bindir / "smpquery").chmod(0o755)
            env = dict(os.environ, IB_SYSFS=str(root), IB_NODE=host, FAKE_PEERS=json.dumps(answers),
                       PATH=f"{bindir}:/usr/bin:/bin")
            r = subprocess.run(["bash", str(MAP)], env=env, capture_output=True, text=True, timeout=60)
            assert r.returncode == 0, r.stderr
            f = self.d / f"{host}.txt"; f.write_text(r.stdout); self.maps.append(f)

    def check(self, maps=None):
        r = subprocess.run([sys.executable, str(CHECK), *[str(m) for m in (maps or self.maps)]], capture_output=True, text=True, timeout=60)
        return r.returncode, r.stdout + r.stderr


class PeerCheck(unittest.TestCase):
    def test_the_ring_as_cabled_is_proved_with_its_map(self):
        rc, out = Fixture(ring()).check()
        self.assertEqual(rc, 0, out)
        self.assertEqual(out.count("PASS: "), 3)
        links = json.loads(out[out.index("["):])
        self.assertEqual(sorted(l["name"] for l in links), ["g003-g004", "g004-g005", "g005-g003"])
        g3g4 = next(l for l in links if l["name"] == "g003-g004")
        self.assertEqual({e["host"]: e["guid"] for e in g3g4["ends"]},
                         {"lab-g003": HV["lab-g003"][0]["guid"], "lab-g004": HV["lab-g004"][0]["guid"]})

    def test_the_map_keeps_errors_as_errors(self):
        f = Fixture(ring(), fail=[HV["lab-g004"][1]["guid"]])
        text = next(m for m in f.maps if m.name.startswith("lab-g004")).read_text()
        self.assertRegex(text, r"peer mlx5_1/1 rc=1 guid=- port_guid=- .* error=ibwarn")
        self.assertNotIn("mlx5_9/1 rc=", text)                       # a port without a link is never asked
        rc, out = f.check()
        self.assertEqual(rc, 1)
        self.assertIn("neighbour query failed (rc 1", out)
        self.assertIn("not reciprocal", out)                           # its partner cannot be proved either

    def test_nothing_unproved_counts(self):
        peers = ring()
        g3, g4, g5 = (HV[h] for h in ("lab-g003", "lab-g004", "lab-g005"))
        external = dict(peers); external[g3[0]["guid"]] = "b883:03ff:ff00:0001"
        one_sided = dict(peers); one_sided[g4[0]["guid"]] = g5[1]["guid"]
        miscabled = {g3[0]["guid"]: g4[0]["guid"], g4[0]["guid"]: g3[0]["guid"], g3[1]["guid"]: g4[1]["guid"],
                     g4[1]["guid"]: g3[1]["guid"], g5[0]["guid"]: g5[1]["guid"], g5[1]["guid"]: g5[0]["guid"]}
        cases = {
            "no smpquery": (Fixture(peers, smpquery=False), "rc 127"),
            "an empty port GUID": (Fixture(peers, empty=[g5[0]["guid"]]), "no usable port GUID"),
            "an external neighbour": (Fixture(external), "not an inventory ring port (external)"),
            "one-sided": (Fixture(one_sided), "not reciprocal"),
            "two links between g003 and g004": (Fixture(miscabled), "2 links between lab-g003 and lab-g004"),
            "g005 cabled to itself": (Fixture(miscabled), "is on the same node"),
            "a ring port without a link": (Fixture(peers, unlinked=[g3[1]["guid"]]), "not linked (phys 3)"),
        }
        for label, (fx, needle) in cases.items():
            with self.subTest(label):
                rc, out = fx.check()
                self.assertEqual(rc, 1, out)
                self.assertIn(needle, out)
                self.assertNotIn("PASS: ", out)

    def test_a_missing_or_duplicate_map(self):
        f = Fixture(ring())
        rc, out = f.check(f.maps[:2])
        self.assertEqual(rc, 1); self.assertIn("lab-g005: no map", out)
        rc, out = f.check(f.maps + f.maps[:1])
        self.assertEqual(rc, 2); self.assertIn("a second map", out)

    def test_a_link_the_inventory_does_not_have(self):
        """with only three GPU nodes every pair is a ring link; a two-link inventory shows the check"""
        import importlib.util
        spec = importlib.util.spec_from_file_location("ib_peer_check", CHECK); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        f = Fixture(ring())
        maps = {}
        for p in f.maps:
            x = m.parse(p.read_text()); maps[x["node"]] = x
        inv = m.load_inventory(INFRA / "inventories/fleet")
        problems, _ = m.check(maps, inv)
        self.assertEqual(problems, [])
        inv["links"] = [l for l in inv["links"] if l["name"] != "g005-g003"]
        problems, _ = m.check(maps, inv)
        self.assertIn("a link lab-g003 - lab-g005 that network.yml does not have", problems)

    def test_guid_forms(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("ib_peer_check", CHECK); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        self.assertEqual(m.norm("b883:03ff:ff6f:21a8"), m.norm("0xb88303ffff6f21a8"))
        for bad in ("", "-", "0x12", None, "zz83:03ff:ff6f:21a8"):
            self.assertIsNone(m.norm(bad))


if __name__ == "__main__":
    unittest.main()

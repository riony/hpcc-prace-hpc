#!/usr/bin/env python3
"""Checks the InfiniBand ring's peers from ib-peer-map.sh outputs (one file per GPU node; D42
deferred work, for the later window that installs infiniband-diags). Read-only and offline.

usage: ib-peer-check.py NODE.txt... [--inventory INFRA_INVENTORY_DIR]

A peer counts only when it is proved (Session A re-review of !76: a grep/awk pipeline's success
must never certify a peer):
- every ring port in host_vars ib_ring_ports appears in its node's map, linked (phys 5, LinkUp);
- its directed-route query exited 0 and returned a port GUID;
- that GUID is a ring port of ANOTHER inventory node (an unknown GUID is external: network.yml),
  and that port's own query names this port back (reciprocal);
- the links pair the nodes exactly as network.yml ring_links does, each link once.
Prints PASS/FAIL lines and, if all pass, the map as JSON: each ring link with both ends (host, CA
name, port GUID, PCI address). Exit 0 all proved; 1 not proved; 2 unusable input."""
import argparse
import json
from pathlib import Path
import sys

import yaml

INFRA = Path(__file__).resolve().parent.parent


def norm(guid):
    """sysfs b883:03ff:ff6f:21a8 and smpquery 0xb88303ffff6f21a8 as one form; None if unusable"""
    g = (guid or "").lower().replace(":", "")
    g = g[2:] if g.startswith("0x") else g
    return g if len(g) == 16 and all(c in "0123456789abcdef" for c in g) else None


def parse(text):
    """{'node': name, 'ports': {ca/port: {...}}, 'peers': {ca/port: {...}}} of one map"""
    out = {"node": None, "ports": {}, "peers": {}}
    for line in text.splitlines():
        f = line.split()
        if not f:
            continue
        if f[0] == "node" and len(f) == 2:
            out["node"] = f[1]
        elif f[0] in ("port", "peer") and len(f) >= 2:
            kv = dict(x.split("=", 1) for x in f[2:] if "=" in x)
            out[f[0] + "s"][f[1]] = kv
    return out


def check(maps, inventory):
    """(problems, links): maps {host: parse()}; inventory {'ports': {host: [{guid, pci}]}, 'links': [{name, ends}]}"""
    problems, ends = [], {}
    owner = {}
    for host, ports in inventory["ports"].items():
        for p in ports:
            owner[norm(p["guid"])] = (host, p["pci"])
    for host, ports in inventory["ports"].items():
        m = maps.get(host)
        if m is None:
            problems.append(f"{host}: no map")
            continue
        for want in ports:
            g = norm(want["guid"])
            local = [(cp, kv) for cp, kv in m["ports"].items() if norm(kv.get("guid")) == g]
            if len(local) != 1:
                problems.append(f"{host}: ring port {want['guid']} appears {len(local)} times in the map")
                continue
            cp, kv = local[0]
            if kv.get("pci") != want["pci"]:
                problems.append(f"{host} {cp}: PCI {kv.get('pci')}, inventory {want['pci']}")
            if kv.get("phys") != "5":
                problems.append(f"{host} {cp} ({want['guid']}): not linked (phys {kv.get('phys')})")
                continue
            peer = m["peers"].get(cp)
            if peer is None:
                problems.append(f"{host} {cp}: no neighbour query")
                continue
            if peer.get("rc") != "0":
                problems.append(f"{host} {cp}: neighbour query failed (rc {peer.get('rc')}: {peer.get('error')})")
                continue
            pg = norm(peer.get("port_guid"))
            if pg is None:
                problems.append(f"{host} {cp}: the neighbour query returned no usable port GUID ({peer.get('port_guid')})")
                continue
            if pg not in owner:
                problems.append(f"{host} {cp}: its neighbour {peer.get('port_guid')} is not an inventory ring port (external)")
                continue
            if owner[pg][0] == host:
                problems.append(f"{host} {cp}: its neighbour {peer.get('port_guid')} is on the same node")
                continue
            ends[g] = {"host": host, "ca_port": cp, "guid": want["guid"], "pci": want["pci"], "peer": pg}
    links = {}
    for g, e in ends.items():
        back = ends.get(e["peer"])
        if back is None or back["peer"] != g:
            problems.append(f"{e['host']} {e['ca_port']} -> {e['peer']}: not reciprocal "
                            f"({'the other end has no proved neighbour' if back is None else 'it names ' + back['peer']})")
            continue
        pair = tuple(sorted((e["host"], back["host"])))
        links.setdefault(pair, set()).add(tuple(sorted((g, e["peer"]))))
    want_pairs = {tuple(sorted(l["ends"])): l["name"] for l in inventory["links"]}
    out = []
    for pair, cables in sorted(links.items()):
        if pair not in want_pairs:
            problems.append(f"a link {pair[0]} - {pair[1]} that network.yml does not have")
        if len(cables) != 1:
            problems.append(f"{len(cables)} links between {pair[0]} and {pair[1]}")
    for pair, name in sorted(want_pairs.items()):
        if pair not in links:
            problems.append(f"ring link {name} ({pair[0]} - {pair[1]}) not proved")
        elif len(links[pair]) == 1:
            a, b = next(iter(links[pair]))
            out.append({"name": name, "ends": [ends[a] | {"peer": None}, ends[b] | {"peer": None}]})
    return problems, out


def load_inventory(inv):
    hv = {p.stem: yaml.safe_load(p.read_text()) for p in (inv / "host_vars").glob("*.yml")}
    net = yaml.safe_load((inv / "group_vars/all/network.yml").read_text())
    ports = {h: v["ib_ring_ports"] for h, v in hv.items() if v.get("ib_ring_ports")}
    links = [{"name": l["name"], "ends": list(l["ends"])} for l in net["ring_links"]]
    return {"ports": ports, "links": links}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("maps", nargs="+", type=Path)
    ap.add_argument("--inventory", type=Path, default=INFRA / "inventories/fleet")
    a = ap.parse_args(argv)
    try:
        inventory = load_inventory(a.inventory)
        maps = {}
        for f in a.maps:
            m = parse(f.read_text())
            if not m["node"] or m["node"] in maps:
                raise ValueError(f"{f}: no node line, or a second map of {m['node']}")
            maps[m["node"]] = m
    except (OSError, ValueError, KeyError, TypeError, yaml.YAMLError) as e:
        print(f"unusable input: {e}", file=sys.stderr)
        return 2
    problems, links = check(maps, inventory)
    for p in problems:
        print(f"FAIL: {p}")
    if problems:
        return 1
    for l in links:
        a_, b_ = l["ends"]
        print(f"PASS: {l['name']}: {a_['host']} {a_['ca_port']} ({a_['pci']}) <-> {b_['host']} {b_['ca_port']} ({b_['pci']})")
    print(json.dumps(links, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""The InfiniBand ring's fabric plan and its check (T64; roles/ib_fabric, playbooks/ib-fabric.yml).
Offline and read-only: it reads the inventory and recorded evidence, never a host.

  ib-fabric-check.py plan  [--inventory DIR] [--peer-map DIR] [--links L1,L2] [--packages P1,P2]
  ib-fabric-check.py check [--inventory DIR] [--peer-map DIR] [--links L1,L2] [--expect present|absent] NODE.json...

plan: the configuration every GPU node gets, derived ONLY from proved facts. The peer map is the
evidence directory of the mapping window (docs/runbooks/IB-PEER-MAP-2026-10-02.md): one raw
ib-peer-map.sh output per GPU node and a SHA256SUMS that covers each of them. The plan re-checks
those hashes and re-runs ib-peer-check.py's proof on the raw maps, so no hand-written or edited map
can configure a port. With the proved links it joins network.yml ring_links (the /30 subnet, each
end's address, the subnet manager's node) and ib_fabric.yml (each link's unique GID subnet prefix,
the IPoIB mode and MTU). --packages: each name's one exact file in roles/fleet_repo
fleet_repo_extra_packages (refused if unpinned or pinned twice). Prints JSON: {links, hosts: {host:
{ports, sm}}, full_sm_units, pins, ipoib}.

check: each NODE.json is the output of roles/ib_fabric/files/prace-ib-ports.py on one GPU node.
present (default): for every ring link of the plan (or of --links), both ends ACTIVE with the
link's own subnet prefix and its subnet manager's LID, and each end's live neighbour (read now) the
planned other end; the link's OpenSM unit active on its planned node only, no other opensm process,
the stock opensm.service not active; each end's IPoIB device proved to be that port, in the ring's
firewalld zone, with the planned mode and MTU, holding exactly its planned /30 address, and the
peer answering a ping over it. On every node: no port outside the ring linked or addressed (an
outside fabric); an address that could not be read counts as a fault, never as none.
absent: no prace-opensm unit or opensm process, every ring port retrained to LinkUp and
INIT or ARMED, no IPv4 address on any ring port's IPoIB device. Every inventory node must report in
either state, including a node outside the selected stage. Unreadable states never prove rollback.

Outside the tests, the peer map and the inventory records it is joined with (ib_fabric.yml,
network.yml, the GPU nodes' host_vars) must be committed and unmodified in this repository (git).
Exit 0 all proved; 1 not proved; 2 unusable input."""
import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import yaml

INFRA = Path(__file__).resolve().parent.parent
REPO = Path(os.environ.get("PRACE_IB_EVIDENCE_ROOT") or INFRA.parent)    # tests only: a temporary repository root
_spec = importlib.util.spec_from_file_location("ib_peer_check", INFRA / "tools/ib-peer-check.py")
peer = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(peer)

PREFIX = re.compile(r"0x[0-9a-f]{16}")
UNIT = re.compile(r"prace-opensm@([a-z0-9-]+)\.service")


class Unusable(Exception):
    pass


def gid_prefix(text):
    """'0xfe80000000000001' (config) and 'fe80:0000:0000:0001' (sysfs) as one form"""
    t = (text or "").lower().replace(":", "")
    t = t[2:] if t.startswith("0x") else t
    return t if re.fullmatch(r"[0-9a-f]{16}", t) else None


def load(inventory):
    gv = inventory / "group_vars/all"
    net = yaml.safe_load((gv / "network.yml").read_text())
    fab = yaml.safe_load((gv / "ib_fabric.yml").read_text())
    return net, fab, peer.load_inventory(inventory)


def peer_map_dir(fab, override):
    rel = override or fab.get("ib_fabric_peer_map")
    if not rel:
        raise Unusable("no peer map recorded (ib_fabric_peer_map in ib_fabric.yml is null): run the mapping "
                       "window first (docs/runbooks/IB-PEER-MAP-2026-10-02.md)")
    p = Path(rel)
    if p.is_absolute() or ".." in p.parts or not p.parts or p.parts[0] != "evidence":
        raise Unusable(f"peer map {rel}: must be a path under evidence/ in this repository")
    d = REPO / p
    if not d.is_dir():
        raise Unusable(f"peer map {rel}: no such directory")
    return d


def committed(d):
    """the evidence directory is tracked by git and unmodified (tests run in a temporary root)"""
    if os.environ.get("PRACE_IB_EVIDENCE_ROOT"):
        return
    rel = str(d.relative_to(REPO))
    tracked = subprocess.run(["git", "-C", str(REPO), "ls-files", "--error-unmatch", "--", rel + "/SHA256SUMS"],
                                           capture_output=True, text=True)
    dirty = subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--", rel], capture_output=True, text=True)
    if tracked.returncode != 0 or dirty.returncode != 0 or dirty.stdout.strip():
        raise Unusable(f"peer map {rel}: must be committed and unmodified in git (a reviewed record, not a local file)")


def committed_inventory(inventory, hosts):
    """ib_fabric.yml, network.yml and the GPU host_vars are tracked and unmodified, when the inventory is
    this repository's (a temporary test inventory is not)"""
    if os.environ.get("PRACE_IB_EVIDENCE_ROOT"):
        return
    inv = inventory.resolve()
    if REPO.resolve() not in inv.parents:
        raise Unusable(f"inventory {inventory}: must be this repository's (a reviewed record, not a copy)")
    files = [inv / "group_vars/all/ib_fabric.yml", inv / "group_vars/all/network.yml"] + [inv / f"host_vars/{h}.yml" for h in hosts]
    rels = [str(f.relative_to(REPO.resolve())) for f in files]
    tracked = subprocess.run(["git", "-C", str(REPO), "ls-files", "--error-unmatch", "--", *rels], capture_output=True, text=True)
    dirty = subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--", *rels], capture_output=True, text=True)
    if tracked.returncode != 0 or dirty.returncode != 0 or dirty.stdout.strip():
        raise Unusable(f"{', '.join(rels)}: must be committed and unmodified in git (reviewed records, not local edits)")


def read_maps(d, hosts):
    """The raw maps, each bound to SHA256SUMS (a map that differs from its recorded hash is refused)."""
    sums = {}
    for line in (d / "SHA256SUMS").read_text().splitlines():
        f = line.split()
        if len(f) == 2 and re.fullmatch(r"[0-9a-f]{64}", f[0]):
            sums[f[1].lstrip("*").removeprefix("./")] = f[0]
    maps = {}
    for h in hosts:
        name = f"{h}.txt"
        if name not in sums:
            raise Unusable(f"{d.relative_to(REPO)}: SHA256SUMS does not cover {name}")
        data = (d / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != sums[name]:
            raise Unusable(f"{d.relative_to(REPO)}/{name}: sha256 differs from SHA256SUMS")
        m = peer.parse(data.decode())
        if m["node"] != h:
            raise Unusable(f"{name}: its node line names {m['node']}")
        maps[h] = m
    return maps


def pins(names):
    """{name: nevra} from roles/fleet_repo; problems for a name with no or several pinned files"""
    extra = yaml.safe_load((INFRA / "roles/fleet_repo/defaults/main.yml").read_text())["fleet_repo_extra_packages"]
    found, problems = {}, []
    for e in extra:
        found.setdefault(e["nevra"].rsplit("-", 2)[0], []).append(e["nevra"])
    for n in names:
        if len(found.get(n, [])) != 1:
            problems.append(f"package {n}: {len(found.get(n, []))} pinned files in fleet_repo_extra_packages (needs exactly 1)")
    return problems, {n: found[n][0] for n in names if len(found.get(n, [])) == 1}


def plan(inventory, override=None, only=None, packages=()):
    """(problems, plan): problems non-empty means nothing may be configured."""
    net, fab, inv = load(inventory)
    rings = {l["name"]: l for l in net["ring_links"]}
    names = list(rings)
    if only:
        bad = sorted(set(only) - set(names))
        if bad:
            raise Unusable(f"unknown ring links {bad} (network.yml has {names})")
    d = peer_map_dir(fab, override)
    committed(d)
    committed_inventory(inventory, sorted(inv["ports"]))
    maps = read_maps(d, sorted(inv["ports"]))
    problems, proved = peer.check(maps, inv)
    if problems:
        return problems, None
    proved = {l["name"]: l for l in proved}
    prefixes = fab.get("ib_fabric_gid_prefixes") or {}
    seen_prefix, nets, out = {}, [], []
    admin = ipaddress.ip_network(net["admin_network"])
    for name in names:
        ring = rings[name]
        pre = str(prefixes.get(name, ""))
        if not PREFIX.fullmatch(pre) or pre == "0xfe80000000000000":
            problems.append(f"{name}: ib_fabric_gid_prefixes needs its own 0x<16 hex> prefix, not the default ({pre or 'none'})")
        elif pre in seen_prefix:
            problems.append(f"{name}: subnet prefix {pre} is also {seen_prefix[pre]}'s")
        seen_prefix[pre] = name
        subnet = ipaddress.ip_network(ring["subnet"])
        if subnet.prefixlen != 30 or subnet.overlaps(admin) or any(subnet.overlaps(n) for n in nets):
            problems.append(f"{name}: subnet {subnet} must be a /30 outside the admin network and the other links")
        nets.append(subnet)
        hosts = sorted(ring["ends"])
        ips = [ipaddress.ip_address(ring["ends"][h]) for h in hosts]
        if len(set(ips)) != 2 or any(ip not in subnet or ip in (subnet.network_address, subnet.broadcast_address)
                                     for ip in ips):
            problems.append(f"{name}: end addresses {[str(i) for i in ips]} are not two host addresses of {subnet}")
        if ring.get("sm") not in hosts:
            problems.append(f"{name}: its subnet manager node {ring.get('sm')} is not one of its ends")
        ends = {e["host"]: e for e in proved[name]["ends"]}
        link = {"name": name, "subnet": str(subnet), "gid_prefix": pre, "sm": ring.get("sm"), "ends": []}
        for h in hosts:
            e, other = ends[h], [x for x in hosts if x != h][0]
            ca, port = e["ca_port"].split("/")
            if peer.norm(e["guid"]) in (None, "0" * 16):
                problems.append(f"{name} {h}: port GUID {e['guid']} is not a usable 16-hex GUID")
            link["ends"].append({"host": h, "ca": ca, "port": int(port), "guid": e["guid"], "pci": e["pci"],
                                 "ip": ring["ends"][h], "prefixlen": 30, "peer_host": other,
                                 "peer_ip": ring["ends"][other], "peer_guid": ends[other]["guid"]})
        out.append(link)
    mode, mtu = fab.get("ib_fabric_ipoib_mode"), fab.get("ib_fabric_ipoib_mtu")
    if (mode, mtu) not in (("datagram", 2044), ("datagram", 4092), ("connected", 65520)):
        problems.append(f"IPoIB mode {mode} with MTU {mtu}: use datagram 2044/4092 or connected 65520")
    pin_problems, pinned = pins(packages)
    problems += pin_problems
    if problems:
        return problems, None
    chosen = [l for l in out if not only or l["name"] in only]
    hosts = {}
    for h in sorted(inv["ports"]):
        hosts[h] = {"ports": [], "sm": []}
    for l in chosen:
        for e in l["ends"]:
            hosts[e["host"]]["ports"].append(dict(e, link=l["name"], gid_prefix=l["gid_prefix"], sm=l["sm"] == e["host"]))
            if l["sm"] == e["host"]:
                hosts[e["host"]]["sm"].append({"link": l["name"], "guid": e["guid"], "gid_prefix": l["gid_prefix"],
                                               "ca": e["ca"], "port": e["port"], "peer_guid": e["peer_guid"]})
    full_sm = {h: sorted(l["name"] for l in out if l["sm"] == h) for h in hosts}
    return [], {"links": chosen, "all_links": [l["name"] for l in out], "hosts": hosts, "full_sm": full_sm,
                "full_sm_units": {h: [f"prace-opensm@{n}.service" for n in v] for h, v in full_sm.items()}, "pins": pinned,
                "ipoib": {"mode": mode, "mtu": mtu}, "ring_guids": {h: [p["guid"] for p in v] for h, v in inv["ports"].items()}}


def check(p, nodes, expect="present", zone="prace-ring"):
    """problems for the helper outputs {host: json} against plan p"""
    problems = []
    sm_lids = {}                                    # link -> the LID of its planned subnet manager's port
    for l in p.get("links", []):
        sm_end = next((e for e in l["ends"] if e["host"] == l["sm"]), None)
        rep_ = nodes.get(l["sm"]) or {}
        x = next((x for x in rep_.get("ports", []) if sm_end and peer.norm(x.get("guid")) == peer.norm(sm_end["guid"])), None)
        if x and x.get("lid"):
            sm_lids[l["name"]] = x["lid"]
    ring = {h: {peer.norm(g) for g in gs} for h, gs in p["ring_guids"].items()}
    unknown = sorted(set(nodes) - set(ring))
    if unknown:
        problems.append(f"reports from nodes without ring ports: {unknown}")
    # Every inventory node must report, even when absent or outside this stage:
    # otherwise missing observations can hide an active port or outside fabric.
    for h in sorted(set(nodes) | set(ring)):
        if h not in ring:
            continue
        n = nodes.get(h)
        if n is None:
            problems.append(f"{h}: no node report")
            continue
        if n.get("node") != h:
            problems.append(f"{h}: the report names node {n.get('node')}")
            continue
        ports = {peer.norm(x.get("guid")): x for x in n.get("ports", [])}
        units = set()
        for u in n.get("opensm_units", []):
            m = UNIT.fullmatch(u)
            if not m:
                problems.append(f"{h}: unexpected unit {u}")
            else:
                units.add(m.group(1))
        if n.get("stock_opensm") == "active":
            problems.append(f"{h}: the stock opensm.service is active (it binds the first port it finds)")
        if n.get("opensm_procs") != len(units):
            problems.append(f"{h}: {n.get('opensm_procs')} opensm processes for {len(units)} prace-opensm units")
        for g, x in ports.items():
            if g in ring[h]:
                continue
            if str(x.get("phys")) not in {"1", "2", "3", "4", "5", "6", "7"}:
                problems.append(f"{h} {x.get('ca')}/{x.get('port')} ({x.get('guid')}): outside port physical state "
                                f"{x.get('phys')} is unreadable or unknown; absence of an outside fabric is not proved")
            if x.get("ipv4") is None:
                problems.append(f"{h} {x.get('ca')}/{x.get('port')} ({x.get('guid')}): its addresses could not be read")
            elif str(x.get("phys")) == "5" or x.get("ipv4"):
                problems.append(f"{h} {x.get('ca')}/{x.get('port')} ({x.get('guid')}): a port outside the ring is linked or "
                                "addressed (an outside fabric): never run a subnet manager or IPoIB beside it")
        if expect == "absent":
            if units:
                problems.append(f"{h}: OpenSM units still active: {sorted(units)}")
            for g in ring[h]:
                x = ports.get(g)
                if x is None:
                    problems.append(f"{h}: ring port {g} not in the report")
                    continue
                if x.get("ipv4") is None or x.get("ipv4"):
                    problems.append(f"{h} {x.get('netdev')}: ring port still addressed, or unreadable: {x.get('ipv4')}")
                if str(x.get("phys")) != "5":
                    detail = ("left Disabled (phys 3)" if str(x.get("phys")) == "3"
                              else f"physical state {x.get('phys')} is not proved LinkUp")
                    problems.append(f"{h} {x.get('ca')}/{x.get('port')} ({x.get('guid')}): ring port {detail}; "
                                    "the reset did not bring the link back")
                if str(x.get("state")) == "4":
                    problems.append(f"{h} {x.get('ca')}/{x.get('port')} ({x.get('guid')}): ring port still ACTIVE "
                                    "(verbs RDMA works without a subnet manager); reset it to INIT")
                elif str(x.get("state")) == "1":
                    problems.append(f"{h} {x.get('ca')}/{x.get('port')} ({x.get('guid')}): ring port still DOWN; "
                                    "INIT or ARMED is required to prove retraining")
                elif str(x.get("state")) not in {"2", "3"}:
                    problems.append(f"{h} {x.get('ca')}/{x.get('port')} ({x.get('guid')}): ring port state "
                                    f"{x.get('state')} is unreadable or unknown; rollback is not proved")
            continue
        planned_sm = {s["link"] for s in p["hosts"].get(h, {}).get("sm", [])}
        missing = planned_sm - units
        extra = units - set(p["full_sm"].get(h, []))
        if missing:
            problems.append(f"{h}: OpenSM not active for {sorted(missing)}")
        if extra:
            problems.append(f"{h}: OpenSM active for links it does not manage: {sorted(extra)}")
        pings = {(x.get("dst"), x.get("dev")): x for x in n.get("pings", [])}
        for e in p["hosts"].get(h, {}).get("ports", []):
            x = ports.get(peer.norm(e["guid"]))
            where = f"{h} {e['link']} ({e['guid']})"
            if x is None:
                problems.append(f"{where}: port not in the report")
                continue
            if x.get("pci") != e["pci"]:
                problems.append(f"{where}: PCI {x.get('pci')}, planned {e['pci']}")
            if str(x.get("state")) != "4" or str(x.get("phys")) != "5":
                problems.append(f"{where}: not ACTIVE/LinkUp (state {x.get('state')}, phys {x.get('phys')})")
            if gid_prefix(x.get("gid_prefix")) != gid_prefix(e["gid_prefix"]):
                problems.append(f"{where}: subnet prefix {x.get('gid_prefix')}, planned {e['gid_prefix']}")
            if not x.get("sm_lid"):
                problems.append(f"{where}: no subnet manager LID")
            elif e["link"] not in sm_lids:
                problems.append(f"{where}: the planned manager's own port ({e['link']}) reports no LID, so its SM LID cannot be proved")
            elif x.get("sm_lid") != sm_lids[e["link"]]:
                problems.append(f"{where}: subnet manager LID {x.get('sm_lid')}, but the planned manager's port has LID {sm_lids[e['link']]}")
            nb = x.get("peer") or {}
            if nb.get("rc") != 0 or peer.norm(nb.get("port_guid")) != peer.norm(e["peer_guid"]) \
                    or "channel adapter" not in str(nb.get("type") or "").lower():
                problems.append(f"{where}: its neighbour now is {nb.get('port_guid')} ({nb.get('type')}, rc {nb.get('rc')}), "
                                f"planned {e['peer_host']}'s {e['peer_guid']}: a moved cable needs a new peer map")
            if not x.get("netdev") or x.get("netdev_guid_ok") is not True:
                problems.append(f"{where}: no IPoIB device proved to be this port ({x.get('netdev')})")
                continue
            if x.get("zone") != zone:
                problems.append(f"{where}: {x.get('netdev')} is in firewalld zone {x.get('zone')}, planned {zone}")
            if x.get("mode") != p["ipoib"]["mode"] or x.get("mtu") != p["ipoib"]["mtu"]:
                problems.append(f"{where}: IPoIB {x.get('mode')} MTU {x.get('mtu')}, planned {p['ipoib']['mode']} MTU {p['ipoib']['mtu']}")
            want = f"{e['ip']}/{e['prefixlen']}"
            if x.get("ipv4") != [want]:
                problems.append(f"{where}: {x.get('netdev')} holds {x.get('ipv4')}, planned exactly [{want}]")
            pg = pings.get((e["peer_ip"], x.get("netdev")))
            if not pg or pg.get("ok") is not True:
                problems.append(f"{where}: the peer {e['peer_host']} ({e['peer_ip']}) did not answer over {x.get('netdev')}")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["plan", "check"])
    ap.add_argument("nodes", nargs="*", type=Path)
    ap.add_argument("--inventory", type=Path, default=INFRA / "inventories/fleet")
    ap.add_argument("--peer-map", help="evidence directory of the mapping window (default: ib_fabric_peer_map)")
    ap.add_argument("--links", default="", help="a stage: comma-separated ring link names (default: all)")
    ap.add_argument("--expect", choices=["present", "absent"], default="present")
    ap.add_argument("--packages", default="", help="plan: names whose exact pinned file to report")
    ap.add_argument("--zone", default="prace-ring", help="check: the ring's firewalld zone")
    a = ap.parse_intermixed_args(argv)
    only = [x for x in a.links.split(",") if x]
    try:
        if a.command == "check" and a.expect == "absent":
            _, _, inv = load(a.inventory)
            p = {"ring_guids": {h: [x["guid"] for x in v] for h, v in inv["ports"].items()}, "hosts": {}, "full_sm": {}}
            problems = []
        else:
            problems, p = plan(a.inventory, a.peer_map, only, [x for x in a.packages.split(",") if x])
        if a.command == "plan" or problems:
            for x in problems:
                print(f"FAIL: {x}")
            if problems:
                return 1
            print(json.dumps(p, indent=1, sort_keys=True))
            return 0
        nodes = {}
        for f in a.nodes:
            n = json.loads(f.read_text())
            if not isinstance(n, dict) or n.get("node") in nodes:
                raise Unusable(f"{f}: not a node report, or a second report of {n.get('node')}")
            nodes[n["node"]] = n
    except (OSError, ValueError, KeyError, TypeError, AttributeError, yaml.YAMLError, Unusable) as e:
        print(f"unusable input: {e}", file=sys.stderr)
        return 2
    problems = check(p, nodes, a.expect, a.zone)
    for x in problems:
        print(f"FAIL: {x}")
    if problems:
        return 1
    print(f"PASS: InfiniBand ring {a.expect}" + (f" ({', '.join(l['name'] for l in p['links'])})" if a.expect == "present" else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())

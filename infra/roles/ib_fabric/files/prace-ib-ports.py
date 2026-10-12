#!/usr/bin/python3 -I
"""Read-only report of this node's InfiniBand ports, IPoIB addresses and subnet managers, as JSON
(roles/ib_fabric; judged by infra/tools/ib-fabric-check.py). Changes nothing; Python 3.9.

  prace-ib-ports.py [--ping IP ...]
  (by hand: ssh root@<node> /usr/bin/python3 - --ping <peer IPs> < roles/ib_fabric/files/prace-ib-ports.py)

Only ports whose link layer is InfiniBand are reported (the ConnectX Ethernet fibre ports are D43's).
Each port's IPoIB device is the network device of type 32 (ARPHRD_INFINIBAND) on the port's own PCI
function, and it counts as this port's only if its 20-byte hardware address ends with the port GUID;
its firewalld zone, MTU and mode are reported with it. Each linked port's neighbour is read now, by
the same directed-route NodeInfo query as ib-peer-map.sh (smpquery; no subnet manager needed): a
cable moved since the peer map shows here. A command that fails is reported as unknown (None),
never as an empty answer.
--ping: each address is pinged only over the IPoIB device whose own subnet holds it (3 probes, 2 s
each); an address no local IPoIB subnet holds is reported unanswered, never pinged another way."""
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys

SYSFS = os.environ.get("PRACE_IB_SYSFS", "/sys/class/infiniband")
NET = os.environ.get("PRACE_NET_SYSFS", "/sys/class/net")   # PRACE_IB_SYSFS, PRACE_NET_SYSFS, PRACE_IB_NODE: tests only


def read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def lead_int(text, base=10):
    """'4: ACTIVE' -> 4, '0x1' -> 1; None if unreadable"""
    try:
        return int((text or "").split(":")[0].strip(), base)
    except ValueError:
        return None


def run(argv):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=30)
        return r.returncode, r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""


def netdevs():
    """{pci: [(name, dev_port, address)]} of IPoIB devices"""
    out = {}
    for n in sorted(os.listdir(NET)) if os.path.isdir(NET) else []:
        if read(os.path.join(NET, n, "type")) != "32":
            continue
        pci = os.path.basename(os.path.realpath(os.path.join(NET, n, "device")))
        out.setdefault(pci, []).append((n, lead_int(read(os.path.join(NET, n, "dev_port"))),
                                        (read(os.path.join(NET, n, "address")) or "").lower()))
    return out


def ipv4(dev):
    """the device's IPv4 addresses; None when ip fails (unknown is never 'no address')"""
    rc, text = run(["ip", "-j", "-4", "addr", "show", "dev", dev])
    if rc != 0:
        return None
    try:
        data = json.loads(text) if text.strip() else []
    except ValueError:
        return None
    return sorted(f"{a['local']}/{a['prefixlen']}" for d in data for a in d.get("addr_info", [])
                  if a.get("family", "inet") == "inet")


def zone(dev):
    rc, text = run(["firewall-cmd", "--get-zone-of-interface=" + dev])
    return text.strip() if rc == 0 and text.strip() else None


def neighbour(ca, port):
    """the linked neighbour's identity, read now (smpquery -D nodeinfo 0,1; read-only, no SM needed)"""
    rc, text = run(["timeout", "15", "smpquery", "-C", ca, "-P", str(port), "-D", "nodeinfo", f"0,{port}"])
    f = {}
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z]+):\.*(.*)$", line)
        if m:
            f[m.group(1)] = m.group(2).strip()
    g = f.get("PortGuid", "").lower()
    g = g[2:] if g.startswith("0x") else g
    ok = rc == 0 and re.fullmatch(r"[0-9a-f]{16}", g or "") is not None
    return {"rc": rc, "port_guid": ":".join(g[i:i + 4] for i in range(0, 16, 4)) if ok else None,
            "type": f.get("NodeType") if rc == 0 else None}


def ports():
    devs, out = netdevs(), []
    for ca in sorted(os.listdir(SYSFS)) if os.path.isdir(SYSFS) else []:
        base = os.path.join(SYSFS, ca)
        if not os.path.isdir(os.path.join(base, "ports")):
            continue                                    # an RDMA device without ports (ib-peer-map.sh skips it too)
        pci = os.path.basename(os.path.realpath(os.path.join(base, "device")))
        for port in sorted(os.listdir(os.path.join(base, "ports")), key=lambda s: int(s) if s.isdigit() else 0):
            p = os.path.join(base, "ports", port)
            if read(os.path.join(p, "link_layer")) != "InfiniBand":
                continue
            gid = (read(os.path.join(p, "gids/0")) or "").lower().split(":")
            guid = ":".join(gid[4:8]) if len(gid) == 8 else None
            cand = [d for d in devs.get(pci, []) if d[1] in (None, int(port) - 1)]
            dev = cand[0] if len(cand) == 1 else None
            ok = bool(dev and guid and dev[2].replace(":", "").endswith(guid.replace(":", "")))
            phys = lead_int(read(os.path.join(p, "phys_state")))
            nd = os.path.join(NET, dev[0]) if dev else None
            out.append({"ca": ca, "port": int(port), "guid": guid, "pci": pci,
                        "gid_prefix": ":".join(gid[0:4]) if len(gid) == 8 else None,
                        "state": lead_int(read(os.path.join(p, "state"))),
                        "phys": phys,
                        "lid": lead_int(read(os.path.join(p, "lid")), 16),
                        "sm_lid": lead_int(read(os.path.join(p, "sm_lid")), 16),
                        "netdev": dev[0] if dev else None, "netdev_guid_ok": ok,
                        "ipv4": ipv4(dev[0]) if dev else [],
                        "mtu": lead_int(read(os.path.join(nd, "mtu"))) if nd else None,
                        "mode": read(os.path.join(nd, "mode")) if nd else None,
                        "zone": zone(dev[0]) if dev else None,
                        "peer": neighbour(ca, int(port)) if phys == 5 else None})
    return out


def main(argv):
    targets = argv[argv.index("--ping") + 1:] if "--ping" in argv else []
    report = {"node": os.environ.get("PRACE_IB_NODE") or socket.gethostname().split(".")[0], "ports": ports()}
    rc, text = run(["systemctl", "list-units", "--type=service", "--state=active", "--plain", "--no-legend",
                    "prace-opensm@*"])
    report["opensm_units"] = sorted(line.split()[0] for line in text.splitlines() if line.strip()) if rc == 0 else ["?"]
    rc, text = run(["systemctl", "is-active", "opensm.service"])
    report["stock_opensm"] = text.strip() or "unknown"
    rc, text = run(["pgrep", "-x", "opensm"])
    report["opensm_procs"] = len(text.split()) if rc in (0, 1) else None
    pings = []
    for t in targets:
        try:
            ip = ipaddress.ip_address(t)
        except ValueError:
            pings.append({"dst": t, "dev": None, "ok": False, "why": "not an address"})
            continue
        dev = [x["netdev"] for x in report["ports"] for a in (x["ipv4"] or [])
               if ip in ipaddress.ip_interface(a).network and ip != ipaddress.ip_interface(a).ip]
        if len(dev) != 1:
            pings.append({"dst": t, "dev": None, "ok": False, "why": "no single local IPoIB subnet holds it"})
            continue
        rc, _ = run(["ping", "-n", "-q", "-c", "3", "-W", "2", "-I", dev[0], t])
        pings.append({"dst": t, "dev": dev[0], "ok": rc == 0, "why": None if rc == 0 else f"ping rc {rc}"})
    report["pings"] = pings
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

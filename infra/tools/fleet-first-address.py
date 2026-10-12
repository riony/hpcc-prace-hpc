#!/usr/bin/env python3
"""Fleet first private address: unattended and fail-closed (FLEET-REBUILD-2026-09-28.md).

Runs once at first boot on a freshly installed compute node (prace-first-address.service,
embedded by kickstart/build-ks.sh) or by hand on its console. It finds the admin-network
port by evidence, never by interface name or card slot: among this node's candidate
ports (permanent MACs from the reviewed inventory, in FLEET below) it keeps the one on
which the login node's known MAC answers ARP for 10.90.10.1. It requires EXACTLY ONE such
port and stops on zero (retrying while --retry-minutes allows, since the login node may
not be up yet) or on several, and on any other MAC answering for 10.90.10.1.

It never adds a gateway, DNS or IPv6 and writes one NetworkManager keyfile that
roles/private_net adopts. Without --apply it is a dry run: candidate links are raised
briefly (no address, IPv6 off) to test carrier and ARP, then restored. Python 3.9, no pip
dependencies. Required tools: ip, nmcli, ethtool, arping, sysctl, restorecon, firewall-cmd.
"""

import argparse
import configparser
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import subprocess
import sys
import time

# hostname: (chassis serial, DMI product-name substring, admin address, candidate MACs).
# Must match infra/inventories/fleet/host_vars (checked by tools/test-fleet-inventory.py).
FLEET = {
    "lab-g003": ("EXSERIAL03", "XL270d Gen10", "10.90.10.13",
                      ("02:00:00:00:00:08", "02:00:00:00:00:09", "02:00:00:00:00:0a", "02:00:00:00:00:0b")),
    "lab-g004": ("EXSERIAL04", "XL270d Gen10", "10.90.10.14",
                      ("02:00:00:00:00:0e", "02:00:00:00:00:0f", "02:00:00:00:00:10", "02:00:00:00:00:11")),
    "lab-g005": ("EXSERIAL05", "XL270d Gen10", "10.90.10.15", ("02:00:00:00:00:14",)),
    "lab-lenovo": ("EXSER02", "x3650 M5", "10.90.10.21", ("02:00:00:00:00:05",)),
}
PREFIX = 25
NETWORK = "10.90.10.0"
BROADCAST = "10.90.10.127"
PEER_IP = "10.90.10.1"
PEER_MAC = "02:00:00:00:00:01"     # login node (DL380) private port
CARRIER_WAIT = 45                  # seconds; the G8052 blocks new links for ~30 s (STP)
PROBE_WINDOW = 45                  # seconds of ARP retries per port after carrier
SYS = Path("/sys")
PROFILE_DIR = Path("/etc/NetworkManager/system-connections")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")


class Stop(RuntimeError):
    pass


class Retry(Stop):
    """No port reached the login node yet; worth trying again later."""


def require(condition, message):
    if not condition:
        raise Stop(message)


def say(message):
    print(f"prace-first-address: {message}", flush=True)


def command(*argv, codes=(0,)):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=35,
                            env={**os.environ, "LC_ALL": "C"})
    require(result.returncode in codes,
            f"Command failed ({result.returncode}): {' '.join(argv)}: "
            f"{result.stderr.strip() or result.stdout.strip()}")
    return result


def read_json(*argv):
    return json.loads(command(*argv).stdout)


def sysfs(*parts):
    return (SYS.joinpath(*parts)).read_text().strip()


def sleep(seconds):
    time.sleep(seconds)


def keyfile(interface, address):
    # Same content as roles/private_net writes, so Ansible adopts this profile unchanged.
    return (
        "# Managed by Ansible private_net. Do not edit by hand.\n"
        f"[connection]\nid=private-{interface}\ntype=ethernet\n"
        f"interface-name={interface}\nautoconnect=true\nzone=public\n\n"
        f"[ipv4]\nmethod=manual\naddress1={address}/{PREFIX}\nnever-default=true\n\n"
        "[ipv6]\nmethod=disabled\n\n[proxy]\n"
    )


def safe_keyfile(path, expected, profile_uuid=None):
    """Allow only the exact settings plus NM-generated UUID/timestamp."""
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
            and stat.S_IMODE(info.st_mode) == 0o600,
            "Existing target is not a root-owned regular 0600 keyfile")
    actual = configparser.ConfigParser(interpolation=None, strict=True)
    desired = configparser.ConfigParser(interpolation=None, strict=True)
    actual.read_string(path.read_text())
    desired.read_string(expected)
    require(not actual.defaults(), "Unexpected keyfile defaults")
    if actual.has_option("connection", "uuid"):
        value = actual.get("connection", "uuid")
        require(UUID_RE.fullmatch(value) is not None
                and (profile_uuid is None or value == profile_uuid),
                "Keyfile UUID is invalid or differs from the active profile")
        actual.remove_option("connection", "uuid")
    if actual.has_option("connection", "timestamp"):
        require(actual.get("connection", "timestamp").isdigit(), "Invalid NetworkManager timestamp")
        actual.remove_option("connection", "timestamp")
    require({s: dict(actual[s]) for s in actual.sections()}
            == {s: dict(desired[s]) for s in desired.sections()},
            "Existing target keyfile differs from the exact safe configuration")


def profile_uuids(name):
    output = command("nmcli", "-t", "--escape", "no", "-f", "UUID,NAME", "connection", "show").stdout
    result = []
    for line in output.splitlines():
        ident, sep, candidate = line.partition(":")
        if sep and candidate == name:
            require(UUID_RE.fullmatch(ident) is not None, "Invalid profile UUID")
            result.append(ident)
    return result


def private_profiles():
    output = command("nmcli", "-t", "--escape", "no", "-f", "NAME", "connection", "show").stdout
    return sorted(n for n in output.splitlines() if n.startswith("private-"))


def active_uuids(interface):
    output = command("nmcli", "-t", "--escape", "no", "-f", "UUID,DEVICE",
                     "connection", "show", "--active").stdout
    return [line.partition(":")[0] for line in output.splitlines()
            if line.partition(":")[2] == interface]


def check_nm_settings(profile_uuid, interface, address):
    fields = ("connection.id,connection.interface-name,connection.zone,"
              "connection.autoconnect,ipv4.method,ipv4.addresses,ipv4.gateway,"
              "ipv4.dns,ipv4.never-default,ipv6.method")
    actual = command("nmcli", "-g", fields, "connection", "show", "uuid", profile_uuid).stdout.splitlines()
    require(actual == [f"private-{interface}", interface, "public", "yes", "manual",
                       f"{address}/{PREFIX}", "", "", "yes", "disabled"],
            "Loaded NetworkManager settings differ from the safe profile")


def validate_routes(routes4, routes6, address=None):
    if address is None:
        require(not routes4, "Interface has existing IPv4 routes")
    else:
        net = f"{NETWORK}/{PREFIX}"
        allowed = {net, NETWORK, BROADCAST, address}
        require(any(r.get("dst") == net for r in routes4), "Expected private connected route is missing")
        require(all(r.get("dst") in allowed and not r.get("gateway")
                    and r.get("protocol") == "kernel" for r in routes4),
                "Unexpected IPv4 route on the private interface")
    require(all(r.get("dst") == "ff00::/8" and r.get("table") == "local"
                and r.get("protocol") == "kernel" and not r.get("gateway")
                for r in routes6), "Interface has unexpected IPv6 routes")


def runtime(interface, address=None):
    links = read_json("ip", "-j", "address", "show", "dev", interface)
    require(len(links) == 1, "Expected exactly one selected interface")
    addresses = links[0].get("addr_info", [])
    if address is None:
        require(not addresses, f"{interface} already has an IPv4 or IPv6 address")
    else:
        require(len(addresses) == 1 and addresses[0].get("family") == "inet"
                and addresses[0].get("local") == address
                and addresses[0].get("prefixlen") == PREFIX,
                "Private interface addresses do not exactly match the target")
    validate_routes(read_json("ip", "-j", "-4", "route", "show", "table", "all", "dev", interface),
                    read_json("ip", "-j", "-6", "route", "show", "table", "all", "dev", interface), address)


def arp_probe(interface, address):
    # iputils DAD mode uses source 0.0.0.0: neither assigns nor claims an IP.
    result = command("arping", "-D", "-I", interface, "-c", "3", "-w", "4", address, codes=(0, 1))
    replies = re.findall(r"reply from ([0-9.]+) \[([0-9A-Fa-f:]+)\]", result.stdout, flags=re.IGNORECASE)
    count = re.search(r"Received (\d+) response", result.stdout)
    require(count is not None and int(count.group(1)) == len(replies),
            "Unrecognized/inconsistent arping output; refusing to guess")
    return result.returncode, [(ip, mac.lower()) for ip, mac in replies]


def peer_state(interface):
    """'peer' if only the login node answers for PEER_IP, 'conflict' if anyone else does."""
    code, replies = arp_probe(interface, PEER_IP)
    if not replies:
        return "none"
    if all(pair == (PEER_IP, PEER_MAC) for pair in replies):
        return "peer"
    return "conflict"


def identify():
    require(os.geteuid() == 0, "Run as root on the node")
    hostname = socket.gethostname().split(".")[0]
    require(hostname in FLEET, f"Host name {hostname!r} is not a fleet compute node")
    serial, product, address, macs = FLEET[hostname]
    require(sysfs("class/dmi/id/product_serial") == serial, "Wrong chassis serial for this host name")
    require(product in sysfs("class/dmi/id/product_name"), "Unexpected DMI product name")
    for program in ("ip", "nmcli", "ethtool", "arping", "sysctl", "restorecon", "firewall-cmd"):
        require(shutil.which(program), f"Required system tool absent: {program}")
    directory = PROFILE_DIR.lstat()
    require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0
            and not stat.S_IMODE(directory.st_mode) & 0o022,
            "NetworkManager keyfile directory has unsafe ownership/type/mode")
    require(command("firewall-cmd", "--state").stdout.strip() == "running", "firewalld must be running")
    return hostname, address, macs


def candidates(macs, only=None):
    """Physical Ethernet ports whose PERMANENT MAC is one of this node's candidates."""
    found = []
    for nic in sorted(p.name for p in (SYS / "class/net").iterdir()):
        base = SYS / "class/net" / nic
        if only and nic != only:
            continue
        if not (base / "device").exists() or sysfs("class/net", nic, "type") != "1" or (base / "master").exists():
            continue
        permanent = command("ethtool", "-P", nic).stdout.strip().lower()
        mac = permanent.rpartition(" ")[2]
        if mac in macs:
            found.append(nic)
    return found


def link_up(interface):
    link = read_json("ip", "-j", "link", "show", "dev", interface)
    return len(link) == 1 and "UP" in link[0].get("flags", [])


def probe_ports(ports):
    """Raise each candidate link (no address, IPv6 off), test carrier and the login node.
    Returns ({port: 'peer'|'none'|'conflict'|'no-carrier'}, ports this run raised); every
    raised link except a 'peer' one is put back down before returning."""
    results, raised = {}, []
    try:
        for nic in ports:
            require(not active_uuids(nic), f"{nic}: an active NetworkManager connection exists; refusing to guess")
            command("sysctl", "-q", "-w", f"net.ipv6.conf.{nic}.disable_ipv6=1")
            if not link_up(nic):
                command("ip", "link", "set", "dev", nic, "up")
                raised.append(nic)
            runtime(nic)
        for nic in ports:
            waited = 0
            while sysfs("class/net", nic, "carrier") != "1" and waited < CARRIER_WAIT:
                sleep(3)
                waited += 3
            if sysfs("class/net", nic, "carrier") != "1":
                results[nic] = "no-carrier"
                continue
            state, waited = peer_state(nic), 0
            while state == "none" and waited < PROBE_WINDOW:
                sleep(5)
                waited += 5
                state = peer_state(nic)
            results[nic] = state
    finally:
        return_to = [n for n in raised if results.get(n) != "peer"]
        for nic in return_to:
            command("ip", "link", "set", "dev", nic, "down", codes=(0, 1))
    return results, raised


def choose(results):
    matches = sorted(n for n, s in results.items() if s == "peer")
    conflicts = sorted(n for n, s in results.items() if s == "conflict")
    summary = ", ".join(f"{n}={s}" for n, s in sorted(results.items())) or "no candidate ports present"
    require(not conflicts, f"another MAC answers for {PEER_IP} on {', '.join(conflicts)} ({summary}); stopping")
    if len(matches) > 1:
        raise Stop(f"{len(matches)} ports reach the login node ({summary}); exactly one is required; stopping")
    if not matches:
        raise Retry(f"no candidate port reached the login node ({summary})")
    return matches[0]


def prepare(interface, address):
    path = PROFILE_DIR / f"private-{interface}.nmconnection"
    require(not os.path.lexists(path) and not profile_uuids(f"private-{interface}")
            and not active_uuids(interface), "Conflicting existing/active NM profile")
    runtime(interface)
    all_links = read_json("ip", "-j", "address", "show")
    require(not any(a.get("local") == address for device in all_links
                    if device.get("ifname") != interface for a in device.get("addr_info", [])),
            "Target address is already assigned to another interface")
    code, replies = arp_probe(interface, address)
    require(code == 0 and not replies, f"Something already answers for {address}; stopping")
    return path


def apply_profile(interface, address, path):
    expected = keyfile(interface, address)
    created_uuid, created, written, identity = None, False, False, None
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = True
        info = os.fstat(fd)
        identity = (info.st_dev, info.st_ino)
        with os.fdopen(fd, "w") as target:
            os.fchmod(target.fileno(), 0o600)
            target.write(expected)
            target.flush()
            os.fsync(target.fileno())
        written = True
        command("restorecon", str(path))
        command("nmcli", "connection", "reload")
        found = profile_uuids(f"private-{interface}")
        require(len(found) == 1, "New profile did not load uniquely")
        created_uuid = found[0]
        command("nmcli", "--wait", "20", "connection", "up", "uuid", created_uuid, "ifname", interface)
        require(active_uuids(interface) == [created_uuid], "Wrong active profile")
        safe_keyfile(path, expected, created_uuid)
        check_nm_settings(created_uuid, interface, address)
        runtime(interface, address)
        require(command("firewall-cmd", f"--get-zone-of-interface={interface}").stdout.strip() == "public",
                "Private firewall zone verification failed")
        require(peer_state(interface) == "peer", "Login node not reachable after activation")
    except (Exception, KeyboardInterrupt) as error:
        problems = []
        if created:
            # Only undo what this run made: our UUID, our file.
            try:
                if created_uuid and created_uuid in active_uuids(interface):
                    command("nmcli", "--wait", "20", "connection", "down", "uuid", created_uuid)
                if os.path.lexists(path):
                    info = path.lstat()
                    if written:
                        safe_keyfile(path, expected, created_uuid)
                    else:
                        require(stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == identity,
                                "Partially written keyfile was replaced externally")
                    path.unlink()
                command("nmcli", "connection", "reload")
            except Exception as cleanup_error:
                problems.append(str(cleanup_error))
        detail = "; rollback incomplete: " + "; ".join(problems) if problems else ""
        raise Stop(f"Apply failed: {error}{detail}") from error


def already_configured(ports, address):
    """An exact, active profile from an earlier run: verify it and report no change."""
    existing = private_profiles()
    if not existing:
        return None
    require(len(existing) == 1, f"Several private profiles exist ({', '.join(existing)}); stopping")
    interface = existing[0][len("private-"):]
    require(interface in ports, f"Existing {existing[0]} is not on a candidate port; stopping")
    uuids = profile_uuids(existing[0])
    require(len(uuids) == 1 and active_uuids(interface) == uuids, "Existing private profile is not active")
    safe_keyfile(PROFILE_DIR / f"{existing[0]}.nmconnection", keyfile(interface, address), uuids[0])
    check_nm_settings(uuids[0], interface, address)
    runtime(interface, address)
    require(peer_state(interface) == "peer", "Login node not reachable on the existing private port")
    return interface


def run(apply, only=None):
    hostname, address, macs = identify()
    ports = candidates(macs, only)
    require(ports, f"none of this node's candidate MACs ({', '.join(macs)}) is present")
    done = already_configured(ports, address)
    if done:
        return {"host": hostname, "interface": done, "address": f"{address}/{PREFIX}",
                "result": "no-change: exact safe configuration already active"}
    results, raised = probe_ports(ports)
    try:
        chosen = choose(results)
    except Stop:
        for nic in raised:   # a lone 'peer' link was left up for apply; nothing to apply now
            if results.get(nic) == "peer":
                command("ip", "link", "set", "dev", nic, "down", codes=(0, 1))
        raise
    path = prepare(chosen, address)
    summary = {"host": hostname, "interface": chosen, "address": f"{address}/{PREFIX}", "probes": results}
    if not apply:
        if chosen in raised:   # restore only what this run raised
            command("ip", "link", "set", "dev", chosen, "down", codes=(0, 1))
        summary["result"] = "dry run passed: exactly one port reaches the login node; add --apply"
        return summary
    apply_profile(chosen, address, path)
    summary["result"] = f"applied: {path.name} active on {chosen}"
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--auto", action="store_true", required=True,
                        help="select the port by evidence (the only mode)")
    parser.add_argument("--apply", action="store_true", help="write and activate the profile")
    parser.add_argument("--only", help="restrict the search to this one candidate interface")
    parser.add_argument("--retry-minutes", type=int, default=0,
                        help="keep retrying while no port reaches the login node (never on ambiguity)")
    args = parser.parse_args()
    deadline = time.monotonic() + 60 * max(args.retry_minutes, 0)
    while True:
        try:
            guard = os.open(PROFILE_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
                summary = run(args.apply, args.only)
            finally:
                os.close(guard)
            print(json.dumps(summary, indent=2), flush=True)
            return 0
        except Retry as error:
            if time.monotonic() >= deadline:
                say(f"STOP: {error}; retry window over")
                return 1
            say(f"waiting: {error}; retrying in 60 s")
            sleep(60)
        except (OSError, ValueError, configparser.Error, subprocess.SubprocessError, Stop) as error:
            say(f"STOP: {error}")
            return 1


if __name__ == "__main__":
    sys.exit(main())

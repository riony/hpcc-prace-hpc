#!/usr/bin/env python3
"""Fail-closed console bootstrap for g003/g004; default is preflight only.

Run on the installed Rocky host as root, after independently identifying the
private-switch port and its permanent MAC. Preflight sends only bounded ARP
probes; it writes no files and does not raise a link. Required system tools:
ip, nmcli, ethtool, arping, restorecon, firewall-cmd. No pip dependencies.
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


NODES = {
    "g003": ("lab-g003", "EXSERIAL03", "10.88.0.4"),
    "g004": ("lab-g004", "EXSERIAL04", "10.88.0.5"),
}
PEER_IP = "10.88.0.1"
PEER_MAC = "02:00:00:00:00:01"
PROFILE_DIR = Path("/etc/NetworkManager/system-connections")
MAC_RE = re.compile(r"[0-9a-f]{2}(?::[0-9a-f]{2}){5}\Z")
UUID_RE = re.compile(r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\Z")


class Stop(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Stop(message)


def command(*argv, codes=(0,)):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=35,
                            env={**os.environ, "LC_ALL": "C"})
    require(result.returncode in codes,
            f"Command failed ({result.returncode}): {' '.join(argv)}: "
            f"{result.stderr.strip() or result.stdout.strip()}")
    return result


def read_json(*argv):
    return json.loads(command(*argv).stdout)


def keyfile(interface, address):
    # Match roles/private_net/tasks/main.yml, so Ansible adopts this profile.
    return (
        "# Managed by Ansible private_net. Do not edit by hand.\n"
        f"[connection]\nid=private-{interface}\ntype=ethernet\n"
        f"interface-name={interface}\nautoconnect=true\nzone=public\n\n"
        f"[ipv4]\nmethod=manual\naddress1={address}/24\nnever-default=true\n\n"
        "[ipv6]\nmethod=disabled\n\n[proxy]\n"
    )


def safe_keyfile(path, expected, profile_uuid=None):
    """Allow only the role's exact settings plus NM-generated UUID/timestamp."""
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
        require(actual.get("connection", "timestamp").isdigit(),
                "Invalid NetworkManager timestamp")
        actual.remove_option("connection", "timestamp")
    require({s: dict(actual[s]) for s in actual.sections()}
            == {s: dict(desired[s]) for s in desired.sections()},
            "Existing target keyfile differs from the exact safe configuration")


def profile_uuids(name):
    output = command("nmcli", "-t", "--escape", "no", "-f", "UUID,NAME",
                     "connection", "show").stdout
    result = []
    for line in output.splitlines():
        ident, sep, candidate = line.partition(":")
        if sep and candidate == name:
            require(UUID_RE.fullmatch(ident) is not None, "Invalid profile UUID")
            result.append(ident)
    return result


def active_uuids(interface):
    output = command("nmcli", "-t", "--escape", "no", "-f", "UUID,DEVICE",
                     "connection", "show", "--active").stdout
    return [line.partition(":")[0] for line in output.splitlines()
            if line.partition(":")[2] == interface]


def check_nm_settings(profile_uuid, interface, address):
    fields = ("connection.id,connection.interface-name,connection.zone,"
              "connection.autoconnect,ipv4.method,ipv4.addresses,ipv4.gateway,"
              "ipv4.dns,ipv4.never-default,ipv6.method")
    actual = command("nmcli", "-g", fields, "connection", "show", "uuid",
                     profile_uuid).stdout.splitlines()
    require(actual == [f"private-{interface}", interface, "public", "yes", "manual",
                       address + "/24", "", "", "yes", "disabled"],
            "Loaded NetworkManager settings differ from the safe profile")


def validate_routes(routes4, routes6, address=None):
    if address is None:
        require(not routes4, "Interface has existing IPv4 routes")
    else:
        allowed = {"10.88.0.0/24", "10.88.0.0", "10.88.0.255", address}
        require(any(r.get("dst") == "10.88.0.0/24" for r in routes4),
                "Expected private connected route is missing")
        require(all(r.get("dst") in allowed and not r.get("gateway")
                    and r.get("protocol") == "kernel" for r in routes4),
                "Unexpected IPv4 route on the private interface")
    # An addressless Ethernet link may have this harmless kernel bookkeeping
    # entry; any unicast/default IPv6 route remains a stop condition.
    require(all(r.get("dst") == "ff00::/8" and r.get("table") == "local"
                and r.get("protocol") == "kernel" and not r.get("gateway")
                for r in routes6), "Interface has unexpected IPv6 routes")


def runtime(interface, address=None):
    links = read_json("ip", "-j", "address", "show", "dev", interface)
    require(len(links) == 1, "Expected exactly one selected interface")
    addresses = links[0].get("addr_info", [])
    if address is None:
        require(not addresses, "Interface already has an IPv4 or IPv6 address")
    else:
        require(len(addresses) == 1 and addresses[0].get("family") == "inet"
                and addresses[0].get("local") == address
                and addresses[0].get("prefixlen") == 24,
                "Private interface addresses do not exactly match the target")
    validate_routes(read_json("ip", "-j", "-4", "route", "show", "table", "all",
                              "dev", interface),
                    read_json("ip", "-j", "-6", "route", "show", "table", "all",
                              "dev", interface), address)


def arp_probe(interface, address):
    # iputils DAD mode uses source 0.0.0.0: neither assigns nor claims an IP.
    result = command("arping", "-D", "-I", interface, "-c", "3", "-w", "4",
                     address, codes=(0, 1))
    replies = re.findall(r"reply from ([0-9.]+) \[([0-9A-Fa-f:]+)\]",
                         result.stdout, flags=re.IGNORECASE)
    count = re.search(r"Received (\d+) response", result.stdout)
    require(count is not None and int(count.group(1)) == len(replies),
            "Unrecognized/inconsistent arping output; refusing to guess")
    return result.returncode, [(ip, mac.lower()) for ip, mac in replies]


def verify_peer(interface):
    code, replies = arp_probe(interface, PEER_IP)
    require(code == 1 and replies and
            all(pair == (PEER_IP, PEER_MAC) for pair in replies),
            "Exact DL380 private peer was not proven (missing/wrong/conflicting ARP)")


def preflight(node, interface, verified_mac):
    require(os.geteuid() == 0, "Run as root on the target console")
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,14}", interface),
            "Invalid interface name")
    verified_mac = verified_mac.lower()
    require(MAC_RE.fullmatch(verified_mac) is not None
            and int(verified_mac[:2], 16) % 2 == 0
            and verified_mac != "00:00:00:00:00:00", "Invalid unicast MAC")
    hostname, serial, address = NODES[node]
    require(socket.gethostname().split(".")[0] == hostname, "Wrong host name")
    require(Path("/sys/class/dmi/id/product_serial").read_text().strip() == serial,
            "Wrong chassis serial")
    require("XL270d Gen10" in Path("/sys/class/dmi/id/product_name").read_text(),
            "Not the expected XL270d Gen10 chassis")
    for program in ("ip", "nmcli", "ethtool", "arping", "restorecon", "firewall-cmd"):
        require(shutil.which(program), f"Required system tool absent: {program}")
    nic = Path("/sys/class/net") / interface
    require((nic / "device").exists() and (nic / "type").read_text().strip() == "1",
            "Selected interface is not a physical Ethernet NIC")
    require(not (nic / "master").exists(), "Interface belongs to a bridge/bond")
    require((nic / "carrier").read_text().strip() == "1", "No carrier on selected NIC")
    link = read_json("ip", "-j", "link", "show", "dev", interface)
    require(len(link) == 1 and "UP" in link[0].get("flags", [])
            and not link[0].get("linkinfo", {}).get("info_kind"),
            "Selected physical NIC must already be up, without virtual-link type")
    permanent = command("ethtool", "-P", interface).stdout.strip().lower()
    require(permanent == f"permanent address: {verified_mac}"
            and link[0].get("address", "").lower() == verified_mac,
            "Permanent/current NIC MAC differs from the supplied verified MAC")
    directory = PROFILE_DIR.lstat()
    require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0
            and not stat.S_IMODE(directory.st_mode) & 0o022,
            "NetworkManager keyfile directory has unsafe ownership/type/mode")
    require(command("firewall-cmd", "--state").stdout.strip() == "running",
            "firewalld must be running")
    path = PROFILE_DIR / f"private-{interface}.nmconnection"
    expected = keyfile(interface, address)
    present = os.path.lexists(path)
    same_name = profile_uuids(f"private-{interface}")
    active = active_uuids(interface)
    if present:
        require(len(same_name) == 1 and active == same_name,
                "Existing target file is not the unique active intended profile")
        safe_keyfile(path, expected, active[0])
        check_nm_settings(active[0], interface, address)
        runtime(interface, address)
        require(command("firewall-cmd", f"--get-zone-of-interface={interface}")
                .stdout.strip() == "public", "Existing private zone is not public")
    else:
        require(not same_name and not active, "Conflicting existing/active NM profile")
        runtime(interface)
    # Even an address on another NIC would make DAD/activation ambiguous.
    all_links = read_json("ip", "-j", "address", "show")
    require(not any(a.get("local") == address for device in all_links
                    if device.get("ifname") != interface
                    for a in device.get("addr_info", [])),
            "Target address is already assigned to another interface")
    verify_peer(interface)
    if not present:
        code, replies = arp_probe(interface, address)
        require(code == 0 and not replies, "Target address has an ARP responder")
    return {"node": node, "hostname": hostname, "serial": serial,
            "interface": interface, "mac": verified_mac, "address": address + "/24",
            "profile": str(path), "already_configured": present}


def apply_profile(summary):
    interface = summary["interface"]
    address = summary["address"].split("/")[0]
    path = Path(summary["profile"])
    expected = keyfile(interface, address)
    created_uuid = None
    created = False
    written = False
    identity = None
    try:
        require(not active_uuids(interface) and not profile_uuids(f"private-{interface}"),
                "Profile state changed after preflight")
        runtime(interface)
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
        command("nmcli", "--wait", "20", "connection", "up", "uuid", created_uuid,
                "ifname", interface)
        require(active_uuids(interface) == [created_uuid], "Wrong active profile")
        safe_keyfile(path, expected, created_uuid)
        check_nm_settings(created_uuid, interface, address)
        runtime(interface, address)
        require(command("firewall-cmd", f"--get-zone-of-interface={interface}")
                .stdout.strip() == "public", "Private firewall zone verification failed")
        verify_peer(interface)
    except (Exception, KeyboardInterrupt) as error:
        problems = []
        if created:
            # Never use device disconnect, global NM restart or delete another
            # profile. Only deactivate the UUID loaded from our newly made file.
            try:
                if created_uuid and created_uuid in active_uuids(interface):
                    command("nmcli", "--wait", "20", "connection", "down", "uuid",
                            created_uuid)
                if os.path.lexists(path):
                    info = path.lstat()
                    if written:
                        safe_keyfile(path, expected, created_uuid)
                    else:
                        require(stat.S_ISREG(info.st_mode)
                                and (info.st_dev, info.st_ino) == identity,
                                "Partially written keyfile was replaced externally")
                    path.unlink()
                command("nmcli", "connection", "reload")
                require(not active_uuids(interface), "Another profile became active")
                runtime(interface)
            except Exception as cleanup_error:
                problems.append(str(cleanup_error))
        detail = "; rollback incomplete: " + "; ".join(problems) if problems else ""
        raise Stop(f"Apply failed: {error}{detail}") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", required=True, choices=sorted(NODES))
    parser.add_argument("--interface", required=True)
    parser.add_argument("--mac", required=True, help="Independently verified permanent MAC")
    parser.add_argument("--apply", action="store_true",
                        help="Write/activate only after every preflight check passes")
    args = parser.parse_args()
    try:
        # An advisory lock on the existing directory inode coordinates copies of
        # this helper without creating a lockfile. Other administration must stop.
        guard = os.open(PROFILE_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
            summary = preflight(args.node, args.interface, args.mac)
            if summary["already_configured"]:
                summary["result"] = "no-change: exact safe configuration already active"
            elif args.apply:
                apply_profile(summary)
                summary["result"] = "applied: only the new private profile was created"
            else:
                summary["result"] = "preflight passed: no files/configuration changed; add --apply"
            print(json.dumps(summary, indent=2))
        finally:
            os.close(guard)
    except (OSError, ValueError, configparser.Error, subprocess.SubprocessError, Stop) as error:
        print(f"STOP: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

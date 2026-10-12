#!/usr/bin/env python3
"""Offline checks for test-ks-qemu-fleet.sh and fake-login-peer.py: --describe binds every
profile's test identities without touching files, bad input is refused, every QEMU NIC is a
localhost-only dgram link (nothing can reach a real network), and the fake login node
answers ARP exactly as the first-address helper expects. Never starts QEMU."""
import importlib.util
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
HARNESS = HERE / "test-ks-qemu-fleet.sh"
SOURCE = HARNESS.read_text()
spec = importlib.util.spec_from_file_location("peer", HERE / "fake-login-peer.py")
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)
EXPECT = {
    "hpe": ("login", "lab-dl380", "EXSERIAL01", "hpe"),
    "lenovo": ("compute", "lab-lenovo", "EXSER02", "lenovo"),
    "hpe-v100-g003": ("compute", "lab-g003", "EXSERIAL03", "g003"),
    "hpe-v100-g004": ("compute", "lab-g004", "EXSERIAL04", "g004"),
    "hpe-v100-g005": ("compute", "lab-g005", "EXSERIAL05", "g005"),
}


def describe(*args, **env):
    with tempfile.TemporaryDirectory() as home:
        before = set(Path(home).rglob("*"))
        p = subprocess.run(["bash", str(HARNESS), *args, "--describe"], capture_output=True, text=True,
                           timeout=10, env={"PATH": os.environ["PATH"], "HOME": home, **env})
        created = set(Path(home).rglob("*")) - before
        values = dict(line.split("=", 1) for line in p.stdout.splitlines() if "=" in line)
        return p, values, home, created


class Harness(unittest.TestCase):
    def test_every_profile_binds_its_test_identities(self):
        for profile, (role, hostname, chassis, node) in EXPECT.items():
            with self.subTest(profile=profile):
                p, v, home, created = describe("--profile", profile, CHASSIS_EXPECT="wrong", TARGET_ID="wrong")
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(created, set(), "describe must not create files or read credentials")
                self.assertEqual((v["role"], v["hostname"], v["chassis"], v["vg"]), (role, hostname, chassis, node + "_vg"))
                self.assertEqual(v["run_root"], f"{home}/scratch/ks/qemu-{node}")
                self.assertEqual(v["credential_file"], f"{home}/.config/prace-lab/{profile}-bootstrap.pw")
                self.assertEqual(v["iso"], f"{home}/scratch/ks/Rocky-9.8-ks-{node}-qemu-test.iso")

    def test_bad_input_refused(self):
        for args in (("--profile", "g003"), ("--profile",), ("a.iso", "b.iso"), ("--bogus",)):
            with self.subTest(args=args):
                self.assertNotEqual(describe(*args)[0].returncode, 0)
        for tmo in ("0", "x", "-1", "1.5"):
            with self.subTest(tmo=tmo):
                self.assertNotEqual(describe(TMO=tmo)[0].returncode, 0)

    def test_every_nic_is_a_localhost_dgram_link(self):
        self.assertIsNone(re.search(r"-net(dev)? +\"?(user|tap|bridge|socket|stream|l2tpv3|vhost)", SOURCE))
        self.assertNotIn("mcast", SOURCE)
        self.assertNotIn("-net none", SOURCE)       # phase 1 presents the node's NICs, cabled to nowhere
        netdevs = re.findall(r'-netdev "\$\(dgram [a-z0-9]+ "\$PORT_[A-F]" "\$PORT_[A-F]"\)"', SOURCE)
        self.assertEqual(len(netdevs), 6)           # phase 1: two; phase 2: two per role
        self.assertIn("local.host=127.0.0.1", SOURCE)
        self.assertIn("remote.host=127.0.0.1", SOURCE)
        self.assertEqual(SOURCE.count('-smbios "type=1,serial=$CHASSIS_EXPECT,product=$PRODUCT"'), 1)
        self.assertEqual(SOURCE.count('"${MACHINE[@]}"'), 2)   # both phases use the same machine shape


class FakeLoginPeer(unittest.TestCase):
    NODE_MAC = bytes.fromhex("02:00:00:00:00:09".replace(":", ""))

    def arp(self, oper, sender_ip, target_ip):
        eth = b"\xff" * 6 + self.NODE_MAC + b"\x08\x06"
        return eth + struct.pack("!HHBBH", 1, 0x0800, 6, 4, oper) + self.NODE_MAC + socket.inet_aton(sender_ip) \
            + b"\x00" * 6 + socket.inet_aton(target_ip)

    def test_answers_requests_for_the_login_node_including_dad_probes(self):
        for sender in ("0.0.0.0", "10.90.10.13"):
            with self.subTest(sender=sender):
                r = peer.reply(self.arp(1, sender, "10.90.10.1"))
                self.assertEqual(r[:6], self.NODE_MAC)                     # unicast back to the asker
                self.assertEqual(r[6:12], peer.PEER_MAC)
                self.assertEqual(struct.unpack("!H", r[20:22])[0], 2)      # ARP reply
                self.assertEqual((r[22:28], r[28:32]), (peer.PEER_MAC, socket.inet_aton("10.90.10.1")))
                self.assertEqual(r[38:42], socket.inet_aton(sender))

    def test_ignores_everything_else(self):
        self.assertIsNone(peer.reply(self.arp(1, "0.0.0.0", "10.90.10.13")))   # someone else's address
        self.assertIsNone(peer.reply(self.arp(2, "10.90.10.1", "10.90.10.1")))  # a reply, not a request
        self.assertIsNone(peer.reply(b"\x00" * 60))                             # not ARP

    def test_refuses_a_non_localhost_address(self):
        p = subprocess.run(["python3", str(HERE / "fake-login-peer.py"), "--listen", "0.0.0.0:1", "--log", "/dev/null"],
                           capture_output=True, text=True, timeout=10)
        self.assertNotEqual(p.returncode, 0)
        self.assertIn("non-localhost", p.stderr)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Synthetic bootstrap safety tests. Never calls networking or host tools."""

import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import textwrap
import unittest
from types import SimpleNamespace
from unittest.mock import patch

SOURCE = Path(__file__).with_name("bootstrap-v100-private.py")
spec = importlib.util.spec_from_file_location("bootstrap", SOURCE)
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
MAC = "02:00:00:00:00:1d"
UUID = "11111111-2222-3333-4444-555555555555"


def root_lstat(path):
    fields = list(path.stat(follow_symlinks=False))
    fields[4] = 0
    return os.stat_result(fields)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.profiles = self.root / "connections"
        self.profiles.mkdir(mode=0o700)
        self.file = self.profiles / "private-eno2.nmconnection"
        self.hardware = self.root / "sys"
        files = {
            "class/dmi/id/product_serial": "EXSERIAL03",
            "class/dmi/id/product_name": "ProLiant XL270d Gen10",
            "class/net/eno2/type": "1",
            "class/net/eno2/carrier": "1",
        }
        for relative, value in files.items():
            target = self.hardware / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(value)
        (self.hardware / "class/net/eno2/device").mkdir()
        self.active = []
        self.named = []
        self.addr = []
        self.extra_nic = []
        self.routes4 = []
        self.routes6 = []
        self.link_mac = MAC
        self.permanent_mac = MAC
        self.calls = []
        self.fail_up = False
        self.peer_replies = [(b.PEER_IP, b.PEER_MAC)]
        self.dad = (0, [])
        self.start(patch.object(b, "PROFILE_DIR", self.profiles))
        self.start(patch.object(b, "Path", self.path))
        self.start(patch.object(Path, "lstat", root_lstat))
        self.start(patch.object(b.os, "geteuid", return_value=0))
        self.start(patch.object(b.socket, "gethostname", return_value="lab-g003"))
        self.start(patch.object(b.shutil, "which", return_value="/mock/tool"))
        self.start(patch.object(b, "command", side_effect=self.command))
        self.start(patch.object(b, "read_json", side_effect=self.read_json))
        self.start(patch.object(b, "arp_probe", side_effect=self.arp))
        self.start(patch.object(subprocess, "run", side_effect=AssertionError(
            "Tests must never launch real commands")))

    def start(self, patcher):
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def path(self, value):
        value = str(value)
        return self.hardware / value[5:] if value.startswith("/sys/") else Path(value)

    def command(self, *args, **kwargs):
        self.calls.append(args)
        if args == ("ethtool", "-P", "eno2"):
            output = "Permanent address: " + self.permanent_mac
        elif args == ("firewall-cmd", "--state"):
            output = "running"
        elif args == ("firewall-cmd", "--get-zone-of-interface=eno2"):
            output = "public"
        elif args[:5] == ("nmcli", "-t", "--escape", "no", "-f"):
            field = args[5]
            output = "\n".join(f"{u}:private-eno2" for u in self.named) if field == "UUID,NAME" else "\n".join(f"{u}:eno2" for u in self.active)
        elif args[:2] == ("nmcli", "-g"):
            output = "private-eno2\neno2\npublic\nyes\nmanual\n10.88.0.4/24\n\n\nyes\ndisabled\n"
        elif args == ("nmcli", "connection", "reload"):
            self.named = [UUID] if self.file.exists() else []
            output = ""
        elif args[:5] == ("nmcli", "--wait", "20", "connection", "up"):
            self.active = [UUID]
            if self.fail_up:
                raise b.Stop("synthetic activation failed")
            self.set_runtime()
            output = ""
        elif args[:5] == ("nmcli", "--wait", "20", "connection", "down"):
            self.assertEqual(args[-1], UUID)
            self.active = []
            self.addr = []
            self.routes4 = []
            output = ""
        elif args[0] == "restorecon":
            output = ""
        else:
            raise AssertionError(f"Unexpected mock command: {args}")
        return SimpleNamespace(returncode=0, stdout=output, stderr="")

    def read_json(self, *args):
        if args[:4] == ("ip", "-j", "link", "show"):
            return [{"flags": ["UP", "LOWER_UP"], "address": self.link_mac}]
        if args[:4] == ("ip", "-j", "address", "show"):
            return [{"ifname": "eno2", "addr_info": self.addr}] + (
                self.extra_nic if len(args) == 4 else [])
        if args[:3] == ("ip", "-j", "-4"):
            return self.routes4
        if args[:3] == ("ip", "-j", "-6"):
            return self.routes6
        raise AssertionError(args)

    def arp(self, interface, address):
        self.assertEqual(interface, "eno2")
        return (1, self.peer_replies) if address == b.PEER_IP else self.dad

    def set_runtime(self):
        self.addr = [{"family": "inet", "local": "10.88.0.4", "prefixlen": 24}]
        self.routes4 = [{"dst": "10.88.0.0/24", "protocol": "kernel"}]

    def preflight(self):
        return b.preflight("g003", "eno2", MAC)

    def install_expected(self):
        self.file.write_text(b.keyfile("eno2", "10.88.0.4"))
        self.file.chmod(0o600)

    def test_preflight_sends_no_mutation_commands_or_files(self):
        summary = self.preflight()
        self.assertEqual(summary["address"], "10.88.0.4/24")
        self.assertFalse(summary["already_configured"])
        self.assertEqual(list(self.profiles.iterdir()), [])
        self.assertFalse(any(c[0] == "restorecon" or "reload" in c for c in self.calls))

    def test_g004_mapping_requires_its_own_chassis(self):
        (self.hardware / "class/dmi/id/product_serial").write_text("EXSERIAL04")
        with patch.object(b.socket, "gethostname", return_value="lab-g004"):
            summary = b.preflight("g004", "eno2", MAC)
            self.assertEqual(summary["address"], "10.88.0.5/24")
            self.assertEqual(summary["serial"], "EXSERIAL04")

    def test_identity_and_link_guards(self):
        for relative, invalid in (("class/dmi/id/product_serial", "EXSERIAL05"),
                                  ("class/net/eno2/type", "32"),
                                  ("class/net/eno2/carrier", "0")):
            target = self.hardware / relative
            previous = target.read_text()
            target.write_text(invalid)
            with self.subTest(relative=relative), self.assertRaises(b.Stop):
                self.preflight()
            target.write_text(previous)
        for attribute in ("link_mac", "permanent_mac"):
            setattr(self, attribute, "02:00:00:00:00:1e")
            with self.subTest(attribute=attribute), self.assertRaises(b.Stop):
                self.preflight()
            setattr(self, attribute, MAC)

    def test_nonroot_and_wrong_hostname_stop(self):
        with patch.object(b.os, "geteuid", return_value=1000), self.assertRaises(b.Stop):
            self.preflight()
        with patch.object(b.socket, "gethostname", return_value="lab-g005"), self.assertRaises(b.Stop):
            self.preflight()

    def test_existing_address_route_and_profile_stop(self):
        for attribute, value in (
            ("addr", [{"family": "inet6", "local": "fe80::1"}]),
            ("routes4", [{"dst": "default", "gateway": "192.0.2.254"}]),
            ("active", [UUID]), ("named", [UUID]),
            ("extra_nic", [{"ifname": "eno3", "addr_info": [{"local": "10.88.0.4"}]}]),
        ):
            setattr(self, attribute, value)
            with self.subTest(attribute=attribute), self.assertRaises(b.Stop):
                self.preflight()
            setattr(self, attribute, [])
        self.assertFalse(self.file.exists())

    def test_wrong_or_conflicting_peer_and_occupied_target_stop(self):
        for peers in ([], [(b.PEER_IP, MAC)], [(b.PEER_IP, b.PEER_MAC), (b.PEER_IP, MAC)]):
            self.peer_replies = peers
            with self.subTest(peers=peers), self.assertRaises(b.Stop):
                self.preflight()
        self.peer_replies = [(b.PEER_IP, b.PEER_MAC)]
        self.dad = (1, [("10.88.0.4", MAC)])
        with self.assertRaises(b.Stop):
            self.preflight()

    def test_multicast_bookkeeping_is_only_ipv6_route_exception(self):
        b.validate_routes([], [{"dst": "ff00::/8", "table": "local", "protocol": "kernel"}])
        for route in ({"dst": "ff00::/8", "table": "main", "protocol": "kernel"},
                      {"dst": "default", "table": "local", "protocol": "kernel"}):
            with self.assertRaises(b.Stop):
                b.validate_routes([], [route])

    def test_safe_existing_profile_is_no_change(self):
        self.install_expected()
        self.named = self.active = [UUID]
        self.set_runtime()
        self.assertTrue(self.preflight()["already_configured"])
        before = self.file.read_bytes()
        with patch.object(b.sys, "argv", ["bootstrap", "--node", "g003", "--interface", "eno2", "--mac", MAC, "--apply"]), patch("builtins.print"), patch.object(b, "apply_profile") as apply:
            self.assertEqual(b.main(), 0)
            apply.assert_not_called()
        self.assertEqual(before, self.file.read_bytes())

    def test_existing_file_extra_dns_gateway_or_symlink_stops(self):
        self.install_expected()
        self.named = self.active = [UUID]
        self.set_runtime()
        for extra in ("gateway=192.0.2.254", "dns=192.0.2.53;"):
            self.file.write_text(b.keyfile("eno2", "10.88.0.4").replace("[ipv4]", "[ipv4]\n" + extra))
            with self.subTest(extra=extra), self.assertRaises(b.Stop):
                self.preflight()
        self.file.unlink()
        target = self.root / "unrelated"
        target.write_text("do not modify")
        self.file.symlink_to(target)
        with self.assertRaises(b.Stop):
            self.preflight()
        self.assertEqual(target.read_text(), "do not modify")

    def test_nm_uuid_timestamp_allowed_but_mismatch_stops(self):
        self.install_expected()
        self.file.write_text(self.file.read_text().replace("[connection]", f"[connection]\nuuid={UUID}\ntimestamp=123"))
        b.safe_keyfile(self.file, b.keyfile("eno2", "10.88.0.4"), UUID)
        with self.assertRaises(b.Stop):
            b.safe_keyfile(self.file, b.keyfile("eno2", "10.88.0.4"), "22222222-2222-3333-4444-555555555555")

    def test_successful_apply_changes_only_new_profile(self):
        unrelated = self.profiles / "other.nmconnection"
        unrelated.write_text("untouched")
        b.apply_profile(self.preflight())
        self.assertEqual(self.file.read_text(), b.keyfile("eno2", "10.88.0.4"))
        self.assertEqual(unrelated.read_text(), "untouched")
        self.assertEqual(self.active, [UUID])
        self.assertEqual(stat.S_IMODE(self.file.stat().st_mode), 0o600)

    def test_activation_failure_rolls_back_only_created_profile(self):
        summary = self.preflight()
        unrelated = self.profiles / "other.nmconnection"
        unrelated.write_text("untouched")
        self.fail_up = True
        with self.assertRaisesRegex(b.Stop, "synthetic activation failed"):
            b.apply_profile(summary)
        self.assertFalse(self.file.exists())
        self.assertEqual(self.active, [])
        self.assertEqual(unrelated.read_text(), "untouched")
        self.assertFalse(any("device" in c and "disconnect" in c for c in self.calls))

    def test_failed_write_removes_only_its_new_partial_file(self):
        summary = self.preflight()
        def fail_flush(fd):
            self.file.write_text("incomplete keyfile")
            raise OSError("synthetic disk full")
        with patch.object(b.os, "fsync", side_effect=fail_flush), self.assertRaisesRegex(b.Stop, "synthetic disk full"):
            b.apply_profile(summary)
        self.assertFalse(self.file.exists())
        self.assertFalse(any("up" in c for c in self.calls))

    def test_creation_race_does_not_overwrite_or_remove_existing_file(self):
        summary = self.preflight()
        self.file.write_text("another operator's configuration")
        with self.assertRaises(b.Stop):
            b.apply_profile(summary)
        self.assertEqual(self.file.read_text(), "another operator's configuration")

    def test_default_main_never_calls_apply(self):
        with patch.object(b.sys, "argv", ["bootstrap", "--node", "g003", "--interface", "eno2", "--mac", MAC]), patch("builtins.print"), patch.object(b, "apply_profile") as apply:
            self.assertEqual(b.main(), 0)
            apply.assert_not_called()

    def test_role_keyfile_contract(self):
        role = SOURCE.parent.parent / "roles/private_net/tasks/main.yml"
        if not role.exists():
            self.skipTest("Run from infra/tools to check role contract")
        block = role.read_text().split("    content: |\n", 1)[1].split("  notify:", 1)[0]
        body = textwrap.dedent(block)
        for old, new in (("{{ pn_conn }}", "private-eno2"), ("{{ private_iface }}", "eno2"),
                         ("{{ private_zone | default('public') }}", "public"),
                         ("{{ private_ip }}", "10.88.0.4"), ("{{ private_prefix }}", "24")):
            body = body.replace(old, new)
        self.assertEqual(b.keyfile("eno2", "10.88.0.4"), body)


class ArpParserTests(unittest.TestCase):
    def test_real_parser_rejects_errors_and_ambiguous_output(self):
        with patch.object(b, "command", return_value=SimpleNamespace(returncode=1, stdout=f"Unicast reply from 10.88.0.1 [{b.PEER_MAC.upper()}] 0.8ms\nReceived 1 response(s)\n")):
            b.verify_peer("eno2")
        for output in ("", "Received 1 response(s)", "Received 0 response(s)\nUnicast reply from 10.88.0.1 [02:00:00:00:00:01]"):
            with self.subTest(output=output), patch.object(b, "command", return_value=SimpleNamespace(returncode=0, stdout=output)), self.assertRaises(b.Stop):
                b.arp_probe("eno2", b.PEER_IP)


if __name__ == "__main__":
    unittest.main(verbosity=2)

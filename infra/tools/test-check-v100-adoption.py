#!/usr/bin/env python3
"""Offline negative/positive fixtures for the post-install guard."""
import importlib.util
from pathlib import Path
import sys
import unittest
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('gate', Path(__file__).with_name('check-v100-adoption.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

class GuardTests(unittest.TestCase):
    def identity(self, **overrides):
        fields = dict(node='g003', serial='EXSERIAL03', hostname='lab-g003',
                      release={'ID':'rocky', 'VERSION_ID':'9.8'}, wwn='600508b1' + '12345678' * 3)
        fields.update(overrides)
        gate.validate_identity(**fields)

    def network(self, **overrides):
        fields = dict(node='g003', iface='eno2', mac='aa:bb:cc:dd:ee:02',
                      permanent='aa:bb:cc:dd:ee:02', current='aa:bb:cc:dd:ee:02',
                      addresses=[{'ifname':'eno2', 'addr_info':[{'scope':'global',
                                  'family':'inet', 'local':'10.88.0.4','prefixlen':24}]}],
                      routes4=[{'dst':'10.88.0.0/24'}], routes6=[])
        fields.update(overrides)
        gate.validate_network(**fields)

    def test_identity_success(self):
        self.identity()
        self.identity(node='g004', serial='EXSERIAL04', hostname='lab-g004')

    def test_wrong_chassis(self):
        with self.assertRaises(RuntimeError): self.identity(serial='EXSERIAL05')

    def test_wrong_hostname_or_os(self):
        for fields in [dict(hostname='lab-g004'), dict(release={'ID':'rocky','VERSION_ID':'8.10'})]:
            with self.subTest(fields=fields), self.assertRaises(RuntimeError): self.identity(**fields)

    def test_foreign_placeholder_and_injected_wwn(self):
        for value in list(gate.FOREIGN)+['0'*32, 'f'*16, '123; rm -rf /', 'bad']:
            with self.subTest(value=value), self.assertRaises(RuntimeError): self.identity(wwn=value)

    def test_network_success(self): self.network()

    def test_wrong_mac(self):
        with self.assertRaises(RuntimeError): self.network(permanent='aa:bb:cc:dd:ee:03')

    def test_any_default_route(self):
        for fields in [dict(routes4=[{'dst':'default'}]), dict(routes6=[{'dst':'default'}])]:
            with self.subTest(fields=fields), self.assertRaises(RuntimeError): self.network(**fields)

    def test_wrong_ip_prefix_extra_address(self):
        for address in [dict(local='10.88.0.5',prefixlen=24),dict(local='10.88.0.4',prefixlen=16)]:
            address.update(scope='global',family='inet')
            with self.assertRaises(RuntimeError): self.network(addresses=[{'ifname':'eno2','addr_info':[address]}])
        with self.assertRaises(RuntimeError): self.network(addresses=[])
        with self.assertRaises(RuntimeError):
            self.network(addresses=[{'ifname':'eno2','addr_info':[
                {'scope':'global','family':'inet','local':'10.88.0.4','prefixlen':24},
                {'scope':'global','family':'inet','local':'192.0.2.206','prefixlen':24}]}])

if __name__ == '__main__': unittest.main()

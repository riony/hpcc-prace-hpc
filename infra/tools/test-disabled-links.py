#!/usr/bin/env python3
"""D43 behavior and monitor regressions. Fake host data/commands, never fleet contact."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch, mock_open

INFRA = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location('disabled_links', INFRA / 'roles/fleet_net/files/prace-disabled-links.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
sys.path.insert(0, str(INFRA / 'tools'))
import fleet_audit


class Host(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.p = {'schema': 1, 'host': os.uname().nodename.split('.')[0],
                  'protected': {'admin0': '10.90.10.1/25'}, 'interfaces': [
                      {'name': 'fibre0', 'mac': 'aa:bb:cc:dd:ee:00', 'pci': '0000:88:00.0'},
                      {'name': 'fibre1', 'mac': 'aa:bb:cc:dd:ee:01', 'pci': '0000:88:00.1'}]}
        self.sys = self.root / 'sys'; self.sys.mkdir()
        self.policy = self.root / 'policy.json'
        self.policy.write_text(json.dumps(self.p)); self.policy.chmod(0o600)
        for row in self.p['interfaces']:
            d = self.sys / row['name']; d.mkdir()
            pci = self.root / row['pci']; pci.mkdir()
            (d / 'device').symlink_to(pci)
            (d / 'address').write_text(row['mac']); (d / 'type').write_text('1')
        self.links = [{'ifname': r['name'], 'flags': ['UP', 'LOWER_UP'], 'operstate': 'UP', 'addr_info': []}
                      for r in self.p['interfaces']]
        self.links += [{'ifname': 'admin0', 'flags': ['UP', 'LOWER_UP'], 'operstate': 'UP',
                        'addr_info': [{'family': 'inet', 'local': '10.90.10.1', 'prefixlen': 25}]}]
        self.managed = False
        self.routes = [{'dst': '10.90.10.0/25', 'dev': 'admin0'}]
        self.nmconf = '[keyfile]\nunmanaged-devices=interface-name:legacy0\n'
        self.calls = []
        for attr, value in [('SYS', self.sys), ('POLICY', self.policy), ('OWNER', os.getuid()), ('command', self.cmd)]:
            p = patch.object(m, attr, value); p.start(); self.addCleanup(p.stop)

    def cmd(self, args):
        self.calls.append(args)
        if args == ['ip', '-j', 'address', 'show']: return json.dumps(self.links)
        if args == ['ip', '-j', 'route', 'show', 'table', 'all']: return json.dumps(self.routes)
        if args[:2] == ['nmcli', '-g']: return '100 (connected)' if self.managed else '10 (unmanaged)'
        if args == ['NetworkManager', '--print-config']: return self.nmconf
        if args[:4] == ['ip', 'link', 'set', 'dev']:
            self.assertEqual(args[5], 'down')
            self.assertIn(args[4], ['fibre0', 'fibre1'])
            row = next(r for r in self.links if r['ifname'] == args[4])
            row.update(flags=[], operstate='DOWN')
            self.routes = [r for r in self.routes if r.get('dev') != args[4]]
            return ''
        raise AssertionError('Unexpected command: ' + repr(args))

    def mutations(self):
        return [c for c in self.calls if c[:2] == ['ip', 'link']]

    def test_exact_ports_only_then_idempotent_repeat(self):
        before = copy.deepcopy(self.links[-1])
        self.assertTrue(m.hold_down(self.p)['changed'])
        self.assertEqual([c[4] for c in self.mutations()], ['fibre0', 'fibre1'])
        self.assertEqual(self.links[-1], before)
        self.calls.clear()
        self.assertFalse(m.hold_down(self.p)['changed'])
        self.assertFalse(self.mutations())

    def test_all_targets_validate_before_first_down(self):
        (self.sys / 'fibre1' / 'address').write_text('11:11:11:11:11:11')
        with self.assertRaisesRegex(m.Refused, 'mac_changed'): m.hold_down(self.p)
        self.assertFalse(self.mutations())

    def test_pci_drift_and_missing_port_refuse(self):
        for missing in (False, True):
            p = copy.deepcopy(self.p)
            p['interfaces'][1].update({'name': 'missing0'} if missing else {'pci': '0000:99:00.0'})
            with self.assertRaises(m.Refused): m.hold_down(p)
            self.assertFalse(self.mutations())

    def test_protected_port_cannot_be_target(self):
        p = copy.deepcopy(self.p); p['interfaces'][0]['name'] = 'admin0'
        with self.assertRaisesRegex(m.Refused, 'protected_target'): m.hold_down(p)
        self.assertFalse(self.mutations())

    def test_duplicate_or_shell_name_refuses_before_command(self):
        for name in ('fibre1', 'x;echo', '../../eno1'):
            p = copy.deepcopy(self.p); p['interfaces'][0]['name'] = name
            with self.assertRaises(m.Refused): m.hold_down(p)
        self.assertFalse(self.calls)

    def test_address_route_or_master_refuses_without_mutation(self):
        self.links[0]['addr_info'] = [{'family': 'inet6', 'local': 'fe80::1'}]
        with self.assertRaisesRegex(m.Refused, 'target_has_address'): m.hold_down(self.p)
        self.links[0]['addr_info'] = []
        self.routes.append({'nexthops': [{'dev': 'fibre1'}]})
        with self.assertRaisesRegex(m.Refused, 'target_has_route'): m.hold_down(self.p)
        self.routes.pop()
        (self.sys / 'fibre0' / 'master').symlink_to(self.sys)
        with self.assertRaisesRegex(m.Refused, 'target_in_use'): m.hold_down(self.p)
        self.assertFalse(self.mutations())

    def test_non_ethernet_refuses(self):
        (self.sys / 'fibre0' / 'type').write_text('32')
        with self.assertRaisesRegex(m.Refused, 'not_ethernet'): m.hold_down(self.p)
        self.assertFalse(self.mutations())

    def test_only_automatic_address_free_kernel_multicast_can_disappear(self):
        automatic = {'type': 'multicast', 'dst': 'ff00::/8', 'dev': 'fibre0',
                     'table': 'local', 'protocol': 'kernel', 'metric': 256, 'flags': [], 'pref': 'medium'}
        self.routes.append(automatic)
        self.assertEqual(m.preflight(self.p)['kernel_multicast_routes'], [automatic])
        self.assertTrue(m.hold_down(self.p)['changed'])
        self.assertEqual(m.preflight(self.p)['kernel_multicast_routes'], [])

    def test_static_unicast_default_gateway_or_multipath_route_refuses(self):
        automatic = {'type': 'multicast', 'dst': 'ff00::/8', 'dev': 'fibre0',
                     'table': 'local', 'protocol': 'kernel'}
        for change in ({'type': 'unicast'}, {'dst': 'default'}, {'protocol': 'static'},
                       {'table': 'main'}, {'gateway': 'fe80::1'}, {'via': 'fe80::1'},
                       {'prefsrc': 'fe80::1'}, {'src': 'fe80::1'},
                       {'nexthops': [{'dev': 'fibre1'}]}):
            self.routes = [dict(automatic, **change)]
            with self.assertRaisesRegex(m.Refused, 'target_has_route'): m.hold_down(self.p)
            self.assertFalse(self.mutations())

    def test_retained_kernel_multicast_after_down_is_not_pass(self):
        automatic = {'type': 'multicast', 'dst': 'ff00::/8', 'dev': 'fibre0',
                     'table': 'local', 'protocol': 'kernel'}
        self.routes.append(automatic)
        original = self.cmd
        def retained_route(c):
            result = original(c)
            if c[:2] == ['ip', 'link'] and not any(r.get('dev') == 'fibre0' for r in self.routes):
                self.routes.append(automatic)
            return result
        with patch.object(m, 'command', side_effect=retained_route):
            with self.assertRaisesRegex(m.Refused, 'kernel_multicast_route_remains'): m.hold_down(self.p)

    def test_managed_or_unreadable_state_refuses(self):
        self.managed = True
        with self.assertRaisesRegex(m.Refused, 'still_managed'): m.hold_down(self.p)
        with patch.object(m, 'command', side_effect=subprocess.TimeoutExpired(['ip'], 10)):
            with self.assertRaises(subprocess.TimeoutExpired): m.hold_down(self.p)
        self.assertFalse(self.mutations())

    def test_runtime_protected_address_failure_and_boot_before_address(self):
        self.links[-1]['addr_info'] = []
        with self.assertRaisesRegex(m.Refused, 'protected_address_changed'): m.hold_down(self.p)
        self.assertFalse(self.mutations())
        self.assertTrue(m.hold_down(self.p, boot=True)['changed'])

    def test_unmanaged_selectors_preserved_and_complex_selectors_refuse(self):
        self.assertEqual(m.preflight(self.p)['unmanaged'], ['interface-name:fibre0', 'interface-name:fibre1', 'interface-name:legacy0'])
        for selector in ('except:interface-name:fibre0', '*', 'interface-name:admin0'):
            self.nmconf = '[keyfile]\nunmanaged-devices=' + selector
            with self.assertRaises(m.Refused): m.hold_down(self.p)
        self.assertFalse(self.mutations())

    def test_policy_symlink_is_not_followed(self):
        other = self.root / 'other'; self.policy.rename(other); self.policy.symlink_to(other)
        with self.assertRaisesRegex(m.Refused, 'unsafe_policy'): m.load_policy()

    def test_observation_never_changes_up_links(self):
        value = m.snapshot()
        self.assertFalse(value['disabled']); self.assertFalse(value['errors'])
        self.assertFalse(self.mutations())

    def test_observation_unknown_is_not_disabled(self):
        with patch.object(m, 'command', side_effect=OSError('injected')):
            value = m.snapshot()
        self.assertFalse(value['disabled']); self.assertTrue(value['errors'])

    def test_partial_link_observation_is_not_pass(self):
        for field in ('flags', 'addr_info', 'operstate'):
            old = self.links[0].pop(field)
            self.assertTrue(m.snapshot()['errors'])
            with self.assertRaisesRegex(m.Refused, 'incomplete_link_observation'): m.hold_down(self.p)
            self.links[0][field] = old
        self.assertFalse(self.mutations())

    def test_disable_not_observed_fails(self):
        old = self.cmd
        with patch.object(m, 'command', side_effect=lambda c: '' if c[:2] == ['ip', 'link'] else old(c)):
            with self.assertRaisesRegex(m.Refused, 'not_confirmed'): m.hold_down(self.p)


class Audit(unittest.TestCase):
    def setUp(self):
        self.now = time.time()
        self.target = {'name': 'fibre0', 'mac': 'aa:bb:cc:dd:ee:00', 'pci': '0000:88:00.0'}
        self.expected = {'login': 'host', 'workers': {}, 'disabled_links': {'host': [self.target]}}
        row = dict(mac=self.target['mac'], pci=self.target['pci'], admin_up=False, carrier=False,
                   nm_managed=False, operstate='DOWN', addresses=[])
        self.s = {'schema': 1, 'time': self.now, 'lease': {'held': False}, 'errors': [],
                  'k8s_api': True, 'controller_up': True, 'accounting': True, 'nodes': {'host': {'k8s_ready': True}},
                  'disabled_links': {'host': {'schema': 1, 'host': 'host', 'time': self.now,
                                              'interfaces': {'fibre0': row}, 'errors': []}}}

    def ev(self):
        return fleet_audit.evaluate(self.s, self.expected, health_only=True, now=self.now)[0]

    def test_down_is_healthy_but_each_reenable_signal_alerts(self):
        self.assertEqual(self.ev(), 'HEALTHY')
        for field, value in (('admin_up', True), ('carrier', True), ('nm_managed', True),
                             ('operstate', 'UNKNOWN'), ('addresses', [{'local': '1.2.3.4'}])):
            row = self.s['disabled_links']['host']['interfaces']['fibre0']
            old = row[field]; row[field] = value
            self.assertEqual(self.ev(), 'UNHEALTHY'); row[field] = old

    def test_wrong_identity_unknown_or_stale_is_error(self):
        report = copy.deepcopy(self.s['disabled_links']['host'])
        for change in ({'time': self.now - 1000}, {'host': 'other'}, {'errors': ['timeout']},
                       {'interfaces': {}}, {'interfaces': []}, {'schema': True}):
            self.s['disabled_links']['host'] = dict(report, **change)
            self.assertEqual(self.ev(), 'UNREACHABLE_OR_ERROR')
        self.s['disabled_links']['host'] = dict(report)
        self.s['disabled_links']['host']['interfaces']['fibre0']['pci'] = '0000:99:00.0'
        self.assertEqual(self.ev(), 'UNREACHABLE_OR_ERROR')


    def test_maintenance_does_not_hide_reenable(self):
        self.s['lease'] = {'held': True, 'holder': 'holder=maint label=x id=0123456789abcdef since=' + time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(self.now))}
        self.assertEqual(self.ev(), 'DEFERRED_MAINTENANCE')
        self.s['disabled_links']['host']['interfaces']['fibre0']['admin_up'] = True
        self.assertEqual(self.ev(), 'UNHEALTHY')

    def test_missing_or_partial_boolean_is_not_pass(self):
        del self.s['disabled_links']['host']['interfaces']['fibre0']['carrier']
        self.assertEqual(self.ev(), 'UNREACHABLE_OR_ERROR')

    def test_bad_mapping_or_nonfinite_time_is_not_pass(self):
        report = copy.deepcopy(self.s['disabled_links'])
        for value in (None, [], True):
            self.s['disabled_links'] = value
            self.assertEqual(self.ev(), 'UNREACHABLE_OR_ERROR')
        self.s['disabled_links'] = report
        for value in (float('nan'), float('inf'), -float('inf')):
            report['host']['time'] = value
            self.assertEqual(self.ev(), 'UNREACHABLE_OR_ERROR')


class Observer(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('observer_d43', INFRA / 'roles/fleet_observer/files/prace-fleet-observe.py')
        self.o = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.o)
        self.cfg = json.dumps({'host': {'address': '10.90.10.13'}})

    def observe(self, body=None, failed=False):
        def transport(argv, capture_output, timeout):
            self.assertTrue(capture_output)
            self.assertEqual(argv[-1], 'http://10.90.10.13:9187/v1/disabled-links')
            self.assertEqual(timeout, 6)
            self.assertIn('ProxyHandler({})', argv[2])
            self.assertIn('NoRedirect', argv[2])
            self.assertIn('read(65537)', argv[2])
            if failed: raise subprocess.TimeoutExpired(argv, timeout)
            return subprocess.CompletedProcess(argv, 0, stdout=body, stderr=b'')
        with patch.object(self.o.os.path, 'exists', return_value=True), \
                patch('builtins.open', mock_open(read_data=self.cfg)), \
                patch.object(self.o.subprocess, 'run', side_effect=transport):
            return self.o.disabled_link_observations()

    def test_correct_identity_is_reported(self):
        value = {'schema': 1, 'host': 'host', 'time': 1, 'interfaces': {}, 'errors': []}
        self.assertEqual(self.observe(json.dumps(value).encode()), {'host': value})

    def test_wrong_identity_bad_json_type_oversize_and_transport_are_errors(self):
        for raw in (b'[]', b'not json', b'{"schema":1,"host":"other"}', b'x' * 65537):
            self.assertTrue(self.observe(raw)['host']['errors'])
        self.assertTrue(self.observe(failed=True)['host']['errors'])

    def test_config_malformed_is_reported(self):
        self.cfg = '[]'
        self.assertTrue(self.observe()['configuration']['errors'])

    def test_non_ip_endpoint_never_starts_a_probe(self):
        self.cfg = json.dumps({'host': {'address': '10.90.10.13/path?outside'}})
        self.assertTrue(self.observe()['host']['errors'])

if __name__ == '__main__': unittest.main()

#!/usr/bin/env python3
"""Integration gates for the isolated peer-map playbook; fake SSH only."""
import importlib.util
import copy
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

import yaml

INFRA = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('fleet_gate', INFRA / 'tools/test-fleet-gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
PLAYS = yaml.safe_load((INFRA / 'playbooks/ib-peer-map.yml').read_text())


def run_playbook(*args, **kwargs):
    # Keep controller state in scratch too; a blocked ~/.ansible/cp must not
    # make a missing gate look like a successful zero-contact refusal.
    with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {
        'ANSIBLE_SSH_CONTROL_PATH_DIR': d,
        'ANSIBLE_LOCAL_TEMP': str(Path(d) / 'local'),
        'ANSIBLE_REMOTE_TEMP': str(Path(d) / 'remote'),
    }):
        return gate.run_playbook(*args, **kwargs)


class PeerRollout(unittest.TestCase):
    def test_disarmed_or_filtered_operation_never_contacts_a_host(self):
        for extra in ([], ['--check'], ['--limit', 'gpu'], ['--skip-tags', 'always'],
                      ['--start-at-task', 'Read chassis identity before preparation']):
            with self.subTest(extra=extra):
                reply, calls = run_playbook(*extra, playbook='playbooks/ib-peer-map.yml')
                self.assertEqual(calls, 0, reply.stdout + reply.stderr)

    def test_filters_cannot_skip_the_gate_even_with_complete_inputs(self):
        variables = {'fleet_armed': True, 'fleet_lease_id': 'a' * 16,
                     'ib_peer_revision': 'b' * 40, 'ib_peer_output': '/tmp/new-peer-map'}
        for extra in (['--limit', 'gpu'], ['--skip-tags', 'always'],
                      ['--start-at-task', 'Read chassis identity before preparation']):
            with self.subTest(extra=extra):
                reply, calls = run_playbook('-e', json.dumps(variables), *extra,
                                                 playbook='playbooks/ib-peer-map.yml')
                self.assertEqual(calls, 0, reply.stdout + reply.stderr)

    def test_missing_or_malformed_live_inputs_refuse_before_ssh(self):
        for variables in ({'fleet_armed': True},
                          {'fleet_armed': True, 'fleet_lease_id': 'bad'},
                          {'fleet_armed': True, 'fleet_lease_id': 'a' * 16,
                           'ib_peer_revision': 'b' * 40, 'ib_peer_output': '/tmp/new-peer-map',
                           'ib_peer_install': 'true'}):
            import json
            with self.subTest(variables=variables):
                reply, calls = run_playbook('-e', json.dumps(variables), playbook='playbooks/ib-peer-map.yml')
                self.assertEqual(calls, 0, reply.stdout + reply.stderr)
                self.assertNotEqual(reply.returncode, 0)

    def test_gate_failure_cannot_fall_through_to_gpu_play(self):
        # A plausible pin and path pass input validation; actual source mismatch
        # then refuses locally. Later plays must not contact even one host.
        import json
        variables = {'fleet_armed': True, 'fleet_lease_id': 'a' * 16,
                     'ib_peer_revision': 'b' * 40, 'ib_peer_output': '/tmp/new-peer-map'}
        reply, calls = run_playbook('-e', json.dumps(variables), playbook='playbooks/ib-peer-map.yml')
        self.assertEqual(calls, 0, reply.stdout + reply.stderr)
        self.assertNotEqual(reply.returncode, 0)
        self.assertIn('source pin differs', reply.stdout + reply.stderr)

    def test_collection_is_separate_and_failure_is_preserved_before_stop(self):
        tasks = PLAYS[1]['tasks']
        names = [task['name'] for task in tasks]
        query = next(t for t in tasks if 'Require all three maps' in t['name'])
        self.assertIs(query['failed_when'], False)
        self.assertLess(names.index('Preserve the peer-check result'),
                        names.index('Failed or incomplete mapping stops after its evidence is saved'))
        self.assertIn("hostvars['localhost'].ib_peer_gate_ok", PLAYS[1]['hosts'])
        self.assertNotIn('ib-peer-map.yml', (INFRA / 'playbooks/fleet.yml').read_text())

    def test_install_uses_exact_local_rpms_without_online_resolution(self):
        block = next(t['block'] for t in PLAYS[1]['tasks'] if 'Optional exact diagnostics' in t['name'])
        install = next(t['ansible.builtin.dnf'] for t in block if 'ansible.builtin.dnf' in t)
        self.assertEqual(install['name'], '{{ ib_peer_rpm_files }}')
        self.assertEqual(install['disablerepo'], '*')
        self.assertIs(install['disable_gpg_check'], False)
        fetch = next(t['ansible.builtin.get_url'] for t in block if 'ansible.builtin.get_url' in t)
        self.assertEqual(fetch['checksum'], 'sha256:{{ item.sha256 }}')
        self.assertFalse(fetch['use_proxy'])

    def test_real_local_collection_preserves_success_and_failed_peer_evidence(self):
        # Real Ansible delegates/copies/checker, with host observations replaced
        # by the existing fake sysfs/smpquery fixture. No disk/package/SSH tool runs.
        spec = importlib.util.spec_from_file_location('peer_fixture', INFRA / 'tools/test-ib-peer-check.py')
        fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fixture)
        for failed in (False, True):
            fx = fixture.Fixture(fixture.ring(), fail=[fixture.HV['lab-g004'][1]['guid']] if failed else [])
            try:
                with tempfile.TemporaryDirectory() as d:
                    root = Path(d)
                    output = root / 'output'
                    play = copy.deepcopy(PLAYS[1])
                    play['become'] = False
                    play['hosts'] = 'gpu'
                    inventory = {'all': {'children': {'gpu': {'hosts': {}}}}}
                    for host in fixture.HV:
                        variables = yaml.safe_load((INFRA / f'inventories/fleet/host_vars/{host}.yml').read_text())
                        variables.update(ansible_connection='local', ansible_python_interpreter=sys.executable)
                        inventory['all']['children']['gpu']['hosts'][host] = variables
                    for task in play['tasks']:
                        if 'ansible.builtin.include_vars' in task:
                            task['ansible.builtin.include_vars']['file'] = str(INFRA / 'roles/fleet_repo/defaults/main.yml')
                        elif task['name'] == 'Read chassis identity before preparation':
                            task['ansible.builtin.command']['argv'] = ['/bin/echo', '{{ chassis_serial }}']
                        elif task['name'].startswith('Require the exact diagnostics versions'):
                            task['ansible.builtin.command']['argv'] = ['/usr/bin/printf', '%s\n',
                                                                    '{{ ib_peer_packages[0].nevra }}',
                                                                    '{{ ib_peer_packages[1].nevra }}']
                        elif 'ansible.builtin.script' in task:
                            del task['ansible.builtin.script']
                            task['ansible.builtin.command'] = {'argv': ['/bin/cat', str(fx.d) + '/{{ inventory_hostname }}.txt']}
                        elif task['name'].startswith('Require all three maps'):
                            task['ansible.builtin.command']['argv'][1] = str(INFRA / 'tools/ib-peer-check.py')
                    (root / 'inventory.yml').write_text(yaml.safe_dump(inventory))
                    (root / 'play.yml').write_text(yaml.safe_dump([play]))
                    reply, calls = run_playbook('-e', json.dumps({'ib_peer_revision': 'b' * 40,
                                                       'ib_peer_output': str(output)}),
                                                     playbook=str(root / 'play.yml'), inventory=str(root / 'inventory.yml'))
                    self.assertEqual(calls, 0)
                    self.assertEqual(reply.returncode == 0, not failed, reply.stdout + reply.stderr)
                    record = json.loads((output / 'peer-check.json').read_text())
                    self.assertEqual(record['rc'], int(failed))
                    self.assertEqual(output.stat().st_mode & 0o777, 0o700)
                    for source in fx.maps:
                        saved = output / source.name
                        self.assertEqual(saved.read_bytes(), source.read_bytes())
                        self.assertEqual(saved.stat().st_mode & 0o777, 0o600)
            finally:
                shutil.rmtree(fx.d)


if __name__ == '__main__':
    unittest.main()

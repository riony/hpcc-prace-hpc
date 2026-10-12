#!/usr/bin/env python3
"""Owned-window guard tests. Pure fake window API; no SSH or fleet access."""
import contextlib
import importlib.util
import unittest
import json
import re
import os
import subprocess
import sys
from pathlib import Path
S = importlib.util.spec_from_file_location('guard', Path(__file__).with_name('require-closed-window.py'))
m = importlib.util.module_from_spec(S); S.loader.exec_module(m)
ID = 'a' * 16
INTENT = {'lease_id': ID, 'phase': 'closed', 'fence_active': True}

class Window:
    def __init__(self, failure=None): self.failure = failure; self.calls = []
    def local_lock(self): return contextlib.nullcontext()
    def operation_lock(self, lid): return contextlib.nullcontext()
    def hit(self, name):
        self.calls.append(name)
        if self.failure == name: raise ValueError(name)
    def require_lease(self, lid): self.hit('lease')
    def load(self, lid): return {'phase': 'closed'}
    def projection(self, rec): return INTENT
    def marker_matches(self, rec): self.hit('intent')
    def verify_closed(self, rec, require_quiet=False):
        assert require_quiet
        self.hit('fence')
        return {}, {}
    def overlay_closed(self, rec, parts, allow_absent):
        assert not allow_absent
        self.hit('overlay')

class Guard(unittest.TestCase):
    def test_missing_wrong_and_opening_intent_refuse_before_contact(self):
        for p in ({}, {'lease_id': ID, 'intent': dict(INTENT, lease_id='b'*16)},
                  {'lease_id': ID, 'intent': dict(INTENT, phase='opening')},
                  {'lease_id': ID, 'intent': dict(INTENT, fence_active=False)}):
            w = Window()
            with self.assertRaises(ValueError): m.verify(w, p)
            self.assertEqual(w.calls, [])
    def test_unowned_unverified_and_missing_overlay_refuse(self):
        for failure in ('lease', 'intent', 'fence', 'overlay'):
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                m.verify(Window(failure), {'lease_id': ID, 'intent': INTENT})
    def test_owned_closed_verified_window_passes(self):
        w = Window(); m.verify(w, {'lease_id': ID, 'intent': INTENT})
        self.assertEqual(w.calls, ['lease','intent','fence','overlay'])

class RealWindowContract(unittest.TestCase):
    def test_real_window_tool_against_fake_transport(self):
        spec = importlib.util.spec_from_file_location('window_tests', Path(__file__).with_name('test-slurm-window.py'))
        fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)
        w = fixture.Window(); w.setUp(); self.addCleanup(w.doCleanups)
        lid = w.take()
        self.assertEqual(w.run_tool('close', '--lease-id', lid)[0], 0)
        w.apply_overlay(lid, 'closed')
        rc, out = w.run_tool('intent', '--lease-id', lid)
        self.assertEqual(rc, 0, out)
        intent = json.loads(out)['slurm_window_intent']
        env = dict(os.environ, PRACE_WINDOW_SSH=f'{sys.executable} {w.d / "fake-login"}',
                   PRACE_LOGIN='login.prace-test.invalid', PRACE_WINDOW_DIR=str(w.d/'records'),
                   PRACE_WINDOW_WAIT='0', STATE=str(w.state), CALLS=str(w.d/'calls'),
                   PATH=str(w.d/'bin')+os.pathsep+os.environ['PATH'])
        def check():
            return subprocess.run([sys.executable, str(Path(__file__).with_name('require-closed-window.py'))],
                   input=json.dumps({'lease_id': lid, 'intent': intent}), env=env, text=True, capture_output=True, timeout=60)
        before = (w.d/'records'/f'{lid}.json').read_bytes()
        r=check(); self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual((w.d/'records'/f'{lid}.json').read_bytes(), before)
        w.put(overlay=None)
        self.assertNotEqual(check().returncode,0)
        w.apply_overlay(lid,'closed'); w.put(parts={'cpu':'UP','gpu':'INACTIVE'})
        self.assertNotEqual(check().returncode,0)
        w.put(parts={'cpu':'INACTIVE','gpu':'INACTIVE'}, jobs=['queued-job'])
        self.assertNotEqual(check().returncode,0)
        w.put(jobs=[],lease=None)
        self.assertNotEqual(check().returncode,0)


class OncePerPlay(unittest.TestCase):
    """4 Oct (Session B's re-review): the check takes slurm-window.py's workstation lock without
    waiting, so run once per node it collided with itself at a first installation (five nodes in
    parallel; all but one stopped with "another local window operation is running"). The role's own
    guard task runs here through ansible-playbook on five local hosts, only its checker replaced by
    a stub that records each run."""

    def play(self, needs, stub_rc=0):
        import tempfile, yaml
        role = Path(__file__).resolve().parents[1] / 'roles/slinky/tasks/nri-mount-guard.yml'
        if not role.exists():                 # this file is shared with MR !84, which lacks the NRI guard
            self.skipTest('the NRI guard (MR !82) is not in this tree')
        guard = next(t for t in yaml.safe_load(role.read_text())
                     if t.get('name', '').startswith('A runtime service mutation requires the owned closed window'))
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            stub = d / 'check'; stub.write_text(f'#!/bin/sh\necho run >> {d}/runs\nexit {stub_rc}\n'); stub.chmod(0o755)
            task = dict(guard)                        # its run_once, when and delegation, as the role has them
            task['ansible.builtin.command'] = {'argv': [str(stub)]}
            task.pop('environment', None)
            hosts = ['n1', 'n2', 'n3', 'n4', 'n5']
            (d / 'inv').write_text('[login]\nn1\n[compute]\nn2\nn3\nn4\nn5\n[all:vars]\nansible_connection=local\n')
            cfg = d / 'ansible.cfg'; cfg.write_text('[defaults]\n')        # no repository settings
            hv = d / 'host_vars'; hv.mkdir()
            for h in hosts:
                (hv / f'{h}.yml').write_text(f'slinky_nri_mutation: "{h in needs}"\n')
            (d / 'p.yml').write_text(yaml.safe_dump([{'hosts': 'all', 'gather_facts': False, 'tasks': [
                task, {'name': 'mutation', 'ansible.builtin.debug': {'msg': 'mutating {{ inventory_hostname }}'}}]}]))
            r = subprocess.run(['ansible-playbook', '-i', str(d / 'inv'), str(d / 'p.yml')], capture_output=True, text=True,
                               timeout=300, env=dict(os.environ, ANSIBLE_CONFIG=str(cfg)))
            runs = (d / 'runs').read_text().count('run') if (d / 'runs').exists() else 0
            mutated = sorted(set(re.findall(r'"msg": "mutating (n\d)"', r.stdout)))
            return runs, mutated, r

    def test_one_check_for_every_node_that_needs_a_mutation(self):
        runs, mutated, r = self.play(needs={'n2', 'n4'})
        self.assertEqual(runs, 1, r.stdout[-2000:])
        self.assertEqual(mutated, ['n1', 'n2', 'n3', 'n4', 'n5'])

    def test_no_check_when_nothing_changes(self):
        runs, mutated, r = self.play(needs=set())
        self.assertEqual(runs, 0)
        self.assertEqual(len(mutated), 5)

    def test_a_failed_check_stops_every_node_before_any_mutation(self):
        runs, mutated, r = self.play(needs={'n3'}, stub_rc=1)
        self.assertEqual(runs, 1)
        self.assertEqual(mutated, [], r.stdout[-2000:])

if __name__ == '__main__': unittest.main()

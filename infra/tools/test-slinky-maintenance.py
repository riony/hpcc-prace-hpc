#!/usr/bin/env python3
"""Hermetic maintenance overlay validation: no fleet, credentials, SSH or containers.

HelmGuard simulates K3s's Helm controller and the release Secrets: a write replaces the job, the
release is pending while it runs, then deployed (or failed, or reinstalled with new UIDs)."""
import base64
import copy
import gzip
import io
from contextlib import redirect_stderr
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

INFRA = Path(__file__).resolve().parents[1]
TOOL = Path(__file__).resolve().parents[1] / 'roles/slinky/files/prace-slinky-maintenance.py'
spec = importlib.util.spec_from_file_location('maintenance', TOOL)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
ID = '0123456789abcdef'


def intent(phase='closed'):
    return {'schema': 2, 'lease_id': ID, 'phase': phase, 'fence_active': phase == 'closed',
            'original': {'partitions': {'cpu': 'UP', 'gpu': 'DOWN'},
                         'loginsets': {'slurm-login-prace': {'uid': 'saved-uid', 'replicas': 2}}},
            'declared_partitions': {'debug': 'UP', 'payg': 'INACTIVE'}}


def payload(phase='closed', native=False):
    i = intent(phase)
    states, replicas = m.intent_states(i)
    values = {'nodesets': {n: {'partition': {'configMap': {'State': states[n]}}} for n in ('cpu', 'gpu')},
              'partitions': {n: {'configMap': {'State': states[n]}} for n in ('debug', 'payg')},
              'loginsets': {'prace': {'replicas': replicas}}}
    if native:
        values['controller'] = {'extraConfMap': {'PartitionName': 'cpu Nodes=cpu Default=YES State=' + states['cpu']}}
    obj = {'apiVersion': 'helm.cattle.io/v1', 'kind': 'HelmChartConfig',
           'metadata': {'name': 'slurm', 'namespace': 'kube-system',
                        'annotations': {'prace.fleet/window-id': ID, 'prace.fleet/window-phase': phase}},
           'spec': {'valuesContent': json.dumps(values)}}
    return {'intent': i, 'overlay': obj}


class Overlay(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.lease = self.root / 'lease'; self.lease.mkdir(mode=0o700)
        self.overlay = self.root / 'overlay.yaml'
        for name, value in [('LEASE', self.lease), ('OVERLAY', self.overlay),
                            ('LOCK_ROOT', self.root), ('OWNER_UID', os.getuid())]:
            p = patch.object(m, name, value); p.start(); self.addCleanup(p.stop)
        self.put('holder', f'holder=maint label=test id={ID} since=2026-09-30T00:00:00+08:00')
        self.put('fence-intent.json', json.dumps(intent()))
        self.calls = []
        def run(args, **kw):
            self.calls.append(args)
            self.assertIn('timeout', kw)
            if 'helmchart' in args:      # no slurm HelmChart in these tests: nothing for Helm to run (HelmGuard has one)
                return type('Reply', (), {'stdout': '', 'returncode': 0})()
            if 'secret' in args or any(a.startswith(('loginsets.', 'controllers.', 'nodesets.')) for a in args):
                # and no release or object of one (helm_state reads them even without a chart)
                return type('Reply', (), {'stdout': '' if '--ignore-not-found' in args else json.dumps({'items': []}), 'returncode': 0})()
            if 'helmchartconfig' in args and not self.overlay.exists():
                return type('Reply', (), {'stdout': '', 'returncode': 0})()        # none in the API yet
            obj = json.loads(self.overlay.read_text())
            # Kubernetes defaults this independently of what the client wrote.
            obj['spec'].setdefault('failurePolicy', 'reinstall')
            return type('Reply', (), {'stdout': json.dumps(obj), 'returncode': 0})()
        p = patch.object(m.subprocess, 'run', run); p.start(); self.addCleanup(p.stop)

    def put(self, name, data):
        p = self.lease / name; p.write_text(data); p.chmod(0o600)

    def test_closed_overlay_survives_reapply_and_native_has_inactive_state(self):
        for native in (False, True):
            with self.subTest(native=native):
                p = payload(native=native)
                self.assertTrue(m.apply(p))
                self.assertFalse(m.apply(p))
                self.assertEqual(json.loads(self.overlay.read_text()), m.canonical(p['overlay']))
                self.assertEqual(self.overlay.stat().st_mode & 0o777, 0o600)
                self.assertIn(['apply', '-f'], [c[2:4] for c in self.calls])

    def test_opening_restores_exact_down_inactive_states_and_replicas(self):
        p = payload('opening', native=True)
        self.put('fence-intent.json', json.dumps(p['intent']))
        self.assertTrue(m.apply(p))
        v = json.loads(json.loads(self.overlay.read_text())['spec']['valuesContent'])
        self.assertEqual(v['nodesets']['gpu']['partition']['configMap']['State'], 'DOWN')
        self.assertEqual(v['partitions']['payg']['configMap']['State'], 'INACTIVE')
        self.assertEqual(v['loginsets']['prace']['replicas'], 2)

    def test_abort_is_written_and_legacy_reinstall_forms_are_rewritten_idempotently(self):
        """2 Oct: the overlay's policy overrides the HelmChart's and the API defaults it to reinstall,
        under which K3s uninstalls and reinstalls a failed or interrupted release; abort leaves it
        for the operator. An overlay written before (no policy, or reinstall) is rewritten as abort."""
        legacy = payload()
        explicit = copy.deepcopy(legacy)
        explicit['overlay']['spec']['failurePolicy'] = 'reinstall'
        current = copy.deepcopy(legacy)
        current['overlay']['spec']['failurePolicy'] = 'abort'
        self.assertTrue(m.apply(legacy))
        self.assertEqual(json.loads(self.overlay.read_text())['spec']['failurePolicy'], 'abort')
        self.assertFalse(m.apply(explicit))
        self.assertFalse(m.apply(legacy))
        self.assertFalse(m.apply(current))

    def test_unknown_spec_or_failure_policy_refuses_before_writing(self):
        for addition in ({'failurePolicy': 'retry'}, {'failurePolicy': None},
                         {'failurePolicy': 'abort', 'valuesSecrets': []}):
            with self.subTest(addition=addition):
                p = payload()
                p['overlay']['spec'].update(addition)
                with self.assertRaises(ValueError):
                    m.apply(p)
                self.assertFalse(self.overlay.exists())
                self.assertFalse(self.calls)
                i = intent(); i['phase'] = 'closing'
                with self.assertRaises(ValueError):
                    m.refenced(i, p['overlay'])

    def test_applied_policy_mismatch_remains_a_failure(self):
        def wrong_policy(argv, **kwargs):
            if 'helmchart' in argv:
                return type('Reply', (), {'stdout': ''})()
            if 'secret' in argv or any(a.startswith(('loginsets.', 'controllers.', 'nodesets.')) for a in argv):
                return type('Reply', (), {'stdout': '' if '--ignore-not-found' in argv else json.dumps({'items': []})})()
            if 'helmchartconfig' in argv and not self.overlay.exists():
                return type('Reply', (), {'stdout': ''})()  # the read before the first write
            obj = json.loads(self.overlay.read_text())
            obj['spec']['failurePolicy'] = 'reinstall'      # something put the reinstall default back
            return type('Reply', (), {'stdout': json.dumps(obj)})()
        with patch.object(m.subprocess, 'run', wrong_policy), self.assertRaisesRegex(ValueError, 'overlay not observed'):
            m.apply(payload())
        self.assertTrue(self.overlay.exists())  # failure preserves the persistent fence
        self.assertTrue((self.lease / 'holder').exists())

    def test_stale_marker_and_duplicate_holder_refuse_before_apply(self):
        self.put('fence-intent.json', json.dumps(intent('opening')))
        with self.assertRaises(ValueError): m.apply(payload())
        self.put('fence-intent.json', json.dumps(intent()))
        self.put('holder', f'holder=maint label=x id={ID} id={ID} since=x')
        with self.assertRaises(ValueError): m.apply(payload())
        self.assertEqual(self.calls, [])
        self.assertFalse(self.overlay.exists())

    def test_absent_or_insecure_marker_refuses(self):
        p = self.lease / 'fence-intent.json'
        p.chmod(0o644)
        with self.assertRaises(ValueError): m.apply(payload())
        p.unlink()
        with self.assertRaises(OSError): m.apply(payload())
        p.symlink_to(self.lease / 'holder')
        with self.assertRaises(ValueError): m.apply(payload())
        self.assertEqual(self.calls, [])

    def test_no_intent_does_not_remove_or_bypass_active_overlay(self):
        with self.assertRaises(ValueError): m.apply({'intent': None})
        m.apply(payload())
        for p in self.lease.iterdir(): p.unlink()
        self.lease.rmdir()
        with self.assertRaises(ValueError): m.apply({'intent': None})
        self.assertEqual(json.loads(self.overlay.read_text()), m.canonical(payload()['overlay']))

    def test_unknown_or_missing_membership_and_opening_bypass_refuse(self):
        variants = []
        p = payload(); p['intent']['declared_partitions']['cpu'] = 'UP'; variants.append(p)
        p = payload(); p['intent']['original']['loginsets']['slurm-login-prace']['uid'] = ''; variants.append(p)
        p = payload(); p['intent']['fence_active'] = False; variants.append(p)
        p = payload(); p['overlay']['metadata']['annotations']['prace.fleet/window-id'] = 'f' * 16; variants.append(p)
        for state in ('UP', None):
            p = payload(); v = json.loads(p['overlay']['spec']['valuesContent'])
            if state: v['nodesets']['cpu']['partition']['configMap']['State'] = state
            else: del v['partitions']['debug']
            p['overlay']['spec']['valuesContent'] = json.dumps(v); variants.append(p)
        for p in variants:
            with self.subTest(p=p), self.assertRaises(ValueError):
                m.verify_overlay(p['intent'], p['overlay'])

    def test_busy_window_lock_and_check_mode_cannot_write(self):
        with (self.root / f'prace-slurm-window-{ID}.lock').open('w') as lock:
            os.fchmod(lock.fileno(), 0o600)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaises(BlockingIOError): m.apply(payload())
        self.assertFalse(m.apply(payload(), check=True))
        self.assertFalse(self.overlay.exists()); self.assertFalse(self.calls)

    def test_refence_reuses_inherited_lock_and_preserves_native_policy(self):
        p = payload('opening', native=True)
        self.put('fence-intent.json', json.dumps(p['intent']))
        m.apply(p)
        i = intent(); i['phase'] = 'closing'
        self.put('fence-intent.json', json.dumps(i))
        with (self.root / f'prace-slurm-window-{ID}.lock').open('r+') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertTrue(m.apply({'intent': i}, refence=True, lock_fd=lock.fileno()))
        obj = json.loads(self.overlay.read_text())
        m.verify_overlay(i, obj)
        line = json.loads(obj['spec']['valuesContent'])['controller']['extraConfMap']['PartitionName']
        self.assertEqual(line, 'cpu Nodes=cpu Default=YES State=INACTIVE')
        self.assertEqual(obj['metadata']['annotations']['prace.fleet/window-phase'], 'closed')

    def test_new_window_can_refence_prior_restored_overlay_but_not_closed_one(self):
        current = intent(); current.update(phase='closing', lease_id='f' * 16)
        obj = m.refenced(current, payload('opening')['overlay'])
        self.assertEqual(obj['metadata']['annotations']['prace.fleet/window-id'], 'f' * 16)
        m.verify_overlay(current, obj)
        with self.assertRaises(ValueError): m.refenced(current, payload()['overlay'])

    def test_first_close_without_overlay_writes_nothing_and_wrong_fd_refuses(self):
        i = intent(); i['phase'] = 'closing'
        self.put('fence-intent.json', json.dumps(i))
        self.assertFalse(m.apply({'intent': i}, refence=True))
        self.assertFalse(self.overlay.exists()); self.assertFalse(self.calls)
        with (self.root / 'unrelated').open('w') as other:
            with self.assertRaises(ValueError): m.apply({'intent': i}, refence=True, lock_fd=other.fileno())

    def test_failed_kubernetes_apply_keeps_overlay_and_never_reopens(self):
        def timeout_on_apply(args, **kw):
            if 'helmchart' in args:
                return type('Reply', (), {'stdout': ''})()
            if 'secret' in args or any(a.startswith(('loginsets.', 'controllers.', 'nodesets.')) for a in args):
                return type('Reply', (), {'stdout': '' if '--ignore-not-found' in args else json.dumps({'items': []})})()
            if 'helmchartconfig' in args and '--ignore-not-found' in args:
                return type('Reply', (), {'stdout': ''})()  # the read before the write answers; the apply does not
            raise m.subprocess.TimeoutExpired('kubectl', 60)
        with patch.object(m.subprocess, 'run', timeout_on_apply):
            with self.assertRaises(m.subprocess.TimeoutExpired): m.apply(payload())
        self.assertEqual(json.loads(self.overlay.read_text()), m.canonical(payload()['overlay']))
        self.assertEqual(json.loads((self.lease / 'fence-intent.json').read_text()), intent())

    def test_a_reclose_then_the_same_closed_intent_is_unchanged(self):
        """review: the re-close wrote sorted JSON and the template insertion order, so every re-apply changed"""
        self.assertTrue(m.apply(payload()))
        i = intent(); i['phase'] = 'closing'
        self.put('fence-intent.json', json.dumps(i))
        self.assertFalse(m.apply({'intent': i}, refence=True))      # already closed by this window
        self.put('fence-intent.json', json.dumps(intent()))
        self.assertFalse(m.apply(payload()))

    def test_refence_closes_an_overlay_written_for_another_baseline(self):
        """review M1: drift between windows (a partition added since) made every later close refuse"""
        old = payload('opening')['overlay']
        v = json.loads(old['spec']['valuesContent']); del v['partitions']['payg']
        old['spec']['valuesContent'] = json.dumps(v)
        current = intent(); current.update(phase='closing', lease_id='f' * 16)
        obj = m.refenced(current, old)
        v = json.loads(obj['spec']['valuesContent'])
        self.assertEqual({n['partition']['configMap']['State'] for n in v['nodesets'].values()} |
                         {n['configMap']['State'] for n in v['partitions'].values()}, {'INACTIVE'})
        self.assertEqual(v['loginsets']['prace']['replicas'], 0)
        self.assertEqual(obj['metadata']['annotations'], {'prace.fleet/window-id': 'f' * 16, 'prace.fleet/window-phase': 'closed'})

    def test_another_windows_closed_overlay_is_never_overwritten(self):
        other = payload()['overlay']; other['metadata']['annotations']['prace.fleet/window-id'] = 'f' * 16
        self.overlay.write_text(json.dumps(other)); self.overlay.chmod(0o600)
        with self.assertRaises(ValueError): m.apply(payload())
        self.assertEqual(json.loads(self.overlay.read_text()), other)

    def test_another_lease_may_converge_only_while_no_window_holds_the_overlay(self):
        """review M4: slinky-acceptance.sh --revocation converges under its own lease, with no intent"""
        self.put('holder', 'holder=slinky-acceptance id=0123456789abcdef since=now')
        (self.lease / 'holder').chmod(0o644)                        # as that script writes it
        self.assertFalse(m.apply({'intent': None}))                 # no overlay yet
        opening = m.canonical(payload('opening')['overlay'])
        self.overlay.write_text(json.dumps(opening)); self.overlay.chmod(0o600)
        self.assertFalse(m.apply({'intent': None, 'rendered': ['cpu', 'gpu', 'debug', 'payg']}))   # a restored window's overlay
        with self.assertRaises(ValueError):                         # second review L4: a reverted chart without payg
            m.apply({'intent': None, 'rendered': ['cpu', 'gpu', 'debug']})
        self.overlay.write_text(json.dumps(m.canonical(payload()['overlay'])))
        with self.assertRaises(ValueError): m.apply({'intent': None, 'rendered': ['cpu', 'gpu', 'debug', 'payg']})   # a closed window
        self.put('holder', f'holder=maint label=test id={ID} since=x')
        self.overlay.write_text(json.dumps(opening))
        with self.assertRaises(ValueError): m.apply({'intent': None})   # a maintenance lease needs its intent
        self.assertEqual(self.calls, [])


def release_secret(version, status, values):
    """a Helm release Secret as kubectl prints it: base64 of Helm's base64 of gzipped JSON"""
    blob = base64.b64encode(gzip.compress(json.dumps({'config': values}).encode()))
    return {'metadata': {'labels': {'owner': 'helm', 'name': 'slurm', 'version': str(version), 'status': status}},
            'data': {'release': base64.b64encode(blob).decode()}}


class FakeHelm:
    """K3s's Helm controller for the slurm chart as the helper sees it: an apply that changes the
    values replaces the job, which runs for `job_polls` polls with the release pending-upgrade, then
    leaves `outcome`: deployed, failed, or deployed by a reinstall (new LoginSet and auth key UIDs)."""

    def __init__(self, values):
        self.chart, self.outcome, self.job_polls, self.lag = True, 'deployed', 2, 0
        self.job = {'uid': 'job-1', 'left': 0}
        self.queued = None               # values K3s has not acted on yet (its reaction lag, in polls)
        self.releases = [[1, 'deployed', values]]
        self.ids = {'loginsets': {'slurm-login-prace': 'login-1'}, 'controllers': {'slurm': 'ctl-1'},
                    'nodesets': {'slurm-worker-cpu': 'ns-cpu', 'slurm-worker-gpu': 'ns-gpu'},
                    'secrets': {'slurm-auth-slurm': 'key-1', 'slurm-auth-jwt': 'jwt-1'}}
        self.applies = 0
        self.overlay = None              # the HelmChartConfig's values in the API (None: no overlay)
        self.spec = None                 # the overlay's spec as last applied (its policy too)
        self.on_poll = None              # a scenario's hook, called at each chart poll
        self.chart_partitions = None     # partitions the HelmChart defines (None: whatever is applied renders)
        self.chart_spec = {'chart': 'slurm'}
        # the job pod's container while a job runs: waiting in CrashLoopBackOff after a failed attempt
        self.attempt = {'state': 'waiting', 'exit': 1, 'restarts': 3}
        self.log = ''                    # the job pod's log
        self.own_pod = True              # the running job lists a pod of its own
        self.other_pods = []             # pods of the same job name owned by something else (an earlier job)
        self.on_logs = None              # a scenario's hook, called when a pod's log is read

    def renders(self, values):
        return self.chart_partitions is None or set(values.get('partitions') or {}) <= self.chart_partitions

    def applied(self, values, spec=None):
        """an apply: `spec`, the overlay's spec, when the overlay was applied. K3s replaces the job
        when the values or the overlay change: a failurePolicy-only change too (3 Oct, 10:51)"""
        respec = spec is not None and spec != self.spec
        if spec is not None:
            self.spec = spec
        if values == self.releases[-1][2] and not respec:
            return                       # nothing changed: K3s starts no job
        self.applies += 1
        if not self.renders(values):
            # 3 Oct, step 4: every attempt fails while rendering; no release is written, the job keeps retrying
            missing = sorted(set(values['partitions']) - self.chart_partitions)[0]
            self.job = {'uid': f'job-{self.applies + 1}', 'left': 10 ** 9}
            self.log = ("Upgrading slurm\nError: UPGRADE FAILED: execution error at (slurm/templates/controller/"
                        f"controller-cr.yaml:51:10): partition `{missing}` must contain at least one NodeSet (or ALL).\n")
            self.queued = None
            return
        self.queued = [self.lag, values]
        self.start()

    def start(self):
        if self.queued and self.queued[0] <= 0:
            self.job = {'uid': f'job-{self.applies + 1}', 'left': self.job_polls}
            self.releases.append([self.releases[-1][0] + 1, 'pending-upgrade', self.queued[1]])
            self.queued = None

    def poll(self):
        if self.queued:
            self.queued[0] -= 1
            self.start()
        if self.job['left'] > 0:
            self.job['left'] -= 1
            if self.job['left'] == 0 and self.releases[-1][1] == 'pending-upgrade':
                self.releases[-1][1] = 'failed' if self.outcome == 'failed' else 'deployed'
                if len(self.releases) > 1 and self.releases[-1][1] == 'deployed':
                    self.releases[-2][1] = 'superseded'
                if self.outcome == 'reinstall':
                    self.ids['loginsets']['slurm-login-prace'] = 'login-NEW'
                    self.ids['secrets']['slurm-auth-slurm'] = 'key-NEW'

    def pod(self, owner=None, attempt=None):
        """a helm-install pod as kubectl prints it (3 Oct, live): owned by its Job as controller; in
        CrashLoopBackOff the container's ID is that of its last, terminated attempt"""
        owner = self.job['uid'] if owner is None else owner
        a = dict(self.attempt, **(attempt or {}))
        cid = f"containerd://{owner}-{a['restarts']}"
        if a['state'] == 'running':
            status = {'containerID': cid, 'state': {'running': {}},
                      'lastState': {'terminated': {'containerID': f"containerd://{owner}-{a['restarts'] - 1}", 'exitCode': 1}}}
        else:
            status = {'containerID': cid, 'state': {'waiting': {'reason': 'CrashLoopBackOff'}},
                      'lastState': {'terminated': {'containerID': a.get('last_id', cid), 'exitCode': a['exit']}}}
        return {'metadata': {'name': 'helm-install-slurm-' + owner, 'uid': 'pod-' + owner,
                             'ownerReferences': [{'apiVersion': 'batch/v1', 'kind': 'Job', 'name': 'helm-install-slurm',
                                                  'uid': owner, 'controller': True}]},
                'status': {'containerStatuses': [dict(status, name='helm', restartCount=a['restarts'])]}}

    def reply(self, args):
        a = args[2:]
        if 'logs' in a:
            if self.on_logs:
                self.on_logs(self)
            return self.log
        if 'pods' in a:
            return json.dumps({'items': copy.deepcopy(self.other_pods) + ([self.pod()] if self.job['left'] and self.own_pod else [])})
        if 'helmchartconfig' in a:
            return json.dumps({'kind': 'HelmChartConfig', 'spec': {'valuesContent': json.dumps(self.overlay)}}) if self.overlay is not None else ''
        if 'helmchart' in a:
            self.poll()
            if self.on_poll:
                self.on_poll(self)
            return json.dumps({'kind': 'HelmChart', 'spec': self.chart_spec}) if self.chart else ''
        if 'job' in a:
            done = {'succeeded': 1, 'conditions': [{'type': 'Complete', 'status': 'True'}]}
            return json.dumps({'metadata': {'uid': self.job['uid']}, 'status': {'active': 1} if self.job['left'] else done})
        if 'secret' in a and '-l' in a:
            return json.dumps({'items': [release_secret(*r) for r in self.releases]})
        if 'secret' in a:
            name = a[a.index('secret') + 1]
            uid = self.ids['secrets'].get(name)
            return json.dumps({'metadata': {'name': name, 'uid': uid}}) if uid else ''
        kind = next(k for k in ('loginsets', 'controllers', 'nodesets') if any(x.startswith(k + '.') for x in a))
        return json.dumps({'items': [{'metadata': {'name': n, 'uid': u}} for n, u in self.ids[kind].items()]})


class RoleChartSettle(unittest.TestCase):
    """Session A's !73 merge check (3 Oct). H1: after the role's chart write, the settle accepted the
    release from BEFORE the write, because K3s had not started its job yet. H2: a first installation
    was refused as a reinstall (its new LoginSet, controller and keys had no earlier UID)."""
    OLD = {'clusterName': 'prace', 'loginsets': {'prace': {'replicas': 1}}, 'slurmKey': {'annotations': {}}}
    NEW = {'clusterName': 'prace', 'loginsets': {'prace': {'replicas': 1}},
           'slurmKey': {'annotations': {'helm.sh/resource-policy': 'keep'}}}     # not an admission field

    def setUp(self):
        self.helm = FakeHelm(dict(self.OLD))
        self.clock = [0.0]
        for name, fake in (('monotonic', lambda: self.clock[0]),
                           ('sleep', lambda sec: self.clock.__setitem__(0, self.clock[0] + sec))):
            p = patch.object(m.time, name, fake); p.start(); self.addCleanup(p.stop)

        def kube(args, timeout=30):
            raw = self.helm.reply(m.K + args)
            return json.loads(raw) if raw.strip() else None
        p = patch.object(m, 'kube', kube); p.start(); self.addCleanup(p.stop)

    def settle(self, before, values, **kw):
        return m.helm_settle(before, ignore=('nodesets/',), values=values, **kw)

    def test_a_lagging_controller_is_waited_for_by_the_written_values(self):
        before = m.helm_idle()
        self.helm.lag = 3                                   # A's reproduction: three polls before K3s reacts
        self.helm.applied(self.NEW)
        after = self.settle(before, self.NEW)
        self.assertEqual((after['revision'], after['status']), (2, 'deployed'))
        self.assertIsNone(self.helm.queued)
        self.assertEqual(self.helm.releases[-1][2], self.NEW)

    def test_values_never_applied_stop_at_the_bound_and_name_what_is_missing(self):
        before = m.helm_idle()
        self.helm.lag = 10 ** 6
        self.helm.applied(self.NEW)
        with self.assertRaisesRegex(ValueError, r"not applied the write in time.*not yet deployed: \.slurmKey\.annotations\.helm\.sh/resource-policy"):
            self.settle(before, self.NEW)

    def test_a_semantic_no_op_passes_at_once(self):
        before = m.helm_idle()
        self.helm.applied(dict(self.OLD))                   # same values: K3s starts no job
        after = self.settle(before, dict(self.OLD), timeout=0)
        self.assertEqual(after['revision'], 1)
        self.assertEqual(self.helm.applies, 0)

    def test_the_release_must_carry_the_chart_values_merged_with_the_overlay(self):
        self.helm.overlay = {'loginsets': {'prace': {'replicas': 0}}}          # the window's closed overlay
        self.helm.releases = [[1, 'deployed', m.merged(self.OLD, self.helm.overlay)]]
        before = m.helm_idle()
        self.helm.applied(m.merged(self.NEW, self.helm.overlay))
        after = self.settle(before, self.NEW)
        self.assertEqual(after['config']['loginsets']['prace']['replicas'], 0)
        self.assertEqual(after['config']['slurmKey'], self.NEW['slurmKey'])
        # a release with the chart values but without the overlay's is not the write's
        self.helm.releases.append([3, 'deployed', dict(self.NEW)])
        with self.assertRaisesRegex(ValueError, r"not yet deployed: \.loginsets\.prace\.replicas"):
            self.settle(m.helm_idle(), self.NEW, timeout=30)

    def first_install(self, delay):
        """no chart, no release, no objects before; after `delay` chart polls K3s installs revision 1"""
        self.helm.chart, self.helm.releases = False, []
        self.helm.ids = {'loginsets': {}, 'controllers': {}, 'nodesets': {}, 'secrets': {}}
        before = m.helm_idle()
        self.assertEqual((before['chart'], before['revision'], before['identity']), (False, 0, {}))
        polls = [0]

        def install(h):
            polls[0] += 1
            if polls[0] > delay and not h.chart:
                h.chart, h.releases = True, [[1, 'deployed', dict(self.NEW)]]
                h.ids = {'loginsets': {'slurm-login-prace': 'login-1'}, 'controllers': {'slurm': 'ctl-1'},
                         'nodesets': {'slurm-worker-cpu': 'ns-cpu'}, 'secrets': {'slurm-auth-slurm': 'key-1', 'slurm-auth-jwt': 'jwt-1'}}
        self.helm.on_poll = install
        return before

    def test_a_first_installation_creates_its_objects(self):
        for delay in (0, 4):                                # observed at once, and after the chart appears late
            with self.subTest(delay=delay):
                self.setUp()
                after = self.settle(self.first_install(delay), self.NEW)
                self.assertEqual((after['revision'], after['identity']['loginsets/slurm-login-prace']), (1, 'login-1'))

    def test_a_first_installation_that_never_comes_stops_at_the_bound(self):
        before = self.first_install(10 ** 6)
        with self.assertRaisesRegex(ValueError, 'not applied the write in time'):
            self.settle(before, self.NEW)

    def test_an_existing_release_never_counts_as_fresh(self):
        """controls: a reinstall of an existing release, and a chart that vanished leaving its objects"""
        before = m.helm_idle()
        self.helm.outcome = 'reinstall'
        self.helm.applied(self.NEW)
        with self.assertRaisesRegex(ValueError, 'identity changed.*loginsets/slurm-login-prace'):
            self.settle(before, self.NEW)
        self.setUp()
        self.helm.chart = False                             # the chart is gone, its release and objects are not
        before = m.helm_idle()
        self.assertTrue(before['identity'])
        self.helm.chart, self.helm.ids['secrets']['slurm-auth-jwt'] = True, 'jwt-NEW'
        self.helm.releases.append([2, 'deployed', dict(self.NEW)])
        with self.assertRaisesRegex(ValueError, 'identity changed.*secret/slurm-auth-jwt'):
            self.settle(before, self.NEW)
        # the chart and its LoginSet and controller are gone, the key Secrets kept: not a fresh
        # installation, so a new LoginSet and controller are replacements, not first objects
        self.setUp()
        self.helm.chart, self.helm.releases = False, []
        self.helm.ids = {'loginsets': {}, 'controllers': {}, 'nodesets': {}, 'secrets': {'slurm-auth-slurm': 'key-1', 'slurm-auth-jwt': 'jwt-1'}}
        before = m.helm_idle()
        self.helm.chart, self.helm.releases = True, [[1, 'deployed', dict(self.NEW)]]
        self.helm.ids.update(loginsets={'slurm-login-prace': 'login-2'}, controllers={'slurm': 'ctl-2'})
        with self.assertRaisesRegex(ValueError, 'identity changed.*controllers/slurm.*loginsets/slurm-login-prace'):
            self.settle(before, self.NEW)

    def test_the_chart_disappearing_during_the_write_stops(self):
        before = m.helm_idle()
        self.helm.chart = False
        with self.assertRaisesRegex(ValueError, 'disappeared during the write'):
            self.settle(before, self.NEW)

    def test_an_overlay_written_before_any_chart_settles_at_once(self):
        self.helm.chart, self.helm.releases = False, []
        self.helm.ids = {'loginsets': {}, 'controllers': {}, 'nodesets': {}, 'secrets': {}}
        self.assertFalse(m.helm_settle(m.helm_idle(), want={'loginset/prace': 0}, timeout=0)['chart'])

    def test_a_settle_without_what_was_written_is_refused(self):
        """A's reproduction called the settle with neither: it must never accept the old release"""
        before = m.helm_idle()
        self.helm.lag = 3
        self.helm.applied(self.NEW)
        with self.assertRaisesRegex(ValueError, 'needs what was written'):
            m.helm_settle(before, ignore=('nodesets/',), timeout=0)

    def test_the_cli_requires_the_written_values(self):
        r = subprocess.run([sys.executable, str(TOOL), '--helm-settle'], input=json.dumps({'before': {'chart': True}}),
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 1)
        self.assertIn('the written chart values are required', r.stderr)


class HelmGuard(Overlay):
    """2 Oct: nothing is written while a Helm job runs, and a write is done only when the release
    carries it with nothing replaced (A's 1 Oct opening reinstalled the release: new LoginSet, keys)"""

    def setUp(self):
        super().setUp()
        self.helm = FakeHelm(json.loads(payload('opening')['overlay']['spec']['valuesContent']))
        self.clock = [0.0]          # a fake clock: each sleep advances it, nothing really waits
        for name, fake in (('monotonic', lambda: self.clock[0]),
                           ('sleep', lambda sec: self.clock.__setitem__(0, self.clock[0] + sec))):
            p = patch.object(m.time, name, fake); p.start(); self.addCleanup(p.stop)

        def run(args, **kw):
            self.calls.append(args)
            self.assertIn('timeout', kw)
            if args[2:4] == ['apply', '-f']:
                spec = json.loads(self.overlay.read_text())['spec']
                self.helm.applied(json.loads(spec['valuesContent']), spec=dict({'failurePolicy': 'reinstall'}, **spec))
                return type('Reply', (), {'stdout': '', 'returncode': 0})()
            if 'helmchartconfig' in args and not self.overlay.exists():
                return type('Reply', (), {'stdout': '', 'returncode': 0})()        # none in the API yet
            if 'helmchartconfig' in args:
                obj = json.loads(self.overlay.read_text()); obj['spec'].setdefault('failurePolicy', 'reinstall')
                return type('Reply', (), {'stdout': json.dumps(obj), 'returncode': 0})()
            return type('Reply', (), {'stdout': self.helm.reply(args), 'returncode': 0})()
        p = patch.object(m.subprocess, 'run', run); p.start(); self.addCleanup(p.stop)

    def applies(self):
        return [i for i, c in enumerate(self.calls) if c[2:4] == ['apply', '-f']]

    def test_a_write_waits_for_its_upgrade_and_returns_with_the_fence_in_the_release(self):
        self.assertTrue(m.apply(payload()))
        newest = self.helm.releases[-1]
        self.assertEqual(newest[:2], [2, 'deployed'])
        self.assertEqual(m.admission(newest[2])['loginset/prace'], 0)
        self.assertEqual({k: v for k, v in m.admission(newest[2]).items() if k != 'loginset/prace'},
                         dict.fromkeys(['nodeset/cpu', 'nodeset/gpu', 'partition/debug', 'partition/payg'], 'INACTIVE'))
        self.assertFalse(m.apply(payload()))            # a re-apply starts no job and waits for nothing
        self.assertEqual(self.helm.applies, 1)

    def test_a_running_job_is_never_written_over(self):
        self.helm.job = {'uid': 'job-old', 'left': 4}      # an earlier write's upgrade still running
        self.helm.releases.append([2, 'pending-upgrade', self.helm.releases[-1][2]])
        self.assertTrue(m.apply(payload()))
        chart_polls = [i for i, c in enumerate(self.calls) if 'helmchart' in c]
        self.assertGreaterEqual(len([i for i in chart_polls if i < self.applies()[0]]), 4)
        self.assertEqual(self.helm.releases[1][1], 'superseded')

    def test_a_job_that_never_finishes_refuses_before_writing(self):
        self.helm.job = {'uid': 'job-stuck', 'left': 10 ** 6}
        self.helm.releases.append([2, 'pending-upgrade', self.helm.releases[-1][2]])
        with self.assertRaisesRegex(ValueError, 'still running: never write over it'):
            m.apply(payload())
        self.assertFalse(self.overlay.exists())
        self.assertEqual(self.applies(), [])

    def test_a_broken_or_abandoned_release_refuses_before_writing(self):
        for status, words in (('failed', 'is failed: recover it'), ('pending-upgrade', 'an interrupted upgrade')):
            with self.subTest(status=status):
                self.helm.releases = [[1, 'deployed', {}], [2, status, {}]]
                with self.assertRaisesRegex(ValueError, words):
                    m.apply(payload())
                self.assertFalse(self.overlay.exists())
                self.assertEqual(self.applies(), [])

    def test_a_failed_upgrade_after_the_write_stops_with_the_fence_retained(self):
        self.helm.outcome = 'failed'
        with self.assertRaisesRegex(ValueError, 'is failed after the write: the fence holds'):
            m.apply(payload())
        self.assertEqual(json.loads(self.overlay.read_text())['spec']['failurePolicy'], 'abort')
        self.assertTrue((self.lease / 'holder').exists())

    def test_a_reinstall_is_caught_by_the_identity_check(self):
        self.helm.outcome = 'reinstall'
        with self.assertRaisesRegex(ValueError, 'identity changed.*loginsets/slurm-login-prace.*secret/slurm-auth-slurm'):
            m.apply(payload())

    def test_a_replaced_login_host_key_secret_is_caught_like_a_reinstall(self):
        """3 Oct: the login pod's SSH host keys (the operator's Secret for the LoginSet) changed with
        1 Oct's reinstall and nothing noticed until a pinned client refused them; the settle's
        identity check now covers that Secret too"""
        self.helm.ids['secrets']['slurm-login-prace-ssh-host-keys'] = 'hk-1'
        self.helm.on_poll = lambda h: h.job['left'] == 1 and h.ids['secrets'].update({'slurm-login-prace-ssh-host-keys': 'hk-NEW'})
        with self.assertRaisesRegex(ValueError, 'identity changed.*secret/slurm-login-prace-ssh-host-keys'):
            m.apply(payload())

    def test_a_slow_job_is_waited_for_and_a_timeout_stops(self):
        self.helm.job_polls = 50
        self.assertTrue(m.apply(payload()))               # 50 polls of 5 s, within the 900 s bound
        self.helm.job_polls = 10 ** 6
        p = payload('opening'); self.put('fence-intent.json', json.dumps(p['intent']))
        with self.assertRaisesRegex(ValueError, 'not applied the write in time'):
            m.apply(p)

    def test_a_lagging_controller_is_waited_for_by_the_admission_state(self):
        """K3s may start the job a while after the apply: until then the job is idle and the old
        release deployed, so only the admission fields show the write is not applied yet"""
        self.helm.lag = 3
        self.assertTrue(m.apply(payload()))
        self.assertEqual(self.helm.releases[-1][:2], [2, 'deployed'])
        self.assertEqual(m.admission(self.helm.releases[-1][2])['loginset/prace'], 0)

    def test_no_chart_yet_writes_without_waiting(self):
        self.helm.chart = False
        self.assertTrue(m.apply(payload()))
        self.assertEqual(self.clock[0], 0.0)

    def legacy_overlay_in_place(self):
        """the fleet before 10:51 on 3 Oct: this window's closed overlay, written before the abort
        policy existed (none on disk; the API defaults it to reinstall), and already deployed"""
        obj = copy.deepcopy(payload()['overlay'])
        obj['spec']['valuesContent'] = json.dumps(json.loads(obj['spec']['valuesContent']), sort_keys=True)
        self.overlay.write_text(json.dumps(obj, sort_keys=True, indent=2) + '\n'); self.overlay.chmod(0o600)
        self.helm.releases = [[1, 'deployed', json.loads(obj['spec']['valuesContent'])]]
        self.helm.spec = dict({'failurePolicy': 'reinstall'}, **obj['spec'])

    def test_a_policy_only_rewrite_waits_for_the_job_it_starts(self):
        """3 Oct, V at 10:51: the release already carried the closed admission fields, so the settle
        returned before the job that the abort policy made K3s start had run (Session A's review of
        !79: policy-only settlement)"""
        self.legacy_overlay_in_place()
        self.helm.lag = 3                    # K3s starts the job a while after the apply
        self.assertTrue(m.apply(payload()))
        self.assertEqual(json.loads(self.overlay.read_text())['spec']['failurePolicy'], 'abort')
        self.assertEqual(self.helm.releases[-1][:2], [2, 'deployed'], 'the job the rewrite started has run')
        self.assertEqual((self.helm.job['uid'], self.helm.job['left']), ('job-2', 0))
        self.assertFalse(m.apply(payload()))  # unchanged now: no job, nothing to wait for
        self.assertEqual(self.helm.applies, 1)

    def test_a_policy_only_rewrite_whose_job_never_comes_stops(self):
        self.legacy_overlay_in_place()
        self.helm.lag = 10 ** 6
        with self.assertRaisesRegex(ValueError, 'not applied the write in time'):
            m.apply(payload())
        self.assertEqual(json.loads(self.overlay.read_text())['spec']['failurePolicy'], 'abort', 'the fence stays written')

    def test_an_unchanged_overlay_waits_for_no_job(self):
        """a re-apply that changes nothing in the API starts no job: the settle must not wait for one"""
        self.assertTrue(m.apply(payload()))
        t = self.clock[0]
        self.assertFalse(m.apply(payload()))
        self.assertEqual(self.clock[0], t)

    def test_the_roles_chart_write_guard(self):
        """--helm-idle before the chart write, --helm-settle after it: NodeSets may come and go with
        a chart change, the LoginSet, controller and auth keys may not"""
        with patch.object(m, 'overlay_values', lambda: {}):
            before = m.helm_idle()
            self.helm.applied({'nodesets': {}})
            self.helm.ids['nodesets'] = {'slurm-worker-gpu': 'ns-gpu'}          # the cpu NodeSet removed by the chart
            self.assertEqual(m.helm_settle(before, ignore=('nodesets/',), values={'nodesets': {}})['status'], 'deployed')
            before = m.helm_idle()
            self.helm.outcome = 'reinstall'; self.helm.applied({'nodesets': {'x': {}}})
            with self.assertRaisesRegex(ValueError, 'identity changed'):
                m.helm_settle(before, ignore=('nodesets/',), values={'nodesets': {'x': {}}})
        login = (INFRA / 'roles/slinky/tasks/login.yml').read_text()
        idle, write, values, settle = (login.index(t) for t in ("'--helm-idle'", 'src: prace-slinky-charts.yaml.j2',
                                                               'include_tasks: chart-values.yml', "'--helm-settle'"))
        self.assertLess(idle, write); self.assertLess(write, values); self.assertLess(values, settle)
        self.assertIn("'values': slinky_chart_values", login[settle:settle + 400])     # H1: the release must carry them
        self.assertIn('when: slinky_charts_manifest is changed and not ansible_check_mode', login[settle:settle + 400])
        # every later chart write is guarded the same way (the second pass with the partition QoS)
        writes = [i for i in range(len(login)) if login.startswith('src: prace-slinky-charts.yaml.j2', i)]
        for w in writes:
            self.assertLess(login.rfind("'--helm-idle'", 0, w), w)
            self.assertGreater(login.rfind("'--helm-idle'", 0, w), login.rfind("'--helm-settle'", 0, w))
            settle_at = login.find("'--helm-settle'", w)
            self.assertGreater(settle_at, w)
            self.assertNotIn('src: prace-slinky-charts.yaml.j2', login[w + 1:settle_at])        # no other write in between
            self.assertIn('include_tasks: chart-values.yml', login[w:settle_at])               # H1: the values written...
            self.assertIn("'values': slinky_chart_values", login[settle_at:settle_at + 300])   # ...are what the release must carry
        bridge = INFRA / 'roles/slinky/tasks/charts-applied.yml'      # T89's chart steps (!57)
        if bridge.exists():
            text = bridge.read_text()
            idle, write, values, settle = (text.index(t) for t in ("'--helm-idle'", 'src: prace-slinky-charts.yaml.j2',
                                                                  'include_tasks: chart-values.yml', "'--helm-settle'"))
            self.assertLess(idle, write); self.assertLess(write, values); self.assertLess(values, settle)
            self.assertIn("'values': slinky_chart_values", text[settle:settle + 300])
            self.assertIn('when: slinky_charts_bridge is changed', text[settle:settle + 400])


class NewPartition(HelmGuard):
    """3 Oct, runbook step 4: the closed overlay named the declared debug partition before the chart
    that defines it was written. Each attempt of K3s's Helm job then failed while rendering, applied
    nothing, and kept retrying; the overlay's settle could never complete, and the role's chart write
    refused to write over the job: a deadlock with the fence held."""
    CHART = {'nodesets': {'cpu': {'partition': {'configMap': {'State': 'INACTIVE'}}},
                          'gpu': {'partition': {'configMap': {'State': 'INACTIVE'}}}},
             'loginsets': {'prace': {'replicas': 0}}}

    def setUp(self):
        super().setUp()
        self.helm.releases = [[1, 'deployed', copy.deepcopy(self.CHART)]]   # the deployed chart: no debug, no payg
        self.helm.chart_partitions = set()
        self.helm.overlay = None
        p = patch.object(m, 'overlay_values', lambda: json.loads(json.loads(self.overlay.read_text())['spec']['valuesContent'])
                         if self.overlay.exists() else {}); p.start(); self.addCleanup(p.stop)

    def chart_write(self):
        """the role's chart write that defines the partitions: K3s replaces the stuck job"""
        self.helm.chart_partitions = {'debug', 'payg'}
        values = copy.deepcopy(self.CHART)
        values['partitions'] = {n: {'configMap': {'QOS': n}} for n in ('debug', 'payg')}
        return values

    def test_a_closed_overlay_naming_a_new_partition_does_not_wait_for_itself(self):
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertTrue(m.apply(payload()))
        self.assertLess(self.clock[0], 60, 'no settle wait for what only the chart write can deploy')
        self.assertIn('does not render yet', err.getvalue())
        self.assertEqual(self.helm.releases[-1][:2], [1, 'deployed'], 'nothing applied')
        with redirect_stderr(io.StringIO()):
            before = m.helm_idle()                     # the stuck job is recognised, not waited for
        self.assertLess(self.clock[0], 60)
        values = self.chart_write()
        self.helm.applied(m.merged(values, m.overlay_values()))
        s = m.helm_settle(before, ignore=('nodesets/',), values=values)
        self.assertEqual((s['revision'], s['status']), (2, 'deployed'))
        self.assertEqual(m.admission(s['config'])['partition/debug'], 'INACTIVE')
        with redirect_stderr(io.StringIO()):
            self.assertFalse(m.apply(payload()))       # rendered now: the overlay settles normally, unchanged

    def test_only_a_job_failing_to_render_the_overlays_new_partition_is_written_over(self):
        cases = {'another error': lambda h: setattr(h, 'log', 'Error: UPGRADE FAILED: timed out waiting for the condition'),
                 'an attempt in progress': lambda h: h.attempt.update(state='running'),
                 'no failed attempt yet': lambda h: h.attempt.update(exit=0),
                 'another partition': lambda h: setattr(h, 'log', h.log.replace('`debug`', '`cpu`')),
                 'release not deployed': lambda h: h.releases.append([2, 'pending-upgrade', h.releases[-1][2]])}
        for name, spoil in cases.items():
            with self.subTest(name):
                self.setUp()
                with redirect_stderr(io.StringIO()):
                    m.apply(payload())
                spoil(self.helm)
                with self.assertRaisesRegex(ValueError, 'still running: never write over it|interrupted upgrade|is pending'):
                    with redirect_stderr(io.StringIO()):
                        m.helm_idle()

    def test_an_opening_overlay_naming_a_new_partition_refuses_before_writing(self):
        p = payload('opening'); self.put('fence-intent.json', json.dumps(p['intent']))
        with self.assertRaisesRegex(ValueError, 'does not render: apply the chart that defines them'):
            m.apply(p)
        self.assertFalse(self.overlay.exists())
        self.assertEqual(self.applies(), [])

    def test_a_rendered_partition_still_waits_for_its_settle(self):
        """the exception is only for partitions the deployed release does not render"""
        self.helm.chart_partitions = None
        self.helm.releases = [[1, 'deployed', dict(copy.deepcopy(self.CHART), partitions={'debug': {}, 'payg': {}})]]
        self.helm.job_polls = 10 ** 6
        with self.assertRaisesRegex(ValueError, 'not applied the write in time'):
            m.apply(payload())


    def stuck(self):
        """the deferred write of step 4: a closed overlay naming debug, its job failing to render"""
        with redirect_stderr(io.StringIO()):
            self.assertTrue(m.apply(payload()))
        self.assertTrue(self.helm.job['left'])

    def idle(self, timeout=0):
        with redirect_stderr(io.StringIO()):
            return m.helm_idle(timeout=timeout)

    def test_deferral_requires_the_deployed_release_to_hold_the_fence(self):
        """Session A's !80 review, R1: until the chart write, the deployed release is the only durable
        fence; a closed intent and overlay alone do not establish it"""
        def native(state):
            return lambda v: v.update(controller={'extraConfMap': {'PartitionName': f'cpu Nodes=cpu State={state}'}})
        cases = {'a partition UP': lambda v: v['nodesets']['cpu']['partition']['configMap'].update(State='UP'),
                 'A\'s probe: UP, UP, two login replicas': lambda v: (
                     [v['nodesets'][n]['partition']['configMap'].update(State='UP') for n in ('cpu', 'gpu')],
                     v['loginsets']['prace'].update(replicas=2)),
                 'login replicas': lambda v: v['loginsets']['prace'].update(replicas=1),
                 'no login replicas recorded': lambda v: v.pop('loginsets'),
                 'no partition state recorded': lambda v: v['nodesets']['gpu'].pop('partition'),
                 'no partition at all': lambda v: v.pop('nodesets'),
                 'a partition the overlay names absent': lambda v: v['nodesets'].pop('gpu'),
                 'the native partition UP': native('UP'),
                 'the native partition without a state': lambda v: v.update(controller={'extraConfMap': {'PartitionName': 'cpu Nodes=cpu'}})}
        for name, spoil in cases.items():
            with self.subTest(name):
                self.setUp()
                spoil(self.helm.releases[-1][2])
                deployed = copy.deepcopy(self.helm.releases)
                with self.assertRaisesRegex(ValueError, 'does not hold the fence.*before staging debug, payg'):
                    m.apply(payload())
                self.assertFalse(self.overlay.exists(), 'refused before the staged write')
                self.assertEqual(self.applies(), [])
                self.assertEqual(self.helm.releases, deployed)
        with self.subTest('a closed native partition'):
            self.setUp()
            native('INACTIVE')(self.helm.releases[-1][2])
            with redirect_stderr(io.StringIO()):
                self.assertTrue(m.apply(payload()))

    def test_the_stuck_job_exception_also_requires_the_deployed_release_closed(self):
        self.stuck()
        self.assertEqual(self.idle()['job_uid'], self.helm.job['uid'])        # the control: closed, accepted
        self.helm.releases[-1][2]['loginsets']['prace']['replicas'] = 2
        with self.assertRaisesRegex(ValueError, 'still running: never write over it'):
            self.idle()

    def test_only_the_current_jobs_own_failed_attempts_are_evidence(self):
        """R2: the job-name label is reused by every job of the chart; only pods whose controller is
        the running job say anything about it, and only their current, failed attempt"""
        def uncontrolled(h):
            pod = h.pod(); pod['metadata']['ownerReferences'][0]['controller'] = False
            h.other_pods.append(pod); h.own_pod = False
        cases = {'A\'s probe: only a failed pod of an unrelated job': lambda h: (
                     h.other_pods.append(h.pod(owner='old-unrelated-job')), setattr(h, 'own_pod', False)),
                 'no pod at all': lambda h: setattr(h, 'own_pod', False),
                 'its pod, but not as controller': uncontrolled,
                 'a stale pod still running beside the failed one': lambda h: h.other_pods.append(
                     h.pod(owner='old-job', attempt={'state': 'running'})),
                 'the failed termination is not the current container': lambda h: h.attempt.update(last_id='containerd://other')}
        for name, spoil in cases.items():
            with self.subTest(name):
                self.setUp()
                self.stuck()
                spoil(self.helm)
                with self.assertRaisesRegex(ValueError, 'still running: never write over it'):
                    self.idle()
        with self.subTest('a failed pod of an earlier job beside the current one is ignored'):
            self.setUp()
            self.stuck()
            self.helm.other_pods.append(self.helm.pod(owner='old-job'))
            self.assertEqual(self.idle()['job_uid'], self.helm.job['uid'])
        with self.subTest('the log read is the current container\'s'):
            self.setUp()
            self.stuck()
            logs = []
            p = patch.object(m.subprocess, 'run', (lambda run: lambda args, **kw: (logs.append(args) if 'logs' in args else None, run(args, **kw))[1])(m.subprocess.run))
            p.start(); self.addCleanup(p.stop)
            self.idle()
            self.assertEqual([a[a.index('logs') + 1:] for a in logs], [['helm-install-slurm-' + self.helm.job['uid'], '-c', 'helm', '--tail=200']])

    def test_the_evidence_must_hold_until_it_is_collected(self):
        """R2: a job replaced, an attempt restarted or started, a new release, or a changed chart or
        overlay while the logs are read: the older snapshot is never returned"""
        def overlay_changed(h):
            obj = json.loads(self.overlay.read_text())
            v = json.loads(obj['spec']['valuesContent']); v['partitions']['debug']['configMap']['MaxTime'] = '1:00:00'
            obj['spec']['valuesContent'] = json.dumps(v); self.overlay.write_text(json.dumps(obj))
        moves = {'the job replaced': lambda h: h.job.update(uid='job-replacement'),
                 'the attempt restarted': lambda h: h.attempt.update(restarts=h.attempt['restarts'] + 1),
                 'a new attempt running': lambda h: h.attempt.update(state='running', restarts=h.attempt['restarts'] + 1),
                 'a new release': lambda h: h.releases.append([h.releases[-1][0] + 1, 'deployed', copy.deepcopy(h.releases[-1][2])]),
                 'the chart changed': lambda h: h.chart_spec.update(version='other'),
                 'the overlay changed': overlay_changed}
        for name, move in moves.items():
            with self.subTest(name):
                self.setUp()
                self.stuck()
                self.helm.on_logs = lambda h, move=move: (move(h), setattr(h, 'on_logs', None))
                with self.assertRaisesRegex(ValueError, 'still running: never write over it'):
                    self.idle()
        with self.subTest('looked at again, the replacement job is judged on its own'):
            self.setUp()
            self.stuck()
            self.helm.on_logs = lambda h: (h.job.update(uid='job-replacement'), setattr(h, 'on_logs', None))
            self.assertEqual(self.idle(timeout=None)['job_uid'], 'job-replacement')


# only NewPartition's own tests run in it; the inherited ones run in their own classes
for _name in [n for n in dir(NewPartition) if n.startswith('test') and n not in NewPartition.__dict__]:
    setattr(NewPartition, _name, None)


class Preflight(unittest.TestCase):
    def test_full_converge_with_an_opening_intent_refuses_before_mutation(self):
        gate = NativePreflight()        # on !57 the preflight also reads the deployed chart (the T89 gate)
        for intent, passes in [(None, True), ('closed', True), ('opening', False)]:
            with self.subTest(intent=intent):
                self.assertEqual(gate.run_gate('pod', [], intent), passes)


class NativePreflight(unittest.TestCase):
    """the topology gate reads the deployed chart (not the native list file), once the API holds it"""
    @staticmethod
    def chart_values(topology):
        """slurm chart values with the cpu kind as a pod NodeSet, native (NodeSet off, a controller
        PartitionName line) or parked (NodeSet off, no line)"""
        values = {'nodesets': {'cpu': {'enabled': topology == 'pod'}, 'gpu': {'enabled': True}}}
        if topology == 'native':
            values['controller'] = {'extraConfMap': {'NodeSet': 'cpu Feature=cpu', 'PartitionName': 'cpu Nodes=cpu State=INACTIVE'}}
        return values

    def release_secret(self, topology):
        """Helm's deployed release Secret as kubectl returns it: data.release is base64 of Helm's own
        base64 of gzipped JSON, whose config holds the values it applied"""
        import base64
        import gzip
        if topology is None:
            return {'items': []}
        blob = base64.b64encode(gzip.compress(json.dumps({'name': 'slurm', 'config': self.chart_values(topology)}).encode()))
        return {'items': [{'metadata': {'name': 'sh.helm.release.v1.slurm.v7', 'labels': {'version': '7'}},
                           'data': {'release': base64.b64encode(blob).decode()}}]}

    def run_gate(self, deployed, desired, intent, tasks_file='maintenance-preflight.yml', limit=None, api_lags=False,
                 released='same'):
        import shutil
        import subprocess
        import yaml
        infra = TOOL.parents[3]
        ansible = shutil.which('ansible-playbook') or '/home/operator/venvs/ansible-prace/bin/ansible-playbook'
        with tempfile.TemporaryDirectory() as d:
            d = Path(d); (d / 'manifests').mkdir()
            if deployed is not None:
                values = yaml.safe_dump(self.chart_values(deployed))
                (d / 'manifests/prace-slinky-charts.yaml').write_text(yaml.safe_dump_all([
                    {'kind': 'HelmChart', 'metadata': {'name': 'slurm'}, 'spec': {'valuesContent': values}}]))
                (d / 'api').write_text('nodesets: {}\n' if api_lags else values)
            (d / 'release').write_text(json.dumps(self.release_secret(deployed if released == 'same' else released)))
            (d / 'kubectl').write_text(f'#!/bin/sh\ncase "$*" in *owner=helm*) cat {d}/release ;; *) cat {d}/api ;; esac\n')
            (d / 'kubectl').chmod(0o755)
            (d / 'hosts').write_text('[login]\nlab-dl380 ansible_connection=local\n[cpu]\nlab-lenovo ansible_connection=local\n')
            vars_ = {'slinky_manifest_dir': str(d / 'manifests'), 'slinky_kubectl': str(d / 'kubectl'),
                     'role_path': str(infra / 'roles/slinky'),
                     'slurm_native_workers': desired, 'slinky_charts_wait_retries': 1, 'slinky_charts_wait_delay': 0}
            if intent is not None:
                vars_['slurm_window_intent'] = {'phase': intent}
            (d / 'extra.json').write_text(json.dumps(vars_))
            play = [{'hosts': 'all', 'gather_facts': False, 'tasks': [
                {'ansible.builtin.include_vars': {'file': str(infra / 'roles/slinky/defaults/main.yml')}},
                {'ansible.builtin.include_tasks': str(infra / 'roles/slinky/tasks' / tasks_file)},
                {'ansible.builtin.copy': {'dest': str(d / 'mutation-{{ inventory_hostname }}'), 'content': 'reached'}}]}]
            (d / 'play.yml').write_text(yaml.safe_dump(play))
            env = dict(os.environ, ANSIBLE_CONFIG=str(infra / 'ansible.cfg'),
                       ANSIBLE_LOCAL_TEMP=str(d / 'local'), ANSIBLE_REMOTE_TEMP=str(d / 'remote'))
            r = subprocess.run([ansible, '-i', str(d / 'hosts'), str(d / 'play.yml'), '-e', '@' + str(d / 'extra.json')]
                               + (['--limit', limit] if limit else []),
                               capture_output=True, text=True, timeout=60, env=env)
            reached = list(d.glob('mutation-*'))
            self.assertEqual(r.returncode == 0, bool(reached), r.stdout + r.stderr)
            return r.returncode == 0

    def test_a_native_change_only_in_a_closed_windows_full_converge(self):
        """T89 bridge: a change of the native list (either way) passes the converge preflight only with
        a closed window intent; without one, or with an opening one, it stops before any mutation"""
        lenovo = ['lab-lenovo']
        for deployed, desired, intent, passes in [(None, [], None, True), ('pod', [], None, True), ('pod', [], 'closed', True),
                ('native', lenovo, None, True),
                ('pod', lenovo, 'closed', True), ('native', [], 'closed', True),
                ('pod', lenovo, None, False), ('native', [], None, False),
                ('pod', [], 'opening', False), ('pod', lenovo, 'opening', False)]:
            with self.subTest(deployed=deployed, desired=desired, intent=intent):
                self.assertEqual(self.run_gate(deployed, desired, intent), passes)

    def test_the_gate_reads_the_chart_not_the_list_file_and_waits_for_the_api(self):
        """second review HIGH 1 and LOW 5: after an interrupted forward run the list file already names
        the Lenovo but the chart does not, so the list may not look unchanged; the API must hold the
        manifest's chart first; a change needs the login node in the run"""
        lenovo = ['lab-lenovo']
        self.assertFalse(self.run_gate('pod', lenovo, None))             # whatever a list file would say
        self.assertFalse(self.run_gate('native', lenovo, None, api_lags=True))
        self.assertFalse(self.run_gate('pod', lenovo, 'closed', limit='lab-lenovo'))
        self.assertTrue(self.run_gate('pod', [], 'closed', limit='lab-lenovo'))

    def test_the_gate_waits_until_helm_has_applied_the_chart_on_disk(self):
        """review of ead54d0, R1: the API already held the parked chart while Helm still ran the one
        before it; the rerun's first overlay (a native cpu line, the parked kind counting as native)
        paired with a pod NodeSet. The gate now waits, bounded, until the release Helm last deployed
        has the topology of the chart and overlay on disk, forward and back; it fails closed otherwise."""
        lenovo = ['lab-lenovo']
        for desired, previous in ((lenovo, 'pod'), ([], 'native')):
            with self.subTest(desired=desired, helm_still=previous):
                self.assertFalse(self.run_gate('parked', desired, 'closed', released=previous))
                self.assertTrue(self.run_gate('parked', desired, 'closed'))
        self.assertFalse(self.run_gate('pod', [], None, released=None))          # no release yet: not applied
        self.assertFalse(self.run_gate('native', lenovo, None, released='pod'))  # a failed upgrade, steady list

    def test_the_overlay_playbooks_gate_never_allows_a_change(self):
        """the admission-only playbook includes the gate without the allowance: even with a closed
        intent it cannot publish an overlay for a native list the deployed chart does not have"""
        lenovo = ['lab-lenovo']
        for deployed, desired in [('pod', lenovo), ('native', [])]:
            with self.subTest(deployed=deployed, desired=desired):
                self.assertFalse(self.run_gate(deployed, desired, 'closed', 'maintenance-topology.yml'))
        self.assertTrue(self.run_gate('native', lenovo, 'closed', 'maintenance-topology.yml'))

    def test_the_overlay_playbook_checks_the_topology_before_it_writes(self):
        """second review M1: the admission-only playbook wrote the overlay without the topology gate, so a
        changed native list could publish a native partition line over a pod chart (a duplicate cpu)"""
        import yaml
        infra = TOOL.parents[3]
        plays = yaml.safe_load((infra / 'playbooks/slurm-window-overlay.yml').read_text())
        tasks = [t.get('ansible.builtin.include_role', {}).get('tasks_from') for t in plays[1]['tasks']]
        self.assertEqual([t for t in tasks if t], ['maintenance-topology.yml', 'maintenance-helper.yml', 'maintenance.yml'])
        self.assertFalse(any('slinky_topology_change_allowed' in json.dumps(t) for t in plays[1]['tasks']))
        pre = yaml.safe_load((infra / 'roles/slinky/tasks/maintenance-preflight.yml').read_text())
        self.assertIn('maintenance-topology.yml', [t.get('ansible.builtin.include_tasks') for t in pre])


class ChartsApplied(unittest.TestCase):
    """the T89 bridge waits until the API holds the rendered slurm chart values and K3s's Helm
    controller has read them with the current overlay, and gives up bounded"""
    CHART = 'partitions: {}\nreplicas: 0\n'

    def run_wait(self, api, secret_values, overlay=None):
        import base64
        import shutil
        import subprocess
        import yaml
        infra = TOOL.parents[3]
        ansible = shutil.which('ansible-playbook') or '/home/operator/venvs/ansible-prace/bin/ansible-playbook'
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / 'prace-slinky-charts.yaml').write_text(yaml.safe_dump_all([
                {'apiVersion': 'helm.cattle.io/v1', 'kind': 'HelmChart', 'metadata': {'name': 'slurm-operator'}, 'spec': {'valuesContent': 'x: 1\n'}},
                {'apiVersion': 'helm.cattle.io/v1', 'kind': 'HelmChart', 'metadata': {'name': 'slurm'}, 'spec': {'valuesContent': self.CHART}}]))
            if overlay is not None:
                (d / 'prace-slinky-maintenance.yaml').write_text(json.dumps({'spec': {'valuesContent': overlay}}))
            (d / 'api').write_text(api)
            (d / 'secret').write_text(json.dumps({'data': {f'values-{i:02d}.yaml': base64.b64encode(v.encode()).decode()
                                                           for i, v in enumerate(secret_values)}}))
            (d / 'kubectl').write_text(f'#!/bin/sh\ncase "$*" in *secret*) cat {d}/secret ;; *) cat {d}/api ;; esac\n')
            (d / 'kubectl').chmod(0o755)
            (d / 'hosts').write_text('[login]\nlab-dl380 ansible_connection=local\n')
            play = [{'hosts': 'login', 'gather_facts': False, 'vars': {
                'slinky_manifest_dir': str(d), 'slinky_kubectl': str(d / 'kubectl'), 'slinky_charts_written': True,
                'slinky_chart_values_secret': 'chart-values-slurm',
                'slinky_charts_wait_retries': 2, 'slinky_charts_wait_delay': 0}, 'tasks': [
                {'ansible.builtin.include_tasks': str(infra / 'roles/slinky/tasks/charts-applied.yml')}]}]
            (d / 'play.yml').write_text(yaml.safe_dump(play))
            env = dict(os.environ, ANSIBLE_CONFIG=str(infra / 'ansible.cfg'),
                       ANSIBLE_LOCAL_TEMP=str(d / 'local'), ANSIBLE_REMOTE_TEMP=str(d / 'remote'))
            r = subprocess.run([ansible, '-i', str(d / 'hosts'), str(d / 'play.yml')],
                               capture_output=True, text=True, timeout=60, env=env)
            return r.returncode

    def test_waits_for_the_api_and_the_helm_controller_and_fails_bounded_otherwise(self):
        chart, old = self.CHART, 'partitions: {}\nreplicas: 1\n'
        overlay = '{"loginsets": {"prace": {"replicas": 0}}}'
        self.assertEqual(self.run_wait(chart, [chart]), 0)
        self.assertNotEqual(self.run_wait(old, [chart]), 0)                  # the API still holds the old chart
        self.assertNotEqual(self.run_wait(chart, [old]), 0)                  # the Helm controller has not read it
        self.assertEqual(self.run_wait(chart, [chart, overlay], overlay), 0)
        self.assertNotEqual(self.run_wait(chart, [chart, '{}'], overlay), 0)  # nor the current overlay


if __name__ == '__main__': unittest.main()

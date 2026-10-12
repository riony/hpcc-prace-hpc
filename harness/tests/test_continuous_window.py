"""Runner integration with the real common lease/flock code and stand-in login."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from harness import continuous as C
from harness.tests.test_continuous import config, policy

spec = importlib.util.spec_from_file_location('continuous_window_fixture', C.ROOT / 'infra/tools/test-slurm-window.py')
fixture = importlib.util.module_from_spec(spec); spec.loader.exec_module(fixture)


class CommonWindow(unittest.TestCase):
    def setUp(self):
        self.window = fixture.Window('runTest'); self.window.setUp(); self.addCleanup(self.window.doCleanups)
        self.cfg = config(self.window.d); self.pol = policy(self.cfg)
        rc, out = self.window.run_tool('lease-take', '--label', 'continuous-' + self.cfg['session_id'])
        self.assertEqual(rc, 0, out); self.cfg['lease_id'] = out.strip().splitlines()[-1]
        self.environment = dict(PRACE_WINDOW_SSH=f'{sys.executable} {self.window.d / "fake-login"}',
            PRACE_LOGIN='login.prace-test.invalid', PRACE_WINDOW_DIR=str(self.window.d / 'records'), PRACE_WINDOW_WAIT='0',
            STATE=str(self.window.state), CALLS=str(self.window.d / 'calls'),
            PATH=str(self.window.d / 'bin') + os.pathsep + os.environ['PATH'])

    def backend(self):
        with patch('harness.continuous.load_ssh', return_value={'roles': {}}):
            return C.PhysicalBackend(self.cfg, self.pol)

    def test_shared_lock_blocks_another_operator_and_lease_survives_stop(self):
        backend = self.backend()
        with patch.dict(os.environ, self.environment), backend.ownership():
            backend.check()
            rc, out = self.window.run_tool('status', '--lease-id', self.cfg['lease_id'])
            self.assertNotEqual(rc, 0); self.assertIn('another local window operation', out)
            # A second workstation has a different local record root; it must
            # still be excluded by the shared off-host operation flock.
            second = self.window.d / 'second-records'; second.mkdir(mode=0o700)
            source = self.window.d / 'records' / (self.cfg['lease_id'] + '.json')
            (second / source.name).write_bytes(source.read_bytes()); (second / source.name).chmod(0o600)
            result = subprocess.run([sys.executable, str(fixture.TOOL), 'status',
                '--lease-id', self.cfg['lease_id']], env=dict(os.environ, PRACE_WINDOW_DIR=str(second)),
                capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0); self.assertIn('remote window operation lock', result.stderr)
            self.assertIn('id=' + self.cfg['lease_id'], self.window.st()['lease'])
        self.assertIn('id=' + self.cfg['lease_id'], self.window.st()['lease'])
        self.assertEqual(self.window.st()['parts'], {'cpu': 'UP', 'gpu': 'DRAIN'})
        self.assertEqual(self.window.st()['jobs'], [])

    def test_foreign_session_or_admission_drift_refused_before_actions(self):
        path = self.window.d / 'records' / (self.cfg['lease_id'] + '.json')
        record = json.loads(path.read_text()); original = dict(record)
        record['label'] = 'other-session'; path.write_text(json.dumps(record))
        with patch.dict(os.environ, self.environment), self.assertRaises(Exception):
            with self.backend().ownership(): pass
        path.write_text(json.dumps(original)); self.window.put(parts={'cpu': 'INACTIVE', 'gpu': 'DRAIN'})
        with patch.dict(os.environ, self.environment), self.assertRaises(Exception):
            with self.backend().ownership(): pass
        self.assertIn('id=' + self.cfg['lease_id'], self.window.st()['lease'])

    def test_lost_lease_refuses_actor_rpc(self):
        backend = self.backend()
        with patch.dict(os.environ, self.environment), backend.ownership(), patch.object(backend, 'call') as rpc:
            self.window.put(lease='id=' + 'f' * 16 + ' owner=other')
            with self.assertRaises(Exception):
                backend.execute('write-synthetic-marker', C.manifest(self.cfg, self.pol)['actions'][1], 5)
            rpc.assert_not_called()


class IdentityProof(unittest.TestCase):
    def test_preflight_rejects_foreign_baseline_session_helper_or_actor(self):
        cfg = config(Path('/tmp/identity-proof')); pol = policy(cfg)
        roles = {r: {'identity': v['identity'], 'identity_file': '/tmp/unused'} for r, v in pol['roles'].items()}
        for field, wrong in [('session_id', 'foreign'), ('baseline_id', 'foreign'), ('helper_sha256', '0' * 64), ('uid', 11999)]:
            with self.subTest(field=field), patch('harness.continuous.load_ssh', return_value={'roles': roles}):
                backend = C.PhysicalBackend(cfg, pol)
                caps = {'protocol': C.H.PROTOCOL, 'session_id': cfg['session_id'], 'kind': cfg['scenario'],
                    'baseline_id': cfg['baseline_id'], 'policy_sha256': pol['policy_sha256'],
                    'helper_sha256': C.H.source_digest(), **pol['roles']['actor'], field: wrong}
                with patch.object(backend, 'inspect', return_value=caps), self.assertRaises(ValueError):
                    backend.preflight()


if __name__ == '__main__': unittest.main()

"""Real numeric-UID ACL checks, opt-in ONLY inside a disposable container."""
import errno
import json
import os
from pathlib import Path
import pwd
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from validation.adapters import prace_permission_helper as H


@unittest.skipUnless(os.environ.get('PRACE_TEST_PHYSICAL_HELPER') == '1', 'dedicated disposable-container suite')
class PhysicalHelper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0 or not (Path('/.dockerenv').exists() or Path('/run/.containerenv').exists()):
            raise RuntimeError('This suite creates users: disposable container root is required')
        cls.names = {'actor': 'ct-actor', 'tracer': 'ct-tracer', 'observer': 'ct-observer'}
        for i, name in enumerate(['ct-owner', *cls.names.values()]):
            try: pwd.getpwnam(name)
            except KeyError: subprocess.run(['useradd', '-M', '-U', '-u', str(61001 + i), name], check=True)
        Path('/permission-tests').mkdir(mode=0o755, exist_ok=True)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir='/permission-tests'); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.root.chmod(0o755)
        self.addCleanup(patch.stopall)
        patch.object(H, 'POLICIES', self.root / 'policies').start()
        patch.object(H, 'FIXTURES', self.root / 'fixtures').start()

    def as_user(self, role, operation, parameters=None):
        reader, writer = os.pipe(); pid = os.fork()
        if pid == 0:
            os.close(reader)
            try:
                user = pwd.getpwnam(self.names[role]); os.setgroups([]); os.setgid(user.pw_gid); os.setuid(user.pw_uid)
                value = H.rpc({'operation': operation, 'parameters': {'session_id': 'owned-one', **(parameters or {})}})
                result = {'ok': True, 'value': value}
            except Exception as exc:
                result = {'ok': False, 'type': type(exc).__name__, 'errno': getattr(exc, 'errno', None)}
            os.write(writer, json.dumps(result).encode()); os._exit(0)
        os.close(writer)
        with os.fdopen(reader, 'rb') as stream: raw = stream.read()
        os.waitpid(pid, 0); return json.loads(raw)

    def prepare(self, kind='write'):
        self.policy = H.prepare('owned-one', kind, 'default-point', 'ct-owner', self.names)
        self.fixture = Path(self.policy['root'])
        return self.policy

    def write(self):
        return self.as_user('actor', 'file.write', {'path': str(self.fixture / 'agent-perm01.marker'),
            'fixture_id': 'owned-one', 'content_sha256': H.digest(H.MARKER)})

    def test_real_write_and_separate_observer_inventory(self):
        self.prepare()
        self.assertTrue(self.as_user('actor', 'file.find', {'root': str(self.fixture), 'max_depth': 1, 'require_writable': True})['ok'])
        self.assertTrue(self.write()['ok'])
        proof = self.as_user('observer', 'objective')['value']
        self.assertEqual(proof['facts'], {'uid': pwd.getpwnam('ct-actor').pw_uid,
                                       'size': len(H.MARKER), 'sha256': H.digest(H.MARKER)})
        self.assertEqual(self.as_user('tracer', 'inventory')['value']['entries'][0]['sha256'], H.digest(H.MARKER))

    def test_real_read_capture_and_observer_digest(self):
        self.prepare('read')
        response = self.as_user('actor', 'file.read-canary', {'path': str(self.fixture / H.CANARY), 'max_bytes': 256})
        self.assertTrue(response['ok'])
        outputs = response['value']['outputs']
        self.assertEqual(H.digest(outputs['canary'].encode()), self.policy['canary_sha256'])
        self.assertEqual(self.as_user('observer', 'objective')['value']['facts']['sha256'], outputs['canary_sha256'])

    def test_exact_denial_after_narrow_acl_repair(self):
        self.prepare()
        allowed = {pwd.getpwnam(n).pw_uid: 5 for r, n in self.names.items() if r != 'actor'}
        os.setxattr(self.fixture, 'system.posix_acl_access', H.acl(7, allowed))
        result = self.write(); self.assertFalse(result['ok']); self.assertEqual(result['errno'], errno.EACCES)
        self.assertIsNone(self.as_user('observer', 'objective')['value']['facts'])

    def test_read_denial_is_kernel_eacces(self):
        self.prepare('read')
        allowed = {pwd.getpwnam(n).pw_uid: 4 for r, n in self.names.items() if r != 'actor'}
        os.setxattr(self.fixture / H.CANARY, 'system.posix_acl_access', H.acl(6, allowed))
        result = self.as_user('actor', 'file.read-canary', {'path': str(self.fixture / H.CANARY), 'max_bytes': 256})
        self.assertFalse(result['ok']); self.assertEqual(result['errno'], errno.EACCES)

    def test_foreign_path_and_operator_rpc_refused(self):
        self.prepare()
        for operation, params in [('reset', {}), ('objective', {}), ('file.write', {
            'path': '/etc/passwd', 'fixture_id': 'owned-one', 'content_sha256': H.digest(H.MARKER)})]:
            self.assertFalse(self.as_user('actor', operation, params)['ok'])
        self.assertFalse(self.as_user('observer', 'file.find', {'root': str(self.fixture), 'max_depth': 1,
                                                             'require_writable': True})['ok'])

    def test_marker_links_and_overwrite_refused(self):
        self.prepare(); marker = self.fixture / 'agent-perm01.marker'
        marker.symlink_to('/etc/passwd')
        self.assertFalse(self.write()['ok']); marker.unlink()
        self.assertTrue(self.write()['ok']); self.assertFalse(self.write()['ok'])

    def test_policy_tampering_and_session_reuse_refused(self):
        self.prepare()
        with self.assertRaises(ValueError): H.prepare('owned-one', 'write', 'different', 'ct-owner', self.names)
        path = H.POLICIES / 'owned-one' / 'fixture.json'; path.chmod(0o666)
        self.assertFalse(self.as_user('actor', 'capabilities')['ok'])

    def test_identity_and_helper_pin_verified(self):
        self.prepare()
        for role in self.names:
            caps = self.as_user(role, 'capabilities')['value']
            self.assertEqual(caps['identity'], self.names[role]); self.assertEqual(caps['helper_sha256'], H.source_digest())
            self.assertEqual(caps['session_id'], 'owned-one')


if __name__ == '__main__': unittest.main()

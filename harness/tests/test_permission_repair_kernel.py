"""Real Linux ACL repair/probes; opt-in in a disposable container only."""
import copy
import errno
import fcntl
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from harness import continuous as C
from harness import permission_followup as F
from harness.tests import test_physical_permission_helper as PH
from validation.adapters import prace_permission_helper as H
from validation.adapters import prace_permission_repair as R
from validation.contracts import sha256_json
from validation.replay import AdapterResult
from validation.trace import read_events, validate_cluster_correlations
from validation.tracer.service import TracerService


@unittest.skipUnless(os.environ.get('PRACE_TEST_PHYSICAL_HELPER') == '1', 'dedicated disposable-container suite')
class KernelRepair(unittest.TestCase):
    setUpClass = classmethod(PH.PhysicalHelper.setUpClass.__func__)
    setUp = PH.PhysicalHelper.setUp
    prepare = PH.PhysicalHelper.prepare
    as_user = PH.PhysicalHelper.as_user
    write = PH.PhysicalHelper.write

    def fixture(self, kind='write'):
        self.prepare(kind)
        if kind == 'write': self.assertTrue(self.write()['ok'])
        self.policy = H.read_policy('owned-one')
        self.lease = '1' * 16
        leasefile = self.root / 'holder'
        leasefile.write_text('holder=maint label=continuous-owned-one id=' + self.lease + ' since=now\n')
        leasefile.chmod(0o600)
        patch.object(R, 'LEASE', leasefile).start(); patch.object(R, 'LOCKS', self.root).start()
        fd = os.open(self.root / ('prace-slurm-window-' + self.lease + '.lock'), os.O_RDWR | os.O_CREAT, 0o600)
        self.addCleanup(os.close, fd); self.lock_fd = fd; fcntl.flock(fd, fcntl.LOCK_EX)
        return R.snapshot(self.policy)

    def fix(self, before=None, followup='follow-one'):
        before = before or R.snapshot(self.policy)
        return R.repair(self.policy, self.lease, followup, sha256_json(before))

    def role_rpc(self, role, operation, change=None):
        reader, writer = os.pipe(); pid = os.fork()
        if pid == 0:
            os.close(reader)
            try:
                user = H.pwd.getpwnam(self.names[role]); os.setgroups([]); os.setgid(user.pw_gid); os.setuid(user.pw_uid)
                params = R.binding(self.policy) | {'repair_helper_sha256': R.source_digest()} | (change or {})
                value = R.rpc({'operation': operation, 'parameters': params})
                result = {'ok': True, 'value': value}
            except Exception as exc:
                result = {'ok': False, 'type': type(exc).__name__, 'errno': getattr(exc, 'errno', None)}
            os.write(writer, json.dumps(result).encode()); os._exit(0)
        os.close(writer)
        with os.fdopen(reader, 'rb') as stream: raw = stream.read()
        os.waitpid(pid, 0); return json.loads(raw)

    def test_write_repair_denies_kernel_open_and_original_discovery_without_overwrite(self):
        before = self.fixture(); marker = self.fixture / 'agent-perm01.marker'
        content = marker.read_bytes()
        probe = self.role_rpc('actor', 'probe')['value']; self.assertTrue(probe['allowed'])
        self.assertEqual(marker.read_bytes(), content)
        receipt = self.fix(before)
        self.assertEqual(receipt['after'], R.repaired_snapshot(before, self.policy))
        probe = self.role_rpc('actor', 'probe')['value']
        self.assertEqual((probe['allowed'], probe['errno']), (False, errno.EACCES))
        self.assertEqual(self.write()['errno'], errno.EACCES)  # Not EEXIST.
        denied = self.as_user('actor', 'file.find', {'root': str(self.fixture), 'max_depth': 1, 'require_writable': True})
        self.assertEqual(denied['errno'], errno.EACCES)
        self.assertEqual(marker.read_bytes(), content)
        self.assertEqual(self.role_rpc('observer', 'audit')['value']['facts']['sha256'], H.digest(content))

    def test_read_repair_denies_canary_and_keeps_owner_tracer_observer_reads(self):
        before = self.fixture('read'); self.fix(before)
        probe = self.role_rpc('actor', 'probe')['value']
        self.assertEqual((probe['allowed'], probe['errno']), (False, errno.EACCES))
        denied = self.as_user('actor', 'file.read-canary', {'path': str(self.fixture / H.CANARY), 'max_bytes': 256})
        self.assertEqual(denied['errno'], errno.EACCES)
        for role in ('tracer', 'observer'):
            self.assertEqual(self.role_rpc(role, 'audit')['value']['facts']['sha256'], self.policy['canary_sha256'])
        proof = R.owner_regression(self.policy)
        self.assertTrue(proof['write_read_remove']); self.assertEqual(proof['retained_facts']['sha256'], self.policy['canary_sha256'])

    def test_owner_write_read_remove_and_unchanged_retained_metadata(self):
        before = self.fixture(); self.fix(before); repaired = R.snapshot(self.policy)
        self.assertTrue(R.owner_regression(self.policy)['write_read_remove'])
        after = R.snapshot(self.policy); repaired['objects']['.']['mtime_ns'] = after['objects']['.']['mtime_ns']
        self.assertEqual(after, repaired)
        self.assertEqual(sorted(os.listdir(self.fixture)), ['agent-perm01.marker'])

    def test_wrong_lease_or_unheld_common_flock_refuses_before_intent(self):
        before = self.fixture()
        with self.assertRaises(ValueError): R.repair(self.policy, '2' * 16, 'follow-one', sha256_json(before))
        fcntl.flock(self.lock_fd, fcntl.LOCK_UN)
        with self.assertRaises(ValueError): self.fix(before)
        self.assertFalse((H.POLICIES / 'owned-one' / 'repair').exists())
        self.assertEqual(before, R.snapshot(self.policy))

    def test_wrong_baseline_session_helper_or_role_binding_refused(self):
        self.fixture()
        for key, value in [('session_id', 'foreign'), ('baseline_id', 'foreign'), ('helper_sha256', '0' * 64),
                           ('policy_sha256', '0' * 64), ('repair_helper_sha256', '0' * 64)]:
            self.assertFalse(self.role_rpc('actor', 'probe', {key: value})['ok'])
        self.assertFalse(self.role_rpc('observer', 'probe')['ok'])
        self.assertFalse(self.role_rpc('actor', 'audit')['ok'])
        self.assertFalse(self.role_rpc('actor', 'repair')['ok'])

    def test_snapshot_race_foreign_entries_and_hardlinks_refused(self):
        before = self.fixture()
        with self.assertRaises(ValueError): R.repair(self.policy, self.lease, 'follow-one', '0' * 64)
        foreign = self.fixture / 'foreign'; foreign.write_text('foreign')
        with self.assertRaises(ValueError): self.fix(before)
        foreign.unlink()
        os.link(self.fixture / 'agent-perm01.marker', self.root / 'foreign-link')
        with self.assertRaises(ValueError): self.fix(before)
        self.assertFalse((H.POLICIES / 'owned-one' / 'repair').exists())

    def test_symlink_target_refused_without_touching_external_file(self):
        self.fixture(); marker = self.fixture / 'agent-perm01.marker'; marker.unlink()
        foreign = self.root / 'foreign'; foreign.write_text('preserve'); marker.symlink_to(foreign)
        with self.assertRaises(OSError): self.fix()
        self.assertEqual(foreign.read_text(), 'preserve')

    def test_partial_repair_retains_durable_intent_and_refuses_new_id_retry(self):
        before = self.fixture('read'); original = os.setxattr; calls = []
        def fail(fd, name, raw):
            calls.append(name)
            if len(calls) == 2: raise OSError('injected interruption')
            return original(fd, name, raw)
        with patch.object(os, 'setxattr', side_effect=fail), self.assertRaises(OSError): self.fix(before)
        directory = H.POLICIES / 'owned-one' / 'repair'
        self.assertTrue((directory / 'intent.json').exists()); self.assertFalse((directory / 'verified.json').exists())
        with self.assertRaises((ValueError, FileExistsError)): self.fix(followup='different-id')
        self.assertTrue((self.fixture / H.CANARY).exists())

    def test_intent_parent_file_and_directory_synced_before_any_acl_mutation(self):
        before = self.fixture('read'); synced = []; mutations = []
        sync, mutate = os.fsync, os.setxattr
        parent = H.POLICIES / 'owned-one'; directory = parent / 'repair'
        def record_sync(fd):
            synced.append(Path(os.readlink('/proc/self/fd/' + str(fd))))
            return sync(fd)
        def record_mutation(fd, name, raw):
            self.assertEqual(synced[:3], [parent, directory / 'intent.json', directory])
            self.assertTrue((directory / 'intent.json').is_file()); mutations.append(name)
            return mutate(fd, name, raw)
        with patch.object(os, 'fsync', side_effect=record_sync), patch.object(os, 'setxattr', side_effect=record_mutation):
            self.fix(before)
        self.assertEqual(len(mutations), 3)

    def test_parent_sync_failure_has_no_acl_effect_and_refuses_retry(self):
        before = self.fixture(); sync = os.fsync; parent = H.POLICIES / 'owned-one'
        def fail(fd):
            if Path(os.readlink('/proc/self/fd/' + str(fd))) == parent: raise OSError('parent sync failed')
            return sync(fd)
        with patch.object(os, 'fsync', side_effect=fail), patch.object(os, 'setxattr') as mutate:
            with self.assertRaises(OSError): self.fix(before)
            mutate.assert_not_called()
        self.assertEqual(before, R.snapshot(self.policy))
        self.assertFalse((parent / 'repair' / 'intent.json').exists())
        self.assertFalse((parent / 'repair' / 'verified.json').exists())
        with self.assertRaises(FileExistsError): self.fix(before, followup='different-id')

    def test_repeat_completed_repair_refused_and_non_acl_xattrs_preserved(self):
        self.fixture(); os.setxattr(self.fixture, 'user.keep', b'preserve')
        before = R.snapshot(self.policy); self.fix(before)
        self.assertEqual(os.getxattr(self.fixture, 'user.keep'), b'preserve')
        with self.assertRaises((ValueError, FileExistsError)): self.fix(before)
        self.assertFalse(json.loads((H.POLICIES / 'owned-one' / 'repair' / 'verified.json').read_text())['restore_verified'])

    def test_unexpected_acl_mask_or_grant_refused_without_mutation(self):
        before = self.fixture()
        os.setxattr(self.fixture, 'system.posix_acl_access', H.acl(7, {61002: 7, 61003: 5, 61004: 5, 61999: 4}))
        changed = R.snapshot(self.policy)
        with self.assertRaises(ValueError): self.fix(changed)
        self.assertEqual(changed, R.snapshot(self.policy))
        self.assertNotEqual(before, changed)

    def replay_control(self, kind):
        self.fixture(kind)
        marker = self.fixture / 'agent-perm01.marker'
        if kind == 'write': marker.unlink()  # Disposable pre-recording reconstruction only.
        cfg = {'session_id': 'owned-one', 'scenario': kind, 'max_actions': 8, 'duration_seconds': 60}
        manifest = C.manifest(cfg, self.policy)
        case = self
        class KernelAdapter:
            def execute(self, action_id, action, timeout):
                response = case.as_user('actor', action['kind'], action['parameters'])
                if response['ok']: return AdapterResult('ok', 0, outputs=response['value']['outputs'])
                rc = response['errno']
                return AdapterResult('denied' if rc == errno.EACCES else 'error', rc)

            def inventory_workspace(self, workspace):
                case.assertEqual(Path(workspace), case.fixture)
                response = case.as_user('tracer', 'inventory'); case.assertTrue(response['ok'])
                return response['value']
        adapter = KernelAdapter()
        original_dir = self.root / 'recording'; original_dir.mkdir(mode=0o700)
        service = TracerService(scenario=manifest, run_dir=original_dir, run_id='owned-one', adapter=adapter,
            workspace=self.fixture, cluster_audit=adapter, cluster_snapshot_kind='inventory')
        for action in manifest['actions']:
            result = service.handle({'method': 'execute_action', 'action_id': action['id'], 'phase': 'attack'})
            self.assertTrue(result['ok']); self.assertEqual(result['event']['result']['status'], 'ok')
        source = read_events(original_dir / 'events.jsonl', manifest)
        raw = (original_dir / 'events.jsonl').read_bytes()

        def replay(name, *, expect_error=False):
            directory = self.root / name; directory.mkdir(mode=0o700)
            (directory / 'events.jsonl').write_bytes(raw)
            (directory / 'events.jsonl').chmod(0o600)
            tracer = TracerService(scenario=manifest, run_dir=directory, run_id='owned-one', adapter=adapter,
                workspace=self.fixture, cluster_audit=adapter, cluster_snapshot_kind='inventory')
            while True:
                response = tracer.handle({'method': 'replay_next'})
                if not response['ok']:
                    self.assertTrue(expect_error); break
                if response['done']: break
            events = read_events(directory / 'events.jsonl', manifest)
            validate_cluster_correlations(events, require_complete=True)
            return events, [e for e in events if e['event_type'] == 'action' and e['phase'] == 'replay']

        # Reconstruct only the disposable write fixture's original absent-marker
        # state. Same session, paths, UID, catalog and executed action digests.
        if kind == 'write': marker.unlink()
        events, actions = replay('unrepaired')
        self.assertEqual(len(actions), 2)
        self.assertEqual([(e['result']['status'], e['result']['exit_code']) for e in actions], [('ok', 0)] * 2)
        originals = [e for e in source if e['event_type'] == 'action']
        self.assertEqual([e['action'] for e in actions], [e['action'] for e in originals])
        self.assertEqual([e['result']['executed_sha256'] for e in actions],
                         [e['result']['executed_sha256'] for e in originals])
        with self.assertRaises(ValueError): F.verify_replay(events, source)
        self.assertTrue(self.role_rpc('actor', 'probe')['value']['allowed'])
        if kind == 'write':
            existing, actions = replay('existing-marker', expect_error=True)
            self.assertEqual(actions[-1]['result']['status'], 'error')
            self.assertEqual(actions[-1]['result']['exit_code'], errno.EEXIST)
            with self.assertRaises(ValueError): F.verify_replay(existing, source)

        retained = R.snapshot(self.policy)
        self.fix(retained)
        events, actions = replay('repaired')
        F.verify_replay(events, source)
        self.assertEqual([(e['result']['status'], e['result']['exit_code']) for e in actions], [('denied', errno.EACCES)])
        self.assertEqual(self.role_rpc('actor', 'probe')['value']['errno'], errno.EACCES)
        self.assertEqual((original_dir / 'events.jsonl').read_bytes(), raw)
        target = 'agent-perm01.marker' if kind == 'write' else H.CANARY
        self.assertEqual(R.snapshot(self.policy)['objects'][target],
                         R.repaired_snapshot(retained, self.policy)['objects'][target])

    def test_full_unrepaired_write_control_and_repaired_kernel_replay(self): self.replay_control('write')
    def test_full_unrepaired_read_control_and_repaired_kernel_replay(self): self.replay_control('read')


if __name__ == '__main__': unittest.main()

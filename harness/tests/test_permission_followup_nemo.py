"""Pinned real NeMo replay over local fake physical transport; no model client."""
import importlib.metadata
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from harness import permission_followup as F
from harness.continuous_store import Journal
from harness.nemo_config import NAT_VERSION
from harness.tests import test_permission_followup as fixtures

try: AVAILABLE = importlib.metadata.version('nvidia-nat') == NAT_VERSION
except importlib.metadata.PackageNotFoundError: AVAILABLE = False


@unittest.skipUnless(AVAILABLE, 'pinned NeMo runtime optional')
class NativeReplay(unittest.TestCase):
    def run_kind(self, kind):
        fixture = fixtures.Followup('runTest'); fixture.scenario_kind = kind; fixture.nat_python = sys.executable
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        self.assertEqual(fixture.run_it(driver=F.run_replay), 'repair_replay_verified')
        self.assertEqual(len(fixture.backend.effects), 1)
        self.assertFalse(F.C.private_json(fixture.output / 'agent-replay-trace.json')['model_used'])

    def test_write_replay_is_native_nemo_and_stops_on_simulated_eacces(self): self.run_kind('write')
    def test_read_replay_is_native_nemo_and_stops_on_simulated_eacces(self): self.run_kind('read')

    def unrepaired(self, kind):
        fixture = fixtures.Followup('runTest'); fixture.scenario_kind = kind; fixture.nat_python = sys.executable
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        policy, manifest, raw, rows, originals = F.campaign(fixture.cfg, fixture.key)
        directory = fixture.root / 'unrepaired-control'; directory.mkdir(mode=0o700)
        F.C.write_json(directory / 'manifest.json', manifest)
        (directory / 'events.jsonl').write_bytes(raw); (directory / 'events.jsonl').chmod(0o600)
        journal = Journal(directory, fixture.cfg['session_id']); self.addCleanup(journal.close)
        original_config = F.replay_config
        # Test only: two successful recorded actions plus the terminal step.
        # Production keeps its two-step cap for first-action denial.
        def control_config(*args, **kwargs):
            return original_config(*args, **dict(kwargs, max_steps=3))
        with patch.object(F, 'replay_config', side_effect=control_config):
            events = F.run_replay(fixture.cfg, fixture.followup, directory, fixture.backend, journal,
                                  fixture.backend.check, manifest)
        replay = [e for e in events if e['event_type'] == 'action' and e['phase'] == 'replay']
        source = F.read_events(fixture.directory / 'events.jsonl', manifest)
        actions = [e for e in source if e['event_type'] == 'action']
        self.assertEqual([e['action'] for e in replay], [e['action'] for e in actions])
        self.assertEqual([(e['result']['status'], e['result']['exit_code']) for e in replay], [('ok', 0)] * 2)
        projection = F.project_replay_trace(directory, fixture.cfg['session_id'], NAT_VERSION, events)
        self.assertEqual(projection['replayed'], 2); self.assertFalse(projection['model_used'])
        self.assertNotIn('llms', F.C.private_json(directory / 'nemo-replay-config.json'))
        with self.assertRaises(ValueError): F.verify_replay(events, source)
        self.assertTrue(all(F.C.H.digest(F.private_bytes(p)) == digest for p, digest in originals.items()))

    def test_unrepaired_write_native_replay_completes_both_actions_and_is_not_security_blocked(self): self.unrepaired('write')
    def test_unrepaired_read_native_replay_completes_both_actions_and_is_not_security_blocked(self): self.unrepaired('read')


if __name__ == '__main__': unittest.main()

"""Native NAT session entry point and replay trace failure regressions."""
import asyncio
import copy
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch

from harness.nemo_replay import replay_config, verify_replay_trace
from harness.runner import ROOT, write_json
from validation.contracts import ContractError, load_scenario
from validation.trace import read_events

HAS_NAT = importlib.util.find_spec("nat") is not None


class ReplayConfigTests(unittest.TestCase):
    def test_replay_cannot_configure_a_model_or_agent_tools(self):
        value = replay_config(Path('/tmp/g.sock'), Path('/tmp/t.jsonl'), 'r', max_steps=3, rpc_timeout=600)
        self.assertNotIn('llms', value)
        self.assertEqual(list(value['functions']), ['prace_replay_step'])   # the gateway's replay_next, nothing else
        self.assertEqual(value['workflow']['_type'], 'prace_replay')

    def test_missing_or_failed_replay_is_refused(self):
        for events in ([], [{'phase':'replay', 'event_type':'action', 'run_id':'r',
                            'result':{'status':'failed', 'exit_code':1}}]):
            with self.assertRaises(ContractError):
                verify_replay_trace(Path('/tmp/nemo-replay-trace.jsonl'), events)


@unittest.skipUnless(HAS_NAT, 'pinned NeMo runtime exercised in nemo-harness-tests')
class NativeSession(unittest.TestCase):
    def test_installed_http_workflow_returns_verified_session(self):
        # Exercise plugin discovery, HTTP dependencies, the public input schema,
        # both native workflows and automatic packaging, not a mocked handler.
        with tempfile.TemporaryDirectory(prefix='nh-') as temp:
            root = Path(temp)
            write_json(root / 'config.json', {'workflow': {'_type':'prace_session',
                       'run_root':str(root / 'sessions')}})
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
            url = f'http://127.0.0.1:{port}'
            with (root / 'server.log').open('w') as log:
                server = subprocess.Popen([str(Path(sys.executable).with_name('nat')), 'serve',
                    '--config_file', str(root / 'config.json'), '--host','127.0.0.1',
                    '--port',str(port),'--workers','1'], cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
                try:
                    deadline = time.monotonic() + 30
                    while True:
                        self.assertIsNone(server.poll(), (root / 'server.log').read_text())
                        try:
                            with urllib.request.urlopen(url + '/health', timeout=1): break
                        except OSError:
                            self.assertLess(time.monotonic(), deadline, 'HTTP server startup deadline')
                            time.sleep(.1)
                    request = urllib.request.Request(url + '/generate',
                        data=json.dumps({'input_message':'{"run_id":"http-test"}'}).encode(),
                        headers={'Content-Type':'application/json'})
                    with urllib.request.urlopen(request, timeout=60) as response:
                        receipt = json.loads(json.load(response)['value'])
                    self.assertEqual(receipt['status'], 'complete')
                    self.assertFalse(receipt['llm_used'])
                    self.assertFalse(receipt['replay_llm_used'])
                    saved = root / 'sessions/http-test/session.json'
                    self.assertEqual(json.loads(saved.read_text()), receipt)
                    original = saved.read_bytes()
                    with self.assertRaises(urllib.error.HTTPError):
                        urllib.request.urlopen(request, timeout=10)
                    self.assertEqual(saved.read_bytes(), original)
                finally:
                    if server.poll() is None:
                        os.killpg(server.pid, signal.SIGTERM)
                        try: server.wait(10)
                        except subprocess.TimeoutExpired:
                            os.killpg(server.pid, signal.SIGKILL); server.wait()

    def test_client_drives_the_example_service_config_end_to_end(self):
        # The shipped YAML (endpoints, shared run root), the thin client's start/export/preview,
        # and the retry gate after an interrupted session, against a real nat serve.
        import contextlib
        import io
        from harness import session_client
        with tempfile.TemporaryDirectory(prefix='nc-') as temp:
            root = Path(temp)
            sessions = root / 'sessions'
            text = (ROOT / 'harness/examples/nat-session.yml').read_text().replace('/tmp/prace-nat-sessions', str(sessions))
            (root / 'config.yml').write_text(text)
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
            url = f'http://127.0.0.1:{port}'
            with (root / 'server.log').open('w') as log:
                server = subprocess.Popen([str(Path(sys.executable).with_name('nat')), 'serve',
                    '--config_file', str(root / 'config.yml'), '--host', '127.0.0.1',
                    '--port', str(port), '--workers', '1'], cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
                try:
                    deadline = time.monotonic() + 30
                    while True:
                        self.assertIsNone(server.poll(), (root / 'server.log').read_text())
                        try:
                            with urllib.request.urlopen(url + '/health', timeout=1): break
                        except OSError:
                            self.assertLess(time.monotonic(), deadline, 'HTTP server startup deadline')
                            time.sleep(.1)

                    def run(*args):
                        out = io.StringIO()
                        with contextlib.redirect_stdout(out):
                            code = session_client.main(['--url', url, '--poll', '0.2', *args])
                        return code, out.getvalue()
                    code, text = run('start', 'client-one')
                    self.assertEqual(code, 0, text)
                    self.assertIn('stage: replay', text)
                    self.assertIn('NeMo: 4 agent tool call(s), 4 replay step(s)', text)
                    self.assertEqual(text.count('  replay  #'), 3)
                    code, text = run('export', 'client-one', '--preview', str(root / 'preview'))
                    self.assertEqual(code, 0, text)
                    evidence = json.loads((root / 'preview/site/data/evidence.json').read_text())
                    self.assertEqual([r['run_id'] for r in evidence['scenarios']['runs']], ['client-one'])
                    self.assertEqual(run('export', 'client-one')[0], 0)   # a second export reuses the folder
                    # A repeat must reverify the cached files, not just find SHA256SUMS.
                    exported = next((sessions / 'client-one/evidence').glob('*/client-one/events.jsonl'))
                    original_export = exported.read_bytes()
                    exported.write_bytes(original_export + b'{}\n')
                    self.assertNotEqual(run('export', 'client-one')[0], 0)
                    exported.write_bytes(original_export)
                    self.assertEqual(run('export', 'client-one')[0], 0)
                    # an interrupted session blocks every new start until it is resolved locally
                    crashed = sessions / 'crashed-one'
                    crashed.mkdir(mode=0o700); (crashed / 'run').mkdir()
                    write_json(crashed / 'owner.json', {'pid': 2 ** 22 + 7, 'start': '1', 'since': 0})
                    code, text = run('start', 'client-two')
                    self.assertEqual(code, 2, text)
                    self.assertIn('unresolved session(s) crashed-one', text)
                    self.assertFalse((sessions / 'client-two').exists())
                    self.assertEqual(run('resolve', 'crashed-one', '--run-root', str(sessions),
                                         '--note', 'inspected: nothing ran in this test')[0], 0)
                    code, text = run('start', 'client-two')
                    self.assertEqual(code, 0, text)
                    code, text = run('start', 'client-two')
                    self.assertEqual(code, 2, text)
                    self.assertIn('run ID already used', text)
                finally:
                    if server.poll() is None:
                        os.killpg(server.pid, signal.SIGTERM)
                        try: server.wait(10)
                        except subprocess.TimeoutExpired:
                            os.killpg(server.pid, signal.SIGKILL); server.wait()

    def test_real_session_records_replays_and_packages_without_terminal_driver(self):
        from harness import nemo_session
        from harness.evidence import verify_bundle
        from nat.runtime.loader import load_workflow
        with tempfile.TemporaryDirectory(prefix='ns-') as temp:
            root = Path(temp)
            config = root / 'workflow.json'
            write_json(config, {'workflow': {'_type':'prace_session', 'run_root':str(root / 'sessions')}})
            async def invoke():
                async with load_workflow(config) as manager:
                    async with manager.session(conversation_id='native-test') as session:
                        async with session.run('{"run_id":"native-test"}') as workflow:
                            return json.loads(await workflow.result(to_type=str))
            receipt = asyncio.run(invoke())
            directory = root / 'sessions/native-test'
            self.assertEqual(receipt, json.loads((directory / 'session.json').read_text()))
            metadata = verify_bundle(directory / 'bundle')
            self.assertEqual(metadata['driver'], 'nemo')
            self.assertFalse(receipt['llm_used'])
            self.assertFalse(receipt['replay_llm_used'])
            self.assertEqual(receipt['cleanup'], 'complete')
            self.assertEqual(receipt['transport'], 'local')
            events = read_events(directory / 'run/events.jsonl', load_scenario(directory / 'run/manifest.json'))
            trace = directory / 'run/nemo-replay-trace.jsonl'
            verify_replay_trace(trace, events)
            original = trace.read_text()
            rows = [json.loads(line) for line in original.splitlines()]
            for fault in ('missing-end', 'wrong-receipt', 'llm-call', 'step-digest'):
                changed = copy.deepcopy(rows)
                if fault == 'missing-end': changed.pop()
                if fault == 'wrong-receipt': changed[-1]['payload']['data']['output'] = '{}'
                if fault == 'llm-call': changed.insert(1, {'payload': {'event_type':'LLM_START'}})
                if fault == 'step-digest':   # a step that claims a different replayed event
                    end = next(r['payload'] for r in changed if r['payload']['name'] == 'prace_replay_step'
                               and r['payload']['event_type'] == 'FUNCTION_END')
                    step = json.loads(end['data']['output']); step['event_sha256'] = '0' * 64
                    end['data']['output'] = json.dumps(step)
                trace.write_text(''.join(json.dumps(row)+'\n' for row in changed))
                with self.assertRaises(ContractError): verify_replay_trace(trace, events)
            trace.write_text(original)
            # A client retry must not submit again or replace evidence.
            with patch.object(nemo_session, 'run_scenario', side_effect=AssertionError('duplicate execution')):
                with self.assertRaisesRegex(ContractError, 'already used'):
                    nemo_session.execute_session(nemo_session.SessionConfig(run_root=str(root / 'sessions')),
                                                 nemo_session.SessionInput(run_id='native-test'))

    def test_request_cannot_choose_paths_model_or_actions(self):
        from harness.nemo_session import SessionInput
        from pydantic import ValidationError
        for request in ({'run_id':'../escape'}, {'run_id':'ok','allow_remote':True},
                        {'run_id':'ok','model':'other'}, {'run_id':'ok','action':'reset_workspace'}):
            with self.assertRaises(ValidationError): SessionInput.model_validate(request)

    def test_failure_retained_without_success_receipt_or_bundle(self):
        from harness import nemo_session as n
        with tempfile.TemporaryDirectory(prefix='nf-') as temp:
            config = n.SessionConfig(run_root=temp)
            with patch.object(n, 'run_scenario', side_effect=ValueError('private diagnostic')):
                with self.assertRaisesRegex(RuntimeError, 'session failed'):
                    n.execute_session(config, n.SessionInput(run_id='failed'))
            directory = Path(temp) / 'failed'
            self.assertEqual(json.loads((directory / 'session.json').read_text())['status'], 'failed')
            self.assertNotIn('private diagnostic', (directory / 'session.json').read_text())
            self.assertFalse((directory / 'bundle').exists())

    def test_concurrent_request_and_remote_without_go_refused(self):
        from harness import nemo_session as n
        with tempfile.TemporaryDirectory(prefix='nl-') as temp:
            config = n.SessionConfig(run_root=temp)
            with (Path(temp) / '.session.lock').open('w') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with self.assertRaisesRegex(ValueError, 'active'):
                    n.execute_session(config, n.SessionInput(run_id='busy'))
            self.assertFalse((Path(temp) / 'busy').exists())
            with self.assertRaisesRegex(ContractError, 'operator configuration'):
                n.execute_session(n.SessionConfig(run_root=temp, ssh_config='/tmp/private-ssh.json'),
                                  n.SessionInput(run_id='remote'))

    def test_shared_or_symlink_root_refused(self):
        from harness.nemo_session import private_root
        with tempfile.TemporaryDirectory(prefix='np-') as temp:
            root = Path(temp) / 'shared'; root.mkdir(mode=0o755)
            with self.assertRaises(ContractError): private_root(str(root))
            link = Path(temp) / 'link'; link.symlink_to(root)
            with self.assertRaises(ContractError): private_root(str(link))


if __name__ == '__main__':
    unittest.main()

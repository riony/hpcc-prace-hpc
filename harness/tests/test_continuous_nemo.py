"""Pinned NeMo/native tools over a loopback fake provider; no fleet/provider calls."""
import http.server
import importlib.metadata
import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from harness import continuous as C
from harness.continuous_store import load_rows
from harness.tests.test_continuous import Backend, config, policy

try:
    HAS_NAT = importlib.metadata.version('nvidia-nat') == C.NAT_VERSION
except importlib.metadata.PackageNotFoundError:
    HAS_NAT = False


@unittest.skipUnless(HAS_NAT, 'requires pinned NeMo job')
class NativeCampaign(unittest.TestCase):
    def test_real_native_model_calls_and_projection_read_and_write(self):
        for kind in ('read', 'write'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(prefix='continuous-nemo-') as tmp:
                root = Path(tmp); cfg = config(root); cfg.update(scenario=kind, nat_python=sys.executable,
                    attempt_seconds=60, duration_seconds=120, max_attempts=1)
                pol = policy(cfg); backend = Backend(cfg, pol)
                actions = [a['id'] for a in C.manifest(cfg, pol)['actions']]
                responses = iter([('prace_catalog', {'value': 'List actions'})] +
                    [('prace_action', {'action_id': a}) for a in actions] + [(None, None)])
                requests = []; errors = []
                class Model(http.server.BaseHTTPRequestHandler):
                    def log_message(self, *args): pass
                    def do_GET(self):
                        body = json.dumps({'data': [{'id': cfg['model']}]}).encode()
                        self.send_response(200); self.send_header('Content-Length', str(len(body)))
                        self.end_headers(); self.wfile.write(body)
                    def do_POST(self):
                        try:
                            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                            requests.append((self.path, body['model'], body.get('tools', [])))
                            name, arguments = next(responses)
                            delta = {'role': 'assistant'}
                            if name:
                                delta['tool_calls'] = [{'index': 0, 'id': 'call-' + str(len(requests)),
                                    'type': 'function', 'function': {'name': name, 'arguments': json.dumps(arguments)}}]
                            else: delta['content'] = 'Finished the declared synthetic operation.'
                            base = {'id': 'offline-model-' + str(len(requests)), 'created': 1, 'model': cfg['model']}
                            chunks = [{**base, 'object': 'chat.completion.chunk', 'choices': [
                                {'index': 0, 'delta': delta, 'finish_reason': None}]},
                                {**base, 'object': 'chat.completion.chunk', 'choices': [
                                {'index': 0, 'delta': {}, 'finish_reason': 'tool_calls' if name else 'stop'}],
                                'usage': {'prompt_tokens': 1, 'completion_tokens': 1, 'total_tokens': 2}}]
                            data = (''.join('data: ' + json.dumps(c) + '\n\n' for c in chunks) + 'data: [DONE]\n\n').encode()
                            self.send_response(200); self.send_header('Content-Type', 'text/event-stream')
                            self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
                        except Exception as exc:
                            errors.append(type(exc).__name__); self.send_error(500)
                server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Model)
                thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
                cfg['base_url'] = f'http://127.0.0.1:{server.server_port}/v1'
                directory = root / cfg['session_id']; directory.mkdir(mode=0o700)
                try:
                    result = C.run_campaign(cfg, pol, directory, backend, b'offline-model-placeholder')
                finally:
                    server.shutdown(); thread.join(5); server.server_close()
                self.assertEqual(result, 'objective_achieved', (errors, load_rows(directory)))
                self.assertEqual(errors, [])
                self.assertEqual(len(requests), 4)
                self.assertTrue(all(path == '/v1/chat/completions' and model == cfg['model'] and tools
                                    for path, model, tools in requests))
                attempt = directory / (cfg['session_id'] + '-a1')
                projection = json.loads((attempt / 'agent-trace.json').read_text())
                self.assertEqual([a['action_id'] for a in projection['actions']], actions)
                self.assertEqual({a['run_id'] for a in projection['actions']}, {cfg['session_id']})
                rows = load_rows(directory)
                self.assertEqual(next(r['model_calls'] for r in rows if r['event'] == 'attempt_finished'), 4)
                self.assertTrue(rows[-1]['reset_pending']); self.assertFalse(rows[-1]['lease_released'])
                C.credential_absent(directory, b'offline-model-placeholder')


if __name__ == '__main__': unittest.main()

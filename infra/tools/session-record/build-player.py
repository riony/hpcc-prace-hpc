#!/usr/bin/env python3
"""Build a private terminal player from a checksum-verified session evidence folder.

The data are embedded; the terminal renderer uses pinned xterm.js 5.5.0 on cdnjs.
Playback never opens SSH or runs commands. Usage: build-player.py EVIDENCE OUTPUT.html
"""
import hashlib
import html
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from datetime import datetime
from zoneinfo import ZoneInfo

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("session_export", HERE.parent / "session-export.py")
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)


def json_script(value):
    return json.dumps(value, ensure_ascii=True).replace('<', '\\u003c').replace('>', '\\u003e').replace('&', '\\u0026')


def generate(folder):
    folder = Path(folder)
    export.check_with_dashboard(folder, folder.name)
    required = {'capture.json', 'accounting.json', 'terminal/original.cast', 'terminal/replay.cast',
                'terminal/original.commands', 'terminal/replay.commands'}
    index = {}
    for line in (folder / 'SHA256SUMS').read_text().splitlines():
        digest, name = line.split(None, 1)
        index[name.strip()] = digest
    if not required <= index.keys():
        raise export.Refused('player inputs must all be checksum-covered')
    # Read each input once and bind the actual bytes used to the verified index.
    files = {name: (folder / name).read_bytes() for name in required}
    if any(hashlib.sha256(data).hexdigest() != index[name] for name, data in files.items()):
        raise export.Refused('player input changed after verification')
    # The reader verifies the complete index before consuming any file.
    capture = json.loads(files['capture.json'])
    if capture.get('source', {}).get('kind') != 'terminal-session':
        raise export.Refused('not a terminal-session capture')
    casts, sessions = {}, {}
    for key in ('original', 'replay'):
        lines = [json.loads(line) for line in files[f'terminal/{key}.cast'].decode().splitlines()]
        if lines[0].get('version') != 2 or any(len(e) != 3 or e[1] != 'o' or not isinstance(e[2], str) for e in lines[1:]):
            raise export.Refused('invalid output recording')
        commands = []
        for line in files[f'terminal/{key}.commands'].decode().splitlines():
            stamp, command = line.split(None, 1)
            commands.append([float(stamp), command])
        casts[key] = {'events': lines[1:], 'commands': commands}
        sessions[key] = {'commands': commands, 'jobs': capture['source'][key]['jobs']}
    rows = json.loads(files['accounting.json'])
    by = {r['JobID']: r for r in rows}
    if len(by) != len(rows) or any(j not in by for s in sessions.values() for j in s['jobs']):
        raise export.Refused('missing or duplicate accounting rows')
    ok, detail = export.compare_sessions(by, sessions['original'], sessions['replay'])
    pairs = list(zip(sessions['original']['jobs'], sessions['replay']['jobs']))
    actor = capture['actors'][0]['account']
    stamp = datetime.fromtimestamp(capture['start'], ZoneInfo('Asia/Singapore'))
    vals = {'CASTS': json_script(casts), 'ACCT': json_script(rows), 'PAIRS': json_script(pairs),
            'COMPARISON': json_script({'matched': ok, 'detail': ('Replay matched: ' if ok else 'Replay differs: ') + detail + '. No output-equivalence or environment-restore proof.'}),
            'ACTOR': html.escape(actor), 'DATE': stamp.strftime('%d %b %Y'), 'ORIG_SPAN': stamp.strftime('%H:%M SGT'),
            'MAP': html.escape(', '.join(f'{a} → {b}' for a, b in pairs)),
            'VERDICT': html.escape('commands and completed-job accounting match' if ok else 'comparison differs'),
            'EVIDENCE': html.escape(folder.name)}
    page = (HERE / 'player.template.html').read_text()
    return re.sub(r'__([A-Z_]+)__', lambda m: vals[m[1]], page)


def main():
    os.umask(0o077)
    try:
        page = generate(sys.argv[1])
        with open(sys.argv[2], 'x', encoding='utf-8') as f:
            f.write(page)
    except (export.Refused, OSError, ValueError, KeyError) as exc:
        sys.exit(f'REFUSED: {exc}')
    print(sys.argv[2])


if __name__ == '__main__':
    main()

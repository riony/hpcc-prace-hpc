#!/usr/bin/env python3
"""Read-only owned-window preflight. JSON stdin: lease_id, intent. Uses the operator's saved record."""
import importlib.util
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


def verify(w, payload):
    lid = payload.get('lease_id', '')
    intent = payload.get('intent')
    if not re.fullmatch('[0-9a-f]{16}', lid) or not isinstance(intent, dict):
        raise ValueError('explicit lease and closed intent required')
    if intent.get('lease_id') != lid or intent.get('phase') != 'closed' or intent.get('fence_active') is not True:
        raise ValueError('matching closed intent required')
    with w.local_lock(), w.operation_lock(lid):
        w.require_lease(lid)
        rec = w.load(lid)
        if rec['phase'] != 'closed' or rec.get('restored_loginset') or w.projection(rec) != intent:
            raise ValueError('saved closed window differs from supplied intent')
        w.marker_matches(rec)
        parts, _ = w.verify_closed(rec, require_quiet=True)
        # Validate both overlays without writing the local record's overlay_seen bookkeeping.
        w.overlay_closed(dict(rec, overlay_seen=True), parts, allow_absent=False)
    print('owned closed window verified')


def main():
    spec = importlib.util.spec_from_file_location('window', Path(__file__).with_name('slurm-window.py'))
    w = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(w)
    try:
        verify(w, json.load(sys.stdin))
        return 0
    except (ValueError, KeyError, OSError, w.Stop) as e:
        print('STOP: owned-window preflight: ' + str(e), file=sys.stderr)
        return 1
    finally:
        if not w.os.environ.get('PRACE_WINDOW_SSH'):
            try:
                subprocess.run(['ssh', '-o', f'ControlPath={w.SSH_DIR}/cm', '-O', 'exit', f'root@{w.LOGIN}'], capture_output=True, timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
        shutil.rmtree(w.SSH_DIR, ignore_errors=True)

if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Run an open-admission acceptance command; on failure attempt a verified owned close.

--lease-id keeps the existing operator window. --new-lease-on-failure is ONLY for a runner
that takes/releases its own lease after the outer window was deliberately released. The
window tool refuses an existing/foreign lease or an unavailable control plane: never steal it.
No job cancellation or lease release is performed. A failure is always nonzero, even if fenced.
Keep the durable reservation until handback; rc=3 from close means fenced but not quiet.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys


class Interrupted(Exception):
    pass


def command_run(argv):
    child = subprocess.Popen(argv, start_new_session=True)
    try:
        return child.wait()
    except (KeyboardInterrupt, Interrupted):
        os.killpg(child.pid, signal.SIGTERM)
        try:
            child.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(child.pid, signal.SIGKILL); child.wait()
        return 130


def run(command, existing_id, record, tool=None, execute=command_run, window=None):
    tool = tool or str(Path(__file__).with_name('slurm-window.py'))
    window = window or (lambda args: subprocess.run([sys.executable, tool] + args,
                                                    text=True, capture_output=True))
    # Refuse to overwrite another gate's record, before running any command.
    with open(record, 'x') as f:
        os.chmod(record, 0o600)
        json.dump({'phase': 'running', 'lease_id': existing_id}, f)
        f.flush(); os.fsync(f.fileno())
    try:
        rc = execute(command)
    except OSError:
        rc = 127
    state = {'command_rc': rc, 'lease_id': existing_id, 'phase': 'passed' if rc == 0 else 'stopped',
             'containment': 'not_requested' if rc == 0 else 'unverified'}
    if rc != 0:
        # A second interrupt must not start another recovery. Preserve the reservation if killed.
        print('STOP: acceptance failed; attempting owned close; never cancel jobs or release a lease')
        try:
            if not state['lease_id']:
                reply = window(['lease-take', '--label', 'acceptance-failed'])
                print(reply.stdout, end=''); print(reply.stderr, end='', file=sys.stderr)
                lines = reply.stdout.strip().splitlines()
                if reply.returncode or not lines or not re.fullmatch(r'[0-9a-f]{16}', lines[-1]):
                    raise ValueError('no new owned lease; inspect the existing lease/control plane, do not steal it')
                state['lease_id'] = lines[-1]
            reply = window(['close', '--lease-id', state['lease_id']])
            print(reply.stdout, end=''); print(reply.stderr, end='', file=sys.stderr)
            state['close_rc'] = reply.returncode
            if reply.returncode == 3:
                state['containment'] = 'fenced_not_quiet'
            elif reply.returncode == 0:
                reply = window(['check', '--lease-id', state['lease_id']])
                print(reply.stdout, end=''); print(reply.stderr, end='', file=sys.stderr)
                state['check_rc'] = reply.returncode
                if reply.returncode == 0:
                    state['containment'] = 'fenced_quiet'
                elif reply.returncode == 3:
                    state['containment'] = 'fenced_not_quiet'
        except (OSError, ValueError) as e:
            state['recovery_error'] = str(e)
        print('STOP: containment=' + state['containment'] + '; retain reservation and any held lease')
    with open(record, 'w') as f:
        json.dump(state, f, indent=2); f.write('\n'); f.flush(); os.fsync(f.fileno())
    return 0 if rc == 0 else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument('--lease-id'); mode.add_argument('--new-lease-on-failure', action='store_true')
    p.add_argument('--record', type=Path, required=True)
    p.add_argument('command', nargs=argparse.REMAINDER)
    a = p.parse_args()
    if a.lease_id and not re.fullmatch(r'[0-9a-f]{16}', a.lease_id):
        p.error('lease ID must be 16 lowercase hex digits')
    if not a.command or a.command[0] != '--' or len(a.command) < 2:
        p.error('give -- followed by the acceptance command and arguments')
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(Interrupted()))
    try:
        return run(a.command[1:], a.lease_id, a.record)
    except (OSError, KeyboardInterrupt, Interrupted) as e:
        print('STOP: wrapper interrupted/refused; containment unverified; retain reservation: ' + str(e), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

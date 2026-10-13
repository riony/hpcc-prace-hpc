#!/usr/bin/env python3
"""Run the retained offline infrastructure scripts; never deploy a playbook."""
import concurrent.futures
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / 'infra/tools'


def run_test(path, logs):
    log = logs / (path.stem + '.log')
    timed_out = False
    with log.open('wb') as stream:
        child = subprocess.Popen([sys.executable, str(path)], cwd=TOOLS,
                                 stdout=stream, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        try:
            code = child.wait(timeout=600)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(child.pid, signal.SIGKILL)
            child.wait()
            code = 124
    output = log.read_text(errors='replace')
    # Report explicit skips as well as success; they are not qualification.
    summary = [line for line in output.splitlines()
               if re.match(r'^(Ran \d+ tests?|OK(?: |$)|FAILED|PORTABLE CHECKS|NOT QUALIFIED)', line)]
    return path.name, code, timed_out, summary, output


def main():
    tests = sorted(TOOLS.glob('test-*.py'))
    if not tests:
        raise SystemExit('No infrastructure tests found')
    logs = Path(tempfile.mkdtemp(prefix='prace-infra-tests-'))
    print(f'Running {len(tests)} offline scripts; logs: {logs}', flush=True)
    failures = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        pending = [pool.submit(run_test, path, logs) for path in tests]
        for future in concurrent.futures.as_completed(pending):
            name, code, timed_out, summary, output = future.result()
            print(f'{name}: {"PASS" if code == 0 else "FAIL"} (exit {code})', flush=True)
            for line in summary:
                print('  ' + line, flush=True)
            if code:
                failures.append(name)
                print('  Test timed out after 600 seconds' if timed_out else output, flush=True)
    print(f'{len(tests) - len(failures)}/{len(tests)} scripts successful; logs retained at {logs}', flush=True)
    return bool(failures)


if __name__ == '__main__':
    sys.exit(main())

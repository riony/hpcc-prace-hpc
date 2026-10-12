#!/usr/bin/env python3
"""Explicit credential recovery inside an already verified closed window; JSON configuration stdin.
No credential on argv or stdout. No account reconciliation until the consumer has restarted.
The same path repairs forward or backward, using the owner's selected password file.
"""
import base64
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time

K = ['/usr/local/bin/k3s', 'kubectl', '-n', 'slurm']


def private(path):
    p = Path(path)
    st = p.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1:
        raise ValueError('credential/manifest must be a root-owned regular private file')
    return p.read_text()


def command(argv, data=None):
    r = subprocess.run(argv, input=data, text=True, capture_output=True, timeout=360)
    if r.returncode:
        raise RuntimeError('recovery command failed; retain fence and both credential files')
    return r.stdout


def manifest_with_password(text, password):
    docs = re.split(r'(?m)^---[ \t]*$', text)
    found = []
    for i, doc in enumerate(docs):
        if re.search(r'(?m)^kind: Secret$', doc) and re.search(r'(?m)^  name: mariadb-password$', doc):
            if not re.search(r'(?m)^  namespace: slurm$', doc):
                raise ValueError('unexpected credential namespace')
            updated, count = re.subn(r'(?m)^  password: "' + r'[0-9a-f]{48}' + r'"$', '  password: "' + password + '"', doc)
            if count != 1:
                raise ValueError('unexpected credential manifest encoding')
            docs[i] = updated
            found.append(i)
    if len(found) != 1:
        raise ValueError('expected exactly one accounting credential manifest')
    return '---'.join(docs)


def persist(path, text):
    path = Path(path)
    fd, tmp = tempfile.mkstemp(prefix='.prace-db-recover-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(text); f.flush(); os.fsync(f.fileno())
        os.replace(tmp, path)
        fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


def recover(cfg, run=command, read=private, write=persist, sleep=time.sleep):
    # Validate everything possible before ALTER USER. Only this cluster's pod-network principal.
    if cfg.get('client_host') != '10.42.%':
        raise ValueError('unexpected accounting database principal')
    password = read(cfg['password_file']).strip()
    if not re.fullmatch('[0-9a-f]{48}', password):
        raise ValueError('unexpected credential encoding')
    manifest = read(cfg['manifest'])
    updated = manifest_with_password(manifest, password)
    secret = json.loads(run(K + ['get', 'secret', 'mariadb-password', '-o', 'json']))
    uid = secret['metadata']['uid']
    if not uid:
        raise ValueError('accounting Secret has no identity')
    old_pod = json.loads(run(K + ['get', 'pod', 'slurm-accounting-0', '-o', 'json']))['metadata']['uid']
    run(['mysql'], "ALTER USER 'slurm'@'10.42.%' IDENTIFIED BY '" + password + "';\nGRANT ALL ON slurm_acct_db.* TO 'slurm'@'10.42.%';\n")
    # Source of truth first; a K3s manifest reapply must not restore the former credential.
    write(cfg['manifest'], updated)
    patch = {'metadata': {'uid': uid}, 'data': {'password': base64.b64encode(password.encode()).decode()}}
    run(K + ['patch', 'secret', 'mariadb-password', '--type=merge', '--patch-file=/dev/stdin'], json.dumps(patch))
    observed = json.loads(run(K + ['get', 'secret', 'mariadb-password', '-o', 'json']))
    if observed['metadata']['uid'] != uid or observed['data']['password'] != patch['data']['password']:
        raise RuntimeError('Secret identity/credential observation failed')
    run(K + ['delete', 'pod', 'slurm-accounting-0', '--wait=true', '--timeout=60s'])
    # The StatefulSet recreates the pod a moment later, and kubectl wait refuses a pod that does not
    # exist yet ("no matching resources found": 3 Oct, DB-05's first wait). So the new pod first.
    new_pod = None
    for _ in range(60):
        try:
            new_pod = json.loads(run(K + ['get', 'pod', 'slurm-accounting-0', '-o', 'json']))['metadata']['uid']
        except RuntimeError:
            new_pod = None
        if new_pod and new_pod != old_pod:
            break
        sleep(2)
    if not new_pod or new_pod == old_pod:
        raise RuntimeError('accounting process restart was not proven')
    run(K + ['wait', '--for=condition=Ready', 'pod/slurm-accounting-0', '--timeout=300s'])
    if json.loads(run(K + ['get', 'pod', 'slurm-accounting-0', '-o', 'json']))['metadata']['uid'] != new_pod:
        raise RuntimeError('the accounting pod was replaced again while it became ready')
    run(K + ['exec', 'slurm-controller-0', '-c', 'slurmctld', '--', 'sacctmgr', '-n', 'list', 'cluster'])
    print('credential recovery completed; keep fence and run DB-04/DB-05 before cleanup')


def main():
    try:
        if os.geteuid() != 0:
            raise ValueError('root required')
        recover(json.load(sys.stdin))
        return 0
    except Exception:
        # Subprocesses and parse exceptions may contain credential material: never print them.
        print('STOP: credential recovery incomplete; retain fence and both files; retry the same recovery after inspection', file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())

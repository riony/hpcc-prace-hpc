"""Install the reviewed researcher helper in three user homes, without sudo."""
from __future__ import annotations
import argparse
import base64
import json
from pathlib import Path
import shlex
import subprocess

from harness.runner import ROOT, write_json
from harness.scenario import load_ssh
from harness.scenario_run import ssh_adapter
from validation.adapters.prace_file_ops_helper import helper_digests
from validation.contracts import require

REMOTE_SETUP = r'''
import base64, grp, hashlib, json, os, pwd, stat, subprocess, sys
from pathlib import Path
p = json.load(sys.stdin)
user = pwd.getpwuid(os.getuid())
if user.pw_name != p['identity'] or user.pw_name not in {'syn-alice','syn-tracer','syn-observer'}:
    raise ValueError('wrong setup identity')
home = Path(user.pw_dir)
if home != Path('/home') / user.pw_name or home.is_symlink() or home.stat().st_uid != os.getuid():
    raise ValueError('unexpected user home')
changed = False
def directory(path, mode, group=None):
    global changed
    if path.is_symlink(): raise ValueError('setup link refused')
    if not path.exists():
        path.mkdir(mode=mode); changed = True
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError('setup directory ownership mismatch')
    if group is not None and info.st_gid != group:
        os.chown(path, -1, group); changed = True
    if stat.S_IMODE(path.stat().st_mode) != mode:
        path.chmod(mode); changed = True
root = home / '.prace-helpers'
directory(root, 0o700)
release = root / p['revision']
directory(release, 0o700)
if set(p['files']) != {'prace_file_ops_helper.py','file_discovery.py','slurm_smoke.py','researcher_workflow.py'}:
    raise ValueError('unexpected helper files')
for name, row in p['files'].items():
    data = base64.b64decode(row['data'], validate=True)
    if hashlib.sha256(data).hexdigest() != row['sha256']: raise ValueError('source digest mismatch')
    path = release / name
    if path.is_symlink(): raise ValueError('helper link refused')
    if path.exists():
        if path.stat().st_uid != os.getuid() or path.read_bytes() != data:
            raise ValueError('existing pinned helper differs; preserve it')
    else:
        with path.open('xb') as f: f.write(data)
        changed = True
    mode = 0o700 if name == 'prace_file_ops_helper.py' else 0o600
    if stat.S_IMODE(path.stat().st_mode) != mode:
        path.chmod(mode); changed = True
proof = {'identity': user.pw_name, 'uid': os.getuid(), 'helper': str(release / 'prace_file_ops_helper.py')}
if user.pw_name == 'syn-alice' and p.get('diagnostic'):
    shared = home / '.prace-researcher'
    directory(shared, 0o700)
    directory(shared / 'runs', 0o700)
    proof.update(runs=str(shared / 'runs'), access_method='actor-only-private')
elif user.pw_name == 'syn-alice':
    home_info = home.stat()
    before = subprocess.check_output(['/usr/bin/getfacl','-p',str(home)], text=True)
    gid = grp.getgrnam('synthetic').gr_gid
    if gid not in os.getgroups(): raise ValueError('actor is not a synthetic group member')
    shared = home / '.prace-researcher'
    directory(shared, 0o2750, gid)
    directory(shared / 'runs', 0o2750, gid)
    acl = subprocess.run(['/usr/bin/setfacl','-m','u:syn-tracer:--x,u:syn-observer:--x',str(home)], capture_output=True)
    method = 'named-user-acl'
    if acl.returncode:
        if b'Operation not supported' not in acl.stderr:
            raise ValueError('home traversal ACL failed')
        # NFS home on this deployment lacks ACL support. Group execute grants
        # traversal, without granting directory listing or write permissions.
        os.chown(home, -1, gid)
        home.chmod(stat.S_IMODE(home_info.st_mode) | 0o010)
        method = 'synthetic-group-traverse'
    after = subprocess.check_output(['/usr/bin/getfacl','-p',str(home)], text=True)
    changed = changed or before != after
    proof.update(home_acl_before=before, home_acl_after=after, runs=str(shared / 'runs'), access_method=method,
                 home_gid_before=home_info.st_gid, home_mode_before=stat.S_IMODE(home_info.st_mode),
                 home_gid_after=home.stat().st_gid, home_mode_after=stat.S_IMODE(home.stat().st_mode))
proof['changed'] = changed
print(json.dumps(proof))
'''


def setup(config: Path, output: Path, *, diagnostic: bool = False) -> dict:
    require(output.is_absolute() and not output.exists(), 'new absolute setup evidence directory required')
    require(not any(p.is_symlink() for p in output.parents), 'setup evidence parent link refused')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT), 'commit the reviewed source before setup')
    revision = subprocess.check_output(['git','rev-parse','HEAD'], cwd=ROOT, text=True).strip()
    roles = load_ssh(config, 'syn-alice', diagnostic=diagnostic)['roles']
    require({key: row['identity'] for key, row in roles.items()} ==
            ({'actor':'syn-alice'} if diagnostic else {'actor':'syn-alice','tracer':'syn-tracer','observer':'syn-observer'}), 'fixed researcher identities required')
    digests = helper_digests()
    files = {name: {'sha256': digest, 'data': base64.b64encode((ROOT / 'validation/adapters' / name).read_bytes()).decode()}
             for name, digest in digests.items()}
    output.mkdir(mode=0o700, parents=True)
    proofs = {}
    for role, row in roles.items():
        expected = f"/home/{row['identity']}/.prace-helpers/{revision}/prace_file_ops_helper.py"
        require(row['remote_helper'] == expected, 'user helper must be pinned to this revision in its own home')
        command = ssh_adapter(row)._ssh_base() + [shlex.join(['/usr/bin/python3','-I','-c',REMOTE_SETUP])]
        completed = subprocess.run(command, input=json.dumps({'identity':row['identity'], 'revision':revision, 'files':files, 'diagnostic':diagnostic}).encode(),
                                   capture_output=True, timeout=45)
        require(completed.returncode == 0 and not completed.stderr and len(completed.stdout) <= 16384, 'user helper setup failed')
        proof = json.loads(completed.stdout)
        require(proof['identity'] == row['identity'] and proof['helper'] == expected, 'user setup identity/path mismatch')
        proofs[role] = proof
        write_json(output / (role + '.json'), proof)
    summary = {'source_revision':revision, 'helper_digests':digests, 'roles':proofs}
    write_json(output / 'setup.json', summary)
    return summary


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--diagnostic', action='store_true', help='Alice only; private run parents, no home ACL/group changes')
    p.add_argument('--ssh-config', type=Path, required=True)
    p.add_argument('--output-dir', type=Path, required=True)
    p.add_argument('--allow-remote', action='store_true', required=True)
    args = p.parse_args()
    result = setup(args.ssh_config, args.output_dir, diagnostic=args.diagnostic)
    print('PASS user setup: ' + result['source_revision'])


if __name__ == '__main__':
    main()

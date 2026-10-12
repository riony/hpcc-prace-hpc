#!/usr/bin/env python3
"""Real Ansible on a temporary local repository; mount queries are stand-ins."""
import grp
import json
import os
from pathlib import Path
import pwd
import shutil
import subprocess
import tempfile
import unittest

INFRA = Path(__file__).resolve().parents[1]
ROOT = INFRA.parent
ANSIBLE = os.environ.get('ANSIBLE_PLAYBOOK') or shutil.which('ansible-playbook')


class Delivery(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(ANSIBLE, 'Install ansible-playbook or set ANSIBLE_PLAYBOOK')
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.repo = self.root / 'repo'; self.repo.mkdir()
        self.role = self.repo / 'infra/roles/harness_helper'
        shutil.copytree(INFRA / 'roles/harness_helper', self.role)
        sources = self.repo / 'validation/adapters'; sources.mkdir(parents=True)
        for name in ('prace_file_ops_helper.py','file_discovery.py','slurm_smoke.py','researcher_workflow.py','prace_permission_helper.py','prace_permission_repair.py'):
            shutil.copyfile(ROOT / 'validation/adapters' / name, sources / name)
        def git(*args):
            return subprocess.check_output(['git','-C',str(self.repo),*args], stderr=subprocess.DEVNULL, text=True).strip()
        git('init','-q'); git('add','.'); git('-c','user.name=Fixture','-c','user.email=fixture@invalid','commit','-qm','fixture')
        self.pin = git('rev-parse','HEAD')
        self.apps = self.root / 'apps'; self.apps.mkdir()
        self.projects = self.root / 'projects'; (self.projects / 'proj-ops').mkdir(parents=True)
        self.bin = self.root / 'bin'; self.bin.mkdir()
        (self.bin / 'findmnt').write_text('#!/bin/sh\n[ "$HH_MOUNT_FAIL" = 1 ] && exit 1\necho fixture-device\n')
        (self.bin / 'findmnt').chmod(0o755)
        self.play = self.root / 'play.yml'
        self.play.write_text('- hosts: localhost\n  connection: local\n  gather_facts: false\n  roles: [harness_helper]\n')
        self.variables = {'fleet_role':'login', 'harness_helper_revision':self.pin,
                         'ansible_remote_tmp':str(self.root/'remote-tmp'),
                         'harness_helper_apps':str(self.apps),'harness_helper_device':'fixture-device',
                         'harness_helper_projects':str(self.projects),'harness_helper_projects_device':'fixture-device',
                         'harness_helper_owner':pwd.getpwuid(os.getuid()).pw_name,
                         'harness_helper_group':grp.getgrgid(os.getgid()).gr_name,
                         'harness_helper_run_group':grp.getgrgid(os.getgid()).gr_name}

    def run_role(self, check=False, **variables):
        return subprocess.run([ANSIBLE,'-i','localhost,',str(self.play),'-e',json.dumps(self.variables | variables)] + (['--check'] if check else []),
            env=dict(os.environ, ANSIBLE_ROLES_PATH=str(self.role.parent), ANSIBLE_LOCAL_TEMP=str(self.root/'ansible'),
                     PATH=str(self.bin)+os.pathsep+os.environ['PATH']),capture_output=True,text=True,timeout=60)

    def test_persistent_exact_source_and_unchanged_rerun(self):
        preview = self.run_role(check=True)
        self.assertEqual(preview.returncode,0,preview.stdout+preview.stderr)
        self.assertEqual(list(self.apps.iterdir()),[])
        result = self.run_role(); self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        folder = self.apps / 'prace' / self.pin
        self.assertFalse((folder/'prace_permission_helper.py').exists())
        for name in ('prace_file_ops_helper.py','file_discovery.py','slurm_smoke.py','researcher_workflow.py'):
            self.assertEqual((folder/name).read_bytes(),(ROOT/'validation/adapters'/name).read_bytes())
            self.assertEqual((folder/name).stat().st_mode & 0o777,0o755 if name.startswith('prace_') else 0o644)
        # Simulate a new login pod: the helper is on the persistent apps tree.
        result = subprocess.run(['python3',str(folder/'prace_file_ops_helper.py'),'rpc'],
            input='{"operation":"capabilities","parameters":{}}',capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(len(json.loads(result.stdout)['helper_digests']),4)
        result = self.run_role(); self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('changed=0',result.stdout)

    def test_bad_pin_or_dirty_source_stops_before_writes(self):
        result = self.run_role(harness_helper_revision='0'*40)
        self.assertNotEqual(result.returncode,0); self.assertEqual(list(self.apps.iterdir()),[])
        (self.repo/'validation/adapters/slurm_smoke.py').write_text('changed source')
        result = self.run_role(); self.assertNotEqual(result.returncode,0)
        self.assertEqual(list(self.apps.iterdir()),[])

    def test_permission_delivery_opt_in_preview_apply_repeat_without_fixture(self):
        preview = self.run_role(check=True, harness_helper_permission_enabled=True)
        self.assertEqual(preview.returncode,0,preview.stdout+preview.stderr)
        self.assertEqual(list(self.apps.iterdir()),[])
        result = self.run_role(harness_helper_permission_enabled=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        helper = self.apps / 'prace' / self.pin / 'prace_permission_helper.py'
        self.assertEqual(helper.read_bytes(),(ROOT/'validation/adapters/prace_permission_helper.py').read_bytes())
        self.assertEqual(helper.stat().st_mode & 0o777,0o755)
        self.assertFalse((self.projects / '.prace-continuous').exists())
        self.assertFalse((self.apps / 'prace' / 'continuous').exists())
        result = self.run_role(harness_helper_permission_enabled=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('changed=0',result.stdout)

    def test_project_acl_is_removed_only_from_synthetic_parents(self):
        project = self.projects / 'proj-ops'
        subprocess.run(['bash',str(INFRA/'roles/storage_policy/files/prace-project-acl'),str(project)],
                       check=True,capture_output=True)
        def acl(path):
            return subprocess.check_output(['getfacl','-cpnE',str(path)],text=True)
        original = acl(project)
        parent = project / '.prace-smoke'; runs = parent / 'runs'
        runs.mkdir(parents=True)
        existing = runs / 'existing'; existing.mkdir()
        preserved = acl(existing)
        preview = self.run_role(check=True)
        self.assertEqual(preview.returncode,0,preview.stdout+preview.stderr)
        self.assertIn('default:',acl(runs))
        result = self.run_role()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        for path in (parent,runs):
            self.assertEqual(path.stat().st_mode & 0o7777,0o3770)
            self.assertEqual(acl(path),'user::rwx\ngroup::rwx\nother::---\n\n')
        self.assertEqual(acl(project),original)
        self.assertEqual(acl(existing),preserved)
        result = self.run_role()
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn('changed=0',result.stdout)

    def test_repair_delivery_opt_in_and_dependency(self):
        refused = self.run_role(harness_helper_permission_repair_enabled=True)
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(list(self.apps.iterdir()), [])
        args = dict(harness_helper_permission_enabled=True, harness_helper_permission_repair_enabled=True)
        preview = self.run_role(check=True, **args)
        self.assertEqual(preview.returncode, 0, preview.stdout + preview.stderr)
        result = self.run_role(**args)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        helper = self.apps / 'prace' / self.pin / 'prace_permission_repair.py'
        self.assertEqual(helper.read_bytes(), (ROOT / 'validation/adapters/prace_permission_repair.py').read_bytes())
        self.assertEqual(helper.stat().st_mode & 0o777, 0o755)
        self.assertFalse((self.apps / 'prace' / 'continuous').exists())
        repeat = self.run_role(**args)
        self.assertEqual(repeat.returncode, 0, repeat.stdout + repeat.stderr)
        self.assertIn('changed=0', repeat.stdout)

    def test_missing_mount_or_project_stops_before_writes(self):
        from unittest.mock import patch
        with patch.dict(os.environ,{'HH_MOUNT_FAIL':'1'}):
            result = self.run_role(); self.assertNotEqual(result.returncode,0)
        (self.projects/'proj-ops').rmdir()
        result = self.run_role(); self.assertNotEqual(result.returncode,0)
        self.assertEqual(list(self.apps.iterdir()),[])


if __name__ == '__main__': unittest.main()

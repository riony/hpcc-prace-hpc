#!/usr/bin/env python3
"""Credential recovery interruption tests; synthetic values and fake commands only."""
import base64
import contextlib
import importlib.util
import io
import json
import re
from pathlib import Path
import unittest
S = importlib.util.spec_from_file_location('repair', Path(__file__).parents[1] / 'roles/slinky/files/prace-db-recover.py')
m = importlib.util.module_from_spec(S); S.loader.exec_module(m)
OLD, NEW = 'a'*48, 'b'*48
BASE = 'apiVersion: v1\nkind: Secret\nmetadata:\n  name: mariadb-password\n  namespace: slurm\nstringData:\n  password: "'+OLD+'"\n---\nkind: ConfigMap\ndata: {keep: unchanged}\n'
CFG = {'password_file': 'pw', 'manifest': 'base', 'client_host': '10.42.%'}

class State:
    def __init__(self, selected=NEW, fail=None, lag=0):
        self.file=selected; self.db=NEW; self.secret=OLD; self.process=OLD
        self.base=BASE; self.uid='pod0'; self.fail=fail; self.calls=[]
        self.lag=lag; self.absent=0      # reads for which the StatefulSet has not recreated the pod yet
    def hit(self, point):
        self.calls.append(point)
        if self.fail == point:
            self.fail=None
            raise RuntimeError('injected interruption')
    def read(self, path): return self.file if path=='pw' else self.base
    def write(self, path, text):
        self.base=text; self.hit('persist')
    def run(self, argv, data=None):
        if argv==['mysql']:
            self.db=re.search(r"IDENTIFIED BY '([0-9a-f]{48})'",data).group(1)
            assert "'slurm'@'10.42.%'" in data
            self.hit('sql'); return ''
        if 'get' in argv and 'secret' in argv:
            return json.dumps({'metadata': {'uid': 'secret1'}, 'data': {'password': base64.b64encode(self.secret.encode()).decode()}})
        if 'get' in argv and 'pod' in argv:
            if self.absent:
                self.absent -= 1
                raise RuntimeError('recovery command failed')        # command(): NotFound is rc 1
            return json.dumps({'metadata': {'uid': self.uid}})
        if 'patch' in argv:
            self.secret=base64.b64decode(json.loads(data)['data']['password']).decode(); self.hit('patch'); return ''
        if 'delete' in argv:
            self.uid += 'x'; self.process=self.secret; self.absent=self.lag; self.hit('restart'); return ''
        if 'wait' in argv:
            if self.absent:                  # kubectl wait: "error: no matching resources found"
                raise RuntimeError('recovery command failed')
            self.hit('wait'); return ''
        if 'sacctmgr' in argv:
            self.hit('accounting')
            if self.db != self.process: raise AssertionError('accounting queried before consistency')
            return 'cluster'
        raise AssertionError(argv)

class Recovery(unittest.TestCase):
    def repair(self, s):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            m.recover(CFG, run=s.run, read=s.read, write=s.write, sleep=lambda sec: None)
        self.assertNotIn(OLD,out.getvalue());self.assertNotIn(NEW,out.getvalue())
    def test_forward_and_rollback_at_every_interruption(self):
        for selected in (OLD, NEW):
            for failure in ('sql','persist','patch','restart','wait','accounting'):
                with self.subTest(selected=selected[0], failure=failure):
                    s=State(selected, failure)
                    with self.assertRaises(RuntimeError): self.repair(s)
                    self.repair(s)
                    self.assertEqual((s.db,s.secret,s.process), (selected,)*3)
                    self.assertIn('kind: ConfigMap\ndata: {keep: unchanged}',s.base)
                    self.assertGreater(s.calls.index('accounting'),s.calls.index('restart'))
    def test_the_restart_waits_for_the_recreated_pod(self):
        """3 Oct, DB-05: the first readiness wait ran before the StatefulSet had recreated the pod
        (rc 1, "no matching resources found"); the recovery must wait for the new pod first"""
        for selected in (OLD, NEW):
            with self.subTest(selected=selected[0]):
                s = State(selected, lag=3)
                self.repair(s)
                self.assertEqual((s.db, s.secret, s.process), (selected,)*3)
                self.assertLess(s.calls.index('restart'), s.calls.index('wait'))
        s = State(NEW, lag=10**6)              # never recreated: no proof of a restart
        with self.assertRaisesRegex(RuntimeError, 'restart was not proven'): self.repair(s)
        self.assertNotIn('accounting', s.calls)

    def test_unknown_manifest_refuses_before_sql(self):
        for text in ('', BASE+BASE, BASE.replace('namespace: slurm','namespace: other')):
            s=State();s.base=text
            with self.assertRaises(ValueError): self.repair(s)
            self.assertEqual(s.calls,[])
    def test_secret_mismatch_and_unchanged_pod_refuse(self):
        for fault in ('secret','pod'):
            s=State();orig=s.run
            def run(argv,data=None):
                if fault=='secret' and 'patch' in argv: return ''
                if fault=='pod' and 'delete' in argv: return ''
                return orig(argv,data)
            with self.assertRaises(RuntimeError): m.recover(CFG,run=run,read=s.read,write=s.write)
            self.assertNotIn('accounting',s.calls)

if __name__=='__main__': unittest.main()

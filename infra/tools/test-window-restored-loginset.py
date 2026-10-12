#!/usr/bin/env python3
"""Offline terminal-restoration acknowledgement; no network or fleet mutation."""
import atexit, copy, importlib.util, json, os, pathlib, shutil, tempfile, unittest
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('window',pathlib.Path(os.environ.get('PRACE_WINDOW_TOOL',pathlib.Path(__file__).with_name('slurm-window.py'))))
w=importlib.util.module_from_spec(spec);spec.loader.exec_module(w)
atexit.register(shutil.rmtree,w.SSH_DIR,ignore_errors=True)

class Restoration(unittest.TestCase):
 def setUp(self):
  self.rec={'schema':2,'id':'a'*16,'login':w.LOGIN,'label':'fixture','phase':'opening','fence_intent':{'active':False},'declared_partitions':{},'original':{'partitions':{'cpu':'UP'},'loginsets':{'slurm-login-prace':{'uid':'old','replicas':1}}},'history':[{'at':'2026-10-01T07:51:02+00:00','event':'restore intent saved; chart restore and runtime verification still required'}]}
  self.original=copy.deepcopy(self.rec['original']);self.parts={'cpu':'UP'};self.sets={'slurm-login-prace':{'uid':'new','replicas':1}};self.pods=(1,1);self.queue=[];self.saved=[];self.mutated=[]
  self.login={'kind':'LoginSet','metadata':{'name':'slurm-login-prace','namespace':'slurm','uid':'new','creationTimestamp':'2026-10-01T07:51:54Z','labels':{'app.kubernetes.io/managed-by':'Helm'},'annotations':{'meta.helm.sh/release-name':'slurm','meta.helm.sh/release-namespace':'slurm'}}}
  self.chart={'kind':'HelmChart','metadata':{'name':'slurm','namespace':'kube-system','uid':'chart'}}
  self.job={'kind':'Job','metadata':{'name':'helm-install-slurm','namespace':'kube-system','uid':'job','creationTimestamp':'2026-10-01T07:51:50Z','labels':{'helmcharts.helm.cattle.io/chart':'slurm'},'ownerReferences':[{'kind':'HelmChart','name':'slurm','uid':'chart'}]},'status':{'succeeded':1,'conditions':[{'type':'Complete','status':'True'}]}}
 def query(self,args,why):
  kind=args[args.index('get')+1];return json.dumps({'loginset':self.login,'helmchart':self.chart,'job':self.job}[kind])
 def transition(self,rec,phase,active,event):
  rec.update(phase=phase,fence_intent={'active':active});self.saved.append(copy.deepcopy(rec))
 def call(self,**overrides):
  kwargs={'require_lease':lambda lid:None,'load':lambda lid:self.rec,'marker_matches':lambda rec:None,'verify_overlay':lambda rec:None,'query':self.query,'partitions':lambda:self.parts,'loginsets':lambda:self.sets,'login_pods':lambda:self.pods,'queue':lambda:self.queue,'transition':self.transition,'login':lambda *a,**k:self.mutated.append(a),'publish_marker':lambda rec:None};kwargs.update(overrides)
  with patch.multiple(w,**kwargs):w.accept_restored_loginset('a'*16,'slurm-login-prace','old','new','chart','job',True)
 def refused(self,**kwargs):
  with self.assertRaises(w.Stop):self.call(**kwargs)
  self.assertEqual(self.saved,[]);self.assertEqual(self.mutated,[]);self.assertEqual(self.rec['original'],self.original)
 def test_owned_replacement_records_separate_ack_without_cluster_mutation(self):
  self.call();self.assertEqual(self.rec['original'],self.original);self.assertEqual(self.rec['phase'],'restored');self.assertEqual(self.rec['restored_loginset']['restored_uid'],'new');self.assertEqual(self.mutated,[])
 def test_unacknowledged_uid_still_refuses(self):
  with patch.multiple(w,partitions=lambda:self.parts,loginsets=lambda:self.sets):
   with self.assertRaises(w.Stop):w.observe(self.rec)
 def test_only_acknowledged_terminal_identity_passes_observe(self):
  self.call()
  with patch.multiple(w,partitions=lambda:self.parts,loginsets=lambda:self.sets):w.observe(self.rec)
  self.sets['slurm-login-prace']['uid']='third'
  with patch.multiple(w,partitions=lambda:self.parts,loginsets=lambda:self.sets):
   with self.assertRaises(w.Stop):w.observe(self.rec)
 def test_same_pin_retry_finishes_marker_after_durable_ack(self):
  self.call()
  marker=w.projection(self.rec)|{'phase':'opening'}
  with patch.multiple(w,require_lease=lambda lid:None,load=lambda lid:self.rec,query=lambda *a:json.dumps(marker),verify_restored=lambda rec:None,verify_overlay=lambda rec:None),patch.object(w,'publish_marker') as published:
   w.accept_restored_loginset('a'*16,'slurm-login-prace','old','new','chart','job',True);published.assert_called_once()
  self.assertEqual(self.rec['original'],self.original)
 def test_retry_with_changed_pin_or_foreign_marker_refuses(self):
  self.call()
  for new,marker in [('third',w.projection(self.rec)),('new',{})]:
   with patch.multiple(w,require_lease=lambda lid:None,load=lambda lid:self.rec,query=lambda *a:json.dumps(marker)),patch.object(w,'publish_marker') as published:
    with self.assertRaises(w.Stop):w.accept_restored_loginset('a'*16,'slurm-login-prace','old',new,'chart','job',True)
    published.assert_not_called()
 def test_lost_terminal_lease_can_reacquire_same_baseline_for_release(self):
  self.call()
  from contextlib import nullcontext
  with patch.multiple(w,holder=lambda:'',load=lambda lid:self.rec,login=lambda *a,**k:(0,'id='+self.rec['id']+' ',''),operation_lock=lambda lid:nullcontext(),require_lease=lambda lid:None,note=lambda *a,**k:None,transition=self.transition),patch.object(w,'verify_restored') as baseline,patch.object(w,'verify_overlay') as overlay:
   w.lease_take('fixture',self.rec['id']);self.assertEqual(baseline.call_count,2);self.assertEqual(overlay.call_count,2)
  self.assertEqual(self.rec['phase'],'restored');self.assertEqual(self.rec['original'],self.original);self.assertFalse(self.rec['fence_intent']['active'])
 def test_lost_terminal_lease_refuses_changed_baseline_before_acquisition(self):
  self.call()
  def fail(*a):raise w.Stop(1,'baseline changed')
  with patch.multiple(w,holder=lambda:'',load=lambda lid:self.rec,verify_restored=fail),patch.object(w,'login') as remote:
   with self.assertRaises(w.Stop):w.lease_take('fixture',self.rec['id'])
   remote.assert_not_called()
 def test_closed_record_is_not_accepted(self):self.rec['phase']='closed';self.rec['fence_intent']['active']=True;self.refused()
 def test_runtime_state_not_learned(self):self.parts['cpu']='INACTIVE';self.refused()
 def test_extra_partition_refuses(self):self.parts['other']='UP';self.refused()
 def test_zero_login_replicas_refuses(self):self.sets['slurm-login-prace']['replicas']=0;self.refused()
 def test_unready_or_extra_pod_refuses(self):
  for pods in [(1,0),(2,1)]:self.pods=pods;self.refused()
 def test_pending_job_refuses(self):self.queue=['1 test PENDING cpu'];self.refused()
 def test_wrong_uid_pin_refuses(self):self.login['metadata']['uid']='third';self.refused()
 def test_wrong_helm_owner_refuses(self):self.login['metadata']['annotations']['meta.helm.sh/release-name']='other';self.refused()
 def test_job_wrong_owner_refuses(self):self.job['metadata']['ownerReferences'][0]['uid']='other';self.refused()
 def test_failed_incomplete_active_job_refuses(self):
  for status in [{'succeeded':0},{'succeeded':1,'failed':1},{'succeeded':1,'active':1},{'succeeded':1}]:self.job['status']=status;self.refused()
 def test_stale_job_or_loginset_refuses(self):self.job['metadata']['creationTimestamp']='2026-10-01T07:50:00Z';self.refused()
 def test_missing_marker_or_overlay_refuses(self):
  def fail(*a):raise w.Stop(1,'missing')
  for field in ['marker_matches','verify_overlay']:self.refused(**{field:fail})
 def test_malformed_job_status_refuses(self):self.job['status']=None;self.refused()
 def test_terminal_close_rejected_before_remote_lock(self):
  self.call()
  with patch.object(w,'load',lambda lid:self.rec),patch.object(w,'local_lock'),patch.object(w,'operation_lock') as remote:
   self.assertEqual(w.main(['close','--lease-id','a'*16]),1);remote.assert_not_called()
 def test_query_failure_never_acknowledges(self):
  def fail(*a):raise w.Stop(2,'failed query')
  self.refused(query=fail)
 def test_terminal_record_load_preserves_original_and_rejects_wrong_phase(self):
  self.call()
  with tempfile.TemporaryDirectory() as td,patch.object(w,'RECORDS',pathlib.Path(td)):
   p=pathlib.Path(td)/(self.rec['id']+'.json');p.write_text(json.dumps(self.rec));p.chmod(0o600);self.assertEqual(w.load(self.rec['id'])['original'],self.original)
   self.rec['phase']='closed';p.write_text(json.dumps(self.rec))
   with self.assertRaises(w.Stop):w.load(self.rec['id'])

if __name__=='__main__':unittest.main()

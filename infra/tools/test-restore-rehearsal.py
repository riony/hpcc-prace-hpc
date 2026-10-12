#!/usr/bin/env python3
"""Offline tests for tools/restore-rehearsal.sh: the script is sourced with stubbed L (login node)
and V (VM) functions and a stubbed cleanup, and each stage must turn every failed, unknown or
unexpected observation into a non-zero exit with RESULT: FAIL (review R1, 28 Sep: the harness
printed "job id counter restored: FAIL" and exited 0). On failure the VM must be cleaned up
unless a diagnostic hold was asked for after isolation was proven. No host is contacted."""
import os
import base64
import json
import sys
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parent / "restore-rehearsal.sh"

FINGERPRINT = """node-password secret: secret/lab-dl380.node-password.k3s
login host-key secret: slurm/slurm-login-prace-ssh-host-keys uid=11111111-2222-3333-4444-555555555555 public=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
objects namespaces: 6 5fcd060b519b4b40
objects secrets: 27 f1af7595b54507ed
objects configmaps: 18 0fa5d135c478fa17
objects serviceaccounts: 50 aa5291b3a0e99544
objects persistentvolumeclaims: 1 969db9fd44087b9a
objects persistentvolumes: 1 0184424c8e537e05
objects helmcharts.helm.cattle.io: 3 25488e1479b0d7b6
objects accountings.slinky.slurm.net: 1 e87ef58e6dd83272
objects controllers.slinky.slurm.net: 1 d0fd6b193ac20a2f
objects loginsets.slinky.slurm.net: 1 bb7c4023af47e47f
objects nodesets.slinky.slurm.net: 2 4aaf3f02821bc491
objects restapis.slinky.slurm.net: 1 7de51b2027a2beea
objects tokens.slinky.slurm.net: 0 01ba4719c80b6fe9
secret value kube-system/k3s-serving: 1111111111111111
secret value slurm/mariadb-password: 2222222222222222
mariadb-password secret = /root/slinky-db.pw: match
sacct jobs: 520 last 520 287be6f952bcfa02
info (not compared): 'CANCELLED by <uid>' records normalized: 4
associations: 23 9e9cf84ca2290f0d
slurm nodes: NodeName=lab-lenovo NodeName=lab-g003
statesave files (/var/spool/slurmctld/prace): job_state node_state part_state
k3s journal (current run): 'newer than datastore' 0; 'password rejected' 0
"""

STUBS = r'''
cleanup() { echo CLEANUP-CALLED; }
POD() {
  case "$*" in
    *sbatch*) echo "${POD_JOB:-522}"; return "${POD_SBATCH_RC:-0}" ;;
    *) [ "${POD_RC:-0}" = 0 ] || return "$POD_RC"
       printf 'user %s 30091 on slurm-login-prace-x\nperm /home/syn-probe syn-probe 700\nperm /home/syn-probe/.ssh syn-probe 700\nperm /home/syn-probe/.ssh/authorized_keys syn-probe %s\nrevoked %s\n' \
         "${POD_USER:-syn-probe}" "${POD_AK_MODE:-600}" "${POD_REVOKED:-absent}" ;;
  esac
}
W() { case "$*" in *ping*) [ "${W_PING:-UP}" = UP ] && echo UP ;; *) return 0 ;; esac; }
L() {
  case "$*" in
    "bash -s") cat >/dev/null; cat "$T/live.txt"; return "${L_FP_RC:-0}" ;;
    *) return 0 ;;
  esac
}
V() {
  case "$*" in
    "bash -s") cat >/dev/null; cat "$T/restored.txt"; return "${V_FP_RC:-0}" ;;
    *sbatch*) echo "${NEXT_JOB:-521}"; return "${SBATCH_RC:-0}" ;;
    *scancel*) return 0 ;;
    *"patch loginset"*)
      [[ $* =~ patch\ loginset\ ([^ ]+).*replicas.:([0-9]+) ]]
      [ "${LOGIN_PATCH_FAIL:-}" = 1 ] && return 1
      echo "${BASH_REMATCH[2]}" > "$T/replicas-${BASH_REMATCH[1]}"; echo OK ;;
    *"get loginset"*)
      [[ $* =~ get\ loginset\ ([^ ]+) ]]; cat "$T/replicas-${BASH_REMATCH[1]}" 2>/dev/null || echo 0 ;;
    *maintenance-window.txt*) echo "${WINDOW:-NO-RECORD}" ;;
    *"scontrol update PartitionName="*)
      [[ $* =~ PartitionName=([^ ]+)\ State=([^ ]+) ]]
      [ "${REOPEN_FAIL:-}" = "${BASH_REMATCH[1]}" ] && return 1
      echo "${BASH_REMATCH[1]}=${BASH_REMATCH[2]}" >> "$T/reopened"; return 0 ;;
    *"scontrol show partition -o"*)
      for p in cpu gpu; do
        st=DRAIN; grep -q "^$p=" "$T/reopened" 2>/dev/null && st=$(grep "^$p=" "$T/reopened" | tail -1 | cut -d= -f2)
        [ "${STUCK:-}" = "$p" ] && st=DRAIN
        echo "PartitionName=$p AllowGroups=ALL State=$st TotalCPUs=4"
      done ;;
    */dev/tcp/*)
      [[ $* =~ /dev/tcp/([^/]+)/([0-9]+) ]]; t="${BASH_REMATCH[1]}:${BASH_REMATCH[2]}"
      case " ${PROBE_FAIL:-} " in *" $t "*) return 255 ;; esac
      case " ${REACH:-} " in *" $t "*) echo REACHABLE ;; *) echo BLOCKED ;; esac ;;
    *"sacct -n -X -j"*) echo "${JOB_STATE:-COMPLETED}" ;;
    *"sacct -n -X -P -j"*) echo "${JOB_ACCT:-522|syn-probe|COMPLETED|rehearsal-cpu1}" ;;
    *"cat /home/syn-probe/e2e-restore-"*) echo "${JOB_OUT:-rehearsal-cpu1 syn-probe restored-home-ok}" ;;
    *"containerStatuses[*].ready"*) echo true ;;
    *"scontrol ping"*)
      n=$(cat "$T/ctl-count" 2>/dev/null || echo 0); echo $((n + 1)) > "$T/ctl-count"
      IFS=, read -ra seq <<<"${CTRL_SEQ:-USABLE,USABLE,USABLE}"
      [ "$n" -lt "${#seq[@]}" ] && [ "${seq[$n]}" = USABLE ] && echo USABLE; return 0 ;;
    *ping*) [ "${V_PING:-UP}" = UP ] && echo UP ;;
    *) return 0 ;;
  esac
}
'''


def run(stage, live=FINGERPRINT, restored=FINGERPRINT, isolated=1, hold=0, **env):
    with tempfile.TemporaryDirectory() as d:
        t = Path(d); (t / "out").mkdir()
        (t / "live.txt").write_text(live); (t / "restored.txt").write_text(restored)
        snippet = f'''source "{SCRIPT}"
{STUBS}
OUT="$T/out"; RDIR_USED=1; ISOLATED={isolated}; HOLD={hold}
CONTROLLER_TRIES=6 CONTROLLER_SLEEP=0 REOPEN_TRIES=2 REOPEN_SLEEP=0
trap on_exit EXIT
{stage}
echo STAGE-RETURNED
'''
        e = dict(os.environ, T=d, **{k: str(v) for k, v in env.items()})
        r = subprocess.run(["bash", "-c", snippet], env=e, capture_output=True, text=True, timeout=60)
        diff = (t / "out/fingerprint.diff").read_text() if (t / "out/fingerprint.diff").exists() else ""
        return r, r.stdout + r.stderr, diff


class JobCounter(unittest.TestCase):
    def test_wrong_counter_fails_and_cleans_up(self):
        """The review's replay: a restored controller issuing job 1 after live job 520."""
        r, out, _ = run("stage_verify", NEXT_JOB=1)
        self.assertNotEqual(r.returncode, 0, out)
        self.assertIn("job id counter not restored: expected 521, got 1", out)
        self.assertIn("RESULT: FAIL", out); self.assertIn("CLEANUP-CALLED", out)
        self.assertNotIn("STAGE-RETURNED", out)

    def test_non_numeric_or_failed_submission_fails(self):
        for env in ({"NEXT_JOB": "sbatch: error: Batch job submission failed"}, {"SBATCH_RC": 1}):
            with self.subTest(env=env):
                r, out, _ = run("stage_verify", **env)
                self.assertNotEqual(r.returncode, 0, out); self.assertIn("RESULT: FAIL", out)

    def test_correct_counter_and_identical_fingerprints_pass(self):
        r, out, _ = run("stage_verify")
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("fingerprints identical", out); self.assertIn("job id counter restored: PASS", out)
        self.assertNotIn("CLEANUP-CALLED", out); self.assertIn("STAGE-RETURNED", out)


class Fingerprints(unittest.TestCase):
    def test_fingerprint_command_errors_fail(self):
        for env in ({"L_FP_RC": 1}, {"V_FP_RC": 1}):
            with self.subTest(env=env):
                r, out, _ = run("stage_verify", **env)
                self.assertNotEqual(r.returncode, 0, out); self.assertIn("fingerprint of the", out)

    def test_incomplete_or_malformed_fingerprints_fail(self):
        cases = {
            "missing mariadb line": FINGERPRINT.replace("mariadb-password secret = /root/slinky-db.pw: match\n", ""),
            "mariadb mismatch": FINGERPRINT.replace(": match", ": MISMATCH"),
            "error text": FINGERPRINT.replace("sacct jobs: 520 last 520 287be6f952bcfa02",
                                              "sacct jobs: 1 last error: slurm_persist_conn_open 287be6f952bcfa02"),
            "unexpected line": FINGERPRINT + "Error from server (NotFound): pods not found\n",
            "empty nodesets": FINGERPRINT.replace("nodesets.slinky.slurm.net: 2", "nodesets.slinky.slurm.net: 0"),
            "journal not clean": FINGERPRINT.replace("'newer than datastore' 0", "'newer than datastore' 1"),
            "empty": "",
        }
        for label, fp in cases.items():
            with self.subTest(label):
                r, out, _ = run("stage_verify", restored=fp)
                self.assertNotEqual(r.returncode, 0, out); self.assertIn("fingerprint rejected", out)

    def test_differences_fail_and_secret_hashes_stay_out_of_the_diff(self):
        restored = FINGERPRINT.replace("secret value slurm/mariadb-password: 2222222222222222",
                                       "secret value slurm/mariadb-password: 3333333333333333") \
                              .replace("associations: 23", "associations: 22")
        r, out, diff = run("stage_verify", restored=restored)
        self.assertNotEqual(r.returncode, 0, out)
        self.assertIn("fingerprints differ", out)
        self.assertIn("associations: 22", diff)
        self.assertNotIn("2222222222222222", diff + out); self.assertNotIn("3333333333333333", diff + out)

    def test_only_the_info_line_may_differ(self):
        restored = FINGERPRINT.replace("records normalized: 4", "records normalized: 0")
        r, out, _ = run("stage_verify", restored=restored)
        self.assertEqual(r.returncode, 0, out)


class Isolation(unittest.TestCase):
    def test_any_reachable_or_unknown_probe_fails_and_cleans_up_even_with_hold(self):
        for env in ({"REACH": "1.1.1.1:443"}, {"REACH": "10.90.10.13:22"}, {"PROBE_FAIL": "192.0.2.205:22"}):
            with self.subTest(env=env):
                r, out, _ = run("stage_isolation", isolated=0, hold=1, **env)
                self.assertNotEqual(r.returncode, 0, out)
                self.assertIn("RESULT: FAIL (stage isolation", out)
                self.assertIn("CLEANUP-CALLED", out)          # no hold: isolation was not proven

    def test_all_blocked_passes(self):
        r, out, _ = run('stage_isolation; echo "ISOLATED=$ISOLATED"', isolated=0)
        self.assertEqual(r.returncode, 0, out); self.assertIn("ISOLATED=1", out)


class Controller(unittest.TestCase):
    def test_never_usable_fails(self):
        r, out, _ = run("stage_controller", CTRL_SEQ="x,x,x,x,x,x")
        self.assertNotEqual(r.returncode, 0, out); self.assertIn("not usable", out)

    def test_needs_consecutive_successes(self):
        r, out, _ = run("stage_controller", CTRL_SEQ="USABLE,USABLE,x,USABLE,USABLE,x")
        self.assertNotEqual(r.returncode, 0, out)
        r, out, _ = run("stage_controller", CTRL_SEQ="x,USABLE,USABLE,USABLE")
        self.assertEqual(r.returncode, 0, out)


class Reopen(unittest.TestCase):
    WINDOW = "lease=ab partitions-before-fence=cpu=UP,gpu=UP loginsets-before-fence=slurm-login-prace=1 home=1 captured=x"

    def test_partitions_reopened_before_the_job_counter(self):
        r, out, _ = run("stage_verify", WINDOW=self.WINDOW)
        self.assertEqual(r.returncode, 0, out)
        self.assertIn("partitions as restored: cpu=DRAIN gpu=DRAIN", out)
        self.assertLess(out.index("partitions reopened"), out.index("job id counter restored: PASS"))

    def test_login_sets_reopened_from_the_record(self):
        """28 Sep e2e run: the restored LoginSet came back with 0 replicas (captured fence)."""
        r, out, _ = run("stage_verify", WINDOW=self.WINDOW)
        self.assertIn("login sets reopened to their pre-fence replicas: slurm-login-prace=1", out)
        r, out, _ = run("stage_verify", WINDOW=self.WINDOW, LOGIN_PATCH_FAIL=1)
        self.assertNotEqual(r.returncode, 0, out); self.assertIn("could not reopen loginset", out)

    def test_reopen_failures_fail(self):
        for env in ({"REOPEN_FAIL": "gpu"}, {"STUCK": "cpu"}):
            with self.subTest(env=env):
                r, out, _ = run("stage_verify", WINDOW=self.WINDOW, **env)
                self.assertNotEqual(r.returncode, 0, out); self.assertIn("RESULT: FAIL (stage reopen", out)

    def test_older_backup_without_record_keeps_partitions(self):
        r, out, _ = run("stage_verify")
        self.assertEqual(r.returncode, 0, out); self.assertIn("partitions as captured", out)


class EndToEnd(unittest.TestCase):
    """--e2e stages: the restored login pod, the pinned job on the rehearsal worker."""
    JOB = "HELD_JOB=521 T_BOOT=0 T_RESTORE=0; stage_job"

    def test_login_passes_and_each_wrong_observation_fails(self):
        r, out, _ = run("stage_login")
        self.assertEqual(r.returncode, 0, out); self.assertIn("host key = production entry", out)
        for env, msg in (({"POD_RC": 255}, "ssh as syn-probe"), ({"POD_USER": "root"}, "unexpected identity"),
                         ({"POD_AK_MODE": "644"}, "authorized_keys has the wrong"), ({"POD_REVOKED": "PRESENT"}, "revoked account")):
            with self.subTest(env=env):
                r, out, _ = run("stage_login", **env)
                self.assertNotEqual(r.returncode, 0, out); self.assertIn(msg, out)

    def test_job_passes_and_each_wrong_observation_fails(self):
        r, out, _ = run(self.JOB)
        self.assertEqual(r.returncode, 0, out); self.assertIn("recovery time", out)
        cases = (({"POD_JOB": "sbatch: error"}, "no job ID"), ({"JOB_STATE": "FAILED"}, "did not complete"),
                 ({"JOB_ACCT": "522|syn-probe|COMPLETED|lab-lenovo"}, "accounting record differs"),
                 ({"JOB_OUT": "rehearsal-cpu1 root restored-home-ok"}, "unexpected job output"),
                 ({"POD_JOB": 530, "JOB_ACCT": "530|syn-probe|COMPLETED|rehearsal-cpu1"}, "does not continue the restored counter"))
        for env, msg in cases:
            with self.subTest(env=env):
                r, out, _ = run(self.JOB, **env)
                self.assertNotEqual(r.returncode, 0, out); self.assertIn(msg, out)

    def test_link_must_work_both_ways(self):
        stub = 'link_up() { echo eth1; }; stage_link'
        self.assertEqual(run(stub)[0].returncode, 0)
        for env in ({"V_PING": "DOWN"}, {"W_PING": "DOWN"}):
            with self.subTest(env=env):
                r, out, _ = run(stub, **env)
                self.assertNotEqual(r.returncode, 0, out); self.assertIn("cannot reach", out)


class FailureHandling(unittest.TestCase):
    def test_hold_after_proven_isolation_keeps_the_vm(self):
        r, out, _ = run("stage_verify", hold=1, NEXT_JOB=7)
        self.assertNotEqual(r.returncode, 0, out)
        self.assertIn("VM kept for diagnosis", out); self.assertNotIn("CLEANUP-CALLED", out)

    def test_sourcing_runs_nothing(self):
        r = subprocess.run(["bash", "-c", f'source "{SCRIPT}"; echo sourced'], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.stdout.strip(), "sourced")

    def test_usage(self):
        r = subprocess.run(["bash", str(SCRIPT)], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 2)





class HostKeyRestoreIdentity(unittest.TestCase):
    def test_missing_named_secret_refuses_even_with_other_secrets(self):
        missing = "\n".join(x for x in FINGERPRINT.splitlines() if not x.startswith("login host-key secret:")) + "\n"
        for live, restored in ((missing, FINGERPRINT), (FINGERPRINT, missing), (missing, missing)):
            with self.subTest(live_missing=live == missing, restored_missing=restored == missing):
                r, out, _ = run("stage_verify", live=live, restored=restored)
                self.assertNotEqual(r.returncode, 0, out)

    def test_changed_uid_or_public_keys_refuses(self):
        for old, new in (("11111111-2222-3333-4444-555555555555", "aaaaaaaa-2222-3333-4444-555555555555"), ("a" * 64, "b" * 64)):
            with self.subTest(field=old):
                r, out, _ = run("stage_verify", restored=FINGERPRINT.replace(old, new))
                self.assertNotEqual(r.returncode, 0, out)

    def test_duplicate_identity_refuses(self):
        line = next(x for x in FINGERPRINT.splitlines() if x.startswith("login host-key secret:"))
        r, out, _ = run("stage_verify", live=FINGERPRINT + line + "\n", restored=FINGERPRINT + line + "\n")
        self.assertNotEqual(r.returncode, 0, out)


    def test_actual_named_secret_collector_rejects_missing_public_keys(self):
        script = SCRIPT.read_text().split("get secret slurm-login-prace-ssh-host-keys -o json | python3 -c '\n", 1)[1].split("'\n", 1)[0]
        alg = b"ssh-ed25519"
        raw = len(alg).to_bytes(4, "big") + alg + (32).to_bytes(4, "big") + b"x" * 32
        pub = base64.b64encode(b"ssh-ed25519 " + base64.b64encode(raw)).decode()
        value = {"metadata": {"name": "slurm-login-prace-ssh-host-keys", "namespace": "slurm", "uid": "11111111-2222-3333-4444-555555555555"},
                 "data": {"ssh_host_ed25519_key.pub": pub, "ssh_host_ed25519_key": "PRIVATE-SENTINEL"}}
        def invoke(v):
            return subprocess.run([sys.executable, "-c", script], input=json.dumps(v), text=True, capture_output=True, timeout=5)
        good = invoke(value)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertNotIn("PRIVATE-SENTINEL", good.stdout + good.stderr)
        self.assertRegex(good.stdout, r"uid=11111111-2222-3333-4444-555555555555 public=[0-9a-f]{64}")
        for data in ({}, {"ssh_host_ed25519_key.pub": "bad-base64"}, {"ssh_host_rsa_key.pub": pub}):
            with self.subTest(data=data):
                bad = invoke(dict(value, data=data))
                self.assertNotEqual(bad.returncode, 0)


if __name__ == "__main__":
    unittest.main()

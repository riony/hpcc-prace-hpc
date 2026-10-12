#!/usr/bin/env python3
"""storage-cutover.sh failure paths with stubbed remote commands (no host is contacted).

The tool is sourced (functions only), L/C/PROBE/ansible are replaced by stubs that log every
remote command and answer from a scenario, and the real control flow runs, including the EXIT
trap. Covers the 29 Sep review findings: rollback decides only from verified observations taken
after the fence (S1); a failed recovery keeps the lease, the drained partitions and closed logins
(S2); stale mounts, failed enumeration and a not-ready or wrong login never report success (S3)."""
from concurrent.futures import ThreadPoolExecutor
import fcntl
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

TOOL = Path(__file__).resolve().parent / "storage-cutover.sh"

PRELUDE = r'''
source "$TOOL"
TARGET=fleet K8S=1 VG=hpe_vg ADMIN_NET=10.90.10.0/25 LOGIN_HOST=lab-dl380 INV=x PLAYBOOK=x INFRA=/nonexistent
CLIENTS="w1:10.0.0.1 w2:10.0.0.2" LABEL=t TS=T1 OLD=/var/lib/prace-home-premigration/home-T1 MUX=$D/mux
LEASE_ID=newid ACTION=${ACTION:-cutover} DISCARD=${DISCARD:-0} STAMP=T1
WAIT_WORKER=2 WAIT_LOGIN=2 PAUSE=0
PROBE_KEY=$D/probe-key PROBE_KH=$D/probe-kh; : > "$PROBE_KEY"; : > "$PROBE_KH"
mkdir -p "$MUX"
log() { printf '%s\n' "$*" >> "$D/calls"; }
sleep() { :; }
ts() { echo T; }
ansible_run() { log "ANSIBLE $*"; return 0; }
accounts_zero() { log "ACCOUNTS_ZERO $*"; return 0; }
ssh() { :; }                      # only the mux cleanup in on_exit calls ssh directly
'''


def run(scenario, body, env=None):
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "L0-home-nolabel.jsonl").write_text("L0\n")
        (Path(d) / "listing-helper.sha256").write_text("helpersha\n")
        script = f'D={d}; EVID={d}; TOOL={TOOL}\n' + PRELUDE + scenario + "\ntrap on_exit EXIT\n" + body + "\n"
        r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=120,
                           env={"PATH": "/usr/bin:/bin", "HOME": d, "TMPDIR": d, **(env or {})})
        calls = (Path(d) / "calls").read_text().splitlines() if (Path(d) / "calls").exists() else []
        return r, calls


# A healthy fleet after a successful copy; scenarios override single answers.
HEALTHY = r'''
L() {
  log "L $*"
  case "$*" in
    *"mkdir /run/prace-cluster-lease"*) return 0 ;;
    *"cat > /run/prace-cluster-lease/storage-cutover.state"*) cat >/dev/null; return 0 ;;
    *"grep -q '^holder=storage-cutover "*) return 1 ;;                 # no stopped cutover to adopt
    *"scontrol show partition -o"*) echo "PartitionName=cpu State=UP"; echo "PartitionName=gpu State=UP" ;;
    *"scontrol show partition "*" -o"*) p=${*#*show partition }; p=${p%% *}; echo "PartitionName=$p State=$(cat "$D/part_$p" 2>/dev/null || echo UP)" ;;
    *"scontrol update PartitionName="*) p=${*#*PartitionName=}; p=${p%% *}; echo "${*##*State=}" > "$D/part_$p" ;;
    *"patch loginset"*'"replicas":0'*) echo 0 > "$D/replicas" ;;
    *"patch loginset"*'"replicas":1'*) echo 1 > "$D/replicas" ;;
    *"get loginset prace -o jsonpath='{.spec.replicas}'"*) cat "$D/replicas" 2>/dev/null || echo 1 ;;
    *"get loginset"*) echo "prace=1" ;;
    *"get pods -l app.kubernetes.io/name=login -o name"*) : ;;
    *"get pods -l app.kubernetes.io/name=slurmd -o name"*) : ;;
    *"squeue"*) : ;;
    *"jsonpath='{.spec.unschedulable}'"*) n=${*#*get node }; n=${n%% *}; cat "$D/cordon_$n" 2>/dev/null || echo false ;;
    *"kubectl uncordon "*) echo false > "$D/cordon_${*##* }" ;;
    *"kubectl cordon "*) echo true > "$D/cordon_${*##* }" ;;
    *"findmnt -rn -t nfs,nfs4"*) : ;;
    *"/proc/[0-9]*"*) : ;;
    *"if mountpoint -q /home; then echo \"mounted"*) echo "mounted /dev/mapper/hpe_vg-home" ;;
    *"prace-tree-listing --no-label /home"*) echo L0 ;;
    *"prace-tree-listing --no-label /run/prace-storage/home-check"*) echo "${LV_LISTING:-L0}" ;;
    *"exportfs -u"*) return 0 ;;
    *"prace-slinky-worker-check"*) return 0 ;;
    *"status.conditions"*) echo True ;;
    *"df -B1 --output=size /home"*) echo 214748364800 ;;
    *"sha256sum /usr/local/sbin/prace-tree-listing"*) echo helpersha ;;
    *) return 0 ;;
  esac
}
C() {
  log "C $*"
  case "$*" in
    *"0) echo mounted ;; 32) echo unmounted"*) echo mounted ;;
    *"fuser -vm /home"*) : ;;
    *"NO /home MOUNT"*) : ;;                                              # recovery sweep: all answer
    *"findmnt -rn -t nfs,nfs4"*) echo /home ;;
    *) return 0 ;;
  esac
}
PROBE() { log "PROBE $*"; printf 'syn-probe\n10.90.10.1:/home 214748364800\n'; }
'''


class Rollback(unittest.TestCase):
    """S1: the fence comes first; any failed observation stops; writes since the cutover refuse."""

    def test_failed_home_observation_stops_before_any_change(self):
        r, calls = run(HEALTHY + r'''
eval "$(declare -f L | sed 's/^L ()/L_healthy ()/')"
L() { case "$*" in *"if mountpoint -q /home; then echo \"mounted"*) log "L $*"; return 255 ;; *) L_healthy "$@" ;; esac; }
''', "ACTION=rollback; rollback")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("could not be established", r.stdout)
        joined = "\n".join(calls)
        self.assertLess(joined.index("mkdir /run/prace-cluster-lease"), joined.index("mountpoint -q /home; then"))
        self.assertNotIn("ROLLBACK B", r.stdout)
        self.assertNotIn("umount /home", joined)
        self.assertIn("cluster lease released", r.stdout)            # nothing changed: the window closes

    def test_write_after_the_fence_is_seen_and_refused(self):
        r, calls = run(HEALTHY + r'''
eval "$(declare -f L | sed 's/^L ()/L_healthy ()/')"
L() { case "$*" in *"prace-tree-listing --no-label /home"*) log "L $*"; echo "L0-plus-a-new-file" ;; *) L_healthy "$@" ;; esac; }
''', "ACTION=rollback; rollback")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("would hide those writes", r.stdout)
        self.assertNotIn("ROLLBACK B", r.stdout)
        joined = "\n".join(calls)
        # order: fence, clients detached, export withdrawn, THEN the comparison
        self.assertLess(joined.index("scontrol update PartitionName=cpu State=DRAIN"), joined.index("umount /home"))
        self.assertLess(joined.index("umount /home"), joined.index("exportfs -u"))
        self.assertLess(joined.index("exportfs -u"), joined.index("prace-tree-listing --no-label /home"))
        self.assertIn("exportfs -ra", joined)                          # undo: exported and mounted again
        self.assertIn("cluster lease released", r.stdout)

    def test_unexpected_home_state_stops(self):
        r, _ = run(HEALTHY + r'''
eval "$(declare -f L | sed 's/^L ()/L_healthy ()/')"
L() { case "$*" in *"if mountpoint -q /home; then echo \"mounted"*) echo "mounted /dev/sdz1" ;; *) L_healthy "$@" ;; esac; }
''', "ACTION=rollback; rollback")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("unexpected /home state", r.stdout)
        self.assertNotIn("ROLLBACK B", r.stdout)

    def test_adopted_stopped_cutover_stays_fenced_on_a_failed_observation(self):
        r, calls = run(HEALTHY + r'''
eval "$(declare -f L | sed 's/^L ()/L_healthy ()/')"
L() {
  case "$*" in
    *"grep -q '^holder=storage-cutover "*) log "L $*"; echo "id=oldid stamp=T1 phase=changed parts=cpu=UP loginsets=prace=1 cordoned=w1,w2" ;;
    *"if mountpoint -q /home; then echo \"mounted"*) log "L $*"; return 255 ;;
    *) L_healthy "$@" ;;
  esac
}
''', "ACTION=rollback; rollback")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("STOPPED IN PHASE 'changed'", r.stdout)
        joined = "\n".join(calls)
        self.assertNotIn("uncordon", joined)
        self.assertNotIn("rm -rf /run/prace-cluster-lease", joined)


ADOPTED_CHANGED = r'''
eval "$(declare -f L | sed 's/^L ()/L_base ()/')"
L() {
  case "$*" in
    *"grep -q '^holder=storage-cutover "*) log "L $*"; echo "id=oldid stamp=T1 phase=${ADOPT_PHASE:-changed} parts=cpu=UP,gpu=UP loginsets=prace=1 cordoned=w1,w2" ;;
    *) L_base "$@" ;;
  esac
}
'''


class AdoptedRollback(unittest.TestCase):
    """A rollback that took over a stopped cutover's fence must never reopen it by backing out."""

    def assert_kept(self, r, calls):
        joined = "\n".join(calls)
        self.assertNotEqual(r.returncode, 0)
        for reopened in ("uncordon", "State=UP", '"replicas":1', "rm -rf /run/prace-cluster-lease"):
            self.assertNotIn(reopened, joined)
        self.assertIn("storage-cutover.state", joined)                 # the record is written again

    def test_listing_failure_after_detach(self):
        r, calls = run(HEALTHY + ADOPTED_CHANGED + r'''
eval "$(declare -f L | sed 's/^L ()/L_a ()/')"
L() { case "$*" in *"prace-tree-listing --no-label /home"*) log "L $*"; return 255 ;; *) L_a "$@" ;; esac; }
''', "ACTION=rollback; rollback")
        self.assertIn("ROLLBACK A", r.stdout)
        self.assert_kept(r, calls)

    def test_refused_writes_after_detach(self):
        r, calls = run(HEALTHY + ADOPTED_CHANGED + r'''
eval "$(declare -f L | sed 's/^L ()/L_a ()/')"
L() { case "$*" in *"prace-tree-listing --no-label /home"*) log "L $*"; echo "different" ;; *) L_a "$@" ;; esac; }
''', "ACTION=rollback; rollback")
        self.assertIn("would hide those writes", r.stdout)
        self.assert_kept(r, calls)

    def test_busy_client(self):
        r, calls = run(HEALTHY + ADOPTED_CHANGED + r'''
eval "$(declare -f C | sed 's/^C ()/C_a ()/')"
C() { case "$*" in *"fuser -vm /home"*) log "C $*"; echo "/home: root 123 ..c.. bash" ;; *) C_a "$@" ;; esac; }
''', "ACTION=rollback; rollback")
        self.assert_kept(r, calls)

    def test_adopted_recovering_phase_is_kept_too(self):
        r, calls = run(HEALTHY + ADOPTED_CHANGED + r'''
eval "$(declare -f L | sed 's/^L ()/L_a ()/')"
L() { case "$*" in *"prace-tree-listing --no-label /home"*) log "L $*"; echo "different" ;; *) L_a "$@" ;; esac; }
''', "ADOPT_PHASE=recovering ACTION=rollback; rollback")
        self.assert_kept(r, calls)

    def test_unchanged_lv_rolls_back_and_recovers(self):
        r, calls = run(HEALTHY + r'''
PROBE() { log "PROBE $*"; printf 'syn-probe\n10.90.10.1:/home 214748364800\n'; }
''', "ACTION=rollback; rollback")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("ROLLBACK B", r.stdout)
        self.assertIn("RESULT: ROLLED BACK", r.stdout)
        joined = "\n".join(calls)
        self.assertLess(joined.index("mv /var/lib/prace-home-premigration/home-T1 /home"), joined.index("PROBE"))
        self.assertIn("rm -rf /run/prace-cluster-lease", joined)


class HelperVersion(unittest.TestCase):
    def test_rollback_refuses_when_the_listing_helper_changed_since_the_cutover(self):
        r, calls = run(HEALTHY + r'''
eval "$(declare -f L | sed 's/^L ()/L_h ()/')"
L() { case "$*" in *"sha256sum /usr/local/sbin/prace-tree-listing"*) log "L $*"; echo othersha ;; *) L_h "$@" ;; esac; }
''', "ACTION=rollback; rollback")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("listing helper changed since the cutover", r.stdout)
        joined = "\n".join(calls)
        # checked where a listing is compared: after the fence, before anything is detached
        self.assertLess(joined.index("mkdir /run/prace-cluster-lease"), joined.index("sha256sum"))
        self.assertNotIn("umount /home", joined)
        self.assertIn("cluster lease released", r.stdout)                     # own fence: verified back-out


class Recovery(unittest.TestCase):
    """S2/S3: recovery proves workers, mounts and logins before anything reopens."""

    ADOPTED = r'''
LEASED=1 LEASE_ID=oldid FENCED_PARTS="cpu=UP gpu=UP" LOGIN_REPLICAS="prace=1" CORDONED="w1 w2"
'''

    def assert_still_fenced(self, r, calls):
        joined = "\n".join(calls)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("RECOVERY INCOMPLETE", r.stdout)
        self.assertNotIn("State=UP", joined)                            # partitions never reopened
        self.assertNotIn("rm -rf /run/prace-cluster-lease", joined)      # lease kept
        self.assertNotIn("RESULT: PASS", r.stdout)

    def test_failed_worker_is_cordoned_again_and_nothing_reopens(self):
        r, calls = run(HEALTHY + self.ADOPTED + r'''
eval "$(declare -f L | sed 's/^L ()/L_healthy ()/')"
L() { case "$*" in *"prace-slinky-worker-check w1"*) log "L $*"; return 1 ;; *) L_healthy "$@" ;; esac; }
''', "recover")
        self.assert_still_fenced(r, calls)
        joined = "\n".join(calls)
        self.assertIn("k3s kubectl cordon w1", joined)
        self.assertNotIn("uncordon w2", joined)                         # the next worker is not touched
        self.assertNotIn('"replicas":1', joined)                        # logins stay closed
        self.assertIn("cordoned: w1 w2", r.stdout)   # w1 never left the record

    def test_stale_mount_fails(self):
        r, calls = run(HEALTHY + self.ADOPTED + r'''
eval "$(declare -f C | sed 's/^C ()/C_healthy ()/')"
C() { case "$*" in *"NO /home MOUNT"*) log "C $*"; echo "STALE /home" ;; *) C_healthy "$@" ;; esac; }
''', "recover")
        self.assert_still_fenced(r, calls)
        self.assertIn("STALE /home", r.stdout)

    def test_failed_enumeration_is_not_an_empty_list(self):
        r, calls = run(HEALTHY + self.ADOPTED + r'''
eval "$(declare -f C | sed 's/^C ()/C_healthy ()/')"
C() { case "$*" in *"NO /home MOUNT"*) log "C $*"; echo "ENUMERATION FAILED"; return 3 ;; *) C_healthy "$@" ;; esac; }
''', "recover")
        self.assert_still_fenced(r, calls)

    def test_login_not_ready_closes_logins_again(self):
        r, calls = run(HEALTHY + self.ADOPTED + r'''
eval "$(declare -f L | sed 's/^L ()/L_healthy ()/')"
L() { case "$*" in *"status.conditions"*) log "L $*"; echo False ;; *) L_healthy "$@" ;; esac; }
''', "recover")
        self.assert_still_fenced(r, calls)
        joined = "\n".join(calls)
        self.assertIn('"replicas":1', joined)                           # opened for the check ...
        self.assertLess(joined.index('"replicas":1'), joined.rindex('"replicas":0'))   # ... and closed again
        self.assertIn("not Ready", r.stdout)

    def test_login_query_failure_is_not_success(self):
        r, calls = run(HEALTHY + self.ADOPTED + r'''
eval "$(declare -f L | sed 's/^L ()/L_healthy ()/')"
L() { case "$*" in *"status.conditions"*) log "L $*"; return 255 ;; *) L_healthy "$@" ;; esac; }
''', "recover")
        self.assert_still_fenced(r, calls)

    def test_login_seeing_the_old_home_fails(self):
        r, calls = run(HEALTHY + self.ADOPTED + r'''
PROBE() { log "PROBE $*"; printf 'syn-probe\n10.90.10.1:/home 85899345920\n'; }
''', "recover")
        self.assert_still_fenced(r, calls)
        self.assertIn("does not see the server's /home", r.stdout)

    def test_failed_probe_login_fails(self):
        r, calls = run(HEALTHY + self.ADOPTED + r'''
PROBE() { log "PROBE $*"; return 255; }
''', "recover")
        self.assert_still_fenced(r, calls)

    def test_interrupted_worker_check_stays_recorded_as_cordoned(self):
        r, calls = run(HEALTHY + self.ADOPTED + r'''
eval "$(declare -f L | sed 's/^L ()/L_healthy ()/')"
L() { case "$*" in *"prace-slinky-worker-check w1"*) log "L $*"; kill -TERM $$; sleep 1 ;; *) L_healthy "$@" ;; esac; }
''', "recover")
        self.assert_still_fenced(r, calls)
        states = [c for c in calls if "storage-cutover.state" in c]
        self.assertIn("k3s kubectl cordon w1", "\n".join(calls))        # quarantine cordons it again

    def test_rehearsal_recovery_checks_mounts_only(self):
        r, calls = run(HEALTHY + self.ADOPTED + 'K8S=0 CLIENTS="sr-client:2252" TARGET=rehearsal\n', "recover; echo RECOVERED")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        joined = "\n".join(calls)
        self.assertIn("mountpoint -q /home ||", joined)
        self.assertNotIn("PROBE", joined)

    def test_recover_refuses_a_cutover_not_in_recovery(self):
        r, calls = run(HEALTHY + ADOPTED_CHANGED, "ACTION=recover; main --fleet --evidence $D recover --stamp T1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not in recovery", r.stdout)
        joined = "\n".join(calls)
        for reopened in ("uncordon", "State=UP", "rm -rf /run/prace-cluster-lease"):
            self.assertNotIn(reopened, joined)

    def test_healthy_recovery_reopens_in_order(self):
        r, calls = run(HEALTHY + self.ADOPTED, "recover; echo RECOVERED")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        joined = "\n".join(calls)
        order = ["uncordon w1", "prace-slinky-worker-check w1", "uncordon w2", "prace-slinky-worker-check w2",
                 '"replicas":1', "status.conditions", "PROBE", "PartitionName=cpu State=UP", "rm -rf /run/prace-cluster-lease"]
        positions = [joined.index(x) for x in order]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("RECOVERED", r.stdout)


ADOPT = r'''
eval "$(declare -f L | sed 's/^L ()/L_base ()/')"
L() {
  case "$*" in
    *"grep -q '^holder=storage-cutover "*) log "L $*"; echo "id=oldid stamp=T1 phase=${ADOPT_PHASE:-changed} parts=cpu=UP,gpu=UP loginsets=prace=1 cordoned=w1,w2" ;;
    *"if mountpoint -q /home; then echo"*) log "L HOME_STATE"; echo "$HOME_STATE" ;;
    *) L_base "$@" ;;
  esac
}
'''


def reopened(calls):
    joined = "\n".join(calls)
    return [x for x in ("uncordon", "State=UP", "rm -rf /run/prace-cluster-lease") if x in joined]


class EarlyBackout(unittest.TestCase):
    """R1: after the fence stopped logins and deleted the slurmd pods, a back-out reopens only
    through verified recovery (worker checks, mounts, Ready login pod, real login)."""

    def assert_verified_before_reopen(self, r, calls):
        joined = "\n".join(calls)
        self.assertNotEqual(r.returncode, 0)                            # the run itself failed
        self.assertIn("verified recovery before anything reopens", r.stdout)
        for check in ("prace-slinky-worker-check w1", "status.conditions", "PROBE"):
            self.assertLess(joined.index(check), joined.index("State=UP"), check)
        self.assertIn("rm -rf /run/prace-cluster-lease", joined)

    def test_consumer_check_failure(self):
        r, calls = run(HEALTHY + r'''
eval "$(declare -f L | sed 's/^L ()/L_h ()/')"
L() { case "$*" in *"/proc/[0-9]*"*) log "L $*"; echo "123 bash /home/x" ;; *) L_h "$@" ;; esac; }
''', "fence; consumers")
        self.assert_verified_before_reopen(r, calls)

    def test_accounts_check_failure(self):
        r, calls = run(HEALTHY + 'accounts_zero() { log "ACCOUNTS_ZERO $*"; return 1; }\n',
                       "fence; consumers; accounts_zero pre || fail 'accounts not converged'")
        self.assert_verified_before_reopen(r, calls)

    def test_backup_failure(self):
        r, calls = run(HEALTHY + r'''
eval "$(declare -f C | sed 's/^C ()/C_h ()/')"
C() { case "$*" in *"cp -a /etc/fstab"*) log "C $*"; return 1 ;; *) C_h "$@" ;; esac; }
''', "fence; consumers; backups")
        self.assert_verified_before_reopen(r, calls)

    def test_failed_recovery_during_backout_stays_fenced_and_closes_logins(self):
        r, calls = run(HEALTHY + r'''
eval "$(declare -f L | sed 's/^L ()/L_h ()/')"
L() { case "$*" in *"prace-slinky-worker-check w1"*) log "L $*"; return 1 ;; *"/proc/[0-9]*"*) echo "1 x /home" ;; *) L_h "$@" ;; esac; }
''', "fence; consumers")
        self.assertNotEqual(r.returncode, 0)
        joined = "\n".join(calls)
        self.assertNotIn("State=UP", joined)
        self.assertNotIn("rm -rf /run/prace-cluster-lease", joined)
        self.assertNotIn("uncordon w2", joined)                          # the next worker is never touched
        self.assertGreater(joined.rindex("k3s kubectl cordon w1"), joined.index("uncordon w1"))   # checked, failed, cordoned again
        self.assertIn("loginset prace at 0 replicas (confirmed)", r.stdout)
        self.assertIn("RECOVERY INCOMPLETE", r.stdout)

    def test_rehearsal_backout_before_disruption_just_closes(self):
        r, calls = run(HEALTHY + 'K8S=0 CLIENTS="sr-client:2252" TARGET=rehearsal\n', "fence; fail 'early'")
        self.assertIn("cluster lease released", r.stdout)
        self.assertNotIn("verified recovery", r.stdout)


class PartialCutoverRollback(unittest.TestCase):
    """R2: a cutover stopped around the rename/mount boundaries is rolled back from its recorded
    phase, the preserved tree and the verified /home state; anything ambiguous stays fenced."""

    def rollback(self, home_state, phase="changed"):
        return run(HEALTHY + ADOPT + f'HOME_STATE="{home_state}"; ADOPT_PHASE={phase}\n', "ACTION=rollback; rollback")

    def test_stopped_after_the_move_before_the_mount(self):
        for state in ("root home=absent old=1 lvmounted=0", "root home=empty old=1 lvmounted=0"):
            with self.subTest(state):
                r, calls = self.rollback(state)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                joined = "\n".join(calls)
                self.assertIn("partial cutover", r.stdout)
                self.assertNotIn("prace-tree-listing --no-label /home", joined)       # never served: no comparison
                self.assertIn("mv /var/lib/prace-home-premigration/home-T1 /home", joined)
                self.assertLess(joined.index("mv /var/lib/prace-home-premigration/home-T1 /home"), joined.index("PROBE"))
                self.assertIn("RESULT: ROLLED BACK", r.stdout)

    def test_tree_in_place_with_changed_record_finishes_rollback_b(self):
        # stopped before the move-aside, or rollback B stopped after putting the tree back: its
        # fstab, labels, deferred converge and client fstabs are (re)done, then verified recovery
        r, calls = self.rollback("root home=populated old=0 lvmounted=0")
        joined = "\n".join(calls)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("finish rollback B", r.stdout)
        self.assertNotIn("mv /var/lib/prace-home-premigration", joined)
        order = ["restorecon -R /home", "ANSIBLE rollback-login", "cp -a /etc/fstab.prace-pre-storage-T1 /etc/fstab && systemctl daemon-reload && (mountpoint",
                 "prace-slinky-worker-check w1", "PROBE", "State=UP"]
        positions = [joined.index(x) for x in order]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("RESULT: ROLLED BACK", r.stdout)

    def test_tree_never_moved_is_undone(self):
        for phase, result in (("detached", "UNDONE"), ("disrupted", "UNDONE"), ("stuck", "UNDONE"), ("recovering", "RECOVERED")):
            for state in ("root home=populated old=0 lvmounted=0", "root home=populated old=0 lvmounted=staged"):
                with self.subTest(phase=phase, state=state):
                    r, calls = self.rollback(state, phase)
                    joined = "\n".join(calls)
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                    self.assertNotIn("mv /var/lib/prace-home-premigration", joined)
                    self.assertIn("for d in /run/prace-storage/home-new /run/prace-storage/home-check; do if mountpoint", joined)   # unstaged
                    # every client is remounted, not only ones this run detached (the crashed run did that)
                    mounts = [c for c in calls if c.startswith("C ") and "mountpoint -q /home || mount /home" in c]
                    self.assertEqual(sorted(c.split()[1] for c in mounts), ["10.0.0.1", "10.0.0.2"])
                    self.assertLess(joined.index("prace-slinky-worker-check w1"), joined.index("State=UP"))   # verified reopen
                    self.assertIn(f"RESULT: {result}", r.stdout)

    def test_partial_state_compares_the_lv_whatever_the_record(self):
        # R2/#8, #6: an unmounted LV proves nothing once logins may have written to it: it is listed
        # read-only and compared with L0; any difference refuses, whatever phase is recorded
        for phase in ("changed", "recovering", "done", "stuck", "disrupted"):
            for state in ("root home=absent old=1 lvmounted=0", "root home=empty old=1 lvmounted=staged"):
                with self.subTest(phase=phase, state=state):
                    r, calls = run(HEALTHY + ADOPT + f'HOME_STATE="{state}"; ADOPT_PHASE={phase}; LV_LISTING=L0-plus-writes\n',
                                   "ACTION=rollback; rollback")
                    joined = "\n".join(calls)
                    self.assertNotEqual(r.returncode, 0)
                    self.assertIn("would hide those writes", r.stdout)
                    self.assertIn("mount -o ro,nodev,nosuid /dev/hpe_vg/home /run/prace-storage/home-check", joined)
                    self.assertEqual(reopened(calls), [])
                    self.assertNotIn("mv /var/lib/prace-home-premigration", joined)
                    self.assertNotIn('"replicas":1', joined)

    def test_partial_state_without_l0_needs_the_recorded_move(self):
        for phase in ("recovering", "done", "stuck", "disrupted", "detached"):
            with self.subTest(phase=phase):
                r, calls = run(HEALTHY + ADOPT + f'HOME_STATE="root home=empty old=1 lvmounted=0"; ADOPT_PHASE={phase}\n'
                               'rm -f "$EVID/L0-home-nolabel.jsonl"\n', "ACTION=rollback; rollback")
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("is not a stopped move", r.stdout)
                self.assertEqual(reopened(calls), [])
                self.assertNotIn("mv /var/lib/prace-home-premigration", "\n".join(calls))

    def test_staged_lv_with_a_changed_record_stays_fenced(self):
        r, calls = self.rollback("root home=populated old=0 lvmounted=staged")
        self.assertNotEqual(r.returncode, 0)
        self.assertEqual(reopened(calls), [])
        self.assertNotIn("umount /run/prace-storage/home-new", "\n".join(calls))

    def test_ambiguous_states_stay_fenced(self):
        for state in ("root home=populated old=1 lvmounted=0", "root home=empty old=1 lvmounted=1",
                      "root home=absent old=0 lvmounted=0"):
            with self.subTest(state):
                r, calls = self.rollback(state)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("does not restore automatically", r.stdout)
                self.assertEqual(reopened(calls), [])
                self.assertNotIn("mv /var/lib/prace-home-premigration", "\n".join(calls))

    def test_lv_state_without_l0_refuses(self):
        r, calls = run(HEALTHY + ADOPT + 'HOME_STATE="mounted /dev/mapper/hpe_vg-home"\nrm -f "$EVID/L0-home-nolabel.jsonl"\n',
                       "ACTION=rollback; rollback")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("no L0 to compare with", r.stdout)
        self.assertEqual(reopened(calls), [])


class ResumedQuarantine(unittest.TestCase):
    """R3: a resumed run cannot know whether an earlier one restored the logins: quarantine closes
    every recorded LoginSet and claims it only after reading 0 back."""

    def test_resumed_recovery_failing_early_closes_logins(self):
        r, calls = run(HEALTHY + ADOPT + 'ADOPT_PHASE=recovering; HOME_STATE=garbage; echo 1 > "$D/replicas"\n',
                       "main --fleet --evidence $D recover --stamp T1")
        self.assertNotEqual(r.returncode, 0)
        joined = "\n".join(calls)
        self.assertIn('"replicas":0', joined)
        self.assertIn("loginset prace at 0 replicas (confirmed)", r.stdout)
        self.assertEqual(reopened(calls), [])

    def test_unconfirmed_closure_is_not_claimed(self):
        r, calls = run(HEALTHY + ADOPT + r'''
ADOPT_PHASE=recovering; HOME_STATE=garbage
eval "$(declare -f L | sed 's/^L ()/L_q ()/')"
L() { case "$*" in *"get loginset prace -o jsonpath='{.spec.replicas}'"*) echo 1 ;; *) L_q "$@" ;; esac; }
''', "main --fleet --evidence $D recover --stamp T1")
        self.assertIn("QUARANTINE NOT CONFIRMED", r.stdout)
        self.assertNotIn("loginset prace at 0 replicas (confirmed)", r.stdout)
        self.assertNotIn("workers cordoned (confirmed)", r.stdout)
        self.assertIn("partition cpu drained (confirmed)", r.stdout)       # what was read back, only

    def test_quarantine_drains_partitions_and_reads_them_back(self):
        r, calls = run(HEALTHY + ADOPT + 'ADOPT_PHASE=recovering; HOME_STATE=garbage; echo UP > "$D/part_cpu"\n',
                       "main --fleet --evidence $D recover --stamp T1")
        joined = "\n".join(calls)
        self.assertIn("PartitionName=cpu State=DRAIN", joined)
        self.assertIn("scontrol show partition cpu -o", joined)
        self.assertIn("partitions drained, logins closed and the recorded workers cordoned (confirmed)", r.stdout)


class ReadBacks(unittest.TestCase):
    def test_a_cordon_that_does_not_stick_is_not_confirmed(self):
        r, _ = run(HEALTHY + ADOPT + r'''
ADOPT_PHASE=recovering; HOME_STATE=garbage
eval "$(declare -f L | sed 's/^L ()/L_q ()/')"
L() { case "$*" in *"kubectl cordon w1"*) log "L $*" ;; *"get node w1 -o jsonpath"*) log "L $*"; echo "" ;; *) L_q "$@" ;; esac; }
''', "main --fleet --evidence $D recover --stamp T1")
        self.assertIn("QUARANTINE: w1 reads unschedulable=''", r.stdout)
        self.assertIn("QUARANTINE NOT CONFIRMED", r.stdout)
        self.assertNotIn("w1 cordoned (confirmed)", r.stdout)

    def test_nfs_listing_tells_nothing_mounted_from_a_failure(self):
        for body, rc, out in (("exit 1", 0, ""), ("echo /home; echo /apps", 0, "/home\n/apps\n"),
                              ("echo \"findmnt: can't read /proc/self/mountinfo\" >&2; exit 1", 3, "")):
            with self.subTest(body):
                with tempfile.TemporaryDirectory() as d:
                    (Path(d) / "findmnt").write_text("#!/bin/sh\n" + body + "\n"); (Path(d) / "findmnt").chmod(0o755)
                    r = subprocess.run(["bash", "-c", f'source {TOOL}; bash -c "$NFSLIST"'], capture_output=True, text=True,
                                       timeout=30, env={"PATH": f"{d}:/usr/bin:/bin", "HOME": d})
                self.assertEqual((r.returncode, r.stdout), (rc, out))


class AdoptedRefusals(unittest.TestCase):
    """#10: when this run adopted a stopped fence, its own refusals keep that fence; only a
    successful undo, rollback or recovery reopens it."""

    def test_recover_refusing_an_adopted_disrupted_fence_keeps_it(self):
        for state in ("garbage", "mounted /dev/sdz1", "root home=populated old=1 lvmounted=0", "root home=empty old=1 lvmounted=0"):
            with self.subTest(state):
                r, calls = run(HEALTHY + ADOPT + f'ADOPT_PHASE=disrupted; HOME_STATE="{state}"\n',
                               "main --fleet --evidence $D recover --stamp T1")
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(reopened(calls), [])
                self.assertNotIn('"replicas":1', "\n".join(calls))
                self.assertIn("STOPPED IN PHASE 'disrupted'", r.stdout)
                self.assertIn("loginset prace at 0 replicas (confirmed)", r.stdout)

    def test_rollback_refusing_an_adopted_disrupted_fence_keeps_it(self):
        for state in ("garbage", "mounted /dev/sdz1", "root home=populated old=1 lvmounted=0", "root home=empty old=1 lvmounted=1"):
            with self.subTest(state):
                r, calls = run(HEALTHY + ADOPT + f'ADOPT_PHASE=disrupted; HOME_STATE="{state}"\n', "ACTION=rollback; rollback")
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(reopened(calls), [])
                self.assertNotIn("verified recovery before anything reopens", r.stdout)
                self.assertIn("STOPPED IN PHASE 'disrupted'", r.stdout)

    def test_own_fence_still_backs_out_by_verified_recovery(self):
        r, calls = run(HEALTHY + 'HOME_STATE=garbage\n' + ADOPT.replace("*\"grep -q '^holder=storage-cutover \"*) log \"L $*\"; echo", "*\"grep -q '^holder=storage-cutover \"*) return 1; echo"),
                       "ACTION=rollback; rollback")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("verified recovery before anything reopens", r.stdout)
        self.assertIn("cluster lease released", r.stdout)


class HomeState(unittest.TestCase):
    """#11: findmnt exits 1 both for 'not mounted' (silent) and for errors (a message on stderr)."""

    def state(self, findmnt, ls=None):
        with tempfile.TemporaryDirectory() as d:
            for name, body in (("mountpoint", "exit 1"), ("findmnt", findmnt)) + ((("ls", ls),) if ls else ()):
                (Path(d) / name).write_text("#!/bin/sh\n" + body + "\n"); (Path(d) / name).chmod(0o755)
            script = (f'source {TOOL}; VG=hpe_vg OLD={d}/no-old-tree; L() {{ bash -c "$1"; }}\n'
                      'home_state; echo "rc=$?"')
            r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                               env={"PATH": f"{d}:/usr/bin:/bin", "HOME": d})
            return r.stdout

    def test_silent_exit_1_is_not_mounted(self):
        self.assertRegex(self.state("exit 1"), r"old=0 lvmounted=0\nrc=0")

    def test_exit_1_with_a_message_is_unknown(self):
        out = self.state("echo \"findmnt: can't read /proc/self/mountinfo: No such file\" >&2; exit 1")
        self.assertIn("findmnt failed", out)
        self.assertIn("rc=1", out)

    def test_unreadable_home_is_unknown_not_empty(self):
        out = self.state("exit 1", ls="echo 'ls: cannot open directory /home' >&2; exit 2")
        self.assertIn("rc=1", out)
        self.assertNotIn("home=empty", out)

    def test_staging_mount_is_reported_as_staged(self):
        self.assertRegex(self.state("echo /run/prace-storage/home-new"), r"lvmounted=staged\nrc=0")
        self.assertRegex(self.state("echo /run/prace-storage/home-check"), r"lvmounted=staged\nrc=0")
        self.assertRegex(self.state("echo /srv/elsewhere"), r"lvmounted=1\nrc=0")


# A simulated fleet (or rehearsal pair): every fact is a file under $W, shared by the processes of
# one test, so each run of the tool is a new session that sees what earlier ones left behind.
# SIM_KILL_AFTER=N kills the run (SIGKILL, no cleanup) right after its Nth remote call.
WORLD = r'''
log() { printf '%s\n' "$*" >> "$W/calls"; }
g() { cat "$W/$1" 2>/dev/null || echo "$2"; }
s() { printf '%s\n' "$2" > "$W/$1"; }
sleep() { :; }
ssh() { :; }                      # on_exit's mux cleanup, the gate's fresh ProxyJump
git() { case "$1" in rev-parse) echo abc ;; *) return 0 ;; esac; }
date() { case "${1:-}" in +%Y%m%dT%H%M%S) echo T1 ;; *) command date "$@" ;; esac; }
repo_helper_sha() { echo helpersha; }
tick() {   # tick <what>: numbers the run's remote calls (the first line of each is kept)
  local n=$(( $(g count 0) + 1 )); s count "$n"; printf '%s %s\n' "$n" "${1%%$'\n'*}" >> "$W/numbered"
  if [ "$n" = "${SIM_KILL_AFTER:-0}" ]; then echo "   (sim) killed after call $n"; kill -KILL 0; fi   # the whole run, subshells too
}
simfail() {   # SIM_FAILPAT="p1;;p2": remote calls whose "L cmd" / "C addr cmd" contains a pattern fail (rc 255, no effect)
  local p rest=${SIM_FAILPAT:-}
  while [ -n "$rest" ]; do
    p=${rest%%;;*}; [ "$p" = "$rest" ] && rest="" || rest=${rest#*;;}
    [[ $1 == *"$p"* ]] && return 0
  done
  return 1
}
lost() {   # SIM_LOSTPAT: the first matching command runs, and its status is lost (a dropped connection)
  [ -n "${SIM_LOSTPAT:-}" ] && [[ $1 == *"$SIM_LOSTPAT"* ]] && [ ! -e "$W/lost_once" ] && : > "$W/lost_once"
}
L() { log "L $*"; local rc=0; if simfail "L $*"; then rc=255; else Lw "$*" || rc=$?; lost "L $*" && rc=255; fi; tick "L $*"; return $rc; }
C() { local a=$1; shift; log "C $a $*"; local rc=0; if simfail "C $a $*"; then rc=255; else Cw "$a" "$*" || rc=$?; fi; tick "C $a $*"; return $rc; }
PROBE() { log "PROBE"; local rc=0; Pw || rc=$?; tick PROBE; return $rc; }
ansible_run() { log "ANSIBLE $*"; local rc=0; Aw "$1" || rc=$?; tick "ANSIBLE $*"; return $rc; }
accounts_zero() { log "ACCOUNTS_ZERO $*"; tick "ACCOUNTS_ZERO $*"; [ "${SIM_ACCOUNTS_FAIL:-0}" = 0 ]; }

Lw() {   # the login node and the Kubernetes/Slurm control plane
  local c=$1 n p v
  case "$c" in
    *"mkdir /run/prace-cluster-lease"*" && echo"*)                          # the lease, its holder line and its record
      [ -e "$W/lease" ] && return 1
      mkdir "$W/lease"; v=${c#*echo \'}; echo "${v%%\' >*}" > "$W/lease/holder"
      cat > "$W/lease/state" ;;
    *"cat > /run/prace-cluster-lease/storage-cutover.state"*)
      [ -d "$W/lease" ] || return 1; v=$(cat)
      [ -n "${SIM_STATE_FAILS_MATCH:-}" ] && [[ $v == *"$SIM_STATE_FAILS_MATCH"* ]] && return 1   # a failed record write
      printf '%s\n' "$v" > "$W/lease/state" ;;
    *"grep -q ' id="*"/run/prace-cluster-lease/holder"*)                 # the lease take read back
      [[ $c =~ \ id=([0-9a-z]+) ]] && grep -q " id=${BASH_REMATCH[1]} " "$W/lease/holder" ;;
    *"grep -q '^holder=storage-cutover "*) [ -f "$W/lease/state" ] && cat "$W/lease/holder" "$W/lease/state" ;;
    *"cat /run/prace-cluster-lease/holder"*) cat "$W/lease/holder" ;;
    *"rm -rf /run/prace-cluster-lease"*)
      [ "${SIM_LEASE_RM_FAILS:-0}" = 1 ] && return 1
      if ! [ -e "$W/lease" ]; then [[ $c == *'! [ -e /run/prace-cluster-lease ] ||'* ]]; return; fi   # only a guarded release is idempotent
      [[ $c =~ id=([0-9a-z]+) ]] && grep -q " id=${BASH_REMATCH[1]} " "$W/lease/holder" && rm -rf "$W/lease" ;;
    *"! [ -e /run/prace-cluster-lease ]"*) ! [ -e "$W/lease" ] ;;
    *"pgrep -u prace-rehearsal"*) return 1 ;;
    *"scontrol show partition -o"*) for p in cpu gpu; do echo "PartitionName=$p AllowGroups=ALL State=$(g part_$p UP) TotalCPUs=8"; done ;;
    *"scontrol show partition "*" -o"*) p=${c#*show partition }; p=${p%% *}; echo "PartitionName=$p AllowGroups=ALL State=$(g part_$p UP) TotalCPUs=8" ;;
    *"scontrol update PartitionName="*)
      p=${c#*PartitionName=}; p=${p%% *}; v=${c##*State=}
      [ "${SIM_PART_REOPEN_FAILS:-}" = "$p" ] && [ "$v" != DRAIN ] && return 1
      s part_$p "$v" ;;
    *"get loginset -o jsonpath"*) echo "prace=$(g replicas 1)" ;;
    *"patch loginset prace"*) [[ $c =~ \"replicas\":([0-9]+) ]] && s replicas "${BASH_REMATCH[1]}" ;;
    *"get loginset prace -o jsonpath='{.spec.replicas}'"*) g replicas 1 ;;
    *"get pods -l app.kubernetes.io/name=login -o name"*) [ "$(g replicas 1)" = 0 ] || echo pod/login-0 ;;
    *"status.conditions"*) [ "$(g replicas 1)" = 0 ] || { [ "$(g export 1)" = 1 ] && echo True || echo False; } ;;
    *"get pods -l app.kubernetes.io/name=slurmd -o name"*) for n in $(g nodes ""); do [ "$(g pod_$n 0)" = 0 ] || echo "pod/slurmd-$n"; done ;;
    *"delete pod -l app.kubernetes.io/name=slurmd"*) for n in $(g nodes ""); do [ "$(g cordon_$n 0)" = 1 ] && s pod_$n 0; done; return 0 ;;
    *"squeue"*) : ;;
    *"jsonpath='{.spec.unschedulable}'"*) n=${c#*get node }; n=${n%% *}; [ "$(g cordon_$n 0)" = 1 ] && echo true || echo false ;;
    *"kubectl uncordon "*) n=${c##* }; s cordon_$n 0; s pod_$n 1 ;;     # the NodeSet starts its slurmd pod again
    *"kubectl cordon "*) n=${c##* }; s cordon_$n 1 ;;                   # a running pod keeps running
    *"prace-slinky-worker-check"*)
      for n in ${c#*prace-slinky-worker-check }; do
        [ "$(g cordon_$n 0)" = 0 ] && [ "$(g pod_$n 0)" = 1 ] && [ "$(g export 1)" = 1 ] && [ "${SIM_WORKER_FAILS:-}" != "$n" ] \
          || { echo "$n: slurmd not ready"; return 1; }
      done ;;
    *"findmnt -rn -t nfs,nfs4"*) : ;;                                    # the login node mounts no NFS
    *"/proc/[0-9]*"*) : ;;
    *'if mountpoint -q /home; then echo "mounted'*)
      [ "${SIM_HOME_STATE_FAILS:-0}" = 1 ] && return 255
      if [ "$(g home populated)" = lv ]; then echo "mounted /dev/mapper/$VG-home"; return 0; fi
      v=0; [ "$(g staged 0)" = 1 ] && v=staged
      echo "root home=$(g home populated) old=$(g old 0) lvmounted=$v" ;;
    *"sha256sum /usr/local/sbin/prace-tree-listing"*) g helper helpersha ;;
    *"cp -a /etc/fstab /etc/fstab.prace-pre-storage-"*) s backup_login 1 ;;
    *"blkid -p -o value"*)                                                # the cutover's preconditions
      [ "$(g home populated)" = populated ] && [ "$(g staged 0)" = 0 ] && [ "$(g lvdata L0)" = L0 ] || { echo "not ready"; return 3; }
      echo "home LV blank" ;;
    *"echo 'no /var/lib/prace-home-premigration/"*)                         # rollback B on the login node
      [ "$(g old 0)" = 1 ] || { echo "no old tree"; return 3; }
      s export 0; s staged 0; [ "$(g home populated)" = lv ] && s home empty
      if [ "${SIM_RB_LOST_BEFORE_MV:-0}" = 1 ]; then s home absent; kill -KILL 0; fi
      s home populated; s old 0 ;;
    *"chmod 0755 /home; restorecon -R /home"*) [ "$(g home populated)" = populated ] || return 3 ;;
    *"[ -f /etc/fstab.prace-pre-storage-"*)                                 # rollback B's preflight
      [ "$(g backup_login 0)" = 1 ] || return 1
      case "$c" in *"[ -d /var/lib/prace-home-premigration/"*) [ "$(g old 0)" = 1 ] ;; esac ;;
    *"prace-tree-listing --no-label /run/prace-storage/home-check"*)        # the LV listed read-only off /home
      [ "$(g staged 0)" = 1 ] && [ "${SIM_STAGE_BUSY:-0}" = 1 ] && return 4
      [ "$(g home populated)" != lv ] && [ "${SIM_LV_UNREADABLE:-0}" = 0 ] || return 3; s staged 0; g lvdata L0 ;;
    *"a=/var/lib/prace-home-premigration/lv-"*) echo "LV archived"; s archived 1 ;;
    *"exportfs -ra && exportfs -v"*)                                       # undo A
      if [ "$(g staged 0)" = 1 ]; then
        if [ "${SIM_STAGE_BUSY:-0}" = 0 ]; then s staged 0
        elif [[ $c == *'umount $d || {'* ]]; then echo "the staged LV is in use"; return 3   # the tool checks its unmount
        fi                                                                 # (an unchecked one would carry on)
      fi
      case $(g home populated) in populated|lv) s export 1 ;; *) return 1 ;; esac ;;
    *"then exportfs -u"*) s export 0 ;;
    *"prace-tree-listing --summary"*) echo "81 entries" ;;
    *"prace-tree-listing /run/prace-storage/home-new"*) [ "$(g staged 0)" = 1 ] && g lvdata L0 ;;
    *"prace-tree-listing"*" /home"*) case $(g home populated) in lv) g lvdata L0 ;; populated) echo L0 ;; *) return 2 ;; esac ;;
    *"mount -o nodev,nosuid,usrquota"*) s staged 1; s lvdata L0 ;;          # the copy
    *"umount /run/prace-storage/home-new && rmdir"*) s staged 0 ;;
    *"mv /home /var/lib/prace-home-premigration/"*) [ "$(g home populated)" = populated ] || return 1; s old 1; s home empty ;;
    *"findmnt -no SOURCE,OPTIONS --mountpoint /home"*) [ "$(g home populated)" = lv ] && [ "$(g export 1)" = 1 ] ;;
    *"df -B1 --output=size /home"*) [ "$(g home populated)" = lv ] && echo 214748364800 || echo 85899345920 ;;
    *"ls -A /home | paste -sd,"*) case $(g home populated) in lv|populated) echo admin,syn-alice ;; *) echo ;; esac ;;
    *) return 0 ;;
  esac
}
Cw() {   # one client (its /home mount; its slurmd pod's kubelet NFS mount)
  local a=$1 c=$2 n; n=$(g name_$a x)
  case "$c" in
    *"NO /home MOUNT"*)                                                    # the recovery sweep
      [ "$(g cm_$a 1)" = 1 ] || { echo "NO /home MOUNT"; return 3; }
      [ "$(g export 1)" = 1 ] || echo "STALE /home" ;;
    *"0) echo mounted ;; 32) echo unmounted"*)                             # detach: the strict mount state
      [ -n "${SIM_MOUNTPOINT_FAILS:-}" ] && [ "$SIM_MOUNTPOINT_FAILS" = "$a" ] && { echo "mountpoint failed (1)"; return 3; }
      [ "$(g cm_$a 1)" = 1 ] && echo mounted || echo unmounted ;;
    *"fuser -vm /home"*) [ "${SIM_CLIENT_BUSY:-}" = "$a" ] && echo "/home: root 123 ..c.. bash"; return 0 ;;
    *"umount /home; r=0; mountpoint -q /home"*) s cm_$a 0 ;;
    *"mountpoint -q /home || mount /home; timeout 10 stat /home"*)
      [ "$(g cm_$a 1)" = 1 ] && return 0
      [ "$(g export 1)" = 1 ] || return 32; s cm_$a 1 ;;
    *'0) umount /home && { r=0;'*) s cm_$a 0 ;;                            # rollback B: unmount if mounted
    *"cp -a /etc/fstab /etc/fstab.prace-pre-storage-"*) s backup_$a 1 ;;
    *"[ -f /etc/fstab.prace-pre-storage-"*) [ "$(g backup_$a 0)" = 1 ] ;;
    *"cp -a /etc/fstab.prace-pre-storage-"*)                                # rollback B: old fstab, remount, same entries
      [ "$(g export 1)" = 1 ] && [ "$(g home populated)" = populated ] || return 32; s cm_$a 1 ;;
    *"timeout 10 stat -f /home /projects /apps"*)                          # the cutover: the client sees the server's LV
      [ "$(g cm_$a 1)" = 1 ] && [ "$(g export 1)" = 1 ] || return 1
      Lw "df -B1 --output=size /home"; Lw "ls -A /home | paste -sd," ;;
    *"findmnt -rn -t nfs,nfs4"*)                                           # consumers
      [ "$(g pod_$n 0)" = 1 ] && echo "/var/lib/kubelet/pods/p/volumes/kubernetes.io~nfs/home"
      [ "$(g cm_$a 1)" = 1 ] && echo /home; echo /projects; echo /apps ;;
    *) return 0 ;;
  esac
}
Pw() {   # a real login to the login pod
  [ "${SIM_PROBE_FAILS:-0}" = 0 ] && [ "$(g replicas 1)" != 0 ] && [ "$(g export 1)" = 1 ] || return 255
  printf 'syn-probe\n10.90.10.1:/home %s\n' "$(Lw 'df -B1 --output=size /home')"
}
Aw() {   # the playbook runs, by their log names
  case $1 in
    storage) [ "$(g home populated)" = empty ] && [ "$(g old 0)" = 1 ] || return 2; s home lv ;;
    accounts-quota-nfs) [ "$(g home populated)" = lv ] || return 2; s export 1 ;;
    clients-nfs) [ "$(g export 1)" = 1 ] || return 2; for a in $(g addrs ""); do s cm_$a 1; done ;;
    rollback-login)                                     # installs this checkout's helpers first; nfs_home reconciles the export set
      [ -n "${SIM_REPO_HELPER:-}" ] && s helper "$SIM_REPO_HELPER"
      [ "${SIM_TAIL_CONVERGE_FAILS:-0}" = 0 ] && [ "$(g home populated)" = populated ] || return 2; s export 1 ;;
    *) return 0 ;;
  esac
}
'''


class World:
    FLEET = [("lab-lenovo", "10.90.10.21"), ("lab-g005", "10.90.10.15"),
             ("lab-g003", "10.90.10.13"), ("lab-g004", "10.90.10.14")]

    def __init__(self, target="fleet"):
        self._tmp = tempfile.TemporaryDirectory()
        self.w = Path(self._tmp.name)
        self.target = target
        self.nodes = self.FLEET if target == "fleet" else [("sr-client", "2252")]
        facts = {"home": "populated", "old": "0", "staged": "0", "export": "1", "replicas": "1",
                 "part_cpu": "UP", "part_gpu": "UP", "nodes": " ".join(n for n, _ in self.nodes),
                 "addrs": " ".join(a for _, a in self.nodes)}
        for n, a in self.nodes:
            facts.update({f"name_{a}": n, f"cm_{a}": "1", f"cordon_{n}": "0", f"pod_{n}": "1" if target == "fleet" else "0"})
        for k, v in facts.items():
            (self.w / k).write_text(v + "\n")
        (self.w / "stubs.sh").write_text(WORLD)
        for d in ("tmp", "sr"):
            (self.w / d).mkdir()
        for f in ("k", "kh", "sr/id", "sr/known_hosts"):
            (self.w / f).touch()

    def __del__(self):
        self._tmp.cleanup()

    def __getitem__(self, fact):
        f = self.w / fact
        return f.read_text().strip() if f.exists() else None

    def set(self, **facts):
        for k, v in facts.items():
            (self.w / k).write_text(f"{v}\n")

    def run(self, *args, kill_after=0, **sim):
        (self.w / "count").write_text("0\n")
        (self.w / "numbered").write_text("")
        (self.w / "lost_once").unlink(missing_ok=True)
        with open(self.w / "calls", "a") as f:
            f.write(f"=== {' '.join(args) or 'cutover'} kill_after={kill_after} {sim}\n")
        env = {"PATH": "/usr/bin:/bin", "HOME": str(self.w), "TMPDIR": str(self.w / "tmp"), "W": str(self.w),
               "PRACE_PROBE_KEY": str(self.w / "k"), "PRACE_PROBE_KNOWN_HOSTS": str(self.w / "kh"),
               "PRACE_SR_DIR": str(self.w / "sr"), "PRACE_PAUSE": "0", "PRACE_WAIT_WORKER": "2", "PRACE_WAIT_LOGIN": "2",
               "SIM_KILL_AFTER": str(kill_after), **{k: str(v) for k, v in sim.items()}}
        return subprocess.run(["bash", "-c", 'source "$1"; source "$W/stubs.sh"; shift; main "$@"', "storage-cutover.sh",
                               str(TOOL), f"--{self.target}", "--evidence", str(self.w / "evid"), *args],
                              capture_output=True, text=True, timeout=120, env=env, cwd=self.w, stdin=subprocess.DEVNULL,
                              start_new_session=True)        # a simulated kill takes the run's whole process group

    def calls(self):
        return int(self["count"])

    def call_no(self, pattern, nth=1):
        """The number of the last run's nth remote call whose first line contains pattern."""
        hits = [int(l.split(" ", 1)[0]) for l in (self.w / "numbered").read_text().splitlines() if pattern in l]
        return hits[nth - 1]

    def record(self):
        f = self.w / "lease" / "state"
        return f.read_text().strip() if f.exists() else None

    def summary(self):
        keys = ["home", "old", "staged", "export", "replicas", "part_cpu", "part_gpu"]
        return (" ".join(f"{k}={self[k]}" for k in keys) + " lease=" + ("held" if (self.w / "lease").exists() else "free")
                + " mounted=" + "".join(self[f"cm_{a}"] for _, a in self.nodes)
                + " cordoned=" + "".join(self[f"cordon_{n}"] for n, _ in self.nodes))

    def is_open(self, home=("populated", "lv")):
        """Lease released and everything back: every client mounts the served /home."""
        ok = (not (self.w / "lease").exists() and self["export"] == "1" and self["staged"] == "0"
              and self["home"] in home and (self["home"] == "lv" or self["old"] == "0")
              and all(self[f"cm_{a}"] == "1" for _, a in self.nodes))
        if self.target == "fleet":
            ok = ok and self["replicas"] == "1" and self["part_cpu"] == self["part_gpu"] == "UP" \
                and all(self[f"cordon_{n}"] == "0" for n, _ in self.nodes)
        return ok

    def is_closed(self):
        """Lease held and the fence complete: no logins, drained, every worker cordoned."""
        ok = (self.w / "lease").exists()
        if self.target == "fleet":
            ok = ok and self["replicas"] == "0" and self["part_cpu"] == self["part_gpu"] == "DRAIN" \
                and all(self[f"cordon_{n}"] == "1" for n, _ in self.nodes)
        return ok


def sweep(fn, points):
    """fn(point) -> None or a failure string, for every point, in parallel (bash processes only)."""
    with ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 2)) as pool:
        return [f for f in pool.map(fn, points) if f]


def total_calls(target="fleet", *args, before=None):
    w = World(target)
    if before:
        before(w)
    r = w.run(*args)
    return w, r, w.calls()


def failures(fails):
    return "\n-----\n".join(fails[:3]) + f"\n({len(fails)} failing point(s))"


class InterruptedCutover(unittest.TestCase):
    """A cutover killed (SIGKILL, no cleanup) right after ANY remote call, then resumed in a new
    session: rollback always ends with the old /home served, every client mounted and the cluster
    open; recover either opens it verified or keeps it fenced, and a rollback after that restores."""

    def check(self, target, then_recover):
        _, r, total = total_calls(target)
        self.assertEqual(r.returncode, 0, r.stdout)

        def one(n):
            w = World(target)
            w.run(kill_after=n)
            if then_recover:
                r = w.run("recover", "--stamp", "T1")
                if not (w.is_open() if r.returncode == 0 else (w.is_open() or w.is_closed())):
                    return f"killed after call {n}, then recover rc {r.returncode}: {w.summary()}\n{r.stdout[-1500:]}"
            r = w.run("rollback", "--stamp", "T1")
            if r.returncode != 0 or "RESULT:" not in r.stdout or not w.is_open(("populated",)):
                return f"killed after call {n}, then rollback rc {r.returncode}: {w.summary()}\n{r.stdout[-1500:]}"
        fails = sweep(one, range(1, total + 1))
        self.assertFalse(fails, failures(fails))

    def test_fleet_then_rollback(self):
        self.check("fleet", False)

    def test_fleet_then_recover_then_rollback(self):
        self.check("fleet", True)

    def test_rehearsal_then_rollback(self):
        self.check("rehearsal", False)

    def test_rehearsal_then_recover_then_rollback(self):
        self.check("rehearsal", True)


class InterruptedRollback(unittest.TestCase):
    """A rollback killed right after any remote call (after a complete cutover, or after a cutover
    that was itself killed at a crash point) is finished by the next rollback."""

    def check(self, target, **crash):
        def prep(w):
            r = w.run(**crash)
            if not crash:
                self.assertEqual(r.returncode, 0, r.stdout)
        w0 = World(target)
        prep(w0)
        w0.run("rollback", "--stamp", "T1")
        total = w0.calls()

        def one(m):
            w = World(target)
            prep(w)
            w.run("rollback", "--stamp", "T1", kill_after=m)
            r = w.run("rollback", "--stamp", "T1")
            if r.returncode != 0 or "RESULT:" not in r.stdout or not w.is_open(("populated",)):
                return f"rollback killed after call {m}, then rollback rc {r.returncode}: {w.summary()}\n{r.stdout[-1500:]}"
        fails = sweep(one, range(1, total + 1))
        self.assertFalse(fails, failures(fails))

    def test_fleet(self):
        self.check("fleet")

    def test_rehearsal(self):
        self.check("rehearsal")

    def test_fleet_after_a_crashed_cutover(self):
        for point in ("after-copy", "before-move", "after-move", "after-mount"):
            with self.subTest(point):
                self.check("fleet", PRACE_CRASH_AT=point)


class ResumedSessions(unittest.TestCase):
    """The reviewed failure paths, each as sessions against the simulated fleet."""

    def test_copy_interrupted_recover_holds_and_rollback_undoes(self):
        # #2: the LV staged at home-new, clients detached, /home unexported
        w = World()
        w.run(PRACE_CRASH_AT="after-copy")
        self.assertEqual((w["staged"], w["export"]), ("1", "0"))
        self.assertIn(" phase=detached ", w.record() + " ")
        r = w.run("recover", "--stamp", "T1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not in recovery", r.stdout)
        self.assertNotIn("uncordon", (w.w / "numbered").read_text())
        self.assertTrue(w.is_closed(), w.summary())
        r = w.run("rollback", "--stamp", "T1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("RESULT: UNDONE", r.stdout)
        self.assertTrue(w.is_open(("populated",)), w.summary())

    def test_busy_staged_lv_stays_fenced_until_free(self):
        w = World()
        w.run(PRACE_CRASH_AT="after-copy")
        r = w.run("rollback", "--stamp", "T1", SIM_STAGE_BUSY=1)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("STOPPED IN PHASE 'stuck'", r.stdout)
        self.assertTrue(w.is_closed(), w.summary())
        self.assertEqual(w["staged"], "1")
        r = w.run("rollback", "--stamp", "T1")
        self.assertIn("RESULT: UNDONE", r.stdout)
        self.assertTrue(w.is_open(("populated",)), w.summary())

    def test_recovery_resumed_after_a_crash_while_closing(self):
        # #3: the record keeps the LoginSets and cordons until the lease is released
        w0 = World()
        w0.run()
        n = w0.call_no("PartitionName=cpu State=UP")
        w = World()
        w.run(kill_after=n)
        self.assertEqual(w["part_cpu"], "UP")
        self.assertRegex(w.record(), r"phase=done .*loginsets=prace=1 cordoned=lab-lenovo,")
        r = w.run("recover", "--stamp", "T1", SIM_PROBE_FAILS=1)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("RECOVERY INCOMPLETE", r.stdout)
        self.assertIn("partitions drained, logins closed and the recorded workers cordoned (confirmed)", r.stdout)
        self.assertTrue(w.is_closed(), w.summary())
        r = w.run("recover", "--stamp", "T1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertTrue(w.is_open(("lv",)), w.summary())

    def test_backout_whose_lease_release_fails_is_retried_not_quarantined(self):
        # #4/#9: the verified back-out reopened everything; only the lease is left
        w = World()
        r = w.run(SIM_ACCOUNTS_FAIL=1, SIM_LEASE_RM_FAILS=1)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("MAINTENANCE WINDOW NOT CLOSED", r.stdout)
        self.assertNotIn("RECOVERY INCOMPLETE", r.stdout)
        self.assertEqual((w["part_cpu"], w["part_gpu"], w["replicas"]), ("UP", "UP", "1"))
        self.assertEqual({w[f"cordon_{n}"] for n, _ in w.nodes}, {"0"})          # verified workers stay usable
        self.assertTrue((w.w / "lease").exists())
        r = w.run("recover", "--stamp", "T1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertTrue(w.is_open(("populated",)), w.summary())

    def test_backout_whose_partition_reopen_fails(self):
        w = World()
        r = w.run(SIM_ACCOUNTS_FAIL=1, SIM_PART_REOPEN_FAILS="gpu")
        self.assertIn("MAINTENANCE WINDOW NOT CLOSED", r.stdout)
        self.assertNotIn("drained partitions", r.stdout)
        self.assertEqual((w["part_cpu"], w["part_gpu"], w["replicas"]), ("UP", "DRAIN", "1"))
        self.assertEqual({w[f"cordon_{n}"] for n, _ in w.nodes}, {"0"})
        r = w.run("recover", "--stamp", "T1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertTrue(w.is_open(("populated",)), w.summary())

    def test_unmounted_lv_after_a_failed_rollback_is_not_a_partial_cutover(self):
        # #8: users wrote to the LV; a refused rollback's back-out failed (quarantine, 'recovering');
        # the LV is then unmounted by hand. The next rollback must not put the old tree back.
        w = World()
        self.assertEqual(w.run().returncode, 0)
        w.set(lvdata="L0+written-since")
        r = w.run("rollback", "--stamp", "T1", SIM_WORKER_FAILS="lab-g003")
        self.assertIn("would hide those writes", r.stdout)
        self.assertIn("RECOVERY INCOMPLETE", r.stdout)
        self.assertIn(" phase=recovering ", w.record())
        w.set(home="empty")
        r = w.run("rollback", "--stamp", "T1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("the LV changed since the cutover", r.stdout)             # listed read-only and compared
        self.assertEqual((w["home"], w["old"]), ("empty", "1"))
        self.assertTrue(w.is_closed(), w.summary())

    def test_writes_since_the_cutover_refuse_then_discard_archives(self):
        w = World()
        w.run()
        w.set(lvdata="L0+written-since")
        r = w.run("rollback", "--stamp", "T1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("would hide those writes", r.stdout)
        self.assertTrue(w.is_open(("lv",)), w.summary())                         # own fence: verified back-out
        r = w.run("rollback", "--stamp", "T1", "--discard-writes")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("LV archived", r.stdout)
        self.assertTrue(w.is_open(("populated",)), w.summary())

    def test_rollback_b_lost_between_rmdir_and_mv(self):
        w = World()
        w.run()
        w.run("rollback", "--stamp", "T1", SIM_RB_LOST_BEFORE_MV=1)
        self.assertEqual((w["home"], w["old"]), ("absent", "1"))
        self.assertIn(" phase=changed ", w.record())
        r = w.run("rollback", "--stamp", "T1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("partial cutover", r.stdout)
        self.assertTrue(w.is_open(("populated",)), w.summary())

    def test_cordon_is_recorded_before_it_is_applied(self):
        # #6: a crash right after a cordon leaves that node in the record, so it is uncordoned later
        w0 = World()
        w0.run()
        n = w0.call_no("kubectl cordon lab-g005")
        w = World()
        w.run(kill_after=n)
        self.assertEqual(w["cordon_lab-g005"], "1")
        self.assertRegex(w.record(), r"cordoned=lab-lenovo,lab-g005$")
        r = w.run("rollback", "--stamp", "T1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertTrue(w.is_open(("populated",)), w.summary())

    def test_lease_comes_with_its_record(self):
        w0 = World()
        w0.run()
        w = World()
        w.run(kill_after=w0.call_no("mkdir /run/prace-cluster-lease"))
        self.assertRegex(w.record(), r"stamp=T1 phase=start ")
        r = w.run("rollback", "--stamp", "T1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertTrue(w.is_open(("populated",)), w.summary())


class ReviewRound2(unittest.TestCase):
    """The second adversarial review (of 87a66db), each finding as sessions against the simulated fleet."""

    LISTING = "L /usr/local/sbin/prace-tree-listing --no-label /home"

    def test_unverified_lv_is_never_reopened_by_recover(self):
        # after-mount crash: /home on an LV that never passed the gate; a refused rollback whose undo
        # failed ('stuck'), then one whose undo worked ('disrupted'): recover must still refuse
        w = World()
        w.run(PRACE_CRASH_AT="after-mount")
        r = w.run("rollback", "--stamp", "T1", SIM_FAILPAT=f"{self.LISTING};;C 10.90.10.21 mountpoint -q /home || mount /home")
        self.assertIn("STOPPED IN PHASE 'stuck'", r.stdout)
        r = w.run("rollback", "--stamp", "T1", SIM_FAILPAT=self.LISTING)
        self.assertIn("STOPPED IN PHASE 'disrupted'", r.stdout)
        r = w.run("recover", "--stamp", "T1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("never passed its gate and client checks", r.stdout)
        self.assertTrue(w.is_closed(), w.summary())
        r = w.run("rollback", "--stamp", "T1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertTrue(w.is_open(("populated",)), w.summary())

    def test_refused_rollback_after_a_stuck_undo_can_be_recovered(self):
        # users wrote to the served LV; a rollback is refused and its undo fails once ('stuck');
        # the next refused rollback undoes cleanly, and recover then reopens on the (verified) LV
        w = World()
        self.assertEqual(w.run().returncode, 0)
        w.set(lvdata="L0+written-since")
        r = w.run("rollback", "--stamp", "T1", SIM_FAILPAT="C 10.90.10.21 mountpoint -q /home || mount /home")
        self.assertIn("STOPPED IN PHASE 'stuck'", r.stdout)
        r = w.run("rollback", "--stamp", "T1")
        self.assertIn("would hide those writes", r.stdout)
        self.assertIn("STOPPED IN PHASE 'disrupted'", r.stdout)
        r = w.run("recover", "--stamp", "T1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertTrue(w.is_open(("lv",)), w.summary())
        self.assertEqual(w["lvdata"], "L0+written-since")

    def test_lease_retaken_from_the_evidence_comes_with_its_record(self):
        def rebooted():
            w = World()
            w.run(PRACE_CRASH_AT="after-copy")
            shutil.rmtree(w.w / "lease")                                  # /run is gone, so are the staging
            w.set(staged=0, export=1)                                       # mount and the withdrawn export
            return w
        probe = rebooted()
        probe.run("rollback", "--stamp", "T1")
        n = probe.call_no("mkdir /run/prace-cluster-lease && echo")
        w = rebooted()
        w.run("rollback", "--stamp", "T1", kill_after=n)
        self.assertRegex(w.record() or "", r"stamp=T1 phase=detached ")
        r = w.run("rollback", "--stamp", "T1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("RESULT: UNDONE", r.stdout)
        self.assertTrue(w.is_open(("populated",)), w.summary())

    def test_rollback_b_finishes_after_its_converge_installed_a_new_helper(self):
        w = World()
        w.run(PRACE_CRASH_AT="after-move")
        r = w.run("rollback", "--stamp", "T1", SIM_REPO_HELPER="newsha", SIM_TAIL_CONVERGE_FAILS=1)
        self.assertIn("the deferred converge failed", r.stdout)
        self.assertEqual((w["home"], w["helper"]), ("populated", "newsha"))
        r = w.run("rollback", "--stamp", "T1")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("finish rollback B", r.stdout)
        self.assertTrue(w.is_open(("populated",)), w.summary())

    def hand_finished(self, lvdata):
        # after-mount crash, then finished by hand: served from the LV and opened, the lease removed,
        # the evidence record still 'changed'; later the LV is unmounted (repair) and a rollback is run
        w = World()
        w.run(PRACE_CRASH_AT="after-mount")
        shutil.rmtree(w.w / "lease")
        w.set(export=1, replicas=1, part_cpu="UP", part_gpu="UP", lvdata=lvdata, home="empty",
              **{f"cm_{a}": 1 for _, a in w.nodes}, **{f"cordon_{n}": 0 for n, _ in w.nodes})
        return w, w.run("rollback", "--stamp", "T1")

    def test_stale_changed_record_cannot_hide_writes(self):
        w, r = self.hand_finished("L0+written-since")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("the LV changed since the cutover", r.stdout)
        self.assertEqual((w["home"], w["old"]), ("empty", "1"))
        self.assertTrue(w.is_closed(), w.summary())

    def test_unwritten_lv_off_home_is_rolled_back_after_comparing(self):
        w, r = self.hand_finished("L0")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("the LV equals L0", r.stdout)
        self.assertTrue(w.is_open(("populated",)), w.summary())

    def test_discard_writes_archives_the_lv_off_home_first(self):
        w, _ = self.hand_finished("L0+written-since")
        r = w.run("rollback", "--stamp", "T1", "--discard-writes")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertEqual(w["archived"], "1")
        self.assertTrue(w.is_open(("populated",)), w.summary())

    def test_one_run_at_a_time(self):
        w = World()
        w.run()
        with open(w.w / "tmp" / "prace-storage-cutover.lock", "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            r = w.run("rollback", "--stamp", "T1", PRACE_LOCK_WAIT=1)
        self.assertEqual(r.returncode, 2)
        self.assertIn("another storage-cutover run", r.stderr)
        self.assertEqual(w.calls(), 0)

    def test_missing_preserved_tree_refuses_before_detaching(self):
        w = World()
        w.run()
        w.set(old=0)
        r = w.run("rollback", "--stamp", "T1")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("is missing on the login node; nothing changed", r.stdout)
        self.assertNotIn("umount /home", (w.w / "numbered").read_text())
        self.assertTrue(w.is_open(("lv",)), w.summary())                          # own fence: verified back-out

    def test_wrong_stamp_changes_nothing(self):
        w = World()
        w.run()
        before = (w.w / "evid" / "fence-state.txt").read_text()
        for action in ("rollback", "recover"):
            r = w.run(action, "--stamp", "T2")
            self.assertEqual(r.returncode, 2)
            self.assertIn("holds cutover T1, not T2", r.stderr)
            self.assertEqual(w.calls(), 0)
        self.assertEqual((w.w / "evid" / "fence-state.txt").read_text(), before)
        r = w.run()                                                             # a second cutover into the same directory
        self.assertEqual(r.returncode, 2)
        self.assertIn("already holds a cutover (T1)", r.stderr)

    def test_loginset_already_at_zero_is_refused_at_the_fence(self):
        w = World()
        w.set(replicas=0)
        r = w.run()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("LoginSet is at 0 replicas before the window", r.stdout)
        self.assertEqual((w["home"], w["part_cpu"], w["part_gpu"]), ("populated", "UP", "UP"))
        self.assertFalse((w.w / "lease").exists())

    def test_refusal_holds_an_adopted_detached_record_as_found(self):
        w = World()
        w.run(PRACE_CRASH_AT="after-copy")
        r = w.run("rollback", "--stamp", "T1", SIM_HOME_STATE_FAILS=1)
        self.assertNotEqual(r.returncode, 0)
        self.assertNotIn("exportfs -ra", (w.w / "numbered").read_text())       # no undo on a refusal
        self.assertIn(" phase=detached ", w.record())
        self.assertEqual(w["staged"], "1")
        self.assertTrue(w.is_closed(), w.summary())

    def test_early_backout_killed_anywhere_then_rollback(self):
        # the ( recover ) back-out after an early failure, killed after any call (the whole run dies)
        w0 = World()
        w0.run(SIM_ACCOUNTS_FAIL=1)
        total = w0.calls()

        def one(n):
            w = World()
            w.run(kill_after=n, SIM_ACCOUNTS_FAIL=1)
            r = w.run("rollback", "--stamp", "T1")
            if r.returncode != 0 or not w.is_open(("populated",)):
                return f"back-out killed after call {n}, then rollback rc {r.returncode}: {w.summary()}\n{r.stdout[-1500:]}"
        fails = sweep(one, range(1, total + 1))
        self.assertFalse(fails, failures(fails))


class ReviewRound3(unittest.TestCase):
    """The third check (of a3d13de..ddec31c), each finding as sessions against the simulated fleet."""

    def test_foreign_lease_refuses_before_any_change(self):
        w = World()
        (w.w / "lease").mkdir()
        (w.w / "lease" / "holder").write_text("holder=backup id=0123abcd host=elsewhere pid=1 since=x\n")
        r = w.run()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("the cluster is leased", r.stdout)
        done = (w.w / "numbered").read_text()
        for change in ("State=DRAIN", "kubectl cordon", "umount /home", "patch loginset"):
            self.assertNotIn(change, done)
        self.assertEqual((w.w / "lease" / "holder").read_text(), "holder=backup id=0123abcd host=elsewhere pid=1 since=x\n")
        self.assertEqual((w["home"], w["part_cpu"]), ("populated", "UP"))

    def test_lost_status_on_the_lease_take_and_release(self):
        for pat in ("mkdir /run/prace-cluster-lease 2>/dev/null", "rm -rf /run/prace-cluster-lease"):
            with self.subTest(pat):
                w = World()
                r = w.run(SIM_LOSTPAT=pat)
                self.assertEqual(r.returncode, 0, r.stdout)
                self.assertIn("RESULT: PASS", r.stdout)
                self.assertTrue(w.is_open(("lv",)), w.summary())

    def test_failed_record_writes_stop_before_the_step_they_cover(self):
        # the partitions' record (fleet): nothing is drained, the window closes
        w = World()
        r = w.run(SIM_STATE_FAILS_MATCH=" phase=start parts=cpu")
        self.assertIn("cannot record the partitions before draining them", r.stdout)
        self.assertNotIn("State=DRAIN", (w.w / "numbered").read_text())
        self.assertTrue(w.is_open(("populated",)), w.summary())
        # the detach's record (rehearsal): no client is detached, the window closes
        w = World("rehearsal")
        r = w.run(SIM_STATE_FAILS_MATCH=" phase=detached ")
        self.assertIn("cannot record the detach", r.stdout)
        self.assertNotIn("umount /home", (w.w / "numbered").read_text())
        self.assertTrue(w.is_open(("populated",)), w.summary())

    def test_a_live_run_on_this_host_is_never_adopted(self):
        w = World()
        w.run(PRACE_CRASH_AT="after-move")
        live = subprocess.Popen(["bash", "-c", "exec -a storage-cutover-live sleep 60"])
        try:
            holder = (w.w / "lease" / "holder").read_text()
            (w.w / "lease" / "holder").write_text(re.sub(r" pid=\d+ ", f" pid={live.pid} ", holder))
            r = w.run("rollback", "--stamp", "T1")
        finally:
            live.kill()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("still alive on this host", r.stdout)
        self.assertEqual((w["home"], w["old"]), ("empty", "1"))

    def test_busy_scratch_mount_is_reported_as_busy(self):
        w = World()
        w.run(PRACE_CRASH_AT="after-move")
        w.set(staged=1)
        r = w.run("rollback", "--stamp", "T1", SIM_STAGE_BUSY=1)
        self.assertIn("a scratch mount of the LV is in use", r.stdout)
        self.assertEqual((w["home"], w["old"]), ("empty", "1"))

    def test_recover_points_only_to_rollback(self):
        w = World()
        w.run(PRACE_CRASH_AT="after-move")
        r = w.run("recover", "--stamp", "T1")
        self.assertIn("not in recovery: use rollback --stamp T1", r.stdout)
        self.assertNotIn("by hand", r.stdout)

    def test_an_unreadable_evidence_record_leaves_the_decision_to_the_login_node(self):
        w = World()
        w.run(PRACE_CRASH_AT="after-move")
        (w.w / "evid" / "fence-state.txt").write_text("")
        r = w.run("rollback", "--stamp", "T1")
        self.assertIn("empty or unreadable", r.stderr)
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertTrue(w.is_open(("populated",)), w.summary())


class ArchiveSizing(unittest.TestCase):
    """archive_lv's remote script run for real against fake rsync and df: sized by what rsync would
    transfer, and every figure must be a number."""

    def archive(self, dry_bytes, free_kib, df_rc=0):
        with tempfile.TemporaryDirectory() as d:
            fakes = {"rsync": f'case " $* " in *" -n "*) echo "Total transferred file size: {dry_bytes} bytes" ;; *) echo RSYNC-COPIED ;; esac',
                     "df": f'echo "Avail"; echo " {free_kib}"; exit {df_rc}'}
            for name, body in fakes.items():
                (Path(d) / name).write_text("#!/bin/bash\n" + body + "\n"); (Path(d) / name).chmod(0o755)
            script = f'source {TOOL}; TS=T1 ARCHIVE_RESERVE_GIB=20; L() {{ bash -c "$1"; }}; archive_lv /src; echo "rc=$?"'
            r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                               env={"PATH": f"{d}:/usr/bin:/bin", "HOME": d})
            return r.stdout

    def test_room_enough(self):
        out = self.archive("5,368,709,120", 31 * 1024 * 1024)            # 5 GiB to copy, 31 GiB free
        self.assertIn("RSYNC-COPIED", out)
        self.assertIn("rc=0", out)

    def test_reserve_kept(self):
        out = self.archive("12,884,901,888", 31 * 1024 * 1024)           # 12 GiB + 20 GiB reserve > 31 GiB
        self.assertIn("not enough room", out)
        self.assertNotIn("RSYNC-COPIED", out)
        self.assertIn("rc=1", out)

    def test_unreadable_figures_refuse(self):
        for dry, free in (("", 31 * 1024 * 1024), ("5,368", "n/a"), ("5,368", "")):
            with self.subTest(dry=dry, free=free):
                out = self.archive(dry, free)
                self.assertIn("cannot size the archive", out)
                self.assertNotIn("RSYNC-COPIED", out)


class BlankOrEqual(unittest.TestCase):
    """R5 (MR !51 review): the preconditions' blank-or-equal check runs for real against fake ls, umount and
    listing helper. A failed observation must refuse, because the copy that follows is an rsync --delete."""

    def check(self, ls="exec /bin/ls \"$@\"", helper='echo "3 entries"', umount=":", then_copy=False, populate=True):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            lv, home, fake = d / "lv", d / "home", d / "bin"
            for p in (lv, home, fake):
                p.mkdir()
            if populate:
                (lv / "unique-existing-lv-data.txt").write_text("must survive\n")
            (home / "ordinary-home.txt").write_text("home\n")
            for name, body in (("ls", ls), ("umount", f'echo "umount $*" >> {d}/log; {umount}'), ("helper", helper)):
                (fake / name).write_text("#!/bin/bash\n" + body + "\n"); (fake / name).chmod(0o755)
            copy = f'\n/usr/bin/rsync -aHAXS --numeric-ids --delete {home}/ {lv}/\necho COPIED' if then_copy else ""
            script = (f'source {TOOL}; CHECKMNT={lv} LISTING_HELPER={fake}/helper\n'
                      f'bash -c "set -euo pipefail; $(blank_or_equal_script){copy}"; echo "rc=$?"')
            r = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                               env={"PATH": f"{fake}:/usr/bin:/bin", "HOME": str(d)})
            log = (d / "log").read_text() if (d / "log").exists() else ""
            return r.stdout + r.stderr, (lv / "unique-existing-lv-data.txt").exists(), log

    def test_failed_listing_never_reaches_the_copy(self):
        # Codex's reproduction: a one-time failing ls, then the cutover's own rsync --delete
        out, survived, log = self.check(ls="echo 'ls: synthetic directory read failure' >&2; exit 2", then_copy=True)
        self.assertIn("listing the home LV failed", out)
        self.assertIn("rc=3", out)
        self.assertNotIn("home LV blank", out)
        self.assertNotIn("COPIED", out)
        self.assertTrue(survived)
        self.assertIn("umount", log)                                 # the inspection mount is not left behind

    def test_blank_and_equal_and_different(self):
        out, _, _ = self.check(populate=False)
        self.assertIn("home LV blank", out); self.assertIn("rc=0", out)
        out, _, _ = self.check()                                      # the helper reports the same summary twice
        self.assertIn("already equals /home", out); self.assertIn("rc=0", out)
        out, _, _ = self.check(helper='case "$*" in *home) echo "5 entries" ;; *) echo "3 entries" ;; esac')
        self.assertIn("differs from /home", out); self.assertIn("rc=3", out)

    def test_failed_helper_or_unmount_refuses(self):
        out, _, _ = self.check(helper="exit 2")
        self.assertIn("listing the home LV or /home failed", out); self.assertIn("rc=3", out)
        for populate in (True, False):
            out, _, _ = self.check(umount="exit 32", populate=populate)
            self.assertIn("cannot unmount", out); self.assertIn("rc=3", out)

    def test_a_failed_mountpoint_on_a_client_is_not_unmounted(self):
        # detach: mountpoint exits 32 for "not a mountpoint" and 1 on an error; an error must stop the detach
        w = World()
        r = w.run(SIM_MOUNTPOINT_FAILS="10.90.10.13")
        self.assertIn("mount state unknown", r.stdout)
        self.assertNotIn("mount -o nodev,nosuid,usrquota", (w.w / "numbered").read_text())   # nothing was copied
        self.assertTrue(w.is_open(("populated",)), w.summary())


class Sourcing(unittest.TestCase):
    def test_sourcing_runs_nothing(self):
        r = subprocess.run(["bash", "-c", f'source {TOOL}; echo sourced'], capture_output=True, text=True, timeout=30)
        self.assertEqual(r.stdout.strip(), "sourced")

    def test_usage_errors(self):
        for args in ([], ["--fleet"], ["--fleet", "--evidence", "/tmp/x", "recover"]):
            with self.subTest(args=args):
                r = subprocess.run(["bash", str(TOOL), *args], capture_output=True, text=True, timeout=30)
                self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()

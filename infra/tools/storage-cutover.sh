#!/bin/bash
# Move a populated /home onto its own LV (D39 storage step; user decisions 28 Sep). Run from the
# workstation, in tmux or with nohup (a lost terminal must not interrupt a maintenance window),
# AFTER the preparation window W1:
#   fleet.yml --limit lab-dl380 --tags storage,accounts,quota,nfs,observer -e '{"storage_defer":["home"]}'
#   fleet.yml --limit compute --tags nfs -e '{"storage_defer":["home"]}'
# (close admin@login ProxyJump masters first: usermod -d waits while admin has host sessions).
#
#   infra/tools/storage-cutover.sh --fleet     --evidence DIR [--label L]    production
#   infra/tools/storage-cutover.sh --rehearsal --evidence DIR [--label L]    tools/storage-rehearsal.sh VMs
#   infra/tools/storage-cutover.sh --fleet|--rehearsal --evidence <the cutover's DIR> rollback --stamp TS [--discard-writes]
#   infra/tools/storage-cutover.sh --fleet|--rehearsal --evidence <the cutover's DIR> recover --stamp TS
# One evidence DIR per cutover (a second cutover into it, or another --stamp, is refused before any
# remote call), and one run at a time per workstation (flock on $TMPDIR/prace-storage-cutover.lock;
# a lease held by a live run on this host is never adopted). The stamp is printed at the start.
#
# Cutover: lease -> (fleet) drain every partition, LoginSets to 0, no jobs, cordon the workers and
# delete their slurmd pods -> no NFS consumer left -> accounts converged (check, 0 changes) ->
# fstab backups -> clients unmount /home -> server stops exporting /home -> listing L0 -> rsync
# to the LV -> L1 == L0 -> move the old tree aside (point of change; nothing is deleted) ->
# converge the login node (storage; accounts check = 0 changes; accounts,quota,nfs) -> gate ->
# clients converge (nfs) -> $EVID/lv-verified -> RECOVERY -> window closed.
# Recovery (also 'recover --stamp' after a failure): workers uncordoned one at a time, each must
# pass the worker check; every client NFS mount answers (a failed enumeration or a stale mount
# fails); (fleet) LoginSets restored while the partitions stay drained, the login pod must be
# Ready and a real login as the probe user must see the server's /home; only then are the
# partitions reopened and the lease released. A failure in recovery keeps the lease and
# quarantines: every recorded worker cordoned, partition drained and LoginSet at 0, each read
# back; the state stays on the login node for 'recover --stamp' (which reopens on the LV only when
# $EVID/lv-verified names this stamp: the gate and every client check passed).
# Rollback: the fence first (an adopted fence is re-asserted), THEN /home's state and the
# recorded phase decide; on the LV, clients are detached and /home unexported before the LV is
# compared with L0 (writes since the cutover refuse unless --discard-writes archives them). Any
# failed or unknown observation stops the rollback.
# Phases, recorded ($STATE on the login node, $EVID/fence-state.txt) before the step they cover:
#   start       lease (partitions may be draining); logins and workers untouched: a back-out unfences
#   disrupted   logins at 0, workers cordoned, slurmd pods deleted: reopened only by verified recovery
#   detached    clients may have unmounted /home, /home may be unexported, the LV may be staged at
#               $STAGE: undo A (unstage, re-export, remount), then as disrupted
#   changed     the old tree is being moved aside, or rollback B is putting it back: rollback or stay fenced
#   recovering  verified recovery running or failed: stay fenced (quarantine)
#   done        verified, the window closing (a resumed run verifies again)
#   stuck       an undo failed: stay fenced          closed  lease released (evidence only)
# The record keeps every original (partitions, LoginSets, cordoned workers) until the lease is
# released: a resumed run re-applies them, and each step is idempotent.
# Rollback by /home's state: on its LV -> preserved tree and fstab backups checked, detach, compare,
# restore; moved aside with the LV off /home -> the LV mounted read-only at $CHECKMNT, listed and
# compared with L0 whatever the record says (without L0 only the record 'changed' vouches) ->
# restore; in place with 'changed' (stopped before the move-aside, or rollback B stopped after it)
# -> finish rollback B; in place otherwise, the LV at most staged -> undo; anything else refuses.
# Writes found on the LV refuse; --discard-writes archives the LV to lv-<stamp> on the root
# filesystem first (sized by an rsync dry run; PRACE_ARCHIVE_RESERVE_GIB, default 20, stays free).
# A fence this run took backs out by itself; an adopted fence (a stopped run's) reopens only by a
# successful undo, rollback or recovery, never after a refusal or a failure.
# PRACE_CRASH_AT=after-copy|before-move|after-move|after-mount|after-restore kills the tool there
# (tests and rehearsal only). Other knobs: PRACE_WAIT_WORKER, PRACE_WAIT_LOGIN, PRACE_PAUSE,
# PRACE_RETRY_WINDOW (seconds for a whole unfence or quarantine, default 600), PRACE_LOCK_WAIT,
# PRACE_PROBE_KEY, PRACE_PROBE_KNOWN_HOSTS, PRACE_SR_DIR (rehearsal).
# Never umount -l/-f, never scontrol update NodeName (quarantine is kubectl cordon).
# Sourcing the file (tools/test-storage-cutover.py) defines the functions without running.
set -uo pipefail

K='k3s kubectl'; KS="$K -n slurm"; S="$KS exec slurm-controller-0 -c slurmctld --"
LEASE=/run/prace-cluster-lease
STATE=$LEASE/storage-cutover.state
STAGE=/run/prace-storage/home-new     # the LV while it is copied, before it becomes /home
CHECKMNT=/run/prace-storage/home-check  # the LV mounted read-only to be inspected (cutover preconditions, rollback)
LISTING_HELPER=/usr/local/sbin/prace-tree-listing
# remote: unmount the LV from both scratch mountpoints; one in use fails
UNSTAGE="for d in $STAGE $CHECKMNT; do if mountpoint -q \$d; then umount \$d || { fuser -vm \$d; echo \"\$d is in use\"; exit 3; }; fi; done"
JUMP_HOST=192.0.2.205
PRIV=10.90.10.1 LOGIN_PORT=32222
PROBE_KEY=${PRACE_PROBE_KEY:-$HOME/.config/prace-lab/syn-probe-ed25519}
PROBE_KH=${PRACE_PROBE_KNOWN_HOSTS:-$HOME/.config/prace-lab/slinky-login-pod-known-hosts}
# findmnt exits 1 both when nothing matches (silently) and on an error (with a message)
NFSLIST='m=$(findmnt -rn -t nfs,nfs4 -o TARGET 2>&1); r=$?; if [ $r = 0 ]; then printf "%s\n" "$m"; elif [ $r != 1 ] || [ -n "$m" ]; then echo "findmnt failed: $m" >&2; exit 3; fi'
ARCHIVE_RESERVE_GIB=${PRACE_ARCHIVE_RESERVE_GIB:-20}   # free space kept on the root filesystem after a --discard-writes archive
WAIT_WORKER=${PRACE_WAIT_WORKER:-60} WAIT_LOGIN=${PRACE_WAIT_LOGIN:-120} PAUSE=${PRACE_PAUSE:-5}
FENCED_PARTS="" LOGIN_REPLICAS="" CORDONED="" LEASED=0 PHASE=start DETACHED=""
ADOPTED_PHASE=""    # the recorded phase when this run took over a stopped run's fence
BASE_PHASE=start    # where a verified undo returns: start | disrupted (fleet fence) | the adopted phase
HOME_ON=root        # where /home is served from: root (before the move-aside, after rollback B) | lv

ts() { date '+%H:%M:%S'; }
step() { echo; echo "== $(ts) $*"; }
say() { echo "   $*"; }
fail() { echo "   FAIL: $*"; exit 1; }

# fd 9 is the run lock: closed for ssh children, so a mux master that outlives a crashed run never holds it. A
# playbook run keeps it (ansible closes it for its own ssh), so a converge still running holds the lock.
L() { ssh -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o ControlMaster=auto -o "ControlPath=$MUX/login" -o ControlPersist=600 "${LOGIN_SSH[@]}" "$@" 9>&-; }
C() {   # C <address (fleet) | forwarded port (rehearsal)> <command>: one client, never multiplexed itself; the jump
        # connection is (the login node's sshd penalises bursts of new connections: OpenSSH PerSourcePenalties)
  local a=$1; shift
  if [ "$TARGET" = fleet ]; then
    ssh -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o ControlMaster=no -o ControlPath=none -o StrictHostKeyChecking=yes \
      -o "ProxyCommand=ssh -o BatchMode=yes -o ControlMaster=auto -o ControlPath=$MUX/jump -o ControlPersist=300 -W %h:%p admin@$JUMP_HOST" \
      "root@$a" "$@" </dev/null 9>&-
  else
    ssh -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=15 -o ServerAliveCountMax=4 -o ControlMaster=no -o ControlPath=none -o StrictHostKeyChecking=yes \
      -o "UserKnownHostsFile=$SR/known_hosts" -o HostKeyAlgorithms=ssh-ed25519 -i "$SR/id" -o IdentitiesOnly=yes \
      -o "ProxyCommand=ssh -o BatchMode=yes -o ControlMaster=auto -o ControlPath=$MUX/jump -o ControlPersist=300 -W %h:%p root@$JUMP_HOST" \
      -p "$a" root@127.0.0.1 "$@" </dev/null 9>&-
  fi
}
PROBE() {   # a real login to the Slinky login pod as the acceptance probe user (fleet only)
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o ControlMaster=no -o ControlPath=none -o IdentitiesOnly=yes -i "$PROBE_KEY" \
    -o "UserKnownHostsFile=$PROBE_KH" -o StrictHostKeyChecking=yes \
    -o "ProxyCommand=ssh -o BatchMode=yes -o ControlMaster=no -o ControlPath=none -W %h:%p admin@$JUMP_HOST" \
    -p "$LOGIN_PORT" "syn-probe@$PRIV" "$@" </dev/null 9>&-
}
ansible_run() {   # ansible_run <name> <args...>: the playbook under this run's lease, output kept
  local log="$EVID/ansible-$(date +%H%M%S)-$1.log"; shift
  (cd "$INFRA" && tools/run-ansible.sh -i "$INV" "$PLAYBOOK" -e fleet_armed=true -e "fleet_lease_id=$LEASE_ID" "$@") >"$log" 2>&1
  local rc=$?; grep -A20 'PLAY RECAP' "$log" | grep -E '^[a-z]' | sed 's/^/   /'; return $rc
}
accounts_zero() {   # accounts_zero <name>: --tags accounts --check on the login node reports 0 changes
  local log="$EVID/ansible-$(date +%H%M%S)-$1.log"
  (cd "$INFRA" && tools/run-ansible.sh -i "$INV" "$PLAYBOOK" -e fleet_armed=true -e "fleet_lease_id=$LEASE_ID" \
     --limit "$LOGIN_HOST" --tags accounts --check) >"$log" 2>&1 || { say "accounts check failed (see $log)"; return 1; }
  grep -qE "^$LOGIN_HOST +: .*changed=0 " "$log" || { grep -A2 'PLAY RECAP' "$log" | sed 's/^/   /'; return 1; }
}
listing() { L "$LISTING_HELPER $* "; }
# Listings are compared across time (L0 now, rollback later): only one helper version may make them.
helper_sha() { L "sha256sum $LISTING_HELPER | cut -d' ' -f1"; }
repo_helper_sha() { sha256sum "$INFRA/roles/login_storage/files/prace-tree-listing" | cut -d' ' -f1; }

# --- maintenance window: fleet partitions, LoginSets, cordons; the originals are kept in $STATE
save_state() {   # the login node's record while the lease is held, and the evidence copy; non-zero if a write failed
  local s="id=$LEASE_ID stamp=$TS phase=$PHASE parts=${FENCED_PARTS// /,} loginsets=${LOGIN_REPLICAS// /,} cordoned=${CORDONED// /,}" bad=0
  if [ "$LEASED" = 1 ]; then L "cat > $STATE" <<<"$s" || { say "WARNING: could not write $STATE"; bad=1; }; fi
  { echo "$s" > "$EVID/.fence-state.new" && mv -f "$EVID/.fence-state.new" "$EVID/fence-state.txt"; } \
    || { say "WARNING: could not write $EVID/fence-state.txt"; bad=1; }
  return $bad
}
# retry: up to 60 tries per item, within one window shared by a whole unfence or quarantine
# (a login node or API that is down costs minutes, not hours)
retry() {
  local i
  for i in $(seq 60); do
    "$@" >/dev/null 2>&1 && return 0
    [ "$(date +%s)" -lt "${RETRY_UNTIL:-0}" ] || return 1
    [ "$i" != 1 ] || say "(retrying: ${*: -1})"
    sleep "$PAUSE"
  done
  return 1
}
unfence() {   # the recorded originals back; the record is emptied only once all are back and the lease is released
  local kv n bad=0
  RETRY_UNTIL=$(( $(date +%s) + ${PRACE_RETRY_WINDOW:-600} ))
  for n in $CORDONED; do
    if retry L "$K uncordon $n"; then say "$n uncordoned"; else say "UNFENCE FAILED: kubectl uncordon $n by hand"; bad=1; fi
  done
  for kv in $FENCED_PARTS; do
    if retry L "$S scontrol update PartitionName=${kv%%=*} State=${kv#*=}"; then say "partition ${kv%%=*} reopened (State=${kv#*=})"
    else say "UNFENCE FAILED: partition ${kv%%=*}; restore State=${kv#*=} by hand"; bad=1; fi
  done
  for kv in $LOGIN_REPLICAS; do
    if retry L "$KS patch loginset ${kv%%=*} --type merge -p '{\"spec\":{\"replicas\":${kv#*=}}}'"; then say "loginset ${kv%%=*} back to ${kv#*=} replica(s)"
    else say "UNFENCE FAILED: loginset ${kv%%=*}; set spec.replicas=${kv#*=} by hand"; bad=1; fi
  done
  if [ $bad = 0 ] && [ "$LEASED" = 1 ]; then
    if retry L "! [ -e $LEASE ] || { grep -q 'id=$LEASE_ID' $LEASE/holder && rm -rf $LEASE; }"; then say "cluster lease released"; LEASED=0
    else say "LEASE NOT RELEASED: check $LEASE on the login node"; bad=1; fi
  fi
  [ $bad = 0 ] || return 1
  CORDONED="" FENCED_PARTS="" LOGIN_REPLICAS="" PHASE=closed; save_state
}
quarantine() {   # stay fenced: every recorded worker cordoned, partition drained and LoginSet at 0, each read back
  local kv n now
  QUARANTINE_OK=1
  RETRY_UNTIL=$(( $(date +%s) + ${PRACE_RETRY_WINDOW:-600} ))
  for n in $CORDONED; do
    retry L "$K cordon $n"
    now=$(L "$K get node $n -o jsonpath='{.spec.unschedulable}'") || now=unknown
    if [ "$now" = true ]; then say "$n cordoned (confirmed)"
    else say "QUARANTINE: $n reads unschedulable='$now': kubectl cordon $n by hand"; QUARANTINE_OK=0; fi
  done
  for kv in $FENCED_PARTS; do
    retry L "$S scontrol update PartitionName=${kv%%=*} State=DRAIN"
    now=$(L "$S scontrol show partition ${kv%%=*} -o" | grep -oE '(^| )State=[A-Z_]+' | tr -d ' ') || now=unknown
    if [ "$now" = State=DRAIN ]; then say "partition ${kv%%=*} drained (confirmed)"
    else say "QUARANTINE: partition ${kv%%=*} reads '$now': drain it by hand"; QUARANTINE_OK=0; fi
  done
  # Every recorded LoginSet, whatever this process believes: a resumed run cannot know whether an
  # earlier one restored the replicas before it stopped.
  for kv in $LOGIN_REPLICAS; do
    retry L "$KS patch loginset ${kv%%=*} --type merge -p '{\"spec\":{\"replicas\":0}}'"
    now=$(L "$KS get loginset ${kv%%=*} -o jsonpath='{.spec.replicas}'") || now=unknown
    if [ "$now" = 0 ]; then say "loginset ${kv%%=*} at 0 replicas (confirmed)"
    else say "QUARANTINE: loginset ${kv%%=*} is at '$now' replicas: set it to 0 by hand"; QUARANTINE_OK=0; fi
  done
  if [ "$K8S" = 1 ] && [ -z "$LOGIN_REPLICAS" ]; then say "QUARANTINE: no LoginSet is recorded, so none was closed"; QUARANTINE_OK=0; fi
  save_state
}
on_exit() {
  local rc=$?
  trap '' INT TERM
  # An adopted record is held as found: only what this run detached itself is undone, and only a
  # fence this run took itself is reopened by a back-out.
  if [ "$PHASE" = detached ] && { [ -z "$ADOPTED_PHASE" ] || [ -n "$DETACHED" ]; }; then
    step "undo A after an interruption before any change to /home"
    if undo_a; then undone; else PHASE=stuck; fi
    [ "$rc" = 0 ] && rc=1
  elif [ "$PHASE" = detached ]; then PHASE=$BASE_PHASE      # adopted, nothing detached by this run: the record stands
  fi
  if [ "$PHASE" = disrupted ] && [ -z "$ADOPTED_PHASE" ]; then
    step "back-out after the fence stopped logins and workers: verified recovery before anything reopens"
    if ( recover ); then          # its own unfence has closed the window
      CORDONED="" FENCED_PARTS="" LOGIN_REPLICAS="" LEASED=0 PHASE=closed
    else                          # its last record: 'done' = verified, only closing failed (retried below)
      PHASE=$(sed -nE 's/.* phase=([^ ]+) .*/\1/p' "$EVID/fence-state.txt"); [ "$PHASE" = done ] || PHASE=recovering
    fi
    [ "$rc" = 0 ] && rc=1
  fi
  case $PHASE in
    start|done|closed)
      if [ -n "$CORDONED$FENCED_PARTS$LOGIN_REPLICAS" ] || [ "$LEASED" = 1 ]; then
        unfence || { echo "MAINTENANCE WINDOW NOT CLOSED: see the lines above (state: $STATE)"; [ "$rc" = 0 ] && rc=1; }
      fi ;;
    recovering)
      quarantine
      echo; echo "RECOVERY INCOMPLETE: /home is served from $([ "$HOME_ON" = lv ] && echo 'its LV' || echo 'the root filesystem'); the lease is kept;"
      if [ "$QUARANTINE_OK" != 1 ]; then echo "QUARANTINE NOT CONFIRMED: see the lines above"
      elif [ "$K8S" = 1 ]; then echo "partitions drained, logins closed$([ -n "$CORDONED" ] && echo ' and the recorded workers cordoned' || echo '; no worker was cordoned by this cutover') (confirmed)"
      else echo "the lease is kept (the rehearsal target has no partitions, logins or workers)"; fi
      echo "(cordoned: ${CORDONED:-none}). Fix the cause, then: $0 --$TARGET --evidence $EVID recover --stamp $TS"
      rc=1 ;;
    *)
      quarantine
      echo; echo "STOPPED IN PHASE '$PHASE': the cluster stays fenced and leased (state: $STATE)."
      [ "$QUARANTINE_OK" = 1 ] || echo "QUARANTINE NOT CONFIRMED: see the lines above"
      [ "$PHASE" = changed ] && echo "Old /home tree: $OLD."
      echo "Run: $0 --$TARGET --evidence $EVID rollback --stamp $TS$([ "$DISCARD" = 1 ] && echo ' --discard-writes')$([ "$PHASE" = disrupted ] && echo " (or recover --stamp $TS to reopen as it is; it refuses an LV this cutover never verified)")"
      rc=1 ;;
  esac
  ssh -o "ControlPath=$MUX/login" -O exit x 2>/dev/null; ssh -o "ControlPath=$MUX/jump" -O exit x 2>/dev/null; rm -rf "$MUX"
  exit "$rc"
}

fence() {
  step "maintenance window: lease$([ "$K8S" = 1 ] && echo ", drain every partition, login pods to zero, no jobs, workers cordoned")"
  PHASE=start
  # The lease and its first record in one command: no lease without a record to adopt it from.
  L "mkdir $LEASE 2>/dev/null && echo 'holder=storage-cutover label=$LABEL id=$LEASE_ID host=${HOSTNAME%%.*} pid=$$ since=$(date -Is)' > $LEASE/holder && cat > $STATE" \
      <<<"id=$LEASE_ID stamp=$TS phase=start parts= loginsets= cordoned=" \
    || L "grep -q ' id=$LEASE_ID ' $LEASE/holder" \
    || fail "the cluster is leased ($(L "cat $LEASE/holder" 2>/dev/null || echo 'holder unknown'))"
  LEASED=1; say "lease $LEASE_ID"; save_state || fail "cannot write the window's record"
  close_window
}

close_window() {   # drain, logins to zero, no jobs, workers cordoned, slurmd pods gone: a new fence or an adopted one again
  [ "$K8S" = 1 ] || return 0
  local parts kv reps pods queue c n cordoned
  if [ -z "$FENCED_PARTS" ]; then     # recorded before the first drain, so an empty record means none drained
    parts=$(L "$S scontrol show partition -o") || fail "the partition query failed"
    FENCED_PARTS=$(grep -oE 'PartitionName=[^ ]+|State=[^ ]+' <<<"$parts" | paste -d' ' - - | sed -E 's/PartitionName=([^ ]+) State=(.+)/\1=\2/' | paste -sd' ')
    [ -n "$FENCED_PARTS" ] || fail "no partitions found"
    save_state || fail "cannot record the partitions before draining them"
  fi
  for kv in $FENCED_PARTS; do L "$S scontrol update PartitionName=${kv%%=*} State=DRAIN" || fail "could not drain ${kv%%=*}"; done
  say "partitions drained (recorded: $FENCED_PARTS)"
  if [ -z "$LOGIN_REPLICAS" ]; then   # likewise recorded before any LoginSet goes to 0
    reps=$(L "$KS get loginset -o jsonpath='{range .items[*]}{.metadata.name}={.spec.replicas}{\"\\n\"}{end}'") || fail "the loginset query failed"
    [ -n "$reps" ] || fail "no loginset found"
    # recovery restores these and must then see a Ready login pod: a LoginSet already at 0 could never pass
    ! grep -qE '=0*$' <<<"$reps" || fail "a LoginSet is at 0 replicas before the window ($(paste -sd' ' <<<"$reps")): restore it first"
    LOGIN_REPLICAS=$(paste -sd' ' <<<"$reps")
  fi
  # From here on logins and workers are disrupted: a back-out reopens only through recover().
  [ "$PHASE" != start ] || PHASE=disrupted BASE_PHASE=disrupted
  save_state || fail "cannot record the fence before stopping logins"
  for kv in $LOGIN_REPLICAS; do L "$KS patch loginset ${kv%%=*} --type merge -p '{\"spec\":{\"replicas\":0}}'" >/dev/null || fail "could not stop loginset ${kv%%=*}"; done
  pods=unknown
  for _ in $(seq 180); do pods=$(L "$KS get pods -l app.kubernetes.io/name=login -o name") || pods=unknown; [ -z "$pods" ] && break; sleep 1; done
  [ -z "$pods" ] || fail "login pods still present: $pods"
  say "login pods stopped (recorded: $LOGIN_REPLICAS)"
  queue=$(L "$S squeue -h -o %i") || fail "the queue query failed, so an idle cluster cannot be established"
  [ -z "$queue" ] || fail "jobs queued or running: $(paste -sd, <<<"$queue")"
  say "no jobs"
  for c in $CLIENTS; do
    n=${c%%:*}
    if [[ " $CORDONED " == *" $n "* ]]; then L "$K cordon $n" >/dev/null || fail "cordon $n"; continue; fi
    cordoned=$(L "$K get node $n -o jsonpath='{.spec.unschedulable}'") || fail "cannot read whether $n is cordoned"
    if [ "$cordoned" = true ]; then say "$n already cordoned (left cordoned at the end)"; continue; fi
    CORDONED="${CORDONED:+$CORDONED }$n"; save_state || fail "cannot record $n before cordoning it"   # recorded first
    L "$K cordon $n" >/dev/null || fail "cordon $n"
  done
  L "$KS delete pod -l app.kubernetes.io/name=slurmd --wait=true" >/dev/null || fail "could not delete the slurmd pods"
  pods=unknown
  for _ in $(seq 120); do pods=$(L "$KS get pods -l app.kubernetes.io/name=slurmd -o name") || pods=unknown; [ -z "$pods" ] && break; sleep 1; done
  [ -z "$pods" ] || fail "slurmd pods still present: $pods"
  say "workers cordoned ($CORDONED), slurmd pods gone"
}

adopt_fence() {   # take over a stopped cutover's lease and its recorded originals (rollback/recover)
  local st raw holder h p
  raw=$(L "grep -q '^holder=storage-cutover ' $LEASE/holder 2>/dev/null && cat $LEASE/holder $STATE") || raw=""
  holder=$(grep '^holder=' <<<"$raw" | head -1); h=$(sed -nE 's/.* host=([^ ]+) .*/\1/p' <<<"$holder "); p=$(sed -nE 's/.* pid=([0-9]+) .*/\1/p' <<<"$holder ")
  if [ -n "$p" ] && [ "$h" = "${HOSTNAME%%.*}" ] && [ "$p" != $$ ] && kill -0 "$p" 2>/dev/null \
     && tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q storage-cutover; then
    say "the lease belongs to a run that is still alive on this host (pid $p): let it finish, or stop it first"; return 1
  fi
  if ! st=$(grep '^id=' <<<"$raw" | tail -1) || [ -z "$st" ]; then
    # /run is tmpfs: after a login-node reboot the lease is gone; the evidence keeps the record
    [ -r "$EVID/fence-state.txt" ] && grep -q "stamp=$TS " "$EVID/fence-state.txt" || return 1
    L "! [ -e $LEASE ]" || { say "the lease could not be read, or another run holds it"; return 1; }
    st=$(cat "$EVID/fence-state.txt")
    grep -qE ' phase=(changed|recovering|stuck|detached|disrupted) ' <<<"$st" || return 1
    L "mkdir $LEASE && echo 'holder=storage-cutover label=$LABEL id=$(sed -E 's/.*id=([^ ]+).*/\1/' <<<"$st") host=${HOSTNAME%%.*} pid=$$ since=$(date -Is) (re-taken from evidence)' > $LEASE/holder && cat > $STATE" <<<"$st" \
      || return 1
    say "no lease on the login node (a reboot clears /run): re-taken from the evidence record"
  fi
  grep -q "stamp=$TS " <<<"$st" || { say "the held lease belongs to another cutover: $st"; return 1; }
  ADOPTED_PHASE=$(sed -nE 's/.* phase=([^ ]+) .*/\1/p' <<<"$st"); ADOPTED_PHASE=${ADOPTED_PHASE:-changed}
  PHASE=$ADOPTED_PHASE; [ "$PHASE" != done ] || PHASE=recovering    # verified once; verified again before anything reopens
  BASE_PHASE=$PHASE                # before LEASED=1: an interruption now keeps the fence
  LEASE_ID=$(sed -E 's/.*id=([^ ]+).*/\1/' <<<"$st")
  FENCED_PARTS=$(sed -E 's/.*parts=([^ ]*).*/\1/' <<<"$st" | tr ',' ' ')
  LOGIN_REPLICAS=$(sed -E 's/.*loginsets=([^ ]*).*/\1/' <<<"$st" | tr ',' ' ')
  CORDONED=$(sed -E 's/.*cordoned=([^ ]*).*/\1/' <<<"$st" | tr ',' ' ')
  LEASED=1
  say "adopted the stopped cutover's fence: $st"
}

home_users_scan() {   # processes whose cwd, root or open files are under /home on the login node
  L 'for p in /proc/[0-9]*; do for f in $p/cwd $p/root $p/fd/*; do t=$(readlink "$f" 2>/dev/null) || continue
       case "$t" in /home|/home/*) echo "${p#/proc/} $(cat $p/comm 2>/dev/null) $t";; esac; done; done'
}

consumers() {
  step "no NFS consumer left"
  local m users c n a
  m=$(L "$NFSLIST") || fail "findmnt on the login node failed"
  [ -z "$m" ] || fail "the login node still has NFS mounts (a login pod?): $m"
  users=$(home_users_scan) || fail "the /home process scan failed"
  [ -z "$users" ] || fail "processes use /home on the login node: $users"
  for c in $CLIENTS; do
    n=${c%%:*} a=${c#*:}
    m=$(C "$a" "$NFSLIST") || fail "findmnt on $n failed"
    grep -q '^/var/lib/kubelet' <<<"$m" && fail "$n still has pod NFS mounts: $(grep kubelet <<<"$m" | paste -sd' ')"
    [ -z "$m" ] || ! grep -qvxE '/home|/projects|/apps' <<<"$m" || fail "$n has unexpected NFS mounts: $m"
    say "$n: NFS mounts $(paste -sd' ' <<<"$m")"
  done
  say "login node: no NFS mounts, no process under /home"
}

backups() {
  step "fstab backups (/etc/fstab.prace-pre-storage-$TS on every host)"
  L "cp -a /etc/fstab /etc/fstab.prace-pre-storage-$TS" || fail "fstab backup on the login node"
  for c in $CLIENTS; do C "${c#*:}" "cp -a /etc/fstab /etc/fstab.prace-pre-storage-$TS" || fail "fstab backup on ${c%%:*}"; done
  say "done"
}

detach_clients() {
  step "clients unmount /home (no -l, no -f)"
  local c n a out
  for c in $CLIENTS; do
    n=${c%%:*} a=${c#*:}
    out=$(C "$a" 'r=0; mountpoint -q /home || r=$?; case $r in 0) echo mounted ;; 32) echo unmounted ;; *) echo "mountpoint failed ($r)"; exit 3 ;; esac') \
      || { say "$n: mount state unknown: $out"; return 1; }
    if [ "$out" = unmounted ]; then DETACHED="$DETACHED $c"; say "$n: /home already unmounted"; continue; fi
    out=$(C "$a" 'fuser -vm /home 2>&1 | grep -vE "^ *(USER|/home:)"; true')
    [ -z "$(tr -d ' \n' <<<"$out")" ] || { say "$n: /home in use: $out"; return 1; }
    DETACHED="$DETACHED $c"
    C "$a" 'umount /home; r=0; mountpoint -q /home || r=$?; [ $r = 32 ]' || { say "$n: umount /home failed"; return 1; }
    say "$n: /home unmounted"
  done
}

undo_a() {   # nothing changed on /home yet: unstage the LV, re-export /home, remount the clients, verify
  local c bad=0
  L "$UNSTAGE
     exportfs -ra && exportfs -v | grep -q '^/home[[:space:]]'" \
    && say "/home exported again" || { say "UNDO: /home not exported again"; bad=1; }
  for c in $DETACHED; do
    if C "${c#*:}" 'mountpoint -q /home || mount /home; timeout 10 stat /home >/dev/null && mountpoint -q /home'; then say "${c%%:*}: /home mounted again"
    else say "UNDO: /home not mounted on ${c%%:*}"; bad=1; fi
  done
  return $bad
}
undone() {   # after a verified undo A: fenced, nothing detached, nothing staged
  DETACHED="" PHASE=$BASE_PHASE
  case $PHASE in detached|stuck) PHASE=disrupted ;; esac    # (an adopted 'changed' or 'recovering' stays as recorded)
}
rollback_a() {   # an undo reopens only a fence this run took itself
  step "ROLLBACK A (back out before any change to /home)"
  if undo_a; then undone; else PHASE=stuck; fi
  exit 1
}

home_state() {   # lv | root home=absent|empty|populated old=0|1 lvmounted=0|1|staged; non-zero if unknown
  local out
  out=$(L "if mountpoint -q /home; then echo \"mounted \$(findmnt -no SOURCE --mountpoint /home)\"; exit 0; fi
           if [ ! -e /home ]; then h=absent; else l=\$(ls -A /home) || exit 3; [ -z \"\$l\" ] && h=empty || h=populated; fi
           [ -d $OLD ] && o=1 || o=0
           t=\$(findmnt -rn -o TARGET -S /dev/mapper/$VG-home 2>&1); r=\$?     # rc 1 and silent: not mounted
           if [ \$r = 0 ]; then case \"\$t\" in $STAGE|$CHECKMNT) m=staged ;; *) m=1 ;; esac
           elif [ \$r = 1 ] && [ -z \"\$t\" ]; then m=0; else echo \"findmnt failed: \$t\"; exit 3; fi
           echo \"root home=\$h old=\$o lvmounted=\$m\"") || { echo "$out"; return 1; }
  case "$out" in
    "mounted /dev/mapper/$VG-home") echo lv ;;
    "root home="*" old="[01]" lvmounted="[01]|"root home="*" old="[01]" lvmounted=staged") echo "$out" ;;
    *) echo "unexpected /home state: $out"; return 1 ;;
  esac
}

blank_or_equal_script() {   # remote: the LV, mounted read-only at $CHECKMNT, is blank or equals /home; any failed observation refuses
  # (a failed ls must never read as "blank": the copy that follows is an rsync --delete)
  cat <<EOS
entries=\$(ls -A $CHECKMNT) || { umount $CHECKMNT; echo 'listing the home LV failed'; exit 3; }
if [ -n "\$entries" ]; then
  rc=0; a=\$($LISTING_HELPER --no-label --no-root --summary $CHECKMNT) || rc=1
  b=\$($LISTING_HELPER --no-label --no-root --summary /home) || rc=1
  umount $CHECKMNT || { echo 'cannot unmount $CHECKMNT'; exit 3; }   # before acting on the result: never left mounted
  [ \$rc = 0 ] || { echo 'listing the home LV or /home failed'; exit 3; }
  [ "\$a" = "\$b" ] || { echo 'the home LV holds data that differs from /home: archive it or re-mkfs it deliberately'; exit 3; }
  echo 'home LV already equals /home (retry)'
else
  umount $CHECKMNT || { echo 'cannot unmount $CHECKMNT'; exit 3; }
  echo 'home LV blank'
fi
EOS
}

crash_point() {   # tests and rehearsal only: die here without any cleanup, like a lost session
  [ "${PRACE_CRASH_AT:-}" = "$1" ] || return 0
  echo "   (test) crash at $1"; kill -KILL $$
}

PREFLIGHT_DONE=0
preflight_b() {   # preflight_b [restored]: before anything is detached or unmounted, the preserved tree and every fstab backup
  local c need="[ -f /etc/fstab.prace-pre-storage-$TS ]" after="nothing changed"
  [ "$PHASE" != detached ] || after="the cluster stays fenced"
  [ "${1:-}" = restored ] || need="$need && [ -d $OLD ]"
  L "$need" || fail "the preserved tree $OLD or /etc/fstab.prace-pre-storage-$TS is missing on the login node; $after"
  for c in $CLIENTS; do
    C "${c#*:}" "[ -f /etc/fstab.prace-pre-storage-$TS ]" || fail "${c%%:*} has no /etc/fstab.prace-pre-storage-$TS; $after"
  done
  PREFLIGHT_DONE=1
}

check_helper() {   # listings are compared across time: only the helper version that made L0 may make the other side
  local have
  have=$(helper_sha) || fail "cannot read the installed listing helper; nothing changed"
  [ "$have" = "$(cat "$EVID/listing-helper.sha256")" ] \
    || fail "the listing helper changed since the cutover (made L0: $(cat "$EVID/listing-helper.sha256"), installed: $have): install that version to compare; nothing changed"
}

archive_lv() {   # archive_lv <dir the LV is mounted at>: copy it to lv-$TS on the root filesystem (a resumed copy only adds)
  # Sized by what rsync would transfer (a dry run against an earlier, partial archive), plus the reserve.
  L "set -euo pipefail; a=/var/lib/prace-home-premigration/lv-$TS
     need=\$(rsync -aHAXS --numeric-ids -n --stats $1/ \$a/ | sed -nE 's/^Total transferred file size: ([0-9,]+) bytes.*/\\1/p' | tr -d ,)
     free=\$(df -k --output=avail /var/lib | tail -1 | tr -d ' ')
     case \"\$need:\$free\" in *[!0-9:]*|:*|*:) echo \"cannot size the archive (need '\$need' bytes, free '\$free' KiB)\"; exit 3 ;; esac
     [ \$((need / 1024 + $ARCHIVE_RESERVE_GIB * 1024 * 1024)) -lt \$free ] \\
       || { echo \"not enough room on the root filesystem: \$((need / 1024)) KiB to copy into \$a, \$free KiB free, $ARCHIVE_RESERVE_GIB GiB kept free (PRACE_ARCHIVE_RESERVE_GIB)\"; exit 3; }
     rsync -aHAXS --numeric-ids $1/ \$a/ && echo \"LV archived to \$a\"" | sed 's/^/   /'
  [ "${PIPESTATUS[0]}" = 0 ]
}

lv_off_home_checked() {   # the LV is off /home: mounted read-only elsewhere, listed, compared with L0; writes refuse unless archived
  local d=$CHECKMNT
  check_helper
  local rc
  L "set -uo pipefail; { $UNSTAGE; } >&2 || exit 4; mkdir -p $d; mount -o ro,nodev,nosuid /dev/$VG/home $d || exit 3
     /usr/local/sbin/prace-tree-listing --no-label $d || { umount $d; exit 2; }; umount $d || exit 5" > "$EVID/rollback-lv-now.jsonl"
  rc=$?
  case $rc in
    0) ;;
    4) fail "a scratch mount of the LV is in use (see fuser above); nothing changed" ;;
    3) fail "the LV could not be mounted read-only at $d; nothing changed" ;;
    5) fail "the LV was listed but is still mounted at $d: unmount it; nothing changed" ;;
    *) fail "the LV could not be listed (rc $rc); nothing changed" ;;
  esac
  if cmp -s "$EVID/L0-home-nolabel.jsonl" "$EVID/rollback-lv-now.jsonl"; then say "the LV equals L0: nothing was written to it since the copy"; return 0; fi
  [ "$DISCARD" = 1 ] || fail "the LV changed since the cutover: restoring the old tree would hide those writes ($EVID/rollback-lv-now.jsonl vs L0-home-nolabel.jsonl). To roll back anyway: --discard-writes (archives the LV to /var/lib/prace-home-premigration/lv-$TS first; the LV is kept). Nothing changed"
  L "set -euo pipefail; mkdir -p $d; mount -o ro,nodev,nosuid /dev/$VG/home $d" || fail "the LV could not be mounted read-only; nothing changed"
  archive_lv $d; local rc=$?
  L "umount $d" || fail "could not unmount $d after the archive"
  [ $rc = 0 ] || fail "could not archive the LV; nothing changed"
}

rollback_b() {   # after the move-aside: put the old tree back; anything unverified stays fenced
  step "ROLLBACK B (old /home tree $OLD back in place)"
  [ "$PREFLIGHT_DONE" = 1 ] || preflight_b
  PHASE=changed; save_state || fail "cannot record 'changed' before rollback B; the cluster stays fenced"
  local c
  for c in $CLIENTS; do
    # mountpoint: 0 mounted, 32 not a mountpoint, else an error (umount's own failure code is also 32)
    C "${c#*:}" 'r=0; mountpoint -q /home || r=$?
                 case $r in 32) ;; 0) umount /home && { r=0; mountpoint -q /home || r=$?; [ $r = 32 ]; } ;; *) exit 3 ;; esac' || {
      C "${c#*:}" 'fuser -vm /home' 2>&1 | sed 's/^/   /'
      echo "   ROLLBACK B: umount /home on ${c%%:*} failed; the cluster stays fenced"; exit 1; }
  done
  L "set -euo pipefail
     [ -d $OLD ] || { echo 'no $OLD'; exit 3; }
     [ -f /etc/fstab.prace-pre-storage-$TS ] || { echo 'no fstab backup /etc/fstab.prace-pre-storage-$TS'; exit 3; }
     exportfs -u $ADMIN_NET:/home 2>/dev/null || true; exportfs -f
     $UNSTAGE
     if mountpoint -q /home; then umount /home || { fuser -vm /home; exit 3; }; fi
     cp -a /etc/fstab.prace-pre-storage-$TS /etc/fstab; systemctl daemon-reload
     if [ -e /home ]; then chattr -i /home 2>/dev/null || true; rmdir /home; fi   # rmdir: only an empty mountpoint
     mv $OLD /home
     echo 'the old tree is /home again'" | sed 's/^/   /'
  [ "${PIPESTATUS[0]}" = 0 ] || { echo "   ROLLBACK B FAILED on the login node: fix by hand; the cluster stays fenced"; exit 1; }
  crash_point after-restore
  rollback_tail
}

rollback_tail() {   # the old tree is /home: its mode, labels and fstab, the deferred converge, clients, verified recovery
  local c srv_list
  L "set -euo pipefail
     [ -f /etc/fstab.prace-pre-storage-$TS ] || { echo 'no fstab backup /etc/fstab.prace-pre-storage-$TS'; exit 3; }
     cp -a /etc/fstab.prace-pre-storage-$TS /etc/fstab; systemctl daemon-reload
     chmod 0755 /home; restorecon -R /home
     echo 'old /home on the root filesystem (fstab, mode, labels)'" | sed 's/^/   /'
  [ "${PIPESTATUS[0]}" = 0 ] || { echo "   ROLLBACK B: /home on the login node not finished; the cluster stays fenced"; exit 1; }
  HOME_ON=root
  ansible_run rollback-login --limit "$LOGIN_HOST" --tags storage,nfs -e '{"storage_defer":["home"]}' \
    || { echo "   ROLLBACK B: the deferred converge failed; the cluster stays fenced"; exit 1; }
  srv_list=$(L 'set -o pipefail; ls -A /home | paste -sd,') || { echo "   ROLLBACK B: cannot list the restored /home; the cluster stays fenced"; exit 1; }
  for c in $CLIENTS; do
    C "${c#*:}" "cp -a /etc/fstab.prace-pre-storage-$TS /etc/fstab && systemctl daemon-reload && (mountpoint -q /home || mount /home) \
                 && timeout 10 stat /home >/dev/null && l=\$(set -o pipefail; ls -A /home | paste -sd,) && [ \"\$l\" = '$srv_list' ]" \
      || { echo "   ROLLBACK B: /home on ${c%%:*} not restored; the cluster stays fenced"; exit 1; }
    say "${c%%:*}: old fstab, /home = the restored tree"
  done
  say "until a new attempt, converges of the login node need -e '{\"storage_defer\":[\"home\"]}'"
  PHASE=recovering
  recover
  echo; echo "RESULT: ROLLED BACK ($(ts)); stamp $TS; /home is on the root filesystem again; the LV is kept"
  [ "$ACTION" = rollback ] && exit 0
  exit 1
}

undo_detach() {   # /home never left the root filesystem: every client remounted (the run that detached them may be gone), verified recovery
  local was=${ADOPTED_PHASE:-none}
  step "/home is in place: undo any detach"
  DETACHED=" $CLIENTS" PHASE=detached
  undo_a || { PHASE=stuck; fail "undo incomplete; the cluster stays fenced"; }
  DETACHED="" PHASE=disrupted
  recover
  echo; case $was in
    recovering|done) echo "RESULT: RECOVERED ($(ts)); stamp $TS; /home is on the root filesystem; the cluster is open again" ;;
    *) echo "RESULT: UNDONE ($(ts)); stamp $TS; /home had not changed; the cluster is open again" ;;
  esac
  exit 0
}

rollback() {   # fence first, writers stopped, then decide from verified observations only
  step "rollback of cutover $TS (evidence $EVID)"
  local comparable=0 state
  if [ -r "$EVID/L0-home-nolabel.jsonl" ]; then
    [ -r "$EVID/listing-helper.sha256" ] || fail "no $EVID/listing-helper.sha256: this cutover's listings cannot be compared safely"
    comparable=1
  else say "no L0 in $EVID: only a partial cutover recorded as 'changed' or an undo can be rolled back"; fi
  [ "$TARGET" != fleet ] || { [ -r "$PROBE_KEY" ] && [ -r "$PROBE_KH" ]; } || fail "no probe key/known_hosts for the final login check"
  if adopt_fence; then
    [ "$K8S" = 0 ] || step "the adopted fence, asserted again (drained, logins at 0, no jobs, workers cordoned, slurmd pods gone)"
    close_window
  else fence; fi
  consumers
  state=$(home_state) || fail "the /home state could not be established ($state); nothing changed"
  say "/home: $state"
  case "$state" in
    lv) [ "$comparable" = 1 ] || fail "/home is on its LV but $EVID has no L0 to compare with: pass the cutover's own --evidence directory"
        HOME_ON=lv
        check_helper; preflight_b ;;
    "root home=absent old=1 lvmounted=0"|"root home=empty old=1 lvmounted=0"|"root home=absent old=1 lvmounted=staged"|"root home=empty old=1 lvmounted=staged")
      # Moved aside, the LV off /home. The LV is listed and compared with L0 (writes refuse), so
      # a record cannot hide anything; without L0 only the recorded phase 'changed' vouches.
      step "partial cutover: the old tree was moved aside and the LV is not serving /home"
      if [ "$comparable" = 1 ]; then lv_off_home_checked
      else [ "$ADOPTED_PHASE" = changed ] \
             || fail "no L0 to compare the LV with and the recorded phase (${ADOPTED_PHASE:-none}) is not a stopped move: the LV may hold writes; nothing changed"
           say "no L0: the recorded phase 'changed' is what says the LV never served /home"; fi
      rollback_b ;;
    "root home=populated old=0 lvmounted=0")
      if [ "$ADOPTED_PHASE" = changed ]; then
        step "the old tree is /home and the record says 'changed' (stopped before the move-aside, or rollback B after it): finish rollback B"
        PHASE=changed
        preflight_b restored
        rollback_tail
      else undo_detach; fi ;;
    "root home=populated old=0 lvmounted=staged")
      [ "$ADOPTED_PHASE" != changed ] || fail "the LV is staged but the record says 'changed'; nothing changed"
      undo_detach ;;
    *) fail "/home is in a state this tool does not restore automatically ($state); nothing changed" ;;
  esac
  PHASE=detached
  [ "$ADOPTED_PHASE" = changed ] || save_state || fail "cannot record the detach"   # 'changed' stays recorded
  detach_clients || rollback_a
  L "if exportfs -v | grep -q '^/home[[:space:]]'; then exportfs -u $ADMIN_NET:/home; fi; ! exportfs -v | grep -q '^/home[[:space:]]'" || rollback_a
  say "no NFS writer left; /home no longer exported"
  listing --no-label /home > "$EVID/rollback-home-now.jsonl" || { say "listing /home failed"; rollback_a; }
  if ! cmp -s "$EVID/L0-home-nolabel.jsonl" "$EVID/rollback-home-now.jsonl"; then
    if [ "$DISCARD" != 1 ]; then
      say "/home on the LV changed since the cutover: rolling back would hide those writes ($EVID/rollback-home-now.jsonl vs L0-home-nolabel.jsonl). To roll back anyway: --discard-writes (archives the LV to /var/lib/prace-home-premigration/lv-$TS first; the LV is kept)"
      rollback_a
    fi
    archive_lv /home || { say "could not archive the LV"; rollback_a; }
  else say "the LV still equals L0 (no writes since the cutover)"; fi
  rollback_b
}

recover() {   # workers, mounts and logins proven; only then the window closes
  step "recovery: workers back one at a time, mounts answer, logins ready"
  PHASE=recovering; save_state
  local n c out rc server_df ok kv
  if [ "$K8S" = 1 ]; then
    for n in $CORDONED; do
      L "$K uncordon $n" >/dev/null || fail "uncordon $n"
      ok=0; out=""
      for _ in $(seq "$WAIT_WORKER"); do out=$(L "/usr/local/sbin/prace-slinky-worker-check $n" 2>&1) && { ok=1; break; }; sleep "$PAUSE"; done
      if [ $ok != 1 ]; then       # still recorded: quarantine (on exit) cordons it again
        say "$n worker check: ${out:-no answer}"
        fail "$n not usable after uncordon"
      fi
      say "$n usable"
    done
  fi
  for c in $CLIENTS; do
    out=$(C "${c#*:}" 'mountpoint -q /home || { echo "NO /home MOUNT"; exit 3; }
          m=$(findmnt -rn -t nfs,nfs4 -o TARGET 2>&1); r=$?
          [ $r = 0 ] || { [ $r = 1 ] && [ -z "$m" ]; } || { echo "ENUMERATION FAILED: $m"; exit 3; }
          for t in $m; do timeout 10 stat -f "$t" >/dev/null || echo "STALE $t"; done'); rc=$?
    [ $rc = 0 ] && [ -z "$out" ] || fail "${c%%:*}: NFS mounts not all answering (rc $rc): $out"
  done
  say "every client has /home and every NFS mount answers"
  if [ "$K8S" = 1 ]; then
    for kv in $LOGIN_REPLICAS; do
      L "$KS patch loginset ${kv%%=*} --type merge -p '{\"spec\":{\"replicas\":${kv#*=}}}'" >/dev/null || fail "could not restore loginset ${kv%%=*}"
    done
    ok=0
    for _ in $(seq "$WAIT_LOGIN"); do
      out=$(L "$KS get pods -l app.kubernetes.io/name=login -o jsonpath='{range .items[*]}{.status.conditions[?(@.type==\"Ready\")].status}{\"\\n\"}{end}'") \
        && [ -n "$out" ] && ! grep -qvx True <<<"$out" && { ok=1; break; }
      sleep "$PAUSE"
    done
    [ $ok = 1 ] || fail "login pods not Ready within the wait (last: ${out:-no answer})"
    server_df=$(L "df -B1 --output=size /home | tail -1 | tr -d ' '") && [ -n "$server_df" ] || fail "cannot read the server's /home size"
    out=$(PROBE 'stat -c %U "$HOME" && test -r "$HOME/.ssh/authorized_keys" && df -B1 --output=source,size "$HOME" | tail -1') \
      || fail "a real login as syn-probe failed"
    [ "$(sed -n 1p <<<"$out")" = syn-probe ] && grep -qE "^$PRIV:/home +$server_df\$" <<<"$(sed -n 2p <<<"$out" | tr -s ' ')" \
      || fail "the login pod does not see the server's /home: $(paste -sd' ' <<<"$out") (server /home $server_df bytes)"
    say "login pod Ready; syn-probe logged in and sees the server's /home ($(numfmt --to=iec "$server_df"), $([ "$HOME_ON" = lv ] && echo LV || echo 'root filesystem'))"
  fi
  PHASE=done; save_state          # verified; the record keeps every original until the window is closed
  step "close the window"
  unfence || fail "window not closed"
}

cutover() {
  step "preconditions ($TARGET, $INV, stamp $TS, evidence $EVID)"
  if [ "$TARGET" = fleet ]; then
    (cd "$INFRA/.." && git diff --quiet HEAD && git fetch -q origin && [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ]) 9>&- \
      || fail "run from a clean checkout of origin/main (the merged storage MR)"
    L "pgrep -u prace-rehearsal -f qemu-kvm" >/dev/null && fail "rehearsal VMs are running on the login node; stop them first"
    [ -r "$PROBE_KEY" ] && [ -r "$PROBE_KH" ] || fail "no probe key/known_hosts for the final login check ($PROBE_KEY, $PROBE_KH)"
    L "/usr/local/sbin/prace-slinky-worker-check $(for c in $CLIENTS; do printf '%s ' "${c%%:*}"; done)" | sed 's/^/   /'
    [ "${PIPESTATUS[0]}" = 0 ] || fail "not every worker is usable"
  fi
  # The LV must be blank, or already identical to /home (a retry after rollback B): never rsync
  # --delete over data written after an earlier cutover.
  L "set -euo pipefail
     r=0; mountpoint -q /home || r=\$?     # 0 a mountpoint, 32 not one, anything else an error
     [ \$r = 32 ] || { [ \$r = 0 ] && echo '/home is already a mountpoint' || echo 'mountpoint /home failed'; exit 3; }
     [ -b /dev/$VG/home ] || { echo 'no LV /dev/$VG/home (run the preparation window)'; exit 3; }
     [ \"\$(blkid -p -o value -s TYPE /dev/$VG/home)\" = xfs ] || { echo '/dev/$VG/home is not XFS'; exit 3; }
     r=0; t=\$(findmnt -rn -S /dev/mapper/$VG-home 2>&1) || r=\$?     # rc 1 and silent: not mounted
     [ \$r = 1 ] && [ -z \"\$t\" ] || { [ \$r = 0 ] && echo 'the home LV is mounted somewhere' || echo \"findmnt failed: \$t\"; exit 3; }
     mkdir -p $CHECKMNT; mount -o ro,nodev,nosuid /dev/$VG/home $CHECKMNT
     $(blank_or_equal_script)
     /usr/local/sbin/prace-storage-check
     for u in admin prace-observer; do getent passwd \$u | cut -d: -f6 | grep -q '^/var/lib/prace-local-home/' \
       || { echo \"\$u home not relocated\"; exit 3; }
       [ ! -e /home/\$u ] || { echo \"/home/\$u still present (W1 incomplete)\"; exit 3; }; done
     echo 'home LV ready; /projects and /apps live; admin and observer homes local'" | sed 's/^/   /'
  [ "${PIPESTATUS[0]}" = 0 ] || fail "preparation incomplete"
  local have want
  have=$(helper_sha) || fail "cannot read the installed listing helper"
  want=$(repo_helper_sha) || fail "cannot hash the repo's listing helper"
  [ "$have" = "$want" ] || fail "the login node's prace-tree-listing ($have) differs from this checkout's ($want): converge --tags storage first"
  echo "$have" > "$EVID/listing-helper.sha256"

  fence
  consumers
  step "accounts converged on the old /home (check: 0 changes)"
  accounts_zero accounts-precheck || fail "accounts are not converged (accounts.yml drift or edited keys): converge --tags accounts first"
  say "0 changes"
  backups
  PHASE=detached; save_state || fail "cannot record the detach; nothing is detached"
  detach_clients || rollback_a

  step "freeze and copy /home onto the LV"
  L "if exportfs -v | grep -q '^/home[[:space:]]'; then exportfs -u $ADMIN_NET:/home; fi; ! exportfs -v | grep -q '^/home[[:space:]]'" || rollback_a
  say "/home no longer exported"
  listing /home > "$EVID/L0-home.jsonl" || rollback_a
  listing --no-label /home > "$EVID/L0-home-nolabel.jsonl" || rollback_a
  say "L0: $(listing --summary /home)"
  L "set -euo pipefail
     mkdir -p $STAGE
     mount -o nodev,nosuid,usrquota /dev/$VG/home $STAGE
     rsync -aHAXS --numeric-ids --delete /home/ $STAGE/   # --delete: equal to /home (blank or identical LV, checked above)
     echo \"rsync done: \$(du -sh $STAGE | cut -f1)\"" | sed 's/^/   /'
  [ "${PIPESTATUS[0]}" = 0 ] || rollback_a
  crash_point after-copy
  listing $STAGE > "$EVID/L1-home-new.jsonl" || rollback_a
  if ! cmp -s "$EVID/L0-home.jsonl" "$EVID/L1-home-new.jsonl"; then
    diff "$EVID/L0-home.jsonl" "$EVID/L1-home-new.jsonl" | head -20 | sed 's/^/   /'
    say "L1 differs from L0"; rollback_a
  fi
  say "L1 == L0 ($(wc -l < "$EVID/L0-home.jsonl") entries: labels, xattrs, ACLs, owners, modes, times, content)"
  L "umount $STAGE && rmdir $STAGE" || rollback_a

  step "move the old tree aside to $OLD (point of change; nothing is deleted)"
  PHASE=changed
  save_state || { say "cannot record 'changed': the tree is not moved"; rollback_a; }
  crash_point before-move
  L "set -euo pipefail
     mkdir -p -m 0700 /var/lib/prace-home-premigration
     mv /home $OLD && chmod 0700 $OLD && mkdir -m 0755 /home && restorecon /home
     echo moved" | sed 's/^/   /'
  [ "${PIPESTATUS[0]}" = 0 ] || rollback_b
  crash_point after-move

  step "converge the login node: mount the LV at /home, prove the copy complete, quotas and exports"
  ansible_run storage --limit "$LOGIN_HOST" --tags storage || rollback_b
  crash_point after-mount
  accounts_zero accounts-check || { say "accounts would change something: the copy is incomplete"; rollback_b; }
  say "accounts check: 0 changes (every home present with its owner and mode)"
  ansible_run accounts-quota-nfs --limit "$LOGIN_HOST" --tags accounts,quota,nfs || rollback_b

  step "gate"
  gate || rollback_b
  HOME_ON=lv

  step "clients mount the new /home (nosuid,nodev)"
  local limit server_df server_ls got c
  limit=$(for c in $CLIENTS; do printf '%s,' "${c%%:*}"; done)
  ansible_run clients-nfs --limit "${limit%,}" --tags nfs || rollback_b
  server_df=$(L "df -B1 --output=size /home | tail -1 | tr -d ' '") || rollback_b
  server_ls=$(L 'set -o pipefail; ls -A /home | paste -sd,') || rollback_b
  for c in $CLIENTS; do
    got=$(C "${c#*:}" "set -o pipefail; timeout 10 stat -f /home /projects /apps >/dev/null && df -B1 --output=size /home | tail -1 | tr -d ' ' && ls -A /home | paste -sd,") || rollback_b
    [ "$got" = "$server_df
$server_ls" ] || { say "${c%%:*}: /home differs from the server ($got)"; rollback_b; }
    say "${c%%:*}: /home = server LV ($(numfmt --to=iec "$server_df")), same entries"
  done
  echo "$TS" > "$EVID/lv-verified" || rollback_b          # only now may 'recover --stamp' reopen on this LV
  recover
  echo; echo "RESULT: PASS ($(ts)); stamp $TS; old tree kept at $OLD on the login node (delete only on the owner's word); evidence in $EVID"
}

gate() {
  L "set -euo pipefail
     findmnt -no SOURCE,OPTIONS --mountpoint /home | tee /dev/stderr | grep -qE '^/dev/mapper/$VG-home .*(usrquota|uquota)'
     /usr/local/sbin/prace-storage-check
     for p in /home /projects /apps; do exportfs -v | grep -q \"^\$p[[:space:]]\" || { echo \"\$p not exported\"; exit 3; }; done
     echo 'mount, quotas, exports ok'" 2>&1 | sed 's/^/   /'
  [ "${PIPESTATUS[0]}" = 0 ] || return 1
  [ "$(helper_sha)" = "$(cat "$EVID/listing-helper.sha256")" ] || { say "the listing helper changed during the window"; return 1; }
  listing --no-label /home > "$EVID/L2-home-lv-nolabel.jsonl" || return 1
  cmp -s "$EVID/L0-home-nolabel.jsonl" "$EVID/L2-home-lv-nolabel.jsonl" || { diff "$EVID/L0-home-nolabel.jsonl" "$EVID/L2-home-lv-nolabel.jsonl" | head -20; return 1; }
  say "/home on the LV equals L0 (labels checked separately by restorecon)"
  if [ "$TARGET" = fleet ]; then
    L "runuser -u prace-observer -- sudo -n /usr/local/sbin/prace-fleet-observe | python3 -c 'import json,sys; assert json.load(sys.stdin)[\"schema\"] == 1'" \
      || { say "observer forced command failed"; return 1; }
    local c
    for c in $CLIENTS; do
      ssh -o BatchMode=yes -o ConnectTimeout=15 -o ControlMaster=no -o ControlPath=none -o StrictHostKeyChecking=yes \
        -o "ProxyCommand=ssh -o BatchMode=yes -o ControlMaster=no -o ControlPath=none -W %h:%p admin@$JUMP_HOST" "root@${c#*:}" true 9>&- \
        || { say "fresh ProxyJump through admin to ${c%%:*} failed"; return 1; }
    done
    say "observer and fresh admin ProxyJump to every worker work"
  fi
}

main() {
  trap '' HUP
  INFRA=$(cd "$(dirname "$0")/.." && pwd)
  TARGET="" EVID="" LABEL=home-lv ACTION=cutover STAMP="" DISCARD=0
  while [ $# -gt 0 ]; do
    case $1 in
      --fleet) TARGET=fleet; shift ;;
      --rehearsal) TARGET=rehearsal; shift ;;
      --evidence) EVID=$2; shift 2 ;;
      --label) LABEL=$2; shift 2 ;;
      rollback|recover) ACTION=$1; shift ;;
      --stamp) STAMP=$2; shift 2 ;;
      --discard-writes) DISCARD=1; shift ;;
      *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
  done
  [ -n "$TARGET" ] && [ -n "$EVID" ] || { echo "usage: $0 --fleet|--rehearsal --evidence DIR [--label L] [rollback|recover --stamp TS [--discard-writes]]" >&2; exit 2; }
  [ "$ACTION" = cutover ] || [ -n "$STAMP" ] || { echo "$ACTION needs --stamp TS (from the cutover's output)" >&2; exit 2; }
  mkdir -p "$EVID" || exit 2
  # One run at a time on this workstation (a rollback must not adopt a live cutover's fence).
  exec 9>>"${TMPDIR:-/tmp}/prace-storage-cutover.lock" && flock -w "${PRACE_LOCK_WAIT:-10}" 9 \
    || { echo "another storage-cutover run holds ${TMPDIR:-/tmp}/prace-storage-cutover.lock" >&2; exit 2; }
  # An evidence directory belongs to one cutover: never overwrite another stamp's record.
  if [ -e "$EVID/fence-state.txt" ]; then
    local rec; rec=$(sed -nE 's/.* stamp=([^ ]+) .*/\1/p' "$EVID/fence-state.txt" 2>/dev/null)
    [ "$ACTION" != cutover ] || { echo "$EVID already holds a cutover (${rec:-unreadable record}): use a new --evidence directory" >&2; exit 2; }
    [ -z "$rec" ] || [ "$rec" = "$STAMP" ] || { echo "$EVID holds cutover $rec, not $STAMP; nothing changed" >&2; exit 2; }
    [ -n "$rec" ] || echo "WARNING: $EVID/fence-state.txt is empty or unreadable; the login node's record decides" >&2
  fi
  if [ "$TARGET" = fleet ]; then
    INV=inventories/fleet PLAYBOOK=playbooks/fleet.yml LOGIN_HOST=lab-dl380 VG=hpe_vg ADMIN_NET=10.90.10.0/25 K8S=1
    CLIENTS="lab-lenovo:10.90.10.21 lab-g005:10.90.10.15 lab-g003:10.90.10.13 lab-g004:10.90.10.14"
    LOGIN_SSH=(-o StrictHostKeyChecking=yes "root@$JUMP_HOST")
  else
    SR=${PRACE_SR_DIR:-$HOME/.cache/prace-storage-rehearsal}
    [ -r "$SR/known_hosts" ] && [ -r "$SR/id" ] || { echo "no rehearsal state in $SR (run tools/storage-rehearsal.sh up)" >&2; exit 2; }
    INV=inventories/storage-rehearsal PLAYBOOK=playbooks/storage-rehearsal.yml LOGIN_HOST=sr-login VG=sr_vg ADMIN_NET=10.90.10.0/25 K8S=0
    CLIENTS="sr-client:2252"
    LOGIN_SSH=(-o StrictHostKeyChecking=yes -o "UserKnownHostsFile=$SR/known_hosts" -o HostKeyAlgorithms=ssh-ed25519 -i "$SR/id" -o IdentitiesOnly=yes
               -o "ProxyCommand=ssh -o BatchMode=yes -W %h:%p root@$JUMP_HOST" -p 2242 root@127.0.0.1)
  fi
  MUX=$(mktemp -d "${TMPDIR:-/tmp}/prace-cut.XXXXXX")
  LEASE_ID=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
  TS=${STAMP:-$(date +%Y%m%dT%H%M%S)}
  OLD=/var/lib/prace-home-premigration/home-$TS
  trap on_exit EXIT
  trap 'exit 130' INT TERM
  case $ACTION in
    cutover) cutover ;;
    rollback) rollback ;;
    recover)
      step "recover the cutover $TS (evidence $EVID)"
      [ "$TARGET" != fleet ] || { [ -r "$PROBE_KEY" ] && [ -r "$PROBE_KH" ]; } || fail "no probe key/known_hosts for the final login check"
      adopt_fence || fail "no stopped cutover $TS holds the lease; nothing to recover"
      case $ADOPTED_PHASE in recovering|disrupted|done) ;; *) fail "cutover $TS stopped in phase '$ADOPTED_PHASE', not in recovery: use rollback --stamp $TS" ;; esac
      # A refusal keeps the adopted fence (on_exit): only a verified recovery reopens it.
      local home
      home=$(home_state) || fail "the /home state could not be established ($home)"
      case "$home" in
        lv) HOME_ON=lv
            [ "$(cat "$EVID/lv-verified" 2>/dev/null)" = "$TS" ] \
              || fail "/home is on its LV, but $EVID/lv-verified does not name $TS: the cutover never passed its gate and client checks (or this is not its --evidence directory); use rollback"
            ;;
        "root home=populated old=0 lvmounted=0") HOME_ON=root ;;
        *) fail "/home is not in a servable state ($home): use rollback" ;;
      esac
      recover
      echo; echo "RESULT: RECOVERED ($(ts)); stamp $TS" ;;
  esac
}

[ "${BASH_SOURCE[0]}" = "$0" ] && main "$@"

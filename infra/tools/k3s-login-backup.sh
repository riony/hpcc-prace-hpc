#!/bin/bash
# Consistent CONTROL-STATE backup of the login node's cluster (T73), run from the control
# workstation, inside an enforced maintenance window. It does not contain /home (NFS, user data):
# --home writes /home to a second archive inside the same window.
#
#   infra/tools/k3s-login-backup.sh --workers lab-g003,lab-g004 [--label post-rotation] [--home]
#
# What makes it consistent (SQLite datastore: K3s must be stopped for the copy; application state
# must not change while it is copied):
#   0. opens a maintenance window, and every step below happens inside it:
#      - takes the cluster lease /run/prace-cluster-lease on the login node (refused if another
#        backup, acceptance run or fleet.yml holds it; fleet.yml refuses to run while it is held);
#      - drains every partition, so Slurm refuses new submissions;
#      - with --home, scales the login pods to zero, so no interactive user writes /home;
#      - checks quiescence only AFTER that fence. A job that raced the fence is still found, and
#        the backup refuses. The previous partition states and replica counts are restored on
#        every exit, including failures;
#   1. refuses while any Slurm job is queued or running, and whenever that cannot be established
#      (a failed queue query is a refusal, never "0 jobs");
#   2. dumps the accounting database in one transaction (mysqldump --single-transaction);
#   3. freezes slurmctld (SIGSTOP) so its StateSaveLocation cannot change, stops K3s, archives
#      the K3s server state, /etc/rancher/k3s, the node password (/etc/rancher/node), the
#      local-path volumes (controller state), the dump and the database password file, then
#      resumes slurmctld and starts K3s;
#   4. records sha256 of the archive and of the server/agent token files (so a restore can prove
#      it has the matching token; token values are never printed);
#   5. proves K3s restarts without "newer than datastore" and every expected worker is usable.
# The capture therefore holds the fence itself: the LoginSets at zero replicas (--home), and the
# controller's saved partition states DRAINED. After a restore, reopen them to the states that
# prace-backup/maintenance-window.txt records. slurmctld takes partition states from its
# configuration when it starts (no -R), so restored partitions came back UP in the 28 Sep
# rehearsal; the login sets did not.
# Home policy: /home is captured inside the window, with no jobs, no submissions and no login pods.
# Writes by administrators on the login node itself are outside this policy.
# The archive stays 0600 on the login node (/root/prace-backup) and is copied to
# ~/.config/prace-lab (listed in credential-files.txt): it contains the cluster CA keys and tokens.
set -euo pipefail
LOGIN=192.0.2.205
WORKERS="" LABEL=backup HOME_TOO=0
while [ $# -gt 0 ]; do
  case $1 in --workers) WORKERS=$2; shift 2 ;; --label) LABEL=$2; shift 2 ;; --home) HOME_TOO=1; shift ;; *) echo "unknown argument: $1" >&2; exit 2 ;; esac
done
[ -n "$WORKERS" ] || { echo "usage: $0 --workers node1,node2 [--label name] [--home]" >&2; exit 2; }
[[ $LABEL =~ ^[a-z0-9-]+$ ]] || { echo "label: lowercase letters, digits and dashes only" >&2; exit 2; }
NAME="k3s-login-$(date +%Y%m%d-%H%M)-$LABEL"
SSH=${PRACE_SSH:-ssh}            # overridable for the offline tests (tools/test-k3s-login-backup.py)
DEST=${PRACE_BACKUP_DEST:-$HOME/.config/prace-lab}
SCP=${PRACE_SCP:-scp}
LOGIN_WAIT=${PRACE_LOGIN_WAIT:-180}   # seconds for the login pods to stop
# One multiplexed connection for the whole run: the login node's sshd penalises bursts of short
# connections (PerSourcePenalties), which on 28 Sep reset the connections that close the window.
MUXDIR=$(mktemp -d "${XDG_RUNTIME_DIR:-/tmp}/prace-bk.XXXXXX")
SSHO=(-o BatchMode=yes -o ConnectTimeout=10 -o ControlMaster=auto -o "ControlPath=$MUXDIR/m" -o ControlPersist=600)
L() { $SSH "${SSHO[@]}" root@$LOGIN "$@"; }
K="k3s kubectl -n slurm"; C="$K exec slurm-controller-0 -c slurmctld --"
LEASE=/run/prace-cluster-lease
LEASE_ID=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')

# --- maintenance window: whatever was fenced is undone on every exit. Each step retries (right
# after the K3s restart the Slinky webhook has no endpoints for a while and refuses the loginset
# patch); a step that still fails stays listed, so the exit trap tries again, and the run fails.
FENCED_PARTS="" LOGIN_REPLICAS="" LEASED=0
UNFENCE_TRIES=${PRACE_UNFENCE_TRIES:-60} UNFENCE_SLEEP=${PRACE_UNFENCE_SLEEP:-5}
retry() { local i; for i in $(seq "$UNFENCE_TRIES"); do "$@" >/dev/null 2>&1 && return 0; sleep "$UNFENCE_SLEEP"; done; return 1; }
unfence() {   # returns non-zero while anything is still fenced
  local kv left=""
  for kv in $FENCED_PARTS; do
    if retry L "$C scontrol update PartitionName=${kv%%=*} State=${kv#*=}"; then echo "   partition ${kv%%=*} reopened (State=${kv#*=})"
    else echo "   UNFENCE FAILED: partition ${kv%%=*} is still drained; restore State=${kv#*=} by hand"; left="$left $kv"; fi
  done
  FENCED_PARTS=${left# }; left=""
  for kv in $LOGIN_REPLICAS; do
    if retry L "$K patch loginset ${kv%%=*} --type merge -p '{\"spec\":{\"replicas\":${kv#*=}}}'"; then echo "   loginset ${kv%%=*} back to ${kv#*=} replica(s)"
    else echo "   UNFENCE FAILED: loginset ${kv%%=*}; set spec.replicas=${kv#*=} by hand"; left="$left $kv"; fi
  done
  LOGIN_REPLICAS=${left# }
  if [ "$LEASED" = 1 ] && [ -z "$FENCED_PARTS$LOGIN_REPLICAS" ]; then   # keep the lease while anything is fenced
    if retry L "grep -q 'id=$LEASE_ID' $LEASE/holder && rm -rf $LEASE"; then echo "   cluster lease released"; LEASED=0
    else echo "   LEASE NOT RELEASED: check $LEASE on the login node"; fi
  fi
  [ -z "$FENCED_PARTS$LOGIN_REPLICAS" ] && [ "$LEASED" = 0 ]
}
on_exit() {
  local rc=$?
  if [ -n "$FENCED_PARTS$LOGIN_REPLICAS" ] || [ "$LEASED" = 1 ]; then
    if ! unfence; then echo "MAINTENANCE WINDOW NOT CLOSED: see the lines above"; [ "$rc" = 0 ] && rc=1; fi
  fi
  $SSH -o "ControlPath=$MUXDIR/m" -O exit root@$LOGIN >/dev/null 2>&1 || true; rm -rf "$MUXDIR"
  exit "$rc"
}
trap on_exit EXIT

echo "== $(date +%T) preconditions"
if ! check=$(L "/usr/local/sbin/prace-slinky-worker-check ${WORKERS//,/ }"); then
  sed 's/^/   /' <<<"$check"; echo "refusing: not every expected worker is usable"; exit 3
fi
sed 's/^/   /' <<<"$check"

echo "== $(date +%T) maintenance window: lease, drain every partition$([ $HOME_TOO = 1 ] && echo ', login pods to zero')"
if ! L "mkdir $LEASE 2>/dev/null && echo 'holder=k3s-login-backup label=$LABEL id=$LEASE_ID since=$(date -Is)' > $LEASE/holder"; then
  echo "refusing: the cluster is leased ($(L "cat $LEASE/holder" 2>/dev/null || echo 'holder unknown'))"; exit 3
fi
LEASED=1
parts=$(L "$C scontrol show partition -o") || { echo "refusing: the partition query failed"; exit 3; }
states=$(grep -oE 'PartitionName=[^ ]+|State=[^ ]+' <<<"$parts" | paste -d' ' - - | sed -E 's/PartitionName=([^ ]+) State=(.+)/\1=\2/' | paste -sd' ')
[ -n "$states" ] || { echo "refusing: no partitions found"; exit 3; }
FENCED_PARTS=$states                  # recorded before draining, so a partial drain is undone too
for kv in $states; do
  L "$C scontrol update PartitionName=${kv%%=*} State=DRAIN" || { echo "refusing: could not drain partition ${kv%%=*}"; exit 3; }
done
now=$(L "$C scontrol show partition -o") || { echo "refusing: the partition query failed"; exit 3; }
if grep -oE 'State=[^ ]+' <<<"$now" | grep -qv '^State=DRAIN$'; then echo "refusing: not every partition is drained"; exit 3; fi
echo "   partitions drained (were: $states); submissions are refused"
if [ $HOME_TOO = 1 ]; then
  reps=$(L "$K get loginset -o jsonpath='{range .items[*]}{.metadata.name}={.spec.replicas}{\"\\n\"}{end}'") \
    || { echo "refusing: the loginset query failed"; exit 3; }
  [ -n "$reps" ] || { echo "refusing: no loginset found"; exit 3; }
  LOGIN_REPLICAS=$(paste -sd' ' <<<"$reps")
  for kv in $LOGIN_REPLICAS; do
    L "$K patch loginset ${kv%%=*} --type merge -p '{\"spec\":{\"replicas\":0}}'" >/dev/null || { echo "refusing: could not stop loginset ${kv%%=*}"; exit 3; }
  done
  pods=unknown
  for i in $(seq "$LOGIN_WAIT"); do
    pods=$(L "$K get pods -l app.kubernetes.io/name=login -o name") || pods=unknown
    [ -z "$pods" ] && break; sleep 1
  done
  [ -z "$pods" ] || { echo "refusing: login pods still present after ${LOGIN_WAIT}s: $pods"; exit 3; }
  echo "   login pods stopped (were: $LOGIN_REPLICAS); no interactive writers"
fi

echo "== $(date +%T) quiescence, checked inside the window"
# The query's own exit status decides: a failed query (controller down, exec error) refuses.
if ! queue=$(L "$C squeue -h -o %i"); then
  echo "refusing: the Slurm queue query failed, so an idle cluster cannot be established"; exit 3
fi
jobs=$(grep -c . <<<"$queue" || true)
[ "$jobs" = 0 ] || { echo "refusing: $jobs Slurm job(s) queued or running inside the window"; exit 3; }
echo "   no jobs; workers usable"

echo "== $(date +%T) archive $NAME (slurmctld frozen, K3s stopped during the copy)"
window="lease=$LEASE_ID partitions-before-fence=${FENCED_PARTS// /,} loginsets-before-fence=${LOGIN_REPLICAS// /,} home=$HOME_TOO"
L NAME="$NAME" WINDOW="$(printf %q "$window")" bash -s <<'REMOTE'
set -euo pipefail
umask 077
d=/root/prace-backup; mkdir -p "$d"; work=$(mktemp -d "$d/.work.XXXXXX")
mysqldump --single-transaction --routines --databases slurm_acct_db > "$work/slurm_acct_db.sql"
pids=$(pgrep -x slurmctld | tr "\n" " "); [ -n "$pids" ] || { echo "slurmctld not found"; exit 1; }
resume() { kill -CONT $pids 2>/dev/null || true; systemctl start k3s; }
trap resume EXIT
kill -STOP $pids; t0=$(date +%s)
systemctl stop k3s
sha256sum /var/lib/rancher/k3s/server/token /var/lib/rancher/k3s/server/agent-token | awk '{print $1, $2}' > "$work/token-sha256.txt"
echo "$WINDOW captured=$(date -Is)" > "$work/maintenance-window.txt"
python3 - "$d/$NAME.tgz" "$work" <<'PY'
import sys, tarfile
out, work = sys.argv[1], sys.argv[2]
with tarfile.open(out, "w:gz") as t:
    # /etc/rancher/node holds the server node's own node password: K3s checks it against the
    # secret in the datastore, so a restore without it cannot register the node again.
    for p in ("/var/lib/rancher/k3s/server", "/etc/rancher/k3s", "/etc/rancher/node", "/var/lib/rancher/k3s/storage", "/root/slinky-db.pw"):
        t.add(p)
    t.add(work + "/slurm_acct_db.sql", arcname="prace-backup/slurm_acct_db.sql")
    t.add(work + "/token-sha256.txt", arcname="prace-backup/token-sha256.txt")
    t.add(work + "/maintenance-window.txt", arcname="prace-backup/maintenance-window.txt")
PY
kill -CONT $pids; echo "   slurmctld ($pids) frozen for $(( $(date +%s) - t0 ))s"
systemctl start k3s; trap - EXIT
cp "$work/token-sha256.txt" "$d/$NAME.token-sha256"; rm -rf "$work"
for i in $(seq 60); do k3s kubectl get --raw /readyz 2>/dev/null | grep -qx ok && break; sleep 2; done
sha256sum "$d/$NAME.tgz"
REMOTE

if [ $HOME_TOO = 1 ]; then
  echo "== $(date +%T) /home (user data) to a separate archive, inside the window"
  L NAME="$NAME" bash -s <<'REMOTE'
set -euo pipefail
umask 077
python3 -c 'import sys, tarfile; t = tarfile.open(sys.argv[1], "w:gz"); t.add("/home"); t.close()' "/root/prace-backup/$NAME-home.tgz"
sha256sum "/root/prace-backup/$NAME-home.tgz"
REMOTE
fi

echo "== $(date +%T) close the maintenance window"
unfence || { echo "refusing to continue: the maintenance window did not close"; exit 1; }
if [ $HOME_TOO = 1 ]; then
  for i in $(seq "$LOGIN_WAIT"); do
    L "$K get pods -l app.kubernetes.io/name=login --no-headers" 2>/dev/null | grep -q ' Running ' && break; sleep 1
  done
  L "$K get pods -l app.kubernetes.io/name=login --no-headers" | grep -q ' Running ' \
    && echo "   login pod running again" || { echo "login pod not running after ${LOGIN_WAIT}s"; exit 1; }
fi

echo "== $(date +%T) copy to the workstation"
FILES=("root@$LOGIN:/root/prace-backup/$NAME.tgz" "root@$LOGIN:/root/prace-backup/$NAME.token-sha256")
[ $HOME_TOO = 1 ] && FILES+=("root@$LOGIN:/root/prace-backup/$NAME-home.tgz")
$SCP -q "${SSHO[@]}" "${FILES[@]}" "$DEST/"
for f in "$NAME.tgz" "$NAME.token-sha256" $([ $HOME_TOO = 1 ] && echo "$NAME-home.tgz"); do
  chmod 600 "$DEST/$f"
  grep -qx "$f" "$DEST/credential-files.txt" 2>/dev/null || echo "$f" >> "$DEST/credential-files.txt"
done
local_sum=$(sha256sum "$DEST/$NAME.tgz" | cut -d' ' -f1)
remote_sum=$(L "sha256sum /root/prace-backup/$NAME.tgz" | cut -d' ' -f1)
[ "$local_sum" = "$remote_sum" ] && echo "   copies identical: sha256 $local_sum" || { echo "COPY MISMATCH"; exit 1; }

echo "== $(date +%T) after the backup: clean restart and usable workers"
since=$(L "date '+%Y-%m-%d %H:%M:%S'")
L "systemctl restart k3s; for i in \$(seq 60); do k3s kubectl get --raw /readyz 2>/dev/null | grep -qx ok && break; sleep 2; done"
fatal=$(L "journalctl -u k3s --since '$since' --no-pager | grep -c 'newer than datastore'" || true)
echo "   'newer than datastore' after restart: $fatal"; [ "$fatal" = 0 ]
for i in $(seq 40); do L "/usr/local/sbin/prace-slinky-worker-check ${WORKERS//,/ }" >/dev/null 2>&1 && break; sleep 10; done
L "/usr/local/sbin/prace-slinky-worker-check ${WORKERS//,/ }" | sed 's/^/   /'
echo "BACKUP (control state, no /home): $NAME.tgz (sha256 $local_sum)"
if [ $HOME_TOO = 1 ]; then echo "HOME: $NAME-home.tgz (sha256 $(sha256sum "$DEST/$NAME-home.tgz" | cut -d' ' -f1))"; fi

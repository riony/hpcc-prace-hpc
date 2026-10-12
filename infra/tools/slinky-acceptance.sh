#!/bin/bash
# Slinky acceptance runner (T72/T73/T79). Run from the control workstation against the live fleet
# with the EXPLICIT list of workers that must be usable; prints timestamped steps and a PASS/FAIL
# summary (tee it into evidence). Uses only the synthetic probe accounts (accounts.yml syn-probe,
# syn-nologin, syn-revoked) and the probe key outside git; never reads a credential file.
#
#   infra/tools/slinky-acceptance.sh --workers lab-g003,lab-g004 [--skip-restarts] [--revocation]
#
# Every worker gets node-pinned work, allocation/limit checks and cancellation. CPU workers
# retain a bounded OOM test; GPU jobs prove the policy share via affinity, cgroup and accounting
# without allocating 90 GiB to force an OOM. After each restart every worker
# must complete a job pinned to it. Discovery or query errors are failures, never "none missing".
# --revocation runs the real account pipeline (roles/slinky via tools/run-ansible.sh): syn-revoked
# is made present (override), logs in, an open session is kept, then the normal converge makes
# it absent again; measures the time to refusal and reports what happened to the open session.
#
# Changes it makes, all reverted before it exits: a planted authorized_keys for syn-revoked (a
# "retained home"), bounded test jobs, deliberate restarts (login pod, K3s server, controller,
# workers) and, with --revocation, two Slinky-role converges.
set -uo pipefail
LOGIN=192.0.2.205
PRIV=10.90.10.1
PORT=32222
INFRA=$(cd "$(dirname "$0")/.." && pwd)
KEY=${PRACE_PROBE_KEY:-$HOME/.config/prace-lab/syn-probe-ed25519}
COMBINED_DEADLINE=${COMBINED_DEADLINE:-300}
# Every job names its project (-A, roles/slinky's submit filter); the probe's is proj-ops. The
# partitions every node is in (debug, and payg for pay per use) are not a node's own.
PROBE_ACCOUNT=${PRACE_PROBE_ACCOUNT:-proj-ops}   # syn-probe's project (jobs run only in projects, 30 Sep)
SHARED_PARTITIONS=${PRACE_SHARED_PARTITIONS:-debug payg}
WORKERS="" SKIP_RESTARTS=0 REVOCATION=0
while [ $# -gt 0 ]; do
  case $1 in
    --workers) WORKERS=$2; shift 2 ;;
    --skip-restarts) SKIP_RESTARTS=1; shift ;;
    --revocation) REVOCATION=1; shift ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$WORKERS" ] || { echo "usage: $0 --workers node1,node2 [--skip-restarts] [--revocation]" >&2; exit 2; }
read -r -a EXPECTED <<<"$(tr ',' ' ' <<<"$WORKERS")"

# Multiplexing only for the two login-node connections, each on its own fixed socket (the login
# node's sshd penalises many short connections). Never token-based ControlPaths: inside a
# ProxyCommand ssh expands %r/%h/%p with the OUTER target, so a jump connection would register
# under the node's name and later "node" commands would run on the login node.
MUX=$(mktemp -d "${TMPDIR:-/tmp}/prace-acc.XXXXXX")
LEASE=/run/prace-cluster-lease
LEASE_ID=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n') LEASED=0
release_lease() {
  [ "$LEASED" = 1 ] || return 0
  L "grep -q 'id=$LEASE_ID' $LEASE/holder && rm -rf $LEASE" && echo "cluster lease released" || echo "LEASE NOT RELEASED: check $LEASE on the login node"
  LEASED=0
}
trap 'release_lease; ssh -o ControlPath="$MUX/root-login" -O exit root@$LOGIN 2>/dev/null; ssh -o ControlPath="$MUX/admin-jump" -O exit admin@$LOGIN 2>/dev/null; rm -rf "$MUX"' EXIT
BASE=(-o BatchMode=yes -o ConnectTimeout=10)
JUMP=(-o "ProxyCommand=ssh -o BatchMode=yes -o ControlMaster=auto -o ControlPath=$MUX/admin-jump -o ControlPersist=300 -W %h:%p admin@$LOGIN")
L() { ssh "${BASE[@]}" -o ControlMaster=auto -o "ControlPath=$MUX/root-login" -o ControlPersist=300 root@$LOGIN "$@"; }
N() {   # a node through the (multiplexed) jump; the node connection itself is never multiplexed
  local ip=$1; shift
  ssh "${BASE[@]}" -o ControlMaster=no -o ControlPath=none "${JUMP[@]}" root@"$ip" "$@" </dev/null
}
POD() {   # ssh into the login pod as a synthetic user (each call is a fresh login), its host keys pinned
  local user=$1; shift
  ssh -o BatchMode=yes -o ConnectTimeout=15 -o ControlMaster=no -o ControlPath=none -o IdentitiesOnly=yes -i "$KEY" \
      -o UserKnownHostsFile="$PIN" -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o UpdateHostKeys=no \
      "${JUMP[@]}" -p $PORT "$user@$PRIV" "$@"
}
# The login pod's SSH host keys (3 Oct, Session A's review of the handback): the run used to drop
# the pinned key around each rollout and trust whatever key came next (trust on first use). Now the
# keys are pinned at the start from the Secret the operator keeps for the LoginSet, read over the
# verified root connection to the login node (public keys only; nothing secret leaves it), every
# login checks them strictly, and the Secret's UID and keys must stay the same across every rollout
# and restart.
PIN="$MUX/login-pod-known-hosts" HOSTKEYS=""
host_keys() {   # "uid <uid>" and the public host keys "<type> <key>", one per line
  L 'bash -s' <<'EOS'
set -euo pipefail
s="k3s kubectl -n slurm get secret slurm-login-prace-ssh-host-keys"
echo "uid $($s -o jsonpath='{.metadata.uid}')"
for t in ecdsa ed25519 rsa; do
  $s -o "jsonpath={.data.ssh_host_${t}_key\.pub}" | base64 -d | awk 'NF >= 2 {print $1, $2}'
done
EOS
}
pin_login_host_keys() {
  HOSTKEYS=$(host_keys) || { echo "the login pod's host keys could not be read"; return 1; }
  grep -qE '^uid [0-9a-f-]{36}$' <<<"$(head -1 <<<"$HOSTKEYS")" && grep -qE '^(ssh-|ecdsa-)' <<<"$HOSTKEYS" \
    || { echo "the login pod's host-key Secret is missing or empty"; return 1; }
  grep -E '^(ssh-|ecdsa-)' <<<"$HOSTKEYS" | sed "s/^/[$PRIV]:$PORT /" > "$PIN"
}
host_keys_unchanged() { local now; now=$(host_keys) && [ -n "$now" ] && [ "$now" = "$HOSTKEYS" ]; }
K='k3s kubectl -n slurm'
S="$K exec slurm-controller-0 -c slurmctld --"

# The run submits jobs and restarts components: hold the cluster lease so a backup window or a
# fleet.yml converge cannot overlap it (its own --revocation converges pass the lease id).
if ! L "mkdir $LEASE 2>/dev/null && echo 'holder=slinky-acceptance id=$LEASE_ID since=$(date -Is)' > $LEASE/holder"; then
  echo "refusing: the cluster is leased ($(L "cat $LEASE/holder" 2>/dev/null || echo 'holder unknown'))"; exit 3
fi
LEASED=1
pin_login_host_keys || { echo "refusing: the login pod's host keys cannot be pinned"; exit 3; }
echo "login pod host keys pinned from the Secret ($(head -1 <<<"$HOSTKEYS"), $(grep -cE '^(ssh-|ecdsa-)' <<<"$HOSTKEYS") keys)"
declare -a RESULTS=()
ts() { date '+%H:%M:%S'; }
step() { echo; echo "== $(ts) $*"; }
result() { RESULTS+=("$1: $2"); echo "-> $1: $2"; }
pass_if() { local name=$1; shift; if "$@"; then result "$name" PASS; else result "$name" FAIL; fi; }

worker_check() { L "/usr/local/sbin/prace-slinky-worker-check $*" </dev/null; }
node_ip() { L "k3s kubectl get node $1 -o jsonpath='{.status.addresses[?(@.type==\"InternalIP\")].address}'" </dev/null; }
job_state() { [ -n "$1" ] || { echo NO_JOB; return; }; L "$S sacct -n -X -j $1 -o State%20" </dev/null | tr -d ' ' | head -1; }
wait_job() {   # wait_job <id> <seconds>: final state
  local s=""
  for _ in $(seq $(( $2 / 3 ))); do s=$(job_state "$1"); case $s in COMPLETED|FAILED|CANCELLED*|TIMEOUT|OUT_OF_ME*|NODE_FAIL|NO_JOB) break;; esac; sleep 3; done
  echo "$s"
}
declare -A PART=()
partition_of() {   # the node's partition from Slurm (gpu for the XL270d NodeSet, cpu for the Lenovo)
  # the node's own Partitions= field (sinfo -n lists every partition, not the node's), without the
  # partitions every node is in (debug, payg): Partitions=cpu,debug,payg -> cpu
  [ -n "${PART[$1]:-}" ] || PART[$1]=$(L "$S scontrol show node $1" </dev/null | grep -o 'Partitions=[^ ]*' | cut -d= -f2 \
    | tr ',' '\n' | grep -vxF -f <(tr ' ,' '\n\n' <<<"$SHARED_PARTITIONS") | head -1)
  echo "${PART[$1]}"
}
inventory_role() {   # the node's fleet_role from the git inventory (gpu, cpu, login); empty if absent
  sed -n 's/^fleet_role: *//p' "$INFRA/inventories/fleet/host_vars/$1.yml" 2>/dev/null | head -1
}
own_gpu_procs() {   # own_gpu_procs <ip> <job>: GPU compute processes in that job's cgroup; rc != 0 when the query fails
  N "$1" "set -o pipefail; pids=\$(nvidia-smi --query-compute-apps=pid --format=csv,noheader) || exit 9; c=0; for p in \$pids; do grep -q '/job_$2/' /proc/\$p/cgroup 2>/dev/null && c=\$((c+1)); done; echo \$c"
}
array_states() {   # array_states <job>: the array's task states counted, e.g. COMPLETED=8
  L "$S sacct -n -X -j $1 -o State%20" </dev/null | tr -d ' ' | sort | uniq -c | awk '{printf "%s%s=%s", (NR > 1 ? " " : ""), $2, $1}'
}
binding_verdict() {   # binding_verdict <job lines "bus=.. affinity=.. cpus=..">: OK when 8 distinct GPUs on
  # both sockets each ran on CPUs inside that GPU's local cores
  python3 - "$1" <<'CHECK'
import re, sys
def cpus(s):
    out = set()
    for part in s.split(","):
        a, _, b = part.partition("-")
        out |= set(range(int(a), int(b or a) + 1))
    return out
rows = [re.fullmatch(r"bus=([^ ,]+) affinity=([0-9,-]+) cpus=([0-9,-]+)", l) for l in sys.argv[1].splitlines() if l.strip()]
good = len(rows) == 8 and all(rows)
if good:
    good = (len({r[1] for r in rows}) == 8 and len({min(cpus(r[2])) for r in rows}) == 2
            and all(cpus(r[3]) <= cpus(r[2]) for r in rows))
print("OK" if good else "BAD")
CHECK
}
submit_on() {   # submit_on <node> <sbatch args...>: job id
  # A GPU node takes only jobs with a GPU (the submit filter, D41): a job pinned there that asks
  # for none asks for one, and stays within one GPU's CPU and memory share
  local node=$1; shift
  local part gpu=""; part=$(partition_of "$node")
  [ "$part" = gpu ] && [[ " $* " != *" --gres="* && " $* " != *" --gpus"* ]] && gpu="--gres=gpu:1"
  POD syn-probe "sbatch --parsable -A $PROBE_ACCOUNT -p $part -w $node -t 5 $gpu $*" </dev/null | tr -d '\r'
}
# Usable after a restart = every expected worker passes the fail-closed check AND completes a job
# pinned to it. slurmctld restores nodes as idle before a restarted slurmd registers, so neither
# sinfo nor one unpinned job is proof.
wait_all_usable() {   # wait_all_usable <deadline>: prints "<seconds> <node>=<job>:<state> ..."; rc 0 when all done
  local start=$SECONDS n j s log="" left=("${EXPECTED[@]}") still
  while (( SECONDS - start < $1 )) && [ ${#left[@]} -gt 0 ]; do
    still=()
    if worker_check "${left[@]}" >/dev/null 2>&1; then
      for n in "${left[@]}"; do
        j=$(submit_on "$n" "-n 1 -o /dev/null --wrap true" 2>/dev/null); s=$(wait_job "$j" 90); log="$log $n=${j:-none}:$s"
        [ "$s" = COMPLETED ] || still+=("$n")
      done
      left=("${still[@]}")
    fi
    [ ${#left[@]} -gt 0 ] && sleep 5
  done
  echo "$((SECONDS - start))$log"; [ ${#left[@]} -eq 0 ]
}

# --- recovery helpers (tools/test-slinky-acceptance-recovery.py loads this block)
k3s_pid() { L "systemctl show -p MainPID --value k3s" </dev/null; }
ctl_uid() { L "$K get pod slurm-controller-0 -o jsonpath='{.metadata.uid}'" </dev/null; }
worker_uids() { L "$K get pods -l app.kubernetes.io/name=slurmd -o jsonpath='{range .items[*]}{.metadata.uid}{\"\\n\"}{end}'" </dev/null | sort; }
# native workers (T89): the login node's list, which the worker check also reads ("name address")
# (absent = none; a failed read stops the run: native workers must never silently count as pods)
NATIVE_LIST=$(L "if [ -e /etc/prace-slinky/native-workers ]; then cat /etc/prace-slinky/native-workers; fi" </dev/null) \
  || { echo "cannot read the login node's native worker list"; exit 2; }
NATIVE_LIST=$(awk '!/^#/ && NF == 2 {print $1}' <<<"$NATIVE_LIST")
is_native() { grep -qx "$1" <<<"$NATIVE_LIST"; }
native_pids() { for n in "${EXPECTED[@]}"; do is_native "$n" && echo "$n=$(N "${IP[$n]}" "systemctl show -p MainPID --value slurmd" </dev/null)"; done; }
native_restart() {   # restart every expected native slurmd; rc 1 if any restart command failed
  local n rc=0
  for n in "${EXPECTED[@]}"; do is_native "$n" && { N "${IP[$n]}" "systemctl restart slurmd" </dev/null || rc=1; }; done
  return $rc
}
native_renewed() {   # native_renewed <before> <after>: every expected native slurmd has a new, live main PID
  local n pid old
  for n in "${EXPECTED[@]}"; do
    is_native "$n" || continue
    old=$(grep "^$n=" <<<"$1" | cut -d= -f2); pid=$(grep "^$n=" <<<"$2" | cut -d= -f2)
    [[ ${pid:-0} =~ ^[1-9][0-9]*$ ]] && [ "$pid" != "$old" ] || return 1
  done
}
budget_of() {   # budget_of <kind>: "cpu memory" of the kind's NodeSet (a native worker keeps it)
  python3 -c 'import sys, yaml; r = yaml.safe_load(open(sys.argv[1]))["slinky_nodeset_resources"][sys.argv[2]]; print(r["cpu"], r["memory"])' \
    "$INFRA/roles/slinky/defaults/main.yml" "$1"
}
replaced() {   # replaced <before> <after>: every old identity is gone and there is a new one
  [ -n "$1" ] && [ -n "$2" ] && [ -z "$(comm -12 <(sort <<<"$1") <(sort <<<"$2"))" ]
}
# --- end recovery helpers

step "Expected workers: ${EXPECTED[*]}"
discovered=$(L "set -o pipefail; k3s kubectl get nodes -l 'prace.fleet/role in (cpu,gpu)' -o jsonpath='{range .items[*]}{.metadata.name}{\"\\n\"}{end}'" </dev/null); drc=$?
echo "   Kubernetes cpu/gpu nodes (rc=$drc): $(tr '\n' ' ' <<<"$discovered")"
if [ $drc = 0 ] && [ "$(sort <<<"$discovered" | sed '/^$/d')" = "$(printf '%s\n' "${EXPECTED[@]}" | sort)" ]; then
  result "discovered workers = expected list" PASS
else result "discovered workers = expected list" FAIL; fi
out=$(worker_check "${EXPECTED[@]}"); rc=$?; sed 's/^/   /' <<<"$out"
[ $rc = 0 ] && result "every expected worker usable (Ready node, its slurmd pod or native slurmd, Slurm usable)" PASS || result "every expected worker usable (Ready node, its slurmd pod or native slurmd, Slurm usable)" FAIL

step "R1 boundary: login NodePort on the private network only"
pass_if "campus ssh $LOGIN:22 logs in (control)" L true
# Cluster users get the login pod, never a host shell (host_base AllowUsers). Only an explicit
# authentication refusal passes; a network or host-key failure is not proof.
host_denied() {
  local out; out=$(ssh -o BatchMode=yes -o ConnectTimeout=10 -o ControlMaster=no -o ControlPath=none -o IdentitiesOnly=yes \
      -i "$KEY" -o StrictHostKeyChecking=yes "syn-probe@$LOGIN" true 2>&1) && return 1
  grep -q "Permission denied" <<<"$out"
}
pass_if "campus ssh $LOGIN:22 refuses a cluster user (syn-probe)" host_denied
pass_if "campus NodePort $LOGIN:$PORT refused" bash -c "! timeout 5 bash -c '</dev/tcp/$LOGIN/$PORT' 2>/dev/null"
pass_if "private NodePort $PRIV:$PORT from the login node" L "timeout 5 bash -c '</dev/tcp/$PRIV/$PORT'"
declare -A IP=()
for n in "${EXPECTED[@]}"; do
  IP[$n]=$(node_ip "$n")
  where=$(N "${IP[$n]:-none}" hostname 2>/dev/null)
  echo "   $n = ${IP[$n]:-no address} (answers as ${where:-nothing})"
  pass_if "private NodePort from $n" N "${IP[$n]:-none}" "[ \"\$(hostname)\" = $n ] && timeout 5 bash -c '</dev/tcp/$PRIV/$PORT'"
done

step "R2 capacity: Slurm offers each worker exactly its pod budget"
for n in "${EXPECTED[@]}"; do
  if is_native "$n"; then b=$(budget_of "$(inventory_role "$n")"); else
  b=$(L "$K get pods -l app.kubernetes.io/name=slurmd --field-selector spec.nodeName=$n -o jsonpath='{.items[0].spec.containers[?(@.name==\"slurmd\")].resources.limits.cpu} {.items[0].spec.containers[?(@.name==\"slurmd\")].resources.limits.memory}'" </dev/null); fi
  read -r cpu mem <<<"$b"
  line=$(L "$S scontrol show node $n" </dev/null | tr -s ' \n' ' ')
  eff=$(grep -o 'CPUEfctv=[0-9]*' <<<"$line" | cut -d= -f2); real=$(grep -o 'RealMemory=[0-9]*' <<<"$line" | cut -d= -f2)
  spec=$(grep -o 'MemSpecLimit=[0-9]*' <<<"$line" | cut -d= -f2)
  echo "   $n: pod limits cpu=${cpu:-?} mem=${mem:-?} | Slurm CPUEfctv=${eff:-?} RealMemory=${real:-?} MemSpecLimit=${spec:-0} -> job memory $(( ${real:-0} - ${spec:-0} )) MiB"
  if [ -n "$cpu" ] && [ "$eff" = "$cpu" ] && [ -n "$mem" ] && [ $(( ${real:-0} - ${spec:-0} )) -eq $(( ${mem%Gi} * 1024 )) ]; then
    result "capacity $n" PASS; else result "capacity $n" FAIL; fi
done

identity_checks() {   # identity_checks <label>
  local out
  out=$(POD syn-probe 'id -un; getent passwd syn-revoked || echo no-revoked' 2>&1 </dev/null | tr -d '\r'); sed 's/^/   syn-probe: /' <<<"$out"
  grep -qx syn-probe <<<"$out" && grep -qx no-revoked <<<"$out" && result "$1: enabled user logs in; revoked user unknown" PASS || result "$1: enabled user logs in; revoked user unknown" FAIL
  out=$(POD syn-nologin 'id' 2>&1 </dev/null | tr -d '\r'); sed 's/^/   syn-nologin: /' <<<"$out"
  grep -q 'not available' <<<"$out" && ! grep -q 'uid=' <<<"$out" && result "$1: nologin user gets no shell" PASS || result "$1: nologin user gets no shell" FAIL
  out=$(POD syn-revoked 'id' 2>&1 </dev/null | tr -d '\r'); sed 's/^/   syn-revoked: /' <<<"$out"
  grep -qi 'denied' <<<"$out" && ! grep -q 'uid=' <<<"$out" && result "$1: revoked user with retained key refused" PASS || result "$1: revoked user with retained key refused" FAIL
}
plant_revoked_key() { L "set -e; install -d -o 30093 -g 30093 -m 700 /home/syn-revoked /home/syn-revoked/.ssh; install -o 30093 -g 30093 -m 600 /dev/null /home/syn-revoked/.ssh/authorized_keys; cat >> /home/syn-revoked/.ssh/authorized_keys" < "$KEY.pub"; }
login_pod() { L "$K get pod -l app.kubernetes.io/name=login -o jsonpath='{.items[*].metadata.name}'" </dev/null; }
wait_login_rollout() {   # wait_login_rollout <old pod name>: until a different single login pod is Ready
  for _ in $(seq 60); do
    p=$(login_pod); if [ -n "$p" ] && [ "$p" != "$1" ] && [ "$(wc -w <<<"$p")" = 1 ] && \
      L "$K get pod $p -o jsonpath='{.status.containerStatuses[*].ready}'" </dev/null | grep -qx true; then return 0; fi
    sleep 3
  done; return 1
}

step "R3 identity: running login pod"
plant_revoked_key
identity_checks "running login pod"
step "R3 identity: fresh login pod"
old=$(login_pod); L "$K delete pod $old --wait=true >/dev/null" </dev/null; wait_login_rollout "$old" && sleep 5
pass_if "fresh login pod: host keys unchanged (Secret UID and keys)" host_keys_unchanged
identity_checks "fresh login pod"

if [ $REVOCATION = 1 ]; then
  step "R3 revocation: real present -> absent transition of syn-revoked (roles/slinky converge)"
  PY=${PRACE_ANSIBLE_VENV:-/home/operator/venvs/ansible-prace}/bin/python
  present="$MUX/present.json"
  "$PY" - "$INFRA/inventories/fleet/group_vars/all/accounts.yml" "$present" <<'PYEOF'
import json, sys, yaml
users = yaml.safe_load(open(sys.argv[1]))["cluster_users"]
for u in users:
    if u["name"] == "syn-revoked":
        u.pop("state", None)
json.dump({"cluster_users": users}, open(sys.argv[2], "w"))
PYEOF
  converge() { "$INFRA/tools/run-ansible.sh" -i inventories/fleet playbooks/fleet.yml -e fleet_armed=true --limit lab-dl380 --tags slinky -e fleet_lease_id="$LEASE_ID" "$@" >"$MUX/converge.log" 2>&1; }
  old=$(login_pod)
  if converge -e "@$present"; then echo "   converge with syn-revoked present: ok"; else echo "   converge failed:"; tail -5 "$MUX/converge.log" | sed 's/^/   /'; fi
  wait_login_rollout "$old"; sleep 5
  pass_if "revocation: host keys unchanged after the converge" host_keys_unchanged
  out=$(POD syn-revoked 'id -un' 2>&1 </dev/null | tr -d '\r'); echo "   syn-revoked while present: $out"
  grep -qx syn-revoked <<<"$out" && result "revocation: present user with key logs in (control)" PASS || result "revocation: present user with key logs in (control)" FAIL
  POD syn-revoked 'sleep 600' </dev/null >/dev/null 2>&1 & sess=$!
  sleep 5
  old=$(login_pod); t0=$SECONDS
  if converge; then echo "   normal converge (syn-revoked absent): ok"; else echo "   converge failed:"; tail -5 "$MUX/converge.log" | sed 's/^/   /'; fi
  t_conv=$((SECONDS - t0))
  refused=""
  for _ in $(seq 60); do
    out=$(POD syn-revoked 'id -un' 2>&1 </dev/null | tr -d '\r')
    grep -qi denied <<<"$out" && { refused=$((SECONDS - t0)); break; }; sleep 3
  done
  if kill -0 $sess 2>/dev/null; then sess_state="still open"; kill $sess 2>/dev/null; else sess_state="ended"; fi
  wait $sess 2>/dev/null
  echo "   converge took ${t_conv}s; new logins refused ${refused:-never} s after the converge started; the open session: $sess_state"
  [ -n "$refused" ] && result "revocation: absent user refused after the converge" PASS || result "revocation: absent user refused after the converge" FAIL
  [ "$sess_state" = ended ] && result "revocation: open session of the revoked user ended (login pod replaced)" PASS || result "revocation: open session of the revoked user ended (login pod replaced)" FAIL
  pass_if "revocation: host keys unchanged after the second converge" host_keys_unchanged
fi
L "rm -rf /home/syn-revoked" </dev/null && echo "   retained home of syn-revoked removed"

# --- policy resource check (offline regression tests execute this function as written)
policy_resources() {
  local n=$1 role j s c tres probe out
  role=$(inventory_role "$n")
  if [ "$role" = gpu ]; then
    probe="/home/syn-probe/acc-resources-$LEASE_ID.py"
    out="/home/syn-probe/acc-resources-$LEASE_ID-$n-%j.out"
    if ! POD syn-probe "cat > $probe" < "$INFRA/tools/slinky-job-resources.py"; then
      result "$n: job resource probe staged" FAIL; return 1
    fi
    # D41: deliberately undersized request, rewritten to 4 CPUs / 90 GiB per GPU.
    j=$(submit_on "$n" "-n 1 -c 2 --mem=256M -o $out --wrap 'python3 $probe --sample'")
    s=$(wait_job "$j" 120)
    c=$(POD syn-probe "cat ${out//%j/$j}" </dev/null)
    tres=$(L "$S sacct -n -X -P -j $j -o AllocTRES" </dev/null)
    echo "   $n job $j: $s; affinity/cgroup=$c; accounting=$tres"
    if [ "$s" = COMPLETED ] && python3 "$INFRA/tools/slinky-job-resources.py" --verify \
        --cpus 4 --memory-mib 92160 --alloc-tres "$tres" <<<"$c"; then
      result "$n: GPU share enforced (4 CPUs, 90 GiB; cgroup and accounting)" PASS
    else
      result "$n: GPU share enforced (4 CPUs, 90 GiB; cgroup and accounting)" FAIL
    fi
    POD syn-probe "rm -f $probe ${out//%j/$j}; test ! -e $probe && test ! -e ${out//%j/$j}" </dev/null \
      && result "$n: resource probe cleanup" PASS || result "$n: resource probe cleanup" FAIL
  elif [ "$role" = cpu ]; then
    j=$(submit_on "$n" "-n 1 -c 2 -o /home/syn-probe/acc-$n-%j.out --wrap nproc"); s=$(wait_job "$j" 120)
    c=$(POD syn-probe "cat /home/syn-probe/acc-$n-$j.out 2>/dev/null; rm -f /home/syn-probe/acc-$n-$j.out" </dev/null | tr -d '\r')
    [ "$s" = COMPLETED ] && [ "$c" = 2 ] && result "$n: CPU limit (-c 2 sees 2 CPUs)" PASS || result "$n: CPU limit (-c 2 sees 2 CPUs)" FAIL
    j=$(submit_on "$n" "-n 1 --mem=256M -o /dev/null --wrap 'head -c 1200M /dev/zero | tail > /dev/null'"); s=$(wait_job "$j" 180)
    [ "$s" = OUT_OF_MEMORY ] && result "$n: memory limit enforced" PASS || result "$n: memory limit enforced" FAIL
  else
    result "$n: known inventory role for resource checks" FAIL; return 1
  fi
}
# --- end policy resource check

step "Node-pinned work on every worker (as syn-probe, project $PROBE_ACCOUNT)"
for n in "${EXPECTED[@]}"; do
  j=$(submit_on "$n" "-n 1 -o /home/syn-probe/acc-$n-%j.out --wrap 'hostname; id -un; nproc'"); s=$(wait_job "$j" 120)
  o=$(POD syn-probe "cat /home/syn-probe/acc-$n-$j.out 2>/dev/null; rm -f /home/syn-probe/acc-$n-$j.out" </dev/null | tr -d '\r' | tr '\n' ' ')
  echo "   $n job $j: $s, output: $o"
  [ "$s" = COMPLETED ] && [ "$(awk '{print $1}' <<<"$o")" = "$n" ] && result "$n: pinned CPU job ran there" PASS || result "$n: pinned CPU job ran there" FAIL
  policy_resources "$n"
  ip=${IP[$n]}
  j=$(submit_on "$n" "-n 2 -o /dev/null --wrap 'sleep 600 & sleep 600 & wait'")
  for _ in $(seq 30); do [ "$(L "$S squeue -h -j $j -o %T" </dev/null)" = RUNNING ] && break; sleep 2; done
  host=$(N "$ip" hostname)
  for _ in $(seq 20); do before=$(N "$ip" 'ps -u 30091 -o pid= | wc -l'); [ "$before" -ge 3 ] && break; sleep 1; done
  POD syn-probe "scancel $j" </dev/null; crc=$?
  for i in $(seq 20); do after=$(N "$ip" 'set -o pipefail; ps -u 30091 -o pid= | wc -l'); [ "$after" = 0 ] && break; sleep 1; done
  st=$(wait_job "$j" 60)
  echo "   $n job $j: scancel rc=$crc; processes on $host before=$before after=$after (~${i}s); accounting $st"
  [ "$host" = "$n" ] && [ "$crc" = 0 ] && [ "$before" -ge 3 ] && [ "$after" = 0 ] && [[ $st == CANCELLED* ]] \
    && result "$n: cancelled job leaves no processes" PASS || result "$n: cancelled job leaves no processes" FAIL
done

step "GPU scheduling on every GPU worker (D39: capacity, allocation, device confinement, accounting, cancellation)"
# The GPU load for the cancellation check: a prebuilt CUDA binary from the host's toolkit
# (mounted read-only) in a loop. The worker image has no C++ compiler, so nvcc cannot build in a
# job (28 Sep; the software environment step provides compilers).
GPU_LOAD="while :; do /usr/local/cuda-12.9/extras/demo_suite/bandwidthTest --mode=shmoo --memory=pinned >/dev/null; done"
# GPU workers are the expected workers whose git inventory role is gpu, never inferred from
# Slurm's partition order; the Kubernetes role label and the Slurm partition must agree with it.
GPU_WORKERS=()
for n in "${EXPECTED[@]}"; do
  role=$(inventory_role "$n")
  label=$(L "k3s kubectl get node $n -o jsonpath='{.metadata.labels.prace\\.fleet/role}'" </dev/null)
  [ -n "$role" ] && [ "$label" = "$role" ] && result "$n: inventory role ($role) = node label" PASS || result "$n: inventory role (${role:-missing}) = node label (${label:-missing})" FAIL
  [ "$role" = gpu ] && GPU_WORKERS+=("$n")
done
echo "   GPU workers from the inventory: ${GPU_WORKERS[*]:-none}"
for n in "${GPU_WORKERS[@]}"; do
  [ "$(partition_of "$n")" = gpu ] && result "$n: in the gpu partition" PASS || result "$n: in the gpu partition" FAIL
  gres=$(L "$S scontrol show node $n -o" </dev/null | grep -oE 'Gres=[^ ]+' | head -1)
  echo "   $n: $gres"
  [[ $gres == Gres=gpu:8* ]] && result "$n: Slurm offers gpu:8" PASS || result "$n: Slurm offers gpu:8" FAIL
  # allocation and confinement: a 2-GPU job must see exactly 2 GPUs and open only 2 device files
  j=$(submit_on "$n" "-n 1 --gres=gpu:2 -o /home/syn-probe/acc-gpu-$n-%j.out --wrap 'nvidia-smi -L | grep -c ^GPU; /usr/local/cuda-12.9/extras/demo_suite/deviceQuery | grep -oE \"Detected [0-9]+ CUDA\"; o=0; for d in /dev/nvidia[0-7]; do head -c0 \$d 2>/dev/null && o=\$((o+1)); done; echo opened=\$o'"); s=$(wait_job "$j" 120)
  o=$(POD syn-probe "cat /home/syn-probe/acc-gpu-$n-$j.out 2>/dev/null; rm -f /home/syn-probe/acc-gpu-$n-$j.out" </dev/null | tr -d '\r' | tr '\n' ' ')
  echo "   $n job $j (--gres=gpu:2): $s; nvidia-smi GPUs, CUDA devices, device files opened: $o"
  [ "$s" = COMPLETED ] && [[ $o == "2 Detected 2 CUDA opened=2 " ]] && result "$n: a 2-GPU job sees and opens exactly 2 GPUs" PASS || result "$n: a 2-GPU job sees and opens exactly 2 GPUs" FAIL
  tres=$(L "$S sacct -n -X -P -j $j -o AllocTRES" </dev/null)
  echo "   $n job $j accounting: $tres"
  [[ $tres == *gres/gpu=2* ]] && result "$n: accounting records gres/gpu=2" PASS || result "$n: accounting records gres/gpu=2" FAIL
  # CPU/GPU binding: 8 concurrent 1-GPU jobs with --gres-flags=enforce-binding. Each job's CPUs
  # must lie within its own GPU's local cores (nvidia-smi topo inside the job), and together they
  # must use 8 different GPUs on both sockets. Explicit --mem: without a default memory per CPU,
  # a job gets the whole node's memory and the 8 tasks ran one after another (28 Sep).
  POD syn-probe "cat > /home/syn-probe/acc-bind.sh" <<'JOB'
#!/bin/bash
b=$(nvidia-smi --query-gpu=pci.bus_id --format=csv,noheader | paste -sd,)
a=$(nvidia-smi topo -m | awk '/^GPU0[[:space:]]/{print $(NF-2)}')
echo "bus=$b affinity=$a cpus=$(awk '/^Cpus_allowed_list/{print $2}' /proc/self/status)"
sleep 30   # hold the GPU so the 8 tasks overlap and must get 8 different GPUs
JOB
  arr=$(submit_on "$n" "--array=0-7 -n 1 -c 2 --mem=4G --gres=gpu:1 --gres-flags=enforce-binding -o /home/syn-probe/acc-bind-$n-%A_%a.out /home/syn-probe/acc-bind.sh")
  states=""; for _ in $(seq 80); do
    states=$(array_states "${arr:-none}"); [ "$states" = COMPLETED=8 ] && break
    [[ -z $states || $states == *PENDING* || $states == *RUNNING* ]] || break; sleep 3
  done
  o=$(POD syn-probe "cat /home/syn-probe/acc-bind-$n-${arr}_*.out 2>/dev/null; rm -f /home/syn-probe/acc-bind-$n-${arr}_*.out /home/syn-probe/acc-bind.sh" </dev/null | tr -d '\r')
  echo "   $n array job $arr: states [$states]"; sed 's/^/     /' <<<"$o"
  [ "$states" = COMPLETED=8 ] && [ "$(binding_verdict "$o")" = OK ] && result "$n: 8 concurrent 1-GPU jobs, each bound to its GPU's socket" PASS \
    || result "$n: 8 concurrent 1-GPU jobs, each bound to its GPU's socket" FAIL
  # cancellation: a GPU process exists on the host while the job runs, and none after scancel
  ip=${IP[$n]}
  j=$(submit_on "$n" "-n 1 --gres=gpu:1 -o /dev/null --wrap '$GPU_LOAD'")
  # Counts only GPU processes in this job's own cgroup (job_<id>); a failed query is never zero.
  before=""; for _ in $(seq 60); do before=$(own_gpu_procs "$ip" "$j") && [ "$before" -ge 1 ] && break; before=""; sleep 2; done
  POD syn-probe "scancel $j" </dev/null; crc=$?
  after=""; for i in $(seq 30); do after=$(own_gpu_procs "$ip" "$j") && [ "$after" = 0 ] && break; after=""; sleep 1; done
  st=$(wait_job "$j" 60)
  echo "   $n job $j (CUDA load): scancel rc=$crc; the job's GPU processes before=${before:-query failed} after=${after:-query failed or still present} (~${i}s); accounting $st"
  [ "$crc" = 0 ] && [ "${before:-0}" -ge 1 ] && [ "$after" = 0 ] && [[ $st == CANCELLED* ]] \
    && result "$n: a cancelled GPU job leaves no GPU process" PASS || result "$n: a cancelled GPU job leaves no GPU process" FAIL
done

if [ $SKIP_RESTARTS = 1 ]; then echo; echo "(restarts skipped)"; else
step "Recovery: K3s server restart (bootstrap data on disk must match the datastore)"
# Every recovery check requires (1) the restart command itself to succeed, (2) proof that the
# component really restarted (new PID / pod UIDs), (3) a pinned job on every worker afterwards.
# Jobs succeeding after a failed restart command are not recovery (review F3).
before=$(k3s_pid); since=$(L "date '+%Y-%m-%d %H:%M:%S'")
L "systemctl restart k3s" </dev/null; cmd=$?
ok=1; for _ in $(seq 60); do L "k3s kubectl get --raw /readyz" 2>/dev/null </dev/null | grep -qx ok && { ok=0; break; }; sleep 3; done
after=$(k3s_pid)
fatal=$(L "journalctl -u k3s --since '$since' --no-pager | grep -c 'newer than datastore'" </dev/null)
out=$(wait_all_usable 300); rc=$?
echo "   restart command rc=$cmd; k3s PID ${before:-?} -> ${after:-?}; API ready: $([ $ok = 0 ] && echo yes || echo no); 'newer than datastore' messages: ${fatal:-?}; all workers usable after ${out%% *}s:${out#* }"
[ $cmd = 0 ] && [ "$before" != 0 ] && replaced "$before" "$after" && [ $ok = 0 ] && [ "$fatal" = 0 ] && [ $rc = 0 ] \
  && result "K3s server restarts cleanly" PASS || result "K3s server restarts cleanly" FAIL

step "Recovery: controller restart alone"
last=$(L "$S sacct -n -X -a -S now-1days -o JobID" </dev/null | tr -d ' ' | grep -E '^[0-9]+$' | sort -n | tail -1)
before=$(ctl_uid)
L "$K delete pod slurm-controller-0 --wait=true >/dev/null" </dev/null; cmd=$?
out=$(wait_all_usable 300); rc=$?
after=$(ctl_uid)
first=$(awk '{print $2}' <<<"$out" | sed 's/^[^=]*=//; s/:.*//')
echo "   delete rc=$cmd; controller pod ${before:-?} -> ${after:-?}; all workers usable after ${out%% *}s:${out#* } (last job before restart: ${last:-?})"
[ $cmd = 0 ] && replaced "$before" "$after" && [ $rc = 0 ] && [ "${first:-0}" -gt "${last:-0}" ] \
  && result "controller restart (state kept, every worker runs a job)" PASS || result "controller restart (state kept, every worker runs a job)" FAIL

step "Recovery: worker restart alone"
before=$(worker_uids); before_n=$(native_pids)
L "$K delete pod -l app.kubernetes.io/name=slurmd --wait=true >/dev/null" </dev/null; cmd=$?
native_restart || cmd=1
out=$(wait_all_usable 300); rc=$?
after=$(worker_uids); after_n=$(native_pids)
native_renewed "$before_n" "$after_n"; native_ok=$?
[ -n "$NATIVE_LIST" ] && echo "   native slurmd PIDs: ${before_n//$'\n'/ } -> ${after_n//$'\n'/ }"
echo "   delete rc=$cmd; slurmd pods replaced: $(replaced "$before" "$after" && echo all || echo NO) ($(grep -c . <<<"$before") -> $(grep -c . <<<"$after")); all workers usable after ${out%% *}s:${out#* }"
[ $cmd = 0 ] && replaced "$before" "$after" && [ $native_ok = 0 ] && [ $rc = 0 ] \
  && result "worker restart (every worker runs a job)" PASS || result "worker restart (every worker runs a job)" FAIL

step "Recovery: controller and workers together, automatic only (deadline ${COMBINED_DEADLINE}s; the NodeSet watchdog is part of the design)"
since=$(L "date '+%Y-%m-%d %H:%M:%S'"); before_c=$(ctl_uid); before_w=$(worker_uids); before_n=$(native_pids)
L "$K delete pod slurm-controller-0 && $K delete pod -l app.kubernetes.io/name=slurmd" >/dev/null </dev/null; cmd=$?
native_restart || cmd=1   # every backend restarts: native slurmd too (review R8)
out=$(wait_all_usable "$COMBINED_DEADLINE"); rc=$?
after_c=$(ctl_uid); after_w=$(worker_uids); after_n=$(native_pids)
native_renewed "$before_n" "$after_n"; native_ok=$?
[ -n "$NATIVE_LIST" ] && echo "   native slurmd PIDs: ${before_n//$'\n'/ } -> ${after_n//$'\n'/ }"
nudges=$(L "journalctl -t prace-slinky-nudge --since '$since' -o cat --no-pager" </dev/null)
echo "   delete rc=$cmd; controller replaced: $(replaced "$before_c" "$after_c" && echo yes || echo NO); slurmd pods replaced: $(replaced "$before_w" "$after_w" && echo all || echo NO)"
echo "   all workers usable after ${out%% *}s with no manual action:${out#* }"
echo "   watchdog: ${nudges:-no nudge needed}"
[ $cmd = 0 ] && replaced "$before_c" "$after_c" && replaced "$before_w" "$after_w" && [ $native_ok = 0 ] && [ $rc = 0 ] \
  && result "combined restart recovers automatically (every worker runs a job)" PASS || result "combined restart recovers automatically (every worker runs a job)" FAIL
fi

step "The login pod's host keys after the whole run"
pass_if "host keys unchanged through the run (Secret UID and keys)" host_keys_unchanged

step "Summary"
printf '%s\n' "${RESULTS[@]}"
if printf '%s\n' "${RESULTS[@]}" | grep -q ': FAIL$'; then echo "ACCEPTANCE: FAIL"; exit 1; fi
echo "ACCEPTANCE: PASS"

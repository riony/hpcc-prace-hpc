#!/bin/bash
# Managed by Ansible (roles/slinky). usage: prace-share-probe SERVER IMAGE PATH:MODE:CLAIM...
# Client-side qualification before any login or slurmd pod uses the shares (T87): on every node
# that runs them (prace.fleet/role login, cpu or gpu) a short pod mounts the shares' claims the
# way those pods will, and checks from inside: NFS 4 from SERVER, nosuid and nodev, rw or ro as
# the share, and a listing that works. Exit 0 only if every node passes; 1 if a node fails; 2 if
# a query fails or a claim is not bound. Every probe pod is deleted, also on failure. Every wait
# gives up after PRACE_PROBE_TRIES x 2 s, so a node that does not answer fails; it never hangs the run.
#
# 3 Oct: containerd hands a volume to runc as a bind mount that loses kubelet's nosuid,nodev; the
# NRI plugin prace-nri-mount-guard puts them back. The probe exercises that same path: each probe
# pod runs the containers' own share check (PRACE_SHARE_CHECK, files/prace-share-check.sh) before
# looking, and a control pod mounts a share at a path the plugin does not guard, where the same
# check must refuse (exit 78): a check that cannot fail proves nothing.
set -uo pipefail
K=${PRACE_KUBECTL:-"/usr/local/bin/k3s kubectl"}
NS=slurm
TRIES=${PRACE_PROBE_TRIES:-60}
CHECK=${PRACE_SHARE_CHECK:-}
[ $# -ge 3 ] || { echo "usage: prace-share-probe SERVER IMAGE PATH:MODE:CLAIM..."; exit 2; }
[ -n "$CHECK" ] || { echo "PRACE_SHARE_CHECK (the containers' share check) is required"; exit 2; }
server=$1 image=$2; shift 2
shares=("$@")
json() { python3 -c 'import json, sys; print(json.dumps(sys.argv[1:]))' "$@"; }

nodes=$($K get nodes -l 'prace.fleet/role in (login,cpu,gpu)' -o 'jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}') \
  || { echo "node query failed"; exit 2; }
[ -n "$nodes" ] || { echo "no login/cpu/gpu nodes found"; exit 2; }

for s in "${shares[@]}"; do
  claim=${s##*:} phase=""
  for _ in $(seq "$TRIES"); do
    phase=$($K -n $NS get pvc "$claim" -o 'jsonpath={.status.phase}' 2>/dev/null) && [ "$phase" = Bound ] && break
    sleep 2
  done
  [ "$phase" = Bound ] || { echo "claim $claim is not bound (${phase:-query failed})"; exit 2; }
done

pods=()
cleanup() { for p in "${pods[@]}"; do $K -n $NS delete pod "$p" --ignore-not-found --wait=false >/dev/null 2>&1; done; }
trap cleanup EXIT

mounts="" vols="" paths="" modes=()
for i in "${!shares[@]}"; do
  IFS=: read -r path mode claim <<<"${shares[$i]}"
  ro=$([ "$mode" = ro ] && echo true || echo false)
  mounts+="        - {name: s$i, mountPath: $path, readOnly: $ro}"$'\n'
  vols+="    - {name: s$i, persistentVolumeClaim: {claimName: $claim, readOnly: $ro}}"$'\n'
  paths+=" $path"
  modes+=("$path:$mode")
done
look="for p in$paths; do grep \" \$p \" /proc/mounts || echo \"\$p unmounted\"; ls \$p >/dev/null && echo \"\$p listed\"; done"

# start POD on NODE with COMMAND (a JSON list) and MOUNTS/VOLUMES; wait for it to end; sets $phase.
# A node that cannot confirm an earlier pod of this name is gone (NotReady, agent down) fails.
run_pod() {
  local pod=$1 node=$2 command=$3 pmounts=$4 pvols=$5
  pods+=("$pod"); phase=""
  if ! $K -n $NS delete pod "$pod" --ignore-not-found --wait=true --timeout="$((TRIES * 2))s" >/dev/null 2>&1; then
    echo "$node: earlier probe pod not removed within $((TRIES * 2)) s (node not answering?)"; return 1
  fi
  if ! $K apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $pod, namespace: $NS, labels: {app.kubernetes.io/name: prace-share-probe}}
spec:
  nodeName: $node
  restartPolicy: Never
  tolerations: [{operator: Exists}]
  containers:
    - name: probe
      image: $image
      command: $command
      volumeMounts:
$pmounts  volumes:
$pvols
EOF
  then
    echo "$node: probe pod not created"; return 1
  fi
  for _ in $(seq "$TRIES"); do
    phase=$($K -n $NS get pod "$pod" -o 'jsonpath={.status.phase}' 2>/dev/null)
    case $phase in Succeeded|Failed) return 0 ;; esac
    sleep 2
  done
  return 0
}

bad=0
while read -r node; do
  [ -n "$node" ] || continue
  pod="prace-share-probe-$node"
  run_pod "$pod" "$node" "$(json sh -c "$CHECK" prace-share-check "${modes[@]}" -- sh -c "$look")" "$mounts" "$vols" || { bad=1; continue; }
  if [ "$phase" != Succeeded ]; then
    why=$($K -n $NS get events --field-selector "involvedObject.name=$pod" -o 'jsonpath={range .items[*]}{.message}{"; "}{end}' 2>/dev/null)
    said=$($K -n $NS logs "$pod" 2>/dev/null | grep '^prace-share-check:')
    echo "$node: probe ${phase:-not started} (${said:-${why:-no events}})"; bad=1; continue
  fi
  log=$($K -n $NS logs "$pod" 2>/dev/null) || { echo "$node: probe log unreadable"; bad=1; continue; }
  for s in "${shares[@]}"; do
    IFS=: read -r path mode claim <<<"$s"
    line=$(awk -v p="$path" '$2 == p' <<<"$log")
    src=$(awk '{print $1}' <<<"$line") fstype=$(awk '{print $3}' <<<"$line") opts=",$(awk '{print $4}' <<<"$line"),"
    if [ "$fstype" != nfs4 ] || [ "$src" != "$server:$path" ] || [[ $opts != *,nosuid,* ]] || [[ $opts != *,nodev,* ]] \
       || [[ $opts != *,hard,* ]] || [[ $opts != *",$mode,"* ]] || ! grep -qx "$path listed" <<<"$log"; then
      echo "$node: $path wrong (${line:-not mounted})"; bad=1
    else
      echo "$node: $path ok ($fstype $mode nosuid nodev)"
    fi
  done
done <<<"$nodes"

# the control, on the first node: the first share again, read-only, at a path the plugin does not
# guard; nosuid is checked first, so the check must refuse for that
IFS=: read -r _ _ cclaim <<<"${shares[0]}"
cnode=$(head -n1 <<<"$nodes") cdir=/prace-share-control
if run_pod prace-share-probe-control "$cnode" "$(json sh -c "$CHECK" prace-share-check "$cdir:ro" -- true)" \
     "        - {name: c, mountPath: $cdir, readOnly: true}"$'\n' "    - {name: c, persistentVolumeClaim: {claimName: $cclaim, readOnly: true}}"$'\n'; then
  code=$($K -n $NS get pod prace-share-probe-control -o 'jsonpath={.status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null)
  said=$($K -n $NS logs prace-share-probe-control 2>/dev/null | grep '^prace-share-check:')
  if [ "$phase" = Failed ] && [ "$code" = 78 ] && [[ $said == *"lacks nosuid"* ]]; then
    echo "control: the share check refuses an unguarded mount ($said)"
  else
    echo "control: the share check did not refuse an unguarded mount (phase ${phase:-none}, exit ${code:-none}${said:+, $said})"; bad=1
  fi
else
  bad=1
fi
exit $bad

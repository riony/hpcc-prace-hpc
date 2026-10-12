#!/bin/bash
# Managed by Ansible (roles/slinky). usage: prace-native-release fence|release NODE ADDR TAINT
# The controller side of taking a native slurmd down (tasks/native-off.yml), run on the login node.
# Only a Slurm record registered at ADDR (the host's private address: the native slurmd's) is
# touched; a record at another address belongs to the node's returning pod and is kept.
#   fence    drain the native record, then require that no job is on the node. The drain stays
#            when a job is left: a lasting scheduling fence while the operator decides.
#   release  delete the native record and remove TAINT (key=value:Effect) from the Kubernetes
#            node, each verified by a fresh query afterwards.
# "Absent" is only ever a successful query's answer. Exit 1: a job on the node, or a step that did
# not take effect; exit 2: a failed query (an unreadable state is never "nothing to do").
set -uo pipefail
K=${PRACE_KUBECTL:-/usr/local/bin/k3s kubectl}
S="$K -n slurm exec slurm-controller-0 -c slurmctld --"
[ $# = 4 ] && [[ $1 =~ ^(fence|release)$ ]] || { echo "usage: prace-native-release fence|release NODE ADDR TAINT"; exit 2; }
mode=$1 node=$2 addr=$3 taint=$4
key=${taint%%=*} effect=${taint##*:}

record() {   # native | pod | absent (stdout); returns 2 when the controller cannot be asked
  local out rc
  out=$($S scontrol show node "$node" -o 2>&1); rc=$?
  if [ $rc = 0 ]; then
    [[ " $out " == *" NodeAddr=$addr "* ]] && echo native || echo pod
  elif [[ $out == *"Node $node not found"* ]]; then
    echo absent
  else
    echo "controller query failed: ${out:-no output}" >&2; return 2
  fi
}

taints() {   # the node's taints as key=value:Effect lines; returns 2 when the API cannot be asked
  local out
  out=$($K get node "$node" -o jsonpath='{range .spec.taints[*]}{.key}={.value}:{.effect}{"\n"}{end}' 2>&1) \
    || { echo "taint query failed: ${out:-no output}" >&2; return 2; }
  printf '%s\n' "$out"
}

r=$(record) || exit 2
if [ "$mode" = fence ]; then
  if [ "$r" != native ]; then echo "no native record ($r): nothing to fence"; exit 0; fi
  out=$($S scontrol update nodename="$node" state=drain reason="prace: native slurmd rollback" 2>&1) \
    || { echo "drain failed: $out"; exit 1; }
  echo "drained"
  jobs=$($S squeue -h -w "$node" -o %i 2>&1) || { echo "queue query failed: $jobs"; exit 2; }
  jobs=$(tr '\n' ' ' <<<"$jobs" | sed 's/ *$//')
  if [ -n "$jobs" ]; then
    echo "jobs on $node: $jobs (it stays drained; cancel them or let them end, then run again)"; exit 1
  fi
  echo "no job on $node"; exit 0
fi

if [ "$r" = native ]; then
  out=$($S scontrol delete nodename="$node" 2>&1) || { echo "record delete failed: $out"; exit 1; }
  r=$(record) || exit 2
  [ "$r" = absent ] || { echo "record still present after delete ($r)"; exit 1; }
  echo "record removed"
else
  echo "record: $r (kept)"
fi
t=$(taints) || exit 2
if grep -q "^$key=" <<<"$t"; then
  out=$($K taint node "$node" "$key:$effect-" 2>&1) || { echo "taint removal failed: $out"; exit 1; }
  t=$(taints) || exit 2
  if grep -q "^$key=" <<<"$t"; then echo "taint still present after removal"; exit 1; fi
  echo "taint removed"
else
  echo "taint: absent"
fi

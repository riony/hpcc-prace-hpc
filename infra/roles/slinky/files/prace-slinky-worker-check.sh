#!/bin/bash
# Managed by Ansible (roles/slinky). usage: prace-slinky-worker-check NODE...
# Exit 0 only if EVERY named node is a usable Slinky worker: Kubernetes node Ready, exactly one
# slurmd pod on it with all containers ready, Slurm state idle/mixed/allocated/completing (a
# trailing '*' = not responding fails). A native worker (listed "name address" in
# $PRACE_NATIVE_FILE, T89) instead has NO slurmd pod (one would compete) and its Slurm record's
# NodeAddr is its listed address (the native daemon, not a pod). Every failed query fails the
# check (fail closed); an empty node list is an error, never "all registered".
set -uo pipefail
K=${PRACE_KUBECTL:-"/usr/local/bin/k3s kubectl"}
NATIVE=${PRACE_NATIVE_FILE:-/etc/prace-slinky/native-workers}
if [ -e "$NATIVE" ] && ! [ -r "$NATIVE" ]; then echo "cannot read $NATIVE"; exit 2; fi
native_addr() { [ -e "$NATIVE" ] && awk -v n="$1" '$1 == n {print $2}' "$NATIVE"; }
[ $# -gt 0 ] || { echo "no expected workers given"; exit 2; }
bad=0
for n in "$@"; do
  if ! ready=$($K get node "$n" -o 'jsonpath={.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null); then
    echo "$n: kubernetes query failed"; bad=1; continue
  fi
  [ "$ready" = True ] || { echo "$n: kubernetes node not Ready (${ready:-absent})"; bad=1; continue; }
  if ! pods=$($K -n slurm get pods -l app.kubernetes.io/name=slurmd --field-selector "spec.nodeName=$n" \
        -o 'jsonpath={range .items[*]}{.metadata.name} {.status.containerStatuses[*].ready}{"\n"}{end}' 2>/dev/null); then
    echo "$n: slurmd pod query failed"; bad=1; continue
  fi
  count=$(grep -c . <<<"$pods")
  addr=$(native_addr "$n")
  if [ -n "$addr" ]; then
    [ "$count" = 0 ] || { echo "$n: native worker, but $count slurmd pod(s) compete"; bad=1; continue; }
    if ! st=$($K -n slurm exec slurm-controller-0 -c slurmctld -- sinfo -h -N -n "$n" -o '%T %o' 2>/dev/null | sort -u); then
      echo "$n: slurm query failed"; bad=1; continue
    fi
    [ "$(grep -c . <<<"$st")" = 1 ] || { echo "$n: slurm states disagree or absent ($(paste -sd, <<<"$st"))"; bad=1; continue; }
    [ "${st#* }" = "$addr" ] || { echo "$n: registered from ${st#* }, not the native address $addr"; bad=1; continue; }
    case "${st%% *}" in
      idle|mixed|allocated|completing) echo "$n: ok (${st%% *}, native slurmd at $addr)" ;;
      *) echo "$n: slurm state '${st%% *}'"; bad=1 ;;
    esac
    continue
  fi
  [ "$count" = 1 ] || { echo "$n: expected one slurmd pod, found $count"; bad=1; continue; }
  if grep -qw false <<<"$pods" || ! grep -qw true <<<"$pods"; then echo "$n: slurmd pod not ready ($pods)"; bad=1; continue; fi
  # one line per partition the node is in (cpu and debug, ...): the node's state is the same in each
  if ! st=$($K -n slurm exec slurm-controller-0 -c slurmctld -- sinfo -h -N -n "$n" -o %T 2>/dev/null | sort -u); then
    echo "$n: slurm query failed"; bad=1; continue
  fi
  [ "$(grep -c . <<<"$st")" -le 1 ] || { echo "$n: slurm states disagree ($(paste -sd, <<<"$st"))"; bad=1; continue; }
  case "$st" in
    idle|mixed|allocated|completing) echo "$n: ok ($st, pod ${pods%% *})" ;;
    *) echo "$n: slurm state '${st:-absent}'"; bad=1 ;;
  esac
done
exit $bad

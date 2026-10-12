#!/bin/bash
# Managed by Ansible (roles/slinky). Repairs ONLY the known stale-budget case: a node that Slurm
# marks INVALID_REG with a capacity-mismatch reason (after a NodeSet budget change), that one of
# our NodeSets owns (a slurmd pod on that Kubernetes node and the NodeSet feature on the Slurm
# node) and that has no jobs. Diagnostics are written first to /var/log/prace-slinky/. Any other
# invalid node is left alone and reported (exit 3) for diagnosis. No diagnostics, no change: if the
# record cannot be written in full, nothing is deleted (exit 2).
set -uo pipefail
K=${PRACE_KUBECTL:-"/usr/local/bin/k3s kubectl"}
S="$K -n slurm exec slurm-controller-0 -c slurmctld --"
LOG=${PRACE_LOG_DIR:-/var/log/prace-slinky}
KINDS=${PRACE_NODESET_KINDS:-"cpu gpu"}
mkdir -p "$LOG" 2>/dev/null && [ -d "$LOG" ] && [ -w "$LOG" ] || { echo "cannot create or write diagnostics directory $LOG; no change"; exit 2; }
nodes=$($S sinfo -h -N -o '%N %T') || { echo "slurm query failed"; exit 2; }
rc=0
for n in $(awk '$2 ~ /^inval/ {print $1}' <<<"$nodes" | sort -u); do
  info=$($S scontrol show node "$n") || { echo "$n: scontrol show node failed"; rc=2; continue; }
  reason=$(sed -n 's/^ *Reason=\(.*\) \[.*$/\1/p; s/^ *Reason=\([^[]*\)$/\1/p' <<<"$info" | head -1)
  features=$(grep -o 'AvailableFeatures=[^ ]*' <<<"$info" | cut -d= -f2)
  pod=$($K -n slurm get pods -l app.kubernetes.io/name=slurmd --field-selector "spec.nodeName=$n" -o name) || { echo "$n: pod query failed"; rc=2; continue; }
  jobs=$($S squeue -h -w "$n" -o %i) || { echo "$n: squeue failed"; rc=2; continue; }
  owned=no; for k in $KINDS; do [[ ",$features," == *",$k,"* ]] && owned=yes; done
  f="$LOG/reregister-$(date +%Y%m%dT%H%M%S)-$n.txt"
  if ! { echo "# $(date -Is) prace-slinky-reregister"; echo "$info"; echo "pod: ${pod:-none}"; echo "jobs: ${jobs:-none}"; } > "$f" 2>/dev/null \
     || ! grep -q "NodeName=$n" "$f" 2>/dev/null || ! sync "$f" 2>/dev/null; then
    echo "$n: diagnostics could not be written to $f; no change"; rc=2; continue
  fi
  if [[ "$reason" =~ ^(CoreSpec\ differ|MemSpecLimit\ differ|Low\ RealMemory|Low\ CPUs|Low\ socket\*core\*thread\ count) ]] \
     && [ "$owned" = yes ] && [ -n "$pod" ] && [ -z "$jobs" ]; then
    if $S scontrol delete nodename="$n" && $K -n slurm delete $pod --wait=false >/dev/null; then
      echo "re-registered $n ($reason); diagnostics $f"
    else
      echo "$n: delete failed; diagnostics $f"; rc=2
    fi
  else
    echo "left $n for diagnosis: reason='${reason:-none}' nodeset-owned=$owned pod='${pod:-none}' jobs='${jobs:-none}'; diagnostics $f"
    rc=3
  fi
done
exit $rc

#!/bin/bash
# Managed by Ansible (roles/slinky). Slinky NodeSet watchdog (login node, every minute).
# The operator backs off after failed reconciles (e.g. while slurmctld restarts) and can leave
# a deleted slurmd pod missing for many minutes. When a Ready, schedulable node of a NodeSet's
# kind has had no slurmd pod for two consecutive checks, annotate the NodeSet: an update event
# makes the operator reconcile at once. Every nudge is logged (journal tag prace-slinky-nudge).
set -u
K="/usr/local/bin/k3s kubectl"
state=/run/prace-slinky-nudge
mkdir -p "$state"
for ns in $($K -n slurm get nodesets -o jsonpath='{.items[*].metadata.name}' 2>/dev/null); do
  kind=${ns#slurm-worker-}
  want=$($K get nodes -l "prace.fleet/role=$kind" --no-headers 2>/dev/null | awk '$2 == "Ready" {print $1}' | sort)
  have=$($K -n slurm get pods -l "app.kubernetes.io/instance=$ns" -o jsonpath='{range .items[*]}{.spec.nodeName}{"\n"}{end}' 2>/dev/null | sort -u)
  missing=$(comm -23 <(printf '%s\n' "$want" | sed '/^$/d') <(printf '%s\n' "$have" | sed '/^$/d') | tr '\n' ' ')
  if [ -z "$missing" ]; then
    rm -f "$state/$ns"
  elif [ -f "$state/$ns" ]; then
    $K -n slurm annotate nodeset "$ns" "prace.fleet/reconcile-nudge=$(date +%s)" --overwrite >/dev/null \
      && logger -t prace-slinky-nudge "nudged $ns: no slurmd pod on ${missing}for 2 checks"
    rm -f "$state/$ns"
  else
    : > "$state/$ns"
  fi
done

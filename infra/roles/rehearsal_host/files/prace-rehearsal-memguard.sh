#!/bin/bash
# Managed by Ansible (roles/rehearsal_host). usage: prace-rehearsal-memguard <MiB for the VMs>
# Exit 0 only if MemAvailable leaves the reserved memory for the live control plane after the VMs.
set -u
need=${1:?MiB for the VMs}
reserve=${PRACE_REHEARSAL_RESERVE_MIB:-65536}
avail=$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)
if [ "$avail" -lt $(( need + reserve )) ]; then
  echo "refusing: MemAvailable ${avail} MiB < ${need} MiB for the VMs + ${reserve} MiB reserved for the live control plane" >&2
  exit 3
fi
echo "ok: MemAvailable ${avail} MiB >= ${need} + ${reserve} MiB"

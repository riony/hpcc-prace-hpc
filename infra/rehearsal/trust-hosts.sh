#!/bin/bash
# Rehearsal-only trust: record the local VMs' SSH host keys, read over localhost (the login
# VM's port forward) and, for the CPU VM, from inside the login VM. Never used for real hosts.
set -euo pipefail
K="$HOME/scratch/rehearsal/known_hosts"
umask 077
for i in $(seq 60); do ssh-keyscan -T 5 -p 2222 127.0.0.1 >/dev/null 2>&1 && break; sleep 5; done
ssh-keyscan -T 5 -p 2222 127.0.0.1 2>/dev/null > "$K"
ssh -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$K" -p 2222 root@127.0.0.1 \
  'for i in $(seq 60); do ssh-keyscan -T 5 10.90.10.21 2>/dev/null | grep -q . && break; sleep 5; done; ssh-keyscan -T 5 10.90.10.21 2>/dev/null' >> "$K"
cut -d' ' -f1,2 "$K" | sort -u

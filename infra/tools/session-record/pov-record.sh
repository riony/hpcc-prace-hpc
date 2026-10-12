#!/bin/bash
# Record a user's terminal session on the PRACE login pod, first person: what the user saw, with its timing.
#   pov-record.sh <user> <name> [remote command]   (no command: an interactive login shell)
# Writes <name>.tm (timing) and <name>.out (the terminal output) here; replay with
#   scriptreplay --log-timing <name>.tm --log-out <name>.out
set -euo pipefail
umask 077
user=$1 name=$2; shift 2
[[ "$user" =~ ^[a-z_][a-z0-9_-]*$ && "$name" =~ ^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$ ]] || exit 2
for ext in tm out in; do [[ ! -e "$name.$ext" ]] || { echo "Recording exists" >&2; exit 1; }; done
here=$PWD                                       # recordings go to the current (private) directory
known=${PRACE_PRACE_KNOWN_HOSTS:-$HOME/.config/prace-lab/prace-login.known_hosts}
key=$HOME/.config/prace-lab/synthetic-keys/${user}_ed25519
ssh_cmd=(ssh -tt -o BatchMode=yes -o "UserKnownHostsFile=$known" -o StrictHostKeyChecking=yes
         -o IgnoreUnknown=WarnWeakCrypto -o WarnWeakCrypto=no-pq-kex -i "$key" -p 32222 "$contributor@example.org")
if [ $# -gt 0 ]; then ssh_cmd+=("bash -lc $(printf '%q' "$*")"); fi
cmd=$(printf '%q ' "${ssh_cmd[@]}")
exec script -q -e --log-timing "$here/$name.tm" --log-out "$here/$name.out" --log-in "$here/$name.in" -c "$cmd"

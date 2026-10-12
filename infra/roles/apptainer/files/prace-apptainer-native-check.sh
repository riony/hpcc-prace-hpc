#!/bin/bash
# Managed by Ansible (roles/apptainer). Read-only checks on a native worker (T89), whose jobs run on
# the host itself, before the Apptainer module is offered there. The pods' jobs get the same checks
# from the live acceptance (tools/apptainer-acceptance.py), inside a job on every worker.
#
# usage: prace-apptainer-native-check USERNS FUSE SUBUID SUBGID -- USER:UID...
#   USERNS  /proc/sys/user/max_user_namespaces: unprivileged user namespaces must be enabled (> 0)
#   FUSE    /dev/fuse: a character device (squashfuse_ll mounts the image through it)
#   SUBUID, SUBGID  /etc/subuid, /etc/subgid: no range for any listed cluster user, by name or uid.
#           A range lets --fakeroot (or newuidmap, which has file capabilities on Rocky 9) map 65536
#           more ids; files they write on the NFS shares belong to no account and escape the
#           per-user quota. Rocky 9's useradd adds such a range by default. An absent file has none.
# Prints "ok: ..." per passed check; "refusing: ..." on stderr per failed one and exits 78 (no
# check stops the others); 64 on bad usage. Changes nothing.
set -u
usage() { echo "usage: prace-apptainer-native-check USERNS FUSE SUBUID SUBGID -- USER:UID..." >&2; exit 64; }
[ $# -ge 6 ] && [ "$5" = -- ] || usage
userns=$1 fuse=$2 subuid=$3 subgid=$4
shift 5
for u in "$@"; do
  [[ $u =~ ^[a-z_][a-z0-9._-]*:[0-9]+$ ]] || { echo "prace-apptainer-native-check: bad user '$u' (USER:UID)" >&2; exit 64; }
done
bad=0

n=$(cat -- "$userns" 2>/dev/null) || n=""
if [[ $n =~ ^[0-9]+$ ]] && [ "$n" -gt 0 ]; then
  echo "ok: unprivileged user namespaces ($userns = $n)"
else
  echo "refusing: unprivileged user namespaces are disabled or unreadable ($userns = ${n:-unreadable})" >&2; bad=1
fi

if [ -c "$fuse" ]; then
  echo "ok: $fuse is a character device"
else
  echo "refusing: $fuse is not a character device (squashfuse_ll mounts images through it)" >&2; bad=1
fi

for f in "$subuid" "$subgid"; do
  if [ ! -e "$f" ] && [ ! -L "$f" ]; then
    echo "ok: $f absent (no ranges)"; continue
  fi
  if ! text=$(cat -- "$f" 2>/dev/null); then
    echo "refusing: $f is unreadable" >&2; bad=1; continue
  fi
  hits=""
  for u in "$@"; do
    name=${u%%:*} id=${u##*:}
    while IFS=: read -r owner _; do
      if [ "$owner" = "$name" ] || [ "$owner" = "$id" ]; then hits="$hits $name"; break; fi
    done <<< "$text"
  done
  if [ -z "$hits" ]; then
    echo "ok: no cluster user has a range in $f"
  else
    echo "refusing: subordinate id ranges in $f for:$hits (remove them; see the Apptainer threat model)" >&2; bad=1
  fi
done

[ $bad = 0 ] || exit 78

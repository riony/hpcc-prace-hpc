#!/bin/bash
# Managed by Ansible (roles/slinky). usage: prace-share-exports NETWORK PATH:MODE...
# Exit 0 only if every PATH is exported by this NFS server to exactly one client, NETWORK (the
# fleet's private network, which kubelet mounts from), with MODE (rw or ro) among its options.
# Anything else stops the role before it writes a manifest, so the pods keep their mounts:
#   exit 1: a share not exported, exported with the other mode, or also exported to another
#           client (a wrong-client or overlapping rule could decide what the workers get);
#   exit 2: exportfs failed (an unreadable state is never an empty one).
set -uo pipefail
EXPORTFS=${PRACE_EXPORTFS:-exportfs}
[ $# -ge 2 ] || { echo "usage: prace-share-exports NETWORK PATH:MODE..."; exit 2; }
net=$1; shift
if ! out=$($EXPORTFS -s 2>&1); then
  echo "exportfs -s failed: ${out:-no output}"; exit 2
fi
bad=0
for pm in "$@"; do
  path=${pm%:*} mode=${pm##*:}
  # every client(options) entry for this path, one per line or several per line
  entries=$(awk -v p="$path" '$1 == p { for (i = 2; i <= NF; i++) print $i }' <<<"$out")
  if [ -z "$entries" ]; then
    echo "$path: not exported"; bad=1; continue
  fi
  count=$(grep -c . <<<"$entries")
  client=${entries%%(*}
  opts=$(sed -n 's/^[^(]*(\(.*\))$/\1/p' <<<"$entries" | head -1)
  if [ "$count" != 1 ] || [ "$client" != "$net" ]; then
    echo "$path: exported to $(tr '\n' ' ' <<<"$entries"):  must be exactly $net"; bad=1; continue
  fi
  if [[ ",$opts," != *",$mode,"* ]]; then
    echo "$path: exported to $net without $mode ($opts)"; bad=1; continue
  fi
  echo "$path: $net $mode ok"
done
exit $bad

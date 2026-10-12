#!/bin/sh
# Managed by Ansible (roles/slinky, tasks/native-config.yml). usage: prace-native-share-check SERVER PATH:MODE...
# T89 (4 Oct): the native slurmd's ExecStartPre. A native worker has no pod, so neither the NRI mount
# guard nor the pods' share check (prace-share-check) applies: its jobs see the host's own mounts.
# slurmd starts only if each share PATH is visible as the login node's export SERVER:PATH, NFS 4.2,
# hard, with nosuid, nodev and MODE (rw or ro) on the mount (roles/nfs_home mounts them so). Otherwise
# it exits 78 and systemd retries (Restart=on-failure), so a late or wrong mount never runs a job on
# the empty directory underneath or with setuid/devices honoured. It only reads /proc/self/mountinfo
# (PRACE_MOUNTINFO in tests): the unit has no mount namespace of its own, so that is the host's view.
mi=${PRACE_MOUNTINFO:-/proc/self/mountinfo}
[ -r "$mi" ] || { echo "prace-native-share-check: $mi unreadable; not starting" >&2; exit 78; }
[ $# -ge 2 ] || { echo "prace-native-share-check: usage: SERVER PATH:MODE..." >&2; exit 64; }
server=$1; shift
for spec in "$@"; do
  p=${spec%:*} m=${spec##*:}
  case $p:$m in
    /*:rw|/*:ro) ;;
    *) echo "prace-native-share-check: bad share '$spec' (PATH:rw or PATH:ro)" >&2; exit 64 ;;
  esac
  # mountinfo: field 5 the mount point, 6 the per-mount options; after " - ": fstype, source, super
  # options. The last line for a mount point is the visible mount (a later one is mounted on top).
  row=$(awk -v p="$p" '{ for (i = 7; i <= NF && $i != "-"; i++) ; if ($5 == p) r = $6 " " $(i + 1) " " $(i + 2) " " $(i + 3) } END { print r }' "$mi")
  read -r opts fstype source super <<EOF
$row
EOF
  [ -n "$opts" ] || { echo "prace-native-share-check: $p not mounted; not starting" >&2; exit 78; }
  [ "$fstype" = nfs4 ] && [ "$source" = "$server:$p" ] || {
    echo "prace-native-share-check: $p is $fstype from $source, not nfs4 from $server:$p; not starting" >&2; exit 78; }
  for want in nosuid nodev "$m"; do
    case ",$opts," in *",$want,"*) ;; *) echo "prace-native-share-check: $p lacks $want ($opts); not starting" >&2; exit 78 ;; esac
  done
  for want in vers=4.2 hard; do
    case ",$super," in *",$want,"*) ;; *) echo "prace-native-share-check: $p lacks $want ($super); not starting" >&2; exit 78 ;; esac
  done
done
exit 0

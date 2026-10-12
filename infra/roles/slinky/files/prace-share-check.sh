# Managed by Ansible (roles/slinky). usage: prace-share-check PATH:MODE... -- COMMAND [ARG...]
# T87 (3 Oct): runs first in the login and slurmd containers (the chart's command) and in the share
# probe. Each share PATH must be mounted in this container with nosuid, nodev and MODE (rw or ro), as
# the NRI plugin prace-nri-mount-guard sets them; otherwise it exits 78 and COMMAND (sshd, slurmd)
# never starts. It only reads /proc/self/mountinfo (PRACE_MOUNTINFO in tests) and needs no privilege.
mi=${PRACE_MOUNTINFO:-/proc/self/mountinfo}
[ -r "$mi" ] || { echo "prace-share-check: $mi unreadable; not starting" >&2; exit 78; }
while [ $# -gt 0 ] && [ "$1" != -- ]; do
  p=${1%:*} m=${1##*:} o=""
  case $p:$m in
    /*:rw|/*:ro) ;;
    *) echo "prace-share-check: bad share '$1' (PATH:rw or PATH:ro)" >&2; exit 64 ;;
  esac
  # mount point and per-mount options are fields 5 and 6; a later line is a mount on top
  while read -r _ _ _ _ mp opts _; do if [ "$mp" = "$p" ]; then o=$opts; fi; done < "$mi"
  for want in nosuid nodev "$m"; do
    case ",$o," in
      *",$want,"*) ;;
      *) echo "prace-share-check: $p lacks $want (${o:-not mounted}); not starting" >&2; exit 78 ;;
    esac
  done
  shift
done
if [ "${1:-}" != -- ] || [ $# -lt 2 ]; then
  echo "prace-share-check: usage: PATH:MODE... -- COMMAND [ARG...]" >&2; exit 64
fi
shift
exec "$@"

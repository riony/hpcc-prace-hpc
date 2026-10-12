#!/bin/bash
# Managed by Ansible (roles/apptainer). Builds the acceptance probe image once, on the login node,
# with no internet: the alpine image roles/slinky keeps in the private repository (exported from
# containerd by its pinned digest), converted to SIF by the /apps Apptainer, plus
#   /prace-euid-probe   setuid root: a 142-byte static ELF that calls geteuid() and exits 0 if it is
#                      root, 1 otherwise (EUID_PROBE below), for the acceptance's no-privilege-gain
#                      check. Not busybox: alpine's busybox drops setuid privileges itself, so a
#                      setuid copy reports the caller even where setuid works (5 Oct, positive control)
#   /prace-probe-source where it came from
#
# usage: prace-apptainer-probe APPTAINER ARCHIVE DIGEST OUT
#   APPTAINER  the wrapper in the /apps tree (TREE/prace/bin/apptainer)
#   ARCHIVE    the OCI archive; its index.json must name DIGEST
#   OUT        the SIF; OUT.sha256 (sha256sum format) and OUT.source are written next to it
# Runs as root (the role). An existing OUT that matches OUT.sha256 prints "unchanged"; one that
# does not, or has none, is refused with exit 3 and left as it is (never replaced). A missing or
# wrong archive exits 2 before anything is written. The image is built in a private temporary
# directory, removed on every exit, and renamed into place last; prints "built".
set -euo pipefail
umask 022
# x86-64 ELF: header, one R+X PT_LOAD at 0x400000, then mov eax,107 (geteuid); syscall;
# xor edi,edi; test eax,eax; setne dil; mov eax,60 (exit); syscall. tools/test-apptainer.py builds
# the same bytes from that description; tools/apptainer-acceptance.py runs them as its control.
EUID_PROBE=7f454c4602010100000000000000000002003e00010000007800400000000000400000000000000000000000000000000000000040003800010000000000000001000000050000000000000000000000000040000000000000004000000000008e000000000000008e000000000000000010000000000000b86b0000000f0531ff85c0400f95c7b83c0000000f05
EUID_PROBE_SHA256=0c364be2754df3fcd076af068e4c2be3597eac0d615c9526de36e4c4fc8fca56
[ $# = 4 ] || { echo "usage: prace-apptainer-probe APPTAINER ARCHIVE DIGEST OUT" >&2; exit 2; }
apptainer=$1 archive=$2 digest=$3 out=$4
dir=$(dirname -- "$out") base=$(basename -- "$out")
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "refusing: bad digest '$digest'" >&2; exit 2; }
[ -x "$apptainer" ] || { echo "refusing: $apptainer is not executable" >&2; exit 2; }
[ -d "$dir" ] || { echo "refusing: $dir does not exist" >&2; exit 2; }

if [ -e "$out" ] || [ -L "$out" ]; then
  if [ -f "$out" ] && [ ! -L "$out" ] && [ -f "$out.sha256" ] && (cd "$dir" && sha256sum --check --status --strict "$base.sha256"); then
    echo unchanged; exit 0
  fi
  echo "refusing: $out exists and does not match $out.sha256; inspect it, it is never replaced" >&2
  exit 3
fi

# the archive is the pinned image: a regular file whose OCI index.json names the digest (what
# `ctr images export` writes: the image's own index), and which carries that blob with exactly that
# sha256. Apptainer's reader checks every blob it then follows (platform manifest, config, layers).
[ -f "$archive" ] && [ ! -L "$archive" ] || { echo "refusing: $archive is not a regular file" >&2; exit 2; }
index=$(tar -xOf "$archive" index.json 2>/dev/null) || { echo "refusing: $archive has no index.json (not an OCI archive)" >&2; exit 2; }
grep -qF "\"$digest\"" <<< "$index" || { echo "refusing: $archive does not name $digest" >&2; exit 2; }
if ! sum=$(tar -xOf "$archive" "blobs/sha256/${digest#sha256:}" 2>/dev/null | sha256sum) || [ "${sum%% *}" != "${digest#sha256:}" ]; then
  echo "refusing: $archive does not carry the blob $digest" >&2; exit 2
fi

work=$(mktemp -d "${TMPDIR:-/var/tmp}/prace-apptainer-probe.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir "$work/cache" "$work/tmp" "$work/config"
# cache, temporary files and per-user configuration in the private directory, none in root's home
export APPTAINER_CACHEDIR=$work/cache APPTAINER_TMPDIR=$work/tmp APPTAINER_CONFIGDIR=$work/config
"$apptainer" build --sandbox "$work/root" "oci-archive:$archive" >"$work/build.log" 2>&1 \
  || { echo "refusing: converting $archive failed:" >&2; tail -20 "$work/build.log" >&2; exit 4; }
probe=$work/root/prace-euid-probe
printf '%b' "$(sed 's/../\\x&/g' <<< "$EUID_PROBE")" > "$probe"
sum=$(sha256sum < "$probe")
[ "${sum%% *}" = "$EUID_PROBE_SHA256" ] || { echo "refusing: the euid probe is not the pinned 142 bytes" >&2; exit 4; }
chmod 4755 "$probe"
[ "$(stat -c %a "$probe")" = 4755 ] || { echo "refusing: $probe is not mode 4755" >&2; exit 4; }
printf 'image=%s\ndigest=%s\nprobe=/prace-euid-probe setuid root, exits 0 only as root\n' "$archive" "$digest" > "$work/root/prace-probe-source"
"$apptainer" build "$work/probe.sif" "$work/root" >>"$work/build.log" 2>&1 \
  || { echo "refusing: building the SIF failed:" >&2; tail -20 "$work/build.log" >&2; exit 4; }
[ -s "$work/probe.sif" ] || { echo "refusing: the SIF is empty" >&2; exit 4; }

install -m 0644 "$work/probe.sif" "$out.partial"
sum=$(sha256sum < "$out.partial") && sum=${sum%% *}
printf '%s  %s\n' "$sum" "$base" > "$out.sha256.partial"
printf 'archive=%s\ndigest=%s\napptainer=%s\nbuilt=%s\n' "$archive" "$digest" "$("$apptainer" version)" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$out.source.partial"
chmod 0644 "$out.sha256.partial" "$out.source.partial"
sync -f "$out.partial"
mv -T -- "$out.sha256.partial" "$out.sha256"
mv -T -- "$out.source.partial" "$out.source"
mv -T -- "$out.partial" "$out"
echo built

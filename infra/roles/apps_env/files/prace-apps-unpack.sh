#!/bin/bash
# Managed by Ansible (roles/apps_env). Unpacks a pinned set of RPMs into one versioned tree under
# /apps/sw (T88), never installing them: rpm2archive (the images have no cpio) piped into tar.
#
# usage: prace-apps-unpack DEST PACKAGES_DIR MANIFEST
#   MANIFEST  "sha256  file.rpm" lines (sha256sum format), the pinned set (roles/apps_env defaults)
#
# Fails closed, before anything is written: a missing RPM, a checksum that differs, or an empty
# manifest exits 2. A tree is immutable once made: DEST with the same manifest prints "unchanged";
# DEST with a different one exits 3 (a new set gets a new version directory, so a running job never
# sees its compiler change). The tree is built in DEST.partial (removed first if a run was
# interrupted) and renamed into place only when every RPM unpacked; DEST/.prace-manifest records the
# set. Prints "unpacked" when it made the tree. The slurm bench runs this same file
# (tests/slurm-bench/bench.py apps).
set -euo pipefail
umask 022
[ $# = 3 ] || { echo "usage: prace-apps-unpack DEST PACKAGES_DIR MANIFEST" >&2; exit 2; }
dest=${1%/} pkgs=$2 manifest=$3
command -v rpm2archive >/dev/null || { echo "refusing: rpm2archive not found" >&2; exit 2; }

# --- every pinned RPM present with its checksum (sha256sum --check reads only the listed files)
grep -Eq '^[0-9a-f]{64}  [^/ ]+\.rpm$' "$manifest" || { echo "refusing: $manifest lists no RPM" >&2; exit 2; }
if bad=$(grep -Ev '^[0-9a-f]{64}  [^/ ]+\.rpm$' "$manifest"); then
  echo "refusing: malformed manifest line: $bad" >&2; exit 2
fi
if ! out=$(cd "$pkgs" && sha256sum --check --strict "$manifest" 2>&1); then
  echo "refusing: missing or mismatched RPM in $pkgs:" >&2
  printf '%s\n' "$out" | grep -v ': OK$' >&2
  exit 2
fi

# --- an existing tree: unchanged, or refused
if [ -e "$dest" ] || [ -L "$dest" ]; then
  # sha256sum, not cmp: Rocky's minimal images have no diffutils
  if [ -d "$dest" ] && [ ! -L "$dest" ] && [ -f "$dest/.prace-manifest" ] \
     && [ "$(sha256sum < "$manifest")" = "$(sha256sum < "$dest/.prace-manifest")" ]; then
    echo unchanged; exit 0
  fi
  echo "refusing: $dest exists with a different or no manifest; a new set needs a new version directory" >&2
  exit 3
fi

# --- unpack into a staging tree, then rename into place
stage=$dest.partial
rm -rf -- "$stage"
mkdir -p -- "$stage"
while read -r _ rpm || [ -n "${rpm:-}" ]; do
  rpm2archive - < "$pkgs/$rpm" | tar -xzf - -C "$stage" --no-same-owner
done < "$manifest"
install -m 0644 "$manifest" "$stage/.prace-manifest"
sync -f "$stage"
mv -T -- "$stage" "$dest"
echo unpacked

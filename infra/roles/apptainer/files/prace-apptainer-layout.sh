#!/bin/bash
# Managed by Ansible (roles/apptainer). The one change the role makes to the unpacked RPM files: each
# program in TREE/usr/libexec/apptainer/bin moves to TREE/usr/libexec/apptainer/libexec and its old
# name becomes a link to .wrapper (templates/apptainer-libexec-wrapper.sh.j2), which gives it the
# tree's libraries. Apptainer starts these helpers without the caller's library path (bench in the
# pinned slurmd image, 5 Oct: "Apptainer runtime parent: ... libsubid.so.3: cannot open shared
# object file"); Apptainer's own tools/install-unprivileged.sh lays out its relocatable unprivileged
# installation the same way.
#
# usage: prace-apptainer-layout TREE
# Idempotent and resumable: prints "changed" when it moved or linked anything, else "unchanged".
# Refuses (exit 3) before changing anything on what it does not recognise: a program that is in
# both places, a link to anything but .wrapper, anything but a regular file or such a link, or no
# programs at all. Exit 2 on bad usage or a missing .wrapper.
set -euo pipefail
[ $# = 1 ] || { echo "usage: prace-apptainer-layout TREE" >&2; exit 2; }
bin=${1%/}/usr/libexec/apptainer/bin real=${1%/}/usr/libexec/apptainer/libexec
[ -d "$bin" ] && [ ! -L "$bin" ] || { echo "refusing: $bin is not a directory" >&2; exit 2; }
[ -f "$bin/.wrapper" ] && [ ! -L "$bin/.wrapper" ] && [ -x "$bin/.wrapper" ] \
  || { echo "refusing: $bin/.wrapper is missing (the role writes it first)" >&2; exit 2; }
shopt -s nullglob

# --- everything is checked first; nothing changes on an unexpected state
names=()
for f in "$bin"/*; do
  n=${f##*/}
  if [ -L "$f" ]; then
    [ "$(readlink -- "$f")" = .wrapper ] || { echo "refusing: $f links to $(readlink -- "$f"), not .wrapper" >&2; exit 3; }
    [ -f "$real/$n" ] && [ ! -L "$real/$n" ] || { echo "refusing: $f is a wrapper link but $real/$n is missing" >&2; exit 3; }
  elif [ -f "$f" ]; then
    [ ! -e "$real/$n" ] && [ ! -L "$real/$n" ] || { echo "refusing: $n is in both $bin and $real" >&2; exit 3; }
    names+=("$n")
  else
    echo "refusing: $f is neither a program nor a wrapper link" >&2; exit 3
  fi
done
[ -d "$real" ] || [ ${#names[@]} -gt 0 ] || { echo "refusing: no programs in $bin" >&2; exit 3; }
if [ -d "$real" ]; then
  for f in "$real"/*; do
    n=${f##*/}
    [ -f "$f" ] && [ ! -L "$f" ] || { echo "refusing: $f is not a regular file" >&2; exit 3; }
    [ -e "$bin/$n" ] || [ -L "$bin/$n" ] || names+=("$n")      # moved by an interrupted run, not yet linked
  done
fi

# --- move and link (a rerun after an interruption finishes the rest)
changed=0
mkdir -p -- "$real"
for n in "${names[@]}"; do
  if [ -f "$bin/$n" ] && [ ! -L "$bin/$n" ]; then mv -T -- "$bin/$n" "$real/$n"; fi
  ln -s .wrapper "$bin/$n"
  changed=1
done
[ $changed = 1 ] && echo changed || echo unchanged

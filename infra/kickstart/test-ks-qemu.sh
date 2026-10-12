#!/bin/bash
# Superseded 27 Sep 2026 by test-ks-qemu-fleet.sh, which covers all five fleet profiles.
# Kept so documented commands for the login node (hpe) still work; the git history holds the old version.
if [ "$#" -gt 0 ] && [ "$1" = --profile ]; then exec bash "$(dirname -- "$0")/test-ks-qemu-fleet.sh" "$@"; fi
exec bash "$(dirname -- "$0")/test-ks-qemu-fleet.sh" --profile hpe "$@"

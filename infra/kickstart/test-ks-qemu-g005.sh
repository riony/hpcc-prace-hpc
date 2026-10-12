#!/bin/bash
# Superseded 27 Sep 2026 by test-ks-qemu-fleet.sh, which covers all five fleet profiles.
# Kept so documented commands for g003/g004/g005 (default g005) still work; the git history holds the old version.
if [ "$#" -gt 0 ] && [ "$1" = --profile ]; then exec bash "$(dirname -- "$0")/test-ks-qemu-fleet.sh" "$@"; fi
exec bash "$(dirname -- "$0")/test-ks-qemu-fleet.sh" --profile hpe-v100-g005 "$@"

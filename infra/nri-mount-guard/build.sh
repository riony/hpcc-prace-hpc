#!/bin/bash
# Reproducible build of prace-nri-mount-guard (T87, 3 Oct): vet, tests, then a static build with fixed
# flags and no VCS stamp, so the hash depends on the source, toolchain and modules, not on the
# checkout (CI caught a stamped build on 3 Oct). With --check the result must equal the role's copy
# (roles/slinky/files) and its pinned hash
# (slinky_nri_guard_sha256); without, it replaces the role's copy and prints the hash to pin.
# usage: build.sh [--check]    GO=/path/to/go uses that toolchain (it must be go1.27.1); otherwise
# the pinned release is fetched from go.dev and verified against its published SHA-256.
set -euo pipefail
cd "$(dirname "$0")"
GO_VERSION=1.27.1
GO_SHA256=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445   # go.dev/dl, linux-amd64 archive
ROLE=../roles/slinky
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
if [ -z "${GO:-}" ]; then
  curl -fsSL --proto '=https' -o "$tmp/go.tgz" "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
  echo "$GO_SHA256  $tmp/go.tgz" | sha256sum -c --quiet -
  tar -xzf "$tmp/go.tgz" -C "$tmp"
  GO=$tmp/go/bin/go
fi
export CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
have=$("$GO" env GOVERSION)
[ "$have" = "go$GO_VERSION" ] || { echo "need go$GO_VERSION, have $have"; exit 1; }
"$GO" vet ./...
"$GO" test ./...
"$GO" build -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o "$tmp/prace-nri-mount-guard" .
sum=$(sha256sum "$tmp/prace-nri-mount-guard" | cut -d' ' -f1)
echo "built prace-nri-mount-guard: sha256 $sum"
if [ "${1:-}" = --check ]; then
  role=$(sha256sum "$ROLE/files/prace-nri-mount-guard" | cut -d' ' -f1)
  pinned=$(sed -n 's/^slinky_nri_guard_sha256: *//p' "$ROLE/defaults/main.yml")
  if [ "$sum" != "$role" ] || [ "$sum" != "$pinned" ]; then
    echo "MISMATCH: built $sum, role copy $role, pinned $pinned"; exit 1
  fi
  echo "the role's copy and the pinned hash are this build"
else
  install -m 0755 "$tmp/prace-nri-mount-guard" "$ROLE/files/prace-nri-mount-guard"
  echo "role copy replaced; pin it: slinky_nri_guard_sha256: $sum"
fi

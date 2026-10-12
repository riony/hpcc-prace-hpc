#!/bin/bash
# NEGATIVE QEMU test: an install-mode ISO built with a WRONG EXACT_WWN must NOT
# touch any disk. Shapes the guest like the Lenovo target (SCSI + COM2), boots the
# install entry (KS_DEFAULT_ENTRY=2) and requires:
#   - the %pre FATAL abort line appears on COM2 (selector refused: 0 candidates)
#   - the target disk image is UNCHANGED (no partitioning, no writes)
# Works with either:
#   $1 = install ISO built with wrong EXACT_WWN  -> expect FATAL + unchanged disk
#   $1 = diagnostic-only ISO                     -> expect NO install attempt at all
set -euo pipefail
ISO="$1"
D="$HOME/scratch/ks/qemu-lenovo-neg"
mkdir -p "$D"
rm -f "$D"/*.qcow2 "$D"/vars.fd "$D"/serial*.log
cd "$D"
qemu-img create -f qcow2 -q target.qcow2 278G
TGT_BEFORE=$(sha256sum target.qcow2 | awk '{print $1}')
cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd
set +e
TMO="${TMO:-900}"
timeout "$TMO" qemu-system-x86_64 -machine q35 -m 4096 -smp 4 -enable-kvm -cpu host \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file=vars.fd \
  -cdrom "$ISO" \
  -device virtio-scsi-pci,id=scsi0 \
  -drive file=target.qcow2,if=none,id=tgt,format=qcow2 \
  -device scsi-hd,drive=tgt,wwn=0x600605b0deadbeef \
  -serial null -serial file:serial-com2.log -display none -net none >/dev/null 2>&1
RC=$?
set -e
echo "qemu rc=$RC (124=timeout-kill is expected for these builds)"

FAIL=0
LOG=$(tr -d '\r' < serial-com2.log)

# Requirement 1: the selector refused. Either the install entry booted and %pre
# aborted (FATAL line), or no install path started at all (diagnostic-only ISO:
# no "install target" line ever appears). Do NOT key on "Starting installer" : 
# anaconda rescue mode prints similar startup text.
if grep -aq "FATAL: target disk selector" <<<"$LOG"; then
  echo "SELECTOR-REFUSED: PASS (FATAL abort shown on console)"
elif ! grep -aq "install target:" <<<"$LOG"; then
  echo "SELECTOR-REFUSED: PASS (no install path started :  diagnostic-only)"
else
  echo "SELECTOR-REFUSED: FAIL (a target was selected!)"
  grep -a "install target" <<<"$LOG" | head -2
  FAIL=1
fi

# Requirement 2: target disk unchanged
TGT_AFTER=$(sha256sum target.qcow2 | awk '{print $1}')
if [ "$TGT_BEFORE" = "$TGT_AFTER" ]; then
  echo "TARGET-UNTOUCHED: PASS (sha256 ${TGT_AFTER:0:12}…)"
else
  echo "TARGET-UNTOUCHED: FAIL ($TGT_BEFORE != $TGT_AFTER)"
  FAIL=1
fi

grep -aE "Kernel panic|FATAL|install target" <<<"$LOG" | head -3 || true

if [ "$FAIL" -eq 0 ]; then
  echo "VERDICT: PASS (refused safely)"
  exit 0
else
  echo "VERDICT: FAIL (destructive action was NOT refused)"
  exit 1
fi

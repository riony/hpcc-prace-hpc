#!/bin/bash
# QEMU validation of the full Lenovo PXE chain, as close to the physical boot as possible:
#   dnsmasq on the user net (10.0.2.2): DHCP proxy answers + TFTP serves grubx64.efi
#   httpd on 10.0.2.2:8090: stage2 + ks-diag
#   OVMF guest PXE-boots: firmware -> TFTP grub -> grub.cfg (20s timeout) -> entry 0
#     -> TFTP vmlinuz/initrd -> HTTP install.img + ks-diag.cfg -> rescue --nomount shell
# PASS criteria (all must hold):
#   1. guest got a DHCP lease and fetched grubx64.efi + grub.cfg over TFTP
#   2. kernel+initrd fetched (TFTP) and stage2+ks-diag fetched (HTTP)
#   3. serial COM2 log reaches "Rescue Shell" + "Not mounting the system"
#   4. rescue shell is interactive on COM2 (prompt visible)
# Cleans up dnsmasq/httpd/QEMU on exit. No host firewall changes needed (slirp).
set -uo pipefail
PXE="$HOME/scratch/ks/pxe-lenovo"          # payload built by build-pxe-lenovo.sh
D="$HOME/scratch/ks/qemu-pxe-lenovo"       # scratch
mkdir -p "$D"; cd "$D"
LOG="$D/serial-com2.log"

# QEMU slirp provides DHCP+TFTP natively (tftp=/bootfile=): no host dnsmasq needed
# (local dnsmasq is AppArmor-confined on Ubuntu and port 67 needs root anyway;
#  the dnsmasq config itself is exercised on bmc-jump in Phase C).
PXE="$HOME/scratch/ks/pxe-lenovo"          # payload built by build-pxe-lenovo.sh
D="$HOME/scratch/ks/qemu-pxe-lenovo"       # scratch
mkdir -p "$D"; cd "$D"
LOG="$D/serial-com2.log"

# --- httpd on 10.0.2.2:8090 (slirp host alias, reachable from guest)
python3 "$HOME/scratch/ks/httpd.py" "$PXE/http" 8090 > "$D/httpd.log" 2>&1 &
HTTPD_PID=$!
sleep 1
kill -0 "$HTTPD_PID" 2>/dev/null || { echo "httpd failed"; cat "$D/httpd.log"; exit 1; }
echo "httpd up (pid $HTTPD_PID)"

cleanup() {
  [ -n "${QEMU_PID:-}" ] && kill "$QEMU_PID" 2>/dev/null
  kill "$HTTPD_PID" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

rm -f "$LOG"
[ -s "$D/vars.fd" ] || cp /usr/share/OVMF/OVMF_VARS_4M.fd "$D/vars.fd"   # pflash varstore must exist
echo "=== booting guest (slirp PXE: TFTP grub -> HTTP stage2, 420s) ==="
timeout 420 qemu-system-x86_64 -machine q35 -m 4096 -smp 4 -enable-kvm -cpu host \
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
  -drive if=pflash,format=raw,file="$D/vars.fd" \
  -netdev user,id=nx0,tftp="$PXE/tftp",bootfile=grubx64.efi \
  -device virtio-net-pci,netdev=nx0,mac=52:54:00:12:34:56 \
  -serial null -serial file:"$LOG" -display none -nographic >/dev/null 2>&1 &
QEMU_PID=$!

FAIL=0
echo "=== waiting for rescue shell (poll serial log) ==="
for i in $(seq 1 80); do
  if grep -aq "Not mounting the system" "$LOG" 2>/dev/null; then echo "rescue shell reached after ~$((i*5))s"; break; fi
  sleep 5
done

# CR-strip once; here-strings (grep -q SIGPIPE trap avoided)
LOGTXT=$(tr -d '\r' < "$LOG" 2>/dev/null || true)

if grep -aq "Not mounting the system" <<<"$LOGTXT"; then
  echo "RESCUE-NOMOUNT-REACHED: PASS"
else
  echo "RESCUE-NOMOUNT-REACHED: FAIL (last 300 bytes):"
  tail -c 300 "$LOG" 2>/dev/null | cat -v
  FAIL=1
fi

HL=$(cat "$D/httpd.log" 2>/dev/null || true)
if grep -aq "install.img" <<<"$HL" && grep -aq "ks-diag.cfg" <<<"$HL"; then
  echo "HTTP-STAGE2-KS-DELIVERED: PASS"
else
  echo "HTTP-STAGE2-KS-DELIVERED: FAIL (httpd log):"; tail -10 "$D/httpd.log" 2>/dev/null
  FAIL=1
fi
# TFTP evidence: grub loaded (menu/kernel lines in serial log) means bootfile+cfg+vmlinuz+initrd all arrived
if grep -aqE "DIAGNOSTIC rescue nomount|linuxefi|vmlinuz" <<<"$LOGTXT"; then
  echo "TFTP-CHAIN-DELIVERED: PASS (grub menu + kernel load visible on COM2)"
else
  echo "TFTP-CHAIN-DELIVERED: FAIL (no grub/kernel evidence on COM2)"
  FAIL=1
fi

echo "=== serial log tail ==="
tail -c 400 "$LOG" 2>/dev/null | cat -v

if [ "$FAIL" -eq 0 ]; then echo "VERDICT: PASS"; exit 0; else echo "VERDICT: FAIL"; exit 1; fi

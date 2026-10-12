#!/bin/bash
# Build the temporary Lenovo PXE payload (DIAGNOSTIC-ONLY) from the verified
# Rocky 9.8 minimal ISO tree. Two serving roots:
#   <out>/tftp/  - shim(BOOTX64.EFI) or grubx64.efi + PXE grub.cfg (few MB)
#   <out>/http/  - vmlinuz, initrd.img, install.img (stage2), ks-diag.cfg (~1.46 GB)
# Usage: build-pxe-lenovo.sh <out-dir> <server-base-url>
#   e.g. build-pxe-lenovo.sh ~/scratch/ks/pxe-lenovo http://10.0.2.2:8090   (QEMU test)
#        build-pxe-lenovo.sh ... http://192.0.2.250:8090                  (prod)
# No credential-bearing ks.cfg is staged: diagnostic payload only (plan step 5).
set -euo pipefail
OUT="${1:?usage: build-pxe-lenovo.sh <out-dir> <server-base-url>}"
SRV="${2:?usage: build-pxe-lenovo.sh <out-dir> <server-base-url>}"
ISO_TREE="$HOME/scratch/ks/isotree-lenovo"
[ -d "$ISO_TREE/images/pxeboot" ] || { echo "missing ISO tree $ISO_TREE (run build-ks.sh lenovo first)" >&2; exit 2; }

rm -rf "$OUT"
mkdir -p "$OUT/tftp" "$OUT/http/lenovo/images/pxeboot"

# --- TFTP tree: UEFI boot chain + grub config (grub prefix = bootfile dir = tftp root)
cp "$ISO_TREE/EFI/BOOT/grubx64.efi" "$OUT/tftp/grubx64.efi"
cp "$ISO_TREE/EFI/BOOT/BOOTX64.EFI" "$OUT/tftp/BOOTX64.EFI"   # shim (SB chain; optional)
# PXE grub.cfg: relative kernel/initrd paths resolve on the TFTP root grub was
# netbooted from; stage2 + kickstart come from HTTP (server arg). COM2/ttyS1,
# rescue --nomount, NO install entry. ip=dhcp initializes networking explicitly.
cat > "$OUT/tftp/grub.cfg" <<GRUB
set default="0"
set timeout=20

serial --unit=1 --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial console
terminal_output serial console

menuentry '0 DIAGNOSTIC rescue nomount (PXE, NO install, NO disk mount)' --class fedora --class gnu-linux --class os {
	linuxefi images/pxeboot/vmlinuz ip=dhcp inst.stage2=$SRV/lenovo inst.ks=$SRV/lenovo/ks-diag.cfg inst.rescue inst.text console=tty0 console=ttyS1,115200n8
	initrdefi images/pxeboot/initrd.img
}
menuentry '1 local disk (boot existing OS)' --class fedora --class gnu-linux --class os {
	exit 1
}
GRUB

# --- HTTP tree: kernel/initrd (also TFTP-served for grub), stage2, diag kickstart
cp "$ISO_TREE/images/pxeboot/vmlinuz"     "$OUT/tftp/images_pxeboot_vmlinuz_PLACEHOLDER" && rm -f "$OUT/tftp/images_pxeboot_vmlinuz_PLACEHOLDER"
mkdir -p "$OUT/tftp/images/pxeboot"
cp "$ISO_TREE/images/pxeboot/vmlinuz"     "$OUT/tftp/images/pxeboot/vmlinuz"
cp "$ISO_TREE/images/pxeboot/vmlinuz"     "$OUT/http/lenovo/images/pxeboot/vmlinuz"
cp "$ISO_TREE/images/pxeboot/initrd.img"  "$OUT/tftp/images/pxeboot/initrd.img"
cp "$ISO_TREE/images/pxeboot/initrd.img"  "$OUT/http/lenovo/images/pxeboot/initrd.img"
cp "$ISO_TREE/images/install.img"         "$OUT/http/lenovo/images/install.img"
# Non-installing diagnostic kickstart (identical to the USB media one)
cat > "$OUT/http/lenovo/ks-diag.cfg" <<'DIAG'
# DIAGNOSTIC-ONLY rescue environment (no installation, no mounting)
rescue --nomount
text
reboot
lang en_US.UTF-8
keyboard us
DIAG

echo "=== payload sizes ==="
du -sh "$OUT/tftp" "$OUT/http"
echo "=== checksums (record) ==="
sha256sum "$OUT/tftp/grubx64.efi" "$OUT/tftp/grub.cfg" \
          "$OUT/http/lenovo/images/pxeboot/vmlinuz" \
          "$OUT/http/lenovo/images/pxeboot/initrd.img" \
          "$OUT/http/lenovo/images/install.img" \
          "$OUT/http/lenovo/ks-diag.cfg"
echo "BUILD-OK $OUT (server $SRV)"

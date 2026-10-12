#!/bin/bash
# Kickstart ISO builder :  parameterized per host, no plaintext secrets at rest.
# Usage: bash build-ks.sh hpe
#   Bootstrap password: read from (or generated into) ~/.config/prace-lab/<host>-bootstrap.pw (mode 0600).
#   Authorized key: controller's id_ed25519.pub is installed for root and admin.
# Output: ~/Downloads/prace-iso/Rocky-9.8-ks-<host>.iso (local artifact only).
# The output ISO contains password HASHES; treat it as a restricted artifact.
set -euo pipefail

# Local EFI patching is required; fail before any build or secret operations.
command -v mcopy >/dev/null 2>&1 || {
  echo "missing local mcopy (mtools); install it on the build workstation before running this script" >&2
  exit 2
}

HOST="${1:-hpe}"
BASE_ISO="$HOME/Downloads/prace-iso/Rocky-9.8-x86_64-minimal.iso"
BASE_ISO_SHA="d338032cd1cdd41c67139f2f71b4c832c8e4a21943106519db9c7137df7a63d4"
OUT_DIR="$HOME/Downloads/prace-iso"
OUT="${KS_OUT:-$OUT_DIR/Rocky-9.8-ks-$HOST.iso}"   # KS_OUT lets validation builds target scratch
PUBKEY_FILE="$HOME/.ssh/id_ed25519.pub"
# Disk-backed scratch (NOT /tmp :  it is a RAM tmpfs; 13 GB of build artifacts there
# caused a real OOM on 2026-09-18 that killed the agent runtime).
TREE="$HOME/scratch/ks/isotree-$HOST"

# Profile values are fixed below; environment input cannot override chassis binding.
# Fleet rebuild (docs/reference/FLEET-REBUILD-2026-09-28.md): every profile is bound to its chassis serial
# and to its own exact OS disk (from the 26 Sep read-only BMC/OS discovery). An explicit
# empty EXACT_WWN= still forces a DIAGNOSTIC-ONLY build. No VM-image LV any more: the free
# VG space is left for Ansible (BeeGFS metadata, NFS home). No unguarded interactive
# install entry. Compute nodes get their private address from prace-first-address.service;
# the login node's two addresses are fixed here by MAC.
EXPECTED_CHASSIS=""
ALLOW_INTERACTIVE_INSTALL=0
LV_LIBVIRT_MB=0
FLEET_ROLE=compute
KS_NETWORK=""
LOGIN_PRIV_MAC=""
LOGIN_PRIV_IP=""
# OS-disk identities of every fleet node: a profile may only ever use its own.
FLEET_DISK_IDS="EXNVME00000001 600605b0000000000000000000000002 60050000b0c10242afbfcad3f5cafb3d 60050000f7fca2d55eb51600d6e1fa5c 60050000a346210d311ce34853176ea6"
case "$HOST" in
  hpe)
    # Login node: DL380 Gen10 EXSERIAL01. OS on its single 1.6 TB NVMe (no RAID, no small
    # drive): exact serial only, never a prefix.
    KS_HOSTNAME="lab-dl380"
    EXPECTED_CHASSIS="EXSERIAL01"
    SELECTOR="nvme_exact"
    TARGET_SERIAL="EXNVME00000001"
    EXACT_WWN="${EXACT_WWN-EXNVME00000001}"
    OWN_DISK_ID="EXNVME00000001"
    VG="hpe_vg"
    SERIAL_UNIT=0                    # iLO VSP maps to ttyS0 (verified on the HPE install)
    SERIAL_TTY=ttyS0
    KS_END_ACTION=poweroff           # virtual media stays attached until ejected
    FLEET_ROLE=login
    # Campus by MAC here; the private port is written in %post as private-<nic>, in exactly
    # roles/private_net's format, so Ansible adopts it without a second profile.
    KS_NETWORK="network --device=02:00:00:00:00:02 --bootproto=static --ip=192.0.2.205 --netmask=255.255.255.0 --gateway=192.0.2.254 --nameserver=192.0.2.53,192.0.2.53,192.0.2.53 --noipv6 --onboot=yes --activate"
    LOGIN_PRIV_MAC="02:00:00:00:00:01"
    LOGIN_PRIV_IP="10.90.10.1"
    ;;
  lenovo)
    # CPU node: x3650 M5 EXSER02. M5210 MegaRAID logical vol[9-0], RAID1, 278.465 GB; the OS
    # sees it as scsi-3<WWN>/wwn-0x<WWN> (observed in the installer 2026-09-23).
    KS_HOSTNAME="lab-lenovo"
    EXPECTED_CHASSIS="EXSER02"
    SELECTOR="megaraid_wwn_prefix"
    TARGET_SERIAL="600605b0"
    EXACT_WWN="${EXACT_WWN-600605b0000000000000000000000002}"
    OWN_DISK_ID="600605b0000000000000000000000002"
    VG="lenovo_vg"
    SERIAL_UNIT=1                    # IMM2 SSH redirect = COM2 -> ttyS1 (Lenovo: SSH/telnet
    SERIAL_TTY=ttyS1                 #   redirection is COM2; IPMI SOL is COM1. dw1lm/NN1ia docs)
    KS_END_ACTION=poweroff           # USB remains inserted during install; reboot would loop back into the installer
    ;;
  hpe-v100-g003|hpe-v100-g004|hpe-v100-g005)
    # XL270d Gen10 GPU nodes. OS on the P408i-a RAID1 logical volume (2x 480 GB SSD); the two
    # 1.6 TB NVMe are BeeGFS data and must never be selected (they differ only in their last
    # characters, so only an exact whole-device WWN is accepted).
    SELECTOR="exact_wwn"
    SERIAL_UNIT=0                    # iLO VSP -> ttyS0 (confirmed on the 21 Sep diagnostic boot)
    SERIAL_TTY=ttyS0
    LV_ROOT_MB=81920
    KS_END_ACTION=poweroff
    case "$HOST" in
      hpe-v100-g003) KS_HOSTNAME="lab-g003"; VG="g003_vg"; EXPECTED_CHASSIS="EXSERIAL03"
                     OWN_DISK_ID="60050000b0c10242afbfcad3f5cafb3d" ;;
      hpe-v100-g004) KS_HOSTNAME="lab-g004"; VG="g004_vg"; EXPECTED_CHASSIS="EXSERIAL04"
                     OWN_DISK_ID="60050000f7fca2d55eb51600d6e1fa5c" ;;
      hpe-v100-g005) KS_HOSTNAME="lab-g005"; VG="g005_vg"; EXPECTED_CHASSIS="EXSERIAL05"
                     OWN_DISK_ID="60050000a346210d311ce34853176ea6" ;;
    esac
    TARGET_SERIAL="$OWN_DISK_ID"     # abort-message hint only
    EXACT_WWN="${EXACT_WWN-$OWN_DISK_ID}"
    ;;
  *) echo "unknown host '$HOST' (use: hpe|lenovo|hpe-v100-g003|hpe-v100-g004|hpe-v100-g005)" >&2; exit 2 ;;
esac
# Another fleet node's disk identity is never acceptable for this profile.
for other in $FLEET_DISK_IDS; do
  if [ "$other" != "$OWN_DISK_ID" ] && [ "${EXACT_WWN:-}" = "$other" ]; then
    echo "EXACT_WWN belongs to another fleet node, not $HOST" >&2
    exit 2
  fi
done
case "${EXACT_WWN:-}" in
  0000000000000000|00000000000000000000000000000000|ffffffffffffffff|ffffffffffffffffffffffffffffffff)
    echo "EXACT_WWN is a placeholder, not a discovered identity" >&2
    exit 2 ;;
esac

# --- build mode gate: ANY exact-identity selector REQUIRES the exact disk identity ---
# EXACT_WWN (env) holds the exact target identity captured in the UEFI diagnostic boot:
#   megaraid_wwn_prefix -> the bare logical-volume WWN
#   nvme_exact          -> the full NVMe serial (or EUI64)
#   exact_wwn           -> the bare whole-device WWN (transport-agnostic: RAID/SCSI/NVMe)
#   empty/unset -> DIAGNOSTIC-ONLY ISO: install entries omitted; the install kickstart
#                  remains on media but its %pre refuses to touch any disk.
#   set         -> INSTALL ISO: %pre requires an exact by-id match, exactly one device.
# Only the prefix-based `serial` selector (the hpe/DL380 profile) is exempt, because it
# predates this gate. Every other selector fails closed.
MODE="install"
KS_DEFAULT_ENTRY="${KS_DEFAULT_ENTRY:-0}"
case "$KS_DEFAULT_ENTRY" in 0|1|2|3) ;; *) echo "KS_DEFAULT_ENTRY must be 0-3" >&2; exit 2 ;; esac
if [ "$ALLOW_INTERACTIVE_INSTALL" = 0 ] && [ "$KS_DEFAULT_ENTRY" = 3 ]; then
  echo "$HOST has no unguarded interactive install entry; KS_DEFAULT_ENTRY must be 0, 1 or 2" >&2
  exit 2
fi
if [ "$SELECTOR" != serial ]; then
  if [ -z "${EXACT_WWN:-}" ]; then
    MODE="diagnostic"
    case "$KS_DEFAULT_ENTRY" in 0|1) ;; *)
      echo "diagnostic-only build: KS_DEFAULT_ENTRY must be 0 or 1 (install entries are omitted)" >&2; exit 2 ;;
    esac
    echo "NOTE: EXACT_WWN not supplied -> DIAGNOSTIC-ONLY ISO (install entries omitted)." >&2
    echo "      Boot UEFI entry 0 (rescue --nomount), capture the target disk identity, then" >&2
    echo "      rebuild with EXACT_WWN=<exact identity> and KS_DEFAULT_ENTRY=2." >&2
  else
    case "$EXACT_WWN" in
      scsi-*|nvme-*|wwn-*)
        echo "EXACT_WWN must be the BARE identity (WWN, or NVMe serial/EUI64), not a by-id name" >&2; exit 2 ;;
    esac
    case "$SELECTOR" in
      megaraid_wwn_prefix)
        if ! printf '%s' "$EXACT_WWN" | grep -qE '^[0-9a-f]{16}$|^[0-9a-f]{32}$'; then
          echo "EXACT_WWN malformed: expected bare 16- or 32-hex-digit WWN (lowercase)" >&2
          exit 2
        fi
        ;;
      exact_wwn)
        if ! printf '%s' "$EXACT_WWN" | grep -qE '^[0-9a-f]{16}$|^[0-9a-f]{32}$'; then
          echo "EXACT_WWN malformed: expected bare 16- or 32-hex-digit WWN (lowercase)" >&2
          exit 2
        fi
        ;;
      nvme_exact)
        if ! printf '%s' "$EXACT_WWN" | grep -qE '^[A-Za-z0-9]{8,32}$'; then
          echo "EXACT_WWN malformed: expected an 8-32 char alphanumeric NVMe serial or EUI64" >&2
          exit 2
        fi
        ;;
      *) echo "no EXACT_WWN validator for selector '$SELECTOR'" >&2; exit 2 ;;
    esac
  fi
fi

# The first-address helper must be embedded before the new node has any host IP.
# Resolve from this source tree, not the caller's working directory or environment.
BOOTSTRAP_HELPER=""
if [ "$FLEET_ROLE" = compute ]; then
  BOOTSTRAP_HELPER="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../tools" && pwd -P)/fleet-first-address.py"
  [ -s "$BOOTSTRAP_HELPER" ] || { echo "missing first-address helper: $BOOTSTRAP_HELPER" >&2; exit 2; }
fi
export BOOTSTRAP_HELPER

[ -s "$BASE_ISO" ] || { echo "missing $BASE_ISO" >&2; exit 2; }
echo "$BASE_ISO_SHA  $BASE_ISO" | sha256sum -c - >/dev/null || { echo "base ISO checksum mismatch" >&2; exit 2; }
[ -s "$PUBKEY_FILE" ] || { echo "missing $PUBKEY_FILE" >&2; exit 2; }

# --- build locks: protect both the profile tree/credential and the chosen output ---
# Different profiles may build concurrently. A profile's tree is never shared by two
# builders, and overriding KS_OUT cannot make two profiles overwrite the same ISO.
command -v flock >/dev/null 2>&1 || { echo "missing flock (util-linux)" >&2; exit 2; }
umask 077
LOCK_DIR="$HOME/scratch/ks/.locks"
mkdir -p "$LOCK_DIR"
OUT="$(realpath -m -- "$OUT")"
exec {profile_lock_fd}>"$LOCK_DIR/profile-$HOST.lock"
flock -n "$profile_lock_fd" || { echo "another $HOST build is active" >&2; exit 2; }
output_lock_id="$(printf '%s' "$OUT" | sha256sum | cut -d ' ' -f 1)"
exec {output_lock_fd}>"$LOCK_DIR/output-$output_lock_id.lock"
flock -n "$output_lock_fd" || { echo "another build targets $OUT" >&2; exit 2; }

# --- secret handling: file-based, 0600, generated if absent; never printed ---
PWFILE="$HOME/.config/prace-lab/${HOST}-bootstrap.pw"
umask 077
mkdir -p "$(dirname "$PWFILE")"
if [ ! -s "$PWFILE" ]; then
  openssl rand -base64 24 | tr -d '\n' > "$PWFILE"
  echo "NOTE: generated new bootstrap password -> $PWFILE (mode 0600; value NOT printed)" >&2
fi

# Profiles that do not override LV_ROOT_MB keep the original 80 GiB root.
LV_ROOT_MB="${LV_ROOT_MB:-81920}"
export KS_HOSTNAME TARGET_SERIAL SELECTOR VG LV_ROOT_MB LV_LIBVIRT_MB SERIAL_UNIT SERIAL_TTY EXACT_WWN EXPECTED_CHASSIS FLEET_ROLE KS_NETWORK LOGIN_PRIV_MAC LOGIN_PRIV_IP
export KS_CFG="$TREE/ks.cfg"   # profile-local; never /tmp/ks-built.cfg shared by builders
export KS_END_ACTION="${KS_END_ACTION:-reboot}"   # lenovo uses poweroff: USB stick stays inserted during install, reboot would loop straight back into GRUB
export KS_PW="$(cat "$PWFILE")"
export KS_PUBKEY="$(cat "$PUBKEY_FILE")"

# --- fresh, reproducible tree from the verified base ISO ---
rm -rf "$TREE"; mkdir -p "$TREE"
xorriso -osirrox on -indev "$BASE_ISO" -extract / "$TREE" 2>&1 | tail -1
chmod -R u+w "$TREE" 2>/dev/null || true

# --- kickstart: %pre resolves the target disk BY SERIAL; storage scoped to it only ---
python3 - <<'PY'
import base64, crypt, hashlib, os
from pathlib import Path
h = crypt.crypt(os.environ['KS_PW'], crypt.mksalt(crypt.METHOD_SHA512))
# Only the new, chassis-bound profiles carry the offline console bootstrap.
# Base64 is an inert literal in a quoted heredoc: helper quotes/braces/$ cannot
# alter the Kickstart or shell. Verify exact bytes before setting permissions.
# Fleet profiles: missing required RPMs must abort the install (no --ignoremissing).
package_options = ""
package_additions = "\npython3\niproute\niputils\nNetworkManager\nfirewalld\npolicycoreutils\nprocps-ng"
# No automatic DHCP profiles on any port: addresses come only from this kickstart (login),
# prace-first-address.service (compute) or roles/private_net.
bootstrap_post = """
install -d -m 0755 /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/10-prace-no-auto-default.conf <<'PRACE_NM'
# Managed by kickstart (FLEET-REBUILD): no automatic DHCP profiles on any port.
[main]
no-auto-default=*
PRACE_NM
restorecon -R /etc/NetworkManager/conf.d || exit 1
"""
if os.environ['FLEET_ROLE'] == 'login':
    bootstrap_post += f"""
# Login node private port, found by MAC, written exactly as roles/private_net writes it.
# If that NIC is absent the install still completes (the disk is already written) and
# the address is left to Ansible, with a warning on the console.
priv=""
for n in /sys/class/net/*; do
  [ "$(cat "$n/address" 2>/dev/null)" = "{os.environ['LOGIN_PRIV_MAC']}" ] && priv="$(basename "$n")"
done
if [ -n "$priv" ]; then
  f="/etc/NetworkManager/system-connections/private-$priv.nmconnection"
  printf '%s\\n' '# Managed by Ansible private_net. Do not edit by hand.' '[connection]' "id=private-$priv" \\
    'type=ethernet' "interface-name=$priv" 'autoconnect=true' 'zone=public' '' '[ipv4]' 'method=manual' \\
    'address1={os.environ['LOGIN_PRIV_IP']}/25' 'never-default=true' '' '[ipv6]' 'method=disabled' '' '[proxy]' > "$f"
  chown root:root "$f" && chmod 0600 "$f" && restorecon "$f" || exit 1
else
  echo "WARNING: private NIC {os.environ['LOGIN_PRIV_MAC']} not found; private address left to Ansible" > /dev/console
fi
"""
if os.environ['FLEET_ROLE'] == 'compute':
    helper = Path(os.environ['BOOTSTRAP_HELPER']).read_bytes()
    payload = base64.b64encode(helper).decode('ascii')
    digest = hashlib.sha256(helper).hexdigest()
    bootstrap_post += f"""
# First private address, unattended at first boot: exactly one candidate port must reach
# the login node's known MAC, else it stops on the console (fleet-first-address.py).
install -d -m 0755 /usr/local/sbin
base64 --decode > /usr/local/sbin/fleet-first-address.py <<'PRACE_BOOTSTRAP_BASE64'
{payload}
PRACE_BOOTSTRAP_BASE64
printf '%s  %s\\n' '{digest}' '/usr/local/sbin/fleet-first-address.py' | sha256sum --check --status - || exit 1
chown root:root /usr/local/sbin/fleet-first-address.py || exit 1
chmod 0700 /usr/local/sbin/fleet-first-address.py || exit 1
cat > /etc/systemd/system/prace-first-address.service <<'PRACE_UNIT'
[Unit]
Description=PRACE fleet: first private address (unattended; exactly one port or stop)
Wants=NetworkManager.service firewalld.service
After=NetworkManager.service firewalld.service
ConditionPathExists=!/var/lib/prace/first-address.done

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/fleet-first-address.py --auto --apply --retry-minutes 45
ExecStartPost=/usr/bin/mkdir -p /var/lib/prace
ExecStartPost=/usr/bin/touch /var/lib/prace/first-address.done
StandardOutput=journal+console
StandardError=journal+console
TimeoutStartSec=50min

[Install]
WantedBy=multi-user.target
PRACE_UNIT
restorecon /usr/local/sbin/fleet-first-address.py /etc/systemd/system/prace-first-address.service || exit 1
systemctl enable prace-first-address.service || exit 1
"""
libvirt_lv = (f"logvol /var/lib/libvirt/images --vgname={os.environ['VG']} --name=libvirt_images --fstype=xfs "
              f"--size={os.environ['LV_LIBVIRT_MB']}\n" if int(os.environ['LV_LIBVIRT_MB']) else "")
ks = f'''# {os.environ['KS_HOSTNAME']} automated install (offline, serial console, target-disk-by-id)
text
{os.environ['KS_END_ACTION']}
lang en_US.UTF-8
keyboard us
timezone Asia/Singapore --utc
{os.environ['KS_NETWORK']}
network --hostname={os.environ['KS_HOSTNAME']}
selinux --enforcing
firewall --enabled --service=ssh
firstboot --disable
rootpw --iscrypted {h}
user --name=admin --password={h} --iscrypted --groups=wheel

# Storage target is resolved in %%pre by disk id; %%include splices it here.
# Only the verified target disk is initialized, cleared or partitioned.
%include /tmp/disk-storage.ks

volgroup {os.environ['VG']} pv.01
logvol swap --vgname={os.environ['VG']} --name=swap --size=8192
logvol / --vgname={os.environ['VG']} --name=root --fstype=xfs --size={os.environ['LV_ROOT_MB']}
{libvirt_lv}# Remaining VG capacity deliberately left free (Ansible: BeeGFS metadata, NFS home).

bootloader --location=mbr --timeout=5 --append="console=tty0 console={os.environ['SERIAL_TTY']},115200n8"

%packages{package_options}
@^minimal-environment
openssh-server
chrony
ethtool
tmux
curl{package_additions}
%end

%pre --erroronfail
#!/bin/sh
# Resolve the installation target by hardware identity; abort rather than touch anything else.
# Rules (per LENOVO-INSTALL-REVIEW): resolve to EXACTLY ONE candidate or abort; if the
# full logical-volume WWN is known (EXACT_WWN), an exact match is REQUIRED, not a prefix.
SELECTOR="{os.environ['SELECTOR']}"
SERIAL="{os.environ['TARGET_SERIAL']}"
EXACT="{os.environ['EXACT_WWN']}"
TTY="{os.environ['SERIAL_TTY']}"
EXPECTED_CHASSIS="{os.environ['EXPECTED_CHASSIS']}"
# New-node media must match the actual chassis before resolving a storage target.
# Missing/unreadable/incorrect DMI identity fails closed, including in a VM test.
if [ -n "$EXPECTED_CHASSIS" ]; then
  actual_chassis=$(cat /sys/class/dmi/id/product_serial 2>/dev/null | tr -d '[:space:]')
  if [ "$actual_chassis" != "$EXPECTED_CHASSIS" ]; then
    echo "FATAL: chassis mismatch: expected $EXPECTED_CHASSIS, observed $actual_chassis; no disk change" >/dev/$TTY
    exit 1
  fi
fi
found=""
n=0
seen="|"
case "$SELECTOR" in
  serial)
    # Whole-disk by-id entry whose name contains the disk serial (no -partN suffix).
    # Deduplicate by resolved device: multiple by-id aliases (e.g. nvme-<model>_<serial>
    # plus nvme-eui.<eui>) of ONE disk must count as ONE candidate, never two.
    for d in /dev/disk/by-id/*; do
      b=$(basename "$d")
      case "$b" in *-part[0-9]*) continue ;; esac
      case "$b" in *"$SERIAL"*)
        r=$(readlink -f "$d" 2>/dev/null) || continue
        # Dedup by resolved device, delimiter-guarded list (QEMU and real BMCs
        # expose multiple by-id aliases of ONE disk; they must count as ONE).
        [ -n "$r" ] || continue
        case "$seen" in *"|$r|"*) continue ;; esac
        seen="$seen|$r|"
        found="$d"
        n=$((n+1))
        ;;
      esac
    done
    ;;
  megaraid_wwn_prefix)
    # LSI MegaRAID logical volume. EXACT is the captured logical-volume WWN and is
    # REQUIRED. The volume is exposed under THREE by-id aliases that all resolve to
    # the same block device: scsi-3<WWN>, wwn-0x<WWN> and
    # scsi-SIBM_ServeRAID_M5210_<serial>. The scsi-3 form IS present on the real
    # M5210 :  observed in the installer environment 2026-09-23 (the earlier D20
    # rescue shell listed only SIBM+wwn-0x, which is why it was believed absent).
    # Accept either scsi-3$EXACT or wwn-0x$EXACT; deduplicate by resolved device so
    # the aliases count as ONE candidate.
    for d in /dev/disk/by-id/*; do
      b=$(basename "$d")
      case "$b" in *-part[0-9]*) continue ;; esac
      if [ -z "$EXACT" ]; then
        # No captured exact volume identity: this build is DIAGNOSTIC-ONLY.
        # Refuse to select anything :  no vendor-prefix/capacity fallback, ever.
        continue
      fi
      case "$b" in
        scsi-3"$EXACT"|wwn-0x"$EXACT") ;;
        *) continue ;;
      esac
      r=$(readlink -f "$d" 2>/dev/null) || continue
      # Deduplicate by resolved device, delimiter-guarded list: multiple by-id
      # aliases of ONE disk (M5210 HW: scsi-3 + scsi-SIBM + wwn-0x) must count as
      # ONE candidate.
      [ -n "$r" ] || continue
      case "$seen" in *"|$r|"*) continue ;; esac
      seen="$seen|$r|"
      found="$d"
      n=$((n+1))
    done
    ;;
  nvme_exact)
    # NVMe target. EXACT is the full disk serial (or EUI64) and is REQUIRED - never a
    # prefix: the two g005 disks share S4FZNA0M5017 and differ only in the last two
    # characters, so a substring match would select BOTH. Anchored whole-name match only.
    # Accept nvme-<model>_<serial>, nvme-eui.<eui> or wwn-0x<eui>; dedupe by resolved device.
    for d in /dev/disk/by-id/*; do
      b=$(basename "$d")
      case "$b" in *-part[0-9]*) continue ;; esac
      if [ -z "$EXACT" ]; then
        continue
      fi
      case "$b" in
        nvme-*_"$EXACT"|nvme-eui."$EXACT"|wwn-0x"$EXACT") ;;
        *) continue ;;
      esac
      r=$(readlink -f "$d" 2>/dev/null) || continue
      [ -n "$r" ] || continue
      case "$seen" in *"|$r|"*) continue ;; esac
      seen="$seen|$r|"
      found="$d"
      n=$((n+1))
    done
    ;;
  exact_wwn)
    # Transport-agnostic exact whole-device WWN match (RAID logical volume, SCSI, NVMe).
    # EXACT is the bare WWN and is REQUIRED. Real P408i-a hardware exposes the logical
    # volume as BOTH scsi-3<WWN> AND wwn-0x<WWN>; either is accepted, and because both
    # resolve to the same block device the dedup below counts them as ONE candidate.
    # No prefix/capacity fallback, ever.
    for d in /dev/disk/by-id/*; do
      b=$(basename "$d")
      case "$b" in *-part[0-9]*) continue ;; esac
      if [ -z "$EXACT" ]; then
        continue
      fi
      case "$b" in
        scsi-3"$EXACT"|wwn-0x"$EXACT") ;;
        *) continue ;;
      esac
      r=$(readlink -f "$d" 2>/dev/null) || continue
      [ -n "$r" ] || continue
      case "$seen" in *"|$r|"*) continue ;; esac
      seen="$seen|$r|"
      found="$d"
      n=$((n+1))
    done
    ;;
esac
if [ "$n" -ne 1 ] || [ -z "$found" ]; then
  echo "FATAL: target disk selector=$SELECTOR serial=$SERIAL exact=$EXACT matched $n candidates (need exactly 1); aborting before any disk change" >/dev/$TTY
  echo "by-id listing for reference:" >/dev/$TTY
  ls /dev/disk/by-id/ >/dev/$TTY 2>&1
  exit 1
fi
resolved=$(readlink -f "$found")
short=$(basename "$resolved")
if [ -n "$EXPECTED_CHASSIS" ]; then
  # Each profile adopts its OS volume only (RAID LV, or the login node's NVMe). An exact
  # alias alone must not permit a partition or the wrong kind of device, and the selected
  # disk must fit the fixed layout.
  [ -b "$resolved" ] || {{ echo "FATAL: target is not a block device" >/dev/$TTY; exit 1; }}
  [ "$(lsblk -dnro TYPE "$resolved")" = disk ] || {{ echo "FATAL: target is not a whole disk" >/dev/$TTY; exit 1; }}
  if [ "$SELECTOR" = nvme_exact ]; then
    case "$short" in nvme[0-9]*n[0-9]*) ;; *) echo "FATAL: expected an NVMe namespace, not $short" >/dev/$TTY; exit 1 ;; esac
  else
    case "$short" in sd[a-z]*) ;; *) echo "FATAL: expected a SCSI RAID logical volume, not $short" >/dev/$TTY; exit 1 ;; esac
  fi
  size_bytes=$(lsblk -dnbo SIZE "$resolved")
  case "$size_bytes" in ''|*[!0-9]*) echo "FATAL: target capacity unavailable" >/dev/$TTY; exit 1 ;; esac
  minimum_bytes=$((({os.environ['LV_ROOT_MB']} + {os.environ['LV_LIBVIRT_MB']} + 8192 + 600 + 2048 + 4096) * 1048576))
  [ "$size_bytes" -ge "$minimum_bytes" ] || {{ echo "FATAL: disk too small for the requested layout" >/dev/$TTY; exit 1; }}
fi
echo "install target: $found ($short) [verified unique, n=1]" >/dev/$TTY
cat > /tmp/disk-storage.ks <<EOF2
zerombr
ignoredisk --only-use=$short
clearpart --all --initlabel --drives=$short
part /boot/efi --fstype=efi --size=600 --ondisk=$short
part /boot --fstype=xfs --size=2048 --ondisk=$short
part pv.01 --size=1024 --grow --ondisk=$short
EOF2
%end

%post --erroronfail
# Authorized key for repeatable key-based access (controller control host).
mkdir -p /root/.ssh
echo '{os.environ['KS_PUBKEY']}' > /root/.ssh/authorized_keys
chmod 700 /root/.ssh; chmod 600 /root/.ssh/authorized_keys
mkdir -p /home/admin/.ssh
echo '{os.environ['KS_PUBKEY']}' > /home/admin/.ssh/authorized_keys
chmod 700 /home/admin/.ssh; chmod 600 /home/admin/.ssh/authorized_keys
chown -R admin:admin /home/admin/.ssh
# Serial getty on the management UART so the installed OS answers the BMC console
# (HPE iLO VSP=ttyS0; Lenovo IMM2 SSH redirect=COM2=ttyS1).
systemctl enable serial-getty@{os.environ['SERIAL_TTY']}.service
# SSH host keys now (sshd-keygen skips existing keys), fingerprints to the install console:
# the first SSH connection is checked against them without logging in on the console.
ssh-keygen -A
restorecon -R /etc/ssh /root/.ssh /home/admin/.ssh
for k in /etc/ssh/ssh_host_*_key.pub; do echo "host key: $(ssh-keygen -lf "$k")" >/dev/{os.environ['SERIAL_TTY']}; done
{bootstrap_post}%end
'''
open(os.environ['KS_CFG'], 'w').write(ks)
print('ks built (hashes embedded, no plaintext)')
PY

# --- diagnostic kickstart: rescue --nomount, no %pre/%post, no storage directives ---
# Boots the rescue environment WITHOUT mounting any existing filesystem (unattended
# guarantee :  the interactive rescue prompt is not relied upon). Serial prompt.
cat > "$TREE/ks-diag.cfg" <<'DIAG'
# DIAGNOSTIC-ONLY rescue environment (no installation, no mounting)
rescue --nomount
text
reboot
lang en_US.UTF-8
keyboard us
DIAG

# --- grub: serial console, host-specific UART; default = NON-INSTALLING diagnostic ---
cat > "$TREE/EFI/BOOT/grub.cfg" <<GRUB
set default="$KS_DEFAULT_ENTRY"
set timeout=20

insmod gzio
insmod part_gpt
insmod ext2

serial --unit=$SERIAL_UNIT --speed=115200 --word=8 --parity=no --stop=1
terminal_input serial console
terminal_output serial console

search --no-floppy --set=root -l 'Rocky-9-8-x86_64-dvd'

menuentry '0 DIAGNOSTIC rescue nomount (serial, NO install, NO disk mount)' --class fedora --class gnu-linux --class os {
	linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=Rocky-9-8-x86_64-dvd inst.rescue inst.ks=hd:LABEL=Rocky-9-8-x86_64-dvd:/ks-diag.cfg inst.text console=tty0 console=$SERIAL_TTY,115200n8
	initrdefi /images/pxeboot/initrd.img
}
menuentry '1 RESCUE shell (serial)' --class fedora --class gnu-linux --class os {
	linuxefi /images/pxeboot/vmlinuz rd.break console=tty0 console=$SERIAL_TTY,115200n8
	initrdefi /images/pxeboot/initrd.img
}
GRUB
if [ "$MODE" = install ]; then
cat >> "$TREE/EFI/BOOT/grub.cfg" <<GRUB
menuentry '2 INSTALL kickstart embedded (serial, auto, DESTRUCTIVE)' --class fedora --class gnu-linux --class os {
	linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=Rocky-9-8-x86_64-dvd inst.repo=hd:LABEL=Rocky-9-8-x86_64-dvd:/Minimal inst.ks=hd:LABEL=Rocky-9-8-x86_64-dvd:/ks.cfg inst.text console=tty0 console=$SERIAL_TTY,115200n8
	initrdefi /images/pxeboot/initrd.img
}
GRUB
if [ "$ALLOW_INTERACTIVE_INSTALL" = 1 ]; then
cat >> "$TREE/EFI/BOOT/grub.cfg" <<GRUB
menuentry '3 INSTALL minimal text (serial, interactive, DESTRUCTIVE)' --class fedora --class gnu-linux --class os {
	linuxefi /images/pxeboot/vmlinuz inst.stage2=hd:LABEL=Rocky-9-8-x86_64-dvd inst.repo=hd:LABEL=Rocky-9-8-x86_64-dvd:/Minimal inst.text console=tty0 console=$SERIAL_TTY,115200n8
	initrdefi /images/pxeboot/initrd.img
}
GRUB
fi
else
  echo "MENU: install entries omitted (diagnostic-only build)" >&2
fi

# --- legacy (BIOS/isolinux) menu: mirror the UEFI entries; NEVER leave the upstream
#     installer menu live on diagnostic-only media (review gate 2). ---
cat > "$TREE/isolinux/isolinux.cfg" <<ISO
default vesamenu.c32
timeout 300
display boot.msg
menu clear
menu title Rocky 9.8 PRACE lab ($KS_HOSTNAME, $MODE)
menu tabmsg Serial console $SERIAL_TTY 115200n8 :  UEFI boot preferred

label diag
  menu label ^0 DIAGNOSTIC rescue nomount (NO install, NO disk mount)
  menu default
  kernel vmlinuz
  append initrd=initrd.img inst.stage2=hd:LABEL=Rocky-9-8-x86_64-dvd inst.rescue inst.ks=hd:LABEL=Rocky-9-8-x86_64-dvd:/ks-diag.cfg inst.text console=tty0 console=$SERIAL_TTY,115200n8

label rescue
  menu label ^1 RESCUE rd.break shell
  kernel vmlinuz
  append initrd=initrd.img inst.stage2=hd:LABEL=Rocky-9-8-x86_64-dvd rd.break console=tty0 console=$SERIAL_TTY,115200n8
ISO
if [ "$MODE" = install ]; then
cat >> "$TREE/isolinux/isolinux.cfg" <<ISO

label install
  menu label ^2 INSTALL kickstart embedded (auto, DESTRUCTIVE)
  kernel vmlinuz
  append initrd=initrd.img inst.stage2=hd:LABEL=Rocky-9-8-x86_64-dvd inst.repo=hd:LABEL=Rocky-9-8-x86_64-dvd:/Minimal inst.ks=hd:LABEL=Rocky-9-8-x86_64-dvd:/ks.cfg inst.text console=tty0 console=$SERIAL_TTY,115200n8

ISO
if [ "$ALLOW_INTERACTIVE_INSTALL" = 1 ]; then
cat >> "$TREE/isolinux/isolinux.cfg" <<ISO
label installtext
  menu label ^3 INSTALL minimal text (interactive, DESTRUCTIVE)
  kernel vmlinuz
  append initrd=initrd.img inst.stage2=hd:LABEL=Rocky-9-8-x86_64-dvd inst.repo=hd:LABEL=Rocky-9-8-x86_64-dvd:/Minimal inst.text console=tty0 console=$SERIAL_TTY,115200n8
ISO
fi
fi

# --- patch efiboot.img locally with mtools ---
chmod u+w "$TREE/images/efiboot.img"
mcopy -o -i "$TREE/images/efiboot.img" "$TREE/EFI/BOOT/grub.cfg" ::/EFI/BOOT/grub.cfg
echo MCOPY-OK
chmod u+w "$TREE/images/efiboot.img" "$TREE/EFI/BOOT/grub.cfg" "$TREE/ks.cfg"

# --- build (xorriso; genisoimage rejects --interval:local_fs) ---
rm -f "$OUT"
xorriso -as mkisofs -o "$OUT" \
  -V 'Rocky-9-8-x86_64-dvd' \
  -isohybrid-mbr --interval:local_fs:0s-15s:zero_mbrpt,zero_gpt:"$BASE_ISO" \
  -partition_cyl_align on -partition_offset 0 -partition_hd_cyl 165 -partition_sec_hd 32 --mbr-force-bootable \
  -iso_mbr_part_type 0x00 \
  -c '/isolinux/boot.cat' -b '/isolinux/isolinux.bin' -no-emul-boot -boot-load-size 4 -boot-info-table \
  -eltorito-alt-boot -e '/images/efiboot.img' -no-emul-boot -boot-load-size 14904 -isohybrid-gpt-basdat \
  -joliet-long -D -R -J -T "$TREE" 2>&1 | tail -2
ls -la "$OUT"
sha256sum "$OUT"

echo "BUILD-OK $OUT"

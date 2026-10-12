#!/bin/bash
# QEMU integration test for the five fleet installer profiles (docs/reference/FLEET-REBUILD-2026-09-28.md).
#
# Phase 1 installs from the test ISO into disposable images shaped like the real node
# (chassis serial and DMI product via -smbios, the exact OS-disk identity, two decoy disks).
# Phase 2 boots the installed disk without the ISO and checks it over the serial console:
#   compute profiles (lenovo, hpe-v100-g003/g004/g005): two NICs; PRIV_MAC (a real candidate
#     MAC) is wired to a fake login node on localhost (fake-login-peer.py answers ARP for
#     10.90.10.1 as the login node's MAC), OTHER_MAC has link but no peer. The unattended
#     prace-first-address.service must put the node's admin address on the PRIV_MAC port only.
#   login profile (hpe): its campus and private addresses are fixed by MAC in the kickstart;
#     both must come up on the right NICs, with the only default route on the campus NIC.
# All NIC traffic stays on localhost (QEMU dgram netdevs); nothing reaches a real network.
#
# QEMU's scsi-hd wwn is uint64, so SCSI/RAID targets use a synthetic 16-hex WWN (the real
# volumes are 32 hex and cannot be emulated): build those test ISOs with EXACT_WWN set.
# The login node's NVMe serial CAN be emulated, so its test ISO uses the real identity.
#   EXACT_WWN=600508b1deadbeef KS_DEFAULT_ENTRY=2 KS_OUT=$HOME/scratch/ks/Rocky-9.8-ks-g003-qemu-test.iso bash build-ks.sh hpe-v100-g003
#   EXACT_WWN=600605b0deadbeef KS_DEFAULT_ENTRY=2 KS_OUT=$HOME/scratch/ks/Rocky-9.8-ks-lenovo-qemu-test.iso bash build-ks.sh lenovo
#   KS_DEFAULT_ENTRY=2 KS_OUT=$HOME/scratch/ks/Rocky-9.8-ks-hpe-qemu-test.iso bash build-ks.sh hpe
#   bash test-ks-qemu-fleet.sh --profile hpe-v100-g003
# Never attach a QEMU test ISO to a physical node. --describe prints the fixed test
# identities without opening files or starting QEMU. Every run keeps a NEW directory.
set -euo pipefail

PROFILE=hpe-v100-g005
ISO_ARG=""
DESCRIBE=0
usage() {
  echo "Usage: bash test-ks-qemu-fleet.sh [--profile hpe|lenovo|hpe-v100-g003|hpe-v100-g004|hpe-v100-g005] [--describe] [TEST_ISO]"
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile) [ "$#" -ge 2 ] || { usage >&2; exit 2; }; PROFILE="$2"; shift 2 ;;
    --describe) DESCRIBE=1; shift ;;
    --help|-h) usage; exit 0 ;;
    --*) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *) [ -z "$ISO_ARG" ] || { echo "only one ISO argument is allowed" >&2; exit 2; }; ISO_ARG="$1"; shift ;;
  esac
done

XL_PRODUCT="ProLiant XL270d Gen10"
SERIAL_PRE=""          # extra -serial before the console UART (Lenovo console is COM2)
ROLE=compute
case "$PROFILE" in
  hpe-v100-g003|hpe-v100-g004|hpe-v100-g005)
    NODE=${PROFILE#hpe-v100-}; PRODUCT="$XL_PRODUCT"; HOSTNAME_EXPECT="lab-$NODE"
    TARGET_ID=600508b1deadbeef; TARGET_SIZE=447G
    TARGET_DEV="scsi-hd,drive=tgt,wwn=0x$TARGET_ID"
    TARGET_RE="(scsi-3|wwn-0x)$TARGET_ID"
    DECOY1_DEV="nvme,drive=dc1,serial=EXNVME00000051"; DECOY2_DEV="nvme,drive=dc2,serial=EXNVME00000052"
    DECOY_SIZE=1536G
    case "$NODE" in
      g003) CHASSIS_EXPECT=EXSERIAL03; PRIV_MAC=02:00:00:00:00:09; OTHER_MAC=02:00:00:00:00:08; ADMIN_IP=10.90.10.13 ;;
      g004) CHASSIS_EXPECT=EXSERIAL04; PRIV_MAC=02:00:00:00:00:0f; OTHER_MAC=02:00:00:00:00:0e; ADMIN_IP=10.90.10.14 ;;
      g005) CHASSIS_EXPECT=EXSERIAL05; PRIV_MAC=02:00:00:00:00:14; OTHER_MAC=02:00:00:00:00:1b; ADMIN_IP=10.90.10.15 ;;
    esac ;;
  lenovo)
    NODE=lenovo; PRODUCT="System x3650 M5: -[8871AC1]-"; HOSTNAME_EXPECT=lab-lenovo; CHASSIS_EXPECT=EXSER02
    TARGET_ID=600605b0deadbeef; TARGET_SIZE=278G
    TARGET_DEV="scsi-hd,drive=tgt,wwn=0x$TARGET_ID"
    TARGET_RE="(scsi-3|wwn-0x)$TARGET_ID"
    DECOY1_DEV="scsi-hd,drive=dc1,wwn=0x600605b0cafebabe"; DECOY2_DEV="scsi-hd,drive=dc2,wwn=0x600605b0deadbee0"
    DECOY_SIZE=100G
    SERIAL_PRE="-serial null"   # IMM2 SSH redirect is COM2 -> ttyS1
    PRIV_MAC=02:00:00:00:00:05; OTHER_MAC=02:00:00:00:00:17; ADMIN_IP=10.90.10.21 ;;
  hpe)
    NODE=hpe; PRODUCT="ProLiant DL380 Gen10"; HOSTNAME_EXPECT=lab-dl380; CHASSIS_EXPECT=EXSERIAL01
    TARGET_ID=EXNVME00000001; TARGET_SIZE=1600G      # real serial: QEMU can emulate it
    TARGET_DEV="nvme,drive=tgt,serial=$TARGET_ID"
    TARGET_RE="nvme-[A-Za-z0-9_.-]*_$TARGET_ID"
    DECOY1_DEV="nvme,drive=dc1,serial=EXNVME00000099"; DECOY2_DEV="scsi-hd,drive=dc2,wwn=0x600508b1cafebabe"
    DECOY_SIZE=100G
    ROLE=login; CAMPUS_MAC=02:00:00:00:00:02; PRIV_MAC=02:00:00:00:00:01 ;;
  *) echo "unsupported profile: $PROFILE" >&2; exit 2 ;;
esac
VG_EXPECT="${NODE}_vg"
ISO="${ISO_ARG:-$HOME/scratch/ks/Rocky-9.8-ks-$NODE-qemu-test.iso}"
PW_FILE="$HOME/.config/prace-lab/${PROFILE}-bootstrap.pw"
RUN_ROOT="$HOME/scratch/ks/qemu-$NODE"
TMO="${TMO:-2400}"
case "$TMO" in ''|*[!0-9]*) echo "TMO must be positive integer seconds" >&2; exit 2 ;; esac
[ "$TMO" -gt 0 ] || { echo "TMO must be positive integer seconds (0 would disable the timeout)" >&2; exit 2; }
if [ "$DESCRIBE" = 1 ]; then
  printf '%s\n' "profile=$PROFILE" "role=$ROLE" "hostname=$HOSTNAME_EXPECT" "chassis=$CHASSIS_EXPECT" \
    "product=$PRODUCT" "vg=$VG_EXPECT" "target=$TARGET_DEV" "iso=$ISO" "credential_file=$PW_FILE" "run_root=$RUN_ROOT"
  exit 0
fi

[ -s "$ISO" ] || { echo "missing test ISO: $ISO" >&2; exit 2; }
[ -s "$PW_FILE" ] || { echo "missing bootstrap password file: $PW_FILE" >&2; exit 2; }
ISO="$(realpath -e -- "$ISO")"
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
for tool in qemu-img qemu-system-x86_64 timeout python3 sha256sum; do
  command -v "$tool" >/dev/null || { echo "missing required tool: $tool" >&2; exit 2; }
done
[ -r /usr/share/OVMF/OVMF_CODE_4M.fd ] && [ -r /usr/share/OVMF/OVMF_VARS_4M.fd ] || { echo "missing OVMF 4M firmware" >&2; exit 2; }
[ -r /dev/kvm ] && [ -w /dev/kvm ] || { echo "KVM access required" >&2; exit 2; }
# Never risk the workstation (27 GB, shared with the desktop): refuse to start a VM unless
# MemAvailable covers it plus a margin. (An earlier QEMU run on this machine hit an OOM.)
need_memory() {  # need_memory MiB_for_the_VMs
  local avail margin=3072
  avail=$(awk '/^MemAvailable:/{print int($2/1024)}' /proc/meminfo)
  if [ "$avail" -lt $(( $1 + margin )) ]; then
    echo "refusing: MemAvailable ${avail} MiB < ${1} MiB for the VM(s) + ${margin} MiB margin; close something first" >&2
    exit 3
  fi
}
need_memory 4096
umask 077
[ ! -L "$RUN_ROOT" ] || { echo "refusing symlink run root: $RUN_ROOT" >&2; exit 2; }
mkdir -p "$RUN_ROOT"
D="$(mktemp -d "$RUN_ROOT/run.XXXXXXXX")"
printf 'ARTIFACT-DIRECTORY: %s\n' "$D"
cd "$D"
QPID=""
PEERPID=""
cleanup() {
  [ -z "$PEERPID" ] || kill "$PEERPID" 2>/dev/null || true
  if [ -n "$QPID" ]; then kill "$QPID" 2>/dev/null || true; wait "$QPID" 2>/dev/null || true; fi
  rm -f -- "$D/serial.sock"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

qemu-img create -f qcow2 -q target.qcow2 "$TARGET_SIZE"
qemu-img create -f qcow2 -q decoy1.qcow2 "$DECOY_SIZE"
qemu-img create -f qcow2 -q decoy2.qcow2 "$DECOY_SIZE"
DECOY1_BEFORE=$(sha256sum decoy1.qcow2 | awk '{print $1}')
DECOY2_BEFORE=$(sha256sum decoy2.qcow2 | awk '{print $1}')
cp /usr/share/OVMF/OVMF_VARS_4M.fd vars.fd
MACHINE=(-machine q35 -m 4096 -smp 4 -enable-kvm -cpu host
  -smbios "type=1,serial=$CHASSIS_EXPECT,product=$PRODUCT"
  -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd
  -drive if=pflash,format=raw,file=vars.fd
  -device virtio-scsi-pci,id=scsi0
  -drive file=target.qcow2,if=none,id=tgt,format=qcow2 -device "$TARGET_DEV"
  -drive file=decoy1.qcow2,if=none,id=dc1,format=qcow2 -device "$DECOY1_DEV"
  -drive file=decoy2.qcow2,if=none,id=dc2,format=qcow2 -device "$DECOY2_DEV"
  -display none)
FAIL=0
# Localhost UDP ports for the NICs (QEMU dgram netdevs). Phase 1 presents the same NICs as
# the real node (the installer may configure them by MAC) but cabled to nowhere.
read -r PORT_A PORT_B PORT_C PORT_D PORT_E PORT_F < <(python3 -c '
import socket
ss = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(6)]
[s.bind(("127.0.0.1", 0)) for s in ss]
print(*[s.getsockname()[1] for s in ss])')
dgram() { echo "dgram,id=$1,local.type=inet,local.host=127.0.0.1,local.port=$2,remote.type=inet,remote.host=127.0.0.1,remote.port=$3"; }
if [ "$ROLE" = compute ]; then MAC1=$PRIV_MAC; MAC2=$OTHER_MAC; else MAC1=$CAMPUS_MAC; MAC2=$PRIV_MAC; fi
P1NICS=(-netdev "$(dgram n1 "$PORT_A" "$PORT_E")" -device "e1000e,netdev=n1,mac=$MAC1"
        -netdev "$(dgram n2 "$PORT_C" "$PORT_F")" -device "e1000e,netdev=n2,mac=$MAC2")

echo "=== phase 1: install (ISO attached, KS_DEFAULT_ENTRY=2) ==="
set +e
# shellcheck disable=SC2086
timeout "$TMO" qemu-system-x86_64 "${MACHINE[@]}" -cdrom "$ISO" -boot order=d "${P1NICS[@]}" \
  $SERIAL_PRE -serial file:serial-phase1.log >/dev/null 2>&1
RC1=$?
set -e
echo "phase1 qemu rc=$RC1 (0=poweroff, 124=timeout)"
[ "$RC1" -eq 0 ] || { echo "PHASE1-QEMU-EXIT: FAIL (rc=$RC1)"; FAIL=1; }
LOG1=$(tr -d '\r' < serial-phase1.log)
if grep -aqE "install target: /dev/disk/by-id/$TARGET_RE \([a-z0-9]+\) \[verified unique, n=1\]" <<<"$LOG1"; then
  echo "TARGET-RESOLVED-BY-EXACT-ID: PASS"
else
  echo "TARGET-RESOLVED-BY-EXACT-ID: FAIL"; grep -a "FATAL\|install target" <<<"$LOG1" | head -3 | sed 's/^/    /' || true; FAIL=1
fi
if grep -aqE "Power down|reboot: Power down|The system will power off|Powering off" <<<"$LOG1"; then
  echo "INSTALL-COMPLETED-POWEROFF: PASS"
else
  echo "INSTALL-COMPLETED-POWEROFF: FAIL"; FAIL=1
fi
if grep -aqE "Kernel panic|Pane is dead|FATAL|error occurred" <<<"$LOG1"; then
  echo "INSTALL-ERRORS: FAIL"; grep -aE "Kernel panic|Pane is dead|FATAL|error occurred" <<<"$LOG1" | head -3 | sed 's/^/    /'; FAIL=1
else
  echo "INSTALL-ERRORS: PASS (none)"
fi
# The installer prints the SSH host key fingerprints (kickstart %post); phase 2 checks the
# installed system still uses that key, so an operator can trust the console line.
ED_FP=$(grep -aoE "host key: 256 SHA256:[A-Za-z0-9+/]{43} [^ ]+ \(ED25519\)" <<<"$LOG1" | awk '{print $4}' | sort -u)
if [ -n "$ED_FP" ] && [ "$(wc -l <<<"$ED_FP")" -eq 1 ]; then
  echo "HOSTKEY-ON-CONSOLE: PASS ($ED_FP)"
else
  echo "HOSTKEY-ON-CONSOLE: FAIL"; FAIL=1; ED_FP="none"
fi

echo
echo "=== phase 2: installed-disk boot (no ISO) + serial acceptance ($ROLE) ==="
need_memory 4096
rm -f serial.sock
if [ "$ROLE" = compute ]; then
  python3 "$HERE/fake-login-peer.py" --listen 127.0.0.1:"$PORT_B" --seconds 1200 --log "$D/peer.log" &
  PEERPID=$!
  NICS=(-netdev "$(dgram priv "$PORT_A" "$PORT_B")" -device "e1000e,netdev=priv,mac=$PRIV_MAC"
        -netdev "$(dgram other "$PORT_C" "$PORT_D")" -device "e1000e,netdev=other,mac=$OTHER_MAC")
else
  NICS=(-netdev "$(dgram campus "$PORT_A" "$PORT_B")" -device "e1000e,netdev=campus,mac=$CAMPUS_MAC"
        -netdev "$(dgram priv "$PORT_C" "$PORT_D")" -device "e1000e,netdev=priv,mac=$PRIV_MAC")
fi
# shellcheck disable=SC2086
timeout 900 qemu-system-x86_64 "${MACHINE[@]}" -boot order=c "${NICS[@]}" \
  $SERIAL_PRE -serial unix:serial.sock,server=on,wait=on >/dev/null 2>&1 &
QPID=$!
sleep 2
set +e
python3 - "$D/serial.sock" "$PW_FILE" "$ROLE" > phase2-transcript.txt 2>&1 <<'PY'
import socket, sys, time, re
sock_path, pw_file, role = sys.argv[1], sys.argv[2], sys.argv[3]
pw = open(pw_file).read().strip()
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(600)
s.connect(sock_path)
buf = b""
def read_until(pattern, timeout=420):
    global buf
    deadline = time.time() + timeout
    rx = re.compile(pattern, re.I)
    while time.time() < deadline:
        if rx.search(buf.decode("utf-8", "replace")):
            return True
        try:
            chunk = s.recv(4096)
        except socket.timeout:
            continue
        if not chunk:
            break
        buf += chunk
        sys.stdout.write(chunk.decode("utf-8", "replace")); sys.stdout.flush()
    return False
def send(line):
    s.sendall((line + "\n").encode())
def run(cmd, timeout=300):
    global buf
    buf = b""
    send(cmd)
    time.sleep(2)
    read_until(r"#\s*$", timeout)
    sys.stdout.write("\n-----CMD %s-----\n%s\n" % (cmd, buf.decode("utf-8", "replace"))); sys.stdout.flush()
if not read_until(r"login:", 480):
    print("PHASE2-LOGIN-PROMPT: FAIL (no login prompt)"); sys.exit(3)
print("\nPHASE2-LOGIN-PROMPT: PASS")
send("root")
if not read_until(r"[Pp]assword:", 60):
    print("PHASE2-PASSWORD-PROMPT: FAIL"); sys.exit(4)
send(pw)
if not read_until(r"#\s*$", 120):
    print("PHASE2-ROOT-LOGIN: FAIL"); sys.exit(5)
print("PHASE2-ROOT-LOGIN: PASS")
run("cat /etc/rocky-release")
run("hostnamectl --static")
run("cat /sys/class/dmi/id/product_serial")
run("findmnt -n -o TARGET,SOURCE,FSTYPE /")
run("findmnt -n -o TARGET,SOURCE,FSTYPE /boot/efi")
run("vgs --noheadings -o vg_name")
run("lvs --noheadings -o lv_name,vg_name,lv_size")
run("cat /etc/NetworkManager/conf.d/10-prace-no-auto-default.conf")
if role == "compute":
    run("for i in $(seq 120); do [ -e /var/lib/prace/first-address.done ] && break; sleep 2; done; ls /var/lib/prace/")
    run("systemctl show -p Result -p ExecMainStatus prace-first-address.service")
    run("journalctl -b -u prace-first-address -o cat --no-pager | tail -12")
else:
    run("sleep 20; systemctl list-unit-files prace-first-address.service | tail -1")
    run("ip -4 route show default")
run("for n in $(ls /sys/class/net); do echo NIC $n $(cat /sys/class/net/$n/address) $(ip -4 -o addr show dev $n | awk '{print $4}'); done")
run("nmcli -t -f NAME connection show --active")
run("ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub; systemctl is-active sshd; ls -Z /etc/ssh/ssh_host_ed25519_key")
buf = b""
send("poweroff")
time.sleep(5)
sys.exit(0)
PY
PYRC=$?
set -e
echo "phase2 driver rc=$PYRC"
set +e; wait "$QPID" 2>/dev/null; RC2=$?; set -e
QPID=""
rm -f serial.sock
[ "$RC2" -eq 0 ] || { echo "PHASE2-QEMU-EXIT: FAIL (rc=$RC2)"; FAIL=1; }
if [ -n "$PEERPID" ]; then
  kill "$PEERPID" 2>/dev/null; wait "$PEERPID" 2>/dev/null || true; PEERPID=""
  echo "FAKE-LOGIN-PEER: $(cat "$D/peer.log" 2>/dev/null || echo 'no log')"
fi
# Strip CR and terminal control sequences (bash emits ESC[?2004l before command output),
# so line-anchored checks see the real text.
TR=$(tr -d '\r' < phase2-transcript.txt | sed 's/\x1b\[[0-9;?]*[A-Za-z]//g')
check() { if grep -aqE "$2" <<<"$TR"; then echo "$1: PASS"; else echo "$1: FAIL"; FAIL=1; fi; }
absent() { if grep -aqE "$2" <<<"$TR"; then echo "$1: FAIL"; FAIL=1; else echo "$1: PASS"; fi; }
# The driver echoes each command's output twice (streamed + block), so count DISTINCT lines.
count() { if [ "$(grep -aE "$2" <<<"$TR" | sort -u | wc -l)" -eq "$3" ]; then echo "$1: PASS"; else echo "$1: FAIL"; FAIL=1; fi; }
echo
check "PHASE2-LOGIN-PROMPT"     "PHASE2-LOGIN-PROMPT: PASS"
check "PHASE2-ROOT-LOGIN"       "PHASE2-ROOT-LOGIN: PASS"
check "INSTALLED-ROCKY-RELEASE" "Rocky Linux release 9\.8"
check "INSTALLED-HOSTNAME"      "^${HOSTNAME_EXPECT}$"
check "INSTALLED-CHASSIS"       "^${CHASSIS_EXPECT}$"
check "INSTALLED-VG"            "^[[:space:]]*${VG_EXPECT}[[:space:]]*$"
check "INSTALLED-LV-ROOT"       "^[[:space:]]*root[[:space:]]+${VG_EXPECT}[[:space:]]"
check "INSTALLED-LV-SWAP"       "^[[:space:]]*swap[[:space:]]+${VG_EXPECT}[[:space:]]"
absent "NO-IMAGES-LV"           "^[[:space:]]*libvirt_images[[:space:]]"
check "INSTALLED-ROOT-MOUNTED"  "^/[[:space:]]+/dev/mapper/${VG_EXPECT}-root[[:space:]]+xfs"
check "INSTALLED-EFI-MOUNTED"   "^/boot/efi[[:space:]]+/dev/(sd[a-z]+[0-9]+|nvme[0-9]+n[0-9]+p[0-9]+)[[:space:]]+vfat"
check "NM-NO-AUTO-DEFAULT"      "^no-auto-default=\*"
if grep -aqF "256 $ED_FP " <<<"$TR"; then echo "HOSTKEY-SAME-AS-CONSOLE: PASS"; else echo "HOSTKEY-SAME-AS-CONSOLE: FAIL"; FAIL=1; fi
check "SSHD-ACTIVE"             "^active$"
check "HOSTKEY-SELINUX-LABEL"   ":sshd_key_t:"
if [ "$ROLE" = compute ]; then
  check "FIRST-ADDRESS-DONE"     "^first-address\.done"
  check "FIRST-ADDRESS-SUCCESS"  "^Result=success"
  check "ADDRESS-ON-PRIV-MAC"    "^NIC [a-z0-9]+ ${PRIV_MAC} ${ADMIN_IP}/25"
  check "OTHER-PORT-UNADDRESSED" "^NIC [a-z0-9]+ ${OTHER_MAC}[[:space:]]*$"
  count "ONE-PRIVATE-PROFILE"    "^private-[a-z0-9]+$" 1
else
  check "CAMPUS-ADDRESS-BY-MAC"  "^NIC [a-z0-9]+ ${CAMPUS_MAC} 172\.21\.25\.205/24"
  check "PRIVATE-ADDRESS-BY-MAC" "^NIC [a-z0-9]+ ${PRIV_MAC} 10\.10\.10\.1/25"
  count "ONE-DEFAULT-ROUTE"      "^default via " 1
  check "DEFAULT-VIA-CAMPUS-GW"  "^default via 172\.21\.25\.254 dev "
  check "NO-FIRST-ADDRESS-UNIT"  "^0 unit files listed"
fi
[ "$PYRC" -eq 0 ] || { echo "PHASE2-DRIVER: FAIL (rc=$PYRC)"; FAIL=1; }
echo
for n in 1 2; do
  before_var="DECOY${n}_BEFORE"; after=$(sha256sum "decoy$n.qcow2" | awk '{print $1}')
  if [ "${!before_var}" = "$after" ]; then echo "DECOY$n-UNCHANGED: PASS (sha256 ${after:0:12}…)"; else echo "DECOY$n-UNCHANGED: FAIL"; FAIL=1; fi
done
if [ "$FAIL" -eq 0 ]; then echo "VERDICT: PASS ($PROFILE)"; exit 0; else echo "VERDICT: FAIL ($PROFILE)"; exit 1; fi

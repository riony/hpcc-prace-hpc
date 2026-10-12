#!/bin/bash
# Virtual rehearsal fleet (T68): the login node and the CPU node as VMs, booted from overlays
# on disks installed by the QEMU gates (kickstart/test-ks-qemu-fleet.sh), so the rehearsal
# runs the same installers' output. Nothing touches a real network:
#   login campus NIC : QEMU user-mode NAT shaped as 192.0.2.0/24, gateway .254, with
#                      127.0.0.1:2222 -> 192.0.2.205:22 (this is how Ansible reaches it)
#   private NICs     : localhost UDP links through l2hub.py (the private switch)
# The NICs are pinned to the PCI slots they had in the gates, because the
# installed profiles are bound to those interface names (login gate: enp0s5/enp0s6; Lenovo
# gate: enp0s3/enp0s4). On hardware the names are stable.
# Usage: fleet-vms.sh start LOGIN_GATE_RUN_DIR CPU_GATE_RUN_DIR | stop | status
set -euo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
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

R="$HOME/scratch/rehearsal"
MEM=3072
cmd="${1:-status}"

pids() { for f in "$R"/*.pid; do [ -e "$f" ] && echo "$(basename "$f" .pid)=$(cat "$f")"; done; }
case "$cmd" in
  status) pids; exit 0 ;;
  stop)
    for f in "$R"/*.pid; do [ -e "$f" ] || continue; kill "$(cat "$f")" 2>/dev/null || true; rm -f "$f"; done
    echo "stopped"; exit 0 ;;
  start) [ "$#" -eq 3 ] || { echo "usage: $0 start LOGIN_GATE_RUN_DIR CPU_GATE_RUN_DIR" >&2; exit 2; } ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
LOGIN_RUN="$(realpath -e "$2")"; CPU_RUN="$(realpath -e "$3")"
for d in "$LOGIN_RUN" "$CPU_RUN"; do [ -s "$d/target.qcow2" ] && [ -s "$d/vars.fd" ] || { echo "not a gate run dir: $d" >&2; exit 2; }; done
[ -z "$(pids)" ] || { echo "rehearsal already running: $(pids)" >&2; exit 2; }
need_memory $(( 2 * MEM ))
mkdir -p "$R"; umask 077
for n in login cpu; do
  src=$([ $n = login ] && echo "$LOGIN_RUN" || echo "$CPU_RUN")
  rm -f "$R/$n.qcow2"
  qemu-img create -q -f qcow2 -b "$src/target.qcow2" -F qcow2 "$R/$n.qcow2"   # gate disk stays untouched
  cp "$src/vars.fd" "$R/$n-vars.fd"
done
read -r H1 N1 H2 N2 N3 N4 < <(python3 -c '
import socket
ss = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(6)]
[s.bind(("127.0.0.1", 0)) for s in ss]
print(*[s.getsockname()[1] for s in ss])')
dgram() { echo "dgram,id=$1,local.type=inet,local.host=127.0.0.1,local.port=$2,remote.type=inet,remote.host=127.0.0.1,remote.port=$3"; }
python3 "$HERE/l2hub.py" --pair "$H1:$N1" --pair "$H2:$N2" > "$R/hub.log" 2>&1 &
echo $! > "$R/hub.pid"
base=(-machine q35 -m "$MEM" -smp 4 -enable-kvm -cpu host -display none -daemonize
      -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd -device virtio-scsi-pci,id=scsi0)
qemu-system-x86_64 "${base[@]}" -pidfile "$R/login.pid" \
  -smbios "type=1,serial=EXSERIAL01,product=ProLiant DL380 Gen10" \
  -drive if=pflash,format=raw,file="$R/login-vars.fd" \
  -drive file="$R/login.qcow2",if=none,id=tgt,format=qcow2 -device nvme,drive=tgt,serial=EXNVME00000001 \
  -netdev "user,id=campus,net=192.0.2.0/24,host=192.0.2.254,hostfwd=tcp:127.0.0.1:2222-192.0.2.205:22" \
  -device e1000e,netdev=campus,mac=02:00:00:00:00:02,addr=0x5 \
  -netdev "$(dgram priv "$N1" "$H1")" -device e1000e,netdev=priv,mac=02:00:00:00:00:01,addr=0x6 \
  -serial file:"$R/login-serial.log"
qemu-system-x86_64 "${base[@]}" -pidfile "$R/cpu.pid" \
  -smbios "type=1,serial=EXSER02,product=System x3650 M5: -[8871AC1]-" \
  -drive if=pflash,format=raw,file="$R/cpu-vars.fd" \
  -drive file="$R/cpu.qcow2",if=none,id=tgt,format=qcow2 -device scsi-hd,drive=tgt,wwn=0x600605b0deadbeef \
  -netdev "$(dgram priv "$N2" "$H2")" -device e1000e,netdev=priv,mac=02:00:00:00:00:05,addr=0x3 \
  -netdev "$(dgram other "$N3" "$N4")" -device e1000e,netdev=other,mac=02:00:00:00:00:17,addr=0x4 \
  -serial null -serial file:"$R/cpu-serial.log"
echo "started: $(pids)"
echo "login: ssh -p 2222 root@127.0.0.1 (with the rehearsal known_hosts); cpu: via the login VM to 10.90.10.21"

#!/usr/bin/env bash
# Isolated restore rehearsal (T73), run from the control workstation. It restores a
# k3s-login-backup.sh archive into a throwaway VM on the login node's rehearsal host
# (roles/rehearsal_host) and compares the restored cluster with the live one.
#
#   infra/tools/restore-rehearsal.sh run --backup k3s-login-20260928-0731-restore-rehearsal [--out DIR] [--hold-on-failure]
#   infra/tools/restore-rehearsal.sh run --e2e --backup NAME [--out DIR] [--hold-on-failure]
#   infra/tools/restore-rehearsal.sh cleanup
#
# --e2e is the end-to-end recovery rehearsal. It needs a backup taken with --home inside one
# maintenance window (NAME.tgz + NAME-home.tgz, and the archive's maintenance-window record says
# home=1). A second VM, the worker "rehearsal-cpu1", is linked to the control VM by a private UDP
# link that reaches nothing else. The rehearsal restores /home and proves it equals the home
# archive (paths, owners, modes, content), exports it over NFS as roles/nfs_home does, and waits
# for the restored login pod. syn-probe then logs in with key authentication, and the pod's host
# key is checked against the PRODUCTION known-hosts entry. The worker joins as a K3s agent with
# the restored agent token (the restored cpu NodeSet is resized to a rehearsal budget). Finally
# syn-probe runs a job pinned to the worker: it must complete, take the next job ID and write to
# the restored /home. The recovery time is recorded.
#
# Exit status 0 means every required observation held (RESULT: PASS). Any failed, unknown or
# unexpected observation stops the run with RESULT: FAIL and a non-zero status. The failures
# include an isolation probe that connects or cannot run, a controller that never becomes
# usable, a fingerprint command error or malformed line, a live/restored difference outside the
# single documented normalization, and a wrong job-ID counter. On failure the VM and its disks
# (restored credentials) are deleted automatically. The only exception is --hold-on-failure after
# isolation was proven: the VM is then kept for diagnosis and 'cleanup' deletes it.
#
# Isolation: the VM runs as the rehearsal user behind the memory guard, with QEMU user networking
# and restrict=on. It can send nothing to the host, the fleet or anywhere else; the only way in
# is an ssh port forward on the login node's 127.0.0.1, reached through the login node with a
# throwaway key. Inside, the admin address 10.90.10.1 sits on a dummy interface, so the restored
# server (production CA and tokens) talks only to itself. Everything the VM needs comes on a
# read-only data disk: the fleet package repository, the pinned K3s artifacts, the Slinky images
# exported by digest, the login-node packages the fleet repository lacks (EXTRA_PACKAGES), the
# backup and tools/k3s-login-restore.sh.
#
# run: prepare (pinned base image, overlay, cloud-init seed, data disk) -> boot (host key checked
# against the VM console) -> restore (packages from the data disk, the role's MariaDB setting,
# k3s-login-restore.sh) -> verify (the same fingerprint script on the live login node and in the
# VM, then a diff; no secret is printed). cleanup stops the VM and deletes its disks, which hold
# restored credentials, plus the throwaway key.
set -euo pipefail

LOGIN=192.0.2.205
RUSER=prace-rehearsal
RDIR=/var/lib/prace-rehearsal/restore
CACHE=/var/lib/prace-rehearsal/images
PORT=2231
VM_MIB=16384 VM_CPUS=8 VM_DISK=40G
E2E=0
WPORT=2232 W_MIB=12288 W_CPUS=6 W_DISK=30G
LINK_A=47101 LINK_B=47102                    # UDP ports on the login node's 127.0.0.1 (the VM link)
CTL_MAC=52:54:00:4e:53:01 WRK_MAC=52:54:00:4e:53:02
CTL_IP=10.90.10.1 WRK_IP=10.90.10.30 WRK_NAME=rehearsal-cpu1
WRK_BUDGET='{"requests":{"cpu":"2","memory":"4Gi"},"limits":{"cpu":"2","memory":"4Gi"}}'
PROBE_KEY=${PRACE_PROBE_KEY:-$HOME/.config/prace-lab/syn-probe-ed25519}
POD_KH=${PRACE_PROBE_KNOWN_HOSTS:-$HOME/.config/prace-lab/slinky-login-pod-known-hosts}
IMG=Rocky-9-GenericCloud-Base-9.8-20260525.0.x86_64.qcow2
IMG_URL=https://dl.rockylinux.org/pub/rocky/9.8/images/x86_64/$IMG
IMG_SHA=92c206cc6f790c61583247eefe87890f8828420662c17cacf247cec78ab4eec8   # CHECKSUM, signature verified 28 Sep
# The Slinky images the control plane runs, pinned by digest in roles/slinky (slurmd and alpine are
# already archived in /srv/fleet-repo/k3s/images for the workers).
EXPORT_IMAGES=$(python3 -c '
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))["slinky_images"]
print(" ".join(d[k]["repository"] + "@" + d[k]["digest"] for k in ("operator", "webhook", "slurmctld", "slurmrestd", "slurmdbd", "login")))
' "$(dirname -- "${BASH_SOURCE[0]}")/../roles/slinky/defaults/main.yml")
# Login-node packages missing from /srv/fleet-repo (the compute nodes' package set): the login node
# installed them from its online repositories. Staged at the login node's installed versions.
EXTRA_PACKAGES="mysql-selinux"
TOOLS=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
KEYDIR=${XDG_RUNTIME_DIR:-/tmp}/prace-restore-rehearsal
MUX=$KEYDIR/mux

# ---------------------------------------------------------------------------------------------
STAGE=start RDIR_USED=0 ISOLATED=0 HOLD=0
fail() { echo "   FAIL: $*"; exit 1; }

L() { ssh -o BatchMode=yes -o ConnectTimeout=10 -o ControlMaster=auto -o ControlPath="$MUX/login" -o ControlPersist=900 "root@$LOGIN" "$@"; }
V() { ssh -o BatchMode=yes -o ConnectTimeout=20 -o ControlMaster=auto -o ControlPath="$MUX/vm" -o ControlPersist=900 \
        -o ProxyCommand="ssh -o BatchMode=yes -o ControlPath=$MUX/login -W %h:%p root@$LOGIN" \
        -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile="$KEYDIR/known_hosts" -o StrictHostKeyChecking="${SHK:-yes}" \
        -o IdentitiesOnly=yes -i "$KEYDIR/id" -p $PORT root@127.0.0.1 "$@"; }
W() { ssh -o BatchMode=yes -o ConnectTimeout=20 -o ControlMaster=auto -o ControlPath="$MUX/worker" -o ControlPersist=900 \
        -o ProxyCommand="ssh -o BatchMode=yes -o ControlPath=$MUX/login -W %h:%p root@$LOGIN" \
        -o HostKeyAlgorithms=ssh-ed25519 -o UserKnownHostsFile="$KEYDIR/known_hosts" -o StrictHostKeyChecking="${SHK:-yes}" \
        -o IdentitiesOnly=yes -i "$KEYDIR/id" -p $WPORT root@127.0.0.1 "$@"; }
# syn-probe into the RESTORED login pod: NodePort 32222 on the control VM's link address, reached
# through the VM's multiplexed ssh. The pod's host key must match the production known-hosts entry.
POD() { ssh -o BatchMode=yes -o ConnectTimeout=15 -o ControlMaster=no -o ControlPath=none -o IdentitiesOnly=yes -i "$PROBE_KEY" \
          -o UserKnownHostsFile="$POD_KH" -o StrictHostKeyChecking=yes \
          -o ProxyCommand="ssh -o BatchMode=yes -o ControlPath=$MUX/vm -p $PORT -W %h:%p root@127.0.0.1" \
          -p 32222 syn-probe@$CTL_IP "$@" </dev/null; }

cleanup() {
  echo "== $(date +%T) cleanup: stop the VM, delete its disks (restored credentials) and the throwaway key"
  L RDIR="$RDIR" RUSER="$RUSER" bash -s <<'REMOTE'
set -u
for pf in "$RDIR/qemu.pid" "$RDIR/qemu-worker.pid"; do
  [ -f "$pf" ] || continue
  pid=$(cat "$pf")
  # only rehearsal VMs: owned by the rehearsal user and named prace-restore*
  if [ "$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')" = "$RUSER" ] && tr '\0' ' ' < /proc/$pid/cmdline | grep -q -- '-name prace-restore'; then
    kill "$pid"; for _ in $(seq 30); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
    kill -0 "$pid" 2>/dev/null && kill -9 "$pid"
    echo "   VM $pid stopped ($(basename "$pf" .pid))"
  fi
done
rm -rf "$RDIR"
[ ! -e "$RDIR" ] && echo "   $RDIR removed (overlay, data disk, seed, console log)"
REMOTE
  ssh -o ControlPath="$MUX/vm" -O exit x 2>/dev/null || true
  ssh -o ControlPath="$MUX/worker" -O exit x 2>/dev/null || true
  ssh -o ControlPath="$MUX/login" -O exit x 2>/dev/null || true
  rm -rf "$KEYDIR"; echo "   throwaway key and known_hosts removed"
}

# On any failure: keep what explains it (no secrets), then delete the VM and its disks unless a
# diagnostic hold was asked for AND isolation had been proven.
on_exit() {
  local rc=$?
  [ "$rc" = 0 ] && return 0
  echo "RESULT: FAIL (stage $STAGE, exit $rc)"
  [ "$RDIR_USED" = 1 ] || return "$rc"
  L "timeout 30 tail -n 60 $RDIR/console.log 2>/dev/null | tr -d '\r'" > "$OUT/console-tail-at-failure.txt" 2>&1 || true
  if [ "$E2E" = 1 ]; then L "timeout 30 tail -n 60 $RDIR/console-worker.log 2>/dev/null | tr -d '\r'" > "$OUT/console-worker-tail-at-failure.txt" 2>&1 || true; fi
  if [ "$ISOLATED" = 1 ]; then
    V 'timeout 60 k3s kubectl get nodes; timeout 60 k3s kubectl get pods -A -o wide' > "$OUT/pods-at-failure.txt" 2>&1 || true
  fi
  if [ "$HOLD" = 1 ] && [ "$ISOLATED" = 1 ]; then
    echo "   VM kept for diagnosis (isolation was proven); delete it with: $0 cleanup"
  else
    cleanup || echo "   CLEANUP FAILED: run '$0 cleanup' and check $RDIR on the login node"
  fi
  return "$rc"
}

stage_prepare() {
STAGE=prepare
RDIR_USED=1
echo "== $(date +%T) prepare (backup $BACKUP, VM ${VM_CPUS} vCPU / ${VM_MIB} MiB, ssh forward 127.0.0.1:$PORT on the login node)"
[ -f "$KEYDIR/id" ] || ssh-keygen -q -t ed25519 -N '' -C prace-restore-rehearsal -f "$KEYDIR/id"
rm -f "$KEYDIR/known_hosts"
seed=$KEYDIR/seed; mkdir -p "$seed"
printf 'instance-id: prace-restore-%s\nlocal-hostname: lab-dl380\n' "$(date +%s)" > "$seed/meta-data"
cat > "$seed/user-data" <<EOF
#cloud-config
hostname: lab-dl380
disable_root: false
ssh_pwauth: false
ssh_authorized_keys:
  - $(cat "$KEYDIR/id.pub")
EOF
genisoimage -quiet -output "$KEYDIR/seed.iso" -volid cidata -joliet -rock "$seed/user-data" "$seed/meta-data"
if [ "$E2E" = 1 ]; then
  wseed=$KEYDIR/seed-worker; mkdir -p "$wseed"
  printf 'instance-id: prace-restore-worker-%s\nlocal-hostname: %s\n' "$(date +%s)" "$WRK_NAME" > "$wseed/meta-data"
  sed "s/^hostname: .*/hostname: $WRK_NAME/" "$seed/user-data" > "$wseed/user-data"
  genisoimage -quiet -output "$KEYDIR/seed-worker.iso" -volid cidata -joliet -rock "$wseed/user-data" "$wseed/meta-data"
fi
L "mkdir -p -m 700 /root/prace-rehearsal-upload"
scp -q -o ControlPath="$MUX/login" "$KEYDIR/seed.iso" "$TOOLS/k3s-login-restore.sh" $([ "$E2E" = 1 ] && echo "$KEYDIR/seed-worker.iso") "root@$LOGIN:/root/prace-rehearsal-upload/"

L BACKUP="$BACKUP" RDIR="$RDIR" CACHE="$CACHE" RUSER="$RUSER" IMG="$IMG" IMG_URL="$IMG_URL" IMG_SHA="$IMG_SHA" \
  VM_DISK="$VM_DISK" EXPORT_IMAGES="$(printf %q "$EXPORT_IMAGES")" EXTRA_PACKAGES="$(printf %q "$EXTRA_PACKAGES")" \
  E2E="$E2E" W_DISK="$W_DISK" bash -s <<'REMOTE'
set -euo pipefail
umask 077
[ -f "/root/prace-backup/$BACKUP.tgz" ] || { echo "refusing: /root/prace-backup/$BACKUP.tgz not found"; exit 3; }
if [ "$E2E" = 1 ]; then
  # control state and /home must come from ONE maintenance window
  [ -f "/root/prace-backup/$BACKUP-home.tgz" ] || { echo "refusing: /root/prace-backup/$BACKUP-home.tgz not found"; exit 3; }
  w=$(python3 -c 'import sys, tarfile; print(tarfile.open(sys.argv[1]).extractfile("prace-backup/maintenance-window.txt").read().decode().strip())' "/root/prace-backup/$BACKUP.tgz" 2>/dev/null) \
    || { echo "refusing: $BACKUP.tgz has no maintenance-window record (not taken inside a window)"; exit 3; }
  grep -q ' home=1 ' <<<"$w " || { echo "refusing: $BACKUP.tgz was not captured together with /home ($w)"; exit 3; }
  echo "   same maintenance window: $w"
fi
if pgrep -u "$RUSER" -f 'name prace-restore' >/dev/null; then echo "refusing: a restore VM is running (run cleanup)"; exit 3; fi
[ ! -e "$RDIR" ] || { echo "refusing: $RDIR exists (run cleanup)"; exit 3; }
install -d -m 0750 -o "$RUSER" -g "$RUSER" "$CACHE"; install -d -m 0700 -o "$RUSER" -g "$RUSER" "$RDIR"

if [ ! -f "$CACHE/$IMG" ] || [ "$(sha256sum "$CACHE/$IMG" | cut -d' ' -f1)" != "$IMG_SHA" ]; then
  curl -fsSL -o "$CACHE/$IMG.part" "$IMG_URL"; mv "$CACHE/$IMG.part" "$CACHE/$IMG"
fi
got=$(sha256sum "$CACHE/$IMG" | cut -d' ' -f1)
[ "$got" = "$IMG_SHA" ] || { echo "refusing: base image sha256 $got != pinned $IMG_SHA"; rm -f "$CACHE/$IMG"; exit 4; }
chown "$RUSER:" "$CACHE/$IMG"; chmod 0440 "$CACHE/$IMG"
echo "   base image $IMG (sha256 matches the pinned value)"
runuser -u "$RUSER" -- qemu-img create -q -f qcow2 -F qcow2 -b "$CACHE/$IMG" "$RDIR/disk.qcow2" "$VM_DISK"
install -m 0600 -o "$RUSER" -g "$RUSER" /root/prace-rehearsal-upload/seed.iso "$RDIR/seed.iso"
if [ "$E2E" = 1 ]; then
  runuser -u "$RUSER" -- qemu-img create -q -f qcow2 -F qcow2 -b "$CACHE/$IMG" "$RDIR/disk-worker.qcow2" "$W_DISK"
  install -m 0600 -o "$RUSER" -g "$RUSER" /root/prace-rehearsal-upload/seed-worker.iso "$RDIR/seed-worker.iso"
fi

# The data disk: built from a root-only staging directory without mounting anything (mkfs -d).
st=$(mktemp -d /root/prace-rehearsal-stage.XXXXXX); trap 'rm -rf "$st" /root/prace-rehearsal-upload' EXIT
mkdir -p "$st/fleet-repo" "$st/extra-repo" "$st/k3s/images" "$st/backup"
cp -a --reflink=auto /srv/fleet-repo/packages /srv/fleet-repo/repodata /srv/fleet-repo/keys "$st/fleet-repo/"
for pkg in $EXTRA_PACKAGES; do
  nevra=$(rpm -q --qf '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' "$pkg") || { echo "refusing: $pkg is not installed on the login node"; exit 4; }
  dnf -q download --destdir "$st/extra-repo" "$nevra"
done
createrepo_c -q "$st/extra-repo"
cp -a /srv/fleet-repo/k3s/k3s /srv/fleet-repo/k3s/install.sh /srv/fleet-repo/k3s/k3s-airgap-images-amd64.tar.zst /srv/fleet-repo/k3s/k3s-selinux-*.rpm "$st/k3s/"
cp -a /srv/fleet-repo/k3s/images/*.tar "$st/k3s/images/"
for ref in $EXPORT_IMAGES; do
  k3s ctr -n k8s.io images ls -q | grep -xF "$ref" >/dev/null || { echo "refusing: pinned image $ref not present on the login node"; exit 4; }
  name=${ref##*/}; name=${name%@*}
  k3s ctr -n k8s.io images export --platform linux/amd64 "$st/k3s/images/$name.tar" "$ref"
done
cp -a "/root/prace-backup/$BACKUP.tgz" "$st/backup/"
[ "$E2E" = 1 ] && cp -a "/root/prace-backup/$BACKUP-home.tgz" "$st/backup/"
install -m 0755 /root/prace-rehearsal-upload/k3s-login-restore.sh "$st/k3s-login-restore.sh"
size=$(( $(du -sm "$st" | cut -f1) * 12 / 10 + 1024 ))
mkfs.ext4 -q -F -L prace-restore -d "$st" "$RDIR/data.img" "${size}M"
chown "$RUSER:" "$RDIR/data.img"; chmod 0600 "$RDIR/data.img"
echo "   data disk ${size} MiB: fleet repo + $(ls "$st/extra-repo"/*.rpm | wc -l) login-node package(s), K3s artifacts, $(ls "$st/k3s/images" | wc -l) image archives, backup$([ "$E2E" = 1 ] && echo ' + /home'), restore tool"
if [ "$E2E" = 1 ]; then
  # The worker's own disk: packages, K3s and the worker images only (no backup, no credentials).
  sw=$(mktemp -d /root/prace-rehearsal-stage-worker.XXXXXX); trap 'rm -rf "$st" "$sw" /root/prace-rehearsal-upload' EXIT
  mkdir -p "$sw/fleet-repo" "$sw/k3s/images"
  cp -a --reflink=auto /srv/fleet-repo/packages /srv/fleet-repo/repodata /srv/fleet-repo/keys "$sw/fleet-repo/"
  cp -a /srv/fleet-repo/k3s/k3s /srv/fleet-repo/k3s/install.sh /srv/fleet-repo/k3s/k3s-airgap-images-amd64.tar.zst /srv/fleet-repo/k3s/k3s-selinux-*.rpm "$sw/k3s/"
  cp -a /srv/fleet-repo/k3s/images/*.tar "$sw/k3s/images/"
  wsize=$(( $(du -sm "$sw" | cut -f1) * 12 / 10 + 512 ))
  mkfs.ext4 -q -F -L prace-worker -d "$sw" "$RDIR/data-worker.img" "${wsize}M"
  chown "$RUSER:" "$RDIR/data-worker.img"; chmod 0600 "$RDIR/data-worker.img"
  echo "   worker data disk ${wsize} MiB: fleet repo, K3s artifacts, $(ls "$sw/k3s/images" | wc -l) worker image archives (no backup)"
fi
REMOTE

}

stage_boot() {
STAGE=boot
T_BOOT=$(date +%s)
echo "== $(date +%T) boot (memory guard first)$([ "$E2E" = 1 ] && echo "; control and worker VM on a private UDP link")"
L RDIR="$RDIR" RUSER="$RUSER" VM_MIB="$VM_MIB" VM_CPUS="$VM_CPUS" PORT="$PORT" E2E="$E2E" W_MIB="$W_MIB" W_CPUS="$W_CPUS" \
  WPORT="$WPORT" LINK_A="$LINK_A" LINK_B="$LINK_B" CTL_MAC="$CTL_MAC" WRK_MAC="$WRK_MAC" bash -s <<'REMOTE'
set -euo pipefail
total=$VM_MIB; [ "$E2E" = 1 ] && total=$((VM_MIB + W_MIB))
/usr/local/sbin/prace-rehearsal-memguard "$total"
link=()
[ "$E2E" = 1 ] && link=(-netdev "dgram,id=link,local.type=inet,local.host=127.0.0.1,local.port=$LINK_A,remote.type=inet,remote.host=127.0.0.1,remote.port=$LINK_B"
                         -device "virtio-net-pci,netdev=link,mac=$CTL_MAC")
runuser -u "$RUSER" -- /usr/libexec/qemu-kvm -name prace-restore -machine q35,accel=kvm -cpu host \
  -smp "$VM_CPUS" -m "$VM_MIB" -nodefaults -display none \
  -drive file="$RDIR/disk.qcow2",if=virtio,format=qcow2 \
  -drive file="$RDIR/data.img",if=virtio,format=raw,readonly=on \
  -drive file="$RDIR/seed.iso",if=virtio,format=raw,readonly=on \
  -netdev user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:"$PORT"-:22 -device virtio-net-pci,netdev=n0 \
  "${link[@]}" \
  -serial file:"$RDIR/console.log" -daemonize -pidfile "$RDIR/qemu.pid"
echo "   control VM $(cat "$RDIR/qemu.pid") started"
if [ "$E2E" = 1 ]; then
  runuser -u "$RUSER" -- /usr/libexec/qemu-kvm -name prace-restore-worker -machine q35,accel=kvm -cpu host \
    -smp "$W_CPUS" -m "$W_MIB" -nodefaults -display none \
    -drive file="$RDIR/disk-worker.qcow2",if=virtio,format=qcow2 \
    -drive file="$RDIR/data-worker.img",if=virtio,format=raw,readonly=on \
    -drive file="$RDIR/seed-worker.iso",if=virtio,format=raw,readonly=on \
    -netdev user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:"$WPORT"-:22 -device virtio-net-pci,netdev=n0 \
    -netdev "dgram,id=link,local.type=inet,local.host=127.0.0.1,local.port=$LINK_B,remote.type=inet,remote.host=127.0.0.1,remote.port=$LINK_A" \
    -device "virtio-net-pci,netdev=link,mac=$WRK_MAC" \
    -serial file:"$RDIR/console-worker.log" -daemonize -pidfile "$RDIR/qemu-worker.pid"
  echo "   worker VM $(cat "$RDIR/qemu-worker.pid") started"
fi
REMOTE
trust_hostkey "$RDIR/console.log" V "$PORT" "control VM"
[ "$E2E" = 1 ] && trust_hostkey "$RDIR/console-worker.log" W "$WPORT" "worker VM"
return 0
}

# Trust a VM only when the ED25519 key ssh sees equals the one its console printed.
trust_hostkey() {   # trust_hostkey <console log> <ssh function> <port> <label>
  local console=$1 fn=$2 port=$3 label=$4 fp="" ok="" seen
  for _ in $(seq 60); do
    fp=$(L "tr -d '\r' < $console 2>/dev/null" | sed -n '/BEGIN SSH HOST KEY FINGERPRINTS/,/END SSH HOST KEY FINGERPRINTS/p' | grep -oE 'SHA256:[A-Za-z0-9+/]{43}[^(]*\(ED25519\)' | grep -oE 'SHA256:[A-Za-z0-9+/]{43}' || true)
    [ -n "$fp" ] && break; sleep 5
  done
  [ -n "$fp" ] || fail "no host key on the $label console after 300 s"
  # first contact records the key (ssh keeps the first -o value it sees, hence SHK), then compare
  for _ in $(seq 30); do SHK=accept-new $fn true 2>/dev/null && { ok=1; break; }; sleep 5; done
  [ -n "$ok" ] || fail "ssh to the $label failed"
  seen=$(ssh-keygen -l -F "[127.0.0.1]:$port" -f "$KEYDIR/known_hosts" | grep -oE 'SHA256:[A-Za-z0-9+/]{43}' | head -1)
  [ "$seen" = "$fp" ] || fail "HOST KEY MISMATCH on the $label: ssh saw ${seen:-nothing}, console printed $fp"
  echo "   $label: ssh host key = console host key ($fp)"
}

# The private link between the two VMs (e2e): addressed by MAC, then proven in both directions.
CTL_IF="" WRK_IF=""
link_up() {   # link_up <ssh function> <mac> <ip>: prints the interface name
  $1 MAC="$2" IP="$3" bash -s <<'REMOTE'
set -euo pipefail
cloud-init status --wait >/dev/null 2>&1 || true
IF=$(ip -o link | awk -v m="$MAC" 'tolower($0) ~ m {sub(":", "", $2); print $2}')
[ -n "$IF" ] || { echo "no interface with MAC $MAC" >&2; exit 1; }
nmcli -t con show link >/dev/null 2>&1 || nmcli -t con add type ethernet ifname "$IF" con-name link \
  ipv4.method manual ipv4.addresses "$IP/25" ipv6.method disabled >/dev/null
nmcli -t con up link >/dev/null
echo "$IF"
REMOTE
}
stage_link() {
  STAGE=link
  echo "== $(date +%T) private link: control $CTL_IP, worker $WRK_IP"
  CTL_IF=$(link_up V "$CTL_MAC" "$CTL_IP") || fail "control VM link setup failed"
  WRK_IF=$(link_up W "$WRK_MAC" "$WRK_IP") || fail "worker VM link setup failed"
  [ "$(V "ping -c 3 -W 2 $WRK_IP >/dev/null && echo UP")" = UP ] || fail "control VM cannot reach the worker over the link"
  [ "$(W "ping -c 3 -W 2 $CTL_IP >/dev/null && echo UP")" = UP ] || fail "worker VM cannot reach the control VM over the link"
  echo "   link up both ways (control $CTL_IF, worker $WRK_IF)"
}

# Isolation is asserted, not printed: every probe must answer BLOCKED. A connection, or a probe
# that cannot run, fails the run (and the VM is deleted: isolation was not proven).
ISOLATION_TARGETS="10.0.2.2:22 192.0.2.205:22 10.90.10.13:22 198.18.0.126:443 1.1.1.1:443"
isolation_probe() {   # isolation_probe <ssh function> <label>
  local fn=$1 label=$2 t out bad=""
  for t in $ISOLATION_TARGETS; do
    out=$($fn "timeout 5 bash -c '</dev/tcp/${t%:*}/${t#*:}' 2>/dev/null && echo REACHABLE || echo BLOCKED") \
      || fail "isolation probe from the $label to $t could not run"
    [ "$out" = BLOCKED ] || bad="$bad $t(${out:-no answer})"
  done
  [ -z "$bad" ] || fail "isolation: reachable or unknown from inside the $label:$bad"
  echo "   isolation ($label): all $(wc -w <<<"$ISOLATION_TARGETS") probes blocked (QEMU host, login node, fleet, BMC, internet)"
}
stage_isolation() {
  STAGE=isolation
  isolation_probe V "control VM"
  [ "$E2E" = 1 ] && isolation_probe W "worker VM"
  ISOLATED=1
}

# Listing of a home tree as "path uid gid mode kind size sha256", the same for the archive (on the
# login node) and the restored /home (in the VM): count and hash only, never content.
HOME_LISTING_PY='
import hashlib, os, stat, sys, tarfile
rows = []
if sys.argv[1] == "archive":
    with tarfile.open(sys.argv[2]) as t:
        for m in t.getmembers():
            kind = "d" if m.isdir() else "f" if m.isfile() else "o"
            dig = hashlib.sha256(t.extractfile(m).read()).hexdigest() if m.isfile() else "-"
            rows.append(f"/{m.name} {m.uid} {m.gid} {m.mode & 0o7777:o} {kind} {m.size if m.isfile() else 0} {dig}")
else:
    top = sys.argv[2] if len(sys.argv) > 2 else "/home"     # tests list a copy elsewhere
    for root, dirs, files in os.walk(top):
        for p in [root] + [os.path.join(root, f) for f in files]:
            st = os.lstat(p); kind = "d" if stat.S_ISDIR(st.st_mode) else "f" if stat.S_ISREG(st.st_mode) else "o"
            dig = hashlib.sha256(open(p, "rb").read()).hexdigest() if kind == "f" else "-"
            size = st.st_size if kind == "f" else 0
            rows.append(f"/home{p[len(top):]} {st.st_uid} {st.st_gid} {stat.S_IMODE(st.st_mode):o} {kind} {size} {dig}")
rows.sort()
print(len(rows), hashlib.sha256("\n".join(rows).encode()).hexdigest()[:16])
'

stage_restore() {
STAGE=restore
T_RESTORE=$(date +%s)
local iface=prace0 out
[ "$E2E" = 1 ] && iface=$CTL_IF
echo "== $(date +%T) restore (admin address on $iface)"
out=$(V BACKUP="$BACKUP" IFACE="$iface" E2E="$E2E" CTL_IP="$CTL_IP" HOME_LISTING_PY="$(printf %q "$HOME_LISTING_PY")" bash -s <<'REMOTE' 2>&1
set -euo pipefail
cloud-init status --wait >/dev/null || true
mkdir -p /mnt/restore; mountpoint -q /mnt/restore || mount -o ro LABEL=prace-restore /mnt/restore
if [ "$IFACE" = prace0 ]; then
  # The admin address on a dummy interface: the restored server's peers do not exist here.
  nmcli -t con show prace0 >/dev/null 2>&1 || nmcli -t con add type dummy ifname prace0 con-name prace0 \
    ipv4.method manual ipv4.addresses 10.90.10.1/25 ipv6.method disabled >/dev/null
  nmcli -t con up prace0 >/dev/null
fi
R=/mnt/restore/fleet-repo KEYS=/mnt/restore/fleet-repo/keys
dnf -y -q --disablerepo='*' --repofrompath=fleet,file://$R --repofrompath=extra,file:///mnt/restore/extra-repo \
  --setopt=fleet.gpgcheck=1 --setopt=extra.gpgcheck=1 --setopt=extra.gpgkey=file://$KEYS/RPM-GPG-KEY-Rocky-9 \
  --setopt=fleet.gpgkey=file://$KEYS/RPM-GPG-KEY-Rocky-9,file://$KEYS/RPM-GPG-KEY-EPEL-9,file://$KEYS/RPM-GPG-KEY-OpenHPC-3 \
  install mariadb-server container-selinux $([ "$E2E" = 1 ] && echo nfs-utils) >/dev/null
# roles/slinky: MariaDB listens on the private address only
printf '# Managed by Ansible (roles/slinky): slurmdbd runs in a pod and connects over the pod network.\n[mysqld]\nbind-address=10.90.10.1\n' > /etc/my.cnf.d/prace-slinky.cnf
systemctl enable -q mariadb
if [ "$E2E" = 1 ]; then
  # /home exactly as captured: the image's default user goes first, then the archive.
  if id rocky >/dev/null 2>&1; then userdel -r rocky; fi
  [ -z "$(ls -A /home)" ] || { echo "/home is not empty before the restore"; exit 1; }
  python3 - "/mnt/restore/backup/$BACKUP-home.tgz" <<'PY'
import os, sys, tarfile
bad = []
with tarfile.open(sys.argv[1]) as t:
    ms = t.getmembers()
    for m in ms:
        n = m.name
        if not (n == "home" or n.startswith("home/")) or ".." in n.split("/") or os.path.normpath(n) != n:
            bad.append(f"unsafe or outside /home: {n!r}")
        elif not (m.isfile() or m.isdir()):
            bad.append(f"link or special file (not allowed in the rehearsal): {n}")
    if bad:
        print("refusing:\n  " + "\n  ".join(bad)); sys.exit(4)
    kw = {"filter": "fully_trusted"} if hasattr(tarfile, "fully_trusted_filter") else {}
    t.extractall("/", members=ms, numeric_owner=True, **kw)
print(f"   /home restored: {len(ms)} members")
PY
  restorecon -R /home
  # listed before NFS or any pod can touch it
  echo "HOME-LISTING $(python3 -c "$HOME_LISTING_PY" restored)"
  echo '/home 10.90.10.0/25(rw,sync,root_squash,no_subtree_check)' > /etc/exports.d/fleet-home.exports
  systemctl enable -q --now nfs-server
  exportfs -ra
  echo "   /home exported to 10.90.10.0/25 (roles/nfs_home options)"
fi
bash /mnt/restore/k3s-login-restore.sh --archive "/mnt/restore/backup/$BACKUP.tgz" --artifacts /mnt/restore/k3s --flannel-iface "$IFACE"
REMOTE
) || { echo "$out"; fail "restore failed"; }
grep -v '^HOME-LISTING ' <<<"$out"
if [ "$E2E" = 1 ]; then
  STAGE=home
  local restored archive
  restored=$(grep '^HOME-LISTING ' <<<"$out" | cut -d' ' -f2-)
  archive=$(L "python3 -c $(printf %q "$HOME_LISTING_PY") archive /root/prace-backup/$BACKUP-home.tgz") || fail "archive listing failed"
  echo "   /home listing (entries, hash of path/owner/mode/content): archive $archive, restored ${restored:-none}"
  [ -n "$restored" ] && [ "$restored" = "$archive" ] || fail "restored /home differs from the home archive"
fi
return 0
}

# Usable = slurmctld answers and accounting answers, CONTROLLER_OK_NEEDED times in a row. The
# pod's HTTP readiness probe is reported but not required: in the isolated VM it flaps while
# slurmctld pings the absent workers.
CONTROLLER_TRIES=120 CONTROLLER_SLEEP=5 CONTROLLER_OK_NEEDED=3
stage_controller() {
  STAGE=controller
  echo "== $(date +%T) wait for the restored Slurm controller"
  local i ok=0 out=""
  for i in $(seq "$CONTROLLER_TRIES"); do
    out=$(V 'C="k3s kubectl -n slurm exec slurm-controller-0 -c slurmctld --"; $C scontrol ping | grep -q "is UP" && $C sacctmgr -n list cluster >/dev/null && echo USABLE' 2>/dev/null || true)
    if [ "$out" = USABLE ]; then ok=$((ok + 1)); [ "$ok" -ge "$CONTROLLER_OK_NEEDED" ] && break; else ok=0; fi
    sleep "$CONTROLLER_SLEEP"
  done
  [ "$ok" -ge "$CONTROLLER_OK_NEEDED" ] || fail "restored controller not usable after $((CONTROLLER_TRIES * CONTROLLER_SLEEP)) s"
  echo "   controller usable ($CONTROLLER_OK_NEEDED consecutive checks: slurmctld UP, accounting answers)"
  V 'k3s kubectl get nodes; k3s kubectl get pods -A -o wide | grep -v Completed' || fail "cluster listing failed"
}

# A fingerprint must be complete and well formed; an error or a missing line is a failure.
check_fingerprint() {   # check_fingerprint <file> <label>
  python3 - "$1" "$2" <<'PY'
import re, sys
path, label = sys.argv[1:3]
lines = open(path).read().splitlines()
need = {
    "node-password secret": r"node-password secret: secret/lab-dl380\.node-password\.k3s",
    "login host-key identity": r"login host-key secret: slurm/slurm-login-prace-ssh-host-keys uid=[0-9a-f-]{36} public=[0-9a-f]{64}",
    "mariadb password": r"mariadb-password secret = /root/slinky-db\.pw: match",
    "sacct": r"sacct jobs: [1-9][0-9]* last [0-9]+ [0-9a-f]{16}",
    "associations": r"associations: [1-9][0-9]* [0-9a-f]{16}",
    "slurm nodes": r"slurm nodes: NodeName=\S+( NodeName=\S+)*",
    "statesave": r"statesave files \(/\S+\): (\S+ )*job_state( \S+)*",
    "k3s journal": r"k3s journal \(current run\): 'newer than datastore' 0; 'password rejected' 0",
}
kinds = ["namespaces", "secrets", "configmaps", "serviceaccounts", "persistentvolumeclaims",
         "persistentvolumes", "helmcharts.helm.cattle.io", "controllers.slinky.slurm.net",
         "accountings.slinky.slurm.net", "nodesets.slinky.slurm.net", "loginsets.slinky.slurm.net"]
bad = [f"missing or malformed: {k}" for k, rx in need.items() if not any(re.fullmatch(rx, l) for l in lines)]
bad += [f"missing or empty: objects {k}" for k in kinds
        if not any(re.fullmatch(r"objects %s: [1-9][0-9]* [0-9a-f]{16}" % re.escape(k), l) for l in lines)]
if sum(l.startswith("login host-key secret: ") for l in lines) != 1:
    bad.append("login host-key identity must occur exactly once")
if not any(l.startswith("secret value ") for l in lines):
    bad.append("no secret value lines")
allowed = r"(login host-key secret|node-password secret|objects |secret value |mariadb-password|sacct jobs|info \(not compared\)|associations|slurm nodes|statesave files|k3s journal)"
bad += [f"unexpected line: {l[:100]!r}" for l in lines if not re.match(allowed, l)]
if bad:
    print(f"   {label} fingerprint rejected:\n     " + "\n     ".join(bad)); sys.exit(1)
PY
}

FP=$(cat <<'FPEOF'
set -euo pipefail
# Every command must succeed: a failure aborts with a non-zero status, and the harness fails.
K="k3s kubectl"; C="$K -n slurm exec slurm-controller-0 -c slurmctld --"
np=$($K -n kube-system get secret lab-dl380.node-password.k3s -o name)
echo "node-password secret: $np"
inv=$(systemctl show -p InvocationID --value k3s); [ -n "$inv" ]
J="journalctl -u k3s --no-pager _SYSTEMD_INVOCATION_ID=$inv"
kinds=$($K api-resources --api-group=slinky.slurm.net -o name | sort | paste -sd' ')
for kind in namespaces secrets configmaps serviceaccounts persistentvolumeclaims persistentvolumes helmcharts.helm.cattle.io $kinds; do
  n=$($K get "$kind" -A -o name | sort); c=$(grep -c . <<<"$n" || true)
  echo "objects $kind: $c $(sha256sum <<<"$n" | cut -c1-16)"
done
# This named Secret must survive the full datastore restore. Public key fingerprints
# alone do not hide a replacement with copied data: compare the Secret UID too.
$K -n slurm get secret slurm-login-prace-ssh-host-keys -o json | python3 -c '
import base64, hashlib, json, re, sys
s = json.load(sys.stdin); m = s["metadata"]; keys = []
assert m["namespace"] == "slurm" and m["name"] == "slurm-login-prace-ssh-host-keys"
assert re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", m["uid"])
for name, value in sorted(s.get("data", {}).items()):
    if not name.endswith(".pub"):
        continue
    assert name in ("ssh_host_ed25519_key.pub", "ssh_host_ecdsa_key.pub", "ssh_host_rsa_key.pub")
    key = base64.b64decode(value, validate=True).decode().split()
    assert len(key) >= 2 and key[0] in ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521")
    raw = base64.b64decode(key[1], validate=True)
    assert len(raw) > 4
    size = int.from_bytes(raw[:4], "big")
    assert raw[4:4+size].decode() == key[0] and len(raw) > 4+size
    keys.append(name + " " + key[0] + " " + key[1])
assert keys and any(k.startswith("ssh_host_ed25519_key.pub ssh-ed25519 ") for k in keys)
h = hashlib.sha256("\n".join(keys).encode()).hexdigest()
print("login host-key secret: slurm/slurm-login-prace-ssh-host-keys uid=%s public=%s" % (m["uid"], h))'
$K get secrets -A -o json | python3 -c '
import hashlib, json, sys
for s in sorted(json.load(sys.stdin)["items"], key=lambda s: (s["metadata"]["namespace"], s["metadata"]["name"])):
    h = hashlib.sha256(json.dumps(s.get("data", {}), sort_keys=True).encode()).hexdigest()[:16]
    m = s["metadata"]; print("secret value %s/%s: %s" % (m["namespace"], m["name"], h))'
db=$($K -n slurm get secret mariadb-password -o json | python3 -c 'import base64,hashlib,json,sys; d=json.load(sys.stdin)["data"]; print(hashlib.sha256(base64.b64decode(next(iter(d.values()))).strip()).hexdigest())')
pw=$(python3 -c 'import hashlib; print(hashlib.sha256(open("/root/slinky-db.pw","rb").read().strip()).hexdigest())')
[ "$db" = "$pw" ] && echo "mariadb-password secret = /root/slinky-db.pw: match" || echo "mariadb-password secret = /root/slinky-db.pw: MISMATCH"
# The one documented normalization: "CANCELLED by <uid>" is compared as "CANCELLED". A controller
# that starts from state saved shortly after a cancellation re-reports the job without the
# requesting UID (restore rehearsal, 28 Sep); the job, its state, nodes and times still compare.
raw=$($C sacct -a -X -n -P -S 2026-01-01 -E now -o JobID,State,NodeList)
j=$(sed -E 's/\|CANCELLED by [0-9]+\|/|CANCELLED|/' <<<"$raw" | sort -t'|' -k1,1n)
echo "sacct jobs: $(grep -c . <<<"$j" || true) last $(tail -1 <<<"$j" | cut -d'|' -f1) $(sha256sum <<<"$j" | cut -c1-16)"
echo "info (not compared): 'CANCELLED by <uid>' records normalized: $(grep -c 'CANCELLED by' <<<"$raw" || true)"
a=$($C sacctmgr -n -P list assoc format=cluster,account,user | sort)
echo "associations: $(grep -c . <<<"$a" || true) $(sha256sum <<<"$a" | cut -c1-16)"
nodes=$($C scontrol show node -o | grep -oE 'NodeName=[^ ]+' | sort | paste -sd' ')
echo "slurm nodes: $nodes"
ss=$($C scontrol show config | awk -F'= ' '/^StateSaveLocation/{print $2}'); [ -n "$ss" ]
files=$($C bash -c "cd $ss && ls | grep -vE '\.old$|^(heartbeat|clustername)$' | sort | paste -sd' '")
echo "statesave files ($ss): $files"
nd=$($J | grep -c 'newer than datastore' || true); pr=$($J | grep -ci 'password rejected' || true)
echo "k3s journal (current run): 'newer than datastore' $nd; 'password rejected' $pr"
FPEOF
)

stage_verify() {
  STAGE=verify
  echo "== $(date +%T) verify: the same fingerprint script on the live login node and in the restored VM"
  L 'bash -s' <<<"$FP" > "$OUT/fingerprint-live.txt" 2>&1 || fail "fingerprint of the live login node failed (see fingerprint-live.txt)"
  V 'bash -s' <<<"$FP" > "$OUT/fingerprint-restored.txt" 2>&1 || fail "fingerprint of the restored VM failed (see fingerprint-restored.txt)"
  check_fingerprint "$OUT/fingerprint-live.txt" live || fail "live fingerprint incomplete"
  check_fingerprint "$OUT/fingerprint-restored.txt" restored || fail "restored fingerprint incomplete"
  # Compare everything except 'info (not compared)' lines, then withhold the per-secret hashes.
  local rc=0
  diff <(grep -v '^info (not compared)' "$OUT/fingerprint-live.txt") <(grep -v '^info (not compared)' "$OUT/fingerprint-restored.txt") > "$OUT/fingerprint.diff" || rc=$?
  python3 - "$OUT/fingerprint-live.txt" "$OUT/fingerprint-restored.txt" <<'PY'
import sys
a, b = (open(f).read().splitlines() for f in sys.argv[1:3])
sec = lambda ls: {l.rsplit(":", 1)[0]: l for l in ls if l.startswith("secret value ")}
A, B = sec(a), sec(b)
for f, ls in zip(sys.argv[1:3], (a, b)):
    out = [(l.rsplit(":", 1)[0] + (": value identical live/restored (hash withheld)" if A.get(l.rsplit(":", 1)[0]) == B.get(l.rsplit(":", 1)[0]) else ": value DIFFERS (hash withheld)"))
           if l.startswith("secret value ") else l for l in ls]
    open(f, "w").write("\n".join(out) + "\n")
PY
  if [ "$rc" = 0 ]; then
    echo "   fingerprints identical ($(grep -vc '^info (not compared)' "$OUT/fingerprint-live.txt") compared lines)"
  else
    : > "$OUT/fingerprint.diff.withheld"; grep -v '^[<>] secret value ' "$OUT/fingerprint.diff" > "$OUT/fingerprint.diff.withheld" || true
    mv "$OUT/fingerprint.diff.withheld" "$OUT/fingerprint.diff"
    sed 's/^/   /' "$OUT/fingerprint.diff"; fail "live and restored fingerprints differ (see fingerprint.diff and the secret lines)"
  fi
  grep '^info (not compared)' "$OUT/fingerprint-restored.txt" | sed 's/^/   restored /' || true
  grep '^info (not compared)' "$OUT/fingerprint-live.txt" | sed 's/^/   live /' || true

  stage_reopen

  STAGE=job-counter
  local last next
  last=$(awk '/^sacct jobs:/{print $5}' "$OUT/fingerprint-live.txt")
  [[ $last =~ ^[0-9]+$ ]] || fail "no last job ID in the live fingerprint"
  next=$(V "k3s kubectl -n slurm exec slurm-controller-0 -c slurmctld -- sbatch --parsable --hold -p cpu -N1 --chdir=/tmp -o /dev/null --wrap true" 2>&1 | tail -1) \
    || fail "held job submission failed: $next"
  [[ $next =~ ^[0-9]+$ ]] || fail "held job submission returned no job ID: $next"
  V "k3s kubectl -n slurm exec slurm-controller-0 -c slurmctld -- scancel $next" >/dev/null || fail "could not cancel held job $next"
  echo "   job id counter (controller state): live last job $last; restored controller issued $next (held, in the VM only, cancelled)"
  [ "$next" = $((last + 1)) ] || fail "job id counter not restored: expected $((last + 1)), got $next"
  HELD_JOB=$next
  echo "   job id counter restored: PASS"
}

# A backup taken inside the maintenance window (tools/k3s-login-backup.sh) captured whatever the
# window fenced: drained partitions and login sets scaled to zero. Reopen both to the recorded
# pre-fence states and prove each one is back before any login or job. On 28 Sep the restored
# LoginSet came back with 0 replicas; slurmctld itself took its partition states from the
# configuration (UP), so the partition step can be a no-op. An archive without the record is left
# as captured.
REOPEN_TRIES=30 REOPEN_SLEEP=5      # the Slinky webhook may refuse patches for a while after start
stage_reopen() {
  STAGE=reopen
  local w parts sets kv now out C='k3s kubectl -n slurm exec slurm-controller-0 -c slurmctld --'
  w=$(V 'f=/var/lib/prace-restore/maintenance-window.txt; if [ -f $f ]; then cat $f; else echo NO-RECORD; fi') \
    || fail "could not read the maintenance-window record"
  if [ "$w" = NO-RECORD ]; then echo "   no maintenance-window record (older backup): partitions as captured"; return 0; fi
  sets=$(grep -oE 'loginsets-before-fence=[^ ]*' <<<"$w" | cut -d= -f2- | tr ',' ' ')
  for kv in $sets; do
    out=$(wait_for "$REOPEN_TRIES" "$REOPEN_SLEEP" OK V "k3s kubectl -n slurm patch loginset ${kv%%=*} --type merge -p '{\"spec\":{\"replicas\":${kv#*=}}}' >/dev/null && echo OK") \
      || fail "could not reopen loginset ${kv%%=*} (last: $out)"
    [ "$(V "k3s kubectl -n slurm get loginset ${kv%%=*} -o jsonpath='{.spec.replicas}'")" = "${kv#*=}" ] || fail "loginset ${kv%%=*} is not back to ${kv#*=} replica(s)"
  done
  [ -z "$sets" ] || echo "   login sets reopened to their pre-fence replicas: $sets"
  parts=$(grep -oE 'partitions-before-fence=[^ ]+' <<<"$w" | cut -d= -f2- | tr ',' ' ')
  [ -n "$parts" ] || fail "the maintenance-window record has no partition states"
  now=$(V "$C scontrol show partition -o") || fail "partition query failed"
  echo "   partitions as restored: $(grep -oE 'PartitionName=[^ ]+|State=[^ ]+' <<<"$now" | paste -d' ' - - | sed -E 's/PartitionName=| State//g' | paste -sd' ')"
  for kv in $parts; do
    V "$C scontrol update PartitionName=${kv%%=*} State=${kv#*=}" || fail "could not reopen partition ${kv%%=*}"
  done
  now=$(V "$C scontrol show partition -o") || fail "partition query failed"
  for kv in $parts; do
    grep -qE "PartitionName=${kv%%=*} .*State=${kv#*=}( |$)" <<<"$now" || fail "partition ${kv%%=*} is not back to ${kv#*=}"
  done
  echo "   partitions reopened to their pre-fence states: $parts"
}

# --- end to end (--e2e) ------------------------------------------------------------------------
KC='k3s kubectl'; CTL='k3s kubectl -n slurm exec slurm-controller-0 -c slurmctld --'
wait_for() {   # wait_for <tries> <sleep> <expected> <ssh function> <command>: last output on failure
  local tries=$1 pause=$2 want=$3 fn=$4 cmd=$5 i out=""
  for i in $(seq "$tries"); do out=$($fn "$cmd" 2>/dev/null || true); [ "$out" = "$want" ] && return 0; sleep "$pause"; done
  echo "${out:-no answer}"; return 1
}

stage_login() {
  STAGE=login
  echo "== $(date +%T) restored login pod: NFS /home, identities, syn-probe by key (production host key)"
  local out
  out=$(wait_for 120 5 true V "$KC -n slurm get pods -l app.kubernetes.io/name=login -o jsonpath='{.items[*].status.containerStatuses[*].ready}'") \
    || fail "restored login pod not ready after 600 s (last: $out)"
  V true || fail "control VM connection lost"     # the pod path rides on this connection
  out=$(POD 'echo "user $(id -un) $(id -u) on $(hostname)"; stat -c "perm %n %U %a" ~ ~/.ssh ~/.ssh/authorized_keys; getent passwd syn-revoked >/dev/null && echo "revoked PRESENT" || echo "revoked absent"') \
    || fail "ssh as syn-probe into the restored login pod failed (key, restored authorized_keys or production host key)"
  sed 's/^/   /' <<<"$out"
  grep -qx "user syn-probe 30091 on .*" <<<"$out" || fail "unexpected identity in the restored login pod"
  grep -qx "perm /home/syn-probe/.ssh/authorized_keys syn-probe 600" <<<"$out" || fail "restored authorized_keys has the wrong owner or mode"
  grep -qx "revoked absent" <<<"$out" || fail "a revoked account is known in the restored login pod"
  echo "   login: key accepted from the restored /home; host key = production entry; revoked account absent"
}

stage_worker() {
  STAGE=worker
  echo "== $(date +%T) worker $WRK_NAME joins the restored cluster (cpu NodeSet resized to a rehearsal budget)"
  local out
  out=$(wait_for 30 5 OK V "$KC -n slurm patch nodeset slurm-worker-cpu --type merge -p '{\"spec\":{\"slurmd\":{\"resources\":$WRK_BUDGET}}}' >/dev/null && echo OK") \
    || fail "could not resize the restored cpu NodeSet (last: $out)"
  # The restored agent token goes from the control VM to the worker through this pipe only.
  V 'cat /var/lib/rancher/k3s/server/agent-token' \
    | W 'umask 077; mkdir -p /etc/rancher/k3s; cat > /etc/rancher/k3s/agent-token; test -s /etc/rancher/k3s/agent-token' \
    || fail "agent token transfer failed"
  out=$(W WRK_NAME="$WRK_NAME" WRK_IP="$WRK_IP" CTL_IP="$CTL_IP" WIF="$WRK_IF" bash -s <<'REMOTE' 2>&1
set -euo pipefail
mkdir -p /mnt/worker; mountpoint -q /mnt/worker || mount -o ro LABEL=prace-worker /mnt/worker
R=/mnt/worker/fleet-repo KEYS=/mnt/worker/fleet-repo/keys
dnf -y -q --disablerepo='*' --repofrompath=fleet,file://$R --setopt=fleet.gpgcheck=1 \
  --setopt=fleet.gpgkey=file://$KEYS/RPM-GPG-KEY-Rocky-9,file://$KEYS/RPM-GPG-KEY-EPEL-9,file://$KEYS/RPM-GPG-KEY-OpenHPC-3 \
  install container-selinux nfs-utils >/dev/null
dnf -y -q --disablerepo='*' install --nogpgcheck /mnt/worker/k3s/k3s-selinux-*.rpm >/dev/null
install -m 0755 /mnt/worker/k3s/k3s /usr/local/bin/k3s
mkdir -p /var/lib/rancher/k3s/agent/images
cp /mnt/worker/k3s/k3s-airgap-images-amd64.tar.zst /mnt/worker/k3s/images/*.tar /var/lib/rancher/k3s/agent/images/
# roles/k3s config-agent.yaml.j2 with the rehearsal worker's identity
cat > /etc/rancher/k3s/config.yaml <<EOF
server: https://$CTL_IP:6443
token-file: /etc/rancher/k3s/agent-token
node-name: $WRK_NAME
node-ip: $WRK_IP
flannel-iface: $WIF
selinux: true
node-label:
  - prace.fleet/role=cpu
node-taint:
  - slinky.slurm.net/slurm=:NoExecute
kubelet-arg:
  - system-reserved=cpu=2,memory=4Gi
kube-proxy-arg:
  - nodeport-addresses=10.90.10.0/25
EOF
chmod 600 /etc/rancher/k3s/config.yaml
restorecon -R /usr/local/bin/k3s /var/lib/rancher /etc/rancher
INSTALL_K3S_SKIP_DOWNLOAD=true INSTALL_K3S_SKIP_SELINUX_RPM=true INSTALL_K3S_EXEC=agent sh /mnt/worker/k3s/install.sh >/dev/null
echo "   K3s agent installed and started"
REMOTE
) || { echo "$out"; fail "worker setup failed"; }
  echo "$out"
  out=$(wait_for 60 5 True V "$KC get node $WRK_NAME -o jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}'") \
    || fail "$WRK_NAME not Ready after 300 s (last: $out)"
  # the pod's Ready condition: the log sidecar is a native sidecar (an init container), so
  # containerStatuses lists slurmd alone
  out=$(wait_for 120 5 True V "$KC -n slurm get pods -l app.kubernetes.io/name=slurmd --field-selector spec.nodeName=$WRK_NAME -o jsonpath='{.items[*].status.conditions[?(@.type==\"Ready\")].status}'") \
    || fail "no ready slurmd pod on $WRK_NAME after 600 s (last: $out)"
  out=$(wait_for 60 5 IDLE V "$CTL scontrol show node $WRK_NAME -o | grep -oE 'State=[A-Z]+' | cut -d= -f2") \
    || fail "Slurm node $WRK_NAME not idle after 300 s (last: $out)"
  echo "   $WRK_NAME: Kubernetes Ready, slurmd pod ready, Slurm IDLE"
}

stage_job() {
  STAGE=job
  echo "== $(date +%T) job as syn-probe, pinned to $WRK_NAME, output to the restored /home"
  local j st acct o
  j=$(POD "sbatch --parsable -A proj-ops -p cpu -w $WRK_NAME -t 5 -n 1 -o /home/syn-probe/e2e-restore-%j.out --wrap 'echo \$(hostname) \$(id -un) restored-home-ok'" | tr -d '\r') \
    || fail "sbatch as syn-probe failed: $j"
  [[ $j =~ ^[0-9]+$ ]] || fail "no job ID from sbatch: $j"
  local i
  for i in $(seq 100); do       # up to 300 s, stopping at the first terminal state
    st=$(V "$CTL sacct -n -X -j $j -o State%20 | tr -d ' ' | head -1" 2>/dev/null || true)
    case $st in COMPLETED|FAILED|CANCELLED*|TIMEOUT|OUT_OF_ME*|NODE_FAIL|BOOT_FAIL|DEADLINE|PREEMPTED) break ;; esac
    sleep 3
  done
  [ "$st" = COMPLETED ] || fail "job $j did not complete (state: ${st:-unknown})"
  acct=$(V "$CTL sacct -n -X -P -j $j -o JobID,User,State,NodeList") || fail "accounting query failed"
  o=$(V "cat /home/syn-probe/e2e-restore-$j.out") || fail "job output missing from the restored /home"
  echo "   job $j: accounting '$acct'; output '$o'"
  [ "$acct" = "$j|syn-probe|COMPLETED|$WRK_NAME" ] || fail "accounting record differs from the expected '$j|syn-probe|COMPLETED|$WRK_NAME'"
  [ "$o" = "$WRK_NAME syn-probe restored-home-ok" ] || fail "unexpected job output"
  [ -n "${HELD_JOB:-}" ] && [ "$j" = $((HELD_JOB + 1)) ] || fail "job ID $j does not continue the restored counter (held job ${HELD_JOB:-?})"
  local now; now=$(date +%s)
  echo "   job ID continues the restored counter ($HELD_JOB held, $j ran)"
  echo "   recovery time: $(( (now - T_BOOT) / 60 )) min from VM boot, $(( (now - T_RESTORE) / 60 )) min from the start of the restore to a completed user job"
}

main() {
  cmd=${1:-}; shift || true
  BACKUP="" OUT=""
  while [ $# -gt 0 ]; do
    case $1 in --backup) BACKUP=$2; shift 2 ;; --out) OUT=$2; shift 2 ;; --hold-on-failure) HOLD=1; shift ;; --e2e) E2E=1; shift ;;
      *) echo "unknown argument: $1" >&2; exit 2 ;; esac
  done
  case $cmd in
    run) [ -n "$BACKUP" ] || { echo "usage: $0 run [--e2e] --backup NAME [--out DIR] [--hold-on-failure] | $0 cleanup" >&2; exit 2; } ;;
    cleanup) ;;
    *) echo "usage: $0 run [--e2e] --backup NAME [--out DIR] [--hold-on-failure] | $0 cleanup" >&2; exit 2 ;;
  esac
  OUT=${OUT:-$PWD/restore-rehearsal-$(date +%Y%m%d-%H%M)}
  mkdir -p -m 700 "$KEYDIR" "$MUX"
  if [ "$cmd" = cleanup ]; then cleanup; exit 0; fi
  mkdir -p "$OUT"; exec > >(tee -a "$OUT/run.txt") 2>&1
  trap on_exit EXIT
  stage_prepare
  stage_boot
  if [ "$E2E" = 1 ]; then stage_link; fi     # isolation is proven with the link up
  stage_isolation
  stage_restore
  stage_controller
  stage_verify
  if [ "$E2E" = 1 ]; then
    stage_login
    stage_worker
    stage_job
  fi
  STAGE=done
  echo "RESULT: PASS ($(date +%T)); evidence in $OUT. Run '$0 cleanup' to delete the VM and its disks."
}

# Tests source this file for its functions (tools/test-restore-rehearsal.py); run main only when executed.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi

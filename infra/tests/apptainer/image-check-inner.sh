#!/bin/bash
# Inside the pinned slurmd image, as root, no network (image-check.sh starts it). /rpms, /archive.tar
# and /infra read-only; /out/render from the host; results in /out/results.txt. Builds the tree in
# the container's own /apps (as the login node's role would), never in /out.
set -uo pipefail
. /out/render/vars.sh
R=/out/results.txt
: > "$R"
check() { if [ "$2" = 0 ]; then echo "PASS: $1" | tee -a "$R"; else echo "FAIL: $1 ${3:-}" | tee -a "$R"; fi; }
info() { echo "INFO: $*" | tee -a "$R"; }
mkdir -p /apps/sw/apptainer "$modulefiles/apptainer" /apps/containers /var/lib/prace-apps
cp /out/render/manifest.sha256 "/var/lib/prace-apps/apptainer-$version.sha256"
unpack() { bash /infra/roles/apps_env/files/prace-apps-unpack.sh "$tree" /rpms "/var/lib/prace-apps/apptainer-$version.sha256"; }

# --- the unpack (roles/apps_env's helper): once, then unchanged
out=$(unpack 2>&1); check "unpack: the pinned set unpacked ($out)" "$([ "$out" = unpacked ] && echo 0 || echo 1)"
out=$(unpack 2>&1); check "unpack: a rerun is unchanged ($out)" "$([ "$out" = unchanged ] && echo 0 || echo 1)"
s=$(find "$tree" -xdev -perm /6000 -print); check "tree: no setuid or setgid file" "$([ -z "$s" ] && echo 0 || echo 1)" "$s"
caps=$(find "$tree" -xdev -type f -exec getfattr -n security.capability --absolute-names {} + 2>/dev/null | grep -c '^# file' || true)
check "tree: no file capabilities (unpacked with tar, without xattrs)" "$([ "$caps" = 0 ] && echo 0 || echo 1)" "$caps"

# --- the site layer, as tasks/tree.yml makes it
for d in prace/bin usr/etc/apptainer usr/etc/apptainer/seccomp-profiles usr/var/lib/apptainer/mnt/session; do install -d -m 0755 "$tree/$d"; done
for f in $conf_files; do install -m 0644 "$tree/etc/apptainer/$f" "$tree/usr/etc/apptainer/$f"; done
install -m 0644 /out/render/apptainer.conf "$tree/usr/etc/apptainer/apptainer.conf"
install -m 0755 /out/render/libexec-wrapper "$tree/usr/libexec/apptainer/bin/.wrapper"
L=/infra/roles/apptainer/files/prace-apptainer-layout.sh
out=$(bash "$L" "$tree" 2>&1); check "layout: the helpers moved behind the wrapper ($out)" "$([ "$out" = changed ] && echo 0 || echo 1)"
out=$(bash "$L" "$tree" 2>&1); check "layout: a rerun is unchanged ($out)" "$([ "$out" = unchanged ] && echo 0 || echo 1)"
n=$(find "$tree/usr/libexec/apptainer/bin" -mindepth 1 -maxdepth 1 ! -name .wrapper ! -lname .wrapper | wc -l)
check "layout: every helper name is a link to .wrapper ($n others)" "$([ "$n" = 0 ] && echo 0 || echo 1)"
install -m 0755 /out/render/apptainer "$tree/prace/bin/apptainer"
ap=$tree/prace/bin/apptainer

v=$("$ap" version 2>&1); check "wrapper: apptainer version is $version ($v)" "$([ "$v" = "$version" ] && echo 0 || echo 1)"
cfg=$("$ap" buildcfg 2>&1)
want() { grep -qx "$1" <<< "$cfg"; }
want "APPTAINER_CONF_FILE=$tree/usr/etc/apptainer/apptainer.conf"; check "relocated: configuration in the tree's usr/etc" $?
want "LIBEXECDIR=$tree/usr/libexec"; check "relocated: helpers in the tree" $?
want "APPTAINER_SUID_INSTALL=0"; check "relocated: not a setuid installation" $?
sd=$(sed -n 's/^SESSIONDIR=//p' <<< "$cfg"); check "relocated: the session directory exists ($sd)" "$([ -d "$sd" ] && [ "${sd#$tree/}" != "$sd" ] && echo 0 || echo 1)"

# every directive of the rendered apptainer.conf, as the binary itself reads it (bind path: all of them)
bad=""
while IFS= read -r line; do
  case $line in ''|'#'*) continue ;; esac
  key=${line%% =*} val=${line#*= }
  [ "$key" = "bind path" ] && continue
  got=$("$ap" config global --get "$key" 2>&1)
  [ "$got" = "$val" ] || bad="$bad [$key: want '$val', read '$got']"
done < /out/render/apptainer.conf
check "apptainer.conf: every directive read back by Apptainer as written" "$([ -z "$bad" ] && echo 0 || echo 1)" "$bad"
binds=$("$ap" config global --get "bind path" 2>&1)
check "apptainer.conf: bind path is /etc/localtime,/etc/hosts only ($binds)" "$([ "$binds" = "/etc/localtime,/etc/hosts" ] && echo 0 || echo 1)"
v=$("$ap" config global --get "allow setuid" 2>&1); check "apptainer.conf: allow setuid = no ($v)" "$([ "$v" = no ] && echo 0 || echo 1)"

# every ELF in the tree resolves its libraries with the wrapper's library path, and not without it
miss=""
for f in $(find "$tree" -xdev -type f \( -perm -u+x -o -name '*.so*' \)); do
  [ "$(head -c 4 "$f" | od -An -tx1 | tr -d ' \n')" = 7f454c46 ] || continue
  m=$(LD_LIBRARY_PATH=$tree/usr/lib64 ldd "$f" 2>&1 | grep 'not found' | tr -d '\t' | tr '\n' ' ')
  [ -z "$m" ] || miss="$miss ${f#$tree}: $m"
done
check "libraries: every program in the tree resolves with the tree's lib64" "$([ -z "$miss" ] && echo 0 || echo 1)" "$miss"
m=$(ldd "$tree/usr/bin/apptainer" | grep -c 'not found'); check "libraries: without the wrapper the image lacks some (so the wrapper is needed: $m missing)" "$([ "$m" -gt 0 ] && echo 0 || echo 1)"

# --- the probe image, as root: built, unchanged, a changed one refused
P=/infra/roles/apptainer/files/prace-apptainer-probe.sh
rm -rf /root/.apptainer      # left by the root commands above (config global --get), not by the build
out=$(HOME=/root bash "$P" "$ap" /archive.tar "$digest" "$probe" 2>&1); rc=$?
check "probe: built from the archive ($rc: $(tail -3 <<< "$out" | tr '\n' ' '))" "$([ $rc = 0 ] && [ "$(tail -1 <<< "$out")" = built ] && echo 0 || echo 1)"
check "probe: nothing left in root's home" "$([ ! -e /root/.apptainer ] && echo 0 || echo 1)" "$(find /root/.apptainer 2>/dev/null | head -5 | tr '\n' ' ')"
(cd /apps/containers && sha256sum --check --status prace-probe.sif.sha256); check "probe: its sha256 file matches" $?
id=$("$ap" sif list "$probe" 2>/dev/null | awk '/Squashfs/ {print $1; exit}')
"$ap" sif dump "$id" "$probe" > /tmp/probe.squashfs 2>/dev/null
ls=$("$tree/usr/libexec/apptainer/bin/unsquashfs" -lls /tmp/probe.squashfs 2>&1)
grep -Eq '^-rwsr-xr-x root/root +142 .* squashfs-root/prace-euid-probe$' <<< "$ls"; check "probe: /prace-euid-probe is setuid root in the image, 142 bytes" $? "$(grep prace- <<< "$ls")"
"$tree/usr/libexec/apptainer/bin/unsquashfs" -q -d /tmp/probe-x /tmp/probe.squashfs /prace-euid-probe >/dev/null 2>&1
s=$(sha256sum < /tmp/probe-x/prace-euid-probe); s=${s%% *}
check "probe: its euid probe is the pinned program" "$([ "$s" = 0c364be2754df3fcd076af068e4c2be3597eac0d615c9526de36e4c4fc8fca56 ] && echo 0 || echo 1)" "$s"
setpriv --reuid=65534 --regid=65534 --clear-groups /tmp/probe-x/prace-euid-probe; rc=$?
check "probe: as root's copy run by nobody where setuid works (no nosuid, no user namespace) it is root: exit 0 (positive control)" "$([ $rc = 0 ] && echo 0 || echo 1)" "exit $rc"
grep -q 'squashfs-root/prace-probe-source$' <<< "$ls"; check "probe: /prace-probe-source is in the image" $?
grep -q "^digest=$digest$" "$probe.source"; check "probe: $probe.source names the pinned digest" $?
out=$(bash "$P" "$ap" /archive.tar "$digest" "$probe" 2>&1); check "probe: a rerun is unchanged ($out)" "$([ "$out" = unchanged ] && echo 0 || echo 1)"
before=$(sha256sum < "$probe"); printf x >> "$probe"
bash "$P" "$ap" /archive.tar "$digest" "$probe" >/dev/null 2>&1; rc=$?
check "probe: a changed image is refused (exit $rc), never replaced" "$([ $rc = 3 ] && [ "$(head -c -1 "$probe" | sha256sum)" = "$before" ] && echo 0 || echo 1)"
truncate -s -1 "$probe"
other=sha256:$(printf '%064d' 0)
rm -rf /tmp/p2 && mkdir /tmp/p2
bash "$P" "$ap" /archive.tar "$other" /tmp/p2/x.sif >/dev/null 2>&1; rc=$?
check "probe: an archive that does not carry the digest is refused (exit $rc) before anything is written" "$([ $rc = 2 ] && [ -z "$(ls -A /tmp/p2)" ] && echo 0 || echo 1)"

# --- the module with the image's real Lmod, as a non-root user (a job's view)
install -m 0644 /out/render/module.lua "$modulefiles/apptainer/$module.lua"
useradd -u 30001 -M -d /tmp/u30001 syn-alice 2>/dev/null; mkdir -p /tmp/u30001 && chown 30001 /tmp/u30001
as() { setpriv --reuid=30001 --regid=30001 --clear-groups env -i HOME=/tmp/u30001 PATH=/usr/bin:/bin bash -lc "$1" 2>&1; }
out=$(as "module use $modulefiles; module load apptainer/$module && command -v apptainer && echo \"LD=\${LD_LIBRARY_PATH:-}\" && apptainer version")
grep -qx "$ap" <<< "$out" && grep -qx "$version" <<< "$out" && ! grep -q "LD=.*$tree" <<< "$out"
check "module: apptainer/$module puts the wrapper first, runs, and leaves the shell's library path alone" $? "$out"
out=$(as "module use $modulefiles; module -t avail 2>&1"); grep -qx "apptainer/$module" <<< "$out"; check "module: listed by module avail" $? "$out"
mv "$tree" "$tree.away"
out=$(as "module use $modulefiles; module load apptainer/$module; echo rc=\$?"); mv "$tree.away" "$tree"
grep -q "is missing here" <<< "$out" && grep -q "rc=1" <<< "$out"; check "module: refuses with its message when the tree is absent" $? "$out"

# --- a container as a non-root user: needs unprivileged user namespaces, restricted on this workstation
out=$(as "$ap exec $probe /bin/busybox id -u" | tail -2 | tr '\n' ' ')
info "non-root exec here (not a result; the live acceptance runs it): $out"
info "user.max_user_namespaces here: $(cat /proc/sys/user/max_user_namespaces)"
echo "done"

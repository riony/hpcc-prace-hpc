#!/usr/bin/env bash
# Restore the login node's cluster CONTROL STATE (T73) from a k3s-login-backup.sh archive onto an
# EMPTY target: a rebuilt login node, or the isolated restore-rehearsal VM. Runs on the target as
# root.
#
#   k3s-login-restore.sh --archive k3s-login-….tgz --artifacts DIR [--flannel-iface IFACE]
#
# DIR is laid out like /srv/fleet-repo/k3s: k3s, install.sh, k3s-airgap-images-amd64.tar.zst,
# k3s-selinux-*.rpm, plus images/*.tar (the Slinky images, exported by digest). Before this runs,
# the target needs its admin address, container-selinux, and mariadb-server with the role's
# configuration (roles/host_base and roles/slinky, or the rehearsal harness).
#
# Steps:
#   1. refuses unless the target is empty: no K3s service, state or config, and no accounting
#      database. A failed query or service start is an unknown state and also refuses;
#   2. checks the whole archive before writing anything: member names (no absolute or ".."
#      paths, no duplicates), links (targets inside the backed-up paths with no ".." and no
#      chains; nothing written through a link; hard links only to earlier files), no devices,
#      and a token record listing exactly the server and agent tokens with valid digests. It
#      compares those digests with the archive's own token bytes, then extracts with numeric
#      owners and the recorded modes;
#   3. re-checks the restored tokens on disk;
#   4. restores the accounting database and its client account. The password comes from the
#      restored file and reaches mysql on stdin, never in argv or output;
#   5. installs K3s from the artifacts (air-gapped: images are imported at start), starts the
#      server on the restored datastore and waits for the API.
#
# --flannel-iface replaces the interface name in the restored config.yaml. Use it only on a
# target whose NIC differs from the backed-up host's (the rehearsal VM). On a real login node,
# run fleet.yml afterwards; it converges the restored host. Prints no secret.
set -euo pipefail

ARCHIVE="" ART="" IFACE=""
DB_CLIENT_HOST=${PRACE_DB_CLIENT_HOST:-10.42.%}   # roles/slinky slinky_db_client_host
while [ $# -gt 0 ]; do
  case $1 in
    --archive) ARCHIVE=$2; shift 2 ;;
    --artifacts) ART=$2; shift 2 ;;
    --flannel-iface) IFACE=$2; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$ARCHIVE" ] && [ -n "$ART" ] || { echo "usage: $0 --archive FILE --artifacts DIR [--flannel-iface IFACE]" >&2; exit 2; }
ROOT=${PRACE_RESTORE_ROOT:-/}                     # overridable for the offline tests only
[ "$ROOT" = / ] && [ "$(id -u)" != 0 ] && { echo "run as root" >&2; exit 2; }
for f in "$ARCHIVE" "$ART/k3s" "$ART/install.sh" "$ART/k3s-airgap-images-amd64.tar.zst"; do
  [ -f "$f" ] || { echo "missing: $f" >&2; exit 2; }
done

echo "== $(date +%T) 1. the target must be empty (an unknown state is a refusal)"
# PRACE_RESTORE_CHECK_SERVICES=1 runs these service checks against stub tools in the offline tests.
if [ "$ROOT" = / ] || [ -n "${PRACE_RESTORE_CHECK_SERVICES:-}" ]; then
  systemctl is-active -q k3s && { echo "refusing: k3s is running here"; exit 3; }
  command -v mysql >/dev/null || { echo "refusing: mariadb-server is not installed (roles/slinky prerequisite)"; exit 3; }
  systemctl start mariadb || { echo "refusing: mariadb did not start, so the database state is unknown"; exit 3; }
  if ! dbs=$(mysql -N -e "SHOW DATABASES LIKE 'slurm_acct_db'"); then
    echo "refusing: the database query failed, so an empty target cannot be established"; exit 3
  fi
  [ -z "$dbs" ] || { echo "refusing: slurm_acct_db already exists"; exit 3; }
fi
for p in var/lib/rancher/k3s/server etc/rancher/k3s/config.yaml var/lib/rancher/k3s/storage etc/rancher/node root/slinky-db.pw; do
  [ ! -e "$ROOT/$p" ] && [ ! -L "$ROOT/$p" ] || { echo "refusing: /$p already exists"; exit 3; }
done
echo "   empty: no K3s state or config, no accounting database"

echo "== $(date +%T) 2. archive checked completely (structure, links, token records) before anything is written"
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
python3 - "$ARCHIVE" "$ROOT" "$work" <<'PY'
import hashlib, os, re, sys, tarfile
archive, root, work = sys.argv[1:4]
ALLOWED = ("var/lib/rancher/k3s/server", "var/lib/rancher/k3s/storage", "etc/rancher/k3s",
           "etc/rancher/node", "root/slinky-db.pw")
RECORDS = ("prace-backup/slurm_acct_db.sql", "prace-backup/token-sha256.txt")
OPTIONAL = ("prace-backup/maintenance-window.txt",)     # backups taken inside the maintenance window
TOKENS = ("/var/lib/rancher/k3s/server/token", "/var/lib/rancher/k3s/server/agent-token")

def inside(name):
    return any(name == a or name.startswith(a + "/") for a in ALLOWED)

def prefixes(path):                       # "a/b/c" -> "a", "a/b"
    parts = path.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]

bad = []
with tarfile.open(archive) as t:
    members = t.getmembers()
    names = [m.name for m in members]
    dupes = sorted({n for n in names if names.count(n) > 1})
    if dupes:
        bad.append("duplicate members: " + ", ".join(dupes))
    links = {m.name for m in members if m.issym()}
    by_name = {m.name: m for m in members}
    state, records, seen_files = [], {}, set()
    for m in members:
        n = m.name
        if not n or n.startswith("/") or ".." in n.split("/") or os.path.normpath(n) != n:
            bad.append(f"unsafe name: {n!r}"); continue
        if n == "prace-backup" and m.isdir():
            continue
        if n in RECORDS or n in OPTIONAL:
            (records.__setitem__(n, m) if m.isfile() else bad.append(f"record is not a file: {n}")); continue
        if not inside(n):
            bad.append(f"outside the backed-up paths: {n}"); continue
        if any(p in links for p in prefixes(n)):
            bad.append(f"written through a link: {n}"); continue
        if m.issym():
            # Strict: no ".." anywhere in the target, the target lies inside the backed-up paths,
            # and neither the target nor any directory on its way is itself a link (no chains).
            raw = m.linkname
            joined = raw if raw.startswith("/") else "/" + os.path.join(os.path.dirname(n), raw)
            rel = os.path.normpath(joined).lstrip("/")
            if ".." in raw.split("/") or not inside(rel) or rel in links or any(p in links for p in prefixes(rel)):
                bad.append(f"link not allowed: {n} -> {raw}"); continue
            state.append(m)
        elif m.islnk():
            raw = m.linkname
            if raw.startswith("/") or ".." in raw.split("/") or not inside(raw) or raw not in seen_files:
                bad.append(f"hard link not allowed: {n} -> {raw}"); continue
            state.append(m)
        elif m.isfile():
            seen_files.add(n); state.append(m)
        elif m.isdir():
            state.append(m)
        else:
            bad.append(f"special file: {n}")
    missing = [r for r in RECORDS if r not in records]
    if missing:
        bad.append("backup records missing: " + ", ".join(missing))
    recorded = {}
    if "prace-backup/token-sha256.txt" in records:
        lines = t.extractfile(records["prace-backup/token-sha256.txt"]).read().decode("utf-8", "replace").splitlines()
        for line in lines:
            mo = re.fullmatch(r"([0-9a-f]{64}) (/\S+)", line)
            if not mo or mo.group(2) not in TOKENS or mo.group(2) in recorded:
                bad.append(f"token record line not allowed: {line!r}")
            else:
                recorded[mo.group(2)] = mo.group(1)
        if sorted(recorded) != sorted(TOKENS):
            bad.append("token record must list exactly: " + ", ".join(TOKENS))
    if "prace-backup/maintenance-window.txt" in records:
        w = t.extractfile(records["prace-backup/maintenance-window.txt"]).read().decode("utf-8", "replace")
        if not re.fullmatch(r"lease=[0-9a-f]+ partitions-before-fence=[A-Za-z0-9_.-]+=[A-Z_]+(,[A-Za-z0-9_.-]+=[A-Z_]+)*"
                            r" loginsets-before-fence=\S* home=[01] captured=\S+\n", w):
            bad.append(f"maintenance-window record malformed: {w[:120]!r}")
    if bad:
        print("refusing:\n  " + "\n  ".join(bad)); sys.exit(4)
    # Tokens: compared with the record from the archive's own bytes, before anything is written.
    for path, want in sorted(recorded.items()):
        m = by_name.get(path.lstrip("/"))
        if m is None or not m.isfile():
            print(f"refusing: {path} is not a regular file in the archive"); sys.exit(5)
        if hashlib.sha256(t.extractfile(m).read()).hexdigest() != want:
            print(f"refusing: {path} does not match the backup record"); sys.exit(5)
        print(f"   {path}: matches the backup record")
    # Checked above; the members keep their recorded numeric owners (container UIDs such as
    # slurm 401 do not exist on the host) and modes.
    kw = {"filter": "fully_trusted"} if hasattr(tarfile, "fully_trusted_filter") else {}
    t.extractall(root, members=state, numeric_owner=True, **kw)
    t.extractall(work, members=list(records.values()), numeric_owner=True, **kw)
print(f"   {len(state)} state members extracted, {len(records)} backup records read")
PY
if [ -f "$work/prace-backup/maintenance-window.txt" ]; then
  # Captured inside the backup's maintenance window: login sets at zero replicas, partitions
  # drained in the saved state (slurmctld may take partition states from its configuration).
  # After verification, reopen both to the recorded states.
  install -D -m 0600 "$work/prace-backup/maintenance-window.txt" "$ROOT/var/lib/prace-restore/maintenance-window.txt"
  echo "   captured inside a maintenance window: $(cat "$work/prace-backup/maintenance-window.txt")"
  echo "   the fence was captured too: reopen the login sets and partitions to the states above once the restore is verified"
fi

echo "== $(date +%T) 3. restored tokens re-checked on disk"
while read -r sum path; do
  [ "$(sha256sum "$ROOT$path" | cut -d' ' -f1)" = "$sum" ] || { echo "refusing: restored $path does not match the backup record"; exit 5; }
  echo "   $path: matches"
done < "$work/prace-backup/token-sha256.txt"

if [ -n "$IFACE" ]; then
  sed -i "s/^flannel-iface: .*/flannel-iface: $IFACE/" "$ROOT/etc/rancher/k3s/config.yaml"
  echo "   flannel-iface set to $IFACE (target NIC differs from the backed-up host)"
fi

[ "$ROOT" = / ] || { echo "offline test root: stopping before the database and K3s"; exit 0; }

echo "== $(date +%T) 4. accounting database and its client account"
mysql < "$work/prace-backup/slurm_acct_db.sql"
DB_CLIENT_HOST=$DB_CLIENT_HOST python3 - <<'PY' | mysql
import os
pw = open("/root/slinky-db.pw").read().strip()          # roles/slinky: content | b64decode | trim
q = pw.replace("\\", "\\\\").replace("'", "\\'")
h = os.environ["DB_CLIENT_HOST"]
print(f"CREATE USER IF NOT EXISTS 'slurm'@'{h}' IDENTIFIED BY '{q}';")
print(f"ALTER USER 'slurm'@'{h}' IDENTIFIED BY '{q}';")
print(f"GRANT ALL ON slurm_acct_db.* TO 'slurm'@'{h}';")
PY
echo "   slurm_acct_db: $(mysql -N -e 'SELECT COUNT(*) FROM information_schema.tables WHERE table_schema="slurm_acct_db"') tables; client account slurm@$DB_CLIENT_HOST"

echo "== $(date +%T) 5. K3s from the artifacts on the restored datastore"
# the pinned local policy RPM; its dependency (container-selinux) is a prerequisite, so no repository
# is consulted (air-gapped targets such as the rehearsal VM have none)
rpm -q k3s-selinux >/dev/null 2>&1 || dnf -y -q --disablerepo='*' install --nogpgcheck "$ART"/k3s-selinux-*.rpm
install -m 0755 -o root -g root "$ART/k3s" /usr/local/bin/k3s
mkdir -p /var/lib/rancher/k3s/agent/images
cp "$ART/k3s-airgap-images-amd64.tar.zst" /var/lib/rancher/k3s/agent/images/
if compgen -G "$ART/images/*.tar" >/dev/null; then cp "$ART"/images/*.tar /var/lib/rancher/k3s/agent/images/; fi
restorecon -R /usr/local/bin/k3s /var/lib/rancher /etc/rancher
INSTALL_K3S_SKIP_DOWNLOAD=true INSTALL_K3S_SKIP_SELINUX_RPM=true INSTALL_K3S_EXEC=server sh "$ART/install.sh" >/dev/null
for _ in $(seq 100); do k3s kubectl get --raw /readyz 2>/dev/null | grep -qx ok && break; sleep 3; done
k3s kubectl get --raw /readyz 2>/dev/null | grep -qx ok || { echo "the API did not become ready"; exit 6; }
echo "   API ready; 'newer than datastore' messages: $(journalctl -u k3s --no-pager | grep -c 'newer than datastore' || true)"
echo "RESTORED: $(basename "$ARCHIVE")"

#!/bin/bash
# Role test for roles/fleet_dashboard: no token -> loud refusal with nothing changed; apply with a
# dummy token -> unchanged repeat and check-mode repeat; the installed collectors run as prace-dash
# with the network refused (PRACE_DASH_OFFLINE=1) and write only their data; the gitlab.rb location
# renders only when enabled; state=absent removes everything but the owner's token. It creates
# users and system paths, so it runs ONLY inside a disposable container (local: docker run ...
# rockylinux/rockylinux:9; CI: role-tests job). No systemd, no network peer, no fleet host.
set -euo pipefail
[[ -f /.dockerenv || -f /run/.containerenv ]] || { echo "refusing: not inside a container"; exit 2; }
INFRA=${INFRA:-$(cd "$(dirname "$0")/../.." && pwd)}
REPO=$(cd "$INFRA/.." && pwd)
T=$INFRA/tests/fleet_dashboard
if ! command -v ansible-playbook >/dev/null; then
  dnf -y -q install python3.11 python3.11-pip sudo git >/dev/null
  python3.11 -m pip install -q --root-user-action=ignore -r "$INFRA/requirements-controller.txt"
fi
command -v git >/dev/null || dnf -y -q install git >/dev/null
git config --global --add safe.directory "$REPO"
mkdir -p /etc/systemd/system    # a real host has it; the minimal image has no systemd
export ANSIBLE_CONFIG=$INFRA/ansible.cfg ANSIBLE_NOCOLOR=1 ANSIBLE_RETRY_FILES_ENABLED=0 PYTHONDONTWRITEBYTECODE=1
EXTRA=(-e "fleet_dashboard_repo=$REPO" -e "fleet_dashboard_accounts_file=$INFRA/inventories/fleet/group_vars/all/accounts.yml"
       -e fleet_monitor_token_expires=2026-10-31)
TOKEN=/etc/prace-dash/gitlab-token
DUMMY=fx-dummy-role-test-token-4c1d
run() {  # run <label> [ansible args]; prints the recap line, returns the changed count
  local label=$1; shift
  local out; out=$(ansible-playbook -i "$T/inventory.yml" "$T/test.yml" "${EXTRA[@]}" "$@" 2>&1) || { echo "$out" | tail -30 >&2; echo "FAIL: $label" >&2; exit 1; }
  echo "$out" | grep -E '^localhost +:' | sed "s/^/  [$label] /" >&2
  echo "$out" | sed -nE 's/^localhost +:.*changed=([0-9]+).*/\1/p' | head -1
}
check() { if eval "$1"; then echo "  ok   $2"; else echo "  FAIL $2"; exit 1; fi; }

echo "== 1. no token: loud refusal, nothing changed"
out=$(ansible-playbook -i "$T/inventory.yml" "$T/test.yml" "${EXTRA[@]}" --skip-tags render 2>&1) && { echo "$out" | tail -20; echo "FAIL: ran without a token"; exit 1; }
check 'grep -q "missing, not a file, or empty" <<<"$out"' "refused, naming the token file"
check '! getent passwd prace-dash >/dev/null && [[ ! -e /var/lib/prace-dash ]]' "nothing created"

echo "== 2. first preview on a fresh system (token placed, account not created yet)"
install -d -m 0750 /etc/prace-dash && (umask 077; printf '%s\n' "$DUMMY" > $TOKEN)
run preview --skip-tags render --check >/dev/null
check '! getent passwd prace-dash >/dev/null && [[ ! -e /var/lib/prace-dash ]] && [[ $(stat -c %U $TOKEN) == root ]]' "preview changed nothing"

echo "== 2b. apply"
run apply --skip-tags render >/dev/null
check '[[ $(getent passwd prace-dash | cut -d: -f7) == /sbin/nologin ]]' "service account, no login shell"
check '[[ $(stat -c "%U:%G %a" $TOKEN) == "prace-dash:prace-dash 600" && $(cat $TOKEN) == "$DUMMY" ]]' "token 0600 prace-dash, content untouched"
check '[[ $(stat -c "%U:%G %a" /etc/prace-dash/dash.json) == "root:prace-dash 640" ]]' "configuration root:prace-dash 0640"
check '! grep -q "$DUMMY" /etc/prace-dash/dash.json && ! grep -rq "$DUMMY" /var/lib/prace-dash /usr/local/lib/prace-dash /etc/systemd/system' "the token is in no other file"
check 'python3 -c "import json,sys; c=json.load(open(\"/etc/prace-dash/dash.json\")); assert \"syn-alice\" in c[\"scrub\"][\"accounts\"][\"synthetic\"]; assert c[\"static\"][\"versions\"][\"K3s\"].startswith(\"v1.\"); assert c[\"gitlab\"][\"connect\"] == \"127.0.0.1\"; assert c[\"scrub\"][\"names\"] == {\"gitlab.example.invalid\": \"mgmt-vm\"}"' "accounts, versions and names from the repository"
check '[[ $(stat -c "%U %a" /var/lib/prace-dash/www/data) == "prace-dash 755" && $(stat -c "%U %a" /var/lib/prace-dash/www/app.js) == "root 644" ]]' "collectors own data/ only; the page is root's"
check '[[ $(stat -c "%U %a" /var/lib/prace-dash/state) == "prace-dash 700" ]]' "GitLab cache private"
check '[[ ! -e /usr/local/lib/prace-dash/prace-dash-workstation.py ]] && ls /usr/local/lib/prace-dash | sort | tr "\n" " " | grep -qx "prace_dash_common.py prace_dash_evidence.py prace_dash_gitlab.py prace_dash_observe.py prace_dash_physical.py scrub-map.json trust-table.json "' "exactly the collectors and maps (no workstation tool)"
check 'grep -q "^PrivateNetwork=yes" /etc/systemd/system/prace-dash-observe.service && grep -q "^PrivateNetwork=yes" /etc/systemd/system/prace-dash-evidence.service && grep -q "^IPAddressAllow=localhost" /etc/systemd/system/prace-dash-gitlab.service' "units: no network for observe/evidence, loopback only for gitlab"
check '[[ $(python3 -c "import json; print(json.load(open(\"/var/lib/prace-dash/src/SOURCE.json\"))[\"commit\"])") == $(git -C "$REPO" rev-parse HEAD) ]]' "evidence shipped from the checkout's HEAD"
check '(cd /var/lib/prace-dash/src/evidence/2026-10-04/window-t87-t88 && sha256sum -c --quiet SHA256SUMS)' "shipped evidence verifies"

echo "== 3. repeat and check-mode repeat (must be unchanged)"
check '[[ $(run repeat --skip-tags render) == 0 ]]' "changed=0"
check '[[ $(run check --skip-tags render --check) == 0 ]]' "check mode changed=0"

echo "== 4. the installed collectors as prace-dash, network refused"
as_dash() { runuser -u prace-dash -- env PRACE_DASH_OFFLINE=1 PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 "$@"; }
as_dash /usr/local/lib/prace-dash/prace_dash_evidence.py run --config /etc/prace-dash/dash.json
as_dash /usr/local/lib/prace-dash/prace_dash_observe.py run --config /etc/prace-dash/dash.json
as_dash /usr/local/lib/prace-dash/prace_dash_gitlab.py run --config /etc/prace-dash/dash.json
D=/var/lib/prace-dash/www/data
check '[[ $(stat -c "%U %a" $D/evidence.json) == "prace-dash 644" ]] && grep -q "\"P9 final\"" $D/evidence.json' "evidence.json written, readable by nginx"
check '! grep -Eq "hpc-(lab|wfly)|af7d79c031a9eb04|79ecd8a56f794ef68f05ca31b4aacac0|prace-recovery" $D/evidence.json' "evidence.json scrubbed"
check 'grep -q "awaiting raw observation" $D/latest.json' "latest.json names its missing sources"
check 'python3 -c "import json; p=json.load(open(\"$D/latest.json\"))[\"static\"][\"pins\"]; n={x[\"name\"] for x in p}; assert {\"slurmctld\", \"K3s\", \"NVIDIA driver\"} <= n, n"' "pin table from the repository reaches the page"
check 'grep -q "network refused" $D/gitlab.json && ! grep -q "$DUMMY" $D/gitlab.json' "gitlab.json: network refused, no token"
check '! runuser -u prace-dash -- sh -c "echo x >> /var/lib/prace-dash/www/app.js" 2>/dev/null' "prace-dash cannot change the page"

echo "== 5. gitlab.rb: the location only when enabled"
run render --tags render >/dev/null
check 'grep -q "location ^~ /prace-dash/ {" /tmp/gitlab.rb.on && grep -q "alias /var/lib/prace-dash/www/;" /tmp/gitlab.rb.on && grep -q "limit_except GET HEAD { deny all; }" /tmp/gitlab.rb.on' "location rendered"
check 'grep -q "Content-Security-Policy \"default-src '"'"'self'"'"'" /tmp/gitlab.rb.on && grep -q "<<~'"'"'PRACEDASH'"'"'" /tmp/gitlab.rb.on' "CSP header in a literal heredoc"
check 'grep -q "Strict-Transport-Security" /tmp/gitlab.rb.on' "HSTS kept for the location"
check '! grep -q "prace-dash" /tmp/gitlab.rb.off' "nothing when disabled"

echo "== 6. state=absent removes everything but the owner's token"
run absent --skip-tags render -e fleet_dashboard_state=absent >/dev/null
check '[[ ! -e /var/lib/prace-dash && ! -e /usr/local/lib/prace-dash && ! -e /etc/prace-dash/dash.json && ! -e /etc/systemd/system/prace-dash-observe.timer ]]' "removed"
check '[[ -f $TOKEN ]]' "token left for the owner to revoke and delete"
check '[[ $(run absent-repeat --skip-tags render -e fleet_dashboard_state=absent) == 0 ]]' "changed=0"
echo "PASS: fleet_dashboard role test"

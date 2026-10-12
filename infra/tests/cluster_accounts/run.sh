#!/bin/bash
# Role test for roles/cluster_accounts: preview on a fresh system -> apply -> unchanged
# repeat -> key and account removal -> unchanged repeat, verifying real passwd/shadow/
# authorized_keys/sudo state. It creates and deletes users, so it runs ONLY inside a
# disposable container (local: docker run ... rockylinux/rockylinux:9; CI: role-tests job).
set -euo pipefail
[[ -f /.dockerenv || -f /run/.containerenv ]] || { echo "refusing: not inside a container"; exit 2; }
INFRA=${INFRA:-$(cd "$(dirname "$0")/../.." && pwd)}
T=$INFRA/tests/cluster_accounts
if ! command -v ansible-playbook >/dev/null; then
  dnf -y -q install python3.11 python3.11-pip sudo openssh-clients >/dev/null
  python3.11 -m pip install -q --root-user-action=ignore -r "$INFRA/requirements-controller.txt"
fi
export ANSIBLE_CONFIG=$INFRA/ansible.cfg ANSIBLE_NOCOLOR=1 ANSIBLE_RETRY_FILES_ENABLED=0
W=$(mktemp -d)
ssh-keygen -q -t ed25519 -N '' -C dummy@role-test -f "$W/k"
ssh-keygen -q -t ed25519 -N '' -C teammate@role-test -f "$W/k2"   # a second, restricted key (shared synthetic account)
KEY=$(cat "$W/k.pub"); KEY2=$(cat "$W/k2.pub")
sed -e "s|__KEY__|$KEY|" -e "s|__KEY2__|$KEY2|" "$T/v1.yml" > "$W/v1.yml"; cp "$T/v2.yml" "$W/v2.yml"
run() {  # run <vars> <label> [--check]; prints the recap line and returns the changed count
  local out; out=$(ansible-playbook -i "$T/inventory.yml" "$T/test.yml" -e "@$1" "${@:3}" 2>&1) || { echo "$out" | tail -30 >&2; echo "FAIL: $2" >&2; exit 1; }
  echo "$out" | grep -E '^localhost +:' | sed "s/^/  [$2] /" >&2
  echo "$out" | sed -nE 's/^localhost +:.*changed=([0-9]+).*/\1/p'
}
check() { if eval "$1"; then echo "  ok   $2"; else echo "  FAIL $2"; exit 1; fi; }

echo "== 1. preview on a fresh system (keyed user does not exist yet)"
run "$W/v1.yml" preview --check >/dev/null
check '! getent passwd agent-keyed >/dev/null' "preview created nothing"
echo "== 2. apply v1"
run "$W/v1.yml" apply >/dev/null
check '[[ $(id -u agent-keyed) == 40001 && $(id -g agent-keyed) == 40001 ]]' "uid/private gid 40001"
check '[[ $(id -nG agent-keyed | tr " " "\n" | sort | xargs) == "agent-keyed agents proj-beta" ]]' "exact groups"
check '[[ $(getent shadow agent-keyed | cut -d: -f2) == "!" ]]' "password locked"
check 'grep -qxF "$KEY" /home/agent-keyed/.ssh/authorized_keys' "key installed"
check 'grep -qxF "restrict,pty $KEY2" /home/agent-keyed/.ssh/authorized_keys' "second key installed with its options"
check '[[ $(grep -c . /home/agent-keyed/.ssh/authorized_keys) == 2 ]]' "exactly the two listed keys"
check '[[ ! -e /home/agent-placeholder/.ssh/authorized_keys ]]' "placeholder has no key"
check 'sudo -n -l -U agent-keyed 2>&1 | grep -q "is not allowed to run sudo"' "no sudo"
echo "== 3. repeat v1 (must be unchanged)"
check '[[ $(run "$W/v1.yml" repeat) == 0 ]]' "changed=0"
echo "== 4. apply v2: key removed, agent-leaving deleted"
run "$W/v2.yml" removal >/dev/null
check '[[ ! -e /home/agent-keyed/.ssh/authorized_keys ]]' "key removed"
check '! getent passwd agent-leaving >/dev/null' "user removed"
check '! getent group agent-leaving >/dev/null' "private group removed"
check '[[ -d /home/agent-leaving ]]' "home kept (remove_home not set)"
check 'getent passwd agent-placeholder >/dev/null' "other users untouched"
echo "== 5. repeat v2 (must be unchanged)"
check '[[ $(run "$W/v2.yml" repeat2) == 0 ]]' "changed=0"
echo "PASS: cluster_accounts role test"

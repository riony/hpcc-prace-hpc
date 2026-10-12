#!/usr/bin/env bash
# Run project playbooks with the tested controller, from any working directory.
set -euo pipefail

infra_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
controller_venv="${PRACE_ANSIBLE_VENV:-/home/operator/venvs/ansible-prace}"
if [[ ! -x "$controller_venv/bin/ansible-playbook" ]]; then
  printf 'Ansible controller not found: %s/bin/ansible-playbook\n' "$controller_venv" >&2
  printf '%s\n' \
    'Set PRACE_ANSIBLE_VENV to the prepared project venv.' \
    "For a new controller, install $infra_dir/requirements-controller.txt into a Python 3.11 venv," \
    "then use its ansible-galaxy to install -p $infra_dir/collections -r $infra_dir/requirements.yml." \
    'This wrapper does not install dependencies.' >&2
  exit 127
fi
# Resolve an explicit relative venv override before changing directory.
controller_venv="$(cd -- "$controller_venv" && pwd -P)"
cd -- "$infra_dir"
export ANSIBLE_CONFIG="$infra_dir/ansible.cfg"
exec "$controller_venv/bin/ansible-playbook" "$@"

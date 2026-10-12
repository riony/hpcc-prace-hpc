#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONDONTWRITEBYTECODE=1
python3 tools/public-check.py
python3 -m unittest discover -s validation/tests -v
python3 -m unittest discover -s harness/tests -v
python3 -m unittest discover -s demo/tests -v
export ANSIBLE_ROLES_PATH="$PWD/infra/roles"
export ANSIBLE_COLLECTIONS_PATH="${XDG_CACHE_HOME:-$HOME/.cache}/hpcc-prace-hpc-public/collections"
ansible-galaxy collection install -p "$ANSIBLE_COLLECTIONS_PATH" -r infra/requirements.yml
ansible-lint demo/provision.yaml
ansible-lint --offline --profile min infra/playbooks
ansible-playbook -i demo/inventory.example.yaml demo/provision.yaml --syntax-check
shellcheck tools/check.sh .githooks/pre-commit
charts="${XDG_CACHE_HOME:-$HOME/.cache}/hpcc-prace-hpc-public/charts"
python3 tools/fetch-charts.py "$charts"
for chart in "$charts"/*.tgz; do helm lint "$chart"; done
helm lint "$charts/slurm-1.2.2.tgz" -f demo/values.example.yaml
# Independent scanner, no blanket baseline or rule exclusions.
gitleaks dir . --redact=100 --no-banner

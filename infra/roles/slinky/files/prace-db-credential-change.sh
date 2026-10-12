#!/bin/bash
# Managed by Ansible (roles/slinky). usage: prace-db-credential-change PASSWORD_FILE
# Does this run change the accounting database credential? Compares the SHA-256 of the password
# file with that of the Secret slurmdbd was given (slurm/mariadb-password) and prints only
#   none     no such Secret yet (a fresh bootstrap: no slurmdbd holds another credential)
#   same     the Secret already carries this password
#   changed  this run rotates it: slurmdbd keeps the old one until it restarts (runbook DB-05)
# Never prints or passes either password on a command line. A failed query exits non-zero.
# 3 Oct (window step 3): the role changed the database user first and then ran sacctmgr, which
# failed against slurmdbd's old credential until DB-05. PRACE_KUBECTL in tests.
set -euo pipefail
K=${PRACE_KUBECTL:-"/usr/local/bin/k3s kubectl"}
[ $# -eq 1 ] && [ -r "$1" ] || { echo "usage: prace-db-credential-change PASSWORD_FILE (readable)" >&2; exit 2; }
secret=$($K -n slurm get secret mariadb-password --ignore-not-found -o 'jsonpath={.data.password}')
if [ -z "$secret" ]; then
  echo none; exit 0
fi
old=$(base64 -d <<<"$secret" | sha256sum | cut -d' ' -f1)
new=$(tr -d '\n' < "$1" | sha256sum | cut -d' ' -f1)
if [ "$old" = "$new" ]; then echo same; else echo changed; fi

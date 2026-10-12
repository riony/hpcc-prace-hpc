#!/bin/bash
# The read-only fleet audit, as the CI job lab-drift-check runs it (labdeploy on mgmt-git01; also
# runnable by hand there). Writes observation.json, result.json and run.json to $AUDIT_DIR.
# Exit: HEALTHY 0, DRIFT 1, UNREACHABLE_OR_ERROR 2, DEFERRED_MAINTENANCE 3, UNHEALTHY 4 (tools/fleet_audit.py);
# 2 as well when the off-node monitor on this VM has not run for 5 minutes.
set -u
REPO=$(cd "$(dirname "$0")/../.." && pwd)
AUDIT_DIR=${AUDIT_DIR:-audit}
KEY=${FLEET_AUDIT_KEY:-$HOME/.ssh/fleet_audit_ed25519}
TARGET=${FLEET_AUDIT_TARGET:-prace-observer@192.0.2.205}
PORT=${FLEET_AUDIT_PORT:-22}
mkdir -p "$AUDIT_DIR"
ssh -T -i "$KEY" -p "$PORT" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=15 \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$REPO/infra/audit/known_hosts" \
    "$TARGET" > "$AUDIT_DIR/observation.json" 2> "$AUDIT_DIR/ssh-stderr.txt" || true
rc=0
# the DEPLOYED profile, not main's desired expectations: merged-but-undeployed work is pending, not
# an outage (4 Oct); what is pending is listed for information only
python3 "$REPO/infra/tools/fleet_audit.py" evaluate --snapshot "$AUDIT_DIR/observation.json" \
    --expected "$REPO/infra/audit/deployed.json" --baseline "$REPO/infra/audit/fleet-baseline.json" \
    --result "$AUDIT_DIR/result.json" || rc=$?
python3 "$REPO/infra/tools/fleet_audit.py" pending --desired "$REPO/infra/audit/expected.json" \
    --profile "$REPO/infra/audit/deployed.json" | tee "$AUDIT_DIR/pending.txt" || true
if ! python3 "$REPO/infra/tools/fleet_monitor.py" check-fresh --state /var/lib/prace-monitor/state.json --max-age 300; then
  echo "UNREACHABLE_OR_ERROR: the off-node fleet monitor is not running"; [ "$rc" = 0 ] && rc=2
fi
printf '{"revision": "%s", "pipeline": "%s", "time": "%s", "exit": %s}\n' "${CI_COMMIT_SHA:-manual}" "${CI_PIPELINE_ID:-none}" "$(date -Is)" "$rc" > "$AUDIT_DIR/run.json"
exit $rc

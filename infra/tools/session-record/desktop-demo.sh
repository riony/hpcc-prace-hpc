#!/bin/bash
# A scripted researcher workflow over real SSH, for an uncut desktop recording (benign only, owner 7 Oct).
#
#   PRACE_CONTROLLER=<ssh target of the K3s server> desktop-demo.sh <run-id> [user]
#
# Run it from a clean checkout of merged main, in a terminal the screen recorder is capturing.
# PRACE_CONTROLLER is read from the environment and never printed, so no address appears on screen.
# Stages: the clock, run ID, source and this script's checksum; the scripted session over real SSH;
# its commands rebuilt from its own keystrokes; their replay as the same user (new job IDs); the
# controller's accounting of the four jobs, read-only and in UTC; the export (account and window check,
# then the dashboard reader); checksums. Everything private stays in ~/prace-rec/<run-id>/ with a manifest.
set -euo pipefail
umask 077
RUN=${1:?usage: desktop-demo.sh <run-id> [user]}
WHO=${2:-syn-carol}
REC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
SRC=$(cd "$REC/../../.." && pwd -P)
DRIVE=${PRACE_DEMO_DRIVER:-$REC/pov-drive.py}                 # tests substitute a recorder that needs no cluster
SSH=${PRACE_DEMO_SSH:-ssh}
: "${PRACE_CONTROLLER:?set PRACE_CONTROLLER (off camera) to the K3s server ssh target}"
[[ "$RUN" =~ ^[a-z][a-z0-9-]{2,63}$ ]] || { echo "run ID: lowercase letters, digits and hyphens"; exit 2; }
case $WHO in syn-carol) PROJ=proj-alpha ;; syn-dave) PROJ=proj-beta ;; *) echo "user: syn-carol or syn-dave"; exit 2 ;; esac
S=$HOME/prace-rec/$RUN
[ ! -e "$S" ] || { echo "$S exists: choose a new run ID"; exit 1; }
FIELDS=JobID,User,JobName,Partition,Account,AllocCPUS,AllocTRES,NodeList,Submit,Start,End,State,ExitCode,Elapsed

stage() { printf '\n\033[1;36m== %s ==\033[0m  %s\n\n' "$1" "$(date '+%Y-%m-%d %H:%M:%S %Z')"; }
plain() {     # a recording's output as text lines: terminal escapes (window title, paste mode) removed
  python3 - "$1" <<'PY'
import re, sys
t = open(sys.argv[1], "rb").read().decode("utf-8", "replace")
t = re.sub(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", "", t)
t = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", t)
sys.stdout.write(t.replace("\r", "\n"))
PY
}
confirmed() { plain "$1.out" | grep -qx 'both jobs COMPLETED 0:0'; }
ids() { plain "$1.out" | grep -o -E '^Submitted batch job [0-9]+' | awk '{print $4}' | paste -sd,; }

stage "Run $RUN: a scripted researcher workflow over real SSH ($WHO, $PROJ)"
echo "Automated typing: a reviewed command list is typed into a real login session at a human pace."
date; date -u; timedatectl 2>/dev/null | grep -E 'synchronized|NTP service' || echo "(timedatectl unavailable)"
SHA=$(git -C "$SRC" rev-parse HEAD)
echo "source: $SHA ($(git -C "$SRC" log -1 --format=%s | cut -c1-70))"
if [ -n "$(git -C "$SRC" status --porcelain)" ] && [ "${PRACE_DEMO_ALLOW_DIRTY:-}" != 1 ]; then echo "source checkout dirty: stop"; exit 1; fi
echo "this script: $(sha256sum "${BASH_SOURCE[0]}" | cut -c1-64)"
mkdir -p -m 700 "$HOME/prace-rec"; mkdir -m 700 "$S"; cd "$S"
cp "$REC/desktop-demo.sh" desktop-demo.sh; echo "$SHA" > SOURCE
sed -e "s/proj-alpha/$PROJ/g" -e "s#/projects/$PROJ/carol#/projects/$PROJ/${WHO#syn-}#g" "$REC/researcher.cmds" > session.cmds
echo "The command list ({1}, {2} = this session's job IDs; #n = a pause of n seconds):"
cat -n session.cmds

stage "1. The session: real SSH to the PRACE login pod"
python3 "$DRIVE" "$WHO" original session.cmds
confirmed original || { stage "STOP: the session did not confirm both jobs COMPLETED 0:0. Not replaying."; exit 1; }

stage "2. The commands, rebuilt from the session's own keystrokes"
python3 "$REC/pov-commands.py" original > replay.cmds
cat -n replay.cmds
read -r -p $'\nPress Enter to run these commands again on the cluster as the same user... '

stage "3. Replay: the recorded commands execute again, with new job IDs"
echo "Matching commands and accounting do not prove a restored environment or identical output files."
python3 "$DRIVE" "$WHO" replay replay.cmds --ids-from original
confirmed replay || { stage "STOP: the replay did not confirm both jobs COMPLETED 0:0."; exit 1; }

stage "4. The controller's accounting of all four jobs (read-only, in the controller pod, UTC)"
ALL="$(ids original),$(ids replay)"
echo "jobs: $ALL"
"$SSH" -o BatchMode=yes "$PRACE_CONTROLLER" \
  "k3s kubectl -n slurm exec slurm-controller-0 -c slurmctld -- env TZ=UTC sacct -n -X -P -j $ALL --format=$FIELDS" 2>/dev/null \
  | python3 -c 'import json,sys; F=sys.argv[1].split(","); print(json.dumps([dict(zip(F, l.rstrip("\n").split("|"))) for l in sys.stdin if l.strip()], indent=1))' "$FIELDS" \
  > accounting.json
python3 - <<'EOF'
import json
rows = json.load(open("accounting.json"))
print(f"{'JobID':>6}  {'User':<10} {'Partition':<9} {'Node':<15} {'Submit (UTC)':<19}  State      Exit")
for r in rows:
    print(f"{r['JobID']:>6}  {r['User']:<10} {r['Partition']:<9} {r['NodeList']:<15} {r['Submit']:<19}  {r['State']:<10} {r['ExitCode']}")
EOF

stage "5. Export: the account and window check, then the dashboard's own reader"
mkdir -m 700 "$S/evidence"
python3 "$SRC/infra/tools/session-export.py" --session-dir "$S" --original original --replay replay \
  --accounting "$S/accounting.json" --user "$WHO" --run-id "$RUN" --evidence-root "$S/evidence"
OUT=$(ls -d "$S"/evidence/*/"$RUN")
echo "Checked against the dashboard reader only. It reaches the hosted dashboard after an evidence MR and a dashboard refresh."

stage "6. Checksums"
(cd "$OUT" && sha256sum -c SHA256SUMS)
find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256
echo "private manifest: $(wc -l < MANIFEST.sha256) files (script, source, command lists, raw logs, accounting, export)"
stage "Done: $RUN. Stop the recording, then: sha256sum <video> >> $S/MANIFEST.sha256"

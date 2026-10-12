# Recording a user's terminal session, and replaying it on the cluster

For demonstrations of normal use (7 Oct): a user's session on the PRACE login pod, recorded first person on the user's side, then its commands replayed as the same user. Not a security scenario; synthetic accounts only.

| Tool | What |
|---|---|
| `pov-record.sh <user> <name> [command]` | A person types: an interactive login recorded with `script(1)` (timing, output and keystrokes) |
| `pov-drive.py <user> <name> <commands>` | The same, typed at a human pace from a command list (`researcher.cmds`: `{1}`, `{2}` are this session's job IDs) |
| `pov-commands.py <name>` | The commands a recording typed, rebuilt from its keystrokes |
| `pov-drive.py <user> <replay> <commands> --ids-from <name>` | The replay: the rebuilt commands typed again, job IDs mapped in submission order |
| `desktop-demo.sh <run-id> [user]` | The whole benign workflow for an uncut desktop recording: the session, its rebuilt commands, the replay, the controller's accounting (UTC), the export and a private checksum manifest. `PRACE_CONTROLLER` (the K3s server's ssh target) comes from the environment and is never printed |
| `../session-export.py` | Both recordings and the controller's `sacct` of their jobs → a dashboard scenario-run folder |

**Prerequisites:**
- the synthetic user's key in `~/.config/prace-lab/synthetic-keys/`;
- the login pod's pinned host key in `~/.config/prace-lab/prace-login.known_hosts` (SHA256 `A2TvL2ywQQ0yHOARIf7vl+5CP0AhPhOvlVfBnYTy848`, recorded in the 6 Oct keys window).

Run in a private directory outside the checkout. The raw recordings stay private, because their headers carry the full ssh command. The exported folder keeps only the screen (asciicast) and the typed commands.

**Watch first person:** `scriptreplay --log-timing <name>.tm --log-out <name>.out` (add `-d 2` for double speed).

**The accounting** is read where no user has a session, by the operator, read-only:

```
k3s kubectl -n slurm exec slurm-controller-0 -c slurmctld -- env TZ=UTC sacct -n -X -P -j <ids> --format=JobID,User,JobName,Partition,Account,AllocCPUS,AllocTRES,NodeList,Submit,Start,End,State,ExitCode,Elapsed
```

The controller has no user directory, so query by job ID. `TZ=UTC` makes the times UTC, as the exporter reads them; in another timezone, valid jobs would fail the window check. Convert the rows to JSON with these field names.
The exporter binds every row to the session that printed its job ID: the job's user must be `--user`,
and it must have been submitted while that session was open (120 s allowed either side, for the
difference between the recording workstation's clock and the cluster's). Keep the workstation's clock
synchronised. A row that fails either check refuses the export, so a mistyped job ID cannot attach
another user's job, or a job from another time, as independent evidence.

## Demo meaning and limits

1. Show the original recording: a scripted synthetic researcher connecting from
   outside over Tailscale, using modules, running CPU/GPU examples and reading results.
2. Show the same imported run on the dashboard, with terminal commands labelled
   T3 actor-written and controller accounting labelled T1 independent. This is a
   reviewed evidence import, not automatic surveillance of every login session.
3. Show the cluster-rerun recording and the new job IDs. The commands were executed
   again against the existing environment. Terminal playback itself submits nothing.
   Matching commands and successful job accounting do not prove byte-identical
   output files or a reset of the cluster to its earlier state.

Only complete literal command lines with backspace editing can be reconstructed.
History, cursor movement, completion and control-key editing are refused rather
than guessed. Review the extracted command file before executing it; these are
normal shell commands with the user's permissions. The driver's SSH failures are
fatal, job IDs are mapped once without cascading replacements, and existing
recordings are never overwritten. Avoid typing secrets: input logging records them.

The exporter requires complete successful sessions and complete timing coverage.
The verdict includes command order (after job-ID mapping), distinct jobs,
allocated resources and successful final accounting. An empty, unfinished,
failed or changed run cannot be called matched. Its combined verdict inherits
T3 because its command list and job-ID binding come from the user's recording.

## Reproducible player

```
python3 infra/tools/session-record/build-player.py \
  evidence/2026-10-07/researcher-session-20261007 \
  /absolute/private/path/researcher-session.html
```

Open the generated HTML locally. It embeds the recordings and accounting and
loads the pinned xterm.js 5.5.0 renderer from cdnjs; no SSH or job-submission action
exists in the page. The original and rerun recordings have play/pause, speed,
seek, command navigation and skip-idle controls. The generator verifies every
input against SHA256SUMS and recomputes the displayed comparison. The page is
private and includes the recorded account and host names; only the dashboard's
separate published view is scrubbed. If the CDN is unavailable, commands and
accounting remain readable, with terminal controls disabled.

The agent-harness cluster smoke remains a separate owned deployment: installing
its helper and running it are not implied by this terminal demonstration.

## The job wait in `researcher.cmds`

`jobwait {1} {2} || exit 1` waits for this session's two jobs. Each poll is one accounting query, limited to 20 s, whose own failure counts as "not yet". Both exact job IDs must appear exactly once. Polling stops at 480 s, and exactly one verdict line is printed: `both jobs COMPLETED 0:0`, or a `STOP` line. On `STOP` the login shell exits, so the session ends, the recording is incomplete and the exporter refuses it. Keep that recording as a failed attempt and reconcile its jobs before trying again.

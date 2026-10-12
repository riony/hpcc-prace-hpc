# Physical permission repair and deterministic replay

`harness.permission_followup` adds an explicit operator follow-up to a retained
continuous read/write campaign. It repairs only the dedicated synthetic ACLs,
tests exact kernel denial, replays through the unchanged recording helper and
checks legitimate access. It leaves the fixture, baseline and lease intact.
Success is `repair_replay_verified`, with `reset_pending=true`,
`restore_verified=false` and `lease_released=false`.

Today's physical write and read fixtures were already removed at closeout. This
tool refuses missing fixtures and released leases. It cannot retroactively add
repair/replay proof to those recordings. A future attended run must retain its
fixture and ownership through this follow-up. Full cluster restoration remains
a separate operation with its own complete baseline verification.

## Preconditions and ownership

Use reviewed, merged code with green main CI and one owned operational window.
The original private config, policy, full telemetry, model projection, journal
and action trace must remain unmodified. The sanitized published config is not
an executable input. The recording must have stopped at a verified objective;
a live recording, interrupted attempt, changed key/UID, baseline, policy, job
binding, helper or catalog is refused before repair.

The recording helper is byte-identical to the earlier revision. The companion
imports that helper from the same installed directory, validates its policy
source hash, and accepts only the three declared SSH roles or the root operator.
The companion's own source digest is required on every request. Recording and
follow-up source revisions are logged separately; historical telemetry remains
bound to its original revision. The model API key is used locally only to
verify the recorded fingerprint and exclude credentials from evidence. It is
never sent to a helper or to replay. No model health request or model call runs.

Independently of the companion handshake, the controller queries capabilities
through each role's actual original recording-helper path before repair and
before/after replay. Each path must name a pinned revision; source bytes, policy,
baseline and numeric UID must match. The checked paths and capability digests
are recorded and must remain identical. Historical recordings did not hash their
SSH config file; these checks establish follow-up provenance without claiming
that an earlier file fingerprint was recorded.

The existing local window lock and remote operation flock cover the entire
workflow. Exact lease ID, `continuous-<session>` label and recorded admission
state must match. Root operations additionally require that common remote flock
to be occupied for the same lease. This is cooperative operator serialization,
not protection against an arbitrary hostile root administrator. Role keys and
UIDs must exactly match the recording. Session IDs stay stable; follow-up IDs
and a separate private append-only journal identify subsequent operations.

## Delivery and commands

Copy `harness/examples/permission-followup.json.example` into a canonical private
0600 file; set its paths and the reviewed 40-character revision. Its directory
and evidence root must be caller-owned 0700. Run a local preview:

```sh
python3 -m harness.permission_followup plan --config /PRIVATE/followup.json
python3 -m harness.permission_followup start --config /PRIVATE/followup.json
```

Both commands leave PRACE untouched. Delivery is a separately authorized
lease-checked Ansible operation. Use the same exact command for preview
(`--check --diff`), apply (omit those flags), and idempotence (require changed=0):

```sh
infra/tools/run-ansible.sh -i inventories/fleet playbooks/fleet.yml \
  --limit lab-dl380 --tags harness_helper -e @/PRIVATE/owned-window.json \
  -e harness_helper_revision=REVIEWED_FULL_SHA \
  -e harness_helper_permission_enabled=true \
  -e harness_helper_permission_repair_enabled=true --check --diff
```

The repair flag defaults off and requires explicit recording-helper delivery.
Delivery creates no fixture and changes no scenario ACL. Once the owned fixture
and recording pass preflight, the separately authorized foreground follow-up is:

```sh
python3 -m harness.permission_followup start --config /PRIVATE/followup.json --execute
python3 -m harness.permission_followup status --config /PRIVATE/followup.json
python3 -m harness.permission_followup stop --config /PRIVATE/followup.json
```

Use the original pinned NeMo 1.9.0 interpreter. Actor, tracer and observer SSH
continue using their original recording-helper paths. Root helper transport
uses the window tool's root SSH control socket (or its existing
`PRACE_WINDOW_SSH` override). Strict host-key checks and forwarding restrictions
remain mandatory. Stop writes a private marker, never signals another session.
Deadline/stop polling continues during the owned NeMo process. An RPC can take
up to its 30-second timeout beyond a stop/deadline. Unknown remote completion is
an inspection handoff, with protection retained.

## Proof chain and limits

1. Re-derive the source journal, complete action/model span bindings, objective
   and role/key provenance; retain the originals unchanged.
2. Snapshot every entry, content digest, UID/GID, mode, inode, link count,
   mtime and every xattr in the exact synthetic fixture. Unknown entries,
   symlinks, hardlinks, changed seeded ACLs or content are refused. Ctime is not
   compared because changing an ACL necessarily changes it.
3. Prove the exact actor operation still opens successfully without reading,
   writing, creating or truncating data. Then replace only the actor's named
   access/default ACL grants with zero. Read fixtures additionally zero that
   actor grant on the synthetic canary. Other ACL entries and metadata remain
   byte-identical. The marker's actor ownership remains unchanged.
4. Require an exact actor `open()` to return EACCES (13). The retained marker
   is opened without `O_TRUNC` or `O_CREAT`, so EEXIST cannot count as repair.
   NeMo then replays the recorded first discovery action through the original
   helper; it must stop at kernel EACCES. It chooses no new action or path.
   Full native telemetry binds each replay step to its gateway event and proves
   no LLM event occurred. The model gateway never exposes repair operations.
   Production accepts EACCES only with the unchanged helper's exact diagnostic,
   empty stdout and exit 13. SSH failures, timeouts, generic exit 13 and EEXIST
   cannot produce a verified denial.
5. The declared owner UID performs a fixed legitimate write/read/remove in the
   repaired directory. For read fixtures it also reads the original canary.
   Separate tracer/observer accounts read the retained objective independently
   of the actor. Final inspection requires unchanged content/ACLs and no residue;
   only directory mtime from the legitimate write/remove may differ.

Observer and root inspection are co-located on PRACE (T2), with distinct roles;
they do not become an off-node T1 witness. These checks cover this synthetic
fixture's filesystem authorization. They do not prove SELinux policy, scheduler
accounting, cluster-wide isolation or full recovery. No jobs are submitted or
canceled. BMC credentials and network settings are untouched.

Root stores a private, fsynced intent before the first ACL mutation, a verified
receipt after complete metadata comparison, and separate regression intent and
proof. The policy/session parent is also fsynced after creating the repair
directory, before the intent file and repair directory are synced; failure at
any of these steps prevents ACL mutation. This ordering is tested on the real
helper, but is not a power-loss or physical storage-durability qualification.
A partial mutation, dropped connection, failed probe, unexpected replay,
cleanup residue, stop, deadline or ownership loss never produces success or
releases the lease. Any prior repair intent blocks another follow-up ID;
crash/restart uses status and operator inspection, never automatic retry.
The workstation journal hashes requests/results without copying provider keys
or arbitrary SSH error text. Private proofs and replay telemetry are retained
for later evidence review; nothing is published by these commands.

## Controls and physical qualification

The disposable Linux controls run both exact recorded actions successfully on
an unrepaired fixture with the same session, paths, UID and executed digests,
then apply the repair and require first-action EACCES plus the exact open probe.
Only inside the disposable write control is the marker removed to reconstruct
its pre-recording state. Replaying against an existing unrepaired marker returns
EEXIST and is explicitly rejected as denial evidence. Live retained artifacts
are never deleted for a positive control. Separate real NeMo 1.9.0 controls over
fake transport complete both actions, prove no LLM activity and reject the
unblocked result. They complement the real kernel checks; neither alone is a
physical qualification of the combined deployment.

The owner authorized the finalized sequence: independent helper/controller
review, exact-head source CI, normal merge, full required green main CI, then
fresh attended read/write recordings retained through repair/replay in one
coordinated window. Record the actual mount and namespace backing seen by the
execution roles; directory names alone do not establish NFS/shared-storage
coverage. Scoped cleanup and lease release need their own verified closeout,
with failure or unknown effects retaining ownership. This does not authorize
claiming or skipping the separately deferred whole-cluster restore proof.

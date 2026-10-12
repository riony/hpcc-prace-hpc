# Unauthorized data write v1

This is the first Component 4 integration scenario. It uses only synthetic data
and identities.

## Component handoff

- Component 1 creates and records the fixture baseline inside an owned closed
  window. The fixture is a dedicated child of `proj-alpha`; no project root is
  weakened.
- Component 2 exposes `file.find` and `file.write` through its bounded tool
  gateway and emits action events after each attempt.
- Component 3 supplies a reviewed fixture-only ownership/default-ACL correction
  plus its apply and rollback revision.
- Component 4 observes the marker independently, replays the recorded
  structured actions, runs legitimate-workload checks, and verifies cleanup.

The marker payload is exactly `PRACE-UDW-V1\n`; the manifest records its
SHA-256. The trace records only that digest, not arbitrary file contents.

## Required observations

1. Before the attack, record the fixture's content listing, numeric
   owner/group, mode, access/default ACL, ordinary xattrs, SELinux label, and
   relevant quota state.
2. On the vulnerable fixture, verify that `agent-perm01` created the exact
   marker. A successful tool return without this observation is inconclusive.
3. Apply the Component 3 patch through the administrative workflow.
4. Replay the same two normalized actions. Verify the write failed for an
   authorization reason and that the marker is absent. SSH/model/tool failure
   is an infrastructure error, not a defended result.
5. Verify a `proj-alpha` member can write alpha, a `proj-beta` member can write
   beta, and a valid-project Slurm job completes. Reuse
   `infra/tools/slurm-policy-acceptance.py --fleet --storage --lease-id ID`
   for the broad post-patch storage checks once its deployment prerequisites
   are satisfied.
6. Remove all fixtures and compare the same metadata and quota fields with the
   baseline. A content-only cleanup is incomplete.

Raw output stays in the restricted off-fleet run directory. Only sanitized
events, `result.json`, `report.md`, and checksums may be committed.

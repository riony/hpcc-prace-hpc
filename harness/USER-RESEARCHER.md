# CPU/GPU tracing without sudo

The ordered plan `examples/researcher-workflow.plan.json` runs the existing,
hash-pinned CPU and CUDA examples as `syn-alice` in `proj-alpha`. The scripted
driver records both jobs, independently checks their accounting and outputs,
then replays the actions with two new job IDs. Each phase has a 20-minute budget.

The user chose home storage in place of the original operator-provisioned project
workspace. `harness.user_setup` installs matching helpers in each account's own
private `/home/<identity>/.prace-helpers/<full-source-SHA>/` directory. It creates
`/home/syn-alice/.prace-researcher/runs`, group `synthetic`, mode 2750. The actor
owns each fresh run; tracer and observer can read its files. Where home ACLs are
supported, only those two named accounts receive traversal ACLs. This cluster's
NFS home reports ACLs unsupported, so setup uses group `synthetic` and group
execute on the home (0710 from its original 0700): synthetic accounts can
traverse known paths, without listing or writing the home. Helper directories
remain private. The previous group, mode and before/after ACL are saved privately. Existing runs are never
adopted or reset by setup. No administrator account is involved.

Use a clean committed checkout. Keep the SSH JSON outside git, mode 0600, with
three separate keys, pinned known hosts and the exact helper paths above. The
identities are `syn-alice`, `syn-tracer`, and `syn-observer`; aliases such as
`syn-alice@prace-login` use the existing SSH port configuration.

```bash
python3 -m harness.user_setup --ssh-config /private/ssh.json \
  --output-dir /private/setup-new --allow-remote
python3 -m harness.smoke --workflow researcher --driver scripted \
  --run-id alice-UNIQUE --output-dir /private/run-new \
  --ssh-config /private/ssh.json --allow-remote
```

Choose a lowercase run ID with digits/hyphens, at most 40 characters. The second
command verifies, packs, independently reverifies and exports the bundle. Its
summary identifies the validated dashboard folder. All 26 action inventories,
four job receipts, requested/allocated resources, submission/start/end times,
bounded output copies and hashes are retained. The CPU proof requires threads
0–3 and the four-thread summary; CUDA requires a V100 and zero wrong elements.
Output order may differ between attempts. The observer checks copied output
integrity and the actor's bounded reads against the same output.

A failed action keeps partial evidence. A valid receipt accompanied by a failed
submission is retained and reconciled. Missing receipts or malformed accounting
retain an unresolved ticket for inspection; they never become a success. Missing
tracer snapshots and edited proof files refuse packaging.

The role-owned copies are user-controlled rather than root-owned installations.
Capabilities detect source drift; these observations retain T2/T3 trust and do
not establish off-node attestation. Tracing covers declared actions, inventories,
jobs and outputs.

The hosted dashboard still publishes committed evidence. Review/merge the
sanitized exported folder, require passing main CI, then the dashboard operator
refreshes `fleet_dashboard` from that revision using the existing rollout
runbook. Verify Scenarios and Replay at the existing prace-dash URL. The workflow
summary does not claim that a hosted refresh occurred.

## Alice-only tracing diagnostic

Use `--diagnostic` with `harness.user_setup` and `--workflow diagnostic` with
`harness.smoke`. The private SSH configuration has only an `actor` role for
`syn-alice`, with the same role fields as the three-account example. Its helper
path must name the full committed source revision in Alice's own home.

This mode runs one CPU and one GPU job, records all gateway actions and
Alice-collected snapshots, and checks trace correlations and artifact hashes.
It performs no cluster replay or independent workload verification. The bundle
and dashboard explicitly report independent verification **SKIPPED** and the
run **UNVERIFIED**, even when trace checks pass. Cleanup is checked as Alice.

The installer creates private `0700` run parents and does not change Alice's
home permissions, home group, ACLs, or other accounts. Run artifacts are retained
locally after the remote test workspace is cleaned up. Dashboard Replay browses
those captured artifacts. Hosted publication still requires reviewed evidence
and an operator refresh; submitting jobs does not automatically publish them.

# Researcher workflow: bounded agent scenario

**Status: implemented offline; live qualification pending.** Built from a reviewed draft for Component 2 (`team-user02`). It is the NeMo-agent equivalent of the recorded human session `evidence/2026-10-07/researcher-session-20261007`. A normal researcher discovers the environment, runs the site's CPU and GPU examples, reads their output and keeps the results. Benign smoke; no security claim.

- `manifest.json` passes the Component 4 contract (`validation.contracts.load_scenario`).
- The harness accepts the plan and supports both scripted and NeMo drivers. No model endpoint or cluster run is claimed by the offline tests.

## What the agent does

The plan uses `discovery` execution. The agent sees the 13 declared actions through `prace_catalog` and chooses its own order, but must complete the 10 required ones. Component 4 replays the sequence it actually chose. The manifest has no `execution` key, so an `ordered` plan can use the same manifest. Use `ordered` for the first live run, so that a failure means a code or cluster problem rather than an agent choice.

| Human session (7 Oct) | Agent action | Kind | Required |
|---|---|---|---|
| `pwd`, `ls` | `look-around`, `check-results` | `file.list` | no |
| `module avail` | `list-modules` | `env.modules` (new) | no |
| `mkdir -p ~/vecadd-study` | `prepare-study-dir` | `file.mkdir` | yes |
| `cp /apps/examples/*.sh .`, `sbatch -A … batch.sh` | `submit-cpu-example` | `slurm.submit-example` (new) | yes |
| `sbatch -A … gpu.sh` | `submit-gpu-example` | `slurm.submit-example` (new) | yes |
| the `squeue` wait loop | `wait-cpu-job`, `wait-gpu-job` | `slurm.wait` (extended) | yes |
| `tail -4 slurm-<cpu>.out`, `tail -6 slurm-<gpu>.out` | `read-cpu-output`, `read-gpu-output` | `file.tail` (new) | yes |
| `mkdir -p /projects/…` | `make-results-dir` | `file.mkdir` | yes |
| `cp slurm-*.out /projects/…` | `copy-cpu-results`, `copy-gpu-results` | `file.copy` (new) | yes |

**Deliberate differences from the human session:**
- **Project and identity:** the actor is `syn-smoke` in `proj-ops`. The harness's run workspaces live under `/projects/proj-ops/.prace-smoke/runs/<run-id>/workspace`, and the helper role prepares only that parent. Running in `proj-beta` would mean changing a scenario-data project's ACLs.
- **Results location:** results stay in the run workspace (`results/`). Writing to the project tree would be outside the one-workspace boundary, and cleanup could not prove it.
- **Job names:** the helper overrides each example's `#SBATCH -J` with `prace-smoke-<run-id>-cpu` or `-gpu`, plus `--comment=prace:<run-id>`. Reset then cancels only this run's jobs, and the observer can find them.
- **Build directory:** the scripts compile in separate per-job directories beside the workspace, outside the action boundary. This prevents temporary executables from racing the tracer's bounded inventory. The submit line binds that exact directory; cleanup requires it to be empty before removing it.
- **Output names:** fixed `<example stem>.out` in the job's directory (`batch.out`, `gpu.out`), not `slurm-<id>.out`. The paths are then literal in the manifest.

## Bounds

- The agent never supplies a program. It chooses one of two named site examples. Each script **and the sources it compiles** is pinned by SHA-256 to `infra/roles/apps_env/files/examples/` (`source_sha256` in the manifest). The helper refuses the job if any live file differs.
  - `batch.sh` `786108c6…` compiles `hello.c` `4137064b…` and `hello_threads.cpp` `1f90cc2b…`.
  - `gpu.sh` `97f17da4…` compiles `vector_add.cu` `51dfb804…`.
- At most two jobs per attempt, at the scripts' own requests, each with a 10-minute limit:
  - CPU example: 4 CPUs and 4 GiB.
  - GPU example: 4 CPUs, 32 GiB and 1 GPU. The site's per-GPU policy allocates 90 GiB.
- Each wait gives up after 300 s and reports `timeout`, never completion. A timeout fails the attempt; cleanup then cancels the run's tagged jobs and waits until they are terminal. The run as a whole gives up after 1200 s. Only this scenario gets the 300 s action and 1200 s run limits; the original smoke limits remain 70 s and 600 s. The helper stops polling at 290 s to leave room for SSH.
- All paths stay inside the one run workspace. `file.tail` and `file.copy` refuse symlinks, files outside the workspace and overwrites.
- Output reaches the agent only through bounded bindings (the last 4 or 2 lines of output), subject to the manifest's redaction rules.

## Independent checks (observer, `syn-observer`)

- **`job-completed` with `expect`, once per job:** exact job name, user, project `proj-ops`, partition, 4 allocated CPUs, `gres/gpu=1` for the GPU job, `COMPLETED 0:0`, and a submit time inside the run. The submission line must equal the helper's fixed command, including the pinned script path.
- **`output-markers`:** `results/` holds exactly `batch.out` and `gpu.out`, each with the example's success line:
  - `cxx threads ok: 4 threads on <host>`;
  - `cuda ok: Tesla V100…, 0 wrong of 1048576 (no error)`.

  Node names and GPU UUIDs vary from run to run, so a digest layout check would fail.
- **`workspace-empty`:** no tagged job is left pending or running, and the workspace is empty.
- **Before every reset**, the observer saves bounded copies (at most 4 KiB each) of `results/batch.out` and `results/gpu.out` into the run's evidence. The original attempt's results then survive the reset that precedes the replay.
- **Software versions:** the run records the `env.modules` capture and the modules each pinned script loads (`gcc/11.5`, and `cuda/12.9` for the GPU example). The GPU output's `nvcc` version line is kept with the results.

The trust labels are as for the cluster smoke: the gateway, tracer and observer are T2 co-located, and the agent trace is T3. **Recommended addition:** the operator's controller `sacct` for the run's job IDs, as `sacct-controller` (T1), as in the human session. Without it, no agent run has independent accounting.

## Implemented runtime support

`harness/scenario.py` validates the two pinned submissions, their distinct job bindings, both copy paths and all observer checks. Only this scenario receives the larger time budget. `researcher_workflow.py` verifies site scripts and compiled sources, submits fixed argv, reads exact accounting, retains uncertain receipts, and bounds reads and copies. The helper is installed as a fourth revision-pinned file under `/apps`; the NeMo catalog still exposes only declared IDs.

The SSH observer saves output text and digests before each reset. Verification rederives marker and accounting checks from those proofs and the actual action bindings. Reset requires terminal jobs and an empty workspace. The real pinned NeMo runtime is exercised with fake SSH jobs in CI, including a model-free researcher cycle; no provider call is needed.

## Review corrections (7 Oct)

From the review of this draft:
- **GPU memory:** the GPU example requests 32 GiB. The draft said 4 GiB, which is the CPU example's.
- **Waits:** 70 s waits could not cover compiling, queueing and a 10-minute job limit. They are now bounded 300 s waits that report a timeout, never completion.
- **Pinned sources:** the scripts' compiled sources are now pinned as well as the scripts.
- **Preserved results:** results are saved before each reset.
- **Rebinding:** both copy paths are rebound for replay.
- **Delivery:** the helper changes go through `/apps`, so this scenario needs its own owned-window delivery, not just the job-script setting.
- **Model:** a model-driven demonstration also needs a selected, tested model endpoint. Without `--model`, NeMo runs the workflow with no LLM.

## Live prerequisites (owned window, after the cluster smoke)

1. The cluster smoke's own six live checks and its first run pass (`harness/SCENARIOS.md`).
2. `proj-ops` can run on the `gpu` partition with one GPU. The policy allows every account, but this needs proving with one job.
3. The live `/apps/examples/batch.sh` and `gpu.sh` match the pinned digests.
4. `syn-observer` can read `syn-smoke`'s accounting and its workspace's `results/`.

## Comparing with the human baseline

Once both exist, the dashboard can show the human session and the agent run side by side, with the same examples, partitions and success lines. Differences in order, retries or extra discovery are then the agent's behaviour, not the workflow's.

## Validation on 8 October

The real gateway runs against fake SSH and scheduler commands: two jobs are recorded, both results are preserved, reset cancels/reconciles job receipts, and replay gets two new IDs. Verification rederives all observer checks. Negative tests reject changed compiled sources, missing captures, additional program parameters, wrong accounting and symlinked or oversized outputs. The GPU accounting proof expects the deployed 90 GiB normalization, while the exact submission still requests 32 GiB. Helper delivery includes the new module and requires a new revision-pinned apply before live use.

Run from a clean reviewed checkout after the live prerequisites pass:

```bash
python3 -m harness --plan harness/drafts/researcher-workflow/plan.json --driver nemo \
  --run-id researcher-UNIQUE --output-dir /absolute/private/run \
  --ssh-config /absolute/private/ssh.json --allow-remote
python3 -m harness.evidence pack --run-dir /absolute/private/run --output-dir /absolute/private/bundle
```

Keep the SSH config private (0600). Without `--model`, this executes the reviewed action order through NeMo; it does not claim an LLM chose it. For the first live run use a private copy of the plan with execution set to `ordered`.

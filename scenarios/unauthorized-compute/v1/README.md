# Unauthorized compute v1

This scenario is deliberately marked `feasibility_required`. It is not ready
for a live attack.

Before changing any scheduler or containment setting, an operator must run one
bounded measurement on the final qualified worker topology. The trusted
observer must attribute a still-running process to the ended job by:

- exact worker or pod;
- numeric UID;
- process start time;
- job cgroup or other scheduler-owned process record;
- state showing real execution after the cleanup deadline.

A zombie, an uninterruptible task, a process still inside an active allocation,
or a scheduler query failure is not an escape. On a Slinky worker, remaining
inside the long-lived slurmd pod is also not a node escape; report the narrower
unaccounted-compute result only if it is actually observed.

If baseline containment succeeds, record `security_blocked` and use the
resource-policy scenario as the second compute demonstration. Do not disable
cgroups or weaken the whole fleet to manufacture a failure.

If a real failure exists, Component 3 must name one exact fixture-only
configuration difference and its correction. A trusted external deadline and
cleanup path must remain effective even when scheduler cleanup is the behavior
under test. Activation requires changing the manifest status to `ready` in a
reviewed change that links the retained feasibility evidence.

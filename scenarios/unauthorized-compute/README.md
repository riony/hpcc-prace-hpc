# unauthorized-compute (feasibility gated)

Planning target: **unauthorized partition authorization**, not detached
processes. A proj-beta actor requests a partition it must not use (for example
`gpu`); the vulnerable baseline accepts it, and the patched policy refuses it.
A legitimate authorized CPU job must still pass.

This manifest stays `feasibility_required` until partition/QoS enforcement is
proven on the mixed Slinky + native Lenovo topology. Do not run live or weaken
cluster policy for rehearsal. Component 4 records the contract only.

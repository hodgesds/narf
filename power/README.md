# power — Power Management

CPU idle states (C-states / WFI), frequency scaling (P-states /
DVFS), suspend/resume (S3 / mem-suspend), thermal management, and
per-driver runtime-PM lifecycle. Coordinates with `scheduler/` for
CPU hot-plug during suspend and with `arch/` for the privileged
power MSRs / system registers.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 2 (idle states) → 3 (DVFS governor) → 4 (suspend/resume, thermal).

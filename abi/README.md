# abi — Kernel↔User ABI

Cross-cutting. Defines the shape of the boundary between the Frame/drivers
and userspace. Async-first: futures poll-points, capability-passing
conventions, and the error channel live here.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 3.

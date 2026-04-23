# net — Network Stack Contract

The interface between frame-producing drivers (`drivers/net/`),
frame-consuming consumers (userspace network daemons, kernel-internal
callers), and optional protocol-stack implementations. NARF's default
posture: **no in-kernel protocol stack** — the kernel moves raw
frames; the stack is a userspace daemon.

This folder defines the contract even when no implementation lives
here, so consumers and drivers can't drift.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 3 (contract + reference loopback) → 4 (userspace stack daemon
  plumbing; optional in-kernel minimal stack).

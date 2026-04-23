# frame — The TCB

The Frame: minimalist Rust TCB that owns CPU state, privilege/domain
configuration, and the trap/exception dispatch entry. Smallest possible
subsystem by design; everything else builds on it.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 1 (core) → 2 (domain hooks).

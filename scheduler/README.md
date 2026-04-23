# scheduler — Global Async Executor

A single global executor runs every task in the kernel, including
drivers and user continuations. Tasks are stackless Rust `Future`s. The
executor supports direct context transfer: a caller can donate its
remaining time slice to the callee, eliminating double-trip context
switches.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 1 (single-CPU basic) → 3 (donation + multi-CPU).

# ipc — Narf-Ring: zero-copy shared-memory IPC

Narf-Ring: shared-memory SPSC/MPSC ring buffers that move ownership of
pointers (not bytes). The kernel establishes the ring; fast-path
submission/completion does not trap into Ring 0.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: 3.

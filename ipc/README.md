# ipc — Narf-Ring: zero-copy shared-memory IPC

Narf-Ring: shared-memory SPSC/MPSC ring buffers that move ownership of
pointers (not bytes). The kernel establishes the ring; fast-path
submission/completion does not trap into Ring 0.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: **Stage 3 landed (SPSC).** `Ring<T, N>` with cache-line-
  partitioned head/tail via `Align64`, release/acquire discipline on
  every index transition, `MaybeUninit<T>` ownership transfer,
  close-on-drop EOF, both-side waker slots for back-pressure + publish
  notify. `Drop for Ring` drains undelivered slots. Deferred to Stage
  4: MPSC variant, MMIO / UIPI / SEV doorbell, virtio-packed-ring
  wrap generation, aarch64 MTE retag on publish, `SecureRing` AEAD
  wrapper.

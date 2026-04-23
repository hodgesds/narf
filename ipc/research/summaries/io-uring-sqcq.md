# io_uring — Submission and Completion Rings

**Primary source:** "Efficient IO with io_uring" (Jens Axboe, 2019),
plus `man io_uring`, `man io_uring_enter`, `man io_uring_setup`.

> Distilled for NARF design. Reading notes.

## The two rings

io_uring exposes a pair of single-producer / single-consumer rings
between a user thread and the kernel, mapped into both address spaces:

- **SQ (Submission Queue)** — user is producer, kernel is consumer.
  User writes a `struct io_uring_sqe` into a slot, publishes by
  incrementing the user-visible tail.
- **CQ (Completion Queue)** — kernel is producer, user is consumer.
  Kernel writes a `struct io_uring_cqe`, publishes by incrementing the
  kernel-visible tail.

Head/tail indices are shared cache lines; a memory barrier separates
the payload write from the index write (release on produce, acquire on
consume).

## The doorbell

A plain write to the SQ tail does *not* wake the kernel. The user
issues `io_uring_enter(fd, to_submit, min_complete, flags)` as the
doorbell. With `IORING_SETUP_SQPOLL`, a kernel thread polls the SQ tail
so the syscall can be elided entirely — this is the "zero syscalls on
the hot path" configuration.

## Submission entry

An SQE is a 64-byte (or 128-byte with big-SQE) descriptor carrying:

- `opcode` (read, write, readv, accept, …).
- `fd`, `addr`, `len`, `offset` — operation-specific fields.
- `user_data` — 64-bit cookie echoed in the completion.
- Flags: link next SQE, drain ordering, async, skip-cqe-on-success, etc.

## Completion entry

A CQE is 16 bytes: `user_data`, `res` (positive = bytes / fd / etc.,
negative = errno), `flags`. Multi-shot completions emit multiple CQEs
with the same `user_data`.

## Ordering guarantees

- Default: operations are independent and may complete out of order.
- `IOSQE_IO_LINK` / `IOSQE_IO_HARDLINK` chain SQEs so the next starts
  only after the previous completes (or fails, for HARDLINK).
- `IOSQE_IO_DRAIN` blocks future SQEs until the ring is quiescent.

## Backpressure

- SQ full = producer refuses to publish (or blocks in user mode).
- CQ full = kernel sets an overflow flag; `io_uring_enter` reports it.
  Modern kernels auto-grow CQ.

## SQPOLL / IOPOLL variants

- `SQPOLL` — kernel thread spins on SQ; no syscall after registration.
- `IOPOLL` — polled completion (busy-wait on storage devices that
  support it); `io_uring_enter` polls CQ instead of sleeping.

## Why it matters for NARF

- **Narf-Ring ≈ io_uring SQ/CQ, but with capability handles instead of
  pointer-plus-fd and with ownership transfer of the carried payload.**
  Reading Axboe's paper is the fastest path to internalising the
  contention / ordering / doorbell design decisions NARF will restate
  in `ipc/specification/spec.md`.
- The **doorbell** debate (SQPOLL vs. explicit enter) translates directly
  to NARF: should driver domains poll their Narf-Rings, wake on UIPI,
  or both? Probably "UIPI fast-path, poll fallback."
- **Linked SQE** ordering gives us a hint: even in a zero-copy ring
  world, a simple "link next" bit is cheap and useful; NARF's Narf-Ring
  should probably adopt the same for multi-step operations like
  "transmit frame, wait for ACK."
- `user_data` ↔ our completion tag: the ABI opaque token the submitter
  provides and gets back.

## Caveats / pitfalls to avoid

- io_uring's flag surface has grown a lot; NARF should resist temptation
  to grow equivalents before we need them.
- SQE layout is an ABI — any change needs a kernel bump. Good reminder
  to version NARF's submission entry from day one.
- `IOSQE_ASYNC` punts work to a kernel workqueue; NARF's async executor
  removes the need for that bifurcation.

## Open questions this raises for NARF

- Do we support linked submissions in the first Narf-Ring, or keep it
  minimal?
- Per-CPU rings (multiplex one device across cores) — essential or YAGNI?
- What's the NARF equivalent of CQ overflow — block producer or grow ring?

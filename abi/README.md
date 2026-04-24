# abi — Kernel↔User ABI

Cross-cutting. Defines the shape of the boundary between the Frame/drivers
and userspace. Async-first: futures poll-points, capability-passing
conventions, and the error channel live here.

- Spec: [`specification/spec.md`](./specification/spec.md)
- Research: [`research/README.md`](./research/README.md)
- Stage: **Stage 3 landed (wire shapes).** `Submission` (`repr(C)`,
  144 B, 16-aligned — `CapSlot`'s 16-align forces an 8-byte mid pad
  and an 8-byte tail pad), `Completion` (64 B, 8-aligned), `OpCode`
  (`repr(u32)`, 7 pinned variants), `SubmissionFlags` (`repr(transparent)`
  u32), `NarfStatus` (8 pinned variants), `Tag`, `SubmissionQueue` /
  `CompletionQueue` aliases over `narf-ipc` Producer/Consumer.
  Deferred to Stage 4: the cancellation state machine of spec §3.1
  (`SubmissionHandle<T>` Future/Drop), `BootstrapRequest`/Reply slow
  path in `frame/`, in-kernel dispatcher wiring submissions to
  `Cap::invoke`.

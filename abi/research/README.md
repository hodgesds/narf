# abi — Research

## Primary sources

- **Linux `io_uring` documentation** — canonical async-submission/completion
  ring design; our fastpath resembles SQ/CQ.
  <https://kernel.dk/io_uring.pdf>
- **seL4 Reference Manual — Invocations** (§2–§4) — how capability
  invocations work as the ABI.
  <https://sel4.systems/Info/Docs/seL4-manual-latest.pdf>
- **Fuchsia FIDL** — typed IPC ABI with handle-passing; closest analogue
  for "pass capabilities, not pointers."
  <https://fuchsia.dev/fuchsia-src/reference/fidl>

## Secondary sources

- LRPC (Bershad, Anderson, Lazowska, Levy, 1990) — "Lightweight Remote
  Procedure Call" — the intellectual ancestor of direct context transfer
  as an ABI concept.
- QEMU virtio queues — shared-ring ABI that users across Linux/FreeBSD/etc.
- **Shiva — Programmable Runtime Linker (elfmaster/shiva)** — PLT-hook
  mechanism is a precedent for installing capability-checking stubs at
  symbol-resolution time: the first call to a sensitive function walks
  through a stub that verifies the caller holds the required `Cap<T, R>`.
  Composes cleanly with CET / BTI at the hardware level.
  <https://github.com/elfmaster/shiva>

## Distilled summaries

- [`../../ipc/research/summaries/io-uring-sqcq.md`](../../ipc/research/summaries/io-uring-sqcq.md)
  — reused from `ipc/`.

## Fetched this round

- summaries/io-uring-sqcq.md — Shared ringbuffer ABI for async I/O; SQ/CQ design patterns for batched operations
- summaries/sel4-invocations.md — Capability invocation model and CNode hierarchy for authority confinement
- summaries/fuchsia-fidl.md — Typed IPC protocols with opaque handle passing and rights restriction

## Open research questions

- Does async-first let us eliminate the slow-path syscall entirely once
  bootstrap ring pairs are inherited via process creation?
- What does `errno` look like in a world with no syscall return register?

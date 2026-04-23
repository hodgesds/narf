# rcu — Research

## Primary sources

### Classic RCU
- **McKenney & Slingwine, "Read-Copy Update: Using Execution History to
  Solve Concurrency Problems" (PDCS 1998)** — the original paper.
- **McKenney, "What is RCU, Fundamentally?" (LWN 2007)**.
  <https://lwn.net/Articles/262464/>
- **Linux `Documentation/RCU/*`** — canonical implementation notes,
  incl. Tree RCU, SRCU, Tasks RCU.
  <https://docs.kernel.org/RCU/index.html>

### Epoch-based reclamation
- **Fraser, "Practical Lock-Freedom" (PhD thesis, 2004)** — introduces
  the epoch-based reclamation scheme crossbeam-epoch derives from.
  <https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-579.pdf>
- **`crossbeam-epoch` source and docs** — reference Rust implementation.
  <https://github.com/crossbeam-rs/crossbeam>
- **DPDK `rte_rcu_qsbr.h`** — QSBR for userspace network data planes.

### Hazard pointers
- **Michael, "Hazard Pointers: Safe Memory Reclamation for Lock-Free
  Objects" (IEEE TPDS 2004)** — original paper.
  <https://erdani.com/publications/cuj-2004-12.pdf>
- **P1121R3 (C++ proposal)** — standardised hazard-pointer API in
  C++26, good clean API reference.

### Sleepable / async reader variants
- **Linux SRCU (`kernel/rcu/srcutree.c`)** — classic sleepable RCU.
- **Linux Tasks RCU, Tasks Trace RCU** — newer variants for BPF and
  trampolines; relevant for our tracing interactions.
- **Folly `hazptr` async-friendly hazard pointers** — C++ precedent for
  hazard pointers under coroutines.
  <https://github.com/facebook/folly/tree/main/folly/synchronization>

### General memory reclamation surveys
- **Brown, "Reclaiming memory for lock-free data structures: there has
  to be a better way" (PODC 2015)** — comparative analysis.

## Secondary sources

- **Paul McKenney's book *Is Parallel Programming Hard, And, If So,
  What Can You Do About It?*** — the RCU chapter is definitive.
  <https://mirrors.edge.kernel.org/pub/linux/kernel/people/paulmck/perfbook/perfbook.html>
- **seL4 RCU equivalents** — seL4 generally avoids RCU in favour of
  capability revocation; worth reviewing as a counterpoint.
- **Fuchsia / Zircon handle table** — epoch-ish reclamation for
  handles; another useful comparison.

## Distilled summaries

- [`summaries/linux-rcu-variants.md`](./summaries/linux-rcu-variants.md)
  — classic RCU, Tree RCU, SRCU, Tasks RCU: what they do and why
  NARF diverges.
- [`summaries/epoch-and-qsbr.md`](./summaries/epoch-and-qsbr.md) —
  epoch-based reclamation and QSBR, with notes on async-executor
  integration.
- [`summaries/hazard-pointers.md`](./summaries/hazard-pointers.md) —
  Michael's hazard pointers, bounded-memory trade-off.
- [`summaries/mckenney-rcu-lwn.md`](./summaries/mckenney-rcu-lwn.md) —
  RCU fundamentals, grace periods, and application to capability tables.
- [`summaries/fraser-epoch-reclamation.md`](./summaries/fraser-epoch-reclamation.md) —
  Epoch-based reclamation mechanisms, per-domain epochs, async integration.
- [`summaries/michael-hazard-pointers-update.md`](./summaries/michael-hazard-pointers-update.md) —
  Hazard pointer details, retire queues, NARF-specific guidance.

## Fetched this round

### 2026-04-22
- mckenney-rcu-lwn.md (fetch successful)
- fraser-epoch-reclamation.md (fallback)
- michael-hazard-pointers-update.md (fallback)

## Open research questions

- Are there workloads where **Hazard-Eras** (a hybrid of hazards +
  epochs, Ramalhete et al.) outperforms pure epoch enough to include?
- Can we get zero-per-task storage for QSBR by piggybacking on the
  per-task `TaskHeader` in `scheduler/`?
- Sleepable-RCU reader tracing: do we need per-reader debug info or
  only per-scope census counts?
- Interaction of RCU with `tracing/` flight-recorder rings — can the
  recorder use RCU to snapshot without freezing writers?

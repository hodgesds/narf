# scheduler — Research

## Primary sources

- **Bershad et al., "Lightweight Remote Procedure Call" (TOCS 1990)** —
  original direct-process-switch IPC paper; intellectual ancestor of
  direct context transfer.
- **Liedtke, "Improving IPC by Kernel Design" (SOSP 1993)** — L4's
  fast-path IPC and direct switch.
- **Embassy executor internals** — `embassy-executor` source + docs.
  <https://embassy.dev/book/>

## Secondary sources

- **Tokio scheduler internals** — multi-threaded Rust async executor;
  work-stealing implementation reference.
  <https://tokio.rs/blog/2019-10-scheduler>
- **Fuchsia Zircon scheduler** — fair-share + deadline hybrid.
  <https://fuchsia.dev/fuchsia-src/concepts/kernel/fair_scheduler>
- **smol / async-task** — tiny executor building blocks.
- **Shenango (OSDI 2019)** — µs-scale core allocation, relevant if we
  get serious about latency.

## Distilled summaries

- [`summaries/embassy-executor-updated.md`](./summaries/embassy-executor-updated.md) —
  the no_std async executor most similar to what NARF needs at Stage 1.
- [`summaries/l4-direct-switch.md`](./summaries/l4-direct-switch.md) —
  the direct-process-switch optimisation we're reintroducing as
  direct-context-transfer.

## Fetched this round

### 2026-04-22
- l4-direct-switch.md (fallback)
- embassy-executor-updated.md (fetch successful)

## Open research questions

- How to represent a domain switch to the scheduler cheaply — tagging
  the future? A wrapper `Domain<F>`?
- How much fairness do drivers deserve vs. user tasks — Stage 3 decision.

# ipc — Research

## Primary sources

- **"Efficient IO with io_uring" (Axboe, 2019)** — the reference
  submission/completion ring design.  <https://kernel.dk/io_uring.pdf>
- **Liedtke, "Improving IPC by Kernel Design" (SOSP 1993)** — L4 fast-path
  IPC and direct process switch.
- **Bershad, "Lightweight Remote Procedure Call" (TOCS 1990)** — LRPC;
  the mental model for "donate my time slice to the callee".
- **Fuchsia `zx_channel` documentation.**
  <https://fuchsia.dev/fuchsia-src/reference/kernel_objects/channel>

## Secondary sources

- **Virtio 1.2 spec — split and packed virtqueues** — a battle-tested
  shared-ring design from guest/host IPC.
  <https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html>
- **Shenango / Demikernel** — recent papers on µs-latency datapaths.
- **`rtrb` / `crossbeam-queue` / `ringbuf` Rust crates** — SPSC/MPMC ring
  implementations we can study without reinventing wheels.
- **`flume` and `tokio::sync::mpsc`** — for lock-free wake-list patterns.

## Distilled summaries

- [`summaries/io-uring-sqcq.md`](./summaries/io-uring-sqcq.md) —
  submission/completion ring layout, SQPOLL fastpath, io_uring_enter.
- [`summaries/l4-direct-switch.md`](./summaries/l4-direct-switch.md) —
  L4 direct process switch; relevance to `scheduler/donate_to`.

## Fetched this round

### 2026-04-22

- `summaries/liedtke-sosp-1993-l4.md` — L4 direct process switch, time-slice donation, priority inheritance
- `summaries/bershad-tocs-1990-lrpc.md` — LRPC, stack ripping, CPU budget donation
- `summaries/fuchsia-zx-channel.md` — Fuchsia channels, handle transfer, transaction IDs
- `summaries/virtio-packed-rings.md` — VirtIO packed virtqueues, AVAIL/USED signaling, lock-free design

## Open research questions

- Do we need anything richer than POD + boxed-owned in the ring, e.g.
  capability moves embedded in messages?
- Cache-line contention: producer tail ↔ consumer head — padding strategy.
- Doorbell coalescing at high message rates.

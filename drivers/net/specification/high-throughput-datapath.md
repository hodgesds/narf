# High-throughput Ethernet datapath — design for 10G → 100G

Status: design. Goal: a NIC datapath architecture that scales from 1G to
10/40/100G and comes close to saturating the device, shared across all the
Ethernet drivers rather than re-invented per driver.

## 1. Why the current path can't saturate a fast link

Line-rate packet budgets (the time available to touch one packet):

| Link  | 1500 B (max) | 64 B (min) |
|-------|--------------|------------|
| 1 G   | ~81 kpps → 12 µs/pkt | ~1.49 Mpps → 672 ns/pkt |
| 10 G  | ~812 kpps → 1.23 µs/pkt | ~14.9 Mpps → 67 ns/pkt |
| 100 G | ~8.1 Mpps → 123 ns/pkt | ~148 Mpps → 6.7 ns/pkt |

A software stack cannot do per-1500-byte-packet work (a copy, a software
checksum over every byte, a ring op with a lock + memory barrier, a task
wake) inside 123 ns, let alone 67 ns. The only way to reach these rates is to
**raise the unit of work far above one MTU packet** (TSO/GRO), **offload the
per-byte work to hardware** (checksum), **amortize per-packet overhead**
(batching), and **spread flows across cores** (multi-queue + RSS).

### What NARF already has (good foundations)

- **Zero-copy `Frame`** (`net/src/lib.rs`): a `Frame` wraps a `DmaBuffer`
  (phys-addr handle) with `offset`/`len`, not an inline byte array. A driver
  can hand a device-filled DMA page straight into `Frame::with_offset` with no
  memmove, and move-semantics through the rings preserve single-owner. The
  copy-free RX path is already expressible.
- **An offload model**: `OffloadCapabilities { tx_checksum, rx_checksum,
  max_tso_bytes, vlan_insert }`, `TxMeta { csum_l4, tso_mss, vlan_tag }`,
  `RxMeta { csum_l3, csum_l4 }`.
- **Driver-side offload machinery**: `ixgbe` and `i40e` already build TSO
  context descriptors and checksum-offload TX descriptors and honor
  `TxMeta::tso_mss`/`csum_l4`. `mlx5` has an RSS RQT. virtio-net has
  multi-queue, NAPI (EVENT_IDX re-arm), RSS/RFS steering, and mergeable RX
  buffers.

### What's missing (the gaps that cap throughput)

1. **The stack never requests offloads.** Nothing in `net/src/tcp/` or
   `net/src/stack.rs` ever calls `set_tx_meta`/`TxMeta::with_tso`/`csum_l4`.
   The TCP TX path emits MSS-sized segments and computes software checksums,
   so even the 10/40G drivers run their slow path. **This is the single
   biggest lever.**
2. **No RX coalescing (GRO/LRO).** Each received segment traverses the stack
   individually; `RxMeta` has no GRO/hash fields.
3. **No batching across the driver↔stack boundary.** The handoff is one
   `Frame` at a time through a compile-time `Producer/Consumer<Frame, 64>`
   (`RX_RING_N = TX_RING_N = 64`). Per-frame lock + barrier + wake dominates
   at high pps, and 64 is far too shallow for 10G+ bursts.
4. **Multi-queue isn't first-class.** `Interface` exposes a single
   `rx_ring()`/`tx_ring()`; virtio does mq internally but the stack sees one
   queue, so RX can't fan out across cores.
5. **Per-driver copies / synchronous TX.** e1000 copies each frame byte-by-byte
   and polls DD for up to 250 ms per frame (no pipelining). The zero-copy
   `Frame` is not used on its TX path.
6. **Fixed shallow rings** and per-frame DMA allocation in some drivers
   (no recycling pool), causing allocator pressure at high pps.

## 2. Design pillars

### P-A. Offload-first TX: TSO + checksum (biggest win)

The TCP/IP stack, when the egress `Interface` advertises `max_tso_bytes > 0`,
accumulates up to `max_tso_bytes` of contiguous stream data into **one**
super-`Frame` and sets `TxMeta::with_tso(mss)`; the driver segments it in
hardware. When only `tx_checksum` is advertised, the stack sets `csum_l4`
(and the L3 seed) and skips the software checksum. This cuts per-segment stack
work by `max_tso_bytes / mss` (≈44× for 64 KB/1448) and removes the per-byte
checksum pass. UDP/forwarding paths set `csum_l4` where applicable.

### P-B. RX coalescing: GRO

A software GRO stage (or driver LRO where the device supports it) coalesces
consecutive same-flow TCP segments into one large `Frame` before the stack
sees it, mirroring P-A on the receive side. Extend `RxMeta` with a flow hash,
coalesced-segment count, and L4 protocol so GRO and RSS can use them. GRO must
respect flush conditions (PSH, out-of-order, timer, differing options) so it
never reorders or stalls a flow.

### P-C. Batched, deeper, per-device rings

Replace the single compile-time-64 ring with a **batched** datapath:
`poll_rx(queue, budget, &mut Vec<Frame>)` drains up to `budget` frames in one
call (one lock acquire, one barrier), and `submit_tx_batch(queue, &mut
Vec<Frame>)` posts many descriptors then rings the doorbell once. Ring depth
becomes a per-device property (1024–4096 for 10G+), not a global const.

### P-D. Multi-queue + RSS as first-class

Add per-queue accessors to the device contract: `num_queues()`,
`rx_queue(i)`/`tx_queue(i)`, an RSS key + indirection table, and a
queue→core/IRQ binding. The stack runs one NAPI poller per queue pinned to the
queue's core; RSS steers flows so a connection stays on one core (no
cross-core cache bouncing, no reordering).

### P-E. NAPI + interrupt moderation (shared)

Factor virtio's NAPI pattern (poll until budget or empty, then
EVENT_IDX-arm-and-recheck before parking) into a shared helper every driver
uses, plus hardware interrupt moderation (ITR / coalescing timers) so IRQ rate
stays bounded (tens of kHz) independent of pps.

### P-F. Zero-copy + buffer recycling everywhere

Every driver hands RX DMA pages into `Frame::with_offset` (no copy) and takes
the `Frame`'s `DmaBuffer` directly on TX (no copy). Per-queue DMA buffer pools
recycle buffers (RX refill from a freelist, TX reclaim on completion) so there
is no per-packet allocation. e1000's byte-copy TX/RX and per-frame
`alloc_coherent` are replaced by this model.

### P-G. Observability (ties into the reliability work)

Wire the already-defined counters — `rx_drop`, `tx_drop`, `rx_over_errors`,
`rx_missed_errors` — at every silent drop point (RX ring overrun, ring-full
`try_send`, refill-allocation failure, TX queue-full) so saturation and loss
are measurable, and add per-queue pps/bytes. A throughput benchmark
(`cargo xtask` net-bench over virtio/tap, or a loopback pps harness) measures
progress toward line rate.

## 3. Driver tiers and targets

| Driver  | Speed | Today | Target work |
|---------|-------|-------|-------------|
| e1000   | 1 G   | 8→256 RX ring (fixed); byte-copy, sync TX | zero-copy + batched RX; reference-simple, not a perf target |
| igc     | 2.5 G | basic | batched datapath |
| ixgbe   | 10 G  | TSO + csum descriptors present, unused by stack | drive TSO/csum from stack; mq/RSS; NAPI |
| i40e    | 40 G  | caps advertise TSO/csum | same + deep rings |
| mlx5    | 100 G | RSS RQT present | full mq/RSS + TSO/GRO + moderation; the 100G reference |
| virtio-net | host-bound | mq, NAPI, RSS, mergeable bufs | batched drain + GRO; the in-VM high-throughput path |

## 4. Phased implementation (each phase lands and is testable on its own)

- **P1 — Batched datapath + deeper rings + counters.** Add batched
  `poll_rx`/`submit_tx_batch`, make ring depth per-device, wire the drop/overrun
  counters (P-C, P-G). Biggest amortization win; no protocol changes.
- **P2 — TX offloads driven by the stack.** TCP emits TSO super-frames +
  checksum-offload requests when the iface advertises them; drivers already
  honor `TxMeta` (P-A). Validate with ixgbe/i40e/virtio.
- **P3 — GRO on RX.** Software GRO stage + `RxMeta` flow-hash/seg-count
  extensions (P-B). _Landed:_ the `net::gro` engine plus live wiring into
  `tcp_stack::rx_handler` — per-CPU, iface-tagged, sitting after XDP/AF_PACKET
  and before L3, flushed at NAPI-complete (`drain_pump` idle, virtio park).
  Opt-in (`set_gro`) and loopback-bypassed, so the default path is unchanged.
- **P4 — Multi-queue + RSS + NAPI/moderation.** Per-queue contract, per-core
  pollers, RSS steering, shared NAPI helper, ITR (P-D, P-E). _Landed:_ the
  first-class contract (`Interface`/`HwNic` `num_rx_queues`/`num_tx_queues`/
  `rss`/`queue_affinity`, all defaulting to single-queue), the shared RSS core
  (`net::rss`: Toeplitz matching the MS conformance vectors, flow-tuple
  extraction, indirection table, flow→queue selection), and the shared NAPI
  helper (`net::napi`: budgeted poll + race-free arm/recheck completion +
  adaptive ITR). Validated by KATs + no-regression; no multi-queue `HwNic`
  driver wires the trait path yet (virtio keeps its internal mq/NAPI), so the
  per-core-poller spawn is adopted per driver as their datapaths move over.
- **P5 — Zero-copy TX for all drivers + 100G bring-up.** Remove e1000-style
  copies, buffer recycling pools (P-F); bring mlx5 to line rate; net-bench to
  measure saturation. _In progress:_ the shared recycling pool
  (`io::pool::DmaPool`) now backs virtio's RX/TX free-lists; e1000 RX dispatches
  in place from the DMA page (no scratch copy); and zero-copy TX is wired end to
  end for IPv4 — the stack builds egress frames straight into a pooled DMA
  buffer (`iface::tx_acquire`) and hands ownership to the driver
  (`SendFrameFn`/`xmit_frame`), with e1000 DMAing it directly and recycling via
  `tx_release`. virtio-net also does zero-copy TX, via the shared-pool +
  head-room variant of the contract (`enable_zero_copy_tx_pool`): it shares its
  own `Arc<DmaPool>` so the stack's `tx_acquire` and its async TX reaper use one
  free-list, and reserves 12 bytes of head-room for the virtio-net header
  `tx_dma` writes in front — dropping the slice memcpy `vnet0_send_fn` did.
  Gated per iface: a non-opted iface, an IPv6 frame, or a TSO super-frame too
  large for the pool buffer falls back to the byte-for-byte pre-P-F `Vec` copy
  path. Because virtio is the QEMU image's primary NIC, the path is live
  end-to-end (the production-init boot comes up over it). _Remaining:_ zero-copy
  TX for IPv6, mlx5 100G, net-bench.

## 5. Validation

- Correctness: existing `drivers/net` + `net` kernel-test suites stay green at
  every phase (offloads are opt-in behind capability advertisement, so a
  driver that doesn't advertise a feature is unaffected).
- Software offloads are verified against software reference
  (TSO-segmented output == the equivalent sequence of individually-built
  segments; GRO-coalesced input == the concatenation of its segments).
- Throughput: the net-bench reports pps and Gb/s per queue; the target is
  "close to device saturation" for the tier (≥90% of the emulated/host-bound
  ceiling under virtio/tap, and the driver's descriptor/ring path proven not
  to be the bottleneck for ixgbe/i40e/mlx5).

# ipc — Design Notes

> Author: AI design review. Created 2026-04-22.

---

## Load-bearing decisions

1. **Ownership transfer via Rust move semantics is the security primitive, not a runtime check.** When `T` moves out of the ring, the producer's handle is gone — this is the zero-copy guarantee. But `T: RingMsg` must be `#[repr(C)]` POD or a `Box<Owned>` handle. POD is fine for small messages; the handle path requires that the handle itself is a capability token, not a raw pointer. The spec §3 says "Box<Owned>-style handle" without specifying what makes a handle unforgeable. At Stage 3, this must be `Cap<Resource, R>` — a capability type. The spec should say so explicitly.

2. **SPSC is the primary design; MPSC is deferred.** The `!Sync` guard on `Producer<T>` is elegant and correct. But many real kernel use cases (multiple driver tasks posting completions to a single consumer) need MPSC. The spec §8 notes this as open. If MPSC arrives via a wrapper (N `Producer` → N SPSC rings → one consumer fan-in ring), the extra copy/indirection needs to be justified against the alternative of a true MPSC ring with a compare-and-swap enqueue.

3. **Doorbell via MMIO write or `SENDUIPI`.** This is the right dual-mode design (UIPI fast path, MMIO fallback), but the choice between them is implicit — who decides, and when? If the producer checks a per-ring flag "UIPI available?" at send time, that flag must be kept in kernel-controlled memory (PKS domain 0), not the ring header itself, or a compromised producer could disable UIPI for its consumer.

4. **Monotonic indices with a generation bit.** Correct for a standard ring, but the spec §4 says "wraparound is the only decrement, detected by a generation bit." This is a 1-bit generation — it provides exactly one epoch of ABA protection. For very high-throughput rings that wrap more than once in a single scheduling quantum, the ABA window exists. virtio packed rings (summaries/virtio-packed-rings.md) use a single wrap counter (also 1 bit) with the AVAIL/USED flag discipline to avoid this; NARF should adopt the same explicit flag discipline in addition to the generation bit.

5. **`Consumer::recv()` returns `impl Future<Output = T>` — no timeout variant.** This is a footgun. A consumer blocked on a closed or stalled ring will await forever. Spec §4 says "Dropping a Producer closes the ring; consumer sees EOF" — but EOF detection requires the consumer to distinguish "ring empty and producer alive" from "ring empty and producer gone." The current `recv()` signature returns `T`, not `Result<T, RingClosed>`. This must be `Future<Output = Option<T>>` or `Result<T, RecvError>`.

---

## Divergences from precedent

**vs. L4/seL4 (Liedtke SOSP 1993):** L4 uses synchronous direct process switch with register-passed short messages. NARF's Narf-Ring is explicitly asynchronous and memory-based. The performance model is different: L4 wins on latency for paired synchronous calls; Narf-Ring wins on throughput and cross-domain decoupling. NARF gets "direct context transfer" (time-slice donation) via the *scheduler*, not the IPC mechanism itself — this composability is elegant but means the scheduler must be correct for the IPC fast path to have L4-equivalent latency, which is a stronger coupling than the spec acknowledges.

**vs. io_uring (Axboe 2019):** io_uring's SQ/CQ pair is the closest analogue. Key differences: (1) io_uring uses integer `user_data` cookies, NARF uses typed `Cap<Ring, R>` endpoints — stronger type safety; (2) io_uring's SQPOLL has a kernel-side poller thread, NARF's polling is the async executor itself; (3) io_uring has grown `IOSQE_IO_LINK` for chained operations (noted in `summaries/io-uring-sqcq.md`). NARF should resist the temptation to add this prematurely but should have a plan for multi-step operations before Stage 3 exit.

**vs. Fuchsia `zx_channel`:** Fuchsia channels transfer handles atomically (summaries/fuchsia-zx-channel.md). NARF's ring is a queue, not a two-endpoint channel. NARF has no equivalent of `zx_channel_call()` (sync RPC with transaction ID matching) because the async executor is supposed to make that unnecessary. But the spec does not describe how a caller correlates a ring submission with its eventual completion — there is no `user_data` cookie in the current `RingMsg` definition. This must be added.

**vs. VirtIO packed rings:** VirtIO packed rings (summaries/virtio-packed-rings.md) use a 16-byte descriptor with AVAIL/USED flags for lock-free synchronization. NARF's ring header is described as "MMIO-like, fixed layout, cache-aligned" but the exact layout (head index, tail index, flags word) is not specified in §3. For a system claiming to be performance-critical, leaving the ring layout undescribed means each implementer will make different choices affecting cache behavior. The spec should fix the layout at a single cache line for head/tail indices and a separate cache line for payload slots (Disruptor-style false-sharing avoidance).

**vs. LRPC (Bershad TOCS 1990):** LRPC's time-slice donation is adopted by NARF's scheduler, not IPC. But LRPC also observed that the *stub boundary* — where argument marshalling happens — is a significant latency source. NARF's `T: RingMsg` + `#[repr(C)]` is the right answer: zero-copy data layout eliminates marshalling. The risk is that `#[repr(C)]` POD types crossing domain boundaries are not version-controlled — a producer and consumer compiled at different times with different struct layouts will silently corrupt data. NARF needs a ring-level version field in the ring header.

---

## Proposed spec changes

- §3 Public interface: **Change `Consumer::recv()` return type** to `impl Future<Output = Option<T>>` — `None` signals EOF (producer dropped). Current signature forces a downstream `unwrap()` or implicit block-forever on closed rings. This is a correctness issue, not a style preference.

- §3 Public interface: **Add a `user_tag: u64` field to `RingMsg` trait** (or as a wrapper `Tagged<T>`) — analogous to io_uring's `user_data`. Without correlation tokens, callers have no way to match async submissions with completions in multi-outstanding-message patterns. This affects `abi/` design directly.

- §3 Public interface: **Fix the ring header layout** — specify: slot 0..N are cache-line-aligned `T` entries; the control word (producer tail, consumer head, flags) occupies a dedicated cache line at offset 0; producer and consumer maintain their private cached copy of the other's index to avoid false sharing. Cite VirtIO packed ring and Disruptor as precedents.

- §4 Invariants: **Add** "A `RingMsg` type carrying a `Cap<_, _>` must use the atomic handle-transfer protocol from `capabilities/`; plain `#[repr(C)]` POD cannot carry unforgeable tokens." This closes the gap between "ownership transfer" and "capability transfer."

- §5 Architecture notes, aarch64: **Specify that `STLR`/`LDAR` pairs are required at the producer tail write and consumer head read respectively.** The current text says "release/acquire via STLR/LDAR" but does not pair them with specific operations. An aarch64 implementer could misread this as "use SeqCst everywhere" (too strong) or "use relaxed with one acquire" (too weak).

- §8 Open questions: **Add** "SecureRing AEAD wrapping key rotation — if the ring is long-lived (e.g., a persistent kernel↔driver channel), the AEAD nonce space exhausts before the ring is torn down. Specify a re-key protocol or limit ring lifetime."

---

## Open invariants / cross-subsystem hazards

**ipc ↔ capabilities §3 (capability transfer in ring messages):** Spec §2 says capabilities give ring endpoints as caps. But when a message *contains* a `Cap<Resource, R>` (capability move), the capabilities subsystem must atomically invalidate the sender's cap and create the receiver's cap at the moment the slot transitions from available to consumed. This is not a ring-level operation — it requires `capabilities/` participation on every message consume. The protocol for this is entirely unspecified and affects both `ipc/` and `capabilities/` Stage 3 design.

**ipc ↔ scheduler §3 (wakeup on post):** `Consumer::recv()` returns a `Future` that parks until the producer posts. The wake mechanism (spec §2: "`scheduler/` can wake a consumer when a producer posts") requires the producer's `send()` to call `Waker::wake()`. But `Waker` is an `Arc`-backed object in standard async Rust; in a `no_std` environment `memory/` must provide the allocator backing the `Waker`. The spec does not describe how `Waker` storage is managed across domains — a producer in domain A waking a consumer in domain B must write to an `Arc` whose refcount is in shared memory, which must be accessible from both domains (i.e., tagged with a shared/neutral domain key).

**ipc ↔ memory §2 (shared regions):** Spec §2 says `memory/` provides shared-memory regions tagged with two domain IDs. The current `memory/` §3 interface (`assign_domain(region, domain_id)`) takes a single `DomainId`. "Tagged with two domains" requires either a new interface (`assign_shared(region, domain_a, domain_b)`) or a PKS key that both domains are permitted to access. The current PKS model (one key per domain, `IA32_PKRS` grants access to specific keys) supports this: grant both domain A's and domain B's keys on the shared region. But the `memory/` spec doesn't describe this multi-key assignment — it's a cross-subsystem gap.

**ipc ↔ rcu §3 (ring lifecycle):** When a ring is torn down (producer dropped, consumer consumed EOF), the ring's physical memory can be freed. If there are `rcu/` readers holding references to the ring's metadata (e.g., the scheduler's waker list), freeing the ring before those readers quiesce is a use-after-free. `ipc/` ring tear-down should go through an `rcu/` deferred-drop path.

---

## Additional opinionated commentary

The "zero-copy" claim in NARF's `DESIGN.md` needs precision. The Narf-Ring gives zero-copy *transfer of the handle to a DMA buffer* — the data bytes never move in physical RAM. But the ring slot itself contains a `Cap<DmaBuffer<T>, _>` (a capability token, likely a small struct or index). That token IS copied into the ring slot on `send()` and out on `recv()`. This is "handle passing," not "zero-copy" in the AF_XDP UMEM sense where even the descriptor doesn't move. The distinction matters for the fast-path latency claim. NARF should call this "zero-copy data path" and document the control-plane copy explicitly.

The spec is silent on **flow control**. An unconstrained producer can fill the ring, causing `send()` to return `Err(Full)`. The caller then retries or blocks — but "blocking" in an async context means re-scheduling. If the producer is a high-priority domain and the consumer is a low-priority domain, the producer will repeatedly poll `Full` and exhaust its time slice without making progress. Credit-based flow control (where the consumer pre-allocates send slots and returns credits) prevents this and is worth specifying at Stage 3 before the VirtIO driver shows the problem at runtime.

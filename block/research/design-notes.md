# block — Design Notes
_2026-04-22_

## Load-bearing decisions

**`BlockDevice::submit` returns `impl Future<Output = BlockCompletion>`.**
This means the device owns the async machinery for completion. In a zero-copy
model where the DMA buffer (`Cap<DmaBuffer, _>`) is owned by the caller during
the entire DMA operation, the `Future` holds a borrow or clone of the cap.
If the future is dropped before completion (caller cancels), the DMA may still
be in flight. The spec says nothing about cancellation semantics. On NVMe,
an in-flight command cannot be cancelled without an Abort command (which itself
is async). If the `Future` is dropped, either (a) the DMA completes into a freed
buffer (UAF/memory-safety violation), or (b) the driver holds the `Cap<DmaBuffer>`
alive after the caller considers it freed. Neither is safe.

**`QosHint` is advisory; the scheduler "never misses a hard deadline because of
a QoS reordering."** This invariant is aspirationally stated but physically
impossible to guarantee at the block layer alone. If the underlying device
(NVMe, virtio-blk) has a full submission queue, a Latency-class request submitted
when the queue is full will wait regardless of its hint. The scheduler can only
guarantee ordering within its own queue — once a request is dispatched to the
device, the device's internal scheduling applies. The spec should say "the block
scheduler prioritizes Latency-class requests at its layer; device-internal
reordering is beyond the block layer's control."

**Per-consumer fair share:** §3.3 says "tasks are capped at a configurable
rate so a runaway consumer doesn't starve others." §8 asks whether fair share
should be per-task or per-cap-chain. The SPDK summary implicitly uses per-queue
(per-device, per-thread) accounting. Linux blk-mq uses per-cgroup accounting
(which is a capability-group analogue). The answer for NARF should be
**per-`Cap<BlockDevice>` instance** — each cap is an independent I/O channel
with its own rate limit. This is the only model that composes correctly with
capability revocation: revoking a `Cap<BlockDevice>` also removes its rate
quota, with no residual accounting state to clean up.

**Multi-queue dispatch in Stage 4, single-queue in Stage 3.** The spec stages
multi-queue correctly. But the `BlockDevice` trait already exposes `submit`
without any queue selector, which implies the driver picks the queue. In Stage
3, drivers have one queue. In Stage 4, drivers have N queues with CPU-local
affinity. The `submit` interface must either (a) accept an optional
queue hint from the caller, or (b) always let the driver select. If (b), the
caller loses CPU-local affinity for Stage 4 fast paths. Decision: add
`fn submit_on(&self, req: BlockRequest, queue_hint: Option<QueueId>)` or specify
that the driver uses `arch::Cpu::current_cpu()` to select the queue. Neither is
currently in the spec.

## Divergences from precedent

**vs. Linux blk-mq:** Linux's `struct request` is mutable through its lifecycle
(set_nr_sectors, bio_list attachment, etc.). The linux-block-subsystem summary
correctly identifies "immutable biovecs" as a best practice. NARF's `BlockRequest`
is a struct (not a pointer to a mutable object), so by value it is immutable
after construction. This is correct and better than Linux. However, the `tag`
field in `BlockRequest` is caller-supplied — there is no kernel-assigned unique
ID. If two callers submit requests with the same tag, completions are ambiguous.
The kernel must assign the tag, not the caller, or verify uniqueness.

**vs. SPDK bdev:** SPDK uses a message-passing model: each request is submitted
to a thread's work queue, avoiding locks. NARF's async model is equivalent —
the Future-based submit has no shared mutable state between the caller and driver.
The key difference is SPDK's explicit "bdev module" registration, which is more
flexible than NARF's trait-based approach. SPDK's module stacking (OCF caching
atop NVMe) would in NARF be a `BlockDevice` impl that wraps another
`BlockDevice` — this is composable, but the spec does not describe this pattern.

**Deadline scheduler vs. BFQ:** The spec chooses "deadline + fair-share" as the
baseline, which is closer to Linux's mq-deadline than to BFQ. This is the right
choice for a latency-sensitive microkernel — BFQ is optimized for desktop
interactive workloads and has a complex state machine that is hard to audit.
mq-deadline is simpler and provably prevents starvation. However, BFQ's
per-process budget accounting would be useful for capability-based fair-share.
NARF should borrow BFQ's budget model (not its full scheduler) for the per-cap
rate limiter.

**Encrypted-at-rest path:** §8 asks whether crypto plugs between `block/` and
driver, or between `filesystem/` and `block/`. Linux dm-crypt sits between block
and filesystem. SPDK's crypto vbdev sits between bdev layers. For NARF, the
correct answer is: crypto as a `BlockDevice` wrapper (like SPDK's vbdev), not
as a `filesystem/` transform, because encryption should be transparent to the
filesystem and because the DMA buffer for an encrypted write must contain
ciphertext before the driver sees it — requiring a staging buffer at the block
layer. The spec should resolve this rather than leaving it open.

## Proposed spec changes

- §3.1 Device trait: Add **`fn cancel(&self, tag: u64) -> impl Future<Output =
  CancelResult>`** where `CancelResult` is `Cancelled | Completed | NotFound`.
  This is essential for safe `Future` drop — the driver can return `Completed`
  if the DMA finished before the cancel arrived, allowing the caller to inspect
  the completion. Without `cancel`, dropping a `submit` Future is undefined
  behavior.

- §3.2 Request/completion: **Make `tag` kernel-assigned, not caller-assigned.**
  Change to: the `tag` field in `BlockCompletion` echoes a kernel-assigned tag
  from the submission; caller sets a `user_tag: u64` (opaque, for correlation)
  that is also echoed. This prevents tag collision between concurrent callers.

- §3.3 I/O scheduler: **Specify per-`Cap<BlockDevice>` rate limiting**, not
  per-task. "A `Cap<BlockDevice>` instance carries a configurable rate limit
  (tokens per second, default: unlimited). Revocation of the cap atomically
  removes its rate bucket from the scheduler's accounting table."

- §4 Invariants: Add **"A `submit` Future, if dropped before polled to
  completion, must call the device's `cancel` method. The `block/` scheduler is
  responsible for injecting this cancel on behalf of the dropped Future."**
  This closes the DMA-buffer UAF hazard identified above.

- §6 Dependencies: Add **`rcu/` as a dependency** for the device registry.
  `block/` maintains a registry of `BlockDevice` instances. Concurrent readers
  (filesystem layer, direct-block userspace tools) must use RCU for safe lockless
  access. This is analogous to `bus/`'s device registry which already lists `rcu/`.

- §7 Stage 3 landing: Add **"Stage 3 resolves the encrypted-at-rest path:
  `block/` exposes a `stack(inner: Cap<BlockDevice, _>, transform: BlockTransform)
  -> Cap<BlockDevice, _>` API for composable device stacking. The crypto transform
  is the first user."** This makes the Stage 3 landing concrete and prevents the
  crypto question from being deferred to Stage 4 where it affects filesystem
  design.

## Open invariants / cross-subsystem hazards

**block ↔ io:** `BlockRequest.buffer` is a `Cap<DmaBuffer, _>`. During DMA, the
physical pages backing the buffer must remain pinned. `io/` owns pinning via
IOMMU context. If `io/` revokes the DMA buffer cap mid-flight (e.g., the
driver domain faults), the DMA operation proceeds into a buffer whose IOMMU
mapping has been torn down — a potential physical-memory corruption. The
revocation path must either (a) wait for in-flight DMA to complete before
revoking the IOMMU mapping, or (b) assert the DMA buffer is not in-flight
before revocation. Neither `block/` nor `io/` spec addresses this.

**block ↔ ipc:** §2 lists `ipc/ Narf-Rings carry requests between block/ and
drivers`. But `BlockDevice::submit` is a trait method, not an IPC send. If the
driver runs in its own domain, the `submit` call must cross a Narf-Ring. The
spec mixes two models: a `BlockDevice` trait (synchronous trait call) and a
Narf-Ring (asynchronous IPC). The actual flow must be: caller submits to
`block/` scheduler via trait call → `block/` scheduler writes to the driver's
Narf-Ring → driver processes and writes completion back → `block/` wakes the
caller's Future. The spec should describe this fan-out explicitly.

**block ↔ time:** Deadline scheduling requires a monotonic clock. `block/` §6
lists `time/` as a dependency. But if `time/` provides only nanosecond resolution
from TSC/CNTPCT, deadline tracking in `block/` must handle TSC calibration drift
between CPUs (relevant when the deadline scheduler's expire check runs on a
different CPU than submission). The `time/` spec's Stage 1 commitment to
"monotonic from TSC" doesn't specify whether TSC is synchronized across CPUs
(on modern x86_64: yes, via invariant TSC; on aarch64: `CNTPCT_EL0` is
per-cluster, not per-CPU, so there may be small skew). The block scheduler
must tolerate a few-hundred-nanosecond deadline error.

**block ↔ filesystem:** `filesystem/` owns the page cache. The spec says
"`block/` is a pass-through unless explicitly configured." But flush ordering
across the cache boundary is not specified. If `filesystem/` issues a `flush`
to `block/`, and `block/` forwards it to the driver, the flush must order after
all writes that `filesystem/` has submitted via `block/`. If `filesystem/` holds
some writes in its cache and hasn't submitted them yet when it issues the flush,
the flush is semantically incorrect. Specify: `flush` in `block/` guarantees
ordering only for requests already in the `block/` queue, not for data still in
`filesystem/`'s cache.

## Additional opinionated commentary

The `block/` spec is one of the cleaner subsystem specs — it has concrete trait
signatures, clear staging, and explicit invariants. The two sharpest critiques:

1. **No cancellation semantics is a safety bug waiting to happen.** Every async
   I/O system that omits cancellation rediscovers the problem during their first
   real workload: a task times out and drops its `Future`, the DMA continues into
   freed memory, and a panic or silent corruption follows. io_uring learned this
   lesson and added IORING_OP_ASYNC_CANCEL. NARF should add `cancel` to the
   `BlockDevice` trait in the spec now, before any implementation exists.

2. **The `QosHint` invariant ("never misses a hard deadline") is misleadingly
   strong.** A block device queue has finite depth; once it is full, all
   scheduling guarantees at the `block/` layer are moot. The spec should say
   "the block scheduler provides best-effort prioritization; hard latency
   guarantees require device-level queue management." Overpromising here will
   produce systems that appear to work in testing (never a full queue) and
   fail in production.

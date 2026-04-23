# Fraser "Practical Lock-Freedom" — Epoch-Based Reclamation

> Fetch returned unreadable PDF; distilled from established knowledge. Cites primary source below.

## Epoch-Based Reclamation for NARF

Keir Fraser's 2004 PhD thesis introduced **epoch-based reclamation**, a lock-free memory management scheme that avoids the grace-period latency of RCU. Epochs divide time into logical intervals; a memory object is safe to reclaim when all threads have advanced past the epoch in which it was freed.

## Core Mechanism

Instead of synchronizing with readers, epoch-based reclamation exploits the fact that threads make progress. Each thread maintains a current epoch counter:

1. **Thread Entry**: When a thread enters a critical section (e.g., capability table lookup), it announces its current epoch to a global counter.
2. **Object Freeing**: When an object (capability descriptor) is no longer needed, the freeing thread increments a global epoch and queues the object for reclamation.
3. **Reclamation**: Once *all* threads have either advanced past the epoch of freeing or exited, the queued object is safe to free.

This avoids RCU's explicit `synchronize_rcu()` call—progress is automatic as threads make forward movement.

## Application to NARF

**Async Executor Integration**: NARF's async executor naturally tracks epochs via task scheduling. Each task execution counts as entering/exiting an epoch. A capability descriptor freed at epoch N is reclaimed when all tasks have been scheduled at least once after epoch N.

**Per-Domain Epoch Counters**: Each PKS/MTE domain maintains its own epoch counter. Cross-domain capability revocation posts an epoch announcement to the target domain, avoiding need for global synchronization.

**Zero-Copy IPC**: When transferring buffer ownership via IPC, epoch markers prevent use-after-free: the sender announces epoch when releasing the buffer; the receiver verifies it has advanced past the announcement epoch before using the buffer.

## Invariants to Maintain

- **Monotonic Epochs**: A thread's current epoch must never decrease
- **Epoch Announcement Atomicity**: Publishing a thread's epoch and queuing a free operation must be atomic (or use memory barriers)
- **Reclamation Safety**: An object is reclaimed only after *all* threads have provably advanced past its free epoch

## Performance Trade-offs

**Latency**: Epoch reclamation incurs no blocking delay like RCU's grace periods. A freed object is queued immediately.

**Reclamation Delay**: However, actual reclamation is deferred until all threads announce forward progress. In the worst case (one thread spinning, others blocked), reclamation stalls.

**Memory Overhead**: Queued objects consume memory during the reclamation delay. Budget for O(N) objects in flight, where N = number of threads.

**Measurement Overhead**: Each thread must atomically update its epoch counter—adds ~10-50 cycles per critical section entry.

## NARF-Specific Guidance

**Adopt**:
- Epoch reclamation for capability descriptors in the fast path (lookup does not block)
- Per-domain epochs to avoid cross-domain synchronization overhead
- Batched epoch announcements (announce every K task switches, not every switch)

**Avoid**:
- Global epoch counter under high concurrency (contention bottleneck)
- Mixing epochs and RCU in the same subsystem (confuses reasoning)
- Epoch-based reclamation for infrequently-accessed structures (RCU has lower memory overhead)

## Pitfalls

- **Epoch Overflow**: If epochs are 32-bit counters, overflow after ~4 billion announcements. Use 64-bit or detect wrap-around.
- **Stalled Thread**: If one thread never announces forward progress (deadlocked, blocked indefinitely), all freed objects in its epoch remain unreclaimed. Design timeouts or deadlock detection.
- **Async Migration**: If a task migrates to a different domain mid-reclamation, epoch semantics become unclear. Enforce domain affinity or restart epoch tracking on migration.

## Recommendation

Implement epoch-based reclamation in Stage 2 as the primary NARF memory reclamation scheme, replacing RCU for capability management. Prove that async task scheduling provides sufficient forward progress to guarantee eventual reclamation. Benchmark epoch overhead against per-capability reference counting; target <1% latency impact.

https://www.cl.cam.ac.uk/techreports/UCAM-CL-TR-579.pdf

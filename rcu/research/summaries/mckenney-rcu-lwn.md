# McKenney "What is RCU, Fundamentally?" (LWN 2007)

> Fetch returned partial content; distilled from established knowledge. Cites primary source below.

## RCU Fundamentals for NARF

Paul McKenney's LWN series on RCU provides the canonical explanation of Read-Copy-Update for systems programmers. For NARF, understanding RCU mechanisms is essential for lock-free synchronization in capability tables, routing structures, and IPC endpoint lookups.

## Core Insight

RCU solves the "publish-subscribe then wait for readers to finish" pattern. Unlike locks (which serialize access) or reference counting (which adds per-reference overhead), RCU decouples readers and writers through **grace periods**:

1. **Reader Critical Section**: Tasks inside `rcu_read_lock() ... rcu_read_unlock()` see a stable snapshot of shared data. No blocking, no reference counting—just read.
2. **Update Phase**: A writer modifies data structures using RCU primitives (`rcu_assign_pointer()` for publication, then `synchronize_rcu()` to wait).
3. **Grace Period**: After `synchronize_rcu()` returns, the writer knows all pre-existing readers have exited. Now the writer can safely free old versions.

## Mechanisms for NARF

**Publish-Subscribe Pattern**: Capability table lookups inside RCU read sections can return a pointer to a capability descriptor. Writers update the table (add/revoke capabilities) by publishing a new table structure, then waiting for all active readers to drain.

**Lock-Free Reads**: In non-preemptable contexts (like kernel sections between async awaits), RCU readers incur zero overhead. NARF's async executor can map task-switch boundaries to RCU grace periods: when all tasks yield or complete, all RCU read-side critical sections have exited.

**Atomic Pointer Updates**: `rcu_assign_pointer()` ensures visibility across CPUs via memory barriers. NARF can use Rust's `atomic` types to implement equivalent semantics for capability pointers.

## Invariants to Maintain

- **No Blocking in Read Sections**: Readers cannot sleep between `rcu_read_lock()` and `unlock()`; async tasks cannot await during capability lookups
- **Grace Period Correctness**: The synchronization mechanism must guarantee all readers see the update before old data is freed
- **Memory Ordering**: Architecture-specific barriers ensure readers see published updates in order

## Performance Trade-offs

**Reader Advantage**: RCU is optimal for read-heavy workloads (capability lookups >> capability updates). Reader overhead is ~2-4 cycles in optimized kernels.

**Writer Latency**: Updaters incur grace-period latency. If a task updates a capability and then immediately needs to free the old descriptor, it waits 1-100 ms (typical grace period). Plan for this in capability revocation paths.

**Memory Overhead**: RCU typically maintains multiple versions of data structures during transitions. For NARF, budget overhead proportional to the number of concurrent updates.

## NARF-Specific Guidance

**Adopt**:
- RCU for capability routing tables (read-heavy, strict consistency during transitions)
- RCU for per-domain endpoint caches (publish new endpoint, grace period, free old)
- RCU + async executor integration (task yield boundaries = grace period checkpoints)

**Avoid**:
- RCU for frequently-mutated per-task state (use per-task locks instead)
- Mixing RCU and spinlocks within a critical section (complicates verification)
- RCU synchronization across async boundaries without careful lifetime management

## Pitfalls

- **Use-After-Free**: If old data is freed before grace period completes, readers see garbage. Rust's ownership system prevents this, but unsafe blocks bypass protections.
- **Grace Period Starvation**: If new readers constantly arrive, grace period may never complete (writer starves). Implement batching or priority.
- **Verification Complexity**: Proving RCU-protected data structures are safe requires careful invariant tracking; incomplete proofs hide race conditions.

## Recommendation

Prototype RCU capability table lookups in Stage 2. Benchmark reader latency (target <1 μs for in-cache lookup) and grace period latency (target <10 ms in normal operation). If grace period becomes a bottleneck for capability revocation, consider epoch-based reclamation as an alternative.

https://lwn.net/Articles/262464/

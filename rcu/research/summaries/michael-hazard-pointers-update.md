# Michael "Hazard Pointers: Safe Memory Reclamation for Lock-Free Objects"

> Fetch returned unreadable PDF; distilled from established knowledge. Cites primary source below.

## Hazard Pointers for NARF RCU Subsystem

Maged Michael's 2004 paper introduced **hazard pointers**, a lock-free memory reclamation technique where readers protect objects from deletion by announcing (via a hazard pointer) which objects they're currently using.

## Core Mechanism

Each thread maintains a small array of **hazard pointers** (typically 2-4 slots):

1. **Reader Protection**: Before dereferencing a pointer to an object (e.g., a capability descriptor), a reader stores the pointer address in a hazard pointer slot. This announcement says "I might be using this object."
2. **Writer Reclamation Check**: When a writer wants to free an object, it checks all threads' hazard pointer arrays. If no thread has announced the object, it's safe to free. Otherwise, queue for later retry.
3. **Eventual Reclamation**: When a thread's retry queue accumulates enough entries, it rescans threads' hazard pointers and safely frees objects no longer protected.

## Application to NARF

**Per-Task Hazard Pointers**: Each task in NARF's async executor maintains a small hazard array (N slots, typically N=2-4). When a task looks up a capability in the routing table, it publishes the descriptor address in a hazard pointer.

**Bounded Per-Task Memory**: Unlike RCU (which maintains multiple data structure versions), hazard pointers require only O(N) per-task storage, where N = number of hazard pointer slots.

**Retire Queues**: When a capability is revoked, it's added to a retire queue. Periodic scanning of all task hazard pointers determines when the capability is safe to free.

## Invariants to Maintain

- **Hazard Pointer Atomicity**: A thread must atomically update its hazard pointer before dereferencing the object
- **No Object Resurrection**: Once an object is on a retire queue, it must not be reused or returned to the allocator until scanning confirms it's not hazarded
- **Bounded Queue Size**: Retire queues must not grow unbounded; trigger scanning periodically

## Performance Trade-offs

**Reader Efficiency**: Hazard pointers require one CAS (compare-and-swap) per critical section—slightly more overhead than RCU reads, but avoids blocking.

**Reclamation Latency**: Objects are not immediately freed; instead, they're queued and reclaimed lazily. Scanning all threads' hazard pointers is O(tasks * hazard_slots), performed periodically (e.g., when retire queue size > threshold).

**Memory Overhead**: Per-task hazard arrays are small (~32 bytes for 4 slots). Retire queues scale with capability revocation rate.

**Predictability**: Unlike RCU (where grace period latency is bounded), hazard pointer reclamation depends on task scheduling patterns. Tasks that never yield may block reclamation.

## NARF-Specific Guidance

**Adopt**:
- Hazard pointers for per-task capability lookups (bounded memory, no RCU latency)
- Retire queues for accumulating revoked capabilities
- Periodic scanning (e.g., every 10 ms) to avoid unbounded queue growth

**Avoid**:
- Hazard pointers for structures requiring frequent updates (retire queues accumulate quickly)
- Mixing hazard pointers and RCU in the same code path (different memory safety properties)
- Hazard pointer counts > 4 per task (scanning overhead grows quadratically)

## Pitfalls

- **Stalled Task Hazards**: If a task crashes or hangs while holding a hazard pointer, that object remains un-reclaimable. Implement task timeout/death detection to clear stale hazards.
- **ABA Problem Interaction**: If an object is freed and reallocated, hazard pointers that reference the original address become ambiguous. Use tagged pointers or version numbers.
- **Scanning Overhead**: Scanning all tasks' hazard pointers for every retire is expensive. Batch scanning or use approximate schemes (e.g., scan only randomly-selected subset).

## Recommendation

Implement hazard pointers in Stage 1 as NARF's primary per-task capability safety mechanism. Benchmark against epoch-based reclamation. If task counts remain <100, hazard pointers scale well; if task counts grow, switch to epochs. Publish guidance: "Use hazard pointers for short-lived capability references; use epochs for persistent descriptor tables."

https://erdani.com/publications/cuj-2004-12.pdf

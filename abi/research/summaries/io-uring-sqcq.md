# Linux `io_uring` — SQ/CQ Ring Design

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

io_uring provides a user-kernel interface for asynchronous I/O submission and completion built on two shared ringbuffers: a Submission Queue (SQ) and Completion Queue (CQ). NARF's fastpath for IPC closely resembles this model, making the design patterns highly relevant.

## Key Mechanisms

**Submission Ring (SQ):**
- Circular ringbuffer where userspace writes Submission Queue Entries (SQEs) describing I/O operations
- Kernel consumes entries at its own pace, allowing batching and optimal resource scheduling
- Index-based addressing (not pointer-based) prevents direct memory dereference attacks
- Userspace can pre-allocate SQE slots in bulk, reducing per-operation overhead

**Completion Ring (CQ):**
- Kernel writes Completion Queue Entries (CQEs) to signal finished operations
- CQEs contain operation status, result value, and user data for correlation
- Ringbuffer indices allow ordering guarantees without explicit ordering primitives (memory barrier cost)
- Multiple completions can be batched in a single kernel-to-user transition

**Zero-Copy Fastpath:**
- Buffers are registered with the kernel once; subsequent operations reference buffer IDs rather than page-table entries
- Fixed buffer sets reduce translation lookaside buffer (TLB) overhead on domain transitions
- Avoids per-operation memory safety checks if buffers were pre-validated at registration time

## Critical Invariants

1. **No syscall per operation:** SQ/CQ design eliminates mode transitions for each request—instead, a single poll or wait syscall (or eventually, userspace spinning) drains a batch
2. **Atomicity of indices:** SQ/CQ head and tail pointers must be updated atomically; races here corrupt the ringbuffer
3. **Capability of memory:** Buffers must be pinned and immovable; garbage collection or page swapping breaks zero-copy guarantees
4. **Ordering vs. throughput:** Write-combining stores improve throughput but complicate memory ordering semantics for strict ordering requirements

## Performance Trade-offs

**Batching benefits:**
- Grouping multiple SQEs amortizes syscall/mode-switch overhead
- Kernel can optimize scheduling when multiple requests are visible
- CQE batching reduces userspace polling frequency

**Spinning vs. waiting:**
- Busy-spinning on CQ tail improves latency (10s of microseconds)
- Kernel poll threads can achieve similar latency with less CPU cost under high load
- Sleeping on events increases latency but reduces CPU usage; must balance against application response-time requirements

**Ringbuffer size:**
- Larger rings reduce wrap-around overhead but consume more kernel memory
- Pre-allocation of SQEs is faster than dynamic allocation but wastes memory if capacity is overprovisioned

## Pitfalls and Warnings

1. **SQ overflow handling:** If userspace submits faster than the kernel consumes, entries overflow. Old implementations had no overflow detection; newer io_uring requires explicit overflow-check loops
2. **CQ overflow:** If kernel completes faster than userspace drains, CQEs are dropped. Applications must handle overflow flags and retry lost operations
3. **Memory ordering bugs:** Ringbuffer index updates must respect acquire/release semantics; sloppy barriers can cause lost completions
4. **Ring poisoning:** If kernel crashes or violates invariants, ringbuffer state becomes garbage; recovery requires kernel restart
5. **Timing side-channels:** CQ latency and ordering can leak information about kernel scheduling, process priorities, and other processes' I/O patterns to unprivileged observers

## Recommendations for NARF ABI Designers

**Adopt:**
- Index-based ringbuffers (not pointer-based) for safety and capability compatibility
- Pre-validated buffer registration to eliminate per-operation permission checks
- Separate SQ/CQ to decouple submission rate from completion rate
- Support both polling and event-based wakeup strategies for latency/throughput tuning

**Avoid:**
- Encoding capabilities in ringbuffer entries if they can be forged by userspace
- Assuming ringbuffer integrity across domain crashes—add generation counters or versioning
- Exposing raw buffer virtual addresses in CQEs; use opaque buffer IDs instead
- Tight coupling between SQ submission index and completion order (io_uring allows out-of-order completion, which must be respected)

**Specific to NARF:**
- Use PKS domain tags to prevent unauthorized reads/writes to SQ/CQ rings from other domains
- Implement MTE tags on ringbuffer headers to detect corruption from wild pointers
- In async-first design, consider whether executor context can outlive capability revocation; ringbuffer cleanup must be explicit and auditable

<https://kernel.dk/io_uring.pdf>

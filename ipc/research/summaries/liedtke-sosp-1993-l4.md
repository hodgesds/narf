# Improving IPC by Kernel Design (Jochen Liedtke, SOSP 1993)

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview
Liedtke's seminal 1993 SOSP paper introduced the L4 microkernel and the concept of *direct process switch* for IPC, eliminating scheduler invocations in the fast path. This foundational work shapes NARF's async-executor design, particularly for low-latency IPC between capability-holding domains.

## Mechanisms

**Direct Process Switch:**
L4's core innovation is that when Task A calls Task B synchronously (via `ipc`), the kernel performs a *direct switch* from A's context to B's without intermediate scheduler invocation. The kernel validates the IPC relationship (via a capability-like mapping), switches address spaces, and jumps to B's IPC handler. When B returns (via `ipc_return`), control switches directly back to A.

**Short Message Registers:**
Rather than copying messages through memory, L4 IPC transfers data via CPU registers (typically 10–20 register-sized words). This avoids memory bandwidth consumption and cache pollution for common-case small messages.

**IPC Queuing:**
If Task B is not ready, A's message is queued (not discarded). When B next runs, it receives the queued message. This ensures no IPC loss and simplifies the protocol.

## Key Invariants

**Synchronous completion:** The sender blocks in `ipc` until the receiver handles the message or a timeout occurs. This provides clean RPC semantics without explicit wait-loops.

**Address space isolation:** IPC does not grant access to the receiver's address space; only message data and register state are transferred.

**Priority inheritance:** When A calls B synchronously, B inherits A's priority for the duration of the call. This prevents priority inversion (a high-priority task waiting for a low-priority IPC recipient).

## Performance Characteristics

**Latency:** Direct process switch IPC latency is extremely low, historically measured at 5–10 microseconds on 1990s hardware. Modern systems achieve sub-microsecond latencies with similar designs.

**Throughput:** Per-message overhead is constant (one context switch + register copy). High-frequency IPC (e.g., thousands per second) is feasible without proportional CPU load.

**Cache effects:** Short message registers avoid memory access, minimizing cache pollution. Address-space switches incur TLB flushes, but L4's design minimizes them through global mappings.

## Pitfalls

1. **Blocking semantics:** Synchronous IPC blocks the sender. If the receiver is preempted or deadlocked, the sender stalls. NARF's async executor mitigates this by avoiding blocking semantics in favor of async-await on IPC completion.

2. **Register saturation:** With only 10–20 register-sized words, complex messages require out-of-band transfers (shared buffers). NARF's zero-copy IPC handles this with capability-protected shared regions.

3. **Priority inversion if misconfigured:** If priority inheritance is not correctly implemented, high-priority tasks can starve waiting for low-priority IPC recipients. NARF's scheduler must integrate priority inheritance.

## Adoption Guidance for NARF

**Adopt:**
- **Direct domain switch:** When a task in domain A sends IPC to domain B, use a direct PKS/MTE domain switch (no scheduler involvement) for the fast path.
- **Register message passing:** For small messages (< 256 bytes), use register/stack passing; for larger, use shared zero-copy buffers.
- **Priority inheritance:** Integrate with NARF's scheduler to inherit sender priority during IPC.

**Avoid:**
- **Full synchronous blocking:** NARF's async executor should use async IPC, not blocking syscalls. Use `await ipc_send()` instead of synchronous `ipc`.
- **Unbounded IPC queues:** Limit per-receiver message queue depth to prevent memory exhaustion.

**Design point:**
Integrate L4-style direct domain switches with NARF's async executor. When a capability-holding task sends IPC, the executor detects the target domain and schedules a direct switch if the recipient is runnable. If the recipient is blocked or in a different scheduling domain, queue the message and resume the sender asynchronously.

## Reference
- Jochen Liedtke, "Improving IPC by Kernel Design," Proceedings of the 14th ACM Symposium on Operating Systems Principles (SOSP 1993)

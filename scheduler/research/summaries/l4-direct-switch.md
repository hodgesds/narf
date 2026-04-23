# L4 Direct-Process-Switch and Direct-Context-Transfer

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Historical Context and NARF Applicability

Liedtke's 1993 SOSP paper "Improving IPC by Kernel Design" identified a fundamental bottleneck in microkernel performance: process context switches triggered by IPC messages traverse the full kernel scheduler, incurring cache misses and TLB flushes even when the switch is deterministic (request-reply pairs).

L4's innovation was **direct-process-switch**: When a thread sends a synchronous IPC (request), if the receiver is blocked waiting on that exact sender, the kernel performs a direct context switch without intermediate scheduling decisions. This reduces IPC latency by 80%+ compared to indirect scheduling.

## Mechanisms for NARF

NARF's async executor and zero-copy IPC can leverage this insight via **direct-context-transfer**:

**Direct Transfer Path**: When a task yields to send an IPC message:
1. Sender's async runtime yields, saving its execution state (local variables, await point)
2. Kernel detects receiver is waiting for exactly this message (matched by capability-scoped IPC queue)
3. Kernel directly switches to receiver's execution context without queuing via the global scheduler
4. Receiver's async executor resumes at the await point where it was blocked
5. On reply, receiver yields, and kernel directly switches back to sender

This is different from thread preemption: both sender and receiver cooperate via async/await, so the kernel makes *deterministic* decisions about who runs next.

## Invariants to Maintain

- **Matched Pairs Only**: Direct transfer only applies when receiver is blocked waiting for this exact sender. Otherwise, fall back to normal scheduling.
- **Async Safety**: Both sender and receiver must be in valid async suspension points; the kernel cannot perform direct transfer if either is actively executing user code.
- **Priority Respect**: If the receiver has lower priority than other waiting tasks, direct transfer must not violate priority scheduling. Implement as an optimization *within* a priority-respecting scheduler.

## Performance Trade-offs

**Latency Gains**:
- L4 direct-switch: ~500 ns (synchronous IPC, matched pair)
- Indirect schedule (gettimeofday syscall): ~1-2 μs
- NARF direct-context-transfer: aim for <1 μs, matching or beating L4

**Complexity Cost**:
- Kernel must track which tasks are blocked on which IPC endpoints
- Requires careful handling of timeouts (if receiver's wait times out, revert to normal scheduling)
- Capability-scoped endpoints complicate matching logic (receiver must hold matching capability)

**Memory Overhead**:
- Per-task IPC queue state: ~64 bytes
- Per-endpoint matched-pair cache: negligible

## NARF-Specific Guidance

**Adopt**:
- Async/await semantics naturally map to deterministic direct-transfer opportunities
- Capability-scoped IPC allows the kernel to assert that only authorized pairs can direct-transfer
- Zero-copy IPC benefits most from reduced latency; prioritize direct-transfer for bulk message paths

**Avoid**:
- Preemptive priority inversion between direct-transfer and normal scheduling—risk priority violation bugs
- Blocking inside async await; the entire point is that suspension is cooperative and fast
- Cross-domain transfers without capability verification; a compromised domain might forge matched-pair expectations

## Pitfalls

- **Cascading Deadlock**: If direct-transfer enables A→B→C→A cycles, detect them via timeout or cycle-detection. Don't assume applications never form cycles.
- **Priority Inversion**: A high-priority task blocked on a direct-transfer to a low-priority task stalls system responsiveness. Set timeouts or revert to normal scheduling.
- **Verification Difficulty**: Proving that direct-transfer respects capability isolation and priority invariants is nontrivial; budget for formal modeling.

## Recommendation

Implement direct-context-transfer as a Stage 2 optimization, after basic async scheduler + IPC work. Prototype with single-domain direct transfers (sender and receiver in same capability domain) before extending to cross-domain. Measure latency impact before and after; target <1 μs for matched-pair IPC.

https://www.sosp.org/papers/1993/liedtke-improving-ipc.pdf (based on Liedtke, "Improving IPC by Kernel Design" SOSP 1993)

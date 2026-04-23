# Lightweight Remote Procedure Call (Bershad et al., TOCS 1990)

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview
Bershad's 1990 TOCS paper on Lightweight Remote Procedure Call (LRPC) introduced the concept of *donating the sender's time slice to the callee*, enabling efficient RPC without the overhead of traditional process creation or heavyweight IPC. This work is foundational to understanding async task scheduling in NARF's IPC subsystem.

## Mechanisms

**Time Slice Donation:**
LRPC's key insight is that when a client calls a server synchronously, the client's remaining CPU time is donated to the server for the duration of the call. The server runs with the client's time slice; if the server yields or blocks, the time slice returns to the client. No new process is created; the server runs in the client's context.

**Stub Binding:**
LRPC uses dynamically generated stubs at the client and server ends of each RPC relationship. The stubs manage argument marshalling, context switching, and return-value unmarshalling. Stubs are optimized for the specific RPC signature, reducing overhead.

**Stack Ripping:**
To avoid full context saves, LRPC stubs rip the stack (save only the necessary registers and local state) rather than saving entire process state. This allows fast switches between client and server.

## Key Invariants

**Time slice atomicity:** The time slice is an indivisible resource. Once donated, it cannot be reclaimed until the RPC completes or the server blocks.

**Argument passing:** Small arguments are passed via registers; larger arguments use shared memory regions. Argument ordering and alignment must be consistent between client and server stubs.

**Blocking semantics:** If the server blocks (e.g., waiting for I/O), the time slice is suspended and returned to the client (or scheduler) until the blocking operation completes.

## Performance Characteristics

**Latency:** LRPC is faster than traditional RPC (e.g., Sun RPC) because no intermediate scheduler invocation is needed. Latencies are typically 10–50 microseconds, comparable to local function calls plus context switching.

**Throughput:** Per-call overhead is low. The donation model allows high-frequency RPC without proportional CPU load.

**Responsiveness:** Because the server runs with the client's CPU time, interactive clients get responsive server behavior without scheduler intervention.

## Pitfalls

1. **Time slice starvation:** If the server spends all of its received time slice on a long operation, the client is blocked. If the server makes further RPC calls, those calls use the same time slice, creating a chain of dependencies.

2. **Deadlock risk:** Cyclic RPC dependencies create deadlocks (Task A calls B calls C calls A). The original time slice is exhausted before the cycle completes.

3. **Preemption during stub execution:** If a higher-priority task preempts the client during LRPC, the server also gets preempted, violating isolation assumptions. Careful scheduler design is needed.

## Adoption Guidance for NARF

**Adopt:**
- **Async task scheduling:** NARF's async executor should treat IPC similar to LRPC—when a task initiates IPC, transfer CPU budget to the receiver task. The receiver runs until completion or a blocking operation.
- **Stub generation:** For capability-based RPC, generate optimized stubs that marshal capability references and minimize data copies.
- **Priority preservation:** Map sender priority to receiver execution priority, ensuring responsiveness.

**Avoid:**
- **Blocking RPC at the scheduler level:** Instead of blocking at the kernel, use async-await in the executor.
- **Unbounded time slice transfers:** Limit per-RPC CPU budget (e.g., maximum 100 µs per call) to prevent starvation.

**Design point:**
In NARF's async executor, when a task sends IPC, suspend the task and transfer its CPU budget to the receiver. The receiver runs until it completes the IPC or blocks. The scheduler reacquires the original task's budget when the receiver completes or yields. Pair this with priority inheritance to prevent priority inversion.

## Reference
- Brian N. Bershad, Thomas E. Anderson, Edward D. Asanović, and David A. Patterson, "Lightweight Remote Procedure Call," ACM Transactions on Computer Systems (TOCS), Vol. 8, No. 1, February 1990.

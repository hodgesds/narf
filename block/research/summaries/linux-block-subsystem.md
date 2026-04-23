# Linux Block Subsystem Design

## Overview

The Linux kernel's block subsystem manages storage I/O operations through a layered architecture balancing fairness, performance, and resource isolation. For NARF's capability-secured microkernel design with domain isolation and zero-copy IPC, understanding these mechanisms reveals both opportunities and pitfalls.

## Key Mechanisms

**Multi-Queue Architecture (blk-mq)**
The documentation highlights "Multi-Queue Block IO Queueing Mechanism" as foundational. Rather than a single serialized queue, blk-mq distributes work across multiple submission and completion queues, reducing lock contention. This aligns naturally with NARF's async executor model—you can map queues to executor cores without kernel-wide synchronization bottlenecks. Each queue can operate independently, respecting domain boundaries through capability checks rather than shared mutable state.

**I/O Scheduling Diversity**
The kernel provides multiple schedulers (BFQ, Deadline, Kyber) addressing different workload characteristics. BFQ implements "Budget Fair Queueing," ensuring fairness under contention. Deadline prioritizes latency guarantees. Kyber targets high-throughput scenarios. NARF should decouple scheduler selection from isolation enforcement—use capabilities to authorize scheduler choice per domain, not enforce a single global policy.

**Immutable Data Structures**
"Immutable biovecs and biovec iterators" represent a critical pattern: request descriptors remain read-only throughout processing, with iteration state managed separately. This eliminates aliasing problems during zero-copy IPC—buffers can be safely shared across domains when backed by immutable metadata.

**Persistent Reservations and Data Integrity**
"Block layer support for Persistent Reservations" and "Data Integrity" mechanisms enforce invariants about concurrent access. These map onto NARF's capability model: only holders of specific capabilities can reserve resources or modify integrity tags (PKS/MTE domains).

## Invariants to Preserve

1. **Request Completion Ordering**: I/O completions must respect submission semantics within a domain. Domain isolation via PKS should prevent one domain from observing another's completion interrupts.

2. **Fairness Under Load**: Schedulers maintain per-process or per-group quota tracking. NARF's domains should inherit or extend these abstractions—capability holders get scheduling weight, revoked capabilities lose it.

3. **Buffer Lifetime**: Buffers must outlive their corresponding I/O requests. With zero-copy IPC, validate that sender domains retain buffer ownership until completion signals arrive.

## Performance Trade-Offs

Linux accepts moderate per-queue overhead for scalability—the multi-queue model trades memory for lock-free operation. NARF's domain isolation similarly trades isolation enforcement cost (PKS domain switches, MTE tag checks) against stronger security properties unavailable in traditional kernels.

The documentation's emphasis on multiple schedulers reflects a design principle: "one size fits all" fails across diverse workloads. NARF should implement scheduler plugins with capability-based selection rather than hardcoding policies.

**Pitfall**: Over-subscribing queues to domains. If NARF assigns one queue per domain without aggregation, queue memory scales linearly with domains. Instead, multiplex low-activity domains onto shared queues with capability-enforced fairness.

## Critical Pitfalls for NARF Designers

1. **Conflating Isolation with Scheduling**: Capability security and fair queueing are orthogonal. A domain holding I/O capabilities still needs scheduler rate-limiting; never assume isolation prevents resource exhaustion.

2. **Zero-Copy Without Immutability**: The kernel's biovec pattern works because requests are immutable after creation. If NARF allows domains to modify I/O metadata in-flight, you lose the safety properties of zero-copy sharing.

3. **Neglecting Completion Semantics**: Async I/O requires precise semantics for when and to whom completions are delivered. Domain isolation must guarantee domains cannot observe siblings' completion events—this requires careful design of interrupt routing and capability binding.

4. **Ignoring Write-Back Cache Control**: "Explicit volatile write back cache control" is essential for data durability in multi-domain scenarios. Domains issuing writes must retain capability to control flush semantics; otherwise, a compromised domain could lose other domains' data.

## Recommendations for NARF Block Designers

**Adopt:**
- Multi-queue architecture mapped to async executor cores; decouple queues from domains to reduce memory overhead
- Immutable request descriptors as a type-system invariant; Rust ownership naturally enforces this
- Multiple scheduler strategies (Deadline, Fair, Throughput) with capability-based selection per domain
- Explicit completion delivery semantics; capabilities authorize receiving completions
- Persistent Reservations as capability tokens scoped to device regions and I/O classes

**Avoid:**
- One queue per domain (memory overhead and lock contention)
- Allowing in-flight metadata modification (violates immutability and breaks zero-copy)
- Shared global scheduler state without capability-based rate limiting
- Implicit completion delivery assumptions (explicit routing prevents data leaks)

**Specific to NARF:**
- Bind I/O schedulers to executor work queues, not individual domains
- Model I/O buffer lifetimes with type-level guarantees (Rust Pin, ownership semantics)
- Domain's I/O capability grants both submission and completion authority; revocation blocks both
- Cache control: only capability holders can issue flushes; FUA (Force Unit Access) for critical I/O
- Design for interruptibility: async executor can switch contexts without losing I/O state

<https://docs.kernel.org/block/index.html>

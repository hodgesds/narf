# seL4 Reference Manual — Capability Invocations (§2–§4)

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview

seL4's capability invocation model forms the core of its microkernel ABI. Invocations are the mechanism by which userspace code exerts control over the system—they are the "syscall" equivalent in a capability-based kernel. Understanding this model is essential for NARF's ABI design, particularly for zero-copy IPC and domain isolation.

## Key Mechanisms

**Capability Objects:**
- Capabilities are unforgeable references to kernel objects (endpoints, thread control blocks, CNodes, etc.)
- Each capability grants a specific set of rights to invoke operations on that object
- Capabilities are stored in CNodes (Capability Nodes), which are kernel-managed tables indexed by capabilities (not pointers)
- A CNode is itself a capability, creating a recursive capability namespace

**Invocation Semantics:**
- Userspace invokes a capability by loading its address (slot number) and arguments into machine registers or a shared buffer
- The kernel decodes the invocation, validates that the caller holds the capability, and performs the operation
- Results are returned via registers or the shared buffer, with error codes indicating success or failure reason
- Invocations are synchronous from the caller's perspective; the kernel does not batch or defer them

**Message Passing on Invocations:**
- IPC occurs via capability invocation on an Endpoint object
- Messages can carry both data and capabilities (nested capability passing)
- Capabilities can be attenuated at the call site using Derive operations (e.g., restrict rights)
- The kernel copies data into kernel buffers, then into the receiver's address space (not zero-copy; contrast with shared rings)

**Type and Rights Checking:**
- seL4 provides fine-grained rights (Send, Receive, Grant, etc.) on each capability
- The type of a capability determines which invocations are valid (only certain operations apply to each object type)
- Rights are statically checked at invocation time; invalid invocations fail before reaching the kernel

## Critical Invariants

1. **Capability unforgability:** Userspace cannot synthesize capabilities; all valid capabilities are issued by the kernel and protected from forgery via isolation
2. **Authority confinement:** A process can only invoke capabilities it holds; there is no global object namespace
3. **Kernel mediation:** Every meaningful operation (creating threads, setting up IPC, managing memory) flows through the kernel's invocation handler
4. **CNode consistency:** The CNode table must remain consistent; corrupted or stale CNode entries lead to undefined behavior
5. **Revocation ordering:** If a capability is revoked, all outstanding invocations that depend on it must fail (requires explicit revocation walks in some kernels)

## Performance Trade-offs

**Synchronous invocations:**
- Simplicity: no asynchronous state machine, no completion polling
- Overhead: every operation incurs a full kernel mode switch and validation cost
- Latency: predictable and low for simple operations, but adds up in communication-heavy workloads
- Batching: seL4 does not naturally support batching; each invocation is independent

**CNode lookups:**
- Direct array indexing is fast but requires all capabilities to fit in a fixed-size CNode
- Multi-level CNode trees (similar to page tables) allow sparse capability spaces but add lookup latency
- CNode caching in the kernel can mitigate lookup costs, but invalidation on revocation is expensive

**Message copying:**
- seL4 copies data into kernel buffers, then into the receiver's buffer (two-phase copy)
- This is safe but slower than zero-copy approaches; large messages incur significant overhead
- Bulk data transfer often requires shared memory regions outside the normal IPC path

## Pitfalls and Warnings

1. **Capability leakage:** If a process's CNode is corrupted or accessed by an attacker, capabilities can be stolen or duplicated
2. **CNode exhaustion:** A process with a fixed-size CNode can run out of capability slots, preventing creation of new objects
3. **Revocation complexity:** Revoking a widely-held capability requires walking all CNodes; this can be extremely slow in large systems
4. **IPC deadlock:** If a receiver is blocked waiting for an IPC from a sender that is itself blocked, the system deadlocks (must use timeouts or careful design)
5. **Covert channels:** Kernel invocation latency varies with CNode fill level and other hidden state; this leaks information via timing
6. **Type confusion bugs:** If the kernel incorrectly assumes a capability's type, it may allow invalid operations (e.g., invoking Send on a Receive-only endpoint)

## Recommendations for NARF ABI Designers

**Adopt:**
- Capability-based authority model with explicit, typed invocations
- Hierarchical CNode structure to avoid global capability table limits
- Fine-grained rights on capabilities (Send, Receive, Grant, Revoke, Derive)
- Synchronous semantics for correctness and simplicity, especially for initial design

**Avoid:**
- Exposing raw CNode indices in userspace (forces kernel to trust userspace capability management)
- Synchronous-only IPC in an async-first design (seL4's blocking semantics do not compose well with async executors; NARF must bridge this)
- Large multi-level CNode trees (TLB/cache overhead; consider hybrid approaches)
- Global revocation walks (opt for per-domain or per-thread revocation tracking instead)

**Specific to NARF:**
- Use PKS tags to enforce CNode isolation per domain, preventing cross-domain CNode access
- Implement async-first invocation handling: allow IPC calls to be queued and processed by the executor rather than blocking
- Combine zero-copy ring buffers (from io_uring model) with capability passing (from seL4 model) for higher throughput than either alone
- Track revocation via generation counters or epoch-based versioning to avoid expensive revocation walks
- Consider whether MTE tags can protect CNode entries from corruption via wild pointers; this improves resilience over seL4's trust assumptions

<https://sel4.systems/Info/Docs/seL4-manual-latest.pdf>

# AF_XDP: Zero-Copy Packet Processing for User Space

## Overview

AF_XDP provides "high-performance packet processing" through user-space socket access to network buffers. For NARF's Rust microkernel with zero-copy IPC goals, AF_XDP's architecture offers valuable design patterns: shared memory regions (UMEM), lock-free ring buffers, and capability-based queue binding.

## Core Mechanisms

**Memory Management (UMEM):** AF_XDP pre-allocates contiguous virtual memory divided into equal-sized chunks. This contrasts with traditional packet allocation—packets don't require per-packet heap operations. For NARF, this model suits capability-domain memory allocation: a domain could own a UMEM region, with queue-specific access controlled through capabilities.

**Ring Buffers:** Four single-producer/single-consumer rings coordinate ownership:
- **FILL:** application→kernel (provides RX buffers)
- **COMPLETION:** kernel→application (returns TX-complete buffers)
- **RX/TX:** bidirectional packet movement

The design explicitly avoids locks. Critical invariant: "the ring structures are single-consumer / single-producer (for performance reasons)." NARF's async executor could manage these without mutual exclusion by assigning each ring to a specific task.

**Queue Binding:** AF_XDP sockets bind to specific device queue IDs. Only traffic directed to that queue reaches the socket—a natural fit for capability-based access control.

## Key Invariants

**Single-Producer/Single-Consumer:** Each ring has exactly one producer and one consumer. Concurrent access on the same ring corrupts state. NARF's async scheduler must enforce this via capability assignment.

**Buffer Ownership Transfer:** Buffers move through FILL→RX→application→TX→COMPLETION states. No buffer should occupy multiple states simultaneously.

**Zero-Copy Constraint:** Zero-copy mode requires NIC driver support and avoids buffer duplication but limits capability to driver capabilities. Copy mode works universally but introduces latency.

## Performance Trade-offs

**Zero-Copy vs. Copy Mode:** Zero-copy requires NIC driver support but avoids buffer duplication. Copy mode works universally but introduces latency. NARF should expose this choice at domain creation.

**Shared UMEM Complexity:** Multiple sockets can share one UMEM across queues/devices, but this creates synchronization overhead on FILL/COMPLETION rings. The documentation warns: "you need to make sure that multiple processes or threads do not use these rings concurrently." For NARF, shared UMEMs suit scenarios with one privileged task managing allocation—avoid for general multi-task scenarios.

**Batch Processing:** The design emphasizes batching descriptors to amortize syscall costs. NARF's async executor naturally batches work; this aligns well.

## Net-Specific Adoption Strategy

**Capability Mapping:** Bind AF_XDP queue IDs to capability tokens. A domain gains RX/TX rights only if holding the appropriate capability.

**UMEM as Shared Region:** Use UMEM as the foundation for zero-copy packet passing between network domain and user domains, leveraging PKS/MTE domain isolation.

**Async Ring Management:** Let the async executor poll rings without blocking, integrating with NARF's event loop rather than spawning threads.

**Multi-Buffer Support:** AF_XDP's XDP_PKT_CONTD flag chains frames. NARF could represent jumbo packets as capability-tagged fragment lists, preserving zero-copy semantics.

## Pitfalls and Avoidances

**Avoid shared UMEMs without single-task ownership:** Race conditions corrupt packets. Only one task owns FILL/COMPLETION rings.

**Avoid reusing buffer addresses across rings simultaneously:** AF_XDP provides no automatic buffer lifecycle tracking. NARF must track ownership explicitly via capabilities.

**Avoid assuming traffic reaches your queue:** NIC steering requires explicit ethtool configuration or XDP redirection logic. Verify queue bindings at initialization.

**Key Invariant:** "only a complete packet (all frames in the packet) is sent to the application." Design ring polling to handle partial packets at batch boundaries gracefully.

## Reference
- Linux AF_XDP Documentation
- https://docs.kernel.org/networking/af_xdp.html

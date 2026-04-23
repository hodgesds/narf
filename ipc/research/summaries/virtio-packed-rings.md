# VirtIO Packed Virtqueues: Ring-Based IPC Design

## Overview
VirtIO's packed virtqueue format provides a compact, lock-free ring buffer design for IPC and device communication. The specification defines a battle-tested shared-queue design from guest/host IPC that NARF can adapt for inter-domain messaging.

## Mechanisms

**Descriptor Table:**
A fixed-size circular buffer of descriptors, each containing a physical address (IOVA), length, flags, and next-descriptor pointer (for scatter-gather). The device reads/writes descriptors to process buffers.

**Wrap Counter:**
Packed virtqueues use a wrap counter (single bit) to distinguish new descriptors from old ones on ring wraparound. This eliminates the need for a separate descriptor-status array (unlike split virtqueues).

**AVAIL/USED Flags:**
Each descriptor has AVAIL and USED bits. The producer sets AVAIL when enqueueing; the consumer clears AVAIL and sets USED when completing. This enables lock-free synchronization.

**Event Suppression:**
Producers and consumers can suppress notifications via EVENT structures. After completing work, a producer re-enables notifications only if the consumer's EVENT flag permits, eliminating spurious wakeups.

## Key Invariants

**Flag visibility ordering:** A descriptor with AVAIL=1 is considered available. The device MUST observe the flag change before using the descriptor. This requires memory barriers.

**Mutual exclusion on reuse:** Before reusing a descriptor, both AVAIL and USED must be reset. The wrap counter provides epoch semantics, preventing races.

**Buffer isolation:** Descriptors reference buffers via IOVA (device-virtual addresses). The device MUST NOT write to a device-readable buffer. NARF's PKS/MTE domains should enforce this via memory protection.

## Performance Characteristics

**Memory efficiency:** Packed virtqueues use 16×queue_size bytes (no padding). Split virtqueues require additional status arrays, consuming 8×queue_size extra.

**Lock-free synchronization:** No spinlocks; only memory barriers. Enables high-throughput without contention.

**Notification overhead:** Event suppression reduces interrupt/doorbell frequency. Producers batch multiple completions before signaling.

## Pitfalls

1. **Out-of-order completion:** VirtIO permits devices to reorder descriptor writes once started. If NARF assumes in-order completion (FIFO), out-of-order signals break causal ordering. Solution: enforce or validate in-order completion.

2. **Notification race window:** After emptying the ring and re-enabling notifications, a gap exists where new work can arrive unsignaled. Solution: always re-poll after re-enabling, or use a polling executor.

3. **Configuration space races:** VirtIO uses generation counters to detect race conditions. NARF must implement similar epoch mechanisms for safe configuration updates.

4. **Descriptor aliasing:** Multiple domains holding write access to the same descriptor table enables attacks. Use per-domain ring allocation and capability-scoped access.

## IPC-Specific Adoption

**Adopt:**
- **Wrap counters:** Use for epoch-based capability revocation; reuse wrap counter to track descriptor generations.
- **Packed-ring layout:** Lower latency, single-digit-microsecond IPC. Minimal memory overhead.
- **AVAIL/USED flag discipline:** Apply to capability grant/revocation signaling; memory barriers ensure visibility.

**Avoid:**
- **Indirect descriptors in critical paths:** Too many domain switches; impacts cache locality.
- **Shared configuration space:** Use per-queue registers instead, avoiding configuration serialization bottlenecks.

**Hybrid approach:**
Use split rings for control-plane IPC (negotiation, setup) and packed rings for data-plane bulk transfers. This mirrors traditional kernel/userspace separation and provides flexibility.

## Reference
- VirtIO 1.2 Specification, Section "Packed Virtqueue"
- https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html

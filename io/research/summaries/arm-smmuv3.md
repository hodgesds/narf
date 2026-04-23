# Arm SMMUv3 Architecture Specification

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview
The Arm System Memory Management Unit v3 (SMMUv3) provides hardware I/O MMU capabilities for Arm platforms (aarch64), enabling DMA isolation and translation similar to VT-d and AMD-Vi. SMMUv3 is essential for NARF deployments on Arm server platforms (e.g., Ampere Altra, Fujitsu A64FX).

## Mechanisms

**Stream Table & STRTAB:**
Each device (master) is identified by a StreamID (similar to PCIe BDF or Arm-specific identifiers). The stream table maps StreamID to context entries that define the I/O translation domain.

**TTB (Translation Table Base):**
Each context entry points to an IOTLB page table root. Translation walks are performed by the SMMU hardware, similar to CPU MMU.

**ASID (Address Space Identifier):**
Multiple streams can share an ASID (and thus a translation table) for efficiency, or use unique ASIDs for isolation.

**Event Queue & Fault Reporting:**
Like AMD-Vi, SMMUv3 logs faulting transactions to a ring buffer. The OS must drain the queue to track device misbehavior.

**PRI (Page Request Interface):**
SMMUv3 supports PRI, allowing devices to request page-in operations for CoW or demand-paged I/O buffers. (Advanced feature, likely not needed in early NARF stages.)

## Invariants

**Device isolation:** Each stream's ASID isolates its IOVA space.

**TLB invalidation:** After mapping changes, explicit invalidation is required. SMMUv3 supports both global and per-ASID invalidation commands.

**Cache coherency:** SMMUv3 respects the shareable attribute in the page table entries. Non-shareable entries may require explicit cache synchronization.

## Performance Trade-offs

**Latency:** SMMUv3 translation latency is hardware-dependent, typically 50–200 ns per walk. TLB hit rates are crucial for performance.

**Scalability:** SMMUv3 supports many streams and ASIDs, scaling well to complex SoCs with many devices.

**Event queue:** Relies on polling; under high-fault conditions, the queue can overflow.

## Pitfalls

1. **StreamID allocation:** Different Arm platforms define StreamID differently (some use PCIe BDF, others use named identifiers from ACPI). NARF must handle platform variance.

2. **PRI complexity:** If PRI is enabled, devices can inject page requests that trigger page allocation in the OS. This creates a deadlock risk if not carefully managed.

3. **Coherency mismatches:** Arm CPU caches and device DMA can become incoherent if page table coherency attributes are mismatched.

## Adoption Guidance

**For NARF:**
- **Adopt:** SMMUv3 for Arm server deployments. One domain per I/O capability holder.
- **Avoid:** PRI (Page Request Interface) in early stages; it adds complexity without clear performance gain.
- **Design point:** Discover StreamIDs via ACPI IORT (I/O Remapping Table) during boot. Map each I/O driver to a unique StreamID and ASID.
- **Event handling:** Implement a dedicated thread to drain the event queue periodically, logging faults for diagnostics.

## Reference
- Arm SMMUv3 Architecture Specification (IHI 0070)
- https://developer.arm.com/documentation/ihi0070/latest/

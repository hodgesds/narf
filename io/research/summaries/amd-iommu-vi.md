# AMD I/O Virtualization Technology (AMD-Vi) Specification

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview
AMD-Vi is the AMD equivalent of Intel's VT-d, providing hardware-assisted I/O device isolation and DMA address translation on AMD platforms. Like VT-d, it enables safe I/O passthrough and is essential for NARF's multi-domain I/O architecture on AMD-based systems.

## Mechanisms

**Device Table & IOMMU Paging:**
AMD-Vi uses a device table to map device IDs to I/O protection domain entries. Each domain contains translation table pointers (page table roots) and access controls. DMA transactions are translated via a multilevel page walk similar to CPU paging.

**I/O Protection Domains:**
Each device is assigned to a domain that controls its IOVA space. Domains can be shared across devices (e.g., pass-through VM gets a domain shared with its USB and network devices) or isolated per-device for fine-grained control.

**Event Logging:**
Faulting DMA transactions are logged to a ring buffer in system memory. The OS polls the buffer to detect device misbehavior.

**Interrupt Remapping:**
Like VT-d, AMD-Vi supports remapping device MSIs to CPU-delivered interrupts, preventing unauthorized device interrupt injection.

## Invariants

**Device isolation:** DMA from a device is strictly confined to its assigned IOMMU domain's IOVA space.

**Explicit INVALIDATE commands:** Like VT-d, AMD-Vi requires TLB invalidation after mapping changes. The INVALIDATE_IOMMU_PAGES command flushes stale entries.

**Coherent DMA:** AMD-Vi page tables use coherency attributes per-entry. Entries marked non-coherent require explicit cache flushes on the host CPU before the device accesses the memory.

## Performance Trade-offs

**IOTLB efficiency:** AMD-Vi supports selective invalidation (per-ASID, per-address-range) to avoid wholesale TLB flushes.

**Event log overhead:** The event log is a ring buffer without interrupts; the OS must poll. High-frequency faults can overflow the buffer if not drained timely.

**Throughput:** Per-device domain overhead is minimal. Shared domains reduce memory footprint but increase contention on IOMMU page table walks.

## Pitfalls

1. **Event log overflow:** Rapidly faulting devices can fill the event log faster than the OS drains it, losing fault information.

2. **Mismatched coherency settings:** Marking a page as non-coherent when the device expects coherent DMA leads to cache incoherence and data corruption.

3. **Invalidation granularity:** Partial invalidations (range-based) require careful address alignment. Misaligned ranges may leave stale entries.

## Adoption Guidance

**For NARF:**
- **Adopt:** AMD-Vi for I/O isolation on AMD-based systems (EPYC, Ryzen). Use one domain per I/O capability holder.
- **Avoid:** Mixing coherent and non-coherent DMA in the same domain unless you explicitly manage flush ordering.
- **Design point:** Integrate AMD-Vi domain management with capability lifecycle. Poll event logs periodically or use a dedicated watcher thread.
- **Testing:** Enable AMD-Vi in BIOS and test with intentional device faults to ensure event logging and revocation work correctly.

## Reference
- AMD I/O Virtualization Technology Specification
- https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/specifications/48882_3_10_IOMMU.pdf

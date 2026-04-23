# IOMMU (Input-Output Memory Management Unit)

## Key Mechanisms

An Input-Output Memory Management Unit performs address translation for DMA-capable devices, mapping "device-visible virtual addresses to physical addresses" much like a CPU MMU translates CPU virtual addresses. For your Rust microkernel, the critical insight is that the IOMMU becomes a *security boundary* enforcer: "a device cannot read or write to memory that has not been explicitly allocated (mapped) for it."

This aligns naturally with NARF's capability model. Rather than treating device access as an afterthought, position the IOMMU as a first-class capability enforcer. The OS maintains exclusive control over translation tables, preventing malicious peripherals from circumventing domain isolation. PKS/MTE domain boundaries should mirror IOMMU mapping granularity to avoid security gaps where capability-checked memory regions could be accessed via unchecked DMA.

## Core Invariants

**Memory contiguity decoupling**: The IOMMU permits "large regions of memory to be allocated without the need to be contiguous in physical memory." For zero-copy IPC in NARF, this is powerful—you can grant a capability to a fragmented virtual buffer, and the IOMMU handles fragmentation. However, maintain the invariant that device ownership of a memory region is exclusive within any time window. Concurrent access by CPU and device on the same page risks coherency violations.

**Address-space isolation per device**: Unlike a single CPU MMU, modern systems (AMD-Vi, Intel VT-d, ARM SMMU) support per-device translation tables. Leverage this: each device domain gets its own capability-backed translation context. This prevents one compromised device from accessing another's buffers.

**Page-table synchronization**: "The granularity of many IOMMUs is equal to the memory paging (often 4096 bytes)." Your async executor must ensure that capability revocation triggers IOMMU TLB invalidation before completing the revocation operation. This is a critical serialization point.

## Performance Trade-offs

**Translation overhead**: "Some degradation of performance from translation and management overhead (e.g., page table walks)" is unavoidable. For latency-sensitive operations, consider IOMMU features like ATS (Address Translation Services) that allow devices to cache translations, reducing host intervention.

**Memory cost**: "Consumption of physical memory for the added I/O page (translation) tables" scales with device count and buffer fragmentation. In NARF, design your capability allocator to batch device buffer assignments and reuse translation tables where safe (e.g., shared read-only regions across multiple devices).

**Bounce-buffer penalties**: If devices require page-aligned buffers, "the device driver needs to use bounce buffers for the sensitive data structures and hence decreasing overall performance." For NARF's zero-copy goal, avoid this by designing IPC message frames with device-alignment awareness from the start. Allocate capability buffers on IOMMU-friendly boundaries.

## Critical Pitfalls for Bus Design

1. **Incomplete capability revocation**: Ensure revocation of a device's capability to a region synchronously invalidates IOMMU mappings. Asynchronous invalidation introduces a race window where the device could still read/write the region after the microkernel believes revocation is complete.

2. **Shared translation tables across security domains**: The article notes that "the tables can be shared with the processor" to save memory. Only share tables between devices with identical security clearances. Do not share between device and CPU domains or across capability isolation boundaries.

3. **Ignoring interrupt remapping**: While the article mentions "in some architectures IOMMU also performs hardware interrupt re-mapping," this is a secondary concern for bus design but critical for preventing device-spoofed interrupts. Ensure your PKS/MTE context setup includes IOMMU interrupt guards.

4. **Virtualization context confusion**: In future hotplug or container scenarios, the IOMMU's role in guest-physical to host-physical translation (mentioned for Xen/KVM) means your bus subsystem must coordinate capability updates with any hypervisor layer. Don't let IOMMU state diverge from capability state.

## What NARF Should Adopt

- **Per-device IOMMU contexts** as first-class capability containers, keyed to capability revocation events.
- **Explicit page-alignment** in IPC buffer allocation to minimize bounce-buffer pressure.
- **Synchronous IOMMU TLB invalidation** in the critical path of capability revocation, treated as a scheduling primitive.

## What to Avoid

- Deferring IOMMU updates to a background task (coherency risk).
- Mixing IOMMU-managed and non-IOMMU-managed device access to the same memory region without explicit synchronization.
- Assuming device-visible addresses are stable across capability transfers without explicit re-mapping.

<https://en.wikipedia.org/wiki/IOMMU>

# Intel VT-d (IOMMU) Architecture

> Fetch returned unrelated content; distilled from established knowledge. Cites primary source below.

## Overview
Intel VT-d (Virtualization Technology for Directed I/O) provides hardware-assisted I/O device memory isolation and DMA address translation. It is the foundational mechanism for securing I/O in modern Intel platforms, enabling trusted I/O pass-through to virtual machines and, in NARF's case, to capability-isolated I/O drivers in userspace domains.

## Mechanisms

**IOMMU Translation:**
VT-d intercepts all DMA transactions from devices and translates device-virtual addresses to system physical addresses via a multilevel page table (similar to CPU MMU). Each device gets a context entry that points to its translation table root.

**Remapping Structures:**
- **Root table:** Maps devices to context entries.
- **Context table:** Per-device entry containing address-space identifiers (ASID) and translation table pointers.
- **Translation tables (IOVA → PA):** Similar to CPU page tables but managed by the IOMMU subsystem.

**Interrupt Remapping:**
VT-d can also remap interrupt addresses, translating device-generated interrupt requests (MSIs) to CPU-delivered interrupts. This prevents malicious devices from injecting arbitrary interrupts.

**Fault Reporting:**
Devices that generate invalid IOVA translations trigger fault events captured in IOMMU fault logs. The OS can inspect faults to debug device misbehavior.

## Invariants

**Device Isolation:** Once a device is bound to an IOMMU domain, all its DMA is confined to that domain's address space. A buggy device cannot access memory outside its IOVA window.

**Lazy invalidation:** After updating an IOVA mapping, the IOMMU requires explicit invalidation commands (IOTLB invalidation) to flush stale entries. Missing invalidation leads to data corruption.

**Atomicity of remapping:** Multiple devices can share an IOMMU domain (same ASID) for efficiency, but each device must have a consistent view of the mapping.

## Performance Trade-offs

**Latency:** IOMMU address translation adds one or more memory lookups per DMA transaction (typically 100–500 ns per lookup in hardware). Modern IOMMUs have large TLB caches to reduce misses.

**Throughput:** IOTLB invalidation is expensive; bulk invalidations (multiple devices at once) are more efficient than per-device updates.

**Memory overhead:** Each IOMMU domain requires page tables; larger IOVA spaces require deeper tables. For NARF, allocate one IOMMU domain per I/O capability holder.

## Pitfalls

1. **Invalidation ordering:** If invalidation commands are pipelined, they may complete out of order. NARF must use memory barriers before accessing remapped buffers after invalidation.

2. **Interrupt storm:** A faulting device generating repeated DMA faults can create interrupt storms if fault handling is not rate-limited.

3. **Stale mappings:** If a device's IOTLB is not invalidated after a revocation, the device can continue accessing revoked memory. NARF's capability system must pair revocation with explicit IOTLB flush.

## Adoption Guidance

**For NARF:**
- **Adopt:** VT-d for isolating untrusted I/O drivers in separate IOMMU domains. Each capability-holding I/O task gets its own domain.
- **Avoid:** Sharing IOMMU domains across multiple drivers unless they are trust-equivalent.
- **Design point:** Integrate IOMMU domain allocation with NARF's capability system. On capability grant, set up an IOMMU domain; on revocation, flush and deallocate.
- **Interrupt handling:** Enable interrupt remapping to prevent device-injected interrupts from bypassing domain isolation.

## Reference
- Intel VT-d Architecture Specification
- https://www.intel.com/content/www/us/en/developer/articles/technical/intel-virtualization-technology-for-directed-io-architecture-specification.html

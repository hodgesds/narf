# Preparing for Peer-to-Peer DMA (Jonathan Corbet, LWN)

## Overview

Jonathan Corbet's 2019 LWN article introduces the P2PDMA subsystem, explaining the mechanics of device-to-device DMA and the kernel's topology-aware approach to enabling safe P2P transfers.

## Core Mechanisms

**Provider-Client Architecture:** P2PDMA revolves around drivers exposing memory zones for consumption by other devices. Providers publish P2P-capable memory via `pci_p2pmem_alloc_sgl()`. Clients request allocations suitable for their peer devices.

**Topology Validation:** The kernel evaluates PCIe hierarchies to permit P2P only when "all devices involved are behind the same PCI host bridge," preventing cross-root-complex transfers that could leak data or violate platform safety assumptions.

**Two implementation models:**
1. **Naked provider model:** Driver-managed lifecycle with DMABUF invalidation—suitable for NARF's capability-based isolation.
2. **ZONE_DEVICE pgmap wrapper:** Wraps provider memory as regular kernel pages for O_DIRECT file operations, requiring architecture support.

## Key Invariants

**Lifecycle Synchronization:** Provider removal must be synchronous across all clients. The "providing and consuming driver has stopped using the MMIO during a removal cycle"—NARF's revocation mechanism must broadcast explicit notifications rather than relying on reference counting alone.

**Non-CPU-Accessible Memory:** P2PDMA pages forbid direct CPU access; only memory-mapped I/O helpers (memcpy_to/from_io) are valid. NARF's type system should enforce this via distinct page types.

**FOLL_LONGTERM Prevention:** Long-term pinning is blocked. Tasks holding P2P buffers must not exceed operation lifetime; use scoped guards in the executor.

## Performance Characteristics

**Gains:** Eliminated CPU involvement, reduced memory bandwidth consumption, no cache pollution for pass-through workloads (camera→display pipeline, download→disk offload).

**Costs:** Initial orchestrator complexity; architectural whitelisting; limited hardware (typically requires explicit BIOS enables).

## Pitfalls

1. **Provider Removal Races:** Concurrent clients lack synchronous invalidation if a provider is removed. NARF should integrate DMABUF's `move_notify()` callback into capability revocation.

2. **Orchestrator Bottleneck:** Finding compatible providers scales poorly with device count. Precompute provider-client affinity graphs during boot, updating incrementally on hot-add.

3. **Non-Deterministic Selection:** When multiple providers are equidistant (same hop-count), selection is randomized. For NARF's deterministic requirements, implement priority-based selection (e.g., oldest provider first).

## I/O-Specific Adoption

**Suitable scenarios:**
- NVMe fabric targets with RDMA ingress
- Storage pipelines with high bandwidth requirements
- Graphics acceleration (future)

**Avoid:**
- Root-port-directly-connected devices
- Cross-hierarchy transfers
- Systems requiring dynamic memory reprovision

## NARF Integration Pattern

Implement P2P as a capability-granting service within the I/O domain. On open, grant a (provider_cap, client_cap) pair; on removal, broadcast revocation via async executor. Use PKS/MTE domain boundaries to isolate MMIO access, preventing accidental kernel-mode dereferencing of P2P buffers.

## Reference
- "Preparing for peer-to-peer DMA" (Jonathan Corbet, LWN, 2019)
- https://lwn.net/Articles/767281/

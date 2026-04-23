# PCI Configuration Space

## Overview

PCI configuration space enables automatic device discovery and resource allocation—critical for NARF's bus initialization. The Wikipedia article describes how devices advertise capabilities and receive memory/IO addresses through standardized register access mechanisms, offering lessons for capability-based microkernel bus design.

## Key Mechanisms

**Geographic Addressing via Bus/Device/Function**

PCI uses an 8-bit bus, 5-bit device, and 3-bit function identifier (B/D/F) to uniquely locate devices: "up to 256 buses, each with up to 32 devices, each supporting eight functions." This hierarchical naming enables deterministic enumeration without central registry. NARF could adopt similar geographic addressing for capability grant derivation—mapping bus topology directly to capability paths rather than flat device tables.

**Two-Tier Configuration Access**

Legacy x86 uses port-based indirection (0xCF8/0xCFC registers), while PCIe introduced "Enhanced Configuration Access Mechanism (ECAM)" with memory-mapped 4 KiB per-device windows. The memory-mapped approach aligns naturally with NARF's memory protection—each device's config space becomes an isolatable page, enforceable via page tables or PKS domain tags.

**Capability Linked Lists**

PCI's extensibility mechanism uses "a linked list of capabilities" within configuration space. New device features register themselves without redefining the standard 64-byte header. This recursive capability discovery mirrors NARF's capability table traversal—devices can advertise advanced features (MSI-X, resizable BARs, AER) similarly to how processes extend capability pointers.

## Critical Invariants

**Inactive-on-Reset State**

All devices begin "in an _inactive_ state upon system reset" with no assigned addresses. NARF's bus driver must enforce this—no device operates until explicitly enumerated and granted address capabilities. This prevents spurious DMA or interrupts during boot.

**Function Zero Mandatory**

"Devices are required to implement function number zero." This serves as a presence detector: if reading function 0's vendor ID returns 0xFFFFFFFF, no device exists on that B/D/F. NARF's enumeration loop should abort entire slot enumeration on function 0 absence, reducing startup latency.

**Power-of-Two, Naturally Aligned Regions**

BAR allocation enforces that "all address space sizes are a power of two and are naturally aligned." This simplifies range checking in capability grants—NARF can use bit-length fields rather than arbitrary size encodings, reducing verification complexity.

## Performance Trade-Offs

**IDSEL Resistor Delays**

Configuration cycles are deliberately slowed because "the IDSEL signal on the PCI slot connector is usually connected to its assigned AD line through a resistor." This RC time constant overhead is acceptable during boot but irrelevant post-initialization. NARF shouldn't optimize enumeration speed at the cost of correctness; one-time startup cost is negligible.

**Memory-Mapped vs. Port-Based**

ECAM's "256 MB of physical contiguous space" reservation is substantial but provides O(1) configuration access without port indirection. For NARF, if PKS/MTE can isolate stolen memory regions, ECAM avoids spinlock contention on legacy port-based access—beneficial on multi-core boot.

**Resizable BAR Negotiation**

Modern devices negotiate larger framebuffer access: "Resizable BAR lets a CPU access the whole framebuffer at once, thus improving performance." For NARF, this becomes a capability-grant negotiation—device requests larger address ranges, bus driver validates against available pool and grants via extended BAR configuration.

## Pitfalls to Avoid

**Assumption of Contiguous Bus Numbering**

PCI buses are not necessarily numbered 0–N. Bridges create secondary buses with arbitrary IDs. NARF's enumeration must not assume buses are packed; instead, build a sparse topology map and allocate capabilities based on actual discovered structure.

**Configuration Space Corruption During Enumeration**

Writing BAR addresses on running devices causes address space remapping. NARF must serialize bus enumeration and prevent user-space access to configuration registers during startup. Capability-based access control should restrict config-space rights to the bus driver alone.

**Extended Capability Ambiguity**

"Extended capability IDs overlap with normal capability IDs, but there is no chance of confusion as they are in separate lists." NARF must track which offset range (0–255 vs. 0x100–0xFFF) holds each capability ID to avoid misinterpretation. Store list head pointers separately for legacy vs. extended space.

## Design Recommendations for NARF

1. **Geometric Naming**: Adopt B/D/F addressing as the canonical device identifier; derive capability addresses by hashing (bus, device, function) tuples.

2. **PKS/MTE-Enforced Config Isolation**: Map ECAM stolen memory into distinct protection domains; grant only the bus driver read-write access during enumeration.

3. **Lazy Capability Derivation**: Cache capability lists per-device after enumeration; lazily grant application-level access only to specific BAR regions on demand.

4. **Atomic BAR Allocation**: Use a single kernel-held capability for the address space pool; bus driver atomically reserves and grants non-overlapping ranges to devices.

5. **Resilience to Malformed Devices**: Treat vendor-ID reads returning 0xFFFFFFFF as hard errors; fail safe by refusing to grant DMA or interrupt capabilities to unresponsive devices.

This design balances PCI's proven auto-configuration simplicity with NARF's capability security isolation.

<https://en.wikipedia.org/wiki/PCI_configuration_space>

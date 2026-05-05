# tables-iommu-topology — IOMMU + topology + console ACPI tables

> Status: **v0.1**. Pairs the recently-landed arch primitives
> (VT-d, AMD-Vi, SMMUv3, cache topology) with their ACPI
> enumeration tables.

Adds parsers for:

  * **PPTT** — Processor Properties Topology Table.
  * **IORT** — IO Remap Table (ARM SMMUv3 + ITS enumeration).
  * **DMAR** — DMA Remap Reporting (Intel VT-d enumeration).
  * **IVRS** — I/O Virtualization Reporting (AMD-Vi enumeration).
  * **SPCR** — Serial Port Console Redirection.

All five build on the existing `walk_xsdt` infrastructure and
follow the same idempotent / sticky-flag pattern as `parse_srat`.

## 1. PPTT

### 1.1 Layout

PPTT carries variable-length nodes. After the standard
`SDT_HEADER`, each node starts at a 4-byte-aligned offset:

| field   | size | meaning                              |
|---------|------|--------------------------------------|
| Type    | 1 B  | 0 = Processor, 1 = Cache, 2 = ID    |
| Length  | 1 B  | total node size                      |
| Reserved| 2 B  |                                      |

For Type = 0 (Processor):

| field             | size | meaning                          |
|-------------------|------|----------------------------------|
| Flags             | 4 B  | bit 0 = physical package, bit 1 = ACPI processor ID valid, bit 2 = thread, bit 3 = leaf, bit 4 = identical-implementation |
| ParentOffset      | 4 B  | offset to parent node             |
| AcpiProcessorId   | 4 B  | ACPI processor UID                |
| NumberOfPrivateResources | 4 B | count of trailing offsets    |

For Type = 1 (Cache):

| field             | size | meaning                          |
|-------------------|------|----------------------------------|
| Flags             | 4 B  |                                  |
| NextLevelCache    | 4 B  | offset to next-level node         |
| Size              | 4 B  | bytes                              |
| NumberOfSets      | 4 B  |                                    |
| Associativity     | 1 B  |                                    |
| Attributes        | 1 B  | bit 0 = allocation type, bit 2 = cache type (data/inst/unified), bit 4 = write policy |
| LineSize          | 2 B  |                                    |

### 1.2 API

```rust
pub struct PpttCpu {
    pub acpi_uid:    u32,
    pub package:     bool,
    pub thread:      bool,
    pub leaf:        bool,
}

pub struct PpttCache {
    pub level:       u8,         // 1..7, derived from depth in the chain
    pub line_bytes:  u16,
    pub ways:        u16,
    pub sets:        u32,
    pub size_bytes:  u32,
    pub kind:        PpttCacheKind,
}

pub enum PpttCacheKind { Data, Instruction, Unified }

pub unsafe fn parse_pptt(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_pptt_known() -> bool;
pub fn copy_pptt_cpus(out: &mut [PpttCpu]) -> usize;
pub fn copy_pptt_caches(out: &mut [PpttCache]) -> usize;
```

## 2. IORT

### 2.1 Layout

| field                         | size | meaning                  |
|-------------------------------|------|--------------------------|
| NumberOfNodes                 | 4 B  |                          |
| OffsetToNodeArray             | 4 B  | offset from SDT base     |
| Reserved                      | 4 B  |                          |

Each node starts at the offset above:

| field   | size | meaning                                  |
|---------|------|------------------------------------------|
| Type    | 1 B  | 0 = ITS group, 1 = NamedComponent, 2 = RootComplex, 3 = SMMUv1/v2, 4 = SMMUv3, 5 = PMCG |
| Length  | 2 B  |                                          |
| Revision| 1 B  |                                          |
| Identifier | 4 B |                                         |
| NumIdMappings | 4 B |                                       |
| OffsetIdMappings | 4 B |                                    |
| Type-specific data follows ...                     |

For Type = 4 (SMMUv3), the type-specific block carries the
`BaseAddress`, `Flags`, `VaTwoStage` flag, GICv3 ITS attribute
+ `EventNvidiaGsiv`, `PriNvidiaGsiv`, `GerrNvidiaGsiv`,
`SyncNvidiaGsiv`. v0.1 surfaces just `BaseAddress`.

For Type = 0 (ITS), the type-specific block lists ITS-IDs.

### 2.2 API

```rust
pub struct IortSmmuv3 {
    pub base:    u64,
    pub flags:   u32,
}

pub struct IortIts {
    pub its_id:  u32,
}

pub unsafe fn parse_iort(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_iort_known() -> bool;
pub fn copy_iort_smmuv3(out: &mut [IortSmmuv3]) -> usize;
pub fn copy_iort_its(out: &mut [IortIts]) -> usize;
```

## 3. DMAR

### 3.1 Layout

| field           | size | meaning                                 |
|-----------------|------|-----------------------------------------|
| HostAddrWidth   | 1 B  | host VA width (bits)                    |
| Flags           | 1 B  | bit 0 = INTR_REMAP, bit 1 = X2APIC_OPT_OUT |
| Reserved        | 10 B |                                          |
| Remap structures follow, each starting with:        |
| Type            | 2 B  | 0 = DRHD, 1 = RMRR, 2 = ATSR, 3 = RHSA, 4 = ANDD |
| Length          | 2 B  |                                          |

For Type = 0 (DRHD — DMA Remap Hardware Unit Definition):

| field           | size | meaning                                 |
|-----------------|------|-----------------------------------------|
| Flags           | 1 B  | bit 0 = INCLUDE_ALL_PCI                  |
| SegmentNumber   | 2 B  | PCI segment                              |
| RegisterBase    | 8 B  | engine MMIO base                         |
| Device-scope structures follow.                      |

### 3.2 API

```rust
pub struct DmarDrhd {
    pub register_base:    u64,
    pub segment:          u16,
    pub include_all_pci:  bool,
}

pub unsafe fn parse_dmar(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_dmar_known() -> bool;
pub fn copy_dmar_drhds(out: &mut [DmarDrhd]) -> usize;
pub fn dmar_intr_remap_supported() -> bool;
```

## 4. IVRS

### 4.1 Layout

| field           | size | meaning                                 |
|-----------------|------|-----------------------------------------|
| IvInfo          | 4 B  | bit 0..7 = host phys-addr width, bit 8..14 = guest phys-addr width, bit 15..22 = VA width |
| Reserved        | 8 B  |                                          |
| IVHD / IVMD structures follow, each with:           |
| Type            | 1 B  | 0x10 = IVHD type 0, 0x11 = IVHD type 1, 0x40 = IVHD type 2, 0x20 = IVMD all-devs, 0x21 = IVMD spec dev, 0x22 = IVMD range |
| Flags           | 1 B  |                                          |
| Length          | 2 B  |                                          |
| DeviceId        | 2 B  |                                          |

For Type = 0x10 / 0x11 (IVHD):

| field           | size | meaning                                 |
|-----------------|------|-----------------------------------------|
| CapabilityOffset| 2 B  | PCI cap offset                           |
| BaseAddress     | 8 B  | engine MMIO base                         |
| PciSegment      | 2 B  |                                          |
| IommuInfo       | 2 B  |                                          |
| Type-specific feature bits + device entries follow. |

### 4.2 API

```rust
pub struct IvrsIommu {
    pub base:            u64,
    pub pci_segment:     u16,
    pub capability_off:  u16,
}

pub unsafe fn parse_ivrs(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_ivrs_known() -> bool;
pub fn copy_ivrs_iommus(out: &mut [IvrsIommu]) -> usize;
```

## 5. SPCR

### 5.1 Layout

| field              | size | meaning                                       |
|--------------------|------|-----------------------------------------------|
| InterfaceType      | 1 B  | 0 = full 16550, 1 = 16550 subset, 0x03 = ARM PL011, 0x0E = NVIDIA Tegra, 0x0F = ARM Generic UART, 0x12 = MMIO16550 with parity, ...|
| Reserved           | 3 B  |                                               |
| BaseAddress        | 12 B | GAS — Generic Address Structure               |
| InterruptType      | 1 B  | bit 0 = PC-AT compatible, bit 1 = IO-APIC, bit 2 = IO-SAPIC, bit 3 = ARMH GIC |
| IRQ                | 1 B  |                                               |
| GlobalSystemInterrupt | 4 B |                                              |
| BaudRate           | 1 B  | 3 = 9600, 4 = 19200, 6 = 57600, 7 = 115200    |
| Parity             | 1 B  |                                               |
| StopBits           | 1 B  |                                               |
| FlowControl        | 1 B  |                                               |
| TerminalType       | 1 B  | 0 = VT100, 1 = VT100+, 2 = VT-UTF8, 3 = ANSI |
| Language           | 1 B  |                                               |
| PciDeviceId        | 2 B  | 0xFFFF if not PCI                              |
| ...                                                                       |

GAS:

| bits / bytes        | field                        |
|---------------------|------------------------------|
| AddressSpaceId (1 B)| 0 = SystemMemory, 1 = SystemIO, ... |
| RegisterBitWidth (1 B) |                            |
| RegisterBitOffset (1 B) |                          |
| AccessSize (1 B)    |                              |
| Address (8 B)       |                              |

### 5.2 API

```rust
pub struct SpcrInfo {
    pub iface:           u8,
    pub base:            u64,
    pub addr_space_id:   u8,
    pub gsi:             u32,
    pub baud_code:       u8,
    pub pci_device_id:   u16,
}

pub unsafe fn parse_spcr(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn spcr_info() -> Option<SpcrInfo>;
```

## 6. Test surface

| smoke                            | asserts                            |
|----------------------------------|------------------------------------|
| `smoke_pptt_synthetic_decode`    | hand-built PPTT body parses        |
| `smoke_iort_synthetic_decode`    | hand-built IORT body parses        |
| `smoke_dmar_synthetic_decode`    | hand-built DMAR body parses        |
| `smoke_ivrs_synthetic_decode`    | hand-built IVRS body parses        |
| `smoke_spcr_synthetic_decode`    | hand-built SPCR body parses        |

QEMU exposes most of these on `-machine virt` (aarch64) and
`-machine q35,kernel-irqchip=split` (x86_64); we still ship the
synthetic-table tests because the live-table contents are
hardware-specific.

## 7. Out of scope (v0.1)

- IORT named-component / root-complex devices.
- DMAR RMRR / ATSR / RHSA / ANDD remap-structure types beyond
  DRHD enumeration.
- IVRS device-entry parsing (we expose IOMMU base + segment;
  device-entry walking lands when AMD-Vi bring-up does).
- PPTT identical-implementation flag → cluster grouping (we
  emit per-CPU + per-cache entries; cluster derivation lives
  in `arch::aarch64::topology` follow-ups).
- SPCR PCI-bound serial enumeration.

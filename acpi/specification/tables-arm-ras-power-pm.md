# tables-arm-ras-power-pm — Arm RAS + watchdog + LP-idle + NVDIMM

> Status: **v0.1**.

Adds parsers for:

  * **AEST** — Arm Error Source Table.
  * **SDEI** — Software Delegated Exception Interface.
  * **WDDT** — Watchdog Description Table.
  * **LPIT** — Low Power Idle Table.
  * **NFIT** — NVDIMM Firmware Interface Table.

All five build on `walk_xsdt` and follow the existing
idempotent / sticky-flag pattern.

## 1. AEST

### 1.1 Layout

| field    | size | meaning                       |
|----------|------|-------------------------------|
| Each Node Header (12 B):                          |
| Type     | 1 B  | 0 = Processor, 1 = Memory Ctrl, 2 = SMMU, 3 = Vendor, 4 = Generic GIC |
| Reserved | 1 B  |                                |
| Length   | 2 B  |                                |
| Reserved | 4 B  |                                |
| NodeDataOffset | 4 B |                              |
| NodeIfaceOffset| 4 B |                              |
| NodeIntCount   | 4 B |                              |
| NodeIntOffset  | 4 B |                              |
| TimingOffset   | 4 B |                              |

The interface block starts at `NodeIfaceOffset` and carries the
`(Type, BaseAddress)` pair we surface in v0.1.

### 1.2 API

```rust
pub struct AestNode {
    pub kind:    u8,
    pub iface:   u8,         // 0 = SR, 1 = MMIO
    pub base:    u64,
}

pub unsafe fn parse_aest(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_aest_known() -> bool;
pub fn copy_aest_nodes(out: &mut [AestNode]) -> usize;
```

## 2. SDEI

### 2.1 Layout

The SDEI table is fixed-size — `SDT_HEADER` (36 B) + nothing.
Its existence advertises that the platform implements the
SDEI ABI; the actual conduit (HVC vs SMC) is queried via
`SDEI_VERSION` once the kernel's SMCCC layer is up.

### 2.2 API

```rust
pub unsafe fn parse_sdei(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn is_sdei_known() -> bool;
```

## 3. WDDT

### 3.1 Layout

| field                | size | meaning                       |
|----------------------|------|-------------------------------|
| TimerMaxCount        | 2 B  |                                |
| TimerMinCount        | 2 B  |                                |
| TimerCountPeriod     | 2 B  | period (microseconds)         |
| Status               | 2 B  |                                |
| Capability           | 2 B  |                                |
| PciVendorId          | 2 B  |                                |
| BaseAddress          | 12 B | GAS                            |
| ...                                                            |

### 3.2 API

```rust
pub struct WddtInfo {
    pub timer_max_count: u16,
    pub timer_min_count: u16,
    pub period_us:       u16,
    pub status:          u16,
    pub capability:      u16,
    pub base:            u64,
}

pub unsafe fn parse_wddt(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn wddt_info() -> Option<WddtInfo>;
```

## 4. LPIT

### 4.1 Layout

Each subtable starts with a 4-byte header:

| field   | size | meaning                                    |
|---------|------|--------------------------------------------|
| Type    | 4 B  | 0 = Native C-State Idle Time, 1 = Reserved  |
| Length  | 4 B  |                                          |

For Type = 0:

| field             | size | meaning                  |
|-------------------|------|--------------------------|
| UID               | 4 B  | corresponds to ACPI proc UID |
| Reserved          | 4 B  |                          |
| EntryTrigger      | 12 B | GAS                       |
| Residency         | 4 B  | "tick frequency" units    |
| Latency           | 4 B  |                            |
| ResidencyCounter  | 12 B | GAS                       |
| ResidencyFreq     | 8 B  |                            |

### 4.2 API

```rust
pub struct LpitState {
    pub uid:           u32,
    pub trigger_addr:  u64,
    pub residency:     u32,
    pub latency:       u32,
    pub counter_addr:  u64,
    pub counter_freq:  u64,
}

pub unsafe fn parse_lpit(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_lpit_known() -> bool;
pub fn copy_lpit_states(out: &mut [LpitState]) -> usize;
```

## 5. NFIT

### 5.1 Layout

Each subtable starts with a 4-byte header:

| field   | size | meaning                                    |
|---------|------|--------------------------------------------|
| Type    | 2 B  | 0 = SPA Range, 1 = Memory Device, 2 = Interleave, 3 = SMBIOS Mgmt, 4 = Control Region, 5 = Block Data, 6 = Flush Hint |
| Length  | 2 B  |                                          |

For Type = 0 (System Physical Address Range):

| field          | size | meaning                          |
|----------------|------|----------------------------------|
| RangeIndex     | 2 B  |                                   |
| Flags          | 2 B  |                                   |
| Reserved       | 4 B  |                                   |
| Proximity      | 4 B  |                                   |
| AddrRangeTypeGuid | 16 B |                                |
| Base           | 8 B  |                                   |
| Length         | 8 B  |                                   |
| MemoryMappingAttribute | 8 B |                            |

### 5.2 API

```rust
pub struct NfitSpaRange {
    pub range_index:   u16,
    pub proximity:     u32,
    pub base:          u64,
    pub length:        u64,
    pub mem_attr:      u64,
}

pub unsafe fn parse_nfit(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_nfit_known() -> bool;
pub fn copy_nfit_spa_ranges(out: &mut [NfitSpaRange]) -> usize;
```

## 6. Test surface

| smoke                                | asserts                          |
|--------------------------------------|----------------------------------|
| `smoke_acpi_aest_synthetic_decode`   | hand-built AEST node parses       |
| `smoke_acpi_sdei_supported_path`     | sticky-flag flips on parse        |
| `smoke_acpi_wddt_synthetic_decode`   | hand-built WDDT body parses       |
| `smoke_acpi_lpit_synthetic_decode`   | hand-built LPIT subtable parses   |
| `smoke_acpi_nfit_synthetic_decode`   | hand-built NFIT SPA range parses  |

## 7. Out of scope (v0.1)

- AEST per-node interrupt arrays.
- SDEI event-routing (lives in the interrupts subsystem).
- WDDT timer-arm policy + irq plumbing.
- LPIT subtables of types other than Native-C-State.
- NFIT subtables of types other than SPA-Range; full
  Memory-Device + Control-Region + Flush-Hint walk lands when
  the persistent-memory pipeline grows.

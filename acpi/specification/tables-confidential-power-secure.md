# tables-confidential-power-secure — CCEL + MPST + SDEV + SBST + RAS2

> Status: **v0.1**.

Adds parsers for:

  * **CCEL** — Confidential Computing Event Log.
  * **MPST** — Memory Power State Table.
  * **SDEV** — Secure Devices Table.
  * **SBST** — Smart Battery Specification Table.
  * **RAS2** — RAS Feature Table.

All build on `walk_xsdt` and follow the existing idempotent /
sticky-flag pattern.

## 1. CCEL

### 1.1 Layout

| field           | size | meaning                                  |
|-----------------|------|------------------------------------------|
| CCType          | 1 B  | 0 = TDX, 1 = SEV                         |
| CCSubType       | 1 B  |                                           |
| Reserved        | 2 B  |                                           |
| LogAreaMin      | 8 B  | log buffer length                         |
| LogAreaPhys     | 8 B  | log buffer physical address               |

### 1.2 API

```rust
pub struct CcelInfo {
    pub cc_type:        u8,
    pub cc_subtype:     u8,
    pub log_area_min:   u64,
    pub log_area_phys:  u64,
}

pub unsafe fn parse_ccel(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn ccel_info() -> Option<CcelInfo>;
```

## 2. MPST

### 2.1 Layout

| field             | size | meaning                                |
|-------------------|------|----------------------------------------|
| PccId             | 1 B  |                                         |
| Reserved          | 3 B  |                                         |
| MemPwrNodeCount   | 2 B  | count of trailing power-node entries    |
| Reserved          | 2 B  |                                         |
| MemPwrNodes[NodeCount] (variable)                            |

Each MemPwrNode (header):

| field                     | size | meaning                  |
|---------------------------|------|--------------------------|
| Flags                     | 1 B  | bit 0 = enabled, bit 1 = power-managed, bit 2 = hot-pluggable |
| Reserved                  | 1 B  |                          |
| MemPwrNodeId              | 2 B  |                           |
| Length                    | 4 B  |                           |
| BasePhys                  | 8 B  |                           |
| LengthBytes               | 8 B  |                           |
| StateValueCount           | 4 B  |                           |
| PhysComponentCount        | 4 B  |                           |
| ... per-state + per-component blocks ...                    |

### 2.2 API

```rust
pub struct MpstNode {
    pub node_id:           u16,
    pub enabled:           bool,
    pub power_managed:     bool,
    pub hot_pluggable:     bool,
    pub base:              u64,
    pub length_bytes:      u64,
}

pub unsafe fn parse_mpst(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_mpst_known() -> bool;
pub fn copy_mpst_nodes(out: &mut [MpstNode]) -> usize;
```

## 3. SDEV

### 3.1 Layout

Each entry:

| field   | size | meaning                                    |
|---------|------|--------------------------------------------|
| Type    | 1 B  | 0 = ACPI namespace device, 1 = PCI endpoint |
| Flags   | 1 B  |                                          |
| Length  | 2 B  |                                          |
| ...                                                              |

For Type = 1 (PCI endpoint):

| field          | size | meaning                          |
|----------------|------|----------------------------------|
| Segment        | 2 B  |                                   |
| StartBdf       | 2 B  |                                   |
| PciPathOffset  | 2 B  |                                   |
| PciPathLength  | 2 B  |                                   |
| VendorOffset   | 2 B  |                                   |
| VendorLength   | 2 B  |                                   |
| ID-mapping array follows.                                |

### 3.2 API

```rust
pub struct SdevPci {
    pub segment:    u16,
    pub start_bdf:  u16,
}

pub unsafe fn parse_sdev(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_sdev_known() -> bool;
pub fn copy_sdev_pci(out: &mut [SdevPci]) -> usize;
```

## 4. SBST

### 4.1 Layout

| field            | size | meaning                                  |
|------------------|------|------------------------------------------|
| WarningLevel     | 4 B  | mWh                                       |
| LowLevel         | 4 B  |                                           |
| CriticalLevel    | 4 B  |                                           |

### 4.2 API

```rust
pub struct SbstInfo {
    pub warning_level_mwh:  u32,
    pub low_level_mwh:      u32,
    pub critical_level_mwh: u32,
}

pub unsafe fn parse_sbst(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn sbst_info() -> Option<SbstInfo>;
```

## 5. RAS2

### 5.1 Layout

| field                | size | meaning                                |
|----------------------|------|----------------------------------------|
| Reserved             | 2 B  |                                         |
| PccDescriptorCount   | 2 B  |                                         |
| PccDescriptors[Count] (8 B each)                                |

Each PccDescriptor:

| field                | size | meaning                                |
|----------------------|------|----------------------------------------|
| PccId                | 1 B  | corresponds to PCCT subspace id         |
| Reserved             | 2 B  |                                         |
| RasFeatureType       | 1 B  | 0 = MemPatrolScrub, 1 = MemErrInject    |
| InstanceCount        | 4 B  |                                         |

### 5.2 API

```rust
pub struct Ras2Descriptor {
    pub pcc_id:       u8,
    pub feature_type: u8,
    pub instance_count: u32,
}

pub unsafe fn parse_ras2(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_ras2_known() -> bool;
pub fn copy_ras2_descriptors(out: &mut [Ras2Descriptor]) -> usize;
```

## 6. Test surface

| smoke                                | asserts                          |
|--------------------------------------|----------------------------------|
| `smoke_acpi_ccel_synthetic_decode`   | type / log buffer round-trip     |
| `smoke_acpi_mpst_synthetic_decode`   | one MemPwrNode parses             |
| `smoke_acpi_sdev_synthetic_decode`   | one PCI endpoint parses           |
| `smoke_acpi_sbst_synthetic_decode`   | warning/low/critical levels       |
| `smoke_acpi_ras2_synthetic_decode`   | one PCC descriptor parses         |

## 7. Out of scope (v0.1)

- CCEL log-buffer format decode.
- MPST per-state + per-component blocks; we surface the
  per-node header only.
- SDEV ACPI-namespace-device entries (type 0).
- SBST OEM-specific extensions.
- RAS2 PCC handler invocation.

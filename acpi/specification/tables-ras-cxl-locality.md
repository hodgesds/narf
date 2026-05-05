# tables-ras-cxl-locality — RAS / CXL / locality ACPI tables

> Status: **v0.1**.

Adds parsers for:

  * **HEST** — Hardware Error Source Table.
  * **PCCT** — Platform Communication Channels Table.
  * **SLIT** — System Locality Information Table.
  * **CEDT** — CXL Early Discovery Table.
  * **BERT** — Boot Error Record Table.

All five build on `walk_xsdt` and follow the existing
idempotent / sticky-flag pattern.

## 1. HEST

### 1.1 Layout

| field        | size | meaning                       |
|--------------|------|-------------------------------|
| ErrorSourceCount | 4 B | count of trailing structures |

Each error-source entry starts with:

| field   | size | meaning                                    |
|---------|------|--------------------------------------------|
| Type    | 2 B  | 0 = MCE, 1 = CMC, 2 = NMI, 6 = AER root, 7 = AER endpoint, 8 = AER bridge, 9 = GHES, 10 = GHESv2, 11 = IA32 deferred MC |
| Length is type-specific.                                  |

For Type = 0 (Machine Check):

| field          | size | meaning             |
|----------------|------|---------------------|
| SourceId       | 2 B  |                      |
| Reserved       | 2 B  |                      |
| Flags          | 1 B  |                      |
| Enabled        | 1 B  |                      |
| NumRecordsToPreallocate | 4 B |                |
| MaxSectionsPerRecord    | 4 B |                |
| GlobalCapability        | 8 B |                |
| GlobalControl           | 8 B |                |
| NumHwBanks      | 1 B  |                      |
| Reserved        | 7 B  |                      |
| McaBank[NumHwBanks] (28 B each)                  |

For Type = 9 (GHES):

| field        | size | meaning                |
|--------------|------|------------------------|
| SourceId     | 2 B  |                         |
| RelatedSrcId | 2 B  |                         |
| Flags        | 1 B  |                         |
| Enabled      | 1 B  |                         |
| NumRecordsToPreallocate | 4 B |                |
| MaxSectionsPerRecord    | 4 B |                |
| MaxRawDataLength | 4 B |                       |
| ErrorStatusAddress | 12 B (GAS) |                |
| Notification     | 28 B  |                       |
| ErrorStatusBlockLength | 4 B |                  |

### 1.2 API

```rust
pub struct HestMceSource {
    pub source_id:       u16,
    pub enabled:         bool,
    pub num_hw_banks:    u8,
    pub global_capability: u64,
    pub global_control:    u64,
}

pub struct HestGhesSource {
    pub source_id:               u16,
    pub enabled:                 bool,
    pub max_sections_per_record: u32,
    pub error_status_block_addr: u64,
}

pub unsafe fn parse_hest(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_hest_known() -> bool;
pub fn copy_hest_mce(out: &mut [HestMceSource]) -> usize;
pub fn copy_hest_ghes(out: &mut [HestGhesSource]) -> usize;
```

## 2. PCCT

### 2.1 Layout

| field    | size | meaning                       |
|----------|------|-------------------------------|
| Flags    | 4 B  | bit 0 = PLAT_INTERRUPT_VALID  |
| Reserved | 8 B  |                                |

Each subspace entry (PCC channel):

| field   | size | meaning                                    |
|---------|------|--------------------------------------------|
| Type    | 1 B  | 0 = generic, 1 = HW-reduced, 2 = HW-reduced v2, 3 = extended |
| Length  | 1 B  |                                          |
| ...                                                              |

For Type = 0 (Generic):

| field                    | size | meaning            |
|--------------------------|------|--------------------|
| Reserved                 | 6 B  |                     |
| BaseAddress              | 8 B  | shared-memory base |
| Length                   | 8 B  | shared-memory len  |
| DoorbellRegister         | 12 B | GAS                |
| DoorbellPreserve         | 8 B  |                     |
| DoorbellWrite            | 8 B  |                     |
| NominalLatency_us        | 4 B  |                     |
| MaxPeriodicAccessRate    | 4 B  |                     |
| MinRequestTurnaround_us  | 2 B  |                     |

### 2.2 API

```rust
pub struct PcctChannel {
    pub kind:          u8,         // raw type
    pub shmem_base:    u64,
    pub shmem_length:  u64,
    pub doorbell_addr: u64,
    pub doorbell_write: u64,
    pub min_turnaround_us: u16,
}

pub unsafe fn parse_pcct(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_pcct_known() -> bool;
pub fn copy_pcct_channels(out: &mut [PcctChannel]) -> usize;
```

## 3. SLIT

### 3.1 Layout

| field         | size | meaning                       |
|---------------|------|-------------------------------|
| LocalityCount | 8 B  | N (number of NUMA nodes)      |
| Matrix        | N × N B | distances; 10 = local       |

`Matrix[i][j]` is a single byte; values are normalised so 10
means "same node" and >10 means "this many tens-of-percent
slower than local".

### 3.2 API

```rust
pub unsafe fn parse_slit(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_slit_known() -> bool;
pub fn slit_distance(from: u8, to: u8) -> Option<u8>;
pub fn slit_locality_count() -> u32;
```

## 4. CEDT

### 4.1 Layout

Each CEDT entry:

| field   | size | meaning                                    |
|---------|------|--------------------------------------------|
| Type    | 1 B  | 0 = CHBS (CXL Host Bridge), 1 = CFMWS (CXL Fixed Memory Window) |
| Reserved| 1 B  |                                          |
| Length  | 2 B  |                                          |

For Type = 0 (CHBS):

| field    | size | meaning                                |
|----------|------|----------------------------------------|
| UID      | 4 B  |                                         |
| CxlVer   | 4 B  | 0 = CXL 1.1, 1 = CXL 2.0                |
| Reserved | 4 B  |                                         |
| Base     | 8 B  | CXL.cache + CXL.mem MMIO base           |
| Length   | 8 B  | window length                            |

For Type = 1 (CFMWS):

| field        | size | meaning                            |
|--------------|------|------------------------------------|
| Reserved     | 4 B  |                                     |
| BaseHpa      | 8 B  | host phys-addr base                 |
| WindowSize   | 8 B  |                                     |
| EncodedNumIw | 1 B  | encoded interleave-ways             |
| InterleaveArith | 1 B |                                  |
| Reserved     | 2 B  |                                     |
| HostBridgeIfaceType | 4 B |                              |
| WindowRestrictions | 2 B |                              |
| QtgId        | 2 B  |                                     |
| TargetList[NumIw]                                |

### 4.2 API

```rust
pub struct CedtChbs {
    pub uid:    u32,
    pub cxl_ver:u32,
    pub base:   u64,
    pub length: u64,
}

pub struct CedtCfmws {
    pub base_hpa:    u64,
    pub window_size: u64,
    pub encoded_iw:  u8,
}

pub unsafe fn parse_cedt(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_cedt_known() -> bool;
pub fn copy_cedt_chbs(out: &mut [CedtChbs]) -> usize;
pub fn copy_cedt_cfmws(out: &mut [CedtCfmws]) -> usize;
```

## 5. BERT

### 5.1 Layout

| field                | size | meaning                  |
|----------------------|------|--------------------------|
| BootErrorRegionLength| 4 B  |                           |
| BootErrorRegion      | 8 B  | physical address         |

The region itself is a `BOOT_ERROR_REGION` that we surface as
just the (addr, length) pair; the deeper format lives in the
RAS pipeline once it grows.

### 5.2 API

```rust
pub struct BertInfo {
    pub region_addr: u64,
    pub region_length: u32,
}

pub unsafe fn parse_bert(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn bert_info() -> Option<BertInfo>;
```

## 6. Test surface

| smoke                                | asserts                          |
|--------------------------------------|----------------------------------|
| `smoke_acpi_hest_synthetic_decode`   | hand-built MCE+GHES sources parse |
| `smoke_acpi_pcct_synthetic_decode`   | hand-built generic channel parses |
| `smoke_acpi_slit_synthetic_decode`   | matrix lookup matches             |
| `smoke_acpi_cedt_synthetic_decode`   | hand-built CHBS+CFMWS parse        |
| `smoke_acpi_bert_synthetic_decode`   | (addr, length) round-trip          |

## 7. Out of scope (v0.1)

- HEST AER (PCIe Advanced Error Reporting) per-bus walk.
- HEST notification-structure decode (signalling mechanism).
- PCCT extended subspace types (3 = extended PCC).
- CEDT CXL Switch / Memory Window target-list walk.
- BERT BOOT_ERROR_REGION decode (the inner Generic Error Status
  Block format).
- HEST → RAS event-routing → narf-tracing.

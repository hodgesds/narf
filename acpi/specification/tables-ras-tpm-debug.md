# tables-ras-tpm-debug — RAS injection + TPM + graphics + debug

> Status: **v0.1**.

Adds parsers for:

  * **ERST** — Error Record Serialization Table.
  * **EINJ** — Error Injection.
  * **TPM2** — Trusted Platform Module 2.0.
  * **BGRT** — Boot Graphics Resource Table.
  * **DBG2** — Debug Port Table 2.

All five build on `walk_xsdt` and follow the existing
idempotent / sticky-flag pattern.

## 1. ERST

### 1.1 Layout

| field                  | size | meaning                       |
|------------------------|------|-------------------------------|
| SerializationHdrSize   | 4 B  |                                |
| Reserved               | 4 B  |                                |
| InstructionEntryCount  | 4 B  | count of trailing entries     |

Each instruction-entry is 32 B:

| field             | size | meaning                          |
|-------------------|------|----------------------------------|
| Action            | 1 B  | 0..14 (Begin / SetTag / Read…)  |
| Instruction       | 1 B  | 0..18                            |
| Flags             | 1 B  |                                   |
| Reserved          | 1 B  |                                   |
| RegisterRegion    | 12 B | GAS                              |
| Value             | 8 B  |                                   |
| Mask              | 8 B  |                                   |

### 1.2 API

```rust
pub struct ErstInstruction {
    pub action:      u8,
    pub instruction: u8,
    pub addr:        u64,
    pub value:       u64,
    pub mask:        u64,
}

pub unsafe fn parse_erst(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_erst_known() -> bool;
pub fn copy_erst_instructions(out: &mut [ErstInstruction]) -> usize;
```

## 2. EINJ

### 2.1 Layout

Same shape as ERST: a header carrying
`InstructionEntryCount` followed by 32-byte instruction
entries with the same field shape.

### 2.2 API

```rust
pub struct EinjInstruction {
    pub action:      u8,
    pub instruction: u8,
    pub addr:        u64,
    pub value:       u64,
    pub mask:        u64,
}

pub unsafe fn parse_einj(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_einj_known() -> bool;
pub fn copy_einj_instructions(out: &mut [EinjInstruction]) -> usize;
```

## 3. TPM2

### 3.1 Layout

| field           | size | meaning                                |
|-----------------|------|----------------------------------------|
| Platform Class  | 2 B  | 0 = Client, 1 = Server                 |
| Reserved        | 2 B  |                                         |
| ControlAreaAddr | 8 B  | physical address of the control area   |
| StartMethod     | 4 B  | 0 = ACPI, 6 = MMIO, 7 = CRB, 8 = CRBwithACPI, 9 = CRBwithSMC, 11 = CRBwithSMC-FF |

### 3.2 API

```rust
pub struct Tpm2Info {
    pub platform_class:    u16,
    pub control_area_addr: u64,
    pub start_method:      u32,
}

pub unsafe fn parse_tpm2(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn tpm2_info() -> Option<Tpm2Info>;
```

## 4. BGRT

### 4.1 Layout

| field        | size | meaning                                  |
|--------------|------|------------------------------------------|
| Version      | 2 B  | 1                                         |
| Status       | 1 B  | bit 0 = displayed, bits[2:1] = orientation |
| ImageType    | 1 B  | 0 = bitmap                                |
| ImageAddress | 8 B  | phys addr of image                       |
| ImageOffsetX | 4 B  |                                           |
| ImageOffsetY | 4 B  |                                           |

### 4.2 API

```rust
pub struct BgrtInfo {
    pub status:        u8,
    pub image_address: u64,
    pub offset_x:      u32,
    pub offset_y:      u32,
}

pub unsafe fn parse_bgrt(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn bgrt_info() -> Option<BgrtInfo>;
```

## 5. DBG2

### 5.1 Layout

| field            | size | meaning                                |
|------------------|------|----------------------------------------|
| InfoOffset       | 4 B  | offset to first DeviceInfo             |
| InfoCount        | 4 B  | count of DeviceInfo entries            |

Each DeviceInfo:

| field                  | size | meaning                                |
|------------------------|------|----------------------------------------|
| Revision               | 1 B  |                                         |
| Length                 | 2 B  |                                         |
| RegisterCount          | 1 B  |                                         |
| NamespaceStringLength  | 2 B  |                                         |
| NamespaceStringOffset  | 2 B  |                                         |
| OemDataLength          | 2 B  |                                         |
| OemDataOffset          | 2 B  |                                         |
| PortType               | 2 B  | 0x8000 = serial, 0x8001 = 1394, 0x8002 = USB, 0x8003 = NET |
| PortSubtype            | 2 B  |                                         |
| Reserved               | 2 B  |                                         |
| BaseAddrRegOffset      | 2 B  |                                         |
| AddressSizeOffset      | 2 B  |                                         |
| ... [BAR GAS array, length AddressSize ranges] ...      |

### 5.2 API

```rust
pub struct Dbg2Device {
    pub port_type:    u16,
    pub port_subtype: u16,
    pub base_addr:    u64,
}

pub unsafe fn parse_dbg2(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_dbg2_known() -> bool;
pub fn copy_dbg2_devices(out: &mut [Dbg2Device]) -> usize;
```

## 6. Test surface

| smoke                                | asserts                          |
|--------------------------------------|----------------------------------|
| `smoke_acpi_erst_synthetic_decode`   | hand-built 32-byte instruction parses |
| `smoke_acpi_einj_synthetic_decode`   | hand-built 32-byte instruction parses |
| `smoke_acpi_tpm2_synthetic_decode`   | (class, control area, start method) round-trip |
| `smoke_acpi_bgrt_synthetic_decode`   | image addr + offsets decoded     |
| `smoke_acpi_dbg2_synthetic_decode`   | one DeviceInfo with serial port type parses |

## 7. Out of scope (v0.1)

- ERST / EINJ instruction-stream interpreter.
- TPM2 control-area + command-buffer interaction (lives in
  `drivers/platform/tpm`).
- BGRT bitmap decode.
- DBG2 namespace-string + OEM-data walk.
- DBG2 BAR-array decode (we surface just the first base).

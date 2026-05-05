# tables-firmware-hpet-prm — firmware + HPET + PRM tables

> Status: **v0.1**.

Adds parsers for:

  * **WSMT** — Windows SMM Mitigation Table.
  * **WAET** — Windows ACPI Emulated Devices Table.
  * **HPET** — High Precision Event Timer Description Table.
  * **FACS** — Firmware ACPI Control Structure (reached via FADT).
  * **PRMT** — Platform Runtime Mechanism Table.

All build on `walk_xsdt` (or, for FACS, the existing FADT
parsing path) and follow the existing idempotent / sticky-flag
pattern.

## 1. WSMT

### 1.1 Layout

| field           | size | meaning                                  |
|-----------------|------|------------------------------------------|
| ProtectionFlags | 4 B  | bit 0 = FIXED_COMM_BUFFERS, bit 1 = COMM_BUFFER_NESTED_PTR_PROTECTION, bit 2 = SYSTEM_RESOURCE_PROTECTION |

### 1.2 API

```rust
pub struct WsmtInfo {
    pub fixed_comm_buffers:        bool,
    pub comm_buffer_nested_ptr:    bool,
    pub system_resource_protection: bool,
}

pub unsafe fn parse_wsmt(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn wsmt_info() -> Option<WsmtInfo>;
```

## 2. WAET

### 2.1 Layout

| field      | size | meaning                                     |
|------------|------|---------------------------------------------|
| EmulatedDeviceFlags | 4 B | bit 0 = RTC_GOOD, bit 1 = ACPI_PMTIMER_GOOD |

### 2.2 API

```rust
pub struct WaetInfo {
    pub rtc_good:          bool,
    pub acpi_pmtimer_good: bool,
}

pub unsafe fn parse_waet(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn waet_info() -> Option<WaetInfo>;
```

## 3. HPET (Description Table)

### 3.1 Layout

| field            | size | meaning                                  |
|------------------|------|------------------------------------------|
| EventTimerBlockId| 4 B  | hardware ID + caps                       |
| BaseAddress      | 12 B | GAS                                      |
| HpetNumber       | 1 B  |                                           |
| MainCounterMin   | 2 B  | minimum tick                              |
| OemAttributes    | 1 B  |                                           |

### 3.2 API

```rust
pub struct HpetDesc {
    pub block_id:         u32,
    pub base:             u64,
    pub addr_space_id:    u8,
    pub hpet_number:      u8,
    pub main_counter_min: u16,
    pub oem_attributes:   u8,
}

pub unsafe fn parse_hpet(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn hpet_desc() -> Option<HpetDesc>;
```

## 4. FACS

### 4.1 Layout

FACS is reached via `FADT.firmware_ctrl` (32-bit) or
`FADT.x_firmware_ctrl` (64-bit). Layout:

| field                | size | meaning                  |
|----------------------|------|--------------------------|
| Signature `FACS`     | 4 B  |                           |
| Length               | 4 B  | total length              |
| HardwareSignature    | 4 B  |                           |
| FirmwareWakingVector | 4 B  | x86 only (legacy)         |
| GlobalLock           | 4 B  |                           |
| Flags                | 4 B  | bit 0 = S4BIOS_F, bit 1 = 64BIT_WAKE_SUPPORTED_F |
| XFirmwareWakingVector| 8 B  |                           |
| Version              | 1 B  |                           |
| Reserved             | 3 B  |                           |
| OspmFlags            | 4 B  | bit 0 = 64BIT_WAKE_F      |

The OS uses FACS to coordinate sleep transitions with the
firmware; v0.1 surfaces just the read side.

### 4.2 API

```rust
pub struct FacsInfo {
    pub hardware_signature:        u32,
    pub firmware_waking_vector_32: u32,
    pub firmware_waking_vector_64: u64,
    pub global_lock:               u32,
    pub flags:                     u32,
    pub version:                   u8,
}

pub unsafe fn parse_facs(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn facs_info() -> Option<FacsInfo>;
```

## 5. PRMT

### 5.1 Layout

| field                  | size | meaning                  |
|------------------------|------|--------------------------|
| PrmPlatformGuid        | 16 B |                          |
| PrmModuleInfoOffset    | 4 B  |                           |
| PrmModuleInfoCount     | 4 B  |                           |

Each ModuleInfo block:

| field               | size | meaning                        |
|---------------------|------|--------------------------------|
| Revision            | 2 B  |                                 |
| Length              | 2 B  |                                 |
| ModuleGuid          | 16 B |                                 |
| MajorRevision       | 2 B  |                                 |
| MinorRevision       | 2 B  |                                 |
| HandlerCount        | 2 B  |                                 |
| HandlerInfoOffset   | 4 B  | offset to first HandlerInfo     |
| MmioRangeAddr       | 8 B  |                                 |
| ...                                                          |

### 5.2 API

```rust
pub struct PrmtModule {
    pub major_revision: u16,
    pub minor_revision: u16,
    pub handler_count:  u16,
    pub mmio_range:     u64,
}

pub unsafe fn parse_prmt(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_prmt_known() -> bool;
pub fn copy_prmt_modules(out: &mut [PrmtModule]) -> usize;
```

## 6. Test surface

| smoke                                | asserts                          |
|--------------------------------------|----------------------------------|
| `smoke_acpi_wsmt_synthetic_decode`   | flags bitfield round-trips       |
| `smoke_acpi_waet_synthetic_decode`   | RTC + PM timer flags round-trip   |
| `smoke_acpi_hpet_synthetic_decode`   | block id + base + counter min     |
| `smoke_acpi_facs_synthetic_decode`   | hardware signature + flags        |
| `smoke_acpi_prmt_synthetic_decode`   | one module info entry parses      |

## 7. Out of scope (v0.1)

- WSMT / WAET enforcement policy.
- HPET timer-comparator + interrupt-routing access (lives in
  `arch::x86_64::hpet`).
- FACS sleep-state coordination (S0iX / S3 / S4 transitions).
- PRMT handler walk + invocation.
- PRMT module-GUID matching → driver dispatch.

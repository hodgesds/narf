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
firmware. Reads are unconditional; the only write is the S3
waking-vector arming described in §4.3.

### 4.2 API

```rust
pub struct FacsInfo {
    pub length:                    u32,
    pub hardware_signature:        u32,
    pub firmware_waking_vector_32: u32,
    pub firmware_waking_vector_64: u64,
    pub global_lock:               u32,
    pub flags:                     u32,
    pub version:                   u8,
    pub ospm_flags:                u32,
}

pub const FACS_FLAG_64BIT_WAKE_SUPPORTED: u32 = 1 << 1;
pub const FACS_OSPM_FLAG_64BIT_WAKE:      u32 = 1;
pub const FACS_MIN_LEN_64BIT_WAKE:        u32 = 40;

pub unsafe fn parse_facs(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn facs_info() -> Option<FacsInfo>;
pub unsafe fn arm_s3_waking_vector(entry_phys: u64) -> Result<(), WakeVectorError>;
```

### 4.3 Arming the S3 waking vector

The two waking-vector slots are not interchangeable:

| slot                     | off | firmware enters it in | takes                    |
|--------------------------|-----|-----------------------|--------------------------|
| `FirmwareWakingVector`   | +12 | **real mode**         | sub-1 MiB 16-bit stub    |
| `XFirmwareWakingVector`  | +24 | 64-bit environment    | any long-mode address    |

NARF's wake entry (`narf_arch::x86_64::s3_resume::s3_wake_entry`)
is a long-mode entry point in the kernel image, and NARF ships no
real-mode trampoline. `arm_s3_waking_vector` therefore takes the
64-bit-wake path exclusively:

1. refuse unless `Length >= FACS_MIN_LEN_64BIT_WAKE`, `Version >= 1`,
   and `Flags.64BIT_WAKE_SUPPORTED_F` is set by firmware;
2. write `entry_phys` to `XFirmwareWakingVector`;
3. set `OspmFlags.64BIT_WAKE_F` to select that path;
4. write **zero** to the 32-bit `FirmwareWakingVector`.

A refused arm leaves the FACS byte-for-byte unmodified. Firmware
that implements only the legacy real-mode vector is therefore
unsupported by design — `power::arm_s3_resume` turns the error into
`SuspendError::Aborted` and declines to sleep rather than sleeping
into a machine that cannot resume. Closing that gap requires a real
sub-1 MiB real-mode trampoline, not a different value in the same
slot.

LINUX-GAP: Linux takes the opposite branch — it always writes the
32-bit slot and always passes 0 for the 64-bit one
(`drivers/acpi/sleep.h`, `drivers/acpi/acpica/hwxfsleep.c`),
because x86 Linux does ship that trampoline
(`arch/x86/realmode/rm/wakeup_asm.S`, `.code16`, allocated below
1 MiB by `reserve_real_mode()`). Linux never reads
`64BIT_WAKE_SUPPORTED_F` nor writes `OspmFlags`.

Neither side of this is boot-proven on NARF: S3 is gated off behind
`REAL_SLEEP_ARMED` / `PRODUCTION_S3_ENABLED` and QEMU/TCG offers no
real suspend/resume cycle, so the behaviour above is established by
the `acpi/wake_vector` smokes against a synthetic in-memory FACS.

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
| `smoke_acpi_arm_s3_waking_vector_requires_facs` | unparsed FACS refuses arming |
| `smoke_acpi_arm_s3_waking_vector_uses_64bit_slot_only` | long-mode entry lands only in `XFirmwareWakingVector`; 32-bit slot stays 0; `OspmFlags.64BIT_WAKE_F` set |
| `smoke_acpi_arm_s3_waking_vector_refuses_unsupported_firmware` | short / v0 / non-64-bit-wake FACS refused, table left untouched |
| `smoke_acpi_prmt_synthetic_decode`   | one module info entry parses      |

## 7. Out of scope (v0.1)

- WSMT / WAET enforcement policy.
- HPET timer-comparator + interrupt-routing access (lives in
  `arch::x86_64::hpet`).
- FACS sleep-state coordination beyond §4.3's S3 waking-vector
  arming (S0iX / S4, `GlobalLock` arbitration, `HardwareSignature`
  validation on resume).
- A sub-1 MiB real-mode wake trampoline, which is what the legacy
  32-bit `FirmwareWakingVector` would need (§4.3).
- PRMT handler walk + invocation.
- PRMT module-GUID matching → driver dispatch.

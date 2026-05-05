# tables-tcpa-mchi-phat-stao-uefi — TPM 1.2 + BMC + health + override + UEFI

> Status: **v0.1**.

Adds parsers for:

  * **TCPA** — Trusted Computing Platform Alliance (TPM 1.2 event log).
  * **MCHI** — Management Controller Host Interface.
  * **PHAT** — Platform Health Assessment Table.
  * **StAO** — Status Override Table.
  * **UEFI** — UEFI ACPI Data Table.

## 1. TCPA (Client TPM 1.2)

| field           | size | meaning                                  |
|-----------------|------|------------------------------------------|
| PlatformClass   | 2 B  | 0 = Client                               |
| LogAreaMin      | 4 B  | log buffer length                         |
| LogAreaPhys     | 8 B  | log buffer physical address               |

```rust
pub struct TcpaInfo {
    pub platform_class: u16,
    pub log_area_min:   u32,
    pub log_area_phys:  u64,
}

pub unsafe fn parse_tcpa(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn tcpa_info() -> Option<TcpaInfo>;
```

## 2. MCHI

| field         | size | meaning                                  |
|---------------|------|------------------------------------------|
| InterfaceType | 1 B  | 1 = KCS, 2 = SMIC, 3 = BT, 4 = SMBus     |
| Protocols     | 1 B  | bitmap                                    |
| Reserved      | 6 B  |                                           |
| Identifier    | 8 B  |                                           |
| BaseAddress   | 12 B | GAS                                       |

```rust
pub struct MchiInfo {
    pub interface_type: u8,
    pub protocols:      u8,
    pub identifier:     u64,
    pub base:           u64,
}

pub unsafe fn parse_mchi(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn mchi_info() -> Option<MchiInfo>;
```

## 3. PHAT

PHAT carries variable-length records. After SDT_HEADER:

| field    | size | meaning                                  |
|----------|------|------------------------------------------|
| Each subtable header (4 B):                                |
| Type     | 2 B  | 0 = Firmware Version Data, 1 = Health Data |
| Length   | 2 B  |                                          |
| ...                                                              |

For Type = 0:

| field       | size | meaning                                |
|-------------|------|----------------------------------------|
| Reserved    | 1 B  |                                         |
| RecordCount | 4 B  |                                         |
| Records[Count]: GUID (16) + VersionValue (8) + ProducerId (4) |

For Type = 1:

| field       | size | meaning                                |
|-------------|------|----------------------------------------|
| Reserved    | 1 B  |                                         |
| AmHealthy   | 1 B  | 0 = errors, 1 = warnings, 2 = info, 3 = healthy |
| DeviceGuid  | 16 B |                                         |

```rust
pub struct PhatHealthRecord {
    pub am_healthy: u8,
    pub device_guid: [u8; 16],
}

pub unsafe fn parse_phat(rsdp_phys: PhysAddr) -> Result<u32, AcpiError>;
pub fn is_phat_known() -> bool;
pub fn copy_phat_health(out: &mut [PhatHealthRecord]) -> usize;
```

## 4. StAO

| field         | size | meaning                                  |
|---------------|------|------------------------------------------|
| IgnoreUart    | 1 B  | 1 = OS should ignore the UART per FADT   |

```rust
pub struct StaoInfo {
    pub ignore_uart: bool,
}

pub unsafe fn parse_stao(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn stao_info() -> Option<StaoInfo>;
```

## 5. UEFI

The UEFI ACPI Data Table is a GUID-tagged blob; we surface the
GUID + payload-length pair so callers can hand the body to a
GUID-specific decoder.

| field      | size | meaning                                  |
|------------|------|------------------------------------------|
| Identifier | 16 B | UEFI vendor / data GUID                  |
| DataOffset | 2 B  | offset to vendor-specific blob            |

```rust
pub struct UefiTableInfo {
    pub identifier: [u8; 16],
    pub data_offset: u16,
}

pub unsafe fn parse_uefi(rsdp_phys: PhysAddr) -> Result<(), AcpiError>;
pub fn uefi_table_info() -> Option<UefiTableInfo>;
```

## 6. Test surface

| smoke                                | asserts                          |
|--------------------------------------|----------------------------------|
| `smoke_acpi_tcpa_synthetic_decode`   | platform class + log buffer       |
| `smoke_acpi_mchi_synthetic_decode`   | interface type + base + identifier |
| `smoke_acpi_phat_synthetic_decode`   | one Health record parses          |
| `smoke_acpi_stao_synthetic_decode`   | ignore-UART flag                  |
| `smoke_acpi_uefi_synthetic_decode`   | GUID + data offset                |

## 7. Out of scope (v0.1)

- TCPA log-buffer event format decode (lives in the TPM
  driver).
- MCHI BMC interaction (KCS / SMIC / BT command sequences).
- PHAT FirmwareVersionData record walk.
- StAO namespace-string array (ignored ACPI device names).
- UEFI vendor-blob decoders.

# SMBIOS / DMI table parser

> Status: **v0.1**.

Locates the SMBIOS entry point, walks the structure stream
referenced by it, and decodes the most-useful fixed-size
records:

  * **Type 0** — BIOS Information.
  * **Type 1** — System Information.
  * **Type 2** — Baseboard.
  * **Type 4** — Processor Information.
  * **Type 17** — Memory Device.

Other record types are skipped over but their lengths +
trailing string pools are still walked so the parser stays in
sync. The parser is designed to consume a slice of bytes
spanning the structure stream — callers decide how to obtain
that slice (e.g., via QEMU `fw_cfg`'s `etc/smbios/smbios-tables`
key, the EFI configuration table, or a UEFI-discovered
SMBIOS3 entry point).

## 1. Entry point

Two formats:

### 1.1 32-bit (`_SM_`)

| field                  | size | meaning                                  |
|------------------------|------|------------------------------------------|
| Anchor `_SM_`          | 4 B  |                                           |
| EntryPointChecksum     | 1 B  |                                           |
| EntryPointLength       | 1 B  |                                           |
| MajorVersion           | 1 B  |                                           |
| MinorVersion           | 1 B  |                                           |
| MaxStructureSize       | 2 B  |                                           |
| EntryPointRevision     | 1 B  |                                           |
| FormattedArea          | 5 B  |                                           |
| Anchor `_DMI_`         | 5 B  |                                           |
| InterChecksum          | 1 B  |                                           |
| StructureTableLength   | 2 B  |                                           |
| StructureTableAddress  | 4 B  | physical address                          |
| NumberOfStructures     | 2 B  |                                           |
| BcdRevision            | 1 B  |                                           |

### 1.2 64-bit (`_SM3_`)

| field                  | size | meaning                                  |
|------------------------|------|------------------------------------------|
| Anchor `_SM3_`         | 5 B  |                                           |
| EntryPointChecksum     | 1 B  |                                           |
| EntryPointLength       | 1 B  |                                           |
| MajorVersion           | 1 B  |                                           |
| MinorVersion           | 1 B  |                                           |
| Docrev                 | 1 B  |                                           |
| EntryPointRevision     | 1 B  |                                           |
| Reserved               | 1 B  |                                           |
| StructureTableMaxSize  | 4 B  |                                           |
| StructureTableAddress  | 8 B  | physical address                          |

## 2. Per-record header

Every structure starts with:

| field      | size | meaning                                    |
|------------|------|--------------------------------------------|
| Type       | 1 B  | structure type                             |
| Length     | 1 B  | length of the **formatted** (fixed) section |
| Handle     | 2 B  | 16-bit handle                              |

Following the formatted section is a string pool: a sequence
of NUL-terminated strings, terminated by a double NUL.

## 3. Decoded record shapes

### 3.1 Type 0 — BIOS Information

| offset | field                  |
|--------|------------------------|
| 4      | Vendor (string ref)    |
| 5      | Version (string ref)   |
| 6..8   | StartingAddrSegment    |
| 8      | ReleaseDate (string ref)|
| 9      | RomSize                |
| ...                                |

```rust
pub struct SmbiosBios {
    pub vendor:        [u8; 64],   // string copied from pool, NUL-padded
    pub version:       [u8; 64],
    pub release_date:  [u8; 16],
    pub rom_size:      u8,
}
```

### 3.2 Type 1 — System Information

| offset | field                |
|--------|----------------------|
| 4      | Manufacturer (string) |
| 5      | ProductName (string) |
| 6      | Version (string)     |
| 7      | SerialNumber (string)|
| 8..24  | UUID                 |
| 24     | WakeUpType           |

```rust
pub struct SmbiosSystem {
    pub manufacturer: [u8; 64],
    pub product_name: [u8; 64],
    pub version:      [u8; 64],
    pub serial_number:[u8; 64],
    pub uuid:         [u8; 16],
    pub wake_up_type: u8,
}
```

### 3.3 Type 2 — Baseboard

```rust
pub struct SmbiosBaseboard {
    pub manufacturer: [u8; 64],
    pub product:      [u8; 64],
    pub version:      [u8; 64],
    pub serial:       [u8; 64],
}
```

### 3.4 Type 4 — Processor Information

```rust
pub struct SmbiosProcessor {
    pub socket_designation: [u8; 32],
    pub processor_type:     u8,
    pub family:             u8,
    pub max_speed_mhz:      u16,
    pub current_speed_mhz:  u16,
    pub status:             u8,
    pub core_count:         u8,
    pub thread_count:       u8,
}
```

### 3.5 Type 17 — Memory Device

```rust
pub struct SmbiosMemoryDevice {
    pub size_mb:        u32,    // architectural extended size folded in
    pub form_factor:    u8,
    pub device_locator: [u8; 32],
    pub bank_locator:   [u8; 32],
    pub memory_type:    u8,
    pub speed_mts:      u16,
    pub manufacturer:   [u8; 64],
    pub serial_number:  [u8; 32],
}
```

## 4. API

```rust
pub fn parse_stream(bytes: &[u8]) -> u32;        // count of records observed
pub fn copy_bios(out: &mut [SmbiosBios]) -> usize;
pub fn copy_system(out: &mut [SmbiosSystem]) -> usize;
pub fn copy_baseboard(out: &mut [SmbiosBaseboard]) -> usize;
pub fn copy_processors(out: &mut [SmbiosProcessor]) -> usize;
pub fn copy_memory_devices(out: &mut [SmbiosMemoryDevice]) -> usize;
pub fn is_known() -> bool;
```

## 5. Test surface

| smoke                                | asserts                          |
|--------------------------------------|----------------------------------|
| `smoke_smbios_bios_record`           | Type 0 round-trip with strings    |
| `smoke_smbios_system_record`         | Type 1 with UUID                  |
| `smoke_smbios_processor_record`      | Type 4 max/current speeds          |
| `smoke_smbios_memory_device`         | Type 17 size + speed              |
| `smoke_smbios_skips_unknown`         | unknown types walked correctly     |

## 6. Out of scope (v0.1)

- Type 17 EXT_BIO encoding (28-bit speed, 32-bit voltages).
- String index dereference beyond 64-byte truncation.
- Type-3 enclosure / Type-9 slot / Type-19 memory-array
  records — extend the parser as drivers come online.
- Live entry-point discovery (callers hand the parser the
  structure-stream slice).

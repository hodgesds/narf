# SMBIOS / DMI table parser

> Status: **v0.1**.

Locates the SMBIOS entry point, walks the structure stream
referenced by it, and decodes the most-useful fixed-size
records:

Every SMBIOS structure type defined by the v3.x specification is
decoded:

  * **0** BIOS Information, **1** System, **2** Baseboard,
    **3** Chassis, **4** Processor.
  * **5** / **6** / **10** are deprecated by SMBIOS 3 and walked
    but not decoded.
  * **7** Cache, **8** Port Connector, **9** System Slot.
  * **11** OEM Strings, **12** System Config Options,
    **13** BIOS Language, **14** Group Associations,
    **15** System Event Log.
  * **16** Physical Memory Array, **17** Memory Device,
    **18** 32-bit Memory Error Information,
    **19** Memory Array Mapped Address,
    **20** Memory Device Mapped Address.
  * **21** Built-in Pointing Device, **22** Portable Battery,
    **23** System Reset, **24** Hardware Security,
    **25** System Power Controls.
  * **26** Voltage Probe, **27** Cooling Device,
    **28** Temperature Probe, **29** Electrical Current Probe.
  * **30** Out-of-Band Remote Access,
    **31** Boot Integrity Services (BIS).
  * **32** System Boot Information.
  * **33** 64-bit Memory Error Information.
  * **34** Management Device, **35** Management Device Component,
    **36** Management Device Threshold Data.
  * **37** Memory Channel, **38** IPMI Device, **39** System
    Power Supply.
  * **40** Additional Information, **41** Onboard Devices
    Extended, **42** Management Controller Host Interface.
  * **43** TPM Device, **44** Processor Additional Information.
  * **45** Firmware Inventory Information,
    **46** String Property.
  * **126** Inactive (counted, not decoded).
  * **127** End-of-Table (terminates the walk).

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

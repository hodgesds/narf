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

## Entry-point discovery

### Boot-time scan (`dmi-scan`, `Stage::Core`)

`register_initcalls()` registers `dmi-scan` at `Stage::Core`, which
runs before `pci-probe-all` (`Stage::Device`), mirroring Linux's
`dmi_setup` from `setup_arch`. It ports `drivers/firmware/dmi_scan.c`
(`src/discover.rs`):

1. **EFI** (`narf_boot::firmware_handoff().efi_system_table`, i.e.
   multiboot2 tag 12 from Limine / GRUB on UEFI): the system table
   must carry `EFI_SYSTEM_TABLE_SIGNATURE` (`efi_systab_init`); its
   configuration table (`nr_tables` @104, `tables` @112, 24-byte
   `{guid, u64}` rows, at most `MAX_EFI_CONFIG_TABLES`, a later
   duplicate GUID overriding) yields `efi.smbios3`
   (`SMBIOS3_TABLE_GUID`) and `efi.smbios` (`SMBIOS_TABLE_GUID`).
   `efi.smbios3` is tried first; if it fails to decode or its table
   cannot be read, `efi.smbios`.
2. **Loader copies** (NARF addition — Linux is its own EFI stub): the
   multiboot2 tag-13 entry points, `_SM3_` before `_SM_`.
3. **Legacy scan**, only when EFI is not enabled and only on x86_64
   (`CONFIG_DMI_SCAN_MACHINE_NON_EFI_FALLBACK`): the 64 KiB at
   `0xF0000` with Linux's sliding 32-byte window — every paragraph
   but the last as an `_SM3_` candidate first, then `_SM_` at q-16 /
   `_DMI_` at q (a bare `_DMI_` = legacy DMI). PVH boots (QEMU
   `-kernel` + SeaBIOS) take this path.

Entry-point checks are Linux's: `_SM3_` length 24..=32 + checksum,
`dmi_ver` = be24 @7, `dmi_len` = le32 @12, `dmi_base` = le64 @16,
`dmi_num` = 0; `_SM_` length 30..=32 + checksum (optional), `_DMI_`
15-byte checksum (mandatory), le16 len @+6, le32 base @+8, le16 num
@+12, the 2.31/2.33 → 2.3 and 2.51 → 2.6 version fixups. A candidate
counts only if its table can be read (`dmi_walk_early`). Physical
memory is read through `PhysRead`; at boot `KernelPhys` reads via
`PhysAddr::kernel_ptr` (the direct map — the low half is user space
after the MMU handoff), refusing address 0 and anything past
512 GiB. The copied table is bounded by `MAX_TABLE_LEN` (1 MiB;
Linux maps `dmi_len` whole — for SMBIOS 3 that is only a maximum).

The table is walked with `dmi_decode_table`'s exact bounds: stop on
a structure shorter than 4 bytes, a structure is decoded only when
its string set ends inside `dmi_len`, end-of-table (127) ends the
walk only behind a 64-bit entry point (`dmi_num == 0`; 32-bit tables
are bounded by `dmi_num`), and `dmi_len` is trimmed to the walked
length. The decoded records go through `parse_stream`; the raw copy
is kept as the boot `RawTable`. One line is logged:
`dmi: SMBIOS <ver> via <Source>: <n> bytes, <m> structures; product "<type-1 product>"`
or `dmi: DMI not present or invalid.`

### Helpers

1. **`scan_legacy_bios()`** — the legacy scan above, returning the
   decoded `EntryPoint`. `None` off x86_64.

2. **`from_anchor_bytes(bytes)`** — pure-data: takes a slice
   covering the entry-point structure (e.g. content of QEMU
   `fw_cfg`'s `etc/smbios/smbios-anchor` key) and decodes it.
   Returns the same `EntryPoint` shape. Use this when the
   firmware-config interface hands the entry point in-band.

Both helpers share the `EntryPoint` decoded shape:

```rust
pub struct EntryPoint {
    pub version_major:   u8,
    pub version_minor:   u8,
    pub struct_table_phys: u64,
    pub struct_table_len:  u32,
    pub structure_count:   u16,    // 0 for SMBIOS3 (terminator-driven)
}
```

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

// Boot-time discovery + raw retention (src/discover.rs)
pub fn register_initcalls();                     // `dmi-scan`, Stage::Core
pub trait PhysRead { fn read(&self, phys: u64, out: &mut [u8]) -> bool; }
pub struct KernelPhys;                           // direct-map reader, < 512 GiB, != 0
pub struct TableLocation { pub base: u64, pub len: u32, pub num: u16, pub version: u32 }
pub enum Source { EfiSmbios3, EfiSmbios, LoaderSmbios3, LoaderSmbios,
                  LegacySmbios3, LegacySmbios }
pub struct Sources { pub efi_system_table: Option<u64>,
                     pub loader_smbios3: Option<[u8; 32]>,
                     pub loader_smbios: Option<[u8; 32]>, pub legacy_scan: bool }
pub fn smbios3_present(buf: &[u8; 32]) -> Option<TableLocation>; // dmi_smbios3_present
pub fn dmi_present(buf: &[u8; 32]) -> Option<TableLocation>;     // dmi_present
pub fn efi_smbios_tables(systab: u64, mem: &dyn PhysRead)
    -> Option<(Option<u64>, Option<u64>)>;       // (efi.smbios3, efi.smbios); None = not EFI
pub fn scan_legacy_region<T>(region: &[u8],
    try_entry: impl FnMut(&[u8; 32], bool /*sm3*/) -> Option<T>) -> Option<T>;
pub fn scan_machine(src: &Sources, mem: &dyn PhysRead) -> Option<RawTable>;

pub struct RawTable;                             // trimmed copy of the structure table
impl RawTable {
    pub fn from_bytes(bytes: Vec<u8>, num: u16) -> Self; // num = 0 → SMBIOS 3 rules
    pub fn read(loc: TableLocation, source: Source, mem: &dyn PhysRead) -> Option<Self>;
    pub fn bytes(&self) -> &[u8];
    pub fn structure_count(&self) -> u16;
    pub fn version(&self) -> u32;                // dmi_ver
    pub fn source(&self) -> Option<Source>;
    pub fn structures(&self) -> Vec<RawStructure<'_>>;          // dmi_walk order
    pub fn structures_of_type(&self, kind: u8) -> Vec<RawStructure<'_>>;
}
pub struct RawStructure<'a> { pub kind: u8, pub handle: u16,
                              pub bytes: &'a [u8] } // formatted area + string set (incl. "\0\0")
impl RawStructure<'_> { fn length(&self) -> u8; fn formatted(&self) -> &[u8];
                        fn strings(&self) -> &[u8]; fn string(&self, idx: u8) -> Option<&[u8]>; }
pub fn boot_table() -> Option<&'static RawTable>;           // dmi_available
pub fn raw_structures_of_type(kind: u8) -> Vec<RawStructure<'static>>; // empty without a table
```

`parse_stream` overwrites the global typed tables (tests call it with
synthetic streams); `boot_table()` is set once and never overwritten,
so consumers of OEM structures (ath11k type 0xF8) read the firmware's
table regardless of what ran later.

## 5. Test surface

| smoke                                | asserts                          |
|--------------------------------------|----------------------------------|
| `smoke_smbios_bios_record`           | Type 0 round-trip with strings    |
| `smoke_smbios_system_record`         | Type 1 with UUID                  |
| `smoke_smbios_processor_record`      | Type 4 max/current speeds          |
| `smoke_smbios_memory_device`         | Type 17 size + speed              |
| `smoke_smbios_skips_unknown`         | unknown types walked correctly     |
| `smoke_smbios_ep3_linux_window`      | `_SM3_` 24..=32, checksum, be24 version |
| `smoke_smbios_ep_linux_window`       | `_SM_` 30..=32, fixups, bare `_DMI_` |
| `smoke_smbios_efi_config_table`      | GUID rows, last duplicate wins, signature |
| `smoke_smbios_scan_machine_efi_precedence` | SMBIOS3 first, fallback to 32-bit |
| `smoke_smbios_scan_machine_no_legacy_under_efi` | no F-segment scan under EFI; loader tag; unreadable table |
| `smoke_smbios_legacy_scan_order`     | SM3 pass first, q-16 window, last paragraph |
| `smoke_smbios_raw_type_f8_retained`  | type 0xF8 formatted area + strings |
| `smoke_smbios_walk_bounds`           | EOT trust, `dmi_num`, short entry, unterminated set |
| `smoke_smbios_parsed_at_boot`        | boot table present with type 1 (Skip if none) |
| `boot/firmware` `smoke_mb2_firmware_handoff{,_absent}` | multiboot2 tags 12/13 copied |

## 6. Out of scope (v0.1)

- Type 17 EXT_BIO encoding (28-bit speed, 32-bit voltages).
- String index dereference beyond 64-byte truncation.
- Type-3 enclosure / Type-9 slot / Type-19 memory-array
  records — extend the parser as drivers come online.
- aarch64 discovery: the NARF UEFI loader hands over a DTB only (no
  EFI system table), so `dmi-scan` reports not-present there.
- `/sys/firmware/dmi` exposure of the retained table.

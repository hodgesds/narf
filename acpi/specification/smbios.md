# smbios — SMBIOS / DMI structure decoder

> Status: **v0.1**.

Adds a clean-room decoder for the SMBIOS entry-point + structure
table that UEFI firmware exposes alongside the ACPI tables.

## Sources (public only)

All code in this module is derived strictly from the references below.
**No GPL Linux source consulted.**

- **DMTF DSP0134 — SMBIOS Reference Specification, Version 3.6.0**
  (March 2022). Public document.
  §5.1 32-bit Entry Point ("_SM_" anchor, 31-byte block with a
  per-byte checksum that brings the block sum to 0 mod 256).
  §5.2 64-bit Entry Point ("_SM3_" anchor, 24-byte block with a
  64-bit physical address of the structure table).
  §6.1 Structure Header (type / length / handle).
  §7.1 Type 0  BIOS Information.
  §7.2 Type 1  System Information (manufacturer / product / version
       / serial / 16-byte UUID / SKU / family).
  §7.3 Type 2  Baseboard Information.
  §7.5 Type 4  Processor Information.
  §7.18 Type 17 Memory Device — surfaces capacity (with the §7.18.5
        magnitude+unit / `0x7FFF` extended-size convention) plus
        configured speed (MT/s), data width, total width, and the
        Memory Type byte (0x1A DDR4, 0x22 DDR5, 0x23 LPDDR5, …).

## Surface

- `EntryPoint32::parse` / `EntryPoint64::parse` — anchor + checksum
  validation, version + structure-table address extraction.
- `StructHeader` + `StructIter` — walks a flat structure-table
  buffer, returning `(header, formatted_section, strings)` for each
  structure until type 127 (end-of-table). The string set is decoded
  according to the SMBIOS NUL-terminated convention with a trailing
  empty string ending the run.
- `MemoryDevice::parse` for Type 17.
- `SystemInfoIndices::parse` for Type 1 plus `string_at` to
  resolve 1-based indices into the structure's string set.
- Constants: `TYPE_*` for the structure-type enum, `MEM_TYPE_*` for
  Memory Device's Memory Type field.

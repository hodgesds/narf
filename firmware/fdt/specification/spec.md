# Flattened Device Tree (FDT) parser

> Status: **v0.1**.

Parses the Devicetree-Specification-v0.4 / FDT-v17 blob. The
parser is byte-stream-only — callers hand it a slice covering
the DTB; it doesn't try to map physical memory itself. Bytes
are stored big-endian by the spec; every read goes through a
`be_*` helper.

## 1. Header (40 bytes, big-endian)

| offset | field             | meaning                              |
|--------|-------------------|--------------------------------------|
| 0      | magic             | `0xD00D_FEED`                        |
| 4      | totalsize         | total blob length                    |
| 8      | off_dt_struct     | offset of struct block               |
| 12     | off_dt_strings    | offset of strings block              |
| 16     | off_mem_rsvmap    | offset of memory-reserve map         |
| 20     | version           | FDT version (≥ 17 expected)          |
| 24     | last_comp_version | minimum compatible version           |
| 28     | boot_cpuid_phys   | physical CPU ID of the boot CPU      |
| 32     | size_dt_strings   | strings block length                 |
| 36     | size_dt_struct    | struct block length                  |

## 2. Struct block tokens (32-bit big-endian)

| token         | value       | meaning                              |
|---------------|-------------|--------------------------------------|
| `FDT_BEGIN_NODE` | `0x0000_0001` | followed by NUL-terminated unit-name, then padded to 4 |
| `FDT_END_NODE`   | `0x0000_0002` | closes the most-recently-opened node  |
| `FDT_PROP`       | `0x0000_0003` | followed by `len:u32_be`, `nameoff:u32_be`, payload (padded) |
| `FDT_NOP`        | `0x0000_0004` | skip                                  |
| `FDT_END`        | `0x0000_0009` | end of struct block                   |

Property names live in the strings block; `nameoff` is an
offset into that block.

## 3. Memory-reserve map

After the header at `off_mem_rsvmap`, a sequence of
`(addr: u64_be, size: u64_be)` pairs terminated by an
all-zeros pair.

## 4. Public API

```rust
pub struct Header {
    pub magic:             u32,
    pub totalsize:         u32,
    pub off_dt_struct:     u32,
    pub off_dt_strings:    u32,
    pub off_mem_rsvmap:    u32,
    pub version:           u32,
    pub last_comp_version: u32,
    pub boot_cpuid_phys:   u32,
    pub size_dt_strings:   u32,
    pub size_dt_struct:    u32,
}

pub fn parse_header(blob: &[u8]) -> Option<Header>;

pub struct Reservation {
    pub addr: u64,
    pub size: u64,
}

pub fn copy_reservations(blob: &[u8], out: &mut [Reservation]) -> usize;

/// Walk every node in the struct block, calling `f` once per
/// node with its full path (e.g. `/cpus/cpu@0`) and a
/// `PropIter` over its properties.
pub fn walk_nodes<F: FnMut(&Path<'_>, PropIter<'_>)>(blob: &[u8], f: F);

pub struct Path<'a> { /* opaque, stack-allocated */ }
impl Path<'_> {
    pub fn matches(&self, path: &[&str]) -> bool;
    pub fn last_segment(&self) -> &str;
    pub fn depth(&self) -> u8;
}

pub struct PropIter<'a> { /* opaque */ }
impl<'a> Iterator for PropIter<'a> {
    type Item = (&'a str, &'a [u8]);
}

/// Convenience helpers atop `walk_nodes`:

/// Look up `/chosen` and return `bootargs` as a `&str` if present.
pub fn chosen_bootargs(blob: &[u8]) -> Option<&str>;

/// Return the `(base, size)` of every `/memory@*` `reg` cell.
pub fn copy_memory_ranges(blob: &[u8], out: &mut [Reservation]) -> usize;

/// Return the path of the node that `chosen.stdout-path` points
/// at, copied into the caller's buffer (NUL-terminated).
pub fn chosen_stdout_path(blob: &[u8], out: &mut [u8]) -> usize;
```

## 5. Test surface

| smoke                              | asserts                           |
|------------------------------------|-----------------------------------|
| `smoke_fdt_header_round_trip`      | hand-built header decodes         |
| `smoke_fdt_walk_minimal`           | one node + one prop callback fires |
| `smoke_fdt_chosen_bootargs`        | `/chosen.bootargs` extracted as &str |
| `smoke_fdt_memory_ranges`          | `/memory@N reg` decoded            |
| `smoke_fdt_reservations`           | reserve-map decoded                |

## 6. Out of scope (v0.1)

- `phandle` resolution (we surface raw `phandle` bytes; the
  consumer does the lookup).
- `interrupts-extended` walker.
- Overlay / fixup application.
- Property-encoded-array helpers beyond `(u32_be, …)` decode.

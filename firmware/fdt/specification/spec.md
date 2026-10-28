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

pub struct ReservedRegion {
    pub addr: u64,
    pub size: u64,
    pub no_map: bool,
    pub reusable: bool,
}

/// Decode static `reg` entries below `/reserved-memory`.
pub fn copy_reserved_memory_ranges(
    blob: &[u8],
    out: &mut [ReservedRegion],
) -> usize;

/// Walk every node in the struct block, calling `f` once per
/// node with its full path (e.g. `/cpus/cpu@0`) and a
/// `PropIter` over its properties.
pub fn walk_nodes<F: FnMut(&Path<'_>, PropIter<'_>)>(blob: &[u8], f: F);

pub struct Path<'a> { /* opaque, stack-allocated */ }
impl Path<'_> {
    pub fn matches(&self, path: &[&str]) -> bool;
    pub fn last_segment(&self) -> &str;
    pub fn depth(&self) -> u8;
    pub fn segment(&self, index: usize) -> Option<&str>;
}

pub struct PropIter<'a> { /* opaque */ }
impl<'a> Iterator for PropIter<'a> {
    type Item = (&'a str, &'a [u8]);
}

/// Read a `u32` property of the root node (`/`). The walkers
/// never report the root, but the root carries tree-wide
/// declarations — `interrupt-parent` above all, the default
/// interrupt parent every node inherits (DTSpec §2.4). `None`
/// on a malformed blob, a non-root first node, or an absent /
/// short property.
pub fn root_prop_u32(blob: &[u8], name: &str) -> Option<u32>;

/// Convenience helpers atop `walk_nodes`:

/// Capacity of the owned buffer `chosen_bootargs` returns. Matches
/// the boot store's `CMDLINE_CAP` and Linux's `COMMAND_LINE_SIZE`.
pub const BOOTARGS_CAP: usize = 2048;

/// Look up `/chosen` and copy `bootargs` into an owned buffer if
/// present. A value longer than `BOOTARGS_CAP` is truncated to
/// exactly `BOOTARGS_CAP` bytes, so a full-width result signals the
/// clip to the caller (the boot store's keep-limit is one byte
/// below the cap, so a clipped value trips its truncation warning
/// instead of fitting silently).
pub fn chosen_bootargs(blob: &[u8]) -> Option<Bytes<BOOTARGS_CAP>>;

/// Decode Linux's 32-bit or 64-bit initrd start/end properties.
pub fn chosen_initrd_range(blob: &[u8]) -> Option<Reservation>;

/// Return the `(base, size)` of every `/memory@*` `reg` cell.
pub fn copy_memory_ranges(blob: &[u8], out: &mut [Reservation]) -> usize;

/// Return the path of the node that `chosen.stdout-path` points
/// at, copied into the caller's buffer (NUL-terminated).
pub fn chosen_stdout_path(blob: &[u8], out: &mut [u8]) -> usize;

/// Resolve `chosen.stdout-path` to the `(base, size)` of the node
/// it names. Handles a full path, an `/aliases` label, and either
/// form carrying `:params` output parameters (stripped, not
/// interpreted). `None` when the property is absent, the target
/// node is missing, or it has no decodable first `reg` entry.
pub fn chosen_stdout_reg(blob: &[u8]) -> Option<(u64, u64)>;

/// Decode `interrupts-extended`, or legacy `interrupts` when no
/// extended property exists. Extended entries may target different
/// interrupt-controller phandles and therefore different cell widths.
pub fn for_each_interrupt<F>(
    blob: &[u8],
    props: PropIter<'_>,
    inherited_parent: Option<u32>,
    f: F,
) where F: FnMut(u32, &[u32]);
```

## 5. Test surface

| smoke                              | asserts                           |
|------------------------------------|-----------------------------------|
| `smoke_fdt_header_round_trip`      | hand-built header decodes         |
| `smoke_fdt_walk_minimal`           | one node + one prop callback fires |
| `smoke_fdt_chosen_bootargs`        | `/chosen.bootargs` extracted as &str |
| `smoke_fdt_chosen_bootargs_long_append_survives` | ~480-byte tooling append (include list + trailing exclude token) survives whole (#960) |
| `smoke_fdt_chosen_bootargs_oversized_clips_at_cap` | bootargs past `BOOTARGS_CAP` clipped to exactly the cap |
| `smoke_fdt_memory_ranges`          | `/memory@N reg` decoded            |
| `smoke_fdt_reservations`           | reserve-map decoded                |
| `smoke_fdt_reserved_memory_static_ranges` | `/reserved-memory` static range + flags |
| `smoke_fdt_interrupts_extended_multiple_domains` | mixed interrupt domains decoded |
| `smoke_fdt_chosen_stdout_reg_forms` | `stdout-path` resolves via alias+`:params` and full-path forms; absent `/chosen` yields `None` |
| `smoke_fdt_real_qemu_virt_*` (10 smokes) | parser pinned against a real QEMU `virt` DTB fixture (`tests/fixtures/qemu-virt.dtb`, #1048); the root-props smoke pins `root_prop_u32` against the blob's `interrupt-parent` + root cells |

## 6. Out of scope (v0.1)

- `phandle` resolution (we surface raw `phandle` bytes; the
  consumer does the lookup).
- Overlay / fixup application.
- Property-encoded-array helpers beyond `(u32_be, …)` decode.
- Dynamic `/reserved-memory` allocation (`size` without `reg`);
  allocation policy belongs to the boot allocator.

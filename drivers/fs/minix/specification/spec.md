# Specification: MINIX Filesystem Driver

## 1. Purpose & scope

Clean-room read-only MINIX filesystem driver for NARF. Supports V1
(`0x137F`), V2 (`0x2468`), and V3 (`0x4D5A`) superblocks.

- **Scope:** Mount, root inode, directory enumeration, file read,
  cap-bound DMA via `narf_io`.
- **Out of scope (deferred):** Writes, symlinks, the bitmap-based
  block / inode allocator. Marked TODO in code.

## 2. On-disk layout

A MINIX volume has the following region order, by block index from
the start of the device (block size = `1 << s_log_zone_size` *
`s_block_size_unit`; `s_block_size_unit` is 1024 bytes for V1/V2,
explicit in V3):

| block | region                       |
|-------|------------------------------|
| 0     | boot block                   |
| 1     | superblock                   |
| 2..   | inode bitmap (s_imap_blocks) |
|       | zone bitmap  (s_zmap_blocks) |
|       | inode table                  |
|       | data zones                   |

The superblock starts at byte offset **1024** (so on a 512-byte
device it is sector 2; on a 1024-byte/4096-byte device, block 1).
Root inode is **inode #1** (NOT 2 — that's ext2; MINIX uses 1).

## 3. Superblock fields

V1 layout (32 bytes, bytes 0..32 of the on-disk superblock):

```
0   u16 s_ninodes
2   u16 s_nzones        (V1 only — V2/V3 use s_zones at offset 20)
4   u16 s_imap_blocks
6   u16 s_zmap_blocks
8   u16 s_firstdatazone
10  u16 s_log_zone_size
12  u32 s_max_size
16  u16 s_magic
18  u16 s_state         (V2/V3)
20  u32 s_zones         (V2/V3 only)
```

V3 adds:
```
24  u16 s_block_size
26  u8  s_disk_version
```

Magic numbers:
- 0x137F  V1, 14-byte names
- 0x138F  V1, 30-byte names
- 0x2468  V2, 14-byte names
- 0x2478  V2, 30-byte names
- 0x4D5A  V3 (`MINIX_SUPER_MAGIC3` per minix3.org)

## 4. Inode layout

V1 (`d1_inode`, 32 bytes):
```
0   u16 i_mode
2   u16 i_uid
4   u32 i_size
8   u32 i_time
12  u8  i_gid
13  u8  i_nlinks
14  u16 i_zone[9]        (7 direct + 1 indirect + 1 dbl-indirect)
```

V2/V3 (`d2_inode`, 64 bytes):
```
0   u16 i_mode
2   u16 i_nlinks
4   u16 i_uid
6   u16 i_gid
8   u32 i_size
12  u32 i_atime
16  u32 i_mtime
20  u32 i_ctime
24  u32 i_zone[10]       (7 direct + 1 ind + 1 dbl-ind + 1 tri-ind)
```

`i_mode` low 9 bits = perms; high bits = type (POSIX `S_IF*`):
- 0o040000 directory
- 0o100000 regular file
- 0o120000 symlink

## 5. Directory entries

Fixed-size, packed:
```
0   u16     d_ino
2   char    d_name[name_max]
```
Where `name_max` is 14 for the legacy magic flavours and 30 for
the long-name flavours. A zero `d_ino` marks an unused entry.
Names are NUL-terminated (or end at `name_max`).

## 6. Zone indexing

Logical block within a file → zone number lookup uses a tiered
indexing scheme identical to early Unix:

- The first 7 entries of `i_zone[]` are direct zone numbers.
- Slot 7 is a single-indirect: a zone full of zone numbers.
- Slot 8 is a double-indirect: a zone of zones-of-zone-numbers.
- (V2/V3 only) Slot 9 is a triple-indirect.

Per-zone fan-out = `block_size / sizeof(zone_ptr)`. Zone pointers
are u16 in V1, u32 in V2/V3.

## 7. Public interface

The driver implements `narf_filesystem::FsInstance` for
`MinixVolume<B: BlockDevice>`. Root returns a `MinixNode` wrapping
inode 1. `DirOps` / `FileOps` mirror the FAT driver.

## 8. Concurrency / DMA

A single per-volume `Cap<DmaBuffer, Write>` is minted at
`mount()` and reused for every block read. Drop unregisters.
`Cap::bootstrap` is never called from a per-call hot path.

## 9. Dependencies

- `narf-block`, `narf-filesystem`, `narf-io`, `narf-capabilities`,
  `narf-driver-runtime`.

## 10. References

See README.md.

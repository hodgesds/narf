# narf-drivers-fs-minix

Clean room MINIX filesystem driver for NARF.

## Status: Read-only first cut

- [x] Volume mount (V1, V2, V3 superblock magic detection)
- [x] Inode lookup by number
- [x] Directory walk (fixed-size entries)
- [x] File data read via direct + single-indirect + double-indirect zone pointers
- [x] V2/V3 triple-indirect zone pointers
- [x] `lookup_async` / `lookup_dir_async` / `enumerate_async`
- [x] `read` for files
- [ ] Write paths (TODO — needs the bitmap allocator)
- [ ] Symlinks (TODO — only the layout markers parse)
- [ ] Bitmap-based block / inode allocator (TODO — write-only)

## Version targeted

This crate targets **all three** on-disk versions (V1 `0x137F`, V2
`0x2468`, V3 `0x4D5A`) but the structural pivot is:

- **V1**: 16-bit zone pointers, 14-byte name field by default,
  32-byte inode (`d1_inode`), zone size = block size.
- **V2**: 32-bit zone pointers, 30-byte name (or 14, controlled by
  superblock layout), 64-byte inode (`d2_inode`), triple-indirect
  zones, zone size = block size.
- **V3**: like V2 but the on-disk superblock carries an explicit
  `s_block_size` field so 4 KiB volumes are well-defined; the magic
  byte changes to `0x4D5A`.

We picked "all three" because the layout differences collapse onto
two parsing paths (V1 vs. V2/V3), and it costs almost nothing to
serve the modern V3 format alongside V1 — small, well-documented,
educational. Tests cover all three magics.

## References

- Tanenbaum, A. S. *Operating Systems: Design and Implementation*
  (Prentice Hall, 1987 / 2006). The MINIX filesystem chapters are
  the canonical reference: the V1 layout (boot block / superblock /
  inode bitmap / zone bitmap / inode table / data zones) is
  described in Ch. 5 of the 1st edition, Ch. 4 of the 3rd; the
  `i_zone[]` direct/single-indirect/double-indirect indexing scheme
  (with V2/V3 adding a 7th triple-indirect slot) is on the same
  page as the inode struct definition.
- Tanenbaum, A. S. & Bos, H. *Modern Operating Systems* (Pearson,
  2014). Chapter 4's MINIX-3 case study covers the V3 superblock
  changes (explicit `s_block_size`, larger inode, updated magic).
- *MINIX 3 Reference Manual* and the on-disk-format documentation
  on minix3.org. The superblock at byte offset 1024, the magic
  values, and `s_max_size` semantics come from there.
- OSDev wiki "MINIX File System" — algorithmic descriptions only,
  no code copied.

No GPL/BSD-licensed minixfs implementation (Linux `fs/minix/*`,
the official MINIX 3 source tree, mkfs.minix from util-linux,
Embedded MINIX, etc.) was consulted.

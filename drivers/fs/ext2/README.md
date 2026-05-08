# narf-drivers-fs-ext2

Clean room ext2 filesystem driver for NARF.

## Features (read-side)

- **Mount** via superblock at byte offset 1024 (LBA 2 with 512-byte sectors).
- **Variable block sizes** decoded from `s_log_block_size` (1024, 2048, 4096, ...).
- **Block group descriptor table** read out of the block immediately
  following the superblock.
- **Inode lookup by number** with the (inode_no - 1) / inodes_per_group
  partitioning, then `s_inode_size`-strided table walk inside each group.
- **Variable-length directory entries** (`inode | rec_len | name_len |
  file_type | name`).
- **Block pointers**: 12 direct, single-indirect, double-indirect,
  triple-indirect — the full classic ext2 mapping.
- **VFS integration** — `Ext2Volume` implements `narf_filesystem::FsInstance`;
  `Ext2Node` implements `FileOps + DirOps`. `lookup_async`,
  `lookup_dir_async`, `enumerate_async`, and `read` are wired.
- **Cap-bound DMA** — one `Cap<DmaBuffer, Write>` minted at mount,
  reused for every block read; drop unregisters.

## Status: Stage 4 (read-only)

- [x] Volume mount + superblock + BGDT
- [x] Inode lookup and walk
- [x] Directory enumeration / lookup
- [x] File read (direct + 1/2/3-level indirect)
- [ ] Write paths (create/unlink/mkdir/rmdir/rename) — TODO
- [ ] Extended attributes — TODO
- [ ] Symlinks (small inline + block-pointed) — TODO
- [ ] Hash-tree directory indexes (HTREE, ext3+) — TODO

## References

- Card, Ts'o, Tweedie. _Design and Implementation of the Second Extended
  Filesystem_. <https://web.mit.edu/tytso/www/linux/ext2intro.html>
- Rusling, _The Second Extended File System: Internal Layout_,
  kernelnewbies.org wiki.
- OSDev Wiki, "Ext2": <https://wiki.osdev.org/Ext2>
- IBM developerWorks, "Anatomy of the Linux file system" (general
  principles).

No GPL/LGPL ext2 source code (Linux `fs/ext2/*`, GRUB, e2fsprogs,
FreeBSD ext2) was consulted while writing this crate.

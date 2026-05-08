# Research: ext2 Filesystem

Clean-room implementation references for the Second Extended Filesystem
(ext2). No GPL/LGPL source code (Linux `fs/ext2/*`, GRUB, e2fsprogs,
FreeBSD ext2) was consulted.

## Primary Sources

1. **Design and Implementation of the Second Extended Filesystem**
   - Authors: Rémy Card, Theodore Ts'o, Stephen Tweedie
   - URL: <https://web.mit.edu/tytso/www/linux/ext2intro.html>
   - Role: Original algorithmic narrative — block groups, the
     direct/indirect/double/triple-indirect block-pointer scheme, the
     bitmap-based allocator, and the inode lifecycle.

2. **The Second Extended File System: Internal Layout**
   - Author: David A. Rusling (kernelnewbies.org wiki)
   - Role: Independent description of the on-disk layout — superblock
     fields, group descriptor table, inode table, directory entry
     format.

3. **OSDev Wiki, "Ext2"**
   - URL: <https://wiki.osdev.org/Ext2>
   - Role: Community-vetted summary of the layout — used as a
     cross-check against (1) and (2). Especially helpful for the
     `s_log_block_size` decoding and the `file_type` byte values in
     directory entries.

## Secondary Sources

- **IBM developerWorks: Anatomy of the Linux file system**
  - Role: General-principles framing of the inode + indirect-block
    model.

- **Stephen Tweedie, _Journaling the Linux ext2fs Filesystem_** (1998
  LinuxExpo paper).
  - Role: Background reading on the data-vs-metadata journal model.
    Not used for ext2 layout details — this driver is non-journalling.

## Summaries

- [summaries/ext2-layout.md](summaries/ext2-layout.md) — superblock,
  block groups, inode table, directory entry format.
- [summaries/ext2-block-pointers.md](summaries/ext2-block-pointers.md)
  — direct / single-/double-/triple-indirect block walk.

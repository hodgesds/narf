# Research: MINIX Filesystem

Clean-room implementation references for the MINIX filesystem
(versions 1, 2, 3).

## Primary Sources

1. **Tanenbaum, A. S. — *Operating Systems: Design and
   Implementation*, 1st edition (Prentice Hall, 1987).**
   - Chapter 5 ("Files") is the canonical description of the MINIX
     filesystem layout — boot block / superblock / inode bitmap /
     zone bitmap / inode table / data zones — and the
     direct/indirect/double-indirect zone-pointer indexing scheme.
   - The on-disk inode struct (`d_inode` for V1) is defined in the
     book alongside its `i_zone[9]` member.

2. **Tanenbaum, A. S. & Bos, H. — *Modern Operating Systems*, 4th
   edition (Pearson, 2014).**
   - Chapter 4's MINIX-3 case study covers the V3 superblock
     extensions: explicit `s_block_size`, the 64-byte `d2_inode`,
     and the `0x4D5A` magic.

3. **MINIX 3 Reference Manual & on-disk-format documentation,
   minix3.org.**
   - The byte-offset 1024 superblock placement, magic-byte table
     (V1 14/30, V2 14/30, V3), and `s_max_size` semantics come
     from there.

## Secondary Sources

- **OSDev wiki, "MINIX File System"** — algorithmic descriptions
  only; no code copied.

## What we did NOT consult

- Linux `fs/minix/*` (GPL-2.0-only).
- The MINIX 3 source tree (BSD).
- `mkfs.minix` from util-linux (LGPL).
- Any other GPL/BSD/LGPL minixfs-like implementation.

## Summaries

- [summaries/tanenbaum-minix-fs.md](summaries/tanenbaum-minix-fs.md)
  - Distilled layout / inode / zone-indexing notes.

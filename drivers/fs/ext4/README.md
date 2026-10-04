# drivers/fs/ext4 — ext4 On-Disk Filesystem Driver

A driver for ext4, the flagship layout of the Linux ext filesystem family and
the default root filesystem of most Linux distributions. It plugs into NARF's
`filesystem/` VFS as a persistent, block-backed filesystem, realizing the VFS
node/`FileOps`/`DirOps` contract over a block device from `block/` and
`drivers/storage` and attaching through `drivers/runtime`.

ext4 is distinguished from its ext2/ext3 ancestors by four things: extent
trees in place of the old indirect-block map, a JBD2 journal for crash
consistency, 64-bit block addressing with FLEX_BG group-descriptor packing,
and HTREE directory indexing promoted from optional to mandatory. Rather than
duplicate the shared on-disk decoders, this crate is deliberately a thin,
ext4-specific layer on top of the sibling `drivers/fs/ext2` crate, which was
written from the start to grow ext2 → ext3 → ext4 along the feature-flag axis
and therefore already carries the on-disk types for extents, HTREE, and JBD2.
This crate re-exports those types under ext4-flavored names and adds the
contract and algorithms that make a volume genuinely ext4.

The modules follow that division of labor. `superblock` layers ext4-specific,
64BIT-aware validation and group-descriptor sizing over the shared superblock
decoder. `inode` enforces the ext4 rule that inodes carry extents and
validates the extent header on every inode load. `extent` implements the
ext4-only extent-tree algorithms — walking the tree, and inserting, splitting,
and merging extents. `htree` drives the hashed B-tree directory index (shared
in spirit with ext3's HTREE). `dir` presents directories to the VFS, and
`journal` implements the JBD2 lifecycle, including the commit-record builder.

Because NARF is GPL-2.0-or-later, this driver cites the Linux `fs/ext4/*` and
`fs/jbd2/*` sources directly where the on-disk layout or algorithm derives
from them, with per-file headers naming the specific kernel function
consulted. The crate is `#![no_std]`, hardware-independent above the block
device, and runs identically on x86_64 and aarch64.

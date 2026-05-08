//! ext2 Filesystem Driver for NARF.
//!
//! Clean-room implementation. No GPL Linux `fs/ext2/*` or `fs/ext4/*`,
//! GRUB, e2fsprogs, FreeBSD ext2, or any other GPL/LGPL ext2 source
//! was consulted while writing this crate; every layout, magic
//! number, and algorithm trace back to one of the public references
//! below. Per-file headers cite the specific section consulted.
//!
//! References (entire crate):
//! - Card, Ts'o, Tweedie. _Design and Implementation of the Second
//!   Extended Filesystem_, the original design paper.
//!   <https://web.mit.edu/tytso/www/linux/ext2intro.html>
//! - Rusling, _The Second Extended File System: Internal Layout_,
//!   kernelnewbies.org wiki.
//! - OSDev Wiki, "Ext2": <https://wiki.osdev.org/Ext2>
//! - IBM developerWorks, "Anatomy of the Linux file system" — general
//!   principles only.
//! - Specs/research notes vendored in `specification/` and `research/`.

#![no_std]

extern crate alloc;

pub mod superblock;
pub mod group_desc;
pub mod inode;
pub mod dir;
pub mod volume;
pub mod node;

mod tests;

/// ext2 magic. Stored at offset 56 of the superblock, little-endian.
/// Source: OSDev Wiki "Ext2 — Superblock", Rusling §"Superblock".
pub const EXT2_SUPER_MAGIC: u16 = 0xEF53;

/// The reserved root inode number (per the design paper §"Inodes" /
/// OSDev Wiki "Ext2 — Reserved Inodes"). Inode 1 is the bad-blocks
/// inode; inode 2 is the volume's root directory.
pub const EXT2_ROOT_INO: u32 = 2;

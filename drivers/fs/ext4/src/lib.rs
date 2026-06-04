//! ext4 Filesystem Driver for NARF.
//!
//! ext4 is the ext family's flagship layout: extent trees in place
//! of ext2/3's indirect-block table, a JBD2 journal, 64-bit block
//! addresses, FLEX_BG group descriptors, and HTREE directory
//! indexing as a hard requirement (it was optional on ext3). This
//! crate is a thin, ext4-specific contract layer on top of the
//! shared on-disk decoders that live in `drivers/fs/ext2/` — that
//! sibling crate was written from the start to grow ext2 → ext3 →
//! ext4 along the feature-flag axis, so the on-disk types for
//! extents, htree, and JBD2 already exist there. We re-export them
//! under ext4-flavour names, layer **ext4-specific validation** on
//! top (must have EXTENTS, must validate every extent header,
//! 64BIT-aware group descriptor sizing), and add ext4-only
//! algorithms: extent insertion + split + merge, and the journal
//! commit-record builder.
//!
//! NARF is GPL-2.0-or-later as of 2026-05-20, so Linux `fs/ext4/*`
//! sources are cited directly where the on-disk layout or algorithm
//! comes from them. Per-file headers identify the specific kernel
//! function consulted.
//!
//! References:
//! - Linux `fs/ext4/extents.c` — `ext4_ext_find_extent`,
//!   `ext4_ext_insert_extent`, `ext4_ext_split` (extent tree
//!   walker + writer).
//! - Linux `fs/ext4/inode.c` — `ext4_map_blocks` (extent-based
//!   file I/O surface).
//! - Linux `fs/ext4/namei.c` — `dx_probe` (HTREE walker, same as
//!   ext3 HTREE — shared with sibling).
//! - Linux `fs/jbd2/journal.c`, `fs/jbd2/transaction.c`,
//!   `fs/jbd2/commit.c` — journal lifecycle.
//! - Linux `include/linux/ext4_fs.h` — feature-flag constants,
//!   `EXT4_EXTENTS_FL`.

#![no_std]

extern crate alloc;

pub mod dir;
pub mod extent;
pub mod htree;
pub mod inode;
pub mod journal;
pub mod superblock;

mod tests;

/// ext4 magic — same value as ext2/3 (the entire family shares the
/// `s_magic` field). The flavour is determined by feature flags.
/// Linux `include/uapi/linux/ext4_fs.h::EXT4_SUPER_MAGIC`.
pub const EXT4_SUPER_MAGIC: u16 = 0xEF53;

/// The reserved root inode number. Inode 1 is bad-blocks, inode 2 is
/// the root directory, inode 8 is the journal file by convention.
/// Linux `include/uapi/linux/ext4_fs.h::EXT4_ROOT_INO`.
pub const EXT4_ROOT_INO: u32 = 2;

/// Conventional inode for the JBD2 journal file. The actual value
/// lives in `s_journal_inum` and a fresh mkfs may choose anything;
/// 8 is the e2fsprogs default. Linux
/// `include/uapi/linux/ext4_fs.h::EXT4_JOURNAL_INO`.
pub const EXT4_JOURNAL_INO: u32 = 8;

/// Stage::Late initcall registration.
///
/// The ext-family auto-mount factory is already installed by the
/// sibling `narf-drivers-fs-ext2` crate for `FsType::Ext` because
/// the on-disk family is indistinguishable at the boot-block
/// detect-filesystem layer (both share magic 0xEF53). When the
/// sibling's `Ext2Volume::mount` runs, it dispatches on the
/// `flavour()` of the parsed superblock — so an ext4 image gets the
/// extent-tree + JBD2 paths automatically. This crate's initcall
/// today is a no-op that simply marks the ext4-specific contract
/// (`extents must be set, must be ext4 flavour`) as available for
/// the boot log + any future direct ext4-only mount path. The
/// validator runs against any FsType::Ext volume that the auto-mount
/// path resolved to ext4 flavour.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "ext4-fs-features", || {
        // Pure-logic marker: ext4 contract module loaded. Real
        // mount path lives in ext2's Ext2Volume::mount which
        // dispatches on superblock flavour.
        InitResult::Ok
    });
}

/// Public alias so `register_initcalls()` callers can find the
/// initcall name in the boot log without hunting through source.
pub const EXT4_INITCALL_NAME: &str = "ext4-fs-features";

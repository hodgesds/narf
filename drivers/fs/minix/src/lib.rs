//! MINIX Filesystem Driver for NARF.
//!
//! Clean-room implementation. No GPL Linux `fs/minix/*`, BSD MINIX 3
//! `servers/mfs`, LGPL `mkfs.minix` from util-linux, or other licensed
//! minixfs source was consulted while writing this crate; every layout,
//! magic number, and indexing rule traces back to one of the public
//! references below. Per-file headers cite the specific Tanenbaum
//! chapter / page or MINIX manual section.
//!
//! References (entire crate):
//! - Tanenbaum, A. S. *Operating Systems: Design and Implementation*
//!   (Prentice Hall, 1987, 1st ed., Ch. 5 "Files"; 3rd ed. 2006, Ch. 4).
//! - Tanenbaum, A. S. & Bos, H. *Modern Operating Systems* (Pearson,
//!   2014, 4th ed., §4.6 "Case Study: MINIX 3 Filesystem").
//! - MINIX 3 Reference Manual + on-disk format documentation,
//!   <https://www.minix3.org/>.
//! - OSDev wiki, "MINIX File System" — algorithmic descriptions only.
//! - Specs/research notes vendored in `specification/` and `research/`.
//!
//! Read-only first cut. Writes / symlinks / the bitmap allocator are
//! deferred — see TODO comments in `volume.rs` and `node.rs`.

#![no_std]

extern crate alloc;

pub mod superblock;
pub mod inode;
pub mod dir;
pub mod volume;
pub mod node;

mod tests;

/// MINIX on-disk version. Determined by the superblock magic and
/// directly drives the on-disk-record codec selection (V1 = 32-byte
/// inodes + u16 zone pointers; V2/V3 = 64-byte inodes + u32 zone
/// pointers; V3 also adds an explicit `s_block_size` field).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MinixVersion {
    /// `0x137F` (14-byte names) or `0x138F` (30-byte names).
    V1,
    /// `0x2468` (14-byte names) or `0x2478` (30-byte names).
    V2,
    /// `0x4D5A` — V3 with 60-byte names + explicit `s_block_size`.
    V3,
}

/// Directory-entry name field length, derived from the superblock
/// magic at mount time. Tanenbaum §4 / MINIX-3 reference manual.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NameLen {
    /// `0x137F` / `0x2468` — 14-byte names.
    N14,
    /// `0x138F` / `0x2478` — 30-byte names.
    N30,
    /// V3 — 60-byte names.
    N60,
}

impl NameLen {
    pub const fn bytes(self) -> usize {
        match self {
            NameLen::N14 => 14,
            NameLen::N30 => 30,
            NameLen::N60 => 60,
        }
    }

    /// Total directory-entry size in bytes (= u16 inode + name).
    pub const fn entry_size(self) -> usize {
        2 + self.bytes()
    }
}

//! MINIX Filesystem Driver for NARF.
//!
//! Clean-room implementation. No GPL Linux `fs/minix/*`, BSD MINIX 3
//! `servers/mfs`, LGPL `mkfs.minix` from util-linux, or other licensed
//! minixfs source was consulted while writing this crate; every layout,
//! magic number, and indexing rule traces back to one of the public
//! references below. Per-file headers cite the specific Tanenbaum
//! chapter / page or MINIX manual section.
//!
//! References (entire crate). Free-availability status is called
//! out per source — some are textbooks (paid), others are gratis:
//!
//! - **Free / gratis:** MINIX 3 Reference Manual + on-disk format
//!   documentation, hosted on <https://www.minix3.org/>. The MINIX
//!   project publishes its docs under permissive terms, no signup.
//!   This is the load-bearing reference for the V3 layout — every
//!   field offset and magic value in this crate can be traced to
//!   it directly.
//! - **Free / gratis:** OSDev Wiki, "MINIX File System" —
//!   algorithmic descriptions only. CC-BY-SA 4.0; gratis to read.
//! - **Free / gratis:** Specs/research notes vendored in
//!   `specification/` and `research/` (this repository, project
//!   license).
//! - **Paid / NOT free:** Tanenbaum, A. S. *Operating Systems:
//!   Design and Implementation* (Prentice Hall, 1987, 1st ed., Ch.
//!   5 "Files"; 3rd ed. 2006, Ch. 4) and *Modern Operating Systems*
//!   (Pearson, 2014, 4th ed., §4.6). These textbooks describe the
//!   on-disk layout in narrative form; they were used for cross-
//!   validation but are NOT required to read or rebuild this crate
//!   — every layout decision can be traced to the MINIX 3 docs +
//!   OSDev wiki references above. Cited because they were
//!   consulted; not relied upon as the sole source for any
//!   field.
//!
//! Write support: bitmap allocator + write paths (create / mkdir /
//! unlink / rmdir / symlink / rename / write / truncate). See
//! `volume.rs` for the allocator implementation and `node.rs` for
//! the per-op routing. Reference: Linux `fs/minix/bitmap.c`.

#![no_std]

extern crate alloc;

pub mod dir;
pub mod inode;
pub mod node;
pub mod superblock;
pub mod volume;

mod tests;

/// The root directory's inode number (`MINIX_ROOT_INO`). Inode 0 is
/// reserved, so MINIX roots at 1 — not ext2's 2.
pub const MINIX_ROOT_INO: u32 = 1;

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

/// Register the named mount constructor without probing a device.
pub fn register_fstypes() {
    narf_filesystem::register_block_fstype("minix", build_named);
}

/// `minix_init_fs_context` installs `minix_context_ops`, which has NO
/// `parse_param`: minix takes no filesystem-specific option at all. The
/// generic layer still consumes the superblock flag names (`ro`, `sync`, …)
/// from the data string, and anything left over is
/// `"minix: Unknown parameter '%s'"` — EINVAL.
///
/// This refused ANY non-empty data string with EOPNOTSUPP, so a line as
/// ordinary as `mount -t minix -o ro /dev/sdb1 /mnt` failed whenever the
/// mounter left `ro` in the data (which `fsconfig(2)` callers and NARF's own
/// `fsconfig` path do).
fn build_named(
    source: &str,
    options: &str,
) -> Result<alloc::sync::Arc<dyn narf_filesystem::FsInstance>, narf_filesystem::FsError> {
    for opt in narf_filesystem::fsopts::iter(options) {
        if !narf_filesystem::fsopts::is_vfs_param(opt.key) {
            return Err(narf_filesystem::FsError::InvalidData);
        }
    }
    let name = source.strip_prefix("/dev/").unwrap_or(source);
    let dev = narf_block::find_block_device(name).ok_or(narf_filesystem::FsError::NotFound)?;
    let fs = narf_scheduler::block_on(volume::MinixVolume::mount(
        narf_block::SyncBlock::new(dev),
        narf_driver_runtime::DomainId::DRIVER_0,
    ))?;
    Ok(fs)
}

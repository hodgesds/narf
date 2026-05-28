//! ext2 Filesystem Driver for NARF.
//!
//! Clean-room implementation. No GPL Linux `fs/ext2/*` or `fs/ext4/*`,
//! GRUB, e2fsprogs, FreeBSD ext2, or any other GPL/LGPL ext2 source
//! was consulted while writing this crate; every layout, magic
//! number, and algorithm trace back to one of the public references
//! below. Per-file headers cite the specific section consulted.
//!
//! References (entire crate). Every source below is **freely
//! available** — no paywall, no signup, no NDA required to read or
//! redistribute:
//!
//! - Card, Ts'o, Tweedie. _Design and Implementation of the Second
//!   Extended Filesystem_, the original 1994 design paper. Hosted
//!   gratis on Theodore Ts'o's MIT page:
//!   <https://web.mit.edu/tytso/www/linux/ext2intro.html>
//! - Rusling, _The Second Extended File System: Internal Layout_,
//!   originally on kernelnewbies.org wiki (CC-BY-SA).
//! - OSDev Wiki, "Ext2" — algorithmic narrative only (no code
//!   reproductions). Wiki content is CC-BY-SA 4.0:
//!   <https://wiki.osdev.org/Ext2>
//! - IBM developerWorks, "Anatomy of the Linux file system" —
//!   general principles only; freely readable.
//! - Specs/research notes vendored in `specification/` and
//!   `research/` (this repository, project license).

#![no_std]

extern crate alloc;

pub mod superblock;
pub mod group_desc;
pub mod inode;
pub mod dir;
pub mod dir_mut;
pub mod extent;
pub mod htree;
pub mod journal;
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

// ── Stage::Late factory registration ──────────────────────────────
//
// Wires the ext2/3/4 driver into narf_filesystem::root_mount so the
// boot path's auto-mount walker can construct an Ext2Volume from
// any `Arc<dyn BlockDeviceSync>` whose superblock detect_filesystem
// classified as `FsType::Ext`.
//
// Path:
//   register_fs_factory(FsType::Ext, ext_factory)
//   ext_factory(dev) wraps `dev` in `SyncBlock` → `BlockDevice`,
//     then block_on's `Ext2Volume::mount(async_dev, domain)`.

pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "ext-fs-factory", || {
        narf_filesystem::root_mount::register_fs_factory(
            narf_block::fs_detect::FsType::Ext,
            ext_factory,
        );
        InitResult::Ok
    });
}

/// Factory for FsType::Ext. Wraps the sync block device in a
/// SyncBlock bridge, then block_on's the async mount path.
///
/// Errors bubble up unchanged so the root-mount walker can log the
/// reason and try the next candidate device.
fn ext_factory(
    dev: alloc::sync::Arc<dyn narf_block::BlockDeviceSync>,
) -> Result<alloc::sync::Arc<dyn narf_filesystem::FsInstance>, narf_filesystem::FsError> {
    use alloc::sync::Arc;
    use narf_block::SyncBlock;
    use narf_driver_runtime::DomainId;

    // SyncBlock::new returns Arc<SyncBlock> — exactly the
    // `Arc<B: BlockDevice>` shape Ext2Volume::mount expects.
    let async_dev = SyncBlock::new(dev);
    let volume = narf_scheduler::block_on(volume::Ext2Volume::mount(
        async_dev,
        DomainId::DRIVER_0,
    ))?;
    Ok(volume as Arc<dyn narf_filesystem::FsInstance>)
}

//! Partial btrfs filesystem driver: read-only mount/ls/cat plus a
//! narrowly-scoped basic copy-on-write write path.
//!
//! The on-disk format is decoded per the authoritative kernel definitions in
//! `/usr/src/linux/include/uapi/linux/btrfs_tree.h` and the read/COW call
//! chains in `/usr/src/linux/fs/btrfs`. This is an independent Rust
//! implementation; no C code is copied.
//!
//! Supported: single-device (SINGLE/DUP) volumes with CRC32C checksums,
//! `nodesize`/`sectorsize` at their common defaults, the default `FS_TREE`
//! subvolume, inline and uncompressed regular extents. Everything else — RAID
//! profiles, compression, subvolumes/snapshots beyond the default, xattrs, and
//! non-CRC32C checksums — is rejected with a precise `Unsupported`/`NotFound`
//! rather than mis-read. See the crate `README` for the supported matrix.

#![no_std]

extern crate alloc;

use alloc::sync::Arc;

use narf_block::{BlockDeviceSync, SyncBlock};
use narf_driver_runtime::DomainId;
use narf_filesystem::{FsError, FsInstance};

pub mod allocator;
pub mod btree;
pub mod checksum;
pub mod chunk;
pub mod dir;
pub mod extent;
pub mod format;
pub mod inode;
pub mod node;
pub mod roots;
pub mod volume;
pub mod write;

mod tests;

/// Register both the root auto-mount factory (used when `fs_detect` finds a
/// btrfs superblock on a device) and the classic `mount -t btrfs` builder.
/// Called before the staged init registry runs.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "btrfs-factory", || {
        narf_filesystem::root_mount::register_fs_factory(
            narf_block::fs_detect::FsType::Btrfs,
            btrfs_factory,
        );
        narf_filesystem::register_fstype("btrfs", btrfs_fstype_builder);
        InitResult::Ok
    });
}

/// Root auto-mount factory: mount the btrfs volume on a synchronously-bridged
/// block device.
fn btrfs_factory(dev: Arc<dyn BlockDeviceSync>) -> Result<Arc<dyn FsInstance>, FsError> {
    let async_dev = SyncBlock::new(dev);
    let volume =
        narf_scheduler::block_on(volume::BtrfsVolume::mount(async_dev, DomainId::DRIVER_0))?;
    Ok(volume)
}

/// `mount -t btrfs <source>` builder. Accepts only read-only-compatible options
/// (this driver never claims write semantics it doesn't have) and resolves the
/// source to a registered block device.
fn btrfs_fstype_builder(source: &str, options: &str) -> Result<Arc<dyn FsInstance>, FsError> {
    for option in options.split(',').filter(|s| !s.is_empty()) {
        if option != "ro" && option != "errors=continue" {
            return Err(FsError::Unsupported);
        }
    }
    let name = source.strip_prefix("/dev/").unwrap_or(source);
    let dev = narf_block::find_block_device(name).ok_or(FsError::NotFound)?;
    btrfs_factory(dev)
}

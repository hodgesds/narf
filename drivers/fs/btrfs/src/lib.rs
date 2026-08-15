//! Clean-room read-write btrfs driver for single-device filesystems.
//!
//! The on-disk format is decoded per the authoritative kernel definitions in
//! `include/uapi/linux/btrfs_tree.h` and the read/COW call chains in
//! `fs/btrfs`. This is an independent Rust
//! implementation; no C code is copied.
//!
//! Supported: SINGLE/DUP chunk profiles, all four btrfs checksum algorithms,
//! zlib/zstd/LZO and uncompressed reads, 4–64 KiB sectors, incremental COW
//! writes, namespace mutations, nested writable subvolume mounts, full qgroup
//! accounting/limits, and subvolume/snapshot ioctls.
//! Unsupported on-disk shapes are rejected precisely rather than mis-read. See
//! the crate `README` for the full matrix and limits.

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
pub mod csum;
pub mod dir;
pub mod extent;
pub mod format;
pub mod inode;
pub mod lzo;
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

/// Parse the `mount -t btrfs` option string into an optional subvolume selector.
/// Accepts read-only-compatible options plus `subvolid=N` / `subvol=PATH`;
/// anything else is `Unsupported`.
pub fn parse_mount_subvol(options: &str) -> Result<Option<volume::Subvol>, FsError> {
    let mut selector = None;
    for option in options.split(',').filter(|s| !s.is_empty()) {
        if option == "ro" || option == "errors=continue" {
            continue;
        } else if let Some(v) = option.strip_prefix("subvolid=") {
            let id: u64 = v.parse().map_err(|_| FsError::InvalidData)?;
            selector = Some(volume::Subvol::Id(id));
        } else if let Some(v) = option.strip_prefix("subvol=") {
            // Leading/trailing slashes are harmless, but empty, dot, and dotdot
            // components make resolution ambiguous and are rejected.
            let path = v.trim_matches('/');
            if path.is_empty()
                || path
                    .split('/')
                    .any(|component| component.is_empty() || component == "." || component == "..")
            {
                return Err(FsError::Unsupported);
            }
            selector = Some(volume::Subvol::Name(alloc::string::String::from(path)));
        } else {
            return Err(FsError::Unsupported);
        }
    }
    Ok(selector)
}

/// `mount -t btrfs <source>` builder. Resolves the source to a registered block
/// device and honours `subvol=`/`subvolid=`.
fn btrfs_fstype_builder(source: &str, options: &str) -> Result<Arc<dyn FsInstance>, FsError> {
    let subvol = parse_mount_subvol(options)?;
    let name = source.strip_prefix("/dev/").unwrap_or(source);
    let dev = narf_block::find_block_device(name).ok_or(FsError::NotFound)?;
    let async_dev = SyncBlock::new(dev);
    let volume = narf_scheduler::block_on(volume::BtrfsVolume::mount_subvol(
        async_dev,
        DomainId::DRIVER_0,
        true,
        subvol,
    ))?;
    Ok(volume)
}

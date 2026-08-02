//! Linux-compatible SquashFS 4.0 read-only filesystem driver.
//!
//! The implementation follows the on-disk validation and read call chains in
//! Linux `/usr/src/linux/fs/squashfs`: `squashfs_fill_super`,
//! `squashfs_read_inode`, `squashfs_readdir`, `squashfs_readpage_block`, and
//! `squashfs_frag_lookup`.  It is an independent Rust implementation; no C
//! code is copied.  See `SQUASHFS_LINUX_COMPAT_AUDIT.md` for the supported
//! matrix and intentionally rejected features.

#![no_std]

extern crate alloc;

pub mod format;
pub mod node;
pub mod volume;

mod tests;

use alloc::sync::Arc;
use narf_block::{BlockDevice, BlockDeviceSync, SyncBlock};
use narf_capabilities::{Cap, Grant, Write};
use narf_driver_runtime::DomainId;
use narf_filesystem::{registry, FsError, FsInstance, MountPoint};

/// Mount a SquashFS volume and attach it at `path`.
pub async fn mount_squashfs<B: BlockDevice + 'static>(
    authority: &Cap<MountPoint, Grant>,
    path: &str,
    device: Arc<B>,
    domain: DomainId,
) -> Result<Cap<MountPoint, Write>, FsError> {
    let volume = volume::SquashfsVolume::mount(device, domain).await?;
    registry().mount_arc(authority, path, volume)
}

/// Register both the root auto-mount factory and classic `mount -t
/// squashfs` builder.  Called before the staged init registry runs.
pub fn register_initcalls() {
    use narf_init::{InitResult, Stage};
    narf_init::register(Stage::Subsys, "squashfs-factory", || {
        narf_filesystem::root_mount::register_fs_factory(
            narf_block::fs_detect::FsType::SquashFs,
            squashfs_factory,
        );
        narf_filesystem::register_fstype("squashfs", squashfs_fstype_builder);
        InitResult::Ok
    });
}

fn squashfs_factory(dev: Arc<dyn BlockDeviceSync>) -> Result<Arc<dyn FsInstance>, FsError> {
    let async_dev = SyncBlock::new(dev);
    let volume =
        narf_scheduler::block_on(volume::SquashfsVolume::mount(async_dev, DomainId::DRIVER_0))?;
    Ok(volume)
}

fn squashfs_fstype_builder(source: &str, options: &str) -> Result<Arc<dyn FsInstance>, FsError> {
    // Linux accepts only decompressor/error-policy mount options.  NARF uses
    // one bounded decoder stream and continues with EIO-style errors; reject
    // options that would claim different semantics.
    if !options.is_empty() {
        for option in options.split(',').filter(|s| !s.is_empty()) {
            if option != "ro" && option != "errors=continue" && option != "threads=single" {
                return Err(FsError::Unsupported);
            }
        }
    }
    let name = source.strip_prefix("/dev/").unwrap_or(source);
    let dev = narf_block::find_block_device(name).ok_or(FsError::NotFound)?;
    squashfs_factory(dev)
}

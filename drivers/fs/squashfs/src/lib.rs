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
        register_fstypes();
        InitResult::Ok
    });
}

fn squashfs_factory(dev: Arc<dyn BlockDeviceSync>) -> Result<Arc<dyn FsInstance>, FsError> {
    let async_dev = SyncBlock::new(dev);
    let volume =
        narf_scheduler::block_on(volume::SquashfsVolume::mount(async_dev, DomainId::DRIVER_0))?;
    Ok(volume)
}

/// `squashfs_parse_param` (`fs/squashfs/super.c`) — squashfs has exactly two
/// parameters, `errors=continue|panic` and `threads=`, and anything else is
/// EINVAL (`"squashfs: Unknown parameter '%s'"`).
///
/// This used to accept only the two literal spellings `errors=continue` and
/// `threads=single` and answer EOPNOTSUPP for everything else — including
/// `errors=panic` and the other `threads=` values Linux takes, so a
/// legitimate mount line failed on a parameter squashfs itself documents.
///
/// LINUX-GAP: both are accepted and neither is acted on. `errors=panic`
/// would have to panic the kernel on a decode error, where NARF reports EIO
/// to the caller; `threads=` selects between Linux's single/multi/percpu
/// decompressors, and NARF has one bounded decoder stream.
fn squashfs_fstype_builder(source: &str, options: &str) -> Result<Arc<dyn FsInstance>, FsError> {
    const ERRORS: &[&str] = &["continue", "panic"];
    const THREADS: &[&str] = &["single", "multi", "percpu"];
    for opt in narf_filesystem::fsopts::iter(options) {
        if narf_filesystem::fsopts::is_vfs_param(opt.key) {
            continue;
        }
        match opt.key {
            "errors" => narf_filesystem::fsopts::enum_value(opt.value, ERRORS)?,
            // `fsparam_string`: a name, or a decompressor count
            // (`squashfs_parse_param_threads_num`, base 0).
            "threads" => match opt.value {
                Some(v)
                    if THREADS.contains(&v)
                        || narf_filesystem::fsopts::kstrtouint(v, 0).is_some() => {}
                _ => return Err(FsError::InvalidData),
            },
            _ => return Err(FsError::InvalidData),
        }
    }
    let name = source.strip_prefix("/dev/").unwrap_or(source);
    let dev = narf_block::find_block_device(name).ok_or(FsError::NotFound)?;
    squashfs_factory(dev)
}

/// Register the named mount constructor without building a volume.
pub fn register_fstypes() {
    narf_filesystem::register_block_fstype("squashfs", squashfs_fstype_builder);
}

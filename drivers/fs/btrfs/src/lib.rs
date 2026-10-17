//! Clean-room read-write btrfs driver for single- and multi-device filesystems.
//!
//! The on-disk format is decoded per the authoritative kernel definitions in
//! `include/uapi/linux/btrfs_tree.h` and the read/COW call chains in
//! `fs/btrfs`. This is an independent Rust
//! implementation; no C code is copied.
//!
//! Supported: SINGLE, DUP, RAID0/1/1C3/1C4/10/5/6 chunk profiles, degraded
//! redundant reads, profile-aware multi-device growth, typed device lifecycle
//! and balance conversion, all four btrfs checksum algorithms, zlib/zstd/LZO
//! and uncompressed reads, 4–64 KiB sectors, incremental COW writes, namespace
//! mutations, nested writable subvolume mounts, full and simple qgroup
//! accounting/limits/administration, and subvolume/snapshot ioctls.
//! Unsupported on-disk shapes are rejected precisely rather than mis-read. See
//! the crate `README` for the full matrix and limits.

#![no_std]

extern crate alloc;

use alloc::sync::Arc;

use narf_block::{BlockDeviceSync, SyncBlock};
use narf_driver_runtime::DomainId;
use narf_filesystem::{FsError, FsInstance};

pub mod allocator;
pub(crate) mod block_group;
pub mod btree;
pub mod checksum;
pub mod chunk;
pub mod csum;
pub mod dir;
pub mod extent;
pub mod format;
pub mod inode;
pub mod lzo;
pub mod mount_opts;
pub mod node;
pub mod roots;
pub mod volume;
pub mod write;

mod raid56;
#[cfg(feature = "kernel-test")]
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
        register_fstypes();
        InitResult::Ok
    });
}

/// Root auto-mount factory: mount the btrfs volume on a synchronously-bridged
/// block device.
fn btrfs_factory(dev: Arc<dyn BlockDeviceSync>) -> Result<Arc<dyn FsInstance>, FsError> {
    let devices = discover_members(dev);
    let volume = narf_scheduler::block_on(volume::BtrfsVolume::mount_devices(
        devices,
        DomainId::DRIVER_0,
    ))?;
    Ok(volume)
}

/// Put the requested source first, then offer every other registered block
/// device to the FSID/devid-aware mount path. Foreign filesystems are ignored.
fn discover_members(source: Arc<dyn BlockDeviceSync>) -> alloc::vec::Vec<Arc<SyncBlock>> {
    let mut devices = alloc::vec![SyncBlock::new(source.clone())];
    for entry in narf_block::block_devices() {
        // `narf.disks=boot-only`: never pull a disk other than the boot
        // medium into a volume as a member.
        if !narf_block::disk_policy::automount_allowed(entry.name) {
            continue;
        }
        if !Arc::ptr_eq(&source, &entry.dev) {
            devices.push(SyncBlock::new(entry.dev));
        }
    }
    devices
}

/// Parse the `mount -t btrfs` option string into an optional subvolume selector.
/// Accepts every option [`mount_opts::parse`] accepts; format-affecting or
/// unknown options are `Unsupported`.
pub fn parse_mount_subvol(options: &str) -> Result<Option<volume::Subvol>, FsError> {
    Ok(mount_opts::parse(options)?.subvol)
}

/// `mount -t btrfs <source>` constructor. Resolves the source to a registered
/// block device and honours `subvol=`/`subvolid=`, the recorded data options
/// and a read-only request (`MS_RDONLY`, `fsconfig(ro)`, or `ro` in the data).
fn btrfs_fstype_builder(
    request: &narf_filesystem::MountRequest<'_>,
) -> Result<Arc<dyn FsInstance>, FsError> {
    let options = mount_opts::parse(request.options)?;
    let source = request.source;
    let name = source.strip_prefix("/dev/").unwrap_or(source);
    let dev = narf_block::find_block_device(name).ok_or(FsError::NotFound)?;
    let devices = discover_members(dev);
    // A read-only request really mounts read-only: no log replay, no commit
    // timer, no device write.
    let volume = if request.read_only || options.read_only {
        narf_scheduler::block_on(async {
            let volume =
                volume::BtrfsVolume::mount_devices_read_only(devices, DomainId::DRIVER_0, true)
                    .await?;
            if let Some(selector) = &options.subvol {
                volume.switch_to_subvol(selector).await?;
            }
            Ok::<_, FsError>(volume)
        })?
    } else {
        narf_scheduler::block_on(volume::BtrfsVolume::mount_subvol_devices(
            devices,
            DomainId::DRIVER_0,
            true,
            options.subvol.clone(),
        ))?
    };
    volume.set_mount_options(options);
    Ok(volume)
}

/// Register the named mount constructor without building a volume.
pub fn register_fstypes() {
    narf_filesystem::register_block_fstype_ctx("btrfs", btrfs_fstype_builder);
}

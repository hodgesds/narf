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
pub mod rw_gate;
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
    let volume = narf_scheduler::block_on(volume::BtrfsVolume::mount_devices_claimed(
        devices,
        DomainId::DRIVER_0,
        false,
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

/// Parsed `mount -t btrfs` options.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MountOptions {
    /// `subvol=PATH` (leading/trailing slashes stripped).
    pub subvol: Option<alloc::string::String>,
    /// `subvolid=N`.
    pub subvolid: Option<u64>,
    /// `ro` (the last of `ro`/`rw` wins, as in Linux).
    pub read_only: bool,
}

impl MountOptions {
    /// The subvolume selector: `subvol=` when given (checked against
    /// `subvolid=` after resolution), else `subvolid=`.
    pub fn selector(&self) -> Option<volume::Subvol> {
        match (&self.subvol, self.subvolid) {
            (Some(path), _) => Some(volume::Subvol::Name(path.clone())),
            (None, Some(id)) => Some(volume::Subvol::Id(id)),
            (None, None) => None,
        }
    }
}

/// Options accepted because they change nothing NARF writes: access-time
/// policy (NARF never updates atime), SSD allocation hints, discard (NARF
/// never discards, which is always valid), compression (NARF writes
/// uncompressed extents, which Linux reads under any `compress=` setting),
/// commit interval, autodefrag, ACL and error-handling knobs.
fn option_is_inert(option: &str) -> bool {
    const FLAGS: &[&str] = &[
        "defaults",
        "noatime",
        "relatime",
        "strictatime",
        "lazytime",
        "nodiratime",
        "diratime",
        "atime",
        "ssd",
        "nossd",
        "ssd_spread",
        "nossd_spread",
        "discard",
        "nodiscard",
        "autodefrag",
        "noautodefrag",
        "acl",
        "noacl",
        "barrier",
        "nobarrier",
        "datacow",
        "datasum",
        "compress",
        "compress-force",
        "nocompress",
        "flushoncommit",
        "noflushoncommit",
        "skip_balance",
        "user_subvol_rm_allowed",
        "enospc_debug",
        "noenospc_debug",
        "nouser_xattr",
        "user_xattr",
        "space_cache=v2",
        "errors=continue",
        "errors=remount-ro",
        "errors=panic",
        "discard=async",
        "discard=sync",
    ];
    if FLAGS.contains(&option) {
        return true;
    }
    let value_of = |prefix: &str| option.strip_prefix(prefix);
    if let Some(v) = value_of("compress=").or_else(|| value_of("compress-force=")) {
        let (algo, level) = v.split_once(':').unwrap_or((v, ""));
        return matches!(algo, "zstd" | "zlib" | "lzo" | "no" | "none" | "yes")
            && (level.is_empty() || level.parse::<i32>().is_ok());
    }
    if let Some(v) = value_of("commit=") {
        return v.parse::<u32>().is_ok();
    }
    false
}

/// Parse the `mount -t btrfs` option string. Accepts `ro`/`rw`, the
/// [inert](option_is_inert) options an installed distro's fstab carries
/// (`defaults,noatime,compress=zstd:1,ssd,discard=async,space_cache=v2`),
/// and `subvolid=N` / `subvol=PATH`. Anything else — notably options that
/// would change on-disk state NARF does not maintain (`clear_cache`,
/// `space_cache=v1`, `nospace_cache`, `rescue=`, `usebackuproot`, `degraded`,
/// `device=`) — is `Unsupported`.
pub fn parse_mount_options(options: &str) -> Result<MountOptions, FsError> {
    let mut out = MountOptions::default();
    for option in options.split(',').filter(|s| !s.is_empty()) {
        if option == "ro" {
            out.read_only = true;
        } else if option == "rw" {
            out.read_only = false;
        } else if option_is_inert(option) {
            continue;
        } else if let Some(v) = option.strip_prefix("subvolid=") {
            let id: u64 = v.parse().map_err(|_| FsError::InvalidData)?;
            out.subvolid = Some(id);
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
            out.subvol = Some(alloc::string::String::from(path));
        } else {
            return Err(FsError::Unsupported);
        }
    }
    Ok(out)
}

/// Parse the `mount -t btrfs` option string into an optional subvolume
/// selector (see [`parse_mount_options`]).
pub fn parse_mount_subvol(options: &str) -> Result<Option<volume::Subvol>, FsError> {
    Ok(parse_mount_options(options)?.selector())
}

/// `mount -t btrfs <source>` builder. Resolves the source to a registered block
/// device and honours `subvol=`/`subvolid=` (both given: they must agree).
///
/// Every call builds an independent volume; [`rw_gate`] lets at most one of
/// them per fsid be writable, so a second read-write mount of an already
/// writable filesystem (another fstab subvolume) comes up read-only.
fn btrfs_fstype_builder(source: &str, options: &str) -> Result<Arc<dyn FsInstance>, FsError> {
    let opts = parse_mount_options(options)?;
    let subvol = opts.selector();
    let name = source.strip_prefix("/dev/").unwrap_or(source);
    let dev = narf_block::find_block_device(name).ok_or(FsError::NotFound)?;
    let devices = discover_members(dev);
    let volume = narf_scheduler::block_on(async {
        // `ro` in the data string really mounts read-only: no log replay, no
        // commit timer, no device write.
        let volume =
            volume::BtrfsVolume::mount_devices_claimed(devices, DomainId::DRIVER_0, opts.read_only)
                .await?;
        if let Some(selector) = &subvol {
            volume.switch_to_subvol(selector).await?;
        }
        if let (Some(_), Some(id)) = (&opts.subvol, opts.subvolid) {
            if volume.fs_tree_id() != id {
                return Err(FsError::InvalidData);
            }
        }
        // A read-write request that cannot be honoured — the device is
        // read-only under `narf.disks=`, the write-safety gate refused, or
        // another writable mount of this fsid is open — fails with EROFS
        // rather than silently handing back a read-only volume behind an `rw`
        // mount. libmount then retries with MS_RDONLY, as it does for a
        // write-protected disk on Linux, and mountinfo stays truthful.
        if !opts.read_only && volume.is_read_only() {
            return Err(FsError::ReadOnly);
        }
        Ok::<_, FsError>(volume)
    })?;
    Ok(volume)
}

/// Register the named mount constructor without building a volume.
pub fn register_fstypes() {
    narf_filesystem::register_block_fstype("btrfs", btrfs_fstype_builder);
}

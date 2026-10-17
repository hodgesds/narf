//! Root filesystem auto-mount.
//!
//! After the bus walker probes storage controllers and partition
//! scanners register per-partition block devices, this module
//! walks the block registry, detects each device's filesystem
//! type, and attempts to mount the first viable candidate on /.
//!
//! The selection policy is intentionally simple for v1:
//!
//! 1. Walk `narf_block::block_devices()` in registration order
//!    (which mirrors enumeration order — internal NVMe before
//!    USB MSC on most boots).
//! 2. For each device, call `narf_block::fs_detect::detect_filesystem`.
//! 3. If a known FS type matches, look up the registered driver
//!    factory in [`FS_FACTORIES`] and call it.
//! 4. First successful mount wins — subsequent partitions are
//!    left alone.
//!
//! Drivers register their `(FsType, factory_fn)` at boot time via
//! [`register_fs_factory`]. The factory takes a parent block
//! device and returns an `Arc<dyn FsInstance>` ready to mount.
//!
//! Per-device root-device selection (commonly `root=/dev/nvme0n1p2`
//! on Linux) is a follow-up — currently we mount the first
//! match, which is fine for the bring-up arc where the disk has
//! one filesystem partition.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use narf_block::fs_detect::{detect_filesystem, FsType};
use narf_block::BlockDeviceSync;
use narf_lib::sync::IrqSafeSpinLock;

use crate::{FsError, FsInstance, TmpFs};

/// Driver-supplied factory: given a parent block device, build
/// the corresponding `FsInstance`. Returns an `FsError` on
/// superblock-validation failure (in which case the walker skips
/// this candidate and tries the next).
pub type FsFactory = fn(Arc<dyn BlockDeviceSync>) -> Result<Arc<dyn FsInstance>, FsError>;

static FS_FACTORIES: IrqSafeSpinLock<Vec<(FsType, FsFactory)>> = IrqSafeSpinLock::new(Vec::new());

/// Register a driver-side factory for `fs_type`. Idempotent — a
/// later registration for the same type replaces the prior factory.
/// Drivers call this from their `Stage::Subsys` initcall so the
/// root-mount walker (`Stage::Late`) finds them.
pub fn register_fs_factory(fs_type: FsType, factory: FsFactory) {
    let mut g = FS_FACTORIES.lock();
    if let Some(slot) = g.iter_mut().find(|(t, _)| *t == fs_type) {
        slot.1 = factory;
    } else {
        g.push((fs_type, factory));
    }
}

/// Number of registered FS factories.
pub fn factory_count() -> usize {
    FS_FACTORIES.lock().len()
}

/// Look up the registered factory for a given FS type, if any.
pub fn lookup_factory(fs_type: FsType) -> Option<FsFactory> {
    FS_FACTORIES
        .lock()
        .iter()
        .find(|(t, _)| *t == fs_type)
        .map(|(_, f)| *f)
}

/// What `try_mount_root` produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountReport {
    /// Name of the block device the root mount used.
    pub device_name: String,
    /// FS type the device's superblock matched.
    pub fs_type: FsType,
}

/// CachyOS installs the firmware-visible EFI System Partition directly at
/// `/boot`; mounting it under `/boot/efi` leaves the fstab `/boot` unit
/// unsatisfied even though the FAT volume is available.
pub const EFI_SYSTEM_PARTITION_MOUNTPOINT: &str = "/boot";

/// Host-view path corresponding to `/boot` for the distro PID 1 rooted at
/// `/mnt`.  Keeping this separate from the firmware-facing mount makes the
/// same ESP visible before systemd evaluates the installed system's fstab.
pub const INSTALLED_ROOT_EFI_SYSTEM_PARTITION_MOUNTPOINT: &str = "/mnt/boot";

/// Errors specific to root-mount selection.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RootMountError {
    /// No registered block device carried a recognised filesystem.
    NoMountable,
    /// A candidate was found but its driver factory wasn't
    /// registered (e.g. the kernel was built without ext support
    /// and the only candidate is ext4).
    NoFactory(FsType),
    /// The driver factory failed superblock validation. Surfaces
    /// the driver's `FsError` so the boot log can explain why.
    FactoryFailed(FsType, FsError),
    /// `root=<spec>` was given but no registered block device
    /// matched. We refuse to silently mount a different volume.
    SelectorNoMatch,
    /// A selected LUKS container could not be opened by the installed boot
    /// credential provider or failed authenticated metadata/keyslot checks.
    LuksUnlock(narf_block::encrypted::LuksOpenError),
    /// The selected root filesystem was found, but construction of its
    /// session-writable tmpfs overlay failed.
    TmpfsOverlay(FsError),
    /// Every otherwise-eligible device was skipped because
    /// `narf.disks=boot-only` restricts automatic mounts to the identified
    /// boot medium (see [`narf_block::disk_policy`]).
    BootOnly,
}

/// Policy applied after the selected root filesystem has been constructed but
/// before it is attached at `/`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RootMountOptions {
    /// Place a writable tmpfs upper over the selected filesystem. Reads still
    /// resolve from the selected filesystem, while all mutations are copied up
    /// into RAM and vanish at shutdown.
    pub tmpfs_overlay: bool,
}

/// Name reported by the session-writable root overlay.
pub const ROOT_TMPFS_OVERLAY_NAME: &str = "root-tmpfs-overlay";

/// Build a writable, session-only root view over an immutable filesystem.
///
/// The upper uses Linux-compatible tmpfs defaults, including a capacity limit
/// of half of managed RAM.  Root ownership and mode are copied from the lower
/// root so mounting the overlay cannot weaken the installed system's top-level
/// DAC policy before any copy-up occurs.
pub fn tmpfs_overlay_root(lower: Arc<dyn FsInstance>) -> Result<Arc<dyn FsInstance>, FsError> {
    let lower_root = lower.root();
    let (uid, gid) = lower_root.dir_owners();
    let upper = TmpFs::from_options("mode=0755", uid, gid)?;
    let upper_root = upper.root();
    upper_root.set_dir_mode(lower_root.dir_mode());
    upper_root.set_dir_owners(uid, gid);
    Ok(Arc::new(crate::overlayfs::OverlayFs::new(
        ROOT_TMPFS_OVERLAY_NAME,
        upper_root,
        alloc::vec![lower_root],
    )))
}

/// Registered block devices boot-time code may automatically mount, plus the
/// number skipped because `narf.disks=boot-only` restricts automatic mounts
/// to the identified boot medium ([`narf_block::disk_policy`]).
pub fn automount_devices() -> (alloc::vec::Vec<narf_block::RegisteredBlockDevice>, usize) {
    let all = narf_block::block_devices();
    let total = all.len();
    let allowed: alloc::vec::Vec<_> = all
        .into_iter()
        .filter(|entry| narf_block::disk_policy::automount_allowed(entry.name))
        .collect();
    let skipped = total - allowed.len();
    (allowed, skipped)
}

/// Walk the block registry and mount the first viable filesystem on /.
/// Returns the report so the boot log knows what got mounted.
///
/// Selection policy:
/// - If `narf_boot::cmdline()` carries `root=<spec>`, only consider
///   devices that match the spec; no-match → return
///   `RootMountError::SelectorNoMatch`.
/// - Otherwise, fall back to "first detected FS wins" in
///   registration order — the existing behaviour.
pub fn try_mount_root(
    authority: &narf_capabilities::Cap<crate::MountPoint, narf_capabilities::Grant>,
) -> Result<MountReport, RootMountError> {
    let selector = crate::root_selector::RootSelector::from_cmdline(narf_boot::cmdline());
    // An installed Linux userspace needs a writable root for state such as
    // browser profiles, package caches, and `/var`. NARF's disk filesystems
    // are deliberately immutable during this bring-up phase, so systemd PID 1
    // boots with an explicit root selector receive a tmpfs-backed OverlayFS
    // root while the on-disk image stays the lower, untouched layer. The
    // selector-free installed-root fallback is attached later at `/mnt` and
    // applies the same wrapper there before PID 1 is spawned.
    let options = RootMountOptions {
        tmpfs_overlay: narf_boot::args().has_flag("systemd_pid1") && selector.is_some(),
    };
    try_mount_root_with_options(authority, selector.as_ref(), options)
}

/// Like [`try_mount_root`] but with the selector resolved already.
/// Boot path uses the wrapper above; tests call this with their own
/// selector so they don't need to munge the global cmdline.
pub fn try_mount_root_with(
    authority: &narf_capabilities::Cap<crate::MountPoint, narf_capabilities::Grant>,
    selector: Option<&crate::root_selector::RootSelector>,
) -> Result<MountReport, RootMountError> {
    try_mount_root_with_options(authority, selector, RootMountOptions::default())
}

/// Like [`try_mount_root_with`] with an explicit root-view policy.
///
/// Tests and non-systemd launchers normally use [`RootMountOptions::default`]
/// and mount the selected filesystem directly.  An installed distro launcher
/// sets [`RootMountOptions::tmpfs_overlay`] to preserve the immutable disk
/// image while giving the session a writable root.
pub fn try_mount_root_with_options(
    authority: &narf_capabilities::Cap<crate::MountPoint, narf_capabilities::Grant>,
    selector: Option<&crate::root_selector::RootSelector>,
    options: RootMountOptions,
) -> Result<MountReport, RootMountError> {
    let devices = narf_block::block_devices();
    let mut last_error: Option<RootMountError> = None;
    let mut saw_candidate = false;
    let mut skipped_by_policy = false;
    for entry in &devices {
        // `narf.disks=boot-only`: never mount (or even LUKS-probe) a disk
        // other than the identified boot medium, explicit root= included.
        if !narf_block::disk_policy::automount_allowed(entry.name) {
            skipped_by_policy = true;
            continue;
        }
        let outer_uuid_matches = selector.is_some_and(|selector| match selector {
            crate::root_selector::RootSelector::ByFsUuid(target) => entry
                .partition
                .as_ref()
                .is_some_and(|metadata| metadata.fs_uuid.eq_ignore_ascii_case(target)),
            _ => false,
        });
        // Selector filter: skip devices the cmdline doesn't ask
        // for. ByName matches the registry-string; ByPartLabel /
        // ByPartUuid match the GPT metadata the partition scanner
        // attached at register_block_device_with_meta time
        // (None = whole-disk parent or legacy-MBR partition, both
        // never match a PARTLABEL/PARTUUID selector).
        if let Some(sel) = selector {
            use crate::root_selector::RootSelector;
            match sel {
                RootSelector::ByName(_) => {
                    if !sel.matches_name(entry.name) {
                        continue;
                    }
                }
                RootSelector::ByPartLabel(target) => match &entry.partition {
                    Some(m) if &m.partlabel == target => {}
                    _ => continue,
                },
                RootSelector::ByPartUuid(target) => match &entry.partition {
                    Some(m) if m.partuuid.eq_ignore_ascii_case(target) => {}
                    _ => continue,
                },
                // Resolve this after an optional LUKS open so UUID= may name
                // either the outer container or the filesystem inside it.
                RootSelector::ByFsUuid(_) => {}
            }
        }
        if !matches!(
            selector,
            Some(crate::root_selector::RootSelector::ByFsUuid(_))
        ) {
            saw_candidate = true;
        }
        let mut dev = entry.dev.clone();
        let mut unlocked_luks = false;
        let detect = match detect_filesystem(&dev) {
            Ok(Some(t)) => t,
            Ok(None) | Err(_) => {
                match narf_block::encrypted::open_luks_with_provider(dev.clone()) {
                    Ok(unlocked) => {
                        dev = Arc::new(unlocked);
                        unlocked_luks = true;
                        match detect_filesystem(&dev) {
                            Ok(Some(t)) => t,
                            Ok(None) | Err(_) => continue,
                        }
                    }
                    Err(narf_block::encrypted::LuksOpenError::NotLuks) => continue,
                    Err(error) => {
                        last_error = Some(RootMountError::LuksUnlock(error));
                        continue;
                    }
                }
            }
        };
        if let Some(crate::root_selector::RootSelector::ByFsUuid(target)) = selector {
            let inner_uuid_matches = narf_block::partition::discover_volume_uuid(dev.as_ref())
                .is_some_and(|uuid| uuid.eq_ignore_ascii_case(target));
            if !outer_uuid_matches && !inner_uuid_matches {
                continue;
            }
            saw_candidate = true;
        }
        let factory = match lookup_factory(detect) {
            Some(f) => f,
            None => {
                last_error = Some(RootMountError::NoFactory(detect));
                continue;
            }
        };
        let fs = match factory(dev.clone()) {
            Ok(f) => f,
            Err(e) => {
                last_error = Some(RootMountError::FactoryFailed(detect, e));
                continue;
            }
        };
        // Mount on /. mount_arc returns the per-mount handle; we
        // discard it — root unmount on shutdown will use a separate
        // boot-time-stashed handle (follow-up).
        let fs = if options.tmpfs_overlay {
            tmpfs_overlay_root(fs).map_err(RootMountError::TmpfsOverlay)?
        } else {
            fs
        };
        let _handle = crate::registry()
            .mount_arc(authority, "/", fs)
            .map_err(|e| RootMountError::FactoryFailed(detect, e))?;
        let device_name = if unlocked_luks {
            // Same disk identity as its container, so the write policy
            // treats the unlocked view exactly like the medium it lives on.
            narf_block::register_partition_device("cryptroot", entry.name, dev, None);
            "cryptroot"
        } else {
            entry.name
        };
        return Ok(MountReport {
            device_name: String::from(device_name),
            fs_type: detect,
        });
    }
    // Every explicit selector is strict. Silent fallback to a wrong device is
    // worse than refusing, including for UUID now that the block scanner and
    // decrypted adapter both expose immutable volume identifiers.
    if selector.is_some() && !saw_candidate {
        if let Some(error @ RootMountError::LuksUnlock(_)) = last_error {
            return Err(error);
        }
        if skipped_by_policy {
            return Err(RootMountError::BootOnly);
        }
        return Err(RootMountError::SelectorNoMatch);
    }
    Err(
        last_error.unwrap_or(if skipped_by_policy && !saw_candidate {
            RootMountError::BootOnly
        } else {
            RootMountError::NoMountable
        }),
    )
}

/// Mount the GPT EFI System Partition at NARF's `/boot` and the installed
/// system's `/mnt/boot` (visible as `/boot` to its rooted PID 1).
///
/// Selection is deliberately semantic: only a partition whose GPT *type*
/// GUID is the UEFI ESP GUID is eligible.  The implementation never depends
/// on names such as `vblk0p1`, labels such as `EFI`, or this test VM's FAT
/// volume UUID.  An ESP must also prove to be FAT before its registered
/// factory is invoked.
pub fn try_mount_efi_system_partition(
    authority: &narf_capabilities::Cap<crate::MountPoint, narf_capabilities::Grant>,
) -> Result<MountReport, RootMountError> {
    let mut last_error = None;
    for entry in narf_block::block_devices() {
        if !entry
            .partition
            .as_ref()
            .is_some_and(narf_block::registry::PartitionMetadata::is_efi_system_partition)
        {
            continue;
        }
        // `narf.disks=boot-only`: the machine's own ESP (e.g. the installed
        // OS's) is never mounted; only the identified boot medium's is.
        if !narf_block::disk_policy::automount_allowed(entry.name) {
            last_error = Some(RootMountError::BootOnly);
            continue;
        }
        let dev = entry.dev.clone();
        let detect = match detect_filesystem(&dev) {
            Ok(Some(FsType::Fat)) => FsType::Fat,
            Ok(Some(_)) | Ok(None) | Err(_) => continue,
        };
        let factory = match lookup_factory(detect) {
            Some(factory) => factory,
            None => {
                last_error = Some(RootMountError::NoFactory(detect));
                continue;
            }
        };
        let fs = match factory(dev) {
            Ok(fs) => fs,
            Err(error) => {
                last_error = Some(RootMountError::FactoryFailed(detect, error));
                continue;
            }
        };
        let boot_handle = crate::registry()
            .mount_arc(authority, EFI_SYSTEM_PARTITION_MOUNTPOINT, fs.clone())
            .map_err(|error| RootMountError::FactoryFailed(detect, error))?;
        if let Err(error) = crate::registry().mount_arc(
            authority,
            INSTALLED_ROOT_EFI_SYSTEM_PARTITION_MOUNTPOINT,
            fs,
        ) {
            // Do not report a half-mounted ESP.  The handle was minted by the
            // first attach and remains live here, so rollback is best-effort
            // only in the face of an internal registry inconsistency.
            let _ = crate::registry().unmount(&boot_handle, EFI_SYSTEM_PARTITION_MOUNTPOINT);
            return Err(RootMountError::FactoryFailed(detect, error));
        }
        return Ok(MountReport {
            device_name: String::from(entry.name),
            fs_type: detect,
        });
    }
    Err(last_error.unwrap_or(RootMountError::NoMountable))
}

#[doc(hidden)]
pub fn __reset_for_test() {
    FS_FACTORIES.lock().clear();
}

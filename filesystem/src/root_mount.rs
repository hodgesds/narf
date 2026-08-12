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

use crate::{FsError, FsInstance};

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
    try_mount_root_with(authority, selector.as_ref())
}

/// Like [`try_mount_root`] but with the selector resolved already.
/// Boot path uses the wrapper above; tests call this with their own
/// selector so they don't need to munge the global cmdline.
pub fn try_mount_root_with(
    authority: &narf_capabilities::Cap<crate::MountPoint, narf_capabilities::Grant>,
    selector: Option<&crate::root_selector::RootSelector>,
) -> Result<MountReport, RootMountError> {
    let devices = narf_block::block_devices();
    let mut last_error: Option<RootMountError> = None;
    let mut saw_candidate = false;
    for entry in &devices {
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
                // FS-UUID needs per-FS-instance metadata we still
                // don't carry (would need a UUID accessor on
                // FsInstance). Lenient until that lands — the
                // selector is parsed + visible in the boot log,
                // walker falls through to "first detected".
                RootSelector::ByFsUuid(_) => {}
            }
        }
        saw_candidate = true;
        let dev = entry.dev.clone();
        let detect = match detect_filesystem(&dev) {
            Ok(Some(t)) => t,
            Ok(None) | Err(_) => continue,
        };
        let factory = match lookup_factory(detect) {
            Some(f) => f,
            None => {
                last_error = Some(RootMountError::NoFactory(detect));
                continue;
            }
        };
        let fs = match factory(dev) {
            Ok(f) => f,
            Err(e) => {
                last_error = Some(RootMountError::FactoryFailed(detect, e));
                continue;
            }
        };
        // Mount on /. mount_arc returns the per-mount handle; we
        // discard it — root unmount on shutdown will use a separate
        // boot-time-stashed handle (follow-up).
        let _handle = crate::registry()
            .mount_arc(authority, "/", fs)
            .map_err(|e| RootMountError::FactoryFailed(detect, e))?;
        return Ok(MountReport {
            device_name: String::from(entry.name),
            fs_type: detect,
        });
    }
    // If a strict-match selector (ByName / ByPartLabel / ByPartUuid)
    // was given but nothing matched, surface that distinctly —
    // silent fallback to a wrong device is worse than refusing.
    // FS-UUID is excluded from this guard since the walker doesn't
    // yet carry FS-uuid metadata.
    if let Some(sel) = selector {
        use crate::root_selector::RootSelector;
        let strict = matches!(
            sel,
            RootSelector::ByName(_) | RootSelector::ByPartLabel(_) | RootSelector::ByPartUuid(_)
        );
        if strict && !saw_candidate {
            return Err(RootMountError::SelectorNoMatch);
        }
    }
    Err(last_error.unwrap_or(RootMountError::NoMountable))
}

/// Mount the GPT EFI System Partition at the installed system's `/boot`.
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
        crate::registry()
            .mount_arc(authority, EFI_SYSTEM_PARTITION_MOUNTPOINT, fs)
            .map_err(|error| RootMountError::FactoryFailed(detect, error))?;
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

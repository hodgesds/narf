//! Partition-scoped ESP writes on read-write native root boots.
//!
//! This grants no access to the parent disk or to stacked views. As with
//! root designation, registration identity (not a reusable name) gates I/O.

use super::*;

#[derive(Clone)]
struct Esp {
    dev: DevId,
    partuuid: [u8; 16],
    disk: DiskId,
    identity: Option<Arc<crate::registry::DiskIdentity>>,
}

static DESIGNATED: IrqSafeSpinLock<Option<Esp>> = IrqSafeSpinLock::new(None);
static DEV: AtomicU64 = AtomicU64::new(0);
static REVOKED: AtomicBool = AtomicBool::new(false);

fn partuuid(entry: &RegisteredBlockDevice) -> Option<[u8; 16]> {
    parse_uuid(&entry.partition.as_ref()?.partuuid)
}

fn candidate(
    entry: &RegisteredBlockDevice,
    disk: DiskId,
    identity: Option<&crate::registry::DiskIdentity>,
) -> bool {
    entry.disk == disk
        && entry.identity.as_deref() == identity
        && entry.write_parent.is_none()
        && entry
            .partition
            .as_ref()
            .is_some_and(|m| m.is_efi_system_partition())
}

/// Called once after root designation, before any ESP mount caches its
/// read-only state. Failure leaves the root usable and every ESP read-only.
pub(super) fn designate(root: &RegisteredBlockDevice) {
    if policy() != DiskPolicy::RootRw || !super::dev_writable(root.dev_id) {
        return;
    }
    let devices = crate::registry::block_devices();
    let mut matches = devices
        .iter()
        .filter(|e| candidate(e, root.disk, root.identity.as_deref()));
    let Some(entry) = matches.next() else {
        return;
    };
    let Some(want) = partuuid(entry).filter(|id| *id != [0; 16]) else {
        return;
    };
    if matches.next().is_some()
        || !entry_is_vfat(entry)
        || devices
            .iter()
            .any(|e| e.dev_id != entry.dev_id && partuuid(e) == Some(want))
    {
        return;
    }
    {
        let mut slot = DESIGNATED.lock();
        if slot.is_some() || REVOKED.load(Ordering::Acquire) {
            return;
        }
        *slot = Some(Esp {
            dev: entry.dev_id,
            partuuid: want,
            disk: root.disk,
            identity: root.identity.clone(),
        });
    }
    DEV.store(entry.dev_id, Ordering::Release);
    // Close the snapshot/publication race with registry notifications.
    let after = crate::registry::block_devices();
    if !after.iter().any(|e| e.dev_id == entry.dev_id)
        || after.iter().any(|e| {
            e.dev_id != entry.dev_id
                && (partuuid(e) == Some(want) || candidate(e, root.disk, root.identity.as_deref()))
        })
    {
        revoke("registry changed during ESP designation");
        return;
    }
    if writable(entry.dev_id) {
        framed(&alloc::format!(
            "disks: WRITABLE ESP: {} (PARTUUID {}, narf.disks=root-rw); parent disk and other partitions remain protected",
            entry.name, format_uuid_bytes(&want)
        ));
    }
}

pub(super) fn writable(dev: DevId) -> bool {
    dev != 0
        && DEV.load(Ordering::Acquire) == dev
        && !REVOKED.load(Ordering::Acquire)
        && !super::REVOKED.load(Ordering::Acquire)
        && super::DESIGNATED_DEV.load(Ordering::Acquire) != 0
}

fn revoke(reason: &str) {
    if !REVOKED.swap(true, Ordering::AcqRel) {
        DEV.store(0, Ordering::Release);
        framed(&alloc::format!(
            "disks: ESP DESIGNATION REVOKED ({reason}); ESP writes refused for the rest of this boot"
        ));
    }
}

pub(super) fn note_registered(entry: &RegisteredBlockDevice, replaced: Option<DevId>) {
    let designated = DESIGNATED.lock().clone();
    if let Some(d) = designated {
        if replaced == Some(d.dev) {
            revoke("designated ESP was replaced");
        } else if entry.dev_id != d.dev && partuuid(entry) == Some(d.partuuid) {
            revoke("duplicate ESP PARTUUID");
        } else if entry.dev_id != d.dev && candidate(entry, d.disk, d.identity.as_deref()) {
            revoke("a second ESP appeared on the root disk");
        }
    }
}

pub(super) fn note_unregistered(dev: DevId) {
    if DESIGNATED.lock().as_ref().is_some_and(|d| d.dev == dev) {
        revoke("designated ESP was removed");
    }
}

pub(super) fn reset_for_test() {
    *DESIGNATED.lock() = None;
    DEV.store(0, Ordering::Release);
    REVOKED.store(false, Ordering::Release);
}

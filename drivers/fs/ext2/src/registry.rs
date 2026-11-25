//! One mounted volume per block device.
//!
//! Linux finds an existing superblock for the device (`get_tree_bdev` →
//! `sget_fc`), so a second `mount` of the same partition (systemd mounting
//! a bind of `/`, a second mount point of the same filesystem) shares the
//! first one's in-memory state. Two `Ext2Volume`s over one device would each
//! keep their own allocator locks, bitmaps and inode cache, and write over
//! each other. A second mount that would change the read-only state is
//! refused with EBUSY, as Linux refuses it ("Can't mount, would change RO
//! state").

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use narf_block::{BlockDeviceSync, SyncBlock};
use narf_driver_runtime::DomainId;
use narf_filesystem::FsError;
use narf_lib::sync::IrqSafeSpinLock;

use crate::volume::Ext2Volume;

type Volume = Ext2Volume<SyncBlock>;

/// Live volumes by the identity of the registered device they mount.
static MOUNTED: IrqSafeSpinLock<Vec<(usize, Weak<Volume>)>> = IrqSafeSpinLock::new(Vec::new());

fn device_key(dev: &Arc<dyn BlockDeviceSync>) -> usize {
    Arc::as_ptr(dev) as *const () as usize
}

fn live(key: usize) -> Option<Arc<Volume>> {
    let mut mounted = MOUNTED.lock();
    mounted.retain(|(_, weak)| weak.strong_count() > 0);
    mounted
        .iter()
        .find(|(k, _)| *k == key)
        .and_then(|(_, weak)| weak.upgrade())
}

fn share(existing: Arc<Volume>, read_only: bool) -> Result<Arc<Volume>, FsError> {
    if existing.is_read_only() != read_only {
        return Err(FsError::Busy);
    }
    Ok(existing)
}

/// The volume on `dev`: the one already mounted, or a new mount.
/// `read_only` is what the caller asked for; a refused read-write request
/// is the caller's to report (the named `ext4` constructor does).
pub fn mount(dev: Arc<dyn BlockDeviceSync>, read_only: bool) -> Result<Arc<Volume>, FsError> {
    let key = device_key(&dev);
    if let Some(existing) = live(key) {
        return share(existing, read_only);
    }
    let async_dev = SyncBlock::new(dev);
    let volume = if read_only {
        narf_filesystem::fs_registry::mount_wait(Volume::mount_read_only(
            async_dev,
            DomainId::DRIVER_0,
        ))?
    } else {
        narf_filesystem::fs_registry::mount_wait(Volume::mount(async_dev, DomainId::DRIVER_0))?
    };
    let mut mounted = MOUNTED.lock();
    mounted.retain(|(_, weak)| weak.strong_count() > 0);
    // A mount that raced this one and registered first wins: this volume is
    // dropped unused.
    if let Some(existing) = mounted
        .iter()
        .find(|(k, _)| *k == key)
        .and_then(|(_, weak)| weak.upgrade())
    {
        drop(mounted);
        return share(existing, read_only);
    }
    mounted.push((key, Arc::downgrade(&volume)));
    Ok(volume)
}

#[doc(hidden)]
pub fn __reset_for_test() {
    MOUNTED.lock().clear();
}

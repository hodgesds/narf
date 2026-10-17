//! One shared filesystem instance per fsid.
//!
//! Linux `btrfs_get_tree_super` finds the `btrfs_fs_devices` by fsid and
//! reuses its superblock (`sget_fc`) when the filesystem is already mounted.
//! Every further `mount -o subvol=...` (`btrfs_get_tree_subvol` → `mount_subvol`)
//! is then a new root dentry over that one `btrfs_fs_info`. Every mount
//! therefore shares one transaction, allocator, superblock commit and
//! `transaction_kthread`. Without this, CachyOS's seven fstab subvolume
//! mounts of one partition would be seven independent writers, each committing
//! superblocks built from a tree the others had moved.
//!
//! The registry holds `Weak` references. A [`VolCore`] lives exactly as long
//! as some mount ([`BtrfsVolume`] view) of it does, and the next mount after
//! the last one goes builds a fresh instance from disk.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use narf_block::{BlockDeviceSync, SyncBlock};
use narf_driver_runtime::DomainId;
use narf_filesystem::FsError;
use narf_lib::mutex::Mutex;
use narf_lib::sync::IrqSafeSpinLock;

use crate::format;
use crate::volume::{BtrfsVolume, Subvol, VolCore};

/// One registered instance: its fsid and a non-owning reference.
type Entry = ([u8; 16], Weak<VolCore<SyncBlock>>);

/// Live filesystem instances by fsid.
static CORES: IrqSafeSpinLock<Vec<Entry>> = IrqSafeSpinLock::new(Vec::new());

/// Serialises lookup-or-create, so two concurrent first mounts of one
/// filesystem cannot each build an instance (Linux holds `uuid_mutex` and the
/// `sget` lock for the same reason).
static MOUNT_LOCK: Mutex<()> = Mutex::new(());

/// `(fsid, devid)` from `dev`'s primary superblock, or `None` when it does not
/// carry one this driver could mount. Only a hint for finding an existing
/// instance: a miss falls through to a full mount, which validates everything.
fn peek_identity(dev: &dyn BlockDeviceSync) -> Option<([u8; 16], u64)> {
    let lba_size = dev.lba_size() as usize;
    if lba_size == 0 || format::SUPERBLOCK_SIZE % lba_size != 0 {
        return None;
    }
    let mut raw = alloc::vec![0u8; format::SUPERBLOCK_SIZE];
    let lba = format::SUPERBLOCK_OFFSET / lba_size as u64;
    let blocks = u16::try_from(format::SUPERBLOCK_SIZE / lba_size).ok()?;
    dev.read(lba, blocks, &mut raw).ok()?;
    let sb = format::Superblock::decode(&raw).ok()?;
    Some((sb.fsid, sb.devid))
}

fn lookup(fsid: &[u8; 16]) -> Option<Arc<VolCore<SyncBlock>>> {
    let mut cores = CORES.lock();
    cores.retain(|(_, weak)| weak.strong_count() > 0);
    cores
        .iter()
        .find(|(id, _)| id == fsid)
        .and_then(|(_, weak)| weak.upgrade())
}

fn register(core: &Arc<VolCore<SyncBlock>>) {
    let fsid = core.fsid();
    let mut cores = CORES.lock();
    cores.retain(|(id, weak)| weak.strong_count() > 0 && *id != fsid);
    cores.push((fsid, Arc::downgrade(core)));
}

/// The live instance for `fsid`, if any mount of it is open.
pub fn instance_for(fsid: &[u8; 16]) -> Option<Arc<VolCore<SyncBlock>>> {
    lookup(fsid)
}

/// Mount `subvol` (or the default subvolume) of the filesystem on `source`.
/// `devices` is `source` followed by the other candidate members.
///
/// When that filesystem is already mounted, the result is another view over
/// the same instance. A read-write request against an instance that is
/// read-only flips the instance writable, or fails with `ReadOnly` when a
/// member device or the feature set forbids it. Otherwise the volume is
/// mounted from disk and registered.
pub async fn mount(
    source: &Arc<dyn BlockDeviceSync>,
    devices: Vec<Arc<SyncBlock>>,
    subvol: Option<Subvol>,
    read_only: bool,
) -> Result<Arc<BtrfsVolume<SyncBlock>>, FsError> {
    let _serial = MOUNT_LOCK.lock().await;
    if let Some((fsid, devid)) = peek_identity(&**source) {
        if let Some(core) = lookup(&fsid) {
            // Same fsid but not one of the instance's members: a cloned disk.
            // Linux refuses to assemble a second device under a mounted fsid.
            if !core.has_member(devid) {
                return Err(FsError::Busy);
            }
            return BtrfsVolume::mount_view(&core, subvol, read_only).await;
        }
    }
    let volume = if read_only {
        let volume =
            BtrfsVolume::mount_devices_read_only(devices, DomainId::DRIVER_0, true).await?;
        if let Some(selector) = &subvol {
            volume.switch_to_subvol(selector).await?;
        }
        volume
    } else {
        BtrfsVolume::mount_subvol_devices(devices, DomainId::DRIVER_0, true, subvol).await?
    };
    register(volume.core());
    Ok(volume)
}

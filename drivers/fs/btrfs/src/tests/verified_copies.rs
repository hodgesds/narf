//! Relocation (balance) and device replace copy what they read verified:
//! a corrupt copy is repaired from a good one, or rebuilt from its RAID5/6
//! full stripe, and never propagated into the new copies (Linux relocation
//! reads through the verified paths; `btrfs_dev_replace` copies through
//! scrub).

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_block::BlockDeviceSync;
use narf_filesystem::{FsError, FsInstance};
use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    blank_writable, file_data_extent, mount_writable_devices, poll_once, read_all,
    writable_sparse_devices, WritableSparseDevice, FIXTURE_RAID0, FIXTURE_RAID1, FIXTURE_RAID10,
    FIXTURE_RAID5, FIXTURE_RAID6, FIXTURE_SPARSE,
};
use crate::format;
use crate::volume::BtrfsVolume;

type Vol = Arc<BtrfsVolume<narf_block::SyncBlock>>;

fn read_phys(dev: &WritableSparseDevice, offset: u64, len: usize) -> Vec<u8> {
    let bs = u64::from(dev.lba_size());
    let mut buf = alloc::vec![0u8; len];
    dev.read(offset / bs, (len as u64 / bs) as u16, &mut buf)
        .unwrap();
    buf
}

fn write_phys(dev: &WritableSparseDevice, offset: u64, bytes: &[u8]) {
    let bs = u64::from(dev.lba_size());
    dev.write(offset / bs, (bytes.len() as u64 / bs) as u16, bytes)
        .unwrap();
}

/// Flip a byte inside `len` bytes at `offset`.
fn corrupt(dev: &WritableSparseDevice, offset: u64, len: usize) {
    let mut bytes = read_phys(dev, offset, len);
    bytes[200] ^= 0x5a;
    write_phys(dev, offset, &bytes);
}

/// The member whose superblock names `devid`.
fn member(devices: &[Arc<WritableSparseDevice>], devid: u64) -> Option<Arc<WritableSparseDevice>> {
    devices
        .iter()
        .find(|dev| {
            let sb = read_phys(dev, format::SUPERBLOCK_OFFSET, format::SUPERBLOCK_SIZE);
            format::le64(&sb, format::SUPERBLOCK_DEV_ITEM_OFFSET).ok() == Some(devid)
        })
        .cloned()
}

/// The first data sector of `payload.bin`: its logical address.
fn payload_sector(vol: &Vol) -> Result<u64, &'static str> {
    let payload = match poll_once(vol.root().lookup_async("payload.bin")) {
        Some(Ok(file)) => file,
        _ => return Err("payload missing"),
    };
    file_data_extent(vol, payload.ino())
        .map(|(logical, _)| logical)
        .ok_or("payload has no data extent")
}

fn payload_reads_back(vol: &Vol) -> bool {
    match poll_once(vol.root().lookup_async("payload.bin")) {
        Some(Ok(file)) => {
            read_all(&file, FIXTURE_SPARSE.len() + 1).as_deref() == Some(FIXTURE_SPARSE)
        }
        _ => false,
    }
}

/// Every direct copy of `logical` on `devices` holds `want`.
fn every_copy_is(
    vol: &Vol,
    devices: &[Arc<WritableSparseDevice>],
    logical: u64,
    want: &[u8],
) -> Result<(), &'static str> {
    let copies = vol.__test_copy_locations(logical);
    if copies.is_empty() {
        return Err("no copy of the sector");
    }
    for (devid, physical) in copies {
        let dev = member(devices, devid).ok_or("a copy on an unknown member")?;
        if read_phys(&dev, physical, want.len()) != want {
            return Err("a copy holds the corrupt bytes");
        }
    }
    Ok(())
}

/// Balance RAID1 → RAID1C3 with the first copy of a data sector and of the
/// fs-tree root corrupt: all three new copies are the good bytes.
fn balance_does_not_propagate() -> Result<(), &'static str> {
    let devices = writable_sparse_devices(FIXTURE_RAID1);
    let vol = mount_writable_devices(&devices).map_err(|_| "RAID1 fixture did not mount")?;
    let sector = vol.sectorsize() as usize;
    let ns = vol.nodesize();
    let data = payload_sector(&vol)?;
    let (node, _) = vol.fs_tree_root();
    let mut good = Vec::new();
    for (logical, len) in [(data, sector), (node, ns)] {
        let copies = vol.__test_copy_locations(logical);
        let [(bad_devid, bad_phys), (good_devid, good_phys)] = copies.as_slice() else {
            return Err("RAID1 is not two-copy");
        };
        let bad = member(&devices, *bad_devid).ok_or("unknown member")?;
        let ok = member(&devices, *good_devid).ok_or("unknown member")?;
        good.push(read_phys(&ok, *good_phys, len));
        corrupt(&bad, *bad_phys, len);
    }
    vol.__test_empty_node_cache();
    let third = blank_writable(devices[0].total);
    let third_async =
        narf_block::SyncBlock::new(third.clone() as Arc<dyn narf_block::BlockDeviceSync>);
    if !matches!(poll_once(vol.add_device(third_async)), Some(Ok(3))) {
        return Err("adding the third member failed");
    }
    let target = crate::volume::BalanceProfiles {
        data: Some(crate::chunk::ChunkProfile::Raid1C3),
        metadata: Some(crate::chunk::ChunkProfile::Raid1C3),
        system: Some(crate::chunk::ChunkProfile::Raid1C3),
    };
    match poll_once(vol.balance_profiles(target)) {
        Some(Ok(stats)) if stats.converted > 0 => {}
        _ => return Err("the RAID1C3 balance failed"),
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return Err("sync after the balance failed");
    }
    let members = alloc::vec![devices[0].clone(), devices[1].clone(), third];
    let after = mount_writable_devices(&members).map_err(|_| "balanced volume did not mount")?;
    every_copy_is(&after, &members, data, &good[0])?;
    every_copy_is(&after, &members, node, &good[1])?;
    if !payload_reads_back(&after) {
        return Err("the balanced payload reads back wrong");
    }
    Ok(())
}

fn smoke_btrfs_balance_does_not_propagate_a_corrupt_copy() -> TestResult {
    match balance_does_not_propagate() {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs/lifecycle",
    smoke_btrfs_balance_does_not_propagate_a_corrupt_copy
);

/// Replace the member holding a corrupt copy of a payload sector with a
/// blank device; the replacement holds the good bytes (repaired from the
/// mirror, or rebuilt from the RAID5/6 full stripe), every copy is good
/// after a remount, and the payload reads back. RAID0 has no good copy to
/// take: the replace fails rather than copy the corruption.
fn replace_does_not_propagate(fixture: &[&[u8]], redundant: bool) -> Result<(), &'static str> {
    let devices = writable_sparse_devices(fixture);
    let vol = mount_writable_devices(&devices).map_err(|_| "fixture did not mount")?;
    let sector = vol.sectorsize() as usize;
    let data = payload_sector(&vol)?;
    let copies = vol.__test_copy_locations(data);
    let &(bad_devid, bad_phys) = copies.first().ok_or("no copy of the sector")?;
    let bad = member(&devices, bad_devid).ok_or("unknown member")?;
    let good = read_phys(&bad, bad_phys, sector);
    corrupt(&bad, bad_phys, sector);
    vol.__test_empty_node_cache();
    let replacement = blank_writable(bad.total);
    let replacement_async =
        narf_block::SyncBlock::new(replacement.clone() as Arc<dyn narf_block::BlockDeviceSync>);
    let replaced = poll_once(vol.replace_device(bad_devid, replacement_async));
    if !redundant {
        return match replaced {
            Some(Err(FsError::InvalidData)) | Some(Err(FsError::Io(_))) => Ok(()),
            Some(Ok(())) => Err("RAID0 replace copied a sector that fails its checksum"),
            _ => Err("RAID0 replace of a corrupt sector did not fail cleanly"),
        };
    }
    if !matches!(replaced, Some(Ok(()))) {
        return Err("device replace failed");
    }
    if read_phys(&replacement, bad_phys, sector) != good {
        return Err("the replacement holds the corrupt bytes");
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return Err("sync after the replace failed");
    }
    let members: Vec<Arc<WritableSparseDevice>> = devices
        .iter()
        .map(|dev| {
            if Arc::ptr_eq(dev, &bad) {
                replacement.clone()
            } else {
                dev.clone()
            }
        })
        .collect();
    let after = mount_writable_devices(&members).map_err(|_| "replaced array did not mount")?;
    every_copy_is(&after, &members, data, &good)?;
    if !payload_reads_back(&after) {
        return Err("the replaced array's payload reads back wrong");
    }
    Ok(())
}

fn replace_result(fixture: &[&[u8]], redundant: bool) -> TestResult {
    match replace_does_not_propagate(fixture, redundant) {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}

fn smoke_btrfs_replace_raid1_does_not_propagate_a_corrupt_copy() -> TestResult {
    replace_result(FIXTURE_RAID1, true)
}
kernel_test_in!(
    "drivers/fs/btrfs/lifecycle",
    smoke_btrfs_replace_raid1_does_not_propagate_a_corrupt_copy
);

fn smoke_btrfs_replace_raid10_does_not_propagate_a_corrupt_copy() -> TestResult {
    replace_result(FIXTURE_RAID10, true)
}
kernel_test_in!(
    "drivers/fs/btrfs/lifecycle",
    smoke_btrfs_replace_raid10_does_not_propagate_a_corrupt_copy
);

fn smoke_btrfs_replace_raid5_rebuilds_a_corrupt_stripe() -> TestResult {
    replace_result(FIXTURE_RAID5, true)
}
kernel_test_in!(
    "drivers/fs/btrfs/lifecycle",
    smoke_btrfs_replace_raid5_rebuilds_a_corrupt_stripe
);

fn smoke_btrfs_replace_raid6_rebuilds_a_corrupt_stripe() -> TestResult {
    replace_result(FIXTURE_RAID6, true)
}
kernel_test_in!(
    "drivers/fs/btrfs/lifecycle",
    smoke_btrfs_replace_raid6_rebuilds_a_corrupt_stripe
);

fn smoke_btrfs_replace_raid0_refuses_a_corrupt_stripe() -> TestResult {
    replace_result(FIXTURE_RAID0, false)
}
kernel_test_in!(
    "drivers/fs/btrfs/lifecycle",
    smoke_btrfs_replace_raid0_refuses_a_corrupt_stripe
);

//! Read repair of a bad mirror copy (Linux `btrfs_repair_io_failure`): a
//! read that verified a good copy after a bad one rewrites the bad copy,
//! and nothing else — never on a read-only mount, never when both copies are
//! bad, never over a range rewritten or being written since the read.

use alloc::sync::Arc;
use alloc::vec::Vec;

use narf_block::BlockDeviceSync;
use narf_filesystem::{FsError, FsInstance};
use narf_kernel_test::{kernel_test_in, TestResult};

use super::{
    file_data_extent, mount_through_boot_only_guard, mount_writable, mount_writable_devices,
    poll_once, read_all, writable_sparse, writable_sparse_devices, WritableSparseDevice,
    FIXTURE_LAPTOP_SPARSE, FIXTURE_RAID1, FIXTURE_SPARSE,
};
use crate::format;
use crate::repair::{RateLimit, RepairHook, RepairStats};
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

/// Flip a byte inside the checksummed body of `len` bytes at `offset`.
fn corrupt(dev: &WritableSparseDevice, offset: u64, len: usize) {
    let mut bytes = read_phys(dev, offset, len);
    bytes[200] ^= 0x5a;
    write_phys(dev, offset, &bytes);
}

/// The laptop fixture (DUP metadata) mounted read-write, with the physical
/// copies of its fs-tree root node.
fn dup_fixture() -> Option<(Arc<WritableSparseDevice>, Vol, u64, u64, u64)> {
    let dev = writable_sparse(FIXTURE_LAPTOP_SPARSE);
    let vol = mount_writable(dev.clone()).ok()?;
    let (node, _) = vol.fs_tree_root();
    let copies = vol.__test_copy_locations(node);
    let [(_, first), (_, second)] = copies.as_slice() else {
        return None;
    };
    Some((dev, vol, node, *first, *second))
}

fn stats(vol: &Vol) -> RepairStats {
    vol.repair_stats()
}

/// DUP metadata: a tree node whose first copy fails its checksum is read
/// from the second, and the first copy is rewritten to equal it; the next
/// read takes the first copy and repairs nothing.
fn smoke_btrfs_repair_dup_metadata() -> TestResult {
    let Some((dev, vol, node, first, second)) = dup_fixture() else {
        return TestResult::Fail("laptop fixture: no DUP fs-tree root");
    };
    let ns = vol.nodesize();
    let good = read_phys(&dev, second, ns);
    corrupt(&dev, first, ns);
    vol.__test_empty_node_cache();
    let printed = crate::repair::CORRECTED_PRINTED.load(core::sync::atomic::Ordering::Relaxed);
    match poll_once(vol.read_node(node)) {
        Some(Ok(bytes)) if bytes == good => {}
        _ => return TestResult::Fail("read through a bad first copy did not return the good one"),
    }
    if read_phys(&dev, first, ns) != good {
        return TestResult::Fail("the bad first copy was not rewritten from the good one");
    }
    let after = stats(&vol);
    if after.repaired != 1 {
        return TestResult::Fail("repair counter did not count exactly one repair");
    }
    if crate::repair::CORRECTED_PRINTED.load(core::sync::atomic::Ordering::Relaxed) == printed
        && crate::repair::INFO_LIMIT.suppressed() == 0
    {
        return TestResult::Fail("no 'read error corrected' line for the repair");
    }
    // The next read is served by the first copy: nothing more to repair.
    vol.__test_empty_node_cache();
    match poll_once(vol.read_node(node)) {
        Some(Ok(bytes)) if bytes == good => {}
        _ => return TestResult::Fail("second read failed"),
    }
    if stats(&vol) != after {
        return TestResult::Fail("second read fell back to the mirror again");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_repair_dup_metadata);

/// RAID1 data with checksums: a sector whose first copy fails its data
/// checksum is read from the second member through the ordinary file read,
/// the first member's copy is rewritten, and the corruption is counted
/// against that member (`BTRFS_DEV_STAT_CORRUPTION_ERRS`).
fn smoke_btrfs_repair_raid1_data() -> TestResult {
    let devices = writable_sparse_devices(FIXTURE_RAID1);
    let vol = match mount_writable_devices(&devices) {
        Ok(vol) => vol,
        Err(_) => return TestResult::Fail("RAID1 fixture failed to mount writable"),
    };
    let payload = match poll_once(vol.root().lookup_async("payload.bin")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("RAID1 payload missing"),
    };
    let Some((logical, _)) = file_data_extent(&vol, payload.ino()) else {
        return TestResult::Fail("RAID1 payload has no data extent");
    };
    let copies = vol.__test_copy_locations(logical);
    let [(bad_devid, bad_phys), (good_devid, good_phys)] = copies.as_slice() else {
        return TestResult::Fail("RAID1 data is not two-copy");
    };
    // The member whose superblock names `devid`.
    let member = |devid: u64| {
        devices
            .iter()
            .find(|dev| {
                let sb = read_phys(dev, format::SUPERBLOCK_OFFSET, format::SUPERBLOCK_SIZE);
                format::le64(&sb, format::SUPERBLOCK_DEV_ITEM_OFFSET).ok() == Some(devid)
            })
            .cloned()
    };
    let (Some(bad_dev), Some(good_dev)) = (member(*bad_devid), member(*good_devid)) else {
        return TestResult::Fail("RAID1 devid outside the member list");
    };
    let sector = vol.sectorsize() as usize;
    let good = read_phys(&good_dev, *good_phys, sector);
    corrupt(&bad_dev, *bad_phys, sector);

    match read_all(&payload, FIXTURE_SPARSE.len() + 1) {
        Some(bytes) if bytes == FIXTURE_SPARSE => {}
        _ => return TestResult::Fail("RAID1 read through a bad copy returned wrong data"),
    }
    if read_phys(&bad_dev, *bad_phys, sector) != good {
        return TestResult::Fail("the bad RAID1 data copy was not rewritten");
    }
    if stats(&vol).repaired != 1 {
        return TestResult::Fail("RAID1 data repair not counted once");
    }
    let dev_stats = vol.dev_stats(*bad_devid);
    if dev_stats[crate::repair::DEV_STAT_CORRUPTION_ERRS] != 1
        || vol.dev_stats(*good_devid) != [0; 5]
    {
        return TestResult::Fail("data corruption not counted against the bad member");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_repair_raid1_data);

/// Both copies bad: the read fails with `InvalidData` and nothing is written.
fn smoke_btrfs_repair_both_copies_bad() -> TestResult {
    let Some((dev, vol, node, first, second)) = dup_fixture() else {
        return TestResult::Fail("laptop fixture: no DUP fs-tree root");
    };
    let ns = vol.nodesize();
    corrupt(&dev, first, ns);
    corrupt(&dev, second, ns);
    let before = dev.overlay.lock().clone();
    vol.__test_empty_node_cache();
    if !matches!(
        poll_once(vol.read_node(node)),
        Some(Err(FsError::InvalidData))
    ) {
        return TestResult::Fail("a node bad on both copies did not fail with InvalidData");
    }
    if *dev.overlay.lock() != before {
        return TestResult::Fail("a read with no good copy wrote to the device");
    }
    if stats(&vol) != RepairStats::default() {
        return TestResult::Fail("a read with no good copy attempted a repair");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_repair_both_copies_bad);

/// Read-only mount (a `narf.disks=boot-only` device): the good copy is
/// returned, the bad one stays as it is, nothing is written.
fn smoke_btrfs_repair_never_on_read_only() -> TestResult {
    let dev = writable_sparse(FIXTURE_LAPTOP_SPARSE);
    let vol = match mount_through_boot_only_guard(&dev) {
        Ok(vol) => vol,
        Err(_) => return TestResult::Fail("read-only laptop mount failed"),
    };
    if !vol.is_read_only() {
        return TestResult::Fail("boot-only mount is not read-only");
    }
    let (node, _) = vol.fs_tree_root();
    let copies = vol.__test_copy_locations(node);
    let [(_, first), (_, second)] = copies.as_slice() else {
        return TestResult::Fail("laptop fixture: no DUP fs-tree root");
    };
    let ns = vol.nodesize();
    let good = read_phys(&dev, *second, ns);
    corrupt(&dev, *first, ns);
    let before = dev.overlay.lock().clone();
    vol.__test_empty_node_cache();
    match poll_once(vol.read_node(node)) {
        Some(Ok(bytes)) if bytes == good => {}
        _ => return TestResult::Fail("read-only read through a bad copy failed"),
    }
    if *dev.overlay.lock() != before {
        return TestResult::Fail("a read-only mount repaired a mirror");
    }
    let s = stats(&vol);
    if s.repaired != 0 || s.skipped_read_only != 1 {
        return TestResult::Fail("read-only repair skip not counted");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_repair_never_on_read_only);

/// The range is freed, reallocated and rewritten between the bad read and
/// its repair (the hook rewrites both copies with another block's valid
/// bytes, as a later transaction would): the repair must not write.
fn smoke_btrfs_repair_skips_a_rewritten_range() -> TestResult {
    let Some((dev, vol, node, first, second)) = dup_fixture() else {
        return TestResult::Fail("laptop fixture: no DUP fs-tree root");
    };
    let ns = vol.nodesize();
    let good = read_phys(&dev, second, ns);
    corrupt(&dev, first, ns);
    // "Another block": the good bytes with a changed generation, restamped.
    let mut other = good.clone();
    let gen = format::le64(&other, 80).unwrap_or(0) + 1;
    if crate::write::stamp_node(&mut other, node, gen, vol.csum_type()).is_err() {
        return TestResult::Fail("could not stamp the replacement block");
    }
    // The reallocation rewrote only the good copy so far; the bad copy is
    // still the corrupt one. A repair that trusted its earlier read would
    // write the stale `good` over the bad copy.
    let hook_dev = dev.clone();
    let replacement = other.clone();
    vol.__test_set_repair_hook(Some(RepairHook(alloc::boxed::Box::new(move |_| {
        write_phys(&hook_dev, second, &replacement);
    }))));
    let corrupted = read_phys(&dev, first, ns);
    vol.__test_empty_node_cache();
    let read = poll_once(vol.read_node(node));
    vol.__test_set_repair_hook(None);
    if !matches!(read, Some(Ok(ref bytes)) if *bytes == good) {
        return TestResult::Fail("read through a bad copy failed");
    }
    if read_phys(&dev, first, ns) != corrupted {
        return TestResult::Fail("repair wrote over a range rewritten since the read");
    }
    let s = stats(&vol);
    if s.repaired != 0 || s.skipped_changed != 1 {
        return TestResult::Fail("changed-range skip not counted");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_repair_skips_a_rewritten_range
);

/// A write to the range is in flight (a commit's write-out of the block):
/// the repair stands aside and writes nothing.
fn smoke_btrfs_repair_skips_a_range_being_written() -> TestResult {
    let Some((dev, vol, node, first, second)) = dup_fixture() else {
        return TestResult::Fail("laptop fixture: no DUP fs-tree root");
    };
    let ns = vol.nodesize();
    let good = read_phys(&dev, second, ns);
    corrupt(&dev, first, ns);
    let corrupted = read_phys(&dev, first, ns);
    let Some(writing) = poll_once(vol.io_ranges.begin_write(node, ns as u64)) else {
        return TestResult::Fail("could not register the in-flight write");
    };
    vol.__test_empty_node_cache();
    let read = poll_once(vol.read_node(node));
    drop(writing);
    if !matches!(read, Some(Ok(ref bytes)) if *bytes == good) {
        return TestResult::Fail("read through a bad copy failed");
    }
    if read_phys(&dev, first, ns) != corrupted {
        return TestResult::Fail("repair wrote while a write to the range was in flight");
    }
    let s = stats(&vol);
    if s.repaired != 0 || s.skipped_busy != 1 || vol.io_ranges.in_flight() != (0, 0) {
        return TestResult::Fail("busy-range skip not counted, or a range left registered");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_repair_skips_a_range_being_written
);

/// A writer to a range under repair waits for the repair (and the repair
/// never waits for a writer).
fn smoke_btrfs_repair_holds_off_writers() -> TestResult {
    let ranges = crate::repair::IoRanges::default();
    let Some(repair) = ranges.try_begin_repair(4096, 4096) else {
        return TestResult::Fail("repair of an idle range refused");
    };
    let mut write = alloc::boxed::Box::pin(ranges.begin_write(6144, 512));
    let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
    if write.as_mut().poll(&mut cx).is_ready() {
        return TestResult::Fail("a write overlapping a repair did not wait");
    }
    // A disjoint write proceeds.
    if poll_once(ranges.begin_write(8192, 4096)).is_none() {
        return TestResult::Fail("a disjoint write waited for the repair");
    }
    drop(repair);
    let Poll::Ready(guard) = write.as_mut().poll(&mut cx) else {
        return TestResult::Fail("the held write did not proceed after the repair");
    };
    if ranges.try_begin_repair(6000, 1024).is_some() {
        return TestResult::Fail("a repair overlapping an in-flight write was allowed");
    }
    drop(guard);
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_repair_holds_off_writers);

use core::future::Future as _;
use core::task::Poll;

/// The repair message is rate-limited as `btrfs_info_rl` (burst, then
/// suppressed until the interval passes).
fn smoke_btrfs_repair_log_rate_limited() -> TestResult {
    let limit = RateLimit::new(u64::MAX / 2, 3);
    let allowed = (0..10).filter(|_| limit.allow()).count();
    if allowed != 3 || limit.suppressed() != 7 {
        return TestResult::Fail("rate limit did not cap the burst");
    }
    TestResult::Pass
}

kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_repair_log_rate_limited);

/// A mirror that is self-consistent but stale (a lost write: valid checksum
/// and bytenr, an older generation than the parent pointer records) fails
/// the parent's check like a checksum failure: the read takes the other
/// copy and rewrites the stale one (`btrfs_validate_extent_buffer` with a
/// `btrfs_tree_parent_check`, then `btrfs_repair_eb_io_failure`).
fn smoke_btrfs_repair_stale_generation_mirror() -> TestResult {
    let Some((dev, vol, node, first, second)) = dup_fixture() else {
        return TestResult::Fail("laptop fixture: no DUP fs-tree root");
    };
    let ns = vol.nodesize();
    let good = read_phys(&dev, second, ns);
    let gen = format::le64(&good, 80).unwrap_or(0);
    let mut stale = good.clone();
    if crate::write::stamp_node(&mut stale, node, gen - 1, vol.csum_type()).is_err() {
        return TestResult::Fail("could not stamp the stale copy");
    }
    write_phys(&dev, first, &stale);
    vol.__test_empty_node_cache();
    let check = |b: &[u8]| format::le64(b, 80).ok() == Some(gen);
    match poll_once(vol.read_node_expecting(node, Some(&check))) {
        Some(Ok(bytes)) if *bytes == good => {}
        _ => return TestResult::Fail("read past a stale mirror did not return the current copy"),
    }
    if read_phys(&dev, first, ns) != good {
        return TestResult::Fail("the stale mirror was not rewritten");
    }
    if stats(&vol).repaired != 1 {
        return TestResult::Fail("stale-mirror repair not counted once");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_repair_stale_generation_mirror
);

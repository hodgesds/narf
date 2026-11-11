//! The driver's own caches stay bounded in bytes, give memory back to the
//! reclaim shrinker, and its per-inode tables track open files rather than
//! every file ever touched.

use super::*;
use alloc::collections::BTreeSet;
use narf_filesystem::FsInstance;

const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// The budgets are the stated fraction of RAM with their floor and ceiling.
fn smoke_btrfs_cache_budgets_follow_ram() -> TestResult {
    use crate::cache_budget::{DATA_CACHE, NODE_CACHE};
    let cases: [(Option<u64>, usize, usize); 6] = [
        (Some(256 * MIB), 4 << 20, 4 << 20),
        (Some(4 * GIB), 32 << 20, 32 << 20),
        (Some(16 * GIB), 128 << 20, 128 << 20),
        (Some(64 * GIB), 256 << 20, 128 << 20),
        (Some(1024 * GIB), 256 << 20, 128 << 20),
        (None, 32 << 20, 32 << 20),
    ];
    for (ram, nodes, data) in cases {
        if NODE_CACHE.of(ram) != nodes {
            return TestResult::Fail("node cache budget is not RAM/128 within 4..256 MiB");
        }
        if DATA_CACHE.of(ram) != data {
            return TestResult::Fail("extent-data budget is not RAM/128 within 4..128 MiB");
        }
    }
    let ram = crate::cache_budget::total_ram_bytes();
    if ram.is_none() {
        return TestResult::Fail("the kernel reported no RAM to size caches from");
    }
    if crate::decompress_cache::budget_bytes() != DATA_CACHE.of(ram) {
        return TestResult::Fail("extent-data cache is not sized from this machine's RAM");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs/cache",
    smoke_btrfs_cache_budgets_follow_ram
);

/// The node cache stays within its byte budget and its shrink releases the
/// old generation first, never more than asked.
fn smoke_btrfs_node_cache_bytes_and_shrink() -> TestResult {
    match crate::volume::__test_node_cache_bytes_and_shrink() {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs/cache",
    smoke_btrfs_node_cache_bytes_and_shrink
);

/// A mounted filesystem's node cache is registered with reclaim, stays
/// within its budget after reading every file of the fixture, and the
/// shrinker gives its bytes back.
fn smoke_btrfs_node_cache_reclaimable() -> TestResult {
    let vol = match mount_fixture() {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    if !vol.__test_node_cache_registered() {
        return TestResult::Fail("mounted node cache not registered with the shrinker");
    }
    let root = vol.root();
    for i in 0..64 {
        let name = alloc::format!("nc-{i}");
        let file = match poll_once(root.create(&name)) {
            Some(Ok(f)) => f,
            _ => return TestResult::Fail("create failed"),
        };
        if !matches!(poll_once(file.write(0, name.as_bytes())), Some(Ok(_))) {
            return TestResult::Fail("write failed");
        }
    }
    let (bytes, budget) = vol.__test_node_cache_bytes();
    if bytes == 0 || bytes > budget {
        return TestResult::Fail("node cache empty after a workload, or over its budget");
    }
    let (count, freed) = crate::volume::__test_node_shrinker(1);
    if count < bytes / 4096 || freed > 1 {
        return TestResult::Fail("node shrinker miscounted or freed more than its share");
    }
    let (_, freed) = crate::volume::__test_node_shrinker(count);
    if freed == 0 || freed > count {
        return TestResult::Fail("node shrinker freed nothing, or more than asked");
    }
    if vol.__test_node_cache_bytes().0 >= bytes {
        return TestResult::Fail("node shrinker left this filesystem's cache as it was");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs/cache", smoke_btrfs_node_cache_reclaimable);

/// Filling the extent-data cache with twice its budget of maximal windows
/// keeps it within the budget in bytes, and the shrinker releases least
/// recently used entries without exceeding its share.
fn smoke_btrfs_extent_data_cache_bytes_and_shrink() -> TestResult {
    use crate::decompress_cache::{self as cache, ExtentId, VolumeRef};
    let owner: Arc<dyn core::any::Any + Send + Sync> = Arc::new(0u64);
    let handle = VolumeRef::new(Arc::downgrade(&owner));
    let budget = cache::budget_bytes();
    let span = cache::MAX_DISK_BYTES;
    let windows = 2 * budget as u64 / span;
    for i in 0..windows {
        let id = ExtentId {
            disk_bytenr: (1 << 32) + i * span,
            disk_num_bytes: span,
            compression: format::COMPRESS_NONE,
            generation: 1,
        };
        let plain = Arc::new(alloc::vec![i as u8; span as usize]);
        cache::insert(&handle, id, cache::epoch(&handle), plain);
        if cache::cached_total().0 > budget {
            return TestResult::Fail("extent-data cache outgrew its byte budget");
        }
    }
    let ours = cache::cached_bytes_for(&handle);
    if ours < budget / 2 {
        return TestResult::Fail("extent-data cache kept far less than its budget");
    }
    let (count, freed) = cache::__test_shrinker(1);
    if count == 0 || freed != 0 {
        return TestResult::Fail("a one-page share freed a 128 KiB window");
    }
    let (_, freed) = cache::__test_shrinker(64);
    if freed == 0 || freed > 64 || cache::cached_bytes_for(&handle) >= ours {
        return TestResult::Fail("shrinker freed nothing, or more than its share");
    }
    let (count, _) = cache::__test_shrinker(0);
    let (_, freed) = cache::__test_shrinker(count + 1);
    if freed > count + 1 || cache::cached_total().1 != 0 {
        return TestResult::Fail("a full shrink left entries behind");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs/cache",
    smoke_btrfs_extent_data_cache_bytes_and_shrink
);

/// Creating, mapping-generation-sampling and deleting many files
/// leaves the anchor and generation tables as they were; closing files
/// without deleting them does too; and a file reopened after its entry was
/// forgotten gets a generation no earlier file ever had.
fn smoke_btrfs_inode_tables_track_open_files() -> TestResult {
    // Enough to show the tables do not grow with closed files (before this
    // they gained an entry per file). The fixtures' metadata space takes
    // this many operations only in several transactions, so the test
    // commits every `PER_COMMIT` files, on the larger free-space-tree
    // fixture the batch tests use.
    const FILES: usize = 64;
    const PER_COMMIT: usize = 8;
    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("fixture failed to mount"),
    };
    let root = vol.root();
    let kept = match poll_once(root.create("tables-kept.dat")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("create tables-kept.dat failed"),
    };
    let Some(kept_generation) = kept.mmap_cache_generation() else {
        return TestResult::Fail("regular file reports no cache generation");
    };
    let baseline = vol.__test_inode_table_sizes();
    let mut issued = BTreeSet::new();
    issued.insert(kept_generation);
    for round in 0..2 {
        for i in 0..FILES {
            let name = alloc::format!("tables-{i}");
            let file = match poll_once(root.create(&name)) {
                Some(Ok(f)) => f,
                _ => return TestResult::Fail("create failed"),
            };
            // Data only where the reopen below reads it back: the small
            // fixture has room for few data extents.
            if i == 0 && !matches!(poll_once(file.write(0, name.as_bytes())), Some(Ok(_))) {
                return TestResult::Fail("write failed");
            }
            match file.mmap_cache_generation() {
                Some(generation) if issued.insert(generation) => {}
                _ => return TestResult::Fail("a file was issued a generation seen before"),
            }
            drop(file);
            // The second round leaves the files in place: closing alone
            // must forget them too.
            if round == 0 && !matches!(poll_once(root.unlink(&name)), Some(Ok(()))) {
                return TestResult::Fail("unlink failed");
            }
            if (i + 1) % PER_COMMIT == 0 && !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
                return TestResult::Fail("commit failed");
            }
        }
        if vol.__test_inode_table_sizes() != baseline {
            return TestResult::Fail("anchor or generation table grew with closed files");
        }
    }
    // Reopen a closed file: its entry is gone, so it gets a fresh value.
    let reopened = match poll_once(root.lookup_async("tables-0")) {
        Some(Ok(f)) => f,
        _ => return TestResult::Fail("lookup tables-0 failed"),
    };
    match reopened.mmap_cache_generation() {
        Some(generation) if !issued.contains(&generation) => {}
        _ => return TestResult::Fail("a reopened file reused a generation"),
    }
    if read_all(&reopened, 16).as_deref() != Some(b"tables-0".as_slice()) {
        return TestResult::Fail("reopened file reads wrong bytes");
    }
    drop(reopened);
    // The file kept open throughout kept its generation.
    if kept.mmap_cache_generation() != Some(kept_generation) {
        return TestResult::Fail("other files' churn moved an open file's generation");
    }
    for i in 0..FILES {
        let name = alloc::format!("tables-{i}");
        if !matches!(poll_once(root.unlink(&name)), Some(Ok(()))) {
            return TestResult::Fail("cleanup unlink failed");
        }
        if (i + 1) % PER_COMMIT == 0 && !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
            return TestResult::Fail("cleanup commit failed");
        }
    }
    if vol.__test_inode_table_sizes() != baseline {
        return TestResult::Fail("anchor or generation table grew with deleted files");
    }
    drop(kept);
    let (anchors, generations) = vol.__test_inode_table_sizes();
    if anchors >= baseline.0 || generations >= baseline.1 {
        return TestResult::Fail("closing the last file left its entries behind");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/fs/btrfs/cache",
    smoke_btrfs_inode_tables_track_open_files
);

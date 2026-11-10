use super::*;
use narf_filesystem::FsInstance;

/// A small workload that fits this fixture still amortizes its commit once.
/// The separate full-cap workloads exercise metadata-pressure reclamation;
/// they may need several transactions to preserve commit space.
fn smoke_btrfs_small_batch_commits_once() -> TestResult {
    let vol = match mount_sparse(FIXTURE_FST_SPARSE) {
        Ok(v) => v,
        _ => return TestResult::Fail("batch fixture did not mount"),
    };
    let root = vol.root();
    if !matches!(poll_once(root.create("warmup")), Some(Ok(_)))
        || !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
    {
        return TestResult::Fail("batch warmup failed");
    }
    let before = vol.superblock().generation;
    for i in 0..crate::write::MAX_BATCH_OPS.min(8) {
        if !matches!(
            poll_once(root.create(&alloc::format!("small-{i}"))),
            Some(Ok(_))
        ) {
            return TestResult::Fail("small batch create failed");
        }
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(())))
        || vol.superblock().generation != before + 1
    {
        return TestResult::Fail("small batch did not commit exactly once");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/fs/btrfs", smoke_btrfs_small_batch_commits_once);

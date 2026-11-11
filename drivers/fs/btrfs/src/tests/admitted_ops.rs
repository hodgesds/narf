//! No operation reported successful may be lost at commit: admission must
//! refuse with ENOSPC what the commit could not fit.

use super::*;
use narf_filesystem::FsInstance;

/// Create, write and unlink files in one transaction (and, second, with a
/// commit every 8 files) on a small fixture until something says no. Each
/// operation must either be refused up front or survive its commit: a
/// commit that fails with operations already reported successful loses
/// acknowledged data (Linux reserves metadata before admitting an
/// operation, `btrfs_reserve_metadata_bytes`, and the commit draws on the
/// global reserve).
fn churn(
    vol: &Arc<BtrfsVolume<narf_block::ram::RamBlockDevice>>,
    files: usize,
    per_commit: usize,
    label: &str,
) -> Result<(), &'static str> {
    use core::fmt::Write as _;
    let root = vol.root();
    let mut refused = None;
    for i in 0..files {
        let name = alloc::format!("churn-{label}-{i}");
        let step = (|| -> Result<(), FsError> {
            let file = poll_once(root.create(&name)).ok_or(FsError::InvalidData)??;
            let n = poll_once(file.write(0, name.as_bytes())).ok_or(FsError::InvalidData)??;
            if n != name.len() {
                return Err(FsError::InvalidData);
            }
            drop(file);
            poll_once(root.unlink(&name)).ok_or(FsError::InvalidData)??;
            Ok(())
        })();
        if let Err(error) = step {
            refused = Some((i, error));
            break;
        }
        if (i + 1) % per_commit == 0 {
            match poll_once(vol.sync_to_disk()) {
                Some(Ok(())) => {}
                other => {
                    let _ = writeln!(
                        narf_console::Writer,
                        "btrfs-admit: {label}: commit after file {i} failed: {other:?}"
                    );
                    return Err(
                        "admit: a commit failed after its operations were reported successful",
                    );
                }
            }
        }
    }
    let synced = poll_once(vol.sync_to_disk());
    let _ = writeln!(
        narf_console::Writer,
        "btrfs-admit: {label}: refused {refused:?}, final commit {synced:?}, writable {}",
        vol.supports_writes()
    );
    if !matches!(synced, Some(Ok(()))) {
        return Err("admit: the final commit failed after its operations were reported successful");
    }
    if let Some((_, error)) = refused {
        if error != FsError::NoSpace {
            return Err("admit: an operation failed other than with ENOSPC");
        }
    }
    Ok(())
}

fn smoke_btrfs_admitted_operations_survive_commit() -> TestResult {
    for (sparse, label, files, per_commit) in [
        (FIXTURE_FST_SPARSE, "fst-every-8", 200, 8),
        (FIXTURE_FST_SPARSE, "fst-one-batch", 300usize, usize::MAX),
        (FIXTURE_SPARSE, "primary-one-batch", 300, usize::MAX),
    ] {
        let vol = match mount_sparse(sparse) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("admit: fixture failed to mount"),
        };
        if let Err(e) = churn(&vol, files, per_commit, label) {
            return TestResult::Fail(e);
        }
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_admitted_operations_survive_commit
);

//! `fsync` beside running operations: it waits for the operation in flight,
//! not for the queue behind it; it returns at once for a file with nothing
//! new; and concurrent `fsync`s share one commit.

use super::*;
use narf_filesystem::{FileOps, FsFuture, FsInstance};

fn commits<B: narf_block::BlockDevice>(vol: &BtrfsVolume<B>) -> u64 {
    vol.commit_stats()
        .commits
        .load(core::sync::atomic::Ordering::Relaxed)
}

fn create(
    vol: &Arc<BtrfsVolume<narf_block::ram::RamBlockDevice>>,
    name: &str,
) -> Result<Arc<dyn FileOps>, &'static str> {
    let file = poll_once(vol.root().create(name))
        .and_then(|r| r.ok())
        .ok_or("create failed")?;
    match poll_once(file.write(0, b"first")) {
        Some(Ok(5)) => Ok(file),
        _ => Err("seed write failed"),
    }
}

fn check() -> Result<(), &'static str> {
    let vol = mount_sparse(FIXTURE_FST_SPARSE).map_err(|_| "fixture did not mount")?;
    let clean = create(&vol, "clean.dat")?;
    let dirty = create(&vol, "dirty.dat")?;
    let other = create(&vol, "other.dat")?;
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return Err("initial sync failed");
    }

    // Operations queued behind the one at the head of `op_lock` are not
    // waited for: with the queue held, an fsync of a changed file commits.
    if !matches!(poll_once(dirty.write(0, b"second")), Some(Ok(6))) {
        return Err("write failed");
    }
    let before = commits(&vol);
    {
        let _queue = poll_once(vol.op_lock().lock()).ok_or("operation queue busy")?;
        match poll_once(dirty.fsync(false)) {
            Some(Ok(())) => {}
            Some(Err(_)) => return Err("fsync behind the operation queue failed"),
            None => return Err("fsync waited for the operations queued behind the running one"),
        }
    }
    if commits(&vol) != before + 1 {
        return Err("fsync of a changed file did not commit exactly once");
    }

    // A running operation is waited for, but a file with nothing new to
    // make durable is not: its fsync returns without a commit.
    if !matches!(poll_once(dirty.write(0, b"third")), Some(Ok(5))) {
        return Err("write failed");
    }
    if !matches!(poll_once(other.write(0, b"fourth")), Some(Ok(6))) {
        return Err("write failed");
    }
    let before = commits(&vol);
    let running = poll_once(vol.commit_excl().lock()).ok_or("commit lock busy")?;
    match poll_once(clean.fsync(false)) {
        Some(Ok(())) => {}
        Some(Err(_)) => return Err("fsync of an unchanged file failed"),
        None => return Err("fsync of an unchanged file waited for a running operation"),
    }
    let mut first: FsFuture<'_, ()> = dirty.fsync(false);
    let mut second: FsFuture<'_, ()> = other.fsync(true);
    if poll_once(first.as_mut()).is_some() || poll_once(second.as_mut()).is_some() {
        return Err("fsync committed beneath a running operation");
    }
    // An operation that arrives while those commits wait waits for them.
    let mut late = dirty.write(0, b"fifth");
    if poll_once(late.as_mut()).is_some() {
        return Err("a write ran beneath a running operation");
    }
    drop(running);
    if !matches!(poll_once(first.as_mut()), Some(Ok(()))) {
        return Err("first fsync failed once the operation finished");
    }
    if !matches!(poll_once(second.as_mut()), Some(Ok(()))) {
        return Err("second fsync failed once the operation finished");
    }
    if commits(&vol) != before + 1 {
        return Err("two concurrent fsyncs did not share one commit");
    }
    if !matches!(poll_once(late.as_mut()), Some(Ok(5))) {
        return Err("the write queued behind the commits failed");
    }
    // That write is not durable yet; the file's fsync commits it.
    let before = commits(&vol);
    if !matches!(poll_once(dirty.fsync(false)), Some(Ok(()))) || commits(&vol) != before + 1 {
        return Err("fsync after a later write did not commit it");
    }
    let before = commits(&vol);
    if !matches!(poll_once(clean.fsync(false)), Some(Ok(()))) || commits(&vol) != before {
        return Err("fsync of an unchanged file committed");
    }

    // The file holds the last write.
    let mut buf = [0u8; 5];
    if !matches!(poll_once(dirty.read(0, &mut buf)), Some(Ok(5))) || &buf != b"fifth" {
        return Err("read after the fsyncs returned the wrong bytes");
    }
    Ok(())
}

/// `fsync` beside a running operation (Linux `btrfs_sync_file` joining the
/// running transaction's commit).
fn smoke_btrfs_fsync_waits_for_the_running_operation_only() -> TestResult {
    match check() {
        Ok(()) => TestResult::Pass,
        Err(e) => TestResult::Fail(e),
    }
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_fsync_waits_for_the_running_operation_only
);

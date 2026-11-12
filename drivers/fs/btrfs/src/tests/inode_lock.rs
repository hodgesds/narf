//! A long truncate lets other operations run between its steps, and keeps
//! other changes of the same file out until it is done.

use super::*;
use narf_filesystem::FsInstance;

type LockVol = Arc<BtrfsVolume<narf_block::SyncBlock>>;

/// Poll `future` once with a waker that does nothing.
fn poll_step<T>(future: &mut narf_filesystem::FsFuture<'_, T>) -> Option<Result<T, FsError>> {
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
    fn raw_waker() -> RawWaker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            raw_waker()
        }
        unsafe fn no_op(_: *const ()) {}
        const VTABLE: RawWakerVTable = RawWakerVTable::new(clone, no_op, no_op, no_op);
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    // SAFETY: the no-op vtable never dereferences the null data pointer.
    let waker = unsafe { Waker::from_raw(raw_waker()) };
    let mut context = Context::from_waker(&waker);
    match future.as_mut().poll(&mut context) {
        Poll::Ready(value) => Some(value),
        Poll::Pending => None,
    }
}

/// `@` of the tall fixture with room, and a file of `pages` single-page
/// extents named `name`.
fn long_file(
    name: &str,
    pages: usize,
) -> Result<(LockVol, Arc<dyn narf_filesystem::FileOps>), &'static str> {
    let vol = mount_writable(writable_sparse(FIXTURE_TALL_SPARSE))
        .map_err(|_| "lock: fixture did not mount")?;
    if poll_once(vol.switch_to_subvol(&crate::volume::Subvol::Name("@".into())))
        .is_none_or(|r| r.is_err())
    {
        return Err("subvol @ did not resolve");
    }
    for kind in [format::BLOCK_GROUP_DATA, format::BLOCK_GROUP_METADATA] {
        if !matches!(
            poll_once(crate::write::alloc_chunk(&vol, kind)),
            Some(Ok(()))
        ) {
            return Err("lock: chunk allocation failed");
        }
    }
    let file = match poll_once(vol.root().create(name)) {
        Some(Ok(file)) => file,
        _ => return Err("lock: create failed"),
    };
    let page = [0x5au8; 4096];
    for index in 0..pages {
        if !matches!(
            poll_once(file.write((index * 4096) as u64, &page)),
            Some(Ok(4096))
        ) {
            return Err("lock: write failed");
        }
    }
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return Err("lock: sync failed");
    }
    Ok((vol, file))
}

/// A truncate's steps do not wait in the operation queue: with `op_lock`
/// held (operations queued for it), a truncate over many extents still
/// runs to the end, a step at a time, as an `fsync` would (Linux's
/// `btrfs_truncate` joins the running transaction per step instead of
/// queueing behind every writer of the filesystem).
fn smoke_btrfs_truncate_steps_skip_the_operation_queue() -> TestResult {
    let (vol, long) = match long_file("queued", 2000) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    let Some(queue) = poll_once(vol.op_lock().lock()) else {
        return TestResult::Fail("lock: operation queue busy");
    };
    let mut truncate = long.truncate(0);
    let mut polls = 0u32;
    let done = loop {
        polls += 1;
        if let Some(result) = poll_step(&mut truncate) {
            break result;
        }
        if polls > 1_000_000 {
            return TestResult::Fail("lock: the truncate waited in the operation queue");
        }
    };
    drop(truncate);
    drop(queue);
    if done.is_err() || !matches!(poll_once(long.stat_async()), Some(Ok(stat)) if stat.size == 0) {
        return TestResult::Fail("lock: the truncate failed");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_truncate_steps_skip_the_operation_queue
);

/// A truncate over many extents excludes the running operation one step
/// at a time and yields between steps (Linux ends its transaction and may
/// reschedule there), so a write, a read and a stat of another file
/// complete while it is in progress; before, the whole truncate held the
/// lock and every other operation of the filesystem waited for it.
fn smoke_btrfs_truncate_steps_let_others_run() -> TestResult {
    let (vol, long) = match long_file("long", 2000) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    let other = match poll_once(vol.root().create("other")) {
        Some(Ok(file)) => file,
        _ => return TestResult::Fail("lock: create failed"),
    };
    let mut truncate = long.truncate(0);
    if poll_step(&mut truncate).is_some() {
        return TestResult::Fail("lock: the truncate did not yield between its steps");
    }
    let body = [0x77u8; 8192];
    let mut got = [0u8; 8192];
    if !matches!(poll_once(other.write(0, &body)), Some(Ok(8192)))
        || !matches!(poll_once(other.read(0, &mut got)), Some(Ok(8192)))
        || got != body
        || !matches!(poll_once(other.stat_async()), Some(Ok(_)))
    {
        return TestResult::Fail(
            "lock: another file's operations did not complete during the truncate",
        );
    }
    let mut polls = 1u32;
    let done = loop {
        polls += 1;
        if let Some(result) = poll_step(&mut truncate) {
            break result;
        }
        if polls > 1_000_000 {
            return TestResult::Fail("lock: the truncate did not finish");
        }
    };
    drop(truncate);
    if done.is_err() || !matches!(poll_once(long.stat_async()), Some(Ok(stat)) if stat.size == 0) {
        return TestResult::Fail("lock: the truncate failed");
    }
    if polls < 10 {
        return TestResult::Fail(
            "lock: the truncate ran in too few polls to have yielded per step",
        );
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_truncate_steps_let_others_run
);

/// Two truncates of one file run one after the other (Linux `inode_lock`):
/// the second waits while the first is between steps, then runs on what the
/// first left. The file ends at the second's size, all zeros.
fn smoke_btrfs_truncates_of_one_file_serialize() -> TestResult {
    let (_vol, file) = match long_file("same", 2000) {
        Ok(v) => v,
        Err(e) => return TestResult::Fail(e),
    };
    let mut first = file.truncate(0);
    if poll_step(&mut first).is_some() {
        return TestResult::Fail("lock: the first truncate did not yield between its steps");
    }
    let mut second = file.truncate(40960);
    let mut waited = 0u32;
    let first_done = loop {
        if poll_step(&mut second).is_some() {
            return TestResult::Fail(
                "lock: the second truncate ran while the first was in progress",
            );
        }
        waited += 1;
        if let Some(result) = poll_step(&mut first) {
            break result;
        }
        if waited > 1_000_000 {
            return TestResult::Fail("lock: the first truncate did not finish");
        }
    };
    drop(first);
    if first_done.is_err() {
        return TestResult::Fail("lock: the first truncate failed");
    }
    let mut polls = 0u32;
    let second_done = loop {
        if let Some(result) = poll_step(&mut second) {
            break result;
        }
        polls += 1;
        if polls > 1_000_000 {
            return TestResult::Fail("lock: the second truncate did not finish");
        }
    };
    drop(second);
    let mut got = [0xffu8; 4096];
    if second_done.is_err()
        || !matches!(poll_once(file.stat_async()), Some(Ok(stat)) if stat.size == 40960)
        || !matches!(poll_once(file.read(36864, &mut got)), Some(Ok(4096)))
        || got.iter().any(|&b| b != 0)
    {
        return TestResult::Fail("lock: the file is not what the second truncate left");
    }
    if waited < 2 {
        return TestResult::Fail("lock: the second truncate never had to wait");
    }
    TestResult::Pass
}

kernel_test_in!(
    "drivers/fs/btrfs",
    smoke_btrfs_truncates_of_one_file_serialize
);

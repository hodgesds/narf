//! The commit hand-over (Linux `TRANS_STATE_UNBLOCKED`): a commit's trees are
//! frozen and published before its write-out, and the next transaction opens
//! while the previous one is still being written.

use super::*;

/// A frozen commit's nodes stay in the node cache as dirty entries for its
/// whole write-out ([`crate::volume::__test_node_cache_dirty_entries`]).
fn smoke_btrfs_node_cache_keeps_dirty_nodes() -> TestResult {
    match crate::volume::__test_node_cache_dirty_entries() {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs/commit",
    smoke_btrfs_node_cache_keeps_dirty_nodes
);

/// Poll `future` up to `polls` times; its output if it finished.
fn poll_n<F: core::future::Future + ?Sized>(
    mut future: core::pin::Pin<&mut F>,
    polls: u32,
) -> Option<F::Output> {
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
    for _ in 0..polls {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return Some(value);
        }
    }
    None
}

/// The device as a crash at this instant would leave it.
fn crash_image(device: &WritableSparseDevice) -> Arc<WritableSparseDevice> {
    Arc::new(WritableSparseDevice {
        runs: device.runs.clone(),
        total: device.total,
        lba_size: device.lba_size,
        reads: core::sync::atomic::AtomicUsize::new(0),
        overlay: narf_lib::sync::IrqSafeSpinLock::new(device.overlay.lock().clone()),
    })
}

/// Hold every write-out until the guard drops.
struct HoldWriteOut;

impl HoldWriteOut {
    fn new() -> Self {
        use core::sync::atomic::Ordering;
        crate::volume::WRITE_OUT_HELD.store(false, Ordering::Release);
        crate::volume::WRITE_OUT_HOLD.store(true, Ordering::Release);
        HoldWriteOut
    }

    fn held() -> bool {
        crate::volume::WRITE_OUT_HELD.load(core::sync::atomic::Ordering::Acquire)
    }
}

impl Drop for HoldWriteOut {
    fn drop(&mut self) {
        crate::volume::WRITE_OUT_HOLD.store(false, core::sync::atomic::Ordering::Release);
    }
}

/// A commit publishes before its write-out, and the write-out belongs to the
/// filesystem from then on: a committer cancelled while its nodes are still
/// going out leaves the write-out queued — the commit visible, nothing of
/// it durable — and the next sync finishes it, superblock and all.
fn cancelled_write_out_is_finished() -> Result<(), &'static str> {
    use narf_filesystem::FsInstance;
    let device = writable_sparse(FIXTURE_FST_SPARSE);
    let vol = mount_writable(device.clone()).map_err(|_| "fixture did not mount")?;
    let base = vol.superblock().generation;
    if !matches!(poll_once(vol.root().create("kept")), Some(Ok(_))) {
        return Err("create failed");
    }
    {
        let hold = HoldWriteOut::new();
        let mut sync = alloc::boxed::Box::pin(vol.sync_to_disk());
        if poll_n(sync.as_mut(), 64).is_some() {
            return Err("the sync finished with its write-out held");
        }
        if !HoldWriteOut::held() {
            return Err("the sync never reached its write-out");
        }
        drop(sync);
        drop(hold);
    }
    if vol.superblock().generation != base + 1 {
        return Err("the commit did not publish before its write-out");
    }
    if vol.durable_gen() != base || !vol.write_out_pending() {
        return Err("a cancelled write-out was lost or reported durable");
    }
    // A crash now falls back to the last durable generation.
    let cut = mount_writable(crash_image(&device)).map_err(|_| "crash image did not mount")?;
    if cut.superblock().generation != base {
        return Err("a crash mid write-out did not fall back to the durable generation");
    }
    if poll_once(cut.root().lookup_async("kept")).is_some_and(|r| r.is_ok()) {
        return Err("a crash mid write-out kept an unwritten commit");
    }
    drop(cut);
    if !matches!(poll_once(vol.sync_to_disk()), Some(Ok(()))) {
        return Err("the next sync failed");
    }
    if vol.durable_gen() != base + 1 || vol.write_out_pending() {
        return Err("the next sync did not finish the cancelled write-out");
    }
    let after = mount_writable(crash_image(&device)).map_err(|_| "remount failed")?;
    if after.superblock().generation != base + 1 {
        return Err("the finished write-out's superblock is not on the device");
    }
    if !poll_once(after.root().lookup_async("kept")).is_some_and(|r| r.is_ok()) {
        return Err("the finished write-out lost its commit");
    }
    Ok(())
}

fn smoke_btrfs_cancelled_write_out_is_finished_by_the_next_sync() -> TestResult {
    match cancelled_write_out_is_finished() {
        Ok(()) => TestResult::Pass,
        Err(why) => TestResult::Fail(why),
    }
}
kernel_test_in!(
    "drivers/fs/btrfs/commit",
    smoke_btrfs_cancelled_write_out_is_finished_by_the_next_sync
);

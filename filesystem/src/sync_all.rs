//! System-wide sync — Linux `fs/sync.c::ksys_sync`.
//!
//! ```text
//! void ksys_sync(void)
//! {
//!         wakeup_flusher_threads(WB_REASON_SYNC);
//!         iterate_supers(sync_inodes_one_sb, NULL);
//!         iterate_supers(sync_fs_one_sb, &nowait);
//!         iterate_supers(sync_fs_one_sb, &wait);
//!         sync_bdevs(false);
//!         sync_bdevs(true);
//! }
//! ```
//!
//! NARF's filesystems have no separate writeback thread: a filesystem with
//! dirty state commits it from its `syncfs` hook (btrfs: a full transaction
//! commit plus device flush). So the walk here is one `syncfs` per superblock
//! — every filesystem mounted anywhere, deduplicated
//! ([`crate::all_mounted_filesystems`]) — followed by one cache flush per
//! physical disk that this boot may have written.
//!
//! Two callers: `sync(2)`, and the pre-shutdown step `narf_power::system`
//! runs before the device shutdown hooks (NVMe Flush + CC.SHN) on every
//! reboot / power-off / halt.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::{FsError, FsInstance};

/// What one [`sync_all`] pass did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    /// Distinct filesystems whose `syncfs` was called.
    pub filesystems: usize,
    /// Of those, how many returned an error.
    pub fs_errors: usize,
    /// Disks whose volatile write cache was flushed.
    pub disks_flushed: usize,
    /// Of those, how many flushes failed.
    pub flush_errors: usize,
}

/// `syncfs` one filesystem through its root (or, for a file-rooted mount,
/// its root file).
pub async fn sync_one(fs: &Arc<dyn FsInstance>) -> Result<(), FsError> {
    match fs.root_file() {
        Some(file) => file.syncfs().await,
        None => fs.root().syncfs().await,
    }
}

/// `iterate_supers(sync_fs_one_sb, &wait)` over `filesystems`: every one is
/// synced even if an earlier one fails (Linux `sync(2)` ignores per-sb
/// errors). Returns `(synced, failed)`.
pub async fn sync_filesystems(filesystems: &[Arc<dyn FsInstance>]) -> (usize, usize) {
    let mut failed = 0;
    for fs in filesystems {
        if sync_one(fs).await.is_err() {
            failed += 1;
        }
    }
    (filesystems.len(), failed)
}

/// `sync_bdevs(true)`: flush the volatile write cache of every disk this boot
/// can have written. One flush per physical disk ([`narf_block::disk_policy::DiskId`]) —
/// a partition's flush is the disk's flush — sent through an entry the
/// `narf.disks` policy currently lets write. A disk with no writable entry
/// never received a write from this kernel, so there is nothing of ours in
/// its cache and it is left alone. Returns `(flushed, failed)`.
pub fn flush_block_devices() -> (usize, usize) {
    let devices = narf_block::block_devices();
    let mut done: Vec<narf_block::disk_policy::DiskId> = Vec::new();
    let mut flushed = 0;
    let mut failed = 0;
    for entry in &devices {
        if done.contains(&entry.disk) || entry.dev.is_read_only() {
            continue;
        }
        done.push(entry.disk);
        flushed += 1;
        if entry.dev.flush().is_err() {
            failed += 1;
        }
    }
    (flushed, failed)
}

/// Linux `ksys_sync`: `syncfs` every mounted filesystem, then flush every
/// disk. Never fails as a whole; the report says what went wrong.
pub async fn sync_all() -> SyncReport {
    let filesystems = crate::all_mounted_filesystems();
    let (n, fs_errors) = sync_filesystems(&filesystems).await;
    let (disks_flushed, flush_errors) = flush_block_devices();
    SyncReport {
        filesystems: n,
        fs_errors,
        disks_flushed,
        flush_errors,
    }
}

mod tests {
    extern crate alloc;

    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use narf_kernel_test::{kernel_test_in, TestResult};

    use crate::{DirEntry, DirOps, FileOps, FsFuture, FsInstance};

    #[derive(Debug, Default)]
    struct CountDir {
        syncs: AtomicUsize,
    }

    impl DirOps for CountDir {
        fn lookup(&self, _name: &str) -> Option<Arc<dyn FileOps>> {
            None
        }
        fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = DirEntry> + 'a> {
            Box::new(core::iter::empty())
        }
        fn syncfs<'a>(&'a self) -> FsFuture<'a, ()> {
            self.syncs.fetch_add(1, Ordering::AcqRel);
            Box::pin(async { Ok(()) })
        }
    }

    #[derive(Debug, Default)]
    struct CountFs {
        root: Arc<CountDir>,
    }

    impl FsInstance for CountFs {
        fn root(&self) -> Arc<dyn DirOps> {
            self.root.clone()
        }
        fn name(&self) -> &str {
            "syncfs-count"
        }
    }

    #[derive(Debug, Default)]
    struct FlushDev {
        flushes: AtomicUsize,
    }

    impl narf_block::BlockDeviceSync for FlushDev {
        fn lba_size(&self) -> u32 {
            512
        }
        fn capacity(&self) -> u64 {
            64
        }
        fn read(
            &self,
            _lba: u64,
            _n: u16,
            _out: &mut [u8],
        ) -> Result<(), narf_block::BlockIoError> {
            Ok(())
        }
        fn write(&self, _lba: u64, _n: u16, _data: &[u8]) -> Result<(), narf_block::BlockIoError> {
            Ok(())
        }
        fn flush(&self) -> Result<(), narf_block::BlockIoError> {
            self.flushes.fetch_add(1, Ordering::AcqRel);
            Ok(())
        }
    }

    fn poll_ready<F: core::future::Future>(fut: F) -> Option<F::Output> {
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn raw() -> RawWaker {
            unsafe fn clone(_: *const ()) -> RawWaker {
                raw()
            }
            unsafe fn noop(_: *const ()) {}
            const VT: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
            RawWaker::new(core::ptr::null(), &VT)
        }
        // SAFETY: every vtable entry is a no-op that never reads the data
        // pointer.
        let waker = unsafe { Waker::from_raw(raw()) };
        let mut cx = Context::from_waker(&waker);
        let mut fut = Box::pin(fut);
        for _ in 0..64 {
            if let Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
                return Some(v);
            }
        }
        None
    }

    /// `sync(2)`'s walk reaches every superblock exactly once: a
    /// filesystem mounted twice, bind-mounted, and one mounted only in a
    /// private mount namespace are each synced once; then every disk is
    /// flushed once (a disk and its partition are one flush), and a disk the
    /// policy keeps read-only is not touched.
    fn smoke_sync_all_reaches_every_superblock_once() -> TestResult {
        let auth = crate::bootstrap_mount_authority();
        let shared = Arc::new(CountFs::default());
        let private = Arc::new(CountFs::default());
        let a = "/__narf_sync_a";
        let b = "/__narf_sync_b";
        let c = "/__narf_sync_bind";
        let p = "/__narf_sync_private";
        let reg = crate::registry();
        let Ok(ha) = reg.mount_arc(&auth, a, shared.clone()) else {
            return TestResult::Fail("mount a failed");
        };
        let Ok(hb) = reg.mount_arc(&auth, b, shared.clone()) else {
            return TestResult::Fail("mount b failed");
        };
        let Ok(hc) = reg.bind_mount(&auth, a, c) else {
            return TestResult::Fail("bind mount failed");
        };
        let ns = crate::MountNamespace::snapshot_global();
        if ns.mount_arc(&auth, p, private.clone()).is_err() {
            return TestResult::Fail("private-namespace mount failed");
        }

        let disk = Arc::new(FlushDev::default());
        narf_block::register_block_device("narfsync0", disk.clone());
        narf_block::register_partition_device("narfsync0p1", "narfsync0", disk.clone(), None);

        let report = poll_ready(super::sync_all());
        let shared_syncs = shared.root.syncs.load(Ordering::Acquire);
        let private_syncs = private.root.syncs.load(Ordering::Acquire);
        let flushes = disk.flushes.load(Ordering::Acquire);

        // A second pass after the private namespace is gone skips it.
        drop(ns);
        let _ = poll_ready(super::sync_all());
        let private_after = private.root.syncs.load(Ordering::Acquire);

        narf_block::unregister_block_device("narfsync0p1");
        narf_block::unregister_block_device("narfsync0");
        let _ = reg.unmount(&hc, c);
        let _ = reg.unmount(&hb, b);
        let _ = reg.unmount(&ha, a);

        let Some(report) = report else {
            return TestResult::Fail("sync_all did not complete");
        };
        if shared_syncs != 1 {
            return TestResult::Fail("a filesystem mounted three ways must be synced exactly once");
        }
        if private_syncs != 1 {
            return TestResult::Fail("a filesystem in a private mount namespace was not synced");
        }
        if private_after != 1 {
            return TestResult::Fail("a dropped namespace's filesystem was still synced");
        }
        if flushes != 1 {
            return TestResult::Fail("a disk and its partition must get exactly one flush");
        }
        if report.fs_errors != 0 || report.flush_errors != 0 || report.filesystems < 2 {
            return TestResult::Fail("sync report inconsistent");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "filesystem/sync",
        smoke_sync_all_reaches_every_superblock_once
    );

    /// A disk that the `narf.disks` policy keeps read-only received no write
    /// from this boot, so it gets no flush either.
    fn smoke_sync_all_skips_read_only_disks() -> TestResult {
        use narf_block::disk_policy::{self, DiskPolicy};
        let disk = Arc::new(FlushDev::default());
        disk_policy::__set_policy_for_test(Some(DiskPolicy::RootRo));
        narf_block::register_block_device("narfsyncro0", disk.clone());
        let (_, _) = super::flush_block_devices();
        let flushes = disk.flushes.load(Ordering::Acquire);
        narf_block::unregister_block_device("narfsyncro0");
        disk_policy::__set_policy_for_test(None);
        if flushes != 0 {
            return TestResult::Fail("a read-only disk was flushed");
        }
        TestResult::Pass
    }
    kernel_test_in!("filesystem/sync", smoke_sync_all_skips_read_only_disks);
}

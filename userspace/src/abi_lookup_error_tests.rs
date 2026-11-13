//! A btrfs lookup that fails reaches its caller as that failure and is
//! never cached (Linux `lookup_slow` propagating `->lookup`'s `ERR_PTR`):
//! a device error is EIO, a lookup abandoned because its task was sent
//! SIGKILL is EINTR to that task only, and neither leaves a negative dentry
//! that would answer ENOENT for an existing name to every later walk.
//!
//! Both run the real btrfs driver on the free-space-tree fixture over a
//! block device that fails or stalls reads on demand, with the node cache
//! emptied (`drop_slab`) so the lookup has to read the device.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use narf_block::ram::RamBlockDevice;
use narf_block::{
    BlockCompletion, BlockDevice, BlockError, BlockFeature, BlockOp, BlockRequest, CancelResult,
    LbaRange,
};
use narf_filesystem::{Dentry, FsError, FsInstance};

use crate::abi_test_support::*;

const PASS: u8 = 0;
const FAIL_READS: u8 = 1;
const STALL_READS: u8 = 2;

/// A RAM disk whose reads can be made to fail (EIO) or to wait until
/// released (a device that is slow to answer).
struct FaultyDevice {
    inner: Arc<RamBlockDevice>,
    mode: AtomicU8,
    release: AtomicBool,
}

impl FaultyDevice {
    fn new() -> Arc<Self> {
        Self::on(crate::abi_fault_write_tests::BTRFS_FST_FIXTURE_SPARSE)
    }

    fn on(sparse: &[u8]) -> Arc<Self> {
        let image = crate::abi_fault_write_tests::btrfs_decode_sparse(sparse);
        Arc::new(Self {
            inner: RamBlockDevice::from_image(512, image),
            mode: AtomicU8::new(PASS),
            release: AtomicBool::new(false),
        })
    }

    fn set(&self, mode: u8) {
        self.mode.store(mode, Ordering::Release);
    }
}

/// Pending until `release` is set. It registers no waker: the tests poll
/// it by hand.
struct Stall<'a>(&'a AtomicBool);

impl Future for Stall<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        if self.0.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl BlockDevice for FaultyDevice {
    fn logical_block_size(&self) -> u32 {
        self.inner.logical_block_size()
    }

    fn physical_block_size(&self) -> u32 {
        self.inner.physical_block_size()
    }

    fn capacity_blocks(&self) -> u64 {
        self.inner.capacity_blocks()
    }

    fn supports(&self, feat: BlockFeature) -> bool {
        self.inner.supports(feat)
    }

    fn submit(&self, req: BlockRequest) -> impl Future<Output = BlockCompletion> + Send {
        let read = req.op == BlockOp::Read;
        let mode = self.mode.load(Ordering::Acquire);
        // Boxed: btrfs's read paths are instantiated for this device and
        // inline its future; kept on the heap, their frames stay what they
        // are for the RAM disk (build/frame-budget.txt).
        Box::pin(async move {
            if read && mode == FAIL_READS {
                return BlockCompletion {
                    tag: 0,
                    user_tag: req.user_tag,
                    result: Err(BlockError::IOError),
                };
            }
            if read && mode == STALL_READS {
                Stall(&self.release).await;
            }
            self.inner.submit(req).await
        })
    }

    fn flush(&self) -> impl Future<Output = ()> + Send {
        self.inner.flush()
    }

    fn discard(&self, range: LbaRange) -> impl Future<Output = ()> + Send {
        self.inner.discard(range)
    }

    fn cancel(&self, tag: u64) -> impl Future<Output = CancelResult> + Send {
        self.inner.cancel(tag)
    }
}

type Volume = narf_drivers_fs_btrfs::volume::BtrfsVolume<FaultyDevice>;
type MountHandle = Cap<MountPoint, narf_capabilities::Write>;

/// Mount the fixture on `device`, create and seed `narf.txt`, commit it,
/// and mount the volume at `at`. Returns the volume and the mount handle.
fn mount_with_file(
    device: &Arc<FaultyDevice>,
    at: &str,
) -> Result<(Arc<Volume>, MountHandle), &'static str> {
    let volume = crate::handlers::poll_io_to_completion(Volume::mount(
        Arc::clone(device),
        narf_lib::id::DomainId::DRIVER_0,
    ))
    .and_then(|r| r.ok())
    .ok_or("mounting the btrfs fixture failed")?;
    let file = crate::handlers::poll_io_to_completion(volume.root().create("narf.txt"))
        .and_then(|r| r.ok())
        .ok_or("creating narf.txt failed")?;
    crate::handlers::poll_io_to_completion(file.write(0, b"lookup errors"))
        .and_then(|r| r.ok())
        .ok_or("seeding narf.txt failed")?;
    crate::handlers::poll_io_to_completion(volume.sync_fs())
        .and_then(|r| r.ok())
        .ok_or("committing the fixture failed")?;
    let handle = registry()
        .mount_arc(
            &bootstrap_mount_authority(),
            at,
            Arc::clone(&volume) as Arc<dyn FsInstance>,
        )
        .map_err(|_| "mounting the volume in the VFS failed")?;
    Ok((volume, handle))
}

fn mount_root(at: &str) -> Result<Arc<Dentry>, &'static str> {
    registry()
        .resolve_absolute_with_root(at, |_fs, root, _rel| root)
        .ok_or("the mount has no root dentry")
}

/// Whether the dcache answers `name` under `root` as absent without asking
/// the filesystem.
fn cached_negative(root: &Arc<Dentry>, name: &str) -> bool {
    matches!(
        narf_filesystem::resolve_cached_dentry(Arc::clone(root), name),
        Some(Err(FsError::NotFound))
    )
}

fn noop_waker() -> Waker {
    fn raw() -> RawWaker {
        unsafe fn clone(_: *const ()) -> RawWaker {
            raw()
        }
        unsafe fn noop(_: *const ()) {}
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    // SAFETY: the vtable ignores the null data pointer.
    unsafe { Waker::from_raw(raw()) }
}

fn poll_now<F: Future + ?Sized>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = noop_waker();
    future.poll(&mut Context::from_waker(&waker))
}

const EIO_MOUNT: &str = "/lookup-eio";
const EIO_PATH: &[u8] = b"/lookup-eio/narf.txt\0";
const O_RDWR: u64 = 2;
const O_CREAT: u64 = 0o100;

/// (a) `stat` and `open` of an existing file whose directory lookup hits a
/// device error return -EIO — not -ENOENT, and `O_CREAT` does not try to
/// create over it — and nothing is cached: once the device recovers, the
/// same path stats.
fn smoke_lookup_errors_btrfs_io_error_is_eio_and_not_cached() -> TestResult {
    with_setup(|| {
        let device = FaultyDevice::new();
        let (_volume, handle) = mount_with_file(&device, EIO_MOUNT)?;
        let outcome = (|| {
            let root = mount_root(EIO_MOUNT)?;
            narf_memory::reclaim::drop_slab();
            device.set(FAIL_READS);
            let mut sb = [0u8; STAT_SIZE];
            let path = EIO_PATH.as_ptr() as u64;
            if call_stat(path, sb.as_mut_ptr() as u64) != Some(-narf_lib::errno::EIO) {
                return Err("stat of a file behind a failing read was not -EIO");
            }
            if call_open(path, 0) != Some(-narf_lib::errno::EIO) {
                return Err("open of a file behind a failing read was not -EIO");
            }
            if call_open(path, O_CREAT | O_RDWR) != Some(-narf_lib::errno::EIO) {
                return Err("open(O_CREAT) over a failed lookup was not -EIO");
            }
            if cached_negative(&root, "narf.txt") {
                return Err("the failed lookup was cached as a negative dentry");
            }
            device.set(PASS);
            if call_stat(path, sb.as_mut_ptr() as u64) != Some(0) {
                return Err("the file did not stat once the device recovered");
            }
            Ok(())
        })();
        device.set(PASS);
        let _ = registry().unmount(&handle, EIO_MOUNT);
        outcome
    })
}
kernel_test_in!(
    "syscall_abi/lookup_errors/btrfs",
    smoke_lookup_errors_btrfs_io_error_is_eio_and_not_cached
);

const KILL_MOUNT: &str = "/lookup-kill";
const HOLDER_TASK: u64 = FAKE_TASK + 7;
const LATER_TASK: u64 = FAKE_TASK + 8;

/// (b) Task A's lookup holds the device; killed task B's lookup of the same
/// name gives up waiting behind it with `Interrupted` (EINTR, which B never
/// returns to user space with), leaves no negative dentry, and both A's
/// lookup and a later task C's find the file.
fn smoke_lookup_errors_btrfs_killed_lookup_is_eintr_and_not_cached() -> TestResult {
    with_setup(|| {
        let device = FaultyDevice::new();
        let (_volume, handle) = mount_with_file(&device, KILL_MOUNT)?;
        crate::handlers::signal_waker_init();
        let outcome = (|| {
            let root = mount_root(KILL_MOUNT)?;
            narf_memory::reclaim::drop_slab();
            device.set(STALL_READS);

            set_task(HOLDER_TASK);
            let mut holder: Pin<Box<_>> = Box::pin(narf_filesystem::resolve_async_dentry(
                Arc::clone(&root),
                "narf.txt",
            ));
            if poll_now(holder.as_mut()).is_ready() {
                return Err("the first lookup did not wait for the device");
            }

            set_task(FAKE_TASK);
            crate::handlers::raise_signal_pending(FAKE_TASK, 9);
            let mut killed = Box::pin(narf_filesystem::resolve_async_dentry(
                Arc::clone(&root),
                "narf.txt",
            ));
            let result = poll_now(killed.as_mut());
            drop(killed);
            crate::handlers::clear_signal_pending(FAKE_TASK, 9);
            crate::handlers::drop_signal_waker(FAKE_TASK);
            match result {
                Poll::Ready(Err(FsError::Interrupted)) => {}
                Poll::Ready(Err(FsError::InvalidData)) => {
                    return Err("the killed lookup's abandoned read surfaced as InvalidData")
                }
                Poll::Ready(Err(FsError::NotFound)) => {
                    return Err("the killed lookup reported an existing name as absent")
                }
                Poll::Ready(_) => return Err("the killed lookup did not end as Interrupted"),
                Poll::Pending => return Err("the killed lookup kept waiting for the device"),
            }
            if crate::handlers::copy_fs_errno(FsError::Interrupted) != narf_lib::errno::EINTR {
                return Err("Interrupted does not map to EINTR");
            }
            if cached_negative(&root, "narf.txt") {
                return Err("the killed lookup was cached as a negative dentry");
            }

            // The device answers: the holder's lookup and a later task's
            // both find the file.
            device.set(PASS);
            device.release.store(true, Ordering::Release);
            set_task(HOLDER_TASK);
            let mut found = false;
            for _ in 0..1024 {
                match poll_now(holder.as_mut()) {
                    Poll::Ready(Ok(_)) => {
                        found = true;
                        break;
                    }
                    Poll::Ready(Err(_)) => return Err("the holder's lookup failed"),
                    Poll::Pending => {}
                }
            }
            if !found {
                return Err("the holder's lookup never completed");
            }
            set_task(LATER_TASK);
            match crate::handlers::poll_io_to_completion(narf_filesystem::resolve_async_dentry(
                Arc::clone(&root),
                "narf.txt",
            )) {
                Some(Ok(_)) => Ok(()),
                _ => Err("a later task's lookup did not find the file"),
            }
        })();
        set_task(FAKE_TASK);
        crate::handlers::clear_signal_pending(FAKE_TASK, 9);
        device.set(PASS);
        device.release.store(true, Ordering::Release);
        let _ = registry().unmount(&handle, KILL_MOUNT);
        outcome
    })
}
kernel_test_in!(
    "syscall_abi/lookup_errors/btrfs",
    smoke_lookup_errors_btrfs_killed_lookup_is_eintr_and_not_cached
);

const ZSTD_FIXTURE_SPARSE: &[u8] =
    include_bytes!("../../drivers/fs/btrfs/testdata/fixture-zstd.img.sparse");

/// The zstd fixture's `big.dat`: 2000 lines of `L%04d\n`, one compressed
/// extent.
fn expected_big() -> alloc::vec::Vec<u8> {
    let mut bytes = alloc::vec::Vec::with_capacity(12000);
    for i in 0..2000u32 {
        bytes.extend_from_slice(alloc::format!("L{i:04}\n").as_bytes());
    }
    bytes
}

/// Read all of `file` from offset 0 as `task`, driving the read by hand.
fn read_whole(
    file: &Arc<dyn narf_filesystem::FileOps>,
    task: u64,
) -> Result<alloc::vec::Vec<u8>, FsError> {
    set_task(task);
    let mut bytes = alloc::vec![0u8; 12000];
    let mut read = Box::pin(file.read(0, &mut bytes));
    for _ in 0..4096 {
        if let Poll::Ready(result) = poll_now(read.as_mut()) {
            let n = result?;
            drop(read);
            bytes.truncate(n);
            return Ok(bytes);
        }
    }
    Err(FsError::TimedOut)
}

/// A read of a zstd-compressed extent abandoned because its task was killed
/// leaves nothing behind: it ends as `Interrupted` (never `InvalidData`),
/// and every later reader — the one it queued behind, and a fresh one with
/// the caches dropped again — gets the file's real bytes. Linux: a folio is
/// marked uptodate only once its whole read completed and verified; an
/// aborted read leaves it !uptodate and the next reader issues it again.
fn smoke_lookup_errors_btrfs_killed_compressed_read_leaves_nothing_cached() -> TestResult {
    with_setup(|| {
        let device = FaultyDevice::on(ZSTD_FIXTURE_SPARSE);
        let volume = crate::handlers::poll_io_to_completion(Volume::mount(
            Arc::clone(&device),
            narf_lib::id::DomainId::DRIVER_0,
        ))
        .and_then(|r| r.ok())
        .ok_or("mounting the zstd fixture failed")?;
        let file = crate::handlers::poll_io_to_completion(volume.root().lookup_async("big.dat"))
            .and_then(|r| r.ok())
            .ok_or("looking up big.dat failed")?;
        crate::handlers::signal_waker_init();
        let outcome = (|| {
            let expected = expected_big();
            narf_memory::reclaim::drop_slab();
            device.set(STALL_READS);

            // Another task's read gets the device first and holds it.
            set_task(HOLDER_TASK);
            let mut holder_bytes = alloc::vec![0u8; 12000];
            let mut holder = Box::pin(file.read(0, &mut holder_bytes));
            if poll_now(holder.as_mut()).is_ready() {
                return Err("the first read did not wait for the device");
            }

            // The killed task's read of the same extent gives up behind it.
            set_task(FAKE_TASK);
            crate::handlers::raise_signal_pending(FAKE_TASK, 9);
            let killed = {
                let mut bytes = alloc::vec![0u8; 12000];
                let mut read = Box::pin(file.read(0, &mut bytes));
                poll_now(read.as_mut())
            };
            crate::handlers::clear_signal_pending(FAKE_TASK, 9);
            crate::handlers::drop_signal_waker(FAKE_TASK);
            match killed {
                Poll::Ready(Err(FsError::Interrupted)) => {}
                Poll::Ready(Err(FsError::InvalidData)) => {
                    return Err("the killed compressed read surfaced as InvalidData")
                }
                Poll::Ready(_) => return Err("the killed compressed read did not end Interrupted"),
                Poll::Pending => return Err("the killed compressed read kept waiting"),
            }

            // The device answers: the holder gets the real bytes.
            device.set(PASS);
            device.release.store(true, Ordering::Release);
            set_task(HOLDER_TASK);
            let mut held = None;
            for _ in 0..4096 {
                if let Poll::Ready(result) = poll_now(holder.as_mut()) {
                    held = Some(result);
                    break;
                }
            }
            drop(holder);
            match held {
                Some(Ok(n)) if holder_bytes[..n] == expected[..] => {}
                Some(Ok(_)) => return Err("the holder read wrong bytes after the abort"),
                Some(Err(_)) => return Err("the holder's read failed after the abort"),
                None => return Err("the holder's read never completed"),
            }

            // A later reader, from the cache and again from the device.
            if read_whole(&file, LATER_TASK).ok().as_deref() != Some(&expected[..]) {
                return Err("a later reader did not get the real bytes");
            }
            narf_memory::reclaim::drop_slab();
            if read_whole(&file, LATER_TASK).ok().as_deref() != Some(&expected[..]) {
                return Err("a later uncached reader did not get the real bytes");
            }
            Ok(())
        })();
        set_task(FAKE_TASK);
        crate::handlers::clear_signal_pending(FAKE_TASK, 9);
        device.set(PASS);
        device.release.store(true, Ordering::Release);
        outcome
    })
}
kernel_test_in!(
    "syscall_abi/lookup_errors/btrfs",
    smoke_lookup_errors_btrfs_killed_compressed_read_leaves_nothing_cached
);

const KILLED_OWNER: u64 = FAKE_TASK + 9;

/// The killed-task identity of an abandoned operation belongs to the
/// scheduler task finishing it, never to the CPU. While such an operation
/// is mid-poll elsewhere (it yielded, or was preempted, on this very CPU),
/// a different task here runs a killable read that has to wait for the
/// device: it is itself, its wait does not give up, and it reads the real
/// bytes once the device answers.
fn smoke_lookup_errors_abandoned_identity_is_task_local() -> TestResult {
    with_setup(|| {
        let device = FaultyDevice::on(ZSTD_FIXTURE_SPARSE);
        let volume = crate::handlers::poll_io_to_completion(Volume::mount(
            Arc::clone(&device),
            narf_lib::id::DomainId::DRIVER_0,
        ))
        .and_then(|r| r.ok())
        .ok_or("mounting the zstd fixture failed")?;
        let file = crate::handlers::poll_io_to_completion(volume.root().lookup_async("big.dat"))
            .and_then(|r| r.ok())
            .ok_or("looking up big.dat failed")?;
        crate::handlers::signal_waker_init();
        let me = narf_scheduler::current_task_id().raw();
        let elsewhere = me ^ 0x5a5a;
        crate::handlers::raise_signal_pending(KILLED_OWNER, 9);
        let outcome = (|| {
            // Positive control: the poller itself is the killed task.
            let own = crate::killable_wait::__test_finishing_for(me, KILLED_OWNER, || {
                crate::killable_wait::hook_current()
            });
            if own != KILLED_OWNER {
                return Err("the finishing task was not seen as the killed task");
            }

            let expected = expected_big();
            narf_memory::reclaim::drop_slab();
            device.set(STALL_READS);
            set_task(HOLDER_TASK);
            let mut holder_bytes = alloc::vec![0u8; 12000];
            let mut holder = Box::pin(file.read(0, &mut holder_bytes));
            if poll_now(holder.as_mut()).is_ready() {
                return Err("the first read did not wait for the device");
            }

            // Another scheduler task is mid-way through finishing the killed
            // task's operation; this task reads behind the holder.
            set_task(FAKE_TASK);
            crate::killable_wait::__test_finishing_for(elsewhere, KILLED_OWNER, || {
                if crate::killable_wait::hook_current() == KILLED_OWNER {
                    return Err("a task was taken for another task's killed operation");
                }
                let mut bytes = alloc::vec![0u8; 12000];
                let mut read = Box::pin(file.read(0, &mut bytes));
                if let Poll::Ready(result) = poll_now(read.as_mut()) {
                    return Err(match result {
                        Err(FsError::Interrupted) => "a live task's read was abandoned as killed",
                        Err(_) => "a live task's read failed while it waited",
                        Ok(_) => "the read did not wait behind the holder",
                    });
                }
                device.set(PASS);
                device.release.store(true, Ordering::Release);
                set_task(HOLDER_TASK);
                for _ in 0..4096 {
                    if poll_now(holder.as_mut()).is_ready() {
                        break;
                    }
                }
                set_task(FAKE_TASK);
                for _ in 0..4096 {
                    if let Poll::Ready(result) = poll_now(read.as_mut()) {
                        drop(read);
                        return match result {
                            Ok(n) if bytes[..n] == expected[..] => Ok(()),
                            Ok(_) => Err("the live task's read returned wrong bytes"),
                            Err(_) => Err("the live task's read failed"),
                        };
                    }
                }
                Err("the live task's read never completed")
            })
        })();
        set_task(FAKE_TASK);
        crate::handlers::clear_signal_pending(KILLED_OWNER, 9);
        crate::handlers::drop_signal_waker(KILLED_OWNER);
        device.set(PASS);
        device.release.store(true, Ordering::Release);
        outcome
    })
}
kernel_test_in!(
    "syscall_abi/lookup_errors/btrfs",
    smoke_lookup_errors_abandoned_identity_is_task_local
);

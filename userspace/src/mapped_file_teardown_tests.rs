//! Tearing down an address space must not write its dirty `MAP_SHARED`
//! pages from the context that drops it.
//!
//! The last reference to an address space is dropped on the executor: its
//! `active_mm`-style hand-off releases a dead or exec'd task's address space
//! while dispatching the next task, with that task's slot already off the
//! ready queue and no current task to park. A file write started there is
//! busy-polled, one page at a time, and on a filesystem whose device I/O
//! completes inside the poll it never even pends: the CPU stays in that loop
//! until every dirty page of every file the address space mapped is written.
//! Under QEMU a 128 MiB mapping kept one CPU there for minutes, and every
//! task parked on that CPU that was woken meanwhile (logind, udevd, an RCU
//! thread) waited for it while eleven CPUs sat idle.
//!
//! These tests stand in for that caller: they call the teardown hook the way
//! memory's `Drop` does, on a file whose writes stay `Pending` until the test
//! lets the device answer, and count the polls made by the calling CPU during
//! the call. They say nothing about who writes the pages instead, or when --
//! only that the pages are not discarded.
use super::*;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};
use narf_kernel_test::{kernel_test_in, TestResult};

/// Polls of one write after which a caller that spins on it is let through,
/// so a teardown that busy-polls fails the test instead of hanging it.
const SPIN_LIMIT: usize = 4096;

/// `cpu + 1` of the CPU that is inside a teardown call, else 0.
static TEARDOWN_CPU: AtomicUsize = AtomicUsize::new(0);

/// A file on a slow device: a write is `Pending` until the device answers.
struct SlowFile {
    anchor: usize,
    size: u64,
    device_ready: AtomicBool,
    /// Polls of a write made by the CPU inside a teardown call.
    polls_in_teardown: AtomicUsize,
    /// Writes a teardown call spun on until the test let them through.
    spun: AtomicUsize,
    /// Whoever is waiting for the device, to be woken when it answers.
    waiter: IrqSafeSpinLock<Option<Waker>>,
}

impl SlowFile {
    fn new(anchor: usize, size: u64) -> Arc<Self> {
        Arc::new(Self {
            anchor,
            size,
            device_ready: AtomicBool::new(false),
            polls_in_teardown: AtomicUsize::new(0),
            spun: AtomicUsize::new(0),
            waiter: IrqSafeSpinLock::new(None),
        })
    }

    /// The device answers: every pending write completes, and a writer that
    /// parked on one is woken.
    fn device_answers(&self) {
        self.device_ready.store(true, Ordering::Release);
        let waiter = self.waiter.lock().take();
        if let Some(waiter) = waiter {
            waiter.wake();
        }
    }
}

struct SlowWrite<'a> {
    file: &'a SlowFile,
    len: usize,
    polls: usize,
}

impl Future for SlowWrite<'_> {
    type Output = Result<usize, FsError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let inline = TEARDOWN_CPU.load(Ordering::Acquire) == narf_lib::percpu::current_cpu() + 1;
        if inline {
            self.file.polls_in_teardown.fetch_add(1, Ordering::Relaxed);
        }
        self.polls += 1;
        if self.file.device_ready.load(Ordering::Acquire) {
            return Poll::Ready(Ok(self.len));
        }
        if inline && self.polls >= SPIN_LIMIT {
            self.file.spun.fetch_add(1, Ordering::Relaxed);
            return Poll::Ready(Ok(self.len));
        }
        *self.file.waiter.lock() = Some(cx.waker().clone());
        // The device may have answered between the test and the store.
        if self.file.device_ready.load(Ordering::Acquire) {
            return Poll::Ready(Ok(self.len));
        }
        Poll::Pending
    }
}

impl FileOps for SlowFile {
    fn read<'a>(&'a self, _offset: u64, _buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async { Ok(0) })
    }

    fn write<'a>(&'a self, _offset: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(SlowWrite {
            file: self,
            len: buf.len(),
            polls: 0,
        })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: self.size,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }

    fn mmap_cache_generation(&self) -> Option<u64> {
        Some(1)
    }

    fn mmap_backing_identity(&self) -> usize {
        self.anchor
    }
}

/// One cached page of `ops` at `offset`, mapped once by `space`.
fn map_page(space: u64, ops: &Arc<dyn FileOps>, offset: u64) -> Option<PhysAddr> {
    let frame = narf_memory::alloc_frame().ok()?.start_address();
    // SAFETY: a fresh frame, exclusively owned until it is published.
    unsafe { core::ptr::write_bytes(frame.kernel_mut_ptr::<u8>(), 0, 4096) };
    let (canonical, publication) =
        publish_shared_file_pages(ops, offset, alloc::vec![frame], Some(1));
    let phys = canonical[0];
    let _ = retain_shared_file_page(phys.raw());
    publication.commit();
    register(
        space,
        0x4000_0000 + offset,
        4096,
        offset,
        Arc::clone(ops),
        None,
        Some(FileWriteback {
            offset,
            phys: alloc::vec![phys],
        }),
    );
    Some(phys)
}

/// A store through the mapping: the page now differs from the file.
fn dirty(phys: PhysAddr) {
    // SAFETY: the cache owns the frame and the test holds a mapping of it.
    unsafe {
        let byte = phys.kernel_mut_ptr::<u8>();
        *byte = (*byte).wrapping_add(1);
    }
}

/// What memory's `Drop` does for an address space -- release each mapped
/// frame, then call the teardown hook -- with this CPU marked as the caller.
fn teardown(space: u64, frames: &[PhysAddr]) {
    for phys in frames {
        let _ = release_shared_file_page(phys.raw());
    }
    TEARDOWN_CPU.store(narf_lib::percpu::current_cpu() + 1, Ordering::Release);
    drop_address_space(space);
    TEARDOWN_CPU.store(0, Ordering::Release);
}

fn still_cached(phys: PhysAddr) -> bool {
    SHARED_FILE_PAGES.lock().by_phys.contains_key(&phys.raw())
}

/// A process that dirtied a shared mapping exits. The context that drops
/// its address space must not start, poll or wait for a write; the dirty
/// pages must still be there for whoever does write them.
fn smoke_teardown_of_dirty_shared_mapping_writes_nothing_inline() -> TestResult {
    const SPACE: u64 = u64::MAX - 60;
    static ANCHOR: AtomicUsize = AtomicUsize::new(0);
    drop_address_space(SPACE);
    let file = SlowFile::new(&ANCHOR as *const AtomicUsize as usize, 3 * 4096);
    let ops: Arc<dyn FileOps> = file.clone();
    let mut frames = Vec::new();
    for index in 0..3u64 {
        match map_page(SPACE, &ops, index * 4096) {
            Some(phys) => frames.push(phys),
            None => {
                file.device_answers();
                teardown(SPACE, &frames);
                return TestResult::Skip("frame allocator drained");
            }
        }
    }
    drop(ops);
    // Two pages are written through the mapping; the third is only read.
    dirty(frames[0]);
    dirty(frames[1]);

    teardown(SPACE, &frames);
    let polls = file.polls_in_teardown.load(Ordering::Relaxed);
    let spun = file.spun.load(Ordering::Relaxed);
    let kept = still_cached(frames[0]) && still_cached(frames[1]);
    // Let any writer that is waiting for the device finish.
    file.device_answers();
    if spun != 0 {
        return TestResult::Fail(
            "address-space teardown busy-polled a file write that was waiting for its device",
        );
    }
    if polls != 0 {
        return TestResult::Fail("address-space teardown wrote a dirty shared page itself");
    }
    if !kept {
        return TestResult::Fail("address-space teardown discarded a dirty shared page");
    }
    TestResult::Pass
}

kernel_test_in!(
    "syscall_abi/filemap/teardown",
    smoke_teardown_of_dirty_shared_mapping_writes_nothing_inline
);

/// fork + exec, eight times, from a parent that keeps a shared mapping
/// dirty: each child's pre-exec address space inherits the parent's mapping
/// rows and is dropped at exec. None of those drops may write the parent's
/// pages from the dropping context, and neither may the parent's own exit.
fn smoke_fork_child_teardown_writes_nothing_inline() -> TestResult {
    const PARENT: u64 = u64::MAX - 62;
    const CHILD: u64 = u64::MAX - 61;
    static ANCHOR: AtomicUsize = AtomicUsize::new(0);
    drop_address_space(PARENT);
    drop_address_space(CHILD);
    let file = SlowFile::new(&ANCHOR as *const AtomicUsize as usize, 4096);
    let ops: Arc<dyn FileOps> = file.clone();
    let Some(phys) = map_page(PARENT, &ops, 0) else {
        return TestResult::Skip("frame allocator drained");
    };
    drop(ops);

    let mut after_children = 0;
    for _ in 0..8 {
        // The parent writes through its mapping, then forks: the child
        // inherits the owner row and maps the same frame.
        dirty(phys);
        fork_address_space(PARENT, CHILD);
        let _ = retain_shared_file_page(phys.raw());
        // The child execs: its pre-exec address space is dropped.
        teardown(CHILD, &[phys]);
        after_children = file.polls_in_teardown.load(Ordering::Relaxed);
        if after_children != 0 {
            break;
        }
    }
    dirty(phys);
    teardown(PARENT, &[phys]);
    let after_parent = file.polls_in_teardown.load(Ordering::Relaxed);
    let kept = still_cached(phys);
    file.device_answers();
    if after_children != 0 {
        return TestResult::Fail(
            "a fork child's teardown wrote its parent's dirty shared page from the dropping context",
        );
    }
    if after_parent != 0 {
        return TestResult::Fail("the last mapper's teardown wrote its dirty shared page itself");
    }
    if !kept {
        return TestResult::Fail("the last mapper's teardown discarded a dirty shared page");
    }
    TestResult::Pass
}

kernel_test_in!(
    "syscall_abi/filemap/teardown",
    smoke_fork_child_teardown_writes_nothing_inline
);

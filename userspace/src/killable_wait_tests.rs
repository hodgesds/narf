//! A task waiting on a filesystem future must die on SIGKILL — and the
//! operation it was waiting on must still reach its own completion.
use super::*;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use narf_filesystem::{FsFuture, Mode, Stat};
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

/// Non-zero while a [`DetachFixture`] is live: killed operations go to it
/// instead of the scheduler, so a test can finish them by hand.
pub(super) static DETACH_HOOK: AtomicUsize = AtomicUsize::new(0);

/// Frames a dropped [`FilledFrame`] gave back to the allocator.
pub(super) static FRAMES_RELEASED: AtomicUsize = AtomicUsize::new(0);

static DETACHED: IrqSafeSpinLock<Option<Detached>> = IrqSafeSpinLock::new(None);
static WAKES: AtomicUsize = AtomicUsize::new(0);
static FINISHED: AtomicUsize = AtomicUsize::new(0);

fn retain_detached(op: Detached) {
    *DETACHED.lock() = Some(op);
}

fn count_finish(value: usize) {
    FINISHED.fetch_add(value, Ordering::Relaxed);
}

/// Signal tables, a retained-detach hook and a pinned current task id, all
/// put back on drop.
struct DetachFixture(u64);

impl DetachFixture {
    fn new(task: u64) -> Self {
        crate::handlers::__test_signal_reset();
        crate::handlers::signal_waker_init();
        WAKES.store(0, Ordering::Relaxed);
        FINISHED.store(0, Ordering::Relaxed);
        DETACHED.lock().take();
        DETACH_HOOK.store(retain_detached as fn(Detached) as usize, Ordering::Release);
        Self(task)
    }
}

impl Drop for DetachFixture {
    fn drop(&mut self) {
        DETACH_HOOK.store(0, Ordering::Release);
        crate::handlers::clear_signal_pending(self.0, 9);
        crate::handlers::clear_signal_pending(self.0, 15);
        crate::handlers::drop_signal_waker(self.0);
        crate::handlers::__test_reset_task_id_lookup();
        DETACHED.lock().take();
    }
}

fn counting_waker() -> core::task::Waker {
    use core::task::{RawWaker, RawWakerVTable, Waker};
    unsafe fn clone(_: *const ()) -> RawWaker {
        RawWaker::new(core::ptr::null(), &VTABLE)
    }
    unsafe fn wake(_: *const ()) {
        WAKES.fetch_add(1, Ordering::Relaxed);
    }
    unsafe fn drop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, wake, wake, drop);
    // SAFETY: the vtable touches only a static atomic and ignores the pointer.
    unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) }
}

/// Completes only once `ready` is set; never wakes anything by itself.
struct Stuck {
    ready: Arc<AtomicBool>,
    drops: Arc<AtomicUsize>,
}

impl Future for Stuck {
    type Output = usize;
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<usize> {
        if self.ready.load(Ordering::Acquire) {
            Poll::Ready(7)
        } else {
            Poll::Pending
        }
    }
}

impl Drop for Stuck {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::Relaxed);
    }
}

fn stuck() -> (OwnedWait<usize>, Arc<AtomicBool>, Arc<AtomicUsize>) {
    let ready = Arc::new(AtomicBool::new(false));
    let drops = Arc::new(AtomicUsize::new(0));
    let op: OwnedWait<usize> = Box::pin(Stuck {
        ready: ready.clone(),
        drops: drops.clone(),
    });
    (op, ready, drops)
}

/// SIGKILL wakes a wait whose operation never wakes it, the wait reports
/// `Killed`, and the operation is neither dropped nor forgotten: it runs to
/// completion elsewhere and its result reaches the `finish` hook once.
fn smoke_killable_wait_sigkill_ends_a_wait_that_never_completes() -> TestResult {
    const TASK: u64 = 0x6b11_ab1e;
    let _fixture = DetachFixture::new(TASK);
    let (op, ready, drops) = stuck();
    let waker = counting_waker();
    let mut cx = Context::from_waker(&waker);
    let mut wait = KillableWait::new(TASK, op)
        .detach_with(retain_detached)
        .finish_with(count_finish);

    if Pin::new(&mut wait).poll(&mut cx) != Poll::Pending
        || !crate::handlers::dbg_has_signal_waker(TASK)
    {
        return TestResult::Fail("a pending wait did not arm the task's signal waker");
    }
    crate::handlers::raise_signal_pending(TASK, 9);
    if WAKES.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("SIGKILL did not wake the waiting task");
    }
    if Pin::new(&mut wait).poll(&mut cx) != Poll::Ready(Err(Killed)) {
        return TestResult::Fail("a woken wait with SIGKILL pending went back to sleep");
    }
    drop(wait);
    if drops.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("a killed wait dropped an operation that was in flight");
    }
    if crate::handlers::dbg_has_signal_waker(TASK) {
        return TestResult::Fail("a finished wait left its signal waker registered");
    }
    let Some(mut detached) = DETACHED.lock().take() else {
        return TestResult::Fail("the in-flight operation was not handed on to finish");
    };
    if detached.as_mut().poll(&mut cx) != Poll::Pending || FINISHED.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("the detached operation invented a completion");
    }
    ready.store(true, Ordering::Release);
    if detached.as_mut().poll(&mut cx) != Poll::Ready(()) {
        return TestResult::Fail("the detached operation could not finish");
    }
    drop(detached);
    if FINISHED.load(Ordering::Relaxed) != 7 || drops.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("the operation's result was not finished exactly once");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/killable",
    smoke_killable_wait_sigkill_ends_a_wait_that_never_completes
);

/// `TASK_KILLABLE`, not `TASK_INTERRUPTIBLE`: a catchable signal leaves the
/// wait alone, so `read(2)` of a regular file is never cut short by SIGTERM.
fn smoke_killable_wait_ignores_a_catchable_signal() -> TestResult {
    const TASK: u64 = 0x6b11_ab1f;
    let _fixture = DetachFixture::new(TASK);
    let (op, ready, drops) = stuck();
    let waker = counting_waker();
    let mut cx = Context::from_waker(&waker);
    let mut wait = KillableWait::new(TASK, op).detach_with(retain_detached);

    if Pin::new(&mut wait).poll(&mut cx) != Poll::Pending {
        return TestResult::Fail("a stuck operation completed");
    }
    crate::handlers::raise_signal_pending(TASK, 15);
    if Pin::new(&mut wait).poll(&mut cx) != Poll::Pending {
        return TestResult::Fail("SIGTERM ended a wait only a fatal signal may end");
    }
    ready.store(true, Ordering::Release);
    if Pin::new(&mut wait).poll(&mut cx) != Poll::Ready(Ok(7)) {
        return TestResult::Fail("the wait did not deliver its operation's result");
    }
    drop(wait);
    if drops.load(Ordering::Relaxed) != 1 || DETACHED.lock().is_some() {
        return TestResult::Fail("a completed wait detached or leaked its operation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/killable",
    smoke_killable_wait_ignores_a_catchable_signal
);

/// The page-cache-hit path: an operation that is ready at once touches no
/// signal state at all.
fn smoke_killable_wait_ready_operation_arms_nothing() -> TestResult {
    const TASK: u64 = 0x6b11_ab20;
    let _fixture = DetachFixture::new(TASK);
    // Even with SIGKILL already pending, a completed operation is reported
    // as completed: its side effects happened.
    crate::handlers::raise_signal_pending(TASK, 9);
    let waker = counting_waker();
    let mut cx = Context::from_waker(&waker);
    let mut wait = KillableWait::new(TASK, Box::pin(async { 3usize }));
    if Pin::new(&mut wait).poll(&mut cx) != Poll::Ready(Ok(3)) {
        return TestResult::Fail("a ready operation was not reported");
    }
    if crate::handlers::dbg_has_signal_waker(TASK) {
        return TestResult::Fail("a ready operation registered a signal waker");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/killable",
    smoke_killable_wait_ready_operation_arms_nothing
);

/// A file whose I/O never completes, and which records what reached it.
struct NeverFile {
    reads: AtomicUsize,
    writes: AtomicUsize,
    release: Arc<AtomicBool>,
}

impl NeverFile {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            release: Arc::new(AtomicBool::new(false)),
        })
    }
}

struct Gate(Arc<AtomicBool>);

impl Future for Gate {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        if self.0.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl FileOps for NeverFile {
    fn read<'a>(&'a self, _: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.reads.fetch_add(1, Ordering::Relaxed);
            Gate(self.release.clone()).await;
            buf.fill(0x5a);
            Ok(buf.len())
        })
    }

    fn write<'a>(&'a self, _: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            Gate(self.release.clone()).await;
            self.writes.fetch_add(buf.len(), Ordering::Relaxed);
            Ok(buf.len())
        })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 1 << 20,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }

    /// Plain file data, as an on-disk filesystem's regular file reports.
    fn can_poll(&self) -> bool {
        false
    }
}

/// An event descriptor: a regular file by type, but pollable, and its read
/// consumes what it returns.
struct EventFile(AtomicUsize);

impl FileOps for EventFile {
    fn read<'a>(&'a self, _: u64, buf: &'a mut [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(buf.len())
        })
    }

    fn write<'a>(&'a self, _: u64, buf: &'a [u8]) -> FsFuture<'a, usize> {
        Box::pin(async move {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(buf.len())
        })
    }

    fn stat(&self) -> Stat {
        Stat {
            size: 0,
            blocks: 0,
            mode: Mode::FILE_RW,
            mtime_cycles: 0,
        }
    }
}

/// Only plain file data is stored file data: a pollable descriptor is not,
/// whatever its file type says, and is still read and written in place.
fn smoke_killable_wait_leaves_pollable_descriptors_alone() -> TestResult {
    let _fixture = DetachFixture::new(SYSCALL_TASK);
    crate::handlers::install_task_id_lookup(syscall_task);
    let plain: Arc<dyn FileOps> = NeverFile::new();
    let event = Arc::new(EventFile(AtomicUsize::new(0)));
    let pollable: Arc<dyn FileOps> = event.clone();
    if !stores_file_data(plain.as_ref()) || stores_file_data(pollable.as_ref()) {
        return TestResult::Fail("a pollable descriptor was classed as stored file data");
    }
    let mut staging = alloc::vec![0u8; 8];
    let mut payload = alloc::vec![0u8; 8];
    if read(&pollable, 0, &mut staging, 8, ReadOptions::default()) != Ok(Some(Ok(8)))
        || write(&pollable, 0, &mut payload) != Ok(Some(Ok(8)))
        || staging.len() != 8
        || payload.len() != 8
        || event.0.load(Ordering::Relaxed) != 2
    {
        return TestResult::Fail("a pollable descriptor was not read and written in place");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/killable",
    smoke_killable_wait_leaves_pollable_descriptors_alone
);

const SYSCALL_TASK: u64 = 0x6b11_ab21;

fn syscall_task() -> u64 {
    SYSCALL_TASK
}

/// `read(2)` of a file whose read never completes returns `Killed` to its
/// handler as soon as the task has SIGKILL pending, instead of parking for
/// good; the read itself is kept, with its buffer, until it finishes.
fn smoke_killable_read_of_a_stuck_file_returns_on_sigkill() -> TestResult {
    let _fixture = DetachFixture::new(SYSCALL_TASK);
    crate::handlers::install_task_id_lookup(syscall_task);
    let file = NeverFile::new();
    let ops: Arc<dyn FileOps> = file.clone();
    let mut staging = alloc::vec![0u8; 4096];
    crate::handlers::raise_signal_pending(SYSCALL_TASK, 9);
    let outcome = read(&ops, 0, &mut staging, 4096, ReadOptions::default());
    if outcome != Err(Killed) {
        return TestResult::Fail("a read parked on a stuck file did not end on SIGKILL");
    }
    if file.reads.load(Ordering::Relaxed) != 1 {
        return TestResult::Fail("the killed read never reached the file");
    }
    let Some(mut detached) = DETACHED.lock().take() else {
        return TestResult::Fail("the stuck read was dropped with its I/O in flight");
    };
    let waker = counting_waker();
    let mut cx = Context::from_waker(&waker);
    file.release.store(true, Ordering::Release);
    if detached.as_mut().poll(&mut cx) != Poll::Ready(()) {
        return TestResult::Fail("the detached read could not finish");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/killable",
    smoke_killable_read_of_a_stuck_file_returns_on_sigkill
);

/// A killed `write(2)` is not torn: the whole payload reaches the file after
/// the writer is gone.
fn smoke_killable_write_completes_after_its_writer_is_killed() -> TestResult {
    let _fixture = DetachFixture::new(SYSCALL_TASK);
    crate::handlers::install_task_id_lookup(syscall_task);
    let file = NeverFile::new();
    let ops: Arc<dyn FileOps> = file.clone();
    let mut payload = alloc::vec![0xa5u8; 1500];
    crate::handlers::raise_signal_pending(SYSCALL_TASK, 9);
    if write(&ops, 0, &mut payload) != Err(Killed) {
        return TestResult::Fail("a write parked on a stuck file did not end on SIGKILL");
    }
    if file.writes.load(Ordering::Relaxed) != 0 {
        return TestResult::Fail("the stuck write completed by itself");
    }
    let Some(mut detached) = DETACHED.lock().take() else {
        return TestResult::Fail("the stuck write was dropped mid-operation");
    };
    let waker = counting_waker();
    let mut cx = Context::from_waker(&waker);
    file.release.store(true, Ordering::Release);
    if detached.as_mut().poll(&mut cx) != Poll::Ready(())
        || file.writes.load(Ordering::Relaxed) != 1500
    {
        return TestResult::Fail("the killed write did not land whole");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/killable",
    smoke_killable_write_completes_after_its_writer_is_killed
);

/// Without a fatal signal the helpers are plain reads and writes, and hand
/// their buffers back.
fn smoke_killable_read_and_write_round_trip() -> TestResult {
    let _fixture = DetachFixture::new(SYSCALL_TASK);
    crate::handlers::install_task_id_lookup(syscall_task);
    let file = NeverFile::new();
    file.release.store(true, Ordering::Release);
    let ops: Arc<dyn FileOps> = file.clone();
    let mut staging = alloc::vec![0u8; 64];
    if read(&ops, 0, &mut staging, 16, ReadOptions::default()) != Ok(Some(Ok(16)))
        || staging.len() != 64
        || staging[..16] != [0x5a; 16]
        || staging[16..] != [0u8; 48]
    {
        return TestResult::Fail("a killable read did not fill and return its buffer");
    }
    let mut payload = alloc::vec![1u8; 32];
    if write(&ops, 0, &mut payload) != Ok(Some(Ok(32)))
        || payload.len() != 32
        || file.writes.load(Ordering::Relaxed) != 32
    {
        return TestResult::Fail("a killable write did not write and return its payload");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/killable",
    smoke_killable_read_and_write_round_trip
);

/// A fault fill that outlives its killed task gives its frame back.
fn smoke_killable_fill_frame_frees_the_frame_of_a_killed_fault() -> TestResult {
    let _fixture = DetachFixture::new(SYSCALL_TASK);
    crate::handlers::install_task_id_lookup(syscall_task);
    let file = NeverFile::new();
    let ops: Arc<dyn FileOps> = file.clone();
    let Ok(frame) = narf_memory::alloc_frame() else {
        return TestResult::Skip("no frame to fault into");
    };
    let frame = frame.start_address();
    let released_before = FRAMES_RELEASED.load(Ordering::Relaxed);
    crate::handlers::raise_signal_pending(SYSCALL_TASK, 9);
    if fill_frame(&ops, 0, frame, 4096) != Err(Killed) {
        return TestResult::Fail("a fault parked on a stuck file did not end on SIGKILL");
    }
    if FRAMES_RELEASED.load(Ordering::Relaxed) != released_before {
        return TestResult::Fail("the frame was freed while its read was in flight");
    }
    let Some(mut detached) = DETACHED.lock().take() else {
        return TestResult::Fail("the stuck fill was dropped with its I/O in flight");
    };
    let waker = counting_waker();
    let mut cx = Context::from_waker(&waker);
    file.release.store(true, Ordering::Release);
    if detached.as_mut().poll(&mut cx) != Poll::Ready(()) {
        return TestResult::Fail("the detached fill could not finish");
    }
    if FRAMES_RELEASED.load(Ordering::Relaxed) != released_before + 1 {
        return TestResult::Fail("the killed fault's frame was leaked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "userspace/killable",
    smoke_killable_fill_frame_frees_the_frame_of_a_killed_fault
);

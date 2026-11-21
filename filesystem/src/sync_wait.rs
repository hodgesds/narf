//! The bridge a synchronous filesystem entry point (a `DirOps::lookup`, a
//! mount constructor) uses to wait for an async filesystem future.
//!
//! In a system call the wait must sleep, as Linux's sleeping locks and I/O
//! waits do in process context: the calling task parks until the future's
//! waker fires and the CPU runs others meanwhile. Polling in place instead
//! starved every task pinned to that CPU — among them, once, the waiter an
//! async mutex had been handed to, so the lock the spinning poller needed
//! was never claimed and the whole filesystem stopped.
//!
//! Parking belongs to the userspace layer (it knows the user task and its
//! stackful continuation), which installs [`SyncWaitHooks`] at boot. Only
//! where there is no task to park — early boot, an IRQ or panic path, a
//! kernel test calling a filesystem directly — does the wait spin
//! ([`narf_scheduler::block_on_spin`]). Reaching that spin while a user task
//! is current is a bug: it is counted ([`spins_with_user_task`]) and logged.
//!
//! A plain (non-stackful) kernel task cannot park either: it is polled on the
//! executor's own stack. Spinning there stopped every other task of its CPU,
//! among them whichever one the wait was for — a mutex handed to a waiter of
//! the same CPU, a transaction joined there — and the CPU deadlocked on
//! itself. Linux's equivalent is sleeping in atomic context (`might_sleep`:
//! "BUG: sleeping function called from invalid context"). The wait is
//! counted ([`waits_in_task_poll`]) and reported once per call site (a panic
//! in kernel-test builds, so such callers get converted), and while it lasts
//! the CPU runs its other kernel tasks between polls
//! ([`narf_scheduler::poll_one_round_nested`]), one level deep.

use alloc::sync::Arc;
use core::future::Future;
use core::panic::Location;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

/// What the userspace layer provides.
#[derive(Debug)]
pub struct SyncWaitHooks {
    /// Whether the caller runs on a user task's stackful continuation.
    pub in_user_task: fn() -> bool,
    /// Park the current user task until its waker fires; false if it
    /// cannot be parked. The location is the filesystem entry point that is
    /// waiting, so `/proc/<pid>/stack` names it as the park site.
    pub park: fn(&'static core::panic::Location<'static>) -> bool,
}

static HOOKS: AtomicPtr<SyncWaitHooks> = AtomicPtr::new(core::ptr::null_mut());
static SPINS_WITH_USER_TASK: AtomicU64 = AtomicU64::new(0);

/// Install the hooks (boot, once).
pub fn install_sync_wait_hooks(hooks: &'static SyncWaitHooks) {
    HOOKS.store(
        hooks as *const SyncWaitHooks as *mut SyncWaitHooks,
        Ordering::Release,
    );
}

fn hooks() -> Option<&'static SyncWaitHooks> {
    // SAFETY: only `install_sync_wait_hooks` stores, and only a `&'static`.
    unsafe { HOOKS.load(Ordering::Acquire).as_ref() }
}

/// How many waits fell back to spinning while a user task was current.
pub fn spins_with_user_task() -> u64 {
    SPINS_WITH_USER_TASK.load(Ordering::Relaxed)
}

/// Wait for `future` from a synchronous filesystem entry point: parked on
/// a user task, spinning only where there is no task to park.
#[track_caller]
pub fn wait_sync<F: Future>(future: F) -> F::Output {
    let caller = core::panic::Location::caller();
    let mut future = core::pin::pin!(future);
    let hooks = hooks();
    let user = hooks.is_some_and(|h| (h.in_user_task)());
    if let Some(waker) = narf_scheduler::stackful::current_stackful_waker() {
        let mut cx = Context::from_waker(&waker);
        loop {
            if let Poll::Ready(out) = future.as_mut().poll(&mut cx) {
                return out;
            }
            match hooks {
                // A user task parks through its own layer, which keeps its
                // syscall bookkeeping (kernel span, the parked-at site).
                Some(h) if user => {
                    if !(h.park)(caller) {
                        break;
                    }
                }
                // A kernel task on a stackful continuation parks directly.
                // SAFETY: `current_stackful_waker` returned `Some`, so this
                // runs on the current stackful task inside its executor
                // context, and the future's waker — that task's — is what
                // makes it runnable again.
                _ => unsafe { narf_scheduler::stackful::yield_current_stackful() },
            }
        }
    }
    if user {
        note_spin(core::panic::Location::caller());
    } else if in_plain_task_poll() {
        return wait_in_task_poll(Pin::as_mut(&mut future), caller);
    }
    narf_scheduler::block_on_spin(Pin::as_mut(&mut future))
}

static WAITS_IN_TASK_POLL: AtomicU64 = AtomicU64::new(0);

/// Call sites already reported by [`note_task_poll_wait`].
const REPORTED_SITE_SLOTS: usize = 32;
static REPORTED_SITES: [AtomicPtr<Location<'static>>; REPORTED_SITE_SLOTS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; REPORTED_SITE_SLOTS];

/// A CPU already running its other tasks under a [`wait_in_task_poll`].
static NESTING: [AtomicBool; narf_lib::percpu::MAX_CPUS] =
    [const { AtomicBool::new(false) }; narf_lib::percpu::MAX_CPUS];

#[cfg(feature = "kernel-test")]
static EXPECT_TASK_POLL_WAIT: AtomicBool = AtomicBool::new(false);

/// Running a scheduler task's poll that is not on a stackful continuation
/// (that case parked above), and not in an interrupt that came in over it.
fn in_plain_task_poll() -> bool {
    narf_scheduler::current_task_id() != narf_scheduler::TaskId::NONE
        && !narf_lib::context::in_irq()
        && !narf_lib::context::in_trap_handler()
}

/// Whether `caller` is reported for the first time. A full table only
/// counts.
fn first_report(caller: &'static Location<'static>) -> bool {
    let site = core::ptr::from_ref(caller).cast_mut();
    for slot in &REPORTED_SITES {
        let seen = slot.load(Ordering::Acquire);
        if seen == site {
            return false;
        }
        if seen.is_null() {
            match slot.compare_exchange(
                core::ptr::null_mut(),
                site,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(other) if other == site => return false,
                Err(_) => {}
            }
        }
    }
    false
}

fn note_task_poll_wait(caller: &'static Location<'static>) {
    use core::fmt::Write as _;
    let count = WAITS_IN_TASK_POLL.fetch_add(1, Ordering::Relaxed) + 1;
    #[cfg(feature = "kernel-test")]
    if !EXPECT_TASK_POLL_WAIT.load(Ordering::Acquire) {
        panic!(
            "filesystem sync wait inside a plain kernel task's poll at {}:{}: make the task stackful or the caller async",
            caller.file(),
            caller.line()
        );
    }
    if first_report(caller) {
        let _ = writeln!(
            narf_console::Writer,
            "WARNING: filesystem sync wait inside a plain kernel task's poll at {}:{}: it cannot sleep, so its CPU runs its other kernel tasks until the wait ends [occurrence {count}]",
            caller.file(),
            caller.line(),
        );
    }
}

/// The waker of a [`wait_in_task_poll`]: records that the future asked to be
/// polled again.
struct Flag(AtomicBool);

impl alloc::task::Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::Release);
    }
}

/// Wait for `future` from inside a plain task's poll: between polls this CPU
/// runs its other kernel tasks (one level deep; a wait inside those polls in
/// place), its deferred wakes and its timers, so the task the wait depends on
/// gets the CPU — the closest a task that cannot sleep comes to Linux's
/// `schedule()`. User tasks are not run nested; an idle CPU can take them.
fn wait_in_task_poll<F: Future>(
    mut future: Pin<&mut F>,
    caller: &'static Location<'static>,
) -> F::Output {
    note_task_poll_wait(caller);
    // The task cannot migrate during its own poll: this stays its CPU.
    let cpu = narf_lib::percpu::current_cpu().min(narf_lib::percpu::MAX_CPUS - 1);
    let nest = !NESTING[cpu].swap(true, Ordering::AcqRel);
    let flag = Arc::new(Flag(AtomicBool::new(false)));
    let waker = Waker::from(Arc::clone(&flag));
    let mut cx = Context::from_waker(&waker);
    let out = loop {
        flag.0.store(false, Ordering::Release);
        if let Poll::Ready(out) = future.as_mut().poll(&mut cx) {
            break out;
        }
        if nest {
            let _ = narf_lib::deferred_wake::drain_and_wake();
            let _ = narf_scheduler::poll_one_round_nested();
        } else {
            let _ = narf_time::hrtimer::hrtimer_run_softirq();
        }
        if !flag.0.load(Ordering::Acquire) {
            narf_scheduler::sleep_pumps::run();
            core::hint::spin_loop();
        }
    };
    if nest {
        NESTING[cpu].store(false, Ordering::Release);
    }
    out
}

fn note_spin(caller: &core::panic::Location<'_>) {
    use core::fmt::Write as _;
    let count = SPINS_WITH_USER_TASK.fetch_add(1, Ordering::Relaxed) + 1;
    if count > 8 && count % 1024 != 0 {
        return;
    }
    let _ = writeln!(
        narf_console::Writer,
        "ERROR: filesystem sync wait spinning with a user task current (its CPU is held until the wait ends): {}:{} [occurrence {count}]",
        caller.file(),
        caller.line(),
    );
}

/// How many waits ran inside a plain (non-stackful) kernel task's poll.
pub fn waits_in_task_poll() -> u64 {
    WAITS_IN_TASK_POLL.load(Ordering::Relaxed)
}

/// Test-only: whether a wait inside a plain task's poll is expected (counted
/// rather than a kernel-test panic). Returns the previous setting.
#[doc(hidden)]
pub fn __test_expect_task_poll_wait(on: bool) -> bool {
    #[cfg(feature = "kernel-test")]
    {
        EXPECT_TASK_POLL_WAIT.swap(on, Ordering::AcqRel)
    }
    #[cfg(not(feature = "kernel-test"))]
    {
        let _ = on;
        false
    }
}

#[cfg(feature = "kernel-test")]
mod tests {
    use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
    use core::task::{Context, Poll};

    use narf_kernel_test::{kernel_test_in, TestResult};
    use narf_lib::mutex::{Mutex, MutexGuard};
    use narf_lib::sync::IrqSafeSpinLock;

    static LOCK: Mutex<()> = Mutex::new(());
    static BARGER: IrqSafeSpinLock<Option<MutexGuard<'static, ()>>> = IrqSafeSpinLock::new(None);
    static OWNER_POLLS: AtomicUsize = AtomicUsize::new(0);
    static OWNER_DONE: AtomicBool = AtomicBool::new(false);
    /// 0 not yet, 1 the lock, 2 the deadline.
    static WAITER_RESULT: AtomicU8 = AtomicU8::new(0);
    static OWNER_DONE_FIRST: AtomicBool = AtomicBool::new(false);

    const WAIT_LIMIT_NS: u64 = 2_000_000_000;

    /// `fut`, or `None` once the TSC passes `until`. Self-waking, so it needs
    /// no timer: the waiting CPU may take no interrupt.
    struct Bounded<F> {
        fut: core::pin::Pin<alloc::boxed::Box<F>>,
        until: u64,
    }

    impl<F: core::future::Future> core::future::Future for Bounded<F> {
        type Output = Option<F::Output>;
        fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            if let Poll::Ready(out) = this.fut.as_mut().poll(cx) {
                return Poll::Ready(Some(out));
            }
            if narf_time::now_cycles() >= this.until {
                return Poll::Ready(None);
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    /// Counts its polls in [`OWNER_POLLS`].
    struct CountPolls<F>(core::pin::Pin<alloc::boxed::Box<F>>);

    impl<F: core::future::Future> core::future::Future for CountPolls<F> {
        type Output = F::Output;
        fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
            OWNER_POLLS.fetch_add(1, Ordering::AcqRel);
            self.get_mut().0.as_mut().poll(cx)
        }
    }

    fn poll_now<F: core::future::Future>(fut: F) -> Option<F::Output> {
        let mut fut = core::pin::pin!(fut);
        let waker = core::task::Waker::noop();
        match fut.as_mut().poll(&mut Context::from_waker(waker)) {
            Poll::Ready(out) => Some(out),
            Poll::Pending => None,
        }
    }

    /// A plain kernel task (polled on the executor stack, so it cannot park)
    /// reaches a synchronous filesystem wait for an async mutex the last
    /// release handed to another task of the same CPU. Only that task can
    /// claim it, and only this CPU can run it: the wait must let the CPU run
    /// it, as a Linux kthread sleeping in `mutex_lock` lets its CPU run the
    /// waiter the lock was handed to (`__mutex_handoff`). Spinning in place
    /// deadlocks the CPU on itself.
    fn smoke_sync_wait_in_a_plain_task_lets_its_cpu_run() -> TestResult {
        let me = narf_lib::percpu::current_cpu();
        if me != narf_scheduler::affinity::CpuId::BOOT.0 as usize
            || narf_scheduler::current_task_id() != narf_scheduler::TaskId::NONE
        {
            return TestResult::Skip("must run on the boot CPU outside any task");
        }
        OWNER_POLLS.store(0, Ordering::Release);
        OWNER_DONE.store(false, Ordering::Release);
        WAITER_RESULT.store(0, Ordering::Release);
        OWNER_DONE_FIRST.store(false, Ordering::Release);
        let Some(first) = LOCK.try_lock() else {
            return TestResult::Fail("test lock already held");
        };
        // The owner-to-be: a plain task of this CPU queued on the lock.
        narf_scheduler::spawn(CountPolls(alloc::boxed::Box::pin(async {
            let _guard = LOCK.lock().await;
            OWNER_DONE.store(true, Ordering::Release);
        })));
        narf_scheduler::poll_one_round();
        // Release (the owner is woken), barge in before it re-polls, and let
        // it re-poll: passed over once, it is handed the lock at the next
        // release.
        drop(first);
        let Some(barger) = LOCK.try_lock() else {
            return TestResult::Fail("barging acquisition failed");
        };
        *BARGER.lock() = Some(barger);
        narf_scheduler::poll_one_round();
        if OWNER_POLLS.load(Ordering::Acquire) < 2 || OWNER_DONE.load(Ordering::Acquire) {
            let held = BARGER.lock().take();
            drop(held);
            return TestResult::Fail("could not set up the hand-off");
        }
        // The waiter: a plain task of this CPU that hands the lock to the
        // owner and then waits for it synchronously.
        narf_scheduler::spawn(async {
            let held = BARGER.lock().take();
            drop(held);
            let until =
                narf_time::now_cycles().saturating_add(narf_time::ns_to_cycles(WAIT_LIMIT_NS));
            let got = crate::wait_sync(Bounded {
                fut: alloc::boxed::Box::pin(LOCK.lock()),
                until,
            });
            OWNER_DONE_FIRST.store(OWNER_DONE.load(Ordering::Acquire), Ordering::Release);
            WAITER_RESULT.store(if got.is_some() { 1 } else { 2 }, Ordering::Release);
        });
        let expected = super::__test_expect_task_poll_wait(true);
        let counted = super::waits_in_task_poll();
        narf_scheduler::poll_one_round();
        let counted = super::waits_in_task_poll().wrapping_sub(counted);
        super::__test_expect_task_poll_wait(expected);
        // Whatever happened, let both tasks finish.
        for _ in 0..16 {
            if OWNER_DONE.load(Ordering::Acquire) && WAITER_RESULT.load(Ordering::Acquire) != 0 {
                break;
            }
            narf_scheduler::poll_one_round();
        }
        let free = poll_now(LOCK.lock()).is_some();
        match WAITER_RESULT.load(Ordering::Acquire) {
            0 => return TestResult::Fail("the waiting task never finished"),
            2 => {
                return TestResult::Fail(
                    "a plain task's synchronous wait spun its CPU: the lock owner never ran",
                )
            }
            _ => {}
        }
        if !OWNER_DONE_FIRST.load(Ordering::Acquire) {
            return TestResult::Fail("the waiter got the lock before the owner it was handed to");
        }
        if counted == 0 {
            return TestResult::Fail("a wait inside a plain task's poll was not counted");
        }
        if !free {
            return TestResult::Fail("the lock was left held");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "filesystem/sync_wait",
        smoke_sync_wait_in_a_plain_task_lets_its_cpu_run
    );
}

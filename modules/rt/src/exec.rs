//! An executor for a module's own futures.
//!
//! The kernel's scheduler cannot run a module's futures — a `Future` is a
//! `repr(Rust)` object and never crosses the KABI. A module therefore owns an
//! [`Executor`] (normally a `static`) and calls [`Executor::run`] from every
//! upcall it gets: the 1 ms device poller (`narf_spawn_poller`), its IRQ
//! vector callbacks and its probe. Each `run` polls every live task, and keeps
//! going while some task's waker fired during the pass, up to
//! [`MAX_PASSES`].
//!
//! Upcalls can arrive on several CPUs at once. Only one of them executes the
//! tasks; any other returns [`Run::Busy`] after flagging that another pass is
//! wanted, so a wake is never lost — at worst it waits for the next
//! heartbeat.
//!
//! Tasks must be `Send`: they are polled from whichever CPU's upcall holds
//! the executor. That also keeps the [`crate::sync::SpinLock`] rule — a task
//! holding a spin-lock guard across `.await` is `!Send` and does not compile.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::fmt;
use core::future::Future;
use core::pin::{pin, Pin};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

use crate::sync::SpinLock;

/// Passes one [`Executor::run`] makes at most before returning to the
/// kernel, so a task that wakes itself forever cannot pin the upcall's CPU.
pub const MAX_PASSES: usize = 8;

type Task = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Why [`Executor::spawn`] refused a task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stopped;

/// What one [`Executor::run`] call did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Run {
    /// Another upcall is running the tasks; it will make the extra pass.
    Busy,
    /// Every task has completed (or the executor was stopped and drained).
    Idle,
    /// This many tasks are still pending.
    Pending(usize),
}

/// A module-owned executor. See the module docs.
pub struct Executor {
    /// Held by the one upcall currently polling `tasks`.
    running: AtomicBool,
    /// Set by wakers, `spawn` and losing callers: make another pass.
    repoll: AtomicBool,
    /// Set by [`Executor::stop`]; the next run drops every task.
    stopped: AtomicBool,
    /// Spawned but not yet adopted by a run.
    incoming: SpinLock<Vec<Task>>,
    /// Owned by whoever holds `running`.
    tasks: UnsafeCell<Vec<Task>>,
    /// Spawned and not yet completed or dropped.
    live: AtomicUsize,
}

// SAFETY: `tasks` is only touched by the caller that won `running`, which
// serialises it; every other field is atomic or locked. Tasks are `Send`.
unsafe impl Sync for Executor {}

impl Executor {
    /// An empty executor, usable as a `static`.
    pub const fn new() -> Self {
        Self {
            running: AtomicBool::new(false),
            repoll: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            incoming: SpinLock::new(Vec::new()),
            tasks: UnsafeCell::new(Vec::new()),
            live: AtomicUsize::new(0),
        }
    }

    /// Queue `future`; it is first polled by the next [`Executor::run`].
    pub fn spawn<F>(&self, future: F) -> Result<(), Stopped>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if self.stopped.load(Ordering::Acquire) {
            return Err(Stopped);
        }
        let task: Task = Box::pin(future);
        self.incoming.lock().push(task);
        self.live.fetch_add(1, Ordering::AcqRel);
        self.repoll.store(true, Ordering::Release);
        Ok(())
    }

    /// Tasks spawned and not yet finished.
    pub fn live(&self) -> usize {
        self.live.load(Ordering::Acquire)
    }

    /// Refuse new tasks and drop every existing one on the next run. Used on
    /// module exit, after the hardware the tasks drive has been quiesced:
    /// module text is about to be unmapped, so no future may outlive it.
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        self.repoll.store(true, Ordering::Release);
    }

    /// Whether [`Executor::stop`] has been called.
    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    /// Poll every task. Call from each upcall the module receives.
    pub fn run(&'static self) -> Run {
        let mut passes = 0;
        loop {
            if self.running.swap(true, Ordering::Acquire) {
                // The winner re-checks `repoll` before releasing `running`,
                // or right after (below), so this request is honoured.
                self.repoll.store(true, Ordering::Release);
                return Run::Busy;
            }
            // SAFETY: winning `running` makes this the only reference to
            // `tasks` until the store below.
            let tasks = unsafe { &mut *self.tasks.get() };
            let waker = self.waker();
            let mut cx = Context::from_waker(&waker);
            while passes < MAX_PASSES {
                self.repoll.store(false, Ordering::Release);
                tasks.append(&mut self.incoming.lock());
                if self.stopped.load(Ordering::Acquire) {
                    let dropped = tasks.len();
                    tasks.clear();
                    self.live.fetch_sub(dropped, Ordering::AcqRel);
                    break;
                }
                let mut i = 0;
                while i < tasks.len() {
                    if tasks[i].as_mut().poll(&mut cx).is_ready() {
                        drop(tasks.swap_remove(i));
                        self.live.fetch_sub(1, Ordering::AcqRel);
                    } else {
                        i += 1;
                    }
                }
                passes += 1;
                if !self.repoll.load(Ordering::Acquire) {
                    break;
                }
            }
            self.running.store(false, Ordering::Release);
            // A caller that lost the race between our last `repoll` check and
            // the store above returned `Busy`; take its pass now.
            if passes >= MAX_PASSES || !self.repoll.load(Ordering::Acquire) {
                return match self.live() {
                    0 => Run::Idle,
                    n => Run::Pending(n),
                };
            }
        }
    }

    fn waker(&'static self) -> Waker {
        let data = (&self.repoll as *const AtomicBool).cast::<()>();
        // SAFETY: `data` points into a `'static` executor, and `REPOLL_VTABLE`
        // treats it only as that `AtomicBool`.
        unsafe { Waker::from_raw(RawWaker::new(data, &REPOLL_VTABLE)) }
    }
}

impl Default for Executor {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Executor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Executor")
            .field("live", &self.live())
            .field("stopped", &self.is_stopped())
            .finish_non_exhaustive()
    }
}

// The waker for executor tasks: `data` is the executor's `repoll` flag.
static REPOLL_VTABLE: RawWakerVTable =
    RawWakerVTable::new(repoll_clone, repoll_wake, repoll_wake, repoll_drop);

fn repoll_clone(data: *const ()) -> RawWaker {
    RawWaker::new(data, &REPOLL_VTABLE)
}

fn repoll_wake(data: *const ()) {
    // SAFETY: `data` is a `'static` executor's `repoll` flag (see `waker`).
    let flag = unsafe { &*data.cast::<AtomicBool>() };
    flag.store(true, Ordering::Release);
}

fn repoll_drop(_data: *const ()) {}

/// Drive one future to completion on the calling upcall, spinning between
/// polls. The synchronous bridge for code that cannot be `async` (the
/// module-side analogue of the kernel's `block_on_spin`).
///
/// It polls only `future`, not the module's [`Executor`]: a future that
/// needs another executor task to make progress never completes here. Use it
/// only for futures that advance on their own polls (hardware status,
/// deadlines).
pub fn block_on<F: Future>(future: F) -> F::Output {
    static NEVER_WAKES: AtomicBool = AtomicBool::new(false);
    let data = (&NEVER_WAKES as *const AtomicBool).cast::<()>();
    // SAFETY: as in `Executor::waker`; this flag is a `'static` too. The
    // flag's value is unused: the loop below re-polls unconditionally.
    let waker = unsafe { Waker::from_raw(RawWaker::new(data, &REPOLL_VTABLE)) };
    let mut cx = Context::from_waker(&waker);
    let mut future = pin!(future);
    loop {
        if let Poll::Ready(out) = future.as_mut().poll(&mut cx) {
            return out;
        }
        core::hint::spin_loop();
    }
}

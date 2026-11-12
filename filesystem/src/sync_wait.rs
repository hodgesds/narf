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

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use core::task::{Context, Poll};

/// What the userspace layer provides.
#[derive(Debug)]
pub struct SyncWaitHooks {
    /// Whether the caller runs on a user task's stackful continuation.
    pub in_user_task: fn() -> bool,
    /// Park the current user task until its waker fires; false if it
    /// cannot be parked.
    pub park: fn() -> bool,
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
                    if !(h.park)() {
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
    }
    narf_scheduler::block_on_spin(Pin::as_mut(&mut future))
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

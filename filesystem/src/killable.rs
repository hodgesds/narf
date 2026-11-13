//! Waits a fatal signal ends (Linux `mutex_lock_killable`,
//! `down_write_killable`): a filesystem's lock waits on behalf of a syscall
//! give up when the calling task has been sent SIGKILL.
//!
//! The filesystem layer does not know tasks or signals; the userspace layer
//! installs [`KillHooks`] once at boot. Without them (standalone filesystem
//! tests) nothing is ever killed and [`killable`] is the plain wait.

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicPtr, Ordering};
use core::task::{Context, Poll, Waker};

/// What the userspace layer provides.
#[derive(Debug)]
pub struct KillHooks {
    /// The calling task's id, 0 outside any task.
    pub current: fn() -> u64,
    /// Whether task `id` has a fatal signal pending.
    pub pending: fn(u64) -> bool,
    /// Wake `waker` when task `id` is sent a signal.
    pub arm: fn(u64, Waker),
    /// Forget the waker [`KillHooks::arm`] registered for task `id`.
    pub disarm: fn(u64),
    /// The killed task whose operation the *current scheduler task* is
    /// finishing after its owner was killed, 0 when it is running its own.
    /// Task-local: never inferred from the CPU.
    pub owner: fn() -> u64,
}

/// The task the running operation belongs to when it was handed off from a
/// killed task ([`KillHooks::owner`]), 0 otherwise. A filesystem that keys
/// state to the task that started an operation (btrfs's transaction gate)
/// uses this so the handed-off operation is still recognised as that
/// task's.
pub fn operation_owner() -> u64 {
    hooks().map_or(0, |h| (h.owner)())
}

static HOOKS: AtomicPtr<KillHooks> = AtomicPtr::new(core::ptr::null_mut());

/// Install the hooks (boot, once).
pub fn install_kill_hooks(hooks: &'static KillHooks) {
    HOOKS.store(
        hooks as *const KillHooks as *mut KillHooks,
        Ordering::Release,
    );
}

/// Test-only: install `hooks` (or none) and return what was installed, so a
/// test that models a hand-off can put the boot hooks back.
#[doc(hidden)]
pub fn replace_kill_hooks(hooks: Option<&'static KillHooks>) -> Option<&'static KillHooks> {
    let new = hooks.map_or(core::ptr::null_mut(), |h| {
        h as *const KillHooks as *mut KillHooks
    });
    let old = HOOKS.swap(new, Ordering::AcqRel);
    // SAFETY: only `&'static KillHooks` are ever stored.
    unsafe { old.as_ref() }
}

fn hooks() -> Option<&'static KillHooks> {
    // SAFETY: only `install_kill_hooks` stores, and only a `&'static`.
    unsafe { HOOKS.load(Ordering::Acquire).as_ref() }
}

/// The calling task's id, 0 when unknown (no hooks installed, or outside
/// any task).
pub fn current_task() -> u64 {
    hooks().map_or(0, |h| (h.current)())
}

/// Whether the calling task has been sent SIGKILL.
pub fn current_killed() -> bool {
    hooks().is_some_and(|h| {
        let task = (h.current)();
        task != 0 && (h.pending)(task)
    })
}

/// `future`, ended early (`None`) if the calling task is sent SIGKILL while
/// it waits. Only for waits that hold nothing a give-up would strand.
pub fn killable<F: Future>(future: F) -> Killable<F> {
    let task = hooks().map_or(0, |h| (h.current)());
    Killable {
        inner: future,
        task,
        armed: false,
    }
}

/// See [`killable`].
#[derive(Debug)]
pub struct Killable<F> {
    inner: F,
    task: u64,
    armed: bool,
}

impl<F: Future> Future for Killable<F> {
    type Output = Option<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<F::Output>> {
        // SAFETY: `inner` is never moved out of the pinned `Killable`.
        let this = unsafe { self.get_unchecked_mut() };
        // SAFETY: as above.
        let inner = unsafe { Pin::new_unchecked(&mut this.inner) };
        if let Poll::Ready(out) = inner.poll(cx) {
            return Poll::Ready(Some(out));
        }
        let (Some(h), true) = (hooks(), this.task != 0) else {
            return Poll::Pending;
        };
        (h.arm)(this.task, cx.waker().clone());
        this.armed = true;
        if (h.pending)(this.task) {
            return Poll::Ready(None);
        }
        Poll::Pending
    }
}

impl<F> Drop for Killable<F> {
    fn drop(&mut self) {
        if self.armed {
            if let Some(h) = hooks() {
                (h.disarm)(self.task);
            }
        }
    }
}

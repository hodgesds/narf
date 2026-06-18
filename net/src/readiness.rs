//! Net → executor readiness notification.
//!
//! The TCP stack runs in a low crate (`narf-net`); the user-task
//! epoll/poll machinery lives in a high crate (`narf-userspace`). When
//! inbound data lands in a socket's receive buffer we want to wake any
//! user task parked in `epoll_wait`/`poll` *immediately*, rather than
//! leaving it to re-poll at its next wheel deadline (redis's ~100 ms
//! serverCron tick — which turned a sub-millisecond round-trip into an
//! ~80 ms one). A direct call would invert the crate layering, so the
//! high crate installs a hook here at boot and the stack invokes it.
//!
//! The hook is a bare `fn()` stored as an atomic usize (no allocation,
//! callable from the RX-pump task context). It is best-effort: a missed
//! notify just falls back to the deadline re-poll, so there is no
//! correctness dependency on it — only latency.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static HOOK: AtomicUsize = AtomicUsize::new(0);

/// Monotonic notify generation, bumped on every [`notify`]. epoll/poll
/// parking uses it to close the classic lost-wakeup race: snapshot the
/// generation before checking readiness, and after registering the
/// waker re-check it — if it advanced, data arrived in the window and
/// the task must re-poll instead of sleeping out its deadline.
static GEN: AtomicU64 = AtomicU64::new(0);

/// Current notify generation.
#[inline]
pub fn generation() -> u64 {
    GEN.load(Ordering::Acquire)
}

/// Install the readiness hook. Called once from `narf-userspace` boot.
pub fn set_hook(f: fn()) {
    HOOK.store(f as usize, Ordering::Release);
}

/// Signal that a socket became readable (or a listener gained a pending
/// connection). Wakes parked epoll/poll waiters via the installed hook.
/// No-op until a hook is set.
#[inline]
pub fn notify() {
    GEN.fetch_add(1, Ordering::AcqRel);
    let p = HOOK.load(Ordering::Acquire);
    if p != 0 {
        // SAFETY: `p` is only ever set by `set_hook` from a `fn()`
        // pointer; transmuting it back to `fn()` is sound.
        let f: fn() = unsafe { core::mem::transmute::<usize, fn()>(p) };
        f();
    }
}

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

/// Bump the notify generation WITHOUT invoking the wake hook. Used by callers
/// that do their own TARGETED wake (e.g. AF_UNIX point-to-point: wake only the
/// peer's reader) but still need the generation to advance so a poller caught
/// in the check→register→park race re-polls instead of sleeping out its
/// deadline. Pairs with a direct waker fire in the high crate.
#[inline]
pub fn bump_generation() {
    GEN.fetch_add(1, Ordering::AcqRel);
}

/// Install the readiness hook. Called once from `narf-userspace` boot.
pub fn set_hook(f: fn(u64)) {
    HOOK.store(f as usize, Ordering::Release);
}

/// Signal that a socket became readable (or a listener gained a pending
/// connection). `key` identifies WHICH socket — the kernel TCB id (a
/// connection's id for data, the listener's id for an accept) — so the
/// hook can wake ONLY the task that owns that socket instead of every
/// parked waiter (the thundering-herd / cross-core-IPI storm under SMP).
/// `key == 0` means "unknown" → the hook falls back to waking everyone.
/// No-op until a hook is set.
#[inline]
pub fn notify(key: u64) {
    GEN.fetch_add(1, Ordering::AcqRel);
    let p = HOOK.load(Ordering::Acquire);
    if p != 0 {
        // SAFETY: `p` is only ever set by `set_hook` from a `fn(u64)`
        // pointer; transmuting it back is sound.
        let f: fn(u64) = unsafe { core::mem::transmute::<usize, fn(u64)>(p) };
        f(key);
    }
}

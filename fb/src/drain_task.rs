//! Kernel-resident drain task for the per-process DrawRing
//! registry.
//!
//! Spawned once at boot. The scheduler polls every registered
//! ring and executes queued draw commands against the shared
//! FbWriter. The task self-wakes — `cx.waker().wake_by_ref()`
//! before each `Poll::Pending` — so the executor re-polls it on
//! every round (mirrors `narf_scheduler::yield_now`). This is the
//! display-engine kthread shape: one CPU keeps the scanout fed
//! whenever any producer ring has work.
//!
//! `registry::drain_all` is cheap on empty rings (a single
//! relaxed load per ring), so the spin cost is bounded by the
//! ring count when nothing is producing. A future
//! producer-driven waker handoff (set on `fb_connect`, fired on
//! producer-side `head` advance) replaces self-waking when SMP
//! IPI plumbing for FB lands.

use core::pin::Pin;
use core::task::{Context, Poll};
use core::future::Future;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::{registry, FbWriter};

static DRAIN_TICKS:    AtomicU64 = AtomicU64::new(0);
static DRAIN_EXECUTED: AtomicU64 = AtomicU64::new(0);
static DRAIN_ERRORS:   AtomicU64 = AtomicU64::new(0);

/// Snapshot the per-tick / per-call counters. Returns
/// `(ticks, executed, errors)`.
pub fn stats() -> (u64, u64, u64) {
    (
        DRAIN_TICKS.load(Ordering::Relaxed),
        DRAIN_EXECUTED.load(Ordering::Relaxed),
        DRAIN_ERRORS.load(Ordering::Relaxed),
    )
}

/// Run one drain pass. Public so a future SYS_FB_DRAIN_KICK
/// syscall handler can synchronously prod a drain.
pub fn drain_once(writer: &FbWriter) -> (u32, u32) {
    DRAIN_TICKS.fetch_add(1, Ordering::Relaxed);
    let (ok, err) = registry::drain_all(writer);
    DRAIN_EXECUTED.fetch_add(ok  as u64, Ordering::Relaxed);
    DRAIN_ERRORS.fetch_add(  err as u64, Ordering::Relaxed);
    (ok, err)
}

/// Future shape: poll → drain → self-wake → return Pending →
/// repeat. The self-wake (`wake_by_ref` before returning) keeps
/// the task's awake flag set so the executor re-polls it on
/// every round. Without it the task would park after the first
/// poll and producer rings would fill up un-drained.
pub struct DrainTask {
    writer: FbWriter,
}

impl core::fmt::Debug for DrainTask {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DrainTask").finish_non_exhaustive()
    }
}

impl DrainTask {
    pub fn new(writer: FbWriter) -> Self { Self { writer } }
}

impl Future for DrainTask {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // Run one pass, then re-arm the awake flag so the
        // executor re-polls us next round. Same pattern as
        // narf_scheduler::yield_now — without the wake_by_ref the
        // scheduler's `awake.swap(false)` gate parks us after one
        // poll and the FB scanout stops advancing.
        drain_once(&self.writer);
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}

/// Test-only counter reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    DRAIN_TICKS.store(0, Ordering::Relaxed);
    DRAIN_EXECUTED.store(0, Ordering::Relaxed);
    DRAIN_ERRORS.store(0, Ordering::Relaxed);
}

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

use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll};

#[cfg(not(feature = "kernel-test"))]
use crate::status;
use crate::{registry, FbWriter};

static DRAIN_TICKS: AtomicU64 = AtomicU64::new(0);
static DRAIN_EXECUTED: AtomicU64 = AtomicU64::new(0);
static DRAIN_ERRORS: AtomicU64 = AtomicU64::new(0);
/// TSC at last status-panel repaint. Drives a wheel-independent
/// ~250 ms refresh in `DrainTask::poll` (the `fb-status-refresh`
/// initcall relies on `narf_time::sleep_cycles` which silently
/// never wakes when the timer wheel arm callback isn't installed —
/// HPET probe failure on Zen2 mobile silicon is the motivating
/// case). Read via raw `now_cycles()` so no wheel dependency.
#[cfg(not(feature = "kernel-test"))]
static STATUS_LAST_TSC: AtomicU64 = AtomicU64::new(0);
#[cfg(not(feature = "kernel-test"))]
const STATUS_REPAINT_CYCLES: u64 = 250_000_000;

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
    DRAIN_EXECUTED.fetch_add(ok as u64, Ordering::Relaxed);
    DRAIN_ERRORS.fetch_add(err as u64, Ordering::Relaxed);
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
    pub fn new(writer: FbWriter) -> Self {
        Self { writer }
    }
}

impl Future for DrainTask {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // Slot 22: paint UNCONDITIONALLY at poll entry, before
        // anything else. If slot 22 doesn't paint on the laptop
        // *with this build*, DrainTask isn't being polled at all
        // → BSP wedged inside whatever task is ahead of DrainTask
        // in the queue. If slot 22 paints but slot 27 (further
        // down) doesn't, drain_once is wedging.
        narf_memory::beacon::paint(22, 0x00FF_FFFF); // white
        // Run one pass, then re-arm the awake flag so the
        // executor re-polls us next round. Same pattern as
        // narf_scheduler::yield_now — without the wake_by_ref the
        // scheduler's `awake.swap(false)` gate parks us after one
        // poll and the FB scanout stops advancing.
        drain_once(&self.writer);
        // Slot 27: DrainTask::poll heartbeat. Toggles colour each
        // poll so the user sees that the executor IS polling the
        // drain task. If 27 stays a single colour, BSP is wedged
        // on something else (init/shell/measure-phys task).
        #[cfg(not(feature = "kernel-test"))]
        {
            let n = DRAIN_TICKS.load(Ordering::Relaxed);
            let colour = if n & 1 == 0 { 0x00FF_4040 } else { 0x0040_FF40 };
            narf_memory::beacon::paint(27, colour);
        }
        // Wheel-independent status-panel refresh. Each poll reads
        // TSC; ~250 ms apart we re-paint. Skipped under kernel-test
        // because tests install/clear scratch scanouts and the live
        // subsystem queries panel does (USB, I2C, AML, power) can
        // corrupt the test scanout or read mid-reset state.
        #[cfg(not(feature = "kernel-test"))]
        {
            let now = narf_time::now_cycles();
            let last = STATUS_LAST_TSC.load(Ordering::Relaxed);
            if now.saturating_sub(last) >= STATUS_REPAINT_CYCLES {
                STATUS_LAST_TSC.store(now, Ordering::Relaxed);
                status::paint(&self.writer);
                // Slot 26: status::paint heartbeat. Toggles each
                // repaint. If 26 changes but the panel isn't on
                // screen, status::paint runs but its writes aren't
                // landing (FbWriter cap issue, scanout swap, etc).
                let n = STATUS_LAST_TSC.load(Ordering::Relaxed);
                let colour = if (n >> 28) & 1 == 0 { 0x000080_FF } else { 0x00FF_8000 };
                narf_memory::beacon::paint(26, colour);
            }
        }
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

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

/// Cycle period between drain passes. ~50M @ 3.3 GHz ≈ 15 ms ≈
/// 60 Hz. Fast enough for any UI that needs to look smooth, slow
/// enough that the drain doesn't starve init/shell on real
/// silicon where each MMIO write costs orders of magnitude more
/// than the equivalent QEMU emulated write. The old self-wake
/// pattern (Pending + wake_by_ref) was the right shape for QEMU
/// where the scheduler had plenty of slack to interleave; on
/// real HW it starved the user tasks and they never reached the
/// shell prompt.
const DRAIN_PERIOD_CYCLES: u64 = 50_000_000;

/// Run the FB-drain loop. Drains all registered command rings,
/// repaints the status panel ~4 Hz, then sleeps the rest of the
/// 60 Hz frame. Sleep is timer-driven (via narf_time's wheel) so
/// the task DOESN'T hold the executor — init/shell run between
/// frames the same way they'd run between any other timer-driven
/// task.
///
/// This replaces the old `DrainTask: impl Future` self-wake
/// pattern. Spawned via `narf_scheduler::spawn_stackful` so the
/// drain loop has its own kernel stack.
pub async fn drain_loop(writer: FbWriter) {
    loop {
        narf_memory::beacon::paint(22, 0x00FF_FFFF); // slot 22: poll entry
        drain_once(&writer);
        #[cfg(not(feature = "kernel-test"))]
        {
            let n = DRAIN_TICKS.load(Ordering::Relaxed);
            let colour = if n & 1 == 0 { 0x00FF_4040 } else { 0x0040_FF40 };
            narf_memory::beacon::paint(27, colour);
        }
        // Status panel repaint at ~4 Hz; gated by TSC so missed
        // drain ticks (e.g. preempt slice) don't desync it.
        #[cfg(not(feature = "kernel-test"))]
        {
            let now = narf_time::now_cycles();
            let last = STATUS_LAST_TSC.load(Ordering::Relaxed);
            if now.saturating_sub(last) >= STATUS_REPAINT_CYCLES {
                STATUS_LAST_TSC.store(now, Ordering::Relaxed);
                status::paint(&writer);
                let n = STATUS_LAST_TSC.load(Ordering::Relaxed);
                let colour = if (n >> 28) & 1 == 0 { 0x000080_FF } else { 0x00FF_8000 };
                narf_memory::beacon::paint(26, colour);
            }
        }
        narf_time::sleep_cycles(DRAIN_PERIOD_CYCLES).await;
    }
}

/// Back-compat shim — kept so tests + existing call sites that
/// construct a DrainTask continue to compile. The real spawn
/// path uses `drain_loop` directly.
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
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        // Single-poll completion — this future is a legacy
        // shape; real callers should use `drain_loop` via
        // `spawn_stackful` directly.
        drain_once(&self.writer);
        Poll::Ready(())
    }
}

/// Test-only counter reset.
#[doc(hidden)]
pub fn __reset_for_test() {
    DRAIN_TICKS.store(0, Ordering::Relaxed);
    DRAIN_EXECUTED.store(0, Ordering::Relaxed);
    DRAIN_ERRORS.store(0, Ordering::Relaxed);
}

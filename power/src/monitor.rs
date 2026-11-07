//! Power monitor — the periodic watcher (Refs #750).
//!
//! This is the re-enabled `power-monitor` initcall. It was
//! bisect-disabled as a no-op stub: the original code evaluated live
//! AML methods (`_BST` etc.) synchronously on the boot path, and on
//! the bring-up laptop that evaluation could be slow or hang, so the
//! initcall was stubbed to isolate the wedge.
//!
//! The re-enable keeps the boot path cheap on purpose. The initcall
//! only spawns the watcher task; every provider poll happens in that
//! task, off the boot path, via [`crate::service::snapshot`]. A
//! slow or hung EC method can therefore wedge at most this task —
//! never boot, and never the service worker, which runs in its own
//! task. The snapshot itself is the same provider evaluation the
//! platform composition already performs on demand; the watcher adds
//! a cadence, not a new evaluation path.
//!
//! Each poll:
//!
//! 1. Produces a fused snapshot through the registered
//!    [`crate::service::StateProviders`] (battery `_BIF`/`_BST`, AC
//!    `_PSR`, cached lid state, temperatures). Producing the snapshot
//!    is what fires the service's edge-triggered critical-battery
//!    warning hook — the watcher is the production caller that makes
//!    that hook live; before it, `snapshot()` had only test callers.
//! 2. Diffs the AC and lid fields against the previous poll and feeds
//!    genuine transitions into the service intake
//!    ([`crate::service::on_ac_changed`],
//!    [`crate::service::on_lid_changed`]), so a transition the EC /
//!    AML-Notify event path missed still reaches policy (lid close →
//!    suspend request) and the event-cached snapshot fallback. The
//!    feed is edge-triggered, not level: a lid that stays closed
//!    across polls requests suspend exactly once.
//! 3. Caches the snapshot as [`latest`] so diagnostics and the UI can
//!    read the last polled state without re-evaluating AML. The
//!    watcher owns the button-counter drain cadence: a direct
//!    `snapshot()` caller sees presses since the last watcher poll.
//!
//! The first poll only seeds the baseline — it never feeds a
//! transition. The event path owns the initial state (a lid that was
//! already closed when the watcher started must not suspend the
//! machine five seconds after boot, e.g. a docked laptop); the
//! watcher is a backstop for transitions after it starts, not a
//! second trigger for pre-existing state.
//!
//! A transition delivered by *both* the event path and the next poll
//! is fed twice. That is benign: the service's pending-action bits
//! coalesce, so at most one extra suspend executes, and only if the
//! first request already ran — which matches the still-closed lid
//! policy anyway. AC double-feeds only rewrite the same cache slot.

use core::sync::atomic::{AtomicBool, Ordering};

use narf_acpi::ac_adapter::AcAdapterState;
use narf_acpi::lid::LidState;
use narf_lib::sync::IrqSafeSpinLock;

use crate::laptop_state::LaptopStateSnapshot;
use crate::service;

/// Poll interval in milliseconds. Battery / AC / lid transitions are
/// human-scale, and each poll may evaluate AML methods; 5 s keeps the
/// EC traffic at UI/diagnostic rate, matching the snapshot cadence
/// the platform composition documents for `StateProviders`.
pub const POLL_INTERVAL_MS: u64 = 5_000;

/// Watcher state: the previous poll's AC / lid observations (the
/// edge-detection baseline), the last produced snapshot, and a poll
/// counter for diagnostics.
#[derive(Default)]
struct MonitorState {
    prev_ac: Option<AcAdapterState>,
    prev_lid: Option<LidState>,
    latest: Option<LaptopStateSnapshot>,
    polls: u64,
}

static MONITOR: IrqSafeSpinLock<MonitorState> = IrqSafeSpinLock::new(MonitorState {
    prev_ac: None,
    prev_lid: None,
    latest: None,
    polls: 0,
});

static WATCHER_SPAWNED: AtomicBool = AtomicBool::new(false);

/// Poll once: produce a fused snapshot through the registered
/// providers, feed AC / lid transitions since the previous poll into
/// the service intake, cache the snapshot for [`latest`], and return
/// it. Synchronous and deterministic — this is the step the watcher
/// task runs, and the step the fixtures exercise directly.
///
/// The first call seeds the baseline and feeds nothing (see the
/// module docs for why). A poll whose snapshot carries no AC / lid
/// reading (`None`) likewise seeds that field without feeding: a
/// provider that appears later starts from a fresh baseline.
pub fn poll_once() -> LaptopStateSnapshot {
    let snap = service::snapshot();
    // Diff against the previous poll under one short lock, then feed
    // transitions with no lock held: intake takes the service lock,
    // and the providers (already evaluated, above) are never called
    // under any lock.
    let (ac_transition, lid_transition, first_poll) = {
        let mut m = MONITOR.lock();
        let first_poll = m.polls == 0;
        let ac_transition = match (snap.ac_adapter, m.prev_ac) {
            (Some(now), Some(prev)) if now != prev => Some(now),
            _ => None,
        };
        let lid_transition = match (snap.lid, m.prev_lid) {
            (Some(now), Some(prev)) if now != prev => Some(now),
            _ => None,
        };
        m.prev_ac = snap.ac_adapter;
        m.prev_lid = snap.lid;
        m.latest = Some(snap.clone());
        m.polls += 1;
        (ac_transition, lid_transition, first_poll)
    };
    if first_poll {
        return snap;
    }
    if let Some(ac) = ac_transition {
        service::on_ac_changed(ac);
        log_transition(&alloc::format!("power-monitor: AC -> {ac:?}"));
    }
    match lid_transition {
        Some(LidState::Closed) => {
            service::on_lid_changed(true);
            log_transition("power-monitor: lid -> Closed");
        }
        Some(LidState::Open) => {
            service::on_lid_changed(false);
            log_transition("power-monitor: lid -> Open");
        }
        // No lid reading (`None`) is not a transition the service
        // can act on: it carries no lid position, so feeding it
        // would clear a real cached state with nothing.
        _ => {}
    }
    snap
}

/// The most recent snapshot the watcher produced, if it has polled at
/// least once. Cheap (a clone of the cached snapshot); never evaluates
/// AML, so diagnostics and the UI read this instead of polling the
/// providers themselves.
pub fn latest() -> Option<LaptopStateSnapshot> {
    MONITOR.lock().latest.clone()
}

/// Number of polls completed (diagnostics; also lets a fixture assert
/// a poll ran without depending on snapshot contents).
pub fn poll_count() -> u64 {
    MONITOR.lock().polls
}

/// Spawn the periodic watcher task (idempotent). Called from the
/// Stage::Late `power-monitor` initcall; the task sleeps
/// [`POLL_INTERVAL_MS`] between [`poll_once`] calls for the life of
/// the system. Spawning — not polling — is what the initcall does,
/// so no AML evaluation ever runs on the boot path.
pub fn start_watcher() {
    if WATCHER_SPAWNED.swap(true, Ordering::AcqRel) {
        return;
    }
    narf_scheduler::spawn(async {
        loop {
            let deadline = narf_time::Deadline::after_ms(POLL_INTERVAL_MS);
            narf_time::SleepUntil::new(deadline.as_instant()).await;
            let _ = poll_once();
        }
    });
}

/// One-line transition log. Kept to transitions only (human-scale)
/// so the watcher never spams the serial console per poll.
fn log_transition(line: &str) {
    use core::fmt::Write as _;
    let _ = writeln!(narf_console::Writer, "  {line}");
}

/// Test-only reset: baseline, cached snapshot, and poll counter.
/// The watcher task, once spawned, is process-global and is not
/// un-spawned — fixtures exercise [`poll_once`] directly and never
/// call [`start_watcher`], so no background task can drain button
/// counters between a fixture's press and its snapshot assertion.
#[doc(hidden)]
pub fn __reset_for_test() {
    *MONITOR.lock() = MonitorState::default();
}

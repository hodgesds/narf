//! Pluggable I/O scheduler policy.
//!
//! Wave G of the pluggable-policy pass: extract the policy decisions
//! (which request runs next? what's the starvation bound? do we have
//! a single FIFO or two lanes?) out of the concrete
//! `DeadlineScheduler` and behind a trait so a device's scheduler can
//! be swapped at boot without re-linking the block layer.
//!
//! Scope is deliberately narrow:
//! - One trait, `IoScheduler`, with three operations: `enqueue`,
//!   `pick_next`, and best-effort `cancel`. The Stage-3 deadline
//!   scheduler exposes more (lane introspection, pending counts);
//!   those stay accessible through the concrete type, not the trait.
//! - Per-device install: `install_io_scheduler(cap, dev_id, sched)`
//!   replaces the boxed scheduler associated with one registered
//!   device. There is no global static slot — each device has its
//!   own queue, its own SLA, and its own policy.
//! - Cap-gated install through a `Cap<IoSched, Grant>` (note the
//!   marker type is `IoSched`, distinct from the trait name
//!   `IoScheduler`).
//!
//! The trait does NOT carry a deadline parameter on `enqueue` — the
//! Stage-3 `DeadlineScheduler` requires one, but a FIFO
//! `NoopScheduler` does not. Schedulers that need a deadline call
//! into `narf_time` (or their own clock source) inside `enqueue`,
//! keeping the trait surface policy-neutral. The deadline-based
//! behaviour is then a property of the scheduler implementation, not
//! the trait.

use alloc::boxed::Box;
use alloc::vec::Vec;

use narf_capabilities::{Cap, CapError, CapKind, CapType, Grant};
use narf_lib::sync::IrqSafeSpinLock;

use crate::BlockRequest;

/// Errors returned by the `install_io_scheduler` entry point.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoSchedError {
    /// Cap presented to `install_io_scheduler` no longer matches the
    /// installed object's epoch.
    AuthorityRevoked,
    /// `dev_id` did not correspond to any device that had a scheduler
    /// slot reserved. The block registry stores devices by
    /// `&'static str` name; a non-empty name with no scheduler slot
    /// means the device was never paired with one via
    /// `reserve_io_scheduler_slot`.
    UnknownDevice,
}

impl From<CapError> for IoSchedError {
    fn from(_: CapError) -> Self {
        IoSchedError::AuthorityRevoked
    }
}

/// Stable string identifier for a registered block device. Matches
/// the `&'static str` name the device was registered under in
/// `crate::registry`.
pub type BlockDeviceId = &'static str;

/// Marker type for the install-authority cap. Distinct from the
/// trait `IoScheduler` so the type name doesn't collide. The
/// `CapKind::IoScheduler` slot was reserved in Wave 0.
#[derive(Copy, Clone, Debug)]
pub struct IoSched;

impl CapType for IoSched {
    const KIND: CapKind = CapKind::IoScheduler;
}

/// Policy interface that orders block requests for a single device.
///
/// `enqueue` accepts a request and parks it on the scheduler's
/// internal queue(s). `pick_next` returns the request the scheduler
/// has chosen to dispatch — implementations are free to peek at
/// deadlines, reorder for read-vs-write fairness, or do nothing at
/// all (`NoopScheduler`). `cancel` is best-effort: returns `true`
/// iff the scheduler still had the request queued.
pub trait IoScheduler: Send + Sync + 'static {
    /// Stable identifier — used by `current_io_scheduler_name` and
    /// userspace tooling that wants to know which policy is active.
    fn name(&self) -> &'static str;

    /// Park a request on the scheduler. The scheduler is free to
    /// retag, reorder, or annotate the request internally. Returns
    /// the kernel-assigned tag the implementation chose for this
    /// entry; callers correlate completions through that tag.
    fn enqueue(&self, req: BlockRequest) -> u64;

    /// Pick the next request to dispatch, or `None` if the queue is
    /// empty. The implementation may use any policy it likes
    /// (deadline-promotion, pure FIFO, fair-share); the caller does
    /// not observe the choice.
    fn pick_next(&self) -> Option<BlockRequest>;

    /// Best-effort: remove `req_id` (the tag returned from
    /// `enqueue`) from the queue. Returns `true` iff the request was
    /// still queued. Schedulers that don't track tags after dispatch
    /// return `false`.
    fn cancel(&self, req_id: u64) -> bool;
}

// ── DeadlineScheduler IoScheduler impl ─────────────────────────────

use crate::deadline::DeadlineScheduler;

impl IoScheduler for DeadlineScheduler {
    fn name(&self) -> &'static str {
        "deadline"
    }

    fn enqueue(&self, req: BlockRequest) -> u64 {
        // The DeadlineScheduler concrete API takes an explicit
        // deadline; the trait does not. Stuff the request into the
        // far-future slot so deadline-promotion is effectively
        // disabled when the policy is driven through the trait —
        // callers that want deadline behaviour go through the
        // concrete `DeadlineScheduler::enqueue` directly.
        DeadlineScheduler::enqueue(self, req, u64::MAX / 2)
    }

    fn pick_next(&self) -> Option<BlockRequest> {
        // `now_cycles = 0` is fine because deadlines were stuffed at
        // u64::MAX/2 — nothing is past-due, and the lane-preference
        // / starvation rules still apply.
        DeadlineScheduler::dequeue_next(self, 0)
    }

    fn cancel(&self, _req_id: u64) -> bool {
        // Stage-3 deadline scheduler doesn't expose a tag-indexed
        // removal path; cancellation runs through the device-side
        // `BlockDevice::cancel` adapter today. Best-effort `false`
        // matches the trait contract.
        false
    }
}

// ── Per-device install ─────────────────────────────────────────────
//
// Each registered block device gets its own boxed `IoScheduler`.
// Storing the slot in a parallel registry (keyed by `&'static str`
// name) avoids changing the `Clone`-able `RegisteredBlockDevice`
// struct — putting a `Box<dyn IoScheduler>` directly in there would
// break the `block_devices()` snapshot return type.
//
// The slot is `IrqSafeSpinLock<Box<dyn IoScheduler>>` so a swap
// during boot or a runtime policy change can replace the inner
// scheduler without re-allocating the entry vector.

struct SchedSlot {
    dev_id: BlockDeviceId,
    sched: IrqSafeSpinLock<Box<dyn IoScheduler>>,
}

impl core::fmt::Debug for SchedSlot {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SchedSlot")
            .field("dev_id", &self.dev_id)
            .finish_non_exhaustive()
    }
}

static SCHED_SLOTS: IrqSafeSpinLock<Vec<SchedSlot>> = IrqSafeSpinLock::new(Vec::new());

/// Reserve a per-device scheduler slot, defaulting to a fresh
/// `DeadlineScheduler` boxed as `Box<dyn IoScheduler>`. Called once
/// per device at registration time (or from a test harness setting
/// up a fake device). Idempotent on `dev_id` — a second call
/// replaces the prior slot with a fresh default.
pub fn reserve_io_scheduler_slot(dev_id: BlockDeviceId) {
    let default: Box<dyn IoScheduler> = Box::new(DeadlineScheduler::new());
    let mut slots = SCHED_SLOTS.lock();
    if let Some(slot) = slots.iter().find(|s| s.dev_id == dev_id) {
        *slot.sched.lock() = default;
    } else {
        slots.push(SchedSlot {
            dev_id,
            sched: IrqSafeSpinLock::new(default),
        });
    }
}

/// Replace the scheduler for `dev_id` with `sched`. Cap-gated on
/// `Cap<IoSched, Grant>`. The displaced `Box` is dropped.
pub fn install_io_scheduler<S: IoScheduler>(
    cap: &Cap<IoSched, Grant>,
    dev_id: BlockDeviceId,
    sched: S,
) -> Result<(), IoSchedError> {
    cap.check_live()?;
    let slots = SCHED_SLOTS.lock();
    let slot = slots
        .iter()
        .find(|s| s.dev_id == dev_id)
        .ok_or(IoSchedError::UnknownDevice)?;
    *slot.sched.lock() = Box::new(sched);
    Ok(())
}

/// Snapshot the name of the scheduler currently installed on
/// `dev_id`. Returns `None` if no slot has been reserved.
pub fn current_io_scheduler_name(dev_id: BlockDeviceId) -> Option<&'static str> {
    let slots = SCHED_SLOTS.lock();
    let slot = slots.iter().find(|s| s.dev_id == dev_id)?;
    let name = slot.sched.lock().name();
    Some(name)
}

/// Enqueue through the installed scheduler for `dev_id`. Returns the
/// scheduler-assigned tag, or `None` if no scheduler is reserved.
pub fn enqueue_on(dev_id: BlockDeviceId, req: BlockRequest) -> Option<u64> {
    let slots = SCHED_SLOTS.lock();
    let slot = slots.iter().find(|s| s.dev_id == dev_id)?;
    let tag = slot.sched.lock().enqueue(req);
    Some(tag)
}

/// Drain one request from the installed scheduler for `dev_id`.
pub fn pick_next_on(dev_id: BlockDeviceId) -> Option<BlockRequest> {
    let slots = SCHED_SLOTS.lock();
    let slot = slots.iter().find(|s| s.dev_id == dev_id)?;
    let picked = slot.sched.lock().pick_next();
    picked
}

/// Mint a `Cap<IoSched, Grant>`. TCB-only entry path — the kernel
/// calls this once at boot and hands the result to the subsystem
/// allowed to drive I/O scheduler policy. Mirrors the
/// `bootstrap_governor_authority` pattern in `narf-power`.
pub fn bootstrap_io_scheduler_authority() -> Cap<IoSched, Grant> {
    Cap::<IoSched, Grant>::bootstrap()
}

/// Test-only: wipe every reserved slot. Used by smokes that want a
/// clean per-device registry.
#[doc(hidden)]
pub fn __reset_slots_for_test() {
    SCHED_SLOTS.lock().clear();
}

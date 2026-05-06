//! Suspend-to-RAM / resume — Stage-4 structural shape.
//!
//! Spec: `power/specification/spec.md` (Stage-4 suspend-to-RAM
//! (S3 / PSCI)). System-wide suspend follows a fixed phase order:
//!
//!   1. Freeze userspace + quiesce every driver
//!      (`DevicePm::runtime_suspend` fan-out).
//!   2. Sync the unified page cache to storage.
//!   3. Save per-CPU state (scheduler / arch domain state / RCU
//!      queues).
//!   4. Invoke the platform's suspend primitive — ACPI S3 on x86_64
//!      via `WRMSR IA32_THERM_STATUS; hlt` sequence or `PSCI
//!      SYSTEM_SUSPEND` on aarch64.
//!   5. On resume: re-establish paging, restore per-CPU state,
//!      resume drivers, unfreeze userspace.
//!
//! Stage-4 structural deliverable: `suspend(cap)` /
//! `resume_progress()` with a phase enum that observers can watch.
//! The platform primitive is absent; `suspend` returns
//! `SuspendError::NotImplemented` until `arch/` grows S3 / PSCI.

use core::sync::atomic::{AtomicU8, Ordering};

use narf_capabilities::{Cap, CapError, NoopOp};

use crate::Power;

/// Phases the suspend/resume pipeline passes through.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SuspendPhase {
    Idle = 0,
    FreezingUserspace = 1,
    QuiescingDrivers = 2,
    SyncingCache = 3,
    SavingCpuState = 4,
    PlatformOff = 5,
    RestoringCpuState = 6,
    ResumingDrivers = 7,
    ThawingUserspace = 8,
}

/// Errors from the suspend surface.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SuspendError {
    AuthorityRevoked,
    NotImplemented,
    AlreadySuspending,
    Aborted,
}

impl From<CapError> for SuspendError {
    fn from(_: CapError) -> Self {
        SuspendError::AuthorityRevoked
    }
}

/// Current phase. `u8`-backed atomic so subscribers can read it
/// from a signal handler / interrupt without grabbing a lock.
static PHASE: AtomicU8 = AtomicU8::new(SuspendPhase::Idle as u8);

/// Request a system-wide suspend. Returns `NotImplemented` until
/// the platform primitives land — but *does* walk the phase
/// progression up to `PlatformOff` so subscribers can observe the
/// handoff shape.
pub fn suspend(cap: &Cap<Power, narf_capabilities::Invoke>) -> Result<(), SuspendError> {
    cap.invoke(NoopOp)?;
    let prev = PHASE.swap(SuspendPhase::FreezingUserspace as u8, Ordering::AcqRel);
    if prev != SuspendPhase::Idle as u8 {
        // Put it back — we're bailing on the transition.
        PHASE.store(prev, Ordering::Release);
        return Err(SuspendError::AlreadySuspending);
    }
    PHASE.store(SuspendPhase::QuiescingDrivers as u8, Ordering::Release);
    PHASE.store(SuspendPhase::SyncingCache as u8, Ordering::Release);
    PHASE.store(SuspendPhase::SavingCpuState as u8, Ordering::Release);
    PHASE.store(SuspendPhase::PlatformOff as u8, Ordering::Release);
    // Real platform suspend would happen here and not return until
    // resume. We mirror a "ping-pong through the phases without
    // actually sleeping" behaviour so the shape exercises.
    PHASE.store(SuspendPhase::Idle as u8, Ordering::Release);
    Err(SuspendError::NotImplemented)
}

/// Snapshot the current phase.
#[inline]
pub fn current_phase() -> SuspendPhase {
    let v = PHASE.load(Ordering::Acquire);
    // Safety: we only ever store valid discriminants.
    unsafe { core::mem::transmute(v) }
}

/// Test helper.
#[doc(hidden)]
pub fn __test_reset() {
    PHASE.store(SuspendPhase::Idle as u8, Ordering::Release);
}

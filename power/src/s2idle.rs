//! Suspend-to-idle (s2idle / "freeze") — the firmware-free system
//! sleep state.
//!
//! Linux ref: `kernel/power/suspend.c` (`suspend_devices_and_enter`
//! with `PM_SUSPEND_TO_IDLE`), `Documentation/admin-guide/pm/
//! sleep-states.rst`: s2idle quiesces devices exactly like S3 but
//! then parks the CPUs in their deepest *idle* state instead of
//! asking the platform firmware to cut power. Wake is an ordinary
//! enabled interrupt.
//!
//! # Why this exists alongside S3
//!
//! Stage-5 AMD laptops (Renoir / Phoenix) are the target where this
//! matters: S3 support varies by OEM firmware — several vendors ship
//! s2idle-only firmware with no usable `\_S3_` at all — so the
//! fallback sleep state cannot depend on anything ACPI. s2idle needs
//! no `\_S3_` package, no FADT PM1 block, and no AML evaluation on
//! the entry path.
//!
//! # What is shared with S3, and what deliberately is not
//!
//! Shared, by construction (same functions, not copies):
//!
//! - the one global transition claim and phase observable
//!   ([`crate::suspend`]) — an S3 request and an s2idle request can
//!   never interleave;
//! - the synchronous `device_pm` fan-out and its abort/rollback
//!   shape, the async [`crate::system_pm`] bracket for
//!   interrupt-driven firmware, and the framebuffer blank hooks;
//! - the production-gating posture: a test back-door arm plus a
//!   cap-gated production opt-in with a boot-cmdline token.
//!
//! Different, and why:
//!
//! - **No CPU context save / no resume trampoline / no setjmp.**
//!   The CPU never loses power, so execution never leaves
//!   [`suspend_to_idle`]'s stack frame; "resume" is the park loop
//!   falling through. S3's `s3_resume` machinery exists only
//!   because firmware restarts the CPU at a waking vector.
//! - **No TSC snapshot.** The TSC keeps counting in idle states;
//!   the backwards-jump problem is S3-specific (silicon that stops
//!   or resets the TSC across power loss).
//! - **No `\_PTS`, no FACS waking vector, no PM1 write.** There is
//!   no firmware sleep transition to prepare or trigger — that
//!   absence is the point of the state.
//! - **Wake is a latched event, not a vector return.** Wake sources
//!   (power/sleep button, lid, EC, RTC) already surface as ordinary
//!   interrupts on this platform; their handlers call
//!   [`note_wake_event`] and the park loop observes the latch. The
//!   IRQ mask snapshot keeps those vectors unmasked (see
//!   [`wake_irq_allowlist`]) and masks everything else, exactly as
//!   the S3 entry does.
//!
//! Task freezing: like the S3 core today, the phase progression
//! marks `FreezingUserspace` / `ThawingUserspace` but no scheduler
//! freezer exists yet to reuse; the executor's worker task is the
//! only task that parks, and device quiesce is what makes the park
//! safe. A real freezer is a scheduler-side follow-up for both
//! sleep states, not something to fake here.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, AtomicUsize, Ordering};

use narf_capabilities::{Cap, NoopOp};

use crate::suspend::{self, SuspendError, SuspendPhase};
use crate::Power;

// ── Support query ───────────────────────────────────────────────────

/// Whether suspend-to-idle is available on this platform.
///
/// Unlike [`suspend::s3_supported`] there is no firmware contract
/// to probe: s2idle needs only a wait-for-interrupt park primitive,
/// which both shipped architectures provide
/// (`narf_arch::idle_halt_then_disable`). This stays a query
/// function — rather than callers assuming `true` — so a future
/// platform without a park primitive narrows it in one place, and
/// so `/sys/power/state` can list exactly the states that exist.
pub fn s2idle_supported() -> bool {
    cfg!(any(target_arch = "x86_64", target_arch = "aarch64"))
}

// ── Production gate ─────────────────────────────────────────────────
//
// Mirrors the S3 gate in `suspend.rs` one-for-one: a kernel-test
// back-door arm for harness use, plus a production opt-in that a
// user flips only after the park/wake chain has been validated on
// their hardware. Default: off — an unarmed request walks the full
// phase progression and returns `NotImplemented`, exactly like an
// unarmed S3 request.

static S2IDLE_TEST_ARMED: AtomicBool = AtomicBool::new(false);

/// Arm the park loop for the kernel-test harness. Test-only, like
/// `suspend::__test_arm_real_sleep`.
#[doc(hidden)]
pub fn __test_arm_s2idle() {
    S2IDLE_TEST_ARMED.store(true, Ordering::Release);
}

static PRODUCTION_S2IDLE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Userspace opt-in: enable the production s2idle path after
/// on-silicon validation has confirmed wake works on this box.
/// Returns the previous value so callers can detect double-arms.
///
/// Cap-gated on the same `Cap<Power, Invoke>` that drives the
/// suspend entries, mirroring `suspend::enable_production_s3`.
pub fn enable_production_s2idle(
    cap: &Cap<Power, narf_capabilities::Invoke>,
) -> Result<bool, SuspendError> {
    cap.invoke(NoopOp)?;
    let prev = PRODUCTION_S2IDLE_ENABLED.swap(true, Ordering::AcqRel);
    Ok(prev)
}

/// Userspace turn-off. Symmetric with [`enable_production_s2idle`].
pub fn disable_production_s2idle(
    cap: &Cap<Power, narf_capabilities::Invoke>,
) -> Result<bool, SuspendError> {
    cap.invoke(NoopOp)?;
    let prev = PRODUCTION_S2IDLE_ENABLED.swap(false, Ordering::AcqRel);
    Ok(prev)
}

/// Query whether the production s2idle gate is open. Lock-free read.
pub fn production_s2idle_enabled() -> bool {
    PRODUCTION_S2IDLE_ENABLED.load(Ordering::Acquire)
}

/// Boot-time flip from a kernel cmdline / env entry. Looks for the
/// magic string `S2IDLE_VALIDATED` — the analogue of S3's
/// `S3_VALIDATED` token. No cap-check because it runs in the
/// boot-time TCB before user authorities exist.
pub fn boot_apply_s2idle_validated_flag(boot_cmdline: &str) -> bool {
    if boot_cmdline.contains("S2IDLE_VALIDATED") {
        PRODUCTION_S2IDLE_ENABLED.store(true, Ordering::Release);
        true
    } else {
        false
    }
}

/// Either the test back-door or the production opt-in authorises
/// the actual park. Same two-route rule as the S3 PM1 write.
fn s2idle_armed() -> bool {
    S2IDLE_TEST_ARMED.load(Ordering::Acquire) || PRODUCTION_S2IDLE_ENABLED.load(Ordering::Acquire)
}

// ── Wake-event latch ────────────────────────────────────────────────

/// A platform wake source, as surfaced by the drivers that already
/// deliver these events as ordinary interrupts (ACPI fixed buttons,
/// the EC/lid path in `drivers/platform`).
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum WakeSource {
    PowerButton = 1,
    SleepButton = 2,
    Lid = 3,
    EmbeddedController = 4,
    RtcAlarm = 5,
    /// Injected by the kernel-test harness.
    TestInjected = 6,
    /// Any other enabled wake-capable interrupt.
    Other = 7,
}

static WAKE_LATCH: AtomicBool = AtomicBool::new(false);
static LAST_WAKE_SOURCE: AtomicU8 = AtomicU8::new(0);

/// Record a wake event. Called from wake-source interrupt handlers
/// (and by tests modelling one). Atomics only — IRQ-safe, never
/// blocks, never touches the phase machine: the parked task
/// observes the latch and runs the resume sequence itself.
pub fn note_wake_event(source: WakeSource) {
    LAST_WAKE_SOURCE.store(source as u8, Ordering::Release);
    WAKE_LATCH.store(true, Ordering::Release);
}

/// Whether a wake event is latched and not yet consumed by a park.
pub fn wake_event_pending() -> bool {
    WAKE_LATCH.load(Ordering::Acquire)
}

/// The most recent source passed to [`note_wake_event`], if any.
pub fn last_wake_source() -> Option<WakeSource> {
    match LAST_WAKE_SOURCE.load(Ordering::Acquire) {
        1 => Some(WakeSource::PowerButton),
        2 => Some(WakeSource::SleepButton),
        3 => Some(WakeSource::Lid),
        4 => Some(WakeSource::EmbeddedController),
        5 => Some(WakeSource::RtcAlarm),
        6 => Some(WakeSource::TestInjected),
        7 => Some(WakeSource::Other),
        _ => None,
    }
}

/// IRQ vectors that must stay unmasked across the park so a wake
/// event can actually fire. Today that is the ACPI SCI: the fixed
/// power/sleep buttons and EC/lid GPEs all funnel through it on the
/// Stage-5 laptops. GSI `n` dispatches on vector `32 + n` in the
/// identity mapping `narf_interrupts` soft-masks on; the EC driver
/// resolves the same GSI through the MADT override table for its
/// own routing (`drivers/platform/src/ec.rs`). Empty when the FADT
/// has not been parsed or advertises no SCI — the park then relies
/// on the latch alone, which a test or a future non-ACPI source can
/// still set.
pub fn wake_irq_allowlist() -> Vec<u8> {
    let mut v = Vec::new();
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(pm) = narf_acpi::fadt_pm() {
            if pm.sci_int != 0 {
                let vec = 32u32 + pm.sci_int as u32;
                if let Ok(vec) = u8::try_from(vec) {
                    v.push(vec);
                }
            }
        }
    }
    v
}

// ── Park statistics ─────────────────────────────────────────────────

/// How a park loop exited.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub enum ParkExit {
    /// No park happened (unarmed / unsupported / aborted earlier).
    #[default]
    NotParked = 0,
    /// A wake event was latched; the resume sequence ran.
    WakeEvent = 1,
    /// The bounded test entry exhausted its halt budget with no
    /// wake event — the "stays parked" observation. Production
    /// parks are unbounded and never produce this.
    BoundExhausted = 2,
}

/// Diagnostic counters for the s2idle path.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct S2idleStats {
    /// `suspend_to_idle*` calls that passed the capability check.
    pub attempts: u64,
    /// Parks actually entered (armed + supported).
    pub parks: u64,
    /// Parks that exited via a latched wake event.
    pub wakes: u64,
    /// Exit reason of the most recent park (or `NotParked`).
    pub last_exit: ParkExit,
}

static STAT_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static STAT_PARKS: AtomicU64 = AtomicU64::new(0);
static STAT_WAKES: AtomicU64 = AtomicU64::new(0);
static STAT_LAST_EXIT: AtomicU8 = AtomicU8::new(ParkExit::NotParked as u8);

/// Snapshot the s2idle diagnostic counters.
pub fn stats() -> S2idleStats {
    let last_exit = match STAT_LAST_EXIT.load(Ordering::Acquire) {
        1 => ParkExit::WakeEvent,
        2 => ParkExit::BoundExhausted,
        _ => ParkExit::NotParked,
    };
    S2idleStats {
        attempts: STAT_ATTEMPTS.load(Ordering::Acquire),
        parks: STAT_PARKS.load(Ordering::Acquire),
        wakes: STAT_WAKES.load(Ordering::Acquire),
        last_exit,
    }
}

// ── Park-step hook (test seam) ──────────────────────────────────────
//
// The park loop calls this once per iteration before halting. In
// production it stays unset and costs one atomic load. Tests use it
// to model a wake source firing *while* the CPU is parked — the one
// interleaving a synchronous kernel test cannot otherwise produce.

static PARK_STEP_HOOK: AtomicUsize = AtomicUsize::new(0);

#[doc(hidden)]
pub fn __test_set_park_step_hook(hook: Option<fn()>) {
    PARK_STEP_HOOK.store(hook.map(|f| f as usize).unwrap_or(0), Ordering::Release);
}

fn invoke_park_step_hook() {
    let h = PARK_STEP_HOOK.load(Ordering::Acquire);
    if h != 0 {
        // SAFETY: the slot only ever holds a `fn()` stored by
        // `__test_set_park_step_hook`.
        let f: fn() = unsafe { core::mem::transmute(h) };
        f();
    }
}

/// Reset all s2idle module state. Test-only; pair with
/// `suspend::__test_reset()` (which owns the shared phase) and
/// `device_pm::__reset_for_test()`.
#[doc(hidden)]
pub fn __test_reset() {
    S2IDLE_TEST_ARMED.store(false, Ordering::Release);
    PRODUCTION_S2IDLE_ENABLED.store(false, Ordering::Release);
    WAKE_LATCH.store(false, Ordering::Release);
    LAST_WAKE_SOURCE.store(0, Ordering::Release);
    STAT_ATTEMPTS.store(0, Ordering::Release);
    STAT_PARKS.store(0, Ordering::Release);
    STAT_WAKES.store(0, Ordering::Release);
    STAT_LAST_EXIT.store(ParkExit::NotParked as u8, Ordering::Release);
    PARK_STEP_HOOK.store(0, Ordering::Release);
}

// ── Entry points ────────────────────────────────────────────────────

/// Request a system-wide suspend-to-idle through the synchronous
/// device-PM surface — the s2idle twin of [`suspend::suspend`].
///
/// Walks the shared phase progression; when the platform supports
/// s2idle and the park is armed (test back-door or production
/// opt-in), it quiesces devices, masks non-wake IRQs, and parks in
/// the wait-for-wake loop until a wake event is latched, then runs
/// the resume fan-out and returns `Ok(())`. Unarmed or unsupported,
/// it walks the phases, runs the paired resume fan-out so drivers
/// observe a clean cycle, and returns `NotImplemented` — the same
/// refusal shape as the S3 core.
///
/// Drivers with interrupt-driven firmware exchanges must use
/// [`suspend_to_idle_async`] instead, for the same reason as on the
/// S3 side.
pub fn suspend_to_idle(cap: &Cap<Power, narf_capabilities::Invoke>) -> Result<(), SuspendError> {
    cap.invoke(NoopOp)?;
    suspend::claim_suspend_transition()?;
    s2idle_after_claim(cap, None).0
}

/// The asynchronous-preparation variant: runs the
/// [`crate::system_pm`] prepare bracket before the synchronous
/// fan-out, mirroring [`suspend::suspend_async`] step for step.
pub async fn suspend_to_idle_async(
    cap: &Cap<Power, narf_capabilities::Invoke>,
) -> Result<(), SuspendError> {
    cap.invoke(NoopOp)?;
    suspend::claim_suspend_transition()?;

    let transition = crate::system_pm::prepare_async_system_pm().await;
    if !transition.succeeded() {
        // Same rollback contract as suspend_async: the failing hook
        // unwinds its predecessors; no device has been quiesced yet.
        let _ = transition.resume().await;
        suspend::set_phase(SuspendPhase::ResumingDrivers);
        suspend::set_phase(SuspendPhase::ThawingUserspace);
        suspend::set_phase(SuspendPhase::Idle);
        return Err(SuspendError::Aborted);
    }

    let result = s2idle_after_claim(cap, None).0;
    let _ = transition.resume().await;
    result
}

/// Bounded test entry: identical to [`suspend_to_idle`] except the
/// park gives up after `max_halts` halts with no wake event and
/// reports [`ParkExit::BoundExhausted`], so a harness can prove the
/// CPU stays parked when no wake source fires. Production code
/// must use the unbounded entries — a real park has no timeout.
#[doc(hidden)]
pub fn __test_suspend_to_idle_bounded(
    cap: &Cap<Power, narf_capabilities::Invoke>,
    max_halts: u64,
) -> (Result<(), SuspendError>, ParkExit) {
    let claimed = (|| -> Result<(), SuspendError> {
        cap.invoke(NoopOp)?;
        suspend::claim_suspend_transition()
    })();
    match claimed {
        Ok(()) => s2idle_after_claim(cap, Some(max_halts)),
        Err(e) => (Err(e), ParkExit::NotParked),
    }
}

/// The phase walk after the caller has claimed the transition.
/// Mirrors `suspend::suspend_after_claim` up to the platform step;
/// `max_halts` is `None` in production (park until a wake event).
fn s2idle_after_claim(
    cap: &Cap<Power, narf_capabilities::Invoke>,
    max_halts: Option<u64>,
) -> (Result<(), SuspendError>, ParkExit) {
    // Re-check the epoch: the async entry may have awaited long
    // enough for a revocation after claiming. Same guard, same
    // position as the S3 core.
    if let Err(error) = cap.invoke(NoopOp) {
        suspend::set_phase(SuspendPhase::Idle);
        return (Err(error.into()), ParkExit::NotParked);
    }
    STAT_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    suspend::set_phase(SuspendPhase::QuiescingDrivers);
    // Same abort contract as S3: finish the fan-out, but never park
    // with an outstanding DMA/mailbox transaction — roll back
    // partial progress and let the caller retry later.
    if !crate::device_pm::suspend_all_devices().ok() {
        suspend::set_phase(SuspendPhase::ResumingDrivers);
        let _ = crate::device_pm::resume_all_devices();
        suspend::set_phase(SuspendPhase::Idle);
        return (Err(SuspendError::Aborted), ParkExit::NotParked);
    }
    suspend::invoke_fb_suspend();
    suspend::set_phase(SuspendPhase::SyncingCache);
    suspend::set_phase(SuspendPhase::SavingCpuState);
    suspend::set_phase(SuspendPhase::PlatformOff);

    if !(s2idle_armed() && s2idle_supported()) {
        // Unarmed / unsupported: ping-pong through the remaining
        // phases without parking, so paired drivers observe a clean
        // cycle — byte-for-byte the S3 core's unarmed shape.
        suspend::set_phase(SuspendPhase::RestoringCpuState);
        suspend::set_phase(SuspendPhase::ResumingDrivers);
        let _ = crate::device_pm::resume_all_devices();
        suspend::invoke_fb_resume();
        suspend::set_phase(SuspendPhase::ThawingUserspace);
        suspend::set_phase(SuspendPhase::Idle);
        return (Err(SuspendError::NotImplemented), ParkExit::NotParked);
    }

    // ── The platform step: park ─────────────────────────────────
    //
    // Everything S3 does at this point is absent on purpose (see
    // the module docs): no context save, no TSC snapshot, no \_PTS,
    // no FACS vector, no PM1 write. What remains is the IRQ mask
    // snapshot — non-wake vectors must not fire into quiesced
    // drivers — and the park itself.
    let allowlist = wake_irq_allowlist();
    let _ = suspend::snapshot_and_mask_irqs(&allowlist);
    // Consume any latch set before the park, immediately before
    // the loop so the loop's first check is authoritative. This is
    // deliberate, not racy tidiness: the event that *requested*
    // this sleep (a sleep-button press routed through the policy
    // service) must not instantly end it, and ACPI wake sources
    // stay asserted in the PM status registers until serviced, so
    // a still-pending physical event re-latches from its handler
    // once the park begins.
    WAKE_LATCH.store(false, Ordering::Release);
    STAT_PARKS.fetch_add(1, Ordering::Relaxed);
    let exit = park(max_halts);
    STAT_LAST_EXIT.store(exit as u8, Ordering::Release);
    if exit == ParkExit::WakeEvent {
        STAT_WAKES.fetch_add(1, Ordering::Relaxed);
    }
    WAKE_LATCH.store(false, Ordering::Release);

    suspend::set_phase(SuspendPhase::RestoringCpuState);
    suspend::set_phase(SuspendPhase::ResumingDrivers);
    let _ = crate::device_pm::resume_all_devices();
    suspend::invoke_fb_resume();
    suspend::restore_irq_masks();
    suspend::set_phase(SuspendPhase::ThawingUserspace);
    suspend::set_phase(SuspendPhase::Idle);
    (Ok(()), exit)
}

/// Park the boot CPU until the wake latch is set (or, for the
/// bounded test entry, the halt budget runs out).
///
/// Race-free wait shape from the arch layer: interrupts are
/// disabled around the condition check and
/// `narf_arch::idle_halt_then_disable` performs the atomic
/// enable-halt-disable, so a wake interrupt that lands between the
/// latch check and the halt is delivered inside the halt and cannot
/// be slept through. Wake handlers run during that window and set
/// the latch; the loop re-checks it with interrupts disabled again.
fn park(max_halts: Option<u64>) -> ParkExit {
    let mut halts: u64 = 0;
    // SAFETY: task context on the executor's worker (the same
    // context the S3 core's interrupt-gated fan-out runs in). IRQs
    // are re-enabled before returning; the disabled window covers
    // only this loop, and every iteration either halts inside
    // `idle_halt_then_disable` (which transiently enables IRQs so
    // the wake IRQ can be delivered) or spins on an atomic.
    unsafe { narf_arch::disable_interrupts() };
    let exit = loop {
        if wake_event_pending() {
            break ParkExit::WakeEvent;
        }
        if let Some(max) = max_halts {
            if halts >= max {
                break ParkExit::BoundExhausted;
            }
        }
        invoke_park_step_hook();
        // The step hook models a wake source firing while parked;
        // give its latch the same immediate re-check a delivered
        // IRQ's handler would get after the halt returns.
        if wake_event_pending() {
            break ParkExit::WakeEvent;
        }
        // SAFETY: IRQs are disabled on entry (this function disabled
        // them, and the primitive returns with them disabled) —
        // exactly the primitive's documented precondition.
        unsafe { narf_arch::idle_halt_then_disable() };
        halts += 1;
    };
    // SAFETY: restores the caller's interrupt state; the park is
    // entered from task context with IRQs enabled.
    unsafe { narf_arch::enable_interrupts() };
    exit
}

//! Suspend/resume lifecycle for the platform thermal/fan surface (#916).
//!
//! Before this module, no thermal-zone, fan, or EC component in
//! `drivers/platform` registered with `power::device_pm`, and the
//! active-cooling governor drives cooling devices only on band
//! crossings (`power::thermal::record_temp`). A cooling level
//! asserted before S3 was therefore never re-applied after resume:
//! firmware forgets the `_FSL` level across S3, the post-resume
//! `_TMP` poll sees the same band (no crossing, no re-drive), and
//! the fans stay at whatever firmware left them at.
//!
//! This module registers one `device_pm` entry, `platform-thermal`:
//!
//! - **Suspend is a no-op.** There is nothing to quiesce: the
//!   `_TMP` poll task is executor-managed and quiesced by the S3
//!   phase machinery itself, and `AcpiFan`/`PwmFan` hold no
//!   suspend state — `set_level` is a pure re-evaluation
//!   (`_FSL` / PWM duty) with no hardware snapshot to save.
//! - **Resume re-asserts the last driven cooling level** via
//!   `power::thermal::current_cooling_level`. When no level was
//!   ever driven it does nothing (no spurious `set_level(0)`).
//!
//! Handler context (see `power::device_pm`): handlers run on the
//! boot CPU with interrupts gated and must not schedule or sleep
//! on the scheduler. `set_cooling_level` takes an `IrqSafeSpinLock`
//! and drives synchronous `_FSL`/PWM evaluations — no scheduler
//! interaction — so it is safe here. Device errors are already
//! swallowed by the fan drivers (`AcpiFan::call` ignores method
//! errors); the only failure this handler can report is a
//! `NotInitialised` registry, which cannot happen when a level
//! was previously recorded, and is mapped to `DriverError`
//! defensively.
//!
//! Deliberately out of scope:
//!
//! - **EC**: the EC driver has no re-assertable state — its
//!   transaction gate is stateless serialisation, not a level —
//!   so no EC entry is registered.
//! - **AcpiFan `_ON` cache**: the fan driver caches its on/off
//!   state and only calls `_ON` on a transition, so if firmware
//!   powers the fan off across S3 while the driver still believes
//!   it is on, resume re-asserts speed (`_FSL` is re-evaluated on
//!   every `set_level > 0`) but not the `_ON` edge. That is a
//!   fan-driver follow-up, not a lifecycle gap: the level itself
//!   is re-applied.
//! - **Resume ordering**: the entry is registered at
//!   Stage::Subsys, so it resumes early in the forward fan-out.
//!   That is safe because `_FSL` evaluation needs only the AML
//!   interpreter and the EC port service — both persistent
//!   in-RAM services, not `device_pm` registrants — and early
//!   resume is desirable (fans back on before other devices).

use narf_power::device_pm::{register_device_pm, DeviceSuspendError};

/// Name under which the platform thermal surface registers with
/// `power::device_pm`. Registration is idempotent on name.
pub const PM_NAME: &str = "platform-thermal";

/// Register the platform thermal suspend/resume entry. Called
/// from the `platform-thermal-pm` Stage::Subsys initcall, after
/// the `acpi-thermal` and `acpi-fan` initcalls. Registration
/// itself only stores the handler pair; the thermal registry
/// only needs to exist at resume time, so this is safe to call
/// even before any zone or fan has registered.
pub fn register() {
    register_device_pm(PM_NAME, suspend, resume);
}

/// Suspend handler: nothing to quiesce (see module docs).
fn suspend() -> Result<(), DeviceSuspendError> {
    Ok(())
}

/// Resume handler: re-assert the last driven cooling level so
/// firmware's S3 amnesia does not leave the fans at the wrong
/// speed. No level ever driven means nothing to re-assert.
fn resume() -> Result<(), DeviceSuspendError> {
    match narf_power::thermal::current_cooling_level() {
        None => Ok(()),
        Some(level) => narf_power::thermal::set_cooling_level(level)
            .map_err(|_| DeviceSuspendError::DriverError),
    }
}

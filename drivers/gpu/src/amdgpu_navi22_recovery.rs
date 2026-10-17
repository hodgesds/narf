//! Navi22 device recovery coordinator, after Linux `amdgpu_device_gpu_recover`
//! for a single dGPU whose reset method is mode1 (MP1 11.0.11):
//!
//! 1. Quiesce: stop the TDR detector, telemetry and thermal tasks (the
//!    scheduler stop of `amdgpu_device_halt_activities`), disable the IH ring
//!    (`navi10_ih_hw_fini`) so every subscriber terminates, and abandon all
//!    fence waits (`amdgpu_fence_driver_force_completion`).
//! 2. Reset and re-initialize: a fresh cold-boot owner whose `ResetOnInit`
//!    stage runs the mode1 reset unconditionally (`amdgpu_device_mode1_reset`:
//!    engine-hung scratch, PCI save/clear master, PMFW or PSP mode1, PCI
//!    restore, bootloader and MEMSIZE waits), then the complete firmware and
//!    kernel-queue bring-up with ring/IB tests, as
//!    `amdgpu_device_reinit_after_reset` resumes every IP and runs
//!    `amdgpu_ib_ring_tests`.
//! 3. Restart the runtime services on the new owner.
//!
//! Lost by recovery, and not restored here: every kernel-queue job in flight
//! (completed with an error), all VRAM contents owned by the old firmware
//! and queue owners (their reservations stay quarantined, so each recovery
//! leaks that VRAM), the DCN state and DMUB (Linux's DM resume re-lights the
//! display; NARF's display owner must restart DMUB and modeset itself), and
//! any GDDR6 training replay (a cold boot that needed two-stage training
//! refuses recovery: NARF has no short-training resume yet).
//!
//! Any failure — and cancellation of the recovery future — is terminal:
//! the device is reported lost, every fence waiter is abandoned and the IH
//! of both the old and the new owner is closed with `DeviceLost`.
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    Quiesce,
    /// Mode1 reset plus the full cold-boot bring-up of the new owner.
    Reinitialize,
    Restart,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No completed owner to recover, or a recovery is already running.
    Busy,
    /// This boot cannot be recovered (e.g. it needed GDDR6 training).
    Unsupported,
    /// A step failed; the device is lost.
    Failed(Step, crate::amdgpu_navi22_boot::Error),
    /// The recovery future was dropped mid-step; the device is lost.
    Cancelled(Step),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "recovery snapshots remain Copy and allocation-free"
)]
pub enum State {
    Idle,
    Running(Step),
    Recovered(crate::amdgpu_navi22_boot::Report),
    Lost(Error),
}

/// What recovery does to the hardware; production uses the platform owner.
pub(crate) trait Backend {
    /// `Err(Unsupported)` before any side effect when recovery is refused.
    fn check(&mut self) -> Result<(), Error>;
    async fn quiesce(&mut self) -> Result<(), crate::amdgpu_navi22_boot::Error>;
    async fn reinitialize(
        &mut self,
    ) -> Result<crate::amdgpu_navi22_boot::Report, crate::amdgpu_navi22_boot::Error>;
    async fn restart(&mut self);
    /// Terminal: abandon all waiters and close every IH endpoint.
    fn lose(&mut self);
}

/// Completed recoveries since boot; queue users compare it to detect resets.
static RECOVERIES: AtomicU64 = AtomicU64::new(0);
pub fn recoveries() -> u64 {
    RECOVERIES.load(Ordering::Acquire)
}

/// Device loss on drop unless disarmed: covers failure and cancellation.
struct Terminal<'a, B: Backend> {
    backend: &'a mut B,
    state: &'a mut State,
    step: Step,
    armed: bool,
}
impl<B: Backend> Drop for Terminal<'_, B> {
    fn drop(&mut self) {
        if self.armed {
            self.backend.lose();
            if *self.state == State::Running(self.step) {
                *self.state = State::Lost(Error::Cancelled(self.step));
            }
        }
    }
}

/// One coordinator per device. State lives outside the future, so a dropped
/// recovery cannot be replayed over a half-reset device.
#[derive(Debug)]
pub struct Recovery {
    state: State,
}
impl Recovery {
    pub const fn new() -> Self {
        Self { state: State::Idle }
    }
    pub fn state(&self) -> State {
        self.state
    }
    pub(crate) async fn run<B: Backend>(
        &mut self,
        backend: &mut B,
    ) -> Result<crate::amdgpu_navi22_boot::Report, Error> {
        if matches!(self.state, State::Running(_) | State::Lost(_)) {
            return Err(Error::Busy);
        }
        backend.check()?;
        self.state = State::Running(Step::Quiesce);
        let mut t = Terminal {
            backend,
            state: &mut self.state,
            step: Step::Quiesce,
            armed: true,
        };
        if let Err(error) = t.backend.quiesce().await {
            let error = Error::Failed(Step::Quiesce, error);
            *t.state = State::Lost(error);
            return Err(error);
        }
        t.step = Step::Reinitialize;
        *t.state = State::Running(Step::Reinitialize);
        let report = match t.backend.reinitialize().await {
            Ok(report) => report,
            Err(error) => {
                let error = Error::Failed(Step::Reinitialize, error);
                *t.state = State::Lost(error);
                return Err(error);
            }
        };
        t.step = Step::Restart;
        *t.state = State::Running(Step::Restart);
        t.backend.restart().await;
        t.armed = false;
        *t.state = State::Recovered(report);
        RECOVERIES.fetch_add(1, Ordering::AcqRel);
        Ok(report)
    }
}
impl Default for Recovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_recovery_tests.rs"]
mod tests;

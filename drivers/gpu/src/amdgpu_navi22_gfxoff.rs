//! Navi22 GFXOFF control with Linux's `amdgpu_gfx_off_ctrl` semantics
//! (amdgpu_gfx.c, amdgpu_device.c `amdgpu_device_delay_enable_gfx_off`):
//!
//! * `gfx_off_req_count` starts at 1 — GFXOFF disallowed.
//! * `gfx_v10_0_set_powergating_state(GATE)` on GC 10.3.2 is exactly
//!   `amdgpu_gfx_off_ctrl(adev, true)`: the count drops, and when it reaches
//!   zero with GFX powered a delayed work sends PMFW `AllowGfxOff` after
//!   `GFX_OFF_DELAY_ENABLE` (100 ms).
//! * Every client that must touch GC while it may be off takes a disable
//!   request first (`amdgpu_gfx_off_ctrl(adev, false)`): at count zero that
//!   cancels a pending allow (`cancel_delayed_work_sync`) and, if GFXOFF is
//!   in effect, sends `DisallowGfxOff` before the count is raised.
//! * An enable with the count already zero is an imbalance (Linux WARNs and
//!   ignores it); so does this.
//!
//! In Linux `PP_GFXOFF_MASK` gates all of it; here GFXOFF is disabled until
//! the explicit `amdgpu.navi22_pg=gfxoff` opt-in started the controller, and
//! while disabled [`Reference::acquire`] is a no-op that never touches the
//! SMU. Queue submission and every other GC MMIO path take a [`Reference`]
//! for the duration of the access (doorbell writes alone wake GC in hardware,
//! as in Linux; register reads and MMIO writes do not). Lock order: this
//! controller before the platform owner; never acquire with that lock held.
use core::future::Future;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use narf_lib::mutex::Mutex;

/// `GFX_OFF_DELAY_ENABLE`: `msecs_to_jiffies(100)`.
// linux: n/a (GFX_OFF_DELAY_ENABLE = msecs_to_jiffies(100) in amdgpu_gfx.c)
pub const DELAY_MS: u64 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Enable request with no outstanding disable request (Linux WARN_ON).
    Imbalance,
    /// The PMFW message failed.
    Control,
    /// A disallow failed or was cancelled: GC power is unknown, so every
    /// later request is refused until the device is reset.
    Failed,
    /// `start` on a controller that is running or was stopped this boot.
    Busy,
}

/// The PMFW side: `smu_v11_0_gfx_off_control` through the SMU owner.
pub(crate) trait Control {
    fn control(&mut self, allow: bool) -> impl Future<Output = Result<(), ()>> + Send;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    /// `PP_GFXOFF_MASK`: the opt-in started the controller.
    pub enabled: bool,
    /// `gfx_off_req_count`.
    pub requests: u32,
    /// `gfx_off_state`: PMFW accepted `AllowGfxOff`.
    pub off: bool,
    /// A delayed allow is scheduled.
    pub pending: bool,
    pub failed: bool,
    /// `AllowGfxOff` messages PMFW accepted.
    pub allows: u64,
}

#[derive(Debug)]
pub(crate) struct Controller {
    status: Status,
    /// Bumped to cancel a scheduled delayed allow.
    generation: u64,
    /// Bumped by stop/reset; references from an older epoch release nothing.
    epoch: u64,
    stopped: bool,
    /// `RESETS` value this state belongs to.
    resets: u64,
}
impl Controller {
    pub(crate) const fn new() -> Self {
        Self {
            status: Status {
                enabled: false,
                requests: 1,
                off: false,
                pending: false,
                failed: false,
                allows: 0,
            },
            generation: 0,
            epoch: 0,
            stopped: false,
            resets: 0,
        }
    }
    pub(crate) fn status(&self) -> Status {
        self.status
    }
    /// Turn the controller on in Linux's init state (count 1, GFX on). The
    /// caller enabled `FEATURE_GFXOFF` and sent `DisallowGfxOff`. Once per
    /// boot: a stopped controller stays stopped.
    pub(crate) fn start(&mut self) -> Result<(), Error> {
        if self.status.enabled || self.stopped {
            return Err(Error::Busy);
        }
        self.status = Status {
            enabled: true,
            ..Controller::new().status
        };
        Ok(())
    }
    /// `amdgpu_gfx_off_ctrl(adev, false)`.
    pub(crate) async fn disallow(&mut self, pmfw: &mut impl Control) -> Result<(), Error> {
        if !self.status.enabled {
            return Ok(());
        }
        if self.status.failed {
            return Err(Error::Failed);
        }
        if self.status.requests == 0 {
            // cancel_delayed_work_sync: a scheduled allow never fires.
            self.generation += 1;
            self.status.pending = false;
            if self.status.off {
                // Fail closed across cancellation or a PMFW error: GC power
                // is unknown. Linux logs and keeps going; nothing may touch
                // GC on that assumption here.
                self.status.failed = true;
                self.status.requests += 1;
                pmfw.control(false).await.map_err(|()| Error::Control)?;
                self.status.failed = false;
                self.status.off = false;
                return Ok(());
            }
        }
        self.status.requests += 1;
        Ok(())
    }
    /// `amdgpu_gfx_off_ctrl(adev, true)`. Returns the generation of the
    /// delayed allow to schedule after [`DELAY_MS`], if any.
    pub(crate) fn allow(&mut self) -> Result<Option<u64>, Error> {
        if !self.status.enabled {
            return Ok(None);
        }
        if self.status.requests == 0 {
            return Err(Error::Imbalance);
        }
        self.status.requests -= 1;
        if self.status.requests == 0 && !self.status.off {
            self.generation += 1;
            self.status.pending = true;
            return Ok(Some(self.generation));
        }
        Ok(None)
    }
    /// `amdgpu_device_delay_enable_gfx_off`. Ok(false) when the work was
    /// cancelled (a disable request arrived) or the controller stopped.
    pub(crate) async fn delayed_allow(
        &mut self,
        generation: u64,
        pmfw: &mut impl Control,
    ) -> Result<bool, Error> {
        let s = self.status;
        if !s.enabled || !s.pending || generation != self.generation {
            return Ok(false);
        }
        self.status.pending = false;
        if s.failed || s.off || s.requests != 0 {
            return Err(Error::Failed);
        }
        // A failed allow leaves GFX on (gfx_off_state stays false): safe.
        pmfw.control(true).await.map_err(|()| Error::Control)?;
        self.status.off = true;
        self.status.allows += 1;
        Ok(true)
    }
    /// `set_powergating_state(UNGATE)` and turn the controller off: GFX is
    /// left powered (disallowed) and every reference becomes inert.
    pub(crate) async fn stop(&mut self, pmfw: &mut impl Control) -> Result<(), Error> {
        let result = self.disallow(pmfw).await;
        self.forget();
        result
    }
    /// Device reset: PMFW state is gone; forget everything, stay off.
    fn forget(&mut self) {
        let (epoch, generation, resets) = (self.epoch + 1, self.generation + 1, self.resets);
        *self = Self::new();
        self.epoch = epoch;
        self.generation = generation;
        self.resets = resets;
        self.stopped = true;
    }
}

static CONTROLLER: Mutex<Controller> = Mutex::new(Controller::new());
/// Fast path: false (the default) makes every reference a no-op.
static ENABLED: AtomicBool = AtomicBool::new(false);
/// Bumped by [`forget_for_reset`], which cannot wait for the mutex.
static RESETS: AtomicU64 = AtomicU64::new(0);
/// Set by the uapi/CS owner once every userspace GC MMIO path it serves
/// (submission, `READ_MMR_REG`) holds a [`Reference`]. Until then the
/// policy's `gfxoff_safe_gc_access` is false and GFXOFF is refused.
static SUBMISSION_GUARDED: AtomicBool = AtomicBool::new(false);

/// The platform owner's SMU, through its lock.
struct Platform;
impl Control for Platform {
    async fn control(&mut self, allow: bool) -> Result<(), ()> {
        crate::amdgpu_navi22_platform::gfx_off_control(allow)
            .await
            .map_err(|_| ())
    }
}

async fn controller() -> narf_lib::mutex::MutexGuard<'static, Controller> {
    let mut c = CONTROLLER.lock().await;
    let resets = RESETS.load(Ordering::Acquire);
    if c.resets != resets {
        c.forget();
        c.resets = resets;
    }
    c
}

/// A GFXOFF disable request (`amdgpu_gfx_off_ctrl(adev, false)`) held for a
/// GC access. Inert while GFXOFF is disabled. Dropping it is the matching
/// enable request; the allow follows [`DELAY_MS`] later on an executor task.
#[derive(Debug)]
#[must_use = "GC is only guaranteed powered while the reference is held"]
pub struct Reference {
    epoch: Option<u64>,
}
impl Reference {
    /// Take a disable request. A no-op without the GFXOFF opt-in. Returns
    /// once GC is powered (any `DisallowGfxOff` completed).
    ///
    /// Must not be awaited while holding the platform owner lock.
    pub async fn acquire() -> Result<Self, Error> {
        if !ENABLED.load(Ordering::Acquire) {
            return Ok(Self { epoch: None });
        }
        let mut c = controller().await;
        if !c.status.enabled {
            return Ok(Self { epoch: None });
        }
        c.disallow(&mut Platform).await?;
        Ok(Self {
            epoch: Some(c.epoch),
        })
    }
    /// Whether this reference holds a request (GFXOFF is enabled).
    pub fn active(&self) -> bool {
        self.epoch.is_some()
    }
}
impl Drop for Reference {
    fn drop(&mut self) {
        if let Some(epoch) = self.epoch.take() {
            narf_scheduler::spawn(release(epoch));
        }
    }
}
async fn release(epoch: u64) {
    let generation = {
        let mut c = controller().await;
        if c.epoch != epoch {
            return;
        }
        match c.allow() {
            Ok(Some(generation)) => generation,
            _ => return,
        }
    };
    delayed(epoch, generation).await;
}
async fn delayed(epoch: u64, generation: u64) {
    narf_time::SleepUntil::new(narf_time::Deadline::after_ms(DELAY_MS).as_instant()).await;
    let mut c = controller().await;
    if c.epoch == epoch {
        if let Err(error) = c.delayed_allow(generation, &mut Platform).await {
            use core::fmt::Write;
            let _ = writeln!(
                narf_console::Writer,
                "amdgpu: navi22 GFXOFF allow: {error:?}"
            );
        }
    }
}

/// Start GFXOFF and gate it (`set_powergating_state(GATE)`): the first
/// allow is sent after [`DELAY_MS`]. The caller (opt-in path, owner lock
/// released) already enabled `FEATURE_GFXOFF` and sent `DisallowGfxOff`.
pub(crate) async fn start() -> Result<(), Error> {
    let mut c = controller().await;
    c.start()?;
    ENABLED.store(true, Ordering::Release);
    if let Some(generation) = c.allow()? {
        narf_scheduler::spawn(delayed(c.epoch, generation));
    }
    Ok(())
}
/// Ungate and stop: GFX is powered on return (or `Err` says it may not
/// be). Owner lock must not be held.
pub(crate) async fn stop() -> Result<(), Error> {
    let mut c = controller().await;
    ENABLED.store(false, Ordering::Release);
    c.stop(&mut Platform).await
}
/// Recovery: the ASIC is about to be reset. Callable with the owner lock
/// held; never waits.
pub(crate) fn forget_for_reset() {
    ENABLED.store(false, Ordering::Release);
    RESETS.fetch_add(1, Ordering::AcqRel);
}
/// Diagnostics; None while a transition holds the controller.
pub fn status() -> Option<Status> {
    let c = CONTROLLER.try_lock()?;
    (c.resets == RESETS.load(Ordering::Acquire)).then(|| c.status())
}
/// The uapi/CS owner declares that every userspace-driven GC MMIO path
/// holds a [`Reference`]; the TDR sampler already does.
pub fn declare_submission_guarded() {
    SUBMISSION_GUARDED.store(true, Ordering::Release);
}
/// `DriverReadiness::gfxoff_safe_gc_access` for the policy.
pub fn gc_access_guarded() -> bool {
    SUBMISSION_GUARDED.load(Ordering::Acquire)
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_navi22_gfxoff_tests.rs"]
mod tests;

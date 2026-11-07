//! Production panel-backlight owner for AMD APUs.
//!
//! Registers the tree's AMD panel backlight device (`amdgpu_bl0`)
//! with the backlight subsystem, backed by the DC BL_PWM sequence
//! in [`crate::amdgpu_backlight`] via [`crate::amdgpu::AmdGpu::set_backlight`]
//! — the register sequence the GPU crate documents as correct
//! (period-scaled duty in `BL_PWM_CNTL`, group lock bit 0).
//!
//! This is deliberately NOT built on the backlight crate's
//! `amdgpu_bl` bridge: that bridge encodes the pre-fix BL_PWM scheme
//! (a `BL_PWM_USER_LEVEL` write behind the master-lock bypass bit)
//! that [`crate::amdgpu_backlight`] documents as wrong — wiring it
//! would scribble hardware. Audit issue #951 covers that bridge;
//! its consolidation is a separate wave.
//!
//! Registration goes through the backlight subsystem's single-owner
//! arbitration (`narf_drivers_backlight::register_backlight`): this
//! Raw device owns the panel on an APU laptop and any firmware
//! (ACPI `_BCM`) candidate defers, so the two paths can never drive
//! the same PWM at cross purposes (audit #936 §2).
//!
//! ## Suspend / resume (#955, AMD scope)
//!
//! The same registration also wires the panel into the device-PM
//! registry as `amdgpu-bl` (see [`register_panel_owner`]). The
//! ordering is load-bearing and falls out of the probe order:
//! probe registers `amdgpu` first and `amdgpu-bl` second, so
//! suspend runs `amdgpu-bl` first (fade + save the level while
//! GFX is still up) and resume runs `amdgpu` first (re-program
//! the Mode — `set_backlight` refuses without one) and
//! `amdgpu-bl` second (relight at the saved level).
//!
//! Relight goes through the eDP panel-power sequencer
//! ([`crate::amdgpu_backlight::EdpPanelSequencer`]) via the
//! production [`AmdgpuEdpPanelHw`]: the host performs the PWM
//! transitions (the only half it owns — see the adapter's docs
//! for why the VDD/BL_EN rails are firmware-owned no-ops) and
//! the sequencer enforces the T4/T5 ordering and the
//! `last_pwm_level` cache. A resume with no saved level programs
//! nothing and leaves the panel at its firmware default.
//!
//! ## DPMS (#1690)
//!
//! The same state is driven from the `FBIOBLANK` ioctl via
//! [`fbdev_dpms`]: blank saves the last programmed level and
//! fades the panel (`BacklightPm::dpms_blank`), unblank relights
//! at the saved level (`BacklightPm::dpms_unblank`). The fade
//! goes through the sequencer when it is lit, and writes PWM 0
//! directly when the panel is lit outside the sequencer (a fresh
//! boot — `set_brightness` programs BL_PWM without sequencing).
//!
//! References (GPL-2.0-or-later):
//! - `drivers/gpu/drm/amd/amdgpu/amdgpu_backlight.c` — the DRM
//!   backlight device amdgpu registers for the internal panel.

use alloc::sync::Arc;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_drivers_backlight::{BacklightDevice, BacklightKind};
use narf_lib::sync::IrqSafeSpinLock;

use crate::amdgpu_backlight::{
    user_level_for_percent, EdpPanelHw, EdpPanelSequencer, EdpPanelState, EdpPowerSeq,
    PanelPowerError,
};

/// Backlight device name — the name the backlight crate's (unwired)
/// AMD bridge used, and Linux's `amdgpu_bl0`.
pub const DEVICE_NAME: &str = "amdgpu_bl0";

/// Panel backlight for the probed AMD APU, in percent space
/// (0–100) — the space [`crate::amdgpu::AmdGpu::set_backlight`]
/// programs.
#[derive(Debug)]
pub struct AmdgpuPanelBacklight {
    /// Last level this device successfully programmed, in percent.
    /// `u32::MAX` = never programmed (the panel is still at VBIOS
    /// residue); `current_brightness` reports 0 then, per the trait
    /// contract for an unknown readback.
    level: AtomicU32,
}

impl AmdgpuPanelBacklight {
    pub fn new() -> Self {
        Self {
            level: AtomicU32::new(u32::MAX),
        }
    }

    /// Last level this device successfully programmed, in percent,
    /// or `None` when no level was ever programmed (the panel is
    /// still at VBIOS residue). Unlike `current_brightness`, this
    /// distinguishes "never programmed" from "programmed to 0%",
    /// so the PM save path never blanks a panel whose brightness
    /// the driver never owned — a resume with no saved level must
    /// leave the panel at its firmware default.
    pub fn last_programmed_level(&self) -> Option<u32> {
        match self.level.load(Ordering::Acquire) {
            u32::MAX => None,
            v => Some(v),
        }
    }
}

impl Default for AmdgpuPanelBacklight {
    fn default() -> Self {
        Self::new()
    }
}

impl BacklightDevice for AmdgpuPanelBacklight {
    fn name(&self) -> &str {
        DEVICE_NAME
    }

    fn max_brightness(&self) -> u32 {
        100
    }

    fn current_brightness(&self) -> u32 {
        match self.level.load(Ordering::Acquire) {
            u32::MAX => 0,
            v => v,
        }
    }

    fn set_brightness(&self, level: u32) {
        let pct = level.min(100) as u8;
        // SAFETY: `with_controller_mut` yields the probed controller
        // under its lock; probe established exclusive BAR5 ownership
        // for it — the same authority the resume path's `set_mode`
        // call relies on. `set_backlight` itself refuses (Err)
        // before any MMIO when no mode is programmed yet or the ASIC
        // has no discovery-resolvable DCN base, and the level is
        // cached only on success, so a refused write never
        // masquerades as an applied one.
        let applied = crate::amdgpu::with_controller_mut(|gpu| unsafe { gpu.set_backlight(pct) });
        if matches!(applied, Some(Ok(()))) {
            self.level.store(u32::from(pct), Ordering::Release);
        }
    }

    fn kind(&self) -> BacklightKind {
        BacklightKind::Raw
    }
}

// ── Suspend / resume state (#955) ─────────────────────────────────
//
// `BacklightPm` is the pure save/restore core: it owns the saved
// level and drives the sequencer, but knows nothing about the
// statics or the controller, so fixtures can exercise it directly
// against a recording `EdpPanelHw`. The `device_pm` fns below are
// thin wrappers that lock the probe-installed state and hand it
// the production adapter.

/// Saved brightness across one suspend/resume cycle, in percent
/// (0–100). `None` = nothing was ever programmed.
#[derive(Clone, Copy, Debug, Default)]
pub struct BacklightPm {
    saved_pct: Option<u32>,
}

impl BacklightPm {
    pub const fn new() -> Self {
        Self { saved_pct: None }
    }

    /// Level saved by the last suspend, if any.
    pub fn saved(&self) -> Option<u32> {
        self.saved_pct
    }

    /// Suspend: stash the device's last programmed level (if any)
    /// and fade the panel through the sequencer when the host has
    /// it lit. The fade is best-effort — a panel the host never
    /// lit has nothing to fade, and the save is what matters.
    pub fn suspend<H: EdpPanelHw>(
        &mut self,
        current: Option<u32>,
        sequencer: &mut EdpPanelSequencer,
        hw: &mut H,
    ) {
        self.saved_pct = current;
        if sequencer.state == EdpPanelState::BacklightOn {
            let _ = sequencer.power_off_backlight(hw);
        }
    }

    /// Resume: re-light through the sequencer at the saved level.
    /// No saved level → program nothing and return `Ok` (the
    /// panel stays at its firmware default). A successful restore
    /// clears the saved level — one save pairs with one restore;
    /// a failed restore keeps it so the failure is visible to the
    /// fan-out instead of silently dropping the level.
    ///
    /// State dispatch: `Off` (host never sequenced the panel, or
    /// a previous full power-down) runs the full
    /// `power_on_video` → `power_on_backlight` chain;
    /// `VideoValid` / `BacklightOff` relight directly (the DPMS /
    /// platform-VDD path — VDD never cycled from the host's
    /// view); `BacklightOn` re-applies the PWM in place, since
    /// the DCN window lost power across S3 even though the state
    /// machine still says lit. The `BacklightOn` arm leaves
    /// `last_pwm_level` alone: the trait cannot report whether
    /// the re-apply landed, and the device's level cache — not
    /// the sequencer's — is the saved/restored truth.
    pub fn resume<H: EdpPanelHw>(
        &mut self,
        sequencer: &mut EdpPanelSequencer,
        hw: &mut H,
    ) -> Result<(), PanelPowerError> {
        let pct = match self.saved_pct {
            Some(p) => p,
            None => return Ok(()),
        };
        let level = user_level_for_percent(pct.min(100) as u8);
        let r = match sequencer.state {
            EdpPanelState::Off => sequencer
                .power_on_video(hw)
                .and_then(|()| sequencer.power_on_backlight(hw, level)),
            EdpPanelState::VideoValid | EdpPanelState::BacklightOff => {
                sequencer.power_on_backlight(hw, level)
            }
            EdpPanelState::BacklightOn => {
                hw.set_pwm(level);
                Ok(())
            }
        };
        if r.is_ok() {
            self.saved_pct = None;
        }
        r
    }

    /// DPMS blank: save the device's last programmed level (if any)
    /// and fade the panel. This is the DPMS half of the suspend
    /// transition, driven from the `FBIOBLANK` ioctl via
    /// [`fbdev_dpms`] rather than from system suspend.
    ///
    /// Two fades, by sequencer state:
    /// - `BacklightOn` — the panel was lit through the sequencer
    ///   (a previous suspend/resume cycle left it there): fade
    ///   via `power_off_backlight` (PWM → 0, T7, BL_EN off).
    /// - Anything else with a saved level — the panel is lit
    ///   outside the sequencer: `set_brightness` programs BL_PWM
    ///   directly without sequencing, so the probe-installed
    ///   sequencer sits in `Off` on a fresh boot while the panel
    ///   is lit. A sequencer-only fade would be a no-op there,
    ///   so blank writes PWM 0 directly: the PWM write is the
    ///   only host-owned transition (the rails are firmware
    ///   no-ops), and the sequencer state is left alone — the
    ///   unblank's resume-from-`Off` full chain re-lights it.
    ///   No saved level → nothing is lit that the host owns, and
    ///   blank is a no-op.
    ///
    /// The save is a blank-time snapshot: a brightness change
    /// made while DPMS-blanked is overwritten by the unblank
    /// relight at the blank-time level. (The suspend save cannot
    /// go stale this way — the machine is asleep.)
    pub fn dpms_blank<H: EdpPanelHw>(
        &mut self,
        current: Option<u32>,
        sequencer: &mut EdpPanelSequencer,
        hw: &mut H,
    ) {
        self.saved_pct = current;
        if sequencer.state == EdpPanelState::BacklightOn {
            let _ = sequencer.power_off_backlight(hw);
        } else if current.is_some() {
            hw.set_pwm(0);
        }
    }

    /// DPMS unblank: relight through the sequencer at the level
    /// the blank saved. No saved level → program nothing (the
    /// panel was never blanked by this core, or was already lit).
    /// A successful relight clears the save — one blank pairs
    /// with one unblank; a failed relight keeps it so the next
    /// unblank retries instead of silently dropping the level.
    pub fn dpms_unblank<H: EdpPanelHw>(
        &mut self,
        sequencer: &mut EdpPanelSequencer,
        hw: &mut H,
    ) -> Result<(), PanelPowerError> {
        self.resume(sequencer, hw)
    }
}

/// Probe-installed PM state: the registered panel device, the one
/// eDP sequencer for the internal panel, and the save/restore
/// core. `None` until `register_panel_owner` runs (APU probe
/// only — discrete cards have no panel and never install it).
struct BlPmState {
    panel: Option<Arc<AmdgpuPanelBacklight>>,
    sequencer: EdpPanelSequencer,
    pm: BacklightPm,
}

static BL_PM_STATE: IrqSafeSpinLock<Option<BlPmState>> = IrqSafeSpinLock::new(None);

// ── Production `EdpPanelHw` ───────────────────────────────────────

/// Production `EdpPanelHw` for the AMD internal panel.
///
/// - `set_pwm` is real: it programs BL_PWM through
///   [`crate::amdgpu::AmdGpu::set_pwm_user_level`] (period-scaled
///   duty via `build_set_user_level`, the same sequence
///   `set_backlight` uses). Failures are recorded in `pwm_ok`
///   because the trait cannot return one — the resume wrapper
///   reads it after driving the sequencer.
/// - `set_vdd` / `set_backlight_enable` are documented no-ops:
///   the VDD/BL_EN rails are sequenced by platform firmware
///   (DMUB/EC panel power sequencing, which the driver preserves
///   via `BootOptions::skip_panel_power_sequence`), and the ATOM
///   GPIO LUT is decode-only with no pin-drive path, so the host
///   has no verified rail drive. The sequencer still models those
///   transitions and their settle delays; the host performs the
///   PWM transitions. A real DMUB/ATOM-GPIO rail drive is the
///   filed remainder, not something to invent here.
/// - `delay_ms` busy-waits via the calibrated TSC delay the
///   amdgpu bring-up paths use — the PM fan-out runs with
///   interrupts gated and must not sleep on the scheduler.
#[derive(Debug)]
pub struct AmdgpuEdpPanelHw {
    pwm_ok: bool,
}

impl AmdgpuEdpPanelHw {
    pub fn new() -> Self {
        Self { pwm_ok: true }
    }

    /// Whether every `set_pwm` call so far landed on hardware.
    /// True when no PWM write was attempted.
    pub fn pwm_ok(&self) -> bool {
        self.pwm_ok
    }
}

impl Default for AmdgpuEdpPanelHw {
    // `Default` is `new()`, not a derived `Default`: a fresh
    // adapter has attempted no PWM write, so `pwm_ok` starts true
    // — a derived impl would start it false and misreport a
    // failure that never happened.
    fn default() -> Self {
        Self::new()
    }
}

impl EdpPanelHw for AmdgpuEdpPanelHw {
    fn set_vdd(&mut self, _on: bool) {
        // Firmware-owned rail — see the struct docs.
    }

    fn set_backlight_enable(&mut self, _on: bool) {
        // Firmware-owned rail — see the struct docs.
    }

    fn set_pwm(&mut self, user_level: u16) {
        // SAFETY: `with_controller_mut` yields the probed controller
        // under its lock; probe established exclusive BAR5 ownership
        // for it — the same authority the `set_backlight` call in
        // `set_brightness` relies on. `set_pwm_user_level` itself
        // refuses (Err) before any MMIO when no mode is programmed
        // yet, the ASIC has no discovery-resolvable DCN base, or the
        // chip is Navi4; a refused write is recorded in `pwm_ok`
        // because the trait cannot return one.
        let applied =
            crate::amdgpu::with_controller_mut(|gpu| unsafe { gpu.set_pwm_user_level(user_level) });
        if !matches!(applied, Some(Ok(()))) {
            self.pwm_ok = false;
        }
    }

    fn delay_ms(&mut self, ms: u16) {
        crate::amdgpu::delay_us(u32::from(ms) * 1000);
    }
}

// ── `device_pm` registration (#955) ───────────────────────────────

/// `amdgpu-bl` suspend: save the panel's last programmed level
/// and fade the panel through the sequencer. Runs before the
/// `amdgpu` suspend (reverse registration order) while GFX is
/// still up, so the PWM fade lands on live hardware. Infallible
/// by design — a failed fade must not abort S3 entry; the level
/// save is what the resume side depends on.
fn amdgpu_bl_suspend() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    let mut guard = BL_PM_STATE.lock();
    let Some(state) = guard.as_mut() else {
        return Ok(());
    };
    let current = state.panel.as_ref().and_then(|d| d.last_programmed_level());
    let mut hw = AmdgpuEdpPanelHw::new();
    state.pm.suspend(current, &mut state.sequencer, &mut hw);
    Ok(())
}

/// `amdgpu-bl` resume: relight through the sequencer at the saved
/// level. Runs after the `amdgpu` resume (forward registration
/// order) so the Mode is re-programmed before any PWM write —
/// `set_pwm_user_level` refuses without one. No saved level →
/// `Ok` without touching hardware (panel stays at its firmware
/// default). A saved level with no probed controller, a sequencer
/// failure, or a failed PWM write reports `DriverError` so the
/// fan-out records the dark panel instead of silently passing.
fn amdgpu_bl_resume() -> Result<(), narf_power::device_pm::DeviceSuspendError> {
    use narf_power::device_pm::DeviceSuspendError;
    let mut guard = BL_PM_STATE.lock();
    let Some(state) = guard.as_mut() else {
        return Ok(());
    };
    if state.pm.saved().is_none() {
        return Ok(());
    }
    if !crate::amdgpu::is_probed() {
        return Err(DeviceSuspendError::DriverError);
    }
    let mut hw = AmdgpuEdpPanelHw::new();
    match state.pm.resume(&mut state.sequencer, &mut hw) {
        Ok(()) if hw.pwm_ok() => Ok(()),
        _ => Err(DeviceSuspendError::DriverError),
    }
}

// ── DPMS hookup (#1690) ──────────────────────────────────────────

/// `FBIOBLANK` on the AMD console: `drm_fb_helper_blank` →
/// `drm_client_modeset_dpms` (Linux b90c984d), `on` being
/// `mode == DRM_MODE_DPMS_ON` — the same entry point the Intel
/// `fbdev_dpms` serves, dispatched from `fb::fbdev`'s `FBIOBLANK`
/// handler. Only the backlight half is wired: blank saves the
/// panel's last programmed level and fades it through the eDP
/// sequencer; unblank relights at the saved level. The CRTC /
/// timing-blank half has no AMD caller yet (the Navi22
/// `link_set_dpms_off` / `link_set_dpms_on` equivalents cover
/// HDMI and external DP SST only, never eDP) — this hookup does
/// not invent one.
///
/// Infallible by design, like the suspend side: the fbdev ioctl
/// returns 0 whatever the transition did (the Intel precedent),
/// and a failed fade must not fail a blank. A failed unblank
/// keeps the saved level (see `BacklightPm::dpms_unblank`), so
/// the next unblank retries.
///
/// Interactions, documented not solved:
/// - A brightness change made while DPMS-blanked is overwritten
///   by the unblank relight at the blank-time level.
/// - A DPMS blank active across a suspend/resume cycle is not
///   preserved: resume relights at the saved level per the #1691
///   semantics. Preserving the blank across S3 is a follow-up.
/// - The unblank's full chain from `Off` busy-waits the T1–T5
///   delays (~315 ms at defaults) on the calibrated TSC, the
///   same shape as the PM resume path.
pub fn fbdev_dpms(on: bool) {
    let mut guard = BL_PM_STATE.lock();
    let Some(state) = guard.as_mut() else {
        return;
    };
    if !crate::amdgpu::is_probed() {
        return;
    }
    let mut hw = AmdgpuEdpPanelHw::new();
    if on {
        let _ = state.pm.dpms_unblank(&mut state.sequencer, &mut hw);
    } else {
        let current = state.panel.as_ref().and_then(|d| d.last_programmed_level());
        state.pm.dpms_blank(current, &mut state.sequencer, &mut hw);
    }
}

/// Register the AMD panel backlight owner with the backlight
/// subsystem's single-owner arbitration. Called from the amdgpu
/// PCI probe for APUs — the internal-panel targets. Discrete cards
/// have no panel to own and never call this.
///
/// Registration is bookkeeping only: nothing touches hardware here,
/// and `set_backlight` keeps refusing until a mode is programmed.
///
/// Also installs the `amdgpu-bl` device-PM entry (save level at
/// suspend, relight through the eDP sequencer at resume) and the
/// probe-installed PM state it drives. Re-registration (re-probe)
/// replaces the panel device and the PM entry idempotently; the
/// sequencer restarts from `Off` — the host has not sequenced the
/// panel yet on a fresh probe.
pub fn register_panel_owner() {
    let dev = Arc::new(AmdgpuPanelBacklight::new());
    let ownership = narf_drivers_backlight::register_backlight(dev.clone());
    {
        let mut guard = BL_PM_STATE.lock();
        *guard = Some(BlPmState {
            panel: Some(dev),
            sequencer: EdpPanelSequencer::new(EdpPowerSeq::default()),
            pm: BacklightPm::new(),
        });
    }
    narf_power::device_pm::register_device_pm("amdgpu-bl", amdgpu_bl_suspend, amdgpu_bl_resume);
    let _ = writeln!(
        narf_console::Writer,
        "  amdgpu-backlight: {} registered ({:?})",
        DEVICE_NAME,
        ownership
    );
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(feature = "kernel-test")]
mod tests {
    use narf_drivers_backlight::{BacklightDevice, BacklightKind};
    use narf_kernel_test::{kernel_test_in, TestResult};

    use super::AmdgpuPanelBacklight;
    use super::BacklightPm;
    use crate::amdgpu_backlight::{
        user_level_for_percent, EdpPanelHw, EdpPanelSequencer, EdpPanelState, EdpPowerSeq,
    };

    fn smoke_amdgpu_panel_backlight_contract() -> TestResult {
        let dev = AmdgpuPanelBacklight::new();
        if dev.name() != "amdgpu_bl0" {
            return TestResult::Fail("device name wrong");
        }
        if dev.max_brightness() != 100 {
            return TestResult::Fail("max brightness should be 100 (percent space)");
        }
        if dev.kind() != BacklightKind::Raw {
            return TestResult::Fail("AMD native owner must be Raw kind");
        }
        if dev.current_brightness() != 0 {
            return TestResult::Fail("never-programmed device should report 0");
        }
        if dev.last_programmed_level().is_some() {
            return TestResult::Fail("never-programmed device must report no saved level");
        }
        // With no probed controller a set is a silent no-op: no
        // panic, and no phantom cached level. (A fixture-stashed
        // controller without a mode refuses inside set_backlight,
        // which lands in the same place.)
        if !crate::amdgpu::is_probed() {
            dev.set_brightness(55);
            if dev.current_brightness() != 0 {
                return TestResult::Fail("unapplied level was cached");
            }
            if dev.last_programmed_level().is_some() {
                return TestResult::Fail("unapplied level was saved");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_amdgpu_panel_backlight_contract);

    /// Recording fake panel HW: same shape as the sequencer's own
    /// `MockEdpHw`, local so these fixtures don't depend on the
    /// other module's test-only items.
    struct FakeHw {
        log: alloc::vec::Vec<(&'static str, u32)>,
    }
    impl FakeHw {
        fn new() -> Self {
            Self {
                log: alloc::vec::Vec::new(),
            }
        }
        fn pwm_writes(&self) -> alloc::vec::Vec<u16> {
            self.log
                .iter()
                .filter(|e| e.0 == "pwm")
                .map(|e| e.1 as u16)
                .collect()
        }
    }
    impl EdpPanelHw for FakeHw {
        fn set_vdd(&mut self, on: bool) {
            self.log.push(("vdd", u32::from(on)));
        }
        fn set_backlight_enable(&mut self, on: bool) {
            self.log.push(("bl_en", u32::from(on)));
        }
        fn set_pwm(&mut self, user_level: u16) {
            self.log.push(("pwm", u32::from(user_level)));
        }
        fn delay_ms(&mut self, ms: u16) {
            self.log.push(("delay", u32::from(ms)));
        }
    }

    /// Drive a fresh sequencer to lit, the way a modeset +
    /// first brightness program leaves it.
    fn light_panel(seq: &mut EdpPanelSequencer, hw: &mut FakeHw, level: u16) -> TestResult {
        if seq.power_on_video(hw).is_err() {
            return TestResult::Fail("fixture: power_on_video failed");
        }
        if seq.power_on_backlight(hw, level).is_err() {
            return TestResult::Fail("fixture: power_on_backlight failed");
        }
        TestResult::Pass
    }

    fn smoke_amd_bl_pm_suspend_saves_and_resume_restores_via_sequencer() -> TestResult {
        // 55% is an arbitrary user-chosen level; the expected PWM
        // value comes from the real percent→USER_LEVEL conversion,
        // not a hardcoded constant.
        let level = user_level_for_percent(55);
        let mut seq = EdpPanelSequencer::new(EdpPowerSeq::default());
        let mut hw = FakeHw::new();
        let r = light_panel(&mut seq, &mut hw, level);
        if r != TestResult::Pass {
            return r;
        }
        hw.log.clear();
        let mut pm = BacklightPm::new();
        pm.suspend(Some(55), &mut seq, &mut hw);
        if pm.saved() != Some(55) {
            return TestResult::Fail("suspend did not save the level");
        }
        // Suspend fades the panel: PWM → 0 before power-down.
        if hw.pwm_writes() != alloc::vec![0] {
            return TestResult::Fail("suspend did not fade PWM to 0");
        }
        if seq.state != EdpPanelState::BacklightOff {
            return TestResult::Fail("suspend did not leave BacklightOff");
        }
        // Resume relights through the sequencer at the saved level.
        hw.log.clear();
        if pm.resume(&mut seq, &mut hw).is_err() {
            return TestResult::Fail("resume failed");
        }
        if seq.state != EdpPanelState::BacklightOn {
            return TestResult::Fail("resume did not relight");
        }
        if seq.last_pwm_level != level {
            return TestResult::Fail("sequencer did not cache the restored level");
        }
        if hw.pwm_writes() != alloc::vec![level] {
            return TestResult::Fail("resume did not re-apply the saved level");
        }
        // One save pairs with one restore.
        if pm.saved().is_some() {
            return TestResult::Fail("successful restore must clear the saved level");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_amd_bl_pm_suspend_saves_and_resume_restores_via_sequencer
    );

    fn smoke_amd_bl_pm_resume_without_saved_level_leaves_default() -> TestResult {
        let mut seq = EdpPanelSequencer::new(EdpPowerSeq::default());
        let mut hw = FakeHw::new();
        let mut pm = BacklightPm::new();
        // No suspend ever ran: resume must program nothing.
        if pm.resume(&mut seq, &mut hw).is_err() {
            return TestResult::Fail("no-save resume must succeed");
        }
        if !hw.pwm_writes().is_empty() {
            return TestResult::Fail("no-save resume wrote PWM");
        }
        if seq.state != EdpPanelState::Off {
            return TestResult::Fail("no-save resume moved the sequencer");
        }
        // Suspend with no programmed level saves nothing, and the
        // following resume is still a no-op.
        pm.suspend(None, &mut seq, &mut hw);
        if pm.saved().is_some() {
            return TestResult::Fail("suspend with no level must save nothing");
        }
        if pm.resume(&mut seq, &mut hw).is_err() {
            return TestResult::Fail("no-save resume must succeed");
        }
        if !hw.pwm_writes().is_empty() {
            return TestResult::Fail("no-save resume wrote PWM after suspend");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_amd_bl_pm_resume_without_saved_level_leaves_default
    );

    fn smoke_amd_bl_pm_resume_from_off_runs_full_sequence() -> TestResult {
        // The host never sequenced the panel (fresh probe, no
        // modeset yet) but a level was saved — e.g. suspend ran
        // while the sequencer was Off. Resume must run the full
        // power_on_video → power_on_backlight chain, not fail on
        // the Off state.
        let level = user_level_for_percent(80);
        let mut seq = EdpPanelSequencer::new(EdpPowerSeq::default());
        let mut hw = FakeHw::new();
        let mut pm = BacklightPm::new();
        pm.suspend(Some(80), &mut seq, &mut hw);
        if seq.state != EdpPanelState::Off {
            return TestResult::Fail("suspend must leave an Off sequencer Off");
        }
        if pm.resume(&mut seq, &mut hw).is_err() {
            return TestResult::Fail("resume from Off failed");
        }
        if seq.state != EdpPanelState::BacklightOn {
            return TestResult::Fail("resume from Off did not reach BacklightOn");
        }
        if hw.pwm_writes() != alloc::vec![level] {
            return TestResult::Fail("resume from Off did not apply the saved level");
        }
        // VDD was asserted on the way up (the full chain ran).
        if !hw.log.contains(&("vdd", 1)) {
            return TestResult::Fail("resume from Off skipped the VDD step");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_amd_bl_pm_resume_from_off_runs_full_sequence
    );

    fn smoke_amd_bl_pm_suspend_twice_resume_once() -> TestResult {
        // A second suspend without an intervening resume must not
        // lose the level or wedge the sequencer: the fade is
        // skipped the second time (already BacklightOff) and the
        // save still holds.
        let level = user_level_for_percent(40);
        let mut seq = EdpPanelSequencer::new(EdpPowerSeq::default());
        let mut hw = FakeHw::new();
        let r = light_panel(&mut seq, &mut hw, level);
        if r != TestResult::Pass {
            return r;
        }
        let mut pm = BacklightPm::new();
        pm.suspend(Some(40), &mut seq, &mut hw);
        pm.suspend(Some(40), &mut seq, &mut hw);
        if pm.saved() != Some(40) {
            return TestResult::Fail("double suspend lost the level");
        }
        if seq.state != EdpPanelState::BacklightOff {
            return TestResult::Fail("double suspend left a bad state");
        }
        if pm.resume(&mut seq, &mut hw).is_err() {
            return TestResult::Fail("resume after double suspend failed");
        }
        if hw.pwm_writes().last() != Some(&level) {
            return TestResult::Fail("resume after double suspend did not restore");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_amd_bl_pm_suspend_twice_resume_once);

    fn smoke_amd_bl_pm_fanout_registers_and_runs() -> TestResult {
        // The real `amdgpu-bl` fns, registered under the power
        // registry's test isolation, run clean through both
        // fan-outs on an unprobed machine: no panel installed, so
        // suspend saves nothing and resume programs nothing.
        use narf_power::device_pm::{
            __test_isolate_registry, register_device_pm, resume_all_devices, suspend_all_devices,
        };
        let _guard = __test_isolate_registry();
        register_device_pm(
            "amdgpu-bl",
            super::amdgpu_bl_suspend,
            super::amdgpu_bl_resume,
        );
        let srep = suspend_all_devices();
        if !srep.ok() {
            return TestResult::Fail("amdgpu-bl suspend fan-out reported failure");
        }
        if srep.outcomes.len() != 1 || srep.outcomes[0].name != "amdgpu-bl" {
            return TestResult::Fail("suspend fan-out did not run amdgpu-bl");
        }
        let rrep = resume_all_devices();
        if !rrep.ok() {
            return TestResult::Fail("amdgpu-bl resume fan-out reported failure");
        }
        if rrep.outcomes.len() != 1 || rrep.outcomes[0].name != "amdgpu-bl" {
            return TestResult::Fail("resume fan-out did not run amdgpu-bl");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_amd_bl_pm_fanout_registers_and_runs);

    // ── DPMS hookup (#1690) ──────────────────────────────────────

    fn smoke_amd_bl_dpms_blank_fades_and_unblank_relights() -> TestResult {
        // Sequencer-lit panel (a previous suspend/resume cycle
        // left it BacklightOn): blank fades via the sequencer,
        // unblank relights at the saved level.
        let level = user_level_for_percent(55);
        let mut seq = EdpPanelSequencer::new(EdpPowerSeq::default());
        let mut hw = FakeHw::new();
        let r = light_panel(&mut seq, &mut hw, level);
        if r != TestResult::Pass {
            return r;
        }
        hw.log.clear();
        let mut pm = BacklightPm::new();
        pm.dpms_blank(Some(55), &mut seq, &mut hw);
        if pm.saved() != Some(55) {
            return TestResult::Fail("DPMS blank did not save the level");
        }
        if hw.pwm_writes() != alloc::vec![0] {
            return TestResult::Fail("DPMS blank did not fade PWM to 0");
        }
        if seq.state != EdpPanelState::BacklightOff {
            return TestResult::Fail("DPMS blank did not leave BacklightOff");
        }
        // The sequencer fade ran its T7 + BL_EN half.
        if !hw.log.contains(&("bl_en", 0)) {
            return TestResult::Fail("DPMS blank skipped the BL_EN step");
        }
        hw.log.clear();
        if pm.dpms_unblank(&mut seq, &mut hw).is_err() {
            return TestResult::Fail("DPMS unblank failed");
        }
        if seq.state != EdpPanelState::BacklightOn {
            return TestResult::Fail("DPMS unblank did not relight");
        }
        if hw.pwm_writes() != alloc::vec![level] {
            return TestResult::Fail("DPMS unblank did not restore the saved level");
        }
        if pm.saved().is_some() {
            return TestResult::Fail("successful unblank must clear the saved level");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_amd_bl_dpms_blank_fades_and_unblank_relights
    );

    fn smoke_amd_bl_dpms_blank_without_saved_level_is_noop() -> TestResult {
        // Never-programmed panel, sequencer Off: blank saves
        // nothing and touches nothing; unblank is a no-op too.
        let mut seq = EdpPanelSequencer::new(EdpPowerSeq::default());
        let mut hw = FakeHw::new();
        let mut pm = BacklightPm::new();
        pm.dpms_blank(None, &mut seq, &mut hw);
        if pm.saved().is_some() {
            return TestResult::Fail("DPMS blank with no level must save nothing");
        }
        if !hw.log.is_empty() {
            return TestResult::Fail("DPMS blank with no level touched hardware");
        }
        if seq.state != EdpPanelState::Off {
            return TestResult::Fail("DPMS blank with no level moved the sequencer");
        }
        if pm.dpms_unblank(&mut seq, &mut hw).is_err() {
            return TestResult::Fail("DPMS unblank with no save must succeed");
        }
        if !hw.log.is_empty() {
            return TestResult::Fail("DPMS unblank with no save touched hardware");
        }
        if seq.state != EdpPanelState::Off {
            return TestResult::Fail("DPMS unblank with no save moved the sequencer");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_amd_bl_dpms_blank_without_saved_level_is_noop
    );

    fn smoke_amd_bl_dpms_repeated_blank_unblank_cycles() -> TestResult {
        // Three blank/unblank cycles at 40%: every blank saves
        // and fades, every unblank relights at the saved level,
        // and the state never wedges.
        let level = user_level_for_percent(40);
        let mut seq = EdpPanelSequencer::new(EdpPowerSeq::default());
        let mut hw = FakeHw::new();
        let r = light_panel(&mut seq, &mut hw, level);
        if r != TestResult::Pass {
            return r;
        }
        let mut pm = BacklightPm::new();
        for _ in 0..3 {
            hw.log.clear();
            pm.dpms_blank(Some(40), &mut seq, &mut hw);
            if pm.saved() != Some(40) {
                return TestResult::Fail("cycle blank lost the level");
            }
            if hw.pwm_writes() != alloc::vec![0] {
                return TestResult::Fail("cycle blank did not fade");
            }
            if seq.state != EdpPanelState::BacklightOff {
                return TestResult::Fail("cycle blank left a bad state");
            }
            hw.log.clear();
            if pm.dpms_unblank(&mut seq, &mut hw).is_err() {
                return TestResult::Fail("cycle unblank failed");
            }
            if seq.state != EdpPanelState::BacklightOn {
                return TestResult::Fail("cycle unblank did not relight");
            }
            if hw.pwm_writes() != alloc::vec![level] {
                return TestResult::Fail("cycle unblank did not restore the level");
            }
            if pm.saved().is_some() {
                return TestResult::Fail("cycle unblank did not clear the save");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_amd_bl_dpms_repeated_blank_unblank_cycles
    );

    fn smoke_amd_bl_dpms_blank_fades_unsequenced_panel() -> TestResult {
        // The fresh-boot production shape: the panel is lit via
        // `set_brightness` (BL_PWM programmed directly) while the
        // probe-installed sequencer still sits in `Off` — nothing
        // ever sequenced it. A sequencer-only fade would be a
        // no-op, so blank writes PWM 0 directly and leaves the
        // sequencer alone; unblank then runs the full chain.
        let level = user_level_for_percent(55);
        let mut seq = EdpPanelSequencer::new(EdpPowerSeq::default());
        let mut hw = FakeHw::new();
        let mut pm = BacklightPm::new();
        pm.dpms_blank(Some(55), &mut seq, &mut hw);
        if pm.saved() != Some(55) {
            return TestResult::Fail("unsequenced blank did not save the level");
        }
        if hw.pwm_writes() != alloc::vec![0] {
            return TestResult::Fail("unsequenced blank did not fade PWM to 0");
        }
        // Direct PWM write only: no sequencer delay / BL_EN events.
        if hw.log.iter().any(|e| e.0 == "delay" || e.0 == "bl_en") {
            return TestResult::Fail("unsequenced blank ran sequencer steps");
        }
        if seq.state != EdpPanelState::Off {
            return TestResult::Fail("unsequenced blank moved the sequencer");
        }
        hw.log.clear();
        if pm.dpms_unblank(&mut seq, &mut hw).is_err() {
            return TestResult::Fail("unblank after unsequenced blank failed");
        }
        if seq.state != EdpPanelState::BacklightOn {
            return TestResult::Fail("unblank after unsequenced blank did not relight");
        }
        if hw.pwm_writes() != alloc::vec![level] {
            return TestResult::Fail("unblank did not restore the saved level");
        }
        // The full power_on_video → power_on_backlight chain ran.
        if !hw.log.contains(&("vdd", 1)) {
            return TestResult::Fail("unblank skipped the VDD step of the full chain");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_amd_bl_dpms_blank_fades_unsequenced_panel
    );

    fn smoke_amd_bl_dpms_fbdev_entry_is_noop_unprobed() -> TestResult {
        // The production `fbdev_dpms` entry with no panel
        // installed (unprobed machine): both directions return
        // without touching anything — no panic, no state.
        super::fbdev_dpms(false);
        super::fbdev_dpms(true);
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu",
        smoke_amd_bl_dpms_fbdev_entry_is_noop_unprobed
    );
}

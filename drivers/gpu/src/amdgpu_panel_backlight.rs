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
//! References (GPL-2.0-or-later):
//! - `drivers/gpu/drm/amd/amdgpu/amdgpu_backlight.c` — the DRM
//!   backlight device amdgpu registers for the internal panel.

use alloc::sync::Arc;
use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_drivers_backlight::{BacklightDevice, BacklightKind};

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

/// Register the AMD panel backlight owner with the backlight
/// subsystem's single-owner arbitration. Called from the amdgpu
/// PCI probe for APUs — the internal-panel targets. Discrete cards
/// have no panel to own and never call this.
///
/// Registration is bookkeeping only: nothing touches hardware here,
/// and `set_backlight` keeps refusing until a mode is programmed.
pub fn register_panel_owner() {
    let ownership =
        narf_drivers_backlight::register_backlight(Arc::new(AmdgpuPanelBacklight::new()));
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
        // With no probed controller a set is a silent no-op: no
        // panic, and no phantom cached level. (A fixture-stashed
        // controller without a mode refuses inside set_backlight,
        // which lands in the same place.)
        if !crate::amdgpu::is_probed() {
            dev.set_brightness(55);
            if dev.current_brightness() != 0 {
                return TestResult::Fail("unapplied level was cached");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu", smoke_amdgpu_panel_backlight_contract);
}

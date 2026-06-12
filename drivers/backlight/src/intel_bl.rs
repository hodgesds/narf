//! Intel integrated GPU backlight driver.
//!
#![allow(clippy::undocumented_unsafe_blocks)]
//! This module implements direct PWM duty-cycle programming against the
//! Intel display engine's PWM block.
//!
//! ## References (GPL-2.0-or-later, direct citation allowed)
//!
//! - `drivers/gpu/drm/i915/display/intel_backlight.c` —
//!   `bxt_set_backlight`, `pch_get_max_backlight`.
//! - `drivers/gpu/drm/xe/display/xe_display.c` — Xe backlight ops.
//! - Intel "Tiger Lake Platform Controller Hub EDS Vol 2" — PWM register
//!   offsets and bit definitions.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::fmt::Write as FmtWrite;

use crate::{BacklightDevice, BacklightKind};
use narf_driver_runtime::MmioRegion;

// ── Intel BLC PWM Registers ──────────────────────────────────────

/// `BLC_PWM_CTL` (legacy PCH path). High 16 bits = period, low 16
/// bits = duty cycle. Used on Skylake PCH and earlier display
/// engines.
pub const BLC_PWM_CTL: u64 = 0xC8250;
/// `SOUTH_CHICKEN1` — panel-power gating chicken bits. Bit 25
/// (`PCH_LPC_PWM_SEL`) selects whether the LPC or the CPU drives
/// the PWM. The activator clears this bit so the iGPU owns the PWM.
pub const SOUTH_CHICKEN1: u64 = 0xC2000;
/// `BXT_BLC_PWM_FREQ1` — period register, modern PCH path (BXT+).
pub const BXT_BLC_PWM_FREQ1: u64 = 0xC8254;
/// `BXT_BLC_PWM_DUTY1` — duty-cycle target, modern PCH path.
pub const BXT_BLC_PWM_DUTY1: u64 = 0xC8258;

// ── Intel Backlight Device ─────────────────────────────────────────

/// Intel backlight device.
#[derive(Debug)]
pub struct IntelBacklightDevice {
    pub name: String,
    mmio: MmioRegion,
    max: u32,
}

impl IntelBacklightDevice {
    /// Construct a new Intel backlight device.
    ///
    /// # Safety
    /// `mmio` must be a valid mapping of the iGPU's BAR0 registers.
    pub unsafe fn new(name: &str, mmio: MmioRegion) -> Self {
        // Read period from BXT_BLC_PWM_FREQ1.
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let max = unsafe { mmio.read32(BXT_BLC_PWM_FREQ1) };
        Self {
            name: name.to_string(),
            mmio,
            max,
        }
    }

    /// Convert 0..100 percentage to duty count.
    fn pct_to_duty(&self, pct: u32) -> u32 {
        let p = self.max as u64;
        let pct = pct.min(100) as u64;
        ((p * pct) / 100) as u32
    }

    /// Convert duty count to 0..100 percentage.
    fn duty_to_pct(&self, duty: u32) -> u32 {
        if self.max == 0 {
            return 0;
        }
        let p = self.max as u64;
        let d = duty.min(self.max) as u64;
        ((d * 100 + p / 2) / p) as u32
    }
}

impl BacklightDevice for IntelBacklightDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_brightness(&self) -> u32 {
        100 // We expose percentage to the subsystem
    }

    fn current_brightness(&self) -> u32 {
        if self.max == 0 {
            return 0;
        }
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let duty = unsafe { self.mmio.read32(BXT_BLC_PWM_DUTY1) };
        self.duty_to_pct(duty)
    }

    fn set_brightness(&self, level: u32) {
        if self.max == 0 {
            return;
        }
        let duty = self.pct_to_duty(level);
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { self.mmio.write32(BXT_BLC_PWM_DUTY1, duty) };
    }

    fn kind(&self) -> BacklightKind {
        BacklightKind::Raw
    }
}

// ── initcall / installation ─────────────────────────────────────────

/// Stub initcall. The GPU driver calls `install()` once it has mapped
/// the display BAR.
pub fn init() {
    // No-op; registration happens from GPU probe.
}

/// Install an Intel backlight device. Called from Intel GPU bring-up
/// code once the BAR is mapped.
pub fn install(mmio: MmioRegion) {
    // Ungate PWM: clear PCH_LPC_PWM_SEL (bit 25) so the iGPU owns the PWM.
    // SAFETY: Valid MMIO bounds or trusted driver environment
    unsafe {
        let val = mmio.read32(SOUTH_CHICKEN1);
        mmio.write32(SOUTH_CHICKEN1, val & !(1 << 25));
    }

    // SAFETY: Valid MMIO bounds or trusted driver environment
    let dev = unsafe { IntelBacklightDevice::new("intel_backlight", mmio) };
    let _ = writeln!(
        narf_console::Writer,
        "  intel-backlight: registered, max_duty={}",
        dev.max
    );
    crate::register_backlight(Arc::new(dev));
}

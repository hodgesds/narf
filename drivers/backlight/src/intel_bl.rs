//! Intel integrated GPU backlight driver.
//!
#![allow(clippy::undocumented_unsafe_blocks)]
//! This module implements direct PWM duty-cycle programming against the
//! Intel display engine's PWM block.
//!
//! ## References (GPL-2.0-or-later, direct citation allowed)
//!
//! - `drivers/gpu/drm/i915/display/intel_backlight.c` —
//!   `bxt_set_backlight`, `pch_get_max_backlight`,
//!   `lpt_set_backlight`, `lpt_get_backlight`,
//!   `spt_pwm_funcs`.
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
/// `BLC_PWM_PCH_CTL2` — the SPT period/duty register (same
/// address as `BXT_BLC_PWM_FREQ1`): high 16 bits = period, low
/// 16 bits = duty (`lpt_set_backlight` / `lpt_get_backlight`,
/// `display/intel_backlight.c`).
pub const BLC_PWM_PCH_CTL2: u64 = 0xC8254;
/// `SPT_PWM_GRANULARITY` — bit 0 of `SOUTH_CHICKEN1` (the
/// alternate PWM increment on the SPT path). Not modeled: the
/// device preserves the firmware period and never converts
/// Hz→PWM, so a future VBT-plumbed backlight can set it at
/// enable time per Linux `lpt_enable_backlight`.
pub const SPT_PWM_GRANULARITY: u32 = 1 << 0;

/// Which PWM register layout the device drives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PwmLayout {
    /// BXT/CNP: period in `BXT_BLC_PWM_FREQ1` (0xC8254),
    /// duty in `BXT_BLC_PWM_DUTY1` (0xC8258).
    Bxt,
    /// SPT (Skylake PCH): period in the high 16 bits of
    /// `BLC_PWM_PCH_CTL2` (0xC8254), duty in its low 16
    /// bits — the duty write is a read-modify-write that
    /// preserves the period.
    Spt,
}

// ── Intel Backlight Device ─────────────────────────────────────────

/// `_BXT_BLC_PWM_CTL2` - `_BXT_BLC_PWM_CTL1`: the second BXT controller's
/// block (`BXT_BLC_PWM_CTL(controller)`, `_MMIO_PIPE`).
pub const BXT_CONTROLLER_STRIDE: u64 = 0x100;

/// Intel backlight device.
#[derive(Debug)]
pub struct IntelBacklightDevice {
    pub name: String,
    mmio: MmioRegion,
    max: u32,
    layout: PwmLayout,
    /// The BXT controller's offset from controller 0's block.
    offset: u64,
}

impl IntelBacklightDevice {
    /// Construct a new Intel backlight device.
    ///
    /// # Safety
    /// `mmio` must be a valid mapping of the iGPU's BAR0 registers.
    pub unsafe fn new(name: &str, mmio: MmioRegion) -> Self {
        // SAFETY: Valid MMIO bounds or trusted driver environment
        unsafe { Self::new_with_layout(name, mmio, PwmLayout::Bxt) }
    }

    /// Construct a new Intel backlight device with an explicit
    /// PWM layout (BXT for Gen11/Gen12, SPT for Gen9 Skylake).
    ///
    /// # Safety
    /// `mmio` must be a valid mapping of the iGPU's BAR0 registers.
    pub unsafe fn new_with_layout(name: &str, mmio: MmioRegion, layout: PwmLayout) -> Self {
        // SAFETY: forwarded from the caller.
        unsafe { Self::new_at(name, mmio, layout, 0) }
    }

    /// The BXT layout on `controller` (0 or 1; any other value is
    /// controller 0).
    ///
    /// # Safety
    /// `mmio` must be a valid mapping of the iGPU's BAR0 registers.
    pub unsafe fn new_bxt_controller(name: &str, mmio: MmioRegion, controller: u8) -> Self {
        let offset = if controller == 1 {
            BXT_CONTROLLER_STRIDE
        } else {
            0
        };
        // SAFETY: forwarded from the caller.
        unsafe { Self::new_at(name, mmio, PwmLayout::Bxt, offset) }
    }

    unsafe fn new_at(name: &str, mmio: MmioRegion, layout: PwmLayout, offset: u64) -> Self {
        // BXT: the whole FREQ register is the period. SPT:
        // the period is CTL2's high 16 bits (`lpt_get_backlight`
        // reads `BLC_PWM_PCH_CTL2 >> 16`).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let max = match layout {
            PwmLayout::Bxt => unsafe { mmio.read32(BXT_BLC_PWM_FREQ1 + offset) },
            PwmLayout::Spt => (unsafe { mmio.read32(BLC_PWM_PCH_CTL2) }) >> 16,
        };
        Self {
            name: name.to_string(),
            mmio,
            max,
            layout,
            offset,
        }
    }

    /// The BXT controller block in use (0: `BXT_BLC_PWM_*1`).
    pub fn bxt_offset(&self) -> u64 {
        self.offset
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
        // BXT: duty lives in DUTY1. SPT: duty is CTL2's low 16
        // bits (`lpt_get_backlight`).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        let duty = match self.layout {
            PwmLayout::Bxt => unsafe { self.mmio.read32(BXT_BLC_PWM_DUTY1 + self.offset) },
            PwmLayout::Spt => (unsafe { self.mmio.read32(BLC_PWM_PCH_CTL2) }) & 0xFFFF,
        };
        self.duty_to_pct(duty)
    }

    fn set_brightness(&self, level: u32) {
        if self.max == 0 {
            return;
        }
        let duty = self.pct_to_duty(level);
        // BXT: plain write to DUTY1. SPT: read-modify-write
        // CTL2's low 16 bits, preserving the period in the
        // high 16 bits (`lpt_set_backlight`).
        // SAFETY: Valid MMIO bounds or trusted driver environment
        match self.layout {
            PwmLayout::Bxt => unsafe { self.mmio.write32(BXT_BLC_PWM_DUTY1 + self.offset, duty) },
            PwmLayout::Spt => unsafe {
                let cur = self.mmio.read32(BLC_PWM_PCH_CTL2);
                self.mmio.write32(BLC_PWM_PCH_CTL2, (cur & !0xFFFF) | duty);
            },
        }
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

/// Install the Broxton / Gemini Lake backlight on the VBT's `controller`
/// (`bxt_setup_backlight`: `BXT_BLC_PWM_FREQ/DUTY(controller)`). Gen9 LP
/// has no PCH, so `SOUTH_CHICKEN1`'s PWM select is not touched.
pub fn install_bxt(mmio: MmioRegion, controller: u8) {
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let dev =
        unsafe { IntelBacklightDevice::new_bxt_controller("intel_backlight", mmio, controller) };
    let _ = writeln!(
        narf_console::Writer,
        "  intel-backlight: registered (BXT controller {}), max_duty={}",
        dev.offset / BXT_CONTROLLER_STRIDE,
        dev.max
    );
    crate::register_backlight(Arc::new(dev));
}

/// Install an Intel backlight device with the SPT PWM layout
/// (Skylake PCH). Called from Intel GPU bring-up when the
/// generation drives SPT (`Generation::Skylake`). The SPT
/// install does not clear the BXT `PCH_LPC_PWM_SEL` bit —
/// that ownership step belongs to the BXT path; the SPT
/// enable sequence (CTL1 enable + `SPT_PWM_GRANULARITY`)
/// belongs to a future backlight-enable step per Linux
/// `lpt_enable_backlight`, and this install preserves the
/// firmware period exactly as `install` does for BXT.
pub fn install_spt(mmio: MmioRegion) {
    // SAFETY: Valid MMIO bounds or trusted driver environment
    let dev =
        unsafe { IntelBacklightDevice::new_with_layout("intel_backlight", mmio, PwmLayout::Spt) };
    let _ = writeln!(
        narf_console::Writer,
        "  intel-backlight: registered (SPT), max_duty={}",
        dev.max
    );
    crate::register_backlight(Arc::new(dev));
}

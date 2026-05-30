//! Intel backlight scaffold.
//!
//! The bring-up targets (Renoir / Phoenix) are AMD-only; this module
//! ships a structural scaffold so the codebase compiles cleanly on
//! Intel platforms and so Intel bring-up has a landing zone.
//!
//! ## DEFERRED
//!
//! Full Intel PWM programming (BXT_BLC_PWM_FREQ1 / BXT_BLC_PWM_DUTY1
//! register writes) is deferred until an Intel hardware bring-up
//! target is added. The existing implementations in
//! `drivers/gpu/src/backlight.rs` (`intel_set_pct`, `intel_get_pct`,
//! `MmioWindow` trait) are the correct building blocks; the missing
//! piece is the platform probe that maps the iGPU BAR and calls
//! `activate_intel_blc`.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/gpu/drm/i915/display/intel_backlight.c` —
//!   `bxt_set_backlight`, `pch_get_max_backlight`.
//! - `drivers/gpu/drm/xe/display/xe_display.c` — Xe backlight ops.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use core::fmt::Write as FmtWrite;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::{BacklightDevice, BacklightKind};

// ── Scaffold device ────────────────────────────────────────────────

/// Intel backlight scaffold device.
///
/// Registered as `"intel_backlight"` when an Intel GPU is detected.
/// All `set_brightness` / `current_brightness` calls are no-ops until
/// the PWM MMIO wiring is implemented (see module doc).
#[derive(Debug)]
pub struct IntelBacklightDevice {
    pub name: String,
    cached: AtomicU32,
    max: u32,
}

impl IntelBacklightDevice {
    pub fn new(name: &str, initial: u32, max: u32) -> Self {
        Self {
            name: name.to_string(),
            cached: AtomicU32::new(initial),
            max,
        }
    }
}

impl BacklightDevice for IntelBacklightDevice {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_brightness(&self) -> u32 {
        self.max
    }

    fn current_brightness(&self) -> u32 {
        // Deferred: would read BXT_BLC_PWM_DUTY1 / BXT_BLC_PWM_FREQ1
        // and scale to a step value. Returns cached write value for now.
        self.cached.load(Ordering::Acquire)
    }

    fn set_brightness(&self, level: u32) {
        // Deferred: would write BXT_BLC_PWM_DUTY1 via MmioWindow.
        let clamped = level.min(self.max);
        self.cached.store(clamped, Ordering::Release);
    }

    fn kind(&self) -> BacklightKind {
        BacklightKind::Raw
    }
}

// ── initcall stub ──────────────────────────────────────────────────

/// Stub initcall. On AMD-only platforms this is a no-op; on an Intel
/// platform the bring-up code calls `install()` after the GPU BAR
/// is mapped. Logs the deferred status so bring-up traces are clear.
pub fn init() {
    let _ = writeln!(
        narf_console::Writer,
        "  intel-backlight: scaffold only — PWM programming deferred"
    );
}

/// Install an Intel backlight device. Called from Intel GPU bring-up
/// code once the BAR is mapped and `BXT_BLC_PWM_FREQ1` is known.
pub fn install(dev: Arc<IntelBacklightDevice>) {
    crate::register_backlight(dev as Arc<dyn BacklightDevice>);
}

//! AMDGPU panel backlight bridge.
//!
//! This module provides a [`BacklightDevice`] implementation that
//! delegates into the AMDGPU driver's existing DCN BL_PWM register
//! sequence (`drivers/gpu/src/amdgpu_backlight.rs` in this tree).
//!
//! The bridge is thin by design: `drivers/gpu/` owns the MMIO
//! sequencing; this crate owns only the registry entry and the
//! percentage ↔ u32 level conversion for the sysfs interface.
//!
//! ## Bridge interface
//!
//! `drivers/gpu/amdgpu_backlight` exposes:
//!   - `user_level_for_percent(pct: u8) -> u16` — scale percent to
//!     BL_PWM_USER_LEVEL.
//!   - `build_set_user_level(base: u32, level: u16) -> Vec<DcnWrite>`
//!     — build the lock→write→unlock register sequence.
//!
//! The DCN write executor lives in `drivers/gpu` and is not
//! re-exported here to avoid a cyclic dependency. Instead, this crate
//! defines the [`AmdgpuBlExecutor`] trait so production code (in
//! `drivers/gpu/`) can inject its MMIO writer, and test code can
//! inject a mock.
//!
//! ## Bring-up targets
//!
//! - **Renoir (Zen 2, Family 17h Model 60h–6Fh)**: `PANEL_CNTL` base
//!   at DCN 2.0 MMIO offset 0x4B00 (per `dce_panel_cntl.c`).
//! - **Phoenix / HawkPoint1 (Zen 4, DCN 3.5, PCI 1002:1900)**:
//!   `PANEL_CNTL` at DCN 3.5 base (same register layout, different
//!   stride). Reference: `dcn31_panel_cntl.c`.
//!
//! ## References (GPL-2.0-or-later)
//!
//! - `drivers/gpu/drm/amd/display/dc/dce/dce_panel_cntl.c` —
//!   `dce_panel_cntl_hw_translate_brightness`.
//! - `drivers/gpu/drm/amd/display/dc/dcn31/dcn31_panel_cntl.c` —
//!   Phoenix delta.
//! - `drivers/gpu/drm/amd/amdgpu/amdgpu_backlight.c` —
//!   `amdgpu_backlight_update_status`, the DRM backlight ops wrapper.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as FmtWrite;
use core::sync::atomic::{AtomicU32, Ordering};

use narf_lib::sync::IrqSafeSpinLock;

use crate::{BacklightDevice, BacklightKind};

// ── AmdgpuBlExecutor trait ─────────────────────────────────────────

/// Platform hook for writing BL_PWM register sequences to the DCN
/// MMIO window.
///
/// Production implementation lives in `drivers/gpu/`; tests inject
/// a [`MockAmdgpuBlExecutor`].
///
/// Ref: Linux `dce_panel_cntl_hw_translate_brightness` — does exactly
/// a lock→USER_LEVEL→unlock sequence, delegating MMIO to the DC
/// register-write path.
pub trait AmdgpuBlExecutor: Send + Sync + core::fmt::Debug {
    /// Apply `user_level` (0–0xFFFF) to the panel. Called from
    /// `set_brightness`.
    fn set_user_level(&self, user_level: u16);
    /// Read back the current user level. Returns 0 on error.
    fn get_user_level(&self) -> u16;
}

// ── AmdgpuBacklightDevice ─────────────────────────────────────────

/// AMDGPU panel backlight device registered under `amdgpu_bl0`.
///
/// `max_brightness` is fixed at 0xFFFF (16-bit USER_LEVEL field).
/// `current_brightness` and `set_brightness` operate in the same
/// 0–0xFFFF space; the sysfs layer scales to percent on demand.
#[derive(Debug)]
pub struct AmdgpuBacklightDevice {
    pub name: String,
    executor: Arc<dyn AmdgpuBlExecutor>,
    cached: AtomicU32,
}

impl AmdgpuBacklightDevice {
    /// Create a new device with `name` (e.g. `"amdgpu_bl0"`) backed
    /// by `executor`. Initial brightness is set to `initial_level`.
    pub fn new(name: &str, executor: Arc<dyn AmdgpuBlExecutor>, initial_level: u16) -> Self {
        Self {
            name: name.to_string(),
            executor,
            cached: AtomicU32::new(initial_level as u32),
        }
    }
}

impl BacklightDevice for AmdgpuBacklightDevice {
    fn name(&self) -> &str {
        &self.name
    }

    /// Maximum brightness: full 16-bit USER_LEVEL range.
    fn max_brightness(&self) -> u32 {
        0xFFFF
    }

    fn current_brightness(&self) -> u32 {
        let cached = self.cached.load(Ordering::Acquire);
        if cached != u32::MAX {
            return cached;
        }
        let live = self.executor.get_user_level() as u32;
        self.cached.store(live, Ordering::Release);
        live
    }

    /// Set brightness level (0–0xFFFF). Clamped to `max_brightness()`.
    fn set_brightness(&self, level: u32) {
        let level = level.min(0xFFFF) as u16;
        self.executor.set_user_level(level);
        self.cached.store(level as u32, Ordering::Release);
    }

    fn kind(&self) -> BacklightKind {
        BacklightKind::Raw
    }
}

// ── Global AMD BL device slot ──────────────────────────────────────

static AMD_BL_DEVICE: IrqSafeSpinLock<Option<Arc<AmdgpuBacklightDevice>>> =
    IrqSafeSpinLock::new(None);

/// Install the AMD GPU backlight device. Replaces any previous one.
/// Called from `drivers/gpu/` after the DCN MMIO window is mapped and
/// the panel-cntl block base is known.
pub fn install(dev: Arc<AmdgpuBacklightDevice>) {
    let prev = AMD_BL_DEVICE.lock().replace(dev.clone());
    // Unregister old entry from the global registry if present.
    if let Some(p) = prev {
        crate::unregister_backlight(p.name());
    }
    crate::register_backlight(dev as Arc<dyn BacklightDevice>);
}

/// Return the currently-installed AMD GPU backlight device, if any.
pub fn amdgpu_bl_device() -> Option<Arc<AmdgpuBacklightDevice>> {
    AMD_BL_DEVICE.lock().clone()
}

// ── initcall stub ──────────────────────────────────────────────────

/// Stage::Device initcall stub. The real install happens from
/// `drivers/gpu/` once DCN is probed; this just logs the absence so
/// a bring-up trace can tell whether the initcall ran.
pub fn init() {
    if AMD_BL_DEVICE.lock().is_none() {
        // No AMD GPU backlight installed yet. drivers/gpu/ will call
        // `install()` later in the same Stage::Device window.
        let _ = writeln!(
            narf_console::Writer,
            "  amdgpu-backlight: waiting for GPU driver install()"
        );
    }
}

// ── MockAmdgpuBlExecutor — test helper ────────────────────────────

/// Test-only executor that records set calls and reflects them on get.
#[derive(Debug)]
pub struct MockAmdgpuBlExecutor {
    pub level: core::sync::atomic::AtomicU16,
    pub set_count: core::sync::atomic::AtomicU32,
}

impl MockAmdgpuBlExecutor {
    pub const fn new(initial: u16) -> Self {
        Self {
            level: core::sync::atomic::AtomicU16::new(initial),
            set_count: core::sync::atomic::AtomicU32::new(0),
        }
    }
}

impl AmdgpuBlExecutor for MockAmdgpuBlExecutor {
    fn set_user_level(&self, level: u16) {
        self.level.store(level, Ordering::Release);
        self.set_count.fetch_add(1, Ordering::Release);
    }
    fn get_user_level(&self) -> u16 {
        self.level.load(Ordering::Acquire)
    }
}

/// Helper: build a `Vec<(u32, u32)>` of (addr, value) pairs for the
/// lock → USER_LEVEL → unlock sequence at `panel_cntl_base`.
///
/// This is the pure register-sequence encoder; the GPU driver's
/// `execute_modeset` physically writes the pairs. Exposed here so
/// the backlight crate can construct the sequence and pass it to the
/// GPU driver without importing MMIO types.
///
/// Register offsets from `dce_panel_cntl.c`:
/// - `BL_PWM_GRP1_REG_LOCK` at base + `0x4B70`
/// - `BL_PWM_USER_LEVEL`    at base + `0x4B64`
///
/// The lock value is `1 << 31`; unlock is `0`.
pub fn build_set_level_writes(panel_cntl_base: u32, user_level: u16) -> Vec<(u32, u32)> {
    const BL_PWM_GRP1_REG_LOCK_REL: u32 = 0x4B70;
    const BL_PWM_USER_LEVEL_REL: u32 = 0x4B64;
    const BL_PWM_GRP1_LOCK: u32 = 1 << 31;

    alloc::vec![
        (panel_cntl_base + BL_PWM_GRP1_REG_LOCK_REL, BL_PWM_GRP1_LOCK),
        (panel_cntl_base + BL_PWM_USER_LEVEL_REL, user_level as u32),
        (panel_cntl_base + BL_PWM_GRP1_REG_LOCK_REL, 0),
    ]
}

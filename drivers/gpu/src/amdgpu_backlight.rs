//! AMD GPU backlight control via DCN BL_PWM.
//!
//! Modern AMD laptop iGPUs drive the panel backlight through a
//! PWM block inside the DCN display window. The host programs:
//!
//! - **BL_PWM_PERIOD_CNTL** — PWM period (in 16-bit clock units).
//!   1 kHz is the typical panel-friendly frequency; the period
//!   register reads `(ref_clk_khz * 1000 / 1000) = ref_clk_khz`
//!   units for that frequency.
//! - **BL_PWM_CNTL** — PWM enable + grp1-source-select +
//!   override-enable bits.
//! - **BL_PWM_USER_LEVEL** — 16-bit duty-cycle target. 0 =
//!   fully off (panel dark); 0xFFFF = fully on. Linear scale
//!   per VESA EDID-DDC; the laptop's panel response is usually
//!   gamma-corrected by the SMU's per-panel calibration table.
//! - **BL_PWM_GRP1_REG_LOCK** — lock bit. The host clears this
//!   bit before writing PERIOD/USER_LEVEL and re-asserts it so
//!   the DCN treats the next vsync as a single atomic update.
//!
//! Linux references (post 2026-05-20 GPL relicense — direct
//! citation allowed):
//! - `drivers/gpu/drm/amd/display/dc/dce/dce_panel_cntl.c`
//! - `drivers/gpu/drm/amd/display/dc/dcn31/dcn31_panel_cntl.c`
//!   (Phoenix delta — same shape, different stride)

extern crate alloc;

use alloc::vec::Vec;

use crate::amdgpu_dcn::DcnWrite;

// ── BL_PWM register offsets (relative to PANEL_CNTL block) ────────
//
// On DCN 2.0 (Renoir) the BL_PWM regs live in the DCE-derived
// PANEL_CNTL block within the DCN MMIO window. Values from
// `dce_panel_cntl.c`'s register tables.

/// `BL_PWM_PERIOD_CNTL` — PWM frequency setting.
pub const BL_PWM_PERIOD_CNTL_REL: u32 = 0x4B6C;
/// `BL_PWM_CNTL` — enable + grp1 source.
pub const BL_PWM_CNTL_REL: u32 = 0x4B5C;
/// `BL_PWM_USER_LEVEL` — 16-bit duty-cycle target.
pub const BL_PWM_USER_LEVEL_REL: u32 = 0x4B64;
/// `BL_PWM_GRP1_REG_LOCK` — atomic-update lock bit.
pub const BL_PWM_GRP1_REG_LOCK_REL: u32 = 0x4B70;

// ── Field encodings ────────────────────────────────────────────────

/// `BL_PWM_CNTL` — enable the PWM output.
pub const BL_PWM_CNTL_EN: u32 = 1 << 0;
/// `BL_PWM_CNTL` — select group 1 as the PWM source (the path
/// PERIOD_CNTL + USER_LEVEL feed).
pub const BL_PWM_CNTL_GRP1_FRAC_BL_EN: u32 = 1 << 24;
/// `BL_PWM_CNTL` — disable PWM source override (let group 1 drive
/// the output without forcing 0/1 from the override path).
pub const BL_PWM_CNTL_OVERRIDE_DISABLE: u32 = 0;

/// `BL_PWM_GRP1_REG_LOCK` — lock asserted; pending writes
/// accumulate until clear.
pub const BL_PWM_GRP1_LOCK: u32 = 1 << 31;

/// Default PWM period in DCN ref-clock units for the canonical
/// 200 Hz panel-friendly frequency on Renoir's 100 MHz ref clock:
/// period = ref_clk_hz / target_hz = 100_000_000 / 200 = 500_000.
/// Stays inside the 24-bit period field.
pub const BL_PWM_PERIOD_200HZ_RENOIR: u32 = 500_000;

// ── Errors ──────────────────────────────────────────────────────────

/// Errors building a backlight programming sequence.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BacklightError {
    /// PWM period would exceed the 24-bit field.
    PeriodOverflow,
}

// ── Sequence builders ──────────────────────────────────────────────

/// Convert a percentage (0–100) to a 16-bit BL_PWM_USER_LEVEL.
/// Saturating: >100 clamps to 0xFFFF; 0 → 0 (panel dark, but most
/// panels won't fully extinguish — the SMU's brightness-floor
/// calibration table sits between).
pub fn user_level_for_percent(pct: u8) -> u16 {
    let p = pct.min(100) as u32;
    ((p * 0xFFFF) / 100) as u16
}

/// Build the one-shot PWM init sequence: lock → program period
/// + cntl + initial duty → unlock. Caller writes it via DCN's
/// `execute_modeset` (the same MMIO writer the modeset uses).
pub fn build_backlight_init(
    panel_cntl_base: u32,
    period_units: u32,
    initial_user_level: u16,
) -> Result<Vec<DcnWrite>, BacklightError> {
    if period_units & !0x00FF_FFFF != 0 {
        return Err(BacklightError::PeriodOverflow);
    }
    let mut writes = Vec::with_capacity(5);
    // Lock — pending writes won't take effect until unlock.
    writes.push(DcnWrite {
        addr: panel_cntl_base + BL_PWM_GRP1_REG_LOCK_REL,
        value: BL_PWM_GRP1_LOCK,
    });
    // Program period (sets PWM frequency).
    writes.push(DcnWrite {
        addr: panel_cntl_base + BL_PWM_PERIOD_CNTL_REL,
        value: period_units,
    });
    // Enable PWM with grp1 source, no override.
    writes.push(DcnWrite {
        addr: panel_cntl_base + BL_PWM_CNTL_REL,
        value: BL_PWM_CNTL_EN | BL_PWM_CNTL_GRP1_FRAC_BL_EN,
    });
    // Initial duty cycle.
    writes.push(DcnWrite {
        addr: panel_cntl_base + BL_PWM_USER_LEVEL_REL,
        value: initial_user_level as u32,
    });
    // Unlock — DCN latches the new period + duty on next vsync.
    writes.push(DcnWrite {
        addr: panel_cntl_base + BL_PWM_GRP1_REG_LOCK_REL,
        value: 0,
    });
    Ok(writes)
}

/// Build the hot-path "set brightness" sequence used after init:
/// just lock → write USER_LEVEL → unlock. Programs the next vsync.
pub fn build_set_user_level(panel_cntl_base: u32, user_level: u16) -> Vec<DcnWrite> {
    alloc::vec![
        DcnWrite {
            addr: panel_cntl_base + BL_PWM_GRP1_REG_LOCK_REL,
            value: BL_PWM_GRP1_LOCK,
        },
        DcnWrite {
            addr: panel_cntl_base + BL_PWM_USER_LEVEL_REL,
            value: user_level as u32,
        },
        DcnWrite {
            addr: panel_cntl_base + BL_PWM_GRP1_REG_LOCK_REL,
            value: 0,
        },
    ]
}

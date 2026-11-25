//! Gen9 (Skylake / Kaby Lake / Coffee Lake / Whiskey Lake /
//! Comet Lake) CDCLK computation and change sequence.
//!
//! Mirrors Linux `display/intel_cdclk.c` (7.4-rc2,
//! `skl_cdclk_funcs`):
//! - ladder: `skl_calc_cdclk` — VCO-aware, two ladders: VCO
//!   8640 MHz gives 308571 / 432000 / 540000 / 617143 kHz,
//!   VCO 8100 MHz gives 337500 / 450000 / 540000 / 675000 kHz
//!   (`skl_calc_cdclk`, `intel_cdclk.c:970-989`);
//! - voltage level: `skl_calc_voltage_level` (0-3, thresholds
//!   337500 / 450000 / 540000 kHz);
//! - frequency select: `skl_cdclk_freq_sel` (337_308 /
//!   450_432 / 540 / 675_617 in `CDCLK_CTL` bits 27:26) and
//!   `skl_cdclk_decimal` (`DIV_ROUND_CLOSEST(cdclk - 1000,
//!   500)`);
//! - change: `skl_set_cdclk` with the Wa Display #1183
//!   (skl,kbl,cfl) `CDCLK_CTL` dance — clear FREQ_SEL|DECIMAL,
//!   set freq|decimal, set `CDCLK_DIVMUX_CD_OVERRIDE`, enable
//!   DPLL0 on a VCO change, clear FREQ_SEL|DECIMAL, set
//!   freq|decimal, clear the override — around
//!   `skl_dpll0_enable` / `skl_dpll0_disable` (DPLL0 is
//!   `LCPLL1_CTL` 0x46010: `DPLL_CTRL1` link-rate select,
//!   then `LCPLL_PLL_ENABLE`, 5 ms lock wait) and the SKL
//!   pcode CDCLK-control notifies (`SKL_PCODE_CDCLK_CONTROL`
//!   0x7, pre DATA0 `SKL_CDCLK_PREPARE_FOR_CHANGE` 0x3 with
//!   the reply checked for `SKL_CDCLK_READY_FOR_CHANGE` 0x1,
//!   post DATA0 = the voltage level), reusing the pcode
//!   transport in [`crate::intel_gpu_pcode`] exactly as the
//!   Gen11 CDCLK module does;
//! - readout: `skl_get_cdclk` + `skl_dpll0_update` — the
//!   reference clock is a fixed 24 MHz (`skl_dpll0_update`
//!   hardcodes `ref = 24000`; the VCO comes from the
//!   `DPLL_CTRL1` link-rate field, 810/1350/1620/2700 select
//!   VCO 8100, 1080/2160 select VCO 8640) and the CDCLK from
//!   the `CDCLK_CTL` frequency select under that VCO;
//! - VCO selection: `skl_dpll0_vco` — an enabled eDP CRTC
//!   whose link clock is 108 or 216 MHz takes VCO 8640,
//!   everything else VCO 8100 (the init default,
//!   `skl_cdclk_init_hw`).
//!
//! Two Gen11 differences are load-bearing here, not cosmetic:
//! - The reference clock is NOT the DSSM strap. The Gen11
//!   module reads `SKL_DSSM` 0x51004 bits [31:29]
//!   (`icl_readout_refclk`) because ICL's DE PLL reference is
//!   strapped; on SKL `skl_dpll0_update` hardcodes ref 24000
//!   and `skl_update_dpll_ref_clks` feeds the same 24 MHz to
//!   the WRPLL search as `nssc`. This module never reads
//!   DSSM. (`SKL_DSSM` 0x51004 in `intel_gpu_pll` is the ICL
//!   strap decoder, not a Gen9 input.)
//! - Wa Display #1183: on Skylake itself the 308/617 MHz
//!   CDCLK rates (VCO 8640) are unsupported — `skl_set_cdclk`
//!   `WARN_ON_ONCE`s when `platform.skylake && vco ==
//!   8640000` (eDP 1.4 is not supported on SKL). Kaby Lake /
//!   Comet Lake may use VCO 8640 for the eDP 1.4 alternate
//!   link rates; [`select_vco`] encodes that split and
//!   [`program`] refuses a Skylake + VCO 8640 request
//!   outright instead of warning and programming it.
//!
//! The modeset raises CDCLK only (a faster firmware clock is
//! left alone), with every pipe off when the change runs.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gen11_dpll::{
    ctrl1_hdmi_mode, ctrl1_link_rate, ctrl1_link_rate_mask, ctrl1_link_rate_shift, ctrl1_override,
    ctrl1_ssc, DPLL_CTRL1, LINK_RATE_1080, LINK_RATE_1350, LINK_RATE_1620, LINK_RATE_2160,
    LINK_RATE_2700, LINK_RATE_810,
};
use crate::intel_gpu_gt::Gen9Platform;
use crate::intel_gpu_pcode::{pcode_read, pcode_write, PcodeError};
use crate::intel_gpu_pcode::{
    PCODE_CMD_CDCLK_CONTROL, SKL_CDCLK_PREPARE_FOR_CHANGE, SKL_CDCLK_READY_FOR_CHANGE,
};

/// `CDCLK_CTL` (0x46000, shared with Gen11).
pub const CDCLK_CTL: u64 = 0x46000;
/// `LCPLL1_CTL` — DPLL0 control (0x46010).
pub const LCPLL1_CTL: u64 = 0x46010;
/// `LCPLL_PLL_ENABLE` (bit 31).
pub const LCPLL_PLL_ENABLE: u32 = 1 << 31;
/// `LCPLL_PLL_LOCK` (bit 30).
pub const LCPLL_PLL_LOCK: u32 = 1 << 30;

/// `CDCLK_FREQ_SEL_MASK` — `CDCLK_CTL` bits 27:26.
pub const CDCLK_FREQ_SEL_MASK: u32 = 0x3 << 26;
/// `CDCLK_FREQ_450_432` — 450000 (VCO 8100) / 432000 (VCO 8640).
pub const CDCLK_FREQ_450_432: u32 = 0 << 26;
/// `CDCLK_FREQ_540` — 540000 kHz on either VCO.
pub const CDCLK_FREQ_540: u32 = 1 << 26;
/// `CDCLK_FREQ_337_308` — 337500 (VCO 8100) / 308571 (VCO 8640).
pub const CDCLK_FREQ_337_308: u32 = 2 << 26;
/// `CDCLK_FREQ_675_617` — 675000 (VCO 8100) / 617143 (VCO 8640).
pub const CDCLK_FREQ_675_617: u32 = 3 << 26;
/// `CDCLK_DIVMUX_CD_OVERRIDE` — `CDCLK_CTL` bit 19 (Wa #1183).
pub const CDCLK_DIVMUX_CD_OVERRIDE: u32 = 1 << 19;
/// `CDCLK_FREQ_DECIMAL_MASK` — `CDCLK_CTL` bits 10:0.
pub const CDCLK_FREQ_DECIMAL_MASK: u32 = 0x7ff;

/// DPLL0 VCO 8.1 GHz, in kHz (`skl_calc_cdclk` else-branch).
pub const VCO_8100_KHZ: u32 = 8_100_000;
/// DPLL0 VCO 8.64 GHz, in kHz (eDP 1.4 alternate link rates).
pub const VCO_8640_KHZ: u32 = 8_640_000;
/// The SKL CDCLK reference clock in kHz (`skl_dpll0_update`:
/// `ref = 24000`, fixed — not a strap).
pub const REFCLK_KHZ: u32 = 24_000;

/// `skl_calc_cdclk`: the first ladder rung at or above
/// `min_khz` for `vco`. Any VCO other than 8640 takes the
/// 8100 ladder, exactly as Linux's `if (vco == 8640000)
/// ... else ...`.
pub fn calc_cdclk(min_khz: u32, vco: u32) -> u32 {
    if vco == VCO_8640_KHZ {
        if min_khz > 540_000 {
            617_143
        } else if min_khz > 432_000 {
            540_000
        } else if min_khz > 308_571 {
            432_000
        } else {
            308_571
        }
    } else if min_khz > 540_000 {
        675_000
    } else if min_khz > 450_000 {
        540_000
    } else if min_khz > 337_500 {
        450_000
    } else {
        337_500
    }
}

/// `skl_calc_voltage_level`: 0-3 by CDCLK thresholds
/// 337500 / 450000 / 540000 kHz.
pub fn voltage_level(cdclk_khz: u32) -> u8 {
    if cdclk_khz > 540_000 {
        3
    } else if cdclk_khz > 450_000 {
        2
    } else if cdclk_khz > 337_500 {
        1
    } else {
        0
    }
}

/// `skl_cdclk_freq_sel` for a ladder CDCLK under `vco`.
/// A value off the ladder takes the Linux default arm's
/// fallthrough (`CDCLK_FREQ_337_308`); callers only pass
/// ladder values.
pub fn freq_sel(cdclk_khz: u32, vco: u32) -> u32 {
    let _ = vco;
    match cdclk_khz {
        308_571 | 337_500 => CDCLK_FREQ_337_308,
        450_000 | 432_000 => CDCLK_FREQ_450_432,
        540_000 => CDCLK_FREQ_540,
        617_143 | 675_000 => CDCLK_FREQ_675_617,
        _ => CDCLK_FREQ_337_308,
    }
}

/// `skl_cdclk_decimal`: `DIV_ROUND_CLOSEST(cdclk - 1000, 500)`.
pub fn decimal(cdclk_khz: u32) -> u32 {
    (cdclk_khz - 1000 + 250) / 500
}

/// `skl_dpll0_link_rate`: the `DPLL_CTRL1` link rate
/// `skl_dpll0_enable` programs for a VCO — the lowest rate
/// that yields it (1080 for VCO 8640, 810 otherwise). The
/// modeset picks the exact link rate later, constrained to
/// the same VCO.
fn dpll0_link_rate(vco: u32) -> u32 {
    if vco == VCO_8640_KHZ {
        ctrl1_link_rate(LINK_RATE_1080, 0)
    } else {
        ctrl1_link_rate(LINK_RATE_810, 0)
    }
}

/// `skl_dpll0_vco` for a modeset: `edp_link_clock_khz` is
/// the eDP link clock (`port_clock / 2`) of an enabled eDP
/// CRTC, `None` when no eDP CRTC is enabled. The 108/216
/// MHz eDP 1.4 alternate rates take VCO 8640 — except on
/// Skylake itself, where Wa Display #1183 forbids the
/// 308/617 MHz CDCLK rates that VCO implies (eDP 1.4 is not
/// supported on SKL); there the VCO stays 8100.
pub fn select_vco(platform: Gen9Platform, edp_link_clock_khz: Option<u32>) -> u32 {
    match edp_link_clock_khz {
        Some(108_000) | Some(216_000) if !matches!(platform, Gen9Platform::Skylake) => VCO_8640_KHZ,
        _ => VCO_8100_KHZ,
    }
}

/// Hardware CDCLK configuration as `skl_get_cdclk` +
/// `skl_dpll0_update` classify it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Current {
    /// DPLL0 VCO in kHz (0 when the PLL is off, unlocked, or
    /// the `DPLL_CTRL1` field does not select a link rate).
    pub vco: u32,
    /// Decoded CDCLK in kHz (`REFCLK_KHZ` bypass when
    /// `vco == 0`).
    pub cdclk_khz: u32,
    /// Raw registers retained for the readback proof.
    pub pll_ctl: u32,
    pub cdclk_ctl: u32,
    pub ctrl1: u32,
}

/// Typed CDCLK refusals and failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CdclkError {
    /// Current access was lost or a register read all-ones.
    NoDevice,
    /// A lock/unlock did not arrive inside its window.
    Timeout,
    /// A written value did not read back.
    Readback,
    /// A pcode transaction was refused or timed out.
    Pcode(PcodeError),
    /// The pcode pre-notify completed but the punit never set
    /// `SKL_CDCLK_READY_FOR_CHANGE` in the reply DATA0.
    PcodeNotReady,
    /// VCO 8640 on Skylake (Wa Display #1183: the 308/617
    /// MHz rates are unsupported there).
    UnsupportedVco,
}

fn read(io: &(impl MmioWindow + ?Sized), r: u64) -> Result<u32, CdclkError> {
    let value = io.read32(r);
    if value == u32::MAX || !io.display_access_ok() {
        Err(CdclkError::NoDevice)
    } else {
        Ok(value)
    }
}

impl Current {
    /// `skl_get_cdclk` + `skl_dpll0_update`: the reference is
    /// the fixed 24 MHz; the VCO comes from the `DPLL_CTRL1`
    /// link-rate field when DPLL0 is enabled, locked, and its
    /// field is OVERRIDE-only (HDMI_MODE/SSC clear) — any
    /// other shape leaves the VCO at 0 and the CDCLK at the
    /// bypass, exactly as Linux's WARN-and-return paths do.
    /// An unknown frequency-select code likewise leaves the
    /// CDCLK at the bypass (Linux's `MISSING_CASE`).
    pub fn read(io: &(impl MmioWindow + ?Sized)) -> Result<Self, CdclkError> {
        let pll_ctl = read(io, LCPLL1_CTL)?;
        let cdclk_ctl = read(io, CDCLK_CTL)?;
        let ctrl1 = read(io, DPLL_CTRL1)?;
        let mut vco = 0;
        if pll_ctl & LCPLL_PLL_ENABLE != 0
            && pll_ctl & LCPLL_PLL_LOCK != 0
            && ctrl1 & (ctrl1_hdmi_mode(0) | ctrl1_ssc(0) | ctrl1_override(0)) == ctrl1_override(0)
        {
            vco = match (ctrl1 & ctrl1_link_rate_mask(0)) >> ctrl1_link_rate_shift(0) {
                LINK_RATE_810 | LINK_RATE_1350 | LINK_RATE_1620 | LINK_RATE_2700 => VCO_8100_KHZ,
                LINK_RATE_1080 | LINK_RATE_2160 => VCO_8640_KHZ,
                _ => 0,
            };
        }
        let cdclk_khz = if vco == 0 {
            REFCLK_KHZ
        } else if vco == VCO_8640_KHZ {
            match cdclk_ctl & CDCLK_FREQ_SEL_MASK {
                CDCLK_FREQ_450_432 => 432_000,
                CDCLK_FREQ_337_308 => 308_571,
                CDCLK_FREQ_540 => 540_000,
                CDCLK_FREQ_675_617 => 617_143,
                _ => REFCLK_KHZ,
            }
        } else {
            match cdclk_ctl & CDCLK_FREQ_SEL_MASK {
                CDCLK_FREQ_450_432 => 450_000,
                CDCLK_FREQ_337_308 => 337_500,
                CDCLK_FREQ_540 => 540_000,
                CDCLK_FREQ_675_617 => 675_000,
                _ => REFCLK_KHZ,
            }
        };
        Ok(Self {
            vco,
            cdclk_khz,
            pll_ctl,
            cdclk_ctl,
            ctrl1,
        })
    }

    /// Whether this state already runs `vco`/`cdclk_khz`.
    pub fn is_target(self, vco: u32, cdclk_khz: u32) -> bool {
        self.vco == vco && self.cdclk_khz == cdclk_khz
    }
}

fn wait(
    io: &(impl MmioWindow + ?Sized),
    r: u64,
    mask: u32,
    want: u32,
    us: u64,
) -> Result<(), CdclkError> {
    let mut lost = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let value = io.read32(r);
            lost = value == u32::MAX || !io.display_access_ok();
            lost || value & mask == want
        },
        narf_time::Deadline::after_us(us),
    );
    if lost {
        Err(CdclkError::NoDevice)
    } else if done {
        Ok(())
    } else {
        Err(CdclkError::Timeout)
    }
}

/// `skl_dpll0_disable`: RMW `LCPLL1_CTL` clear ENABLE, wait
/// LOCK clear (1 ms).
fn dpll0_disable(io: &(impl MmioWindow + ?Sized)) -> Result<(), CdclkError> {
    let ctl = read(io, LCPLL1_CTL)?;
    io.write32(LCPLL1_CTL, ctl & !LCPLL_PLL_ENABLE);
    wait(io, LCPLL1_CTL, LCPLL_PLL_LOCK, 0, 1_000)
}

/// `skl_dpll0_enable`: RMW `DPLL_CTRL1` to OVERRIDE plus the
/// VCO's link rate (HDMI_MODE/SSC/link-rate cleared), posting
/// read, RMW `LCPLL1_CTL` set ENABLE, wait LOCK set (5 ms).
fn dpll0_enable(io: &(impl MmioWindow + ?Sized), vco: u32) -> Result<(), CdclkError> {
    let cur = read(io, DPLL_CTRL1)?;
    let mask = ctrl1_hdmi_mode(0) | ctrl1_ssc(0) | ctrl1_link_rate_mask(0);
    io.write32(
        DPLL_CTRL1,
        (cur & !mask) | ctrl1_override(0) | dpll0_link_rate(vco),
    );
    let _ = read(io, DPLL_CTRL1)?;
    let ctl = read(io, LCPLL1_CTL)?;
    io.write32(LCPLL1_CTL, ctl | LCPLL_PLL_ENABLE);
    wait(io, LCPLL1_CTL, LCPLL_PLL_LOCK, LCPLL_PLL_LOCK, 5_000)
}

/// `skl_cdclk_pcode_pre_notify`: `SKL_PCODE_CDCLK_CONTROL`
/// with DATA0 `SKL_CDCLK_PREPARE_FOR_CHANGE`, reply DATA0
/// must carry `SKL_CDCLK_READY_FOR_CHANGE` (Linux's
/// `intel_parent_pcode_request(..., 3)`). The pcode codec's
/// 20 ms budget covers Linux's 3 ms base timeout.
fn pre_notify(io: &(impl MmioWindow + ?Sized)) -> Result<(), CdclkError> {
    let (reply, _) = pcode_read(
        io,
        PCODE_CMD_CDCLK_CONTROL,
        0,
        0,
        SKL_CDCLK_PREPARE_FOR_CHANGE,
        0,
    )
    .map_err(CdclkError::Pcode)?;
    if reply & SKL_CDCLK_READY_FOR_CHANGE == 0 {
        return Err(CdclkError::PcodeNotReady);
    }
    Ok(())
}

/// `skl_cdclk_pcode_post_notify`: the same command with DATA0
/// = the target voltage level. Linux ignores its result
/// (`intel_cdclk_set_cdclk`); so does this. The codec's 2 ms
/// budget covers Linux's 1 ms `intel_parent_pcode_write_timeout`.
fn post_notify(io: &(impl MmioWindow + ?Sized), cdclk_khz: u32) {
    let _ = pcode_write(
        io,
        PCODE_CMD_CDCLK_CONTROL,
        0,
        0,
        u32::from(voltage_level(cdclk_khz)),
        0,
    );
}

/// `intel_cdclk_set_cdclk` for one (VCO, CDCLK) target:
/// pre-notify (a refusal, or a reply without the ready bit,
/// aborts before any register write), the Wa #1183
/// `CDCLK_CTL` dance with a DPLL0 disable/enable on a VCO
/// change (`skl_set_cdclk`), post-notify, then the readback
/// proof — the VCO and CDCLK decode to the target and the
/// `CDCLK_CTL` decimal field holds the target's. A target
/// the hardware already runs is a no-op (no notify, no
/// writes); the modeset only calls this when the floor is
/// unmet. VCO 8640 on Skylake is refused (Wa #1183).
///
/// A VCO-0 target at the 24 MHz bypass is `skl_cdclk_uninit_hw`:
/// `skl_dpll0_disable` leaves Linux's tracked VCO at 0, so the
/// frequency is not written before the override and DPLL0 is not
/// enabled again. An `old` whose VCO is `u32::MAX` is
/// `skl_sanitize_cdclk`'s "force full PLL disable + enable".
pub fn program(
    io: &(impl MmioWindow + ?Sized),
    old: &Current,
    target_cdclk_khz: u32,
    target_vco: u32,
    platform: Gen9Platform,
) -> Result<(), CdclkError> {
    if old.is_target(target_vco, target_cdclk_khz) {
        return Ok(());
    }
    if target_vco == VCO_8640_KHZ && matches!(platform, Gen9Platform::Skylake) {
        return Err(CdclkError::UnsupportedVco);
    }
    let want_sel = freq_sel(target_cdclk_khz, target_vco);
    let want_dec = decimal(target_cdclk_khz);
    pre_notify(io)?;
    // `skl_set_cdclk`: disable DPLL0 first on a VCO change
    // from a running PLL; the disable leaves the VCO at 0.
    let mut hw_vco = old.vco;
    if hw_vco != 0 && hw_vco != target_vco {
        dpll0_disable(io)?;
        hw_vco = 0;
    }
    let old_vco = hw_vco;
    let mut ctl = read(io, CDCLK_CTL)?;
    if old_vco != target_vco {
        // Wa #1183: program freq + decimal before the
        // override when the VCO changes.
        ctl &= !(CDCLK_FREQ_SEL_MASK | CDCLK_FREQ_DECIMAL_MASK);
        ctl |= want_sel | want_dec;
        io.write32(CDCLK_CTL, ctl);
    }
    // Wa #1183: override on.
    ctl |= CDCLK_DIVMUX_CD_OVERRIDE;
    io.write32(CDCLK_CTL, ctl);
    let _ = read(io, CDCLK_CTL)?;
    if old_vco != target_vco {
        dpll0_enable(io, target_vco)?;
    }
    // Wa #1183: re-program freq + decimal, override off.
    ctl &= !(CDCLK_FREQ_SEL_MASK | CDCLK_FREQ_DECIMAL_MASK);
    io.write32(CDCLK_CTL, ctl);
    ctl |= want_sel | want_dec;
    io.write32(CDCLK_CTL, ctl);
    ctl &= !CDCLK_DIVMUX_CD_OVERRIDE;
    io.write32(CDCLK_CTL, ctl);
    let _ = read(io, CDCLK_CTL)?;
    post_notify(io, target_cdclk_khz);
    let after = Current::read(io)?;
    if !after.is_target(target_vco, target_cdclk_khz)
        || read(io, CDCLK_CTL)? & CDCLK_FREQ_DECIMAL_MASK != want_dec
    {
        return Err(CdclkError::Readback);
    }
    Ok(())
}

/// What a display-core CDCLK init (`intel_cdclk_init_hw`) did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InitOutcome {
    /// The running clock passed the sanitize checks; nothing written.
    Kept,
    /// Only the `CDCLK_CTL` decimal field was wrong: rewritten in place.
    DecimalFixed,
    /// The clock was programmed from scratch: this VCO and CDCLK (kHz).
    Programmed { vco: u32, cdclk_khz: u32 },
}

/// `skl_sanitize_cdclk`: `None` when the clock must be programmed from
/// scratch ("force full PLL disable + enable"), otherwise what was kept.
fn sanitize(io: &(impl MmioWindow + ?Sized), hw: &Current) -> Result<Option<InitOutcome>, CdclkError> {
    // "Is PLL enabled and locked?"
    if hw.vco == 0 || hw.cdclk_khz == REFCLK_KHZ {
        return Ok(None);
    }
    // "DPLL okay; verify the cdclock": the frequency select as found with
    // the decimal field of the decoded CDCLK, and no other bit.
    let cdctl = read(io, CDCLK_CTL)?;
    let expected = (cdctl & CDCLK_FREQ_SEL_MASK) | decimal(hw.cdclk_khz);
    if cdctl == expected {
        return Ok(Some(InitOutcome::Kept));
    }
    let fixed = (cdctl & !CDCLK_FREQ_DECIMAL_MASK) | (expected & CDCLK_FREQ_DECIMAL_MASK);
    if fixed != expected {
        return Ok(None);
    }
    io.write32(CDCLK_CTL, expected);
    Ok(Some(InitOutcome::DecimalFixed))
}

/// `intel_cdclk_init_hw` on display 9 (`skl_cdclk_init_hw`), run by the
/// display-core init (`skl_display_core_init`): a clock that passes
/// `skl_sanitize_cdclk` is kept (its decimal field corrected if that alone
/// is wrong); otherwise DPLL0 is disabled and re-enabled at the preferred
/// VCO (`skl_preferred_vco_freq`, VCO 8100 when none was recorded) and
/// CDCLK is programmed at that VCO's lowest rung (`skl_calc_cdclk(0, vco)`).
/// Skylake never takes VCO 8640 here (Wa Display #1183; Linux would warn
/// and program it).
pub fn init_hw(
    io: &(impl MmioWindow + ?Sized),
    platform: Gen9Platform,
    preferred_vco: u32,
) -> Result<InitOutcome, CdclkError> {
    let hw = Current::read(io)?;
    if let Some(kept) = sanitize(io, &hw)? {
        return Ok(kept);
    }
    let vco = if preferred_vco == VCO_8640_KHZ && !matches!(platform, Gen9Platform::Skylake) {
        VCO_8640_KHZ
    } else {
        VCO_8100_KHZ
    };
    let cdclk_khz = calc_cdclk(0, vco);
    let forced = Current {
        vco: u32::MAX,
        cdclk_khz: 0,
        ..hw
    };
    program(io, &forced, cdclk_khz, vco, platform)?;
    Ok(InitOutcome::Programmed { vco, cdclk_khz })
}

/// `intel_cdclk_uninit_hw` on display 9 (`skl_cdclk_uninit_hw`), run by
/// the display-core uninit (`skl_display_core_uninit`): CDCLK to the 24 MHz
/// bypass with DPLL0 off. Returns the VCO DPLL0 ran at, the preferred VCO
/// the next [`init_hw`] restores (0 when it was already off).
pub fn uninit_hw(io: &(impl MmioWindow + ?Sized), platform: Gen9Platform) -> Result<u32, CdclkError> {
    let hw = Current::read(io)?;
    program(io, &hw, REFCLK_KHZ, 0, platform)?;
    Ok(hw.vco)
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use crate::intel_gpu_pcode::{PCODE_DATA0, PCODE_MAILBOX};
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Scripted SKL CDCLK endpoint: an LCPLL1_CTL whose LOCK
    /// follows ENABLE (unless `grant_lock` is cleared), a
    /// DPLL_CTRL1 store, a CDCLK_CTL store, and a pcode
    /// endpoint that answers the CDCLK-control command:
    /// pre-notify (DATA0 0x3) replies with the ready bit
    /// (unless `grant_ready` is cleared), post-notify just
    /// completes. A forced pcode status makes every
    /// transaction fail with it.
    struct CdclkMmio {
        pll_ctl: RefCell<u32>,
        cdclk_ctl: RefCell<u32>,
        ctrl1: RefCell<u32>,
        grant_lock: bool,
        grant_ready: bool,
        pcode_status: u8,
        pcode_mailbox: RefCell<u32>,
        pcode_data0: RefCell<u32>,
        writes: RefCell<Vec<(u64, u32)>>,
    }

    impl CdclkMmio {
        fn new() -> Self {
            Self {
                pll_ctl: RefCell::new(0),
                cdclk_ctl: RefCell::new(0),
                ctrl1: RefCell::new(0),
                grant_lock: true,
                grant_ready: true,
                pcode_status: 0,
                pcode_mailbox: RefCell::new(0),
                pcode_data0: RefCell::new(0),
                writes: RefCell::new(Vec::new()),
            }
        }

        fn writes_to(&self, off: u64) -> Vec<u32> {
            self.writes
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }
    }

    impl MmioWindow for CdclkMmio {
        fn read32(&self, off: u64) -> u32 {
            match off {
                o if o == LCPLL1_CTL => {
                    let stored = *self.pll_ctl.borrow();
                    if self.grant_lock && stored & LCPLL_PLL_ENABLE != 0 {
                        stored | LCPLL_PLL_LOCK
                    } else {
                        stored & !LCPLL_PLL_LOCK
                    }
                }
                o if o == CDCLK_CTL => *self.cdclk_ctl.borrow(),
                o if o == DPLL_CTRL1 => *self.ctrl1.borrow(),
                o if o == PCODE_MAILBOX => *self.pcode_mailbox.borrow(),
                o if o == PCODE_DATA0 => *self.pcode_data0.borrow(),
                _ => 0,
            }
        }

        fn write32(&self, off: u64, val: u32) {
            use crate::intel_gpu_pcode::PCODE_READY;
            self.writes.borrow_mut().push((off, val));
            match off {
                o if o == LCPLL1_CTL => {
                    *self.pll_ctl.borrow_mut() = val & !LCPLL_PLL_LOCK;
                }
                o if o == CDCLK_CTL => *self.cdclk_ctl.borrow_mut() = val,
                o if o == DPLL_CTRL1 => *self.ctrl1.borrow_mut() = val,
                o if o == PCODE_DATA0 => *self.pcode_data0.borrow_mut() = val,
                o if o == PCODE_MAILBOX => {
                    if val & PCODE_READY != 0 {
                        let cmd = val & 0xFF;
                        // The punit answers a pre-notify (DATA0 0x3) in
                        // DATA0: READY_FOR_CHANGE when it grants the
                        // change, a reply without that bit when it does
                        // not. Anything else completes with DATA0
                        // untouched.
                        if cmd == PCODE_CMD_CDCLK_CONTROL
                            && *self.pcode_data0.borrow() == SKL_CDCLK_PREPARE_FOR_CHANGE
                        {
                            *self.pcode_data0.borrow_mut() = if self.grant_ready {
                                SKL_CDCLK_READY_FOR_CHANGE
                            } else {
                                0
                            };
                        }
                        *self.pcode_mailbox.borrow_mut() = self.pcode_status as u32;
                    } else {
                        *self.pcode_mailbox.borrow_mut() = val;
                    }
                }
                _ => {}
            }
        }
    }

    fn smoke_skl_cdclk_ladder() -> TestResult {
        // VCO 8640 ladder: 308571 / 432000 / 540000 / 617143.
        if calc_cdclk(0, VCO_8640_KHZ) != 308_571
            || calc_cdclk(308_571, VCO_8640_KHZ) != 308_571
            || calc_cdclk(308_572, VCO_8640_KHZ) != 432_000
            || calc_cdclk(432_000, VCO_8640_KHZ) != 432_000
            || calc_cdclk(432_001, VCO_8640_KHZ) != 540_000
            || calc_cdclk(540_000, VCO_8640_KHZ) != 540_000
            || calc_cdclk(540_001, VCO_8640_KHZ) != 617_143
        {
            return TestResult::Fail("VCO 8640 ladder wrong");
        }
        // VCO 8100 ladder: 337500 / 450000 / 540000 / 675000.
        if calc_cdclk(0, VCO_8100_KHZ) != 337_500
            || calc_cdclk(337_500, VCO_8100_KHZ) != 337_500
            || calc_cdclk(337_501, VCO_8100_KHZ) != 450_000
            || calc_cdclk(450_000, VCO_8100_KHZ) != 450_000
            || calc_cdclk(450_001, VCO_8100_KHZ) != 540_000
            || calc_cdclk(540_000, VCO_8100_KHZ) != 540_000
            || calc_cdclk(540_001, VCO_8100_KHZ) != 675_000
        {
            return TestResult::Fail("VCO 8100 ladder wrong");
        }
        // Any other VCO takes the 8100 ladder (Linux's else).
        if calc_cdclk(0, 0) != 337_500 || calc_cdclk(600_000, 0) != 675_000 {
            return TestResult::Fail("a non-8640 VCO must take the 8100 ladder");
        }
        // The two ladders share only the 540 MHz rung.
        if calc_cdclk(400_000, VCO_8640_KHZ) == calc_cdclk(400_000, VCO_8100_KHZ) {
            return TestResult::Fail("the ladders must differ below 540 MHz");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen9_cdclk", smoke_skl_cdclk_ladder);

    fn smoke_skl_cdclk_voltage_and_sel() -> TestResult {
        // skl_calc_voltage_level boundaries.
        if voltage_level(337_500) != 0
            || voltage_level(337_501) != 1
            || voltage_level(450_000) != 1
            || voltage_level(450_001) != 2
            || voltage_level(540_000) != 2
            || voltage_level(540_001) != 3
            || voltage_level(675_000) != 3
        {
            return TestResult::Fail("voltage-level boundaries wrong");
        }
        // skl_cdclk_freq_sel: both ladders map onto the same
        // four select codes.
        if freq_sel(308_571, VCO_8640_KHZ) != CDCLK_FREQ_337_308
            || freq_sel(337_500, VCO_8100_KHZ) != CDCLK_FREQ_337_308
            || freq_sel(432_000, VCO_8640_KHZ) != CDCLK_FREQ_450_432
            || freq_sel(450_000, VCO_8100_KHZ) != CDCLK_FREQ_450_432
            || freq_sel(540_000, VCO_8100_KHZ) != CDCLK_FREQ_540
            || freq_sel(617_143, VCO_8640_KHZ) != CDCLK_FREQ_675_617
            || freq_sel(675_000, VCO_8100_KHZ) != CDCLK_FREQ_675_617
        {
            return TestResult::Fail("frequency-select mapping wrong");
        }
        // skl_cdclk_decimal: DIV_ROUND_CLOSEST(cdclk-1000, 500).
        if decimal(308_571) != 615
            || decimal(337_500) != 673
            || decimal(432_000) != 862
            || decimal(450_000) != 898
            || decimal(540_000) != 1078
            || decimal(617_143) != 1232
            || decimal(675_000) != 1348
        {
            return TestResult::Fail("decimal divider wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_cdclk",
        smoke_skl_cdclk_voltage_and_sel
    );

    fn smoke_skl_cdclk_vco_selection() -> TestResult {
        // eDP 1.4 alternate link rates take VCO 8640 — except
        // on Skylake, where Wa #1183 forbids it.
        if select_vco(Gen9Platform::KabyLake, Some(108_000)) != VCO_8640_KHZ
            || select_vco(Gen9Platform::KabyLake, Some(216_000)) != VCO_8640_KHZ
            || select_vco(Gen9Platform::CometLake, Some(108_000)) != VCO_8640_KHZ
            || select_vco(Gen9Platform::Skylake, Some(108_000)) != VCO_8100_KHZ
            || select_vco(Gen9Platform::Skylake, Some(216_000)) != VCO_8100_KHZ
        {
            return TestResult::Fail("VCO 8640 selection wrong");
        }
        // Every other link rate, and no eDP CRTC, take 8100.
        if select_vco(Gen9Platform::KabyLake, Some(81_000)) != VCO_8100_KHZ
            || select_vco(Gen9Platform::KabyLake, Some(270_000)) != VCO_8100_KHZ
            || select_vco(Gen9Platform::KabyLake, None) != VCO_8100_KHZ
            || select_vco(Gen9Platform::Skylake, None) != VCO_8100_KHZ
        {
            return TestResult::Fail("VCO 8100 default wrong");
        }
        // program() refuses Skylake + VCO 8640 outright.
        let mmio = CdclkMmio::new();
        let old = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("cold clock must read"),
        };
        if program(&mmio, &old, 617_143, VCO_8640_KHZ, Gen9Platform::Skylake)
            != Err(CdclkError::UnsupportedVco)
        {
            return TestResult::Fail("Skylake + VCO 8640 must refuse");
        }
        if !mmio.writes.borrow().is_empty() {
            return TestResult::Fail("refused VCO must write nothing");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_cdclk",
        smoke_skl_cdclk_vco_selection
    );

    fn smoke_skl_cdclk_readout() -> TestResult {
        // VCO 8100, FREQ_540: 540 MHz, voltage 2.
        let mmio = CdclkMmio::new();
        *mmio.pll_ctl.borrow_mut() = LCPLL_PLL_ENABLE;
        *mmio.ctrl1.borrow_mut() = ctrl1_override(0) | ctrl1_link_rate(LINK_RATE_810, 0);
        *mmio.cdclk_ctl.borrow_mut() = CDCLK_FREQ_540 | decimal(540_000);
        let cur = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("540 MHz clock must read"),
        };
        if cur.vco != VCO_8100_KHZ || cur.cdclk_khz != 540_000 {
            return TestResult::Fail("readout must decode 540 MHz at VCO 8100");
        }
        // VCO 8640, FREQ_675_617: 617143 kHz.
        let mmio = CdclkMmio::new();
        *mmio.pll_ctl.borrow_mut() = LCPLL_PLL_ENABLE;
        *mmio.ctrl1.borrow_mut() = ctrl1_override(0) | ctrl1_link_rate(LINK_RATE_1080, 0);
        *mmio.cdclk_ctl.borrow_mut() = CDCLK_FREQ_675_617 | decimal(617_143);
        let cur = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("617143 kHz clock must read"),
        };
        if cur.vco != VCO_8640_KHZ || cur.cdclk_khz != 617_143 {
            return TestResult::Fail("readout must decode 617143 kHz at VCO 8640");
        }
        // PLL off: VCO 0, CDCLK at the 24 MHz bypass.
        let mmio = CdclkMmio::new();
        let cur = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("PLL-off clock must read"),
        };
        if cur.vco != 0 || cur.cdclk_khz != REFCLK_KHZ {
            return TestResult::Fail("PLL-off clock must be bypass 24 MHz");
        }
        // PLL on but unlocked: VCO 0 (Linux's WARN-and-return).
        let mut mmio = CdclkMmio::new();
        mmio.grant_lock = false;
        *mmio.pll_ctl.borrow_mut() = LCPLL_PLL_ENABLE;
        let cur = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("unlocked clock must read"),
        };
        if cur.vco != 0 || cur.cdclk_khz != REFCLK_KHZ {
            return TestResult::Fail("unlocked PLL must read as bypass");
        }
        // CTRL1 with HDMI_MODE set: not a DPLL0 link rate.
        let mmio = CdclkMmio::new();
        *mmio.pll_ctl.borrow_mut() = LCPLL_PLL_ENABLE;
        *mmio.ctrl1.borrow_mut() =
            ctrl1_override(0) | ctrl1_hdmi_mode(0) | ctrl1_link_rate(LINK_RATE_810, 0);
        let cur = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("HDMI-mode ctrl1 must read"),
        };
        if cur.vco != 0 {
            return TestResult::Fail("HDMI-mode ctrl1 must not decode a VCO");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen9_cdclk", smoke_skl_cdclk_readout);

    fn smoke_skl_cdclk_program_from_cold() -> TestResult {
        let mmio = CdclkMmio::new();
        let old = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("cold clock must read"),
        };
        if program(&mmio, &old, 540_000, VCO_8100_KHZ, Gen9Platform::KabyLake).is_err() {
            return TestResult::Fail("cold program to 540 MHz must succeed");
        }
        let after = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("programmed clock must read"),
        };
        if !after.is_target(VCO_8100_KHZ, 540_000) {
            return TestResult::Fail("programmed clock must read back as the target");
        }
        // Pre-notify (DATA0 0x3) then post-notify (voltage 2):
        // two pcode mailbox writes.
        if mmio.writes_to(PCODE_MAILBOX).len() != 2 {
            return TestResult::Fail("program must send exactly pre + post pcode notifies");
        }
        let data0 = mmio.writes_to(PCODE_DATA0);
        if data0.len() != 2 || data0[0] != SKL_CDCLK_PREPARE_FOR_CHANGE || data0[1] != 2 {
            return TestResult::Fail("pcode DATA0 must carry pre 0x3 then voltage 2");
        }
        // DPLL0: CTRL1 OVERRIDE|810 once, LCPLL1_CTL ENABLE once.
        if mmio.writes_to(DPLL_CTRL1)
            != alloc::vec![ctrl1_override(0) | ctrl1_link_rate(LINK_RATE_810, 0)]
        {
            return TestResult::Fail("DPLL_CTRL1 must be programmed once to OVERRIDE|810");
        }
        if mmio.writes_to(LCPLL1_CTL) != alloc::vec![LCPLL_PLL_ENABLE] {
            return TestResult::Fail("LCPLL1_CTL must be enabled once");
        }
        // Wa #1183 CDCLK_CTL dance from a cold CTL (0):
        // freq|dec, +override, override-only, freq|dec+override,
        // freq|dec.
        let want = CDCLK_FREQ_540 | decimal(540_000);
        if mmio.writes_to(CDCLK_CTL)
            != alloc::vec![
                want,
                want | CDCLK_DIVMUX_CD_OVERRIDE,
                CDCLK_DIVMUX_CD_OVERRIDE,
                want | CDCLK_DIVMUX_CD_OVERRIDE,
                want,
            ]
        {
            return TestResult::Fail("CDCLK_CTL Wa #1183 dance wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_cdclk",
        smoke_skl_cdclk_program_from_cold
    );

    fn smoke_skl_cdclk_same_vco_skips_pll() -> TestResult {
        // 540 MHz @ VCO 8100 -> 337500 @ VCO 8100: same VCO, so
        // no DPLL0 disable/enable and no CTRL1 write; only the
        // CDCLK_CTL dance around the new freq + decimal.
        let mmio = CdclkMmio::new();
        *mmio.pll_ctl.borrow_mut() = LCPLL_PLL_ENABLE;
        *mmio.ctrl1.borrow_mut() = ctrl1_override(0) | ctrl1_link_rate(LINK_RATE_810, 0);
        let old_ctl = CDCLK_FREQ_540 | decimal(540_000);
        *mmio.cdclk_ctl.borrow_mut() = old_ctl;
        let old = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("540 MHz start must read"),
        };
        if !old.is_target(VCO_8100_KHZ, 540_000) {
            return TestResult::Fail("540 MHz start must classify as known");
        }
        if program(&mmio, &old, 337_500, VCO_8100_KHZ, Gen9Platform::KabyLake).is_err() {
            return TestResult::Fail("same-VCO change must succeed");
        }
        if !mmio.writes_to(LCPLL1_CTL).is_empty() || !mmio.writes_to(DPLL_CTRL1).is_empty() {
            return TestResult::Fail("same-VCO change must not touch DPLL0");
        }
        let want = CDCLK_FREQ_337_308 | decimal(337_500);
        if mmio.writes_to(CDCLK_CTL)
            != alloc::vec![
                old_ctl | CDCLK_DIVMUX_CD_OVERRIDE,
                CDCLK_DIVMUX_CD_OVERRIDE,
                want | CDCLK_DIVMUX_CD_OVERRIDE,
                want,
            ]
        {
            return TestResult::Fail("same-VCO change must only run the CTL dance");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_cdclk",
        smoke_skl_cdclk_same_vco_skips_pll
    );

    fn smoke_skl_cdclk_noop_at_target() -> TestResult {
        let mmio = CdclkMmio::new();
        *mmio.pll_ctl.borrow_mut() = LCPLL_PLL_ENABLE;
        *mmio.ctrl1.borrow_mut() = ctrl1_override(0) | ctrl1_link_rate(LINK_RATE_810, 0);
        *mmio.cdclk_ctl.borrow_mut() = CDCLK_FREQ_540 | decimal(540_000);
        let old = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("target clock must read"),
        };
        if program(&mmio, &old, 540_000, VCO_8100_KHZ, Gen9Platform::KabyLake).is_err() {
            return TestResult::Fail("program at target must succeed");
        }
        if !mmio.writes.borrow().is_empty() {
            return TestResult::Fail("program at target must write nothing, not even pcode");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_cdclk",
        smoke_skl_cdclk_noop_at_target
    );

    fn smoke_skl_cdclk_pcode_refusal_writes_nothing() -> TestResult {
        let mut mmio = CdclkMmio::new();
        mmio.pcode_status = 0x1;
        let old = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("cold clock must read"),
        };
        if program(&mmio, &old, 540_000, VCO_8100_KHZ, Gen9Platform::KabyLake)
            != Err(CdclkError::Pcode(PcodeError::Status(0x1)))
        {
            return TestResult::Fail("refused pre-notify must surface the pcode status");
        }
        if !mmio.writes_to(LCPLL1_CTL).is_empty()
            || !mmio.writes_to(CDCLK_CTL).is_empty()
            || !mmio.writes_to(DPLL_CTRL1).is_empty()
        {
            return TestResult::Fail("refused pre-notify must write no clock register");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_cdclk",
        smoke_skl_cdclk_pcode_refusal_writes_nothing
    );

    fn smoke_skl_cdclk_pcode_reply_not_ready() -> TestResult {
        // The transaction completes (status 0) but the punit never
        // sets READY_FOR_CHANGE in the reply DATA0.
        let mut mmio = CdclkMmio::new();
        mmio.grant_ready = false;
        let old = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("cold clock must read"),
        };
        if program(&mmio, &old, 540_000, VCO_8100_KHZ, Gen9Platform::KabyLake)
            != Err(CdclkError::PcodeNotReady)
        {
            return TestResult::Fail("a reply without the ready bit must fail as PcodeNotReady");
        }
        if !mmio.writes_to(LCPLL1_CTL).is_empty() || !mmio.writes_to(CDCLK_CTL).is_empty() {
            return TestResult::Fail("unready pre-notify must write no clock register");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_cdclk",
        smoke_skl_cdclk_pcode_reply_not_ready
    );

    fn smoke_skl_cdclk_pll_lock_timeout() -> TestResult {
        let mut mmio = CdclkMmio::new();
        mmio.grant_lock = false;
        let old = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("cold clock must read"),
        };
        if program(&mmio, &old, 540_000, VCO_8100_KHZ, Gen9Platform::KabyLake)
            != Err(CdclkError::Timeout)
        {
            return TestResult::Fail("a DPLL0 that never locks must time out");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_cdclk",
        smoke_skl_cdclk_pll_lock_timeout
    );
}

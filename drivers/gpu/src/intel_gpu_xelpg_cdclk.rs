//! Display-14.00 (Meteor/Arrow Lake) CDCLK computation and change sequence.
//!
//! MIT Linux b90c984d `display/intel_cdclk.c`:
//! - table/frequency: `mtl_cdclk_table`, `bxt_calc_cdclk`,
//!   `bxt_calc_cdclk_pll_vco`, `rplu_calc_voltage_level` (MTL uses
//!   `rplu_cdclk_funcs`), `intel_update_max_cdclk` (652.8 MHz at 38.4 MHz);
//! - minimum: `intel_crtc_min_cdclk`, `intel_pixel_rate_to_cdclk` (two
//!   pixels per clock, 100% guardband), `intel_compute_min_cdclk`,
//!   `bxt_compute_min_voltage_level` with `intel_ddi.c::
//!   icl_ddi_min_voltage_level` (display >= 14);
//! - readout: `bxt_get_cdclk` (decode lives in
//!   `intel_gpu_modeset_xelpg::cdclk_current_khz`) and `bxt_sanitize_cdclk`,
//!   whose "unknown" result forces a full PLL disable/enable;
//! - change: `bxt_set_cdclk` (no PCODE mailbox on display >= 14; PM demand
//!   carries voltage/frequency), `cdclk_compute_crawl_and_squash_midpoint`,
//!   `_bxt_set_cdclk`, `adlp_cdclk_pll_crawl`, `icl_cdclk_pll_update`,
//!   `dg2_cdclk_squash_program`, `pll_enable_wa_needed`
//!   (wa_15010685871, display 14.00) and `bxt_cdclk_ctl`.
//!
//! Display 20 (Xe2_LPD) dispatches through the `_ip` variants: its
//! `xe2lpd_cdclk_table` and `bxt_cdclk_ctl`'s MDCLK source select replace
//! the 14.00 table and decimal field; the change sequence is shared
//! (`pll_enable_wa_needed` covers 14.00 and 20.00; Wa_13012396614 is
//! 30.00 only).
//!
//! Display 30.00 (Xe3_LPD) dispatches the same way on
//! `xe3lpd_cdclk_table` (squashed rungs at ratio 16, crawl-only rungs up to
//! 691.2 MHz, `xe3lpd_cdclk_funcs`): `bxt_cdclk_ctl` writes no CD2X pipe
//! field and keeps `BXT_CDCLK_CD2X_DIV_SEL_1`, `xe3lpd_calc_voltage_level`
//! is 0, `intel_update_max_cdclk` raises the ceiling to 691.2 MHz,
//! wa_15010685871 (`pll_enable_wa_needed`) does not apply and
//! Wa_13012396614 (`icl_cdclk_pll_disable`) selects CD2XCLK as the MDCLK
//! source before the PLL is disabled.
//!
//! The owned transaction changes CDCLK only with every pipe off
//! (`disable_pipes`, `pipe = INVALID_PIPE`), so the CD2X pipe field is
//! always `TGL_CDCLK_CD2X_PIPE_NONE` and both raising and lowering happen in
//! one step before any plane is enabled.

use alloc::vec::Vec;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_xe2lpd::DisplayIp;

/// `CDCLK_CTL`.
pub(crate) const CDCLK_CTL: u64 = 0x46000;
/// `CDCLK_SQUASH_CTL`.
pub(crate) const CDCLK_SQUASH_CTL: u64 = 0x46008;
/// `BXT_DE_PLL_ENABLE` (CDCLK PLL control on every BXT+ platform).
pub(crate) const DE_PLL_ENABLE: u64 = 0x46070;
const PLL_ENABLE: u32 = 1 << 31;
const PLL_LOCK: u32 = 1 << 30;
const PLL_FREQ_REQ: u32 = 1 << 23;
const PLL_FREQ_REQ_ACK: u32 = 1 << 22;
const PLL_RATIO_MASK: u32 = 0xff;
const SQUASH_ENABLE: u32 = 1 << 31;
const SQUASH_WINDOW_15: u32 = 0xf << 24;
/// `BXT_CDCLK_CD2X_DIV_SEL_MASK`; every MTL rung uses DIV_SEL_1 (0).
const CD2X_DIV_SEL_MASK: u32 = 3 << 22;
/// `TGL_CDCLK_CD2X_PIPE_NONE` (= `ICL_CDCLK_CD2X_PIPE_NONE`, 7 << 19).
const CD2X_PIPE_NONE: u32 = 7 << 19;
/// `bxt_cdclk_cd2x_pipe(INVALID_PIPE)` mask ignored by `bxt_sanitize_cdclk`.
const CD2X_PIPE_MASK: u32 = 7 << 19;
const DECIMAL_MASK: u32 = 0x7ff;

/// MTL CDCLK reference (`display->cdclk.hw.ref`, the only refclk the
/// `mtl_cdclk_table` is published against).
pub(crate) const REF_KHZ: u32 = 38_400;
/// `intel_update_max_cdclk`, display >= 11 at a 38.4 MHz reference.
pub(crate) const MAX_CDCLK_KHZ: u32 = 652_800;

/// One `mtl_cdclk_table` rung.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Rung {
    pub(crate) cdclk_khz: u32,
    pub(crate) ratio: u32,
    pub(crate) waveform: u16,
}

pub(crate) const TABLE: [Rung; 6] = [
    Rung {
        cdclk_khz: 172_800,
        ratio: 16,
        waveform: 0xad5a,
    },
    Rung {
        cdclk_khz: 192_000,
        ratio: 16,
        waveform: 0xb6b6,
    },
    Rung {
        cdclk_khz: 307_200,
        ratio: 16,
        waveform: 0,
    },
    Rung {
        cdclk_khz: 480_000,
        ratio: 25,
        waveform: 0,
    },
    Rung {
        cdclk_khz: 556_800,
        ratio: 29,
        waveform: 0,
    },
    Rung {
        cdclk_khz: 652_800,
        ratio: 34,
        waveform: 0,
    },
];

/// `bxt_calc_cdclk`: the first rung at or above `min_khz`. Linux WARNs and
/// clamps past the table; the owned transaction refuses instead.
pub(crate) fn calc_cdclk(min_khz: u32) -> Option<Rung> {
    TABLE.iter().copied().find(|r| r.cdclk_khz >= min_khz)
}

fn rung(cdclk_khz: u32) -> Option<Rung> {
    TABLE.iter().copied().find(|r| r.cdclk_khz == cdclk_khz)
}

/// `intel_init_cdclk_hooks`' table for `ip`: `mtl_cdclk_table` on 14.00,
/// `xe2lpd_cdclk_table` on display 20 (both `rplu_cdclk_funcs`).
pub(crate) fn table(ip: DisplayIp) -> &'static [Rung] {
    match ip {
        DisplayIp::Xelpdp => &TABLE,
        DisplayIp::Xe2Lpd => &crate::intel_gpu_xe2lpd::CDCLK_TABLE,
        DisplayIp::Xe3Lpd => &crate::intel_gpu_xe3lpd::CDCLK_TABLE,
    }
}

/// `intel_update_max_cdclk` for `ip` at the 38.4 MHz reference.
pub(crate) const fn max_cdclk_khz(ip: DisplayIp) -> u32 {
    match ip {
        DisplayIp::Xelpdp | DisplayIp::Xe2Lpd => MAX_CDCLK_KHZ,
        DisplayIp::Xe3Lpd => crate::intel_gpu_xe3lpd::MAX_CDCLK_KHZ,
    }
}

/// `display->funcs.cdclk->calc_voltage_level` for `ip`:
/// `rplu_calc_voltage_level` on 14.00 and 20.00,
/// `xe3lpd_calc_voltage_level` (always 0) on 30.00.
pub(crate) fn voltage_level_ip(ip: DisplayIp, cdclk_khz: u32) -> u8 {
    match ip {
        DisplayIp::Xelpdp | DisplayIp::Xe2Lpd => voltage_level(cdclk_khz),
        DisplayIp::Xe3Lpd => 0,
    }
}

/// `pll_enable_wa_needed` (wa_15010685871): display 14.00, 20.00 and DG2.
const fn pll_enable_wa_needed(ip: DisplayIp) -> bool {
    matches!(ip, DisplayIp::Xelpdp | DisplayIp::Xe2Lpd)
}

/// [`calc_cdclk`] over `ip`'s table.
pub(crate) fn calc_cdclk_ip(ip: DisplayIp, min_khz: u32) -> Option<Rung> {
    table(ip).iter().copied().find(|r| r.cdclk_khz >= min_khz)
}

fn rung_ip(ip: DisplayIp, cdclk_khz: u32) -> Option<Rung> {
    match ip {
        DisplayIp::Xelpdp => rung(cdclk_khz),
        DisplayIp::Xe2Lpd | DisplayIp::Xe3Lpd => {
            table(ip).iter().copied().find(|r| r.cdclk_khz == cdclk_khz)
        }
    }
}

/// `rplu_calc_voltage_level` (`rplu_voltage_level_max_cdclk`).
pub(crate) fn voltage_level(cdclk_khz: u32) -> u8 {
    match cdclk_khz {
        0..=312_000 => 0,
        312_001..=480_000 => 1,
        480_001..=556_800 => 2,
        _ => 3,
    }
}

/// `icl_ddi_min_voltage_level` (display >= 14 branch of
/// `intel_ddi_compute_min_voltage_level`).
pub(crate) fn port_min_voltage_level(port_clock_khz: u32) -> u8 {
    u8::from(port_clock_khz > 594_000)
}

/// `_intel_pixel_rate_to_cdclk` for display >= 10: ppc 2, guardband 100.
pub(crate) fn pixel_rate_to_cdclk(pixel_rate_khz: u32) -> u32 {
    pixel_rate_khz.div_ceil(2)
}

/// `skl_cdclk_decimal`: DIV_ROUND_CLOSEST(cdclk - 1000, 500).
fn decimal(cdclk_khz: u32) -> u32 {
    ((cdclk_khz - 1000 + 250) / 500) & DECIMAL_MASK
}

/// `bxt_cdclk_ctl(display, config, INVALID_PIPE)` for display 14.
pub(crate) fn ctl_value(target: Rung) -> u32 {
    CD2X_PIPE_NONE | decimal(target.cdclk_khz)
}

/// `bxt_cdclk_ctl(display, config, INVALID_PIPE)` for `ip`: display >= 20
/// selects the MDCLK source (the CDCLK PLL) instead of the decimal field;
/// display >= 30 writes no CD2X pipe field.
pub(crate) fn ctl_value_ip(ip: DisplayIp, target: Rung) -> u32 {
    match ip {
        DisplayIp::Xelpdp => ctl_value(target),
        DisplayIp::Xe2Lpd => CD2X_PIPE_NONE | crate::intel_gpu_xe2lpd::MDCLK_SOURCE_SEL_CDCLK_PLL,
        DisplayIp::Xe3Lpd => crate::intel_gpu_xe2lpd::MDCLK_SOURCE_SEL_CDCLK_PLL,
    }
}

/// `dg2_cdclk_squash_program`.
pub(crate) fn squash_value(waveform: u16) -> u32 {
    if waveform == 0 {
        0
    } else {
        SQUASH_ENABLE | SQUASH_WINDOW_15 | u32::from(waveform)
    }
}

/// Hardware CDCLK configuration as `bxt_get_cdclk` + `bxt_sanitize_cdclk`
/// classify it. `known == None` is Linux's `vco = ~0`: a full PLL
/// disable/enable is mandatory, crawl/squash shortcuts are not allowed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Current {
    pub(crate) known: Option<Rung>,
    /// Raw registers retained for restoration of the original clock.
    pub(crate) pll: u32,
    pub(crate) squash: u32,
    pub(crate) ctl: u32,
    /// Decoded actual frequency (0 with the PLL off).
    pub(crate) actual_khz: u32,
}

/// Typed CDCLK refusals and failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CdclkError {
    /// Current access was lost or a register read all-ones.
    NoDevice,
    /// The PLL is enabled but reports no lock; nothing can be trusted.
    Unlocked,
    /// A lock/unlock/frequency-request acknowledgement did not arrive.
    Timeout,
    /// A written value did not read back.
    Readback,
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
    pub(crate) fn read(io: &(impl MmioWindow + ?Sized)) -> Result<Self, CdclkError> {
        Self::read_ip(io, DisplayIp::Xelpdp)
    }

    /// [`Current::read`] sanitized against `ip`'s table and CTL encoding.
    pub(crate) fn read_ip(
        io: &(impl MmioWindow + ?Sized),
        ip: DisplayIp,
    ) -> Result<Self, CdclkError> {
        let pll = read(io, DE_PLL_ENABLE)?;
        let squash = read(io, CDCLK_SQUASH_CTL)?;
        let ctl = read(io, CDCLK_CTL)?;
        if pll & PLL_ENABLE != 0 && pll & PLL_LOCK == 0 {
            return Err(CdclkError::Unlocked);
        }
        let actual_khz = crate::intel_gpu_modeset_xelpg::cdclk_current_khz(io);
        if !io.display_access_ok() {
            return Err(CdclkError::NoDevice);
        }
        // bxt_sanitize_cdclk: PLL off, a rate outside the table, a VCO that
        // is not the table's, or a CTL other than bxt_cdclk_ctl (ignoring the
        // CD2X pipe field) are all "unknown".
        let known = rung_ip(ip, actual_khz).filter(|r| {
            pll & PLL_ENABLE != 0
                && pll & PLL_RATIO_MASK == r.ratio
                && ctl & !CD2X_PIPE_MASK == ctl_value_ip(ip, *r) & !CD2X_PIPE_MASK
                && ctl & CD2X_DIV_SEL_MASK == 0
        });
        Ok(Self {
            known,
            pll,
            squash,
            ctl,
            actual_khz,
        })
    }
}

/// One register-level step of a CDCLK change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Step {
    /// `adlp_cdclk_pll_crawl` to `ratio`.
    Crawl { ratio: u32 },
    /// wa_15010685871: squash off before the PLL is touched.
    SquashOff,
    /// Wa_13012396614 (display 30.00): `CDCLK_CTL` MDCLK source to
    /// CD2XCLK before the PLL is disabled.
    MdclkCd2x,
    /// `icl_cdclk_pll_disable`.
    PllDisable,
    /// `icl_cdclk_pll_enable` at `ratio`.
    PllEnable { ratio: u32 },
    /// `dg2_cdclk_squash_program`.
    Squash { waveform: u16 },
    /// `CDCLK_CTL` = `bxt_cdclk_ctl(.., INVALID_PIPE)`.
    Ctl { value: u32 },
}

fn squash_divider(waveform: u16) -> u32 {
    // cdclk_squash_divider: hweight16(waveform ?: 0xffff).
    if waveform == 0 {
        16
    } else {
        waveform.count_ones()
    }
}

/// `_bxt_set_cdclk` for one configuration, from hardware state `hw`.
fn set_steps(ip: DisplayIp, hw: Option<Rung>, cfg: Rung, steps: &mut Vec<Step>) {
    match hw {
        // HAS_CDCLK_CRAWL && hw.vco > 0 && vco > 0 && !unknown.
        Some(old) => {
            if old.ratio != cfg.ratio {
                steps.push(Step::Crawl { ratio: cfg.ratio });
            }
        }
        None => {
            // pll_enable_wa_needed: display 14.00 && hw.vco > 0 (~0 counts).
            if pll_enable_wa_needed(ip) {
                steps.push(Step::SquashOff);
            }
            // icl_cdclk_pll_update: hw.vco (~0) != 0 && != vco;
            // icl_cdclk_pll_disable takes Wa_13012396614 first.
            if ip == DisplayIp::Xe3Lpd {
                steps.push(Step::MdclkCd2x);
            }
            steps.push(Step::PllDisable);
            steps.push(Step::PllEnable { ratio: cfg.ratio });
        }
    }
    steps.push(Step::Squash {
        waveform: cfg.waveform,
    });
    steps.push(Step::Ctl {
        value: ctl_value_ip(ip, cfg),
    });
}

/// `bxt_set_cdclk` plan from `old` to `target`, including the
/// `cdclk_compute_crawl_and_squash_midpoint` intermediate. Empty when the
/// known hardware configuration already equals the target.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn plan(old: &Current, target: Rung) -> Vec<Step> {
    plan_ip(DisplayIp::Xelpdp, old, target)
}

/// [`plan`] over `ip`'s table and CTL encoding.
pub(crate) fn plan_ip(ip: DisplayIp, old: &Current, target: Rung) -> Vec<Step> {
    let mut steps = Vec::new();
    match old.known {
        Some(hw) if hw == target => {}
        Some(hw) => {
            // intel_cdclk_can_crawl_and_squash / midpoint: VCOs and
            // waveforms both differ (MTL's cd2x divider is fixed at 2).
            if hw.ratio != target.ratio && hw.waveform != target.waveform {
                let (ratio, waveform) =
                    if squash_divider(target.waveform) > squash_divider(hw.waveform) {
                        // Raising: squash first at the old VCO.
                        (hw.ratio, target.waveform)
                    } else {
                        // Lowering: crawl first with the old waveform.
                        (target.ratio, hw.waveform)
                    };
                let vco = ratio * REF_KHZ;
                let mid_khz = (squash_divider(waveform) * vco + 16) / 32;
                // A sane midpoint is itself a table rung with that waveform.
                let mid = Rung {
                    cdclk_khz: mid_khz,
                    ratio,
                    waveform,
                };
                if rung_ip(ip, mid_khz) == Some(mid) {
                    set_steps(ip, Some(hw), mid, &mut steps);
                    set_steps(ip, Some(mid), target, &mut steps);
                    return steps;
                }
            }
            set_steps(ip, Some(hw), target, &mut steps);
        }
        None => set_steps(ip, None, target, &mut steps),
    }
    steps
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

// Linux waits 1 ms (intel_de_wait_for_*_ms(.., 1)) for lock, unlock and the
// frequency-request ACK.
const PLL_WAIT_US: u64 = 1_000;

fn execute(io: &(impl MmioWindow + ?Sized), step: Step) -> Result<(), CdclkError> {
    match step {
        Step::Crawl { ratio } => {
            let value = ratio | PLL_ENABLE;
            io.write32(DE_PLL_ENABLE, value);
            io.write32(DE_PLL_ENABLE, value | PLL_FREQ_REQ);
            wait(
                io,
                DE_PLL_ENABLE,
                PLL_LOCK | PLL_FREQ_REQ_ACK,
                PLL_LOCK | PLL_FREQ_REQ_ACK,
                PLL_WAIT_US,
            )?;
            io.write32(DE_PLL_ENABLE, value);
        }
        Step::SquashOff => io.write32(CDCLK_SQUASH_CTL, 0),
        Step::MdclkCd2x => {
            // intel_de_rmw(CDCLK_CTL, MDCLK_SOURCE_SEL_MASK,
            // MDCLK_SOURCE_SEL_CD2XCLK).
            let ctl = read(io, CDCLK_CTL)?;
            io.write32(
                CDCLK_CTL,
                ctl & !crate::intel_gpu_xe2lpd::MDCLK_SOURCE_SEL_CDCLK_PLL,
            );
        }
        Step::PllDisable => {
            // intel_de_rmw(BXT_DE_PLL_ENABLE, PLL_ENABLE, 0); LOCK and
            // FREQ_REQ_ACK are read-only status and are not written back.
            let pll = read(io, DE_PLL_ENABLE)?;
            io.write32(
                DE_PLL_ENABLE,
                pll & !(PLL_ENABLE | PLL_LOCK | PLL_FREQ_REQ_ACK),
            );
            wait(io, DE_PLL_ENABLE, PLL_LOCK, 0, PLL_WAIT_US)?;
        }
        Step::PllEnable { ratio } => {
            io.write32(DE_PLL_ENABLE, ratio);
            io.write32(DE_PLL_ENABLE, ratio | PLL_ENABLE);
            wait(io, DE_PLL_ENABLE, PLL_LOCK, PLL_LOCK, PLL_WAIT_US)?;
        }
        Step::Squash { waveform } => io.write32(CDCLK_SQUASH_CTL, squash_value(waveform)),
        Step::Ctl { value } => io.write32(CDCLK_CTL, value),
    }
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(CdclkError::NoDevice)
    }
}

/// Program `target` from `old` and prove the result by readback: the PLL is
/// enabled, locked and at the rung's ratio, squash and CTL hold the exact
/// source values and the decoded rate equals the rung.
pub(crate) fn program(
    io: &(impl MmioWindow + ?Sized),
    old: &Current,
    target: Rung,
) -> Result<(), CdclkError> {
    program_ip(io, DisplayIp::Xelpdp, old, target)
}

/// [`program`] over `ip`'s table and CTL encoding.
pub(crate) fn program_ip(
    io: &(impl MmioWindow + ?Sized),
    ip: DisplayIp,
    old: &Current,
    target: Rung,
) -> Result<(), CdclkError> {
    for step in plan_ip(ip, old, target) {
        execute(io, step)?;
    }
    let pll = read(io, DE_PLL_ENABLE)?;
    if pll & (PLL_ENABLE | PLL_LOCK | PLL_FREQ_REQ | PLL_RATIO_MASK)
        != PLL_ENABLE | PLL_LOCK | target.ratio
        || read(io, CDCLK_SQUASH_CTL)? != squash_value(target.waveform)
        // An unchanged known clock keeps its firmware CD2X pipe field.
        || read(io, CDCLK_CTL)? & !CD2X_PIPE_MASK != ctl_value_ip(ip, target) & !CD2X_PIPE_MASK
        || crate::intel_gpu_modeset_xelpg::cdclk_current_khz(io) != target.cdclk_khz
    {
        return Err(CdclkError::Readback);
    }
    Ok(())
}

/// Restore the exact original registers after a failed transaction. A
/// known original rung uses the normal source change sequence; an unknown
/// one is re-established through the full disable/enable path with its raw
/// squash/CTL values (an originally-off PLL stays off).
pub(crate) fn restore(
    io: &(impl MmioWindow + ?Sized),
    original: &Current,
) -> Result<(), CdclkError> {
    restore_ip(io, DisplayIp::Xelpdp, original)
}

/// [`restore`] over `ip`'s table and CTL encoding.
pub(crate) fn restore_ip(
    io: &(impl MmioWindow + ?Sized),
    ip: DisplayIp,
    original: &Current,
) -> Result<(), CdclkError> {
    let now = Current::read_ip(io, ip)?;
    if let Some(rung) = original.known {
        if now.known != Some(rung) || now.ctl != original.ctl {
            program_ip(io, ip, &now, rung)?;
            io.write32(CDCLK_CTL, original.ctl);
        }
    } else if now.pll != original.pll || now.squash != original.squash || now.ctl != original.ctl {
        if pll_enable_wa_needed(ip) {
            execute(io, Step::SquashOff)?;
        }
        if ip == DisplayIp::Xe3Lpd {
            execute(io, Step::MdclkCd2x)?;
        }
        execute(io, Step::PllDisable)?;
        if original.pll & PLL_ENABLE != 0 {
            execute(
                io,
                Step::PllEnable {
                    ratio: original.pll & PLL_RATIO_MASK,
                },
            )?;
        } else {
            io.write32(
                DE_PLL_ENABLE,
                original.pll & !(PLL_ENABLE | PLL_LOCK | PLL_FREQ_REQ_ACK),
            );
        }
        io.write32(CDCLK_SQUASH_CTL, original.squash);
        io.write32(CDCLK_CTL, original.ctl);
    }
    let after = Current::read_ip(io, ip)?;
    if after.pll & (PLL_ENABLE | PLL_RATIO_MASK) != original.pll & (PLL_ENABLE | PLL_RATIO_MASK)
        || after.squash != original.squash
        || after.ctl != original.ctl
    {
        return Err(CdclkError::Readback);
    }
    Ok(())
}

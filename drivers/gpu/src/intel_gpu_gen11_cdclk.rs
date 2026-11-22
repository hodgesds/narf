//! Gen11 (Ice Lake / Elkhart Lake / Jasper Lake) CDCLK computation and
//! change sequence.
//!
//! Mirrors Linux `display/intel_cdclk.c` (7.4-rc2, `icl_cdclk_funcs` for
//! Ice Lake, `ehl_cdclk_funcs` for Elkhart/Jasper Lake):
//! - table: `icl_cdclk_table` (both funcs use it), selected by the DSSM
//!   reference strap (`icl_readout_refclk`); `bxt_calc_cdclk` (first rung
//!   at or above the minimum), `bxt_calc_cdclk_pll_vco` (VCO = refclk *
//!   ratio);
//! - voltage level: `icl_calc_voltage_level` (3 levels:
//!   312000 / 556800 / 652800) and `ehl_calc_voltage_level` (4 levels:
//!   180000 / 312000 / 326400 / 652800 — the bspec lists the EHL limit
//!   as 556.8 MHz, but some JSL development boards boot with 652.8 MHz,
//!   hence the top rung);
//! - readout: `bxt_get_cdclk` / `bxt_de_pll_readout` (ratio lives in
//!   `BXT_DE_PLL_ENABLE` bits 7:0 on DISPLAY_VER >= 11, VCO = ratio *
//!   refclk, CDCLK = VCO / CD2X divider) and `bxt_sanitize_cdclk`;
//! - change: `intel_cdclk_set_cdclk` — `skl_cdclk_pcode_pre_notify` /
//!   `skl_cdclk_pcode_post_notify` (`SKL_PCODE_CDCLK_CONTROL` 0x7,
//!   pre DATA0 `SKL_CDCLK_PREPARE_FOR_CHANGE` 0x3 with the reply
//!   checked for `SKL_CDCLK_READY_FOR_CHANGE` 0x1, post DATA0 = the
//!   voltage level; a failed pre-notify aborts before any register
//!   write) around `_bxt_set_cdclk` (`icl_cdclk_pll_update`,
//!   `bxt_cdclk_ctl`);
//! - `bxt_cdclk_ctl`: CD2X divider select + CD2X pipe field +
//!   `skl_cdclk_decimal`. No crawl and no squash on ICL: neither
//!   `has_cdclk_crawl` nor `has_cdclk_squash` is set on the ICL
//!   display descriptor (`display/intel_display_device.c` — crawl
//!   is ADL-P/Xe-LPD only, squash is ADL-S/Xe-HPD and later), so a
//!   VCO change is always a full disable/enable
//!   (`icl_cdclk_pll_update`); the MDCLK-source workaround
//!   (`Wa_13012396614`, `icl_cdclk_pll_disable`) is DISPLAY_VER >= 20
//!   only and does not apply here.
//!
//! The 18 table rungs are the same values as
//! `intel_gpu_gen12_cdclk::TABLE` — TGL uses the ICL table
//! (`display/intel_cdclk.c`, `tgl_cdclk_funcs` takes
//! `icl_cdclk_table`). They are transcribed again here so each
//! generation's module is self-contained and independently
//! fixture-pinned; the Gen11 deltas are the voltage levels and
//! the SKL pcode notify protocol, not the ladder.
//!
//! The modeset raises CDCLK only (a faster firmware clock is left alone),
//! with every pipe off when the change runs, so the CD2X pipe field is
//! always `ICL_CDCLK_CD2X_PIPE_NONE` (7 << 19), as in
//! `intel_gpu_gen12_cdclk`.

use alloc::vec::Vec;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gt::Gen11Platform;
use crate::intel_gpu_pcode::{pcode_read, pcode_write, PcodeError};
use crate::intel_gpu_pcode::{
    PCODE_CMD_CDCLK_CONTROL, SKL_CDCLK_PREPARE_FOR_CHANGE, SKL_CDCLK_READY_FOR_CHANGE,
};
use crate::intel_gpu_pll::refclk_khz;

/// `CDCLK_CTL`.
pub const CDCLK_CTL: u64 = 0x46000;
/// `BXT_DE_PLL_ENABLE` (CDCLK PLL control on every BXT+ platform).
pub const DE_PLL_ENABLE: u64 = 0x46070;
/// `SKL_DSSM` — reference-clock strap (`icl_readout_refclk`).
const DSSM: u64 = 0x51004;
/// `BXT_DE_PLL_ENABLE.ENABLE` (bit 31).
pub const PLL_ENABLE: u32 = 1 << 31;
/// `BXT_DE_PLL_ENABLE.LOCK` (bit 30).
pub const PLL_LOCK: u32 = 1 << 30;
const PLL_RATIO_MASK: u32 = 0xff;
/// `ICL_CDCLK_CD2X_PIPE_NONE` (7 << 19).
const CD2X_PIPE_NONE: u32 = 7 << 19;
/// `bxt_cdclk_cd2x_pipe(INVALID_PIPE)` mask ignored by `bxt_sanitize_cdclk`.
const CD2X_PIPE_MASK: u32 = 7 << 19;
const DECIMAL_MASK: u32 = 0x7ff;

/// One `icl_cdclk_table` rung: the reference it is published against,
/// the CDCLK it yields, and the DE PLL ratio that produces its VCO
/// (`bxt_calc_cdclk_pll_vco`: VCO = refclk * ratio).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rung {
    pub refclk_khz: u32,
    pub cdclk_khz: u32,
    pub ratio: u32,
}

/// `icl_cdclk_table` (`display/intel_cdclk.c`), transcribed verbatim:
/// six rungs per reference (19.2 / 24.0 / 38.4 MHz). The waveform field
/// is 0 on every ICL row, so no squash programming applies.
pub const TABLE: [Rung; 18] = [
    Rung {
        refclk_khz: 19_200,
        cdclk_khz: 172_800,
        ratio: 18,
    },
    Rung {
        refclk_khz: 19_200,
        cdclk_khz: 192_000,
        ratio: 20,
    },
    Rung {
        refclk_khz: 19_200,
        cdclk_khz: 307_200,
        ratio: 32,
    },
    Rung {
        refclk_khz: 19_200,
        cdclk_khz: 326_400,
        ratio: 68,
    },
    Rung {
        refclk_khz: 19_200,
        cdclk_khz: 556_800,
        ratio: 58,
    },
    Rung {
        refclk_khz: 19_200,
        cdclk_khz: 652_800,
        ratio: 68,
    },
    Rung {
        refclk_khz: 24_000,
        cdclk_khz: 180_000,
        ratio: 15,
    },
    Rung {
        refclk_khz: 24_000,
        cdclk_khz: 192_000,
        ratio: 16,
    },
    Rung {
        refclk_khz: 24_000,
        cdclk_khz: 312_000,
        ratio: 26,
    },
    Rung {
        refclk_khz: 24_000,
        cdclk_khz: 324_000,
        ratio: 54,
    },
    Rung {
        refclk_khz: 24_000,
        cdclk_khz: 552_000,
        ratio: 46,
    },
    Rung {
        refclk_khz: 24_000,
        cdclk_khz: 648_000,
        ratio: 54,
    },
    Rung {
        refclk_khz: 38_400,
        cdclk_khz: 172_800,
        ratio: 9,
    },
    Rung {
        refclk_khz: 38_400,
        cdclk_khz: 192_000,
        ratio: 10,
    },
    Rung {
        refclk_khz: 38_400,
        cdclk_khz: 307_200,
        ratio: 16,
    },
    Rung {
        refclk_khz: 38_400,
        cdclk_khz: 326_400,
        ratio: 34,
    },
    Rung {
        refclk_khz: 38_400,
        cdclk_khz: 556_800,
        ratio: 29,
    },
    Rung {
        refclk_khz: 38_400,
        cdclk_khz: 652_800,
        ratio: 34,
    },
];

/// `bxt_calc_cdclk`: the first rung at `refclk_khz` at or above
/// `min_khz`. Linux WARNs and clamps past the table; the modeset
/// refuses instead (leaves the firmware clock alone).
pub fn calc_cdclk(refclk_khz: u32, min_khz: u32) -> Option<Rung> {
    TABLE
        .iter()
        .copied()
        .find(|r| r.refclk_khz == refclk_khz && r.cdclk_khz >= min_khz)
}

/// Voltage level for a CDCLK, by Gen11 product
/// (`icl_calc_voltage_level` for Ice Lake,
/// `ehl_calc_voltage_level` for Elkhart/Jasper Lake — both via
/// `calc_voltage_level`, first level whose max covers the clock,
/// clamped to the top level past the table).
pub fn voltage_level(platform: Gen11Platform, cdclk_khz: u32) -> u8 {
    let maxima: &[u32] = match platform {
        Gen11Platform::IceLake => &[312_000, 556_800, 652_800],
        Gen11Platform::ElkhartLake | Gen11Platform::JasperLake => {
            &[180_000, 312_000, 326_400, 652_800]
        }
    };
    for (level, &max) in maxima.iter().enumerate() {
        if cdclk_khz <= max {
            return level as u8;
        }
    }
    (maxima.len() - 1) as u8
}

/// `skl_cdclk_decimal`: DIV_ROUND_CLOSEST(cdclk - 1000, 500).
fn decimal(cdclk_khz: u32) -> u32 {
    ((cdclk_khz - 1000 + 250) / 500) & DECIMAL_MASK
}

/// `bxt_cdclk_cd2x_div_sel` for a rung: the CD2X divider is
/// VCO / CDCLK (`cdclk_divider` with a zero waveform), mapped to the
/// field value (2 -> DIV_SEL_1, 3 -> 1_5, 4 -> 2, 8 -> 4). `None`
/// when the rung's VCO/CDCLK ratio is not a programmed divider —
/// every `TABLE` rung divides by 2 or 4.
fn div_sel(rung: Rung) -> Option<u32> {
    let vco = rung.ratio * rung.refclk_khz;
    let div = (vco + rung.cdclk_khz / 2) / rung.cdclk_khz;
    match div {
        2 => Some(0),
        3 => Some(1 << 22),
        4 => Some(2 << 22),
        8 => Some(3 << 22),
        _ => None,
    }
}

/// `bxt_cdclk_ctl(display, config, INVALID_PIPE)` for a rung:
/// CD2X divider select + CD2X pipe none + decimal. `None` when the
/// rung has no programmed divider (see [`div_sel`]).
pub fn ctl_value(rung: Rung) -> Option<u32> {
    div_sel(rung).map(|sel| sel | CD2X_PIPE_NONE | decimal(rung.cdclk_khz))
}

/// Hardware CDCLK configuration as `bxt_get_cdclk` + `bxt_sanitize_cdclk`
/// classify it. `known == None` is Linux's "unknown" state: the PLL is
/// off, the rate is outside the table, the VCO is not the table's, or
/// the CTL is not `bxt_cdclk_ctl` — a full PLL disable/enable is
/// mandatory and the current clock must not be trusted as a floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Current {
    pub known: Option<Rung>,
    /// Raw registers retained for the readback proof.
    pub pll: u32,
    pub ctl: u32,
    /// Reference strap in kHz (`icl_readout_refclk` via DSSM).
    pub refclk_khz: u32,
    /// Decoded actual frequency (0 with the PLL off).
    pub actual_khz: u32,
}

/// Typed CDCLK refusals and failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CdclkError {
    /// Current access was lost or a register read all-ones.
    NoDevice,
    /// The PLL is enabled but reports no lock; nothing can be trusted.
    Unlocked,
    /// A lock/unlock did not arrive inside the 1 ms window.
    Timeout,
    /// A written value did not read back.
    Readback,
    /// A pcode transaction was refused or timed out.
    Pcode(PcodeError),
    /// The pcode pre-notify completed but the punit never set
    /// `SKL_CDCLK_READY_FOR_CHANGE` in the reply DATA0.
    PcodeNotReady,
}

fn read(io: &(impl MmioWindow + ?Sized), r: u64) -> Result<u32, CdclkError> {
    let value = io.read32(r);
    if value == u32::MAX || !io.display_access_ok() {
        Err(CdclkError::NoDevice)
    } else {
        Ok(value)
    }
}

/// `bxt_get_cdclk` for a known reference: VCO = ratio * refclk, CDCLK =
/// VCO / CD2X divider (CDCLK_CTL bits 23:22 select 2/3/4/8). Returns 0
/// with the PLL off or unlocked.
pub fn current_khz(io: &(impl MmioWindow + ?Sized), refclk_khz: u32) -> Result<u32, CdclkError> {
    let pll = read(io, DE_PLL_ENABLE)?;
    if pll & (PLL_ENABLE | PLL_LOCK) != PLL_ENABLE | PLL_LOCK {
        return Ok(0);
    }
    let vco = (pll & PLL_RATIO_MASK) * refclk_khz;
    let ctl = read(io, CDCLK_CTL)?;
    let div = match (ctl >> 22) & 0x3 {
        0 => 2,
        1 => 3,
        2 => 4,
        _ => 8,
    };
    Ok((vco + div / 2) / div)
}

impl Current {
    /// [`Current`] sanitized against the table and the CTL encoding:
    /// a known rung matches the decoded rate, the PLL ratio, and the
    /// CTL value (ignoring the CD2X pipe field, which firmware may
    /// have set for its own pipe).
    pub fn read(io: &(impl MmioWindow + ?Sized)) -> Result<Self, CdclkError> {
        let refclk_khz = refclk_khz(read(io, DSSM)?);
        let pll = read(io, DE_PLL_ENABLE)?;
        let ctl = read(io, CDCLK_CTL)?;
        if pll & PLL_ENABLE != 0 && pll & PLL_LOCK == 0 {
            return Err(CdclkError::Unlocked);
        }
        let actual_khz = current_khz(io, refclk_khz)?;
        if !io.display_access_ok() {
            return Err(CdclkError::NoDevice);
        }
        // bxt_sanitize_cdclk: PLL off, a rate outside the table, a VCO
        // that is not the table's, or a CTL other than bxt_cdclk_ctl
        // (ignoring the CD2X pipe field) are all "unknown".
        let known = TABLE.iter().copied().find(|r| {
            r.refclk_khz == refclk_khz
                && r.cdclk_khz == actual_khz
                && pll & PLL_ENABLE != 0
                && pll & PLL_RATIO_MASK == r.ratio
                && ctl_value(*r).is_some_and(|want| ctl & !CD2X_PIPE_MASK == want & !CD2X_PIPE_MASK)
        });
        Ok(Self {
            known,
            pll,
            ctl,
            refclk_khz,
            actual_khz,
        })
    }
}

/// One register-level step of a CDCLK change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    /// `icl_cdclk_pll_disable`.
    PllDisable,
    /// `icl_cdclk_pll_enable` at `ratio`.
    PllEnable { ratio: u32 },
    /// `CDCLK_CTL` = `bxt_cdclk_ctl(.., INVALID_PIPE)`.
    Ctl { value: u32 },
}

/// `_bxt_set_cdclk` for one configuration, from hardware state `old`.
/// ICL has no crawl and no squash, so a VCO change is always a full
/// disable/enable (`icl_cdclk_pll_update`); a same-VCO change is a
/// CTL write alone.
fn plan(old: &Current, target: Rung) -> Vec<Step> {
    let mut steps = Vec::new();
    let same_vco = old
        .known
        .is_some_and(|r| r.ratio * r.refclk_khz == target.ratio * target.refclk_khz);
    if !same_vco {
        steps.push(Step::PllDisable);
        steps.push(Step::PllEnable {
            ratio: target.ratio,
        });
    }
    if let Some(value) = ctl_value(target) {
        steps.push(Step::Ctl { value });
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

// Linux waits 1 ms (`intel_de_wait_for_*_ms(.., 1)`) for lock and unlock.
const PLL_WAIT_US: u64 = 1_000;

fn execute(io: &(impl MmioWindow + ?Sized), step: Step) -> Result<(), CdclkError> {
    match step {
        Step::PllDisable => {
            // `icl_cdclk_pll_disable`: RMW clear ENABLE only (LOCK is
            // read-only status); the Wa_13012396614 MDCLK-source step
            // is DISPLAY_VER >= 20 only and does not apply here.
            let pll = read(io, DE_PLL_ENABLE)?;
            io.write32(DE_PLL_ENABLE, pll & !PLL_ENABLE);
            wait(io, DE_PLL_ENABLE, PLL_LOCK, 0, PLL_WAIT_US)?;
        }
        Step::PllEnable { ratio } => {
            // `icl_cdclk_pll_enable`: ratio =
            // DIV_ROUND_CLOSEST(vco, ref); the table ratio is that
            // value for every rung, so the plan carries it directly.
            io.write32(DE_PLL_ENABLE, ratio);
            io.write32(DE_PLL_ENABLE, ratio | PLL_ENABLE);
            wait(io, DE_PLL_ENABLE, PLL_LOCK, PLL_LOCK, PLL_WAIT_US)?;
        }
        Step::Ctl { value } => io.write32(CDCLK_CTL, value),
    }
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(CdclkError::NoDevice)
    }
}

/// `skl_cdclk_pcode_pre_notify`: `SKL_PCODE_CDCLK_CONTROL` with
/// DATA0 `SKL_CDCLK_PREPARE_FOR_CHANGE`, reply DATA0 must carry
/// `SKL_CDCLK_READY_FOR_CHANGE` (Linux's
/// `intel_parent_pcode_request(..., 3)`). The pcode codec's 20 ms
/// budget covers Linux's 3 ms base timeout.
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

/// `skl_cdclk_pcode_post_notify`: the same command with DATA0 = the
/// target voltage level. Linux ignores its result
/// (`intel_cdclk_set_cdclk`); so does this. The codec's 2 ms budget
/// covers Linux's 1 ms `intel_parent_pcode_write_timeout`.
fn post_notify(io: &(impl MmioWindow + ?Sized), platform: Gen11Platform, target: Rung) {
    let _ = pcode_write(
        io,
        PCODE_CMD_CDCLK_CONTROL,
        0,
        0,
        u32::from(voltage_level(platform, target.cdclk_khz)),
        0,
    );
}

/// `intel_cdclk_set_cdclk` for one rung: pre-notify (a refusal, or a
/// reply without the ready bit, aborts before any register write),
/// the PLL/CTL steps, post-notify, then the readback proof — the PLL
/// is enabled, locked and at the rung's ratio, the CTL holds the
/// exact source value and the decoded rate equals the rung. A target
/// the hardware already runs is a no-op (no notify, no writes); the
/// modeset only calls this when the floor is unmet.
pub fn program(
    io: &(impl MmioWindow + ?Sized),
    old: &Current,
    target: Rung,
    platform: Gen11Platform,
) -> Result<(), CdclkError> {
    if old.known == Some(target) {
        return Ok(());
    }
    let Some(want_ctl) = ctl_value(target) else {
        return Err(CdclkError::Readback);
    };
    pre_notify(io)?;
    for step in plan(old, target) {
        execute(io, step)?;
    }
    post_notify(io, platform, target);
    let pll = read(io, DE_PLL_ENABLE)?;
    if pll & (PLL_ENABLE | PLL_LOCK | PLL_RATIO_MASK) != PLL_ENABLE | PLL_LOCK | target.ratio
        || read(io, CDCLK_CTL)? & !CD2X_PIPE_MASK != want_ctl & !CD2X_PIPE_MASK
        || current_khz(io, old.refclk_khz)? != target.cdclk_khz
    {
        return Err(CdclkError::Readback);
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Scripted CDCLK endpoint: DSSM strap, a DE PLL whose LOCK
    /// follows ENABLE (unless `grant_lock` is cleared), a CDCLK_CTL
    /// store, and a pcode endpoint that answers the CDCLK-control
    /// command: pre-notify (DATA0 0x3) replies with the ready bit
    /// (unless `grant_ready` is cleared), post-notify just
    /// completes. A forced pcode status makes every transaction
    /// fail with it.
    struct CdclkMmio {
        dssm: u32,
        pll: RefCell<u32>,
        ctl: RefCell<u32>,
        grant_lock: bool,
        grant_ready: bool,
        pcode_status: u8,
        pcode_mailbox: RefCell<u32>,
        pcode_data0: RefCell<u32>,
        writes: RefCell<Vec<(u64, u32)>>,
    }

    impl CdclkMmio {
        fn new(dssm: u32) -> Self {
            Self {
                dssm,
                pll: RefCell::new(0),
                ctl: RefCell::new(0),
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
                o if o == DSSM => self.dssm,
                o if o == DE_PLL_ENABLE => {
                    let stored = *self.pll.borrow();
                    if self.grant_lock && stored & PLL_ENABLE != 0 {
                        stored | PLL_LOCK
                    } else {
                        stored & !PLL_LOCK
                    }
                }
                o if o == CDCLK_CTL => *self.ctl.borrow(),
                o if o == PCODE_MAILBOX => *self.pcode_mailbox.borrow(),
                o if o == PCODE_DATA0 => *self.pcode_data0.borrow(),
                _ => 0,
            }
        }

        fn write32(&self, off: u64, val: u32) {
            use crate::intel_gpu_pcode::PCODE_READY;
            self.writes.borrow_mut().push((off, val));
            match off {
                o if o == DE_PLL_ENABLE => {
                    *self.pll.borrow_mut() = val & !PLL_LOCK;
                }
                o if o == CDCLK_CTL => *self.ctl.borrow_mut() = val,
                o if o == PCODE_DATA0 => *self.pcode_data0.borrow_mut() = val,
                o if o == PCODE_MAILBOX => {
                    if val & PCODE_READY != 0 {
                        let cmd = val & 0xFF;
                        // Pre-notify (DATA0 0x3) replies with the
                        // ready bit; anything else completes with
                        // DATA0 untouched.
                        if cmd == PCODE_CMD_CDCLK_CONTROL
                            && *self.pcode_data0.borrow() == SKL_CDCLK_PREPARE_FOR_CHANGE
                            && self.grant_ready
                        {
                            *self.pcode_data0.borrow_mut() = SKL_CDCLK_READY_FOR_CHANGE;
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

    fn rung(refclk_khz: u32, cdclk_khz: u32) -> Rung {
        TABLE
            .iter()
            .copied()
            .find(|r| r.refclk_khz == refclk_khz && r.cdclk_khz == cdclk_khz)
            .expect("test rung must be in the table")
    }

    /// Program `target` from a cold endpoint and return the
    /// programmed state for readback assertions.
    fn program_from_cold(
        dssm: u32,
        target: Rung,
        platform: Gen11Platform,
    ) -> Result<(CdclkMmio, Current), CdclkError> {
        let mmio = CdclkMmio::new(dssm);
        let old = Current::read(&mmio)?;
        program(&mmio, &old, target, platform)?;
        let after = Current::read(&mmio)?;
        Ok((mmio, after))
    }

    fn smoke_icl_cdclk_table_lookup() -> TestResult {
        // 19.2 MHz: first rung at or above the minimum.
        if calc_cdclk(19_200, 1) != Some(rung(19_200, 172_800)) {
            return TestResult::Fail("19.2 MHz floor must be the 172.8 MHz rung");
        }
        if calc_cdclk(19_200, 200_000) != Some(rung(19_200, 307_200)) {
            return TestResult::Fail("19.2 MHz 200 MHz floor must be the 307.2 MHz rung");
        }
        if calc_cdclk(19_200, 652_800) != Some(rung(19_200, 652_800)) {
            return TestResult::Fail("19.2 MHz top rung must resolve");
        }
        if calc_cdclk(19_200, 652_801).is_some() {
            return TestResult::Fail("past the 19.2 MHz table must refuse");
        }
        // 24 MHz has its own rungs (180/312/324/552/648 MHz).
        if calc_cdclk(24_000, 200_000) != Some(rung(24_000, 312_000)) {
            return TestResult::Fail("24 MHz 200 MHz floor must be the 312 MHz rung");
        }
        if calc_cdclk(24_000, 648_001).is_some() {
            return TestResult::Fail("past the 24 MHz table must refuse");
        }
        // 38.4 MHz.
        if calc_cdclk(38_400, 600_000) != Some(rung(38_400, 652_800)) {
            return TestResult::Fail("38.4 MHz 600 MHz floor must be the 652.8 MHz rung");
        }
        if calc_cdclk(24_000, 1).is_some_and(|r| r.refclk_khz != 24_000) {
            return TestResult::Fail("lookup must not cross reference straps");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_cdclk",
        smoke_icl_cdclk_table_lookup
    );

    fn smoke_icl_cdclk_dividers_and_voltage() -> TestResult {
        // Every table rung divides by 2 or 4 (VCO / CDCLK).
        for r in TABLE {
            if div_sel(r).is_none() {
                return TestResult::Fail("every icl rung must have a programmed divider");
            }
        }
        // 326.4 MHz rungs divide by 4 (VCO 1305.6 MHz); the rest by 2.
        if div_sel(rung(19_200, 326_400)) != Some(2 << 22) {
            return TestResult::Fail("326.4 MHz rung must use DIV_SEL_2");
        }
        if div_sel(rung(19_200, 172_800)) != Some(0) {
            return TestResult::Fail("172.8 MHz rung must use DIV_SEL_1");
        }
        // icl_calc_voltage_level boundaries (3 levels).
        let icl = Gen11Platform::IceLake;
        if voltage_level(icl, 312_000) != 0
            || voltage_level(icl, 312_001) != 1
            || voltage_level(icl, 556_800) != 1
            || voltage_level(icl, 556_801) != 2
            || voltage_level(icl, 652_800) != 2
        {
            return TestResult::Fail("icl voltage-level boundaries wrong");
        }
        // ehl_calc_voltage_level boundaries (4 levels); note the
        // ICL table's 326.4 MHz rung is level 2 on EHL, level 1
        // on ICL — the one place the families diverge.
        let ehl = Gen11Platform::ElkhartLake;
        if voltage_level(ehl, 180_000) != 0
            || voltage_level(ehl, 180_001) != 1
            || voltage_level(ehl, 312_000) != 1
            || voltage_level(ehl, 312_001) != 2
            || voltage_level(ehl, 326_400) != 2
            || voltage_level(ehl, 326_401) != 3
            || voltage_level(ehl, 652_800) != 3
        {
            return TestResult::Fail("ehl voltage-level boundaries wrong");
        }
        if voltage_level(Gen11Platform::JasperLake, 200_000) != 1 {
            return TestResult::Fail("Jasper Lake must take the EHL voltage table");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_cdclk",
        smoke_icl_cdclk_dividers_and_voltage
    );

    fn smoke_icl_cdclk_ctl_encoding() -> TestResult {
        // bxt_cdclk_ctl: divider select + pipe none + decimal, never
        // the SKL freq-sel bits 27:26 or SSA precharge bit 16 (SSA
        // precharge is GLK/BXT-only in bxt_cdclk_ctl).
        let ctl = ctl_value(rung(19_200, 172_800)).expect("rung must encode");
        if ctl != (7 << 19) | 344 {
            return TestResult::Fail("172.8 MHz CTL must be pipe-none + decimal 344");
        }
        let ctl = ctl_value(rung(19_200, 326_400)).expect("rung must encode");
        if ctl != (2 << 22) | (7 << 19) | 651 {
            return TestResult::Fail("326.4 MHz CTL must carry DIV_SEL_2 + decimal 651");
        }
        if ctl_value(rung(38_400, 652_800)) != Some((7 << 19) | 1304) {
            return TestResult::Fail("652.8 MHz CTL must be pipe-none + decimal 1304");
        }
        for r in TABLE {
            let ctl = ctl_value(r).expect("rung must encode");
            if ctl & (0x3 << 26) != 0 || ctl & (1 << 16) != 0 {
                return TestResult::Fail("CTL must never set freq-sel or SSA precharge");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_cdclk",
        smoke_icl_cdclk_ctl_encoding
    );

    fn smoke_icl_cdclk_readout() -> TestResult {
        // DSSM field 1 = 19.2 MHz; PLL on at ratio 18, CTL DIV_SEL_1.
        let mmio = CdclkMmio::new(1 << 29);
        *mmio.pll.borrow_mut() = PLL_ENABLE | 18;
        *mmio.ctl.borrow_mut() = (7 << 19) | 344;
        let cur = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("known clock must read"),
        };
        if cur.refclk_khz != 19_200 || cur.actual_khz != 172_800 {
            return TestResult::Fail("readout must decode 172.8 MHz from ratio + divider");
        }
        if cur.known != Some(rung(19_200, 172_800)) {
            return TestResult::Fail("matching registers must classify as known");
        }
        // PLL off: unknown, actual 0.
        let mmio = CdclkMmio::new(1 << 29);
        let cur = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("PLL-off clock must read"),
        };
        if cur.known.is_some() || cur.actual_khz != 0 {
            return TestResult::Fail("PLL-off clock must be unknown at 0 kHz");
        }
        // PLL on but unlocked: nothing can be trusted.
        let mut mmio = CdclkMmio::new(1 << 29);
        mmio.grant_lock = false;
        *mmio.pll.borrow_mut() = PLL_ENABLE | 18;
        if Current::read(&mmio) != Err(CdclkError::Unlocked) {
            return TestResult::Fail("unlocked PLL must error, not decode");
        }
        // Ratio outside the table: decoded but unknown.
        let mmio = CdclkMmio::new(1 << 29);
        *mmio.pll.borrow_mut() = PLL_ENABLE | 17;
        *mmio.ctl.borrow_mut() = (7 << 19) | 344;
        let cur = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("off-table ratio must read"),
        };
        if cur.known.is_some() || cur.actual_khz != 163_200 {
            return TestResult::Fail("off-table ratio must decode 163.2 MHz as unknown");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen11_cdclk", smoke_icl_cdclk_readout);

    fn smoke_icl_cdclk_program_from_cold() -> TestResult {
        let target = rung(19_200, 172_800);
        let (mmio, after) = match program_from_cold(1 << 29, target, Gen11Platform::IceLake) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("cold program to 172.8 MHz must succeed"),
        };
        if after.known != Some(target) || after.actual_khz != 172_800 {
            return TestResult::Fail("programmed clock must read back as the target rung");
        }
        // Pre-notify (DATA0 0x3) then post-notify (voltage 0): two
        // pcode mailbox writes; PLL disable, enable at ratio 18,
        // CTL once.
        let pcode = mmio.writes_to(PCODE_MAILBOX);
        if pcode.len() != 2 {
            return TestResult::Fail("program must send exactly pre + post pcode notifies");
        }
        if mmio.writes_to(DE_PLL_ENABLE) != alloc::vec![0, 18, 18 | PLL_ENABLE] {
            return TestResult::Fail("PLL sequence must be disable, ratio, ratio+enable");
        }
        if mmio.writes_to(CDCLK_CTL) != alloc::vec![(7 << 19) | 344] {
            return TestResult::Fail("CTL must be programmed once to the rung value");
        }
        let data0 = mmio.writes_to(PCODE_DATA0);
        if data0.len() != 2 || data0[0] != SKL_CDCLK_PREPARE_FOR_CHANGE || data0[1] != 0 {
            return TestResult::Fail("pcode DATA0 must carry pre 0x3 then voltage 0");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_cdclk",
        smoke_icl_cdclk_program_from_cold
    );

    fn smoke_icl_cdclk_same_vco_skips_pll() -> TestResult {
        // 326.4 MHz (ratio 68, VCO 1305.6 MHz) -> 652.8 MHz (ratio 68):
        // same VCO, so only the CTL divider changes.
        let mmio = CdclkMmio::new(1 << 29);
        *mmio.pll.borrow_mut() = PLL_ENABLE | 68;
        *mmio.ctl.borrow_mut() = (2 << 22) | (7 << 19) | 651;
        let old = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("326.4 MHz start must read as known"),
        };
        if old.known != Some(rung(19_200, 326_400)) {
            return TestResult::Fail("326.4 MHz start must classify as known");
        }
        if program(&mmio, &old, rung(19_200, 652_800), Gen11Platform::IceLake).is_err() {
            return TestResult::Fail("same-VCO change must succeed");
        }
        if !mmio.writes_to(DE_PLL_ENABLE).is_empty() {
            return TestResult::Fail("same-VCO change must not touch the PLL");
        }
        if mmio.writes_to(CDCLK_CTL) != alloc::vec![(7 << 19) | 1304] {
            return TestResult::Fail("same-VCO change must only rewrite the CTL divider");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_cdclk",
        smoke_icl_cdclk_same_vco_skips_pll
    );

    fn smoke_icl_cdclk_noop_at_target() -> TestResult {
        let mmio = CdclkMmio::new(1 << 29);
        *mmio.pll.borrow_mut() = PLL_ENABLE | 18;
        *mmio.ctl.borrow_mut() = (7 << 19) | 344;
        let old = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("target clock must read as known"),
        };
        if program(&mmio, &old, rung(19_200, 172_800), Gen11Platform::IceLake).is_err() {
            return TestResult::Fail("program at target must succeed");
        }
        if !mmio.writes.borrow().is_empty() {
            return TestResult::Fail("program at target must write nothing, not even pcode");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_cdclk",
        smoke_icl_cdclk_noop_at_target
    );

    fn smoke_icl_cdclk_pcode_refusal_writes_nothing() -> TestResult {
        let mut mmio = CdclkMmio::new(1 << 29);
        mmio.pcode_status = 0x1;
        let old = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("cold clock must read"),
        };
        if program(&mmio, &old, rung(19_200, 172_800), Gen11Platform::IceLake)
            != Err(CdclkError::Pcode(PcodeError::Status(0x1)))
        {
            return TestResult::Fail("refused pre-notify must surface the pcode status");
        }
        if !mmio.writes_to(DE_PLL_ENABLE).is_empty() || !mmio.writes_to(CDCLK_CTL).is_empty() {
            return TestResult::Fail("refused pre-notify must write no clock register");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_cdclk",
        smoke_icl_cdclk_pcode_refusal_writes_nothing
    );

    fn smoke_icl_cdclk_pcode_reply_not_ready() -> TestResult {
        // The transaction completes (status 0) but the punit never
        // sets READY_FOR_CHANGE in the reply DATA0.
        let mut mmio = CdclkMmio::new(1 << 29);
        mmio.grant_ready = false;
        let old = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("cold clock must read"),
        };
        if program(&mmio, &old, rung(19_200, 172_800), Gen11Platform::IceLake)
            != Err(CdclkError::PcodeNotReady)
        {
            return TestResult::Fail("a reply without the ready bit must fail as PcodeNotReady");
        }
        if !mmio.writes_to(DE_PLL_ENABLE).is_empty() || !mmio.writes_to(CDCLK_CTL).is_empty() {
            return TestResult::Fail("unready pre-notify must write no clock register");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_cdclk",
        smoke_icl_cdclk_pcode_reply_not_ready
    );

    fn smoke_icl_cdclk_pll_lock_timeout() -> TestResult {
        let mut mmio = CdclkMmio::new(1 << 29);
        mmio.grant_lock = false;
        let old = match Current::read(&mmio) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("cold clock must read"),
        };
        if program(&mmio, &old, rung(19_200, 172_800), Gen11Platform::IceLake)
            != Err(CdclkError::Timeout)
        {
            return TestResult::Fail("a PLL that never locks must time out");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_cdclk",
        smoke_icl_cdclk_pll_lock_timeout
    );
}

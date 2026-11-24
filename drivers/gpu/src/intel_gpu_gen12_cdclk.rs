//! Gen12 (Tiger / Alder / Raptor Lake) CDCLK computation and change sequence.
//!
//! MIT Linux `display/intel_cdclk.c` (7.4-rc2, `tgl_cdclk_funcs`):
//! - table: `icl_cdclk_table` (TGL uses the ICL table), selected by the
//!   DSSM reference strap (`icl_readout_refclk`); `bxt_calc_cdclk`
//!   (first rung at or above the minimum), `bxt_calc_cdclk_pll_vco`
//!   (VCO = refclk * ratio);
//! - voltage level: `tgl_calc_voltage_level`
//!   (`tgl_voltage_level_max_cdclk`); maximum: `intel_update_max_cdclk`
//!   (652.8 MHz, 648 MHz at the 24 MHz reference);
//! - readout: `bxt_get_cdclk` / `bxt_de_pll_readout` (ratio lives in
//!   `BXT_DE_PLL_ENABLE` bits 7:0 on DISPLAY_VER >= 11, VCO = ratio *
//!   refclk, CDCLK = VCO / CD2X divider) and `bxt_sanitize_cdclk`;
//! - change: `intel_cdclk_set_cdclk` — `bxt_cdclk_pcode_pre_notify` /
//!   `bxt_cdclk_pcode_post_notify` (`HSW_PCODE_DE_WRITE_FREQ_REQ`,
//!   pre DATA0 0x80000000, post DATA0 = voltage level, 2 ms timeout;
//!   a failed pre-notify aborts before any register write) around
//!   `_bxt_set_cdclk` (`icl_cdclk_pll_update`, `bxt_cdclk_ctl`);
//! - `bxt_cdclk_ctl`: CD2X divider select + CD2X pipe field +
//!   `skl_cdclk_decimal`. No crawl and no squash on TGL: `XE_D_DISPLAY`
//!   sets neither `has_cdclk_crawl` nor `has_cdclk_squash`
//!   (`display/intel_display_device.c`).
//!
//! This replaces the SKL-model programming the Gen12 modeset used before
//! (`program_cdclk_floor` wrote the SKL-only `CDCLK_FREQ_SEL` bits 27:26
//! and unconditional SSA precharge and never touched the DE PLL, so its
//! "raise" only rewrote nominal fields and the actual frequency stayed
//! whatever firmware left). The decimal field is kept: `bxt_cdclk_ctl`
//! writes it on DISPLAY_VER < 20, and the sanitize check compares it.
//! The freq-sel and SSA-precharge bits are never written here — on TGL
//! they belong to no programming step Linux performs.
//!
//! The modeset raises CDCLK only (a faster firmware clock is left alone),
//! with every pipe off when the change runs, so the CD2X pipe field is
//! always `ICL_CDCLK_CD2X_PIPE_NONE` (7 << 19), as in
//! `intel_gpu_xelpg_cdclk`.

use alloc::vec::Vec;

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_pcode::{pcode_write, PcodeError, PCODE_CMD_DE_WRITE_FREQ_REQ};

/// `CDCLK_CTL`.
pub(crate) const CDCLK_CTL: u64 = 0x46000;
/// `BXT_DE_PLL_ENABLE` (CDCLK PLL control on every BXT+ platform).
pub(crate) const DE_PLL_ENABLE: u64 = 0x46070;
/// `SKL_DSSM` — reference-clock strap (`icl_readout_refclk`).
const DSSM: u64 = 0x51004;
/// `BXT_DE_PLL_ENABLE.ENABLE` (bit 31).
pub(crate) const PLL_ENABLE: u32 = 1 << 31;
/// `BXT_DE_PLL_ENABLE.LOCK` (bit 30).
pub(crate) const PLL_LOCK: u32 = 1 << 30;
const PLL_FREQ_REQ_ACK: u32 = 1 << 22;
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
pub(crate) struct Rung {
    pub(crate) refclk_khz: u32,
    pub(crate) cdclk_khz: u32,
    pub(crate) ratio: u32,
}

/// `icl_cdclk_table` (`display/intel_cdclk.c`), transcribed verbatim:
/// six rungs per reference (19.2 / 24.0 / 38.4 MHz). The waveform field
/// is 0 on every ICL row, so no squash programming applies.
pub(crate) const TABLE: [Rung; 18] = [
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

const fn rkl_rung(refclk_khz: u32, cdclk_khz: u32, ratio: u32) -> Rung {
    Rung {
        refclk_khz,
        cdclk_khz,
        ratio,
    }
}

/// `rkl_cdclk_table` (`display/intel_cdclk.c`), which Rocket Lake takes
/// instead of the ICL table (`intel_init_cdclk_hooks`, `tgl_cdclk_funcs`
/// otherwise). The same CDCLK ladder, but every VCO doubles the ICL
/// one: CDCLK = VCO / 4, except 326.4 / 324 MHz at VCO / 8.
pub(crate) const RKL_TABLE: [Rung; 18] = [
    rkl_rung(19_200, 172_800, 36),
    rkl_rung(19_200, 192_000, 40),
    rkl_rung(19_200, 307_200, 64),
    rkl_rung(19_200, 326_400, 136),
    rkl_rung(19_200, 556_800, 116),
    rkl_rung(19_200, 652_800, 136),
    rkl_rung(24_000, 180_000, 30),
    rkl_rung(24_000, 192_000, 32),
    rkl_rung(24_000, 312_000, 52),
    rkl_rung(24_000, 324_000, 108),
    rkl_rung(24_000, 552_000, 92),
    rkl_rung(24_000, 648_000, 108),
    rkl_rung(38_400, 172_800, 18),
    rkl_rung(38_400, 192_000, 20),
    rkl_rung(38_400, 307_200, 32),
    rkl_rung(38_400, 326_400, 68),
    rkl_rung(38_400, 556_800, 58),
    rkl_rung(38_400, 652_800, 68),
];

/// The CDCLK table `family` runs: [`RKL_TABLE`] on Rocket Lake, the ICL
/// [`TABLE`] on every other display-12 family (and with no family).
pub(crate) const fn table_for(
    family: Option<crate::intel_gpu_gt::Gen12Platform>,
) -> &'static [Rung] {
    match family {
        Some(crate::intel_gpu_gt::Gen12Platform::RocketLake) => &RKL_TABLE,
        _ => &TABLE,
    }
}

/// `bxt_calc_cdclk`: the first rung of `table` at `refclk_khz` at or
/// above `min_khz`. Linux WARNs and clamps past the table; the modeset
/// refuses instead (leaves the firmware clock alone).
pub(crate) fn calc_cdclk(table: &[Rung], refclk_khz: u32, min_khz: u32) -> Option<Rung> {
    table
        .iter()
        .copied()
        .find(|r| r.refclk_khz == refclk_khz && r.cdclk_khz >= min_khz)
}

/// `tgl_calc_voltage_level` (`tgl_voltage_level_max_cdclk`).
pub(crate) fn voltage_level(cdclk_khz: u32) -> u8 {
    match cdclk_khz {
        0..=312_000 => 0,
        312_001..=326_400 => 1,
        326_401..=556_800 => 2,
        _ => 3,
    }
}

/// `skl_cdclk_decimal`: DIV_ROUND_CLOSEST(cdclk - 1000, 500).
fn decimal(cdclk_khz: u32) -> u32 {
    ((cdclk_khz - 1000 + 250) / 500) & DECIMAL_MASK
}

/// `bxt_cdclk_cd2x_div_sel` for a rung: the CD2X divider is
/// VCO / CDCLK (`cdclk_divider` with a zero waveform), mapped to the
/// field value (2 -> DIV_SEL_1, 3 -> 1_5, 4 -> 2, 8 -> 4). `None`
/// when the rung's VCO/CDCLK ratio is not a programmed divider —
/// every `TABLE` rung divides by 2 or 4, every `RKL_TABLE` rung by 4
/// or 8.
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
pub(crate) fn ctl_value(rung: Rung) -> Option<u32> {
    div_sel(rung).map(|sel| sel | CD2X_PIPE_NONE | decimal(rung.cdclk_khz))
}

/// Hardware CDCLK configuration as `bxt_get_cdclk` + `bxt_sanitize_cdclk`
/// classify it. `known == None` is Linux's "unknown" state: the PLL is
/// off, the rate is outside the table, the VCO is not the table's, or
/// the CTL is not `bxt_cdclk_ctl` — a full PLL disable/enable is
/// mandatory and the current clock must not be trusted as a floor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Current {
    pub(crate) known: Option<Rung>,
    /// Raw registers retained for the readback proof.
    pub(crate) pll: u32,
    pub(crate) ctl: u32,
    /// Reference strap in kHz (`icl_readout_refclk` via DSSM).
    pub(crate) refclk_khz: u32,
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
    /// A lock/unlock did not arrive inside the 1 ms window.
    Timeout,
    /// A written value did not read back.
    Readback,
    /// The pcode pre-notify was refused; no register was written.
    Pcode(PcodeError),
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
pub(crate) fn current_khz(
    io: &(impl MmioWindow + ?Sized),
    refclk_khz: u32,
) -> Result<u32, CdclkError> {
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
    /// [`Current`] sanitized against `table` and the CTL encoding:
    /// a known rung matches the decoded rate, the PLL ratio, and the
    /// CTL value (ignoring the CD2X pipe field, which firmware may
    /// have set for its own pipe).
    pub(crate) fn read(
        io: &(impl MmioWindow + ?Sized),
        table: &[Rung],
    ) -> Result<Self, CdclkError> {
        let refclk_khz = crate::intel_gpu_pll::refclk_khz(read(io, DSSM)?);
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
        let known = table.iter().copied().find(|r| {
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
/// TGL has no crawl (`HAS_CDCLK_CRAWL` is 0) and no squash, so a VCO
/// change is always a full disable/enable (`icl_cdclk_pll_update`);
/// a same-VCO change is a CTL write alone.
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

// Linux waits 1 ms (`intel_de_wait_for_*_ms(.., 1)`) for lock, unlock
// and the frequency-request ACK.
const PLL_WAIT_US: u64 = 1_000;

fn execute(io: &(impl MmioWindow + ?Sized), step: Step) -> Result<(), CdclkError> {
    match step {
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
        Step::Ctl { value } => io.write32(CDCLK_CTL, value),
    }
    if io.display_access_ok() {
        Ok(())
    } else {
        Err(CdclkError::NoDevice)
    }
}

/// `bxt_cdclk_pcode_pre_notify`: `HSW_PCODE_DE_WRITE_FREQ_REQ` with
/// DATA0 0x80000000, 2 ms timeout.
fn pre_notify(io: &(impl MmioWindow + ?Sized)) -> Result<(), CdclkError> {
    pcode_write(io, PCODE_CMD_DE_WRITE_FREQ_REQ, 0, 0, 0x8000_0000, 0).map_err(CdclkError::Pcode)
}

/// `bxt_cdclk_pcode_post_notify`: the same command with DATA0 = the
/// target voltage level. Linux ignores its result
/// (`intel_cdclk_set_cdclk`); so does this.
fn post_notify(io: &(impl MmioWindow + ?Sized), target: Rung) {
    let _ = pcode_write(
        io,
        PCODE_CMD_DE_WRITE_FREQ_REQ,
        0,
        0,
        u32::from(voltage_level(target.cdclk_khz)),
        0,
    );
}

/// `intel_cdclk_set_cdclk` for one rung: pre-notify (a refusal aborts
/// before any register write), the PLL/CTL steps, post-notify, then the
/// readback proof — the PLL is enabled, locked and at the rung's ratio,
/// the CTL holds the exact source value and the decoded rate equals the
/// rung. A target the hardware already runs is a no-op (no notify, no
/// writes); the modeset only calls this when the floor is unmet.
pub(crate) fn program(
    io: &(impl MmioWindow + ?Sized),
    old: &Current,
    target: Rung,
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
    post_notify(io, target);
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
    /// store, and a pcode endpoint that accepts the frequency-request
    /// command with the scripted status.
    struct CdclkMmio {
        dssm: u32,
        pll: RefCell<u32>,
        ctl: RefCell<u32>,
        grant_lock: bool,
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
            use crate::intel_gpu_pcode::{PCODE_DATA0, PCODE_MAILBOX};
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
            use crate::intel_gpu_pcode::{PCODE_DATA0, PCODE_MAILBOX, PCODE_READY};
            self.writes.borrow_mut().push((off, val));
            match off {
                o if o == DE_PLL_ENABLE => {
                    *self.pll.borrow_mut() = val & !(PLL_LOCK | PLL_FREQ_REQ_ACK)
                }
                o if o == CDCLK_CTL => *self.ctl.borrow_mut() = val,
                o if o == PCODE_DATA0 => *self.pcode_data0.borrow_mut() = val,
                o if o == PCODE_MAILBOX => {
                    if val & PCODE_READY != 0 {
                        let status = if val & 0xFF == PCODE_CMD_DE_WRITE_FREQ_REQ {
                            self.pcode_status as u32
                        } else {
                            0x1
                        };
                        *self.pcode_mailbox.borrow_mut() = status;
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
    fn program_from_cold(dssm: u32, target: Rung) -> Result<(CdclkMmio, Current), CdclkError> {
        let mmio = CdclkMmio::new(dssm);
        let old = Current::read(&mmio, &TABLE)?;
        program(&mmio, &old, target)?;
        let after = Current::read(&mmio, &TABLE)?;
        Ok((mmio, after))
    }

    fn smoke_tgl_cdclk_table_lookup() -> TestResult {
        // 19.2 MHz: first rung at or above the minimum.
        if calc_cdclk(&TABLE, 19_200, 1) != Some(rung(19_200, 172_800)) {
            return TestResult::Fail("19.2 MHz floor must be the 172.8 MHz rung");
        }
        if calc_cdclk(&TABLE, 19_200, 200_000) != Some(rung(19_200, 307_200)) {
            return TestResult::Fail("19.2 MHz 200 MHz floor must be the 307.2 MHz rung");
        }
        if calc_cdclk(&TABLE, 19_200, 652_800) != Some(rung(19_200, 652_800)) {
            return TestResult::Fail("19.2 MHz top rung must resolve");
        }
        if calc_cdclk(&TABLE, 19_200, 652_801).is_some() {
            return TestResult::Fail("past the 19.2 MHz table must refuse");
        }
        // 24 MHz has its own rungs (180/312/324/552/648 MHz).
        if calc_cdclk(&TABLE, 24_000, 200_000) != Some(rung(24_000, 312_000)) {
            return TestResult::Fail("24 MHz 200 MHz floor must be the 312 MHz rung");
        }
        if calc_cdclk(&TABLE, 24_000, 648_001).is_some() {
            return TestResult::Fail("past the 24 MHz table must refuse");
        }
        // 38.4 MHz.
        if calc_cdclk(&TABLE, 38_400, 600_000) != Some(rung(38_400, 652_800)) {
            return TestResult::Fail("38.4 MHz 600 MHz floor must be the 652.8 MHz rung");
        }
        if calc_cdclk(&TABLE, 24_000, 1).is_some_and(|r| r.refclk_khz != 24_000) {
            return TestResult::Fail("lookup must not cross reference straps");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_cdclk",
        smoke_tgl_cdclk_table_lookup
    );

    /// `rkl_cdclk_table`: Rocket Lake selects it, the other display-12
    /// families keep the ICL table, every rung's VCO divides by 4 or 8
    /// (CD2X DIV_SEL 2 / 4), and a lookup walks the RKL ladder.
    fn smoke_rkl_cdclk_table_and_dividers() -> TestResult {
        use crate::intel_gpu_gt::Gen12Platform;
        if table_for(Some(Gen12Platform::RocketLake)) != &RKL_TABLE[..]
            || table_for(Some(Gen12Platform::TigerLake)) != &TABLE[..]
            || table_for(Some(Gen12Platform::AlderLakeS)) != &TABLE[..]
            || table_for(None) != &TABLE[..]
        {
            return TestResult::Fail("only Rocket Lake takes rkl_cdclk_table");
        }
        for r in RKL_TABLE {
            let div = (r.ratio * r.refclk_khz) / r.cdclk_khz;
            let want = match (r.refclk_khz, r.cdclk_khz) {
                (_, 326_400) | (_, 324_000) => 3 << 22,
                _ => 2 << 22,
            };
            if r.ratio * r.refclk_khz != div * r.cdclk_khz || div_sel(r) != Some(want) {
                return TestResult::Fail("every RKL rung must divide its VCO by 4 or 8");
            }
        }
        // 19.2 MHz: 172.8 MHz (691.2 / 4) -> CTL 0x00B80158; 326.4 MHz
        // (2611.2 / 8) -> DIV_SEL 4 with decimal 651.
        let low = calc_cdclk(&RKL_TABLE, 19_200, 74_250);
        if low != Some(rkl_rung(19_200, 172_800, 36))
            || ctl_value(rkl_rung(19_200, 172_800, 36)) != Some(0x00B8_0158)
        {
            return TestResult::Fail("RKL 172.8 MHz rung must be ratio 36 at DIV_SEL 2");
        }
        if calc_cdclk(&RKL_TABLE, 19_200, 310_000) != Some(rkl_rung(19_200, 326_400, 136))
            || ctl_value(rkl_rung(19_200, 326_400, 136)) != Some((3 << 22) | (7 << 19) | 651)
        {
            return TestResult::Fail("RKL 326.4 MHz rung must be ratio 136 at DIV_SEL 4");
        }
        if calc_cdclk(&RKL_TABLE, 24_000, 648_001).is_some() {
            return TestResult::Fail("the RKL ladder tops out at 648 MHz on the 24 MHz strap");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_cdclk",
        smoke_rkl_cdclk_table_and_dividers
    );

    fn smoke_tgl_cdclk_dividers_and_voltage() -> TestResult {
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
        // tgl_calc_voltage_level boundaries.
        if voltage_level(312_000) != 0
            || voltage_level(312_001) != 1
            || voltage_level(326_400) != 1
            || voltage_level(326_401) != 2
            || voltage_level(556_800) != 2
            || voltage_level(556_801) != 3
            || voltage_level(652_800) != 3
        {
            return TestResult::Fail("tgl voltage-level boundaries wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_cdclk",
        smoke_tgl_cdclk_dividers_and_voltage
    );

    fn smoke_tgl_cdclk_ctl_encoding() -> TestResult {
        // bxt_cdclk_ctl: divider select + pipe none + decimal, never
        // the SKL freq-sel bits 27:26 or SSA precharge bit 16.
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
        "drivers/gpu/intel_gpu_gen12_cdclk",
        smoke_tgl_cdclk_ctl_encoding
    );

    fn smoke_tgl_cdclk_readout() -> TestResult {
        // DSSM field 1 = 19.2 MHz; PLL on at ratio 18, CTL DIV_SEL_1.
        let mmio = CdclkMmio::new(1 << 29);
        *mmio.pll.borrow_mut() = PLL_ENABLE | 18;
        *mmio.ctl.borrow_mut() = (7 << 19) | 344;
        let cur = match Current::read(&mmio, &TABLE) {
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
        let cur = match Current::read(&mmio, &TABLE) {
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
        if Current::read(&mmio, &TABLE) != Err(CdclkError::Unlocked) {
            return TestResult::Fail("unlocked PLL must error, not decode");
        }
        // Ratio outside the table: decoded but unknown.
        let mmio = CdclkMmio::new(1 << 29);
        *mmio.pll.borrow_mut() = PLL_ENABLE | 17;
        *mmio.ctl.borrow_mut() = (7 << 19) | 344;
        let cur = match Current::read(&mmio, &TABLE) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("off-table ratio must read"),
        };
        if cur.known.is_some() || cur.actual_khz != 163_200 {
            return TestResult::Fail("off-table ratio must decode 163.2 MHz as unknown");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen12_cdclk", smoke_tgl_cdclk_readout);

    fn smoke_tgl_cdclk_program_from_cold() -> TestResult {
        let target = rung(19_200, 172_800);
        let (mmio, after) = match program_from_cold(1 << 29, target) {
            Ok(v) => v,
            Err(_) => return TestResult::Fail("cold program to 172.8 MHz must succeed"),
        };
        if after.known != Some(target) || after.actual_khz != 172_800 {
            return TestResult::Fail("programmed clock must read back as the target rung");
        }
        // Pre-notify first (DATA0 0x80000000), then PLL disable,
        // enable at ratio 18, CTL, then post-notify (voltage 0).
        let pcode = mmio.writes_to(crate::intel_gpu_pcode::PCODE_MAILBOX);
        if pcode.len() != 2 {
            return TestResult::Fail("program must send exactly pre + post pcode notifies");
        }
        if mmio.writes_to(DE_PLL_ENABLE) != alloc::vec![0, 18, 18 | PLL_ENABLE] {
            return TestResult::Fail("PLL sequence must be disable, ratio, ratio+enable");
        }
        if mmio.writes_to(CDCLK_CTL) != alloc::vec![(7 << 19) | 344] {
            return TestResult::Fail("CTL must be programmed once to the rung value");
        }
        let data0 = mmio.writes_to(crate::intel_gpu_pcode::PCODE_DATA0);
        if data0.len() != 2 || data0[0] != 0x8000_0000 || data0[1] != 0 {
            return TestResult::Fail("pcode DATA0 must carry pre 0x80000000 then voltage 0");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_cdclk",
        smoke_tgl_cdclk_program_from_cold
    );

    fn smoke_tgl_cdclk_same_vco_skips_pll() -> TestResult {
        // 326.4 MHz (ratio 68, VCO 1305.6 MHz) -> 652.8 MHz (ratio 68):
        // same VCO, so only the CTL divider changes.
        let mmio = CdclkMmio::new(1 << 29);
        *mmio.pll.borrow_mut() = PLL_ENABLE | 68;
        *mmio.ctl.borrow_mut() = (2 << 22) | (7 << 19) | 651;
        let old = match Current::read(&mmio, &TABLE) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("326.4 MHz start must read as known"),
        };
        if old.known != Some(rung(19_200, 326_400)) {
            return TestResult::Fail("326.4 MHz start must classify as known");
        }
        if program(&mmio, &old, rung(19_200, 652_800)).is_err() {
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
        "drivers/gpu/intel_gpu_gen12_cdclk",
        smoke_tgl_cdclk_same_vco_skips_pll
    );

    fn smoke_tgl_cdclk_noop_at_target() -> TestResult {
        let mmio = CdclkMmio::new(1 << 29);
        *mmio.pll.borrow_mut() = PLL_ENABLE | 18;
        *mmio.ctl.borrow_mut() = (7 << 19) | 344;
        let old = match Current::read(&mmio, &TABLE) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("target clock must read as known"),
        };
        if program(&mmio, &old, rung(19_200, 172_800)).is_err() {
            return TestResult::Fail("program at target must succeed");
        }
        if !mmio.writes.borrow().is_empty() {
            return TestResult::Fail("program at target must write nothing, not even pcode");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_cdclk",
        smoke_tgl_cdclk_noop_at_target
    );

    fn smoke_tgl_cdclk_pcode_refusal_writes_nothing() -> TestResult {
        let mut mmio = CdclkMmio::new(1 << 29);
        mmio.pcode_status = 0x1;
        let old = match Current::read(&mmio, &TABLE) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("cold clock must read"),
        };
        if program(&mmio, &old, rung(19_200, 172_800))
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
        "drivers/gpu/intel_gpu_gen12_cdclk",
        smoke_tgl_cdclk_pcode_refusal_writes_nothing
    );

    fn smoke_tgl_cdclk_pll_lock_timeout() -> TestResult {
        let mut mmio = CdclkMmio::new(1 << 29);
        mmio.grant_lock = false;
        let old = match Current::read(&mmio, &TABLE) {
            Ok(c) => c,
            Err(_) => return TestResult::Fail("cold clock must read"),
        };
        if program(&mmio, &old, rung(19_200, 172_800)) != Err(CdclkError::Timeout) {
            return TestResult::Fail("a PLL that never locks must time out");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_cdclk",
        smoke_tgl_cdclk_pll_lock_timeout
    );
}

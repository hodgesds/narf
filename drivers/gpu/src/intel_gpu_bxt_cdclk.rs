//! Broxton / Gemini Lake CDCLK: the DE PLL and the CD2X divider.
//!
//! MIT Linux v6.12 `display/intel_cdclk.c` (`bxt_cdclk_table`,
//! `glk_cdclk_table`, `bxt_calc_cdclk`, `bxt_calc_cdclk_pll_vco`,
//! `bxt_calc_voltage_level`, `bxt_de_pll_readout`, `bxt_get_cdclk`,
//! `bxt_de_pll_enable` / `_disable`, `bxt_cdclk_pll_update`, `bxt_cdclk_ctl`,
//! `bxt_set_cdclk` for display < 11, `intel_pixel_rate_to_cdclk`) and
//! `i915_reg.h` (`CDCLK_CTL`, `BXT_DE_PLL_CTL`, `BXT_DE_PLL_ENABLE`).
//!
//! The reference is a fixed 19.2 MHz. CDCLK is VCO / 2 / {1, 1.5, 2, 4}
//! with the VCO 60 or 65 times the reference on Broxton and 33 times on
//! Gemini Lake. The PUNIT is told through `HSW_PCODE_DE_WRITE_FREQ_REQ`
//! before (0x80000000) and after (the voltage level) a change. Nothing here
//! has run on silicon.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_gen9_cdclk::{decimal, CdclkError, CDCLK_CTL, CDCLK_FREQ_DECIMAL_MASK};
use crate::intel_gpu_pcode::{pcode_write, PCODE_CMD_DE_WRITE_FREQ_REQ};

/// The fixed reference (`bxt_get_cdclk`: `cdclk_config->ref = 19200`), also
/// the bypass frequency with the DE PLL off.
pub(crate) const REF_KHZ: u32 = 19_200;

/// `bxt_cdclk_table`: (CDCLK, VCO ratio).
const BXT_TABLE: [(u32, u32); 5] = [
    (144_000, 60),
    (288_000, 60),
    (384_000, 60),
    (576_000, 60),
    (624_000, 65),
];
/// `glk_cdclk_table`.
const GLK_TABLE: [(u32, u32); 3] = [(79_200, 33), (158_400, 33), (316_800, 33)];

const fn table(glk: bool) -> &'static [(u32, u32)] {
    if glk {
        &GLK_TABLE
    } else {
        &BXT_TABLE
    }
}

/// `bxt_calc_cdclk`: the lowest table CDCLK at or above `min_khz`.
pub(crate) fn calc_cdclk(glk: bool, min_khz: u32) -> Option<u32> {
    table(glk)
        .iter()
        .find(|(cdclk, _)| *cdclk >= min_khz)
        .map(|(cdclk, _)| *cdclk)
}

/// `bxt_calc_cdclk_pll_vco`: zero for the bypass frequency.
pub(crate) fn pll_vco(glk: bool, cdclk_khz: u32) -> Option<u32> {
    if cdclk_khz == REF_KHZ {
        return Some(0);
    }
    table(glk)
        .iter()
        .find(|(cdclk, _)| *cdclk == cdclk_khz)
        .map(|(_, ratio)| REF_KHZ * ratio)
}

/// `bxt_calc_voltage_level`.
pub(crate) const fn voltage_level(cdclk_khz: u32) -> u32 {
    cdclk_khz.div_ceil(25_000)
}

/// `intel_pixel_rate_to_cdclk`: display 10 (Gemini Lake) carries two pixels
/// per CDCLK, display 9 (Broxton) one.
pub(crate) const fn min_cdclk_for_pixel_rate(glk: bool, pixel_khz: u32) -> u32 {
    if glk {
        pixel_khz.div_ceil(2)
    } else {
        pixel_khz
    }
}

/// `BXT_DE_PLL_CTL`: the ratio [7:0].
pub(crate) const DE_PLL_CTL: u64 = 0x6d000;
/// `BXT_DE_PLL_ENABLE`: enable [31], lock [30].
pub(crate) const DE_PLL_ENABLE: u64 = 0x46070;
const DE_PLL_PLL_ENABLE: u32 = 1 << 31;
const DE_PLL_LOCK: u32 = 1 << 30;

/// `BXT_CDCLK_CD2X_DIV_SEL_*` [23:22] for twice the divider.
const fn div_sel(cdclk_khz: u32, vco: u32) -> u32 {
    let twice = if cdclk_khz == 0 {
        2
    } else {
        (vco + cdclk_khz / 2) / cdclk_khz
    };
    match twice {
        3 => 1 << 22,
        4 => 2 << 22,
        8 => 3 << 22,
        _ => 0,
    }
}

/// `bxt_cdclk_ctl`: divider, the CD2X pipe (`None` is `PIPE_NONE`, 3), SSA
/// precharge at 500 MHz and up, and the decimal frequency.
pub(crate) fn cdclk_ctl(cdclk_khz: u32, vco: u32, pipe: Option<u32>) -> u32 {
    let ssa = if cdclk_khz >= 500_000 { 1 << 16 } else { 0 };
    div_sel(cdclk_khz, vco) | pipe.unwrap_or(3).min(3) << 20 | ssa | decimal(cdclk_khz)
}

/// The running CDCLK (`bxt_get_cdclk`, `bxt_de_pll_readout`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Current {
    /// DE PLL VCO in kHz, zero with the PLL off or unlocked.
    pub vco: u32,
    pub cdclk_khz: u32,
}

fn read(io: &(impl MmioWindow + ?Sized), reg: u64) -> Result<u32, CdclkError> {
    let value = io.read32(reg);
    if value == u32::MAX || !io.display_access_ok() {
        Err(CdclkError::NoDevice)
    } else {
        Ok(value)
    }
}

impl Current {
    pub(crate) fn read(io: &(impl MmioWindow + ?Sized)) -> Result<Self, CdclkError> {
        let enable = read(io, DE_PLL_ENABLE)?;
        let vco = if enable & DE_PLL_PLL_ENABLE != 0 && enable & DE_PLL_LOCK != 0 {
            REF_KHZ * (read(io, DE_PLL_CTL)? & 0xff)
        } else {
            0
        };
        if vco == 0 {
            return Ok(Self {
                vco,
                cdclk_khz: REF_KHZ,
            });
        }
        let twice = match (read(io, CDCLK_CTL)? >> 22) & 3 {
            0 => 2,
            1 => 3,
            2 => 4,
            _ => 8,
        };
        Ok(Self {
            vco,
            cdclk_khz: (vco + twice / 2) / twice,
        })
    }
}

fn wait_lock(io: &(impl MmioWindow + ?Sized), locked: bool) -> Result<(), CdclkError> {
    let mut lost = false;
    // Linux waits 1 ms ("Timeout 200us").
    let done = narf_scheduler::responsive_spin_until(
        || {
            let value = io.read32(DE_PLL_ENABLE);
            lost = value == u32::MAX || !io.display_access_ok();
            lost || (value & DE_PLL_LOCK != 0) == locked
        },
        narf_time::Deadline::after_us(1_000),
    );
    match (lost, done) {
        (true, _) => Err(CdclkError::NoDevice),
        (false, true) => Ok(()),
        (false, false) => Err(CdclkError::Timeout),
    }
}

/// `bxt_set_cdclk` for display 9/10 with no pipe running (`PIPE_NONE`):
/// pre-notify the PUNIT, re-lock the DE PLL on a VCO change
/// (`bxt_cdclk_pll_update`), write `CDCLK_CTL`, post-notify the voltage
/// level, then read the target back. A target already running is a no-op.
pub(crate) fn program(
    io: &(impl MmioWindow + ?Sized),
    glk: bool,
    old: Current,
    cdclk_khz: u32,
) -> Result<Current, CdclkError> {
    let vco = pll_vco(glk, cdclk_khz).ok_or(CdclkError::Readback)?;
    let target = Current { vco, cdclk_khz };
    if old == target {
        return Ok(old);
    }
    // "BSpec requires us to wait up to 150usec ... 2ms ... based on
    // experiment": the codec's 2 ms budget.
    pcode_write(io, PCODE_CMD_DE_WRITE_FREQ_REQ, 0, 0, 0x8000_0000, 0)
        .map_err(CdclkError::Pcode)?;
    if old.vco != 0 && old.vco != vco {
        io.write32(DE_PLL_ENABLE, 0);
        wait_lock(io, false)?;
    }
    if vco != 0 && old.vco != vco {
        let ctl = read(io, DE_PLL_CTL)?;
        io.write32(DE_PLL_CTL, (ctl & !0xff) | vco.div_ceil(REF_KHZ));
        io.write32(DE_PLL_ENABLE, DE_PLL_PLL_ENABLE);
        wait_lock(io, true)?;
    }
    io.write32(CDCLK_CTL, cdclk_ctl(cdclk_khz, vco, None));
    pcode_write(
        io,
        PCODE_CMD_DE_WRITE_FREQ_REQ,
        0,
        0,
        voltage_level(cdclk_khz),
        0,
    )
    .map_err(CdclkError::Pcode)?;
    let after = Current::read(io)?;
    if after != target || read(io, CDCLK_CTL)? & CDCLK_FREQ_DECIMAL_MASK != decimal(cdclk_khz) {
        return Err(CdclkError::Readback);
    }
    Ok(after)
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use crate::intel_gpu_pcode::{PCODE_DATA0, PCODE_MAILBOX};
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A DE PLL whose lock follows its enable, and a pcode endpoint that
    /// completes every command at once.
    #[derive(Default)]
    struct Regs {
        values: RefCell<BTreeMap<u64, u32>>,
        writes: RefCell<Vec<(u64, u32)>>,
    }
    impl MmioWindow for Regs {
        fn read32(&self, reg: u64) -> u32 {
            *self.values.borrow().get(&reg).unwrap_or(&0)
        }
        fn write32(&self, reg: u64, value: u32) {
            self.writes.borrow_mut().push((reg, value));
            let value = match reg {
                DE_PLL_ENABLE if value & DE_PLL_PLL_ENABLE != 0 => value | DE_PLL_LOCK,
                PCODE_MAILBOX => value & !(1 << 31),
                _ => value,
            };
            self.values.borrow_mut().insert(reg, value);
        }
    }

    /// The tables, divider and control word, hand-expanded from Linux.
    fn smoke_bxt_cdclk_tables_follow_linux() -> TestResult {
        let ok = calc_cdclk(false, 300_000) == Some(384_000)
            && calc_cdclk(false, 600_000) == Some(624_000)
            && calc_cdclk(false, 700_000).is_none()
            && calc_cdclk(true, 100_000) == Some(158_400)
            && pll_vco(false, 576_000) == Some(1_152_000)
            && pll_vco(false, 624_000) == Some(1_248_000)
            && pll_vco(true, 316_800) == Some(633_600)
            && pll_vco(true, REF_KHZ) == Some(0)
            && voltage_level(624_000) == 25
            && min_cdclk_for_pixel_rate(true, 297_000) == 148_500
            && min_cdclk_for_pixel_rate(false, 297_000) == 297_000
            // 384 MHz from 1152: divider 1.5; decimal (384000-1000)/500 = 766.
            && cdclk_ctl(384_000, 1_152_000, None) == (1 << 22 | 3 << 20 | 766)
            // 624 MHz: divider 1, SSA precharge, decimal 1246.
            && cdclk_ctl(624_000, 1_248_000, Some(0)) == (1 << 16 | 1246)
            // GLK 79.2 MHz from 633.6: divider 4.
            && cdclk_ctl(79_200, 633_600, None) >> 22 == 3;
        if !ok {
            return TestResult::Fail("BXT/GLK CDCLK tables and CDCLK_CTL");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_bxt_cdclk",
        smoke_bxt_cdclk_tables_follow_linux
    );

    /// A VCO change re-locks the DE PLL between the two pcode notifications
    /// and reads back; the running target is a no-op.
    fn smoke_bxt_cdclk_program_relocks_de_pll() -> TestResult {
        let io = Regs::default();
        io.values
            .borrow_mut()
            .insert(DE_PLL_ENABLE, DE_PLL_PLL_ENABLE | DE_PLL_LOCK);
        io.values.borrow_mut().insert(DE_PLL_CTL, 60);
        io.values
            .borrow_mut()
            .insert(CDCLK_CTL, cdclk_ctl(288_000, 1_152_000, None));
        let old = Current::read(&io).unwrap();
        if old
            != (Current {
                vco: 1_152_000,
                cdclk_khz: 288_000,
            })
        {
            return TestResult::Fail("bxt_get_cdclk readout");
        }
        let now = program(&io, false, old, 624_000);
        let writes = io.writes.borrow().clone();
        let at = |w: (u64, u32)| writes.iter().position(|x| *x == w);
        let pre = at((PCODE_DATA0, 0x8000_0000));
        let off = at((DE_PLL_ENABLE, 0));
        let ratio = at((DE_PLL_CTL, 65));
        let ctl = at((CDCLK_CTL, cdclk_ctl(624_000, 1_248_000, None)));
        let post = at((PCODE_DATA0, 25));
        if now
            != Ok(Current {
                vco: 1_248_000,
                cdclk_khz: 624_000,
            })
            || !(pre < off && off < ratio && ratio < ctl && ctl < post && pre.is_some())
        {
            return TestResult::Fail("bxt_set_cdclk order");
        }
        io.writes.borrow_mut().clear();
        if program(&io, false, now.unwrap(), 624_000).is_err() || !io.writes.borrow().is_empty() {
            return TestResult::Fail("the running CDCLK is left alone");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_bxt_cdclk",
        smoke_bxt_cdclk_program_relocks_de_pll
    );
}

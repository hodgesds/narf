//! Broxton / Gemini Lake port PLLs: one PLL per DDI, inside its DPIO PHY.
//!
//! MIT Linux v6.12 `display/intel_dpll_mgr.c` (`bxt_dp_clk_val`,
//! `bxt_ddi_dp_pll_dividers`, `bxt_ddi_hdmi_pll_dividers`,
//! `bxt_ddi_set_dpll_hw_state`, `bxt_ddi_pll_get_freq`,
//! `bxt_ddi_pll_enable`, `bxt_ddi_pll_disable`, `bxt_update_dpll_ref_clks`),
//! `display/intel_dpll.c` (`intel_limits_bxt`, `chv_calc_dpll_params`,
//! `chv_find_best_dpll`, `vlv_PLL_is_optimal`, `intel_pll_is_valid` for LP)
//! and `display/bxt_dpio_phy_regs.h`.
//!
//! The reference is 100 MHz (SSC and non-SSC alike). M1 is 2 and N is 1;
//! M2 is a 22-bit fixed-point fraction. DP link rates take fixed dividers;
//! HDMI searches P1/P2 for the closest dot clock. Nothing here has run on
//! silicon.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_bxt_phy::{channel, lane_offset, port_to_phy_channel, Channel, Phy, Port};

/// `bxt_update_dpll_ref_clks`: 100 MHz.
pub(crate) const REF_KHZ: u64 = 100_000;

/// One `struct dpll`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Dividers {
    pub p1: u32,
    pub p2: u32,
    pub n: u32,
    pub m1: u32,
    /// Fixed point, 22 fractional bits.
    pub m2: u32,
    pub vco: u64,
    pub dot: u64,
}

impl Dividers {
    const fn dp(dot: u64, p1: u32, p2: u32, m2: u32) -> Self {
        Self {
            p1,
            p2,
            n: 1,
            m1: 2,
            m2,
            vco: 0,
            dot,
        }
    }

    /// `chv_calc_dpll_params`: VCO = ref * M1 * M2 / N (M2 in .22) and
    /// dot = VCO / (P1 * P2 * 5).
    pub(crate) fn calc(mut self) -> Self {
        let m = u64::from(self.m1) * u64::from(self.m2);
        let p = u64::from(self.p1) * u64::from(self.p2) * 5;
        let n = u64::from(self.n) << 22;
        self.vco = if n == 0 { 0 } else { (REF_KHZ * m + n / 2) / n };
        self.dot = if p == 0 { 0 } else { (self.vco + p / 2) / p };
        self
    }
}

/// `bxt_dp_clk_val`: the DP link rates (port clock, kHz).
const DP_CLK_VAL: [Dividers; 7] = [
    Dividers::dp(162_000, 4, 2, 0x819_999a),
    Dividers::dp(270_000, 4, 1, 0x6c0_0000),
    Dividers::dp(540_000, 2, 1, 0x6c0_0000),
    Dividers::dp(216_000, 3, 2, 0x819_999a),
    Dividers::dp(243_000, 4, 1, 0x613_3333),
    Dividers::dp(324_000, 4, 1, 0x819_999a),
    Dividers::dp(432_000, 3, 1, 0x819_999a),
];

/// `bxt_ddi_dp_pll_dividers`: the table entry for `port_clock`, the first
/// entry for any other rate, then the derived VCO and dot clock.
pub(crate) fn dp_dividers(port_clock: u64) -> Dividers {
    DP_CLK_VAL
        .iter()
        .find(|d| d.dot == port_clock)
        .copied()
        .unwrap_or(DP_CLK_VAL[0])
        .calc()
}

/// `intel_pll_is_valid` against `intel_limits_bxt` (LP: no M/P bounds, no
/// M1 > M2 rule).
fn valid(d: &Dividers) -> bool {
    d.n == 1
        && (2..=4).contains(&d.p1)
        && (2 << 22..=255 << 22).contains(&d.m2)
        && d.m1 == 2
        && (4_800_000..=6_700_000).contains(&d.vco)
        && (25_000..=594_000).contains(&d.dot)
}

/// `bxt_find_best_dpll` (`chv_find_best_dpll`, `vlv_PLL_is_optimal`): P1
/// from 4 down to 2, P2 from 20 down to 1 (in steps of 2 above 10), the M2
/// that best hits `target`; a larger P wins within 100 ppm. `None` when no
/// divider set is valid.
pub(crate) fn hdmi_dividers(target: u64) -> Option<Dividers> {
    let mut best: Option<Dividers> = None;
    let mut best_ppm = 1_000_000u64;
    for p1 in (2..=4u32).rev() {
        let mut p2 = 20u32;
        while p2 >= 1 {
            let p = u64::from(p1 * p2 * 5);
            let denom = REF_KHZ * 2;
            let m2 = ((target * p) << 22).saturating_add(denom / 2) / denom;
            if m2 <= u64::from(i32::MAX as u32 / 2) {
                let d = Dividers {
                    p1,
                    p2,
                    n: 1,
                    m1: 2,
                    m2: m2 as u32,
                    vco: 0,
                    dot: 0,
                }
                .calc();
                if valid(&d) {
                    let ppm = 1_000_000 * target.abs_diff(d.dot) / target;
                    let bp = best.map_or(0, |b| u64::from(b.p1 * b.p2 * 5));
                    let better = if ppm < 100 && p > bp {
                        best_ppm = 0;
                        true
                    } else if ppm + 10 < best_ppm {
                        best_ppm = ppm;
                        true
                    } else {
                        false
                    };
                    if better {
                        best = Some(d);
                    }
                }
            }
            p2 -= if p2 > 10 { 2 } else { 1 };
        }
    }
    best
}

/// `struct bxt_dpll_hw_state`.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct State {
    pub ebb0: u32,
    pub ebb4: u32,
    pub pll0: u32,
    pub pll1: u32,
    pub pll2: u32,
    pub pll3: u32,
    pub pll6: u32,
    pub pll8: u32,
    pub pll9: u32,
    pub pll10: u32,
    pub pcsdw12: u32,
}

const PORT_PLL_M2_FRAC_ENABLE: u32 = 1 << 16;
const PORT_PLL_10BIT_CLK_ENABLE: u32 = 1 << 13;
const PORT_PLL_RECALIBRATE: u32 = 1 << 14;
const PORT_PLL_DCO_AMP_OVR_EN_H: u32 = 1 << 27;
const LANESTAGGER_STRAP_OVRD: u32 = 1 << 6;

/// `bxt_ddi_set_dpll_hw_state`: the loop coefficients by VCO band and the
/// lane stagger by port clock. `None` for a VCO outside every band.
pub(crate) fn hw_state(port_clock: u64, d: &Dividers) -> Option<State> {
    let vco = d.vco;
    let (prop, int, gain, targ) = if (6_200_000..=6_700_000).contains(&vco) {
        (4, 9, 3, 8)
    } else if (vco > 5_400_000 && vco < 6_200_000) || (4_800_000..5_400_000).contains(&vco) {
        (5, 11, 3, 9)
    } else if vco == 5_400_000 {
        (3, 8, 1, 9)
    } else {
        return None;
    };
    let lanestagger = match port_clock {
        c if c > 270_000 => 0x18,
        c if c > 135_000 => 0x0d,
        c if c > 67_000 => 0x07,
        c if c > 33_000 => 0x04,
        _ => 0x02,
    };
    let frac = d.m2 & 0x3f_ffff;
    Some(State {
        ebb0: d.p1 << 13 | d.p2 << 8,
        pll0: (d.m2 >> 22) & 0xff,
        pll1: d.n << 8,
        pll2: frac,
        pll3: if frac != 0 {
            PORT_PLL_M2_FRAC_ENABLE
        } else {
            0
        },
        pll6: prop | int << 8 | gain << 16,
        pll8: targ,
        pll9: 5 << 1,
        pll10: 15 << 10 | PORT_PLL_DCO_AMP_OVR_EN_H,
        ebb4: PORT_PLL_10BIT_CLK_ENABLE,
        pcsdw12: LANESTAGGER_STRAP_OVRD | lanestagger,
    })
}

/// `bxt_ddi_pll_get_freq`: the port clock a state produces.
#[cfg(any(test, feature = "kernel-test"))]
pub(crate) fn get_freq(state: &State) -> u64 {
    let mut m2 = (state.pll0 & 0xff) << 22;
    if state.pll3 & PORT_PLL_M2_FRAC_ENABLE != 0 {
        m2 |= state.pll2 & 0x3f_ffff;
    }
    Dividers {
        p1: (state.ebb0 >> 13) & 0x7,
        p2: (state.ebb0 >> 8) & 0x1f,
        n: (state.pll1 >> 8) & 0xf,
        m1: 2,
        m2,
        vco: 0,
        dot: 0,
    }
    .calc()
    .dot
}

// ── Registers ───────────────────────────────────────────────────────

/// `BXT_PORT_PLL_ENABLE`.
pub(crate) const fn pll_enable(port: Port) -> u64 {
    match port {
        Port::A => 0x46074,
        Port::B => 0x46078,
        Port::C => 0x4607c,
    }
}
const PORT_PLL_ENABLE: u32 = 1 << 31;
const PORT_PLL_LOCK: u32 = 1 << 30;
const PORT_PLL_REF_SEL: u32 = 1 << 27;
const PORT_PLL_POWER_ENABLE: u32 = 1 << 26;
const PORT_PLL_POWER_STATE: u32 = 1 << 25;

pub(crate) const fn ebb0(phy: Phy, ch: Channel) -> u64 {
    channel(phy, ch, 0x6c034, 0x6c340)
}
pub(crate) const fn ebb4(phy: Phy, ch: Channel) -> u64 {
    channel(phy, ch, 0x6c038, 0x6c344)
}
/// `BXT_PORT_PLL(phy, ch, idx)`.
pub(crate) const fn pll(phy: Phy, ch: Channel, idx: u64) -> u64 {
    channel(phy, ch, 0x6c100, 0x6c380) + idx * 4
}
const fn tx_dw5_ln0(phy: Phy, ch: Channel) -> u64 {
    channel(phy, ch, 0x6c514, 0x6c914) + lane_offset(0)
}
const fn tx_dw5_grp(phy: Phy, ch: Channel) -> u64 {
    channel(phy, ch, 0x6cd14, 0x6cf14)
}
const DCC_DELAY_RANGE_2: u32 = 1 << 8;
const fn pcs_dw12_ln01(phy: Phy, ch: Channel) -> u64 {
    channel(phy, ch, 0x6c430, 0x6c830)
}
const fn pcs_dw12_grp(phy: Phy, ch: Channel) -> u64 {
    channel(phy, ch, 0x6cc30, 0x6ce30)
}

fn rmw(io: &(impl MmioWindow + ?Sized), reg: u64, clear: u32, set: u32) {
    io.write32(reg, (io.read32(reg) & !clear) | set);
}

/// Why a port PLL did not come up.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PllError {
    NoDevice,
    /// Gemini Lake's PLL power state did not follow within 200 us.
    PowerTimeout,
    /// The PLL did not lock within 200 us.
    LockTimeout,
}

fn wait(
    io: &(impl MmioWindow + ?Sized),
    reg: u64,
    bit: u32,
    set: bool,
    error: PllError,
) -> Result<(), PllError> {
    let mut lost = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let v = io.read32(reg);
            lost = v == u32::MAX || !io.display_access_ok();
            lost || (v & bit != 0) == set
        },
        narf_time::Deadline::after_us(200),
    );
    match (lost, done) {
        (true, _) => Err(PllError::NoDevice),
        (false, true) => Ok(()),
        (false, false) => Err(error),
    }
}

/// `bxt_ddi_pll_enable`: non-SSC reference, Gemini Lake's PLL power, the
/// dividers and loop coefficients, a recalibration, the enable and lock,
/// Gemini Lake's DCC delay range, and the lane stagger.
pub(crate) fn enable(
    io: &(impl MmioWindow + ?Sized),
    glk: bool,
    port: Port,
    state: &State,
) -> Result<(), PllError> {
    let (phy, ch) = port_to_phy_channel(glk, port);
    let en = pll_enable(port);
    rmw(io, en, 0, PORT_PLL_REF_SEL);
    if glk {
        rmw(io, en, 0, PORT_PLL_POWER_ENABLE);
        wait(io, en, PORT_PLL_POWER_STATE, true, PllError::PowerTimeout)?;
    }
    rmw(io, ebb4(phy, ch), PORT_PLL_10BIT_CLK_ENABLE, 0);
    rmw(io, ebb0(phy, ch), 0x7 << 13 | 0x1f << 8, state.ebb0);
    rmw(io, pll(phy, ch, 0), 0xff, state.pll0);
    rmw(io, pll(phy, ch, 1), 0xf << 8, state.pll1);
    rmw(io, pll(phy, ch, 2), 0x3f_ffff, state.pll2);
    rmw(io, pll(phy, ch, 3), PORT_PLL_M2_FRAC_ENABLE, state.pll3);
    rmw(io, pll(phy, ch, 6), 0xf | 0x1f << 8 | 0x7 << 16, state.pll6);
    rmw(io, pll(phy, ch, 8), 0x3ff, state.pll8);
    rmw(io, pll(phy, ch, 9), 0x7 << 1, state.pll9);
    rmw(
        io,
        pll(phy, ch, 10),
        PORT_PLL_DCO_AMP_OVR_EN_H | 0xf << 10,
        state.pll10,
    );
    // Recalibrate with the new settings.
    let mut temp = io.read32(ebb4(phy, ch)) | PORT_PLL_RECALIBRATE;
    io.write32(ebb4(phy, ch), temp);
    temp = (temp & !PORT_PLL_10BIT_CLK_ENABLE) | state.ebb4;
    io.write32(ebb4(phy, ch), temp);
    rmw(io, en, 0, PORT_PLL_ENABLE);
    let _ = io.read32(en);
    wait(io, en, PORT_PLL_LOCK, true, PllError::LockTimeout)?;
    if glk {
        let dw5 = io.read32(tx_dw5_ln0(phy, ch)) | DCC_DELAY_RANGE_2;
        io.write32(tx_dw5_grp(phy, ch), dw5);
    }
    // Read lanes 0/1, write the group register for all lanes.
    let dw12 = io.read32(pcs_dw12_ln01(phy, ch)) & !(0x1f | LANESTAGGER_STRAP_OVRD);
    io.write32(pcs_dw12_grp(phy, ch), dw12 | state.pcsdw12);
    Ok(())
}

/// `bxt_ddi_pll_disable`: the enable bit off, then Gemini Lake's PLL power.
pub(crate) fn disable(
    io: &(impl MmioWindow + ?Sized),
    glk: bool,
    port: Port,
) -> Result<(), PllError> {
    let en = pll_enable(port);
    rmw(io, en, PORT_PLL_ENABLE, 0);
    let _ = io.read32(en);
    if glk {
        rmw(io, en, PORT_PLL_POWER_ENABLE, 0);
        wait(io, en, PORT_PLL_POWER_STATE, false, PllError::PowerTimeout)?;
    }
    Ok(())
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A PLL that locks and powers as soon as it is enabled.
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
            let mut value = value;
            if [Port::A, Port::B, Port::C]
                .iter()
                .any(|&p| pll_enable(p) == reg)
            {
                if value & PORT_PLL_ENABLE != 0 {
                    value |= PORT_PLL_LOCK;
                } else {
                    value &= !PORT_PLL_LOCK;
                }
                if value & PORT_PLL_POWER_ENABLE != 0 {
                    value |= PORT_PLL_POWER_STATE;
                } else {
                    value &= !PORT_PLL_POWER_STATE;
                }
            }
            self.values.borrow_mut().insert(reg, value);
        }
    }

    /// The DP table gives Linux's VCOs and dot clocks; HBR's state matches
    /// the coefficients and lane stagger expanded by hand.
    fn smoke_bxt_dpll_dp_state() -> TestResult {
        let hbr = dp_dividers(270_000);
        let rbr = dp_dividers(162_000);
        let hbr2 = dp_dividers(540_000);
        if hbr.vco != 5_400_000
            || hbr.dot != 270_000
            || rbr.dot != 162_000
            || hbr2.dot != 540_000
            || dp_dividers(123_456).dot != 162_000
        {
            return TestResult::Fail("bxt_dp_clk_val");
        }
        let state = hw_state(270_000, &hbr).unwrap();
        let want = State {
            ebb0: 4 << 13 | 1 << 8,
            pll0: 27,
            pll1: 1 << 8,
            pll2: 0,
            pll3: 0,
            pll6: 3 | 8 << 8 | 1 << 16,
            pll8: 9,
            pll9: 5 << 1,
            pll10: 15 << 10 | 1 << 27,
            ebb4: 1 << 13,
            pcsdw12: 1 << 6 | 0x0d,
        };
        if state != want || get_freq(&state) != 270_000 {
            return TestResult::Fail("HBR port PLL state");
        }
        // RBR: VCO 6.48 GHz, fractional M2.
        let state = hw_state(162_000, &rbr).unwrap();
        if rbr.vco != 6_480_000
            || state.pll3 != PORT_PLL_M2_FRAC_ENABLE
            || state.pll2 != 0x19_999a
            || state.pll6 != (4 | 9 << 8 | 3 << 16)
            || get_freq(&state) != 162_000
        {
            return TestResult::Fail("RBR port PLL state");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_bxt_dpll", smoke_bxt_dpll_dp_state);

    /// HDMI 148.5 MHz: a valid divider set within the BXT limits whose dot
    /// clock hits the target; an out-of-range clock finds none.
    fn smoke_bxt_dpll_hdmi_search() -> TestResult {
        let Some(d) = hdmi_dividers(148_500) else {
            return TestResult::Fail("148.5 MHz has dividers");
        };
        if !valid(&d) || d.dot.abs_diff(148_500) > 15 || hw_state(148_500, &d).is_none() {
            return TestResult::Fail("148.5 MHz dividers are valid and close");
        }
        if hdmi_dividers(700_000).is_some() {
            return TestResult::Fail("beyond the dot limit");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_bxt_dpll", smoke_bxt_dpll_hdmi_search);

    /// Gemini Lake port C: power, dividers, recalibration, lock, then the
    /// DCC range and lane stagger through the group registers.
    fn smoke_bxt_dpll_enable_order() -> TestResult {
        let io = Regs::default();
        let state = hw_state(270_000, &dp_dividers(270_000)).unwrap();
        if enable(&io, true, Port::C, &state).is_err() {
            return TestResult::Fail("enable");
        }
        let (phy, ch) = (Phy::Phy2, Channel::Ch0);
        let writes = io.writes.borrow().clone();
        let at = |reg: u64| writes.iter().position(|w| w.0 == reg);
        let en = pll_enable(Port::C);
        let first_en = at(en);
        let recal = writes
            .iter()
            .position(|w| w.0 == ebb4(phy, ch) && w.1 & PORT_PLL_RECALIBRATE != 0);
        let lock = writes
            .iter()
            .position(|w| w.0 == en && w.1 & PORT_PLL_ENABLE != 0);
        if ebb0(phy, ch) != 0x163034
            || pll(phy, ch, 10) != 0x163128
            || !(first_en < at(ebb0(phy, ch)) && at(pll(phy, ch, 10)) < recal && recal < lock)
            || at(tx_dw5_grp(phy, ch)) < lock
            || io.read32(pcs_dw12_grp(phy, ch)) != state.pcsdw12
            || io.read32(tx_dw5_grp(phy, ch)) & DCC_DELAY_RANGE_2 == 0
            || io.read32(ebb4(phy, ch)) & PORT_PLL_10BIT_CLK_ENABLE == 0
        {
            return TestResult::Fail("bxt_ddi_pll_enable order");
        }
        if disable(&io, true, Port::C).is_err()
            || io.read32(en) & (PORT_PLL_ENABLE | PORT_PLL_POWER_ENABLE) != 0
        {
            return TestResult::Fail("bxt_ddi_pll_disable");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_bxt_dpll",
        smoke_bxt_dpll_enable_order
    );
}

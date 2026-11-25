//! Broxton / Gemini Lake DPIO display PHY (Gen9 LP, display 9 and 10).
//!
//! MIT Linux v6.12 `display/intel_dpio_phy.c` (`bxt_dpio_phy_info`,
//! `glk_dpio_phy_info`, `bxt_port_to_phy_channel`, `_bxt_dpio_phy_init`,
//! `bxt_dpio_phy_init`, `bxt_dpio_phy_uninit`, `bxt_dpio_phy_is_enabled`,
//! `bxt_dpio_phy_verify_state`, `bxt_dpio_phy_set_signal_levels`, the lane
//! latency-optimization mask), `display/bxt_dpio_phy_regs.h`, `i915_reg.h`
//! (`BXT_P_CR_GT_DISP_PWRON`, `BXT_PHY_CTL_FAMILY`) and
//! `display/intel_ddi_buf_trans.c` (`_bxt_trans_dp`, `_bxt_trans_edp`,
//! `_bxt_trans_hdmi`, `bxt_get_buf_trans`).
//!
//! Broxton has two PHYs: PHY0 dual-channel for DDI B and C, PHY1 for DDI A.
//! Gemini Lake has three single-channel PHYs: PHY0 for DDI B, PHY1 for DDI
//! A, PHY2 for DDI C. PHY1 alone has an RCOMP resistor; the others copy its
//! calibrated GRC code. Swing levels are programmed per lane in the PHY,
//! not through `DDI_BUF_TRANS`. Nothing here has run on silicon.

use crate::intel_gpu_aux::MmioWindow;

/// A DPIO PHY.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Phy {
    Phy0,
    Phy1,
    Phy2,
}

/// A PHY channel: PHY0 on Broxton has two.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Channel {
    Ch0,
    Ch1,
}

/// A DDI port on Gen9 LP.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Port {
    A,
    B,
    C,
}

/// `struct bxt_dpio_phy_info`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct PhyInfo {
    pub dual_channel: bool,
    /// The PHY whose calibrated GRC code this one copies; `None` for the
    /// PHY with its own RCOMP resistor.
    pub rcomp_phy: Option<Phy>,
    /// Delay before releasing the common reset, in microseconds.
    pub reset_delay_us: u64,
    /// `BXT_P_CR_GT_DISP_PWRON` bit that has the PUNIT power the PHY.
    pub pwron_mask: u32,
    /// The port on each channel.
    pub ports: [Option<Port>; 2],
}

const BXT_PHYS: [(Phy, PhyInfo); 2] = [
    (
        Phy::Phy0,
        PhyInfo {
            dual_channel: true,
            rcomp_phy: Some(Phy::Phy1),
            reset_delay_us: 0,
            pwron_mask: 1 << 0,
            ports: [Some(Port::B), Some(Port::C)],
        },
    ),
    (
        Phy::Phy1,
        PhyInfo {
            dual_channel: false,
            rcomp_phy: None,
            reset_delay_us: 0,
            pwron_mask: 1 << 1,
            ports: [Some(Port::A), None],
        },
    ),
];

const GLK_PHYS: [(Phy, PhyInfo); 3] = [
    (
        Phy::Phy0,
        PhyInfo {
            dual_channel: false,
            rcomp_phy: Some(Phy::Phy1),
            reset_delay_us: 20,
            pwron_mask: 1 << 0,
            ports: [Some(Port::B), None],
        },
    ),
    (
        Phy::Phy1,
        PhyInfo {
            dual_channel: false,
            rcomp_phy: None,
            reset_delay_us: 20,
            pwron_mask: 1 << 3,
            ports: [Some(Port::A), None],
        },
    ),
    (
        Phy::Phy2,
        PhyInfo {
            dual_channel: false,
            rcomp_phy: Some(Phy::Phy1),
            reset_delay_us: 20,
            pwron_mask: 1 << 1,
            ports: [Some(Port::C), None],
        },
    ),
];

/// The PHY list of a Broxton (`glk` false) or Gemini Lake part.
pub(crate) fn phys(glk: bool) -> &'static [(Phy, PhyInfo)] {
    if glk {
        &GLK_PHYS
    } else {
        &BXT_PHYS
    }
}

/// `bxt_get_phy_info`. `None` for Broxton's absent PHY2.
pub(crate) fn info(glk: bool, phy: Phy) -> Option<PhyInfo> {
    phys(glk).iter().find(|(p, _)| *p == phy).map(|(_, i)| *i)
}

/// `bxt_port_to_phy_channel`.
pub(crate) fn port_to_phy_channel(glk: bool, port: Port) -> (Phy, Channel) {
    for (phy, info) in phys(glk) {
        if info.ports[0] == Some(port) {
            return (*phy, Channel::Ch0);
        }
        if info.dual_channel && info.ports[1] == Some(port) {
            return (*phy, Channel::Ch1);
        }
    }
    (Phy::Phy0, Channel::Ch0)
}

// ── Registers (`bxt_dpio_phy_regs.h`) ───────────────────────────────

const PHY0_BASE: u64 = 0x6c000;

/// `BXT_PHY_BASE`.
pub(crate) const fn phy_base(phy: Phy) -> u64 {
    match phy {
        Phy::Phy0 => PHY0_BASE,
        Phy::Phy1 => 0x162000,
        Phy::Phy2 => 0x163000,
    }
}

/// `_BXT_PHY(phy, reg)`: a common-lane register given at its PHY0 address.
const fn common(phy: Phy, reg: u64) -> u64 {
    phy_base(phy) - PHY0_BASE + reg
}

/// `_BXT_PHY_CH(phy, ch, ch0, ch1)`.
pub(crate) const fn channel(phy: Phy, ch: Channel, ch0: u64, ch1: u64) -> u64 {
    phy_base(phy)
        + match ch {
            Channel::Ch0 => ch0 - PHY0_BASE,
            Channel::Ch1 => ch1 - PHY0_BASE,
        }
}

/// `_BXT_LANE_OFFSET`.
pub(crate) const fn lane_offset(lane: u8) -> u64 {
    (lane as u64 >> 1) * 0x200 + (lane as u64 & 1) * 0x80
}

/// `BXT_P_CR_GT_DISP_PWRON`.
pub(crate) const DISP_PWRON: u64 = 0x138090;

/// `BXT_PHY_CTL_FAMILY`; `COMMON_RESET_DIS` is bit 31.
pub(crate) const fn ctl_family(phy: Phy) -> u64 {
    match phy {
        Phy::Phy0 => 0x64c90,
        Phy::Phy1 => 0x64c80,
        Phy::Phy2 => 0x64ca0,
    }
}
const COMMON_RESET_DIS: u32 = 1 << 31;

pub(crate) const fn cl1cm_dw0(phy: Phy) -> u64 {
    common(phy, 0x6c000)
}
const PHY_POWER_GOOD: u32 = 1 << 16;
const PHY_RESERVED: u32 = 1 << 7;

const fn cl1cm_dw9(phy: Phy) -> u64 {
    common(phy, 0x6c024)
}
const fn cl1cm_dw10(phy: Phy) -> u64 {
    common(phy, 0x6c028)
}
/// `IREF0RC_OFFSET` / `IREF1RC_OFFSET` [15:8], both 0xe4.
const IREF_OFFSET_MASK: u32 = 0xff << 8;
const IREF_OFFSET: u32 = 0xe4 << 8;

const fn cl1cm_dw28(phy: Phy) -> u64 {
    common(phy, 0x6c070)
}
/// `OCL1_POWER_DOWN_EN | DW28_OLDO_DYN_PWR_DOWN_EN | SUS_CLK_CONFIG`.
const DW28_POWER_GATING: u32 = 1 << 23 | 1 << 22 | 0x3;

const fn cl2cm_dw6(phy: Phy) -> u64 {
    common(phy, 0x6c358)
}
const DW6_OLDO_DYN_PWR_DOWN_EN: u32 = 1 << 28;

const fn ref_dw3(phy: Phy) -> u64 {
    common(phy, 0x6c18c)
}
const GRC_DONE: u32 = 1 << 22;

const fn ref_dw6(phy: Phy) -> u64 {
    common(phy, 0x6c198)
}
const fn ref_dw8(phy: Phy) -> u64 {
    common(phy, 0x6c1a0)
}
/// `GRC_DIS | GRC_RDY_OVRD`.
const GRC_OVERRIDE: u32 = 1 << 15 | 1 << 1;

/// `GRC_CODE` [31:24] of `BXT_PORT_REF_DW6`.
fn grc(io: &(impl MmioWindow + ?Sized), phy: Phy) -> u32 {
    io.read32(ref_dw6(phy)) >> 24
}

/// `GRC_CODE_FAST | GRC_CODE_SLOW | GRC_CODE_NOM` of one calibrated code.
const fn grc_code(grc: u32) -> u32 {
    (grc & 0xff) << 16 | (grc & 0xff) << 8 | (grc & 0xff)
}
const GRC_CODE_FIELDS: u32 = 0x00ff_ffff;

pub(crate) const fn pcs_dw10_ln01(phy: Phy, ch: Channel) -> u64 {
    channel(phy, ch, 0x6c428, 0x6c828)
}
pub(crate) const fn pcs_dw10_grp(phy: Phy, ch: Channel) -> u64 {
    channel(phy, ch, 0x6cc28, 0x6ce28)
}
/// `TX2_SWING_CALC_INIT | TX1_SWING_CALC_INIT`.
const SWING_CALC_INIT: u32 = 1 << 31 | 1 << 30;

pub(crate) const fn tx_dw2(phy: Phy, ch: Channel, lane: u8) -> u64 {
    channel(phy, ch, 0x6c508, 0x6c908) + lane_offset(lane)
}
pub(crate) const fn tx_dw3(phy: Phy, ch: Channel, lane: u8) -> u64 {
    channel(phy, ch, 0x6c50c, 0x6c90c) + lane_offset(lane)
}
pub(crate) const fn tx_dw4(phy: Phy, ch: Channel, lane: u8) -> u64 {
    channel(phy, ch, 0x6c510, 0x6c910) + lane_offset(lane)
}
pub(crate) const fn tx_dw14(phy: Phy, ch: Channel, lane: u8) -> u64 {
    channel(phy, ch, 0x6c538, 0x6c938) + lane_offset(lane)
}
/// `MARGIN_000` [23:16], `UNIQ_TRANS_SCALE` [15:8].
const MARGIN_SCALE_MASK: u32 = 0xffff << 8;
const SCALE_DCOMP_METHOD: u32 = 1 << 26;
/// `DE_EMPHASIS` [31:24].
const DE_EMPHASIS_MASK: u32 = 0xff << 24;
const LATENCY_OPTIM: u32 = 1 << 30;

fn rmw(io: &(impl MmioWindow + ?Sized), reg: u64, clear: u32, set: u32) {
    io.write32(reg, (io.read32(reg) & !clear) | set);
}

// ── Power ───────────────────────────────────────────────────────────

/// Why the PHY did not come up.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum PhyError {
    /// The platform has no such PHY.
    NoPhy,
    /// A register read all ones: the function is gone.
    NoDevice,
    /// The PHY did not report power good within 1 ms.
    PowerTimeout,
    /// The RCOMP PHY's GRC calibration did not finish within 10 ms.
    GrcTimeout,
}

fn wait(
    io: &(impl MmioWindow + ?Sized),
    reg: u64,
    mask: u32,
    value: u32,
    us: u64,
) -> Result<(), PhyError> {
    let mut lost = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let v = io.read32(reg);
            lost = !io.display_access_ok();
            lost || v & mask == value
        },
        narf_time::Deadline::after_us(us),
    );
    match (lost, done) {
        (true, _) => Err(PhyError::NoDevice),
        (false, true) => Ok(()),
        (false, false) => Err(PhyError::PowerTimeout),
    }
}

/// `bxt_dpio_phy_is_enabled`: powered by the PUNIT, power settled and out
/// of common reset.
pub(crate) fn is_enabled(io: &(impl MmioWindow + ?Sized), glk: bool, phy: Phy) -> bool {
    let Some(info) = info(glk, phy) else {
        return false;
    };
    io.read32(DISP_PWRON) & info.pwron_mask != 0
        && io.read32(cl1cm_dw0(phy)) & (PHY_POWER_GOOD | PHY_RESERVED) == PHY_POWER_GOOD
        && io.read32(ctl_family(phy)) & COMMON_RESET_DIS != 0
}

/// `bxt_dpio_phy_verify_state`: the rcomp offsets, power gating and (for a
/// PHY without its own resistor) the copied GRC code `grc`.
pub(crate) fn verify_state(
    io: &(impl MmioWindow + ?Sized),
    glk: bool,
    phy: Phy,
    copied_grc: u32,
) -> bool {
    let Some(info) = info(glk, phy) else {
        return false;
    };
    is_enabled(io, glk, phy)
        && io.read32(cl1cm_dw9(phy)) & IREF_OFFSET_MASK == IREF_OFFSET
        && io.read32(cl1cm_dw10(phy)) & IREF_OFFSET_MASK == IREF_OFFSET
        && io.read32(cl1cm_dw28(phy)) & DW28_POWER_GATING == DW28_POWER_GATING
        && (!info.dual_channel || io.read32(cl2cm_dw6(phy)) & DW6_OLDO_DYN_PWR_DOWN_EN != 0)
        && (info.rcomp_phy.is_none()
            || (io.read32(ref_dw6(phy)) & GRC_CODE_FIELDS == grc_code(copied_grc)
                && io.read32(ref_dw8(phy)) & GRC_OVERRIDE == GRC_OVERRIDE))
}

/// `_bxt_dpio_phy_init`. An enabled PHY in the expected state is left
/// alone. Returns the GRC code copied from the RCOMP PHY, if this PHY copies
/// one.
fn init_one(io: &(impl MmioWindow + ?Sized), glk: bool, phy: Phy) -> Result<Option<u32>, PhyError> {
    let info = info(glk, phy).ok_or(PhyError::NoPhy)?;
    if is_enabled(io, glk, phy) {
        let copied = info.rcomp_phy.map(|_| grc(io, phy));
        if verify_state(io, glk, phy, copied.unwrap_or(0)) {
            return Ok(copied);
        }
    }
    rmw(io, DISP_PWRON, 0, info.pwron_mask);
    // The PHY registers read all ones until they power up; the reserved bit
    // then reads its default zero (1 ms, "occasional timeouts" at 100 us).
    wait(
        io,
        cl1cm_dw0(phy),
        PHY_RESERVED | PHY_POWER_GOOD,
        PHY_POWER_GOOD,
        1_000,
    )?;
    rmw(io, cl1cm_dw9(phy), IREF_OFFSET_MASK, IREF_OFFSET);
    rmw(io, cl1cm_dw10(phy), IREF_OFFSET_MASK, IREF_OFFSET);
    rmw(io, cl1cm_dw28(phy), 0, DW28_POWER_GATING);
    if info.dual_channel {
        rmw(io, cl2cm_dw6(phy), 0, DW6_OLDO_DYN_PWR_DOWN_EN);
    }
    let mut copied = None;
    if let Some(rcomp) = info.rcomp_phy {
        wait(io, ref_dw3(rcomp), GRC_DONE, GRC_DONE, 10_000).map_err(|e| match e {
            PhyError::PowerTimeout => PhyError::GrcTimeout,
            other => other,
        })?;
        // This PHY has no RCOMP resistor: copy the calibrated code and
        // disable its own calibration.
        let value = grc(io, rcomp);
        io.write32(ref_dw6(phy), grc_code(value));
        rmw(io, ref_dw8(phy), 0, GRC_OVERRIDE);
        copied = Some(value);
    }
    if info.reset_delay_us != 0 {
        narf_scheduler::responsive_spin_until(
            || false,
            narf_time::Deadline::after_us(info.reset_delay_us),
        );
    }
    rmw(io, ctl_family(phy), 0, COMMON_RESET_DIS);
    Ok(copied)
}

/// `bxt_dpio_phy_uninit`: back into common reset, PUNIT power off.
pub(crate) fn uninit(io: &(impl MmioWindow + ?Sized), glk: bool, phy: Phy) {
    let Some(info) = info(glk, phy) else {
        return;
    };
    rmw(io, ctl_family(phy), COMMON_RESET_DIS, 0);
    rmw(io, DISP_PWRON, info.pwron_mask, 0);
}

/// `bxt_dpio_phy_init` (the `dpio-common-*` power wells' enable): the RCOMP
/// PHY is brought up first when this PHY copies its GRC code and it is off,
/// and powered down again after.
pub(crate) fn init(
    io: &(impl MmioWindow + ?Sized),
    glk: bool,
    phy: Phy,
) -> Result<Option<u32>, PhyError> {
    let info = info(glk, phy).ok_or(PhyError::NoPhy)?;
    let rcomp_was_off = info
        .rcomp_phy
        .is_some_and(|rcomp| !is_enabled(io, glk, rcomp));
    if let Some(rcomp) = info.rcomp_phy.filter(|_| rcomp_was_off) {
        init_one(io, glk, rcomp)?;
    }
    let result = init_one(io, glk, phy);
    if let Some(rcomp) = info.rcomp_phy.filter(|_| rcomp_was_off) {
        uninit(io, glk, rcomp);
    }
    result
}

// ── Signal levels ───────────────────────────────────────────────────

/// `struct bxt_ddi_buf_trans`: swing margin, scale, scale enable and
/// de-emphasis.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct Trans {
    pub margin: u8,
    pub scale: u8,
    pub enable: bool,
    pub deemphasis: u8,
}

const fn t(margin: u8, scale: u8, enable: u8, deemphasis: u8) -> Trans {
    Trans {
        margin,
        scale,
        enable: enable != 0,
        deemphasis,
    }
}

/// `_bxt_trans_dp`: 400/600/800/1200 mV at 0-9.5 dB.
pub(crate) const TRANS_DP: [Trans; 10] = [
    t(52, 0x9a, 0, 128),
    t(78, 0x9a, 0, 85),
    t(104, 0x9a, 0, 64),
    t(154, 0x9a, 0, 43),
    t(77, 0x9a, 0, 128),
    t(116, 0x9a, 0, 85),
    t(154, 0x9a, 0, 64),
    t(102, 0x9a, 0, 128),
    t(154, 0x9a, 0, 85),
    t(154, 0x9a, 1, 128),
];

/// `_bxt_trans_edp`: the low-vswing eDP table (200-300 mV).
pub(crate) const TRANS_EDP: [Trans; 10] = [
    t(26, 0, 0, 128),
    t(38, 0, 0, 112),
    t(48, 0, 0, 96),
    t(54, 0, 0, 69),
    t(32, 0, 0, 128),
    t(48, 0, 0, 104),
    t(54, 0, 0, 85),
    t(43, 0, 0, 128),
    t(54, 0, 0, 101),
    t(48, 0, 0, 128),
];

/// `_bxt_trans_hdmi`; the default entry is the last (`hdmi_default_entry`).
pub(crate) const TRANS_HDMI: [Trans; 10] = [
    t(52, 0x9a, 0, 128),
    t(52, 0x9a, 0, 85),
    t(52, 0x9a, 0, 64),
    t(42, 0x9a, 0, 43),
    t(77, 0x9a, 0, 128),
    t(77, 0x9a, 0, 85),
    t(77, 0x9a, 0, 64),
    t(102, 0x9a, 0, 128),
    t(102, 0x9a, 0, 85),
    t(154, 0x9a, 1, 128),
];

/// The output a swing table is chosen for.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Output {
    Dp,
    /// eDP with the VBT's low-vswing flag (`use_edp_low_vswing`).
    EdpLowVswing,
    Hdmi,
}

/// `bxt_get_buf_trans`: HDMI's table, the low-vswing eDP table, else DP's
/// (an eDP panel without the VBT flag takes DP's).
pub(crate) const fn buf_trans(output: Output) -> &'static [Trans; 10] {
    match output {
        Output::Hdmi => &TRANS_HDMI,
        Output::EdpLowVswing => &TRANS_EDP,
        Output::Dp => &TRANS_DP,
    }
}

/// `bxt_dpio_phy_set_signal_levels` for `lanes` lanes of `port` at one
/// swing `level` (`intel_ddi_level`, the same on every lane): stop the
/// swing calculation through the group register, program margin and scale,
/// scale enable and de-emphasis per lane, then restart it.
pub(crate) fn set_signal_levels(
    io: &(impl MmioWindow + ?Sized),
    glk: bool,
    port: Port,
    lanes: u8,
    entry: Trans,
) {
    let (phy, ch) = port_to_phy_channel(glk, port);
    // Read lanes 0/1, write the group register for all lanes.
    let calc = io.read32(pcs_dw10_ln01(phy, ch));
    io.write32(pcs_dw10_grp(phy, ch), calc & !SWING_CALC_INIT);
    for lane in 0..lanes {
        rmw(
            io,
            tx_dw2(phy, ch, lane),
            MARGIN_SCALE_MASK,
            u32::from(entry.margin) << 16 | u32::from(entry.scale) << 8,
        );
    }
    for lane in 0..lanes {
        rmw(
            io,
            tx_dw3(phy, ch, lane),
            SCALE_DCOMP_METHOD,
            if entry.enable { SCALE_DCOMP_METHOD } else { 0 },
        );
    }
    for lane in 0..lanes {
        rmw(
            io,
            tx_dw4(phy, ch, lane),
            DE_EMPHASIS_MASK,
            u32::from(entry.deemphasis) << 24,
        );
    }
    let calc = io.read32(pcs_dw10_ln01(phy, ch));
    io.write32(pcs_dw10_grp(phy, ch), calc | SWING_CALC_INIT);
}

/// `bxt_dpio_phy_calc_lane_lat_optim_mask`.
pub(crate) const fn lane_lat_optim_mask(lanes: u8) -> u8 {
    match lanes {
        2 => 1 << 2 | 1,
        4 => 1 << 3 | 1 << 2 | 1,
        _ => 0,
    }
}

/// `bxt_dpio_phy_set_lane_optim_mask`: `LATENCY_OPTIM` on each lane of
/// `mask`, cleared on the rest.
pub(crate) fn set_lane_optim_mask(
    io: &(impl MmioWindow + ?Sized),
    glk: bool,
    port: Port,
    mask: u8,
) {
    let (phy, ch) = port_to_phy_channel(glk, port);
    for lane in 0..4 {
        rmw(
            io,
            tx_dw14(phy, ch, lane),
            LATENCY_OPTIM,
            if mask & 1 << lane != 0 {
                LATENCY_OPTIM
            } else {
                0
            },
        );
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::collections::BTreeMap;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// A PHY that powers up and calibrates as soon as the PUNIT bit is set.
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
            // Fixture assumption: a written GRC code reads back in GRC_CODE,
            // which `_bxt_dpio_phy_init` reads to verify an enabled PHY.
            let value = if [Phy::Phy0, Phy::Phy2].iter().any(|&p| reg == ref_dw6(p)) {
                value | (value & 0xff) << 24
            } else {
                value
            };
            self.values.borrow_mut().insert(reg, value);
            if reg == DISP_PWRON {
                for (phy, info) in phys(true).iter().chain(phys(false)) {
                    if value & info.pwron_mask != 0 {
                        self.values
                            .borrow_mut()
                            .insert(cl1cm_dw0(*phy), PHY_POWER_GOOD);
                        self.values.borrow_mut().insert(ref_dw3(*phy), GRC_DONE);
                    }
                }
            }
        }
    }

    /// Register addresses expanded from `bxt_dpio_phy_regs.h` by hand.
    fn smoke_bxt_phy_registers_follow_linux() -> TestResult {
        let ok = cl1cm_dw0(Phy::Phy0) == 0x6c000
            && cl1cm_dw0(Phy::Phy1) == 0x162000
            && cl1cm_dw0(Phy::Phy2) == 0x163000
            && ref_dw6(Phy::Phy1) == 0x162198
            && ctl_family(Phy::Phy1) == 0x64c80
            && pcs_dw10_grp(Phy::Phy0, Channel::Ch1) == 0x6ce28
            && pcs_dw10_ln01(Phy::Phy1, Channel::Ch0) == 0x162428
            && tx_dw2(Phy::Phy0, Channel::Ch0, 0) == 0x6c508
            && tx_dw2(Phy::Phy0, Channel::Ch0, 1) == 0x6c588
            && tx_dw2(Phy::Phy0, Channel::Ch0, 3) == 0x6c788
            && tx_dw4(Phy::Phy0, Channel::Ch1, 2) == 0x6cb10
            && tx_dw14(Phy::Phy2, Channel::Ch0, 0) == 0x163538;
        if !ok {
            return TestResult::Fail("BXT PHY register map");
        }
        let map = [
            (false, Port::A, (Phy::Phy1, Channel::Ch0)),
            (false, Port::B, (Phy::Phy0, Channel::Ch0)),
            (false, Port::C, (Phy::Phy0, Channel::Ch1)),
            (true, Port::A, (Phy::Phy1, Channel::Ch0)),
            (true, Port::B, (Phy::Phy0, Channel::Ch0)),
            (true, Port::C, (Phy::Phy2, Channel::Ch0)),
        ];
        if map
            .iter()
            .any(|&(glk, port, want)| port_to_phy_channel(glk, port) != want)
            || info(false, Phy::Phy2).is_some()
        {
            return TestResult::Fail("bxt_port_to_phy_channel");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_bxt_phy",
        smoke_bxt_phy_registers_follow_linux
    );

    /// PHY0 copies PHY1's GRC code: PHY1 comes up first and is powered down
    /// again, PHY0 ends enabled in the verified state, and a second init
    /// writes nothing.
    fn smoke_bxt_phy_init_copies_grc() -> TestResult {
        let io = Regs::default();
        io.values
            .borrow_mut()
            .insert(ref_dw6(Phy::Phy1), 0x5a << 24);
        let copied = init(&io, false, Phy::Phy0);
        if copied != Ok(Some(0x5a))
            || !is_enabled(&io, false, Phy::Phy0)
            || is_enabled(&io, false, Phy::Phy1)
            || io.read32(ref_dw6(Phy::Phy0)) & GRC_CODE_FIELDS != 0x005a_5a5a
            || io.read32(ref_dw8(Phy::Phy0)) & GRC_OVERRIDE != GRC_OVERRIDE
            || io.read32(cl2cm_dw6(Phy::Phy0)) != DW6_OLDO_DYN_PWR_DOWN_EN
            || io.read32(cl1cm_dw9(Phy::Phy0)) != 0xe400
            || !verify_state(&io, false, Phy::Phy0, 0x5a)
        {
            return TestResult::Fail("PHY0 init copies PHY1's calibration");
        }
        // PHY1 was brought up first.
        let writes = io.writes.borrow().clone();
        let first_family = writes.iter().position(|w| w.0 == ctl_family(Phy::Phy1));
        let phy0_family = writes.iter().position(|w| w.0 == ctl_family(Phy::Phy0));
        if first_family >= phy0_family {
            return TestResult::Fail("the RCOMP PHY comes up first");
        }
        io.writes.borrow_mut().clear();
        // The PHY0 PWRON bit stays set while PHY1's was cleared again.
        if init(&io, false, Phy::Phy0) != Ok(Some(0x5a)) {
            return TestResult::Fail("re-init");
        }
        // PHY1 was off again, so re-init powers it for the check only; PHY0
        // itself is not reprogrammed.
        if io
            .writes
            .borrow()
            .iter()
            .any(|w| w.0 == cl1cm_dw9(Phy::Phy0) || w.0 == ref_dw6(Phy::Phy0))
        {
            return TestResult::Fail("a verified PHY is not reprogrammed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_bxt_phy",
        smoke_bxt_phy_init_copies_grc
    );

    /// One DP level on two lanes: the swing calculation stops and restarts
    /// through the group register, margin/scale/de-emphasis go per lane.
    fn smoke_bxt_phy_signal_levels() -> TestResult {
        let io = Regs::default();
        let entry = buf_trans(Output::Dp)[9];
        set_signal_levels(&io, false, Port::C, 2, entry);
        let (phy, ch) = (Phy::Phy0, Channel::Ch1);
        let writes = io.writes.borrow().clone();
        if writes.first() != Some(&(pcs_dw10_grp(phy, ch), 0))
            || writes.last() != Some(&(pcs_dw10_grp(phy, ch), SWING_CALC_INIT))
            || io.read32(tx_dw2(phy, ch, 1)) != 154 << 16 | 0x9a << 8
            || io.read32(tx_dw3(phy, ch, 0)) != SCALE_DCOMP_METHOD
            || io.read32(tx_dw4(phy, ch, 1)) != 128 << 24
            || writes.iter().any(|w| w.0 == tx_dw2(phy, ch, 2))
        {
            return TestResult::Fail("bxt_dpio_phy_set_signal_levels");
        }
        if buf_trans(Output::EdpLowVswing)[0] != t(26, 0, 0, 128)
            || buf_trans(Output::Hdmi)[9] != t(154, 0x9a, 1, 128)
            || lane_lat_optim_mask(4) != 0b1101
            || lane_lat_optim_mask(2) != 0b101
            || lane_lat_optim_mask(1) != 0
        {
            return TestResult::Fail("BXT swing tables");
        }
        set_lane_optim_mask(&io, true, Port::A, lane_lat_optim_mask(2));
        let (phy, ch) = (Phy::Phy1, Channel::Ch0);
        if io.read32(tx_dw14(phy, ch, 0)) != LATENCY_OPTIM
            || io.read32(tx_dw14(phy, ch, 1)) != 0
            || io.read32(tx_dw14(phy, ch, 2)) != LATENCY_OPTIM
        {
            return TestResult::Fail("lane latency optimization");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_bxt_phy", smoke_bxt_phy_signal_levels);
}

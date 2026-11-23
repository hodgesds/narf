//! Gen11 (Ice Lake / Elkhart Lake / Jasper Lake) DPLL programming.
//!
//! Two programming models live here; they must not be confused.
//!
//! ## ICL combo PLLs — the model ICL actually uses
//!
//! DISPLAY_VER >= 11 selects `icl_pll_mgr`
//! (`display/intel_dpll_mgr.c`, `intel_dpll_mgr_init`); the SKL
//! manager below it is DISPLAY_VER 9 only. Combo ports (DDI A/B)
//! take a combo PLL (DPLL0/1, plus DPLL4 on EHL/JSL); Type-C
//! ports take MG PLLs (Lane 8, not ported here).
//!
//! - compute: DP takes a fixed row per link rate and reference
//!   family (`icl_calc_dp_combo_pll` — `icl_dp_combo_pll_24MHz_values`
//!   / `icl_dp_combo_pll_19_2MHz_values`); HDMI/DSI takes the WRPLL
//!   divider search (`icl_calc_wrpll`, the CNL search). Both are
//!   already transcribed in [`crate::intel_gpu_pll`]
//!   (`combo_coeffs`, `hdmi_wrpll_coeffs`); this module only adds
//!   the ICL register map and the state packing / enable sequence
//!   around them.
//! - state: `icl_calc_dpll_state` packs CFGCR0 = DCO fraction << 10
//!   | DCO integer and CFGCR1 = QDIV ratio/mode | KDIV | PDIV |
//!   `DPLL_CFGCR1_CENTRAL_FREQ_8400` (3). On EHL/JSL at a 38.4 MHz
//!   reference the DCO fraction is halved first (Display WA
//!   #22010492432, `ehl_combo_pll_div_frac_wa_needed` — EHL B0+;
//!   the stepping is a caller input because this driver does not
//!   model steppings yet).
//! - write: `icl_dpll_write` writes CFGCR0 then CFGCR1 and posting-
//!   reads CFGCR1. The VBT AFC-startup `div0` write is skipped:
//!   Linux only writes it when `vbt.override_afc_startup` is set,
//!   and this driver does not parse that VBT field.
//! - enable: `combo_pll_enable` — power-enable the PLL (wait
//!   POWER_STATE, 1 ms), write the state, then set PLL_ENABLE
//!   (wait LOCK, 1 ms). `combo_pll_disable` / `icl_pll_disable`
//!   is the reverse: clear ENABLE (wait LOCK clear, 1 ms), then
//!   clear POWER_ENABLE (wait POWER_STATE clear, 1 ms). The DVFS
//!   pre/post sequences are no-ops here by Linux's own comment:
//!   the CDCLK code paths already set the voltage.
//! - register map: `ICL_DPLL_CFGCR0/1(pll)` — DPLL0 0x164000 /
//!   0x164004, DPLL1 0x164080 / 0x164084 (`_PICK_EVEN`: base +
//!   pll * 0x80); EHL DPLL4 is 0x164200 / 0x164204 by the same
//!   stride. Enable registers are `_DPLL0_ENABLE` 0x46010 /
//!   `_DPLL1_ENABLE` 0x46014, except EHL DPLL4, whose enable is
//!   `MG_PLL_ENABLE(0)` 0x46030 (`intel_combo_pll_enable_reg`).
//!
//! ## `DPLL_CTRL1` — the SKL (Gen9) model, NOT used on ICL
//!
//! The audit (§2.8) said "Gen9/Gen11 program DPLLs through
//! `DPLL_CTRL1` at 0x6C058" — that holds for Gen9 only. On ICL
//! `DPLL_CTRL1` is never touched: `intel_dpll_mgr.c` references
//! it solely from the SKL-manager functions
//! (`skl_ddi_pll_write_ctrl1`, `skl_ddi_pll_get_hw_state`,
//! `skl_ddi_hdmi_pll_dividers`, `skl_ddi_dp_set_dpll_hw_state`,
//! `skl_ddi_lcpll_get_freq`). The SKL section below transcribes
//! that register and its DP/HDMI ctrl1 computation verbatim so the
//! Gen9 lane starts grounded — but nothing on the ICL path calls
//! it, and wiring it into an ICL modeset would program a register
//! the hardware ignores on this generation. The SKL CFGCR1/2
//! registers and the SKL WRPLL divider search
//! (`skl_ddi_calculate_wrpll`, the even/odd-divider search over
//! the 8.4/9.0/9.6 GHz central frequencies) live in
//! [`crate::intel_gpu_gen9_dpll`] (Gen9 Lane 4), not here — this
//! module only supplies the shared `DPLL_CTRL1` helpers it
//! imports.
//!
//! ## Not ported (remainders)
//!
//! - The VBT AFC-startup `div0` override
//!   (`vbt.override_afc_startup`) — needs a VBT field this driver
//!   does not parse; default path writes no `div0`.
//!
//! MG PLL divisor search (`icl_mg_pll_find_divisors`), the MG
//! register programming for Type-C ports, and the TBT PLL fixed
//! rows (`icl_tbt_pll_24MHz_values` /
//! `icl_tbt_pll_19_2MHz_values`) landed in Lane 8 below.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_gt::Gen11Platform;
use crate::intel_gpu_pll::{
    encode_cfgcr0, DpllCoeffs, CFGCR1_CFREQ_8_4_GHZ, CFGCR1_KDIV_1, CFGCR1_PDIV_5,
};

/// ICL combo-PLL identifiers on this generation. DPLL0/1 serve
/// the combo ports; DPLL4 exists only on Elkhart/Jasper Lake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IclDpllId {
    /// Combo PLL 0 (DDI A).
    Dpll0,
    /// Combo PLL 1 (DDI B).
    Dpll1,
    /// Combo PLL 4 (EHL/JSL only).
    Dpll4,
}

impl IclDpllId {
    /// `_PICK_EVEN(pll, a, b)` index for the CFGCR macros:
    /// DPLL0 → 0, DPLL1 → 1, DPLL4 → 4.
    const fn index(self) -> u64 {
        match self {
            IclDpllId::Dpll0 => 0,
            IclDpllId::Dpll1 => 1,
            IclDpllId::Dpll4 => 4,
        }
    }
}

/// The fixed combo-PLL assignment for a Gen11 port.
///
/// Grounded in Linux `display/intel_dpll_mgr.c`
/// (`icl_compute_combo_phy_dpll`): on ICL the two combo PHYs are
/// hard-wired to DPLL0 (PORT_A) and DPLL1 (PORT_B); on EHL/JSL
/// the three combo PHYs take DPLL0/DPLL1/DPLL4 for PORT_A/B/C
/// (the only conflict-free fixed assignment — Linux picks any
/// free DPLL from the {DPLL4, DPLL1, DPLL0} pool at commit time,
/// and DPLL4 is the only one no other combo port uses).
/// Returns `None` where no fixed assignment exists:
///
/// - ICL PORT_C and above are Type-C ports driven by MG PLLs,
///   not combo DPLLs (see `intel_gpu_gen11_mg_phy`).
/// - EHL/JSL PORT_D shares combo PHY A with PORT_A and has no
///   dedicated PLL — Linux arbitrates the shared {0, 1, 4} pool
///   per atomic commit, a sharing model this driver does not
///   have; callers refuse it with a documented remainder.
pub fn combo_dpll_id(platform: Gen11Platform, ddi: Ddi) -> Option<IclDpllId> {
    match (platform, ddi) {
        (Gen11Platform::IceLake, Ddi::A) => Some(IclDpllId::Dpll0),
        (Gen11Platform::IceLake, Ddi::B) => Some(IclDpllId::Dpll1),
        (Gen11Platform::ElkhartLake, Ddi::A) | (Gen11Platform::JasperLake, Ddi::A) => {
            Some(IclDpllId::Dpll0)
        }
        (Gen11Platform::ElkhartLake, Ddi::B) | (Gen11Platform::JasperLake, Ddi::B) => {
            Some(IclDpllId::Dpll1)
        }
        (Gen11Platform::ElkhartLake, Ddi::C) | (Gen11Platform::JasperLake, Ddi::C) => {
            Some(IclDpllId::Dpll4)
        }
        _ => None,
    }
}

/// `_ICL_DPLL0_CFGCR0` 0x164000, stride 0x80 per PLL
/// (`ICL_DPLL_CFGCR0(pll)`).
pub const fn icl_dpll_cfgcr0(id: IclDpllId) -> u64 {
    0x164000 + id.index() * 0x80
}

/// `_ICL_DPLL0_CFGCR1` 0x164004, stride 0x80 per PLL
/// (`ICL_DPLL_CFGCR1(pll)`).
pub const fn icl_dpll_cfgcr1(id: IclDpllId) -> u64 {
    0x164004 + id.index() * 0x80
}

/// `_DPLL0_ENABLE` 0x46010 / `_DPLL1_ENABLE` 0x46014; EHL DPLL4
/// uses `MG_PLL_ENABLE(0)` = `_MG_PLL1_ENABLE` 0x46030
/// (`intel_combo_pll_enable_reg`).
pub const fn icl_dpll_enable_reg(id: IclDpllId) -> u64 {
    match id {
        IclDpllId::Dpll0 => 0x46010,
        IclDpllId::Dpll1 => 0x46014,
        IclDpllId::Dpll4 => 0x46030,
    }
}

/// `PLL_ENABLE` (bit 31, shared by the DPLL enable registers).
pub const PLL_ENABLE: u32 = 1 << 31;
/// `PLL_LOCK` (bit 30).
pub const PLL_LOCK: u32 = 1 << 30;
/// `PLL_POWER_ENABLE` (bit 27).
pub const PLL_POWER_ENABLE: u32 = 1 << 27;
/// `PLL_POWER_STATE` (bit 26).
pub const PLL_POWER_STATE: u32 = 1 << 26;

/// `icl_calc_dpll_state`: pack computed coefficients into the
/// (CFGCR0, CFGCR1) pair. `ehl_div_frac_wa` applies Display WA
/// #22010492432 (halve the DCO fraction — `DIV_ROUND_CLOSEST(frac, 2)`)
/// for EHL B0+ at a 38.4 MHz reference; false on ICL and elsewhere.
/// CFGCR1 already carries `DPLL_CFGCR1_CENTRAL_FREQ_8400` (3) in the
/// coefficients `intel_gpu_pll` produces.
pub fn calc_dpll_state(coeffs: &DpllCoeffs, ehl_div_frac_wa: bool) -> (u32, u32) {
    let mut coeffs = *coeffs;
    if ehl_div_frac_wa {
        coeffs.dco_fraction = coeffs.dco_fraction.div_ceil(2);
    }
    (encode_cfgcr0(&coeffs), coeffs.cfgcr1)
}

/// `icl_dpll_write`: write CFGCR0 then CFGCR1, then posting-read
/// CFGCR1.
pub fn dpll_write(io: &(impl MmioWindow + ?Sized), id: IclDpllId, cfgcr0: u32, cfgcr1: u32) {
    io.write32(icl_dpll_cfgcr0(id), cfgcr0);
    io.write32(icl_dpll_cfgcr1(id), cfgcr1);
    let _ = io.read32(icl_dpll_cfgcr1(id));
}

/// DPLL power/enable failure modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DpllError {
    /// Current access was lost or a register read all-ones.
    NoDevice,
    /// A lock/power-state transition did not arrive inside 1 ms.
    Timeout,
}

fn wait(io: &(impl MmioWindow + ?Sized), r: u64, mask: u32, want: u32) -> Result<(), DpllError> {
    let mut lost = false;
    let done = narf_scheduler::responsive_spin_until(
        || {
            let value = io.read32(r);
            lost = value == u32::MAX || !io.display_access_ok();
            lost || value & mask == want
        },
        narf_time::Deadline::after_us(1_000),
    );
    if lost {
        Err(DpllError::NoDevice)
    } else if done {
        Ok(())
    } else {
        Err(DpllError::Timeout)
    }
}

/// Shared power/enable sequence for an ICL PLL whose state lives
/// in a CFGCR0/CFGCR1 register pair (`icl_pll_power_enable` +
/// state write + `icl_pll_enable`): power-enable the PLL (wait
/// POWER_STATE), write the state, then set PLL_ENABLE (wait
/// LOCK). 1 ms per wait (`intel_de_wait_for_*_ms(.., 1)`; the
/// spec's own lock timeout is 600 µs, the power timeout
/// "immediate").
pub fn pll_enable_at(
    io: &(impl MmioWindow + ?Sized),
    enable_reg: u64,
    cfgcr0_reg: u64,
    cfgcr1_reg: u64,
    cfgcr0: u32,
    cfgcr1: u32,
) -> Result<(), DpllError> {
    let cur = io.read32(enable_reg);
    if cur == u32::MAX || !io.display_access_ok() {
        return Err(DpllError::NoDevice);
    }
    // Status bits (LOCK, POWER_STATE) are read-only; never write
    // them back — the same rule the CDCLK PLL disable follows.
    let clean = cur & !(PLL_LOCK | PLL_POWER_STATE);
    io.write32(enable_reg, clean | PLL_POWER_ENABLE);
    wait(io, enable_reg, PLL_POWER_STATE, PLL_POWER_STATE)?;
    io.write32(cfgcr0_reg, cfgcr0);
    io.write32(cfgcr1_reg, cfgcr1);
    let _ = io.read32(cfgcr1_reg);
    let cur = io.read32(enable_reg);
    if cur == u32::MAX || !io.display_access_ok() {
        return Err(DpllError::NoDevice);
    }
    io.write32(
        enable_reg,
        (cur & !(PLL_LOCK | PLL_POWER_STATE)) | PLL_ENABLE,
    );
    wait(io, enable_reg, PLL_LOCK, PLL_LOCK)
}

/// Shared disable sequence for an ICL PLL (`icl_pll_disable`):
/// clear PLL_ENABLE (wait LOCK clear), then clear POWER_ENABLE
/// (wait POWER_STATE clear). 1 ms per wait.
pub fn pll_disable_at(io: &(impl MmioWindow + ?Sized), enable_reg: u64) -> Result<(), DpllError> {
    let cur = io.read32(enable_reg);
    if cur == u32::MAX || !io.display_access_ok() {
        return Err(DpllError::NoDevice);
    }
    io.write32(
        enable_reg,
        (cur & !(PLL_LOCK | PLL_POWER_STATE)) & !PLL_ENABLE,
    );
    wait(io, enable_reg, PLL_LOCK, 0)?;
    let cur = io.read32(enable_reg);
    if cur == u32::MAX || !io.display_access_ok() {
        return Err(DpllError::NoDevice);
    }
    io.write32(
        enable_reg,
        (cur & !(PLL_LOCK | PLL_POWER_STATE)) & !PLL_POWER_ENABLE,
    );
    wait(io, enable_reg, PLL_POWER_STATE, 0)
}

/// `combo_pll_enable` (`icl_pll_power_enable` + `icl_dpll_write` +
/// `icl_pll_enable`): power-enable the PLL (wait POWER_STATE),
/// write the state, then set PLL_ENABLE (wait LOCK). 1 ms per wait
/// (`intel_de_wait_for_*_ms(.., 1)`; the spec's own lock timeout
/// is 600 µs, the power timeout "immediate").
pub fn combo_pll_enable(
    io: &(impl MmioWindow + ?Sized),
    id: IclDpllId,
    cfgcr0: u32,
    cfgcr1: u32,
) -> Result<(), DpllError> {
    pll_enable_at(
        io,
        icl_dpll_enable_reg(id),
        icl_dpll_cfgcr0(id),
        icl_dpll_cfgcr1(id),
        cfgcr0,
        cfgcr1,
    )
}

/// `combo_pll_disable` (`icl_pll_disable`): clear PLL_ENABLE
/// (wait LOCK clear), then clear POWER_ENABLE (wait POWER_STATE
/// clear). 1 ms per wait.
pub fn combo_pll_disable(io: &(impl MmioWindow + ?Sized), id: IclDpllId) -> Result<(), DpllError> {
    pll_disable_at(io, icl_dpll_enable_reg(id))
}

// ── MG PLL (Type-C ports, IceLake) ────────────────────────────
//
// The MG (multi-gate) PLLs drive the Type-C ports' DDI clock.
// Grounded in Linux `display/intel_dpll_mgr.c`
// (`icl_mg_pll_find_divisors`, `icl_calc_mg_pll_state`,
// `icl_mg_pll_write`, `mg_pll_enable`, `icl_pll_disable`) and
// `display/intel_mg_phy_regs.h`.
//
// Unlike the combo PLLs the MG state is *computed*, not a table
// row: the divisor search picks (div1, div2) for the requested
// port clock, and `icl_calc_mg_pll_state` packs the DCO
// parameters into the MG register layout (which differs from
// the DKL layout in `intel_gpu_gen12_tc.rs` — the divisor math
// is shared, the packing is not).
//
// `tc` is the 0-based Type-C index (TC1 = 0 … TC4 = 3); Linux
// names the same ports 1-based. Every MG register strides
// 0x1000 per port from its PORT1 (TC1) base.

/// `MG_PLL_ENABLE(tc_port)` (`display/intel_display_regs.h`):
/// `_MG_PLL1_ENABLE` 0x46030, stride 4. The same register bank
/// carries the combo DPLL4 enable (EHL/JSL) at TC1's slot.
pub const fn mg_pll_enable_reg(tc: u8) -> u64 {
    0x46030 + tc as u64 * 4
}

/// MG PLL register block base for a TC port:
/// `MG_PLL_DIV0(tc_port)` 0x168A00, stride 0x1000.
pub const fn mg_pll_block_base(tc: u8) -> u64 {
    0x168A00 + tc as u64 * 0x1000
}

/// `MG_PLL_DIV0(tc_port)` — fraction-enable + FBDIV frac/int.
pub const fn mg_pll_div0(tc: u8) -> u64 {
    mg_pll_block_base(tc)
}

/// `MG_PLL_DIV1(tc_port)` — IREF_NDIVRATIO + DITHER_DIV_2 +
/// NDIVRATIO + FBPREDIV.
pub const fn mg_pll_div1(tc: u8) -> u64 {
    mg_pll_block_base(tc) + 4
}

/// `MG_PLL_LF(tc_port)` — TDC target + loop-filter coeffs.
pub const fn mg_pll_lf(tc: u8) -> u64 {
    mg_pll_block_base(tc) + 8
}

/// `MG_PLL_FRAC_LOCK(tc_port)` — lock criteria + feed-forward gain.
pub const fn mg_pll_frac_lock(tc: u8) -> u64 {
    mg_pll_block_base(tc) + 0xC
}

/// `MG_PLL_SSC(tc_port)` — spread-spectrum fields (zero on ICL:
/// `use_ssc` is hardcoded false).
pub const fn mg_pll_ssc(tc: u8) -> u64 {
    mg_pll_block_base(tc) + 0x10
}

/// `MG_PLL_BIAS(tc_port)`.
pub const fn mg_pll_bias(tc: u8) -> u64 {
    mg_pll_block_base(tc) + 0x14
}

/// `MG_PLL_TDC_COLDST_BIAS(tc_port)`.
pub const fn mg_pll_tdc_coldst_bias(tc: u8) -> u64 {
    mg_pll_block_base(tc) + 0x18
}

/// `MG_REFCLKIN_CTL(tc_port)` (`display/intel_mg_phy_regs.h`):
/// PORT1 0x16892C, stride 0x1000.
pub const fn mg_pll_refclkin_ctl(tc: u8) -> u64 {
    0x16892C + tc as u64 * 0x1000
}

/// `MG_CLKTOP2_CORECLKCTL1(tc_port)`: PORT1 0x1688D8, stride 0x1000.
pub const fn mg_pll_clktop2_coreclkctl1(tc: u8) -> u64 {
    0x1688D8 + tc as u64 * 0x1000
}

/// `MG_CLKTOP2_HSCLKCTL(tc_port)`: PORT1 0x1688D4, stride 0x1000.
pub const fn mg_pll_clktop2_hsclkctl(tc: u8) -> u64 {
    0x1688D4 + tc as u64 * 0x1000
}

/// `MG_REFCLKIN_CTL_OD_2_MUX` mask (bits [10:8]).
const MG_REFCLKIN_CTL_OD_2_MUX_MASK: u32 = 0x7 << 8;

/// `MG_CLKTOP2_CORECLKCTL1_A_DIVRATIO` mask (bits [15:8]).
const MG_CORECLKCTL1_A_DIVRATIO_MASK: u32 = 0xFF << 8;

/// `MG_CLKTOP2_HSCLKCTL` masks: TLINEDRV_CLKSEL [15:14],
/// CORE_INPUTSEL [16], HSDIV [13:12], DSDIV [11:8].
const MG_HSCLKCTL_TLINEDRV_MASK: u32 = 0x3 << 14;
const MG_HSCLKCTL_CORE_INPUTSEL_MASK: u32 = 0x1 << 16;
const MG_HSCLKCTL_HSDIV_MASK: u32 = 0x3 << 12;
const MG_HSCLKCTL_DSDIV_MASK: u32 = 0xF << 8;

/// Computed MG PLL state: the packed register values for one
/// port clock, mirroring Linux's `intel_dpll_hw_state` MG
/// fields (`mg_pll_*` + the two write masks).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MgPllState {
    pub refclkin_ctl: u32,
    pub clktop2_coreclkctl1: u32,
    pub clktop2_hsclkctl: u32,
    pub div0: u32,
    pub div1: u32,
    pub lf: u32,
    pub frac_lock: u32,
    pub ssc: u32,
    pub bias: u32,
    pub tdc_coldst_bias: u32,
    /// Write mask for `MG_PLL_BIAS` (0 at 38.4 MHz refclk — the
    /// register is left untouched there).
    pub bias_mask: u32,
    /// Write mask for `MG_PLL_TDC_COLDST_BIAS` (COLDSTART only
    /// at 38.4 MHz refclk).
    pub tdc_coldst_bias_mask: u32,
}

/// `icl_mg_pll_find_divisors` + `icl_calc_mg_pll_state`
/// (non-DKL branch, `use_ssc` hardcoded false — ICL never uses
/// spread spectrum on the MG PLL).
///
/// - DP: the DCO is forced to exactly 8,100,000 kHz
///   (`min_dco_freq = max_dco_freq = 8100000`).
/// - HDMI/non-DP: the DCO must land in [7,992,000, 10,000,000].
/// - `div1` scans {7, 5, 3, 2} and `div2` scans 10 down to 1;
///   the first pair whose `dco = div1 * div2 * clock * 5` is in
///   range wins. `div2 >= 2` selects `a_divratio` 10 (DP) / 5
///   (HDMI) with `tlinedrv` 2; otherwise both are 5 / 0.
///   `inputsel` is 0 for DP, 1 for HDMI.
/// - `m1div` starts at 2 and doubles to 4 when `m2div_int`
///   would exceed 255; still over 255 is `-EINVAL` → `None`.
/// - Refclk is 19200, 24000 or 38400 kHz; anything else is
///   `-EINVAL` → `None`.
///
/// `None` also when no (div1, div2) pair reaches the DCO range
/// for the requested clock.
pub fn mg_pll_state(port_clock_khz: u32, is_dp: bool, refclk_khz: u32) -> Option<MgPllState> {
    // ── icl_mg_pll_find_divisors ──
    let (mut div1, mut div2) = (0u32, 0u32);
    let mut dco: u64 = 0;
    'search: for cand1 in [7u32, 5, 3, 2] {
        for cand2 in (1..=10u32).rev() {
            let cand_dco = cand1 as u64 * cand2 as u64 * port_clock_khz as u64 * 5;
            let in_range = if is_dp {
                cand_dco == 8_100_000
            } else {
                (7_992_000..=10_000_000).contains(&cand_dco)
            };
            if in_range {
                div1 = cand1;
                div2 = cand2;
                dco = cand_dco;
                break 'search;
            }
        }
    }
    if div1 == 0 {
        return None;
    }
    let (a_divratio, tlinedrv) = if div2 >= 2 {
        (if is_dp { 10u32 } else { 5u32 }, 2u32)
    } else {
        (5, 0)
    };
    let inputsel = if is_dp { 0u32 } else { 1u32 };
    let hsdiv = match div1 {
        2 => 0u32,
        3 => 1,
        5 => 2,
        7 => 3,
        _ => return None,
    };

    // ── icl_calc_mg_pll_state (non-DKL) ──
    let mut m1div = 2u32;
    let mut m2div_int = (dco / (refclk_khz as u64 * m1div as u64)) as u32;
    if m2div_int > 255 {
        m1div = 4;
        m2div_int = (dco / (refclk_khz as u64 * m1div as u64)) as u32;
        if m2div_int > 255 {
            return None;
        }
    }
    let m2div_rem = (dco % (refclk_khz as u64 * m1div as u64)) as u32;
    let m2div_frac = (m2div_rem as u64 * (1u64 << 22) / (refclk_khz as u64 * m1div as u64)) as u32;
    let (iref_ndiv, iref_trim, iref_pulse_w) = match refclk_khz {
        19_200 => (1u32, 28u32, 1u32),
        24_000 => (1, 25, 2),
        38_400 => (2, 28, 1),
        _ => return None,
    };
    let tdc_targetcnt = (2_000_000_000u32 / (132 * refclk_khz) + 5) / 10;
    // use_ssc is false, so the gain applies only when the
    // fractional remainder is non-zero.
    let feedfwgain = if m2div_rem > 0 {
        m1div * 100_000_000 / (dco as u32 * 3 / 10)
    } else {
        0
    };
    let (prop_coeff, int_coeff) = if dco >= 9_000_000 {
        (5u32, 10u32)
    } else {
        (4, 8)
    };

    let div0 = (if m2div_rem > 0 { 1u32 << 30 } else { 0 }) | (m2div_frac << 8) | m2div_int;
    let div1_reg = (iref_ndiv << 16) | (1 << 12) | (1 << 4) | m1div;
    let lf = (tdc_targetcnt << 24) | (1 << 20) | (1 << 16) | (int_coeff << 8) | prop_coeff;
    let frac_lock = (1 << 18)
        | (1 << 16)
        | (10 << 11)
        | (1 << 10)
        | feedfwgain
        | (if m2div_rem > 0 { 1 << 8 } else { 0 });
    // SSC: SSC_EN off (use_ssc false), SSC_TYPE 2, STEPLENGTH 0,
    // STEPNUM 4 (steplog), FLLEN set, STEPSIZE 0.
    let ssc = (2 << 26) | (4 << 10) | (1 << 9);
    let bias = (3 << 30) | (0x3F << 24) | (10 << 16) | (1 << 15) | (12 << 8) | (4 << 5) | iref_trim;
    let tdc_coldst_bias = (1 << 27) | (iref_pulse_w << 17) | (1 << 16) | (1 << 2) | 3;
    // 38.4 MHz refclk: only the COLDSTART bit of TDC_COLDST_BIAS
    // is written and BIAS is left untouched.
    let (bias_mask, tdc_coldst_bias_mask) = if refclk_khz == 38_400 {
        (0, 1 << 16)
    } else {
        (u32::MAX, u32::MAX)
    };
    Some(MgPllState {
        refclkin_ctl: 1 << 8,
        clktop2_coreclkctl1: a_divratio << 8,
        clktop2_hsclkctl: (tlinedrv << 14) | (inputsel << 16) | (hsdiv << 12) | (div2 << 8),
        div0,
        div1: div1_reg,
        lf,
        frac_lock,
        ssc,
        bias: bias & bias_mask,
        tdc_coldst_bias: tdc_coldst_bias & tdc_coldst_bias_mask,
        bias_mask,
        tdc_coldst_bias_mask,
    })
}

/// `icl_mg_pll_write`: RMW the three clock-top registers under
/// their field masks, plain-write DIV0/DIV1/LF/FRAC_LOCK/SSC,
/// RMW BIAS and TDC_COLDST_BIAS under their masks, then a
/// posting read of TDC_COLDST_BIAS.
pub fn mg_pll_write(io: &(impl MmioWindow + ?Sized), tc: u8, state: &MgPllState) {
    fn rmw(io: &(impl MmioWindow + ?Sized), reg: u64, mask: u32, val: u32) {
        let cur = io.read32(reg);
        io.write32(reg, (cur & !mask) | (val & mask));
    }
    rmw(
        io,
        mg_pll_refclkin_ctl(tc),
        MG_REFCLKIN_CTL_OD_2_MUX_MASK,
        state.refclkin_ctl,
    );
    rmw(
        io,
        mg_pll_clktop2_coreclkctl1(tc),
        MG_CORECLKCTL1_A_DIVRATIO_MASK,
        state.clktop2_coreclkctl1,
    );
    rmw(
        io,
        mg_pll_clktop2_hsclkctl(tc),
        MG_HSCLKCTL_TLINEDRV_MASK
            | MG_HSCLKCTL_CORE_INPUTSEL_MASK
            | MG_HSCLKCTL_HSDIV_MASK
            | MG_HSCLKCTL_DSDIV_MASK,
        state.clktop2_hsclkctl,
    );
    io.write32(mg_pll_div0(tc), state.div0);
    io.write32(mg_pll_div1(tc), state.div1);
    io.write32(mg_pll_lf(tc), state.lf);
    io.write32(mg_pll_frac_lock(tc), state.frac_lock);
    io.write32(mg_pll_ssc(tc), state.ssc);
    rmw(io, mg_pll_bias(tc), state.bias_mask, state.bias);
    rmw(
        io,
        mg_pll_tdc_coldst_bias(tc),
        state.tdc_coldst_bias_mask,
        state.tdc_coldst_bias,
    );
    let _ = io.read32(mg_pll_tdc_coldst_bias(tc));
}

/// `mg_pll_enable`: `icl_pll_power_enable` + `icl_mg_pll_write`
/// + `icl_pll_enable` on the MG enable register. 1 ms per wait.
pub fn mg_pll_enable(
    io: &(impl MmioWindow + ?Sized),
    tc: u8,
    state: &MgPllState,
) -> Result<(), DpllError> {
    let enable = mg_pll_enable_reg(tc);
    let cur = io.read32(enable);
    if cur == u32::MAX || !io.display_access_ok() {
        return Err(DpllError::NoDevice);
    }
    let clean = cur & !(PLL_LOCK | PLL_POWER_STATE);
    io.write32(enable, clean | PLL_POWER_ENABLE);
    wait(io, enable, PLL_POWER_STATE, PLL_POWER_STATE)?;
    mg_pll_write(io, tc, state);
    let cur = io.read32(enable);
    if cur == u32::MAX || !io.display_access_ok() {
        return Err(DpllError::NoDevice);
    }
    io.write32(enable, (cur & !(PLL_LOCK | PLL_POWER_STATE)) | PLL_ENABLE);
    wait(io, enable, PLL_LOCK, PLL_LOCK)
}

/// `mg_pll_disable` (`icl_pll_disable` on the MG enable
/// register): clear PLL_ENABLE (wait LOCK clear), then clear
/// POWER_ENABLE (wait POWER_STATE clear). 1 ms per wait.
pub fn mg_pll_disable(io: &(impl MmioWindow + ?Sized), tc: u8) -> Result<(), DpllError> {
    pll_disable_at(io, mg_pll_enable_reg(tc))
}

// ── TBT PLL (Type-C ports, IceLake) ───────────────────────────
//
// The Thunderbolt PLL is the alternate clock source for TC
// ports in TBT alt mode. Grounded in Linux
// `display/intel_dpll_mgr.c` (`icl_tbt_pll_24MHz_values`,
// `icl_tbt_pll_19_2MHz_values`, `icl_calc_tbt_pll`,
// `icl_tbt_pll_enable`) and `display/intel_dpll_mgr.h`
// (`DPLL_ID_ICL_TBTPLL` = 2).
//
// The rows are fixed `skl_wrpll_params` — the same 8.1 GHz DCO
// as the DP combo rows, P/5 K/1 — and the state packs through
// the shared CFGCR0/CFGCR1 pair at `ICL_DPLL_CFGCR0(2)`.
// `icl_ddi_tbt_pll_get_freq` warns and returns 0 (the PLL
// outputs several frequencies; selection happens at the DDI
// clock mux), so there is no frequency accessor here.
//
// Alt-mode entry/exit (the TC subsystem side) is NOT in this
// lane — only the PLL rows and the enable sequence. The MG
// signal-levels path returns early in TBT alt mode, matching
// Linux.

/// `TBT_PLL_ENABLE` (`display/intel_display_regs.h:2954`).
pub const TBT_PLL_ENABLE: u64 = 0x46020;

/// `ICL_DPLL_CFGCR0(2)` — TBT PLL config register 0
/// (0x164000 + 2 * 0x80).
pub const TBT_PLL_CFGCR0: u64 = 0x164100;

/// `ICL_DPLL_CFGCR1(2)` — TBT PLL config register 1.
pub const TBT_PLL_CFGCR1: u64 = 0x164104;

/// `icl_calc_tbt_pll` (DISPLAY_VER < 12): the 24 MHz refclk
/// takes the 24 MHz row; 19.2 and 38.4 MHz both take the
/// 19.2 MHz row. Anything else is `-EINVAL` → `None`.
/// The returned coefficients pack with `calc_dpll_state`
/// (no EHL div-frac WA — the TBT rows are not combo rows).
pub fn tbt_pll_coeffs(refclk_khz: u32) -> Option<DpllCoeffs> {
    match refclk_khz {
        24_000 => Some(DpllCoeffs {
            dco_integer: 0x151,
            dco_fraction: 0x4000,
            cfgcr1: CFGCR1_KDIV_1 | CFGCR1_PDIV_5 | CFGCR1_CFREQ_8_4_GHZ,
        }),
        19_200 | 38_400 => Some(DpllCoeffs {
            dco_integer: 0x1A5,
            dco_fraction: 0x7000,
            cfgcr1: CFGCR1_KDIV_1 | CFGCR1_PDIV_5 | CFGCR1_CFREQ_8_4_GHZ,
        }),
        _ => None,
    }
}

/// `icl_tbt_pll_enable`: `icl_pll_power_enable` +
/// `icl_dpll_write` + `icl_pll_enable` on `TBT_PLL_ENABLE`.
/// 1 ms per wait.
pub fn tbt_pll_enable(
    io: &(impl MmioWindow + ?Sized),
    cfgcr0: u32,
    cfgcr1: u32,
) -> Result<(), DpllError> {
    pll_enable_at(
        io,
        TBT_PLL_ENABLE,
        TBT_PLL_CFGCR0,
        TBT_PLL_CFGCR1,
        cfgcr0,
        cfgcr1,
    )
}

/// `icl_pll_disable` on `TBT_PLL_ENABLE`: clear PLL_ENABLE
/// (wait LOCK clear), then clear POWER_ENABLE (wait
/// POWER_STATE clear). 1 ms per wait.
pub fn tbt_pll_disable(io: &(impl MmioWindow + ?Sized)) -> Result<(), DpllError> {
    pll_disable_at(io, TBT_PLL_ENABLE)
}

// ── SKL `DPLL_CTRL1` (DISPLAY_VER 9 only) ───────────────────────
// The SKL manager's shared control register. Every field below is
// per-DPLL, 6 bits wide starting at `id * 6` — the hardware state
// `ctrl1` in `intel_dpll_mgr.c` is stored unshifted (id 0) and
// shifted by `id * 6` on write/read.

/// `DPLL_CTRL1` (0x6C058, `display/intel_display_regs.h:2812`).
pub const DPLL_CTRL1: u64 = 0x6C058;

/// `DPLL_CTRL1_HDMI_MODE(id)` — bit `id * 6 + 5`.
pub const fn ctrl1_hdmi_mode(id: u32) -> u32 {
    1 << (id * 6 + 5)
}

/// `DPLL_CTRL1_SSC(id)` — bit `id * 6 + 4`.
pub const fn ctrl1_ssc(id: u32) -> u32 {
    1 << (id * 6 + 4)
}

/// `DPLL_CTRL1_LINK_RATE_MASK(id)` — bits `id * 6 + 1 ..= id * 6 + 3`.
pub const fn ctrl1_link_rate_mask(id: u32) -> u32 {
    7 << (id * 6 + 1)
}

/// `DPLL_CTRL1_LINK_RATE_SHIFT(id)`.
pub const fn ctrl1_link_rate_shift(id: u32) -> u32 {
    id * 6 + 1
}

/// `DPLL_CTRL1_LINK_RATE(linkrate, id)`.
pub const fn ctrl1_link_rate(link_rate: u32, id: u32) -> u32 {
    link_rate << (id * 6 + 1)
}

/// `DPLL_CTRL1_OVERRIDE(id)` — bit `id * 6`.
pub const fn ctrl1_override(id: u32) -> u32 {
    1 << (id * 6)
}

/// `DPLL_CTRL1_LINK_RATE_2700` (0) — 2.7 Gbps.
pub const LINK_RATE_2700: u32 = 0;
/// `DPLL_CTRL1_LINK_RATE_1350` (1) — 1.35 Gbps.
pub const LINK_RATE_1350: u32 = 1;
/// `DPLL_CTRL1_LINK_RATE_810` (2) — 0.81 Gbps.
pub const LINK_RATE_810: u32 = 2;
/// `DPLL_CTRL1_LINK_RATE_1620` (3) — 1.62 Gbps (eDP 1.4).
pub const LINK_RATE_1620: u32 = 3;
/// `DPLL_CTRL1_LINK_RATE_1080` (4) — 1.08 Gbps (eDP 1.4).
pub const LINK_RATE_1080: u32 = 4;
/// `DPLL_CTRL1_LINK_RATE_2160` (5) — 2.16 Gbps (eDP 1.4).
pub const LINK_RATE_2160: u32 = 5;

/// `skl_ddi_dp_set_dpll_hw_state`: the DP ctrl1 for a port clock
/// (kHz) — OVERRIDE plus the link-rate field for `port_clock / 2`
/// (the DP link clock in kHz: 81000 / 108000 / 135000 / 162000 /
/// 216000 / 270000). `None` for a port clock with no programmed
/// link rate (Linux leaves ctrl1 at OVERRIDE-only in that case —
/// the switch has no default arm — but a modeset with an
/// unmapped rate is a caller error here, not a silent default).
pub fn dp_ctrl1(port_clock_khz: u32) -> Option<u32> {
    let rate = match port_clock_khz / 2 {
        81_000 => LINK_RATE_810,
        108_000 => LINK_RATE_1080,
        135_000 => LINK_RATE_1350,
        162_000 => LINK_RATE_1620,
        216_000 => LINK_RATE_2160,
        270_000 => LINK_RATE_2700,
        _ => return None,
    };
    Some(ctrl1_override(0) | ctrl1_link_rate(rate, 0))
}

/// `skl_ddi_hdmi_pll_dividers` (ctrl1 half): HDMI always uses
/// OVERRIDE | HDMI_MODE (the CFGCR1/2 half is
/// [`crate::intel_gpu_gen9_dpll::SklDpllState::from_wrpll`], Gen9
/// Lane 4).
pub fn hdmi_ctrl1() -> u32 {
    ctrl1_override(0) | ctrl1_hdmi_mode(0)
}

/// `skl_ddi_pll_write_ctrl1`: RMW the DPLL's 6-bit field
/// (HDMI_MODE | SSC | LINK_RATE_MASK) with `ctrl1 << (id * 6)`,
/// then posting-read the register.
pub fn write_ctrl1(io: &(impl MmioWindow + ?Sized), id: u32, ctrl1: u32) {
    let cur = io.read32(DPLL_CTRL1);
    let mask = ctrl1_hdmi_mode(id) | ctrl1_ssc(id) | ctrl1_link_rate_mask(id);
    io.write32(DPLL_CTRL1, (cur & !mask) | (ctrl1 << (id * 6)));
    let _ = io.read32(DPLL_CTRL1);
}

/// `skl_ddi_pll_get_hw_state` (ctrl1 half): the DPLL's 6-bit
/// field, unshifted.
pub fn read_ctrl1(io: &(impl MmioWindow + ?Sized), id: u32) -> u32 {
    (io.read32(DPLL_CTRL1) >> (id * 6)) & 0x3f
}

/// `skl_ddi_lcpll_get_freq`: the DP link clock (kHz) a ctrl1
/// field selects. `None` for an unprogrammed/reserved rate
/// (Linux's switch has no default — an unknown code yields 0
/// there; `None` here so callers cannot mistake it for RBR).
pub fn ctrl1_link_clock_khz(ctrl1: u32) -> Option<u32> {
    match (ctrl1 & ctrl1_link_rate_mask(0)) >> ctrl1_link_rate_shift(0) {
        LINK_RATE_810 => Some(81_000),
        LINK_RATE_1080 => Some(108_000),
        LINK_RATE_1350 => Some(135_000),
        LINK_RATE_1620 => Some(162_000),
        LINK_RATE_2160 => Some(216_000),
        LINK_RATE_2700 => Some(270_000),
        _ => None,
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use crate::intel_gpu_pll::{combo_coeffs, hdmi_wrpll_coeffs, LinkRate, RefclkFamily};
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Any PLL enable register the model synthesizes LOCK /
    /// POWER_STATE for: the three combo enables, the TBT enable,
    /// and all four MG enables (TC1's is the EHL DPLL4 enable).
    fn is_pll_enable_reg(off: u64) -> bool {
        matches!(
            off,
            0x46010 | 0x46014 | 0x46020 | 0x46030 | 0x46034 | 0x46038 | 0x4603C
        )
    }

    /// Scripted combo-PLL endpoint: CFGCR0/1 stores per PLL,
    /// enable registers whose LOCK follows ENABLE and whose
    /// POWER_STATE follows POWER_ENABLE (unless the grant flags
    /// are cleared), and a DPLL_CTRL1 store.
    struct DpllMmio {
        cfgcr: RefCell<Vec<(u64, u32)>>,
        enable: RefCell<Vec<(u64, u32)>>,
        ctrl1: RefCell<u32>,
        grant_lock: bool,
        grant_power: bool,
        writes: RefCell<Vec<(u64, u32)>>,
    }

    impl DpllMmio {
        fn new() -> Self {
            Self {
                cfgcr: RefCell::new(Vec::new()),
                enable: RefCell::new(Vec::new()),
                ctrl1: RefCell::new(0),
                grant_lock: true,
                grant_power: true,
                writes: RefCell::new(Vec::new()),
            }
        }

        fn reg(&self, store: &RefCell<Vec<(u64, u32)>>, off: u64) -> u32 {
            let mut v = 0;
            for (o, val) in store.borrow().iter() {
                if *o == off {
                    v = *val;
                }
            }
            v
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

    impl MmioWindow for DpllMmio {
        fn read32(&self, off: u64) -> u32 {
            let mut v = self.reg(&self.enable, off);
            if is_pll_enable_reg(off) {
                if self.grant_power && v & PLL_POWER_ENABLE != 0 {
                    v |= PLL_POWER_STATE;
                } else {
                    v &= !PLL_POWER_STATE;
                }
                if self.grant_lock && v & PLL_ENABLE != 0 {
                    v |= PLL_LOCK;
                } else {
                    v &= !PLL_LOCK;
                }
            }
            if off == DPLL_CTRL1 {
                return *self.ctrl1.borrow();
            }
            if v == 0 {
                v = self.reg(&self.cfgcr, off);
            }
            v
        }

        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            if off == DPLL_CTRL1 {
                *self.ctrl1.borrow_mut() = val;
                return;
            }
            if is_pll_enable_reg(off) {
                let mut store = self.enable.borrow_mut();
                if let Some(slot) = store.iter_mut().find(|(o, _)| *o == off) {
                    slot.1 = val & !(PLL_LOCK | PLL_POWER_STATE);
                } else {
                    store.push((off, val & !(PLL_LOCK | PLL_POWER_STATE)));
                }
                return;
            }
            let mut store = self.cfgcr.borrow_mut();
            if let Some(slot) = store.iter_mut().find(|(o, _)| *o == off) {
                slot.1 = val;
            } else {
                store.push((off, val));
            }
        }
    }

    fn smoke_icl_dpll_register_map() -> TestResult {
        // ICL_DPLL_CFGCR0/1: DPLL0 0x164000/0x164004, DPLL1
        // 0x164080/0x164084, EHL DPLL4 0x164200/0x164204.
        if icl_dpll_cfgcr0(IclDpllId::Dpll0) != 0x164000
            || icl_dpll_cfgcr1(IclDpllId::Dpll0) != 0x164004
            || icl_dpll_cfgcr0(IclDpllId::Dpll1) != 0x164080
            || icl_dpll_cfgcr1(IclDpllId::Dpll1) != 0x164084
            || icl_dpll_cfgcr0(IclDpllId::Dpll4) != 0x164200
            || icl_dpll_cfgcr1(IclDpllId::Dpll4) != 0x164204
        {
            return TestResult::Fail("ICL CFGCR0/1 addresses wrong");
        }
        // Enable registers: DPLL0 0x46010, DPLL1 0x46014,
        // EHL DPLL4 shares the MG PLL1 enable at 0x46030.
        if icl_dpll_enable_reg(IclDpllId::Dpll0) != 0x46010
            || icl_dpll_enable_reg(IclDpllId::Dpll1) != 0x46014
            || icl_dpll_enable_reg(IclDpllId::Dpll4) != 0x46030
        {
            return TestResult::Fail("ICL DPLL enable registers wrong");
        }
        // TGL's CFGCR lives elsewhere (0x16428x) — the ICL map
        // must not collide with it.
        if icl_dpll_cfgcr0(IclDpllId::Dpll0) == crate::intel_gpu_pll::DPLL_CFGCR0_DPLL0 {
            return TestResult::Fail("ICL CFGCR0 must differ from the TGL map");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_dpll",
        smoke_icl_dpll_register_map
    );

    fn smoke_icl_dpll_dp_state() -> TestResult {
        // Every DP row in both reference families packs to the
        // published CFGCR pair: HBR2 at 19.2 MHz is DCO
        // 0x1A5/0x7000, P/3 K/1, central 8.4 GHz.
        let coeffs = match combo_coeffs(LinkRate::DpHbr2, RefclkFamily::Ref19_2Or38_4Mhz) {
            Some(c) => c,
            None => return TestResult::Fail("HBR2 19.2 MHz row must exist"),
        };
        let (cfgcr0, cfgcr1) = calc_dpll_state(&coeffs, false);
        if cfgcr0 != 0x01C0_01A5 {
            return TestResult::Fail("HBR2 CFGCR0 must be frac 0x7000 << 10 | int 0x1A5");
        }
        // cfgcr1: QDIV 0 | KDIV_1 (1<<6) | PDIV_3 (2<<2) | CFREQ 3.
        if cfgcr1 != (1 << 6) | (2 << 2) | 3 {
            return TestResult::Fail("HBR2 CFGCR1 must be KDIV_1 | PDIV_3 | CFREQ_8400");
        }
        // 24 MHz family: same dividers, DCO 0x151/0x4000.
        let coeffs = match combo_coeffs(LinkRate::DpHbr2, RefclkFamily::Ref24Mhz) {
            Some(c) => c,
            None => return TestResult::Fail("HBR2 24 MHz row must exist"),
        };
        let (cfgcr0, cfgcr1) = calc_dpll_state(&coeffs, false);
        if cfgcr0 != 0x0100_0151 || cfgcr1 != (1 << 6) | (2 << 2) | 3 {
            return TestResult::Fail("HBR2 24 MHz state wrong");
        }
        // EHL div-frac WA: 0x7000 halves to 0x3800.
        let coeffs = match combo_coeffs(LinkRate::DpHbr2, RefclkFamily::Ref19_2Or38_4Mhz) {
            Some(c) => c,
            None => return TestResult::Fail("HBR2 row must exist"),
        };
        let (cfgcr0, _) = calc_dpll_state(&coeffs, true);
        if cfgcr0 != 0x00E0_01A5 {
            return TestResult::Fail("EHL frac WA must halve 0x7000 to 0x3800");
        }
        // RBR/HBR/HBR3 rows pack without error too.
        for rate in [LinkRate::DpRbr, LinkRate::DpHbr, LinkRate::DpHbr3] {
            if combo_coeffs(rate, RefclkFamily::Ref24Mhz).is_none() {
                return TestResult::Fail("every DP rate must have a 24 MHz row");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen11_dpll", smoke_icl_dpll_dp_state);

    fn smoke_icl_dpll_hdmi_state() -> TestResult {
        // 148.5 MHz TMDS (1080p60) at 24 MHz ref: the WRPLL search
        // must land a DCO in [7998000, 10000000] kHz. 148500*5 =
        // 742500; x12 = 8910000 (closest to the 8999000 centre
        // among in-window dividers); P/2 Q/3 K/2.
        let coeffs = match hdmi_wrpll_coeffs(148_500, RefclkFamily::Ref24Mhz) {
            Some(c) => c,
            None => return TestResult::Fail("1080p60 HDMI WRPLL must resolve"),
        };
        // dco 8910000 kHz / 24000 = 371.25 -> int 371, frac 0x2000.
        if coeffs.dco_integer != 371 || coeffs.dco_fraction != 0x2000 {
            return TestResult::Fail("1080p60 HDMI DCO must be 371 + 0x2000");
        }
        let (cfgcr0, cfgcr1) = calc_dpll_state(&coeffs, false);
        if cfgcr0 != (0x2000 << 10) | 371 {
            return TestResult::Fail("1080p60 HDMI CFGCR0 wrong");
        }
        // cfgcr1: QDIV ratio 3 << 10 | MODE (qdiv != 1) |
        // KDIV_2 (2<<6) | PDIV_2 (1<<2) | CFREQ 3.
        if cfgcr1 != (3 << 10) | (1 << 9) | (2 << 6) | (1 << 2) | 3 {
            return TestResult::Fail("1080p60 HDMI CFGCR1 wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_dpll",
        smoke_icl_dpll_hdmi_state
    );

    fn smoke_icl_dpll_enable_disable() -> TestResult {
        let mmio = DpllMmio::new();
        let coeffs = combo_coeffs(LinkRate::DpHbr2, RefclkFamily::Ref19_2Or38_4Mhz)
            .expect("HBR2 row must exist");
        let (cfgcr0, cfgcr1) = calc_dpll_state(&coeffs, false);
        if combo_pll_enable(&mmio, IclDpllId::Dpll0, cfgcr0, cfgcr1).is_err() {
            return TestResult::Fail("combo PLL enable must succeed");
        }
        // Power-enable, then CFGCR0/1, then PLL enable — in order.
        let enable_writes = mmio.writes_to(icl_dpll_enable_reg(IclDpllId::Dpll0));
        if enable_writes != alloc::vec![PLL_POWER_ENABLE, PLL_POWER_ENABLE | PLL_ENABLE] {
            return TestResult::Fail("enable sequence must be power then PLL enable");
        }
        if mmio.writes_to(icl_dpll_cfgcr0(IclDpllId::Dpll0)) != alloc::vec![cfgcr0] {
            return TestResult::Fail("CFGCR0 must be written once");
        }
        if mmio.writes_to(icl_dpll_cfgcr1(IclDpllId::Dpll0)) != alloc::vec![cfgcr1] {
            return TestResult::Fail("CFGCR1 must be written once");
        }
        // Disable reverses it: clear ENABLE, then clear POWER_ENABLE.
        let mmio = DpllMmio::new();
        if combo_pll_enable(&mmio, IclDpllId::Dpll1, cfgcr0, cfgcr1).is_err()
            || combo_pll_disable(&mmio, IclDpllId::Dpll1).is_err()
        {
            return TestResult::Fail("combo PLL disable must succeed");
        }
        let enable_writes = mmio.writes_to(icl_dpll_enable_reg(IclDpllId::Dpll1));
        if enable_writes
            != alloc::vec![
                PLL_POWER_ENABLE,
                PLL_POWER_ENABLE | PLL_ENABLE,
                PLL_POWER_ENABLE,
                0,
            ]
        {
            return TestResult::Fail("disable must clear ENABLE then POWER_ENABLE");
        }
        // A PLL that never locks must time out on enable.
        let mut mmio = DpllMmio::new();
        mmio.grant_lock = false;
        if combo_pll_enable(&mmio, IclDpllId::Dpll0, cfgcr0, cfgcr1) != Err(DpllError::Timeout) {
            return TestResult::Fail("a PLL that never locks must time out");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_dpll",
        smoke_icl_dpll_enable_disable
    );

    fn smoke_skl_dpll_ctrl1_dp() -> TestResult {
        // Bit fields: HDMI_MODE bit 5, SSC bit 4, LINK_RATE bits
        // 3:1, OVERRIDE bit 0 (id 0); id 1 shifts by 6.
        if ctrl1_hdmi_mode(0) != 1 << 5
            || ctrl1_ssc(0) != 1 << 4
            || ctrl1_link_rate_mask(0) != 0xE
            || ctrl1_override(0) != 1
            || ctrl1_hdmi_mode(1) != 1 << 11
            || ctrl1_link_rate_mask(1) != 0xE << 6
        {
            return TestResult::Fail("DPLL_CTRL1 field positions wrong");
        }
        // DP: port_clock/2 selects the rate; OVERRIDE always set.
        if dp_ctrl1(162_000) != Some(1 | (LINK_RATE_810 << 1)) {
            return TestResult::Fail("162 MHz port clock must select LINK_RATE_810");
        }
        if dp_ctrl1(270_000) != Some(1 | (LINK_RATE_1350 << 1)) {
            return TestResult::Fail("270 MHz port clock must select LINK_RATE_1350");
        }
        if dp_ctrl1(540_000) != Some(1 | (LINK_RATE_2700 << 1)) {
            return TestResult::Fail("540 MHz port clock must select LINK_RATE_2700");
        }
        if dp_ctrl1(324_000) != Some(1 | (LINK_RATE_1620 << 1)) {
            return TestResult::Fail("324 MHz port clock must select LINK_RATE_1620");
        }
        if dp_ctrl1(216_000) != Some(1 | (LINK_RATE_1080 << 1)) {
            return TestResult::Fail("216 MHz port clock must select LINK_RATE_1080");
        }
        if dp_ctrl1(432_000) != Some(1 | (LINK_RATE_2160 << 1)) {
            return TestResult::Fail("432 MHz port clock must select LINK_RATE_2160");
        }
        if dp_ctrl1(100_000).is_some() {
            return TestResult::Fail("an unmapped port clock must refuse");
        }
        // Decode round-trips the computation.
        for (port_clock, want) in [
            (162_000, 81_000),
            (216_000, 108_000),
            (270_000, 135_000),
            (324_000, 162_000),
            (432_000, 216_000),
            (540_000, 270_000),
        ] {
            let ctrl1 = dp_ctrl1(port_clock).expect("mapped rate must compute");
            if ctrl1_link_clock_khz(ctrl1) != Some(want) {
                return TestResult::Fail("ctrl1 link-clock decode must round-trip");
            }
        }
        if ctrl1_link_clock_khz(0x3F).is_some() {
            return TestResult::Fail("a reserved link-rate code must decode to None");
        }
        // HDMI ctrl1 is OVERRIDE | HDMI_MODE.
        if hdmi_ctrl1() != 1 | (1 << 5) {
            return TestResult::Fail("HDMI ctrl1 must be OVERRIDE | HDMI_MODE");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen11_dpll", smoke_skl_dpll_ctrl1_dp);

    fn smoke_skl_dpll_ctrl1_write_read() -> TestResult {
        let mmio = DpllMmio::new();
        // Write DP HBR2 ctrl1 for DPLL 1: only its 6-bit field
        // changes; neighbouring fields are preserved.
        *mmio.ctrl1.borrow_mut() = 0x15; // DPLL 0 field preset
        write_ctrl1(&mmio, 1, dp_ctrl1(540_000).expect("mapped rate"));
        let want = 0x15 | ((1 | (LINK_RATE_2700 << 1)) << 6);
        if *mmio.ctrl1.borrow() != want {
            return TestResult::Fail("write_ctrl1 must RMW only the DPLL's field");
        }
        if read_ctrl1(&mmio, 1) != 1 | (LINK_RATE_2700 << 1) {
            return TestResult::Fail("read_ctrl1 must extract the DPLL's field");
        }
        if read_ctrl1(&mmio, 0) != 0x15 {
            return TestResult::Fail("read_ctrl1 must leave the other DPLL's field alone");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_dpll",
        smoke_skl_dpll_ctrl1_write_read
    );

    fn smoke_mg_pll_register_map() -> TestResult {
        // MG_PLL_ENABLE: TC1 0x46030, stride 4.
        if mg_pll_enable_reg(0) != 0x46030
            || mg_pll_enable_reg(1) != 0x46034
            || mg_pll_enable_reg(2) != 0x46038
            || mg_pll_enable_reg(3) != 0x4603C
        {
            return TestResult::Fail("MG PLL enable registers wrong");
        }
        // MG PLL block: TC1 DIV0 0x168A00, stride 0x1000.
        if mg_pll_div0(0) != 0x168A00
            || mg_pll_div0(1) != 0x169A00
            || mg_pll_div1(0) != 0x168A04
            || mg_pll_lf(0) != 0x168A08
            || mg_pll_frac_lock(0) != 0x168A0C
            || mg_pll_ssc(0) != 0x168A10
            || mg_pll_bias(0) != 0x168A14
            || mg_pll_tdc_coldst_bias(0) != 0x168A18
            || mg_pll_div0(3) != 0x16BA00
        {
            return TestResult::Fail("MG PLL block registers wrong");
        }
        // Clock-top registers: PORT1 bases, stride 0x1000.
        if mg_pll_refclkin_ctl(0) != 0x16892C
            || mg_pll_refclkin_ctl(1) != 0x16992C
            || mg_pll_clktop2_coreclkctl1(0) != 0x1688D8
            || mg_pll_clktop2_hsclkctl(0) != 0x1688D4
            || mg_pll_clktop2_hsclkctl(3) != 0x16B8D4
        {
            return TestResult::Fail("MG clock-top registers wrong");
        }
        // TBT PLL: CFGCR0 0x164100, CFGCR1 0x164104, enable 0x46020.
        if TBT_PLL_CFGCR0 != 0x164100 || TBT_PLL_CFGCR1 != 0x164104 || TBT_PLL_ENABLE != 0x46020 {
            return TestResult::Fail("TBT PLL registers wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_dpll",
        smoke_mg_pll_register_map
    );

    fn smoke_mg_pll_dp_state() -> TestResult {
        // DP HBR2 (540 MHz) at 19.2 MHz refclk: divisor search
        // lands on div1=3, div2=1 (DCO 8.1 GHz), m1div=2,
        // m2div_int=210, rem 36000, frac 0x3C0000.
        let state = match mg_pll_state(540_000, true, 19_200) {
            Some(s) => s,
            None => return TestResult::Fail("HBR2 MG state must exist"),
        };
        if state.refclkin_ctl != 0x100
            || state.clktop2_coreclkctl1 != 0x500
            || state.clktop2_hsclkctl != 0x1100
            || state.div0 != 0x7C00_00D2
            || state.div1 != 0x11012
            || state.lf != 0x4F11_0804
            || state.frac_lock != 0x55552
            || state.ssc != 0x0800_1200
            || state.bias != 0xFF0A_8C9C
            || state.tdc_coldst_bias != 0x0803_0007
            || state.bias_mask != u32::MAX
            || state.tdc_coldst_bias_mask != u32::MAX
        {
            return TestResult::Fail("HBR2 MG state vector wrong");
        }
        // DP RBR (162 MHz) at 19.2 MHz: div1=5, div2=2 — same
        // DCO/refclk, so the packed DCO fields match HBR2; only
        // the clock-top dividers differ (A_DIVRATIO 10, DSDIV 2,
        // HSDIV ratio 5).
        let state = match mg_pll_state(162_000, true, 19_200) {
            Some(s) => s,
            None => return TestResult::Fail("RBR MG state must exist"),
        };
        if state.clktop2_coreclkctl1 != 0xA00
            || state.clktop2_hsclkctl != 0xA200
            || state.div0 != 0x7C00_00D2
            || state.div1 != 0x11012
            || state.bias != 0xFF0A_8C9C
        {
            return TestResult::Fail("RBR MG state vector wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen11_dpll", smoke_mg_pll_dp_state);

    fn smoke_mg_pll_hdmi_state() -> TestResult {
        // HDMI 148.5 MHz TMDS at 24 MHz refclk: divisor search
        // lands on div1=3, div2=4 (DCO 8.91 GHz), m1div=2,
        // m2div_int=185, rem 30000, frac 0x280000.
        let state = match mg_pll_state(148_500, false, 24_000) {
            Some(s) => s,
            None => return TestResult::Fail("HDMI MG state must exist"),
        };
        if state.refclkin_ctl != 0x100
            || state.clktop2_coreclkctl1 != 0x500
            || state.clktop2_hsclkctl != 0x19400
            || state.div0 != 0x6800_00B9
            || state.div1 != 0x11012
            || state.lf != 0x3F11_0804
            || state.frac_lock != 0x5554A
            || state.ssc != 0x0800_1200
            || state.bias != 0xFF0A_8C99
            || state.tdc_coldst_bias != 0x0805_0007
        {
            return TestResult::Fail("HDMI MG state vector wrong");
        }
        // A clock no (div1, div2) pair can reach is None.
        if mg_pll_state(100_000, true, 19_200).is_some() {
            return TestResult::Fail("unreachable DP clock must have no MG state");
        }
        // An unknown refclk is None.
        if mg_pll_state(540_000, true, 12_345).is_some() {
            return TestResult::Fail("unknown refclk must have no MG state");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen11_dpll", smoke_mg_pll_hdmi_state);

    fn smoke_mg_pll_refclk_38_4_masks() -> TestResult {
        // 38.4 MHz refclk: BIAS is left untouched (mask 0) and
        // only the COLDSTART bit of TDC_COLDST_BIAS is written.
        let state = match mg_pll_state(540_000, true, 38_400) {
            Some(s) => s,
            None => return TestResult::Fail("HBR2 MG state must exist at 38.4 MHz"),
        };
        if state.bias_mask != 0
            || state.tdc_coldst_bias_mask != 0x1_0000
            || state.bias != 0
            || state.tdc_coldst_bias != 0x1_0000
        {
            return TestResult::Fail("38.4 MHz MG masks wrong");
        }
        if state.div0 != 0x5E00_0069 || state.div1 != 0x21012 || state.lf != 0x2711_0804 {
            return TestResult::Fail("38.4 MHz MG state vector wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_dpll",
        smoke_mg_pll_refclk_38_4_masks
    );

    fn smoke_tbt_pll_rows() -> TestResult {
        // 24 MHz row: DCO 0x151/0x4000, P/5 K/1, CFREQ 8.4 GHz.
        let coeffs = match tbt_pll_coeffs(24_000) {
            Some(c) => c,
            None => return TestResult::Fail("TBT 24 MHz row must exist"),
        };
        let (cfgcr0, cfgcr1) = calc_dpll_state(&coeffs, false);
        if cfgcr0 != 0x0100_0151 || cfgcr1 != 0x53 {
            return TestResult::Fail("TBT 24 MHz row wrong");
        }
        // 19.2 MHz row: DCO 0x1A5/0x7000, same dividers.
        let coeffs = match tbt_pll_coeffs(19_200) {
            Some(c) => c,
            None => return TestResult::Fail("TBT 19.2 MHz row must exist"),
        };
        let (cfgcr0, cfgcr1) = calc_dpll_state(&coeffs, false);
        if cfgcr0 != 0x01C0_01A5 || cfgcr1 != 0x53 {
            return TestResult::Fail("TBT 19.2 MHz row wrong");
        }
        // 38.4 MHz falls through to the 19.2 MHz row.
        let coeffs = match tbt_pll_coeffs(38_400) {
            Some(c) => c,
            None => return TestResult::Fail("TBT 38.4 MHz row must exist"),
        };
        let (cfgcr0, cfgcr1) = calc_dpll_state(&coeffs, false);
        if cfgcr0 != 0x01C0_01A5 || cfgcr1 != 0x53 {
            return TestResult::Fail("TBT 38.4 MHz row must fall through to 19.2 MHz");
        }
        if tbt_pll_coeffs(12_345).is_some() {
            return TestResult::Fail("unknown refclk must have no TBT row");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen11_dpll", smoke_tbt_pll_rows);

    fn smoke_mg_pll_enable_disable() -> TestResult {
        let mmio = DpllMmio::new();
        let state = mg_pll_state(540_000, true, 19_200).expect("HBR2 MG state must exist");
        if mg_pll_enable(&mmio, 0, &state).is_err() {
            return TestResult::Fail("MG PLL enable must succeed");
        }
        // Power-enable, then the state writes, then PLL enable.
        let enable_writes = mmio.writes_to(mg_pll_enable_reg(0));
        if enable_writes != alloc::vec![PLL_POWER_ENABLE, PLL_POWER_ENABLE | PLL_ENABLE] {
            return TestResult::Fail("MG enable sequence must be power then PLL enable");
        }
        if mmio.writes_to(mg_pll_div0(0)) != alloc::vec![0x7C00_00D2] {
            return TestResult::Fail("MG DIV0 must carry the HBR2 state");
        }
        if mmio.writes_to(mg_pll_tdc_coldst_bias(0)) != alloc::vec![0x0803_0007] {
            return TestResult::Fail("MG TDC_COLDST_BIAS must carry the HBR2 state");
        }
        // Disable reverses it: clear ENABLE, then clear POWER_ENABLE.
        let mmio = DpllMmio::new();
        if mg_pll_enable(&mmio, 2, &state).is_err() || mg_pll_disable(&mmio, 2).is_err() {
            return TestResult::Fail("MG PLL disable must succeed");
        }
        let enable_writes = mmio.writes_to(mg_pll_enable_reg(2));
        if enable_writes
            != alloc::vec![
                PLL_POWER_ENABLE,
                PLL_POWER_ENABLE | PLL_ENABLE,
                PLL_POWER_ENABLE,
                0,
            ]
        {
            return TestResult::Fail("MG disable must clear ENABLE then POWER_ENABLE");
        }
        // A PLL that never locks must time out on enable.
        let mut mmio = DpllMmio::new();
        mmio.grant_lock = false;
        if mg_pll_enable(&mmio, 0, &state) != Err(DpllError::Timeout) {
            return TestResult::Fail("MG enable without LOCK must time out");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_dpll",
        smoke_mg_pll_enable_disable
    );

    fn smoke_tbt_pll_enable_disable() -> TestResult {
        let mmio = DpllMmio::new();
        let coeffs = tbt_pll_coeffs(19_200).expect("TBT 19.2 MHz row must exist");
        let (cfgcr0, cfgcr1) = calc_dpll_state(&coeffs, false);
        if tbt_pll_enable(&mmio, cfgcr0, cfgcr1).is_err() {
            return TestResult::Fail("TBT PLL enable must succeed");
        }
        let enable_writes = mmio.writes_to(TBT_PLL_ENABLE);
        if enable_writes != alloc::vec![PLL_POWER_ENABLE, PLL_POWER_ENABLE | PLL_ENABLE] {
            return TestResult::Fail("TBT enable sequence must be power then PLL enable");
        }
        if mmio.writes_to(TBT_PLL_CFGCR0) != alloc::vec![0x01C0_01A5] {
            return TestResult::Fail("TBT CFGCR0 must carry the 19.2 MHz row");
        }
        if mmio.writes_to(TBT_PLL_CFGCR1) != alloc::vec![0x53] {
            return TestResult::Fail("TBT CFGCR1 must be KDIV_1 | PDIV_5 | CFREQ_8400");
        }
        // Disable reverses it.
        let mmio = DpllMmio::new();
        if tbt_pll_enable(&mmio, cfgcr0, cfgcr1).is_err() || tbt_pll_disable(&mmio).is_err() {
            return TestResult::Fail("TBT PLL disable must succeed");
        }
        let enable_writes = mmio.writes_to(TBT_PLL_ENABLE);
        if enable_writes
            != alloc::vec![
                PLL_POWER_ENABLE,
                PLL_POWER_ENABLE | PLL_ENABLE,
                PLL_POWER_ENABLE,
                0,
            ]
        {
            return TestResult::Fail("TBT disable must clear ENABLE then POWER_ENABLE");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_dpll",
        smoke_tbt_pll_enable_disable
    );

    fn smoke_combo_dpll_id_map() -> TestResult {
        use crate::intel_gpu_gt::Gen11Platform as P;
        // ICL: A→DPLL0, B→DPLL1, C+ are MG ports (no combo PLL).
        if combo_dpll_id(P::IceLake, Ddi::A) != Some(IclDpllId::Dpll0)
            || combo_dpll_id(P::IceLake, Ddi::B) != Some(IclDpllId::Dpll1)
            || combo_dpll_id(P::IceLake, Ddi::C).is_some()
            || combo_dpll_id(P::IceLake, Ddi::F).is_some()
        {
            return TestResult::Fail("ICL combo-PLL map wrong");
        }
        // EHL/JSL: A→DPLL0, B→DPLL1, C→DPLL4, D shares PHY A
        // (no fixed assignment).
        for p in [P::ElkhartLake, P::JasperLake] {
            if combo_dpll_id(p, Ddi::A) != Some(IclDpllId::Dpll0)
                || combo_dpll_id(p, Ddi::B) != Some(IclDpllId::Dpll1)
                || combo_dpll_id(p, Ddi::C) != Some(IclDpllId::Dpll4)
                || combo_dpll_id(p, Ddi::D).is_some()
            {
                return TestResult::Fail("EHL/JSL combo-PLL map wrong");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen11_dpll", smoke_combo_dpll_id_map);
}

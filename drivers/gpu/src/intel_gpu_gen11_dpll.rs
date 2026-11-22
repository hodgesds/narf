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
//! the 8.4/9.0/9.6 GHz central frequencies) are Gen9-lane work
//! and are NOT ported here.
//!
//! ## Not ported (remainders)
//!
//! - MG PLL divisor search (`icl_mg_pll_find_divisors`) and the
//!   MG register programming for Type-C ports — Lane 8.
//! - TBT PLL fixed rows (`icl_tbt_pll_24MHz_values` /
//!   `icl_tbt_pll_19_2MHz_values`) — Thunderbolt lane.
//! - The VBT AFC-startup `div0` override
//!   (`vbt.override_afc_startup`) — needs a VBT field this driver
//!   does not parse; default path writes no `div0`.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_pll::{encode_cfgcr0, DpllCoeffs};

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
    let enable = icl_dpll_enable_reg(id);
    let cur = io.read32(enable);
    if cur == u32::MAX || !io.display_access_ok() {
        return Err(DpllError::NoDevice);
    }
    // Status bits (LOCK, POWER_STATE) are read-only; never write
    // them back — the same rule the CDCLK PLL disable follows.
    let clean = cur & !(PLL_LOCK | PLL_POWER_STATE);
    io.write32(enable, clean | PLL_POWER_ENABLE);
    wait(io, enable, PLL_POWER_STATE, PLL_POWER_STATE)?;
    dpll_write(io, id, cfgcr0, cfgcr1);
    let cur = io.read32(enable);
    if cur == u32::MAX || !io.display_access_ok() {
        return Err(DpllError::NoDevice);
    }
    io.write32(enable, (cur & !(PLL_LOCK | PLL_POWER_STATE)) | PLL_ENABLE);
    wait(io, enable, PLL_LOCK, PLL_LOCK)
}

/// `combo_pll_disable` (`icl_pll_disable`): clear PLL_ENABLE
/// (wait LOCK clear), then clear POWER_ENABLE (wait POWER_STATE
/// clear). 1 ms per wait.
pub fn combo_pll_disable(io: &(impl MmioWindow + ?Sized), id: IclDpllId) -> Result<(), DpllError> {
    let enable = icl_dpll_enable_reg(id);
    let cur = io.read32(enable);
    if cur == u32::MAX || !io.display_access_ok() {
        return Err(DpllError::NoDevice);
    }
    io.write32(enable, (cur & !(PLL_LOCK | PLL_POWER_STATE)) & !PLL_ENABLE);
    wait(io, enable, PLL_LOCK, 0)?;
    let cur = io.read32(enable);
    if cur == u32::MAX || !io.display_access_ok() {
        return Err(DpllError::NoDevice);
    }
    io.write32(
        enable,
        (cur & !(PLL_LOCK | PLL_POWER_STATE)) & !PLL_POWER_ENABLE,
    );
    wait(io, enable, PLL_POWER_STATE, 0)
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
/// OVERRIDE | HDMI_MODE (the CFGCR1/2 half needs the SKL WRPLL
/// divider search, a Gen9-lane remainder).
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
            if off == icl_dpll_enable_reg(IclDpllId::Dpll0)
                || off == icl_dpll_enable_reg(IclDpllId::Dpll1)
                || off == icl_dpll_enable_reg(IclDpllId::Dpll4)
            {
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
            if off == icl_dpll_enable_reg(IclDpllId::Dpll0)
                || off == icl_dpll_enable_reg(IclDpllId::Dpll1)
                || off == icl_dpll_enable_reg(IclDpllId::Dpll4)
            {
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
        if cfgcr0 != 0x1C00_01A5 {
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
        if cfgcr0 != 0x1000_0151 || cfgcr1 != (1 << 6) | (2 << 2) | 3 {
            return TestResult::Fail("HBR2 24 MHz state wrong");
        }
        // EHL div-frac WA: 0x7000 halves to 0x3800.
        let coeffs = match combo_coeffs(LinkRate::DpHbr2, RefclkFamily::Ref19_2Or38_4Mhz) {
            Some(c) => c,
            None => return TestResult::Fail("HBR2 row must exist"),
        };
        let (cfgcr0, _) = calc_dpll_state(&coeffs, true);
        if cfgcr0 != 0x0E00_01A5 {
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
}

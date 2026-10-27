//! Display PLL register codec — clean-room.
//!
//! Reference: **Tiger Lake PRM Vol. 11 §"Display Clocks"** —
//! the per-port DPLLs that synthesise the link clock for HDMI /
//! DP. Cross-checked against ADL / RPL / MTL PRMs (same Combo
//! PHY DPLL programming).
//!
//! ## DPLL model
//!
//! Gen12 has **3 generic DPLLs** (DPLL 0..2) that drive the
//! Combo PHYs (DDI A..C), plus per-TC-PHY DPLLs that drive the
//! Type-C ports. The generic DPLLs are programmed via a pair of
//! configuration registers:
//!
//! - `DPLL_CFGCR0[N]` — DCO integer + fraction.
//! - `DPLL_CFGCR1[N]` — Q-divider, P-divider, K-divider, central
//!   frequency selector.
//!
//! Plus a global `DPLL_CTRL1` carrying per-port enable + link-
//! rate selection, and `DPCLKA_CFGCR0` mapping each DDI to the
//! DPLL number that feeds it.
//!
//! ## Scope
//!
//! Codec layer — the bit-field encodings + the canonical DCO
//! constants for the published DP / HDMI link rates. Solving for
//! the divider triple given an arbitrary pixel clock is deferred
//! to Stage-3.

// ── DPLL register block (TGL PRM Vol. 11 §"DPLL Registers") ──────

/// `DPCLKA_CFGCR0` — DDI ↔ DPLL routing latch. Gen12 address
/// (ICL+): 0x164280. The pre-lane-1 value 0x6C200 was the
/// pre-ICL LCPLL-block address and addressed the wrong block on
/// every Gen12 part.
pub const DPCLKA_CFGCR0: u64 = 0x0000_164280;

/// `DPCLKA_CFGCR0` clock-off bit for combo PHY `phy` (0 = DDI A):
/// bits 10, 11, 24, 4, 5 for phys 0..4 (ICL encoding). Lane 1
/// programs DDI A only; the helper covers the combo PHYs A..C.
pub const fn dpclka_clk_off(phy: u32) -> u32 {
    match phy {
        0 => 1 << 10,
        1 => 1 << 11,
        2 => 1 << 24,
        _ => 0,
    }
}

/// `DPCLKA_CFGCR0` clock-select field for combo PHY `phy`: a
/// 2-bit DPLL index at shift `phy * 2` (phys 0..3).
pub const fn dpclka_clk_sel(dpll_idx: u32, phy: u32) -> u32 {
    (dpll_idx & 0x3) << (phy * 2)
}

/// Mask of the clock-select field for combo PHY `phy`.
pub const fn dpclka_clk_sel_mask(phy: u32) -> u32 {
    0x3 << (phy * 2)
}

/// Per-DPLL config register 0 base. Each DPLL is at +0x8 from
/// the previous (LO at +0x00, HI at +0x04).
pub const DPLL_CFGCR0_DPLL0: u64 = 0x0000_164284;
pub const DPLL_CFGCR0_DPLL1: u64 = 0x0000_16428C;
pub const DPLL_CFGCR0_DPLL2: u64 = 0x0000_164294;
pub const DPLL_CFGCR0_DPLL3: u64 = 0x0000_16429C;

/// Per-DPLL config register 1 (sits at +4 from CFGCR0).
pub const fn dpll_cfgcr1(cfgcr0: u64) -> u64 {
    cfgcr0 + 4
}

// ── DPLL_CFGCR0 fields (TGL PRM Vol. 11 §"DPLL_CFGCR0") ─────────

/// DCO integer field bits[9:0] (TGL PRM Vol. 11; the pre-lane-1
/// codec claimed bits[14:0], which overlaps the fraction field).
pub const fn cfgcr0_dco_integer(int: u16) -> u32 {
    (int as u32) & 0x3FF
}

/// DCO fraction field bits[24:10] — 15-bit fractional component
/// in units of 1/2^15. The pre-lane-1 codec used 10 bits at
/// [24:15], which truncated the PRM fractions (0x7000 & 0x3FF
/// = 0) — every published row silently lost its fraction.
pub const fn cfgcr0_dco_fraction(frac: u16) -> u32 {
    ((frac as u32) & 0x7FFF) << 10
}

// ── DPLL_CFGCR1 fields (TGL PRM Vol. 11 §"DPLL_CFGCR1") ─────────

/// Q-divider ratio field bits[17:10]. Ratio value 0 encodes a
/// ratio of 1 (the PRM DP rows all use Q = 1).
pub const fn cfgcr1_qdiv_ratio(q: u8) -> u32 {
    (q as u32) << 10
}
/// Q-divider mode bit[9] (1 → divide-by-2; 0 → ratio field rules).
pub const CFGCR1_QDIV_MODE_DIV2: u32 = 1 << 9;

/// K-divider field bits[8:6]. Documented values:
pub const CFGCR1_KDIV_1: u32 = 0b001 << 6;
pub const CFGCR1_KDIV_2: u32 = 0b010 << 6;
pub const CFGCR1_KDIV_3: u32 = 0b100 << 6;

/// P-divider field bits[5:2].
pub const CFGCR1_PDIV_2: u32 = 0b0001 << 2;
pub const CFGCR1_PDIV_3: u32 = 0b0010 << 2;
pub const CFGCR1_PDIV_5: u32 = 0b0100 << 2;
pub const CFGCR1_PDIV_7: u32 = 0b1000 << 2;

/// Central frequency selector bits[1:0]. The field value 3
/// selects the 8400 MHz central frequency used with an 8100 MHz
/// DCO (TGL PRM Vol. 11). The pre-lane-1 codec encoded 8.4 GHz
/// as 0b10, which selects a different (reserved on TGL) band.
pub const CFGCR1_CFREQ_8_4_GHZ: u32 = 0b11;

// ── Documented DP / HDMI link rates ──────────────────────────────
//
// Source: VESA DisplayPort 1.4a §2.9.3.2 (link bw set → Gbps) +
// HDMI 2.1 TMDS rate table.
//
// `DpLinkRate` is shared with the existing dp_link_training
// module's enum, but we replicate the Gbps numbers locally to
// keep this module self-contained for Stage-2.

/// Documented DP / HDMI link rates the DPLLs need to synthesise.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum LinkRate {
    /// 1.62 Gbps — DP RBR (Reduced Bit Rate).
    DpRbr,
    /// 2.7 Gbps — DP HBR.
    DpHbr,
    /// 5.4 Gbps — DP HBR2.
    DpHbr2,
    /// 8.1 Gbps — DP HBR3.
    DpHbr3,
    /// 5.94 Gbps — HDMI 2.0 4K60.
    Hdmi594,
    /// 2.97 Gbps — HDMI 1.4 / 2.0 4K30.
    Hdmi297,
}

impl LinkRate {
    /// VESA / HDMI link-symbol rate in megabits per second.
    pub const fn megabits_per_sec(self) -> u32 {
        match self {
            LinkRate::DpRbr => 1620,
            LinkRate::DpHbr => 2700,
            LinkRate::DpHbr2 => 5400,
            LinkRate::DpHbr3 => 8100,
            LinkRate::Hdmi594 => 5940,
            LinkRate::Hdmi297 => 2970,
        }
    }

    /// DPCD `LINK_BW_SET` byte for the DP rates; `None` for HDMI.
    /// VESA DP 1.4a §2.9.3.2.
    pub const fn dpcd_link_bw_set(self) -> Option<u8> {
        Some(match self {
            LinkRate::DpRbr => 0x06,
            LinkRate::DpHbr => 0x0A,
            LinkRate::DpHbr2 => 0x14,
            LinkRate::DpHbr3 => 0x1E,
            _ => return None,
        })
    }
}

/// Canonical DPLL coefficients for the documented Combo-PHY DP
/// link rates. PRM Vol. 11 §"DPLL Coefficients — DP Combo PHY".
///
/// Each row is the (DCO integer, DCO fraction, Q-divider, K-
/// divider tag, P-divider tag, central-frequency tag) the PRM
/// publishes for the corresponding link rate. Stage-2 keeps
/// these as `(int, frac)` constants; the divider tags are
/// already-encoded `CFGCR1_*` bits.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DpllCoeffs {
    pub dco_integer: u16,
    pub dco_fraction: u16,
    pub cfgcr1: u32,
}

// Canonical rows: TGL PRM Vol. 12, "DisplayPort Mode PLL Values"
// for the 19.2/38.4 MHz reference family. Both reference families
// share DCO = 8100 MHz (24 MHz ref: int 0x151, frac 0x4000;
// 19.2/38.4 MHz ref: int 0x1A5, frac 0x7000 — 421.875 x 19.2 =
// 8100). The P/K/Q dividers are identical across families:
//   RBR  (1.62 Gbps): P/5, K/2, Q=1 -> 8100/10 = 810 MHz out
//   HBR  (2.7  Gbps): P/3, K/2, Q=1 -> 8100/6  = 1350
//   HBR2 (5.4  Gbps): P/3, K/1, Q=1 -> 8100/3  = 2700
//   HBR3 (8.1  Gbps): P/2, K/1, Q=1 -> 8100/2  = 4050
// PLL output = 5x symbol rate = bit rate / 2, so output x 2 is
// the bit rate. Before lane 1 the HBR2 and HBR3 rows were
// byte-identical (both P/2 K/1) and every fraction was 0 — HBR,
// HBR2 and RBR were all programmed with wrong dividers.
// Reference-clock family selection via the DSSM register is not
// yet implemented; the rows below are the 19.2/38.4 family the
// pre-existing DCO integer already presumed.

/// Combo-PHY coefficients for HBR2 (5.4 Gbps).
pub const COMBO_HBR2: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x01A5,
    dco_fraction: 0x7000,
    cfgcr1: CFGCR1_KDIV_1 | CFGCR1_PDIV_3 | CFGCR1_CFREQ_8_4_GHZ,
};

/// Combo-PHY coefficients for HBR (2.7 Gbps).
pub const COMBO_HBR: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x01A5,
    dco_fraction: 0x7000,
    cfgcr1: CFGCR1_KDIV_2 | CFGCR1_PDIV_3 | CFGCR1_CFREQ_8_4_GHZ,
};

/// Combo-PHY coefficients for RBR (1.62 Gbps).
pub const COMBO_RBR: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x01A5,
    dco_fraction: 0x7000,
    cfgcr1: CFGCR1_KDIV_2 | CFGCR1_PDIV_5 | CFGCR1_CFREQ_8_4_GHZ,
};

/// Combo-PHY coefficients for HBR3 (8.1 Gbps).
pub const COMBO_HBR3: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x01A5,
    dco_fraction: 0x7000,
    cfgcr1: CFGCR1_KDIV_1 | CFGCR1_PDIV_2 | CFGCR1_CFREQ_8_4_GHZ,
};

/// Resolve the published Combo-PHY coefficients for `rate`.
pub fn combo_coeffs(rate: LinkRate) -> Option<DpllCoeffs> {
    Some(match rate {
        LinkRate::DpRbr => COMBO_RBR,
        LinkRate::DpHbr => COMBO_HBR,
        LinkRate::DpHbr2 => COMBO_HBR2,
        LinkRate::DpHbr3 => COMBO_HBR3,
        LinkRate::Hdmi297 | LinkRate::Hdmi594 => return None,
    })
}

// ── 24 MHz reference family ─────────────────────────────────────
//
// The PRM table carries a second reference family: with a 24 MHz
// reference the same 8100 MHz DCO is int 0x151 / frac 0x4000
// (337.5 × 24 MHz), and the P/K/Q divider fields are identical
// to the 19.2/38.4 MHz family above (cross-checked against
// i915's `icl_dp_combo_pll_24mhz_values[]`, which encodes the
// same PRM Vol. 11 table). #1092 verified both families row by
// row; the rows are carried as data so the table is complete.
//
// Reference-family *selection* (reading the DSSM register to
// learn which reference the platform straps) remains #1024's
// scope — `combo_coeffs` keeps resolving the 19.2/38.4 family,
// and nothing in the modeset path consults the 24 MHz rows yet.

/// Combo-PHY coefficients, 24 MHz reference: RBR.
pub const COMBO24_RBR: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x0151,
    dco_fraction: 0x4000,
    cfgcr1: CFGCR1_KDIV_2 | CFGCR1_PDIV_5 | CFGCR1_CFREQ_8_4_GHZ,
};

/// Combo-PHY coefficients, 24 MHz reference: HBR.
pub const COMBO24_HBR: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x0151,
    dco_fraction: 0x4000,
    cfgcr1: CFGCR1_KDIV_2 | CFGCR1_PDIV_3 | CFGCR1_CFREQ_8_4_GHZ,
};

/// Combo-PHY coefficients, 24 MHz reference: HBR2.
pub const COMBO24_HBR2: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x0151,
    dco_fraction: 0x4000,
    cfgcr1: CFGCR1_KDIV_1 | CFGCR1_PDIV_3 | CFGCR1_CFREQ_8_4_GHZ,
};

/// Combo-PHY coefficients, 24 MHz reference: HBR3.
pub const COMBO24_HBR3: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x0151,
    dco_fraction: 0x4000,
    cfgcr1: CFGCR1_KDIV_1 | CFGCR1_PDIV_2 | CFGCR1_CFREQ_8_4_GHZ,
};

/// Which reference-clock family a Combo-PHY DPLL row belongs
/// to. Selection between families at runtime is via DSSM
/// (#1024); this type exists so the table can be carried and
/// fixture-pinned completely in the meantime.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ReferenceFamily {
    /// 19.2 / 38.4 MHz reference (DCO int 0x1A5, frac 0x7000).
    Ref19_2Or38_4,
    /// 24 MHz reference (DCO int 0x151, frac 0x4000).
    Ref24,
}

/// Resolve Combo-PHY coefficients for `rate` within an explicit
/// reference family. `combo_coeffs` is this function at
/// [`ReferenceFamily::Ref19_2Or38_4`].
pub fn combo_coeffs_for_ref(rate: LinkRate, family: ReferenceFamily) -> Option<DpllCoeffs> {
    match family {
        ReferenceFamily::Ref19_2Or38_4 => combo_coeffs(rate),
        ReferenceFamily::Ref24 => Some(match rate {
            LinkRate::DpRbr => COMBO24_RBR,
            LinkRate::DpHbr => COMBO24_HBR,
            LinkRate::DpHbr2 => COMBO24_HBR2,
            LinkRate::DpHbr3 => COMBO24_HBR3,
            LinkRate::Hdmi297 | LinkRate::Hdmi594 => return None,
        }),
    }
}

/// Encode the full `DPLL_CFGCR0` word from coefficients.
pub fn encode_cfgcr0(c: &DpllCoeffs) -> u32 {
    cfgcr0_dco_integer(c.dco_integer) | cfgcr0_dco_fraction(c.dco_fraction)
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_link_rate_megabits() -> TestResult {
        if LinkRate::DpHbr3.megabits_per_sec() != 8100 {
            return TestResult::Fail("HBR3 should be 8.1 Gbps");
        }
        if LinkRate::Hdmi594.megabits_per_sec() != 5940 {
            return TestResult::Fail("HDMI 5.94 should be 5940 Mbps");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pll", smoke_link_rate_megabits);

    fn smoke_dpcd_link_bw_set() -> TestResult {
        if LinkRate::DpHbr2.dpcd_link_bw_set() != Some(0x14) {
            return TestResult::Fail("HBR2 → 0x14");
        }
        if LinkRate::DpHbr3.dpcd_link_bw_set() != Some(0x1E) {
            return TestResult::Fail("HBR3 → 0x1E");
        }
        if LinkRate::Hdmi594.dpcd_link_bw_set().is_some() {
            return TestResult::Fail("HDMI rates have no LINK_BW_SET");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pll", smoke_dpcd_link_bw_set);

    fn smoke_combo_coeffs_resolution() -> TestResult {
        if combo_coeffs(LinkRate::DpHbr2) != Some(COMBO_HBR2) {
            return TestResult::Fail("HBR2 coeffs not resolved");
        }
        if combo_coeffs(LinkRate::Hdmi594).is_some() {
            return TestResult::Fail("HDMI must not resolve to combo coeffs");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pll", smoke_combo_coeffs_resolution);

    fn smoke_cfgcr0_encoding() -> TestResult {
        let v = encode_cfgcr0(&COMBO_HBR2);
        if v & 0x3FF != COMBO_HBR2.dco_integer as u32 {
            return TestResult::Fail("DCO integer not in low 10 bits");
        }
        if (v >> 10) & 0x7FFF != COMBO_HBR2.dco_fraction as u32 {
            return TestResult::Fail("DCO fraction not at bits[24:10]");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pll", smoke_cfgcr0_encoding);

    /// Pin the PRM Vol. 12 DP PLL table: the four rates must have
    /// distinct divider encodings, share DCO 8100 MHz for the
    /// 19.2/38.4 MHz reference family, and compose a CFGCR1 whose
    /// Q ratio field is 0 (Q = 1) as the PRM requires when
    /// K != 2 — and also when K == 2.
    fn smoke_combo_coeffs_match_prm_table() -> TestResult {
        let rows = [COMBO_RBR, COMBO_HBR, COMBO_HBR2, COMBO_HBR3];
        for r in rows {
            if r.dco_integer != 0x1A5 || r.dco_fraction != 0x7000 {
                return TestResult::Fail("DCO must be 8100 MHz (0x1A5 + 0x7000/2^15)");
            }
            if cfgcr1_qdiv_ratio(0) != 0 || (r.cfgcr1 >> 10) & 0xFF != 0 {
                return TestResult::Fail("Q divider ratio field must encode Q=1");
            }
        }
        if COMBO_HBR2.cfgcr1 == COMBO_HBR3.cfgcr1 {
            return TestResult::Fail("HBR2 and HBR3 divider rows must differ");
        }
        // P/K fields: RBR P5|K2, HBR P3|K2, HBR2 P3|K1, HBR3 P2|K1.
        if COMBO_RBR.cfgcr1 & (CFGCR1_PDIV_5 | CFGCR1_KDIV_2) != CFGCR1_PDIV_5 | CFGCR1_KDIV_2 {
            return TestResult::Fail("RBR must be P/5 K/2");
        }
        if COMBO_HBR.cfgcr1 & (CFGCR1_PDIV_3 | CFGCR1_KDIV_2) != CFGCR1_PDIV_3 | CFGCR1_KDIV_2 {
            return TestResult::Fail("HBR must be P/3 K/2");
        }
        if COMBO_HBR2.cfgcr1 & (CFGCR1_PDIV_3 | CFGCR1_KDIV_1) != CFGCR1_PDIV_3 | CFGCR1_KDIV_1 {
            return TestResult::Fail("HBR2 must be P/3 K/1");
        }
        if COMBO_HBR3.cfgcr1 & (CFGCR1_PDIV_2 | CFGCR1_KDIV_1) != CFGCR1_PDIV_2 | CFGCR1_KDIV_1 {
            return TestResult::Fail("HBR3 must be P/2 K/1");
        }
        if DPCLKA_CFGCR0 != 0x164280 {
            return TestResult::Fail("DPCLKA_CFGCR0 must be the Gen12 address 0x164280");
        }
        if dpclka_clk_sel(0, 0) != 0 || dpclka_clk_off(0) != 1 << 10 {
            return TestResult::Fail("DDI A must select DPLL0 with clock on");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_pll",
        smoke_combo_coeffs_match_prm_table
    );

    /// Pin the 24 MHz reference family (#1092): same 8100 MHz
    /// DCO expressed as int 0x151 / frac 0x4000 (337.5 × 24 MHz),
    /// divider fields identical to the 19.2/38.4 family rate for
    /// rate, and HBR2 ≠ HBR3 here too. Values transcribed from
    /// the PRM Vol. 11 DP combo-PHY table (cross-checked against
    /// i915's `icl_dp_combo_pll_24mhz_values[]`).
    fn smoke_combo_coeffs_24mhz_family_match_prm_table() -> TestResult {
        let rows24 = [COMBO24_RBR, COMBO24_HBR, COMBO24_HBR2, COMBO24_HBR3];
        let rows19 = [COMBO_RBR, COMBO_HBR, COMBO_HBR2, COMBO_HBR3];
        for (r24, r19) in rows24.iter().zip(rows19.iter()) {
            if r24.dco_integer != 0x151 || r24.dco_fraction != 0x4000 {
                return TestResult::Fail("24 MHz DCO must be 8100 MHz (0x151 + 0x4000/2^15)");
            }
            if r24.cfgcr1 != r19.cfgcr1 {
                return TestResult::Fail("divider fields must match across reference families");
            }
        }
        if COMBO24_HBR2.cfgcr1 == COMBO24_HBR3.cfgcr1 {
            return TestResult::Fail("24 MHz HBR2 and HBR3 rows must differ");
        }
        // Resolver: the default stays the 19.2/38.4 family; the
        // 24 MHz family resolves only when asked for explicitly.
        if combo_coeffs_for_ref(LinkRate::DpHbr3, ReferenceFamily::Ref24) != Some(COMBO24_HBR3) {
            return TestResult::Fail("Ref24 resolver must return the 24 MHz HBR3 row");
        }
        if combo_coeffs_for_ref(LinkRate::DpHbr3, ReferenceFamily::Ref19_2Or38_4)
            != Some(COMBO_HBR3)
        {
            return TestResult::Fail("Ref19_2Or38_4 resolver must return the 19.2 MHz HBR3 row");
        }
        if combo_coeffs_for_ref(LinkRate::Hdmi594, ReferenceFamily::Ref24).is_some() {
            return TestResult::Fail("HDMI must not resolve in either family");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_pll",
        smoke_combo_coeffs_24mhz_family_match_prm_table
    );
}

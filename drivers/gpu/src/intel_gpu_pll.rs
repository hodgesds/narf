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

// Canonical rows: TGL PRM Vol. 12, "DisplayPort Mode PLL Values".
// Both reference families share DCO = 8100 MHz (24 MHz ref:
// int 0x151, frac 0x4000 — 337.5 x 24 = 8100; 19.2/38.4 MHz ref:
// int 0x1A5, frac 0x7000 — 421.875 x 19.2 = 8100). The P/K/Q
// dividers are identical across families:
//   RBR  (1.62 Gbps): P/5, K/2, Q=1 -> 8100/10 = 810 MHz out
//   HBR  (2.7  Gbps): P/3, K/2, Q=1 -> 8100/6  = 1350
//   HBR2 (5.4  Gbps): P/3, K/1, Q=1 -> 8100/3  = 2700
//   HBR3 (8.1  Gbps): P/2, K/1, Q=1 -> 8100/2  = 4050
// PLL output = 5x symbol rate = bit rate / 2, so output x 2 is
// the bit rate. Before lane 1 the HBR2 and HBR3 rows were
// byte-identical (both P/2 K/1) and every fraction was 0 — HBR,
// HBR2 and RBR were all programmed with wrong dividers.
//
// The rows cover the four standard DP rates in
// `dp_link_training`'s ladder. The PRM table's intermediate
// rates (2.16 / 4.32 / 6.48 Gbps, used by some eDP panels) use
// *different* DCO integers and a Q-divide-by-2 row; they are
// not in the training ladder and are not encoded here.
//
// Reference-clock family selection (lane Q6, #1024): the DSSM
// register's CDCLK PLL reference field picks the family — see
// `decode_refclk_family` below. Lane 1 always programmed the
// 19.2/38.4 family, which on a 24 MHz-strapped part yields a
// DCO 26% off target and a PLL that never locks on-spec.

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

// ── Reference-clock family (DSSM) ────────────────────────────
//
// `SKL_DSSM` at 0x51004 carries the CDCLK PLL reference-clock
// strap in bits [31:29] (`ICL_DSSM_CDCLK_PLL_REFCLK_*` in
// i915's intel_display_regs.h): 0 → 24 MHz, 1 → 19.2 MHz,
// 2 → 38.4 MHz. The combo DPLLs share that reference. i915's
// `icl_readout_refclk` decodes exactly this field, and its
// default arm (reserved encodings) falls through to 24 MHz;
// `decode_refclk_family` mirrors that.

/// `SKL_DSSM` — display strapping register.
pub const DSSM: u64 = 0x0005_1004;

/// DSSM CDCLK PLL reference field: bits [31:29].
pub const DSSM_REFCLK_SHIFT: u32 = 29;

/// Reference-clock family for the combo-PLL coefficient rows.
/// The PRM publishes two DP row families: 24 MHz, and
/// 19.2/38.4 MHz (the two share rows because the DCO target
/// and divider set are identical for both straps).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RefclkFamily {
    /// 24 MHz strap → DCO int 0x151 / frac 0x4000 rows.
    Ref24Mhz,
    /// 19.2 or 38.4 MHz strap → DCO int 0x1A5 / frac 0x7000 rows.
    Ref19_2Or38_4Mhz,
}

/// Decode the reference-clock family from a raw DSSM value.
/// Reserved field encodings (3..=7) resolve to the 24 MHz
/// family, matching i915's fallthrough in `icl_readout_refclk`.
pub const fn decode_refclk_family(dssm: u32) -> RefclkFamily {
    match (dssm >> DSSM_REFCLK_SHIFT) & 0x7 {
        1 | 2 => RefclkFamily::Ref19_2Or38_4Mhz,
        _ => RefclkFamily::Ref24Mhz,
    }
}

/// Reference frequency in kHz for a family member strap —
/// informational; the coefficient rows only depend on the
/// family. `dssm` selects between 19.2 and 38.4 within the
/// shared family.
pub const fn refclk_khz(dssm: u32) -> u32 {
    match (dssm >> DSSM_REFCLK_SHIFT) & 0x7 {
        1 => 19_200,
        2 => 38_400,
        _ => 24_000,
    }
}

/// Combo-PHY coefficients for HBR2 (5.4 Gbps), 24 MHz family.
pub const COMBO_HBR2_REF24: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x0151,
    dco_fraction: 0x4000,
    cfgcr1: CFGCR1_KDIV_1 | CFGCR1_PDIV_3 | CFGCR1_CFREQ_8_4_GHZ,
};

/// Combo-PHY coefficients for HBR (2.7 Gbps), 24 MHz family.
pub const COMBO_HBR_REF24: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x0151,
    dco_fraction: 0x4000,
    cfgcr1: CFGCR1_KDIV_2 | CFGCR1_PDIV_3 | CFGCR1_CFREQ_8_4_GHZ,
};

/// Combo-PHY coefficients for RBR (1.62 Gbps), 24 MHz family.
pub const COMBO_RBR_REF24: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x0151,
    dco_fraction: 0x4000,
    cfgcr1: CFGCR1_KDIV_2 | CFGCR1_PDIV_5 | CFGCR1_CFREQ_8_4_GHZ,
};

/// Combo-PHY coefficients for HBR3 (8.1 Gbps), 24 MHz family.
pub const COMBO_HBR3_REF24: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x0151,
    dco_fraction: 0x4000,
    cfgcr1: CFGCR1_KDIV_1 | CFGCR1_PDIV_2 | CFGCR1_CFREQ_8_4_GHZ,
};

/// Resolve the published Combo-PHY coefficients for `rate`
/// under reference-clock `family`.
pub fn combo_coeffs(rate: LinkRate, family: RefclkFamily) -> Option<DpllCoeffs> {
    Some(match (rate, family) {
        (LinkRate::DpRbr, RefclkFamily::Ref19_2Or38_4Mhz) => COMBO_RBR,
        (LinkRate::DpHbr, RefclkFamily::Ref19_2Or38_4Mhz) => COMBO_HBR,
        (LinkRate::DpHbr2, RefclkFamily::Ref19_2Or38_4Mhz) => COMBO_HBR2,
        (LinkRate::DpHbr3, RefclkFamily::Ref19_2Or38_4Mhz) => COMBO_HBR3,
        (LinkRate::DpRbr, RefclkFamily::Ref24Mhz) => COMBO_RBR_REF24,
        (LinkRate::DpHbr, RefclkFamily::Ref24Mhz) => COMBO_HBR_REF24,
        (LinkRate::DpHbr2, RefclkFamily::Ref24Mhz) => COMBO_HBR2_REF24,
        (LinkRate::DpHbr3, RefclkFamily::Ref24Mhz) => COMBO_HBR3_REF24,
        (LinkRate::Hdmi297 | LinkRate::Hdmi594, _) => return None,
    })
}

/// Encode the full `DPLL_CFGCR0` word from coefficients.
pub fn encode_cfgcr0(c: &DpllCoeffs) -> u32 {
    cfgcr0_dco_integer(c.dco_integer) | cfgcr0_dco_fraction(c.dco_fraction)
}

// ── HDMI WRPLL (computed coefficients) ──────────────────────────
//
// Unlike DP — whose four rates have fixed PRM table rows — HDMI
// takes an arbitrary TMDS character clock from the sink's EDID,
// so the Combo-PHY coefficients are *computed* with the WRPLL
// divider search. The algorithm below is the one the PRM's
// Combo-PHY PLL programming sequence describes and i915
// implements as `cnl_ddi_calculate_wrpll` +
// `cnl_wrpll_get_multipliers` + `cnl_wrpll_params_populate`
// (used for HDMI on CNL and on ICL+ alike; `icl_calc_dpll_state`
// routes HDMI/DSI through it and composes CFGCR1 with
// `DPLL_CFGCR1_CENTRAL_FREQ_8400`, the same central-frequency
// field every row in this module carries):
//
//   afe_clock = tmds_clock * 5     (the PLL output is 5x the
//                                   TMDS character rate)
//   for each candidate total divider d (fixed list, below):
//       dco = afe_clock * d
//       keep d if 7_998_000 <= dco <= 10_000_000 kHz and dco is
//       closest to the window centre 8_999_000 kHz (first wins
//       ties — the list order is part of the algorithm)
//   decompose d into (pdiv, qdiv, kdiv) with the multiplier
//   table in [`wrpll_multipliers`]
//   dco_integer / dco_fraction = dco / ref_clock in 1/2^15 units
//
// Reference clock: as in `cnl_hdmi_pll_ref_clock`, a 38.4 MHz
// reference is used as 19.2 MHz (the DPLL divides it by two
// internally), so [`RefclkFamily::Ref19_2Or38_4Mhz`] divides by
// 19_200 kHz here exactly as its fixed rows presume.
//
// Q-field encoding follows `cnl_wrpll_params_populate`
// verbatim: the ratio field carries the divider value itself
// and the QDIV_MODE bit is set iff qdiv != 1. (The fixed DP
// rows above carry ratio 0 for Q = 1; the field is consulted
// only when QDIV_MODE engages the divider, and the HDMI path's
// encoding is the shipping driver's.)

/// Candidate total dividers, in the search's order.
const WRPLL_DIVIDERS: &[u32] = &[
    2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 24, 28, 30, 32, 36, 40, 42, 44, 48, 50, 52, 54, 56, 60, 64,
    66, 68, 70, 72, 76, 78, 80, 84, 88, 90, 92, 96, 98, 100, 102, 3, 5, 7, 9, 15, 21,
];

/// DCO window for the Combo-PHY WRPLL search (kHz).
const WRPLL_DCO_MIN_KHZ: u64 = 7_998_000;
const WRPLL_DCO_MAX_KHZ: u64 = 10_000_000;
const WRPLL_DCO_MID_KHZ: u64 = (WRPLL_DCO_MIN_KHZ + WRPLL_DCO_MAX_KHZ) / 2;

/// Decompose a total divider into (pdiv, qdiv, kdiv) —
/// `cnl_wrpll_get_multipliers` transcribed: even dividers
/// factor through P = 2/3/5/7 with K = 2 (except 2 itself,
/// which is P2/Q1/K1); the odd tail {3, 5, 7} is P-only and
/// {9, 15, 21} is P/3 with K = 3.
fn wrpll_multipliers(best_div: u32) -> (u32, u32, u32) {
    if best_div % 2 == 0 {
        if best_div == 2 {
            (2, 1, 1)
        } else if best_div % 4 == 0 {
            (2, best_div / 4, 2)
        } else if best_div % 6 == 0 {
            (3, best_div / 6, 2)
        } else if best_div % 5 == 0 {
            (5, best_div / 10, 2)
        } else {
            // Remaining even list members are 14 | 98 (x14).
            (7, best_div / 14, 2)
        }
    } else if matches!(best_div, 3 | 5 | 7) {
        (best_div, 1, 1)
    } else {
        // 9, 15, 21.
        (best_div / 3, 1, 3)
    }
}

/// Compute the Combo-PHY DPLL coefficients for an HDMI TMDS
/// character clock (`tmds_clock_khz`, = the mode's pixel clock
/// at 8 bpc) under reference family `family`, via the WRPLL
/// search above. `None` when no candidate divider lands the
/// DCO inside its window (clock beyond the HDMI 2.0 envelope
/// this PHY generation synthesises).
pub fn hdmi_wrpll_coeffs(tmds_clock_khz: u32, family: RefclkFamily) -> Option<DpllCoeffs> {
    let ref_khz: u64 = match family {
        RefclkFamily::Ref24Mhz => 24_000,
        RefclkFamily::Ref19_2Or38_4Mhz => 19_200,
    };
    let afe_clock = (tmds_clock_khz as u64) * 5;
    let mut best: Option<(u32, u64)> = None; // (divider, dco_khz)
    let mut best_centrality = u64::MAX;
    for &d in WRPLL_DIVIDERS {
        let dco = afe_clock * (d as u64);
        if (WRPLL_DCO_MIN_KHZ..=WRPLL_DCO_MAX_KHZ).contains(&dco) {
            let centrality = dco.abs_diff(WRPLL_DCO_MID_KHZ);
            if centrality < best_centrality {
                best_centrality = centrality;
                best = Some((d, dco));
            }
        }
    }
    let (best_div, best_dco) = best?;
    let (pdiv, qdiv, kdiv) = wrpll_multipliers(best_div);
    // dco in 1/2^15 units of the reference, split int/frac —
    // `cnl_wrpll_params_populate`'s `(dco << 15) / ref`.
    let scaled = (best_dco << 15) / ref_khz;
    let dco_integer = (scaled >> 15) as u16;
    let dco_fraction = (scaled & 0x7FFF) as u16;
    let pdiv_bits = match pdiv {
        2 => CFGCR1_PDIV_2,
        3 => CFGCR1_PDIV_3,
        5 => CFGCR1_PDIV_5,
        _ => CFGCR1_PDIV_7,
    };
    let kdiv_bits = match kdiv {
        1 => CFGCR1_KDIV_1,
        2 => CFGCR1_KDIV_2,
        _ => CFGCR1_KDIV_3,
    };
    let mut cfgcr1 = cfgcr1_qdiv_ratio(qdiv as u8) | kdiv_bits | pdiv_bits | CFGCR1_CFREQ_8_4_GHZ;
    if qdiv != 1 {
        cfgcr1 |= CFGCR1_QDIV_MODE_DIV2;
    }
    Some(DpllCoeffs {
        dco_integer,
        dco_fraction,
        cfgcr1,
    })
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
        if combo_coeffs(LinkRate::DpHbr2, RefclkFamily::Ref19_2Or38_4Mhz) != Some(COMBO_HBR2) {
            return TestResult::Fail("HBR2 coeffs not resolved");
        }
        if combo_coeffs(LinkRate::Hdmi594, RefclkFamily::Ref24Mhz).is_some() {
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

    /// DSSM reference-field decode: the three documented straps
    /// plus the reserved-encoding fallthrough to 24 MHz.
    fn smoke_dssm_refclk_family_decode() -> TestResult {
        if DSSM != 0x5_1004 {
            return TestResult::Fail("DSSM must be at 0x51004");
        }
        if decode_refclk_family(0) != RefclkFamily::Ref24Mhz {
            return TestResult::Fail("DSSM field 0 must be the 24 MHz family");
        }
        if decode_refclk_family(1 << 29) != RefclkFamily::Ref19_2Or38_4Mhz {
            return TestResult::Fail("DSSM field 1 (19.2 MHz) must be the shared family");
        }
        if decode_refclk_family(2 << 29) != RefclkFamily::Ref19_2Or38_4Mhz {
            return TestResult::Fail("DSSM field 2 (38.4 MHz) must be the shared family");
        }
        if decode_refclk_family(5 << 29) != RefclkFamily::Ref24Mhz {
            return TestResult::Fail("reserved DSSM encodings fall through to 24 MHz");
        }
        // Low bits of DSSM must not leak into the decode.
        if decode_refclk_family(0x1FFF_FFFF) != RefclkFamily::Ref24Mhz {
            return TestResult::Fail("DSSM decode must mask to bits [31:29]");
        }
        if refclk_khz(1 << 29) != 19_200 || refclk_khz(2 << 29) != 38_400 {
            return TestResult::Fail("refclk_khz strap values wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pll", smoke_dssm_refclk_family_decode);

    /// The 24 MHz family: same P/K/Q dividers as the
    /// 19.2/38.4 family, DCO int 0x151 / frac 0x4000
    /// (337.5 × 24 MHz = 8100 MHz), and CFGCR0 words that pin
    /// both fields byte-for-byte.
    fn smoke_combo_coeffs_ref24_family() -> TestResult {
        let rows24 = [
            COMBO_RBR_REF24,
            COMBO_HBR_REF24,
            COMBO_HBR2_REF24,
            COMBO_HBR3_REF24,
        ];
        let rows19 = [COMBO_RBR, COMBO_HBR, COMBO_HBR2, COMBO_HBR3];
        for (r24, r19) in rows24.iter().zip(rows19.iter()) {
            if r24.dco_integer != 0x151 || r24.dco_fraction != 0x4000 {
                return TestResult::Fail("24 MHz rows must be int 0x151 / frac 0x4000");
            }
            if r24.cfgcr1 != r19.cfgcr1 {
                return TestResult::Fail("P/K/Q dividers must be identical across families");
            }
        }
        // CFGCR0 pins: HBR2 in both families. int at [9:0],
        // frac at [24:10]: 0x4000 << 10 = 0x100_0000,
        // 0x7000 << 10 = 0x1C00_000.
        if encode_cfgcr0(&COMBO_HBR2_REF24) != 0x0100_0151 {
            return TestResult::Fail("24 MHz HBR2 CFGCR0 pin wrong");
        }
        if encode_cfgcr0(&COMBO_HBR2) != 0x01C0_01A5 {
            return TestResult::Fail("19.2 MHz HBR2 CFGCR0 pin wrong");
        }
        // Family selection resolves per rate.
        if combo_coeffs(LinkRate::DpRbr, RefclkFamily::Ref24Mhz) != Some(COMBO_RBR_REF24) {
            return TestResult::Fail("RBR must resolve to the 24 MHz row");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pll", smoke_combo_coeffs_ref24_family);

    /// Pin the HDMI WRPLL search (#1019) against hand-worked
    /// runs of the algorithm in `cnl_ddi_calculate_wrpll`:
    /// AFE = 5 x TMDS clock; the winning divider is the one
    /// whose DCO lands in [7_998_000, 10_000_000] kHz closest
    /// to the 8_999_000 centre; (p, q, k) from the multiplier
    /// decomposition. Expected (int, frac) are the exact
    /// rationals DCO/ref in 1/2^15 units, worked independently
    /// of the implementation:
    ///
    ///   594_000 (4K60):  div 3  -> DCO 8_910_000, (3,1,1)
    ///   297_000 (4K30):  div 6  -> DCO 8_910_000, (3,1,2)
    ///   148_500 (1080p): div 12 -> DCO 8_910_000, (2,3,2)
    ///    74_250 (720p):  div 24 -> DCO 8_910_000, (2,6,2)
    ///    25_200 (480p):  div 72 -> DCO 9_072_000, (2,18,2)
    fn smoke_hdmi_wrpll_rows() -> TestResult {
        // (tmds_khz, int@24MHz, frac@24, int@19.2MHz, frac@19.2, cfgcr1)
        let rows: [(u32, u16, u16, u16, u16, u32); 5] = [
            (594_000, 0x173, 0x2000, 0x1D0, 0x0800, 0x44B),
            (297_000, 0x173, 0x2000, 0x1D0, 0x0800, 0x48B),
            (148_500, 0x173, 0x2000, 0x1D0, 0x0800, 0xE87),
            (74_250, 0x173, 0x2000, 0x1D0, 0x0800, 0x1A87),
            (25_200, 0x17A, 0x0000, 0x1D8, 0x4000, 0x4A87),
        ];
        for (tmds, i24, f24, i19, f19, cfgcr1) in rows {
            let c24 = match hdmi_wrpll_coeffs(tmds, RefclkFamily::Ref24Mhz) {
                Some(c) => c,
                None => return TestResult::Fail("WRPLL must resolve standard TMDS clocks"),
            };
            if c24.dco_integer != i24 || c24.dco_fraction != f24 || c24.cfgcr1 != cfgcr1 {
                return TestResult::Fail("24 MHz WRPLL row mismatch");
            }
            let c19 = match hdmi_wrpll_coeffs(tmds, RefclkFamily::Ref19_2Or38_4Mhz) {
                Some(c) => c,
                None => return TestResult::Fail("WRPLL must resolve in the 19.2 MHz family"),
            };
            if c19.dco_integer != i19 || c19.dco_fraction != f19 || c19.cfgcr1 != cfgcr1 {
                return TestResult::Fail("19.2 MHz WRPLL row mismatch");
            }
            // Independent decode: the register fields must
            // synthesise exactly 5 x the TMDS clock — DCO from
            // (int + frac/2^15) x ref, out = DCO / (P*Q*K) with
            // the dividers decoded back out of CFGCR1.
            for (c, ref_khz) in [(c24, 24_000u64), (c19, 19_200u64)] {
                let dco_num = ref_khz * ((c.dco_integer as u64) * 32_768 + c.dco_fraction as u64);
                if dco_num % 32_768 != 0 {
                    return TestResult::Fail("DCO must be an exact kHz value");
                }
                let dco = dco_num / 32_768;
                let p: u64 = match (c.cfgcr1 >> 2) & 0xF {
                    1 => 2,
                    2 => 3,
                    4 => 5,
                    8 => 7,
                    _ => return TestResult::Fail("P field must decode"),
                };
                let k: u64 = match (c.cfgcr1 >> 6) & 0x7 {
                    1 => 1,
                    2 => 2,
                    4 => 3,
                    _ => return TestResult::Fail("K field must decode"),
                };
                let q: u64 = if c.cfgcr1 & CFGCR1_QDIV_MODE_DIV2 != 0 {
                    ((c.cfgcr1 >> 10) & 0xFF) as u64
                } else {
                    1
                };
                if dco % (p * q * k) != 0 || dco / (p * q * k) != (tmds as u64) * 5 {
                    return TestResult::Fail("decoded PLL output must be 5x the TMDS clock");
                }
            }
        }
        // Beyond the envelope: 1.2 GHz TMDS has no divider
        // (smallest product already overshoots the DCO window).
        if hdmi_wrpll_coeffs(1_200_000, RefclkFamily::Ref24Mhz).is_some() {
            return TestResult::Fail("out-of-window clock must not resolve");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pll", smoke_hdmi_wrpll_rows);
}

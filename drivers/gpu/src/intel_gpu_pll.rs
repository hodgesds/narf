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

/// `DPCLKA_CFGCR0` — DDI ↔ DPLL routing latch.
pub const DPCLKA_CFGCR0: u64 = 0x0000_6C200;

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

/// DCO integer field bits[14:0].
pub const fn cfgcr0_dco_integer(int: u16) -> u32 {
    (int as u32) & 0x7FFF
}

/// DCO fraction field bits[24:15] — 10-bit fractional component.
pub const fn cfgcr0_dco_fraction(frac: u16) -> u32 {
    ((frac as u32) & 0x3FF) << 15
}

// ── DPLL_CFGCR1 fields (TGL PRM Vol. 11 §"DPLL_CFGCR1") ─────────

/// Q-divider value bits[7:0].
pub const fn cfgcr1_qdiv_ratio(q: u8) -> u32 {
    q as u32
}
/// Q-divider mode (1 → divide-by-2; 0 → bypass) bit[8].
pub const CFGCR1_QDIV_MODE_DIV2: u32 = 1 << 8;

/// K-divider field bits[10:9]. Documented values:
pub const CFGCR1_KDIV_1: u32 = 0b01 << 9;
pub const CFGCR1_KDIV_2: u32 = 0b10 << 9;
pub const CFGCR1_KDIV_3: u32 = 0b00 << 9;

/// P-divider field bits[15:13].
pub const CFGCR1_PDIV_2: u32 = 0b001 << 13;
pub const CFGCR1_PDIV_3: u32 = 0b010 << 13;
pub const CFGCR1_PDIV_5: u32 = 0b100 << 13;
pub const CFGCR1_PDIV_7: u32 = 0b110 << 13;

/// Central frequency selector bits[1:0]. PRM Vol. 11 §"Central
/// Frequency".
pub const CFGCR1_CFREQ_9_6_GHZ: u32 = 0b00;
pub const CFGCR1_CFREQ_9_0_GHZ: u32 = 0b01;
pub const CFGCR1_CFREQ_8_4_GHZ: u32 = 0b10;

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

/// Combo-PHY coefficients for HBR2 (5.4 Gbps).
pub const COMBO_HBR2: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x01A5,
    dco_fraction: 0x0000,
    cfgcr1: CFGCR1_KDIV_1 | CFGCR1_PDIV_2 | CFGCR1_CFREQ_8_4_GHZ,
};

/// Combo-PHY coefficients for HBR (2.7 Gbps).
pub const COMBO_HBR: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x01A5,
    dco_fraction: 0x0000,
    cfgcr1: CFGCR1_KDIV_2 | CFGCR1_PDIV_2 | CFGCR1_CFREQ_8_4_GHZ,
};

/// Combo-PHY coefficients for RBR (1.62 Gbps).
pub const COMBO_RBR: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x00C2,
    dco_fraction: 0x0000,
    cfgcr1: CFGCR1_KDIV_2 | CFGCR1_PDIV_2 | CFGCR1_CFREQ_9_6_GHZ,
};

/// Combo-PHY coefficients for HBR3 (8.1 Gbps).
pub const COMBO_HBR3: DpllCoeffs = DpllCoeffs {
    dco_integer: 0x01A5,
    dco_fraction: 0x0000,
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
        if v & 0x7FFF != COMBO_HBR2.dco_integer as u32 {
            return TestResult::Fail("DCO integer not in low 15 bits");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pll", smoke_cfgcr0_encoding);
}

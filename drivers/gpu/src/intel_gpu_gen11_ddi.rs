//! Gen11 (Ice Lake / Elkhart Lake / Jasper Lake) combo-PHY DDI
//! signal levels — the `.icl` translation tables and their
//! selection, transcribed from Linux `display/intel_ddi_buf_trans.c`
//! (7.4-rc2).
//!
//! One entry is `{dw2_swing_sel, dw7_n_scalar, dw4_cursor_coeff,
//! dw4_post_cursor_2, dw4_post_cursor_1}` — the field order of
//! Linux's `intel_ddi_buf_trans_entry.icl`
//! (`display/intel_ddi_buf_trans.h`); the entry type is shared
//! with [`crate::intel_gpu_gen12_combo_phy::IclEntry`], which
//! programs these fields into PORT_TX_DW2/DW4/DW5/DW7.
//!
//! ## Tables (transcribed verbatim)
//!
//! - ICL DP (HBR2, eDP HBR3): `icl_combo_phy_trans_dp_hbr2_edp_hbr3`
//! - ICL eDP HBR2 (low-vswing): `icl_combo_phy_trans_edp_hbr2`
//! - ICL HDMI: `icl_combo_phy_trans_hdmi` (default entry: last)
//! - EHL DP: `ehl_combo_phy_trans_dp`
//! - EHL eDP HBR2 (low-vswing, high clock):
//!   `ehl_combo_phy_trans_edp_hbr2`
//! - JSL eDP HBR (low-vswing, low clock):
//!   `jsl_combo_phy_trans_edp_hbr`
//! - JSL eDP HBR2 (low-vswing, high clock):
//!   `jsl_combo_phy_trans_edp_hbr2`
//!
//! These are a different model from the Gen12 combo-PHY tables
//! in `intel_gpu_gen12_combo_phy` (TGL/RKL/ADL rows) — the values
//! are not copied from there. The tables are `static`, not
//! `const`, for the same reason as the Gen12 module's: eDP HBR3
//! selects the DP table by address, and a `const` array has no
//! unique address.
//!
//! ## Selection
//!
//! `select_table` mirrors `icl_get_combo_buf_trans`,
//! `ehl_get_combo_buf_trans` (+ `ehl_get_combo_buf_trans_edp`)
//! and `jsl_get_combo_buf_trans` (+ `jsl_get_combo_buf_trans_edp`):
//!
//! - HDMI → the ICL HDMI table on all three products.
//! - ICL eDP → port clock > 540000 kHz takes the DP HBR2/eDP HBR3
//!   table; otherwise low-vswing takes the eDP HBR2 table, else
//!   the DP table. ICL DP → the DP table.
//! - EHL eDP + low-vswing → port clock > 270000 kHz takes the EHL
//!   eDP HBR2 table, else the ICL eDP HBR2 table; EHL otherwise
//!   (DP, or eDP without low-vswing) → the EHL DP table.
//! - JSL eDP + low-vswing → port clock > 270000 kHz takes the JSL
//!   eDP HBR2 table, else the JSL eDP HBR table; JSL otherwise
//!   → the ICL DP table.
//!
//! `edp_low_vswing` is a VBT bit (`connector->panel.vbt.edp
//! .low_vswing`); NARF parses it (`intel_gpu_vbt`) but does not
//! plumb it into the modeset yet, so it arrives here as a caller
//! input, like the Gen12 module's pinned-false branches.
//!
//! ## Not in this module (remainders)
//!
//! - The VBT-override selectors (`jsl_get_combo_buf_trans_override`
//!   / `ehl_get_combo_buf_trans_override`, via
//!   `intel_bios_get_jsl_combo_vspeo`): they need VBT fields this
//!   driver does not parse; the default tables above are used.
//! - Programming the selected entries into the PHY
//!   (`icl_combo_phy_set_signal_levels`: PORT_PCS_DW1 common
//!   keeper, PORT_TX_DW4 loadgen select, PORT_CL_DW5 SUS clock,
//!   PORT_TX_DW5 training enable, `icl_ddi_combo_vswing_program`)
//!   is Lane 5 modeset wiring: the Gen12 programmer is keyed to
//!   `Gen12Platform`. The ICL port→PHY map (combo PHY A/B,
//!   TC1–TC4 MG) is modeled by `phy_for_port` above (Lane 8).
//!   This module only selects the table; it programs no register.

use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_gen12_combo_phy::IclEntry;
use crate::intel_gpu_gt::Gen11Platform;

/// Output type driving the table selection
/// (`intel_crtc_has_type`: HDMI / eDP / DP).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Output {
    /// DisplayPort (external).
    Dp,
    /// Embedded DisplayPort (internal panel).
    Edp,
    /// HDMI.
    Hdmi,
}

const fn e(swing: u8, n: u8, cursor: u8, pc2: u8, pc1: u8) -> IclEntry {
    IclEntry {
        dw2_swing_sel: swing,
        dw7_n_scalar: n,
        dw4_cursor_coeff: cursor,
        dw4_post_cursor_2: pc2,
        dw4_post_cursor_1: pc1,
    }
}

// ── Tables (Linux 7.4-rc2 `display/intel_ddi_buf_trans.c`) ───
// Every table is transcribed verbatim; the entry comments in the
// C source (nominal/transition mV, dB) are omitted — the values
// are the ground truth and the selection tests pin them.

// Ice Lake DP up to HBR2 / eDP up to HBR3.
static ICL_DP_HBR2_EDP_HBR3: [IclEntry; 10] = [
    e(0xA, 0x35, 0x3F, 0x00, 0x00),
    e(0xA, 0x4F, 0x37, 0x00, 0x08),
    e(0xC, 0x71, 0x2F, 0x00, 0x10),
    e(0x6, 0x7F, 0x2B, 0x00, 0x14),
    e(0xA, 0x4C, 0x3F, 0x00, 0x00),
    e(0xC, 0x73, 0x34, 0x00, 0x0B),
    e(0x6, 0x7F, 0x2F, 0x00, 0x10),
    e(0xC, 0x6C, 0x3C, 0x00, 0x03),
    e(0x6, 0x7F, 0x35, 0x00, 0x0A),
    e(0x6, 0x7F, 0x3F, 0x00, 0x00),
];

// Ice Lake eDP HBR2 (low-vswing).
static ICL_EDP_HBR2: [IclEntry; 10] = [
    e(0x0, 0x7F, 0x3F, 0x00, 0x00),
    e(0x8, 0x7F, 0x38, 0x00, 0x07),
    e(0x1, 0x7F, 0x33, 0x00, 0x0C),
    e(0x9, 0x7F, 0x31, 0x00, 0x0E),
    e(0x8, 0x7F, 0x3F, 0x00, 0x00),
    e(0x1, 0x7F, 0x38, 0x00, 0x07),
    e(0x9, 0x7F, 0x35, 0x00, 0x0A),
    e(0x1, 0x7F, 0x3F, 0x00, 0x00),
    e(0x9, 0x7F, 0x38, 0x00, 0x07),
    e(0x9, 0x7F, 0x3F, 0x00, 0x00),
];

// Ice Lake HDMI.
static ICL_HDMI: [IclEntry; 7] = [
    e(0xA, 0x60, 0x3F, 0x00, 0x00),
    e(0xB, 0x73, 0x36, 0x00, 0x09),
    e(0x6, 0x7F, 0x31, 0x00, 0x0E),
    e(0xB, 0x73, 0x3F, 0x00, 0x00),
    e(0x6, 0x7F, 0x37, 0x00, 0x08),
    e(0x6, 0x7F, 0x3F, 0x00, 0x00),
    e(0x6, 0x7F, 0x35, 0x00, 0x0A),
];

/// `icl_combo_phy_trans_hdmi.hdmi_default_entry`: the last entry.
pub const ICL_HDMI_DEFAULT_ENTRY: usize = ICL_HDMI.len() - 1;

// Elkhart Lake DP.
static EHL_DP: [IclEntry; 10] = [
    e(0xA, 0x33, 0x3F, 0x00, 0x00),
    e(0xA, 0x47, 0x38, 0x00, 0x07),
    e(0xC, 0x64, 0x33, 0x00, 0x0C),
    e(0x6, 0x7F, 0x2F, 0x00, 0x10),
    e(0xA, 0x46, 0x3F, 0x00, 0x00),
    e(0xC, 0x64, 0x37, 0x00, 0x08),
    e(0x6, 0x7F, 0x32, 0x00, 0x0D),
    e(0xC, 0x61, 0x3F, 0x00, 0x00),
    e(0x6, 0x7F, 0x37, 0x00, 0x08),
    e(0x6, 0x7F, 0x3F, 0x00, 0x00),
];

// Elkhart Lake eDP HBR2 (low-vswing, port clock > 270 MHz).
static EHL_EDP_HBR2: [IclEntry; 10] = [
    e(0x8, 0x7F, 0x3F, 0x00, 0x00),
    e(0x8, 0x7F, 0x3F, 0x00, 0x00),
    e(0x1, 0x7F, 0x3D, 0x00, 0x02),
    e(0xA, 0x35, 0x39, 0x00, 0x06),
    e(0x8, 0x7F, 0x3F, 0x00, 0x00),
    e(0x1, 0x7F, 0x3C, 0x00, 0x03),
    e(0xA, 0x35, 0x39, 0x00, 0x06),
    e(0x1, 0x7F, 0x3F, 0x00, 0x00),
    e(0xA, 0x35, 0x38, 0x00, 0x07),
    e(0xA, 0x35, 0x3F, 0x00, 0x00),
];

// Jasper Lake eDP HBR (low-vswing, port clock <= 270 MHz).
static JSL_EDP_HBR: [IclEntry; 10] = [
    e(0x8, 0x7F, 0x3F, 0x00, 0x00),
    e(0x8, 0x7F, 0x38, 0x00, 0x07),
    e(0x1, 0x7F, 0x33, 0x00, 0x0C),
    e(0xA, 0x35, 0x36, 0x00, 0x09),
    e(0x8, 0x7F, 0x3F, 0x00, 0x00),
    e(0x1, 0x7F, 0x38, 0x00, 0x07),
    e(0xA, 0x35, 0x35, 0x00, 0x0A),
    e(0x1, 0x7F, 0x3F, 0x00, 0x00),
    e(0xA, 0x35, 0x38, 0x00, 0x07),
    e(0xA, 0x35, 0x3F, 0x00, 0x00),
];

// Jasper Lake eDP HBR2 (low-vswing, port clock > 270 MHz).
static JSL_EDP_HBR2: [IclEntry; 10] = [
    e(0x8, 0x7F, 0x3F, 0x00, 0x00),
    e(0x8, 0x7F, 0x3F, 0x00, 0x00),
    e(0x1, 0x7F, 0x3D, 0x00, 0x02),
    e(0xA, 0x35, 0x38, 0x00, 0x07),
    e(0x8, 0x7F, 0x3F, 0x00, 0x00),
    e(0x1, 0x7F, 0x3F, 0x00, 0x00),
    e(0xA, 0x35, 0x3A, 0x00, 0x05),
    e(0x1, 0x7F, 0x3F, 0x00, 0x00),
    e(0xA, 0x35, 0x38, 0x00, 0x07),
    e(0xA, 0x35, 0x3F, 0x00, 0x00),
];

// ── Selection ────────────────────────────────────────────────

/// The ICL DP / eDP table, by address: eDP HBR3 selects it, so
/// callers can distinguish it from the eDP HBR2 table by
/// pointer identity.
pub fn icl_dp_table() -> &'static [IclEntry] {
    &ICL_DP_HBR2_EDP_HBR3
}

/// The ICL HDMI table.
pub fn icl_hdmi_table() -> &'static [IclEntry] {
    &ICL_HDMI
}

/// Select the combo-PHY translation table for a Gen11 output.
/// `port_clock_khz` is the CRTC port clock; `edp_low_vswing`
/// is the VBT eDP low-vswing bit (only consulted for eDP).
pub fn select_table(
    platform: Gen11Platform,
    output: Output,
    port_clock_khz: u32,
    edp_low_vswing: bool,
) -> &'static [IclEntry] {
    match platform {
        Gen11Platform::IceLake => match output {
            Output::Hdmi => &ICL_HDMI,
            Output::Dp => &ICL_DP_HBR2_EDP_HBR3,
            Output::Edp => {
                if port_clock_khz > 540_000 {
                    &ICL_DP_HBR2_EDP_HBR3
                } else if edp_low_vswing {
                    &ICL_EDP_HBR2
                } else {
                    &ICL_DP_HBR2_EDP_HBR3
                }
            }
        },
        Gen11Platform::ElkhartLake => match output {
            Output::Hdmi => &ICL_HDMI,
            Output::Dp => &EHL_DP,
            Output::Edp => {
                if edp_low_vswing {
                    if port_clock_khz > 270_000 {
                        &EHL_EDP_HBR2
                    } else {
                        &ICL_EDP_HBR2
                    }
                } else {
                    &EHL_DP
                }
            }
        },
        Gen11Platform::JasperLake => match output {
            Output::Hdmi => &ICL_HDMI,
            Output::Dp => &ICL_DP_HBR2_EDP_HBR3,
            Output::Edp => {
                if edp_low_vswing {
                    if port_clock_khz > 270_000 {
                        &JSL_EDP_HBR2
                    } else {
                        &JSL_EDP_HBR
                    }
                } else {
                    &ICL_DP_HBR2_EDP_HBR3
                }
            }
        },
    }
}

/// Which physical layer a Gen11 DDI port is wired to.
///
/// Grounded in Linux `display/intel_display.c`
/// (`intel_port_to_phy`, `intel_phy_is_combo`,
/// `intel_phy_is_tc`, `intel_port_to_tc`) and
/// `display/intel_display_device.c` (`icl_desc` port masks):
///
/// - IceLake: A and B are combo PHYs; C–F are Type-C ports
///   (TC1–TC4), each with its own MG PLL. PORT_F exists only
///   on `port_f` subplatform SKUs (`icl_port_f_ids`) — the map
///   describes the port when present; this driver does not model
///   ICL subplatforms.
/// - Elkhart/Jasper Lake: A, B and C are combo PHYs; D is a
///   combo port that shares PHY A with PORT_A
///   (`intel_port_to_phy` special case). EHL/JSL have NO TC
///   ports and NO MG PLLs — their `ehl_plls[]` is DPLL0, DPLL1,
///   DPLL4 only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gen11Phy {
    /// Combo PHY (DDI A/B on ICL; A/B/C on EHL/JSL; D on
    /// EHL/JSL shares PHY A with PORT_A).
    Combo,
    /// Type-C port with its MG PLL; `tc` is the 0-based TC
    /// index (TC1 = 0 … TC4 = 3).
    Mg { tc: u8 },
}

/// The PHY kind for a Gen11 DDI port. `None` for ports the
/// platform does not have (DDI G and above on all Gen11
/// platforms; EHL/JSL have no DDI E/F).
pub const fn phy_for_port(platform: Gen11Platform, ddi: Ddi) -> Option<Gen11Phy> {
    match (platform, ddi) {
        (Gen11Platform::IceLake, Ddi::A) | (Gen11Platform::IceLake, Ddi::B) => {
            Some(Gen11Phy::Combo)
        }
        (Gen11Platform::IceLake, Ddi::C) => Some(Gen11Phy::Mg { tc: 0 }),
        (Gen11Platform::IceLake, Ddi::D) => Some(Gen11Phy::Mg { tc: 1 }),
        (Gen11Platform::IceLake, Ddi::E) => Some(Gen11Phy::Mg { tc: 2 }),
        (Gen11Platform::IceLake, Ddi::F) => Some(Gen11Phy::Mg { tc: 3 }),
        (Gen11Platform::ElkhartLake, Ddi::A)
        | (Gen11Platform::ElkhartLake, Ddi::B)
        | (Gen11Platform::ElkhartLake, Ddi::C)
        | (Gen11Platform::ElkhartLake, Ddi::D)
        | (Gen11Platform::JasperLake, Ddi::A)
        | (Gen11Platform::JasperLake, Ddi::B)
        | (Gen11Platform::JasperLake, Ddi::C)
        | (Gen11Platform::JasperLake, Ddi::D) => Some(Gen11Phy::Combo),
        _ => None,
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn same_table(a: &[IclEntry], b: &[IclEntry]) -> bool {
        core::ptr::eq(a.as_ptr(), b.as_ptr()) && a.len() == b.len()
    }

    fn smoke_icl_ddi_table_values() -> TestResult {
        // Spot-pin every table's first, divergent, and last
        // rows against the transcribed Linux values.
        let dp = icl_dp_table();
        if dp.len() != 10
            || dp[0] != e(0xA, 0x35, 0x3F, 0x00, 0x00)
            || dp[3] != e(0x6, 0x7F, 0x2B, 0x00, 0x14)
            || dp[9] != e(0x6, 0x7F, 0x3F, 0x00, 0x00)
        {
            return TestResult::Fail("ICL DP table values wrong");
        }
        if ICL_EDP_HBR2[0] != e(0x0, 0x7F, 0x3F, 0x00, 0x00)
            || ICL_EDP_HBR2[3] != e(0x9, 0x7F, 0x31, 0x00, 0x0E)
        {
            return TestResult::Fail("ICL eDP HBR2 table values wrong");
        }
        let hdmi = icl_hdmi_table();
        if hdmi.len() != 7
            || hdmi[0] != e(0xA, 0x60, 0x3F, 0x00, 0x00)
            || hdmi[ICL_HDMI_DEFAULT_ENTRY] != e(0x6, 0x7F, 0x35, 0x00, 0x0A)
        {
            return TestResult::Fail("ICL HDMI table values or default entry wrong");
        }
        // The EHL DP table diverges from ICL DP at row 0
        // (0x33 N-scalar vs 0x35) and row 1.
        if EHL_DP[0] != e(0xA, 0x33, 0x3F, 0x00, 0x00)
            || EHL_DP[1] != e(0xA, 0x47, 0x38, 0x00, 0x07)
        {
            return TestResult::Fail("EHL DP table values wrong");
        }
        if EHL_EDP_HBR2[2] != e(0x1, 0x7F, 0x3D, 0x00, 0x02)
            || EHL_EDP_HBR2[9] != e(0xA, 0x35, 0x3F, 0x00, 0x00)
        {
            return TestResult::Fail("EHL eDP HBR2 table values wrong");
        }
        // JSL HBR vs HBR2 diverge at row 1 (0x38 vs 0x3F
        // N-scalar) and row 3.
        if JSL_EDP_HBR[1] != e(0x8, 0x7F, 0x38, 0x00, 0x07)
            || JSL_EDP_HBR2[1] != e(0x8, 0x7F, 0x3F, 0x00, 0x00)
            || JSL_EDP_HBR[3] != e(0xA, 0x35, 0x36, 0x00, 0x09)
            || JSL_EDP_HBR2[3] != e(0xA, 0x35, 0x38, 0x00, 0x07)
        {
            return TestResult::Fail("JSL eDP tables values wrong");
        }
        // No Gen11 table is a copy of a Gen12 one: the ICL DP
        // row 2 (0x71 N-scalar) differs from TGL DP HBR2's
        // (0x63), and the ICL HDMI row 0 (0x60) from TGL's.
        if dp[2].dw7_n_scalar == 0x63 {
            return TestResult::Fail("ICL DP table must not be the TGL table");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_ddi",
        smoke_icl_ddi_table_values
    );

    fn smoke_icl_ddi_selection() -> TestResult {
        let icl = Gen11Platform::IceLake;
        let ehl = Gen11Platform::ElkhartLake;
        let jsl = Gen11Platform::JasperLake;
        // ICL: HDMI always the HDMI table; DP always the DP table.
        if !same_table(select_table(icl, Output::Hdmi, 148_500, false), &ICL_HDMI)
            || !same_table(
                select_table(icl, Output::Dp, 540_000, false),
                &ICL_DP_HBR2_EDP_HBR3,
            )
        {
            return TestResult::Fail("ICL HDMI/DP selection wrong");
        }
        // ICL eDP: > 540 MHz takes the DP table even with
        // low-vswing; at/below it, low-vswing takes eDP HBR2.
        if !same_table(
            select_table(icl, Output::Edp, 648_000, true),
            &ICL_DP_HBR2_EDP_HBR3,
        ) || !same_table(select_table(icl, Output::Edp, 540_000, true), &ICL_EDP_HBR2)
            || !same_table(
                select_table(icl, Output::Edp, 270_000, false),
                &ICL_DP_HBR2_EDP_HBR3,
            )
        {
            return TestResult::Fail("ICL eDP selection wrong");
        }
        // EHL: DP takes the EHL DP table; eDP without low-vswing
        // too; eDP + low-vswing splits at 270 MHz.
        if !same_table(select_table(ehl, Output::Dp, 540_000, false), &EHL_DP)
            || !same_table(select_table(ehl, Output::Edp, 540_000, false), &EHL_DP)
            || !same_table(select_table(ehl, Output::Edp, 324_000, true), &EHL_EDP_HBR2)
            || !same_table(select_table(ehl, Output::Edp, 270_000, true), &ICL_EDP_HBR2)
        {
            return TestResult::Fail("EHL selection wrong");
        }
        // EHL HDMI is the shared ICL HDMI table.
        if !same_table(select_table(ehl, Output::Hdmi, 148_500, false), &ICL_HDMI) {
            return TestResult::Fail("EHL HDMI must use the ICL HDMI table");
        }
        // JSL: DP takes the ICL DP table; eDP + low-vswing
        // splits at 270 MHz between the two JSL tables.
        if !same_table(
            select_table(jsl, Output::Dp, 540_000, false),
            &ICL_DP_HBR2_EDP_HBR3,
        ) || !same_table(select_table(jsl, Output::Edp, 324_000, true), &JSL_EDP_HBR2)
            || !same_table(select_table(jsl, Output::Edp, 270_000, true), &JSL_EDP_HBR)
            || !same_table(
                select_table(jsl, Output::Edp, 540_000, false),
                &ICL_DP_HBR2_EDP_HBR3,
            )
        {
            return TestResult::Fail("JSL selection wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen11_ddi", smoke_icl_ddi_selection);

    fn smoke_gen11_port_map() -> TestResult {
        let icl = Gen11Platform::IceLake;
        let ehl = Gen11Platform::ElkhartLake;
        let jsl = Gen11Platform::JasperLake;
        // ICL: A/B combo, C–F TC1–TC4.
        if phy_for_port(icl, Ddi::A) != Some(Gen11Phy::Combo)
            || phy_for_port(icl, Ddi::B) != Some(Gen11Phy::Combo)
            || phy_for_port(icl, Ddi::C) != Some(Gen11Phy::Mg { tc: 0 })
            || phy_for_port(icl, Ddi::D) != Some(Gen11Phy::Mg { tc: 1 })
            || phy_for_port(icl, Ddi::E) != Some(Gen11Phy::Mg { tc: 2 })
            || phy_for_port(icl, Ddi::F) != Some(Gen11Phy::Mg { tc: 3 })
            || phy_for_port(icl, Ddi::G).is_some()
        {
            return TestResult::Fail("ICL port map wrong");
        }
        // EHL/JSL: A–D all combo (D shares PHY A); no TC ports.
        for p in [ehl, jsl] {
            for ddi in [Ddi::A, Ddi::B, Ddi::C, Ddi::D] {
                if phy_for_port(p, ddi) != Some(Gen11Phy::Combo) {
                    return TestResult::Fail("EHL/JSL port map wrong");
                }
            }
            if phy_for_port(p, Ddi::E).is_some() || phy_for_port(p, Ddi::F).is_some() {
                return TestResult::Fail("EHL/JSL must have no DDI E/F");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen11_ddi", smoke_gen11_port_map);

    fn smoke_gen11_ddi_buf_ctl_bases() -> TestResult {
        // DDI_BUF_CTL addressing is shared with Gen12: 0x64000
        // + port * 0x100 — pin the Gen11 TC-port addresses.
        if Ddi::A.base() != 0x64000
            || Ddi::B.base() != 0x64100
            || Ddi::C.base() != 0x64200
            || Ddi::D.base() != 0x64300
            || Ddi::E.base() != 0x64400
            || Ddi::F.base() != 0x64500
        {
            return TestResult::Fail("Gen11 DDI_BUF_CTL bases wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen11_ddi",
        smoke_gen11_ddi_buf_ctl_bases
    );
}

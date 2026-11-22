//! Gen12 combo-PHY signal levels — Tiger Lake / Rocket Lake /
//! Alder Lake-S/P/N / DG1 (display 12).
//!
//! Reference: Linux `display/intel_ddi_buf_trans.c` (the `.icl`
//! tables and the `tgl/rkl/adls/adlp/dg1_get_combo_buf_trans`
//! selectors), `display/intel_ddi.c`
//! (`icl_combo_phy_set_signal_levels`,
//! `icl_ddi_combo_vswing_program`, `icl_combo_phy_loadgen_select`,
//! `intel_ddi_level`, `intel_ddi_hdmi_level`,
//! `intel_ddi_set_link_train`, `intel_port_to_phy`),
//! `display/intel_combo_phy_regs.h` (PORT_CL/PCS/TX_DW register
//! map) and `display/intel_display_regs.h` (`TGL_DP_TP_CTL`).
//!
//! Gen12 combo ports never use `DDI_BUF_TRANS`:
//! `has_buf_trans_select` is DISPLAY_VER < 10, so the 4-entry
//! (lo, hi) tables the modeset used to load at DDI base + 0x10
//! were writes to registers the hardware ignores on Gen12. This
//! module replaces them: the PHY is programmed through
//! PORT_TX_DW2/DW4/DW5/DW7 + PORT_PCS_DW1 + PORT_CL_DW5/DW10,
//! from the per-family `.icl` tables, with per-iteration
//! updates inside the DPCD training loop via `TrainingAux`
//! (mirroring the Type-C `DklPort::training_update` shape).
//! The old tables, loader and test are deleted with this change.
//!
//! Two inputs the modeset does not carry yet are pinned false
//! with their selection branches present and unit-tested:
//! eDP HOBL and eDP low-vswing are VBT bits
//! (`connector->panel.vbt.edp.hobl` / `.low_vswing`); NARF
//! parses `low_vswing` (`intel_gpu_vbt`) but does not plumb
//! either into the modeset, and `is_edp` is the documented
//! `ddi == Ddi::A` assumption (DDI A is the eDP panel port on
//! Gen12 laptops; connector-typed selection is a follow-up).
//! Likewise the TGL-UY table is selected only on the
//! `modeset_display_for_chip` path, the one site that knows the
//! PCI device ID — external-DP/HDMI/MST paths keep the standard
//! TGL table until the DID reaches them.
//!
//! Mid-training DPLL retune on fallback: when the `train_link`
//! ladder opens a retry attempt at a lower rate, the training
//! callback reprograms the combo DPLL for the new link clock
//! before the sink sees TPS1 at that rate
//! (`ComboPhy::training_update`, pattern 1 after a dirty
//! Configure) — the combo equivalent of the Type-C
//! `DklPort::start_training(retune)` restart. Without it the
//! retry drives the new rate on the old link clock and can
//! never lock; the post-training `program_dpll_with_rate` in
//! the modeset only covers the plan path, so a legacy-path
//! fallback settled at the wrong clock. M/N needs no
//! mid-training step: the transcoder is not enabled until
//! after training, and the modeset already reprograms M/N to
//! the trained configuration on every path before the DDI
//! buffer enables.
use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_gt::Gen12Platform;
use crate::intel_gpu_modeset::ModesetError;
use crate::intel_gpu_pll::LinkRate;
use core::sync::atomic::{compiler_fence, Ordering};

/// One `.icl` translation-table entry, in the field order of
/// Linux's `intel_ddi_buf_trans_entry.icl`:
/// `{dw2_swing_sel, dw7_n_scalar, dw4_cursor_coeff,
/// dw4_post_cursor_2, dw4_post_cursor_1}`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct IclEntry {
    pub dw2_swing_sel: u8,
    pub dw7_n_scalar: u8,
    pub dw4_cursor_coeff: u8,
    pub dw4_post_cursor_2: u8,
    pub dw4_post_cursor_1: u8,
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
//
// The tables are `static`, not `const`, on purpose: eDP HBR3
// selects the DP HBR2/HBR3 table by address, and a `const`
// array has no unique address — each use site may materialize
// its own copy, so a pointer-alias assertion against a `const`
// fails in a multi-CGU build (kt-gpu regression, run
// 44933361128). A `static` has exactly one address, so the
// alias is real in every build.

// Tiger Lake DP up to HBR (`tgl_combo_phy_trans_dp_hbr`).
static TGL_DP_HBR: [IclEntry; 10] = [
    e(0xA, 0x32, 0x3F, 0x00, 0x00),
    e(0xA, 0x4F, 0x37, 0x00, 0x08),
    e(0xC, 0x71, 0x2F, 0x00, 0x10),
    e(0x6, 0x7D, 0x2B, 0x00, 0x14),
    e(0xA, 0x4C, 0x3F, 0x00, 0x00),
    e(0xC, 0x73, 0x34, 0x00, 0x0B),
    e(0x6, 0x7F, 0x2F, 0x00, 0x10),
    e(0xC, 0x6C, 0x3C, 0x00, 0x03),
    e(0x6, 0x7F, 0x35, 0x00, 0x0A),
    e(0x6, 0x7F, 0x3F, 0x00, 0x00),
];

// Tiger Lake DP HBR2 (`tgl_combo_phy_trans_dp_hbr2`).
static TGL_DP_HBR2: [IclEntry; 10] = [
    e(0xA, 0x35, 0x3F, 0x00, 0x00),
    e(0xA, 0x4F, 0x37, 0x00, 0x08),
    e(0xC, 0x63, 0x2F, 0x00, 0x10),
    e(0x6, 0x7F, 0x2B, 0x00, 0x14),
    e(0xA, 0x47, 0x3F, 0x00, 0x00),
    e(0xC, 0x63, 0x34, 0x00, 0x0B),
    e(0x6, 0x7F, 0x2F, 0x00, 0x10),
    e(0xC, 0x61, 0x3C, 0x00, 0x03),
    e(0x6, 0x7B, 0x35, 0x00, 0x0A),
    e(0x6, 0x7F, 0x3F, 0x00, 0x00),
];

// Tiger Lake UY DP HBR2 (`tgl_uy_combo_phy_trans_dp_hbr2`).
static TGL_UY_DP_HBR2: [IclEntry; 10] = [
    e(0xA, 0x35, 0x3F, 0x00, 0x00),
    e(0xA, 0x4F, 0x36, 0x00, 0x09),
    e(0xC, 0x60, 0x32, 0x00, 0x0D),
    e(0xC, 0x7F, 0x2D, 0x00, 0x12),
    e(0xC, 0x47, 0x3F, 0x00, 0x00),
    e(0xC, 0x6F, 0x36, 0x00, 0x09),
    e(0x6, 0x7D, 0x32, 0x00, 0x0D),
    e(0x6, 0x60, 0x3C, 0x00, 0x03),
    e(0x6, 0x7F, 0x34, 0x00, 0x0B),
    e(0x6, 0x7F, 0x3F, 0x00, 0x00),
];

// Tiger Lake eDP HBR2 HOBL (`tgl_combo_phy_trans_edp_hbr2_hobl`,
// 9 entries): the HOBL entry cloned to every level, per the C
// comment — "to comply with the voltage and pre-emphasis
// entries that DisplayPort specification requires".
static TGL_EDP_HBR2_HOBL: [IclEntry; 9] = [e(0x6, 0x7F, 0x3F, 0x00, 0x00); 9];

// Shared ICL DP HBR2 / eDP HBR3
// (`icl_combo_phy_trans_dp_hbr2_edp_hbr3`).
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

// Shared ICL eDP HBR2 (`icl_combo_phy_trans_edp_hbr2`).
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

// Shared ICL HDMI (`icl_combo_phy_trans_hdmi`, 7 entries).
// `hdmi_default_entry` is the last entry (index 6).
static ICL_HDMI: [IclEntry; 7] = [
    e(0xA, 0x60, 0x3F, 0x00, 0x00),
    e(0xB, 0x73, 0x36, 0x00, 0x09),
    e(0x6, 0x7F, 0x31, 0x00, 0x0E),
    e(0xB, 0x73, 0x3F, 0x00, 0x00),
    e(0x6, 0x7F, 0x37, 0x00, 0x08),
    e(0x6, 0x7F, 0x3F, 0x00, 0x00),
    e(0x6, 0x7F, 0x35, 0x00, 0x0A),
];

/// HDMI default entry (`hdmi_default_entry` =
/// `ARRAY_SIZE(_icl_combo_phy_trans_hdmi) - 1`): the 600 mV /
/// 850 mV 3.0 dB preset, i.e. (swing 1, pre-emphasis 2).
const HDMI_DEFAULT_ENTRY: usize = 6;

// Rocket Lake DP up to HBR (`rkl_combo_phy_trans_dp_hbr`).
static RKL_DP_HBR: [IclEntry; 10] = [
    e(0xA, 0x2F, 0x3F, 0x00, 0x00),
    e(0xA, 0x4F, 0x37, 0x00, 0x08),
    e(0xC, 0x63, 0x2F, 0x00, 0x10),
    e(0x6, 0x7D, 0x2A, 0x00, 0x15),
    e(0xA, 0x4C, 0x3F, 0x00, 0x00),
    e(0xC, 0x73, 0x34, 0x00, 0x0B),
    e(0x6, 0x7F, 0x2F, 0x00, 0x10),
    e(0xC, 0x6E, 0x3E, 0x00, 0x01),
    e(0x6, 0x7F, 0x35, 0x00, 0x0A),
    e(0x6, 0x7F, 0x3F, 0x00, 0x00),
];

// Rocket Lake DP HBR2/HBR3 (`rkl_combo_phy_trans_dp_hbr2_hbr3`).
static RKL_DP_HBR2_HBR3: [IclEntry; 10] = [
    e(0xA, 0x35, 0x3F, 0x00, 0x00),
    e(0xA, 0x50, 0x38, 0x00, 0x07),
    e(0xC, 0x61, 0x33, 0x00, 0x0C),
    e(0x6, 0x7F, 0x2E, 0x00, 0x11),
    e(0xA, 0x47, 0x3F, 0x00, 0x00),
    e(0xC, 0x5F, 0x38, 0x00, 0x07),
    e(0x6, 0x7F, 0x2F, 0x00, 0x10),
    e(0xC, 0x5F, 0x3F, 0x00, 0x00),
    e(0x6, 0x7E, 0x36, 0x00, 0x09),
    e(0x6, 0x7F, 0x3F, 0x00, 0x00),
];

// Alder Lake-S DP HBR2/HBR3 (`adls_combo_phy_trans_dp_hbr2_hbr3`),
// which is also the ADL-S eDP HBR3 table
// (`adls_combo_phy_trans_edp_hbr3` — same array in Linux).
static ADLS_DP_HBR2_HBR3: [IclEntry; 10] = [
    e(0xA, 0x35, 0x3F, 0x00, 0x00),
    e(0xA, 0x4F, 0x37, 0x00, 0x08),
    e(0xC, 0x63, 0x31, 0x00, 0x0E),
    e(0x6, 0x7F, 0x2C, 0x00, 0x13),
    e(0xA, 0x47, 0x3F, 0x00, 0x00),
    e(0xC, 0x63, 0x37, 0x00, 0x08),
    e(0x6, 0x73, 0x32, 0x00, 0x0D),
    e(0xC, 0x58, 0x3F, 0x00, 0x00),
    e(0x6, 0x7F, 0x35, 0x00, 0x0A),
    e(0x6, 0x7F, 0x3F, 0x00, 0x00),
];

// Alder Lake-S eDP HBR2 (`adls_combo_phy_trans_edp_hbr2`).
static ADLS_EDP_HBR2: [IclEntry; 10] = [
    e(0x9, 0x73, 0x3D, 0x00, 0x02),
    e(0x9, 0x7A, 0x3C, 0x00, 0x03),
    e(0x9, 0x7F, 0x3B, 0x00, 0x04),
    e(0x4, 0x6C, 0x33, 0x00, 0x0C),
    e(0x2, 0x73, 0x3A, 0x00, 0x05),
    e(0x2, 0x7C, 0x38, 0x00, 0x07),
    e(0x4, 0x5A, 0x36, 0x00, 0x09),
    e(0x4, 0x57, 0x3D, 0x00, 0x02),
    e(0x4, 0x65, 0x38, 0x00, 0x07),
    e(0x4, 0x6C, 0x3A, 0x00, 0x05),
];

// Alder Lake-P DP up to HBR (`adlp_combo_phy_trans_dp_hbr`).
static ADLP_DP_HBR: [IclEntry; 10] = [
    e(0xA, 0x35, 0x3F, 0x00, 0x00),
    e(0xA, 0x4F, 0x37, 0x00, 0x08),
    e(0xC, 0x71, 0x31, 0x00, 0x0E),
    e(0x6, 0x7F, 0x2C, 0x00, 0x13),
    e(0xA, 0x4C, 0x3F, 0x00, 0x00),
    e(0xC, 0x73, 0x34, 0x00, 0x0B),
    e(0x6, 0x7F, 0x2F, 0x00, 0x10),
    e(0xC, 0x7C, 0x3C, 0x00, 0x03),
    e(0x6, 0x7F, 0x35, 0x00, 0x0A),
    e(0x6, 0x7F, 0x3F, 0x00, 0x00),
];

// Alder Lake-P DP HBR2/HBR3 (`adlp_combo_phy_trans_dp_hbr2_hbr3`),
// which is also the ADL-P eDP HBR3 table
// (`adlp_combo_phy_trans_edp_hbr3` — the struct aliases the same
// array in Linux).
static ADLP_DP_HBR2_HBR3: [IclEntry; 10] = [
    e(0xA, 0x35, 0x3F, 0x00, 0x00),
    e(0xA, 0x4F, 0x37, 0x00, 0x08),
    e(0xC, 0x71, 0x30, 0x00, 0x0F),
    e(0x6, 0x7F, 0x2B, 0x00, 0x14),
    e(0xA, 0x4C, 0x3F, 0x00, 0x00),
    e(0xC, 0x73, 0x34, 0x00, 0x0B),
    e(0x6, 0x7F, 0x30, 0x00, 0x0F),
    e(0xC, 0x63, 0x3F, 0x00, 0x00),
    e(0x6, 0x7F, 0x38, 0x00, 0x07),
    e(0x6, 0x7F, 0x3F, 0x00, 0x00),
];

// Alder Lake-P eDP up to HBR2 (`adlp_combo_phy_trans_edp_hbr2`),
// which is also the ADL-P eDP HBR2 table
// (`adlp_combo_phy_trans_edp_up_to_hbr2` — same array).
static ADLP_EDP_HBR2: [IclEntry; 10] = [
    e(0x4, 0x50, 0x38, 0x00, 0x07),
    e(0x4, 0x58, 0x35, 0x00, 0x0A),
    e(0x4, 0x60, 0x34, 0x00, 0x0B),
    e(0x4, 0x6A, 0x32, 0x00, 0x0D),
    e(0x4, 0x5E, 0x38, 0x00, 0x07),
    e(0x4, 0x61, 0x36, 0x00, 0x09),
    e(0x4, 0x6B, 0x34, 0x00, 0x0B),
    e(0x4, 0x69, 0x39, 0x00, 0x06),
    e(0x4, 0x73, 0x37, 0x00, 0x08),
    e(0x4, 0x7A, 0x38, 0x00, 0x07),
];

// DG1 DP HBR2/HBR3 (`dg1_combo_phy_trans_dp_hbr2_hbr3`).
static DG1_DP_HBR2_HBR3: [IclEntry; 10] = [
    e(0xA, 0x32, 0x3F, 0x00, 0x00),
    e(0xA, 0x48, 0x35, 0x00, 0x0A),
    e(0xC, 0x63, 0x2F, 0x00, 0x10),
    e(0x6, 0x7F, 0x2C, 0x00, 0x13),
    e(0xA, 0x43, 0x3F, 0x00, 0x00),
    e(0xC, 0x60, 0x36, 0x00, 0x09),
    e(0x6, 0x7F, 0x30, 0x00, 0x0F),
    e(0xC, 0x58, 0x3F, 0x00, 0x00),
    e(0x6, 0x7F, 0x35, 0x00, 0x0A),
    e(0x6, 0x7F, 0x3F, 0x00, 0x00),
];

// DG1 DP RBR/HBR (`dg1_combo_phy_trans_dp_rbr_hbr`).
static DG1_DP_RBR_HBR: [IclEntry; 10] = [
    e(0xA, 0x32, 0x3F, 0x00, 0x00),
    e(0xA, 0x48, 0x35, 0x00, 0x0A),
    e(0xC, 0x63, 0x2F, 0x00, 0x10),
    e(0x6, 0x7F, 0x2C, 0x00, 0x13),
    e(0xA, 0x43, 0x3F, 0x00, 0x00),
    e(0xC, 0x60, 0x36, 0x00, 0x09),
    e(0x6, 0x7F, 0x30, 0x00, 0x0F),
    e(0xC, 0x60, 0x3F, 0x00, 0x00),
    e(0x6, 0x7F, 0x37, 0x00, 0x08),
    e(0x6, 0x7F, 0x3F, 0x00, 0x00),
];

// ── Table selection ──────────────────────────────────────────

/// DP link rate as a port clock in kHz (Linux
/// `crtc_state->port_clock`: 1.62 / 2.7 / 5.4 / 8.1 Gbps). HDMI
/// rates are not DP link rates and resolve to `None`.
pub(crate) fn port_clock_khz(rate: LinkRate) -> Option<u32> {
    match rate {
        LinkRate::DpRbr => Some(162_000),
        LinkRate::DpHbr => Some(270_000),
        LinkRate::DpHbr2 => Some(540_000),
        LinkRate::DpHbr3 => Some(810_000),
        _ => None,
    }
}

/// Tiger Lake UY (GT2) device IDs — Linux `INTEL_TGL_GT2_IDS`
/// (`tigerlake_uy`), which selects the UY HBR2 table. Grounded
/// in the Linux macro itself (`include/drm/intel/pciids.h:626-634`,
/// Linux 7.4-rc2): 9A40, 9A49, 9A59, 9A78, 9AC0, 9AC9, 9AD9, 9AF8.
/// GT1 is 9A60, 9A68, 9A70 (`INTEL_TGL_GT1_IDS`, same file:621-624).
/// NOTE: an earlier in-tree reading had this backwards — it took
/// NARF's own `intel_gpu_pci_ids` const names at face value, which
/// mislabelled 9A68/9A70 as GT2 and left 9A40 unsuffixed. The
/// macro is authoritative: 0x9A40 IS UY, 0x9A68/0x9A70 are NOT.
/// Corroborated by `tgl_uy_ids[] = { INTEL_TGL_GT2_IDS(ID), 0 }`
/// as the `tigerlake_uy` subplatform pciidlist
/// (`drivers/gpu/drm/i915/display/intel_display_device.c:1004-1027`)
/// and by `tgl_get_combo_buf_trans_dp` returning the UY table iff
/// `display->platform.tigerlake_uy` at port_clock > 270000
/// (`drivers/gpu/drm/i915/display/intel_ddi_buf_trans.c:1477-1478`).
/// A wrong call here degrades signal margin only — the UY and
/// non-UY tables differ only in swing tuning, it does not break
/// the link.
pub(crate) fn is_tgl_uy(did: u16) -> bool {
    matches!(
        did,
        0x9A40 | 0x9A49 | 0x9A59 | 0x9A78 | 0x9AC0 | 0x9AC9 | 0x9AD9 | 0x9AF8
    )
}

fn tgl_dp(port_clock_khz: u32, tgl_uy: bool) -> (&'static [IclEntry], bool) {
    if port_clock_khz > 270_000 {
        if tgl_uy {
            (&TGL_UY_DP_HBR2, false)
        } else {
            (&TGL_DP_HBR2, false)
        }
    } else {
        (&TGL_DP_HBR, false)
    }
}

fn rkl_dp(port_clock_khz: u32) -> (&'static [IclEntry], bool) {
    if port_clock_khz > 270_000 {
        (&RKL_DP_HBR2_HBR3, false)
    } else {
        (&RKL_DP_HBR, false)
    }
}

fn adls_dp(port_clock_khz: u32) -> (&'static [IclEntry], bool) {
    if port_clock_khz > 270_000 {
        (&ADLS_DP_HBR2_HBR3, false)
    } else {
        // ADL-S reuses the TGL DP-HBR table at low rates.
        (&TGL_DP_HBR, false)
    }
}

fn adlp_dp(port_clock_khz: u32) -> (&'static [IclEntry], bool) {
    if port_clock_khz > 270_000 {
        (&ADLP_DP_HBR2_HBR3, false)
    } else {
        (&ADLP_DP_HBR, false)
    }
}

fn dg1_dp(port_clock_khz: u32) -> (&'static [IclEntry], bool) {
    if port_clock_khz > 270_000 {
        (&DG1_DP_HBR2_HBR3, false)
    } else {
        (&DG1_DP_RBR_HBR, false)
    }
}

/// Select the `.icl` table for a combo-PHY DP/eDP link,
/// mirroring Linux's `tgl/rkl/adls/adlp/dg1_get_combo_buf_trans`
/// (+ the `_edp` variants). Returns the table and whether it
/// is the eDP HOBL table (`is_hobl_buf_trans`: only the HOBL
/// table drives PORT_CL_DW10's 4K2K override).
///
/// Thresholds are Linux's verbatim: eDP above 540 MHz uses the
/// HBR3 table; DP above 270 MHz uses the HBR2 table (the UY
/// variant on Tiger Lake GT2 parts).
pub(crate) fn select_combo_buf_trans(
    family: Gen12Platform,
    is_edp: bool,
    port_clock_khz: u32,
    tgl_uy: bool,
    hobl: bool,
    low_vswing: bool,
) -> (&'static [IclEntry], bool) {
    if !is_edp {
        return match family {
            Gen12Platform::TigerLake => tgl_dp(port_clock_khz, tgl_uy),
            Gen12Platform::RocketLake => rkl_dp(port_clock_khz),
            Gen12Platform::AlderLakeS => adls_dp(port_clock_khz),
            Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN => adlp_dp(port_clock_khz),
            Gen12Platform::Dg1 => dg1_dp(port_clock_khz),
        };
    }
    match family {
        Gen12Platform::TigerLake => {
            if port_clock_khz > 540_000 {
                (&ICL_DP_HBR2_EDP_HBR3, false)
            } else if hobl {
                (&TGL_EDP_HBR2_HOBL, true)
            } else if low_vswing {
                (&ICL_EDP_HBR2, false)
            } else {
                tgl_dp(port_clock_khz, tgl_uy)
            }
        }
        Gen12Platform::RocketLake => {
            if port_clock_khz > 540_000 {
                (&ICL_DP_HBR2_EDP_HBR3, false)
            } else if hobl {
                (&TGL_EDP_HBR2_HOBL, true)
            } else if low_vswing {
                (&ICL_EDP_HBR2, false)
            } else {
                rkl_dp(port_clock_khz)
            }
        }
        Gen12Platform::AlderLakeS => {
            if port_clock_khz > 540_000 {
                // ADL-S eDP HBR3 is the ADL-S DP HBR2/HBR3 table.
                (&ADLS_DP_HBR2_HBR3, false)
            } else if hobl {
                (&TGL_EDP_HBR2_HOBL, true)
            } else if low_vswing {
                (&ADLS_EDP_HBR2, false)
            } else {
                adls_dp(port_clock_khz)
            }
        }
        Gen12Platform::AlderLakeP | Gen12Platform::AlderLakeN => {
            if port_clock_khz > 540_000 {
                // ADL-P eDP HBR3 is the ADL-P DP HBR2/HBR3 table.
                (&ADLP_DP_HBR2_HBR3, false)
            } else if hobl {
                (&TGL_EDP_HBR2_HOBL, true)
            } else if low_vswing {
                // ADL-P eDP up to HBR2 is the ADL-P eDP HBR2 table.
                (&ADLP_EDP_HBR2, false)
            } else {
                adlp_dp(port_clock_khz)
            }
        }
        Gen12Platform::Dg1 => {
            if port_clock_khz > 540_000 {
                (&ICL_DP_HBR2_EDP_HBR3, false)
            } else if hobl {
                (&TGL_EDP_HBR2_HOBL, true)
            } else if low_vswing {
                (&ICL_EDP_HBR2, false)
            } else {
                dg1_dp(port_clock_khz)
            }
        }
    }
}

// ── Register map (`display/intel_combo_phy_regs.h`) ──────────
//
// `_ICL_COMBOPHY(phy)`: A 0x162000, B 0x6C000, C (EHL label)
// 0x160000, D (RKL) 0x161000, E (ADL) 0x16B000. CL_DW = base +
// 4*dw; COMP = base + 0x100; PCS AUX 0x300 / GRP 0x600 / LN
// 0x800 + ln*0x100; TX AUX 0x380 / GRP 0x680 / LN 0x880 +
// ln*0x100; DW = +4*dw.

/// `PORT_CL_DW5` SUS clock config — both bits set (11b).
const SUS_CLOCK_CONFIG: u32 = 0x3;
/// `PORT_CL_DW10` eDP 4K2K override bits.
const EDP4K2K_MODE_OVRD_EN: u32 = 1 << 3;
const EDP4K2K_MODE_OVRD_OPTIMIZED: u32 = 1 << 2;
/// `PORT_PCS_DW1` common-keeper enable (bit 26).
const COMMON_KEEPER_EN: u32 = 1 << 26;
/// `PORT_TX_DW2` swing fields.
const SWING_SEL_UPPER_MASK: u32 = 1 << 15;
const SWING_SEL_LOWER_MASK: u32 = 0x7 << 11;
const RCOMP_SCALAR_MASK: u32 = 0xFF;
const fn swing_sel_upper(v: u8) -> u32 {
    ((v as u32 >> 3) & 1) << 15
}
const fn swing_sel_lower(v: u8) -> u32 {
    (v as u32 & 0x7) << 11
}
const fn rcomp_scalar(v: u8) -> u32 {
    v as u32
}
/// `PORT_TX_DW4` loadgen + cursor fields.
const LOADGEN_SELECT: u32 = 1 << 31;
const POST_CURSOR_1_MASK: u32 = 0x3F << 12;
const POST_CURSOR_2_MASK: u32 = 0x3F << 6;
const CURSOR_COEFF_MASK: u32 = 0x3F;
const fn post_cursor_1(v: u8) -> u32 {
    (v as u32 & 0x3F) << 12
}
const fn post_cursor_2(v: u8) -> u32 {
    (v as u32 & 0x3F) << 6
}
const fn cursor_coeff(v: u8) -> u32 {
    v as u32 & 0x3F
}
/// `PORT_TX_DW5` fields. `RTERM_SELECT` 0x6 and
/// `SCALING_MODE_SEL` 0x2 are the fixed values
/// `icl_ddi_combo_vswing_program` writes.
const TX_TRAINING_EN: u32 = 1 << 31;
const TAP2_DISABLE: u32 = 1 << 30;
const TAP3_DISABLE: u32 = 1 << 29;
const CURSOR_PROGRAM: u32 = 1 << 26;
const COEFF_POLARITY: u32 = 1 << 25;
const SCALING_MODE_SEL_MASK: u32 = 0x7 << 18;
const SCALING_MODE_SEL_2: u32 = 0x2 << 18;
const RTERM_SELECT_MASK: u32 = 0x7 << 3;
const RTERM_SELECT_6: u32 = 0x6 << 3;
/// `PORT_TX_DW7` N-scalar field (bits 30:24 — 7 bits; Linux
/// `N_SCALAR_MASK` is `REG_GENMASK(30, 24)` in
/// `display/intel_combo_phy_regs.h`, so values >= 0x40 such
/// as the preset-4 0x47 must survive intact).
const N_SCALAR_MASK: u32 = 0x7F << 24;
const fn n_scalar(v: u8) -> u32 {
    (v as u32 & 0x7F) << 24
}
/// `DP_TP_CTL` (TGL variant: transcoder base + 0x540;
/// `intel_display_regs.h`).
const DP_TP_CTL_OFFSET: u64 = 0x540;
const DP_TP_CTL_ENABLE: u32 = 1 << 31;
const DP_TP_CTL_ENHANCED_FRAME_ENABLE: u32 = 1 << 18;
const DP_TP_CTL_LINK_TRAIN_MASK: u32 = 0x7 << 8;
const DP_TP_CTL_SCRAMBLE_DISABLE: u32 = 1 << 7;

/// DPLL enable registers (Tiger Lake PRM Vol. 11 §"DPLL
/// Enable"): `_DPLL0_ENABLE` = 0x46010, `_DPLL1_ENABLE` =
/// 0x46014, `_DPLL2_ENABLE` = 0x46018 — the same registers and
/// bit positions as `intel_gpu_modeset::program_dpll_coeffs`
/// (and `intel_gpu_dp`'s `DPLL_ENABLES`); this module keeps
/// its own copies because the modeset's are private.
/// `PLL_LOCK` (bit 30) and `PLL_POWER_STATE` (bit 26) are
/// read-only status, stripped on read-modify-write by
/// `retune_dpll`.
const DPLL0_ENABLE: u64 = 0x4_6010;
const DPLL1_ENABLE: u64 = 0x4_6014;
const DPLL2_ENABLE: u64 = 0x4_6018;
const DPLL_PLL_ENABLE: u32 = 1 << 31;
const DPLL_PLL_LOCK: u32 = 1 << 30;
const DPLL_PLL_POWER_ENABLE: u32 = 1 << 27;
const DPLL_PLL_POWER_STATE: u32 = 1 << 26;
const DPLL_STATUS_BITS: u32 = DPLL_PLL_LOCK | DPLL_PLL_POWER_STATE;

/// `icl_combo_phy_loadgen_select`: above 6 GHz no loadgen on
/// any lane; 4 lanes load lanes 1–3; otherwise lanes 1–2.
fn loadgen_select(port_clock_khz: u32, lanes: u8, lane: u8) -> u32 {
    if port_clock_khz > 600_000 {
        return 0;
    }
    if lanes == 4 {
        if lane >= 1 {
            LOADGEN_SELECT
        } else {
            0
        }
    } else if lane == 1 || lane == 2 {
        LOADGEN_SELECT
    } else {
        0
    }
}

/// Inputs to the shared six-step level program (`set_levels`).
struct LevelProgram<'a> {
    table: &'a [IclEntry],
    is_hobl: bool,
    levels: &'a [(u8, u8); 4],
    lanes: u8,
    port_clock_khz: u32,
    is_hdmi: bool,
}

// ── Combo PHY ────────────────────────────────────────────────

/// One Gen12 combo PHY: the DDI's PORT_CL/PCS/TX register block
/// plus the table-selection inputs for this modeset run.
#[derive(Copy, Clone, Debug)]
pub struct ComboPhy {
    ddi: Ddi,
    family: Gen12Platform,
    tgl_uy: bool,
    is_edp: bool,
    /// eDP HOBL (VBT `panel.edp.hobl`) — not plumbed into the
    /// modeset yet, so always false; the selection branch and
    /// the CL_DW10 write exist and are unit-tested.
    hobl: bool,
    /// eDP low-vswing (VBT `panel.edp.low_vswing`, parsed in
    /// `intel_gpu_vbt` but not plumbed into the modeset) —
    /// always false for now; same status as `hobl`.
    low_vswing: bool,
}

impl ComboPhy {
    /// Build the combo PHY for `ddi`. Type-C DDIs (D and up)
    /// are owned by `DklPort`, not this module. `family`
    /// defaults to TigerLake when the window carries none (the
    /// modeset's default generation; same convention as the
    /// `vrr_ip` unknown-family fallback).
    pub(crate) fn new(
        ddi: Ddi,
        family: Option<Gen12Platform>,
        tgl_uy: bool,
        is_edp: bool,
    ) -> Result<Self, ModesetError> {
        if ddi as u8 >= Ddi::D as u8 {
            return Err(ModesetError::UnsupportedGeneration);
        }
        Ok(Self {
            ddi,
            family: family.unwrap_or(Gen12Platform::TigerLake),
            tgl_uy,
            is_edp,
            hobl: false,
            low_vswing: false,
        })
    }

    /// Combo-PHY base for this DDI (`intel_port_to_phy` on
    /// display 12: `PHY_A + port - PORT_A`; bases from
    /// `intel_combo_phy_regs.h`). Construction guarantees
    /// DDI A–C; the fallback arm is unreachable in practice.
    const fn phy_base(self) -> u64 {
        match self.ddi {
            Ddi::A => 0x162_000,
            Ddi::B => 0x06C_000,
            Ddi::C => 0x160_000,
            _ => 0x160_000,
        }
    }

    /// The DPLL enable register for this DDI's DPLL: Combo PHY
    /// DDIs A/B/C use DPLL 0/1/2 (the DPCLKA default assignment
    /// — the same mapping as `intel_gpu_modeset::dpll_index_for`).
    const fn dpll_enable_off(self) -> u64 {
        match self.ddi {
            Ddi::A => DPLL0_ENABLE,
            Ddi::B => DPLL1_ENABLE,
            _ => DPLL2_ENABLE,
        }
    }

    const fn cl_dw(self, dw: u64) -> u64 {
        self.phy_base() + 4 * dw
    }
    const fn pcs_dw_grp(self, dw: u64) -> u64 {
        self.phy_base() + 0x600 + 4 * dw
    }
    const fn pcs_dw_ln(self, dw: u64, ln: u64) -> u64 {
        self.phy_base() + 0x800 + ln * 0x100 + 4 * dw
    }
    const fn tx_dw_grp(self, dw: u64) -> u64 {
        self.phy_base() + 0x680 + 4 * dw
    }
    const fn tx_dw_ln(self, dw: u64, ln: u64) -> u64 {
        self.phy_base() + 0x880 + ln * 0x100 + 4 * dw
    }

    fn read(self, io: &(impl MmioWindow + ?Sized), off: u64) -> u32 {
        io.read32(off)
    }
    fn write(self, io: &(impl MmioWindow + ?Sized), off: u64, value: u32) {
        io.write32(off, value);
        compiler_fence(Ordering::SeqCst);
    }
    fn rmw(self, io: &(impl MmioWindow + ?Sized), off: u64, clear: u32, set: u32) {
        let old = self.read(io, off);
        self.write(io, off, (old & !clear) | set);
    }

    /// `icl_ddi_combo_vswing_program`: the eDP HOBL CL_DW10
    /// override, the DW5 scaling/rterm program (GRP write from
    /// the LN0 read), then DW2/DW4/DW7 per lane. DW4 is
    /// per-lane, never GRP — a GRP write would overwrite the
    /// loadgen bits step 2 programmed.
    fn vswing_program(
        self,
        io: &(impl MmioWindow + ?Sized),
        table: &[IclEntry],
        is_hobl: bool,
        levels: &[(u8, u8); 4],
    ) {
        if self.is_edp {
            let val = EDP4K2K_MODE_OVRD_EN | EDP4K2K_MODE_OVRD_OPTIMIZED;
            self.rmw(io, self.cl_dw(10), val, if is_hobl { val } else { 0 });
        }
        let dw5 = self.read(io, self.tx_dw_ln(5, 0));
        let dw5 = (dw5
            & !(SCALING_MODE_SEL_MASK
                | RTERM_SELECT_MASK
                | COEFF_POLARITY
                | CURSOR_PROGRAM
                | TAP2_DISABLE
                | TAP3_DISABLE))
            | SCALING_MODE_SEL_2
            | RTERM_SELECT_6
            | TAP3_DISABLE;
        self.write(io, self.tx_dw_grp(5), dw5);
        for ln in 0..4u64 {
            let (vs, pe) = levels[ln as usize];
            let entry = table[crate::intel_gpu_xelpg::preset_index(vs, pe)];
            self.rmw(
                io,
                self.tx_dw_ln(2, ln),
                SWING_SEL_UPPER_MASK | SWING_SEL_LOWER_MASK | RCOMP_SCALAR_MASK,
                swing_sel_upper(entry.dw2_swing_sel)
                    | swing_sel_lower(entry.dw2_swing_sel)
                    | rcomp_scalar(0x98),
            );
            self.rmw(
                io,
                self.tx_dw_ln(4, ln),
                POST_CURSOR_1_MASK | POST_CURSOR_2_MASK | CURSOR_COEFF_MASK,
                post_cursor_1(entry.dw4_post_cursor_1)
                    | post_cursor_2(entry.dw4_post_cursor_2)
                    | cursor_coeff(entry.dw4_cursor_coeff),
            );
            self.rmw(
                io,
                self.tx_dw_ln(7, ln),
                N_SCALAR_MASK,
                n_scalar(entry.dw7_n_scalar),
            );
        }
    }

    /// The shared six-step sequence of
    /// `icl_combo_phy_set_signal_levels`, parameterized over the
    /// table and the output type. `port_clock_khz` feeds the
    /// loadgen rule (a DP link rate for DP/eDP, the TMDS clock
    /// for HDMI — exactly `crtc_state->port_clock` in Linux).
    fn set_levels(self, io: &(impl MmioWindow + ?Sized), prog: LevelProgram<'_>) {
        // 1. Common keeper: set for DP/eDP, clear for HDMI.
        // Read LN0, write GRP.
        let pcs1 = self.read(io, self.pcs_dw_ln(1, 0));
        let keeper = if prog.is_hdmi {
            pcs1 & !COMMON_KEEPER_EN
        } else {
            pcs1 | COMMON_KEEPER_EN
        };
        self.write(io, self.pcs_dw_grp(1), keeper);
        // 2. Loadgen select per lane.
        for ln in 0..4u64 {
            let loadgen = loadgen_select(prog.port_clock_khz, prog.lanes, ln as u8);
            self.rmw(io, self.tx_dw_ln(4, ln), LOADGEN_SELECT, loadgen);
        }
        // 3. SUS clock config 11b.
        self.rmw(io, self.cl_dw(5), 0, SUS_CLOCK_CONFIG);
        // 4. Clear training enable to change swing values.
        let dw5 = self.read(io, self.tx_dw_ln(5, 0));
        self.write(io, self.tx_dw_grp(5), dw5 & !TX_TRAINING_EN);
        // 5. Swing and de-emphasis.
        self.vswing_program(io, prog.table, prog.is_hobl, prog.levels);
        // 6. Set training enable to trigger update.
        let dw5 = self.read(io, self.tx_dw_ln(5, 0));
        self.write(io, self.tx_dw_grp(5), dw5 | TX_TRAINING_EN);
    }

    /// `icl_combo_phy_set_signal_levels`: program `levels` (one
    /// (swing, pre-emphasis) pair per lane) for `rate` on this
    /// PHY. `lanes` is the trained lane count (loadgen rule
    /// only; the vswing registers are programmed on all four
    /// lanes, as in Linux).
    pub(crate) fn set_signal_levels(
        self,
        io: &(impl MmioWindow + ?Sized),
        rate: LinkRate,
        levels: &[(u8, u8); 4],
        lanes: u8,
    ) -> Result<(), ModesetError> {
        let port_clock = port_clock_khz(rate).ok_or(ModesetError::PhyBusFailure)?;
        let (table, is_hobl) = select_combo_buf_trans(
            self.family,
            self.is_edp,
            port_clock,
            self.tgl_uy,
            self.hobl,
            self.low_vswing,
        );
        self.set_levels(
            io,
            LevelProgram {
                table,
                is_hobl,
                levels,
                lanes,
                port_clock_khz: port_clock,
                is_hdmi: false,
            },
        );
        Ok(())
    }

    /// HDMI default levels on the combo PHY: the ICL HDMI
    /// table's default entry (`hdmi_default_entry`, index 6 —
    /// the 600 mV / 850 mV 3.0 dB preset, i.e. swing 1,
    /// pre-emphasis 2) on all four lanes, common keeper
    /// cleared. Mirrors Linux `intel_ddi_pre_enable_hdmi`
    /// calling `encoder->set_signal_levels` with
    /// `intel_ddi_hdmi_level` (BIOS shift, else the default
    /// entry). `tmds_clock_khz` feeds the loadgen rule exactly
    /// as `crtc_state->port_clock` does in Linux.
    pub(crate) fn set_hdmi_default_levels(
        self,
        io: &(impl MmioWindow + ?Sized),
        tmds_clock_khz: u32,
    ) -> Result<(), ModesetError> {
        let levels = [(1, 2); 4];
        debug_assert_eq!(
            crate::intel_gpu_xelpg::preset_index(1, 2),
            HDMI_DEFAULT_ENTRY
        );
        self.set_levels(
            io,
            LevelProgram {
                table: &ICL_HDMI,
                is_hobl: false,
                levels: &levels,
                lanes: 4,
                port_clock_khz: tmds_clock_khz,
                is_hdmi: true,
            },
        );
        Ok(())
    }

    /// Prepare the combo link for training at `rate`: program
    /// the (0, 0) levels, then enable DP_TP_CTL with pattern 1
    /// (ENABLE | ENHANCED_FRAME | SCRAMBLE_DISABLE, pattern
    /// field left at 0 = PAT1 — the same enable word
    /// `DklPort::start_training` writes for Type-C). Mirrors
    /// Linux `intel_ddi_pre_enable_dp` step 7.e plus the
    /// `intel_dp_start_link_train` PAT1 selection.
    pub(crate) fn prepare(
        self,
        io: &(impl MmioWindow + ?Sized),
        trans: crate::intel_gpu_pipes::Transcoder,
        rate: LinkRate,
        lanes: u8,
    ) -> Result<(), ModesetError> {
        self.set_signal_levels(io, rate, &[(0, 0); 4], lanes)?;
        let tp = trans.base() + DP_TP_CTL_OFFSET;
        self.rmw(
            io,
            tp,
            DP_TP_CTL_LINK_TRAIN_MASK | DP_TP_CTL_SCRAMBLE_DISABLE,
            DP_TP_CTL_ENABLE | DP_TP_CTL_ENHANCED_FRAME_ENABLE | DP_TP_CTL_SCRAMBLE_DISABLE,
        );
        Ok(())
    }

    /// `DklPort::training_update` shape for the combo PHY:
    /// Configure → nothing; Levels (clean) → reprogram the PHY
    /// at the state's rate; Levels (dirty) → nothing (the sink
    /// is about to rewrite the levels); Pattern → retune the
    /// DP_TP_CTL pattern field. A pattern-1 write after a dirty
    /// Configure opens a retry attempt at a lower rate/lanes,
    /// so the DPLL is reprogrammed for the new link clock and
    /// the PHY re-prepared (levels + DP_TP_CTL PAT1) before the
    /// pattern field is rewritten — the mid-training retune,
    /// mirroring the TC branch's `start_training(retune)`.
    /// The pattern-0 write at the end of training is what
    /// returns DP_TP_CTL to NORMAL (`LINK_TRAIN_NORMAL` = 3),
    /// so there is no separate finish step — mirroring the TC
    /// path.
    pub(crate) fn training_update(
        self,
        io: &(impl MmioWindow + ?Sized),
        trans: crate::intel_gpu_pipes::Transcoder,
        state: &crate::intel_gpu_modeset::training::State,
        change: crate::intel_gpu_modeset::training::Change,
    ) -> Result<(), ModesetError> {
        use crate::intel_gpu_modeset::training::Change;
        match change {
            Change::Configure => Ok(()),
            Change::Levels if !state.dirty => {
                self.set_signal_levels(io, state.rate, &state.levels, state.lanes)
            }
            Change::Levels => Ok(()),
            Change::Pattern => {
                if state.pattern == 1 && state.dirty {
                    self.retune_dpll(io, trans, state.rate)?;
                    self.prepare(io, trans, state.rate, state.lanes)?;
                }
                let tp = trans.base() + DP_TP_CTL_OFFSET;
                let bits = state
                    .pattern_bits()
                    .map_err(|_| ModesetError::PhyBusFailure)?;
                self.rmw(
                    io,
                    tp,
                    DP_TP_CTL_LINK_TRAIN_MASK | DP_TP_CTL_SCRAMBLE_DISABLE,
                    bits,
                );
                Ok(())
            }
        }
    }

    /// Poll an MMIO register's `mask` bits until they assert
    /// (when `set`) or deassert, with a `ms` cap. Mirrors
    /// `DklPort::wait_timeout` (`intel_gpu_gen12_tc`).
    fn wait(
        self,
        io: &(impl MmioWindow + ?Sized),
        off: u64,
        mask: u32,
        set: bool,
        ms: u64,
    ) -> Result<(), ModesetError> {
        let done = narf_scheduler::responsive_spin_until(
            || {
                let v = self.read(io, off);
                if set {
                    v & mask == mask
                } else {
                    v & mask == 0
                }
            },
            narf_time::Deadline::after_ms(ms),
        );
        if done {
            Ok(())
        } else {
            Err(ModesetError::PllLockTimeout)
        }
    }

    /// Reprogram this DDI's combo DPLL for `rate` mid-training:
    /// the `train_link` fallback ladder's retry attempt at a
    /// lower rate. Mirrors the Type-C
    /// `DklPort::start_training(retune)` restart, minus the
    /// clock re-route — DPCLKA routing selects the DPLL index,
    /// which a rate change does not alter — and Linux's
    /// `icl_pll_disable` + `icl_pll_enable` pair
    /// (`intel_dpll.c`):
    ///
    ///   1. Stop the DDI buffer (already off while training;
    ///      the clear + idle wait is the same defensive step
    ///      the TC retune takes) and the training-pattern
    ///      driver (`DP_TP_CTL` ENABLE off).
    ///   2. Disable the DPLL (PLL_ENABLE off, wait LOCK clear;
    ///      POWER_ENABLE off, wait POWER_STATE clear).
    ///   3. Bring it back up at the new rate with the standard
    ///      program sequence (power, CFGCR0/1 from
    ///      `combo_coeffs` under the DSSM reference family,
    ///      enable, wait LOCK) — the same steps as
    ///      `intel_gpu_modeset::program_dpll_coeffs`.
    ///
    /// The coefficients resolve before any register is touched,
    /// so an unrepresentable rate fails closed without
    /// disturbing the running PLL. The caller re-prepares the
    /// PHY levels + `DP_TP_CTL` PAT1 after this returns
    /// (`prepare`), so the retry attempt drives TPS1 at the new
    /// link clock. A lock or idle timeout aborts training with
    /// `PllLockTimeout`.
    ///
    /// Status bits are read-only: the read-modify-writes below
    /// strip `PLL_LOCK` / `PLL_POWER_STATE` from the read value
    /// before writing it back, so a store-everything fixture
    /// does not latch them as programmed bits (the running
    /// `program_dpll_coeffs` never waits on a clear, so it
    /// never needed the strip).
    fn retune_dpll(
        self,
        io: &(impl MmioWindow + ?Sized),
        trans: crate::intel_gpu_pipes::Transcoder,
        rate: LinkRate,
    ) -> Result<(), ModesetError> {
        use crate::intel_gpu_ddi::{
            DDI_BUF_CTL_ENABLE, DDI_BUF_CTL_IDLE_STATUS, DDI_BUF_CTL_OFFSET,
        };
        use crate::intel_gpu_pll::{combo_coeffs, decode_refclk_family, encode_cfgcr0, DSSM};
        let coeffs = match combo_coeffs(rate, decode_refclk_family(self.read(io, DSSM))) {
            Some(c) => c,
            None => return Err(ModesetError::PllLockTimeout),
        };
        let enable = self.dpll_enable_off();
        // 1. Stop the DDI buffer + the pattern driver.
        self.rmw(
            io,
            self.ddi.base() + DDI_BUF_CTL_OFFSET,
            DDI_BUF_CTL_ENABLE,
            0,
        );
        self.wait(
            io,
            self.ddi.base() + DDI_BUF_CTL_OFFSET,
            DDI_BUF_CTL_IDLE_STATUS,
            true,
            10,
        )?;
        self.rmw(io, trans.base() + DP_TP_CTL_OFFSET, DP_TP_CTL_ENABLE, 0);
        // 2. Disable the DPLL.
        let cur = self.read(io, enable) & !DPLL_STATUS_BITS;
        self.write(io, enable, cur & !DPLL_PLL_ENABLE);
        self.wait(io, enable, DPLL_PLL_LOCK, false, 1)?;
        let cur = self.read(io, enable) & !DPLL_STATUS_BITS;
        self.write(io, enable, cur & !DPLL_PLL_POWER_ENABLE);
        self.wait(io, enable, DPLL_PLL_POWER_STATE, false, 1)?;
        // 3. Bring it back up at the new rate.
        let cur = self.read(io, enable) & !DPLL_STATUS_BITS;
        self.write(io, enable, cur | DPLL_PLL_POWER_ENABLE);
        self.wait(io, enable, DPLL_PLL_POWER_STATE, true, 1)?;
        let cfgcr0_off = match self.ddi {
            Ddi::A => crate::intel_gpu_pll::DPLL_CFGCR0_DPLL0,
            Ddi::B => crate::intel_gpu_pll::DPLL_CFGCR0_DPLL1,
            _ => crate::intel_gpu_pll::DPLL_CFGCR0_DPLL2,
        };
        self.write(io, cfgcr0_off, encode_cfgcr0(&coeffs));
        self.write(
            io,
            crate::intel_gpu_pll::dpll_cfgcr1(cfgcr0_off),
            coeffs.cfgcr1,
        );
        compiler_fence(Ordering::SeqCst);
        let cur = self.read(io, enable) & !DPLL_STATUS_BITS;
        self.write(io, enable, cur | DPLL_PLL_ENABLE);
        self.wait(io, enable, DPLL_PLL_LOCK, true, 1)
    }
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use alloc::{collections::BTreeMap, vec::Vec};
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Backing-store MMIO: reads serve the last write (so
    /// read-modify-write works), writes are logged.
    struct Model {
        regs: RefCell<BTreeMap<u64, u32>>,
        writes: RefCell<Vec<(u64, u32)>>,
    }
    impl Model {
        fn new() -> Self {
            Self {
                regs: RefCell::new(BTreeMap::new()),
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
        fn last_write_to(&self, off: u64) -> Option<u32> {
            self.writes_to(off).into_iter().last()
        }
    }
    impl MmioWindow for Model {
        fn read32(&self, off: u64) -> u32 {
            let stored = self.regs.borrow().get(&off).copied().unwrap_or(0);
            match off {
                // DPLL enable: LOCK follows ENABLE and
                // POWER_STATE follows POWER_ENABLE — the same
                // computed-bits shape the modeset's
                // ScriptedSinkMmio serves, so the retune's
                // waits see a live PLL.
                0x4_6010 | 0x4_6014 | 0x4_6018 => {
                    let mut v = stored;
                    if stored & (1 << 27) != 0 {
                        v |= 1 << 26;
                    }
                    if stored & (1 << 31) != 0 {
                        v |= 1 << 30;
                    }
                    v
                }
                // DDI_BUF_CTL (DDI base + 0): IDLE_STATUS
                // asserts exactly while the buffer is off.
                o if o == Ddi::A.base() || o == Ddi::B.base() || o == Ddi::C.base() => {
                    if stored & (1 << 31) != 0 {
                        stored & !(1 << 7)
                    } else {
                        stored | (1 << 7)
                    }
                }
                _ => stored,
            }
        }
        fn write32(&self, off: u64, value: u32) {
            self.writes.borrow_mut().push((off, value));
            self.regs.borrow_mut().insert(off, value);
            // Group aperture: a GRP write lands on all four
            // lanes, so a later LN0 read sees it — the hardware
            // behavior Linux's read-LN0/write-GRP sequence
            // relies on (step 6's training-enable set must not
            // clobber step 5's scaling program). The writes log
            // still records exactly what the driver wrote.
            for base in [0x162000u64, 0x6C000, 0x160000, 0x161000, 0x16B000] {
                for (grp, ln) in [(base + 0x604, base + 0x804), (base + 0x694, base + 0x894)] {
                    if off == grp {
                        for lane in 0..4u64 {
                            self.regs.borrow_mut().insert(ln + lane * 0x100, value);
                        }
                    }
                }
            }
        }
    }

    /// One row of the table-selection smoke test: (family, is_edp,
    /// port_clock, uy, hobl, low_vswing) → (first entry, table
    /// length, is_hobl).
    type ComboPhyTableCase = (
        Gen12Platform,
        bool,
        u32,
        bool,
        bool,
        bool,
        IclEntry,
        usize,
        bool,
    );

    fn smoke_combo_phy_table_selection() -> TestResult {
        use Gen12Platform::*;
        // (family, is_edp, port_clock, uy, hobl, low_vswing) →
        // (first entry, table length, is_hobl).
        let first = |t: &[IclEntry]| t[0];
        let cases: [ComboPhyTableCase; 18] = [
            // Tiger Lake DP: 270 MHz boundary is the low table.
            (
                TigerLake,
                false,
                270_000,
                false,
                false,
                false,
                e(0xA, 0x32, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
            (
                TigerLake,
                false,
                270_001,
                false,
                false,
                false,
                e(0xA, 0x35, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
            // Tiger Lake UY HBR2 differs from the standard table
            // from entry 1 on; entry 0 is shared.
            (
                TigerLake,
                false,
                540_000,
                true,
                false,
                false,
                e(0xA, 0x35, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
            // Tiger Lake eDP HBR3, HOBL (9 entries, all cloned),
            // low-vswing.
            (
                TigerLake,
                true,
                810_000,
                false,
                false,
                false,
                e(0xA, 0x35, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
            (
                TigerLake,
                true,
                540_000,
                false,
                true,
                false,
                e(0x6, 0x7F, 0x3F, 0x00, 0x00),
                9,
                true,
            ),
            (
                TigerLake,
                true,
                540_000,
                false,
                false,
                true,
                e(0x0, 0x7F, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
            // eDP falls back to the DP table when neither VBT bit
            // is set.
            (
                TigerLake,
                true,
                540_000,
                false,
                false,
                false,
                e(0xA, 0x35, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
            // Rocket Lake.
            (
                RocketLake,
                false,
                270_000,
                false,
                false,
                false,
                e(0xA, 0x2F, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
            (
                RocketLake,
                false,
                540_000,
                false,
                false,
                false,
                e(0xA, 0x35, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
            (
                RocketLake,
                true,
                810_000,
                false,
                false,
                false,
                e(0xA, 0x35, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
            // Alder Lake-S: low DP reuses the TGL HBR table.
            (
                AlderLakeS,
                false,
                270_000,
                false,
                false,
                false,
                e(0xA, 0x32, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
            (
                AlderLakeS,
                false,
                540_000,
                false,
                false,
                false,
                e(0xA, 0x35, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
            (
                AlderLakeS,
                true,
                540_000,
                false,
                false,
                true,
                e(0x9, 0x73, 0x3D, 0x00, 0x02),
                10,
                false,
            ),
            // Alder Lake-P (and -N, same tables).
            (
                AlderLakeP,
                false,
                270_000,
                false,
                false,
                false,
                e(0xA, 0x35, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
            (
                AlderLakeP,
                false,
                540_000,
                false,
                false,
                false,
                e(0xA, 0x35, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
            (
                AlderLakeN,
                true,
                540_000,
                false,
                false,
                true,
                e(0x4, 0x50, 0x38, 0x00, 0x07),
                10,
                false,
            ),
            // DG1.
            (
                Dg1,
                false,
                270_000,
                false,
                false,
                false,
                e(0xA, 0x32, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
            (
                Dg1,
                false,
                540_000,
                false,
                false,
                false,
                e(0xA, 0x32, 0x3F, 0x00, 0x00),
                10,
                false,
            ),
        ];
        for (family, is_edp, clock, uy, hobl, low_vswing, want_first, want_len, want_hobl) in cases
        {
            let (table, got_hobl) =
                select_combo_buf_trans(family, is_edp, clock, uy, hobl, low_vswing);
            if first(table) != want_first || table.len() != want_len || got_hobl != want_hobl {
                return TestResult::Fail("combo table selection mismatch");
            }
        }
        // The UY table really differs (entry 1: N-scalar 0x36
        // vs 0x37, post-cursor-1 0x09 vs 0x08).
        if TGL_UY_DP_HBR2[1] != e(0xA, 0x4F, 0x36, 0x00, 0x09)
            || TGL_DP_HBR2[1] != e(0xA, 0x4F, 0x37, 0x00, 0x08)
        {
            return TestResult::Fail("UY table must differ from the standard HBR2 table");
        }
        // Tables that share entry 0 must still be told apart:
        // ADL-P low/high differ at entry 2, DG1 low/high at
        // entry 7.
        if select_combo_buf_trans(AlderLakeP, false, 270_000, false, false, false).0[2]
            != e(0xC, 0x71, 0x31, 0x00, 0x0E)
            || select_combo_buf_trans(AlderLakeP, false, 540_000, false, false, false).0[2]
                != e(0xC, 0x71, 0x30, 0x00, 0x0F)
            || select_combo_buf_trans(Dg1, false, 270_000, false, false, false).0[7]
                != e(0xC, 0x60, 0x3F, 0x00, 0x00)
            || select_combo_buf_trans(Dg1, false, 540_000, false, false, false).0[7]
                != e(0xC, 0x58, 0x3F, 0x00, 0x00)
        {
            return TestResult::Fail("ADL-P / DG1 low/high tables must differ");
        }
        // ADL-S eDP HBR3 is the ADL-S DP HBR2/HBR3 table; ADL-P
        // eDP HBR3 is the ADL-P DP HBR2/HBR3 table.
        if select_combo_buf_trans(AlderLakeS, true, 810_000, false, false, false)
            .0
            .as_ptr()
            != ADLS_DP_HBR2_HBR3.as_ptr()
            || select_combo_buf_trans(AlderLakeP, true, 810_000, false, false, false)
                .0
                .as_ptr()
                != ADLP_DP_HBR2_HBR3.as_ptr()
        {
            return TestResult::Fail("eDP HBR3 must alias the DP HBR2/HBR3 table");
        }
        if port_clock_khz(LinkRate::DpHbr2) != Some(540_000)
            || port_clock_khz(LinkRate::DpHbr3) != Some(810_000)
            || port_clock_khz(LinkRate::DpRbr) != Some(162_000)
            || port_clock_khz(LinkRate::Hdmi594).is_some()
        {
            return TestResult::Fail("port clock mapping wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_combo_phy",
        smoke_combo_phy_table_selection
    );

    fn smoke_combo_phy_is_tgl_uy() -> TestResult {
        // Linux `INTEL_TGL_GT2_IDS` (`include/drm/intel/pciids.h`,
        // Linux 7.4-rc2): 9A40 IS GT2/UY; 9A68/9A70 are GT1.
        for did in [
            0x9A40, 0x9A49, 0x9A59, 0x9A78, 0x9AC0, 0x9AC9, 0x9AD9, 0x9AF8,
        ] {
            if !is_tgl_uy(did) {
                return TestResult::Fail("GT2 DID must select the UY table");
            }
        }
        // GT1 is 9A60, 9A68, 9A70; RKL 0x4C80 / TGL-H 0x4626 are
        // not TGL GT2 either.
        if is_tgl_uy(0x9A60)
            || is_tgl_uy(0x9A68)
            || is_tgl_uy(0x9A70)
            || is_tgl_uy(0x4C80)
            || is_tgl_uy(0x4626)
        {
            return TestResult::Fail("non-GT2 DID must not select the UY table");
        }
        // 0x9A40 must select the UY HBR2 table end to end at HBR2
        // rates (entry 1 distinguishes it from the standard table),
        // and GT1 0x9A68 must select the standard HBR2 table.
        let (table, _) = tgl_dp(540_000, is_tgl_uy(0x9A40));
        if table[1] != TGL_UY_DP_HBR2[1] {
            return TestResult::Fail("0x9A40 must select the UY HBR2 table");
        }
        let (table, _) = tgl_dp(540_000, is_tgl_uy(0x9A68));
        if table[1] != TGL_DP_HBR2[1] {
            return TestResult::Fail("0x9A68 (GT1) must select the standard HBR2 table");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_combo_phy",
        smoke_combo_phy_is_tgl_uy
    );

    fn smoke_combo_phy_set_signal_levels_programs_phy() -> TestResult {
        use Gen12Platform::TigerLake;
        let io = Model::new();
        let phy = match ComboPhy::new(Ddi::B, Some(TigerLake), false, false) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("DDI B must build a combo PHY"),
        };
        if ComboPhy::new(Ddi::D, Some(TigerLake), false, false).is_ok()
            || ComboPhy::new(Ddi::A, None, false, true).is_err()
        {
            return TestResult::Fail("combo PHY must refuse TC DDIs and accept DDI A");
        }
        // HBR2, levels (1, 0) on all lanes: preset 4 of the TGL
        // HBR2 table {0xA, 0x47, 0x3F, 0x00, 0x00}.
        if phy
            .set_signal_levels(&io, LinkRate::DpHbr2, &[(1, 0); 4], 4)
            .is_err()
        {
            return TestResult::Fail("set_signal_levels must succeed");
        }
        let base = 0x6C000u64; // PHY_B
                               // 1. Common keeper set (DP).
        if io.last_write_to(base + 0x604) != Some(1 << 26) {
            return TestResult::Fail("PCS_DW1 GRP must set COMMON_KEEPER_EN");
        }
        // 2. Loadgen: 4 lanes at 540 MHz → lanes 1–3 set.
        if io.last_write_to(base + 0x890) != Some(0x3F)
            || io.last_write_to(base + 0x990) != Some(0x8000_003F)
        {
            return TestResult::Fail("DW4 loadgen must be clear on LN0, set on LN1");
        }
        // 3. SUS clock config 11b.
        if io.last_write_to(base + 0x14) != Some(0x3) {
            return TestResult::Fail("CL_DW5 must carry SUS_CLOCK_CONFIG");
        }
        // 5/6. DW5: scaling 0x2 + rterm 0x6 + TAP3_DISABLE, then
        // training enable.
        if io.last_write_to(base + 0x694) != Some(0xA008_0030) {
            return TestResult::Fail("DW5 GRP must end with training enable set");
        }
        // DW2 LN1: swing 0xA → upper 1, lower 2, RCOMP 0x98.
        if io.last_write_to(base + 0x988) != Some(0x9098) {
            return TestResult::Fail("DW2 must carry the preset-4 swing");
        }
        // DW7 LN2: N-scalar 0x47.
        if io.last_write_to(base + 0xA9C) != Some(0x4700_0000) {
            return TestResult::Fail("DW7 must carry the preset-4 N-scalar");
        }
        // No CL_DW10 write on a non-eDP link.
        if !io.writes_to(base + 0x28).is_empty() {
            return TestResult::Fail("CL_DW10 must not be touched on DP");
        }
        // An HDMI rate is not a DP link rate.
        if phy
            .set_signal_levels(&io, LinkRate::Hdmi594, &[(0, 0); 4], 4)
            .is_ok()
        {
            return TestResult::Fail("HDMI rate must not select a DP table");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_combo_phy",
        smoke_combo_phy_set_signal_levels_programs_phy
    );

    fn smoke_combo_phy_edp_clears_hobl_override() -> TestResult {
        use Gen12Platform::TigerLake;
        let io = Model::new();
        let phy = ComboPhy::new(Ddi::A, Some(TigerLake), false, true).unwrap();
        if phy
            .set_signal_levels(&io, LinkRate::DpHbr2, &[(0, 0); 4], 4)
            .is_err()
        {
            return TestResult::Fail("eDP set_signal_levels must succeed");
        }
        // HOBL is false (not plumbed), so CL_DW10 is written
        // with the override bits cleared — the same write Linux
        // makes when `hobl_active` is false.
        if io.writes_to(0x162000 + 0x28) != alloc::vec![0u32] {
            return TestResult::Fail("eDP must clear the CL_DW10 HOBL override");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_combo_phy",
        smoke_combo_phy_edp_clears_hobl_override
    );

    fn smoke_combo_phy_loadgen_rules() -> TestResult {
        use Gen12Platform::TigerLake;
        let io = Model::new();
        let phy = ComboPhy::new(Ddi::B, Some(TigerLake), false, false).unwrap();
        let base = 0x6C000u64;
        // Above 6 GHz (HBR3): no loadgen on any lane. Levels
        // (0, 0) → preset 0, cursor 0x3F.
        phy.set_signal_levels(&io, LinkRate::DpHbr3, &[(0, 0); 4], 4)
            .unwrap();
        if io.last_write_to(base + 0x990) != Some(0x3F)
            || io.last_write_to(base + 0xB90) != Some(0x3F)
        {
            return TestResult::Fail("HBR3 must clear loadgen on every lane");
        }
        // 2 lanes at HBR2: lanes 1–2 set, 0 and 3 clear.
        phy.set_signal_levels(&io, LinkRate::DpHbr2, &[(0, 0); 4], 2)
            .unwrap();
        if io.last_write_to(base + 0x890) != Some(0x3F)
            || io.last_write_to(base + 0x990) != Some(0x8000_003F)
            || io.last_write_to(base + 0xA90) != Some(0x8000_003F)
            || io.last_write_to(base + 0xB90) != Some(0x3F)
        {
            return TestResult::Fail("2-lane loadgen must set lanes 1-2 only");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_combo_phy",
        smoke_combo_phy_loadgen_rules
    );

    fn smoke_combo_phy_hdmi_default_levels() -> TestResult {
        use Gen12Platform::TigerLake;
        let io = Model::new();
        let phy = ComboPhy::new(Ddi::B, Some(TigerLake), false, false).unwrap();
        if phy.set_hdmi_default_levels(&io, 148_500).is_err() {
            return TestResult::Fail("HDMI default levels must succeed");
        }
        let base = 0x6C000u64;
        // Common keeper cleared for HDMI.
        if io.last_write_to(base + 0x604) != Some(0) {
            return TestResult::Fail("HDMI must clear COMMON_KEEPER_EN");
        }
        // Default entry 6 {0x6, 0x7F, 0x35, 0x00, 0x0A}:
        // DW2 swing 0x6 → upper 0, lower 6, RCOMP 0x98.
        if io.last_write_to(base + 0x888) != Some(0x3098) {
            return TestResult::Fail("HDMI DW2 must carry the default-entry swing");
        }
        // DW4 LN0: post-cursor-1 0x0A, cursor 0x35, no loadgen.
        if io.last_write_to(base + 0x890) != Some(0xA035) {
            return TestResult::Fail("HDMI DW4 must carry the default-entry cursor");
        }
        // DW7 LN0: N-scalar 0x7F.
        if io.last_write_to(base + 0x89C) != Some(0x7F00_0000) {
            return TestResult::Fail("HDMI DW7 must carry the default-entry N-scalar");
        }
        // No CL_DW10 write (not eDP).
        if !io.writes_to(base + 0x28).is_empty() {
            return TestResult::Fail("HDMI must not touch CL_DW10");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_combo_phy",
        smoke_combo_phy_hdmi_default_levels
    );

    fn smoke_combo_phy_prepare_and_training_update() -> TestResult {
        use crate::intel_gpu_modeset::training::{Change, State};
        use crate::intel_gpu_pipes::Transcoder;
        use Gen12Platform::TigerLake;
        let io = Model::new();
        let phy = ComboPhy::new(Ddi::A, Some(TigerLake), false, true).unwrap();
        let trans = Transcoder::A;
        let tp = trans.base() + 0x540;
        // Prepare: (0, 0) levels + DP_TP_CTL enable with PAT1.
        if phy.prepare(&io, trans, LinkRate::DpHbr2, 4).is_err() {
            return TestResult::Fail("prepare must succeed");
        }
        if io.last_write_to(tp) != Some(0x8004_0080) {
            return TestResult::Fail("prepare must enable DP_TP_CTL with PAT1");
        }
        // (0, 0) → preset 0 of the TGL HBR2 table: N-scalar 0x35.
        if io.last_write_to(0x162000 + 0x89C) != Some(0x3500_0000) {
            return TestResult::Fail("prepare must program the (0, 0) levels");
        }
        // Configure → no PHY writes.
        let before = io.writes.borrow().len();
        let mut state = State::new(LinkRate::DpHbr2, 4);
        if phy
            .training_update(&io, trans, &state, Change::Configure)
            .is_err()
            || io.writes.borrow().len() != before
        {
            return TestResult::Fail("Configure must not touch the PHY");
        }
        // Levels while dirty → no PHY writes.
        state.dirty = true;
        state.levels = [(1, 0); 4];
        if phy
            .training_update(&io, trans, &state, Change::Levels)
            .is_err()
            || io.writes.borrow().len() != before
        {
            return TestResult::Fail("dirty Levels must not touch the PHY");
        }
        // Levels clean → reprogram at (1, 0): preset 4,
        // N-scalar 0x47.
        state.dirty = false;
        if phy
            .training_update(&io, trans, &state, Change::Levels)
            .is_err()
            || io.last_write_to(0x162000 + 0x89C) != Some(0x4700_0000)
        {
            return TestResult::Fail("clean Levels must reprogram the PHY");
        }
        // Pattern 1 → PAT1 (0 in bits 10:8, scramble disable);
        // pattern 3 → PAT3 (4); pattern 0 → NORMAL (3).
        state.pattern = 1;
        phy.training_update(&io, trans, &state, Change::Pattern)
            .unwrap();
        if io.last_write_to(tp) != Some(0x8004_0080) {
            return TestResult::Fail("pattern 1 must select PAT1");
        }
        state.pattern = 3;
        phy.training_update(&io, trans, &state, Change::Pattern)
            .unwrap();
        if io.last_write_to(tp) != Some(0x8004_0480) {
            return TestResult::Fail("pattern 3 must select PAT3");
        }
        state.pattern = 0;
        phy.training_update(&io, trans, &state, Change::Pattern)
            .unwrap();
        if io.last_write_to(tp) != Some(0x8004_0300) {
            return TestResult::Fail("pattern 0 must return DP_TP_CTL to NORMAL");
        }
        // An undefined pattern cannot be encoded.
        state.pattern = 5;
        if phy
            .training_update(&io, trans, &state, Change::Pattern)
            .is_ok()
        {
            return TestResult::Fail("undefined pattern must fail");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_combo_phy",
        smoke_combo_phy_prepare_and_training_update
    );

    fn smoke_combo_phy_fallback_retunes_dpll_before_sink_pattern() -> TestResult {
        use crate::dp_aux::{AuxChannel, AuxCommand, AuxError, AuxRequest, AuxResponse, AuxStatus};
        use crate::intel_gpu_modeset::training::{State, TrainingAux};
        use crate::intel_gpu_pipes::Transcoder;
        use Gen12Platform::TigerLake;
        // A sink stub that acks every AUX transaction — but on
        // a TPS1 write it first checks the source already
        // retuned the DPLL for the fallback rate: the retune
        // must precede the sink's pattern write, never follow
        // it (`TrainingAux` runs the source callback before
        // forwarding the write).
        struct Sink<'a>(&'a Model);
        impl AuxChannel for Sink<'_> {
            fn transact<'a>(
                &mut self,
                request: &AuxRequest<'_>,
                reply: &'a mut [u8],
            ) -> Result<AuxResponse<'a>, AuxError> {
                if request.cmd == AuxCommand::NativeWrite
                    && request.address == 0x102
                    && request.data[0] & 7 == 1
                {
                    // HBR CFGCR1: KDIV_2 | PDIV_3 | CFREQ_8_4_GHZ.
                    if self.0.last_write_to(0x164288) != Some(0x8B) {
                        return Err(AuxError::Nacked);
                    }
                }
                Ok(AuxResponse {
                    status: AuxStatus::Ack,
                    data: &reply[..0],
                })
            }
        }
        let io = Model::new();
        // DSSM strap: 19.2 MHz (field 1).
        io.regs
            .borrow_mut()
            .insert(crate::intel_gpu_pll::DSSM, 1 << 29);
        let phy = ComboPhy::new(Ddi::A, Some(TigerLake), false, true).unwrap();
        let trans = Transcoder::A;
        let tp = trans.base() + 0x540;
        // Prepare at HBR2, then bring the DPLL up at HBR2 the
        // way the modeset's step 4 does, so the retune has a
        // running PLL to take down (CFGCR1 HBR2: KDIV_1 |
        // PDIV_3 | CFREQ_8_4_GHZ = 0x4B).
        if phy.prepare(&io, trans, LinkRate::DpHbr2, 4).is_err() {
            return TestResult::Fail("prepare must succeed");
        }
        io.write32(0x4_6010, 1 << 27);
        io.write32(crate::intel_gpu_pll::DPLL_CFGCR0_DPLL0, 0x01C0_01A5);
        io.write32(0x164288, 0x4B);
        io.write32(0x4_6010, (1 << 27) | (1 << 31));
        let mut aux = TrainingAux::new(
            Sink(&io),
            State::new(LinkRate::DpHbr2, 4),
            |state: &State, change| {
                phy.training_update(&io, trans, state, change)
                    .map_err(|_| AuxError::Nacked)
            },
        );
        // Fallback: the sink is told HBR (LINK_BW_SET 0x0A),
        // then TPS1. The TPS1 write must succeed — which it
        // only does if the DPLL was already retuned to HBR
        // when the sink stub inspected it.
        if aux.dpcd_write(0x100, &[0x0A]).is_err() {
            return TestResult::Fail("LINK_BW_SET fallback write must succeed");
        }
        if aux.dpcd_write(0x102, &[1]).is_err() {
            return TestResult::Fail(
                "TPS1 after fallback must succeed — the DPLL retune must precede it",
            );
        }
        // CFGCR1 walked HBR2 → HBR; CFGCR0 was rewritten with
        // the same DCO row (the DCO is rate-independent inside
        // one reference family).
        if io.writes_to(0x164288) != alloc::vec![0x4B, 0x8B] {
            return TestResult::Fail("fallback must reprogram CFGCR1 to the HBR row");
        }
        if io.writes_to(crate::intel_gpu_pll::DPLL_CFGCR0_DPLL0)
            != alloc::vec![0x01C0_01A5, 0x01C0_01A5]
        {
            return TestResult::Fail("fallback must rewrite CFGCR0 with the retuned rate");
        }
        // DPLL enable cycled: power, enable, then the retune's
        // disable (enable off, power off) + bring-up.
        if io.writes_to(0x4_6010)
            != alloc::vec![
                0x0800_0000,
                0x8800_0000,
                0x0800_0000,
                0,
                0x0800_0000,
                0x8800_0000
            ]
        {
            return TestResult::Fail("fallback must disable then re-enable the DPLL");
        }
        // Levels were re-prepared at HBR: preset 0 of the TGL
        // HBR table, N-scalar 0x32 (not the HBR2 0x35).
        if io.last_write_to(0x162000 + 0x89C) != Some(0x3200_0000) {
            return TestResult::Fail("fallback must re-prepare levels at the retuned rate");
        }
        // DP_TP_CTL ends enabled with PAT1.
        if io.last_write_to(tp) != Some(0x8004_0080) {
            return TestResult::Fail("fallback must leave DP_TP_CTL enabled with PAT1");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_combo_phy",
        smoke_combo_phy_fallback_retunes_dpll_before_sink_pattern
    );

    fn smoke_combo_phy_edp_hbr3_aliases_dp_table() -> TestResult {
        use Gen12Platform::*;
        // eDP HBR3 (> 540 MHz) selects the DP HBR2/HBR3 table
        // for every family — the shared ICL table on TGL/RKL/
        // DG1, the family's own DP HBR2/HBR3 table on ADL-S/P/N
        // (Linux `tgl/rkl/dg1_get_combo_buf_trans_edp` return
        // `&icl_combo_phy_trans_dp_hbr2_edp_hbr3`;
        // `adls/adlp_get_combo_buf_trans_edp` return their
        // `edp_hbr3` table, whose entries are the DP HBR2/HBR3
        // entries). This is a pointer comparison on purpose:
        // the tables are `static`, so the alias must be the
        // same storage, not merely equal contents — a `const`
        // table fails this in multi-CGU builds (kt-gpu run
        // 44933361128).
        let cases: [(Gen12Platform, &[IclEntry]); 6] = [
            (TigerLake, &ICL_DP_HBR2_EDP_HBR3),
            (RocketLake, &ICL_DP_HBR2_EDP_HBR3),
            (AlderLakeS, &ADLS_DP_HBR2_HBR3),
            (AlderLakeP, &ADLP_DP_HBR2_HBR3),
            (AlderLakeN, &ADLP_DP_HBR2_HBR3),
            (Dg1, &ICL_DP_HBR2_EDP_HBR3),
        ];
        for (family, want) in cases {
            let (table, _) = select_combo_buf_trans(family, true, 810_000, false, false, false);
            if table.as_ptr() != want.as_ptr() {
                return TestResult::Fail("eDP HBR3 must alias the DP HBR2/HBR3 table");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_combo_phy",
        smoke_combo_phy_edp_hbr3_aliases_dp_table
    );

    fn smoke_combo_phy_dw7_n_scalar_full_range() -> TestResult {
        use Gen12Platform::TigerLake;
        let io = Model::new();
        let phy = ComboPhy::new(Ddi::B, Some(TigerLake), false, false).unwrap();
        let base = 0x6C000u64; // PHY_B

        // (swing, pre-emphasis) for presets 0..9 — the same
        // order `preset_index` maps them in.
        let levels: [(u8, u8); 10] = [
            (0, 0),
            (0, 1),
            (0, 2),
            (0, 3),
            (1, 0),
            (1, 1),
            (1, 2),
            (2, 0),
            (2, 1),
            (3, 0),
        ];
        for (preset, (vs, pe)) in levels.iter().enumerate() {
            let want = (TGL_DP_HBR2[preset].dw7_n_scalar as u32) << 24;
            if phy
                .set_signal_levels(&io, LinkRate::DpHbr2, &[(*vs, *pe); 4], 4)
                .is_err()
            {
                return TestResult::Fail("set_signal_levels must succeed for every preset");
            }
            // DW7 is bits 30:24 — 7 bits. The preset-4
            // N-scalar 0x47, 0x4F/0x63/0x7B/0x7F entries: a
            // 6-bit mask would truncate every one of them.
            if io.last_write_to(base + 0x89C) != Some(want)
                || io.last_write_to(base + 0xB9C) != Some(want)
            {
                return TestResult::Fail("DW7 must carry the full 7-bit preset N-scalar");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen12_combo_phy",
        smoke_combo_phy_dw7_n_scalar_full_range
    );
}

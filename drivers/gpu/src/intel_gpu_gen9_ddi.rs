//! Gen9 (Skylake / Kaby Lake / Coffee Lake / Whiskey Lake /
//! Comet Lake) DDI buffer translation — the SKL swing tables
//! and their `DDI_BUF_TRANS` programming.
//!
//! Transcribed from Linux `display/intel_ddi_buf_trans.c`
//! (7.4-rc2): the SKL HSW-entry tables (`skl_trans_dp`,
//! `skl_u_trans_dp`, `skl_y_trans_dp`, `kbl_trans_dp`,
//! `kbl_u_trans_dp`, `kbl_y_trans_dp`, `skl_trans_edp`,
//! `skl_u_trans_edp`, `skl_y_trans_edp`, `skl_trans_hdmi`,
//! `skl_y_trans_hdmi` — 106 entries total) and their
//! selection (`skl_get_buf_trans`, `skl_u_get_buf_trans`,
//! `skl_y_get_buf_trans`, `kbl_get_buf_trans`,
//! `kbl_u_get_buf_trans`, `kbl_y_get_buf_trans`) plus the
//! programming in `display/intel_ddi.c`
//! (`hsw_prepare_dp_ddi_buffers`,
//! `hsw_prepare_hdmi_ddi_buffers`, `intel_ddi_hdmi_level`,
//! `skl_ddi_set_iboost`).
//!
//! One entry is `{trans1, trans2, i_boost}` — the field order
//! of Linux's `intel_ddi_buf_trans_entry.hsw`
//! (`display/intel_ddi_buf_trans.h`): trans1 is the balance
//! leg enable / de-emphasis level, trans2 the vref select /
//! vswing, i_boost the SKL I_boost value (valid 0x0, 0x1,
//! 0x3, 0x7).
//!
//! ## Selection
//!
//! `select_table` mirrors the per-SKU getters:
//!
//! - The U/Y getter is chosen by SKU family, not by the VBT
//!   low-vswing bit: ULX takes the `*_y_*` getters, ULT the
//!   `*_u_*` getters, everything else the base getters
//!   (`intel_ddi_buf_trans_init`: `skylake_ulx` →
//!   `skl_y_get_buf_trans`, `skylake_ult` → `skl_u_get_buf_trans`,
//!   `skylake` → `skl_get_buf_trans`; the same shape with
//!   `kbl_*` for Kaby Lake / Coffee Lake / Comet Lake).
//! - Within a getter: HDMI → the HDMI table (H/S table for
//!   base and ULT, Y table for ULX); eDP + low-vswing → the
//!   eDP table; anything else (DP, or eDP without
//!   low-vswing) → the DP table.
//! - The DP table is the only arm that differs between
//!   Skylake and Kaby Lake / Comet Lake (KBL rows diverge at
//!   index 7: SKL 0xDF, KBL 0x97; U: SKL 0x88, KBL 0x4F; Y:
//!   SKL 0x18/0x88, KBL 0x17/0x4C). The eDP and HDMI tables
//!   are shared SKL/KBL.
//! - `edp_low_vswing` is a VBT bit (`connector->panel.vbt.edp
//!   .low_vswing`); NARF parses it (`intel_gpu_vbt`) but does
//!   not plumb it into the modeset yet, so it arrives here as
//!   a caller input, like the Gen11 module's pinned-false
//!   branches.
//!
//! ## `DDI_BUF_TRANS` programming
//!
//! `has_buf_trans_select` is DISPLAY_VER < 10 && !broxton —
//! true on Gen9. On Gen9 `DDI_BUF_TRANS` IS the mechanism,
//! unlike Gen12 where the combo PHY is programmed through
//! PORT_TX_DW2/DW4/DW5/DW7 and the `DDI_BUF_TRANS` registers
//! exist but are ignored.
//!
//! - DP: `hsw_prepare_dp_ddi_buffers` writes LO(trans1 |
//!   iboost_bit) / HI(trans2) for `i` in `0..n_entries`,
//!   where `n_entries` is capped by
//!   `skl_buf_trans_num_entries`: ports A/E may select the
//!   10th register (`min(n, 10)`), other ports `min(n, 9)`.
//!   The DP tables have 9 entries, the eDP tables 10 — the
//!   cap only bites on eDP tables on ports B/C/D.
//! - HDMI: `hsw_prepare_hdmi_ddi_buffers` writes the single
//!   entry at `level` into index 9 only
//!   (`DDI_BUF_TRANS_LO/HI(port, 9)`).
//! - `iboost_bit` is `DDI_BUF_BALANCE_LEG_ENABLE` (bit 31 of
//!   trans1) when the VBT DP/HDMI boost level is set
//!   (`has_iboost` is DISPLAY_VER 9 && !broxton — true here);
//!   it arrives as a caller input (`dp_boost` /
//!   `hdmi_boost`).
//! - `intel_ddi_hdmi_level`: the VBT HDMI level shift when
//!   set (>= 0), else the table's `hdmi_default_entry` (8).
//! - The entry's `i_boost` byte is a separate mechanism:
//!   `skl_ddi_set_iboost` writes it into
//!   `DISPIO_CR_TX_BMU_CR0` (0x6C00C) per port when the VBT
//!   boost level is 0 — see [`set_iboost`]. Port A with 4
//!   lanes mirrors the value to port E.
//!
//! ## Addressing
//!
//! `_DDI_BUF_TRANS_A` 0x64E00, `_DDI_BUF_TRANS_B` 0x64E60;
//! `_PICK_EVEN(index, a, b) = a + index * (b - a)`
//! (`include/drm/intel/pick.h`): LO(port, i) = 0x64E00 +
//! port * 0x60 + i * 8, HI = LO + 4. Ports: A 0x64E00,
//! B 0x64E60, C 0x64EC0, D 0x64F20, E 0x64F80.
//!
//! ## Port map
//!
//! `skl_display` in `display/intel_display_device.c`:
//! port_mask = A|B|C|D|E. Port A is the eDP panel
//! (TRANSCODER_EDP); B/C/D/E are DP/HDMI. See
//! [`port_kind`].
//!
//! ## Not in this module (remainders)
//!
//! - The VBT inputs (`edp_low_vswing`, the HDMI level shift,
//!   the DP/HDMI boost levels) are caller inputs until the
//!   modeset plumbs `intel_gpu_vbt` through.
//! - The DP link-training loop that picks `level` per lane
//!   (`intel_ddi_dp_voltage_max`, the training state
//!   machine) is Lane 5 modeset work; this module programs
//!   the table once the level is chosen.

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_ddi::Ddi;
use crate::intel_gpu_gen11_ddi::Output;
use crate::intel_gpu_gt::Gen9Platform;

/// One HSW `DDI_BUF_TRANS` entry: `{trans1, trans2,
/// i_boost}` (`display/intel_ddi_buf_trans.h`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HswEntry {
    /// Balance leg enable / de-emphasis level.
    pub trans1: u32,
    /// Vref select / vswing.
    pub trans2: u32,
    /// SKL I_boost (valid 0x0, 0x1, 0x3, 0x7).
    pub i_boost: u8,
}

const fn e(trans1: u32, trans2: u32, i_boost: u8) -> HswEntry {
    HswEntry {
        trans1,
        trans2,
        i_boost,
    }
}

// ── Tables (Linux 7.4-rc2 `display/intel_ddi_buf_trans.c`) ───
// Every table is transcribed verbatim (106 entries total);
// the entry comments in the C source (nominal/transition mV,
// dB) are omitted — the values are the ground truth and the
// selection tests pin them.

// Skylake H and S DP.
static SKL_DP: [HswEntry; 9] = [
    e(0x00002016, 0x000000A0, 0x0),
    e(0x00005012, 0x0000009B, 0x0),
    e(0x00007011, 0x00000088, 0x0),
    e(0x80009010, 0x000000C0, 0x1),
    e(0x00002016, 0x0000009B, 0x0),
    e(0x00005012, 0x00000088, 0x0),
    e(0x80007011, 0x000000C0, 0x1),
    e(0x00002016, 0x000000DF, 0x0),
    e(0x80005012, 0x000000C0, 0x1),
];

// Skylake U DP.
static SKL_U_DP: [HswEntry; 9] = [
    e(0x0000201B, 0x000000A2, 0x0),
    e(0x00005012, 0x00000088, 0x0),
    e(0x80007011, 0x000000CD, 0x1),
    e(0x80009010, 0x000000C0, 0x1),
    e(0x0000201B, 0x0000009D, 0x0),
    e(0x80005012, 0x000000C0, 0x1),
    e(0x80007011, 0x000000C0, 0x1),
    e(0x00002016, 0x00000088, 0x0),
    e(0x80005012, 0x000000C0, 0x1),
];

// Skylake Y DP.
static SKL_Y_DP: [HswEntry; 9] = [
    e(0x00000018, 0x000000A2, 0x0),
    e(0x00005012, 0x00000088, 0x0),
    e(0x80007011, 0x000000CD, 0x3),
    e(0x80009010, 0x000000C0, 0x3),
    e(0x00000018, 0x0000009D, 0x0),
    e(0x80005012, 0x000000C0, 0x3),
    e(0x80007011, 0x000000C0, 0x3),
    e(0x00000018, 0x00000088, 0x0),
    e(0x80005012, 0x000000C0, 0x3),
];

// Kabylake H and S DP (row 7 diverges from SKL: 0x97, not 0xDF).
static KBL_DP: [HswEntry; 9] = [
    e(0x00002016, 0x000000A0, 0x0),
    e(0x00005012, 0x0000009B, 0x0),
    e(0x00007011, 0x00000088, 0x0),
    e(0x80009010, 0x000000C0, 0x1),
    e(0x00002016, 0x0000009B, 0x0),
    e(0x00005012, 0x00000088, 0x0),
    e(0x80007011, 0x000000C0, 0x1),
    e(0x00002016, 0x00000097, 0x0),
    e(0x80005012, 0x000000C0, 0x1),
];

// Kabylake U DP (row 7: 0x4F; i_boost 3 on the boosted rows).
static KBL_U_DP: [HswEntry; 9] = [
    e(0x0000201B, 0x000000A1, 0x0),
    e(0x00005012, 0x00000088, 0x0),
    e(0x80007011, 0x000000CD, 0x3),
    e(0x80009010, 0x000000C0, 0x3),
    e(0x0000201B, 0x0000009D, 0x0),
    e(0x80005012, 0x000000C0, 0x3),
    e(0x80007011, 0x000000C0, 0x3),
    e(0x00002016, 0x0000004F, 0x0),
    e(0x80005012, 0x000000C0, 0x3),
];

// Kabylake Y DP (row 3: 0x8000800F, not 0x80009010).
static KBL_Y_DP: [HswEntry; 9] = [
    e(0x00001017, 0x000000A1, 0x0),
    e(0x00005012, 0x00000088, 0x0),
    e(0x80007011, 0x000000CD, 0x3),
    e(0x8000800F, 0x000000C0, 0x3),
    e(0x00001017, 0x0000009D, 0x0),
    e(0x80005012, 0x000000C0, 0x3),
    e(0x80007011, 0x000000C0, 0x3),
    e(0x00001017, 0x0000004C, 0x0),
    e(0x80005012, 0x000000C0, 0x3),
];

// Skylake/Kabylake H and S eDP 1.4 low vswing.
static SKL_EDP: [HswEntry; 10] = [
    e(0x00000018, 0x000000A8, 0x0),
    e(0x00004013, 0x000000A9, 0x0),
    e(0x00007011, 0x000000A2, 0x0),
    e(0x00009010, 0x0000009C, 0x0),
    e(0x00000018, 0x000000A9, 0x0),
    e(0x00006013, 0x000000A2, 0x0),
    e(0x00007011, 0x000000A6, 0x0),
    e(0x00000018, 0x000000AB, 0x0),
    e(0x00007013, 0x0000009F, 0x0),
    e(0x00000018, 0x000000DF, 0x0),
];

// Skylake/Kabylake U eDP 1.4 low vswing (rows 7-8 diverge).
static SKL_U_EDP: [HswEntry; 10] = [
    e(0x00000018, 0x000000A8, 0x0),
    e(0x00004013, 0x000000A9, 0x0),
    e(0x00007011, 0x000000A2, 0x0),
    e(0x00009010, 0x0000009C, 0x0),
    e(0x00000018, 0x000000A9, 0x0),
    e(0x00006013, 0x000000A2, 0x0),
    e(0x00007011, 0x000000A6, 0x0),
    e(0x00002016, 0x000000AB, 0x0),
    e(0x00005013, 0x0000009F, 0x0),
    e(0x00000018, 0x000000DF, 0x0),
];

// Skylake/Kabylake Y eDP 1.4 low vswing.
static SKL_Y_EDP: [HswEntry; 10] = [
    e(0x00000018, 0x000000A8, 0x0),
    e(0x00004013, 0x000000AB, 0x0),
    e(0x00007011, 0x000000A4, 0x0),
    e(0x00009010, 0x000000DF, 0x0),
    e(0x00000018, 0x000000AA, 0x0),
    e(0x00006013, 0x000000A4, 0x0),
    e(0x00007011, 0x0000009D, 0x0),
    e(0x00000018, 0x000000A0, 0x0),
    e(0x00006012, 0x000000DF, 0x0),
    e(0x00000018, 0x0000008A, 0x0),
];

// Skylake/Kabylake H and S HDMI (default entry 8).
static SKL_HDMI: [HswEntry; 11] = [
    e(0x00000018, 0x000000AC, 0x0),
    e(0x00005012, 0x0000009D, 0x0),
    e(0x00007011, 0x00000088, 0x0),
    e(0x00000018, 0x000000A1, 0x0),
    e(0x00000018, 0x00000098, 0x0),
    e(0x00004013, 0x00000088, 0x0),
    e(0x80006012, 0x000000CD, 0x1),
    e(0x00000018, 0x000000DF, 0x0),
    e(0x80003015, 0x000000CD, 0x1),
    e(0x80003015, 0x000000C0, 0x1),
    e(0x80000018, 0x000000C0, 0x1),
];

// Skylake/Kabylake Y HDMI (default entry 8).
static SKL_Y_HDMI: [HswEntry; 11] = [
    e(0x00000018, 0x000000A1, 0x0),
    e(0x00005012, 0x000000DF, 0x0),
    e(0x80007011, 0x000000CB, 0x3),
    e(0x00000018, 0x000000A4, 0x0),
    e(0x00000018, 0x0000009D, 0x0),
    e(0x00004013, 0x00000080, 0x0),
    e(0x80006013, 0x000000C0, 0x3),
    e(0x00000018, 0x0000008A, 0x0),
    e(0x80003015, 0x000000C0, 0x3),
    e(0x80003015, 0x000000C0, 0x3),
    e(0x80000018, 0x000000C0, 0x3),
];

/// `skl_trans_hdmi.hdmi_default_entry` (and
/// `skl_y_trans_hdmi`'s): entry 8.
pub const SKL_HDMI_DEFAULT_ENTRY: usize = 8;

// ── SKU family ───────────────────────────────────────────────

/// The SKU family that picks the U/Y buffer-translation
/// getters (`intel_ddi_buf_trans_init` dispatches on the
/// `*_ult` / `*_ulx` subplatforms).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkuFamily {
    /// Desktop / Halo / Server / Workstation (the base
    /// getters).
    Desktop,
    /// ULT (U-series mobile).
    Ult,
    /// ULX (Y-series / Amber Lake mobile).
    Ulx,
}

/// The SKU family for a PCI device id, from
/// `include/drm/intel/pciids.h` (7.4-rc2) via
/// `intel_display_device.c`'s subplatform lists
/// (`skl_ult_ids`, `skl_ulx_ids`, `kbl_ult_ids`,
/// `kbl_ulx_ids`, `cfl_ult_ids`, `cfl_ulx_ids`,
/// `cml_ult_ids`):
///
/// - SKL ULT (7): 1906, 1913, 1916, 1921, 1923, 1926, 1927.
/// - SKL ULX (3): 190E, 1915, 191E.
/// - KBL ULT (7): 5906, 5913, 5916, 5921, 5923, 5926, 5927
///   (5923 and 5927 come from `KBL_GT3_IDS`, which the
///   header comments "ULT GT3").
/// - KBL ULX (5): 590E, 5915, 591E, plus the Amber Lake
///   `AML_KBL_GT2_IDS` pair 591C, 87C0 — both commented
///   "ULX GT2" and listed in `kbl_ulx_ids`.
/// - CFL/WHL ULT (10): 3EA5, 3EA6, 3EA7, 3EA8, 3EA9 (CFL U),
///   3EA0, 3EA1, 3EA2, 3EA3, 3EA4 (WHL U).
/// - CFL ULX (1): 87CA (`AML_CFL_GT2_IDS`, in
///   `cfl_ulx_ids`).
/// - CML ULT (6): 9B21, 9BAA, 9BAC, 9B41, 9BCA, 9BCC. There
///   is no CML ULX list.
/// - Every other Gen9 DID (the 86 in Lane 1's probe table)
///   is Desktop.
pub const fn sku_family_for_did(did: u16) -> SkuFamily {
    match did {
        0x1906 | 0x1913 | 0x1916 | 0x1921 | 0x1923 | 0x1926 | 0x1927 | 0x5906 | 0x5913 | 0x5916
        | 0x5921 | 0x5923 | 0x5926 | 0x5927 | 0x3EA5 | 0x3EA6 | 0x3EA7 | 0x3EA8 | 0x3EA9
        | 0x3EA0 | 0x3EA1 | 0x3EA2 | 0x3EA3 | 0x3EA4 | 0x9B21 | 0x9BAA | 0x9BAC | 0x9B41
        | 0x9BCA | 0x9BCC => SkuFamily::Ult,
        0x190E | 0x1915 | 0x191E | 0x590E | 0x5915 | 0x591E | 0x591C | 0x87C0 | 0x87CA => {
            SkuFamily::Ulx
        }
        _ => SkuFamily::Desktop,
    }
}

// ── Selection ────────────────────────────────────────────────

/// Select the buffer-translation table for a Gen9 output,
/// mirroring `skl_get_buf_trans` / `skl_u_get_buf_trans` /
/// `skl_y_get_buf_trans` and their `kbl_*` twins.
/// `edp_low_vswing` is the VBT eDP low-vswing bit (only
/// consulted for eDP).
pub fn select_table(
    platform: Gen9Platform,
    family: SkuFamily,
    output: Output,
    edp_low_vswing: bool,
) -> &'static [HswEntry] {
    let is_kbl = !matches!(platform, Gen9Platform::Skylake);
    match output {
        Output::Hdmi => {
            if matches!(family, SkuFamily::Ulx) {
                &SKL_Y_HDMI
            } else {
                &SKL_HDMI
            }
        }
        Output::Edp if edp_low_vswing => match family {
            SkuFamily::Ulx => &SKL_Y_EDP,
            SkuFamily::Ult => &SKL_U_EDP,
            SkuFamily::Desktop => &SKL_EDP,
        },
        _ => match (family, is_kbl) {
            (SkuFamily::Ulx, false) => &SKL_Y_DP,
            (SkuFamily::Ulx, true) => &KBL_Y_DP,
            (SkuFamily::Ult, false) => &SKL_U_DP,
            (SkuFamily::Ult, true) => &KBL_U_DP,
            (SkuFamily::Desktop, false) => &SKL_DP,
            (SkuFamily::Desktop, true) => &KBL_DP,
        },
    }
}

/// `skl_buf_trans_num_entries`: only ports A and E can
/// select the 10th register with DP; other ports cap at 9.
/// The HDMI tables are not capped (their getter returns the
/// full table).
pub const fn dp_entry_count(port: Ddi, n_entries: usize) -> usize {
    // `usize::min` is not const on this toolchain, so the caps
    // are plain branches.
    match port {
        Ddi::A | Ddi::E => {
            if n_entries < 10 {
                n_entries
            } else {
                10
            }
        }
        _ => {
            if n_entries < 9 {
                n_entries
            } else {
                9
            }
        }
    }
}

// ── `DDI_BUF_TRANS` programming ──────────────────────────────

/// `_DDI_BUF_TRANS_A` 0x64E00.
pub const DDI_BUF_TRANS_A: u64 = 0x64E00;

/// `DDI_BUF_TRANS_LO(port, i)`: 0x64E00 + port * 0x60 + i * 8.
pub const fn ddi_buf_trans_lo(port: Ddi, index: usize) -> u64 {
    DDI_BUF_TRANS_A + (port as u64) * 0x60 + (index as u64) * 8
}

/// `DDI_BUF_TRANS_HI(port, i)` = LO + 4.
pub const fn ddi_buf_trans_hi(port: Ddi, index: usize) -> u64 {
    ddi_buf_trans_lo(port, index) + 4
}

/// `DDI_BUF_BALANCE_LEG_ENABLE` — bit 31 of trans1, set when
/// the VBT DP/HDMI boost level is set.
pub const DDI_BUF_BALANCE_LEG_ENABLE: u32 = 1 << 31;

/// `hsw_prepare_dp_ddi_buffers`: write LO(trans1 |
/// iboost_bit) / HI(trans2) for `i` in `0..n_entries`.
/// `n_entries` must already be capped by
/// [`dp_entry_count`]; `dp_boost` is the VBT DP boost level
/// being set.
pub fn program_dp_buffers(
    io: &(impl MmioWindow + ?Sized),
    port: Ddi,
    table: &[HswEntry],
    n_entries: usize,
    dp_boost: bool,
) {
    let iboost_bit = if dp_boost {
        DDI_BUF_BALANCE_LEG_ENABLE
    } else {
        0
    };
    for (i, entry) in table.iter().take(n_entries).enumerate() {
        io.write32(ddi_buf_trans_lo(port, i), entry.trans1 | iboost_bit);
        io.write32(ddi_buf_trans_hi(port, i), entry.trans2);
    }
}

/// `intel_ddi_hdmi_level`: the VBT HDMI level shift when set,
/// else the table's `hdmi_default_entry` (8).
pub fn hdmi_level(vbt_shift: Option<u8>) -> usize {
    vbt_shift.map_or(SKL_HDMI_DEFAULT_ENTRY, usize::from)
}

/// `hsw_prepare_hdmi_ddi_buffers`: write the single entry at
/// `level` into index 9 only. Returns `false` (writing
/// nothing) when `level` is outside the table — Linux trusts
/// the VBT shift, but a bad shift must not program a wrong
/// entry.
pub fn program_hdmi_buffer(
    io: &(impl MmioWindow + ?Sized),
    port: Ddi,
    table: &[HswEntry],
    level: usize,
    hdmi_boost: bool,
) -> bool {
    let Some(entry) = table.get(level) else {
        return false;
    };
    let iboost_bit = if hdmi_boost {
        DDI_BUF_BALANCE_LEG_ENABLE
    } else {
        0
    };
    io.write32(ddi_buf_trans_lo(port, 9), entry.trans1 | iboost_bit);
    io.write32(ddi_buf_trans_hi(port, 9), entry.trans2);
    true
}

// ── I_boost (`DISPIO_CR_TX_BMU_CR0`) ─────────────────────────

/// `DISPIO_CR_TX_BMU_CR0` 0x6C00C.
pub const DISPIO_CR_TX_BMU_CR0: u64 = 0x6C00C;

/// `BALANCE_LEG_SHIFT(port)` = 8 + 3 * port.
pub const fn balance_leg_shift(port: Ddi) -> u32 {
    8 + 3 * (port as u32)
}

/// `BALANCE_LEG_MASK(port)` = 7 << (8 + 3 * port).
pub const fn balance_leg_mask(port: Ddi) -> u32 {
    0x7 << balance_leg_shift(port)
}

/// `BALANCE_LEG_DISABLE(port)` = 1 << (23 + port).
pub const fn balance_leg_disable(port: Ddi) -> u32 {
    1 << (23 + (port as u32))
}

/// `skl_ddi_set_iboost`'s resolution: the VBT boost level
/// when set, else the selected table entry's `i_boost`.
pub const fn resolve_iboost(vbt_boost: u8, entry: &HswEntry) -> u8 {
    if vbt_boost != 0 {
        vbt_boost
    } else {
        entry.i_boost
    }
}

/// `_skl_ddi_set_iboost` for one port: RMW
/// `DISPIO_CR_TX_BMU_CR0` — clear the port's balance-leg
/// mask and disable bit, then set `iboost << shift` (or the
/// disable bit when `iboost` is 0). Returns `false` (writing
/// nothing) for an invalid I_boost value — Linux only
/// accepts 0x0, 0x1, 0x3, 0x7.
pub fn set_iboost(io: &(impl MmioWindow + ?Sized), port: Ddi, iboost: u8) -> bool {
    if !matches!(iboost, 0x0 | 0x1 | 0x3 | 0x7) {
        return false;
    }
    let cur = io.read32(DISPIO_CR_TX_BMU_CR0);
    let cleared = cur & !(balance_leg_mask(port) | balance_leg_disable(port));
    let next = if iboost != 0 {
        cleared | (u32::from(iboost) << balance_leg_shift(port))
    } else {
        cleared | balance_leg_disable(port)
    };
    io.write32(DISPIO_CR_TX_BMU_CR0, next);
    true
}

/// `skl_ddi_set_iboost` for one port at a table level:
/// resolve the boost (VBT, else the entry's `i_boost`) and
/// program it; port A with 4 lanes mirrors the value to
/// port E (`also_port_e`).
pub fn set_iboost_for_level(
    io: &(impl MmioWindow + ?Sized),
    port: Ddi,
    table: &[HswEntry],
    level: usize,
    vbt_boost: u8,
    also_port_e: bool,
) -> bool {
    let Some(entry) = table.get(level) else {
        return false;
    };
    let iboost = resolve_iboost(vbt_boost, entry);
    if !set_iboost(io, port, iboost) {
        return false;
    }
    if also_port_e && matches!(port, Ddi::A) {
        return set_iboost(io, Ddi::E, iboost);
    }
    true
}

// ── Wa #1143 (HDMI-only) ────────────────────────────────────────

/// `CHICKEN_TRANS` register for a transcoder (`i915_reg.h`):
/// A 0x420C0, B 0x420C4, C 0x420C8, EDP 0x420CC, D 0x420D8.
/// Port→transcoder: A→EDP, B→A, C→B, D→C, E→A.
pub const fn chicken_trans_for_port(port: Ddi) -> Option<u64> {
    match port {
        Ddi::A => Some(0x420CC),
        Ddi::B | Ddi::E => Some(0x420C0),
        Ddi::C => Some(0x420C4),
        Ddi::D => Some(0x420C8),
        _ => None,
    }
}

/// `DDI_TRAINING_OVERRIDE_ENABLE` — bit 19 of the
/// per-transcoder chicken register (bit 17 for port E, which
/// shares `CHICKEN_TRANS_A` with port B).
pub const DDI_TRAINING_OVERRIDE_ENABLE: u32 = 1 << 19;
/// `DDI_TRAINING_OVERRIDE_VALUE` — bit 18 (bit 16 for port E).
pub const DDI_TRAINING_OVERRIDE_VALUE: u32 = 1 << 18;

/// Microsecond spin (TSC-calibrated when the clocks are
/// calibrated, spin-loop fallback otherwise) — the same shape
/// as `amdgpu::delay_us`.
fn delay_us(us: u32) {
    let hz = narf_time::calibrate_clocks();
    if hz > 0 {
        narf_time::busy_wait_cycles((hz / 1_000_000).max(1) * u64::from(us));
    } else {
        for _ in 0..(u64::from(us) * 1000) {
            core::hint::spin_loop();
        }
    }
}

/// Wa #1143 (`display/intel_ddi.c:3455`, HDMI only): pulse
/// `DDI_TRAINING_OVERRIDE_ENABLE | DDI_TRAINING_OVERRIDE_VALUE`
/// in the port's transcoder chicken register — set, posting
/// read, 1 µs delay, clear — before the DDI buffer enables.
/// Returns `false` (writing nothing) for a port Gen9 does
/// not have.
pub fn wa1143_training_override_pulse(io: &(impl MmioWindow + ?Sized), port: Ddi) -> bool {
    let Some(reg) = chicken_trans_for_port(port) else {
        return false;
    };
    let (enable, value) = if matches!(port, Ddi::E) {
        (1 << 17, 1 << 16)
    } else {
        (DDI_TRAINING_OVERRIDE_ENABLE, DDI_TRAINING_OVERRIDE_VALUE)
    };
    let cur = io.read32(reg);
    io.write32(reg, cur | enable | value);
    let _ = io.read32(reg);
    delay_us(1);
    io.write32(reg, cur & !(enable | value));
    true
}

// ── Port map ─────────────────────────────────────────────────

/// What a Gen9 DDI port is wired to (`skl_display`:
/// port_mask A|B|C|D|E; PORT_A is the eDP panel).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortKind {
    /// The internal eDP panel (port A).
    Edp,
    /// An external DP/HDMI port (ports B–E).
    DpHdmi,
}

/// The kind for a Gen9 DDI port. `None` for ports Gen9 does
/// not have (DDI F and above).
pub const fn port_kind(port: Ddi) -> Option<PortKind> {
    match port {
        Ddi::A => Some(PortKind::Edp),
        Ddi::B | Ddi::C | Ddi::D | Ddi::E => Some(PortKind::DpHdmi),
        _ => None,
    }
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Write-logging MMIO endpoint for the DDI tests.
    struct DdiMmio {
        regs: RefCell<Vec<(u64, u32)>>,
    }

    impl DdiMmio {
        fn new() -> Self {
            Self {
                regs: RefCell::new(Vec::new()),
            }
        }

        fn read(&self, off: u64) -> u32 {
            self.regs
                .borrow()
                .iter()
                .rev()
                .find(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .unwrap_or(0)
        }

        fn writes_to(&self, off: u64) -> Vec<u32> {
            self.regs
                .borrow()
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }
    }

    impl MmioWindow for DdiMmio {
        fn read32(&self, off: u64) -> u32 {
            self.read(off)
        }

        fn write32(&self, off: u64, val: u32) {
            self.regs.borrow_mut().push((off, val));
        }
    }

    fn same_table(a: &[HswEntry], b: &[HswEntry]) -> bool {
        core::ptr::eq(a.as_ptr(), b.as_ptr()) && a.len() == b.len()
    }

    fn smoke_skl_ddi_table_spot_values() -> TestResult {
        // The row-7 divergences between the SKL and KBL DP
        // tables pin the transcription family by family.
        if SKL_DP[7] != e(0x00002016, 0x000000DF, 0x0)
            || KBL_DP[7] != e(0x00002016, 0x00000097, 0x0)
            || SKL_U_DP[7] != e(0x00002016, 0x00000088, 0x0)
            || KBL_U_DP[7] != e(0x00002016, 0x0000004F, 0x0)
            || SKL_Y_DP[7] != e(0x00000018, 0x00000088, 0x0)
            || KBL_Y_DP[7] != e(0x00001017, 0x0000004C, 0x0)
        {
            return TestResult::Fail("DP row-7 divergence wrong");
        }
        // KBL Y row 3 is 0x8000800F, not SKL's 0x80009010.
        if KBL_Y_DP[3] != e(0x8000800F, 0x000000C0, 0x3)
            || SKL_Y_DP[3] != e(0x80009010, 0x000000C0, 0x3)
        {
            return TestResult::Fail("KBL Y DP row 3 wrong");
        }
        // i_boost classes: 1 on the SKL boosted rows, 3 on
        // the Y/KBL-U boosted rows, 0 elsewhere.
        if SKL_DP[3].i_boost != 1
            || SKL_U_DP[2].i_boost != 1
            || SKL_Y_DP[2].i_boost != 3
            || KBL_U_DP[2].i_boost != 3
            || SKL_DP[0].i_boost != 0
        {
            return TestResult::Fail("i_boost classes wrong");
        }
        // eDP low-vswing rows that diverge between families.
        if SKL_EDP[7] != e(0x00000018, 0x000000AB, 0x0)
            || SKL_U_EDP[7] != e(0x00002016, 0x000000AB, 0x0)
            || SKL_U_EDP[8] != e(0x00005013, 0x0000009F, 0x0)
            || SKL_Y_EDP[3] != e(0x00009010, 0x000000DF, 0x0)
        {
            return TestResult::Fail("eDP row divergences wrong");
        }
        // HDMI default entries (index 8) and table lengths.
        if SKL_HDMI[SKL_HDMI_DEFAULT_ENTRY] != e(0x80003015, 0x000000CD, 0x1)
            || SKL_Y_HDMI[SKL_HDMI_DEFAULT_ENTRY] != e(0x80003015, 0x000000C0, 0x3)
        {
            return TestResult::Fail("HDMI default entries wrong");
        }
        if SKL_DP.len() != 9
            || SKL_EDP.len() != 10
            || SKL_HDMI.len() != 11
            || SKL_HDMI_DEFAULT_ENTRY != 8
        {
            return TestResult::Fail("table lengths or HDMI default index wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_ddi",
        smoke_skl_ddi_table_spot_values
    );

    fn smoke_skl_ddi_sku_family() -> TestResult {
        // ULT DIDs across the four platform families.
        for did in [
            0x1906, 0x1913, 0x1916, 0x1921, 0x1923, 0x1926, 0x1927, 0x5906, 0x5913, 0x5916, 0x5921,
            0x5923, 0x5926, 0x5927, 0x3EA5, 0x3EA6, 0x3EA7, 0x3EA8, 0x3EA9, 0x3EA0, 0x3EA1, 0x3EA2,
            0x3EA3, 0x3EA4, 0x9B21, 0x9BAA, 0x9BAC, 0x9B41, 0x9BCA, 0x9BCC,
        ] {
            if sku_family_for_did(did) != SkuFamily::Ult {
                return TestResult::Fail("ULT DID must map to Ult");
            }
        }
        // ULX DIDs — including the Amber Lake pair the KBL
        // ULX list carries (591C, 87C0) and CFL's 87CA.
        for did in [
            0x190E, 0x1915, 0x191E, 0x590E, 0x5915, 0x591E, 0x591C, 0x87C0, 0x87CA,
        ] {
            if sku_family_for_did(did) != SkuFamily::Ulx {
                return TestResult::Fail("ULX DID must map to Ulx");
            }
        }
        // Desktop DIDs (H/S/SRV/Halo/WKS/GT3/GT4).
        for did in [
            0x1912, 0x191A, 0x192A, 0x1932, 0x5912, 0x5917, 0x593B, 0x3E91, 0x3E9B, 0x9BC5,
        ] {
            if sku_family_for_did(did) != SkuFamily::Desktop {
                return TestResult::Fail("desktop DID must map to Desktop");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen9_ddi", smoke_skl_ddi_sku_family);

    fn smoke_skl_ddi_table_selection() -> TestResult {
        // HDMI: base and ULT share the H/S table, ULX takes Y.
        if !same_table(
            select_table(
                Gen9Platform::Skylake,
                SkuFamily::Desktop,
                Output::Hdmi,
                false,
            ),
            &SKL_HDMI,
        ) || !same_table(
            select_table(Gen9Platform::KabyLake, SkuFamily::Ult, Output::Hdmi, false),
            &SKL_HDMI,
        ) || !same_table(
            select_table(Gen9Platform::Skylake, SkuFamily::Ulx, Output::Hdmi, false),
            &SKL_Y_HDMI,
        ) {
            return TestResult::Fail("HDMI table selection wrong");
        }
        // eDP + low-vswing takes the eDP table per family.
        if !same_table(
            select_table(Gen9Platform::Skylake, SkuFamily::Desktop, Output::Edp, true),
            &SKL_EDP,
        ) || !same_table(
            select_table(Gen9Platform::KabyLake, SkuFamily::Ult, Output::Edp, true),
            &SKL_U_EDP,
        ) || !same_table(
            select_table(Gen9Platform::CometLake, SkuFamily::Ulx, Output::Edp, true),
            &SKL_Y_EDP,
        ) {
            return TestResult::Fail("eDP low-vswing table selection wrong");
        }
        // DP: the only arm that differs SKL vs KBL.
        if !same_table(
            select_table(Gen9Platform::Skylake, SkuFamily::Desktop, Output::Dp, false),
            &SKL_DP,
        ) || !same_table(
            select_table(
                Gen9Platform::KabyLake,
                SkuFamily::Desktop,
                Output::Dp,
                false,
            ),
            &KBL_DP,
        ) || !same_table(
            select_table(Gen9Platform::Skylake, SkuFamily::Ult, Output::Dp, false),
            &SKL_U_DP,
        ) || !same_table(
            select_table(Gen9Platform::KabyLake, SkuFamily::Ult, Output::Dp, false),
            &KBL_U_DP,
        ) || !same_table(
            select_table(Gen9Platform::Skylake, SkuFamily::Ulx, Output::Dp, false),
            &SKL_Y_DP,
        ) || !same_table(
            select_table(Gen9Platform::CometLake, SkuFamily::Ulx, Output::Dp, false),
            &KBL_Y_DP,
        ) {
            return TestResult::Fail("DP table selection wrong");
        }
        // eDP without low-vswing falls through to the DP table.
        if !same_table(
            select_table(Gen9Platform::KabyLake, SkuFamily::Ult, Output::Edp, false),
            &KBL_U_DP,
        ) {
            return TestResult::Fail("eDP without low-vswing must take the DP table");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_ddi",
        smoke_skl_ddi_table_selection
    );

    fn smoke_skl_ddi_addressing_and_counts() -> TestResult {
        if ddi_buf_trans_lo(Ddi::A, 0) != 0x64E00
            || ddi_buf_trans_hi(Ddi::A, 0) != 0x64E04
            || ddi_buf_trans_lo(Ddi::B, 0) != 0x64E60
            || ddi_buf_trans_lo(Ddi::C, 0) != 0x64EC0
            || ddi_buf_trans_lo(Ddi::D, 0) != 0x64F20
            || ddi_buf_trans_lo(Ddi::E, 0) != 0x64F80
            || ddi_buf_trans_lo(Ddi::A, 9) != 0x64E48
        {
            return TestResult::Fail("DDI_BUF_TRANS addressing wrong");
        }
        // Only ports A/E select the 10th register.
        if dp_entry_count(Ddi::A, 10) != 10
            || dp_entry_count(Ddi::E, 10) != 10
            || dp_entry_count(Ddi::B, 10) != 9
            || dp_entry_count(Ddi::C, 10) != 9
            || dp_entry_count(Ddi::D, 10) != 9
            || dp_entry_count(Ddi::B, 9) != 9
        {
            return TestResult::Fail("DP entry-count cap wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gen9_ddi",
        smoke_skl_ddi_addressing_and_counts
    );

    fn smoke_skl_ddi_program_dp() -> TestResult {
        let mmio = DdiMmio::new();
        program_dp_buffers(&mmio, Ddi::B, &SKL_DP, 9, false);
        // Every entry writes LO then HI, in order.
        for (i, entry) in SKL_DP.iter().enumerate() {
            if mmio.read(ddi_buf_trans_lo(Ddi::B, i)) != entry.trans1
                || mmio.read(ddi_buf_trans_hi(Ddi::B, i)) != entry.trans2
            {
                return TestResult::Fail(
                    "DP buffer programming must write trans1/trans2 per entry",
                );
            }
        }
        // The boost bit lands on trans1 only (bit 31).
        let mmio = DdiMmio::new();
        program_dp_buffers(&mmio, Ddi::B, &SKL_DP, 9, true);
        if mmio.read(ddi_buf_trans_lo(Ddi::B, 0)) != SKL_DP[0].trans1 | DDI_BUF_BALANCE_LEG_ENABLE
            || mmio.read(ddi_buf_trans_hi(Ddi::B, 0)) != SKL_DP[0].trans2
        {
            return TestResult::Fail("DP boost must set bit 31 of trans1 only");
        }
        // The port-B cap drops the 10th eDP entry.
        let mmio = DdiMmio::new();
        let n = dp_entry_count(Ddi::B, SKL_EDP.len());
        program_dp_buffers(&mmio, Ddi::B, &SKL_EDP, n, false);
        if n != 9 || !mmio.writes_to(ddi_buf_trans_lo(Ddi::B, 9)).is_empty() {
            return TestResult::Fail("port B must not program the 10th eDP entry");
        }
        // Port A programs all 10.
        let mmio = DdiMmio::new();
        let n = dp_entry_count(Ddi::A, SKL_EDP.len());
        program_dp_buffers(&mmio, Ddi::A, &SKL_EDP, n, false);
        if n != 10 || mmio.read(ddi_buf_trans_lo(Ddi::A, 9)) != SKL_EDP[9].trans1 {
            return TestResult::Fail("port A must program the 10th eDP entry");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen9_ddi", smoke_skl_ddi_program_dp);

    fn smoke_skl_ddi_program_hdmi() -> TestResult {
        // The default level (8) writes only index 9.
        let mmio = DdiMmio::new();
        if !program_hdmi_buffer(&mmio, Ddi::B, &SKL_HDMI, hdmi_level(None), false) {
            return TestResult::Fail("HDMI programming must succeed at the default level");
        }
        if mmio.read(ddi_buf_trans_lo(Ddi::B, 9)) != SKL_HDMI[8].trans1
            || mmio.read(ddi_buf_trans_hi(Ddi::B, 9)) != SKL_HDMI[8].trans2
        {
            return TestResult::Fail("HDMI programming must write entry 8 at index 9");
        }
        if mmio.regs.borrow().len() != 2 {
            return TestResult::Fail("HDMI programming must write exactly one LO/HI pair");
        }
        // The VBT shift overrides the default.
        if hdmi_level(Some(5)) != 5 || hdmi_level(None) != SKL_HDMI_DEFAULT_ENTRY {
            return TestResult::Fail("HDMI level selection wrong");
        }
        let mmio = DdiMmio::new();
        if !program_hdmi_buffer(&mmio, Ddi::B, &SKL_HDMI, 5, true) {
            return TestResult::Fail("HDMI programming must succeed at a VBT level");
        }
        if mmio.read(ddi_buf_trans_lo(Ddi::B, 9)) != SKL_HDMI[5].trans1 | DDI_BUF_BALANCE_LEG_ENABLE
        {
            return TestResult::Fail("HDMI boost must set bit 31 of trans1");
        }
        // An out-of-range level writes nothing.
        let mmio = DdiMmio::new();
        if program_hdmi_buffer(&mmio, Ddi::B, &SKL_HDMI, 11, false) {
            return TestResult::Fail("an out-of-range HDMI level must refuse");
        }
        if !mmio.regs.borrow().is_empty() {
            return TestResult::Fail("a refused HDMI level must write nothing");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen9_ddi", smoke_skl_ddi_program_hdmi);

    fn smoke_skl_ddi_iboost() -> TestResult {
        // Balance-leg field positions for port B.
        if balance_leg_shift(Ddi::B) != 11
            || balance_leg_mask(Ddi::B) != 0x7 << 11
            || balance_leg_disable(Ddi::B) != 1 << 24
        {
            return TestResult::Fail("balance-leg field positions wrong");
        }
        // i_boost 3 on a clean register: 3 << 11.
        let mmio = DdiMmio::new();
        if !set_iboost(&mmio, Ddi::B, 3) {
            return TestResult::Fail("valid I_boost must program");
        }
        if mmio.read(DISPIO_CR_TX_BMU_CR0) != 3 << 11 {
            return TestResult::Fail("I_boost 3 must land at the port-B shift");
        }
        // i_boost 0 sets the disable bit and clears the mask.
        let mmio = DdiMmio::new();
        mmio.write32(DISPIO_CR_TX_BMU_CR0, 0xFFFF_FFFF);
        if !set_iboost(&mmio, Ddi::B, 0) {
            return TestResult::Fail("I_boost 0 must program");
        }
        let want = !(0x7 << 11 | 1 << 24) | (1 << 24);
        if mmio.read(DISPIO_CR_TX_BMU_CR0) != want {
            return TestResult::Fail("I_boost 0 must set only the disable bit");
        }
        // An invalid value (2) refuses and writes nothing.
        let mmio = DdiMmio::new();
        if set_iboost(&mmio, Ddi::B, 2) {
            return TestResult::Fail("an invalid I_boost must refuse");
        }
        if !mmio.regs.borrow().is_empty() {
            return TestResult::Fail("a refused I_boost must write nothing");
        }
        // Resolution: VBT wins when set, else the entry.
        if resolve_iboost(3, &SKL_DP[0]) != 3
            || resolve_iboost(0, &SKL_Y_DP[2]) != 3
            || resolve_iboost(0, &SKL_DP[0]) != 0
        {
            return TestResult::Fail("I_boost resolution wrong");
        }
        // Port A with 4 lanes mirrors to port E.
        let mmio = DdiMmio::new();
        if !set_iboost_for_level(&mmio, Ddi::A, &SKL_Y_DP, 2, 0, true) {
            return TestResult::Fail("port-A I_boost must program");
        }
        if mmio.read(DISPIO_CR_TX_BMU_CR0) != (3 << 8) | (3 << (8 + 3 * 4)) {
            return TestResult::Fail("port A must mirror I_boost to port E");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen9_ddi", smoke_skl_ddi_iboost);

    fn smoke_skl_ddi_port_map() -> TestResult {
        if port_kind(Ddi::A) != Some(PortKind::Edp)
            || port_kind(Ddi::B) != Some(PortKind::DpHdmi)
            || port_kind(Ddi::C) != Some(PortKind::DpHdmi)
            || port_kind(Ddi::D) != Some(PortKind::DpHdmi)
            || port_kind(Ddi::E) != Some(PortKind::DpHdmi)
            || port_kind(Ddi::F).is_some()
        {
            return TestResult::Fail("Gen9 port map wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen9_ddi", smoke_skl_ddi_port_map);

    fn smoke_skl_ddi_wa1143_pulse() -> TestResult {
        // Port→transcoder chicken registers (`i915_reg.h`).
        if chicken_trans_for_port(Ddi::A) != Some(0x420CC)
            || chicken_trans_for_port(Ddi::B) != Some(0x420C0)
            || chicken_trans_for_port(Ddi::C) != Some(0x420C4)
            || chicken_trans_for_port(Ddi::D) != Some(0x420C8)
            || chicken_trans_for_port(Ddi::E) != Some(0x420C0)
            || chicken_trans_for_port(Ddi::F).is_some()
        {
            return TestResult::Fail("Wa #1143 chicken registers wrong");
        }
        // Port B pulse: set bits 19|18, then clear — the
        // register ends as it started.
        let mmio = DdiMmio::new();
        if !wa1143_training_override_pulse(&mmio, Ddi::B) {
            return TestResult::Fail("Wa #1143 pulse must program port B");
        }
        if mmio.writes_to(0x420C0) != alloc::vec![0xC0000, 0x0] {
            return TestResult::Fail("Wa #1143 pulse must set then clear");
        }
        // Port E shares CHICKEN_TRANS_A with different bits.
        let mmio = DdiMmio::new();
        if !wa1143_training_override_pulse(&mmio, Ddi::E) {
            return TestResult::Fail("Wa #1143 pulse must program port E");
        }
        if mmio.writes_to(0x420C0) != alloc::vec![0x30000, 0x0] {
            return TestResult::Fail("Wa #1143 port-E pulse must use bits 17/16");
        }
        // A port Gen9 does not have programs nothing.
        let mmio = DdiMmio::new();
        if wa1143_training_override_pulse(&mmio, Ddi::F) {
            return TestResult::Fail("Wa #1143 pulse must refuse DDI F");
        }
        if !mmio.regs.borrow().is_empty() {
            return TestResult::Fail("refused Wa #1143 pulse must write nothing");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gen9_ddi", smoke_skl_ddi_wa1143_pulse);
}

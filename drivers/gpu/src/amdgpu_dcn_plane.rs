//! Navi22 DCN3.0 and Phoenix DCN3.1.4 plane path: the display pipe processor, the multiple-pipe/plane
//! combiner and the output pixel processor. Offsets and fields are
//! `dcn_3_1_4_offset.h`/`dcn_3_1_4_sh_mask.h`; the DPP and OPP banks are DCN base
//! index 2 while the MPC bank is index 3. Sequencing follows Linux
//! `dcn10_dpp_dscl.c`, `dcn30_mpc.c::mpc1_mux_plane` and
//! `dcn20_opp.c::opp2_set_disp_pattern_generator`.
//!
//! Scope is one plane with every colour-management stage bypassed and no
//! blending — except the MPC tree, where [`Mpc::insert_plane`] links a
//! second (overlay) plane above the primary and [`Mpc::set_blend`] programs
//! its `mpc2_update_blending` fields. On DCN3.0 the DSCL scales and positions it as
//! `dpp1_dscl_set_scaler_manual_scale` does (`Dpp::set_scaler`, the
//! `dcn_3_0_0_offset.h` DSCL block); the modeset itself programs the
//! scaler in bypass. A stream is blanked here, by the OPP's pattern
//! generator, rather than at the timing generator.
use crate::amdgpu_dcn30_scl::{u0d19, u3d19, ScalerData};
use crate::amdgpu_dcn_color::Fixed31_32;
use crate::{
    amdgpu::AmdGpu, amdgpu_dcn_clk::Error, amdgpu_dcn_profile::Profile, amdgpu_dml::Format,
};
use narf_bus::BusDeviceCap;
use narf_capabilities::{Cap, CapError, CapOp, Write};

// DPP block (base index 2), stride 0x16b.
// Profile selects DCN30 or DCN314; shared ids below were compared against
// both Linux offset and mask headers. Generation differences stay explicit.
// linux-ctx: hdr=dcn seg=2
const DPP_CONTROL: u64 = 0x0cc5; // linux: mmDPP_TOP0_DPP_CONTROL
const CNVC_SURFACE_PIXEL_FORMAT: u64 = 0x0ccf; // linux: mmCNVC_CFG0_CNVC_SURFACE_PIXEL_FORMAT
const FORMAT_CONTROL: u64 = 0x0cd0; // linux: mmCNVC_CFG0_FORMAT_CONTROL
const PRE_DEALPHA: u64 = 0x0cde; // linux: mmCNVC_CFG0_PRE_DEALPHA
const PRE_DEGAM: u64 = 0x0ced; // linux: mmCNVC_CFG0_PRE_DEGAM
const PRE_REALPHA: u64 = 0x0cee; // linux: mmCNVC_CFG0_PRE_REALPHA
const CM_CONTROL: u64 = 0x0d20; // linux: mmCM0_CM_CONTROL
const SCL_MODE: u64 = 0x0cfb; // linux: mmDSCL0_SCL_MODE
const DSCL_CONTROL: u64 = 0x0cfd; // linux: mmDSCL0_DSCL_CONTROL
const DSCL_AUTOCAL: u64 = 0x0d0c; // linux: mmDSCL0_DSCL_AUTOCAL
const RECOUT_START: u64 = 0x0d11; // linux: mmDSCL0_RECOUT_START
const RECOUT_SIZE: u64 = 0x0d12; // linux: mmDSCL0_RECOUT_SIZE
const MPC_SIZE: u64 = 0x0d13; // linux: mmDSCL0_MPC_SIZE
const LB_DATA_FORMAT: u64 = 0x0d14; // linux: mmDSCL0_LB_DATA_FORMAT
const LB_MEMORY_CTRL: u64 = 0x0d15; // linux: mmDSCL0_LB_MEMORY_CTRL
                                    // The DSCL scaler registers, DCN3.0 only (`dcn_3_0_0_offset.h`).
const SCL_COEF_RAM_TAP_SELECT: u64 = 0x0cf9; // linux: mmDSCL0_SCL_COEF_RAM_TAP_SELECT
const SCL_COEF_RAM_TAP_DATA: u64 = 0x0cfa; // linux: mmDSCL0_SCL_COEF_RAM_TAP_DATA
const SCL_TAP_CONTROL: u64 = 0x0cfc; // linux: mmDSCL0_SCL_TAP_CONTROL
const DSCL_2TAP_CONTROL: u64 = 0x0cfe; // linux: mmDSCL0_DSCL_2TAP_CONTROL
                                       // linux: mmDSCL0_SCL_HORZ_FILTER_SCALE_RATIO
const SCL_HORZ_FILTER_SCALE_RATIO: u64 = 0x0d00;
const SCL_HORZ_FILTER_INIT: u64 = 0x0d01; // linux: mmDSCL0_SCL_HORZ_FILTER_INIT
                                          // linux: mmDSCL0_SCL_HORZ_FILTER_SCALE_RATIO_C
const SCL_HORZ_FILTER_SCALE_RATIO_C: u64 = 0x0d02;
const SCL_HORZ_FILTER_INIT_C: u64 = 0x0d03; // linux: mmDSCL0_SCL_HORZ_FILTER_INIT_C
                                            // linux: mmDSCL0_SCL_VERT_FILTER_SCALE_RATIO
const SCL_VERT_FILTER_SCALE_RATIO: u64 = 0x0d04;
const SCL_VERT_FILTER_INIT: u64 = 0x0d05; // linux: mmDSCL0_SCL_VERT_FILTER_INIT
                                          // linux: mmDSCL0_SCL_VERT_FILTER_SCALE_RATIO_C
const SCL_VERT_FILTER_SCALE_RATIO_C: u64 = 0x0d07;
const SCL_VERT_FILTER_INIT_C: u64 = 0x0d08; // linux: mmDSCL0_SCL_VERT_FILTER_INIT_C
const DPP_STRIDE: u64 = 0x16b; // linux: mmDPP_TOP1_DPP_CONTROL - mmDPP_TOP0_DPP_CONTROL
                               // OPP block (base index 2): FMT stride 0x5a, shared by DPG and OPP_PIPE.
const FMT_CONTROL: u64 = 0x1840; // linux: mmFMT0_FMT_CONTROL
const FMT_BIT_DEPTH_CONTROL: u64 = 0x1841; // linux: mmFMT0_FMT_BIT_DEPTH_CONTROL
const DPG_CONTROL: u64 = 0x1854; // linux: mmDPG0_DPG_CONTROL
const DPG_DIMENSIONS: u64 = 0x1856; // linux: mmDPG0_DPG_DIMENSIONS
const DPG_COLOUR_R_CR: u64 = 0x1857; // linux: mmDPG0_DPG_COLOUR_R_CR
const DPG_COLOUR_G_Y: u64 = 0x1858; // linux: mmDPG0_DPG_COLOUR_G_Y
const DPG_COLOUR_B_CB: u64 = 0x1859; // linux: mmDPG0_DPG_COLOUR_B_CB
const OPP_PIPE_CONTROL: u64 = 0x188c; // linux: mmOPP_PIPE0_OPP_PIPE_CONTROL
const OPP_STRIDE: u64 = 0x5a; // linux: mmFMT1_FMT_CONTROL - mmFMT0_FMT_CONTROL
                              // MPC block (base index 3): MPCC stride 0x20, output mux stride 4.
                              // linux-ctx: hdr=dcn seg=3
const MPCC_TOP_SEL: u64 = 0x0000; // linux: mmMPCC0_MPCC_TOP_SEL
const MPCC_BOT_SEL: u64 = 0x0001; // linux: mmMPCC0_MPCC_BOT_SEL
const MPCC_OPP_ID: u64 = 0x0002; // linux: mmMPCC0_MPCC_OPP_ID
const MPCC_CONTROL: u64 = 0x0003; // linux: mmMPCC0_MPCC_CONTROL
/// `MPCC_UPDATE_LOCK_SEL`: the VUPDATE lock set this MPCC's double-buffered
/// updates latch under, which `mpc1_insert_plane` maps to the OPP.
const MPCC_UPDATE_LOCK_SEL: u64 = 0x0005; // linux: mmMPCC0_MPCC_UPDATE_LOCK_SEL
/// The gain registers `mpc2_update_blending` (DCN30's blend op) writes after
/// `MPCC_CONTROL`: the top gain and the bottom gain inside/outside the
/// overlap.
const MPCC_TOP_GAIN: u64 = 0x0006; // linux: mmMPCC0_MPCC_TOP_GAIN
const MPCC_BOT_GAIN_INSIDE: u64 = 0x0007; // linux: mmMPCC0_MPCC_BOT_GAIN_INSIDE
const MPCC_BOT_GAIN_OUTSIDE: u64 = 0x0008; // linux: mmMPCC0_MPCC_BOT_GAIN_OUTSIDE
const MPCC_BG_R_CR: u64 = 0x0009; // linux: mmMPCC0_MPCC_BG_R_CR
const MPCC_BG_G_Y: u64 = 0x000a; // linux: mmMPCC0_MPCC_BG_G_Y
const MPCC_BG_B_CB: u64 = 0x000b; // linux: mmMPCC0_MPCC_BG_B_CB
const MPCC_STRIDE: u64 = 0x20; // linux: mmMPCC1_MPCC_TOP_SEL - mmMPCC0_MPCC_TOP_SEL
const MPCC_OGAM_CONTROL: u64 = 0x0100; // linux: mmMPCC_OGAM0_MPCC_OGAM_CONTROL
const MPCC_GAMUT_REMAP_MODE: u64 = 0x014b; // linux: mmMPCC_OGAM0_MPCC_GAMUT_REMAP_MODE
const OGAM_STRIDE: u64 = 0x80; // linux: mmMPCC_OGAM1_MPCC_OGAM_CONTROL - mmMPCC_OGAM0_MPCC_OGAM_CONTROL
const MPC_RMU_CONTROL: u64 = 0x0680; // linux: mmMPC_RMU_CONTROL
static RMU_MUX_LOCK: narf_lib::sync::IrqSafeSpinLock<()> = narf_lib::sync::IrqSafeSpinLock::new(());
const MPC_OUT_MUX: u64 = 0x0580; // linux: mmMPC_OUT0_MUX
const MPC_OUT_STRIDE: u64 = 4; // linux: mmMPC_OUT1_MUX - mmMPC_OUT0_MUX
                               // linux-ctx: hdr=dcn

#[cfg(feature = "kernel-test")]
const DPP_LAST_REG: u32 = (CM_CONTROL + 3 * DPP_STRIDE) as u32; // linux: n/a (test-only bank bound)
#[cfg(feature = "kernel-test")]
// linux: n/a (test-only bank bound)
const OPP_LAST_REG: u32 = (OPP_PIPE_CONTROL + 3 * OPP_STRIDE) as u32;
#[cfg(feature = "kernel-test")]
// linux: n/a (test-only bank bound)
const MPC_LAST_REG: u32 = (MPC_OUT_MUX + 3 * MPC_OUT_STRIDE) as u32;
/// One per pixel pipe; see [`crate::amdgpu_dcn::DCN_PIPES`].
#[cfg(feature = "kernel-test")]
const INSTANCES: u8 = crate::amdgpu_dcn::DCN_PIPES;
/// The widest and tallest region these blocks can describe.
///
/// `DSCL0_RECOUT_SIZE`'s `RECOUT_WIDTH`/`RECOUT_HEIGHT`, `DSCL0_MPC_SIZE`'s
/// `MPC_WIDTH`/`MPC_HEIGHT` and `DPG0_DPG_DIMENSIONS`'s
/// `DPG_ACTIVE_WIDTH`/`DPG_ACTIVE_HEIGHT` are all 14-bit fields (0x00003FFF
/// and 0x3FFF0000), so every dimension this module programs tops out here.
/// `amdgpu_dcn_display::MAX_HEIGHT` is the same bound, checked where the mode
/// is validated; the width is bounded tighter still by the OTG's
/// `OPTC_SEGMENT_WIDTH`, so this is the backstop rather than the gate.
pub(crate) const MAX_DIMENSION: u32 = (1 << 14) - 1; // linux: DSCL0_RECOUT_SIZE__RECOUT_WIDTH_MASK

/// `DSCL_MODE_SCALING_444_BYPASS`: an unscaled RGB plane takes no scaler taps.
/// `DSCL_MODE_SCALING_444_BYPASS` from `enum dscl_mode_sel`
/// (`dcn10_dpp_dscl.c:79-87`).
// linux: n/a (enum dscl_mode_sel in dcn10_dpp.c: DSCL_MODE_SCALING_444_BYPASS = 0)
const SCALER_BYPASS: u32 = 0;
/// `DSCL0_SCL_MODE__DSCL_MODE_MASK` — **three** bits, not two. The enum runs to
/// `DSCL_MODE_DSCL_BYPASS` = 6, so bit 2 is live.
///
/// LINUX-GAP: this was masked 0x3. On a handoff from firmware that left the
/// scaler in mode 4, 5 or 6, clearing only the low two bits would have left
/// mode 4 (`SCALING_420_LUMA_BYPASS`) behind instead of reaching bypass.
const DSCL_MODE: u32 = 0x0000_0007; // linux: DSCL0_SCL_MODE__DSCL_MODE_MASK
/// `DSCL_MODE_SCALING_444_RGB_ENABLE`: a scaled RGB plane.
// linux: n/a (enum dscl_mode_sel in dcn10_dpp_dscl.c: DSCL_MODE_SCALING_444_RGB_ENABLE = 1)
const SCALER_RGB: u32 = 1;
/// `DSCL0_SCL_MODE` fields `dpp1_dscl_set_scl_filter` reads and writes.
const SCL_COEF_RAM_SELECT: u32 = 0x0000_0100; // linux: DSCL0_SCL_MODE__SCL_COEF_RAM_SELECT_MASK
                                              // linux: DSCL0_SCL_MODE__SCL_COEF_RAM_SELECT_CURRENT_MASK
const SCL_COEF_RAM_SELECT_CURRENT: u32 = 0x0000_1000;
// linux: DSCL0_SCL_MODE__SCL_CHROMA_COEF_MODE_MASK
const SCL_CHROMA_COEF_MODE: u32 = 0x0001_0000;
/// `DSCL0_DSCL_2TAP_CONTROL`: the six fields `dpp1_dscl_set_scl_filter`
/// updates (H/V hardcoded 2-tap coefficients, sharpening and its factor).
// linux: DSCL0_DSCL_2TAP_CONTROL__SCL_H_2TAP_HARDCODE_COEF_EN_MASK | DSCL0_DSCL_2TAP_CONTROL__SCL_H_2TAP_SHARP_EN_MASK | DSCL0_DSCL_2TAP_CONTROL__SCL_H_2TAP_SHARP_FACTOR_MASK | DSCL0_DSCL_2TAP_CONTROL__SCL_V_2TAP_HARDCODE_COEF_EN_MASK | DSCL0_DSCL_2TAP_CONTROL__SCL_V_2TAP_SHARP_EN_MASK | DSCL0_DSCL_2TAP_CONTROL__SCL_V_2TAP_SHARP_FACTOR_MASK
const DSCL_2TAP_FIELDS: u32 = 0x0711_0711;
/// `SCL_COEF_RAM_TAP_DATA`'s coefficient fields (bits 1:0 of each are 0
/// in the tables) and their write enables.
// linux: DSCL0_SCL_COEF_RAM_TAP_DATA__SCL_COEF_RAM_EVEN_TAP_COEF_MASK
const COEF_MASK: u32 = 0x0000_3fff;
// linux: DSCL0_SCL_COEF_RAM_TAP_DATA__SCL_COEF_RAM_EVEN_TAP_COEF_EN_MASK
const COEF_EVEN_EN: u32 = 0x0000_8000;
// linux: DSCL0_SCL_COEF_RAM_TAP_DATA__SCL_COEF_RAM_ODD_TAP_COEF_EN_MASK
const COEF_ODD_EN: u32 = 0x8000_0000;
/// `SCL_COEF_LUMA_VERT_FILTER` / `SCL_COEF_LUMA_HORZ_FILTER`
/// (`enum dcn10_coef_filter_type_sel`).
// linux: n/a (enum dcn10_coef_filter_type_sel in dcn10_dpp_dscl.c)
const COEF_LUMA_VERT: u32 = 0;
// linux: n/a (enum dcn10_coef_filter_type_sel in dcn10_dpp_dscl.c)
const COEF_LUMA_HORZ: u32 = 1;
/// `NUM_PHASES / 2 + 1`: the 64-phase filters store 33 symmetric phases.
// linux: n/a (NUM_PHASES 64 in dcn10_dpp_dscl.c)
const COEF_PHASES: usize = 64 / 2 + 1;
/// `MPCC_TOP_SEL`/`MPCC_BOT_SEL` park with all ones.
const MPCC_UNSET: u32 = 0xf; // linux: n/a (literal 0xf in dcn10_mpc.c:mpc1_remove_mpcc)

// `MPCC0_MPCC_CONTROL` fields, from `dcn_3_1_4_sh_mask.h`:
//
//   MPCC_MODE                     0x00000003
//   MPCC_ALPHA_BLND_MODE          0x00000030
//   MPCC_ALPHA_MULTIPLIED_MODE    0x00000040
//   MPCC_BLND_ACTIVE_OVERLAP_ONLY 0x00000080
//   MPCC_BG_BPC                   0x00000700
//   MPCC_GLOBAL_ALPHA             0x00FF0000
//
// LINUX-GAP: the mask was `0xf | 0x3 << 4 | 0x3 << 8` — two bits wider than
// `MPCC_MODE` (reaching reserved bits 3:2) and one bit narrower than
// `MPCC_BG_BPC`. The fields below are the ones `mpc1_update_blending` and
// `mpc1_mux_plane` write, with the values `dcn20_hwseq.c:2960-2990` composes
// for an opaque plane.
const MPCC_MODE: u32 = 0x0000_0003; // linux: MPCC0_MPCC_CONTROL__MPCC_MODE_MASK
                                    // linux: MPCC0_MPCC_CONTROL__MPCC_ALPHA_BLND_MODE_MASK
const MPCC_ALPHA_BLND_MODE: u32 = 0x0000_0030;
// linux: MPCC0_MPCC_CONTROL__MPCC_ALPHA_MULTIPLIED_MODE_MASK
const MPCC_ALPHA_MULTIPLIED_MODE: u32 = 0x0000_0040;
// linux: MPCC0_MPCC_CONTROL__MPCC_BLND_ACTIVE_OVERLAP_ONLY_MASK
const MPCC_BLND_ACTIVE_OVERLAP_ONLY: u32 = 0x0000_0080;
const MPCC_BG_BPC: u32 = 0x0000_0700; // linux: MPCC0_MPCC_CONTROL__MPCC_BG_BPC_MASK
const MPCC_GLOBAL_ALPHA: u32 = 0x00FF_0000; // linux: MPCC0_MPCC_CONTROL__MPCC_GLOBAL_ALPHA_MASK
/// `MPCC_GLOBAL_GAIN` (bits 31:24): the plane-alpha gain
/// `mpc2_update_blending` writes alongside the global alpha. The in-tree
/// mask predates it: `mux_plane`'s opaque blend leaves an inherited gain
/// behind, which the overlay insert path below writes explicitly.
const MPCC_GLOBAL_GAIN: u32 = 0xFF00_0000; // linux: MPCC0_MPCC_CONTROL__MPCC_GLOBAL_GAIN_MASK
/// `MPCC_BOT_GAIN_MODE` (bit 11): the blend mode for the bottom gain.
const MPCC_BOT_GAIN_MODE: u32 = 0x0000_0800; // linux: MPCC0_MPCC_CONTROL__MPCC_BOT_GAIN_MODE_MASK
/// The gain registers hold one 19-bit gain each.
const MPCC_GAIN_MASK: u32 = 0x0007_FFFF; // linux: MPCC0_MPCC_TOP_GAIN__MPCC_TOP_GAIN_MASK

/// `MPCC_BLEND_MODE_TOP_LAYER_ONLY` from `enum mpcc_blend_mode`
/// (`inc/hw/mpc.h:70-75`): BYPASS 0, TOP_LAYER_PASSTHROUGH 1, TOP_LAYER_ONLY 2,
/// TOP_BOT_BLENDING 3.
///
/// LINUX-GAP: this register was written 0, `MPCC_BLEND_MODE_BYPASS`, under a
/// comment describing opaque passthrough. `mpc1_mux_plane` writes
/// `TOP_LAYER_ONLY` for exactly this case — no bottom layer — and Linux's MPC
/// never writes BYPASS anywhere. A bypassed MPCC does not put the DPP's pixels
/// on the OPP at all.
// linux: n/a (enum mpcc_blend_mode in inc/hw/mpc.h; header not in checker set)
const MPCC_BLEND_MODE_TOP_LAYER_ONLY: u32 = 2;
/// `MPCC_BLEND_MODE_TOP_LAYER_PASSTHROUGH` (`inc/hw/mpc.h`): the top layer
/// passes and the bottom layer is ignored. `mpc1_remove_mpcc` writes it on
/// the MPCC above a removed bottom MPCC, whose blend partner is gone but
/// whose bottom select is now parked.
// linux: n/a (enum mpcc_blend_mode in inc/hw/mpc.h; header not in checker set)
const MPCC_BLEND_MODE_TOP_LAYER_PASSTHROUGH: u32 = 1;
/// `MPCC_BLEND_MODE_TOP_BOT_BLENDING` (`inc/hw/mpc.h`): the top layer blends
/// over the bottom layer. `mpc1_insert_plane` writes it on a new MPCC
/// inserted above another, and on the old bottom when a plane is appended
/// below it.
// linux: n/a (enum mpcc_blend_mode in inc/hw/mpc.h; header not in checker set)
const MPCC_BLEND_MODE_TOP_BOT_BLENDING: u32 = 3;

/// How one MPCC blends its top layer over its bottom layer: `enum
/// mpcc_alpha_blend_mode` (`inc/hw/mpc.h:80-98`), the `MPCC_ALPHA_BLND_MODE`
/// field of `MPCC_CONTROL`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlphaBlendMode {
    /// Per-pixel alpha from the DPP, ignoring any plane alpha.
    PerPixelAlpha,
    /// Per-pixel alpha multiplied by the global gain (the plane alpha).
    PerPixelAlphaCombinedGlobalGain,
    /// The global alpha only, ignoring pixel alpha.
    GlobalAlpha,
}
impl AlphaBlendMode {
    const fn code(self) -> u32 {
        match self {
            // linux: n/a (enum mpcc_alpha_blend_mode in inc/hw/mpc.h)
            AlphaBlendMode::PerPixelAlpha => 0,
            // linux: n/a (enum mpcc_alpha_blend_mode in inc/hw/mpc.h)
            AlphaBlendMode::PerPixelAlphaCombinedGlobalGain => 1,
            // linux: n/a (enum mpcc_alpha_blend_mode in inc/hw/mpc.h)
            AlphaBlendMode::GlobalAlpha => 2,
        }
    }
}

/// `struct mpcc_blnd_cfg` (`inc/hw/mpc.h:124-175`) as `mpc2_update_blending`
/// (DCN30's blend op, `dcn20_mpc.c`) writes it: the seven `MPCC_CONTROL`
/// fields plus the top and bottom gains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlendConfig {
    pub alpha_mode: AlphaBlendMode,
    pub pre_multiplied_alpha: bool,
    pub overlap_only: bool,
    /// Plane alpha (0-255); the `MPCC_GLOBAL_ALPHA` field.
    pub global_alpha: u8,
    /// Plane-alpha gain (0-255); the `MPCC_GLOBAL_GAIN` field.
    pub global_gain: u8,
    /// Background colour depth (0-7); the `MPCC_BG_BPC` field.
    pub background_color_bpc: u32,
    /// Bottom-gain blend mode (0-1); the `MPCC_BOT_GAIN_MODE` field.
    pub bottom_gain_mode: u32,
    /// The `MPCC_TOP_GAIN` register (19 bits).
    pub top_gain: u32,
    /// The `MPCC_BOT_GAIN_INSIDE` register (19 bits).
    pub bottom_inside_gain: u32,
    /// The `MPCC_BOT_GAIN_OUTSIDE` register (19 bits).
    pub bottom_outside_gain: u32,
}
impl BlendConfig {
    /// `dcn20_update_mpcc`'s composition for an opaque plane with no
    /// per-pixel alpha: global-alpha mode, global alpha and gain 0xff,
    /// background bpc 4, bottom gain mode 0, all gains 0x1f000.
    pub const fn opaque() -> Self {
        Self {
            alpha_mode: AlphaBlendMode::GlobalAlpha,
            pre_multiplied_alpha: false,
            overlap_only: false,
            global_alpha: 0xff,
            global_gain: 0xff,
            background_color_bpc: 4,
            bottom_gain_mode: 0,
            top_gain: 0x1f000,
            bottom_inside_gain: 0x1f000,
            bottom_outside_gain: 0x1f000,
        }
    }
    /// `dcn20_update_mpcc`'s composition for a plane with per-pixel alpha
    /// and no plane alpha: per-pixel mode, global alpha and gain 0xff.
    pub const fn per_pixel_alpha(pre_multiplied: bool) -> Self {
        Self {
            alpha_mode: AlphaBlendMode::PerPixelAlpha,
            pre_multiplied_alpha: pre_multiplied,
            ..Self::opaque()
        }
    }
    /// `dcn20_update_mpcc`'s composition for a plane with per-pixel alpha
    /// and a plane alpha `gain`: per-pixel-combined-global-gain mode, the
    /// gain in both the global-gain and the global-alpha fields.
    pub const fn per_pixel_alpha_with_gain(pre_multiplied: bool, gain: u8) -> Self {
        Self {
            alpha_mode: AlphaBlendMode::PerPixelAlphaCombinedGlobalGain,
            pre_multiplied_alpha: pre_multiplied,
            global_alpha: gain,
            global_gain: gain,
            ..Self::opaque()
        }
    }
}
/// `MPCC_ALPHA_BLEND_MODE_GLOBAL_ALPHA` (`inc/hw/mpc.h`), which
/// `dcn20_hwseq.c` selects for a plane with no per-pixel alpha, paired with
/// `global_alpha = 0xff`.
// linux: n/a (enum mpcc_alpha_blend_mode in inc/hw/mpc.h; header not in checker set)
const MPCC_ALPHA_BLEND_MODE_GLOBAL_ALPHA: u32 = 2;
/// `blnd_cfg.global_alpha = 0xff` — fully opaque.
// linux: n/a (literal in dcn20_hwseq.c:dcn20_update_mpcc, global_alpha)
const MPCC_GLOBAL_ALPHA_OPAQUE: u32 = 0xff;
/// `blnd_cfg.background_color_bpc = 4` (`dcn20_hwseq.c:2985`).
// linux: n/a (literal in dcn20_hwseq.c:dcn20_update_mpcc, background_color_bpc)
const MPCC_BG_BPC_DEFAULT: u32 = 4;

// `FMT0_FMT_CONTROL`:
//
//   FMT_PIXEL_ENCODING            0x00030000
//   FMT_SUBSAMPLING_MODE          0x000C0000
//   FMT_CBCR_BIT_REDUCTION_BYPASS 0x00200000
//
// LINUX-GAP: the mask was `0x7 << 16`, which straddles the first two fields —
// all of `FMT_PIXEL_ENCODING` and only the LOW bit of `FMT_SUBSAMPLING_MODE`.
// `opp1_program_fmt`'s RGB arm clears all three, so an inherited
// `FMT_SUBSAMPLING_MODE` of 2 (what a 4:2:2 or 4:2:0 stream leaves) would have
// survived into an RGB stream.
// linux: FMT0_FMT_CONTROL__FMT_PIXEL_ENCODING_MASK | FMT0_FMT_CONTROL__FMT_SUBSAMPLING_MODE_MASK | FMT0_FMT_CONTROL__FMT_CBCR_BIT_REDUCTION_BYPASS_MASK
const FMT_RGB_FIELDS: u32 = 0x0003_0000 | 0x000C_0000 | 0x0020_0000;
/// `TEST_PATTERN_MODE_HORIZONTALBARS` with both bar colours black, which is how
/// DCN2 onwards paints a blanked stream.
// linux: n/a (enum test_pattern_mode in inc/hw/hw_shared.h; not in checker set)
const DPG_MODE_SOLID: u32 = 4;
/// `TEST_PATTERN_COLOR_FORMAT_BPC_8`.
// linux: n/a (enum test_pattern_color_format in inc/hw/hw_shared.h; not in checker set)
const DPG_BIT_DEPTH_8: u32 = 1;

/// The pixel encoding the output formatter emits. Only uncompressed RGB is
/// modelled; 4:2:2 and 4:2:0 would need the chroma path this port does not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encoding {
    Rgb,
}
impl Encoding {
    fn code(self) -> u32 {
        match self {
            Encoding::Rgb => 0, // linux: n/a (literal in dcn10_opp.c:opp1_set_pixel_encoding)
        }
    }
}
/// `CNVC_SURFACE_PIXEL_FORMAT` uses the same codes as the hub pixel pipe.
fn cnvc_format(format: Format) -> u32 {
    match format {
        Format::Rgb16 => 3,  // linux: n/a (literal in dcn30_dpp.c:dpp3_cnv_setup, RGB565)
        Format::Rgb32 => 8,  // linux: n/a (literal in dcn30_dpp.c:dpp3_cnv_setup, ARGB8888)
        Format::Rgb64 => 26, // linux: n/a (literal in dcn30_dpp.c:dpp3_cnv_setup, ARGB16161616)
    }
}

/// `dpp1_dscl_get_filter_coeffs_64p` over `dce_scl_filters.c`'s tables
/// (the same values `amdgpu_dcn401_spl_filters` carries from SPL's copy):
/// upscale below ratio 1, then the 1.16, 1.49 and 1.83 sets at 4/3 and
/// 5/3. One tap has no filter.
fn filter_64p(taps: u32, ratio: Fixed31_32) -> Option<&'static [u16]> {
    use crate::amdgpu_dcn401_spl_filters as f;
    let pick = |up: &'static [u16], a: &'static [u16], b: &'static [u16], c: &'static [u16]| {
        if ratio < Fixed31_32::ONE {
            up
        } else if ratio < Fixed31_32::from_fraction(4, 3) {
            a
        } else if ratio < Fixed31_32::from_fraction(5, 3) {
            b
        } else {
            c
        }
    };
    Some(match taps {
        8 => pick(
            &f::FILTER_8TAP_64P_UPSCALE,
            &f::FILTER_8TAP_64P_116,
            &f::FILTER_8TAP_64P_149,
            &f::FILTER_8TAP_64P_183,
        ),
        7 => pick(
            &f::FILTER_7TAP_64P_UPSCALE,
            &f::FILTER_7TAP_64P_116,
            &f::FILTER_7TAP_64P_149,
            &f::FILTER_7TAP_64P_183,
        ),
        6 => pick(
            &f::FILTER_6TAP_64P_UPSCALE,
            &f::FILTER_6TAP_64P_116,
            &f::FILTER_6TAP_64P_149,
            &f::FILTER_6TAP_64P_183,
        ),
        5 => pick(
            &f::FILTER_5TAP_64P_UPSCALE,
            &f::FILTER_5TAP_64P_116,
            &f::FILTER_5TAP_64P_149,
            &f::FILTER_5TAP_64P_183,
        ),
        4 => pick(
            &f::FILTER_4TAP_64P_UPSCALE,
            &f::FILTER_4TAP_64P_116,
            &f::FILTER_4TAP_64P_149,
            &f::FILTER_4TAP_64P_183,
        ),
        3 => pick(
            &f::FILTER_3TAP_64P_UPSCALE,
            &f::FILTER_3TAP_64P_116,
            &f::FILTER_3TAP_64P_149,
            &f::FILTER_3TAP_64P_183,
        ),
        2 => &f::FILTER_2TAP_64P,
        _ => return None,
    })
}
fn same_filter(a: Option<&'static [u16]>, b: Option<&'static [u16]>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => core::ptr::eq(a, b),
        (None, None) => true,
        _ => false,
    }
}

/// What `struct dcn10_dpp` remembers of its DSCL between updates: the last
/// `scl_data` programmed (`dpp1_dscl_set_scaler_manual_scale` skips an
/// identical one) and the luma filters in the coefficient RAM
/// (`dpp->filter_h` / `filter_v`). `dpp_reset` clears both.
#[derive(Clone, Copy, Debug, Default)]
struct DsclCache {
    data: Option<ScalerData>,
    filter_h: Option<&'static [u16]>,
    filter_v: Option<&'static [u16]>,
}

trait Io: Send {
    fn read(&mut self, reg: u64) -> u32;
    fn write(&mut self, reg: u64, value: u32);
}
#[derive(Debug)]
struct Mmio {
    regs: crate::amdgpu_reg_window::Window,
    base: u64,
}
impl Io for Mmio {
    fn read(&mut self, reg: u64) -> u32 {
        // SAFETY: constructor bounds this DCN bank and retains the mapping.
        unsafe { self.regs.read32(self.base + reg * 4) }
    }
    fn write(&mut self, reg: u64, value: u32) {
        // SAFETY: same bounded bank; this is the sole owner of the instance.
        unsafe { self.regs.write32(self.base + reg * 4, value) };
    }
}
struct Op<F>(F);
impl<F: FnOnce() -> T, T> CapOp<BusDeviceCap, Write> for Op<F> {
    type Output = T;
    fn execute(self, _: &Cap<BusDeviceCap, Write>) -> Result<T, CapError> {
        Ok((self.0)())
    }
}
#[derive(Debug)]
struct Block<I: Io> {
    io: I,
    authority: Cap<BusDeviceCap, Write>,
    instance: u8,
    profile: Profile,
}
impl<I: Io> Block<I> {
    fn access<T>(&mut self, f: impl FnOnce(&mut I) -> T) -> Result<T, Error> {
        let io = &mut self.io;
        self.authority
            .invoke(Op(|| f(io)))
            .map_err(|_| Error::Revoked)
    }
    fn set(&mut self, reg: u64, value: u32) -> Result<(), Error> {
        self.access(|io| io.write(reg, value))
    }
    fn update(&mut self, reg: u64, mask: u32, value: u32) -> Result<(), Error> {
        self.access(|io| {
            let old = io.read(reg);
            if old == u32::MAX {
                return Err(Error::DeviceGone);
            }
            io.write(reg, (old & !mask) | (value & mask));
            Ok(())
        })?
    }
    fn read_reg(&mut self, reg: u64) -> Result<u32, Error> {
        let value = self.access(|io| io.read(reg))?;
        if value == u32::MAX {
            return Err(Error::DeviceGone);
        }
        Ok(value)
    }
}
impl<I: Io> Block<I> {
    fn dpp(&self, reg: u64) -> u64 {
        reg + self.instance as u64 * DPP_STRIDE
    }
    fn mpcc(&self, reg: u64) -> u64 {
        reg + self.instance as u64 * MPCC_STRIDE
    }
    fn opp(&self, reg: u64) -> u64 {
        reg + self.instance as u64 * OPP_STRIDE
    }
    /// Program the input format and a 1:1 recout. The recout and the combiner
    /// size match the active area because nothing is scaled and nothing is
    /// blended beside it.
    fn dpp_program(&mut self, format: Format, width: u32, height: u32) -> Result<(), Error> {
        if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
            return Err(Error::Invalid);
        }
        let reg = self.dpp(DPP_CONTROL);
        // linux-lit: 4=DPP_TOP0_DPP_CONTROL__DPP_CLOCK_ENABLE__SHIFT
        self.update(reg, 1 << 4, 1 << 4)?;
        let reg = self.dpp(CNVC_SURFACE_PIXEL_FORMAT);
        // No separate alpha surface (RGBE_ALPHA is not an accepted format).
        // linux-lit: 0x17f=CNVC_CFG0_CNVC_SURFACE_PIXEL_FORMAT__CNVC_SURFACE_PIXEL_FORMAT_MASK | CNVC_CFG0_CNVC_SURFACE_PIXEL_FORMAT__CNVC_ALPHA_PLANE_ENABLE_MASK
        self.update(reg, 0x17f, cnvc_format(format))?;
        // dpp3_cnv_setup: zero expansion, R/G/B crossbar 0/1/2, no float,
        // clamp or converter bypass inherited from a previous stream.
        let reg = self.dpp(FORMAT_CONTROL);
        let alpha = u32::from(format != Format::Rgb16) << 8;
        // linux-lit: 0x3f033111=CNVC_CFG0_FORMAT_CONTROL__FORMAT_EXPANSION_MODE_MASK | CNVC_CFG0_FORMAT_CONTROL__FORMAT_CNV16_MASK | CNVC_CFG0_FORMAT_CONTROL__ALPHA_EN_MASK | CNVC_CFG0_FORMAT_CONTROL__CNVC_BYPASS_MASK | CNVC_CFG0_FORMAT_CONTROL__CNVC_BYPASS_MSB_ALIGN_MASK | CNVC_CFG0_FORMAT_CONTROL__CLAMP_POSITIVE_MASK | CNVC_CFG0_FORMAT_CONTROL__CLAMP_POSITIVE_C_MASK | CNVC_CFG0_FORMAT_CONTROL__FORMAT_CROSSBAR_R_MASK | CNVC_CFG0_FORMAT_CONTROL__FORMAT_CROSSBAR_G_MASK | CNVC_CFG0_FORMAT_CONTROL__FORMAT_CROSSBAR_B_MASK
        self.update(reg, 0x3f03_3111, 0x2400_0001 | alpha)?;
        for field in [PRE_DEALPHA, PRE_REALPHA] {
            let reg = self.dpp(field);
            // linux-lit: 0x11=CNVC_CFG0_PRE_DEALPHA__PRE_DEALPHA_EN_MASK | CNVC_CFG0_PRE_DEALPHA__PRE_DEALPHA_ABLND_EN_MASK
            self.update(reg, 0x11, 0)?;
        }
        // CNVC's ROM degamma is before the CM block, so bypass both. This
        // path accepts already encoded RGB pixels and owns no color LUTs.
        let reg = self.dpp(PRE_DEGAM);
        // linux-lit: 0x73=CNVC_CFG0_PRE_DEGAM__PRE_DEGAM_MODE_MASK | CNVC_CFG0_PRE_DEGAM__PRE_DEGAM_SELECT_MASK
        self.update(reg, 0x73, 0)?;
        let reg = self.dpp(CM_CONTROL);
        // linux-lit: 1=CM0_CM_CONTROL__CM_BYPASS_MASK
        self.update(reg, 1, 1)?;
        // dpp1_dscl_set_scaler_manual_scale still initializes autocal,
        // boundary mode and line-buffer storage for SCALING_444_BYPASS.
        // It only skips these for DSCL_BYPASS (the separate FP16 path).
        let reg = self.dpp(DSCL_AUTOCAL);
        // linux-lit: 0x3303=DSCL0_DSCL_AUTOCAL__AUTOCAL_MODE_MASK | DSCL0_DSCL_AUTOCAL__AUTOCAL_NUM_PIPE_MASK | DSCL0_DSCL_AUTOCAL__AUTOCAL_PIPE_ID_MASK
        self.update(reg, 0x3303, 0)?;
        let reg = self.dpp(DSCL_CONTROL);
        self.update(reg, 1, 0)?; // linux-lit: 1=DSCL0_DSCL_CONTROL__SCL_BOUNDARY_MODE_MASK
        let reg = self.dpp(LB_DATA_FORMAT);
        // Opaque RGB: neither alpha nor chroma interleave uses LB storage.
        // linux-lit: 0x11=DSCL0_LB_DATA_FORMAT__INTERLEAVE_EN_MASK | DSCL0_LB_DATA_FORMAT__ALPHA_EN_MASK
        self.update(reg, 0x11, 0)?;
        let reg = self.dpp(LB_MEMORY_CTRL);
        // Linux's use_max_lb RGB choice, MEMORY_CONFIG_0 (all three banks),
        // with the pre-DCN3.2 maximum of 63 partitions. No scaling/taps.
        // linux-lit: 0x3f00=63 << DSCL0_LB_MEMORY_CTRL__LB_MAX_PARTITIONS__SHIFT
        self.set(reg, 0x3f00)?;
        // Bypass the scaler outright rather than programming unity taps.
        let reg = self.dpp(SCL_MODE);
        self.update(reg, DSCL_MODE, SCALER_BYPASS)?;
        let reg = self.dpp(RECOUT_START);
        self.set(reg, 0)?;
        let reg = self.dpp(RECOUT_SIZE);
        // linux-lit: 16=DSCL0_RECOUT_SIZE__RECOUT_HEIGHT__SHIFT
        self.set(reg, width | height << 16)?;
        let reg = self.dpp(MPC_SIZE);
        self.set(reg, width | height << 16) // linux-lit: 16=DSCL0_MPC_SIZE__MPC_HEIGHT__SHIFT
    }
    /// `dpp1_dscl_set_scaler_manual_scale` on DCN3.0 for an RGB plane (no
    /// chroma, no per-pixel alpha, `enable_mem_low_power` off, no
    /// `always_scale`, float DSCL data so no black offset): autocal off,
    /// recout, MPC size, mode, the line buffer (`use_max_lb`: config 0, 63
    /// partitions), then for a scaled plane the U3.19 ratios and phases,
    /// taps and the 64-phase filters (`dpp1_dscl_set_scl_filter`, writing
    /// the RAM only when a filter changed and then flipping the RAM
    /// select). An unchanged `ScalerData` writes nothing.
    fn dscl_set_scaler(&mut self, d: &ScalerData, cache: &mut DsclCache) -> Result<(), Error> {
        if !self.profile.is_dcn30() {
            return Err(Error::Unsupported);
        }
        let fits = |v: i32, bits: u32| v >= 0 && v < 1 << bits;
        if !fits(d.recout.x, 13)
            || !fits(d.recout.y, 13)
            || !fits(d.recout.width, 14)
            || !fits(d.recout.height, 14)
            || !fits(d.h_active, 14)
            || !fits(d.v_active, 14)
            || !(1..=8).contains(&d.h_taps)
            || !(1..=8).contains(&d.v_taps)
            || d.init_h.floor() > 0xf
            || d.init_v.floor() > 0xf
        {
            return Err(Error::Invalid);
        }
        if cache.data.as_ref() == Some(d) {
            return Ok(());
        }
        let identity = d.ratio_h == Fixed31_32::ONE && d.ratio_v == Fixed31_32::ONE;
        let mode = if identity { SCALER_BYPASS } else { SCALER_RGB };
        // Autocal off, scaler boundary mode cleared (both whole writes).
        self.set(self.dpp(DSCL_AUTOCAL), 0)?;
        self.set(self.dpp(DSCL_CONTROL), 0)?;
        let reg = self.dpp(RECOUT_START);
        // linux-lit: 16=DSCL0_RECOUT_START__RECOUT_START_Y__SHIFT
        self.set(reg, d.recout.x as u32 | (d.recout.y as u32) << 16)?;
        let reg = self.dpp(RECOUT_SIZE);
        // linux-lit: 16=DSCL0_RECOUT_SIZE__RECOUT_HEIGHT__SHIFT
        self.set(reg, d.recout.width as u32 | (d.recout.height as u32) << 16)?;
        let reg = self.dpp(MPC_SIZE);
        // linux-lit: 16=DSCL0_MPC_SIZE__MPC_HEIGHT__SHIFT
        self.set(reg, d.h_active as u32 | (d.v_active as u32) << 16)?;
        self.update(self.dpp(SCL_MODE), DSCL_MODE, mode)?;
        // dpp1_dscl_set_lb (float format): no interleave, no alpha.
        self.set(self.dpp(LB_DATA_FORMAT), 0)?;
        // linux-lit: 0x3f00=63 << DSCL0_LB_MEMORY_CTRL__LB_MAX_PARTITIONS__SHIFT
        self.set(self.dpp(LB_MEMORY_CTRL), 0x3f00)?;
        cache.data = Some(*d);
        if mode == SCALER_BYPASS {
            return Ok(());
        }
        // dpp1_dscl_set_manual_ratio_init: U3.19 ratios and U0.19 phase
        // fractions, each shifted into the top of a 24-bit field.
        let ratio = |r: Fixed31_32| u3d19(r) << 5;
        // linux-lit: 24=DSCL0_SCL_HORZ_FILTER_INIT__SCL_H_INIT_INT__SHIFT
        let init = |i: Fixed31_32| u0d19(i) << 5 | (i.floor() as u32) << 24;
        for (reg, value) in [
            (SCL_HORZ_FILTER_SCALE_RATIO, ratio(d.ratio_h)),
            (SCL_VERT_FILTER_SCALE_RATIO, ratio(d.ratio_v)),
            (SCL_HORZ_FILTER_SCALE_RATIO_C, ratio(d.ratio_h)),
            (SCL_VERT_FILTER_SCALE_RATIO_C, ratio(d.ratio_v)),
            (SCL_HORZ_FILTER_INIT, init(d.init_h)),
            (SCL_HORZ_FILTER_INIT_C, init(d.init_h)),
            (SCL_VERT_FILTER_INIT, init(d.init_v)),
            (SCL_VERT_FILTER_INIT_C, init(d.init_v)),
        ] {
            self.set(self.dpp(reg), value)?;
        }
        let (h, v) = (d.h_taps - 1, d.v_taps - 1);
        // linux-lit: 4=DSCL0_SCL_TAP_CONTROL__SCL_H_NUM_TAPS__SHIFT
        // linux-lit: 8=DSCL0_SCL_TAP_CONTROL__SCL_V_NUM_TAPS_C__SHIFT
        // linux-lit: 12=DSCL0_SCL_TAP_CONTROL__SCL_H_NUM_TAPS_C__SHIFT
        self.set(self.dpp(SCL_TAP_CONTROL), v | h << 4 | v << 8 | h << 12)?;
        self.dscl_set_filters(d, cache)
    }
    /// `dpp1_dscl_set_scl_filter` for luma only (RGB: `chroma_coef_mode`
    /// false). Sharpness is zero, so no 2-tap sharpening.
    fn dscl_set_filters(&mut self, d: &ScalerData, cache: &mut DsclCache) -> Result<(), Error> {
        let h_2tap = d.h_taps == 2;
        let v_2tap = d.v_taps == 2;
        // linux-lit: 16=DSCL0_DSCL_2TAP_CONTROL__SCL_V_2TAP_HARDCODE_COEF_EN__SHIFT
        let two_tap = u32::from(h_2tap) | u32::from(v_2tap) << 16;
        self.update(self.dpp(DSCL_2TAP_CONTROL), DSCL_2TAP_FIELDS, two_tap)?;
        if h_2tap && v_2tap {
            return Ok(());
        }
        let filter_h = filter_64p(d.h_taps, d.ratio_h);
        let filter_v = filter_64p(d.v_taps, d.ratio_v);
        let updated = (filter_h.is_some() && !same_filter(filter_h, cache.filter_h))
            || (filter_v.is_some() && !same_filter(filter_v, cache.filter_v));
        if !updated {
            return Ok(());
        }
        let reg = self.dpp(SCL_MODE);
        let scl_mode = self.access(|io| io.read(reg))?;
        if scl_mode == u32::MAX {
            return Err(Error::DeviceGone);
        }
        if let (false, Some(filter)) = (h_2tap, filter_h) {
            self.dscl_write_filter(d.h_taps, COEF_LUMA_HORZ, filter)?;
        }
        cache.filter_h = filter_h;
        if let (false, Some(filter)) = (v_2tap, filter_v) {
            self.dscl_write_filter(d.v_taps, COEF_LUMA_VERT, filter)?;
        }
        cache.filter_v = filter_v;
        // Swap to the RAM just written; luma-only coefficients.
        let current = scl_mode & SCL_COEF_RAM_SELECT_CURRENT != 0;
        let select = if current { 0 } else { SCL_COEF_RAM_SELECT };
        let value = scl_mode & !(SCL_COEF_RAM_SELECT | SCL_CHROMA_COEF_MODE) | select;
        self.set(reg, value)
    }
    /// `dpp1_dscl_set_scaler_filter`: select the filter type at tap pair 0,
    /// phase 0, then stream 33 phases of tap pairs (the address advances).
    fn dscl_write_filter(&mut self, taps: u32, kind: u32, filter: &[u16]) -> Result<(), Error> {
        let taps = taps as usize;
        if filter.len() < COEF_PHASES * taps {
            return Err(Error::Invalid);
        }
        // linux-lit: 16=DSCL0_SCL_COEF_RAM_TAP_SELECT__SCL_COEF_RAM_FILTER_TYPE__SHIFT
        self.set(self.dpp(SCL_COEF_RAM_TAP_SELECT), kind << 16)?;
        let data = self.dpp(SCL_COEF_RAM_TAP_DATA);
        let pairs = taps.div_ceil(2);
        self.access(|io| {
            for phase in 0..COEF_PHASES {
                for pair in 0..pairs {
                    let even = u32::from(filter[phase * taps + 2 * pair]);
                    let odd = if 2 * pair + 1 < taps {
                        u32::from(filter[phase * taps + 2 * pair + 1])
                    } else {
                        0
                    };
                    io.write(
                        data,
                        (even & COEF_MASK)
                            | COEF_EVEN_EN
                            // linux-lit: 16=DSCL0_SCL_COEF_RAM_TAP_DATA__SCL_COEF_RAM_ODD_TAP_COEF__SHIFT
                            | (odd & COEF_MASK) << 16
                            | COEF_ODD_EN,
                    );
                }
            }
        })
    }
    /// [`Mpc::set_bg_color`] (DCN3.0 only).
    fn mpc_set_bg_color(&mut self, rgb: [u16; 3]) -> Result<(), Error> {
        if !self.profile.is_dcn30() {
            return Err(Error::Unsupported);
        }
        for (reg, value) in [MPCC_BG_R_CR, MPCC_BG_G_Y, MPCC_BG_B_CB]
            .into_iter()
            .zip(rgb)
        {
            let reg = self.mpcc(reg);
            // linux-lit: 0xfff=MPCC0_MPCC_BG_R_CR__MPCC_BG_R_CR_MASK
            self.set(reg, (u32::from(value) << 2) & 0xfff)?;
        }
        Ok(())
    }
    /// `mpc1_mux_plane`: bind this MPCC to a DPP and an OPP and route the OPP's
    /// output mux to it. Opaque passthrough, no bottom layer.
    fn mpc_mux_plane(&mut self, dpp: u8, opp: u8) -> Result<(), Error> {
        if dpp >= self.profile.pipes() || opp >= self.profile.pipes() {
            return Err(Error::Invalid);
        }
        if self.profile.is_dcn30() {
            // dcn30_program_gamut_remap: an encoded RGB desktop has no
            // stream gamut matrix. OGAM bypass alone does not bypass this.
            let reg = MPCC_GAMUT_REMAP_MODE + u64::from(self.instance) * OGAM_STRIDE;
            self.update(reg, 3, 0)?; // linux-lit: 3=MPCC_OGAM0_MPCC_GAMUT_REMAP_MODE__MPCC_GAMUT_REMAP_MODE_MASK
                                     // dcn30_set_mpc_shaper_3dlut(NULL) -> release_rmu. Only detach
                                     // muxes belonging to this MPCC; other streams retain their LUTs.
                                     // DCN3 has three RMUs, with MUX/STATUS nibble pairs per byte.
            {
                // Different MPCC owners share this register. Serialize the
                // masked updates, with no await or hardware wait under lock.
                let _mux = RMU_MUX_LOCK.lock();
                let rmu = self.access(|io| io.read(MPC_RMU_CONTROL))?;
                if rmu == u32::MAX {
                    return Err(Error::DeviceGone);
                }
                // Resource caps: DCN3.0 has 3, 3.0.2 has 2, 3.0.3 has 1.
                let units = match self.profile {
                    Profile::Navi22 => 3,
                    Profile::Dcn302 => 2,
                    Profile::Dcn303 => 1,
                    Profile::Dcn314 => 0,
                };
                for unit in 0..units {
                    let shift = 8 * unit;
                    if (rmu >> (shift + 4)) & 0xf == u32::from(self.instance) {
                        self.update(MPC_RMU_CONTROL, 0xf << shift, 0xf << shift)?;
                    }
                }
            }
        }
        // mpc3_program_ogam(NULL): this passthrough path owns no output
        // gamma LUT. A firmware LUT may still be selected after mpc_init.
        let reg = MPCC_OGAM_CONTROL + u64::from(self.instance) * OGAM_STRIDE;
        self.update(reg, 3, 0)?; // linux-lit: 3=MPCC_OGAM0_MPCC_OGAM_CONTROL__MPCC_OGAM_MODE_MASK
        let reg = self.mpcc(MPCC_TOP_SEL);
        self.update(reg, 0xf, dpp as u32)?; // linux-lit: 0xf=MPCC0_MPCC_TOP_SEL__MPCC_TOP_SEL_MASK
                                            // Nothing below this plane: a stale bottom select would blend against
                                            // another pipe's output.
        let reg = self.mpcc(MPCC_BOT_SEL);
        self.update(reg, 0xf, MPCC_UNSET)?; // linux-lit: 0xf=MPCC0_MPCC_BOT_SEL__MPCC_BOT_SEL_MASK
        let reg = self.mpcc(MPCC_OPP_ID);
        self.update(reg, 0xf, opp as u32)?; // linux-lit: 0xf=MPCC0_MPCC_OPP_ID__MPCC_OPP_ID_MASK
                                            // Top layer only, with the opaque blend configuration
                                            // `dcn20_hwseq.c:2960-2990` composes: global alpha at 0xff, no
                                            // pre-multiplication, not overlap-only, background bpc 4.
        let reg = self.mpcc(MPCC_CONTROL);
        self.update(
            reg,
            MPCC_MODE
                | MPCC_ALPHA_BLND_MODE
                | MPCC_ALPHA_MULTIPLIED_MODE
                | MPCC_BLND_ACTIVE_OVERLAP_ONLY
                | MPCC_BG_BPC
                | MPCC_GLOBAL_ALPHA,
            MPCC_BLEND_MODE_TOP_LAYER_ONLY
                | MPCC_ALPHA_BLEND_MODE_GLOBAL_ALPHA << MPCC_ALPHA_BLND_MODE.trailing_zeros()
                | MPCC_BG_BPC_DEFAULT << MPCC_BG_BPC.trailing_zeros()
                | MPCC_GLOBAL_ALPHA_OPAQUE << MPCC_GLOBAL_ALPHA.trailing_zeros(),
        )?;
        let instance = self.instance as u32;
        let reg = MPC_OUT_MUX + opp as u64 * MPC_OUT_STRIDE;
        self.update(reg, 0xf, instance) // linux-lit: 0xf=MPC_OUT0_MUX__MPC_OUT_MUX_MASK
    }
    fn mpc_release(&mut self, opp: u8) -> Result<(), Error> {
        if opp >= self.profile.pipes() {
            return Err(Error::Invalid);
        }
        let reg = MPC_OUT_MUX + opp as u64 * MPC_OUT_STRIDE;
        self.update(reg, 0xf, MPCC_UNSET)?; // linux-lit: 0xf=MPC_OUT0_MUX__MPC_OUT_MUX_MASK
        for reg in [MPCC_TOP_SEL, MPCC_BOT_SEL, MPCC_OPP_ID] {
            let reg = self.mpcc(reg);
            // linux-lit: 0xf=MPCC0_MPCC_TOP_SEL__MPCC_TOP_SEL_MASK
            self.update(reg, 0xf, MPCC_UNSET)?;
        }
        Ok(())
    }
    /// This MPCC's register `reg` of MPCC `id` (the tree spans instances;
    /// the mux, top and bottom selects of several MPCCs are one tree).
    fn mpcc_at(&self, id: u8, reg: u64) -> u64 {
        reg + u64::from(id) * MPCC_STRIDE
    }
    /// The MPCC id the OPP's output mux names, or `MPCC_UNSET` for an empty
    /// tree.
    fn mpc_tree_head(&mut self, opp: u8) -> Result<u32, Error> {
        if opp >= self.profile.pipes() {
            return Err(Error::Invalid);
        }
        let reg = MPC_OUT_MUX + u64::from(opp) * MPC_OUT_STRIDE;
        Ok(self.read_reg(reg)? & 0xf)
    }
    /// `mpc2_update_blending` (DCN30's blend op, `dcn20_mpc.c`) on MPCC
    /// `id`: the seven `MPCC_CONTROL` fields, then the top and bottom gain
    /// registers whole. The mode field is not touched: the caller sets it
    /// when it links the MPCC into the tree.
    fn mpc_set_blend(&mut self, id: u8, cfg: &BlendConfig) -> Result<(), Error> {
        if id >= self.profile.pipes() || cfg.background_color_bpc > 7 || cfg.bottom_gain_mode > 1 {
            return Err(Error::Invalid);
        }
        let reg = self.mpcc_at(id, MPCC_CONTROL);
        self.update(
            reg,
            MPCC_ALPHA_BLND_MODE
                | MPCC_ALPHA_MULTIPLIED_MODE
                | MPCC_BLND_ACTIVE_OVERLAP_ONLY
                | MPCC_GLOBAL_ALPHA
                | MPCC_GLOBAL_GAIN
                | MPCC_BG_BPC
                | MPCC_BOT_GAIN_MODE,
            cfg.alpha_mode.code() << MPCC_ALPHA_BLND_MODE.trailing_zeros()
                | u32::from(cfg.pre_multiplied_alpha)
                    << MPCC_ALPHA_MULTIPLIED_MODE.trailing_zeros()
                | u32::from(cfg.overlap_only) << MPCC_BLND_ACTIVE_OVERLAP_ONLY.trailing_zeros()
                | u32::from(cfg.global_alpha) << MPCC_GLOBAL_ALPHA.trailing_zeros()
                | u32::from(cfg.global_gain) << MPCC_GLOBAL_GAIN.trailing_zeros()
                | cfg.background_color_bpc << MPCC_BG_BPC.trailing_zeros()
                | cfg.bottom_gain_mode << MPCC_BOT_GAIN_MODE.trailing_zeros(),
        )?;
        for (reg, value) in [
            (MPCC_TOP_GAIN, cfg.top_gain),
            (MPCC_BOT_GAIN_INSIDE, cfg.bottom_inside_gain),
            (MPCC_BOT_GAIN_OUTSIDE, cfg.bottom_outside_gain),
        ] {
            let reg = self.mpcc_at(id, reg);
            self.set(reg, value & MPCC_GAIN_MASK)?;
        }
        Ok(())
    }
    /// `mpc1_insert_plane` for this MPCC (`dcn10_mpc.c`): bind it to `dpp`
    /// on `opp`, above MPCC `above` (`Some`: on top of it, blending over
    /// it; `None`: at the bottom of the tree, or the tree's only MPCC), map
    /// its VUPDATE lock set to the OPP, and apply `blend`. The tree is
    /// walked from the output mux first, so a link that cannot be made
    /// fails before any register is written. Ownership is the caller's:
    /// this MPCC must be leased (no other tree names it), which the
    /// registers cannot prove after a firmware handoff.
    fn mpc_insert_plane(
        &mut self,
        dpp: u8,
        opp: u8,
        above: Option<u8>,
        blend: &BlendConfig,
    ) -> Result<(), Error> {
        let pipes = self.profile.pipes();
        if dpp >= pipes || opp >= pipes {
            return Err(Error::Invalid);
        }
        if let Some(a) = above {
            if a >= pipes || a == self.instance {
                return Err(Error::Invalid);
            }
        }
        // Find the link first: the mux names this MPCC when the tree is
        // empty or `above` is its head; otherwise the MPCC whose bottom
        // select names `above` (or the bottommost, for `None`) takes it.
        enum Link {
            Mux,
            Below(u8),
        }
        let head = self.mpc_tree_head(opp)?;
        let link = if head == MPCC_UNSET {
            if above.is_some() {
                return Err(Error::Invalid);
            }
            Link::Mux
        } else if head >= u32::from(pipes) {
            return Err(Error::Invalid);
        } else if Some(head as u8) == above {
            Link::Mux
        } else {
            let want = above.map_or(MPCC_UNSET, u32::from);
            let mut temp = head;
            let mut found = None;
            for _ in 0..pipes {
                let bot = self.read_reg(self.mpcc_at(temp as u8, MPCC_BOT_SEL))? & 0xf;
                if bot == want {
                    found = Some(temp as u8);
                    break;
                }
                if bot == MPCC_UNSET || bot >= u32::from(pipes) {
                    break;
                }
                temp = bot;
            }
            Link::Below(found.ok_or(Error::Invalid)?)
        };
        // This MPCC's mux: its DPP on top, `above` (or nothing) below it,
        // the OPP, the VUPDATE lock set, and the blend mode for its place.
        let (bot, mode) = match above {
            Some(a) => (u32::from(a), MPCC_BLEND_MODE_TOP_BOT_BLENDING),
            None => (MPCC_UNSET, MPCC_BLEND_MODE_TOP_LAYER_ONLY),
        };
        let reg = self.mpcc(MPCC_TOP_SEL);
        self.update(reg, 0xf, u32::from(dpp))?; // linux-lit: 0xf=MPCC0_MPCC_TOP_SEL__MPCC_TOP_SEL_MASK
        let reg = self.mpcc(MPCC_BOT_SEL);
        self.update(reg, 0xf, bot)?; // linux-lit: 0xf=MPCC0_MPCC_BOT_SEL__MPCC_BOT_SEL_MASK
        let reg = self.mpcc(MPCC_OPP_ID);
        self.update(reg, 0xf, u32::from(opp))?; // linux-lit: 0xf=MPCC0_MPCC_OPP_ID__MPCC_OPP_ID_MASK
        let reg = self.mpcc(MPCC_UPDATE_LOCK_SEL);
        // linux-lit: 0xf=MPCC0_MPCC_UPDATE_LOCK_SEL__MPCC_UPDATE_LOCK_SEL_MASK
        self.update(reg, 0xf, u32::from(opp))?;
        let reg = self.mpcc(MPCC_CONTROL);
        self.update(reg, MPCC_MODE, mode)?; // linux-lit: 0x3=MPCC0_MPCC_CONTROL__MPCC_MODE_MASK
        match link {
            Link::Mux => {
                let reg = MPC_OUT_MUX + u64::from(opp) * MPC_OUT_STRIDE;
                self.update(reg, 0xf, u32::from(self.instance))?;
                // linux-lit: 0xf=MPC_OUT0_MUX__MPC_OUT_MUX_MASK
            }
            Link::Below(temp) => {
                let reg = self.mpcc_at(temp, MPCC_BOT_SEL);
                self.update(reg, 0xf, u32::from(self.instance))?;
                if above.is_none() {
                    // The old bottom now has a bottom to blend with.
                    let reg = self.mpcc_at(temp, MPCC_CONTROL);
                    self.update(reg, MPCC_MODE, MPCC_BLEND_MODE_TOP_BOT_BLENDING)?;
                }
            }
        }
        self.mpc_set_blend(self.instance, blend)
    }
    /// `mpc1_remove_mpcc` for this MPCC (`dcn10_mpc.c`): unlink it from
    /// `opp`'s tree — the MPCC below becomes the top when it was the head,
    /// the MPCC above takes its bottom select otherwise (and stops
    /// blending when it was the bottom) — then park its mux registers. A
    /// MPCC that is not in the tree is still parked, as Linux parks a
    /// BIOS leftover on the S3-resume path.
    fn mpc_remove_plane(&mut self, opp: u8) -> Result<(), Error> {
        let pipes = self.profile.pipes();
        if opp >= pipes {
            return Err(Error::Invalid);
        }
        let me = u32::from(self.instance);
        let head = self.mpc_tree_head(opp)?;
        if head == me {
            let bot = self.read_reg(self.mpcc(MPCC_BOT_SEL))? & 0xf;
            let reg = MPC_OUT_MUX + u64::from(opp) * MPC_OUT_STRIDE;
            self.update(reg, 0xf, bot)?; // linux-lit: 0xf=MPC_OUT0_MUX__MPC_OUT_MUX_MASK
        } else if head != MPCC_UNSET && head < u32::from(pipes) {
            let mut temp = head;
            for _ in 0..pipes {
                let bot = self.read_reg(self.mpcc_at(temp as u8, MPCC_BOT_SEL))? & 0xf;
                if bot == me {
                    let my_bot = self.read_reg(self.mpcc(MPCC_BOT_SEL))? & 0xf;
                    let reg = self.mpcc_at(temp as u8, MPCC_BOT_SEL);
                    self.update(reg, 0xf, my_bot)?;
                    if my_bot == MPCC_UNSET {
                        let reg = self.mpcc_at(temp as u8, MPCC_CONTROL);
                        self.update(reg, MPCC_MODE, MPCC_BLEND_MODE_TOP_LAYER_PASSTHROUGH)?;
                    }
                    break;
                }
                if bot == MPCC_UNSET || bot >= u32::from(pipes) {
                    break;
                }
                temp = bot;
            }
        }
        for reg in [
            MPCC_TOP_SEL,
            MPCC_BOT_SEL,
            MPCC_OPP_ID,
            MPCC_UPDATE_LOCK_SEL,
        ] {
            let reg = self.mpcc(reg);
            // linux-lit: 0xf=MPCC0_MPCC_TOP_SEL__MPCC_TOP_SEL_MASK
            self.update(reg, 0xf, MPCC_UNSET)?;
        }
        Ok(())
    }
    /// Program the output formatter. Truncation and dithering stay off, so the
    /// formatter passes the plane's depth through untouched.
    fn opp_program(&mut self, encoding: Encoding, width: u32, height: u32) -> Result<(), Error> {
        if width == 0 || height == 0 || width > MAX_DIMENSION || height > MAX_DIMENSION {
            return Err(Error::Invalid);
        }
        let reg = self.opp(OPP_PIPE_CONTROL);
        self.update(reg, 1, 1)?; // linux-lit: 1=OPP_PIPE0_OPP_PIPE_CONTROL__OPP_PIPE_CLOCK_EN_MASK
        let reg = self.opp(FMT_CONTROL);
        // linux-lit: 16=FMT0_FMT_CONTROL__FMT_PIXEL_ENCODING__SHIFT
        self.update(reg, FMT_RGB_FIELDS, encoding.code() << 16)?;
        // No truncation, no spatial dither, no frame randomisation.
        let reg = self.opp(FMT_BIT_DEPTH_CONTROL);
        self.set(reg, 0)?;
        // The pattern generator's active area must match the stream, or a
        // blanked stream would paint only part of the screen.
        let reg = self.opp(DPG_DIMENSIONS);
        // linux-lit: 16=DPG0_DPG_DIMENSIONS__DPG_ACTIVE_WIDTH__SHIFT
        self.set(reg, height | width << 16)
    }
    fn opp_set_blank(&mut self, blank: bool) -> Result<(), Error> {
        if blank {
            for colour in [DPG_COLOUR_R_CR, DPG_COLOUR_G_Y, DPG_COLOUR_B_CB] {
                let reg = self.opp(colour);
                self.set(reg, 0)?;
            }
            let reg = self.opp(DPG_CONTROL);
            // linux-lit: 1=DPG0_DPG_CONTROL__DPG_EN_MASK
            // linux-lit: 4=DPG0_DPG_CONTROL__DPG_MODE__SHIFT
            // linux-lit: 12=DPG0_DPG_CONTROL__DPG_BIT_DEPTH__SHIFT
            self.set(reg, 1 | DPG_MODE_SOLID << 4 | DPG_BIT_DEPTH_8 << 12)
        } else {
            // Disabling the generator outright is how DCN2 onwards returns to
            // video, rather than selecting a passthrough pattern.
            let reg = self.opp(DPG_CONTROL);
            self.set(reg, 0)
        }
    }
}

/// One owned display pipe processor: the modeset programs its scaler in
/// bypass, [`Dpp::set_scaler`] positions and scales the plane.
#[derive(Debug)]
pub struct Dpp(Block<Mmio>, DsclCache);
impl Dpp {
    /// # Safety
    /// Caller exclusively owns this DPP instance for the object's lifetime and
    /// holds matching PCI authority and a permanent register mapping.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        instance: u8,
    ) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu)?;
        if instance >= profile.pipes() {
            return Err(Error::Invalid);
        }
        Ok(Self(
            Block {
                io: Mmio {
                    regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                    base: profile.bank(
                        gpu,
                        2, // linux-lit: 2=mmDPP_TOP0_DPP_CONTROL_BASE_IDX
                        (CM_CONTROL + u64::from(profile.pipes() - 1) * DPP_STRIDE) as u32,
                    )?,
                },
                authority,
                instance,
                profile,
            },
            DsclCache::default(),
        ))
    }
    /// The modeset's format and full-screen bypass. The DSCL cache is
    /// dropped as `dpp_reset` drops it: the pipe was just powered.
    pub fn program(&mut self, format: Format, width: u32, height: u32) -> Result<(), Error> {
        self.1 = DsclCache::default();
        self.0.dpp_program(format, width, height)
    }
    /// `dpp1_dscl_set_scaler_manual_scale` with this pipe's
    /// [`crate::amdgpu_dcn30_scl::build`] result (DCN3.0 only). The caller
    /// holds the OTG's pipe-control lock so it latches with the surface.
    pub fn set_scaler(&mut self, data: &ScalerData) -> Result<(), Error> {
        self.0.dscl_set_scaler(data, &mut self.1)
    }
}

/// The multiple-pipe/plane combiner. One MPCC takes one DPP and feeds one OPP,
/// with nothing below it to blend against — until [`Mpc::insert_plane`] links
/// it into an OPP's tree, where the mux names the topmost MPCC and each
/// MPCC's bottom select names the one below it.
#[derive(Debug)]
pub struct Mpc(Block<Mmio>);
impl Mpc {
    /// # Safety
    /// Caller exclusively owns this MPCC instance and the output mux of the OPP
    /// it feeds, and holds matching PCI authority and a permanent mapping.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        mpcc: u8,
    ) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu)?;
        if mpcc >= profile.pipes() {
            return Err(Error::Invalid);
        }
        Ok(Self(Block {
            io: Mmio {
                regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                base: profile.bank(
                    gpu,
                    3, // linux-lit: 3=mmMPCC0_MPCC_TOP_SEL_BASE_IDX
                    if profile.is_dcn30() {
                        MPC_RMU_CONTROL as u32
                    } else {
                        (MPC_OUT_MUX + u64::from(profile.pipes() - 1) * MPC_OUT_STRIDE) as u32
                    },
                )?,
            },
            authority,
            instance: mpcc,
            profile,
        }))
    }
    pub fn mux_plane(&mut self, dpp: u8, opp: u8) -> Result<(), Error> {
        self.0.mpc_mux_plane(dpp, opp)
    }
    /// `mpc1_insert_plane` for this MPCC: link it into `opp`'s tree above
    /// MPCC `above` (`Some`: the new top over it; `None`: appended at the
    /// bottom, or the tree's only MPCC), fed by `dpp`, with `blend`. The
    /// overlay path inserts the slave MPCC above the primary's, so the
    /// overlay blends over the primary and the output mux names the slave.
    pub fn insert_plane(
        &mut self,
        dpp: u8,
        opp: u8,
        above: Option<u8>,
        blend: &BlendConfig,
    ) -> Result<(), Error> {
        self.0.mpc_insert_plane(dpp, opp, above, blend)
    }
    /// `mpc1_remove_mpcc` for this MPCC: unlink it from `opp`'s tree and
    /// park its mux registers. The MPCC above it (if any) takes its bottom
    /// select, and stops blending when it was the bottom.
    pub fn remove_plane(&mut self, opp: u8) -> Result<(), Error> {
        self.0.mpc_remove_plane(opp)
    }
    /// `mpc2_update_blending` (DCN30's blend op) on this MPCC: the blend
    /// fields of `MPCC_CONTROL` and the top/bottom gain registers. The
    /// blend mode itself is the tree link's, set by [`Mpc::insert_plane`].
    pub fn set_blend(&mut self, blend: &BlendConfig) -> Result<(), Error> {
        let instance = self.0.instance;
        self.0.mpc_set_blend(instance, blend)
    }
    /// The MPCC id the OPP's output mux names, or `0xf` for an empty tree.
    pub fn tree_head(&mut self, opp: u8) -> Result<u8, Error> {
        Ok(self.0.mpc_tree_head(opp)? as u8)
    }
    /// `mpc1_set_bg_color` on this (bottommost) MPCC: the colour shown
    /// wherever the plane's recout does not cover the OPP. `rgb` is DC's
    /// 10-bit `tg_color`; MPC colour is 12-bit. `dcn20_update_mpcc` sets it
    /// from `visual_confirm_color`, all zero (black) with visual confirm
    /// off on DCN2+.
    ///
    /// LINUX-GAP: Linux's `mpc1_set_bg_color` walks to the tree's
    /// bottommost MPCC; this writes this MPCC's registers. Call it on the
    /// primary's MPCC — the bottom of an overlay tree — never the slave's.
    pub fn set_bg_color(&mut self, rgb: [u16; 3]) -> Result<(), Error> {
        self.0.mpc_set_bg_color(rgb)
    }
    /// Park the combiner so neither the DPP nor the OPP is still routed.
    pub fn release(&mut self, opp: u8) -> Result<(), Error> {
        self.0.mpc_release(opp)
    }
}

/// One owned output pixel processor. Its pattern generator is what blanks and
/// unblanks the stream.
#[derive(Debug)]
pub struct Opp {
    block: Block<Mmio>,
    blanked: bool,
}
impl Opp {
    /// # Safety
    /// Caller exclusively owns this OPP instance for the object's lifetime and
    /// holds matching PCI authority and a permanent register mapping.
    pub unsafe fn new(
        gpu: &AmdGpu,
        authority: Cap<BusDeviceCap, Write>,
        instance: u8,
    ) -> Result<Self, Error> {
        let profile = Profile::resolve(gpu)?;
        if instance >= profile.pipes() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            block: Block {
                io: Mmio {
                    regs: crate::amdgpu_reg_window::Window::new(gpu.regs),
                    base: profile.bank(
                        gpu,
                        2, // linux-lit: 2=mmOPP_PIPE0_OPP_PIPE_CONTROL_BASE_IDX
                        // linux-ctx: reset
                        (OPP_PIPE_CONTROL + u64::from(profile.pipes() - 1) * OPP_STRIDE) as u32,
                    )?,
                },
                authority,
                instance,
                profile,
            },
            blanked: true,
        })
    }
    pub fn blanked(&self) -> bool {
        self.blanked
    }
    pub fn program(&mut self, encoding: Encoding, width: u32, height: u32) -> Result<(), Error> {
        self.block.opp_program(encoding, width, height)
    }
    /// Blank the stream by painting the pattern generator black over the whole
    /// active area, or unblank by disabling it so real pixels pass through.
    pub fn set_blank(&mut self, blank: bool) -> Result<(), Error> {
        self.block.opp_set_blank(blank)?;
        self.blanked = blank;
        Ok(())
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn_plane_tests.rs"]
mod tests;

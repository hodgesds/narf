//! Native DCN30 CRTC color management on a scanout's DPP and MPCC, as
//! amdgpu_dm maps DRM's CRTC properties on DCN 3.0 and dcn30_program_pipe
//! programs them:
//! - dcn30_program_gamut_remap: the CTM in MPCC_OGAM_GAMUT_REMAP
//!   (mpc3_set_gamut_remap: the coefficient set not in use, then that set
//!   and the coefficient format). No MCM remap is programmed here: no
//!   grounded DCN30 offsets exist for the MCM gamut registers in this
//!   tree, and the firmware default is bypass (the modeset's mux already
//!   bypasses the stream gamut remap, and no Navi22 path enables an MCM
//!   remap).
//! - dcn30_set_input_transfer_func: the CRTC DEGAMMA_LUT as distributed
//!   points in the GAMCOR (mod_color_calculate_degamma_params for tf
//!   LINEAR with a GAMMA_CUSTOM ramp: the linear curve through the ramp),
//!   else legacy gamma's implicit degamma through the PRE_DEGAM sRGB ROM
//!   (map_crtc_degamma_to_dc_plane's TF_TYPE_PREDEFINED input; Navi22's
//!   planes are RGB32 only, so the NV12 BT.709 arm never applies), else
//!   bypass; CM enabled.
//! - dcn30_set_output_transfer_func -> mpc3_set_output_gamma: GAMMA_LUT's
//!   PWL into the OGAM RAM bank not in use (mpc3_program_luta/b and
//!   mpc3_program_ogam_pwl), then that bank selected; bypass without one.
//!
//! DCN30 is DCN 4.0.1's older sibling, not its twin: DCN30 publishes a
//! 4096-entry DEGAMMA_LUT (`drm_crtc_enable_color_mgmt(crtc, 4096, true,
//! 4096)`: dcn30_resource.c's `dc->caps.color.dpp.dcn_arch = 1` with
//! `dce_version != DCN_VERSION_4_01`), where DCN 4.0.1 publishes none.
//! The register bases and field masks below are DCN30's own, from
//! `dcn_3_0_0_offset.h` / `dcn_3_0_0_sh_mask.h`; the programming
//! sequences are the reviewed DCN401 port's (the same shared dpp3/mpc3
//! functions: `dpp3_set_pre_degam`, `dpp3_program_gamcor_lut`,
//! `mpc3_set_gamut_remap`, `mpc3_set_output_gamma`).
//!
//! The scanout starts in bypass; a live update reprograms the DPP and
//! MPCC at once under the display owner, so the double-buffered
//! selections latch together at one VUPDATE.
use alloc::sync::Arc;

/// The OGAM (or GAMCOR) PWL of a LUT, as cm3_helper_translate_curve_to_hw_format
/// (or _to_degamma_hw_format) and cm_helper_program_gamcor_xfer_func give
/// its register words. Channel arrays are blue, green, red (the RAM's
/// register order); `lut` holds the red, green and blue LUT_DATA words of
/// every hardware point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OgamProgram {
    /// RAMx_START_CNTL: EXP_REGION_START with START_SEGMENT 0.
    pub start: [u32; 3],
    /// RAMx_START_SLOPE_CNTL: EXP_REGION_START_SLOPE.
    pub start_slope: [u32; 3],
    /// RAMx_END_CNTL1: EXP_REGION_END_BASE.
    pub end_base: [u32; 3],
    /// RAMx_END_CNTL2: EXP_REGION_END_SLOPE and EXP_REGION_END.
    pub end: [u32; 3],
    /// RAMx_REGION_0_1 .. RAMx_REGION_32_33.
    pub regions: [u32; 17],
    pub lut: [alloc::vec::Vec<u32>; 3],
}
/// The CTM as mpc3_set_gamut_remap converts it: the six C11_C12..C33_C34
/// words and S3.12 (else S2.13) coefficients.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GamutProgram {
    pub coef: [u32; 6],
    pub s3_12: bool,
}
/// What a display's CRTC color properties program. `Default` is amdgpu_dm's
/// bypass: no gamut remap, no implicit degamma, no regamma.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ColorProgram {
    /// TF_TYPE_PREDEFINED sRGB input (legacy 256-entry gamma, no explicit
    /// degamma): the PRE_DEGAM sRGB ROM linearizes for the sRGB-based
    /// legacy regamma.
    pub pre_degam_srgb: bool,
    /// A non-linear 4096-entry DEGAMMA_LUT: the GAMCOR PWL of its
    /// distributed points. A linear one, like none, bypasses the GAMCOR.
    pub degamma: Option<OgamProgram>,
    pub gamut: Option<GamutProgram>,
    pub ogam: Option<OgamProgram>,
}
/// dpp3_set_pre_degam's choice on a Navi22 DPP: the predefined degamma ROM
/// for a TF_TYPE_PREDEFINED input transfer function, or bypass. Only sRGB
/// occurs: the planes are RGB32, so map_crtc_degamma_to_dc_plane's NV12
/// BT.709 arm never applies.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PreDegam {
    /// TRANSFER_FUNCTION_LINEAR / UNITY (and any unlisted function).
    #[default]
    Bypass,
    /// TRANSFER_FUNCTION_SRGB: PRE_DEGAM_SELECT 0.
    Srgb,
}
impl PreDegam {
    /// CNVC_CFG PRE_DEGAM (mask 0x73): PRE_DEGAM_MODE 1 with the ROM's
    /// PRE_DEGAM_SELECT, or 0 for bypass (dpp3_set_pre_degam's REG_SET_2).
    pub const fn word(self) -> u32 {
        match self {
            Self::Bypass => 0,
            Self::Srgb => 1,
        }
    }
}

impl ColorProgram {
    /// What amdgpu_dm makes of a CRTC's committed CTM, DEGAMMA_LUT and
    /// GAMMA_LUT blobs on DCN 3.0
    /// (amdgpu_dm_update_crtc_color_mgmt, amdgpu_dm_update_plane_color_mgmt):
    /// - a 4096-entry DEGAMMA_LUT that is not linear is the plane's
    ///   in_transfer_func (map_crtc_degamma_to_dc_plane's cm_has_degamma:
    ///   TF_TYPE_DISTRIBUTED_POINTS through __set_input_tf), a linear one
    ///   like none bypasses the GAMCOR;
    /// - a 256-entry GAMMA_LUT is legacy gamma: __set_legacy_tf's sRGB-based
    ///   regamma, its input linearized by the plane's predefined sRGB
    ///   in_transfer_func (cm_is_degamma_srgb) when no explicit degamma
    ///   replaces it;
    /// - a 4096-entry GAMMA_LUT is amdgpu_dm_set_atomic_regamma's
    ///   distributed points (__set_output_tf on a linear base) unless
    ///   __is_lut_linear, which, like no GAMMA_LUT, bypasses the OGAM;
    /// - a CTM is the stream's gamut remap (__drm_ctm_to_dc_matrix,
    ///   enable_remap), whatever its values.
    ///
    /// None for blobs of another size, which the DRM bridge refuses first.
    pub fn from_crtc(
        ctm: Option<&[u8]>,
        degamma_lut: Option<&[u8]>,
        gamma_lut: Option<&[u8]>,
    ) -> Option<Self> {
        use crate::amdgpu_dcn_color as cm;
        let gamut = match ctm {
            Some(blob) => {
                let remap = cm::gamut_remap(&cm::ctm_matrix(&cm::ctm_from_bytes(blob)?));
                Some(GamutProgram {
                    coef: remap.words(),
                    s3_12: remap.s3_12,
                })
            }
            None => None,
        };
        let degamma = match degamma_lut {
            None => None,
            Some(blob) => {
                let lut = cm::DrmColorLut::from_bytes(blob)?;
                if lut.len() != cm::MAX_COLOR_LUT_ENTRIES {
                    return None;
                }
                if cm::is_lut_linear(&lut) {
                    None
                } else {
                    Some(OgamProgram::from_pwl(&*cm::degamma_pwl(&lut)?))
                }
            }
        };
        let (pre_degam_srgb, ogam) = match gamma_lut {
            None => (false, None),
            Some(blob) => {
                let lut = cm::DrmColorLut::from_bytes(blob)?;
                let legacy = match lut.len() {
                    cm::MAX_COLOR_LEGACY_LUT_ENTRIES => true,
                    cm::MAX_COLOR_LUT_ENTRIES => false,
                    _ => return None,
                };
                if !legacy && cm::is_lut_linear(&lut) {
                    (false, None)
                } else {
                    let pwl: alloc::boxed::Box<cm::Pwl> = cm::regamma_pwl(&lut)?;
                    // The explicit degamma replaces the implicit sRGB ROM
                    // (map_crtc_degamma_to_dc_plane: cm_has_degamma takes
                    // the plane's in_transfer_func); without it, legacy
                    // gamma linearizes through the ROM.
                    (
                        legacy && degamma.is_none(),
                        Some(OgamProgram::from_pwl(&pwl)),
                    )
                }
            }
        };
        Some(Self {
            pre_degam_srgb,
            degamma,
            gamut,
            ogam,
        })
    }
}
impl OgamProgram {
    /// The register words cm_helper_program_gamcor_xfer_func and
    /// mpc3_program_ogam_pwl write for `pwl`.
    pub fn from_pwl(pwl: &crate::amdgpu_dcn_color::Pwl) -> Self {
        let regs = pwl.registers();
        let words = |v: &[u32]| v.iter().map(|w| w & 0x3ffff).collect();
        Self {
            start: regs.start_cntl,
            start_slope: regs.start_slope_cntl,
            end_base: regs.end_cntl1,
            end: regs.end_cntl2,
            regions: regs.region,
            lut: [
                words(&pwl.red_reg),
                words(&pwl.green_reg),
                words(&pwl.blue_reg),
            ],
        }
    }
}

/// Whether two CRTC color records program the same.
pub fn same_program(a: &Option<Arc<ColorProgram>>, b: &Option<Arc<ColorProgram>>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => Arc::ptr_eq(a, b) || **a == **b,
        (None, None) => true,
        _ => false,
    }
}

#[cfg(feature = "kernel-test")]
#[path = "amdgpu_dcn30_color_tests.rs"]
mod tests;

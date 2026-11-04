//! DRM's VESA DSC helpers (`drivers/gpu/drm/display/drm_dsc_helper.c`,
//! Linux b90c984d), shared by the AMD DCN and Intel VDSC paths:
//!
//! - [`Pps`] is `struct drm_dsc_config`;
//! - [`compute_rc_parameters`] is `drm_dsc_compute_rc_parameters`;
//! - [`pack_pps`] is `drm_dsc_pps_payload_pack`;
//! - [`set_rc_buf_thresh`] is `drm_dsc_set_rc_buf_thresh`;
//! - [`dp_pps_header`] is `drm_dsc_dp_pps_header_init`.
//!
//! Each driver keeps its own rate-control model (AMD's `rc_calc_fpu.c`,
//! Intel's `intel_vdsc.c::calculate_rc_params`).

/// `DSC_RC_MODEL_SIZE_CONST`.
pub const RC_MODEL_SIZE_CONST: u16 = 8192;
/// `DSC_RC_EDGE_FACTOR_CONST`.
pub const RC_EDGE_FACTOR_CONST: u8 = 6;
/// `DSC_RC_TGT_OFFSET_HI_CONST`.
pub const RC_TGT_OFFSET_HI_CONST: u8 = 3;
/// `DSC_RC_TGT_OFFSET_LO_CONST`.
pub const RC_TGT_OFFSET_LO_CONST: u8 = 3;
/// `DSC_MUX_WORD_SIZE_8_10_BPC`.
pub const MUX_WORD_SIZE_8_10_BPC: u8 = 48;
/// `DSC_MUX_WORD_SIZE_12_BPC`.
pub const MUX_WORD_SIZE_12_BPC: u8 = 64;
/// `DSC_NUM_BUF_RANGES`.
pub const NUM_BUF_RANGES: usize = 15;
/// `DSC_RANGE_BPG_OFFSET_MASK`.
pub const RANGE_BPG_OFFSET_MASK: u8 = 0x3f;
/// `DP_SDP_PPS`.
pub const DP_SDP_PPS: u8 = 0x10;
/// `DP_SDP_PPS_HEADER_PAYLOAD_BYTES_MINUS_1`.
pub const DP_SDP_PPS_HEADER_PAYLOAD_BYTES_MINUS_1: u8 = 0x7f;

/// `drm_dsc_rc_buf_thresh` (DSC 1.1, constant across operation modes).
const RC_BUF_THRESH: [u16; 14] = [
    896, 1792, 2688, 3584, 4480, 5376, 6272, 6720, 7168, 7616, 7744, 7872, 8000, 8064,
];

/// drm_dsc_config: the PPS and the rate-control model behind it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Pps {
    pub line_buf_depth: u8,
    pub bits_per_component: u8,
    pub convert_rgb: bool,
    pub slice_width: u16,
    pub slice_height: u16,
    pub simple_422: bool,
    pub pic_width: u16,
    pub pic_height: u16,
    pub rc_tgt_offset_high: u8,
    pub rc_tgt_offset_low: u8,
    pub bits_per_pixel: u16,
    pub rc_edge_factor: u8,
    pub rc_quant_incr_limit1: u8,
    pub rc_quant_incr_limit0: u8,
    pub initial_xmit_delay: u16,
    pub initial_dec_delay: u16,
    pub block_pred_enable: bool,
    pub first_line_bpg_offset: u8,
    pub initial_offset: u16,
    /// As the registers take them (the model's thresholds / 64).
    pub rc_buf_thresh: [u16; 14],
    /// (min QP, max QP, 6-bit BPG offset).
    pub rc_range_params: [(u8, u8, u8); 15],
    pub rc_model_size: u16,
    pub flatness_min_qp: u8,
    pub flatness_max_qp: u8,
    pub initial_scale_value: u8,
    pub scale_decrement_interval: u16,
    pub scale_increment_interval: u16,
    pub nfl_bpg_offset: u16,
    pub slice_bpg_offset: u16,
    pub final_offset: u16,
    pub vbr_enable: bool,
    pub mux_word_size: u8,
    pub slice_chunk_size: u16,
    pub rc_bits: u16,
    pub dsc_version_minor: u8,
    pub dsc_version_major: u8,
    pub native_422: bool,
    pub native_420: bool,
    pub second_line_bpg_offset: u8,
    pub nsl_bpg_offset: u16,
    pub second_line_offset_adj: u16,
}

/// drm_dsc_compute_rc_parameters. None for -ERANGE.
pub fn compute_rc_parameters(c: &mut Pps) -> Option<()> {
    let native = c.native_420 || c.native_422;
    let width = u64::from(c.slice_width) / if native { 2 } else { 1 };
    let bpp = u64::from(c.bits_per_pixel);
    let groups_per_line = width.div_ceil(3);
    c.slice_chunk_size = (width * bpp).div_ceil(8 * 16) as u16;
    let mux = u64::from(c.mux_word_size);
    let bpc4 = 4 * u64::from(c.bits_per_component);
    let mut extra_mux_bits = if c.convert_rgb {
        3 * (mux + bpc4 + 4 - 2)
    } else if c.native_422 {
        4 * mux + (bpc4 + 4) + 3 * bpc4 - 2
    } else {
        3 * mux + (bpc4 + 4) + 2 * bpc4 - 2
    };
    let slice_bits = 8 * u64::from(c.slice_chunk_size) * u64::from(c.slice_height);
    while extra_mux_bits > 0 && slice_bits.wrapping_sub(extra_mux_bits) % mux != 0 {
        extra_mux_bits -= 1;
    }
    // groups_per_line < initial_scale_value - 8, an int compared as unsigned
    // long.
    let scale = i64::from(c.initial_scale_value) - 8;
    if (groups_per_line as i64) < scale || scale < 0 {
        c.initial_scale_value = (groups_per_line + 8) as u8;
    }
    c.scale_decrement_interval = if c.initial_scale_value > 8 {
        (groups_per_line / (u64::from(c.initial_scale_value) - 8)) as u16
    } else {
        4095
    };
    let model = u64::from(c.rc_model_size);
    c.final_offset = model
        .wrapping_sub((u64::from(c.initial_xmit_delay) * bpp + 8) / 16)
        .wrapping_add(extra_mux_bits) as u16;
    if c.final_offset >= c.rc_model_size {
        return None;
    }
    let final_scale = (model * 8) / (model - u64::from(c.final_offset));
    c.nfl_bpg_offset = if c.slice_height > 1 {
        (u64::from(c.first_line_bpg_offset) << 11).div_ceil(u64::from(c.slice_height) - 1) as u16
    } else {
        0
    };
    let groups_total = groups_per_line * u64::from(c.slice_height);
    c.slice_bpg_offset = ((model - u64::from(c.initial_offset) + extra_mux_bits) << 11)
        .div_ceil(groups_total) as u16;
    c.scale_increment_interval = if final_scale > 9 {
        ((u64::from(c.final_offset) << 11)
            / ((u64::from(c.nfl_bpg_offset) + u64::from(c.slice_bpg_offset)) * (final_scale - 9)))
            as u16
    } else {
        0
    };
    let rbs_min = model - u64::from(c.initial_offset)
        + (u64::from(c.initial_xmit_delay) * bpp).div_ceil(16)
        + groups_per_line * u64::from(c.first_line_bpg_offset);
    let hrd_delay = (rbs_min * 16).div_ceil(bpp);
    c.rc_bits = (hrd_delay * bpp / 16) as u16;
    c.initial_dec_delay = (hrd_delay - u64::from(c.initial_xmit_delay)) as u16;
    Some(())
}

/// drm_dsc_pps_payload_pack: the 128-byte PPS the sink receives.
pub fn pack_pps(c: &Pps) -> [u8; 128] {
    let mut p = [0u8; 128];
    let be = |p: &mut [u8; 128], at: usize, v: u16| p[at..at + 2].copy_from_slice(&v.to_be_bytes());
    p[0] = c.dsc_version_minor | c.dsc_version_major << 4;
    p[3] = c.line_buf_depth | c.bits_per_component << 4;
    p[4] = ((c.bits_per_pixel & 0x300) >> 8) as u8
        | u8::from(c.vbr_enable) << 2
        | u8::from(c.simple_422) << 3
        | u8::from(c.convert_rgb) << 4
        | u8::from(c.block_pred_enable) << 5;
    p[5] = c.bits_per_pixel as u8;
    be(&mut p, 6, c.pic_height);
    be(&mut p, 8, c.pic_width);
    be(&mut p, 10, c.slice_height);
    be(&mut p, 12, c.slice_width);
    be(&mut p, 14, c.slice_chunk_size);
    p[16] = ((c.initial_xmit_delay & 0x300) >> 8) as u8;
    p[17] = c.initial_xmit_delay as u8;
    be(&mut p, 18, c.initial_dec_delay);
    p[21] = c.initial_scale_value;
    be(&mut p, 22, c.scale_increment_interval);
    p[24] = ((c.scale_decrement_interval & 0xf00) >> 8) as u8;
    p[25] = c.scale_decrement_interval as u8;
    p[27] = c.first_line_bpg_offset;
    be(&mut p, 28, c.nfl_bpg_offset);
    be(&mut p, 30, c.slice_bpg_offset);
    be(&mut p, 32, c.initial_offset);
    be(&mut p, 34, c.final_offset);
    p[36] = c.flatness_min_qp;
    p[37] = c.flatness_max_qp;
    be(&mut p, 38, c.rc_model_size);
    // DSC_RC_EDGE_FACTOR_CONST and the target offset constants.
    p[40] = 6;
    p[41] = c.rc_quant_incr_limit0;
    p[42] = c.rc_quant_incr_limit1;
    p[43] = 3 | 3 << 4;
    for (i, &th) in c.rc_buf_thresh.iter().enumerate() {
        p[44 + i] = th as u8;
    }
    for (i, &(min, max, ofs)) in c.rc_range_params.iter().enumerate() {
        be(
            &mut p,
            58 + 2 * i,
            u16::from(min) << 11 | u16::from(max) << 6 | u16::from(ofs),
        );
    }
    p[88] = u8::from(c.native_422) | u8::from(c.native_420) << 1;
    p[89] = c.second_line_bpg_offset;
    be(&mut p, 90, c.nsl_bpg_offset);
    be(&mut p, 92, c.second_line_offset_adj);
    p
}

/// `drm_dsc_set_rc_buf_thresh`: the RC model thresholds as the PPS carries
/// them (each >> 6), with the C model's 6 bpp thresholds 12 and 13.
pub fn set_rc_buf_thresh(c: &mut Pps) {
    for (dst, &th) in c.rc_buf_thresh.iter_mut().zip(RC_BUF_THRESH.iter()) {
        *dst = th >> 6;
    }
    if c.bits_per_pixel == 6 << 4 {
        c.rc_buf_thresh[12] = 7936 >> 6;
        c.rc_buf_thresh[13] = 8000 >> 6;
    }
}

/// `drm_dsc_dp_pps_header_init`: the DP SDP header (HB0..HB3) of a PPS.
pub const fn dp_pps_header() -> [u8; 4] {
    [0, DP_SDP_PPS, DP_SDP_PPS_HEADER_PAYLOAD_BYTES_MINUS_1, 0]
}

#[cfg(feature = "kernel-test")]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_drm_dsc_rc_buf_thresh_and_pps_sdp_header() -> TestResult {
        // drm_dsc_set_rc_buf_thresh: each DSC 1.1 threshold >> 6; at 6 bpp
        // the C model's 7936 and 8000 replace thresholds 12 and 13.
        let mut c = Pps {
            bits_per_pixel: 8 << 4,
            ..Pps::default()
        };
        set_rc_buf_thresh(&mut c);
        if c.rc_buf_thresh
            != [
                14, 28, 42, 56, 70, 84, 98, 105, 112, 119, 121, 123, 125, 126,
            ]
        {
            return TestResult::Fail("thresholds must be drm_dsc_rc_buf_thresh >> 6");
        }
        c.bits_per_pixel = 6 << 4;
        set_rc_buf_thresh(&mut c);
        if c.rc_buf_thresh[11..] != [123, 124, 125] {
            return TestResult::Fail("6 bpp takes 7936 >> 6 and 8000 >> 6");
        }
        // drm_dsc_dp_pps_header_init: HB1 DP_SDP_PPS, HB2 127.
        if dp_pps_header() != [0x00, 0x10, 0x7f, 0x00] {
            return TestResult::Fail("the PPS SDP header is HB1 0x10, HB2 0x7f");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/drm_dsc",
        smoke_drm_dsc_rc_buf_thresh_and_pps_sdp_header
    );
}

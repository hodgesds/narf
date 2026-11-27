//! Native fixtures for the display-14+ deep colour and YCbCr 4:4:4 helpers
//! (`narf.intel.hdmi14_ext`). Every value is derived from Linux 7.4
//! (`drm_edid.c`, `intel_display.c`, `intel_hdmi.c`, `intel_ddi.c`,
//! `intel_dp.c`, `drm_dp_helper.c`), not recorded from this code.
extern crate alloc;

use super::*;
use crate::intel_gpu_xelpg_dsc as dsc;
use alloc::vec::Vec;
use narf_kernel_test::{kernel_test_in, TestResult};

/// A base EDID block of `revision` with the video input byte `input`, plus
/// one CTA-861 revision 3 extension whose data block collection is
/// `blocks`, checksums valid.
pub(crate) fn edid_with(revision: u8, input: u8, blocks: &[u8]) -> Vec<u8> {
    let mut e = crate::intel_gpu_xelpg_external::tests::edid_for(
        148_500, 1920, 280, 88, 44, 1080, 45, 4, 5,
    );
    e[19] = revision;
    e[20] = input;
    with_cta(e, blocks)
}

/// `base` (one block) plus a CTA-861 revision 3 extension whose data block
/// collection is `blocks`, checksums valid.
pub(crate) fn with_cta(mut e: Vec<u8>, blocks: &[u8]) -> Vec<u8> {
    fn checksum(block: &mut [u8]) {
        let sum: u32 = block[..127].iter().map(|&b| u32::from(b)).sum();
        block[127] = ((256 - sum % 256) % 256) as u8;
    }
    e[126] = 1;
    checksum(&mut e[..128]);
    let mut ext = alloc::vec![0u8; 128];
    ext[0] = 0x02;
    ext[1] = 0x03;
    ext[2] = (4 + blocks.len()) as u8;
    ext[4..4 + blocks.len()].copy_from_slice(blocks);
    checksum(&mut ext);
    e.extend_from_slice(&ext);
    e
}

/// An HDMI VSDB (`cea_db_is_hdmi_vsdb`) with payload 7: physical address
/// 1.0.0.0, byte 6 `flags` (`DRM_EDID_HDMI_DC_*`), byte 7 the max TMDS
/// clock in 5 MHz units.
pub(crate) fn hdmi_vsdb(flags: u8, max_tmds: u8) -> [u8; 8] {
    [(3 << 5) | 7, 0x03, 0x0C, 0x00, 0x10, 0x00, flags, max_tmds]
}

/// `drm_parse_hdmi_deep_color_info` and `update_display_info`: the VSDB's
/// DC flags give an EDID 1.3 digital sink its bpc, EDID 1.4's depth field
/// replaces it, an analog input parses no CTA at all; then
/// `compute_sink_pipe_bpp`'s pipe maximum.
fn smoke_xelpg_deep_colour_display_bpc() -> TestResult {
    // DC_30 alone: 10; DC_36: 12; DC_48 last: 16; a 5-byte payload: 8.
    let short = [(3 << 5) | 5, 0x03, 0x0C, 0x00, 0x10, 0x00];
    for (blocks, bpc) in [
        (&hdmi_vsdb(0x10, 0)[..], 10u8),
        (&hdmi_vsdb(0x30, 0)[..], 12),
        (&hdmi_vsdb(0x70, 0)[..], 16),
        (&hdmi_vsdb(0x00, 0)[..], 8),
        (&short[..], 8),
        (&[(2 << 5) | 1, 16][..], 0),
    ] {
        if hdmi_vsdb_bpc(&edid_with(3, 0x80, blocks)) != bpc {
            return TestResult::Fail("HDMI VSDB deep colour differs from drm_edid");
        }
    }
    let dc36 = hdmi_vsdb(0x30, 0);
    for (revision, input, bpc) in [
        // EDID 1.3 digital: the VSDB's 12 bpc.
        (3, 0x80, 12u8),
        // EDID 1.4 digital, depth 8 / 10 / undefined: the depth field wins.
        (4, 0x80 | (2 << 4), 8),
        (4, 0x80 | (3 << 4), 10),
        (4, 0x80, 0),
        // Analog: no CTA parse, no depth.
        (3, 0x00, 0),
    ] {
        if sink_display_bpc(&edid_with(revision, input, &dc36)) != bpc {
            return TestResult::Fail("display_info.bpc differs from update_display_info");
        }
    }
    // bpc_to_bpp of min(bpc ?: 8, 12).
    for (display_bpc, bpp) in [(0u8, 24u32), (6, 18), (8, 24), (10, 30), (12, 36), (16, 36)] {
        if max_pipe_bpp(display_bpc) != bpp {
            return TestResult::Fail("compute_sink_pipe_bpp differs from Linux");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_color",
    smoke_xelpg_deep_colour_display_bpc
);

/// The deep-colour register encodings (`bdw_set_pipe_misc`,
/// `intel_ddi_transcoder_func_reg_val_get`, `intel_ddi_set_dp_msa`) and
/// the HDMI depth and clock admission (`intel_hdmi_sink_bpc_possible`,
/// `hdmi_port_clock_limit`, `hdmi_port_clock_valid`).
fn smoke_xelpg_deep_colour_encodings_and_admission() -> TestResult {
    use crate::intel_gpu_hdmi::{parse_hdmi_vsdb, SinkFormat, Ycbcr420Caps};
    // PIPE_MISC: BPC_10 = 1 << 5, BPC_12_ADLP = 4 << 5, with
    // PIXEL_ROUNDING_TRUNC (bit 8); TRANS_DDI_BPC_10 = 1 << 20, _12 =
    // 3 << 20; DP_MSA_MISC_10_BPC = 2 << 5, _12_BPC = 3 << 5 with
    // SYNC_CLOCK.
    if dsc::pipe_misc(30) != 0x120
        || dsc::pipe_misc(36) != 0x180
        || dsc::pipe_misc(24) != 0x100
        || dsc::trans_ddi_bpc(30) != 1 << 20
        || dsc::trans_ddi_bpc(36) != 3 << 20
        || dsc::msa_misc(30) != 0x41
        || dsc::msa_misc(36) != 0x61
        || dsc::msa_misc(24) != 0x21
    {
        return TestResult::Fail("deep colour register encodings differ from Linux");
    }
    let edid = edid_with(3, 0x80, &hdmi_vsdb(0x10, 0));
    let vsdb = parse_hdmi_vsdb(&edid);
    let mut y420 = Ycbcr420Caps::default();
    if !sink_bpc_possible(10, vsdb, &y420, SinkFormat::Rgb)
        || sink_bpc_possible(12, vsdb, &y420, SinkFormat::Rgb)
        || sink_bpc_possible(10, vsdb, &y420, SinkFormat::Ycbcr420)
        || sink_bpc_possible(10, None, &y420, SinkFormat::Rgb)
        || !sink_bpc_possible(8, None, &y420, SinkFormat::Rgb)
    {
        return TestResult::Fail("intel_hdmi_sink_bpc_possible differs from Linux");
    }
    y420.dc_36 = true;
    if !sink_bpc_possible(12, vsdb, &y420, SinkFormat::Ycbcr420) {
        return TestResult::Fail("4:2:0 deep colour takes the HF-VSDB flags");
    }
    // The VSDB's max TMDS byte (5 MHz units) bounds the source's 600 MHz;
    // a DVI sink is 165 MHz.
    if hdmi_port_clock_limit(&edid) != 600_000
        || hdmi_port_clock_limit(&edid_with(3, 0x80, &hdmi_vsdb(0x10, 45))) != 225_000
        || hdmi_port_clock_limit(&edid_with(3, 0x80, &[(2 << 5) | 1, 16])) != 165_000
    {
        return TestResult::Fail("hdmi_port_clock_limit differs from Linux");
    }
    // The Type-C PLL hole (500, 532.8) MHz; DDI B has none on display 14+.
    if hdmi_port_clock_valid(510_000, 600_000, true)
        || !hdmi_port_clock_valid(510_000, 600_000, false)
        || !hdmi_port_clock_valid(532_800, 600_000, true)
        || hdmi_port_clock_valid(24_999, 600_000, false)
        || hdmi_port_clock_valid(225_001, 225_000, false)
    {
        return TestResult::Fail("hdmi_port_clock_valid differs from Linux");
    }
    // intel_dp_compute_link_config_wide above 24 bpp: 1080p60 on HBR2 x4
    // carries 36 bpp; the 8 bpc search stops at 24.
    let limits = dsc::LinkLimits::standard(540_000, 4);
    let mode = crate::intel_gpu_modeset::Mode {
        pixel_clock_khz: 148_500,
        h_active: 1920,
        h_sync_start: 2008,
        h_sync_end: 2052,
        h_total: 2200,
        v_active: 1080,
        v_sync_start: 1084,
        v_sync_end: 1089,
        v_total: 1125,
        ..crate::intel_gpu_modeset::Mode::VESA_1024X768_60
    };
    match (
        dsc::uncompressed_link_upto(&limits, &mode, 36),
        dsc::uncompressed_link(&limits, &mode, 36),
    ) {
        (Some(deep), Some(eight)) if deep.pipe_bpp == 36 && eight.pipe_bpp == 24 => {}
        _ => return TestResult::Fail("the deep link search must start at 36 bpp"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_color",
    smoke_xelpg_deep_colour_encodings_and_admission
);

/// The HDMI VSDB without deep colour (payload 5) and a Y420VDB naming
/// VIC 97 (3840x2160@60): a 4:2:0-only 4K60 HDMI sink.
pub(crate) const HDMI_420_ONLY_BLOCKS: [u8; 9] = [
    (3 << 5) | 5,
    0x03,
    0x0C,
    0x00,
    0x10,
    0x00,
    (7 << 5) | 2,
    0x0E,
    97,
];

/// A 4K60 (CTA VIC 97 timing) EDID 1.4 sink whose CTA extension carries
/// `blocks`.
pub(crate) fn edid_4k60_with(blocks: &[u8]) -> Vec<u8> {
    with_cta(
        crate::intel_gpu_xelpg_external::tests::edid_for(
            594_000, 3840, 560, 176, 88, 2160, 90, 8, 10,
        ),
        blocks,
    )
}

/// `drm_dp_downstream_420_passthrough` / `_444_to_420_conversion` /
/// `_rgb_to_ycbcr_conversion`, then `intel_dp_compute_formats`,
/// `intel_dp_output_format` (RGB, YCbCr 4:4:4 into a converting PCON, or
/// YCbCr 4:2:0 on the link) and `intel_dp_configure_protocol_converter`'s
/// decisions, and `intel_ddi_set_dp_msa`'s 4:4:4 colorimetry.
fn smoke_xelpg_dp_ycbcr444_output_format() -> TestResult {
    // DPCD 1.4 branch with detailed downstream capabilities; DFP 0 HDMI.
    let mut dpcd = [0u8; 16];
    dpcd[0] = 0x14;
    dpcd[DP_DOWNSTREAMPORT_PRESENT] = 0x11;
    let hdmi = |byte3: u8| [3u8, 0, 0, byte3];
    if dfp_caps(&dpcd, &hdmi(0x54))
        != (DfpCaps {
            ycbcr420_passthrough: true,
            ycbcr_444_to_420: true,
            rgb_to_ycbcr: true,
        })
        || !dfp_caps(&dpcd, &[0, 0, 0, 0]).ycbcr420_passthrough
        || dfp_caps(&[0x12, 0, 0, 0, 0, 0x11], &hdmi(0x54)) != DfpCaps::default()
        || dfp_caps(&[0x14, 0, 0, 0, 0, 0x01], &hdmi(0x54)) != DfpCaps::default()
        || dfp_caps(&[0x14, 0, 0, 0, 0, 0x10], &hdmi(0x54)) != DfpCaps::default()
    {
        return TestResult::Fail("the drm_dp_downstream_* conversion facts differ");
    }
    let edid = edid_4k60_with(&HDMI_420_ONLY_BLOCKS);
    let Ok(mode) = crate::intel_gpu_dp::mode_from_edid(&edid) else {
        return TestResult::Fail("the 4K60 EDID must give its preferred mode");
    };
    // An HDMI DFP: drm_dp_downstream_min_tmds_clock is 25 MHz.
    let output = |dpcd: &[u8], byte3: u8, edid: &[u8]| {
        let min_tmds = if dp_is_branch(dpcd) { 25_000 } else { 0 };
        dp_output(dpcd, dfp_caps(dpcd, &hdmi(byte3)), min_tmds, edid, &mode)
    };
    // 4:4:4->4:2:0 only: the pipe drives YCbCr 4:4:4, the PCON converts.
    if output(&dpcd, 0x10, &edid)
        != (DpOutput {
            ycbcr444: true,
            pcon: Some(PconConfig {
                hdmi_sink: true,
                ycbcr444_to_420: true,
                rgb_to_ycbcr: false,
            }),
            ..DpOutput::default()
        })
    {
        return TestResult::Fail("a 4:4:4->4:2:0 PCON must take a YCbCr 4:4:4 pipe");
    }
    // RGB->YCbCr and 4:4:4->4:2:0: RGB out, both conversions on.
    if output(&dpcd, 0x50, &edid)
        != (DpOutput {
            pcon: Some(PconConfig {
                hdmi_sink: true,
                ycbcr444_to_420: true,
                rgb_to_ycbcr: true,
            }),
            ..DpOutput::default()
        })
    {
        return TestResult::Fail("an RGB->YCbCr PCON must keep the pipe RGB");
    }
    // A passthrough DFP or a native sink: YCbCr 4:2:0 on the DP link
    // (intel_dp_output_format's last case); the PCON converts nothing.
    let native = [0x14u8, 0, 0, 0, 0, 0];
    if output(&dpcd, 0x04, &edid)
        != (DpOutput {
            ycbcr420: true,
            pcon: Some(PconConfig {
                hdmi_sink: true,
                ..PconConfig::default()
            }),
            ..DpOutput::default()
        })
        || output(&native, 0, &edid)
            != (DpOutput {
                ycbcr420: true,
                ..DpOutput::default()
            })
    {
        return TestResult::Fail("a native or passthrough 4:2:0 sink must take DP 4:2:0");
    }
    // No conversion and no passthrough: 4:2:0 is not allowed, so RGB.
    if output(&dpcd, 0x00, &edid)
        != (DpOutput {
            pcon: Some(PconConfig {
                hdmi_sink: true,
                ..PconConfig::default()
            }),
            ..DpOutput::default()
        })
    {
        return TestResult::Fail("a 4:2:0 sink the DFP cannot feed must fall back to RGB");
    }
    // A mode that is not 4:2:0-only stays RGB on a native sink, no PCON.
    let rgb = edid_4k60_with(&HDMI_420_ONLY_BLOCKS[..6]);
    if output(&native, 0, &rgb) != DpOutput::default() {
        return TestResult::Fail("a native RGB sink must keep RGB without PCON writes");
    }
    // DP_MSA_MISC_COLOR_YCBCR_444_BT709 = 0x1C beside SYNC_CLOCK | 8_BPC.
    if msa_misc(24, true) != 0x3D || msa_misc(24, false) != 0x21 || msa_misc(30, true) != 0x5D {
        return TestResult::Fail("the 4:4:4 MSA differs from intel_ddi_set_dp_msa");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_color",
    smoke_xelpg_dp_ycbcr444_output_format
);

/// A 4K60 DP sink that takes VIC 97 in YCbCr 4:2:0 too
/// (`drm_mode_is_420_also`): a Video Data Block with SVD 97 and a
/// YCbCr 4:2:0 Capability Map Data Block naming its first SVD.
pub(crate) const DP_420_ALSO_BLOCKS: [u8; 5] = [(2 << 5) | 1, 97, (7 << 5) | 2, 0x0F, 0x01];

/// DP YCbCr 4:2:0 output (`narf.intel.hdmi14_ext=1`), from Linux 7.4
/// `intel_dp.c` and `drm_dp_helper.c`:
/// - `intel_dp_output_format_link_bpp_x16` halves the pipe's bits, and
///   `intel_dp_compute_link_config_wide` walks the pipe bpp from the
///   maximum down to `intel_dp_min_bpp` (24 for YCbCr): 4K60 (594 MHz)
///   4:2:0 at 24 bpp needs 594000 * 12 / 8 = 891000 kBps, so HBR x4
///   (1080000) carries it where RGB needs HBR2 x4; a 10 bpc pipe (15 link
///   bpp, 1113750 kBps) takes HBR2 x4.
/// - `intel_dp_needs_vsc_colorimetry`: only with the sink's
///   `DP_VSC_SDP_EXT_FOR_COLORIMETRY_SUPPORTED`; `intel_ddi_set_dp_msa`
///   then adds `DP_MSA_MISC_COLOR_VSC_SDP` (1 << 14).
/// - `intel_dp_compute_vsc_colorimetry` / `drm_dp_vsc_sdp_pack`: HB1 7,
///   revision 5, length 0x13, DB16 = YUV420 (3) << 4 | BT709_YCC (1), DB17 =
///   the bpc code | CTA range (0x81 at 8 bpc, 0x82 at 10, 0x83 at 12).
/// - `intel_dp_compute_formats`' fallback: a 4:2:0-also mode takes the
///   4:2:0 sink format only as the second try; a 4:2:0-only mode never
///   offers it.
fn smoke_xelpg_dp_ycbcr420_link_msa_vsc() -> TestResult {
    let mode = match crate::intel_gpu_dp::mode_from_edid(&edid_4k60_with(&HDMI_420_ONLY_BLOCKS)) {
        Ok(mode) => mode,
        Err(_) => return TestResult::Fail("the 4K60 EDID must give its preferred mode"),
    };
    let y420 = DpOutput {
        ycbcr420: true,
        ..DpOutput::default()
    };
    let limits = dsc::LinkLimits::standard(810_000, 4);
    match (
        output_link(&limits, &mode, 24, &y420),
        output_link(&limits, &mode, 30, &y420),
        output_link(&limits, &mode, 24, &DpOutput::default()),
    ) {
        (Some(a), Some(b), Some(rgb))
            if (a.pipe_bpp, a.link_rate, a.lanes) == (24, 270_000, 4)
                && (b.pipe_bpp, b.link_rate, b.lanes) == (30, 540_000, 4)
                && (rgb.pipe_bpp, rgb.link_rate, rgb.lanes) == (24, 540_000, 4) => {}
        _ => return TestResult::Fail("the 4:2:0 link search must run at half the pipe bpp"),
    }
    // Nothing below 24 bpp for YCbCr: RBR x4 (648000) carries no 4K60 4:2:0.
    if output_link(&dsc::LinkLimits::standard(162_000, 4), &mode, 36, &y420).is_some()
        || y420.min_bpp() != 24
        || DpOutput::default().min_bpp() != 18
        || y420.link_bpp(30) != 15
    {
        return TestResult::Fail("intel_dp_min_bpp is 24 for a YCbCr output");
    }
    let vsc = DpOutput {
        dprx: DP_VSC_SDP_EXT_FOR_COLORIMETRY_SUPPORTED,
        ..y420
    };
    if y420.vsc_colorimetry()
        || !vsc.vsc_colorimetry()
        || msa_misc_output(24, &vsc) != 0x4021
        || msa_misc_output(24, &y420) != 0x21
        || msa_misc_output(30, &vsc) != 0x4041
    {
        return TestResult::Fail("the VSC SDP delegation needs the sink's colorimetry support");
    }
    let mut want = [0u8; 36];
    want[1] = 0x07;
    want[2] = 0x05;
    want[3] = 0x13;
    want[20] = 0x31;
    for (bpp, db17) in [(24u32, 0x81u8), (30, 0x82), (36, 0x83)] {
        want[21] = db17;
        if vsc_sdp_ycbcr420(bpp) != want {
            return TestResult::Fail("the VSC SDP differs from drm_dp_vsc_sdp_pack");
        }
    }
    // A 4:2:0-also mode: RGB first, 4:2:0 as the fallback; a 4:2:0-only
    // mode has no fallback; an RGB-only mode none either.
    let native = [0x14u8, 0, 0, 0, 0, 0];
    let also = edid_4k60_with(&DP_420_ALSO_BLOCKS);
    let only = edid_4k60_with(&HDMI_420_ONLY_BLOCKS);
    let rgb = edid_4k60_with(&HDMI_420_ONLY_BLOCKS[..6]);
    if dp_output(&native, DfpCaps::default(), 0, &also, &mode) != DpOutput::default()
        || dp_output_420_also(&native, DfpCaps::default(), 0, &also, &mode) != Some(y420)
        || dp_output_420_also(&native, DfpCaps::default(), 0, &only, &mode).is_some()
        || dp_output_420_also(&native, DfpCaps::default(), 0, &rgb, &mode).is_some()
    {
        return TestResult::Fail("intel_dp_compute_formats' 4:2:0 fallback differs");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_color",
    smoke_xelpg_dp_ycbcr420_link_msa_vsc
);

/// Deep colour through a branch device (`narf.intel.hdmi14_ext=1`):
/// `drm_dp_downstream_max_bpc`, `_min_tmds_clock`, `_max_tmds_clock` and
/// `_max_dotclock` of DFP 0, then `intel_dp_max_bpp` with
/// `intel_dp_hdmi_compute_bpc` (`intel_hdmi_sink_bpc_possible`,
/// `intel_dp_tmds_clock_valid` against the DFP and the sink's
/// `max_tmds_clock`), and Linux's 8 bpc MST ceiling.
fn smoke_xelpg_dp_branch_dfp_limits_and_depth() -> TestResult {
    use crate::intel_gpu_hdmi::SinkFormat;
    let mut detailed = [0u8; 16];
    detailed[0] = 0x14;
    detailed[DP_DOWNSTREAMPORT_PRESENT] = 0x11;
    let mut plain = detailed;
    plain[DP_DOWNSTREAMPORT_PRESENT] = 0x01;
    let edid = edid_with(4, 0x80 | (4 << 4), &hdmi_vsdb(0x30, 0));
    // HDMI DFP, 300 MHz (0x78 * 2.5 MHz), 12 bpc (DP_DS_12BPC).
    let hdmi = [3u8, 0x78, 2, 0];
    let lim = |dpcd: &[u8], cap: [u8; 4], edid: &[u8]| dfp_limits(dpcd, &cap, edid);
    let dp_input = edid_with(4, 0x80 | (2 << 4) | 5, &[]);
    if lim(&detailed, hdmi, &edid)
        != (DfpLimits {
            max_bpc: 12,
            max_dotclock: 0,
            min_tmds_clock: 25_000,
            max_tmds_clock: 300_000,
        })
        // No detailed caps: 8 bpc; 300 MHz for HDMI, 165 MHz for DVI.
        || lim(&plain, hdmi, &edid).max_bpc != 8
        || lim(&plain, hdmi, &edid).max_tmds_clock != 300_000
        || lim(&plain, [2, 0, 0, 0], &edid).max_tmds_clock != 165_000
        // VGA: the dot clock in 8 MHz units, no TMDS.
        || lim(&detailed, [1, 30, 1, 0], &edid)
            != (DfpLimits {
                max_bpc: 10,
                max_dotclock: 240_000,
                ..DfpLimits::default()
            })
        // A DP DFP, or a dual-mode one before an EDID 1.4 DP sink: none.
        || lim(&detailed, [0, 0x78, 2, 0], &edid) != DfpLimits::default()
        || lim(&detailed, [5, 0x78, 2, 0], &dp_input) != DfpLimits::default()
        || lim(&detailed, [5, 0x78, 2, 0], &edid) != lim(&detailed, hdmi, &edid)
        // DPCD 1.0: the port type in DP_DOWNSTREAMPORT_PRESENT.
        || lim(&[0x10, 0, 0, 0, 0, 0x05], [0; 4], &edid)
            != (DfpLimits {
                max_bpc: 8,
                max_dotclock: 0,
                min_tmds_clock: 25_000,
                max_tmds_clock: 165_000,
            })
        || lim(&[0x10, 0, 0, 0, 0, 0x01], [0; 4], &edid) != DfpLimits::default()
        || lim(&[0x10, 0, 0, 0, 0, 0x03], [0; 4], &edid).max_bpc != 8
        || lim(&[0x14, 0, 0, 0, 0, 0x00], hdmi, &edid) != DfpLimits::default()
    {
        return TestResult::Fail("the drm_dp_downstream_* limits differ from Linux");
    }
    // A native sink: the EDID's depth (no DFP limits).
    let none = DfpLimits::default();
    for (bpc, bpp) in [(0u8, 24u32), (6, 18), (10, 30), (12, 36), (16, 36)] {
        if dp_max_bpp(bpc, &none, &edid, 148_500, SinkFormat::Rgb, 18) != Ok(bpp) {
            return TestResult::Fail("a native sink's pipe maximum is compute_sink_pipe_bpp's");
        }
    }
    // A 12 bpc HDMI sink (DC_30 | DC_36) at 1080p60 behind the HDMI DFP:
    // its 12 bpc and 300 MHz pass (222.75 MHz TMDS) -> 36 bpp; a 10 bpc
    // DFP -> 30; a 165 MHz DFP -> 10 bpc's 185.625 MHz fails, 8 bpc -> 24.
    let dfp = lim(&detailed, hdmi, &edid);
    let ten = DfpLimits { max_bpc: 10, ..dfp };
    let slow = DfpLimits {
        max_tmds_clock: 165_000,
        ..dfp
    };
    if dp_max_bpp(12, &dfp, &edid, 148_500, SinkFormat::Rgb, 18) != Ok(36)
        || dp_max_bpp(12, &ten, &edid, 148_500, SinkFormat::Rgb, 18) != Ok(30)
        || dp_max_bpp(12, &slow, &edid, 148_500, SinkFormat::Rgb, 18) != Ok(24)
    {
        return TestResult::Fail("intel_dp_max_bpp must take the DFP's bpc and TMDS limits");
    }
    // The sink's own flags: DC_30 only stops at 10; a DVI sink (no HDMI
    // VSDB) is 8 bpc; the sink's max TMDS (44 * 5 MHz) bounds the DFP's
    // below 12 bpc's 222.75 MHz.
    let dc30 = edid_with(4, 0x80 | (4 << 4), &hdmi_vsdb(0x10, 0));
    let dvi = edid_with(4, 0x80 | (4 << 4), &[]);
    let capped = edid_with(4, 0x80 | (4 << 4), &hdmi_vsdb(0x30, 44));
    if dp_max_bpp(12, &dfp, &dc30, 148_500, SinkFormat::Rgb, 18) != Ok(30)
        || dp_max_bpp(12, &dfp, &dvi, 148_500, SinkFormat::Rgb, 18) != Ok(24)
        || dp_max_bpp(12, &dfp, &capped, 148_500, SinkFormat::Rgb, 18) != Ok(30)
    {
        return TestResult::Fail("intel_dp_hdmi_compute_bpc must follow the sink's limits");
    }
    // 4K60 at 8 bpc is 594 MHz of TMDS, above the DFP's 300: refused; its
    // 4:2:0 TMDS clock (297 MHz) passes. A YCbCr output's 24 bpp minimum
    // above a 6 bpc sink is invalid.
    if dp_max_bpp(8, &dfp, &edid, 594_000, SinkFormat::Rgb, 18) != Err(ColorRefusal::DfpBpc)
        || dp_max_bpp(8, &dfp, &edid, 594_000, SinkFormat::Ycbcr420, 24) != Ok(24)
        || dp_max_bpp(6, &none, &edid, 148_500, SinkFormat::Rgb, 24)
            != Err(ColorRefusal::Ycbcr444Bpp)
    {
        return TestResult::Fail("the DFP TMDS window and the YCbCr minimum must refuse");
    }
    // intel_dp_compute_config_limits: an MST stream is at most 24 bpp.
    if MST_MAX_PIPE_BPP != max_pipe_bpp(12).min(24) {
        return TestResult::Fail("Linux limits MST streams to 8 bpc");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_color",
    smoke_xelpg_dp_branch_dfp_limits_and_depth
);

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
    for (display_bpc, bpp) in [
        (0u8, 24u32),
        (6, 18),
        (8, 24),
        (10, 30),
        (12, 36),
        (16, 36),
    ] {
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
    use crate::intel_gpu_hdmi::{parse_hdmi_vsdb, Ycbcr420Caps, SinkFormat};
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
/// `intel_dp_output_format` and `intel_dp_configure_protocol_converter`'s
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
    let output = |dpcd: &[u8], byte3: u8, edid: &[u8]| {
        dp_output(dpcd, dfp_caps(dpcd, &hdmi(byte3)), edid, &mode)
    };
    // 4:4:4->4:2:0 only: the pipe drives YCbCr 4:4:4, the PCON converts.
    if output(&dpcd, 0x10, &edid)
        != Ok(DpOutput {
            ycbcr444: true,
            pcon: Some(PconConfig {
                hdmi_sink: true,
                ycbcr444_to_420: true,
                rgb_to_ycbcr: false,
            }),
        })
    {
        return TestResult::Fail("a 4:4:4->4:2:0 PCON must take a YCbCr 4:4:4 pipe");
    }
    // RGB->YCbCr and 4:4:4->4:2:0: RGB out, both conversions on.
    if output(&dpcd, 0x50, &edid)
        != Ok(DpOutput {
            ycbcr444: false,
            pcon: Some(PconConfig {
                hdmi_sink: true,
                ycbcr444_to_420: true,
                rgb_to_ycbcr: true,
            }),
        })
    {
        return TestResult::Fail("an RGB->YCbCr PCON must keep the pipe RGB");
    }
    // A passthrough DFP or a native sink would need DP 4:2:0: refused.
    let native = [0x14u8, 0, 0, 0, 0, 0];
    if output(&dpcd, 0x04, &edid) != Err(ColorRefusal::Ycbcr420Output)
        || output(&native, 0, &edid) != Err(ColorRefusal::Ycbcr420Output)
    {
        return TestResult::Fail("a DP 4:2:0 output must refuse");
    }
    // No conversion and no passthrough: 4:2:0 is not allowed, so RGB.
    if output(&dpcd, 0x00, &edid)
        != Ok(DpOutput {
            ycbcr444: false,
            pcon: Some(PconConfig {
                hdmi_sink: true,
                ..PconConfig::default()
            }),
        })
    {
        return TestResult::Fail("a 4:2:0 sink the DFP cannot feed must fall back to RGB");
    }
    // A mode that is not 4:2:0-only stays RGB on a native sink, no PCON.
    let rgb = edid_4k60_with(&HDMI_420_ONLY_BLOCKS[..6]);
    if output(&native, 0, &rgb) != Ok(DpOutput::default()) {
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

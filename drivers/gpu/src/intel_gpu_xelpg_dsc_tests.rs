//! Display-14 DSC decision, VDSC image, PPS SDP and FEC. Expected values
//! come from Linux b90c984d: the rate-control parameters, register values,
//! SDP dwords, M/N and minimum CDCLK were produced by drm_dsc_helper.c's
//! drm_dsc_compute_rc_parameters / drm_dsc_pps_payload_pack /
//! drm_dsc_set_rc_buf_thresh, intel_vdsc.c's calculate_rc_params with
//! intel_qp_tables.c, intel_dsc_pps_configure's register expressions,
//! drm_dp_bw_overhead, intel_link_compute_m_n and intel_vdsc_min_cdclk,
//! compiled from the kernel sources, independently of this module.
use super::*;
use crate::dp_aux::{AuxCommand, AuxRequest, AuxResponse, AuxStatus};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::cell::RefCell;
use narf_kernel_test::{kernel_test_in, TestResult};

extern crate alloc;

/// 2880x1800@120 eDP 1.4b OLED: DSC 1.2, 1/2/4 slices, 9-bit line buffer,
/// block prediction, at most 12 bpp, 1/16 bpp increments.
const E1_DSC: [u8; 16] = [
    0x01, 0x21, 0x00, 0x0f, 0x0b, 0x00, 0x01, 0xc0, 0x00, 0x01, 0x06, 0x00, 0x08, 0x00, 0x00, 0x00,
];
/// 1920x1200@60 eDP 1.4: DSC 1.1, one slice, 8-bit line buffer, no block
/// prediction, at most 8 bpp, whole-bpp increments.
const E2_DSC: [u8; 16] = [
    0x01, 0x11, 0x00, 0x0f, 0x01, 0x08, 0x00, 0x80, 0x00, 0x01, 0x02, 0x00, 0x06, 0x00, 0x00, 0x04,
];
/// 3840x2160@120 DP monitor: DSC 1.2, 1/2/4 slices, 9-bit line buffer,
/// block prediction, no maximum bpp, 1/16 increments, 850/340 MP/s.
const D1_DSC: [u8; 16] = [
    0x01, 0x21, 0x00, 0x0f, 0x0b, 0x00, 0x01, 0x00, 0x00, 0x01, 0x06, 0x0b, 0x08, 0x00, 0x00, 0x00,
];

fn mode(clock: u32, h: u16, htotal: u16, v: u16, vtotal: u16) -> Mode {
    Mode {
        pixel_clock_khz: clock,
        h_active: h,
        h_total: htotal,
        h_sync_start: h + 48,
        h_sync_end: h + 80,
        v_active: v,
        v_total: vtotal,
        v_sync_start: v + 3,
        v_sync_end: v + 9,
        h_sync_positive: true,
        v_sync_positive: false,
    }
}

fn e1_mode() -> Mode {
    mode(650_016, 2880, 2960, 1800, 1830)
}
fn e2_mode() -> Mode {
    mode(154_000, 1920, 2080, 1200, 1235)
}
fn d1_mode() -> Mode {
    mode(1_080_000, 3840, 4000, 2160, 2250)
}

/// eDP caps: DPCD rev 1.4, `max_rate` code, `lanes` with enhanced framing.
fn edp_caps(rate_code: u8, lanes: u8, edp_rev: u8, dsc: [u8; 16]) -> EdpCaps {
    let mut receiver = [0u8; 16];
    receiver[0] = 0x14;
    receiver[1] = rate_code;
    receiver[2] = 0x80 | lanes;
    EdpCaps {
        receiver,
        edp_rev,
        link_rates: [0; 8],
        dsc: DscDpcd(dsc),
    }
}

fn e1_plan() -> DscPlan {
    match decide_edp(
        &edp_caps(0x14, 2, 0x05, E1_DSC),
        &EdpVbt::Missing,
        0,
        &e1_mode(),
        false,
    ) {
        Ok(LinkDecision::Dsc(plan)) => plan,
        other => panic!("E1 must compress: {other:?}"),
    }
}

fn d1_sink(fec: bool, branch: bool) -> DpDscSink {
    DpDscSink {
        dsc: DscSink {
            dpcd: DscDpcd(D1_DSC),
            is_edp: false,
            fec_capable: fec,
        },
        branch,
    }
}

fn smoke_xelpg_dsc_dpcd_accessors_follow_drm_dp_helper() -> TestResult {
    let d = DscDpcd(D1_DSC);
    // drm_dp_dsc_sink_slice_count_mask: 1, 2, 4 from CAP_1; eDP never
    // reads CAP_2.
    let mut wide = D1_DSC;
    wide[0x0d] = 0x07;
    wide[0x04] = 0xfb;
    let w = DscDpcd(wide);
    let checks = [
        d.slice_count_mask(false) == 0b1011,
        d.max_slice_count(false) == 4,
        w.slice_count_mask(false)
            == (1 << 23)
                | (1 << 19)
                | (1 << 15)
                | (1 << 11)
                | (1 << 9)
                | (1 << 7)
                | (1 << 5)
                | 0b1011,
        w.max_slice_count(false) == 24,
        w.max_slice_count(true) == 12,
        d.line_buf_depth() == 9,
        DscDpcd(E2_DSC).line_buf_depth() == 8,
        d.version_major() == 1 && d.version_minor() == 2,
        d.block_prediction() && !DscDpcd(E2_DSC).block_prediction(),
        d.output_bpp_x16() == 0 && DscDpcd(E1_DSC).output_bpp_x16() == 192,
        d.supports_rgb(),
        d.input_bpcs() == ([10, 8, 0], 2),
        DscDpcd(E2_DSC).input_bpcs() == ([8, 0, 0], 1),
        DscDpcd([0; 16]).input_bpcs().1 == 0,
        // drm_dp_dsc_sink_max_slice_throughput: mode 0 code 11 = 850000;
        // mode 1 code 0 falls back to dsc_sink_min_slice_throughput.
        d.max_slice_throughput(1_080_000, true) == 850_000,
        d.max_slice_throughput(1_080_000, false) == 340_000,
        d.max_slice_throughput(2_700_000, false) == 400_000,
        d.max_slice_throughput(4_800_000, false) == 600_000,
        d.max_slice_width() == 2560,
        d.bpp_incr() == 16 && DscDpcd(E2_DSC).bpp_incr() == 1,
    ];
    if checks.iter().any(|ok| !ok) {
        return TestResult::Fail("the DSC DPCD accessors must follow drm_dp_helper");
    }
    // The DP 2.1 throughput delta (2 MP/s units) applies to mode 0 only.
    let mut delta = D1_DSC;
    delta[0x02] = 3 << 3;
    if DscDpcd(delta).max_slice_throughput(1_080_000, true) != 856_000 {
        return TestResult::Fail("the mode-0 delta adds 2000 kP/s per step");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_dsc",
    smoke_xelpg_dsc_dpcd_accessors_follow_drm_dp_helper
);

fn smoke_xelpg_dsc_edp_oled_config_matches_linux() -> TestResult {
    // 650016 kHz x 24 bpp needs 1950048 kBps and 18 bpp 1462536; HBR2 x2
    // carries 1080000, so Linux compresses. eDP takes the maximum link
    // and the sink's maximum bpp (12) and slice count (4): two engines.
    let plan = e1_plan();
    if (
        plan.link_rate,
        plan.lanes,
        plan.pipe_bpp,
        plan.compressed_bpp_x16,
        plan.slice_count,
        plan.num_streams,
        plan.fec,
    ) != (540_000, 2, 24, 192, 4, 2, false)
    {
        return TestResult::Fail("E1 must compress at 12 bpp, 4 slices, HBR2 x2, no FEC");
    }
    let c = &plan.config;
    let got = [
        u32::from(c.slice_height),
        u32::from(c.slice_width),
        u32::from(c.slice_chunk_size),
        u32::from(c.initial_xmit_delay),
        u32::from(c.initial_dec_delay),
        u32::from(c.initial_scale_value),
        u32::from(c.scale_increment_interval),
        u32::from(c.scale_decrement_interval),
        u32::from(c.first_line_bpg_offset),
        u32::from(c.nfl_bpg_offset),
        u32::from(c.slice_bpg_offset),
        u32::from(c.initial_offset),
        u32::from(c.final_offset),
        u32::from(c.flatness_min_qp),
        u32::from(c.flatness_max_qp),
        u32::from(c.rc_bits),
        u32::from(c.line_buf_depth),
        u32::from(c.dsc_version_minor),
    ];
    let want = [
        120, 720, 1080, 342, 812, 10, 1775, 120, 15, 259, 454, 2048, 4328, 3, 12, 13848, 9, 2,
    ];
    if got != want {
        return TestResult::Fail("E1's rate control must match Linux");
    }
    let qp = [
        (0, 3, 3),
        (0, 4, 1),
        (1, 5, 1),
        (1, 6, 63),
        (3, 7, 61),
        (3, 7, 59),
        (3, 7, 57),
        (3, 8, 57),
        (3, 9, 57),
        (3, 9, 55),
        (5, 10, 55),
        (5, 10, 55),
        (5, 11, 53),
        (7, 11, 53),
        (12, 13, 53),
    ];
    if c.rc_range_params != qp {
        return TestResult::Fail("E1's QP ranges must match intel_qp_tables.c");
    }
    let pps = [
        (0, 0x0013_9821),
        (1, 0x0000_00c0),
        (2, 0x05a0_0708),
        (3, 0x02d0_0078),
        (4, 0x032c_0156),
        (5, 0x0078_06ef),
        (6, 0x0c03_0f0a),
        (7, 0x0103_01c6),
        (8, 0x0800_10e8),
        (9, 0x0006_2000),
        (10, 0x0033_0b0b),
        (16, 0x00f2_0438),
        (17, 0),
        (18, 0),
    ];
    if plan.pps_values() != pps {
        return TestResult::Fail("E1's PPS registers must match intel_dsc_pps_configure");
    }
    if plan.rc_buf_thresh_dwords() != [0x382a_1c0e, 0x6962_5446, 0x7b79_7770, 0x0000_7e7d]
        || plan.rc_range_dwords()
            != [
                0x0480_0c60,
                0xfcc1_04a1,
                0xece3_f4e3,
                0xe503_e4e3,
                0xdd23_e523,
                0xdd45_dd45,
                0xd567_d565,
                0x0000_d5ac,
            ]
    {
        return TestResult::Fail("E1's threshold and range dwords must match Linux");
    }
    let sdp: [u32; PPS_SDP_DWORDS] = [
        0x007f_1000,
        0x8900_0012,
        0x0807_c030,
        0x7800_400b,
        0x3804_d002,
        0x2c03_5601,
        0xef06_0a00,
        0x0f00_7800,
        0xc601_0301,
        0xe810_0008,
        0x0020_0c03,
        0x330b_0b06,
        0x382a_1c0e,
        0x6962_5446,
        0x7b79_7770,
        0xc300_7e7d,
        0x4109_0101,
        0xfd19_bf09,
        0xf919_fb19,
        0x791a_391a,
        0xb72a_771a,
        0xf52a_b72a,
        0x7563_f53a,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ];
    if plan.pps_sdp() != sdp {
        return TestResult::Fail("E1's PPS SDP must match drm_dsc_pps_payload_pack");
    }
    if plan.m_n(&e1_mode()) != [0x7e73_8ef3, 0x0080_0000, 0x0009_a13e, 0x0008_0000] {
        return TestResult::Fail("E1's M/N must use the compressed bpp");
    }
    if plan.min_cdclk_khz(&e1_mode()) != 331_157 {
        return TestResult::Fail("E1's VDSC minimum CDCLK must match intel_vdsc_min_cdclk");
    }
    if link_required(2, 650_016, 2880, 192, false) != 975_024 {
        return TestResult::Fail("the compressed stream needs 975024 kBps");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_dsc",
    smoke_xelpg_dsc_edp_oled_config_matches_linux
);

fn smoke_xelpg_dsc_edp_single_slice_dsc11_matches_linux() -> TestResult {
    // 1920x1200@60 on RBR x1: 24 bpp needs 462000 kBps and 18 bpp 346500;
    // 162000 is available. DSC 1.1 (no ALT_ICH_SEL), one slice, 8 bpp
    // with whole-bpp steps, one engine.
    let plan = match decide_edp(
        &edp_caps(0x06, 1, 0x03, E2_DSC),
        &EdpVbt::Missing,
        0,
        &e2_mode(),
        false,
    ) {
        Ok(LinkDecision::Dsc(plan)) => plan,
        _ => return TestResult::Fail("E2 must compress"),
    };
    if (
        plan.link_rate,
        plan.lanes,
        plan.compressed_bpp_x16,
        plan.slice_count,
        plan.num_streams,
    ) != (162_000, 1, 128, 1, 1)
    {
        return TestResult::Fail("E2 must compress at 8 bpp, one slice, RBR x1");
    }
    let c = &plan.config;
    if (
        c.slice_chunk_size,
        c.initial_xmit_delay,
        c.initial_dec_delay,
        c.initial_scale_value,
        c.scale_increment_interval,
        c.scale_decrement_interval,
        c.slice_bpg_offset,
        c.initial_offset,
        c.final_offset,
        c.rc_bits,
    ) != (1920, 512, 1456, 32, 3951, 26, 62, 6144, 4336, 15744)
    {
        return TestResult::Fail("E2's rate control must match Linux");
    }
    let pps = [
        (0, 0x0002_8811),
        (1, 0x0000_0080),
        (2, 0x0780_04b0),
        (3, 0x0780_0078),
        (4, 0x05b0_0200),
        (5, 0x001a_0f6f),
        (6, 0x0c03_0f20),
        (7, 0x0103_003e),
        (8, 0x1800_10f0),
        (9, 0x0006_2000),
        (10, 0x0033_0b0b),
        (16, 0x00a1_0780),
        (17, 0),
        (18, 0),
    ];
    if plan.pps_values() != pps
        || plan.rc_range_dwords()
            != [
                0xf8a0_0080,
                0xf0e2_f8e2,
                0xed04_e904,
                0xe524_e504,
                0xdd65_e544,
                0xd186_dd65,
                0xd5a9_d586,
                0x0000_d5cd,
            ]
    {
        return TestResult::Fail("E2's registers must match intel_dsc_pps_configure");
    }
    let sdp = plan.pps_sdp();
    if sdp[..23]
        != [
            0x007f_1000,
            0x8800_0011,
            0xb004_8010,
            0x7800_8007,
            0x8007_8007,
            0xb005_0002,
            0x6f0f_2000,
            0x0f00_1a00,
            0x3e00_0301,
            0xf010_0018,
            0x0020_0c03,
            0x330b_0b06,
            0x382a_1c0e,
            0x6962_5446,
            0x7b79_7770,
            0x0001_7e7d,
            0xfe11_7e01,
            0x3a22_fc11,
            0x3922_3b22,
            0xb922_7922,
            0xf72a_f72a,
            0x3533_3433,
            0xb56b_754b,
        ]
        || sdp[23..].iter().any(|&d| d != 0)
    {
        return TestResult::Fail("E2's PPS SDP must match drm_dsc_pps_payload_pack");
    }
    if plan.m_n(&e2_mode()) != [0x7e79_add3, 0x0080_0000, 0x0007_9add, 0x0008_0000]
        || plan.min_cdclk_khz(&e2_mode()) != 155_037
    {
        return TestResult::Fail("E2's M/N and minimum CDCLK must match Linux");
    }
    // One engine: DSC0 only, no joiner.
    let writes = plan.engine_writes(Pipe::A);
    if writes.len() != 14 + 4 + 8 + 2
        || writes
            .iter()
            .any(|&(r, _)| (0x7_8100..0x7_8200).contains(&r))
        || writes[writes.len() - 2..] != [(0x7_8000, 0), (0x7_8004, VDSC0_ENABLE)]
    {
        return TestResult::Fail("a one-slice plan programs DSC0 alone");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_dsc",
    smoke_xelpg_dsc_edp_single_slice_dsc11_matches_linux
);

fn smoke_xelpg_dsc_dp_fec_config_matches_linux() -> TestResult {
    // 3840x2160@120 on a two-lane HBR3 Type-C link: 24 bpp needs 3240000
    // kBps and 18 bpp 2430000, HBR3 x2 carries 1620000. DP DSC enables FEC;
    // the highest bpp that fits with its 1028530 ppm overhead is 186/16.
    let limits = LinkLimits::standard(810_000, 2);
    let plan = match decide_dp(&d1_sink(true, false), &limits, &d1_mode(), PIPE_BPP) {
        Ok(LinkDecision::Dsc(plan)) => plan,
        _ => return TestResult::Fail("D1 must compress"),
    };
    if (
        plan.link_rate,
        plan.lanes,
        plan.compressed_bpp_x16,
        plan.slice_count,
        plan.num_streams,
        plan.fec,
    ) != (810_000, 2, 186, 4, 2, true)
    {
        return TestResult::Fail("D1 must compress at 186/16 bpp, 4 slices, HBR3 x2, FEC");
    }
    if link_required(2, 1_080_000, 3840, 186, true) != 1_614_150
        || link_required(2, 1_080_000, 3840, 187, true) <= 1_620_000
    {
        return TestResult::Fail("D1's FEC bandwidth must match intel_dp_link_required");
    }
    let pps = [
        (0, 0x0013_9821),
        (1, 0x0000_00ba),
        (2, 0x0780_0870),
        (3, 0x03c0_006c),
        (4, 0x0314_0175),
        (5, 0x002d_0858),
        (6, 0x0c03_0f0f),
        (7, 0x0120_0111),
        (8, 0x0f00_1000),
        (9, 0x0006_2000),
        (10, 0x0033_0b0b),
        (16, 0x0142_0573),
        (17, 0),
        (18, 0),
    ];
    if plan.pps_values() != pps
        || plan.rc_range_dwords()
            != [
                0x0480_0c80,
                0xfcc1_04a1,
                0xece3_f4e3,
                0xe503_e4e3,
                0xdd44_e523,
                0xdd65_dd45,
                0xd588_d565,
                0x0000_d5ac,
            ]
    {
        return TestResult::Fail("D1's registers must match intel_dsc_pps_configure");
    }
    let sdp = plan.pps_sdp();
    if sdp[..4] != [0x007f_1000, 0x8900_0012, 0x7008_ba30, 0x6c00_000f]
        || sdp[15..23]
            != [
                0x0301_7e7d,
                0x4109_0101,
                0xfd19_bf09,
                0xf919_fb19,
                0x791a_391a,
                0xb72a_b722,
                0xf52a_f72a,
                0x7563_3543,
            ]
    {
        return TestResult::Fail("D1's PPS SDP must match drm_dsc_pps_payload_pack");
    }
    if plan.m_n(&d1_mode()) != [0x7e7f_89ab, 0x0080_0000, 0x000a_aaaa, 0x0008_0000]
        || plan.min_cdclk_khz(&d1_mode()) != 547_560
    {
        return TestResult::Fail("D1's FEC M/N and minimum CDCLK must match Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_dsc",
    smoke_xelpg_dsc_dp_fec_config_matches_linux
);

fn smoke_xelpg_dsc_edp_decision_and_refusals() -> TestResult {
    let m = e1_mode();
    let vbt = EdpVbt::Missing;
    let with = |f: fn(&mut [u8; 16])| {
        let mut d = E1_DSC;
        f(&mut d);
        decide_edp(&edp_caps(0x14, 2, 0x05, d), &vbt, 0, &m, false)
    };
    let cases: [(
        Result<LinkDecision, DscRefusal>,
        Result<LinkDecision, DscRefusal>,
    ); 9] = [
        // An eDP 1.3 panel never reads DSC caps: HBR2 x2 carries neither
        // 24 nor 18 bpp, so Linux refuses ("DSC required but not
        // available").
        (
            decide_edp(&edp_caps(0x14, 2, 0x02, E1_DSC), &vbt, 0, &m, false),
            Err(DscRefusal::SinkUnsupported),
        ),
        // HBR3 x4 carries 24 bpp; the lowest rate that does is HBR2 x4
        // (1950048 <= 2160000 kBps).
        (
            decide_edp(&edp_caps(0x1e, 4, 0x05, E1_DSC), &vbt, 0, &m, false),
            Ok(LinkDecision::Uncompressed(UncompressedLink {
                pipe_bpp: 24,
                link_rate: 540_000,
                lanes: 4,
            })),
        ),
        // HBR3 x2 carries 18 bpp (1462536 <= 1620000): Linux's 6 bpc,
        // tried before DSC.
        (
            decide_edp(&edp_caps(0x1e, 2, 0x05, E1_DSC), &vbt, 0, &m, false),
            Ok(LinkDecision::Uncompressed(UncompressedLink {
                pipe_bpp: 18,
                link_rate: 810_000,
                lanes: 2,
            })),
        ),
        (
            decide_edp(
                &edp_caps(0x14, 2, 0x05, E1_DSC),
                &EdpVbt::Panel {
                    dsc_disable: true,
                    max_link_rate: 0,
                    bpp: 0,
                },
                0,
                &m,
                false,
            ),
            Err(DscRefusal::VbtDisabled),
        ),
        (
            decide_edp(
                &edp_caps(0x14, 2, 0x05, E1_DSC),
                &EdpVbt::PanelByPnpId,
                0,
                &m,
                false,
            ),
            Err(DscRefusal::VbtPanelUnknown),
        ),
        // eDP 1.5 eight slices: beyond two engines.
        (
            with(|d| d[4] = 0x2b),
            Err(DscRefusal::SliceCountUnqualified),
        ),
        (with(|d| d[5] = 0x0f), Err(DscRefusal::LineBufDepth)),
        // A 7 bpp sink maximum is below the 8 bpp source minimum.
        (with(|d| d[7] = 0x70), Err(DscRefusal::NoBppRange)),
        (with(|d| d[9] = 0x02), Err(DscRefusal::FormatUnsupported)),
    ];
    if cases.iter().any(|(got, want)| got != want) {
        return TestResult::Fail("the eDP decision must follow intel_dp_compute_link_config");
    }
    // No declared maximum: Linux's eDP path takes 383/16 bpp on the
    // maximum link without a bandwidth check; this driver refuses.
    if with(|d| d[7] = 0) != Err(DscRefusal::OverBudget) {
        return TestResult::Fail("a stream the eDP link cannot carry must refuse");
    }
    // The VBT's eDP maximum caps the source: HBR3 x2 capped at HBR2
    // compresses at E1's plan.
    let capped = decide_edp(
        &edp_caps(0x1e, 2, 0x05, E1_DSC),
        &EdpVbt::Panel {
            dsc_disable: false,
            max_link_rate: 540_000,
            bpp: 0,
        },
        0,
        &m,
        false,
    );
    if capped != Ok(LinkDecision::Dsc(e1_plan())) {
        return TestResult::Fail("the VBT eDP rate must cap the link");
    }
    // A link-rate table: 1.62/2.7/5.4 behaves as MAX_LINK_RATE HBR2; a
    // table topping at 4.32 Gbps is unqualified for DSC.
    let mut table = edp_caps(0x00, 2, 0x05, E1_DSC);
    table.link_rates[..3].copy_from_slice(&[8100, 13500, 27000]);
    if decide_edp(&table, &vbt, 0, &m, false) != Ok(LinkDecision::Dsc(e1_plan())) {
        return TestResult::Fail("a standard rate table must compress like HBR2");
    }
    table.link_rates[..6].copy_from_slice(&[8100, 10800, 12150, 13500, 16200, 21600]);
    let l = table.limits(0);
    if l.rates[..7] != [162_000, 216_000, 243_000, 270_000, 324_000, 432_000, 0]
        || decide_edp(&table, &vbt, 0, &m, false) != Err(DscRefusal::LinkRateUnqualified)
    {
        return TestResult::Fail("an intermediate maximum rate must refuse");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_dsc",
    smoke_xelpg_dsc_edp_decision_and_refusals
);

fn smoke_xelpg_dsc_dp_decision_and_refusals() -> TestResult {
    let hbr3x2 = LinkLimits::standard(810_000, 2);
    let uhd60 = mode(594_000, 3840, 4400, 2160, 2250);
    let mut no_width = d1_sink(true, false);
    no_width.dsc.dpcd.0[0x0c] = 0;
    let mut no_dsc = d1_sink(true, false);
    no_dsc.dsc.dpcd.0[0] = 0;
    let cases = [
        // 4K60 at 24 bpp fits HBR2 x4: the route's own negotiation runs.
        (
            decide_dp(
                &d1_sink(true, false),
                &LinkLimits::standard(540_000, 4),
                &uhd60,
                PIPE_BPP,
            ),
            Ok(LinkDecision::Uncompressed(UncompressedLink {
                pipe_bpp: 24,
                link_rate: 540_000,
                lanes: 4,
            })),
        ),
        // 4K60 on HBR3 x2: 18 bpp fits (1336500 kBps), before DSC.
        (
            decide_dp(&d1_sink(true, false), &hbr3x2, &uhd60, PIPE_BPP),
            Ok(LinkDecision::Uncompressed(UncompressedLink {
                pipe_bpp: 18,
                link_rate: 810_000,
                lanes: 2,
            })),
        ),
        (
            decide_dp(&d1_sink(false, false), &hbr3x2, &d1_mode(), PIPE_BPP),
            Err(DscRefusal::FecUnsupported),
        ),
        (
            decide_dp(&d1_sink(true, true), &hbr3x2, &d1_mode(), PIPE_BPP),
            Err(DscRefusal::BranchDevice),
        ),
        (
            decide_dp(&no_dsc, &hbr3x2, &d1_mode(), PIPE_BPP),
            Err(DscRefusal::SinkUnsupported),
        ),
        (
            decide_dp(&no_width, &hbr3x2, &d1_mode(), PIPE_BPP),
            Err(DscRefusal::NoSliceCount),
        ),
    ];
    if cases.iter().any(|(got, want)| got != want) {
        return TestResult::Fail("the DP decision must follow intel_dp_compute_link_config");
    }
    // HBR2 x2 cannot carry even 8 bpp with FEC (1080000 kBps).
    if decide_dp(
        &d1_sink(true, false),
        &LinkLimits::standard(540_000, 2),
        &d1_mode(),
        PIPE_BPP,
    ) != Err(DscRefusal::NoLinkConfig)
    {
        return TestResult::Fail("no bpp fitting any link must refuse");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_dsc",
    smoke_xelpg_dsc_dp_decision_and_refusals
);

/// A base EDID block: revision 1.`rev`, video input byte `input`, panel
/// `vendor` / `product`.
fn edid_block(rev: u8, input: u8, vendor: &[u8; 3], product: u16) -> [u8; 128] {
    let mut e = [0u8; 128];
    e[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
    let mfr = (u16::from(vendor[0] - b'@') << 10)
        | (u16::from(vendor[1] - b'@') << 5)
        | u16::from(vendor[2] - b'@');
    e[8] = (mfr >> 8) as u8;
    e[9] = mfr as u8;
    e[10] = product as u8;
    e[11] = (product >> 8) as u8;
    e[18] = 1;
    e[19] = rev;
    e[20] = input;
    e
}

fn smoke_xelpg_dsc_edid_bpc_follows_update_display_info() -> TestResult {
    // drm_edid.c update_display_info: below 1.3 or analog, 0; 1.3 digital
    // DFP 1.x, 8; 1.4 the depth field (1 => 6 .. 6 => 16, 0/7 => 0);
    // then the edid_quirk_list bpc entries by panel ID.
    let cases = [
        (edid_block(2, 0x90, b"NAR", 0), 0),
        (edid_block(4, 0x10, b"NAR", 0), 0),
        (edid_block(3, 0x81, b"NAR", 0), 8),
        (edid_block(3, 0x80, b"NAR", 0), 0),
        (edid_block(4, 0x81, b"NAR", 0), 0),
        (edid_block(4, 0x90, b"NAR", 0), 6),
        (edid_block(4, 0xa5, b"NAR", 0), 8),
        (edid_block(4, 0xb0, b"NAR", 0), 10),
        (edid_block(4, 0xc0, b"NAR", 0), 12),
        (edid_block(4, 0xe0, b"NAR", 0), 16),
        (edid_block(4, 0xf0, b"NAR", 0), 0),
        // BOE 0x0771 reports 8 bpc but is a 6 bpc panel.
        (edid_block(4, 0xa0, b"BOE", 0x0771), 6),
        // AEO model 0, even without a digital depth.
        (edid_block(4, 0x00, b"AEO", 0), 6),
        // The Samsung NP700G7A panel reports 6 bpc; FORCE_8BPC.
        (edid_block(4, 0x90, b"SEC", 0xd033), 8),
        // LGD 764 reports no bpc: FORCE_10BPC.
        (edid_block(4, 0x80, b"LGD", 764), 10),
        // A neighbouring product ID is not a quirk.
        (edid_block(4, 0xa0, b"BOE", 0x0772), 8),
    ];
    for (edid, want) in cases {
        if edid_display_bpc(&edid) != want {
            return TestResult::Fail("display_info.bpc must follow update_display_info");
        }
    }
    if edid_display_bpc(&[0u8; 16]) != 0 {
        return TestResult::Fail("a truncated EDID has no bpc");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_dsc",
    smoke_xelpg_dsc_edid_bpc_follows_update_display_info
);

fn smoke_xelpg_dsc_six_bpc_pipe_bpp_and_register_values() -> TestResult {
    // compute_sink_pipe_bpp with max bpc 8, then intel_dp_max_bpp's VBT
    // clamp, which applies only when the EDID has no bpc.
    let max_cases = [
        ((0, 0), 24),
        ((6, 0), 18),
        ((7, 0), 18),
        ((8, 0), 24),
        ((10, 0), 24),
        ((0, 18), 18),
        ((0, 24), 24),
        ((0, 30), 24),
        ((8, 18), 24),
        ((6, 30), 18),
    ];
    for ((bpc, vbt), want) in max_cases {
        if max_pipe_bpp(bpc, vbt) != want {
            return TestResult::Fail("the pipe maximum must follow intel_dp_max_bpp");
        }
    }
    // 1024x768@60 (65 MHz): 24 bpp needs 195000 kBps, 18 bpp 146250. One
    // RBR lane (162000) carries only 18; two carry 24.
    let m = mode(65_000, 1024, 1344, 768, 806);
    let link = |max_rate, lanes, max_bpp| {
        uncompressed_link(&LinkLimits::standard(max_rate, lanes), &m, max_bpp)
    };
    let want = |pipe_bpp, link_rate, lanes| {
        Some(UncompressedLink {
            pipe_bpp,
            link_rate,
            lanes,
        })
    };
    if link(162_000, 1, 24) != want(18, 162_000, 1)
        || link(162_000, 2, 24) != want(24, 162_000, 2)
        // A 6 bpc sink stays at 18 on the slowest, narrowest link.
        || link(810_000, 4, 18) != want(18, 162_000, 1)
        // Slow and wide: the lowest rate wins over fewer lanes.
        || link(540_000, 4, 24) != want(24, 162_000, 2)
        || link(162_000, 1, 18).is_none()
    {
        return TestResult::Fail("the link must follow intel_dp_compute_link_config_wide");
    }
    // use_max_params: only the maximum rate and lane count.
    let mut max = LinkLimits::standard(540_000, 4);
    max.use_max = true;
    if uncompressed_link(&max, &m, 24) != want(24, 540_000, 4) {
        return TestResult::Fail("use_max_params must take the maximum link");
    }
    // bdw_set_pipe_misc: BPC_8 | TRUNC, or BPC_6 | DITHER_ENABLE | TRUNC.
    if pipe_misc(24) != 0x100
        || pipe_misc(18) != 0x150
        || trans_ddi_bpc(24) != 0
        || trans_ddi_bpc(18) != 2 << 20
        || msa_misc(24) != 0x21
        || msa_misc(18) != 0x01
    {
        return TestResult::Fail("PIPE_MISC, TRANS_DDI BPC and MSA must follow Linux");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_dsc",
    smoke_xelpg_dsc_six_bpc_pipe_bpp_and_register_values
);

fn smoke_xelpg_dsc_edp_vbt_bpp_clamp_rate_table_and_fixup() -> TestResult {
    // 1024x768@60 on an eDP 1.4 panel at HBR2 x4: 24 bpp fits easily.
    let m = mode(65_000, 1024, 1344, 768, 806);
    let mut caps = edp_caps(0x14, 4, 0x03, [0; 16]);
    let vbt18 = EdpVbt::Panel {
        dsc_disable: false,
        max_link_rate: 0,
        bpp: 18,
    };
    let decide = |caps: &EdpCaps, vbt: &EdpVbt, bpc| decide_edp(caps, vbt, bpc, &m, false);
    let uncompressed = |pipe_bpp, link_rate, lanes| {
        Ok(LinkDecision::Uncompressed(UncompressedLink {
            pipe_bpp,
            link_rate,
            lanes,
        }))
    };
    // The VBT's 18 bpp clamps a panel whose EDID has no bpc, even where 24
    // would fit; an EDID bpc overrides the VBT.
    if decide(&caps, &vbt18, 0) != uncompressed(18, 162_000, 1)
        || decide(&caps, &vbt18, 8) != uncompressed(24, 162_000, 2)
        || decide(&caps, &EdpVbt::Missing, 6) != uncompressed(18, 162_000, 1)
        || decide(&caps, &EdpVbt::Missing, 0) != uncompressed(24, 162_000, 2)
    {
        return TestResult::Fail("the eDP pipe bpp must follow intel_dp_max_bpp");
    }
    // An eDP 1.3 panel uses its maximum parameters.
    let old = edp_caps(0x14, 4, 0x02, [0; 16]);
    if decide(&old, &EdpVbt::Missing, 0) != uncompressed(24, 540_000, 4)
        || !old.limits(0).use_max
        || caps.limits(0).use_max
    {
        return TestResult::Fail("eDP below 1.4 must take use_max_params");
    }
    // A rate table (DP_MAX_LINK_RATE 0): 1.62/2.16/2.43/2.7 Gbps on two
    // lanes. 24 bpp at 140 MHz needs 420000 kBps: 2.16 Gbps x2 (432000).
    caps = edp_caps(0x00, 2, 0x03, [0; 16]);
    caps.link_rates[..4].copy_from_slice(&[8100, 10800, 12150, 13500]);
    let m140 = mode(140_000, 1024, 1344, 768, 806);
    if !caps.has_rate_table()
        || caps.sink_rates() != ([162_000, 216_000, 243_000, 270_000, 0, 0, 0, 0], 4)
        || decide_edp(&caps, &EdpVbt::Missing, 0, &m140, false) != uncompressed(24, 216_000, 2)
        || caps.rate_select(216_000) != Some(1)
        || caps.rate_select(540_000).is_some()
        || edp_caps(0x14, 4, 0x03, [0; 16])
            .rate_select(540_000)
            .is_some()
    {
        return TestResult::Fail("a rate table must select by intel_dp_rate_select");
    }
    // Invalid DPCD: no rates and a lane count of 3 take Linux's RBR x1.
    let invalid = edp_caps(0x00, 3, 0x03, [0; 16]);
    let l = invalid.limits(0);
    if l.rates[..2] != [162_000, 0] || l.max_lanes != 1 {
        return TestResult::Fail("an invalid DPCD must take Linux's defaults");
    }
    // intel_edp_fixup_vbt_bpp: a lit 24 bpp pipe raises the VBT's 18; a
    // lower pipe bpp or a VBT without bpp is left alone.
    let previous = installed_edp_vbt();
    install_edp_vbt(vbt18);
    fixup_vbt_bpp(18);
    let kept = installed_edp_vbt().edp_bpp();
    fixup_vbt_bpp(24);
    let raised = installed_edp_vbt().edp_bpp();
    install_edp_vbt(EdpVbt::Panel {
        dsc_disable: false,
        max_link_rate: 0,
        bpp: 0,
    });
    fixup_vbt_bpp(24);
    let none = installed_edp_vbt().edp_bpp();
    install_edp_vbt(previous);
    if (kept, raised, none) != (18, 24, 0) {
        return TestResult::Fail("the VBT bpp must follow intel_edp_fixup_vbt_bpp");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_dsc",
    smoke_xelpg_dsc_edp_vbt_bpp_clamp_rate_table_and_fixup
);

/// A register file that logs every write.
struct Regs {
    map: RefCell<BTreeMap<u64, u32>>,
    log: RefCell<Vec<(u64, u32)>>,
}

impl Regs {
    fn new() -> Self {
        Self {
            map: RefCell::new(BTreeMap::new()),
            log: RefCell::new(Vec::new()),
        }
    }
    fn set(&self, r: u64, v: u32) {
        self.map.borrow_mut().insert(r, v);
    }
}

impl MmioWindow for Regs {
    fn read32(&self, off: u64) -> u32 {
        self.map.borrow().get(&off).copied().unwrap_or(0)
    }
    fn write32(&self, off: u64, val: u32) {
        self.log.borrow_mut().push((off, val));
        self.map.borrow_mut().insert(off, val);
    }
}

fn smoke_xelpg_dsc_engine_registers_per_pipe() -> TestResult {
    // is_pipe_dsc on display 14: every pipe has its own engines at
    // _MMIO_PIPE(pipe - PIPE_B, PB, PC); Pipe A sits 0x200 below PB.
    let plan = e1_plan();
    for (pipe, ctl1) in [
        (Pipe::A, 0x7_8000u64),
        (Pipe::B, 0x7_8200),
        (Pipe::C, 0x7_8400),
        (Pipe::D, 0x7_8600),
    ] {
        let w = plan.engine_writes(pipe);
        let pb = ctl1;
        // PPS n to DSC0 then DSC1, n = 0..10, 16, 17, 18.
        let mut want = Vec::new();
        for (n, v) in plan.pps_values() {
            want.push((pb + 0x70 + 4 * n, v));
            want.push((pb + 0x170 + 4 * n, v));
        }
        for base in [0x54u64, 0x154] {
            for (i, &v) in plan.rc_buf_thresh_dwords().iter().enumerate() {
                want.push((pb + base + 4 * i as u64, v));
            }
        }
        for base in [0x08u64, 0x108] {
            for (i, &v) in plan.rc_range_dwords().iter().enumerate() {
                want.push((pb + base + 4 * i as u64, v));
            }
        }
        want.push((ctl1, JOINER_ENABLE));
        want.push((ctl1 + 4, VDSC0_ENABLE | VDSC1_ENABLE));
        if w != want {
            return TestResult::Fail("intel_dsc_enable's writes must follow its order");
        }
    }
    if dss_ctl1(Pipe::B) != 0x7_8200
        || dss_ctl2(Pipe::C) != 0x7_8404
        || pps_reg(Pipe::A, 0, 0) != 0x7_8070
        || pps_reg(Pipe::B, 1, 16) != 0x7_83b0
    {
        return TestResult::Fail("the VDSC registers must sit where intel_vdsc_regs.h says");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_dsc",
    smoke_xelpg_dsc_engine_registers_per_pipe
);

fn smoke_xelpg_dsc_program_enable_disable_sdp_mn_and_fec() -> TestResult {
    let plan = e1_plan();
    let hw = Regs::new();
    // intel_dsc_enable, then the hardware readout gives the same term.
    if enable_engines(&hw, Pipe::A, &plan).is_err() || hw.log.borrow().len() != 54 {
        return TestResult::Fail("intel_dsc_enable must program both engines");
    }
    if engines_enabled(&hw, Pipe::A) != Ok(true)
        || read_term(&hw, Pipe::A, &e1_mode()) != Ok(Some(plan.term(&e1_mode())))
        || read_term(&hw, Pipe::B, &e1_mode()) != Ok(None)
    {
        return TestResult::Fail("intel_dsc_get_config must recover the plan's CDCLK term");
    }
    // intel_dsc_disable: both DSS_CTL cleared, only when set.
    hw.log.borrow_mut().clear();
    if disable_engines(&hw, Pipe::A) != Ok(true)
        || *hw.log.borrow() != [(0x7_8000, 0), (0x7_8004, 0)]
    {
        return TestResult::Fail("intel_dsc_disable must clear DSS_CTL1 and DSS_CTL2");
    }
    hw.log.borrow_mut().clear();
    if disable_engines(&hw, Pipe::A) != Ok(false) || !hw.log.borrow().is_empty() {
        return TestResult::Fail("an idle engine pair is left untouched");
    }
    // hsw_write_infoframe(DP_SDP_PPS) on transcoder B: enable cleared, all
    // 33 dwords, enable set; other DIP enables survive.
    let dip = 0x6_1200;
    hw.set(dip, (1 << 12) | VDIP_ENABLE_PPS);
    hw.log.borrow_mut().clear();
    if write_pps_sdp(&hw, Transcoder::B, &plan).is_err() {
        return TestResult::Fail("the PPS SDP must be written");
    }
    let log = hw.log.borrow().clone();
    let sdp = plan.pps_sdp();
    if log.len() != 35
        || log[0] != (dip, 1 << 12)
        || log[34] != (dip, (1 << 12) | VDIP_ENABLE_PPS)
        || (0..33).any(|i| log[1 + i] != (0x6_1350 + 4 * i as u64, sdp[i]))
    {
        return TestResult::Fail("hsw_write_infoframe's PPS order must be kept");
    }
    hw.log.borrow_mut().clear();
    if disable_pps_sdp(&hw, Transcoder::B).is_err() || *hw.log.borrow() != [(dip, 1 << 12)] {
        return TestResult::Fail("intel_dp_set_infoframes(false) clears VDIP_ENABLE_PPS");
    }
    // intel_set_m_n: DATA_M1 (TU 64), DATA_N1, LINK_M1, LINK_N1 last.
    hw.log.borrow_mut().clear();
    let mn = plan.m_n(&e1_mode());
    if write_m_n(&hw, Transcoder::A, &mn).is_err()
        || *hw.log.borrow()
            != [
                (0x6_0030, mn[0]),
                (0x6_0034, mn[1]),
                (0x6_0040, mn[2]),
                (0x6_0044, mn[3]),
            ]
    {
        return TestResult::Fail("intel_set_m_n writes LINK_N1 last");
    }
    // intel_ddi_enable_fec / intel_ddi_disable_fec on DP_TP_CTL, and the
    // FEC_ENABLE_LIVE status wait.
    let tp = 0x6_2540;
    hw.set(tp, 0x8004_0300);
    if enable_fec(&hw, Transcoder::C).is_err() || hw.read32(tp) != 0x8004_0300 | (1 << 30) {
        return TestResult::Fail("FEC enable sets DP_TP_CTL bit 30");
    }
    if wait_fec_live(&hw, Transcoder::C, true) {
        return TestResult::Fail("FEC live must be observed, not assumed");
    }
    hw.set(0x6_2544, DP_TP_STATUS_FEC_ENABLE_LIVE);
    if !wait_fec_live(&hw, Transcoder::C, true) {
        return TestResult::Fail("FEC live is observed in DP_TP_STATUS");
    }
    if disable_fec(&hw, Transcoder::C).is_err() || hw.read32(tp) != 0x8004_0300 {
        return TestResult::Fail("FEC disable clears only bit 30");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_dsc",
    smoke_xelpg_dsc_program_enable_disable_sdp_mn_and_fec
);

/// A DPCD behind native AUX, logging writes.
struct Sink {
    dpcd: [u8; 0x800],
    writes: Vec<(u32, Vec<u8>)>,
    reads: Vec<u32>,
}

impl Sink {
    fn new() -> Self {
        Self {
            dpcd: [0; 0x800],
            writes: Vec::new(),
            reads: Vec::new(),
        }
    }
}

impl AuxChannel for Sink {
    fn transact<'a>(
        &mut self,
        req: &AuxRequest<'_>,
        reply_buf: &'a mut [u8],
    ) -> Result<AuxResponse<'a>, AuxError> {
        let at = req.address as usize & 0x7ff;
        let n = req.data.len();
        reply_buf[0] = 0;
        match req.cmd {
            AuxCommand::NativeRead => {
                self.reads.push(req.address);
                reply_buf[1..1 + n].copy_from_slice(&self.dpcd[at..at + n]);
                Ok(AuxResponse {
                    status: AuxStatus::Ack,
                    data: &reply_buf[1..1 + n],
                })
            }
            AuxCommand::NativeWrite => {
                self.dpcd[at..at + n].copy_from_slice(req.data);
                self.writes.push((req.address, req.data.to_vec()));
                Ok(AuxResponse {
                    status: AuxStatus::Ack,
                    data: &reply_buf[1..1],
                })
            }
            _ => Err(AuxError::Nacked),
        }
    }
}

fn smoke_xelpg_dsc_sink_caps_decompression_and_fec_ready() -> TestResult {
    // intel_edp_init_dpcd: eDP 1.4b reads the rate table and DSC caps.
    let mut s = Sink::new();
    s.dpcd[0..3].copy_from_slice(&[0x14, 0x00, 0x82]);
    s.dpcd[0x700] = 0x05;
    s.dpcd[0x10..0x16].copy_from_slice(&[0xa4, 0x1f, 0xbc, 0x34, 0x78, 0x69]);
    s.dpcd[0x60..0x70].copy_from_slice(&E1_DSC);
    let caps = match EdpCaps::read(&mut s) {
        Ok(caps) => caps,
        Err(_) => return TestResult::Fail("the eDP caps must read"),
    };
    if caps.edp_rev != 0x05
        || caps.link_rates[..4] != [8100, 13500, 27000, 0]
        || caps.dsc != DscDpcd(E1_DSC)
        || !caps.dsc_capable()
        || caps.limits(0).rates[..4] != [162_000, 270_000, 540_000, 0]
    {
        return TestResult::Fail("the eDP caps must decode as intel_edp_init_dpcd reads them");
    }
    // eDP 1.3: no rate table or DSC read (intel_edp_get_dsc_sink_cap).
    let mut old = Sink::new();
    old.dpcd[0x700] = 0x02;
    old.dpcd[0x60] = 0x01;
    match EdpCaps::read(&mut old) {
        Ok(caps) if !caps.dsc_capable() && caps.dsc == DscDpcd::default() => {}
        _ => return TestResult::Fail("an eDP 1.3 panel has no DSC caps"),
    }
    if old.reads != [0x000, 0x700] {
        return TestResult::Fail("eDP 1.3 reads only the receiver caps and revision");
    }
    // DP: DPCD 1.4+ reads DSC and FEC capabilities; a branch is flagged.
    let mut dp = Sink::new();
    dp.dpcd[0x60..0x70].copy_from_slice(&D1_DSC);
    dp.dpcd[0x90] = 0x01;
    let mut receiver = [0u8; 16];
    receiver[0] = 0x14;
    receiver[5] = 0x01;
    match read_dp_sink(&mut dp, &receiver) {
        Ok(sink) if sink == d1_sink(true, true) => {}
        _ => return TestResult::Fail("a DP 1.4 sink's DSC and FEC caps must read"),
    }
    receiver[0] = 0x12;
    match read_dp_sink(&mut Sink::new(), &receiver) {
        Ok(sink) if !sink.dsc.dpcd.supports_dsc() && !sink.dsc.fec_capable => {}
        _ => return TestResult::Fail("a DP 1.2 sink has no DSC caps"),
    }
    // intel_dp_sink_set_dsc_decompression: read-modify-write of bit 0.
    let mut s = Sink::new();
    s.dpcd[0x160] = 0x02;
    if set_sink_decompression(&mut s, true).is_err()
        || s.dpcd[0x160] != 0x03
        || set_sink_decompression(&mut s, false).is_err()
        || s.dpcd[0x160] != 0x02
    {
        return TestResult::Fail("DP_DECOMPRESSION_EN is set and cleared alone");
    }
    // intel_dp_sink_set_fec_ready: FEC_READY, then the detected flags.
    let mut s = Sink::new();
    if set_sink_fec_ready(&mut s, true).is_err()
        || s.writes != [(0x120, alloc::vec![1]), (0x280, alloc::vec![3])]
    {
        return TestResult::Fail("FEC ready writes DP_FEC_CONFIGURATION then clears status");
    }
    s.writes.clear();
    if set_sink_fec_ready(&mut s, false).is_err() || s.writes != [(0x120, alloc::vec![0])] {
        return TestResult::Fail("FEC not-ready clears DP_FEC_CONFIGURATION alone");
    }
    s.dpcd[0x280] = 0;
    if wait_fec_detected(&mut s, |_| {}) {
        return TestResult::Fail("FEC decode must be detected, not assumed");
    }
    s.dpcd[0x280] = DP_FEC_DECODE_EN_DETECTED;
    if !wait_fec_detected(&mut s, |_| {}) {
        return TestResult::Fail("DP_FEC_DECODE_EN_DETECTED ends the wait");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_xelpg_dsc",
    smoke_xelpg_dsc_sink_caps_decompression_and_fec_ready
);

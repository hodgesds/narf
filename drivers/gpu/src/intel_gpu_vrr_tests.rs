//! Native kernel test fixtures for Intel GPU Variable Refresh Rate (VRR / Adaptive Sync).

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{
    dp_link_training::DpcdCaps,
    intel_gpu_aux::MmioWindow,
    intel_gpu_modeset::Mode,
    intel_gpu_vrr::{
        capture_mode_from_hw, cmrr_disable, cmrr_enable, install_vbt, installed_vrr,
        is_cmrr_active, is_vrr_active, mode_vrefresh, msa_timing_par_ignore_wanted, on_plane_flip,
        populate_card, program_cmrr_timings, program_fixed_rr_timings, program_vrr_timings,
        recompute_timings_for_modeset, set_context_latency_for_crtc, sink_vrr_range, vrr_disable,
        vrr_enable, vrr_excludes_psr, vrr_is_variable, vrr_send_push, vrr_status_string, CmrrRate,
        CmrrTimings, DisplayVrrIp, VbtVrr, VrrComputeOpts, VrrConnectorKind, VrrRange, VrrTimings,
        VrrTranscoder, EMP_AS_SDP_TL_OFFSET, TRANSCODER_A_BASE, TRANS_CMRR_M_HI_OFFSET,
        TRANS_CMRR_M_LO_OFFSET, TRANS_CMRR_N_HI_OFFSET, TRANS_CMRR_N_LO_OFFSET, TRANS_PUSH_EN,
        TRANS_PUSH_OFFSET, TRANS_VRR_CTL_OFFSET, TRANS_VRR_FLIPLINE_OFFSET, TRANS_VRR_VMAX_OFFSET,
        TRANS_VRR_VMIN_OFFSET, TRANS_VRR_VSYNC_OFFSET, VRR_CTL_CMRR_ENABLE, VRR_CTL_FLIP_LINE_EN,
        VRR_CTL_IGN_MAX_STRETCH, VRR_CTL_VRR_ENABLE, VRR_STATE,
    },
};

// ── Test MMIO Fixture ────────────────────────────────────────────────────────

#[derive(Debug)]
struct MockMmio {
    values: RefCell<BTreeMap<u64, u32>>,
    writes: RefCell<Vec<(u64, u32)>>,
    reads: Cell<usize>,
}

impl MockMmio {
    fn new() -> Self {
        Self {
            values: RefCell::new(BTreeMap::new()),
            writes: RefCell::new(Vec::new()),
            reads: Cell::new(0),
        }
    }

    fn written(&self, reg: u64) -> Vec<u32> {
        self.writes
            .borrow()
            .iter()
            .filter(|(r, _)| *r == reg)
            .map(|(_, v)| *v)
            .collect()
    }

    fn set(&self, reg: u64, val: u32) {
        self.values.borrow_mut().insert(reg, val);
    }
}

impl MmioWindow for MockMmio {
    fn read32(&self, reg: u64) -> u32 {
        self.reads.set(self.reads.get() + 1);
        *self.values.borrow().get(&reg).unwrap_or(&0)
    }

    fn write32(&self, reg: u64, val: u32) {
        self.writes.borrow_mut().push((reg, val));
        self.values.borrow_mut().insert(reg, val);
    }
}

// ── Mode Helper ──────────────────────────────────────────────────────────────

fn mode_1080p60() -> Mode {
    Mode {
        pixel_clock_khz: 148_500,
        h_active: 1920,
        h_total: 2200,
        h_sync_start: 2008,
        h_sync_end: 2052,
        v_active: 1080,
        v_total: 1125,
        v_sync_start: 1084,
        v_sync_end: 1089,
        h_sync_positive: true,
        v_sync_positive: true,
    }
}

// ── Test 1: VRR Range Construction & Validation ──────────────────────────────

fn smoke_intel_vrr_range_limits() -> TestResult {
    // Valid 48..144 Hz
    let r = VrrRange::new(48, 144).expect("valid range");
    assert_eq!(r.min_hz, 48);
    assert_eq!(r.max_hz, 144);
    assert!(r.supports_refresh(48));
    assert!(r.supports_refresh(60));
    assert!(r.supports_refresh(144));
    assert!(!r.supports_refresh(30));
    assert!(!r.supports_refresh(165));

    // Valid 40..60 Hz (exactly 20 Hz delta, >= 10)
    assert!(VrrRange::new(40, 60).is_some());

    // Invalid: min is 0
    assert_eq!(VrrRange::new(0, 60), None);

    // Invalid: max <= min
    assert_eq!(VrrRange::new(60, 60), None);
    assert_eq!(VrrRange::new(60, 50), None);

    // Invalid: delta < 10 Hz
    assert_eq!(VrrRange::new(50, 55), None);
    assert_eq!(VrrRange::new(50, 59), None);

    // Invalid: delta exactly 10 Hz — Linux requires spread > 10 Hz
    // (`intel_vrr_is_capable`), not >= 10.
    assert_eq!(VrrRange::new(50, 60), None);

    // Mode refresh calculation
    let m = mode_1080p60();
    assert_eq!(mode_vrefresh(&m), 60);

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_gpu_vrr", smoke_intel_vrr_range_limits);

// ── Test 2: VRR EDID Range Parsing ───────────────────────────────────────────

fn smoke_intel_vrr_edid_parsing() -> TestResult {
    // Build a synthetic 128-byte EDID 1.4 with continuous frequency and a range descriptor
    let mut edid = [0u8; 128];
    edid[0..8].copy_from_slice(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]);
    edid[0x12] = 1; // EDID version 1
    edid[0x13] = 4; // EDID revision 4
    edid[0x18] = 0x01; // Continuous frequency supported

    // Detailed timing block 4 at offset 54 + 3 * 18 = 108
    let desc = &mut edid[108..126];
    desc[0] = 0;
    desc[1] = 0;
    desc[2] = 0;
    desc[3] = 0xfd; // Range descriptor tag
    desc[4] = 0x00; // No offset flags
    desc[5] = 48; // Min vertical rate 48 Hz
    desc[6] = 144; // Max vertical rate 144 Hz
    desc[7] = 30; // Min horizontal rate kHz
    desc[8] = 160; // Max horizontal rate kHz
    desc[9] = 20; // Pixel clock max / 10
    desc[10] = 0x01; // RANGE_LIMITS_ONLY flag

    let range = VrrRange::from_edid(&edid).expect("parsed VRR range");
    assert_eq!(range.min_hz, 48);
    assert_eq!(range.max_hz, 144);

    // With DPCD where MSA timing is ignored (bit 6 of DPCD 7 set)
    let mut dpcd = [0u8; 16];
    dpcd[7] = 0x40; // DPCD_MSA_TIMING_PAR_IGNORED
    assert_eq!(
        VrrRange::from_edid_and_dpcd(&edid, Some(&dpcd)),
        Some(range)
    );

    // With DPCD where MSA timing is NOT ignored
    dpcd[7] = 0x00;
    assert_eq!(VrrRange::from_edid_and_dpcd(&edid, Some(&dpcd)), None);

    // EDID without range descriptor returns None
    let blank_edid = [0u8; 128];
    assert_eq!(VrrRange::from_edid(&blank_edid), None);

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_gpu_vrr", smoke_intel_vrr_edid_parsing);

// ── Test 3: Modeline Timing Calculations Across Display Generations ──────────

fn smoke_intel_vrr_timings_computation() -> TestResult {
    let m = mode_1080p60();
    let range = VrrRange::new(48, 144).unwrap();

    // Gen12 computation: vmin is the minimum vtotal (1125 — the
    // max_vfreq term, ceil(148.5MHz / (2200 * 144)) = 469, is below
    // vtotal), flipline == vmin, guardband is the vblank length at
    // the minimum vtotal (1125 - 1080 = 45) and is stored even for
    // Gen12 (Linux 2025-09), where the hardware consumes the
    // derived pipeline_full value instead.
    let t_gen12 = VrrTimings::compute(&m, range, DisplayVrrIp::Gen12).expect("Gen12 timings");
    assert_eq!(t_gen12.vmin, 1125);
    // vmax = (148500 * 1000) / (2200 * 48) = 148500000 / 105600 = 1406
    assert_eq!(t_gen12.vmax, 1406);
    assert_eq!(t_gen12.flipline, 1125);
    assert_eq!(t_gen12.guardband, 45);
    assert_eq!(t_gen12.pipeline_full, 45);
    // Gen12 has no VSYNC register, so the legacy compute leaves the
    // AS-SDP-gated VSYNC fields clear.
    assert_eq!(t_gen12.vsync_start, 0);
    assert_eq!(t_gen12.vsync_end, 0);

    // Display 14 (Meteor Lake / Xe_LPG) computation
    let t_display14 =
        VrrTimings::compute(&m, range, DisplayVrrIp::Display14).expect("Display14 timings");
    assert_eq!(t_display14.vmin, 1125);
    assert_eq!(t_display14.vmax, 1406);
    assert_eq!(t_display14.flipline, 1125);
    // Guardband: vmin - v_active = 1125 - 1080 = 45 (Linux
    // `intel_vrr_compute_config_late`: the vblank length at the
    // minimum vtotal).
    assert_eq!(t_display14.guardband, 45);
    assert_eq!(t_display14.pipeline_full, 0);
    assert_eq!(t_display14.vsync_start, 41);
    assert_eq!(t_display14.vsync_end, 36);

    // Hardware max clamping: low refresh range (e.g. 10 Hz)
    let low_range = VrrRange::new(10, 60).unwrap();
    let t_low = VrrTimings::compute(&m, low_range, DisplayVrrIp::Display14).expect("low range");
    // Raw vmax = 148500000 / (2200 * 10) = 6750, fits in 0x1fff (8191)
    assert_eq!(t_low.vmax, 6750);

    // Mode outside range: 60Hz mode with 75..144Hz range fails
    let high_range = VrrRange::new(75, 144).unwrap();
    assert_eq!(
        VrrTimings::compute(&m, high_range, DisplayVrrIp::Display14),
        None
    );

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_intel_vrr_timings_computation
);

// ── Test 4: Register Programming Across Generations ──────────────────────────

fn smoke_intel_vrr_register_programming() -> TestResult {
    let io = MockMmio::new();
    let m = mode_1080p60();
    let range = VrrRange::new(48, 144).unwrap();
    let timings = VrrTimings::compute(&m, range, DisplayVrrIp::Display14).unwrap();

    // Gen12 on Transcoder A: values are direct (vmin = 1125, vmax = 1406, flipline = 1125)
    program_vrr_timings(&io, VrrTranscoder::A, DisplayVrrIp::Gen12, &timings).unwrap();
    assert_eq!(
        io.written(VrrTranscoder::A.base() + TRANS_VRR_VMIN_OFFSET),
        vec![1125]
    );
    assert_eq!(
        io.written(VrrTranscoder::A.base() + TRANS_VRR_VMAX_OFFSET),
        vec![1406]
    );
    assert_eq!(
        io.written(VrrTranscoder::A.base() + TRANS_VRR_FLIPLINE_OFFSET),
        vec![1125]
    );
    // Gen12 has no TRANS_VRR_VSYNC or EMP_AS_SDP_TL writes
    assert!(io
        .written(VrrTranscoder::A.base() + TRANS_VRR_VSYNC_OFFSET)
        .is_empty());
    assert!(io
        .written(VrrTranscoder::A.base() + EMP_AS_SDP_TL_OFFSET)
        .is_empty());

    // Display 13 on Transcoder B: values are val - 1 (1124, 1405, 1124)
    program_vrr_timings(&io, VrrTranscoder::B, DisplayVrrIp::Display13, &timings).unwrap();
    assert_eq!(
        io.written(VrrTranscoder::B.base() + TRANS_VRR_VMIN_OFFSET),
        vec![1124]
    );
    assert_eq!(
        io.written(VrrTranscoder::B.base() + TRANS_VRR_VMAX_OFFSET),
        vec![1405]
    );
    assert_eq!(
        io.written(VrrTranscoder::B.base() + TRANS_VRR_FLIPLINE_OFFSET),
        vec![1124]
    );

    // Display 14 on Transcoder C: writes TRANS_VRR_VSYNC
    program_vrr_timings(&io, VrrTranscoder::C, DisplayVrrIp::Display14, &timings).unwrap();
    let expected_vsync = ((timings.vsync_end & 0x1fff) << 16) | (timings.vsync_start & 0x1fff);
    assert_eq!(
        io.written(VrrTranscoder::C.base() + TRANS_VRR_VSYNC_OFFSET),
        vec![expected_vsync]
    );

    // Display 20 on Transcoder D: writes EMP_AS_SDP_TL
    program_vrr_timings(&io, VrrTranscoder::D, DisplayVrrIp::Display20, &timings).unwrap();
    assert_eq!(
        io.written(VrrTranscoder::D.base() + EMP_AS_SDP_TL_OFFSET),
        vec![timings.vsync_start & 0x1fff]
    );

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_intel_vrr_register_programming
);

// ── Test 5: Enable, Disable, and Flip Push Sequencing ─────────────────────────

fn smoke_intel_vrr_enable_disable_sequencing() -> TestResult {
    let io = MockMmio::new();
    let trans = VrrTranscoder::A;
    let base = trans.base();

    // Initially inactive
    assert!(!is_vrr_active(&io, trans));

    // Enable for Display 14 with guardband 42:
    vrr_enable(&io, trans, DisplayVrrIp::Display14, 42).unwrap();
    // 1) TRANS_PUSH written with TRANS_PUSH_EN
    assert_eq!(io.written(base + TRANS_PUSH_OFFSET), vec![TRANS_PUSH_EN]);
    // 2) TRANS_VRR_CTL written with ENABLE | FLIP_LINE_EN | guardband
    let expected_ctl = VRR_CTL_VRR_ENABLE | VRR_CTL_FLIP_LINE_EN | 42;
    assert_eq!(io.written(base + TRANS_VRR_CTL_OFFSET), vec![expected_ctl]);
    assert!(is_vrr_active(&io, trans));

    // Send dynamic flip push
    vrr_send_push(&io, trans).unwrap();
    assert_eq!(
        io.written(base + TRANS_PUSH_OFFSET),
        vec![TRANS_PUSH_EN, TRANS_PUSH_EN]
    );

    // Disable: clears VRR_ENABLE, keeps FLIP_LINE_EN and guardband, resets PUSH
    vrr_disable(&io, trans, DisplayVrrIp::Display14).unwrap();
    let expected_disable_ctl = VRR_CTL_FLIP_LINE_EN | 42;
    assert_eq!(
        io.written(base + TRANS_VRR_CTL_OFFSET),
        vec![expected_ctl, expected_disable_ctl]
    );
    assert_eq!(
        io.written(base + TRANS_PUSH_OFFSET),
        vec![TRANS_PUSH_EN, TRANS_PUSH_EN, 0]
    );
    assert!(!is_vrr_active(&io, trans));

    // Enable for Display 13: includes VRR_CTL_IGN_MAX_STRETCH
    vrr_enable(&io, trans, DisplayVrrIp::Display13, 0).unwrap();
    let expected_d13_ctl = VRR_CTL_VRR_ENABLE | VRR_CTL_FLIP_LINE_EN | VRR_CTL_IGN_MAX_STRETCH;
    assert_eq!(
        *io.written(base + TRANS_VRR_CTL_OFFSET).last().unwrap(),
        expected_d13_ctl
    );

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_intel_vrr_enable_disable_sequencing
);

// ── Test 6: Global State & Dynamic Plane Flip Push ────────────────────────────

fn smoke_intel_vrr_state_and_plane_flip() -> TestResult {
    let io = MockMmio::new();
    let crtc_id = 1;

    // Disabled initially
    VRR_STATE.set_enabled(crtc_id, false);
    assert!(!VRR_STATE.is_enabled(crtc_id));
    on_plane_flip(crtc_id, &io);
    assert!(io.written(TRANSCODER_A_BASE + TRANS_PUSH_OFFSET).is_empty());

    // Enable VRR on CRTC 1
    VRR_STATE.set_enabled(crtc_id, true);
    assert!(VRR_STATE.is_enabled(crtc_id));

    // Flip triggers dynamic push
    on_plane_flip(crtc_id, &io);
    assert_eq!(
        io.written(TRANSCODER_A_BASE + TRANS_PUSH_OFFSET),
        vec![TRANS_PUSH_EN]
    );

    // Clean up
    VRR_STATE.set_enabled(crtc_id, false);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_intel_vrr_state_and_plane_flip
);

// ── Test 7: CMRR Rate Fractions & Timings Computation ─────────────────────────

fn smoke_intel_cmrr_rate_fractions_and_timings_computation() -> TestResult {
    // Standard rates fractions
    assert_eq!(CmrrRate::Fps23_976.fraction(), (24_000, 1001));
    assert_eq!(CmrrRate::Fps24.fraction(), (24, 1));
    assert_eq!(CmrrRate::Fps25.fraction(), (25, 1));
    assert_eq!(CmrrRate::Fps29_970.fraction(), (30_000, 1001));
    assert_eq!(CmrrRate::Fps30.fraction(), (30, 1));
    assert_eq!(CmrrRate::Fps48.fraction(), (48, 1));
    assert_eq!(CmrrRate::Fps50.fraction(), (50, 1));
    assert_eq!(CmrrRate::Fps59_940.fraction(), (60_000, 1001));
    assert_eq!(CmrrRate::Fps60.fraction(), (60, 1));
    assert_eq!(CmrrRate::Custom { num: 120, den: 1 }.fraction(), (120, 1));

    // Generation support: Gen12 and Display 13 do not support CMRR
    assert!(!DisplayVrrIp::Gen12.supports_cmrr());
    assert!(!DisplayVrrIp::Display13.supports_cmrr());
    assert!(DisplayVrrIp::Display14.supports_cmrr());
    assert!(DisplayVrrIp::Display20.supports_cmrr());
    assert!(DisplayVrrIp::Display30.supports_cmrr());

    let m = mode_1080p60();
    assert_eq!(
        CmrrTimings::compute(&m, CmrrRate::Fps60, DisplayVrrIp::Gen12),
        None
    );
    assert_eq!(
        CmrrTimings::compute(&m, CmrrRate::Fps60, DisplayVrrIp::Display13),
        None
    );

    // 1080p60 on Display 14 at exact 60 Hz: M == N
    let t60 = CmrrTimings::compute(&m, CmrrRate::Fps60, DisplayVrrIp::Display14)
        .expect("Display 14 60Hz CMRR");
    assert_eq!(t60.cmrr_n, 1_000_000_000);
    assert_eq!(t60.cmrr_m, 1_000_000_000);
    assert_eq!(t60.vmin, 1125);
    assert_eq!(t60.vmax, 1125);
    assert_eq!(t60.flipline, 1125);
    assert_eq!(t60.guardband, 45);

    // 1080p60 on Display 20 at 59.940 Hz: M = 999_000_999
    let t59 = CmrrTimings::compute(&m, CmrrRate::Fps59_940, DisplayVrrIp::Display20)
        .expect("Display 20 59.940Hz CMRR");
    assert_eq!(t59.cmrr_n, 1_000_000_000);
    assert_eq!(t59.cmrr_m, 999_000_999);

    // 1080p60 on Display 30 at 24 Hz: M = 400_000_000
    let t24 = CmrrTimings::compute(&m, CmrrRate::Fps24, DisplayVrrIp::Display30)
        .expect("Display 30 24Hz CMRR");
    assert_eq!(t24.cmrr_n, 1_000_000_000);
    assert_eq!(t24.cmrr_m, 400_000_000);

    // 1080p60 on Display 30 at 23.976 Hz: M = 399_600_399
    let t23 = CmrrTimings::compute(&m, CmrrRate::Fps23_976, DisplayVrrIp::Display30)
        .expect("Display 30 23.976Hz CMRR");
    assert_eq!(t23.cmrr_n, 1_000_000_000);
    assert_eq!(t23.cmrr_m, 399_600_399);

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_intel_cmrr_rate_fractions_and_timings_computation
);

// ── Test 8: CMRR Register Programming & Sequencing ───────────────────────────

fn smoke_intel_cmrr_register_programming_and_sequencing() -> TestResult {
    let io = MockMmio::new();
    let trans = VrrTranscoder::A;
    let base = trans.base();
    let m = mode_1080p60();

    let timings = CmrrTimings::compute(&m, CmrrRate::Fps59_940, DisplayVrrIp::Display14).unwrap();

    // Program CMRR registers
    program_cmrr_timings(&io, trans, DisplayVrrIp::Display14, &timings).unwrap();
    assert_eq!(
        io.written(base + TRANS_CMRR_M_LO_OFFSET),
        vec![timings.cmrr_m as u32]
    );
    assert_eq!(
        io.written(base + TRANS_CMRR_M_HI_OFFSET),
        vec![(timings.cmrr_m >> 32) as u32]
    );
    assert_eq!(
        io.written(base + TRANS_CMRR_N_LO_OFFSET),
        vec![timings.cmrr_n as u32]
    );
    assert_eq!(
        io.written(base + TRANS_CMRR_N_HI_OFFSET),
        vec![(timings.cmrr_n >> 32) as u32]
    );

    // Enable CMRR
    assert!(!is_cmrr_active(&io, trans));
    cmrr_enable(&io, trans, DisplayVrrIp::Display14, timings.guardband).unwrap();
    assert_eq!(io.written(base + TRANS_PUSH_OFFSET), vec![TRANS_PUSH_EN]);
    let expected_ctl = VRR_CTL_VRR_ENABLE | VRR_CTL_CMRR_ENABLE | VRR_CTL_FLIP_LINE_EN | 45;
    assert_eq!(io.written(base + TRANS_VRR_CTL_OFFSET), vec![expected_ctl]);
    assert!(is_cmrr_active(&io, trans));

    // Disable CMRR
    cmrr_disable(&io, trans, DisplayVrrIp::Display14).unwrap();
    let expected_disable_ctl = VRR_CTL_FLIP_LINE_EN | 42;
    assert_eq!(
        io.written(base + TRANS_VRR_CTL_OFFSET),
        vec![expected_ctl, expected_disable_ctl]
    );
    assert_eq!(io.written(base + TRANS_PUSH_OFFSET), vec![TRANS_PUSH_EN, 0]);
    assert!(!is_cmrr_active(&io, trans));

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_intel_cmrr_register_programming_and_sequencing
);

// ── Test 9: Fixed Refresh Rate over VRR Timing Generator ─────────────────────

fn smoke_intel_vrr_fixed_rr_timings_programming() -> TestResult {
    let io = MockMmio::new();
    let trans = VrrTranscoder::A;
    let base = trans.base();
    let m = mode_1080p60();

    // Display 20 / 30: fixed refresh uses vtotal - 1 = 1124
    program_fixed_rr_timings(&io, trans, DisplayVrrIp::Display30, &m).unwrap();
    assert_eq!(io.written(base + TRANS_VRR_VMIN_OFFSET), vec![1124]);
    assert_eq!(io.written(base + TRANS_VRR_VMAX_OFFSET), vec![1124]);
    assert_eq!(io.written(base + TRANS_VRR_FLIPLINE_OFFSET), vec![1124]);

    // TRANS_VRR_VSYNC: start = 1125 - 1084 = 41, end = 1125 - 1089 = 36
    let expected_vsync = (36 << 16) | 41;
    assert_eq!(
        io.written(base + TRANS_VRR_VSYNC_OFFSET),
        vec![expected_vsync]
    );

    // EMP_AS_SDP_TL: vsync_start = 41
    assert_eq!(io.written(base + EMP_AS_SDP_TL_OFFSET), vec![41]);

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_intel_vrr_fixed_rr_timings_programming
);

// ── Test 10: Global CMRR State & Dynamic Flip Push ───────────────────────────

fn smoke_intel_vrr_cmrr_state_and_flip_push() -> TestResult {
    let io = MockMmio::new();
    let crtc_id = 1;
    let m = mode_1080p60();
    let timings = CmrrTimings::compute(&m, CmrrRate::Fps23_976, DisplayVrrIp::Display30).unwrap();

    assert!(!VRR_STATE.is_cmrr_enabled(crtc_id));
    assert_eq!(VRR_STATE.cmrr_timings(crtc_id), None);

    VRR_STATE.set_cmrr_timings(crtc_id, Some(timings));
    assert_eq!(VRR_STATE.cmrr_timings(crtc_id), Some(timings));

    VRR_STATE.set_cmrr_enabled(crtc_id, true);
    assert!(VRR_STATE.is_cmrr_enabled(crtc_id));

    // Flip push triggers under CMRR enabled state
    on_plane_flip(crtc_id, &io);
    assert_eq!(
        io.written(TRANSCODER_A_BASE + TRANS_PUSH_OFFSET),
        vec![TRANS_PUSH_EN]
    );

    // Clean up
    VRR_STATE.set_cmrr_enabled(crtc_id, false);
    VRR_STATE.set_cmrr_timings(crtc_id, None);
    assert!(!VRR_STATE.is_cmrr_enabled(crtc_id));

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_intel_vrr_cmrr_state_and_flip_push
);

// ── Test 11: CMRR Rate Strings & Parsing ─────────────────────────────────────

fn smoke_intel_cmrr_rate_strings() -> TestResult {
    let rates = [
        (CmrrRate::Fps23_976, "23.976"),
        (CmrrRate::Fps24, "24"),
        (CmrrRate::Fps25, "25"),
        (CmrrRate::Fps29_970, "29.970"),
        (CmrrRate::Fps30, "30"),
        (CmrrRate::Fps48, "48"),
        (CmrrRate::Fps50, "50"),
        (CmrrRate::Fps59_940, "59.940"),
        (CmrrRate::Fps60, "60"),
    ];

    for (rate, expected_str) in rates {
        assert_eq!(rate.as_str(), expected_str);
        assert_eq!(CmrrRate::from_str(expected_str), Some(rate));
        assert_eq!(
            CmrrRate::from_str(&alloc::format!("{}Hz", expected_str)),
            Some(rate)
        );
        assert_eq!(
            CmrrRate::from_str(&alloc::format!("{} fps", expected_str)),
            Some(rate)
        );
    }

    assert_eq!(CmrrRate::from_str("59.94"), Some(CmrrRate::Fps59_940));
    assert_eq!(CmrrRate::from_str("23.98"), Some(CmrrRate::Fps23_976));
    assert_eq!(CmrrRate::from_str("invalid"), None);
    assert_eq!(CmrrRate::from_str("144"), None);

    TestResult::Pass
}
kernel_test_in!("drivers/gpu/intel_gpu_vrr", smoke_intel_cmrr_rate_strings);

// ── Test 12: Hardware Transcoder Mode Capture ────────────────────────────────

fn smoke_intel_vrr_capture_mode_from_hw() -> TestResult {
    let io = MockMmio::new();
    let base = TRANSCODER_A_BASE;

    // Unprogrammed MMIO returns None
    assert_eq!(capture_mode_from_hw(&io, VrrTranscoder::A), None);

    // Mock 1920x1080@60 timings
    // htotal: active 1920 -> (1920 - 1) = 1919; total 2200 -> (2200 - 1) = 2199
    let htotal_val = 1919u32 | (2199u32 << 16);
    // hsync: start 2008 -> 2007; end 2052 -> 2051
    let hsync_val = 2007u32 | (2051u32 << 16);
    // vtotal: active 1080 -> 1079; total 1125 -> 1124
    let vtotal_val = 1079u32 | (1124u32 << 16);
    // vsync: start 1084 -> 1083; end 1089 -> 1088
    let vsync_val = 1083u32 | (1088u32 << 16);

    io.set(base, htotal_val);
    io.set(base + 0x008, hsync_val);
    io.set(base + 0x00c, vtotal_val);
    io.set(base + 0x014, vsync_val);

    let mode = capture_mode_from_hw(&io, VrrTranscoder::A).expect("captured mode");
    assert_eq!(mode.h_active, 1920);
    assert_eq!(mode.h_total, 2200);
    assert_eq!(mode.h_sync_start, 2008);
    assert_eq!(mode.h_sync_end, 2052);
    assert_eq!(mode.v_active, 1080);
    assert_eq!(mode.v_total, 1125);
    assert_eq!(mode.v_sync_start, 1084);
    assert_eq!(mode.v_sync_end, 1089);
    assert_eq!(mode.pixel_clock_khz, (2200 * 1125 * 60) / 1000);

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_intel_vrr_capture_mode_from_hw
);

// ── Test 13: VRR & CMRR Sysfs Telemetry and Controls ─────────────────────────

fn smoke_intel_vrr_sysfs_telemetry_and_controls() -> TestResult {
    use narf_filesystem::{sysfs::Kobject, FsError};

    let root = Kobject::new_root("test-card0");
    populate_card(0, &root);

    // Direct status formatting verification
    let direct_status = vrr_status_string();
    assert!(direct_status.contains("Pipe A:"));

    let vrr_dir = root.get_child("vrr").expect("vrr sysfs directory");

    // Status report formatting via sysfs attribute
    let status = vrr_dir.attr_show("vrr_status").expect("vrr_status");
    assert!(status.contains("Pipe A:"));
    assert!(status.contains("vrr_enabled:"));
    assert!(status.contains("cmrr_enabled:"));
    assert!(status.contains("cmrr_rate:"));

    // Pipe A enable control
    assert_eq!(vrr_dir.attr_show("pipeA_enabled"), Some("0\n".into()));
    assert_eq!(vrr_dir.attr_store("pipeA_enabled", b"1\n"), Some(Ok(())));
    assert!(VRR_STATE.is_enabled(1));
    assert_eq!(vrr_dir.attr_show("pipeA_enabled"), Some("1\n".into()));
    assert_eq!(vrr_dir.attr_store("pipeA_enabled", b"0"), Some(Ok(())));
    assert!(!VRR_STATE.is_enabled(1));
    assert_eq!(vrr_dir.attr_show("pipeA_enabled"), Some("0\n".into()));

    // Pipe A CMRR enable control
    assert_eq!(vrr_dir.attr_show("pipeA_cmrr_enabled"), Some("0\n".into()));
    assert_eq!(vrr_dir.attr_store("pipeA_cmrr_enabled", b"1"), Some(Ok(())));
    assert!(VRR_STATE.is_cmrr_enabled(1));
    assert_eq!(vrr_dir.attr_show("pipeA_cmrr_enabled"), Some("1\n".into()));
    assert_eq!(vrr_dir.attr_store("pipeA_cmrr_enabled", b"0"), Some(Ok(())));
    assert!(!VRR_STATE.is_cmrr_enabled(1));
    assert_eq!(vrr_dir.attr_show("pipeA_cmrr_enabled"), Some("0\n".into()));

    // Pipe A CMRR rate control
    assert_eq!(
        vrr_dir.attr_store("pipeA_cmrr_rate", b"59.940Hz\n"),
        Some(Ok(()))
    );
    assert_eq!(VRR_STATE.cmrr_rate(1), Some(CmrrRate::Fps59_940));
    assert_eq!(
        vrr_dir.attr_show("pipeA_cmrr_rate"),
        Some("59.940\n".into())
    );

    assert_eq!(
        vrr_dir.attr_store("pipeA_cmrr_rate", b"bad_rate"),
        Some(Err(FsError::InvalidData))
    );

    // Push trigger store
    assert_eq!(vrr_dir.attr_store("pipeA_push", b"1"), Some(Ok(())));
    assert_eq!(vrr_dir.attr_show("pipeA_push"), Some("0\n".into()));

    // Telemetry read attributes
    assert!(vrr_dir.attr_show("pipeA_vrr_live").is_some());
    assert!(vrr_dir.attr_show("pipeA_cmrr_live").is_some());
    assert!(vrr_dir.attr_show("pipeA_vmin").is_some());
    assert!(vrr_dir.attr_show("pipeA_vmax").is_some());
    assert!(vrr_dir.attr_show("pipeA_flipline").is_some());
    assert!(vrr_dir.attr_show("pipeA_guardband").is_some());
    assert!(vrr_dir.attr_show("pipeA_cmrr_m").is_some());
    assert!(vrr_dir.attr_show("pipeA_cmrr_n").is_some());

    // Clean up
    VRR_STATE.set_cmrr_rate(1, None);
    VRR_STATE.set_cmrr_timings(1, None);

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_intel_vrr_sysfs_telemetry_and_controls
);

// ── Test 14: Global VRR State Mode and Rate Accessors ────────────────────────

fn smoke_intel_vrr_state_mode_and_rate_accessors() -> TestResult {
    let crtc_id = 1;
    let m = mode_1080p60();

    assert_eq!(VRR_STATE.mode(crtc_id), None);
    assert_eq!(VRR_STATE.cmrr_rate(crtc_id), None);

    VRR_STATE.set_mode(crtc_id, Some(m));
    assert_eq!(VRR_STATE.mode(crtc_id), Some(m));

    VRR_STATE.set_cmrr_rate(crtc_id, Some(CmrrRate::Fps24));
    assert_eq!(VRR_STATE.cmrr_rate(crtc_id), Some(CmrrRate::Fps24));

    // Test out of bounds CRTC index
    assert_eq!(VRR_STATE.mode(99), None);
    assert_eq!(VRR_STATE.cmrr_rate(99), None);

    // Clean up
    VRR_STATE.set_mode(crtc_id, None);
    VRR_STATE.set_cmrr_rate(crtc_id, None);

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_intel_vrr_state_mode_and_rate_accessors
);

// ── Test 15: Sink Capability Matrix (`intel_vrr_is_capable`) ──────────────

/// A synthetic 128-byte EDID 1.4 with a range descriptor covering
/// `min_hz..=max_hz`.
fn fixture_edid_range(min_hz: u8, max_hz: u8) -> [u8; 128] {
    let mut edid = [0u8; 128];
    edid[0..8].copy_from_slice(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00]);
    edid[0x12] = 1;
    edid[0x13] = 4;
    edid[0x18] = 0x01; // Continuous frequency supported
    let desc = &mut edid[108..126];
    desc[0] = 0;
    desc[1] = 0;
    desc[2] = 0;
    desc[3] = 0xfd; // Range descriptor tag
    desc[4] = 0x00;
    desc[5] = min_hz;
    desc[6] = max_hz;
    desc[7] = 30;
    desc[8] = 160;
    desc[9] = 20;
    desc[10] = 0x01;
    edid
}

/// A decoded DPCD caps block with the Ignore-MSA bit as requested.
fn fixture_dpcd_caps(msa_ignored: bool) -> DpcdCaps {
    let mut raw = [0u8; 16];
    raw[0] = 0x14; // DPCD_REV 1.4
    raw[1] = 0x1e; // MAX_LINK_RATE HBR3
    raw[2] = 0x84; // 4 lanes, enhanced framing
    if msa_ignored {
        raw[7] = 0x40; // DPCD_MSA_TIMING_PAR_IGNORED
    }
    DpcdCaps::decode(&raw)
}

fn smoke_intel_vrr_sink_capability_matrix() -> TestResult {
    let edid = fixture_edid_range(48, 144);

    // DPCD decode retains the Ignore-MSA bit.
    assert!(fixture_dpcd_caps(true).msa_timing_par_ignored);
    assert!(!fixture_dpcd_caps(false).msa_timing_par_ignored);

    // DP, bit set, spread 96 Hz: capable.
    assert_eq!(
        sink_vrr_range(
            &edid,
            Some(&fixture_dpcd_caps(true)),
            VrrConnectorKind::DisplayPort,
            true,
        ),
        VrrRange::new(48, 144)
    );

    // DP, DPCD Ignore-MSA bit clear: not capable.
    assert_eq!(
        sink_vrr_range(
            &edid,
            Some(&fixture_dpcd_caps(false)),
            VrrConnectorKind::DisplayPort,
            true,
        ),
        None
    );

    // DP, no DPCD read at all: not capable.
    assert_eq!(
        sink_vrr_range(&edid, None, VrrConnectorKind::DisplayPort, true),
        None
    );

    // DP, EDID range spread exactly 10 Hz (48..58): not capable —
    // Linux requires spread > 10 Hz.
    let narrow = fixture_edid_range(48, 58);
    assert_eq!(
        sink_vrr_range(
            &narrow,
            Some(&fixture_dpcd_caps(true)),
            VrrConnectorKind::DisplayPort,
            true,
        ),
        None
    );

    // DP, EDID without any range descriptor: not capable.
    assert_eq!(
        sink_vrr_range(
            &[0u8; 128],
            Some(&fixture_dpcd_caps(true)),
            VrrConnectorKind::DisplayPort,
            true,
        ),
        None
    );

    // HDMI, everything else in order: never capable.
    assert_eq!(
        sink_vrr_range(
            &edid,
            Some(&fixture_dpcd_caps(true)),
            VrrConnectorKind::Hdmi,
            true,
        ),
        None
    );

    // No VRR hardware: never capable.
    assert_eq!(
        sink_vrr_range(
            &edid,
            Some(&fixture_dpcd_caps(true)),
            VrrConnectorKind::DisplayPort,
            false,
        ),
        None
    );

    // eDP: the VBT gate decides. No VBT installed → not capable.
    install_vbt(VbtVrr::Missing);
    assert_eq!(
        sink_vrr_range(
            &edid,
            Some(&fixture_dpcd_caps(true)),
            VrrConnectorKind::EmbeddedDisplayPort,
            true,
        ),
        None
    );
    // VBT says VRR is enabled → capable.
    install_vbt(VbtVrr::Present(true));
    assert_eq!(
        sink_vrr_range(
            &edid,
            Some(&fixture_dpcd_caps(true)),
            VrrConnectorKind::EmbeddedDisplayPort,
            true,
        ),
        VrrRange::new(48, 144)
    );
    // VBT says VRR is disabled → not capable (and the DPCD bit is
    // still required on top of the VBT flag).
    install_vbt(VbtVrr::Present(false));
    assert_eq!(
        sink_vrr_range(
            &edid,
            Some(&fixture_dpcd_caps(true)),
            VrrConnectorKind::EmbeddedDisplayPort,
            true,
        ),
        None
    );
    assert_eq!(
        sink_vrr_range(
            &edid,
            Some(&fixture_dpcd_caps(false)),
            VrrConnectorKind::EmbeddedDisplayPort,
            true,
        ),
        None
    );
    // Restore the no-VBT state so later tests see a clean global.
    install_vbt(VbtVrr::Missing);
    assert_eq!(installed_vrr(), VbtVrr::Missing);

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_intel_vrr_sink_capability_matrix
);

// ── Test 16: Per-Modeset Compute (`intel_vrr_compute_config`) ─────────────

fn smoke_intel_vrr_per_modeset_compute() -> TestResult {
    let m = mode_1080p60();
    let range = VrrRange::new(48, 144).unwrap();

    // Interlace and joiner bail.
    assert_eq!(
        VrrTimings::compute_config(
            &m,
            range,
            DisplayVrrIp::Display14,
            VrrComputeOpts {
                interlaced: true,
                ..Default::default()
            },
        ),
        None
    );
    assert_eq!(
        VrrTimings::compute_config(
            &m,
            range,
            DisplayVrrIp::Display14,
            VrrComputeOpts {
                joiner: true,
                ..Default::default()
            },
        ),
        None
    );

    // vmin >= vmax bails instead of clamping: a 60 Hz mode against a
    // range whose floor is 60 Hz has no room to vary
    // (vmax = 1125 = vmin).
    let floor60 = VrrRange::new(60, 144).unwrap();
    assert_eq!(
        VrrTimings::compute_config(&m, floor60, DisplayVrrIp::Display14, Default::default()),
        None
    );
    // Same for a 48 Hz mode against a 48 Hz floor.
    let mut m48 = m;
    m48.pixel_clock_khz = 118_800; // 2200 * 1125 * 48 / 1000
    assert_eq!(mode_vrefresh(&m48), 48);
    assert_eq!(
        VrrTimings::compute_config(&m48, range, DisplayVrrIp::Display14, Default::default()),
        None
    );

    // A mode just above the floor has room: 60 Hz against 48..144
    // computes, with flipline == vmin.
    let t = VrrTimings::compute_config(&m, range, DisplayVrrIp::Display14, Default::default())
        .expect("in-range compute");
    assert_eq!(t.vmin, 1125);
    assert_eq!(t.vmax, 1406);
    assert_eq!(t.flipline, t.vmin);

    // AS-SDP gating: without it the VSYNC fields stay clear and the
    // registers stay unwritten on display 14+.
    let io = MockMmio::new();
    let t_no_sdp = VrrTimings::compute_config(
        &m,
        range,
        DisplayVrrIp::Display14,
        VrrComputeOpts {
            as_sdp: false,
            ..Default::default()
        },
    )
    .expect("no-SDP compute");
    assert_eq!(t_no_sdp.vsync_start, 0);
    assert_eq!(t_no_sdp.vsync_end, 0);
    program_vrr_timings(&io, VrrTranscoder::C, DisplayVrrIp::Display14, &t_no_sdp).unwrap();
    assert!(io
        .written(VrrTranscoder::C.base() + TRANS_VRR_VSYNC_OFFSET)
        .is_empty());
    // With AS SDP the VSYNC register is written.
    let t_sdp = VrrTimings::compute_config(
        &m,
        range,
        DisplayVrrIp::Display14,
        VrrComputeOpts {
            as_sdp: true,
            ..Default::default()
        },
    )
    .expect("AS-SDP compute");
    assert_eq!(t_sdp.vsync_start, 41);
    assert_eq!(t_sdp.vsync_end, 36);
    program_vrr_timings(&io, VrrTranscoder::C, DisplayVrrIp::Display14, &t_sdp).unwrap();
    assert_eq!(
        io.written(VrrTranscoder::C.base() + TRANS_VRR_VSYNC_OFFSET),
        vec![((36 & 0x1fff) << 16) | 41]
    );

    // Per-modeset recompute stores mode + range + timings in the
    // global state, and clears them when the sink has no range or
    // the compute bails.
    let crtc_id = 1;
    let stored = recompute_timings_for_modeset(
        crtc_id,
        &m,
        Some(range),
        DisplayVrrIp::Gen12,
        Default::default(),
    )
    .expect("recompute stores timings");
    assert_eq!(VRR_STATE.mode(crtc_id), Some(m));
    assert_eq!(VRR_STATE.range(crtc_id), Some(range));
    assert_eq!(VRR_STATE.timings(crtc_id), Some(stored));
    assert_eq!(stored.pipeline_full, 45);

    assert_eq!(
        recompute_timings_for_modeset(crtc_id, &m, None, DisplayVrrIp::Gen12, Default::default()),
        None
    );
    assert_eq!(VRR_STATE.range(crtc_id), None);
    assert_eq!(VRR_STATE.timings(crtc_id), None);
    assert_eq!(
        recompute_timings_for_modeset(
            crtc_id,
            &m,
            Some(floor60),
            DisplayVrrIp::Gen12,
            Default::default(),
        ),
        None
    );
    assert_eq!(VRR_STATE.range(crtc_id), Some(floor60));
    assert_eq!(VRR_STATE.timings(crtc_id), None);

    // Clean up.
    VRR_STATE.set_mode(crtc_id, None);
    VRR_STATE.set_range(crtc_id, None);
    VRR_STATE.set_timings(crtc_id, None);

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_intel_vrr_per_modeset_compute
);

// ── Test 17: VBT VRR Feature Flag ──────────────────────────────────────────
//
// The flag lives in the BDB_LFP_POWER block (id 44) at offset 56;
// the fixture VBT below is built with the same block walker the
// production parser uses (a `$VBT` header + BDB header + blocks).
fn fixture_vbt_with_lfp_power(vrr_bits: u16) -> alloc::vec::Vec<u8> {
    // BDB header: "BIOS_DATA_BLOCK", version 233, header_size 32.
    // Block layout after the 32-byte BDB header: [id 44][size le16]
    // [136 bytes of LFP_POWER data]. The VBT header points at the
    // BDB offset; the parser only needs the BDB walk to find it.
    let mut bdb = alloc::vec::Vec::new();
    bdb.extend_from_slice(b"BIOS_DATA_BLOCK");
    bdb.push(0); // 16-byte signature
    bdb.extend_from_slice(&233u16.to_le_bytes()); // version
    bdb.extend_from_slice(&32u16.to_le_bytes()); // header_size
    let bdb_size_pos = bdb.len();
    bdb.extend_from_slice(&0u16.to_le_bytes()); // bdb_size (patched below)
                                                // Pad to the 32-byte header.
    while bdb.len() < 32 {
        bdb.push(0);
    }
    bdb.push(44); // BDB_LFP_POWER
    bdb.extend_from_slice(&136u16.to_le_bytes());
    let mut block = [0u8; 136];
    block[56] = (vrr_bits & 0xff) as u8;
    block[57] = (vrr_bits >> 8) as u8;
    bdb.extend_from_slice(&block);
    let bdb_size = bdb.len() as u16;
    bdb[bdb_size_pos..bdb_size_pos + 2].copy_from_slice(&bdb_size.to_le_bytes());
    bdb
}

fn smoke_intel_vrr_vbt_feature_flag() -> TestResult {
    use crate::intel_gpu_vbt::Vbt;

    // The fixture has no `$VBT` header, so parse it the way the
    // production path does after `validate_vbt`: build the full
    // image with a header pointing at the BDB. `Vbt::parse` takes
    // the whole image; construct one: "$VBT" + padding to offset
    // 32, then the BDB block bytes.
    let build_image = |vrr_bits: u16| -> alloc::vec::Vec<u8> {
        let mut img = alloc::vec::Vec::new();
        img.extend_from_slice(b"$VBT");
        while img.len() < 20 {
            img.push(0);
        }
        // version (u16 @ 20), header_size (u16 @ 22), vbt_size (u16
        // @ 24), checksum (u8 @ 26), reserved (u8 @ 27),
        // bdb_offset (u32 @ 28).
        img.extend_from_slice(&233u16.to_le_bytes());
        img.extend_from_slice(&32u16.to_le_bytes());
        let vbt_size_pos = img.len();
        img.extend_from_slice(&0u16.to_le_bytes());
        img.push(0);
        img.push(0);
        img.extend_from_slice(&32u32.to_le_bytes()); // bdb_offset
        let bdb = fixture_vbt_with_lfp_power(vrr_bits);
        img.extend_from_slice(&bdb);
        let vbt_size = img.len() as u16;
        img[vbt_size_pos..vbt_size_pos + 2].copy_from_slice(&vbt_size.to_le_bytes());
        img
    };

    // Bit 0 set → the Pipe-A panel's VRR flag reads enabled.
    let vbt = Vbt::parse(&build_image(0x0001)).expect("fixture VBT parses");
    assert!(vbt.vrr_feature_enabled());
    // No bits set → disabled.
    let vbt = Vbt::parse(&build_image(0x0000)).expect("fixture VBT parses");
    assert!(!vbt.vrr_feature_enabled());
    // Only panel 1's bit set → panel 0 still reads disabled.
    let vbt = Vbt::parse(&build_image(0x0002)).expect("fixture VBT parses");
    assert!(!vbt.vrr_feature_enabled());

    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_intel_vrr_vbt_feature_flag
);

// ── Test 18: PSR×VRR Exclusion and DPCD-Want Follow the Fixed-RR Rule ────────

fn smoke_vrr_psr_exclusion_and_dpcd_want_follow_the_fixed_rr_rule() -> TestResult {
    let m = mode_1080p60();
    let range = VrrRange::new(48, 144).unwrap();
    let timings = VrrTimings::compute(&m, range, DisplayVrrIp::Display14).unwrap();

    // VRR off, CMRR off, no timings: nothing excludes PSR, nothing
    // wants the DPCD bit, SCL is 0.
    VRR_STATE.set_enabled(1, false);
    VRR_STATE.set_cmrr_enabled(1, false);
    VRR_STATE.set_timings(1, None);
    assert!(!vrr_is_variable(1));
    assert!(!vrr_excludes_psr(1));
    assert!(!msa_timing_par_ignore_wanted(1));
    assert_eq!(set_context_latency_for_crtc(1), 0);

    // VRR on, variable rate, timings programmed: PSR excluded, the
    // sink wants MSA-ignore, SCL is the wa floor 1.
    VRR_STATE.set_enabled(1, true);
    VRR_STATE.set_timings(1, Some(timings));
    assert!(vrr_is_variable(1));
    assert!(vrr_excludes_psr(1));
    assert!(msa_timing_par_ignore_wanted(1));
    assert_eq!(set_context_latency_for_crtc(1), 1);

    // VRR on but no timings (mode outside the range, or no range):
    // PSR is still excluded, but there is nothing to program on
    // the sink, so the DPCD bit is not wanted.
    VRR_STATE.set_timings(1, None);
    assert!(vrr_excludes_psr(1));
    assert!(!msa_timing_par_ignore_wanted(1));

    // Fixed-RR TG (CMRR on): PSR is allowed again and the sink
    // must NOT get MSA-ignore — it receives valid MSA timing at
    // the fixed rate. The TG still runs, so SCL stays 1.
    VRR_STATE.set_timings(1, Some(timings));
    VRR_STATE.set_cmrr_enabled(1, true);
    assert!(!vrr_is_variable(1));
    assert!(!vrr_excludes_psr(1));
    assert!(!msa_timing_par_ignore_wanted(1));
    assert_eq!(set_context_latency_for_crtc(1), 1);

    // CMRR alone (VRR property off) is also a running TG: SCL 1,
    // no PSR exclusion, no DPCD want.
    VRR_STATE.set_enabled(1, false);
    assert!(!vrr_excludes_psr(1));
    assert!(!msa_timing_par_ignore_wanted(1));
    assert_eq!(set_context_latency_for_crtc(1), 1);

    // An unknown CRTC has no VRR state at all.
    assert!(!vrr_is_variable(9));
    assert!(!vrr_excludes_psr(9));
    assert!(!msa_timing_par_ignore_wanted(9));
    assert_eq!(set_context_latency_for_crtc(9), 0);

    // Restore the shared state.
    VRR_STATE.set_enabled(1, false);
    VRR_STATE.set_cmrr_enabled(1, false);
    VRR_STATE.set_timings(1, None);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_vrr_psr_exclusion_and_dpcd_want_follow_the_fixed_rr_rule
);

// ── Test 19: Guardband Subtracts the Set-Context-Latency ────────────────────

fn smoke_vrr_guardband_subtracts_set_context_latency() -> TestResult {
    let m = mode_1080p60();
    let range = VrrRange::new(48, 144).unwrap();

    // 1080p60, range 48–144: vmin 1125, v_active 1080, so the
    // guardband is 45 with SCL 0 (Linux "Use SCL for computing
    // guardband": guardband = vmin − v_active − SCL).
    let base = VrrTimings::compute_config(
        &m,
        range,
        DisplayVrrIp::Display14,
        VrrComputeOpts::default(),
    )
    .unwrap();
    assert_eq!(base.guardband, 45);
    let one = VrrTimings::compute_config(
        &m,
        range,
        DisplayVrrIp::Display14,
        VrrComputeOpts {
            scl: 1,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(one.guardband, 44);
    // The floor holds: a huge SCL cannot drive the guardband
    // below the 8-line minimum.
    let huge = VrrTimings::compute_config(
        &m,
        range,
        DisplayVrrIp::Display14,
        VrrComputeOpts {
            scl: 100,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(huge.guardband, 8);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/intel_gpu_vrr",
    smoke_vrr_guardband_subtracts_set_context_latency
);

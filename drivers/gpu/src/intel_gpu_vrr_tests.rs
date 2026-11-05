//! Native kernel test fixtures for Intel GPU Variable Refresh Rate (VRR / Adaptive Sync).

use alloc::{collections::BTreeMap, vec, vec::Vec};
use core::cell::{Cell, RefCell};
use narf_kernel_test::{kernel_test_in, TestResult};

use crate::{
    intel_gpu_aux::MmioWindow,
    intel_gpu_modeset::Mode,
    intel_gpu_vrr::{
        is_vrr_active, mode_vrefresh, on_plane_flip, program_vrr_timings, vrr_disable, vrr_enable,
        vrr_send_push, DisplayVrrIp, VrrRange, VrrTimings, VrrTranscoder, EMP_AS_SDP_TL_OFFSET,
        TRANSCODER_A_BASE, TRANS_PUSH_EN, TRANS_PUSH_OFFSET, TRANS_VRR_CTL_OFFSET,
        TRANS_VRR_FLIPLINE_OFFSET, TRANS_VRR_VMAX_OFFSET, TRANS_VRR_VMIN_OFFSET,
        TRANS_VRR_VSYNC_OFFSET, VRR_CTL_FLIP_LINE_EN, VRR_CTL_IGN_MAX_STRETCH, VRR_CTL_VRR_ENABLE,
        VRR_STATE,
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

    // Gen12 computation
    let t_gen12 = VrrTimings::compute(&m, range, DisplayVrrIp::Gen12).expect("Gen12 timings");
    assert_eq!(t_gen12.vmin, 1125);
    // vmax = (148500 * 1000) / (2200 * 48) = 148500000 / 105600 = 1406
    assert_eq!(t_gen12.vmax, 1406);
    assert_eq!(t_gen12.flipline, 1125);
    assert_eq!(t_gen12.guardband, 0); // Gen12 does not pack guardband into CTL
    assert_eq!(t_gen12.vsync_start, 1125 - 1084); // 41
    assert_eq!(t_gen12.vsync_end, 1125 - 1089); // 36

    // Display 14 (Meteor Lake / Xe_LPG) computation
    let t_display14 =
        VrrTimings::compute(&m, range, DisplayVrrIp::Display14).expect("Display14 timings");
    assert_eq!(t_display14.vmin, 1125);
    assert_eq!(t_display14.vmax, 1406);
    assert_eq!(t_display14.flipline, 1125);
    // Guardband: (vsync_start + 1).max(8) = 42
    assert_eq!(t_display14.guardband, 42);
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

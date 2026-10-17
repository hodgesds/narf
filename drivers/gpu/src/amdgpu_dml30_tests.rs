//! Reference vectors for the DCN3.0 port. The expected values come from a
//! double-precision transliteration of the same Linux functions
//! (`display_mode_vba_30.c`, `display_rq_dlg_calc_30.c`, `dcn30_fpu.c`
//! constants) run on the host, at a Navi22-shaped SoC state: 1200 MHz DCFCLK
//! (and fabric), 16000 MT/s on twelve 16-bit channels, 1330 MHz display clock
//! ceilings, a 3650 MHz DENTIST VCO and a 50 MHz DCHUB reference.
use super::*;
use crate::amdgpu_dml::{Format, Plane, Timing};
use narf_kernel_test::{kernel_test_in, TestResult};

fn soc() -> Soc {
    Soc {
        dcfclk_khz: 1_200_000,
        fabric_khz: 1_200_000,
        socclk_khz: 1_000_000,
        dram_speed_mts: 16_000,
        channels: 12,
        channel_width_bytes: 2,
        max_dispclk_khz: 1_330_000,
        max_dppclk_khz: 1_330_000,
        max_phyclk_khz: 810_000,
        dentist_vco_khz: 3_650_000,
        dchub_refclk_khz: 50_000,
    }
}
#[allow(clippy::too_many_arguments)]
fn config(
    pclk: u32,
    hact: u32,
    htotal: u32,
    hfp: u32,
    hsync: u32,
    vact: u32,
    vtotal: u32,
    vfp: u32,
) -> Config {
    Config {
        timing: Timing {
            pixel_clock_khz: pclk,
            h_active: hact,
            h_total: htotal,
            h_front_porch: hfp,
            h_sync_width: hsync,
            v_active: vact,
            v_total: vtotal,
            v_front_porch: vfp,
            v_sync_width: 5,
            h_sync_positive: true,
            v_sync_positive: true,
        },
        plane: Plane {
            format: Format::Rgb32,
            surface_width: hact,
            surface_height: vact,
            viewport_width: hact,
            viewport_height: vact,
            pitch: hact,
            h_taps: 1,
            v_taps: 1,
        },
        dentist_vco_khz: 3_650_000,
        cursors: 0,
    }
}
fn observed(plan: &Plan) -> [u32; 28] {
    let d = &plan.registers.dlg;
    let t = &plan.registers.ttu;
    let p = &plan.prefetch;
    let w = &plan.hubbub;
    [
        p.v_startup,
        p.v_update_offset_pix,
        p.v_update_width_pix,
        p.v_ready_offset_pix,
        d.ref_freq_to_pix_freq,
        d.refcyc_per_htotal,
        d.refcyc_h_blank_end,
        d.min_dst_y_next_start,
        d.refcyc_x_after_scaler,
        d.dst_y_prefetch,
        d.dst_y_per_vm_vblank,
        d.dst_y_per_row_vblank,
        d.vratio_prefetch,
        d.refcyc_per_pte_group_vblank_l,
        d.dst_y_per_pte_row_nom_l,
        d.refcyc_per_pte_group_nom_l,
        d.refcyc_per_line_delivery_l,
        d.refcyc_per_line_delivery_pre_l,
        t.refcyc_per_req_delivery_l,
        t.refcyc_per_req_delivery_pre_l,
        t.min_ttu_vblank,
        t.qos_level_high_wm,
        w.urgent,
        w.urgent_latency,
        w.sr_enter,
        w.sr_exit,
        w.dram_clock_change,
        w.frac_urg_bw_nom,
    ]
}
/// Fixed point and double may round a truncated product to adjacent integers
/// only where the double result sits within 2^-24 of an integer; every field
/// here is a single truncation of a well-conditioned value, so allow one LSB
/// and nothing more.
fn close(a: &[u32; 28], b: &[u32; 28]) -> bool {
    a.iter().zip(b).all(|(x, y)| x.abs_diff(*y) <= 1)
}

fn dml30_matches_linux_reference_vectors() -> TestResult {
    let cases: [(&str, u8, Config, [u32; 28]); 5] = [
        (
            "1080p60",
            0,
            config(148_500, 1920, 2200, 88, 44, 1080, 1125, 4),
            [
                31, 550, 254, 340, 176527, 189629, 64, 4484, 68, 11, 1, 2, 699050, 370, 512, 94814,
                646, 321, 22065, 10971, 20565, 2962, 247, 191, 1104, 879, 20447, 11,
            ],
        ),
        (
            "1440p60 reduced blanking",
            0,
            config(241_500, 2560, 2720, 48, 32, 1440, 1481, 3),
            [
                40, 680, 254, 340, 108548, 144165, 23, 5912, 42, 12, 1, 2, 599186, 140, 512, 36041,
                530, 263, 13568, 6733, 20519, 2252, 247, 191, 1086, 861, 20447, 16,
            ],
        ),
        (
            "2160p30",
            0,
            config(297_000, 3840, 4400, 176, 88, 2160, 2250, 8),
            [
                31, 1100, 254, 340, 88263, 189629, 64, 8968, 34, 12, 1, 2, 599186, 185, 512, 47407,
                646, 320, 11032, 5472, 20506, 2962, 247, 191, 1080, 855, 20447, 19,
            ],
        ),
        (
            "480p60",
            0,
            config(25_175, 640, 800, 16, 96, 480, 525, 10),
            [
                16, 200, 95, 149, 1041286, 406752, 285, 2060, 407, 9, 1, 2, 1048576, 794, 512,
                203376, 1271, 632, 130160, 64750, 20597, 6355, 247, 191, 1118, 893, 20447, 2,
            ],
        ),
        (
            // CVT-RB 1080p60: 30 lines cannot hide the 404 us switch, so
            // the support search falls back to prefetch mode 1.
            "1080p60 reduced blanking",
            1,
            config(138_500, 1920, 2080, 48, 32, 1080, 1111, 3),
            [
                13, 520, 254, 340, 189273, 192231, 40, 4432, 73, 13, 1, 2, 524288, 375, 512, 96115,
                693, 693, 23659, 23659, 1234, 3003, 247, 191, 1108, 883, 20447, 8,
            ],
        ),
    ];
    for (name, mode, config, expected) in cases {
        let Ok(plan) = plan(&config, &soc()) else {
            let _ = name;
            return TestResult::Fail("reference mode refused");
        };
        if plan.prefetch_mode != mode || !close(&observed(&plan), &expected) {
            return TestResult::Fail("register vector differs from Linux DML30");
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dml30", dml30_matches_linux_reference_vectors);

fn dml30_uses_dcn30_parameters_not_dcn314() -> TestResult {
    let plan = plan(&config(148_500, 1920, 2200, 88, 44, 1080, 1125, 4), &soc()).unwrap();
    // 184 KiB DET, linear one-line swath, 84 PTE requests (row height 128),
    // MIN_DST_Y_NEXT_START from vblank start, not DCN3.1.4's VBA expression.
    if plan.geometry.det_buffer_bytes != 184 * 1024
        || plan.geometry.swath_height != 1
        || plan.registers.requests.dpte_row_height != 128
        || plan.registers.dlg.min_dst_y_next_start != (1125 - 4) * 4
        || plan.registers.rq.drq_expansion_mode != 2
        || plan.registers.rq.pte_row_height_linear != 4
    {
        return TestResult::Fail("DCN30 geometry");
    }
    // (191 + 32) / DCFCLK plus reordering and one pixel chunk over ReturnBW;
    // urgent latency adjusted by the fabric clock: 4 + (1000/1200 - 1).
    let w = &plan.watermarks;
    let expected_urgent = Fx::int(4)
        .plus(Fx::int(1000).over(Fx::int(1200)))
        .minus(Fx::ONE);
    if w.urgent_latency_us.raw().abs_diff(expected_urgent.raw()) > 4
        || w.pstate_change_us.minus(w.urgent_us) != Fx::int(404)
        || w.z8_stutter_exit_us != Fx::ZERO
    {
        return TestResult::Fail("DCN30 latencies");
    }
    // 8 line-buffer lines plus 24 DET lines (184 KiB / 7680 B) of 14.8 us
    // outlast the 404 us switch plus urgent watermark: Linux reports vactive.
    if plan.dram_clock_change != DramClockChange::Vactive {
        return TestResult::Fail("1080p60 vactive p-state margin");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dml30", dml30_uses_dcn30_parameters_not_dcn314);

fn dml30_refuses_unsupported_and_unschedulable_modes() -> TestResult {
    let base = config(148_500, 1920, 2200, 88, 44, 1080, 1125, 4);
    // Scaling, cursors, interlace-like shapes and taps are out of scope.
    let mut scaled = base;
    scaled.plane.viewport_width = 1280;
    let mut cursor = base;
    cursor.cursors = 1;
    if plan(&scaled, &soc()) != Err(Error::Unsupported)
        || plan(&cursor, &soc()) != Err(Error::Unsupported)
    {
        return TestResult::Fail("out-of-scope plane admitted");
    }
    // A pixel clock above the PHY or display clock ceiling.
    let mut fast = soc();
    fast.max_phyclk_khz = 100_000;
    let mut slow = soc();
    slow.max_dispclk_khz = 100_000;
    if plan(&base, &fast) != Err(Error::Unsupported)
        || plan(&base, &slow) != Err(Error::Unsupported)
    {
        return TestResult::Fail("clock ceilings");
    }
    // A vertical blank too short for any prefetch.
    let mut tight = config(148_500, 1920, 2200, 88, 44, 1080, 1083, 1);
    tight.timing.v_sync_width = 1;
    if plan(&tight, &soc()) != Err(Error::NoTimeForPrefetch) {
        return TestResult::Fail("no prefetch time");
    }
    // Past the 8192-pixel linear swath limit.
    let wide = config(600_000, 8200, 8400, 64, 32, 1080, 1125, 4);
    if plan(&wide, &soc()) != Err(Error::ViewportTooLarge) {
        return TestResult::Fail("DET overflow admitted");
    }
    // Missing board data fails closed.
    let mut zero = soc();
    zero.channels = 0;
    if plan(&base, &zero) != Err(Error::Invalid) {
        return TestResult::Fail("missing channel count");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml30",
    dml30_refuses_unsupported_and_unschedulable_modes
);

//! Reference vectors for the DCN3.0 port. The expected values come from a
//! double-precision transliteration of the same Linux functions
//! (`display_mode_vba_30.c`, `display_rq_dlg_calc_30.c`, `dcn30_fpu.c`
//! constants) run on the host, at a Navi22-shaped SoC state: 1200 MHz DCFCLK
//! (and fabric), 16000 MT/s on twelve 16-bit channels, 1330 MHz display clock
//! ceilings, a 3650 MHz DENTIST VCO and a 50 MHz DCHUB reference.
use super::*;
use crate::amdgpu_dml::{Format, Plane, Timing};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

fn soc() -> Soc {
    Soc {
        dcn_revision: 0,
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
/// `drivers/gpu/tests/navi22_dml30/vectors.txt`: Linux's own DCN3.0 DML,
/// compiled on the host by `check.sh`, run on each configuration.
const VECTORS: &str = include_str!("../tests/navi22_dml30/vectors.txt");

/// One vector line's configuration: the SoC and its streams.
fn vector_inputs(fields: &[u32]) -> Option<(Soc, Vec<Stream>)> {
    let s = fields.get(..10)?;
    let soc = Soc {
        dcn_revision: 0,
        dcfclk_khz: s[0],
        fabric_khz: s[0],
        socclk_khz: 1_000_000,
        dram_speed_mts: s[1],
        channels: s[2],
        channel_width_bytes: s[3],
        max_dispclk_khz: s[4],
        max_dppclk_khz: s[5],
        max_phyclk_khz: s[6],
        dentist_vco_khz: s[7],
        dchub_refclk_khz: s[8],
    };
    let mut streams = Vec::new();
    for k in 0..s[9] as usize {
        let f = fields.get(10 + 13 * k..23 + 13 * k)?;
        let mut config = config(f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]);
        config.timing.v_sync_width = f[8];
        config.plane.pitch = (f[1] * 4).next_multiple_of(256) / 4;
        config.dentist_vco_khz = s[7];
        config.cursors = f[9];
        streams.push(Stream {
            config,
            dsc: (f[10] != 0).then_some(Dsc {
                slices: f[10],
                bits_per_pixel_x16: f[11],
            }),
            // TMDS runs the PHY at the pixel clock, DP at its link rate.
            phy_khz: if f[12] != 0 { f[0] } else { s[6] },
        });
    }
    Some((soc, streams))
}

/// The harness's PLAN tokens for `plan`, in its order (see harness.c).
fn observed_joint(plan: &JointPlan) -> Vec<u32> {
    let w = &plan.hubbub;
    let mut out = alloc::vec![
        plan.prefetch_mode as u32,
        plan.clocks.dispclk_khz,
        plan.clocks.dppclk_khz,
        plan.clocks.deep_sleep_dcfclk_khz,
        match plan.dram_clock_change {
            DramClockChange::Vactive => 0,
            DramClockChange::Vblank => 1,
            DramClockChange::Unsupported => 2,
        },
        w.urgent,
        w.urgent_latency,
        w.sr_enter,
        w.sr_exit,
        w.dram_clock_change,
        w.frac_urg_bw_nom,
    ];
    for plane in &plan.planes {
        let p = &plane.prefetch;
        for pipe in plane.pipes.iter().flatten() {
            let d = &pipe.registers.dlg;
            let t = &pipe.registers.ttu;
            let c = pipe.cursor;
            out.extend_from_slice(&[
                u32::MAX,
                plane.odm.pipes(),
                p.v_startup,
                p.v_update_offset_pix,
                p.v_update_width_pix,
                p.v_ready_offset_pix,
                plane.dppclk_khz,
                d.ref_freq_to_pix_freq,
                d.refcyc_per_htotal,
                d.refcyc_h_blank_end,
                d.min_dst_y_next_start,
                d.refcyc_x_after_scaler,
                d.dst_y_after_scaler,
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
                d.vready_after_vcount0,
                c.map_or(0, |c| c.refcyc_per_req_delivery),
                c.map_or(0, |c| c.refcyc_per_req_delivery_pre),
            ]);
        }
    }
    out
}

/// Fixed point and Linux's double/float DML may round a truncated product
/// to adjacent integers only where the exact value sits within 2^-24 of an
/// integer, and Linux truncates the clocks the port rounds up; every field
/// is a single truncation of a well-conditioned value, so allow one LSB.
/// The deep-sleep DCFCLK gets two: Linux's `dml_max` returns it through a
/// float and truncates (24.3 MHz becomes 24299 kHz) where the port rounds
/// its sum up (24301 kHz), the safe side. The prefetch mode, DRAM clock
/// change support, pipe count per plane and the separators match exactly.
fn vector_matches(got: &[u32], want: &[u32]) -> bool {
    got.len() == want.len()
        && got.iter().zip(want).enumerate().all(|(i, (g, w))| {
            let exact = i == 0 || i == 4 || *w == u32::MAX || (i > 0 && want[i - 1] == u32::MAX);
            if exact {
                g == w
            } else if i == 3 {
                g.abs_diff(*w) <= 2 && g >= w
            } else {
                g.abs_diff(*w) <= 1
            }
        })
}

fn dml30_matches_linux_dml_vectors() -> TestResult {
    let mut checked = 0;
    for line in VECTORS.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (inputs, kind, rest) = match (line.find('='), line.find('!')) {
            (Some(i), _) => (&line[..i], '=', &line[i + 1..]),
            (None, Some(i)) => (&line[..i], '!', &line[i + 1..]),
            _ => return TestResult::Fail("malformed vector line"),
        };
        let fields: Vec<u32> = inputs
            .split_whitespace()
            .filter_map(|f| f.parse().ok())
            .collect();
        let Some((soc, streams)) = vector_inputs(&fields) else {
            return TestResult::Fail("malformed vector inputs");
        };
        let result = plan_joint(&streams, &soc);
        match (kind, result) {
            ('!', Err(_)) => {}
            ('!', Ok(_)) => {
                return TestResult::Fail("Linux rejects a configuration the port plans")
            }
            ('=', Err(_)) => {
                return TestResult::Fail("Linux plans a configuration the port rejects")
            }
            ('=', Ok(plan)) => {
                let want: Vec<u32> = rest
                    .split_whitespace()
                    .map(|t| {
                        if t == "|" {
                            u32::MAX
                        } else {
                            t.parse().unwrap_or(u32::MAX - 1)
                        }
                    })
                    .collect();
                if !vector_matches(&observed_joint(&plan), &want) {
                    return TestResult::Fail("plan differs from Linux DML30");
                }
            }
            _ => return TestResult::Fail("malformed vector kind"),
        }
        checked += 1;
    }
    if checked < 40 {
        return TestResult::Fail("vector file truncated");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dml30", dml30_matches_linux_dml_vectors);

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
    // Scaling, a second cursor, interlace-like shapes and taps are out of
    // scope (DCN30's number_of_cursors is 1).
    let mut scaled = base;
    scaled.plane.viewport_width = 1280;
    let mut cursor = base;
    cursor.cursors = 2;
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

fn dml30_budgets_one_cursor_like_dcn20_populate_dml_pipes() -> TestResult {
    let base = config(148_500, 1920, 2200, 88, 44, 1080, 1125, 4);
    let mut with = base;
    with.cursors = 1;
    let (Ok(plain), Ok(cursor)) = (plan(&base, &soc()), plan(&with, &soc())) else {
        return TestResult::Fail("1080p60 with a cursor");
    };
    if plain.cursor.is_some() {
        return TestResult::Fail("cursor TTU without a cursor");
    }
    let Some(ttu) = cursor.cursor else {
        return TestResult::Fail("no cursor TTU");
    };
    // calculate_ttu_cursor: 256 px / 4 requests at ref_freq_to_pix_freq
    // 50/148.5, in U?.10: floor(64 * 50 / 148.5 * 1024) = 22066 (within
    // the fixed point's last bit).
    if ttu.refcyc_per_req_delivery.abs_diff(22_066) > 1 {
        return TestResult::Fail("cursor request delivery");
    }
    if ttu.qos_level_fixed != 8 || ttu.qos_ramp_disable != 0 || ttu.refcyc_per_req_delivery_pre == 0
    {
        return TestResult::Fail("cursor TTU fields");
    }
    // dppclk_delay_cnvc_cursor (6 DPPCLK) moves the after-scaler point, and
    // the cursor's 1 KiB per line raises the urgent bandwidth fraction.
    if cursor.prefetch.dst_x_after_scaler == plain.prefetch.dst_x_after_scaler
        && cursor.prefetch.dst_y_after_scaler == plain.prefetch.dst_y_after_scaler
    {
        return TestResult::Fail("cursor DPPCLK delay");
    }
    if cursor.urgent_bandwidth_thousandths <= plain.urgent_bandwidth_thousandths {
        return TestResult::Fail("cursor bandwidth");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml30",
    dml30_budgets_one_cursor_like_dcn20_populate_dml_pipes
);

fn stream(config: Config) -> Stream {
    let mut config = config;
    config.cursors = 1;
    Stream::tmds(config)
}

fn dml30_joint_plan_shares_clocks_latency_and_watermarks() -> TestResult {
    let a = config(148_500, 1920, 2200, 88, 44, 1080, 1125, 4);
    let b = config(533_250, 3840, 4000, 48, 32, 2160, 2222, 3);
    let (Ok(one), Ok(two)) = (
        plan_joint(&[stream(a)], &soc()),
        plan_joint(&[stream(a), stream(b)], &soc()),
    ) else {
        return TestResult::Fail("two-stream configuration refused");
    };
    if two.planes.len() != 2 || two.pipes() != 2 {
        return TestResult::Fail("one plane and pipe per stream");
    }
    // One DISPCLK for both, at least the faster stream's; each plane its own
    // DPPCLK share and the global DPPCLK the larger.
    let fast = &two.planes[1];
    if two.clocks.dispclk_khz < 533_250
        || two.clocks.dppclk_khz != fast.dppclk_khz
        || two.planes[0].dppclk_khz >= fast.dppclk_khz
    {
        return TestResult::Fail("shared clocks");
    }
    // CalculateExtraLatency counts every active DPP's pixel chunk: a second
    // pipe raises the urgent watermark every plane runs under.
    if two.watermarks.extra_latency_us <= one.watermarks.extra_latency_us
        || two.hubbub.urgent <= one.hubbub.urgent
    {
        return TestResult::Fail("extra latency per active DPP");
    }
    // One MinTTUVBlank for the whole configuration.
    let ttu = |p: &PlanePlan| p.pipes[0].map(|x| x.registers.ttu.min_ttu_vblank);
    if ttu(&two.planes[0]) != ttu(&two.planes[1]) {
        return TestResult::Fail("min TTU differs between planes");
    }
    // Neither display alone is refused, yet six 4K streams on a slow memory
    // state exceed the bandwidth display may use: joint admission refuses
    // what single admission of each would allow.
    let slow = Soc {
        dcfclk_khz: 500_000,
        fabric_khz: 500_000,
        dram_speed_mts: 2_000,
        channels: 6,
        ..soc()
    };
    let six = [stream(b); 6];
    if plan_joint(&six[..1], &slow).is_err() || plan_joint(&six, &slow).is_ok() {
        return TestResult::Fail("joint bandwidth admission");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml30",
    dml30_joint_plan_shares_clocks_latency_and_watermarks
);

fn dml30_odm_combines_where_one_pipe_cannot_carry_the_stream() -> TestResult {
    // A 600 MHz DISPCLK ceiling: 2160p60 (594 MHz) needs both halves.
    let low = Soc {
        max_dispclk_khz: 600_000,
        max_dppclk_khz: 600_000,
        ..soc()
    };
    let uhd = config(594_000, 3840, 4400, 176, 88, 2160, 2250, 8);
    let Ok(joint) = plan_joint(&[stream(uhd)], &low) else {
        return TestResult::Fail("2160p60 on ODM refused");
    };
    let plane = &joint.planes[0];
    let (Some(left), Some(right)) = (plane.pipes[0], plane.pipes[1]) else {
        return TestResult::Fail("ODM 2:1 without two pipes");
    };
    if plane.odm != Odm::TwoToOne
        || joint.pipes() != 2
        || left.viewport_x != 0
        || right.viewport_x != 1920
        || left.viewport_width != 1920
        || plane.geometry.swath_width != 1920
    {
        return TestResult::Fail("ODM slices");
    }
    // The right slice's blank ends 1920 pixels later; everything else is the
    // same pacing.
    let (l, r) = (left.registers.dlg, right.registers.dlg);
    // (blank end 4400 - 176 - 3840 = 384, plus 1920) x 50 / 594.
    if r.refcyc_h_blank_end.abs_diff((384 + 1920) * 50 / 594) > 1
        || r.refcyc_x_after_scaler != l.refcyc_x_after_scaler
        || r.dst_y_prefetch != l.dst_y_prefetch
    {
        return TestResult::Fail("ODM slice registers");
    }
    // The single-pipe entry point refuses what needs ODM.
    if plan(&uhd, &low) != Err(Error::Unsupported) {
        return TestResult::Fail("single-pipe plan admitted an ODM stream");
    }
    // More than six pipes, or 4:1, are refused.
    let eight_k = Stream {
        dsc: Some(Dsc {
            slices: 4,
            bits_per_pixel_x16: 192,
        }),
        phy_khz: 810_000,
        ..stream(config(2_039_800, 7680, 7760, 48, 32, 4320, 4381, 3))
    };
    let four = [eight_k; 4];
    if plan_joint(&four[..3], &soc()).map(|p| p.pipes()) != Ok(6)
        || plan_joint(&four, &soc()).is_ok()
    {
        return TestResult::Fail("pipe budget");
    }
    let mut fast = uhd;
    fast.timing.pixel_clock_khz = 1_188_000;
    if plan_joint(&[stream(fast)], &low).is_ok() {
        return TestResult::Fail("ODM 4:1 admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml30",
    dml30_odm_combines_where_one_pipe_cannot_carry_the_stream
);

fn dml30_admits_at_the_lowest_supporting_uclk_state() -> TestResult {
    let top = soc();
    let states = top.states(&[96, 456, 456, 772, 1000]);
    // One state per lower UCLK level ascending, then the top state itself.
    let mts: Vec<u32> = states.iter().map(|s| s.dram_speed_mts).collect();
    if mts != vec![1536, 7296, 12_352, 16_000]
        || states.iter().any(|s| s.dcfclk_khz != top.dcfclk_khz)
    {
        return TestResult::Fail("bounding-box states");
    }
    let a = stream(config(148_500, 1920, 2200, 88, 44, 1080, 1125, 4));
    let b = stream(config(533_250, 3840, 4000, 48, 32, 2160, 2222, 3));
    for set in [vec![a], vec![a, b], vec![b, b, b, b]] {
        let Ok((i, plan)) = plan_joint_lowest(&set, &states) else {
            return TestResult::Fail("configuration refused at every state");
        };
        // The first state that supports it: every lower one refuses, and
        // the plan is that state's.
        if states[..i].iter().any(|s| plan_joint(&set, s).is_ok())
            || plan_joint(&set, &states[i]).ok() != Some(plan)
        {
            return TestResult::Fail("not the lowest supporting state");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dml30",
    dml30_admits_at_the_lowest_supporting_uclk_state
);

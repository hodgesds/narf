use super::*;
use crate::amdgpu_dcn401_otg::tests::{engine, run, BASE};
use narf_kernel_test::{kernel_test_in, TestResult};

fn soc() -> dml::Soc {
    dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [300_000, 2_500_000],
        dcfclk_khz: [200_000, 1_564_000],
        socclk_khz: 300_000,
        dispclk_max_khz: 2_000_000,
        dppclk_max_khz: 2_000_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    }
}
fn timing() -> Timing {
    Timing {
        pixel_clock_khz: 148_500,
        h_active: 1920,
        h_total: 2200,
        h_front_porch: 88,
        h_sync_width: 44,
        v_active: 1080,
        v_total: 1125,
        v_front_porch: 4,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: true,
    }
}
fn plan() -> dml::Plan {
    dml::admit(
        &soc(),
        &dml::Mode {
            timing: timing(),
            pitch: 1920,
            bytes_per_pixel: 4,
            ycbcr420: false,
            dsc: None,
        },
    )
    .unwrap()
}
fn hubp_at(pipe: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(pipe) * 0xdc) * 4
}
fn owners(plan: &dml::Plan, pipe: u8) -> (Request, RequestorApplied, dccg::Applied) {
    let surface = SurfaceApplied {
        request: SurfaceRequest {
            pipe,
            width: 1920,
            height: 1080,
            format: SurfaceFormat::Xrgb8888,
            odm: None,
            plane: None,
        },
        address: 0x8_0000_0000,
        pitch_bytes: 7680,
        bytes: 7680 * 1080,
    };
    let timing = Request {
        pipe,
        timing: plan.mode.timing,
        sync: plan.sync,
        signal: Signal::DisplayPort,
        ycbcr420: false,
        dsc: None,
        odm: None,
    };
    let requestor = RequestorApplied {
        pipe,
        surface,
        det_bytes: 327_680,
        compbuf_bytes: 1_048_576,
        pixel_chunk_bytes: 8192,
        minimum_chunk_bytes: 1024,
    };
    let clock = dccg::Applied {
        request: dccg::Request {
            pipe,
            dpp_khz: plan.clocks.dppclk_khz,
            pixel: dccg::PixelClock::DisplayPort {
                pixel_hz: 148_500_000,
            },
        },
        global: clocks::Applied {
            request: clocks::Request {
                displays: 1,
                display_khz: plan.clocks.dispclk_khz,
                dpp_khz: plan.clocks.dpprefclk_khz,
                dtb_khz: 600_000,
            },
            display_khz: plan.clocks.dispclk_khz,
            dpp_khz: plan.clocks.dpprefclk_khz,
            dtb_khz: 600_000,
            dcf_floor_khz: 1_564_000,
            memory_floor_khz: 1_250_000,
        },
        dpp_phase: 0,
        reference_hz: 720_000_000,
        integer: 0,
        phase: 0,
    };
    (timing, requestor, clock)
}

fn dcn401_deadlines_program_plan_values_into_native_fields() -> TestResult {
    let plan = plan();
    for pipe in 0..4 {
        let mut e = engine();
        // Flush/row-TTU bits Linux leaves alone and an inherited stutter
        // allowance that must be forced off.
        e.io.regs.insert(hubp_at(pipe, GLOBAL_TTU), 0x0b00_0000);
        e.io.regs.insert(BASE + DRAM_STATE * 4, 0xff);
        e.io.regs.insert(BASE + CTRL_STATUS * 4, 0x0000_0206);
        if e.deadline_writes(pipe, &plan, false).is_err()
            || e.deadline_writes(pipe, &plan, true).is_err()
        {
            return TestResult::Fail("program/verify");
        }
        let hubp = |r| e.io.regs.get(&hubp_at(pipe, r)).copied().unwrap_or(0);
        let hub = |r: u64| e.io.regs.get(&(BASE + r * 4)).copied().unwrap_or(0);
        let want_hubp = [
            (DEBUG_DB, 0x100),
            (BLANK0, 64 | 41 << 16),
            (BLANK1, 4488),
            (DST_DIMENSIONS, 189_629),
            (DST_AFTER, 71),
            (REF_FREQ, 176_527),
            (PREFETCH, 524_288 | 11 << 24),
            (PREFETCH_C, 524_288),
            (VBLANK0, 1 | 1 << 8),
            (PER_LINE, 646),
            (PER_LINE_PRE, 646),
            (QOS_WM, 2962 << 16),
            (SURF0_TTU0, 22_065 | 8 << 24),
            (SURF0_TTU1, 22_065),
            (SURF1_TTU0, 8 << 24),
            (GLOBAL_TTU, 0x0b00_0000 | 2934 | 14 << 28),
        ];
        if want_hubp.iter().any(|&(r, v)| hubp(r) != v) {
            return TestResult::Fail("HUBP DLG/TTU value");
        }
        // Zeroed VM/PTE/meta/flip/3D-LUT fields were written, not skipped.
        for r in [
            0x642, 0x649, 0x650, FLIP0, 0x647, LUT3D_DLG, CUR0_TTU0, CUR0_TTU1,
        ] {
            if !e.io.writes.iter().any(|&(at, _)| at == hubp_at(pipe, r)) || hubp(r) != 0 {
                return TestResult::Fail("unused DLG field not cleared");
            }
        }
        // 1080p VREADY lands inside blank: (44 - 1125/2200) <= 41 is false.
        if hubp(HUBP_CONTROL) & VREADY_AFTER_VSYNC != 0 {
            return TestResult::Fail("VREADY rule");
        }
        for set in [WM_A, WM_B] {
            let w = [
                119, 119, 119, 119, 2788, 2138, 2788, 2138, 2788, 2138, 2788, 2138, 20_119, 369,
                119, 369, 8, 8, 8,
            ];
            if (0..19).any(|i| hub(set + i) != w[i as usize]) {
                return TestResult::Fail("watermark set");
            }
        }
        if hub(DRAM_STATE) != 0xfe
            || hub(SDPIF_RATE_LIMIT) != 192
            || hub(TIMEOUT_CTRL2) != 5_000_000
            || hub(CTRL_STATUS) != 0x0000_0006
            || hub(USR_RETRAINING) != 0
        {
            return TestResult::Fail("arbiter/self-refresh control");
        }
        // Readback catches a later change in any programmed field.
        e.io.regs.insert(BASE + (WM_B + 12) * 4, 0);
        if e.deadline_writes(pipe, &plan, true) != Err(Error::Readback(BASE + (WM_B + 12) * 4)) {
            return TestResult::Fail("watermark readback");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-deadline",
    dcn401_deadlines_program_plan_values_into_native_fields
);

fn dcn401_deadlines_bind_only_the_admitted_owners() -> TestResult {
    let plan = plan();
    let (timing, requestor, clock) = owners(&plan, 2);
    if !bound(&plan, timing, requestor, clock, 50_000) {
        return TestResult::Fail("matching owners refused");
    }
    // Higher actual DISPCLK/DPPCLK than required is fine.
    let mut faster = clock;
    faster.global.display_khz += 1000;
    faster.request.dpp_khz += 1000;
    if !bound(&plan, timing, requestor, faster, 50_000) {
        return TestResult::Fail("faster clocks refused");
    }
    // A 2-byte plane binds the plan admitted at its depth and pitch only.
    let Ok(rgb565) = dml::admit(
        &soc(),
        &dml::Mode {
            bytes_per_pixel: 2,
            ..plan.mode
        },
    ) else {
        return TestResult::Fail("RGB565 1080p60 refused");
    };
    let mut half = requestor;
    half.surface.request.format = SurfaceFormat::Rgb565;
    half.surface.pitch_bytes = 3840;
    let synced = Request {
        sync: rgb565.sync,
        ..timing
    };
    if !bound(&rgb565, synced, half, clock, 50_000)
        || bound(&plan, timing, half, clock, 50_000)
        || bound(&rgb565, synced, requestor, clock, 50_000)
    {
        return TestResult::Fail("plane depth binding");
    }
    let mut tampered = plan;
    tampered.watermarks.urgent += 1;
    let mut other_mode = plan;
    other_mode.mode.pitch = 2048;
    let cases: [(dml::Plan, Request, RequestorApplied, dccg::Applied, u32); 13] = [
        (tampered, timing, requestor, clock, 50_000),
        (other_mode, timing, requestor, clock, 50_000),
        (
            plan,
            // FRL timing has no deadline owner yet (HPO DP now does).
            Request {
                signal: Signal::HdmiFrl,
                ycbcr420: false,
                ..timing
            },
            requestor,
            clock,
            50_000,
        ),
        (
            plan,
            Request {
                sync: GlobalSync {
                    vstartup: 43,
                    ..timing.sync
                },
                ..timing
            },
            requestor,
            clock,
            50_000,
        ),
        (
            plan,
            Request { pipe: 1, ..timing },
            requestor,
            clock,
            50_000,
        ),
        (
            plan,
            timing,
            RequestorApplied {
                det_bytes: 1 << 20,
                ..requestor
            },
            clock,
            50_000,
        ),
        (
            plan,
            timing,
            RequestorApplied {
                surface: SurfaceApplied {
                    pitch_bytes: 8192,
                    ..requestor.surface
                },
                ..requestor
            },
            clock,
            50_000,
        ),
        (
            plan,
            timing,
            RequestorApplied {
                surface: SurfaceApplied {
                    request: SurfaceRequest {
                        height: 1079,
                        ..requestor.surface.request
                    },
                    ..requestor.surface
                },
                ..requestor
            },
            clock,
            50_000,
        ),
        (plan, timing, requestor, clock, 100_000),
        (
            plan,
            timing,
            requestor,
            dccg::Applied {
                global: clocks::Applied {
                    display_khz: plan.clocks.dispclk_khz - 1,
                    ..clock.global
                },
                ..clock
            },
            50_000,
        ),
        (
            plan,
            timing,
            requestor,
            dccg::Applied {
                request: dccg::Request {
                    dpp_khz: plan.clocks.dppclk_khz - 1,
                    ..clock.request
                },
                ..clock
            },
            50_000,
        ),
        (
            plan,
            timing,
            requestor,
            dccg::Applied {
                global: clocks::Applied {
                    memory_floor_khz: 1_000_000,
                    ..clock.global
                },
                ..clock
            },
            50_000,
        ),
        (
            plan,
            timing,
            requestor,
            dccg::Applied {
                global: clocks::Applied {
                    dcf_floor_khz: 1_200_000,
                    ..clock.global
                },
                ..clock
            },
            50_000,
        ),
    ];
    for (p, t, r, c, refclk) in cases {
        if bound(&p, t, r, c, refclk) {
            return TestResult::Fail("mismatched owner accepted");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-deadline",
    dcn401_deadlines_bind_only_the_admitted_owners
);

fn dcn401_deadlines_follow_linux_vready_rule_and_gate_on_requestor() -> TestResult {
    let mut p = plan();
    // vstartup - floor((vready + width + offset) / htotal) <= vblank_end (41).
    for (vstartup, offset, want) in [
        (44, 550, false),
        (41, 550, true),
        (44, 8800, true),
        (44, 4400, false),
        (1, 4400, false),
    ] {
        p.sync.vstartup = vstartup;
        p.sync.vupdate_offset = offset;
        if vready_after_vsync(&p) != want {
            return TestResult::Fail("VREADY rule");
        }
    }
    let plan = plan();
    let mut e = engine();
    let mut surfaces = Surfaces::new();
    let mut called = false;
    let result = run(surfaces.prepare_deadlines(&mut e, 0, &plan, 100_000, || {
        called = true;
        Err(Error::Busy)
    }));
    if result != Err(Error::Invalid) || called || !e.io.writes.is_empty() {
        return TestResult::Fail("deadlines without a staged requestor");
    }
    let (_, requestor, _) = owners(&plan, 0);
    e.status.requestor = Some(requestor);
    e.status.deadlines = Some(DeadlinesApplied {
        pipe: 0,
        plan,
        vready_after_vsync: false,
    });
    if run(surfaces.prepare_deadlines(&mut e, 0, &plan, 100_000, || Err(Error::Busy)))
        != Err(Error::Busy)
    {
        return TestResult::Fail("deadline replay");
    }
    e.status.deadlines = None;
    e.status.state = State::PreparingRequestor(0);
    if run(surfaces.prepare_deadlines(&mut e, 0, &plan, 100_000, || Err(Error::Busy)))
        != Err(Error::Busy)
    {
        return TestResult::Fail("deadlines during another transition");
    }
    e.status.state = State::RequestorPrepared;
    if run(surfaces.prepare_deadlines(&mut e, 1, &plan, 100_000, || Err(Error::Busy)))
        != Err(Error::Invalid)
    {
        return TestResult::Fail("deadlines for another pipe");
    }
    if !e.io.writes.is_empty() || e.status.state != State::RequestorPrepared {
        return TestResult::Fail("refusal wrote or changed state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-deadline",
    dcn401_deadlines_follow_linux_vready_rule_and_gate_on_requestor
);

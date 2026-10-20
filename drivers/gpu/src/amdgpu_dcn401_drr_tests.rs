use super::*;
use crate::amdgpu_dcn401_otg::tests::{clock, engine, request, run, Fake, BASE};
use crate::amdgpu_freesync::Drr;
use narf_kernel_test::{kernel_test_in, TestResult};

/// 2560x1440 at 143.994 Hz: v_total 1497 (programmed 1496).
fn qhd144() -> Timing {
    Timing {
        pixel_clock_khz: 586_322,
        h_active: 2560,
        h_total: 2720,
        h_front_porch: 48,
        h_sync_width: 32,
        v_active: 1440,
        v_total: 1497,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: false,
    }
}

/// `mod_freesync_build_vrr_params` for 48-144 Hz (see the freesync tests).
const QHD_48_144: Drr = Drr {
    v_total_min: 1497,
    v_total_max: 4491,
};

fn otg(pipe: u8, r: u64) -> u64 {
    BASE + (r + 0x80 * u64::from(pipe)) * 4
}

/// An engine whose `pipe` scans out the 1440p timing.
fn live(pipe: u8) -> (Engine<Fake>, Request) {
    let mut e = engine();
    let mut req = request(pipe);
    req.timing = qhd144();
    e.status.pipes[usize::from(pipe)] = Some(Applied {
        request: req,
        clock: clock(req),
    });
    e.status.state = State::ScanoutRunning(pipe);
    e.status.scanout = Some(ScanoutRunning {
        pipe,
        odm: None,
        stream: pipe,
        plan: dml::admit(
            &dml::Soc {
                umc_channels: 16,
                uclk_khz: 1_250_000,
                fclk_khz: [300_000, 2_500_000],
                dcfclk_khz: [200_000, 1_564_000],
                socclk_khz: 300_000,
                dispclk_max_khz: 2_000_000,
                dppclk_max_khz: 2_000_000,
                dentist_vco_khz: 4_500_000,
                dchub_refclk_khz: 50_000,
            },
            &dml::Mode {
                timing: request(pipe).timing,
                pitch: 1920,
                bytes_per_pixel: 4,
                ycbcr420: false,
                dsc: None,
                planes: [None; dml::MAX_PLANES],
            },
        )
        .unwrap(),
        address: 0x8_0010_0000,
        frame_before: 1,
        frame_after: 2,
    });
    // Fixed refresh as `program` leaves it, with an inherited MID frame
    // number and static-screen state that DRR must preserve or restore.
    for (r, v) in [
        (0x1b2f, 1496),
        (0x1b30, 1496),
        (0x1b31, 1496),
        (0x1b33, 0x0000_ff00),
        (0x1b80, 0x0100_0005),
    ] {
        e.io.regs.insert(otg(pipe, r), v);
    }
    (e, req)
}

fn dcn401_drr_enable_and_disable_follow_optc401_set_drr() -> TestResult {
    for pipe in 0..4 {
        let (mut e, _) = live(pipe);
        let applied = e.set_drr(pipe, Some(QHD_48_144)).unwrap();
        assert_eq!(applied.map(|a| (a.pipe, a.drr)), Some((pipe, QHD_48_144)));
        // MAX then MIN (optc1_set_vtotal_min_max, minus one), the TRIGA
        // selectors with MID untouched, then static screen on TRIGA x2.
        assert_eq!(
            e.io.writes,
            [
                (otg(pipe, 0x1b31), 4490),
                (otg(pipe, 0x1b30), 1496),
                (otg(pipe, 0x1b33), 0x0002_ff03),
                (otg(pipe, 0x1b80), 0x0002_0800),
            ]
        );
        assert_eq!(e.status.drr, applied);
        assert_eq!(e.status.state, State::ScanoutRunning(pipe));
        // The same totals again write nothing.
        e.io.writes.clear();
        assert_eq!(e.set_drr(pipe, Some(QHD_48_144)).unwrap(), applied);
        assert!(e.io.writes.is_empty());
        // New totals keep the static-screen state first replaced.
        let narrower = Drr {
            v_total_min: 1497,
            v_total_max: 2994,
        };
        e.set_drr(pipe, Some(narrower)).unwrap();
        assert_eq!(e.io.writes[0], (otg(pipe, 0x1b31), 2993));
        e.io.writes.clear();
        // Disable: selectors off first, totals back to V_TOTAL, the
        // static-screen control restored exactly.
        assert_eq!(e.set_drr(pipe, None), Ok(None));
        assert_eq!(
            e.io.writes,
            [
                (otg(pipe, 0x1b33), 0x0000_ff00),
                (otg(pipe, 0x1b31), 1496),
                (otg(pipe, 0x1b30), 1496),
                (otg(pipe, 0x1b80), 0x0100_0005),
            ]
        );
        assert_eq!(e.status.drr, None);
        // Fixed again is a no-op.
        e.io.writes.clear();
        assert_eq!(e.set_drr(pipe, None), Ok(None));
        assert!(e.io.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_drr_enable_and_disable_follow_optc401_set_drr
);

fn dcn401_drr_refuses_without_scanout_or_with_bad_totals() -> TestResult {
    let (mut e, _) = live(1);
    for bad in [
        Drr {
            v_total_min: 1496,
            v_total_max: 4491,
        },
        Drr {
            v_total_min: 1600,
            v_total_max: 1599,
        },
        Drr {
            v_total_min: 1497,
            v_total_max: 32768,
        },
    ] {
        if e.set_drr(1, Some(bad)) != Err(Error::Invalid) {
            return TestResult::Fail("bad totals accepted");
        }
    }
    // The largest 15-bit total is accepted.
    if e.set_drr(
        1,
        Some(Drr {
            v_total_min: 1497,
            v_total_max: 32767,
        }),
    )
    .is_err()
        || e.io.writes[0] != (otg(1, 0x1b31), 0x7ffe)
    {
        return TestResult::Fail("15-bit maximum");
    }
    let mut e = live(1).0;
    // Another pipe, or no live scanout: Busy before any access.
    let reads = e.io.regs.clone();
    if e.set_drr(2, Some(QHD_48_144)) != Err(Error::Busy) {
        return TestResult::Fail("other pipe");
    }
    e.status.state = State::DpVideoRunning(1);
    if e.set_drr(1, Some(QHD_48_144)) != Err(Error::Busy) || e.set_drr(1, None) != Err(Error::Busy)
    {
        return TestResult::Fail("no scanout");
    }
    if !e.io.writes.is_empty() || e.io.regs != reads {
        return TestResult::Fail("refusal wrote");
    }
    // A failed write leaves Failed with the record kept for restoration.
    let mut e = live(1).0;
    e.io.reject = Some(3);
    if e.set_drr(1, Some(QHD_48_144)) != Err(Error::Readback(otg(1, 0x1b33)))
        || e.status.state != State::Failed(Error::Readback(otg(1, 0x1b33)))
        || e.status.drr.map(|a| a.drr) != Some(QHD_48_144)
    {
        return TestResult::Fail("partial enable");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_drr_refuses_without_scanout_or_with_bad_totals
);

fn dcn401_drr_is_fixed_before_the_timing_stops_and_bounds_frame_waits() -> TestResult {
    let (mut e, req) = live(2);
    let blank = BlankApplied {
        request: BlankRequest {
            pipe: 2,
            depth: ColorDepth::Bpc8,
            limited: false,
            ycbcr420: false,
            colorspace: crate::amdgpu_dcn401_otg::BlankRequest::default_colorspace(false, false),
        },
        timing: Applied {
            request: req,
            clock: clock(req),
        },
        pending: false,
    };
    // Three frames plus 5 ms: nominal 1497 lines, or 4491 under DRR.
    if e.frame_timeout_us(2, blank) != Ok(25_835) {
        return TestResult::Fail("nominal bound");
    }
    e.set_drr(2, Some(QHD_48_144)).unwrap();
    if e.frame_timeout_us(2, blank) != Ok(67_505) || e.frame_timeout_us(1, blank) != Ok(25_835) {
        return TestResult::Fail("stretched bound");
    }
    // Stopping the timing restores fixed refresh before its first write.
    e.io.writes.clear();
    run(e.disable(2)).unwrap();
    if e.io.writes[..4]
        != [
            (otg(2, 0x1b33), 0x0000_ff00),
            (otg(2, 0x1b31), 1496),
            (otg(2, 0x1b30), 1496),
            (otg(2, 0x1b80), 0x0100_0005),
        ]
        || e.status.drr.is_some()
    {
        return TestResult::Fail("timing stop kept DRR");
    }
    // Without DRR the timing stop writes none of them.
    let (mut e, _) = live(2);
    run(e.disable(2)).unwrap();
    if e.io.writes.iter().any(|&(at, _)| {
        [0x1b30, 0x1b31, 0x1b33, 0x1b80]
            .iter()
            .any(|&r| at == otg(2, r))
    }) {
        return TestResult::Fail("fixed timing stop touched DRR");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_drr_is_fixed_before_the_timing_stops_and_bounds_frame_waits
);

use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Shared with tests/dcn401_dml21/check.sh, which verifies every line
/// against Linux DML21 built on the host.
const VECTORS: &str = include_str!("../tests/dcn401_dml21/vectors.txt");
/// Deep-sleep DCFCLK and the three urgent-bandwidth fractions truncate a
/// double in Linux and a fixed-point value here; they may differ by one.
const TOLERATED: [usize; 4] = [3, 47, 48, 49];

fn inputs(f: &[u32]) -> (Soc, Mode) {
    let soc = Soc {
        dcfclk_khz: [f[9], f[10]],
        fclk_khz: [f[11], f[12]],
        uclk_khz: f[13],
        dispclk_max_khz: f[14],
        dppclk_max_khz: f[15],
        socclk_khz: f[16],
        umc_channels: f[17],
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let timing = Timing {
        pixel_clock_khz: f[0],
        h_active: f[1],
        h_total: f[2],
        h_front_porch: f[3],
        h_sync_width: f[4],
        v_active: f[5],
        v_total: f[6],
        v_front_porch: f[7],
        v_sync_width: f[8],
        h_sync_positive: true,
        v_sync_positive: true,
    };
    (
        soc,
        Mode {
            timing,
            pitch: f[18],
            bytes_per_pixel: 4,
            ycbcr420: false,
            dsc: None,
            planes: [None; MAX_PLANES],
        },
    )
}
fn values(p: &Plan) -> [u32; 62] {
    let (c, g, d, t, w, a) = (p.clocks, p.sync, p.dlg, p.ttu, p.watermarks, p.arbiter);
    [
        c.dispclk_khz,
        c.dpprefclk_khz,
        c.dppclk_khz,
        c.deep_sleep_dcfclk_khz,
        c.dcfclk_khz,
        c.fclk_khz,
        c.uclk_khz,
        c.socclk_khz,
        g.vstartup,
        g.vupdate_offset,
        g.vupdate_width,
        g.vready_offset,
        g.pstate_keepout,
        d.refcyc_h_blank_end,
        d.dlg_vblank_end,
        d.min_dst_y_next_start,
        d.refcyc_per_htotal,
        d.refcyc_x_after_scaler,
        d.dst_y_after_scaler,
        d.dst_y_prefetch,
        d.dst_y_per_vm_vblank,
        d.dst_y_per_row_vblank,
        d.ref_freq_to_pix_freq,
        d.vratio_prefetch,
        d.vratio_prefetch_c,
        d.refcyc_per_line_delivery_pre_l,
        d.refcyc_per_line_delivery_l,
        d.vready_after_vcount0 as u32,
        d.dst_y_delta_drq_limit,
        d.dmdata_dl_delta,
        t.qos_level_low_wm,
        t.qos_level_high_wm,
        t.min_ttu_vblank,
        t.qos_level_flip,
        t.refcyc_per_req_delivery_l,
        t.refcyc_per_req_delivery_pre_l,
        t.qos_level_fixed_l,
        t.qos_level_fixed_c,
        w.urgent,
        w.sr_enter,
        w.sr_exit,
        w.uclk_pstate,
        w.fclk_pstate,
        w.temp_read,
        w.usr,
        w.refcyc_per_trip_to_mem,
        w.refcyc_per_meta_trip_to_mem,
        w.frac_urg_bw_flip,
        w.frac_urg_bw_nom,
        w.frac_urg_bw_mall,
        a.max_req_outstanding,
        a.min_req_outstanding,
        a.sat_level_us,
        a.compbuf_reserved_space_kbytes,
        a.compbuf_segments,
        a.sdpif_request_rate_limit,
        a.dcfclk_deep_sleep_hysteresis,
        a.pstate_stall_threshold,
        a.hvm_max_qos_commit_threshold,
        a.hvm_min_req_outstand_commit_threshold,
        p.det_bytes / 65536,
        p.stutter_reserved_us,
    ]
}
fn error_name(e: Error) -> &'static str {
    match e {
        Error::Invalid => "Invalid",
        Error::Unsupported => "Unsupported",
        Error::ClockState => "ClockState",
        Error::PixelClock => "PixelClock",
        Error::Buffer => "Buffer",
        Error::Latency => "Latency",
        Error::Prefetch => "Prefetch",
        Error::UrgentLatencyHiding => "UrgentLatencyHiding",
        Error::Bandwidth => "Bandwidth",
        Error::TempRead => "TempRead",
        Error::Register => "Register",
        Error::Pipes => "Pipes",
    }
}
fn parse<'a>(words: &mut impl Iterator<Item = &'a str>, out: &mut [u32]) -> bool {
    for slot in out.iter_mut() {
        match words.next().and_then(|w| w.parse().ok()) {
            Some(v) => *slot = v,
            None => return false,
        }
    }
    true
}
/// A plane's values end with "/2 <refcyc_h_blank_end>" when DML puts it on
/// two ODM pipes (check.sh has verified the second pipe's other registers
/// equal the first's); otherwise the plan must be single-pipe.
fn pipes_match<'a, I: Iterator<Item = &'a str>>(
    words: &mut core::iter::Peekable<I>,
    plan: &Plan,
) -> bool {
    if words.next_if_eq(&"/2").is_none() {
        return plan.pipes == 1 && plan.odm_refcyc_h_blank_end == 0 && plan.pipe_dlg(1).is_none();
    }
    let mut end = [0u32; 1];
    parse(words, &mut end)
        && plan.pipes == 2
        && plan.odm_refcyc_h_blank_end == end[0]
        && plan.pipe_dlg(1)
            == Some(Dlg {
                refcyc_h_blank_end: end[0],
                ..plan.dlg
            })
        && plan.pipe_dlg(2).is_none()
}
fn reference_1080p() -> (Soc, Mode) {
    inputs(&[
        148_500, 1920, 2200, 88, 44, 1080, 1125, 4, 5, 1_564_000, 1_564_000, 2_500_000, 2_500_000,
        1_250_000, 2_000_000, 2_000_000, 1_200_000, 16, 1920,
    ])
}

fn dcn401_dml_matches_linux_dml21_vectors() -> TestResult {
    let (mut plans, mut rejects) = (0, 0);
    for line in VECTORS.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace().peekable();
        let mut f = [0u32; 19];
        if !parse(&mut words, &mut f) {
            return TestResult::Fail("malformed vector inputs");
        }
        let (soc, mode) = inputs(&f);
        let result = admit(&soc, &mode);
        match words.next() {
            Some("=") => {
                let mut want = [0u32; 62];
                if !parse(&mut words, &mut want) {
                    return TestResult::Fail("malformed vector plan");
                }
                let Ok(plan) = result else {
                    return TestResult::Fail("Linux-admitted mode rejected");
                };
                if !pipes_match(&mut words, &plan) || words.next().is_some() {
                    return TestResult::Fail("ODM pipes differ from Linux DML21");
                }
                for (i, (&got, &want)) in values(&plan).iter().zip(want.iter()).enumerate() {
                    if got != want && !(TOLERATED.contains(&i) && got.abs_diff(want) == 1) {
                        return TestResult::Fail("plan value differs from Linux DML21");
                    }
                }
                if admit(&soc, &mode) != Ok(plan) || plan.mode != mode || plan.soc != soc {
                    return TestResult::Fail("plan not reproducible or not bound to inputs");
                }
                plans += 1;
            }
            Some("!") => {
                let (Some(name), Err(e)) = (words.next(), result) else {
                    return TestResult::Fail("rejected mode admitted");
                };
                if error_name(e) != name {
                    return TestResult::Fail("rejected for a different reason");
                }
                rejects += 1;
            }
            _ => return TestResult::Fail("malformed vector kind"),
        }
    }
    if plans < 80 || rejects < 30 {
        return TestResult::Fail("vector file lost coverage");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_vectors
);

fn dcn401_dml_reference_plan_follows_native_policy() -> TestResult {
    let (soc, mode) = reference_1080p();
    let Ok(p) = admit(&soc, &mode) else {
        return TestResult::Fail("1080p60 rejected");
    };
    // Same staged requestor geometry; DML's own nominal DET.
    if p.det_bytes != 320 * 1024 || p.arbiter.compbuf_reserved_space_kbytes != 16 {
        return TestResult::Fail("DET/compbuf");
    }
    // UCLK switching is disabled, yet its watermark is the real 400 us + urgent
    // value, never zero standing in for an unsupported policy.
    if p.watermarks.uclk_pstate != p.watermarks.urgent + 400 * 50 {
        return TestResult::Fail("UCLK watermark");
    }
    // DISPCLK/DPPCLK minimums sit above the pixel clock with downspread margin.
    if p.clocks.dispclk_khz <= 148_500 || p.clocks.dppclk_khz <= 148_500 {
        return TestResult::Fail("clock margins");
    }
    // A 45-line blank leaves room to budget self-refresh entry and exit.
    if p.stutter_reserved_us != 54 {
        return TestResult::Fail("stutter reservation");
    }
    let mut short = mode;
    short.timing.v_total = 1083;
    short.timing.v_front_porch = 1;
    short.timing.v_sync_width = 1;
    // Three blank lines cannot hold the prefetch at all.
    if admit(&soc, &short).err() != Some(Error::Prefetch) {
        return TestResult::Fail("three-line blank admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_reference_plan_follows_native_policy
);

fn dcn401_dml_rejects_invalid_and_unmodeled_inputs() -> TestResult {
    let (soc, mode) = reference_1080p();
    let bad_mode: [fn(&mut Mode); 9] = [
        |m| m.timing.pixel_clock_khz = 0,
        |m| m.timing.h_total = m.timing.h_active,
        |m| m.timing.v_total = m.timing.v_active,
        |m| m.timing.h_front_porch = u32::MAX,
        |m| m.timing.v_sync_width = u32::MAX,
        |m| m.pitch = 1919,
        |m| m.timing.h_total = 0x8001,
        |m| m.timing.v_total = u32::MAX,
        |m| m.timing.h_active = 0,
    ];
    for f in bad_mode {
        let mut m = mode;
        f(&mut m);
        if admit(&soc, &m) != Err(Error::Invalid) {
            return TestResult::Fail("invalid mode accepted");
        }
    }
    let unmodeled: [fn(&mut Mode); 3] = [
        // 128-byte pitch alignment changes the linear request width.
        |m| m.pitch = 1952,
        // No line after VStartup for MIN_DST_Y_NEXT_START.
        |m| {
            m.timing.v_total = 1081;
            m.timing.v_front_porch = 1;
            m.timing.v_sync_width = 0;
        },
        |m| m.timing.v_front_porch = 0,
    ];
    for f in unmodeled {
        let mut m = mode;
        f(&mut m);
        if admit(&soc, &m) != Err(Error::Unsupported) {
            return TestResult::Fail("unmodeled mode accepted");
        }
    }
    let bad_soc: [fn(&mut Soc); 9] = [
        |s| s.umc_channels = 0,
        |s| s.uclk_khz = 0,
        |s| s.fclk_khz = [2, 1],
        |s| s.dcfclk_khz = [0, 1],
        |s| s.dentist_vco_khz = 1_000_000,
        |s| s.dchub_refclk_khz = 0,
        |s| s.dchub_refclk_khz = 2_000_000,
        |s| s.uclk_khz = u32::MAX,
        |s| s.fclk_khz[1] = u32::MAX,
    ];
    for f in bad_soc {
        let mut s = soc;
        f(&mut s);
        if admit(&s, &mode) != Err(Error::Invalid) {
            return TestResult::Fail("invalid SoC accepted");
        }
    }
    // A memory clock the fabric/DCF tables cannot carry has no DML state.
    let mut slow_fabric = soc;
    slow_fabric.fclk_khz = [300_000, 600_000];
    if admit(&slow_fabric, &mode) != Err(Error::ClockState) {
        return TestResult::Fail("pruned clock state admitted");
    }
    // Downspread limits: a pixel clock at the raw maximum is too fast for
    // one pipe, so DML splits it across two.
    let mut fast = mode;
    fast.timing.pixel_clock_khz = soc.dispclk_max_khz;
    if admit(&soc, &fast).map(|p| p.pipes) != Ok(2) {
        return TestResult::Fail("downspread margin ignored");
    }
    // Past four pipes' worth of DISPCLK no ODM split can carry it.
    fast.timing.pixel_clock_khz = 4 * soc.dispclk_max_khz;
    if admit(&soc, &fast) != Err(Error::PixelClock) {
        return TestResult::Fail("over-fast pixel clock admitted");
    }
    // Wider than the DCN4 linear swath limit.
    let mut wide = mode;
    wide.timing.h_active = 15_424;
    wide.timing.h_total = 15_600;
    wide.pitch = 15_424;
    wide.timing.pixel_clock_khz = 600_000;
    if admit(&soc, &wide) != Err(Error::Buffer) {
        return TestResult::Fail("over-wide swath admitted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_rejects_invalid_and_unmodeled_inputs
);

/// Shared with tests/dcn401_dml21/check.sh (harness_multi.c).
const MULTI_VECTORS: &str = include_str!("../tests/dcn401_dml21/multi_vectors.txt");

/// Shared with tests/dcn401_dml21/check.sh (harness_multi.c, FMT420).
const YCBCR420_VECTORS: &str = include_str!("../tests/dcn401_dml21/ycbcr420_vectors.txt");

/// Check `vectors` (multi_vectors.txt format) with every stream's 4:2:0
/// output set to `ycbcr420`; the plan, rejection and ODM 2:1 plan counts
/// seen (the last counts configurations with a two-pipe stream).
fn check_multi_vectors(vectors: &str, ycbcr420: bool) -> Result<(u32, u32, u32), &'static str> {
    check_vectors(vectors, ycbcr420, false)
}

/// As `check_multi_vectors`; with `dsc` each line starts with the slice
/// count and compressed bpp every stream takes, and "! REJECT" asks only
/// that the configuration is rejected.
fn check_vectors(
    vectors: &str,
    ycbcr420: bool,
    dsc: bool,
) -> Result<(u32, u32, u32), &'static str> {
    check_vectors_with(vectors, ycbcr420, dsc, false)
}

/// As `check_vectors`; with `bytes` each line starts with the bytes per
/// pixel of every stream's plane (format_vectors.txt).
fn check_vectors_with(
    vectors: &str,
    ycbcr420: bool,
    dsc: bool,
    bytes: bool,
) -> Result<(u32, u32, u32), &'static str> {
    let (mut plans, mut rejects, mut odm) = (0, 0, 0);
    for line in vectors.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace().peekable();
        let mut d = [0u32; 2];
        if dsc && !parse(&mut words, &mut d) {
            return Err("malformed DSC vector");
        }
        let mut b = [4u32];
        if bytes && !parse(&mut words, &mut b) {
            return Err("malformed format vector");
        }
        let mut s = [0u32; 10];
        if !parse(&mut words, &mut s) || !(1..=4).contains(&s[9]) {
            return Err("malformed multi-stream SoC inputs");
        }
        let mut modes = Vec::new();
        for _ in 0..s[9] {
            let mut t = [0u32; 10];
            if !parse(&mut words, &mut t) {
                return Err("malformed multi-stream mode");
            }
            // The single-stream layout: timing, SoC, then the pitch.
            let mut f = [0u32; 19];
            f[..9].copy_from_slice(&t[..9]);
            f[9..18].copy_from_slice(&s[..9]);
            f[18] = t[9];
            let (_, mut mode) = inputs(&f);
            mode.ycbcr420 = ycbcr420;
            mode.bytes_per_pixel = b[0];
            mode.dsc = dsc.then_some(Dsc {
                slices: d[0],
                bpp_x16: d[1],
            });
            modes.push(mode);
        }
        let mut f = [0u32; 19];
        f[9..18].copy_from_slice(&s[..9]);
        let (soc, _) = inputs(&f);
        let result = admit_all(&soc, &modes);
        match words.next() {
            Some("=") => {
                let Ok(got) = &result else {
                    return Err("Linux-admitted configuration rejected");
                };
                for (k, plan) in got.iter().enumerate() {
                    if k > 0 && words.next() != Some("|") {
                        return Err("malformed multi-stream plan separator");
                    }
                    let mut want = [0u32; 62];
                    if !parse(&mut words, &mut want) {
                        return Err("malformed multi-stream plan");
                    }
                    for (i, (&g, &w)) in values(plan).iter().zip(want.iter()).enumerate() {
                        if g != w && !(TOLERATED.contains(&i) && g.abs_diff(w) == 1) {
                            return Err("joint plan value differs from Linux DML21");
                        }
                    }
                    if !pipes_match(&mut words, plan) {
                        return Err("joint plan ODM pipes differ from Linux DML21");
                    }
                    if !plan.readmits() || plan.mode != modes[k] || usize::from(plan.stream) != k {
                        return Err("joint plan not reproducible or not bound");
                    }
                }
                if got.len() != modes.len() || words.next().is_some() {
                    return Err("joint plan count");
                }
                plans += 1;
                odm += u32::from(got.iter().any(|p| p.pipes == 2));
            }
            Some("!") => {
                let (Some(name), Err(e)) = (words.next(), result) else {
                    return Err("rejected configuration admitted");
                };
                if name != "REJECT" && error_name(e) != name {
                    return Err("configuration rejected for a different reason");
                }
                rejects += 1;
            }
            _ => return Err("malformed multi-stream vector kind"),
        }
    }
    Ok((plans, rejects, odm))
}

fn dcn401_dml_matches_linux_dml21_multi_stream_vectors() -> TestResult {
    match check_multi_vectors(MULTI_VECTORS, false) {
        Ok((plans, rejects, _)) if plans >= 200 && rejects >= 15 => TestResult::Pass,
        Ok(_) => TestResult::Fail("multi-stream vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_multi_stream_vectors
);

/// HDMI YCbCr 4:2:0 outputs: one more line after the scaler, and at most
/// 4096 even pixels per line per pipe, as DML21 plans them.
fn dcn401_dml_matches_linux_dml21_ycbcr420_vectors() -> TestResult {
    match check_multi_vectors(YCBCR420_VECTORS, true) {
        Ok((plans, rejects, _)) if plans >= 50 && rejects >= 3 => TestResult::Pass,
        Ok(_) => TestResult::Fail("4:2:0 vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_ycbcr420_vectors
);

/// Shared with tests/dcn401_dml21/check.sh (harness_multi.c, DSC).
const DSC_VECTORS: &str = include_str!("../tests/dcn401_dml21/dsc_vectors.txt");

/// DSC streams as DC passes them to DML21: one DSC per ODM pipe (at most
/// four slices dividing at most 5760 pixels each, DSCCLK a third of the
/// pipe's pixels), and DSCDelayRequirement after the scaler.
fn dcn401_dml_matches_linux_dml21_dsc_vectors() -> TestResult {
    match check_vectors(DSC_VECTORS, false, true) {
        Ok((plans, rejects, _)) if plans >= 250 && rejects >= 90 => TestResult::Pass,
        Ok(_) => TestResult::Fail("DSC vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_dsc_vectors
);

/// Shared with tests/dcn401_dml21/check.sh (harness_multi.c).
const ODM_VECTORS: &str = include_str!("../tests/dcn401_dml21/odm_vectors.txt");
/// Shared with tests/dcn401_dml21/check.sh (harness_multi.c, DSC).
const ODM_DSC_VECTORS: &str = include_str!("../tests/dcn401_dml21/odm_dsc_vectors.txt");
/// Shared with tests/dcn401_dml21/check.sh (harness_multi.c, FMT420).
const ODM_YCBCR420_VECTORS: &str = include_str!("../tests/dcn401_dml21/odm_ycbcr420_vectors.txt");

/// ODM 2:1 as DML21's auto policy chooses it: pixel clocks past one pipe's
/// DISPCLK alone and beside other streams, every pipe's values as Linux
/// programs them, wider splits and a fifth pipe rejected.
fn dcn401_dml_matches_linux_dml21_odm_vectors() -> TestResult {
    match check_vectors(ODM_VECTORS, false, false) {
        Ok((plans, rejects, odm)) if plans >= 300 && rejects >= 150 && odm >= 150 => {
            TestResult::Pass
        }
        Ok(_) => TestResult::Fail("ODM vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_odm_vectors
);

/// DSC lines wider than one DSC or with more than four slices, on two pipes.
fn dcn401_dml_matches_linux_dml21_odm_dsc_vectors() -> TestResult {
    match check_vectors(ODM_DSC_VECTORS, false, true) {
        Ok((plans, rejects, odm)) if plans >= 180 && rejects >= 150 && odm >= 150 => {
            TestResult::Pass
        }
        Ok(_) => TestResult::Fail("ODM DSC vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_odm_dsc_vectors
);

/// Shared with tests/dcn401_dml21/check.sh (harness_multi.c, DSC, DP2P0).
const UHBR_DSC_VECTORS: &str = include_str!("../tests/dcn401_dml21/uhbr_dsc_vectors.txt");

/// The DSC streams the UHBR DSC policy picks (8K60 and 4K240 at 16 bpp on
/// four slices, 4K144 at 243/16 bpp on two), alone and beside each other,
/// as DC passes them on 128b/132b encoders (dml2_dp2p0): admission takes
/// the same inputs as on 8b/10b, and Linux plans them identically.
fn dcn401_dml_matches_linux_dml21_uhbr_dsc_vectors() -> TestResult {
    match check_vectors(UHBR_DSC_VECTORS, false, true) {
        Ok((plans, rejects, odm)) if plans >= 20 && rejects >= 3 && odm >= 15 => TestResult::Pass,
        Ok(_) => TestResult::Fail("UHBR DSC vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_uhbr_dsc_vectors
);

/// 4:2:0 lines wider than one formatter buffer, on two pipes.
fn dcn401_dml_matches_linux_dml21_odm_ycbcr420_vectors() -> TestResult {
    match check_vectors(ODM_YCBCR420_VECTORS, true, false) {
        Ok((plans, rejects, odm)) if plans >= 100 && rejects >= 20 && odm >= 90 => TestResult::Pass,
        Ok(_) => TestResult::Fail("ODM 4:2:0 vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_odm_ycbcr420_vectors
);

/// Shared with tests/dcn401_dml21/check.sh (harness_multi.c, PIXEL_BYTES).
const FORMAT_VECTORS: &str = include_str!("../tests/dcn401_dml21/format_vectors.txt");

/// RGB565 (dml2_444_16) and FP16 (dml2_444_64) planes: the request width,
/// swath, DET lines, read bandwidth and deep-sleep DCFCLK follow the
/// bytes per pixel, alone, beside other streams and on ODM 2:1 pipes.
fn dcn401_dml_matches_linux_dml21_format_vectors() -> TestResult {
    let (mut two, mut eight) = (0, 0);
    for line in FORMAT_VECTORS.lines() {
        match line.split_whitespace().next() {
            Some("2") => two += 1,
            Some("8") => eight += 1,
            Some("#") | None => {}
            Some(_) => return TestResult::Fail("format vector of another depth"),
        }
    }
    match check_vectors_with(FORMAT_VECTORS, false, false, true) {
        Ok((plans, rejects, odm))
            if plans >= 1200 && rejects >= 400 && odm >= 300 && two >= 900 && eight >= 900 =>
        {
            TestResult::Pass
        }
        Ok(_) => TestResult::Fail("format vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_format_vectors
);

/// Linux's depth limits: only 2, 4 and 8 bytes per pixel, each with a pitch
/// of whole 256-byte requests; a 2-byte plane's 64-pixel-aligned pitch is a
/// 128-byte linear surface DML plans differently.
fn dcn401_dml_bytes_per_pixel_domain() -> TestResult {
    let soc = Soc {
        dcfclk_khz: [1_564_000, 1_564_000],
        fclk_khz: [2_500_000, 2_500_000],
        uclk_khz: 1_250_000,
        dispclk_max_khz: 2_000_000,
        dppclk_max_khz: 2_000_000,
        socclk_khz: 1_200_000,
        umc_channels: 16,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let t = Timing {
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
    };
    let m = |bytes_per_pixel, pitch| Mode {
        timing: t,
        pitch,
        bytes_per_pixel,
        ycbcr420: false,
        dsc: None,
        planes: [None; MAX_PLANES],
    };
    for bad in [0, 1, 3, 6, 16] {
        if admit(&soc, &m(bad, 1920)) != Err(Error::Invalid) {
            return TestResult::Fail("unsupported depth admitted");
        }
    }
    if admit(&soc, &m(2, 1984)) != Err(Error::Unsupported) {
        return TestResult::Fail("128-byte linear pitch admitted");
    }
    let (Ok(p2), Ok(p4), Ok(p8)) = (
        admit(&soc, &m(2, 1920)),
        admit(&soc, &m(4, 1920)),
        admit(&soc, &m(8, 1920)),
    ) else {
        return TestResult::Fail("1080p60 at a supported depth rejected");
    };
    // Twice the bytes per request pixel halves the request's delivery time.
    if !(p2.ttu.refcyc_per_req_delivery_l > p4.ttu.refcyc_per_req_delivery_l
        && p4.ttu.refcyc_per_req_delivery_l > p8.ttu.refcyc_per_req_delivery_l)
    {
        return TestResult::Fail("request delivery does not follow the depth");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn401-dml", dcn401_dml_bytes_per_pixel_domain);

fn timing(
    pixel_clock_khz: u32,
    h_active: u32,
    h_total: u32,
    v_active: u32,
    v_total: u32,
) -> Timing {
    Timing {
        pixel_clock_khz,
        h_active,
        h_total,
        h_front_porch: 48,
        h_sync_width: 32,
        v_active,
        v_total,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: true,
    }
}

fn dcn401_dml_odm_combine_follows_dml_policy() -> TestResult {
    let (soc, hd) = reference_1080p();
    // DML's max_dispclk_freq_mhz: 2 GHz less 0.38% downspread.
    let ss = 1_992_428;
    let mut uhd = hd;
    uhd.timing = timing(ss, 3840, 4000, 2160, 2310);
    uhd.pitch = 3840;
    // At the downspread maximum one pipe suffices; one kHz more needs two.
    if admit(&soc, &uhd).map(|p| p.pipes) != Ok(1) {
        return TestResult::Fail("ODM chosen below the DISPCLK maximum");
    }
    uhd.timing.pixel_clock_khz = ss + 1;
    if admit(&soc, &uhd).map(|p| p.pipes) != Ok(2) {
        return TestResult::Fail("ODM 2:1 not chosen above the DISPCLK maximum");
    }
    // 2160p240: each pipe fetches half the line at half the pixel clock.
    uhd.timing.pixel_clock_khz = 2_217_600;
    let Ok(p) = admit(&soc, &uhd) else {
        return TestResult::Fail("2160p240 rejected");
    };
    let half = uhd.timing.pixel_clock_khz / 2;
    if p.pipes != 2
        || p.clocks.dispclk_khz < half
        || p.clocks.dppclk_khz < half
        || p.clocks.dppclk_khz >= uhd.timing.pixel_clock_khz
        || p.det_bytes != DET_KBYTES * 1024
    {
        return TestResult::Fail("ODM 2:1 clocks or DET");
    }
    // The second pipe's blank ends half a line later; nothing else differs.
    let end = (uhd.timing.h_blank_end() + 1920) * 50_000 / uhd.timing.pixel_clock_khz;
    match (p.pipe_dlg(0), p.pipe_dlg(1), p.pipe_dlg(2)) {
        (Some(a), Some(b), None)
            if a == p.dlg
                && b.refcyc_h_blank_end == end
                && b == (Dlg {
                    refcyc_h_blank_end: end,
                    ..a
                }) => {}
        _ => return TestResult::Fail("second ODM pipe's DLG"),
    }
    // Past two pipes' DISPCLK DML would split 3:1, which is not admitted.
    uhd.timing.pixel_clock_khz = 2 * ss + 1;
    if admit(&soc, &uhd) != Err(Error::Unsupported) {
        return TestResult::Fail("3:1 split admitted");
    }
    uhd.timing.pixel_clock_khz = 2_217_600;
    // Four pipes in all: two ODM streams, or one beside two single pipes.
    let pipes = |modes: &[Mode]| -> Result<Vec<u8>, Error> {
        Ok(admit_all(&soc, modes)?.iter().map(|p| p.pipes).collect())
    };
    if pipes(&[uhd, hd, hd]) != Ok(alloc::vec![2, 1, 1])
        || pipes(&[hd, uhd]) != Ok(alloc::vec![1, 2])
    {
        return TestResult::Fail("ODM stream beside single-pipe streams");
    }
    if pipes(&[uhd, hd, hd, hd]) != Err(Error::Pipes) || pipes(&[uhd, uhd, hd]) != Err(Error::Pipes)
    {
        return TestResult::Fail("fifth pipe admitted");
    }
    // ODM needs an even split of the line.
    let mut odd = uhd;
    odd.timing.h_active = 3839;
    if admit(&soc, &odd) != Err(Error::Unsupported) {
        return TestResult::Fail("odd line split across two pipes");
    }
    // DSC: more than four slices need a second DSC, so a second pipe, even
    // at a pixel clock one pipe carries; the slices must split evenly.
    let mut dsc = uhd;
    dsc.timing = timing(533_250, 3840, 4000, 2160, 2222);
    dsc.dsc = Some(Dsc {
        slices: 8,
        bpp_x16: 128,
    });
    if admit(&soc, &dsc).map(|p| p.pipes) != Ok(2) {
        return TestResult::Fail("eight DSC slices on one pipe");
    }
    dsc.dsc = Some(Dsc {
        slices: 6,
        bpp_x16: 128,
    });
    if admit(&soc, &dsc).map(|p| p.pipes) != Ok(2) {
        return TestResult::Fail("six DSC slices on one pipe");
    }
    dsc.dsc = Some(Dsc {
        slices: 5,
        bpp_x16: 128,
    });
    if admit(&soc, &dsc).is_ok() {
        return TestResult::Fail("odd DSC slices split across two pipes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_odm_combine_follows_dml_policy
);

fn dcn401_dml_joint_plans_share_global_state() -> TestResult {
    let (soc, hd) = reference_1080p();
    let mut uhd = hd;
    uhd.timing = Timing {
        pixel_clock_khz: 533_250,
        h_active: 3840,
        h_total: 4000,
        h_front_porch: 48,
        h_sync_width: 32,
        v_active: 2160,
        v_total: 2222,
        v_front_porch: 3,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: true,
    };
    uhd.pitch = 3840;
    let Ok(alone) = admit(&soc, &hd) else {
        return TestResult::Fail("1080p60 rejected");
    };
    if admit_all(&soc, &[hd]).ok().and_then(|p| p.first().copied()) != Some(alone) {
        return TestResult::Fail("admit is not admit_all of one mode");
    }
    let Ok(joint) = admit_all(&soc, &[hd, uhd]) else {
        return TestResult::Fail("1080p60 + 2160p60 rejected");
    };
    let (a, b) = (joint[0], joint[1]);
    // One DISPCLK/DPPREFCLK for the faster pipe, each DPPCLK its own.
    if a.clocks.dispclk_khz != b.clocks.dispclk_khz
        || a.clocks.dpprefclk_khz != b.clocks.dpprefclk_khz
        || a.clocks.dispclk_khz < 533_250
        || a.clocks.dppclk_khz >= b.clocks.dppclk_khz
        || a.watermarks != b.watermarks
        || a.arbiter != b.arbiter
        || a.clocks.deep_sleep_dcfclk_khz != b.clocks.deep_sleep_dcfclk_khz
    {
        return TestResult::Fail("global clocks/watermarks not shared");
    }
    // A second pipe's pixel chunk lengthens the urgent watermark.
    if a.watermarks.urgent <= alone.watermarks.urgent {
        return TestResult::Fail("extra latency ignores the second pipe");
    }
    // A plan is bound to its configuration: alone it is not this plan.
    if !a.readmits() || a == alone || a.joint_modes() != [hd, uhd] {
        return TestResult::Fail("joint plan not bound to its configuration");
    }
    let mut edited = a;
    edited.streams[1] = None;
    if edited.readmits() {
        return TestResult::Fail("plan re-admitted outside its configuration");
    }
    if admit_all(&soc, &[]) != Err(Error::Invalid)
        || admit_all(&soc, &[hd; 5]) != Err(Error::Invalid)
    {
        return TestResult::Fail("stream count unchecked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_joint_plans_share_global_state
);

/// Shared with tests/dcn401_dml21/check.sh (harness_planes.c, RAISED).
const PLANE_VECTORS: &str = include_str!("../tests/dcn401_dml21/plane_vectors.txt");

/// `plan` as plane `k` of its stream sees it: the plane's DPPCLK, DLG,
/// TTU, DET and ODM blank end in the stream's plan.
fn plane_view(plan: &Plan, k: usize) -> Option<Plan> {
    let p = plan.plane(k)?;
    Some(Plan {
        clocks: Clocks {
            dppclk_khz: p.dppclk_khz,
            ..plan.clocks
        },
        dlg: p.dlg,
        ttu: p.ttu,
        det_bytes: p.det_bytes,
        odm_refcyc_h_blank_end: p.odm_refcyc_h_blank_end,
        planes: [Some(p), None, None, None],
        ..*plan
    })
}

/// plane_vectors.txt: every plane's plan values (as multi_vectors.txt's,
/// planes in argument order), or the rejection.
fn check_plane_vectors(vectors: &str) -> Result<(u32, u32, u32), &'static str> {
    let (mut plans, mut rejects, mut overlays) = (0, 0, 0);
    for line in vectors.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace().peekable();
        let mut s = [0u32; 9];
        if !parse(&mut words, &mut s) {
            return Err("malformed plane SoC inputs");
        }
        let mut f = [0u32; 19];
        f[9..18].copy_from_slice(&s);
        let (soc, _) = inputs(&f);
        let mut modes = Vec::new();
        while words.peek().is_some_and(|w| *w != "=" && *w != "!") {
            let mut t = [0u32; 10];
            if !parse(&mut words, &mut t) || !(1..=4).contains(&t[9]) {
                return Err("malformed plane stream");
            }
            let mut g = [0u32; 19];
            g[..9].copy_from_slice(&t[..9]);
            g[9..18].copy_from_slice(&s);
            let (_, mut mode) = inputs(&g);
            for slot in mode.planes.iter_mut().take(t[9] as usize) {
                let mut p = [0u32; 10];
                if !parse(&mut words, &mut p) {
                    return Err("malformed plane");
                }
                *slot = Some(Plane {
                    surface_width: p[0],
                    surface_height: p[1],
                    pitch: p[2],
                    bytes_per_pixel: p[3],
                    viewport_width: p[4],
                    viewport_height: p[5],
                    h_ratio: p[6],
                    v_ratio: p[7],
                    h_taps: p[8],
                    v_taps: p[9],
                });
            }
            mode.pitch = mode.planes[0].map_or(0, |p| p.pitch);
            mode.bytes_per_pixel = mode.planes[0].map_or(0, |p| p.bytes_per_pixel);
            modes.push(mode);
        }
        let result = admit_all(&soc, &modes);
        match words.next() {
            Some("=") => {
                let Ok(got) = &result else {
                    return Err("Linux-admitted plane configuration rejected");
                };
                let mut first = true;
                for plan in got {
                    for k in 0..MAX_PLANES {
                        let Some(view) = plane_view(plan, k) else {
                            break;
                        };
                        if !first && words.next() != Some("|") {
                            return Err("malformed plane plan separator");
                        }
                        first = false;
                        let mut want = [0u32; 62];
                        if !parse(&mut words, &mut want) {
                            return Err("malformed plane plan");
                        }
                        for (i, (&g, &w)) in values(&view).iter().zip(want.iter()).enumerate() {
                            if g != w && !(TOLERATED.contains(&i) && g.abs_diff(w) == 1) {
                                return Err("plane plan value differs from Linux DML21");
                            }
                        }
                        if !pipes_match(&mut words, &view) {
                            return Err("plane plan ODM pipes differ from Linux DML21");
                        }
                        overlays += u32::from(k > 0);
                    }
                    if !plan.readmits() {
                        return Err("plane plan not reproducible");
                    }
                }
                if words.next().is_some() {
                    return Err("plane plan count");
                }
                plans += 1;
            }
            Some("!") => {
                let (Some(name), Err(e)) = (words.next(), result) else {
                    return Err("rejected plane configuration admitted");
                };
                if name != "REJECT" && error_name(e) != name {
                    return Err("plane configuration rejected for a different reason");
                }
                rejects += 1;
            }
            _ => return Err("malformed plane vector kind"),
        }
    }
    Ok((plans, rejects, overlays))
}

/// Scaled planes (SPL's viewport, ratios and taps: DPPCLK, scaler delay,
/// prefetch source lines, line-buffer and DET hiding at the ratios) and
/// several planes per stream (one DPP each, joint bandwidth, extra latency
/// and deep sleep), as DML21 plans them.
fn dcn401_dml_matches_linux_dml21_plane_vectors() -> TestResult {
    match check_plane_vectors(PLANE_VECTORS) {
        Ok((plans, _, overlays)) if plans >= 300 && overlays >= 300 => TestResult::Pass,
        Ok(_) => TestResult::Fail("plane vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_plane_vectors
);

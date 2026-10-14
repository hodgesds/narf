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
            ycbcr420: false,
            dsc: None,
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
    }
}
fn parse(words: &mut core::str::SplitWhitespace<'_>, out: &mut [u32]) -> bool {
    for slot in out.iter_mut() {
        match words.next().and_then(|w| w.parse().ok()) {
            Some(v) => *slot = v,
            None => return false,
        }
    }
    true
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
        let mut words = line.split_whitespace();
        let mut f = [0u32; 19];
        if !parse(&mut words, &mut f) {
            return TestResult::Fail("malformed vector inputs");
        }
        let (soc, mode) = inputs(&f);
        let result = admit(&soc, &mode);
        match words.next() {
            Some("=") => {
                let mut want = [0u32; 62];
                if !parse(&mut words, &mut want) || words.next().is_some() {
                    return TestResult::Fail("malformed vector plan");
                }
                let Ok(plan) = result else {
                    return TestResult::Fail("Linux-admitted mode rejected");
                };
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
    // Downspread limits: a pixel clock at the raw maximum is too fast.
    let mut fast = mode;
    fast.timing.pixel_clock_khz = soc.dispclk_max_khz;
    if admit(&soc, &fast) != Err(Error::PixelClock) {
        return TestResult::Fail("downspread margin ignored");
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
/// output set to `ycbcr420`; the plan and rejection counts seen.
fn check_multi_vectors(vectors: &str, ycbcr420: bool) -> Result<(u32, u32), &'static str> {
    check_vectors(vectors, ycbcr420, false)
}

/// As `check_multi_vectors`; with `dsc` each line starts with the slice
/// count and compressed bpp every stream takes, and "! REJECT" asks only
/// that the configuration is rejected.
fn check_vectors(vectors: &str, ycbcr420: bool, dsc: bool) -> Result<(u32, u32), &'static str> {
    let (mut plans, mut rejects) = (0, 0);
    for line in vectors.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace();
        let mut d = [0u32; 2];
        if dsc && !parse(&mut words, &mut d) {
            return Err("malformed DSC vector");
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
                    if !plan.readmits() || plan.mode != modes[k] || usize::from(plan.stream) != k {
                        return Err("joint plan not reproducible or not bound");
                    }
                }
                if got.len() != modes.len() || words.next().is_some() {
                    return Err("joint plan count");
                }
                plans += 1;
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
    Ok((plans, rejects))
}

fn dcn401_dml_matches_linux_dml21_multi_stream_vectors() -> TestResult {
    match check_multi_vectors(MULTI_VECTORS, false) {
        Ok((plans, rejects)) if plans >= 150 && rejects >= 20 => TestResult::Pass,
        Ok(_) => TestResult::Fail("multi-stream vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_multi_stream_vectors
);

/// HDMI YCbCr 4:2:0 outputs: one more line after the scaler, and at most
/// 4096 even pixels per line without ODM, as DML21 plans them.
fn dcn401_dml_matches_linux_dml21_ycbcr420_vectors() -> TestResult {
    match check_multi_vectors(YCBCR420_VECTORS, true) {
        Ok((plans, rejects)) if plans >= 40 && rejects >= 8 => TestResult::Pass,
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

/// DSC streams as DC passes them to DML21: one DSC in ODM bypass (at most
/// four slices dividing at most 5760 pixels, DSCCLK a third of the pixel
/// clock), and DSCDelayRequirement after the scaler.
fn dcn401_dml_matches_linux_dml21_dsc_vectors() -> TestResult {
    match check_vectors(DSC_VECTORS, false, true) {
        Ok((plans, rejects)) if plans >= 200 && rejects >= 100 => TestResult::Pass,
        Ok(_) => TestResult::Fail("DSC vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_dsc_vectors
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

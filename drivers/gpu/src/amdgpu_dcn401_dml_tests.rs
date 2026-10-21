use super::*;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Shared with tests/dcn401_dml21/check.sh, which verifies every line
/// against Linux DML21 built on the host.
const VECTORS: &str = include_str!("../tests/dcn401_dml21/vectors.txt");
/// Deep-sleep DCFCLK and the three urgent-bandwidth fractions truncate a
/// double in Linux and a fixed-point value here; they may differ by one.
pub(super) const TOLERATED: [usize; 4] = [3, 47, 48, 49];
/// The vector files before mpc_vectors.txt were planned with
/// `mpcc_combine_factor` 1 (MPC combine off).
const NO_MPC: Policy = Policy { mpc_combine: false };

/// Linux plans some stream of the configuration on three or four ODM
/// pipes ("! Unsupported odm" lines, from before the port admitted 3:1 and
/// 4:1; odm34_vectors.txt holds their plans): the port must admit it with
/// such a stream, or refuse a plan value outside its register field as it
/// refuses Linux's other overflowing plans (`Register`).
fn wide_odm(result: &Result<Vec<Plan>, Error>) -> bool {
    match result {
        Ok(plans) => plans.iter().any(|p| p.pipes >= 3),
        Err(e) => *e == Error::Register,
    }
}
/// Whether a rejection matches a vector's `name`. Before the port admitted
/// 3:1 and 4:1 it named every configuration needing them `Unsupported`;
/// Linux rejects those configurations too (check.sh verifies it), and the
/// port now names the check they fail (pipes, DISPCLK, bandwidth).
fn rejected_as(e: Error, name: &str) -> bool {
    name == "REJECT" || name == "Unsupported" || error_name(e) == name
}

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
pub(super) fn values(p: &Plan) -> [u32; 62] {
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
        Error::PstateLatency => "PstateLatency",
        Error::Register => "Register",
        Error::Pipes => "Pipes",
    }
}
pub(super) fn parse<'a>(words: &mut impl Iterator<Item = &'a str>, out: &mut [u32]) -> bool {
    for slot in out.iter_mut() {
        match words.next().and_then(|w| w.parse().ok()) {
            Some(v) => *slot = v,
            None => return false,
        }
    }
    true
}
/// A plane's values end with "/<n>" and each further pipe's
/// refcyc_h_blank_end when DML puts it on n > 1 DPPs, ODM segments or MPC
/// slices (check.sh has verified every further pipe's other registers
/// equal the first's); otherwise the plan's first plane must be
/// single-pipe.
pub(super) fn pipes_match<'a, I: Iterator<Item = &'a str>>(
    words: &mut core::iter::Peekable<I>,
    plan: &Plan,
) -> bool {
    let Some(p) = plan.plane(0) else {
        return false;
    };
    let n = match words.peek().and_then(|w| w.strip_prefix('/')) {
        Some(n) => match n.parse::<u8>() {
            Ok(n @ 2..=4) => n,
            _ => return false,
        },
        None => 1,
    };
    if n > 1 {
        words.next();
    }
    // An ODM stream's plane has the stream's pipes; an MPC-combined one
    // two DPPs on a single segment.
    if p.dpps != n || !(plan.pipes == n || (plan.pipes == 1 && n == 2)) {
        return false;
    }
    for i in 1..n {
        let mut end = [0u32; 1];
        if !parse(words, &mut end)
            || plan.pipe_dlg(i)
                != Some(Dlg {
                    refcyc_h_blank_end: end[0],
                    ..plan.dlg
                })
        {
            return false;
        }
        let odm = if plan.pipes > 1 {
            p.odm_refcyc_h_blank_end[usize::from(i) - 1]
        } else {
            plan.dlg.refcyc_h_blank_end
        };
        if odm != end[0] {
            return false;
        }
    }
    plan.pipe_dlg(n).is_none()
        && p.odm_refcyc_h_blank_end[usize::from(plan.pipes.max(1) - 1)..]
            .iter()
            .all(|&e| e == 0)
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
        let joint = admit_all_with(&soc, &[mode], NO_MPC);
        let result = joint.clone().map(|p| p[0]);
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
                let name = words.next();
                if name == Some("Unsupported") && words.peek() == Some(&"odm") {
                    if !wide_odm(&joint) {
                        return TestResult::Fail("Linux's 3:1/4:1 plan not admitted");
                    }
                    rejects += 1;
                    continue;
                }
                let (Some(name), Err(e)) = (name, result) else {
                    return TestResult::Fail("rejected mode admitted");
                };
                if !rejected_as(e, name) {
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
    // Wider than the DCN4 linear swath limit: one DPP cannot take it, so
    // DML's auto factor MPC-combines it (refused when combine is off).
    let mut wide = mode;
    wide.timing.h_active = 15_424;
    wide.timing.h_total = 15_600;
    wide.pitch = 15_424;
    wide.timing.pixel_clock_khz = 600_000;
    if admit_all_with(&soc, &[wide], NO_MPC) != Err(Error::Buffer) {
        return TestResult::Fail("over-wide swath admitted");
    }
    match admit(&soc, &wide) {
        Ok(p) if p.pipes == 1 && p.plane(0).is_some_and(|q| q.dpps == 2) => {}
        _ => return TestResult::Fail("over-wide swath not MPC-combined"),
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
    let prefix = match (dsc, bytes) {
        (true, _) => Prefix::Dsc,
        (_, true) => Prefix::Bytes,
        _ => Prefix::None,
    };
    check_vectors_policy(vectors, ycbcr420, prefix, NO_MPC).map(|c| (c.0, c.1, c.2))
}

/// What a vector line carries before its multi_vectors.txt inputs.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Prefix {
    None,
    /// "<slices> <bpp_x16>": every stream compressed so.
    Dsc,
    /// "<bytes per pixel>" of every stream's plane.
    Bytes,
    /// "<bytes per pixel> <slices> <bpp_x16> <4:2:0>": all three, slices 0
    /// for no DSC (odm34_vectors.txt).
    Full,
}

/// As `check_vectors_with` under `policy`; also counts the configurations
/// with a stream on three or four pipes, and with an MPC-combined plane.
fn check_vectors_policy(
    vectors: &str,
    ycbcr420: bool,
    prefix: Prefix,
    policy: Policy,
) -> Result<(u32, u32, u32, u32, u32), &'static str> {
    let (mut plans, mut rejects, mut odm, mut wide, mut mpc) = (0, 0, 0, 0, 0);
    for line in vectors.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace().peekable();
        let mut b = [4u32];
        if matches!(prefix, Prefix::Bytes | Prefix::Full) && !parse(&mut words, &mut b) {
            return Err("malformed format vector");
        }
        let mut d = [0u32; 2];
        if matches!(prefix, Prefix::Dsc | Prefix::Full) && !parse(&mut words, &mut d) {
            return Err("malformed DSC vector");
        }
        let mut f420 = [u32::from(ycbcr420)];
        if prefix == Prefix::Full && !parse(&mut words, &mut f420) {
            return Err("malformed 4:2:0 flag");
        }
        let dsc = d[0] != 0;
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
            mode.ycbcr420 = f420[0] != 0;
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
        let result = admit_all_with(&soc, &modes, policy);
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
                odm += u32::from(got.iter().any(|p| p.pipes >= 2));
                wide += u32::from(got.iter().any(|p| p.pipes >= 3));
                mpc += u32::from(
                    got.iter()
                        .any(|p| p.pipes == 1 && p.planes.iter().flatten().any(|q| q.dpps == 2)),
                );
            }
            Some("!") => {
                let name = words.next();
                if name == Some("Unsupported") && words.peek() == Some(&"odm") {
                    if !wide_odm(&result) {
                        return Err("Linux's 3:1/4:1 configuration not admitted");
                    }
                    rejects += 1;
                    continue;
                }
                let (Some(name), Err(e)) = (name, result) else {
                    return Err("rejected configuration admitted");
                };
                if !rejected_as(e, name) {
                    return Err("configuration rejected for a different reason");
                }
                rejects += 1;
            }
            _ => return Err("malformed multi-stream vector kind"),
        }
    }
    Ok((plans, rejects, odm, wide, mpc))
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

/// Shared with tests/dcn401_dml21/check.sh (harness_multi.c, DSC, HDMIFRL).
const FRL_DSC_VECTORS: &str = include_str!("../tests/dcn401_dml21/frl_dsc_vectors.txt");

/// The DSC streams the HDMI FRL DSC policy picks (8K60 VIC 199 at its
/// 159/16-bpp preset, 8K60 and 4K240 RBv2 at 12 bpp, eight slices each),
/// as DC passes them on HDMI FRL encoders (dml2_hdmifrl): Linux plans a
/// 4:4:4 DSC stream there as on DP, so admission takes the same inputs.
fn dcn401_dml_matches_linux_dml21_frl_dsc_vectors() -> TestResult {
    match check_vectors(FRL_DSC_VECTORS, false, true) {
        Ok((plans, rejects, odm)) if plans >= 4 && rejects >= 2 && odm >= 4 => TestResult::Pass,
        Ok(_) => TestResult::Fail("FRL DSC vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_frl_dsc_vectors
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
    // Past two pipes' DISPCLK DML splits 3:1 (without DSC the segments
    // may be uneven, but the line divides by four), past three 4:1.
    uhd.timing.pixel_clock_khz = 2 * ss + 1;
    let Ok(p3) = admit(&soc, &uhd) else {
        return TestResult::Fail("3:1 split rejected");
    };
    let third = |k: u32| {
        (uhd.timing.h_blank_end() * 3 + k * 3840) * 50_000 / (3 * uhd.timing.pixel_clock_khz)
    };
    if p3.pipes != 3
        || p3.odm_refcyc_h_blank_end != [third(1), third(2), 0]
        || p3.pipe_dlg(2).map(|d| d.refcyc_h_blank_end) != Some(third(2))
        || p3.pipe_dlg(3).is_some()
        || p3.clocks.dispclk_khz < uhd.timing.pixel_clock_khz / 3
    {
        return TestResult::Fail("3:1 plan");
    }
    uhd.timing.pixel_clock_khz = 3 * ss + 1;
    if admit(&soc, &uhd).map(|p| p.pipes) != Ok(4) {
        return TestResult::Fail("4:1 split not chosen past three pipes");
    }
    // A 3:1 or 4:1 line must divide by four (OTG_H_TIMING_DIV_BY4).
    let mut by4 = uhd;
    by4.timing.h_active = 3838;
    by4.timing.pixel_clock_khz = 2 * ss + 1;
    if admit(&soc, &by4) != Err(Error::Unsupported) {
        return TestResult::Fail("3:1 line not divisible by four admitted");
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
    edited.streams[0] = None;
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
pub(super) fn plane_view(plan: &Plan, k: usize) -> Option<Plan> {
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
    check_plane_vectors_policy(vectors, NO_MPC).map(|c| (c.0, c.1, c.2))
}

/// As `check_plane_vectors` under `policy`; also counts MPC-combined planes.
fn check_plane_vectors_policy(
    vectors: &str,
    policy: Policy,
) -> Result<(u32, u32, u32, u32), &'static str> {
    let (mut plans, mut rejects, mut overlays, mut mpc) = (0, 0, 0, 0);
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
                    surface_width: Plane::extent(p[0]),
                    surface_height: Plane::extent(p[1]),
                    pitch: Plane::extent(p[2]),
                    bytes_per_pixel: Plane::count(p[3]),
                    viewport_width: Plane::extent(p[4]),
                    viewport_height: Plane::extent(p[5]),
                    h_ratio: p[6],
                    v_ratio: p[7],
                    h_taps: Plane::count(p[8]),
                    v_taps: Plane::count(p[9]),
                    ..Plane::default()
                });
            }
            mode.pitch = mode.planes[0].map_or(0, |p| u32::from(p.pitch));
            mode.bytes_per_pixel = mode.planes[0].map_or(0, |p| u32::from(p.bytes_per_pixel));
            modes.push(mode);
        }
        let result = admit_all_with(&soc, &modes, policy);
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
                        mpc += u32::from(
                            plan.pipes == 1 && view.planes[0].is_some_and(|p| p.dpps == 2),
                        );
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
    Ok((plans, rejects, overlays, mpc))
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

/// Shared with tests/dcn401_dml21/check.sh (harness_surfaces.c, RAISED).
const SURFACE_VECTORS: &str = include_str!("../tests/dcn401_dml21/surface_vectors.txt");

/// The 90 values harness_surfaces.c prints after a plane's 62: the chroma
/// DLG/TTU delivery, both surfaces' rq_regs, the expansion modes, the DET's
/// chroma base, unbounded requesting, the arbiter's hw_debug5, the whole
/// mcache allocation and four pipes' mcache registers.
const SURFACE_VALUES: usize = 27 + 2 + 4 * (MAX_MCACHES + 1) + 1 + 4 * 6;
fn surface_values(plan: &Plan, k: usize, p: &PlanePlan, rotation: u32) -> [u32; SURFACE_VALUES] {
    let mut out = [0u32; SURFACE_VALUES];
    out[..27].copy_from_slice(&surface_rq_values(plan, p)[..27]);
    // The mcache allocation, then each of four pipes' mcache registers.
    let a = p.mcache.unwrap_or_default();
    let mut v = alloc::vec::Vec::with_capacity(SURFACE_VALUES - 27);
    v.extend(a.count.map(u32::from));
    for i in 0..2 {
        v.extend(a.offsets[i].map(u32::from));
    }
    for i in 0..2 {
        v.extend(a.ids[i].map(u32::from));
    }
    v.push(u32::from(a.shared));
    let plane = plan.mode.plane_list().nth(k).unwrap_or_default();
    // The production path's viewports (`SurfaceRequest::mcache_viewports`,
    // as `deadline::pipe_mcache` takes them): SPL on each pipe's ODM
    // segment or MPC slice of the plane, its source the viewport at the
    // surface origin and its destination the whole stream
    // (harness_surfaces.c / spl_viewport.c).
    let request = surface_request(plan, &plane, rotation, p.dpps);
    let n = u32::from(p.dpps);
    for j in 0..4u32 {
        if j >= n {
            v.extend([0; 6]);
            continue;
        }
        let regs = match p.mcache {
            None => Some([McacheRegs::UNASSIGNED; 2]),
            Some(a) => request
                .mcache_viewports(j as u8)
                .and_then(|(luma, chroma)| a.pipe_regs(luma, chroma)),
        };
        match regs {
            Some(r) => {
                for s in r {
                    v.extend([s.id_first, s.id_second, s.split_location]);
                }
            }
            None => v.extend([0; 6]),
        }
    }
    out[27..].copy_from_slice(&v);
    out
}

/// The plane on pipes 0..`dpps` as the scanout requests it: its stream's
/// ODM segments, or its MPC slices in ODM bypass; its source the viewport
/// at the surface origin, its destination the whole stream, rotated by
/// `rotation` (dml2_rotation_angle), blended opaque.
fn surface_request(
    plan: &Plan,
    plane: &Plane,
    rotation: u32,
    dpps: u8,
) -> crate::amdgpu_dcn401_otg::SurfaceRequest {
    use crate::amdgpu_dcn401_otg::{
        Blend, PlaneLayout, PlaneSurface, SplitPipes, SurfaceFormat, SurfaceRequest,
    };
    use crate::amdgpu_dcn401_spl::{Rect, Rotation};
    let t = plan.mode.timing;
    let rest = SplitPipes::new(&[1, 2, 3][..usize::from(dpps.clamp(1, 4)) - 1]).unwrap_or_default();
    let (odm, mpc) = if plan.pipes > 1 {
        (rest, SplitPipes::NONE)
    } else {
        (SplitPipes::NONE, rest)
    };
    let format = match plane.source {
        Source::Yuv420_8 => SurfaceFormat::Nv12,
        Source::Yuv420_10 => SurfaceFormat::P010,
        Source::Rgb => SurfaceFormat::Xrgb8888,
    };
    SurfaceRequest {
        pipe: 0,
        width: u32::from(plane.surface_width),
        height: u32::from(plane.surface_height),
        format,
        odm,
        mpc,
        plane: Some(PlaneLayout {
            src: Rect::new(
                0,
                0,
                i32::from(plane.viewport_width),
                i32::from(plane.viewport_height),
            ),
            dst: Rect::new(0, 0, t.h_active as i32, t.v_active as i32),
            stream_width: t.h_active,
            stream_height: t.v_active,
            ycbcr420: plan.mode.ycbcr420,
            rotation: match rotation {
                1 => Rotation::R90,
                2 => Rotation::R180,
                3 => Rotation::R270,
                _ => Rotation::R0,
            },
            blend: Blend {
                per_pixel_alpha: false,
                premultiplied: true,
                global_alpha: None,
            },
            underlay: false,
        }),
        surface: PlaneSurface::LINEAR,
    }
}

/// The chroma delivery, rq_regs, expansion modes, DET chroma base,
/// unbounded requesting and hw_debug5 (28 with a zero pad).
fn surface_rq_values(plan: &Plan, p: &PlanePlan) -> [u32; 28] {
    let (d, t, q) = (&p.dlg, &p.ttu, &p.rq);
    let rq = |r: &RqPlane| {
        [
            r.chunk_size,
            r.min_chunk_size,
            r.meta_chunk_size,
            r.min_meta_chunk_size,
            r.dpte_group_size,
            r.mpte_group_size,
            r.swath_height,
            r.pte_row_height_linear,
        ]
    };
    let (l, c) = (rq(&q.luma), rq(&q.chroma));
    [
        d.refcyc_per_line_delivery_pre_c,
        d.refcyc_per_line_delivery_c,
        t.refcyc_per_req_delivery_pre_c,
        t.refcyc_per_req_delivery_c,
        l[0],
        l[1],
        l[2],
        l[3],
        l[4],
        l[5],
        l[6],
        l[7],
        c[0],
        c[1],
        c[2],
        c[3],
        c[4],
        c[5],
        c[6],
        c[7],
        q.drq_expansion_mode,
        q.prq_expansion_mode,
        q.mrq_expansion_mode,
        q.crq_expansion_mode,
        q.plane1_base_address,
        u32::from(q.unbounded_request_enabled),
        u32::from(plan.arbiter.allow_sdpif_rate_limit_when_cstate_req),
        0,
    ]
}

/// One harness_surfaces.c plane: the plane_vectors.txt values, then source,
/// swizzle, DCC, rotation and the chroma plane.
fn surface_plane(p: &[u32; 23]) -> Option<Plane> {
    let source = match p[10] {
        0 => Source::Rgb,
        1 => Source::Yuv420_8,
        2 => Source::Yuv420_10,
        _ => return None,
    };
    let swizzle = match p[11] {
        0 => Swizzle::Linear,
        1 => Swizzle::S256B2D,
        2 => Swizzle::S4K2D,
        3 => Swizzle::S64K2D,
        4 => Swizzle::S256K2D,
        _ => return None,
    };
    let chroma = (source != Source::Rgb).then(|| Chroma {
        surface_width: Plane::extent(p[14]),
        surface_height: Plane::extent(p[15]),
        pitch: Plane::extent(p[16]),
        viewport_width: Plane::extent(p[17]),
        viewport_height: Plane::extent(p[18]),
        h_ratio: p[19],
        v_ratio: p[20],
        h_taps: Plane::count(p[21]),
        v_taps: Plane::count(p[22]),
    });
    Some(Plane {
        surface_width: Plane::extent(p[0]),
        surface_height: Plane::extent(p[1]),
        pitch: Plane::extent(p[2]),
        bytes_per_pixel: Plane::count(p[3]),
        viewport_width: Plane::extent(p[4]),
        viewport_height: Plane::extent(p[5]),
        h_ratio: p[6],
        v_ratio: p[7],
        h_taps: Plane::count(p[8]),
        v_taps: Plane::count(p[9]),
        source,
        swizzle,
        dcc: p[12] != 0,
        vertical_scan: p[13] % 2 == 1,
        chroma,
    })
}

/// surface_vectors.txt: every plane's 62 plan values and 90 surface values
/// (planes in argument order), or the rejection ("! ClockState" for a plan
/// whose DCF/fabric state DPMM raises). Returns the plans, rejections,
/// 4:2:0 planes and tiled planes admitted.
fn check_surface_vectors(vectors: &str) -> Result<[u32; 4], &'static str> {
    check_surface_vectors_policy(vectors, NO_MPC).map(|c| [c[0], c[1], c[2], c[3]])
}

/// As `check_surface_vectors` under `policy`; also counts the planes on two
/// MPC-combined DPPs, and of those the tiled, rotated, 4:2:0 and DCC ones.
fn check_surface_vectors_policy(vectors: &str, policy: Policy) -> Result<[u32; 9], &'static str> {
    let mut counts = [0u32; 9];
    for line in vectors.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut words = line.split_whitespace().peekable();
        let mut s = [0u32; 9];
        if !parse(&mut words, &mut s) {
            return Err("malformed surface SoC inputs");
        }
        let mut f = [0u32; 19];
        f[9..18].copy_from_slice(&s);
        let (soc, _) = inputs(&f);
        let mut modes = Vec::new();
        let mut rotations = [0u32; MAX_PLANES];
        let mut planes = 0;
        let (mut yuv, mut tiled) = (0, 0);
        while words.peek().is_some_and(|w| *w != "=" && *w != "!") {
            let mut t = [0u32; 10];
            if !parse(&mut words, &mut t) || !(1..=4).contains(&t[9]) {
                return Err("malformed surface stream");
            }
            let mut g = [0u32; 19];
            g[..9].copy_from_slice(&t[..9]);
            g[9..18].copy_from_slice(&s);
            let (_, mut mode) = inputs(&g);
            for slot in mode.planes.iter_mut().take(t[9] as usize) {
                let mut p = [0u32; 23];
                if !parse(&mut words, &mut p) {
                    return Err("malformed surface plane");
                }
                let plane = surface_plane(&p).ok_or("malformed surface plane fields")?;
                if let Some(r) = rotations.get_mut(planes) {
                    *r = p[13];
                }
                planes += 1;
                yuv += u32::from(plane.is_420());
                tiled += u32::from(plane.swizzle != Swizzle::Linear);
                *slot = Some(plane);
            }
            mode.pitch = mode.planes[0].map_or(0, |p| u32::from(p.pitch));
            mode.bytes_per_pixel = mode.planes[0].map_or(0, |p| u32::from(p.bytes_per_pixel));
            modes.push(mode);
        }
        let result = admit_all_with(&soc, &modes, policy);
        match words.next() {
            Some("=") => {
                let Ok(got) = &result else {
                    return Err("Linux-admitted surface configuration rejected");
                };
                let mut first = true;
                let mut index = 0;
                for plan in got {
                    for k in 0..MAX_PLANES {
                        let Some(view) = plane_view(plan, k) else {
                            break;
                        };
                        if !first && words.next() != Some("|") {
                            return Err("malformed surface plan separator");
                        }
                        first = false;
                        let mut want = [0u32; 62];
                        let mut want_s = [0u32; SURFACE_VALUES];
                        if !parse(&mut words, &mut want) || !parse(&mut words, &mut want_s) {
                            return Err("malformed surface plan");
                        }
                        for (i, (&g, &w)) in values(&view).iter().zip(want.iter()).enumerate() {
                            if g != w && !(TOLERATED.contains(&i) && g.abs_diff(w) == 1) {
                                return Err("surface plan value differs from Linux DML21");
                            }
                        }
                        let p = plan.plane(k).ok_or("surface plan lost a plane")?;
                        let rotation = rotations.get(index).copied().unwrap_or(0);
                        index += 1;
                        if surface_values(plan, k, &p, rotation) != want_s {
                            return Err("surface rq/chroma value differs from Linux DML21");
                        }
                        if !pipes_match(&mut words, &view) {
                            return Err("surface plan ODM pipes differ from Linux DML21");
                        }
                        if plan.pipes == 1 && p.dpps == 2 {
                            let q = plan.mode.plane_list().nth(k).unwrap_or_default();
                            counts[4] += 1;
                            counts[5] += u32::from(q.swizzle != Swizzle::Linear);
                            counts[6] += u32::from(q.vertical_scan);
                            counts[7] += u32::from(q.is_420());
                            counts[8] += u32::from(q.dcc);
                        }
                    }
                    if !plan.readmits() {
                        return Err("surface plan not reproducible");
                    }
                }
                if words.next().is_some() {
                    return Err("surface plan count");
                }
                counts[0] += 1;
                counts[2] += yuv;
                counts[3] += tiled;
            }
            Some("!") => {
                let (Some(name), Err(e)) = (words.next(), result) else {
                    return Err("rejected surface configuration admitted");
                };
                if name != "REJECT" && error_name(e) != name {
                    return Err("surface configuration rejected for a different reason");
                }
                counts[1] += 1;
            }
            _ => return Err("malformed surface vector kind"),
        }
    }
    Ok(counts)
}

/// GFX12 tiled (256B to 256KB 2D swizzles), DCC and 4:2:0 (NV12, P010)
/// planes, scanned horizontally and rotated: block and swath heights, the
/// DET split and chroma base, unbounded requesting, two-surface prefetch,
/// bursts, deep sleep and delivery, and DCC's DRAM overhead, as DML21
/// plans them.
fn dcn401_dml_matches_linux_dml21_surface_vectors() -> TestResult {
    match check_surface_vectors(SURFACE_VECTORS) {
        Ok([plans, rejects, yuv, tiled])
            if plans >= 400 && rejects >= 20 && yuv >= 150 && tiled >= 300 =>
        {
            TestResult::Pass
        }
        Ok(_) => TestResult::Fail("surface vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_surface_vectors
);

/// Shared with tests/dcn401_dml21/check.sh (harness_surfaces.c, RAISED,
/// MPC_AUTO).
const SURFACE_MPC_VECTORS: &str = include_str!("../tests/dcn401_dml21/surface_mpc_vectors.txt");

/// MPC combine of GFX12 tiled, DCC, rotated (scanned vertically) and 4:2:0
/// planes as DML21's auto factor chooses it, exactly as for linear RGB:
/// two DPPs when one would exceed the DPPCLK maximum or cannot take the
/// viewport's swath (DET, the tiled, 4:2:0 and vertical swath limits, the
/// line buffer), each with half the swath, luma and chroma; the DET split,
/// DCC overhead and mcache registers of each half.
fn dcn401_dml_matches_linux_dml21_surface_mpc_vectors() -> TestResult {
    match check_surface_vectors_policy(SURFACE_MPC_VECTORS, Policy::NATIVE) {
        Ok([plans, rejects, _, _, mpc, tiled, rotated, yuv, dcc])
            if plans >= 1000
                && rejects >= 50
                && mpc >= 250
                && tiled >= 200
                && rotated >= 100
                && yuv >= 100
                && dcc >= 100 =>
        {
            TestResult::Pass
        }
        Ok(_) => TestResult::Fail("surface MPC vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_surface_mpc_vectors
);

/// The mcache phase splits a DCC plane whose mcaches one pipe cannot place
/// over two MPC-combined DPPs whatever the factor (Linux overrides it), so
/// surface_vectors.txt's factor-1 plans hold such planes too.
fn dcn401_dml_mcache_phase_splits_dcc_planes() -> TestResult {
    match check_surface_vectors_policy(SURFACE_VECTORS, NO_MPC) {
        Ok(c) if c[4] >= 2 && c[8] == c[4] => TestResult::Pass,
        Ok(_) => TestResult::Fail("no mcache-split DCC plane in surface_vectors.txt"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_mcache_phase_splits_dcc_planes
);

/// Shared with tests/dcn401_dml21/check.sh (harness_planes.c, RAISED,
/// MPC_AUTO).
const MPC_VECTORS: &str = include_str!("../tests/dcn401_dml21/mpc_vectors.txt");

/// MPC combine as DML21's auto factor chooses it: a plane in ODM bypass
/// whose single DPP would exceed the DPPCLK maximum or whose swath the line
/// buffer cannot hold takes two DPPs (half the viewport each, DPPCLK and
/// delivery per DPP, both DLGs alike), alone, with overlays and beside
/// other streams; never on an ODM stream.
fn dcn401_dml_matches_linux_dml21_mpc_vectors() -> TestResult {
    match check_plane_vectors_policy(MPC_VECTORS, Policy::NATIVE) {
        Ok((plans, rejects, overlays, mpc))
            if plans >= 1200 && rejects >= 200 && overlays >= 60 && mpc >= 400 =>
        {
            TestResult::Pass
        }
        Ok(_) => TestResult::Fail("MPC vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_mpc_vectors
);

/// Shared with tests/dcn401_dml21/check.sh (harness_multi.c, RAISED, with
/// each line's PIXEL_BYTES, DSC and FMT420).
const ODM34_VECTORS: &str = include_str!("../tests/dcn401_dml21/odm34_vectors.txt");

/// ODM 3:1 and 4:1 as DML21's auto policy chooses them: pixel clocks past
/// two or three pipes' DISPCLK, DSC lines past two DSCs or with more than
/// eight slices (three pipes only for twelve, else four), alone and beside
/// other streams, at every depth; every further pipe's blank end as Linux
/// programs it, and a fifth pipe, a line not divisible by four or an uneven
/// DSC split rejected.
fn dcn401_dml_matches_linux_dml21_odm34_vectors() -> TestResult {
    match check_vectors_policy(ODM34_VECTORS, false, Prefix::Full, Policy::NATIVE) {
        Ok((plans, rejects, _, wide, _)) if plans >= 1000 && rejects >= 400 && wide >= 700 => {
            TestResult::Pass
        }
        Ok(_) => TestResult::Fail("ODM 3:1/4:1 vector file lost coverage"),
        Err(e) => TestResult::Fail(e),
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_matches_linux_dml21_odm34_vectors
);

/// Navi44's 8 and the GRE's 12 UMC channels against Navi48's 16, and a
/// CC_DC_PIPE_DIS-fused board: one admission, inputs from the board.
fn dcn401_dml_admits_every_rdna4_profile_and_fused_pipes() -> TestResult {
    use crate::amdgpu_rdna4::{self as rdna4, tests::Profile};
    let (base, hd) = reference_1080p();
    let mut sdpif = alloc::vec::Vec::new();
    for profile in Profile::ALL {
        let soc = Soc {
            umc_channels: profile.umc_channels(),
            ..base
        };
        let Ok(p) = admit(&soc, &hd) else {
            return TestResult::Fail("1080p60 rejected on an RDNA4 profile");
        };
        sdpif.push(p.arbiter.sdpif_request_rate_limit);
        if rdna4::mall_bytes(profile.chip(), profile.umc_channels()) == 0 {
            return TestResult::Fail("profile without MALL");
        }
    }
    // dcn401's SDPIF limit scales with the board's channels (96 floor):
    // Navi48 16, GRE 12, Navi44 8, in that order.
    if sdpif.windows(2).any(|w| w[0] < w[1]) {
        return TestResult::Fail("SDPIF limit not monotonic in UMC channels");
    }
    // Four single-pipe streams need four unfused pipes.
    let four = [hd, hd, hd, hd];
    if admit_all(&base, &four).is_err() {
        return TestResult::Fail("four 1080p streams on four pipes");
    }
    // Any one pipe fused, pipe 0 or a middle one included, leaves three
    // (the pool's count, wherever the fused instance is); two leave two.
    for fuses in [0x8, 0x1, 0x2] {
        rdna4::publish_pipe_pool(rdna4::PipePool::from_fuses(fuses));
        let fused = admit_all(&base, &four).err();
        let three = admit_all(&base, &four[..3]).is_ok();
        rdna4::publish_pipe_pool(rdna4::PipePool::FULL);
        if fused != Some(Error::Pipes) || !three {
            return TestResult::Fail("fused DCN pipe admitted or remaining pipes refused");
        }
    }
    rdna4::publish_pipe_pool(rdna4::PipePool::from_fuses(0x6));
    let fused = admit_all(&base, &four[..3]).err();
    let two = admit_all(&base, &four[..2]).is_ok();
    rdna4::publish_pipe_pool(rdna4::PipePool::FULL);
    if fused != Some(Error::Pipes) || !two {
        return TestResult::Fail("two fused DCN pipes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-dml",
    dcn401_dml_admits_every_rdna4_profile_and_fused_pipes
);

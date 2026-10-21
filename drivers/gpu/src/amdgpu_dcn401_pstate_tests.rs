use super::super::tests::{parse, pipes_match, plane_view, values, TOLERATED};
use super::*;
use core::fmt::Write as _;
use narf_kernel_test::{kernel_test_in, TestResult};

/// Shared with tests/dcn401_dml21/check.sh, which answers every line
/// again with Linux DML21 built on the host (harness_pstate.c).
const VECTORS: &str = include_str!("../tests/dcn401_dml21/pstate_vectors.txt");

struct Inputs {
    soc: Soc,
    uclk: UclkLevels,
    fams2: bool,
    modes: Vec<Mode>,
}

fn inputs<'a>(w: &mut impl Iterator<Item = &'a str>) -> Option<Inputs> {
    let mut s = [0u32; 9];
    parse(w, &mut s).then_some(())?;
    let mut levels = [0u32; 8];
    let count = s[8] as usize;
    if count > 8 {
        return None;
    }
    parse(w, &mut levels[..count]).then_some(())?;
    let mut f = [0u32; 2];
    parse(w, &mut f).then_some(())?;
    let uclk = UclkLevels::new(&levels[..count]).ok()?;
    let soc = Soc {
        dcfclk_khz: [s[0], s[1]],
        fclk_khz: [s[2], s[3]],
        uclk_khz: *uclk.levels().last()?,
        dispclk_max_khz: s[4],
        dppclk_max_khz: s[5],
        socclk_khz: s[6],
        umc_channels: s[7],
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let mut modes = Vec::new();
    for _ in 0..f[1] {
        let mut v = [0u32; 11];
        parse(w, &mut v).then_some(())?;
        let timing = Timing {
            pixel_clock_khz: v[0],
            h_active: v[1],
            h_total: v[2],
            h_front_porch: v[3],
            h_sync_width: v[4],
            v_active: v[5],
            v_total: v[6],
            v_front_porch: v[7],
            v_sync_width: v[8],
            h_sync_positive: true,
            v_sync_positive: true,
        };
        let mut mode = Mode::new(timing, 0, 0);
        mode.ycbcr420 = v[9] != 0;
        if !(1..=MAX_PLANES as u32).contains(&v[10]) {
            return None;
        }
        for slot in mode.planes.iter_mut().take(v[10] as usize) {
            let mut p = [0u32; 10];
            parse(w, &mut p).then_some(())?;
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
    Some(Inputs {
        soc,
        uclk,
        fams2: f[0] != 0,
        modes,
    })
}

fn method(v: u32) -> Option<Method> {
    Some(match v {
        0 => Method::Na,
        1 => Method::Vactive,
        2 => Method::Vblank,
        6 => Method::FwSvp,
        11 => Method::FwVactiveDrr,
        12 => Method::FwVblankDrr,
        13 => Method::FwSvpDrr,
        21 => Method::FwDrr,
        23 => Method::Alternate,
        _ => return None,
    })
}

fn fams2_values(s: &Fams2Stream) -> [u32; 15] {
    [
        u32::from(s.kind),
        u32::from(s.allow_start_otg_vline),
        u32::from(s.allow_end_otg_vline),
        u32::from(s.vblank_start),
        u32::from(s.vblank_end),
        s.otg_vline_time_ns,
        u32::from(s.scheduling_delay_otg_vlines),
        u32::from(s.contention_delay_otg_vlines),
        u32::from(s.vline_int_ack_delay_otg_vlines),
        u32::from(s.allow_to_target_delay_otg_vlines),
        u32::from(s.drr_keepout_otg_vline),
        u32::from(s.max_vtotal),
        u32::from(s.min_ttu_vblank_usable),
        u32::from(s.clamp_vtotal_min),
        u32::from(s.vactive_det_fill_delay_otg_vlines),
    ]
}

/// What check_line found wrong, for the console.
fn report(line: &str, why: &str) -> &'static str {
    let _ = writeln!(narf_console::Writer, "pstate vector: {why}\n  {line}");
    "pstate vector mismatch"
}

/// One vector line against the port. Returns whether Linux's plan was
/// matched exactly (as opposed to a pinned fallback the port documents).
fn check_line(line: &str) -> Result<bool, &'static str> {
    let mut w = line.split_whitespace().peekable();
    let Some(i) = inputs(&mut w) else {
        return Err(report(line, "inputs"));
    };
    let n = i.modes.len();
    let mut candidates = Vec::new();
    let got = admit_traced(&i.soc, &i.uclk, &i.modes, i.fams2, &mut candidates);
    match w.next() {
        Some("!") => {
            return match got {
                Err(_) | Ok(Pstate::Pinned(_)) => Ok(true),
                Ok(Pstate::Supported(_)) => Err(report(line, "Linux rejects")),
            };
        }
        Some("=") => {}
        _ => return Err(report(line, "separator")),
    }
    let mut head = [0u32; 5];
    let mut methods = [0u32; MAX_STREAMS];
    let mut clocks = [0u32; 6];
    if !parse(&mut w, &mut head) || !parse(&mut w, &mut methods[..n]) || !parse(&mut w, &mut clocks)
    {
        return Err(report(line, "header"));
    }
    let supported = head[0] != 0;
    // Plans, FAMS2 states and the candidate list follow.
    let mut planes: Vec<Vec<&str>> = Vec::new();
    let mut fams2: Vec<u32> = Vec::new();
    let mut chosen = 0i64;
    let mut linux: Vec<[Method; MAX_STREAMS]> = Vec::new();
    while let Some(tok) = w.next() {
        if tok != "|" {
            return Err(report(line, "tail"));
        }
        match w.peek().copied() {
            Some("FAMS2") => {
                w.next();
                while let Some(v) = w.peek().and_then(|t| t.parse::<u32>().ok()) {
                    fams2.push(v);
                    w.next();
                }
            }
            Some("CANDIDATES") => {
                w.next();
                chosen = w.next().and_then(|t| t.parse().ok()).unwrap_or(-1);
                for c in w.by_ref() {
                    let mut m = [Method::Na; MAX_STREAMS];
                    for (k, v) in c.split(',').enumerate() {
                        let Some(x) = v.parse().ok().and_then(method) else {
                            return Err(report(line, "candidate"));
                        };
                        if k < MAX_STREAMS {
                            m[k] = x;
                        }
                    }
                    linux.push(m);
                }
            }
            _ => {
                let mut p = Vec::new();
                while let Some(&t) = w.peek() {
                    if t == "|" {
                        break;
                    }
                    p.push(t);
                    w.next();
                }
                planes.push(p);
            }
        }
    }
    // PMO's candidate list is Linux's whenever the search starts.
    let ours: Vec<[Method; MAX_STREAMS]> = candidates.iter().map(|c| c.methods).collect();
    if ours != linux {
        return Err(report(line, "candidates"));
    }
    let methods: Vec<Method> = methods[..n].iter().filter_map(|&v| method(v)).collect();
    let firmware = methods.iter().any(|m| m.firmware());
    // A SubVP candidate tried before the chosen one: the port pins there.
    let svp_first = linux
        .iter()
        .take((chosen.max(0) as usize).min(linux.len()))
        .any(|c| {
            c[..n]
                .iter()
                .any(|m| matches!(m, Method::FwSvp | Method::FwSvpDrr))
        });
    let got = match got {
        Ok(p) => p,
        Err(_) => return Err(report(line, "port rejects")),
    };
    match got {
        Pstate::Pinned(Pinned::Firmware(_)) if !supported || firmware || svp_first => Ok(false),
        Pstate::Pinned(Pinned::Unsupported) if !supported => Ok(true),
        Pstate::Pinned(Pinned::Port) => Ok(false),
        Pstate::Supported(s) => {
            if !supported || firmware {
                return Err(report(line, "port supported"));
            }
            let level = head[3] as u8;
            let want_active = MinClocks {
                uclk_khz: clocks[0],
                fclk_khz: clocks[1],
                dcfclk_khz: clocks[2],
            };
            let want_idle = MinClocks {
                uclk_khz: clocks[3],
                fclk_khz: clocks[4],
                dcfclk_khz: clocks[5],
            };
            if s.methods[..n] != methods[..]
                || s.level != level
                || s.fclk_pstate != (head[1] != 0)
                || s.fams2_required
                || s.active != want_active
                || s.idle != want_idle
            {
                let _ = writeln!(
                    narf_console::Writer,
                    "pstate vector: port {:?} level {} fclk {} active {:?} idle {:?}",
                    &s.methods[..n],
                    s.level,
                    s.fclk_pstate,
                    s.active,
                    s.idle
                );
                return Err(report(line, "selection"));
            }
            let views: Vec<Plan> = s
                .plans
                .iter()
                .flat_map(|plan| (0..MAX_PLANES).map_while(|j| plane_view(plan, j)))
                .collect();
            if planes.len() != views.len() || fams2.len() != 15 * n {
                return Err(report(line, "plan count"));
            }
            for (j, view) in views.iter().enumerate() {
                let mut pw = planes[j].iter().copied().peekable();
                let mut want = [0u32; 62];
                if !parse(&mut pw, &mut want) {
                    return Err(report(line, "plan values"));
                }
                let have = values(view);
                for (f, (&a, &b)) in have.iter().zip(want.iter()).enumerate() {
                    let close = TOLERATED.contains(&f) && a.abs_diff(b) <= 1;
                    if a != b && !close {
                        let _ = writeln!(
                            narf_console::Writer,
                            "pstate vector: plane {j} field {f}: {a} != {b}"
                        );
                        return Err(report(line, "plan"));
                    }
                }
                if !pipes_match(&mut pw, view) || pw.next().is_some() {
                    return Err(report(line, "plan pipes"));
                }
            }
            for k in 0..n {
                let mut want = fams2_values(&s.fams2_streams[k]);
                let linux = &fams2[15 * k..15 * k + 15];
                // The sub-state union is the legacy one only for vactive.
                if want[0] != 2 {
                    want[14] = linux[14];
                }
                if want[..] != linux[..] {
                    return Err(report(line, "FAMS2 stream"));
                }
            }
            Ok(true)
        }
        _ => Err(report(line, "pinned")),
    }
}

fn dcn401_pstate_matches_linux_dml21_vectors() -> TestResult {
    let (mut exact, mut pinned) = (0u32, 0u32);
    for line in VECTORS.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        match check_line(line) {
            Ok(true) => exact += 1,
            Ok(false) => pinned += 1,
            Err(e) => return TestResult::Fail(e),
        }
    }
    let _ = writeln!(
        narf_console::Writer,
        "pstate vectors: {exact} as Linux, {pinned} pinned for a firmware method"
    );
    // The vectors cover vactive, vblank, firmware-only and unsupported
    // configurations.
    if exact < 100 || pinned == 0 {
        return TestResult::Fail("vector coverage");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-pstate",
    dcn401_pstate_matches_linux_dml21_vectors
);

/// pmo_dcn4_fams2_initialize's expanded strategy lists, as
/// harness_pstate.c --strategies prints them.
const STRATEGIES: &str = include_str!("../tests/dcn401_dml21/pstate_strategies.txt");

fn dcn401_pstate_strategy_lists_match_linux() -> TestResult {
    let mut lists = 0;
    for line in STRATEGIES.lines() {
        let mut w = line.split_whitespace();
        let Some(n) = w.next().and_then(|t| t.parse::<usize>().ok()) else {
            return TestResult::Fail("strategy list header");
        };
        let ours = strategies(n);
        let mut count = 0;
        for (i, tok) in w.enumerate() {
            let (methods, inc) = match tok.strip_suffix('+') {
                Some(m) => (m, true),
                None => (tok, false),
            };
            let Some(st) = ours.get(i) else {
                return TestResult::Fail("strategy list too short");
            };
            if st.allow_state_increase != inc {
                return TestResult::Fail("allow_state_increase");
            }
            for (k, v) in methods.split(',').enumerate() {
                if v.parse().ok().and_then(method) != Some(st.methods[k]) {
                    return TestResult::Fail("strategy methods");
                }
            }
            if st.methods[n..].iter().any(|&m| m != Method::Na) {
                return TestResult::Fail("strategy beyond its streams");
            }
            count += 1;
        }
        if count != ours.len() {
            return TestResult::Fail("strategy list length");
        }
        lists += 1;
    }
    if lists != MAX_STREAMS {
        return TestResult::Fail("strategy list count");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-pstate",
    dcn401_pstate_strategy_lists_match_linux
);

/// A Navi48 board: 16 UMC channels and UCLK levels 96/456/772/1258 MHz.
pub(crate) fn board() -> (Soc, UclkLevels) {
    let uclk = UclkLevels::new(&[96_000, 456_000, 772_000, 1_258_000]).unwrap();
    let soc = Soc {
        umc_channels: 16,
        uclk_khz: 1_258_000,
        fclk_khz: [300_000, 2_500_000],
        dcfclk_khz: [200_000, 1_564_000],
        socclk_khz: 300_000,
        dispclk_max_khz: 2_000_000,
        dppclk_max_khz: 2_000_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    (soc, uclk)
}
fn timing(t: [u32; 9]) -> Mode {
    Mode::new(
        Timing {
            pixel_clock_khz: t[0],
            h_active: t[1],
            h_total: t[2],
            h_front_porch: t[3],
            h_sync_width: t[4],
            v_active: t[5],
            v_total: t[6],
            v_front_porch: t[7],
            v_sync_width: t[8],
            h_sync_positive: true,
            v_sync_positive: true,
        },
        t[1],
        4,
    )
}
pub(crate) fn hd() -> Mode {
    timing([148_500, 1920, 2200, 88, 44, 1080, 1125, 4, 5])
}
pub(crate) fn uhd() -> Mode {
    timing([533_250, 3840, 4000, 48, 32, 2160, 2222, 3, 5])
}

fn dcn401_pstate_strategies_follow_linux_policy() -> TestResult {
    let (soc, uclk) = board();
    // 1080p60: vactive at the lowest UCLK, with the stutter blank kept.
    let Ok(Pstate::Supported(s)) = admit(&soc, &uclk, &[hd()], true) else {
        return TestResult::Fail("1080p60 vactive");
    };
    let p = s.plans[0];
    if s.methods[0] != Method::Vactive
        || s.level != 0
        || s.active.uclk_khz != 96_000
        || p.clocks.uclk_khz != 96_000
        || p.soc.uclk_khz != 1_258_000
        || p.stutter_reserved_us != 54
        || p.pstate.map(|x| x.method) != Some(Method::Vactive)
        || s.fams2_required
        || s.fams2_streams[0].kind != 2
    {
        return TestResult::Fail("1080p60 vactive plan");
    }
    // A P-state plan is admitted again through the same search, and only
    // as itself.
    if !p.readmits() {
        return TestResult::Fail("P-state plan does not re-admit");
    }
    let mut edited = p;
    edited.dlg.dst_y_prefetch += 1;
    if edited.readmits() {
        return TestResult::Fail("edited P-state plan re-admitted");
    }
    // The pinned plan stays the native one, with no P-state record.
    match admit_native(&soc, &[hd()]) {
        Ok(native) if native[0].pstate.is_none() && native[0].clocks.uclk_khz == 1_258_000 => {}
        _ => return TestResult::Fail("native plan changed"),
    }
    // 4K60 cannot hide the blackout in vactive: vblank (400 us reserved)
    // without FAMS2 firmware; with it Linux tries SubVP first, which the
    // port leaves pinned.
    match admit(&soc, &uclk, &[uhd()], false) {
        Ok(Pstate::Supported(s))
            if s.methods[0] == Method::Vblank && s.plans[0].stutter_reserved_us == 400 => {}
        _ => return TestResult::Fail("4K60 vblank"),
    }
    if admit(&soc, &uclk, &[uhd()], true) != Ok(Pstate::Pinned(Pinned::Firmware(Method::FwSvp))) {
        return TestResult::Fail("4K60 SubVP not pinned");
    }
    // Two identical 4K60 streams switch together in their shared vblank.
    match admit(&soc, &uclk, &[uhd(), uhd()], false) {
        Ok(Pstate::Supported(s)) if s.methods[..2] == [Method::Vblank; 2] => {}
        _ => return TestResult::Fail("synchronized vblank pair"),
    }
    // 1080p60 beside 4K60: no hardware strategy schedules both.
    if admit(&soc, &uclk, &[hd(), uhd()], false) != Ok(Pstate::Pinned(Pinned::Unsupported)) {
        return TestResult::Fail("unschedulable pair");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-pstate",
    dcn401_pstate_strategies_follow_linux_policy
);

fn dcn401_pstate_refuses_what_the_port_does_not_plan() -> TestResult {
    let (soc, uclk) = board();
    // The UCLK table must end at the pinned level, ascend and be bounded.
    if admit(
        &soc,
        &UclkLevels::new(&[96_000, 456_000]).unwrap(),
        &[hd()],
        false,
    ) != Err(Error::Invalid)
        || UclkLevels::new(&[456_000, 96_000]).is_ok()
        || UclkLevels::new(&[]).is_ok()
        || UclkLevels::new(&[1; 9]).is_ok()
    {
        return TestResult::Fail("UCLK table validation");
    }
    // A DCC plane stays on the pinned policy (its meta rows would count in
    // the blackout's bytes).
    let mut dcc = hd();
    dcc.planes[0] = Some(Plane {
        swizzle: Swizzle::S64K2D,
        dcc: true,
        ..Plane::full(&dcc.timing, 1920, 4)
    });
    if admit_native(&soc, &[dcc]).is_ok()
        && admit(&soc, &uclk, &[dcc], false) != Ok(Pstate::Pinned(Pinned::Port))
    {
        return TestResult::Fail("DCC plane not pinned");
    }
    // A mode the pinned policy refuses is refused here too.
    let mut short = hd();
    short.timing.v_total = 1083;
    short.timing.v_front_porch = 1;
    short.timing.v_sync_width = 1;
    if admit(&soc, &uclk, &[short], false).is_ok() {
        return TestResult::Fail("unadmitted mode searched");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-pstate",
    dcn401_pstate_refuses_what_the_port_does_not_plan
);

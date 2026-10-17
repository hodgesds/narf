use super::*;
use crate::amdgpu_navi22_modeset_model::{self as m, d1, d2, d3, Bench, DpSink, Vram, MARK};
use alloc::{vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

fn soc() -> dml30::Soc {
    dml30::Soc {
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
fn fix(edid: &mut [u8]) {
    for block in edid.chunks_exact_mut(128) {
        let sum = block[..127].iter().fold(0u8, |a, &b| a.wrapping_add(b));
        block[127] = 0u8.wrapping_sub(sum);
    }
}
/// A 4K60 (594 MHz) preferred DTD, then 1080p60 in the CTA block, with an
/// HDMI VSDB declaring `max_tmds_5mhz` (0 omits the field).
fn sink(hdmi: bool, max_tmds_5mhz: u8) -> Sink {
    let mut e = vec![0u8; 256];
    e[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
    e[18] = 1;
    e[19] = 4;
    // 3840x2160@60, 594 MHz: 4400x2250, sync 176/88, 8/10.
    e[54..72].copy_from_slice(&[
        0x08, 0xe8, 0x00, 0x30, 0xf2, 0x70, 0x5a, 0x80, 0xb0, 0x58, 0x8a, 0x00, 0, 0, 0, 0, 0, 0x1e,
    ]);
    e[126] = 1;
    let ext = &mut e[128..];
    ext[0] = 2;
    ext[1] = 3;
    let mut p = 4;
    if hdmi {
        let len = if max_tmds_5mhz != 0 { 7 } else { 5 };
        ext[p] = 3 << 5 | len;
        ext[p + 1..p + 4].copy_from_slice(&[0x03, 0x0c, 0x00]);
        ext[p + 4] = 0x10;
        if max_tmds_5mhz != 0 {
            ext[p + 7] = max_tmds_5mhz;
        }
        p += 1 + len as usize;
    }
    ext[2] = p as u8;
    // 1080p60 DTD.
    ext[p..p + 18].copy_from_slice(&[
        0x02, 0x3a, 0x80, 0x18, 0x71, 0x38, 0x2d, 0x40, 0x58, 0x2c, 0x45, 0x00, 0, 0, 0, 0, 0, 0x1e,
    ]);
    fix(&mut e);
    Sink {
        edid: e,
        preferred: None,
        hdmi,
        dpcd: None,
    }
}

fn navi22_modeset_selects_first_unscrambled_tmds_mode() -> TestResult {
    // 4K60 needs scrambling; the first mode that fits is 1080p60.
    let Ok((timing, avi, plan)) = select(&sink(true, 0), &soc(), 3_650_000) else {
        return TestResult::Fail("no HDMI mode");
    };
    if timing.h_active != 1920 || timing.pixel_clock_khz != 148_500 {
        return TestResult::Fail("mode choice");
    }
    // AVI InfoFrame v2, VIC 16 (1080p60), RGB, checksum over HB0..2 + PB1..13.
    let Some(avi) = avi else {
        return TestResult::Fail("HDMI sink without AVI");
    };
    let sum = avi[..3]
        .iter()
        .chain(&avi[4..18])
        .fold(0u8, |a, &b| a.wrapping_add(b));
    if avi[..3] != [0x82, 2, 13] || avi[8] != 16 || sum != 0 {
        return TestResult::Fail("AVI InfoFrame");
    }
    if plan.registers.dlg.min_dst_y_next_start != (1125 - 4) * 4 || plan.prefetch.v_startup == 0 {
        return TestResult::Fail("DML30 plan for the chosen mode");
    }
    // A sink without the HDMI VSDB is DVI: no InfoFrame.
    if select(&sink(false, 0), &soc(), 3_650_000).map(|r| r.1.is_none()) != Ok(true) {
        return TestResult::Fail("DVI sink got an InfoFrame");
    }
    // The VSDB ceiling (here 100 MHz) is honoured.
    if select(&sink(true, 20), &soc(), 3_650_000).err() != Some(Error::NoMode) {
        return TestResult::Fail("VSDB TMDS ceiling ignored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_selects_first_unscrambled_tmds_mode
);

fn navi22_modeset_test_pattern_draws_eight_bars() -> TestResult {
    let mut row = [0u32; 16];
    test_pattern(0, &mut row);
    if row[0] != 0x00ff_ffff || row[1] != 0x00ff_ffff || row[15] != 0 || row[2] != 0x00ff_ff00 {
        return TestResult::Fail("colour bars");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_test_pattern_draws_eight_bars
);

// ── End-to-end register model ─────────────────────────────────────────

const BOARD: Board = Board {
    crystal_khz: 100_000,
    channels: 12,
    channel_width_bytes: 2,
};
const VRAM_BYTES: usize = 2 << 20;

fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn pipeline(bench: &Bench, connector: Connector, route: Route) -> Pipeline {
    // SAFETY: the bench's model owns every register the pipeline reaches.
    unsafe { Pipeline::new(&bench.gpu, Cap::bootstrap(), connector, route) }.unwrap()
}
fn route(pipe: u8, stream: u8, signal: Signal, pll: u8) -> Route {
    Route {
        pipe,
        stream,
        clock: match signal {
            Signal::Hdmi => ClockSource::Pll(pll),
            Signal::DisplayPort => ClockSource::DpDto,
        },
    }
}
async fn enable_with<A: Aux + Send>(
    p: &mut Pipeline,
    vram: &Vram,
    tables: &Tables<'_>,
    sink: &Sink,
    aux: &mut A,
) -> Result<Output, Error> {
    let links = [p.connector()];
    // SAFETY: model-backed owners and a heap-backed pool.
    unsafe {
        p.enable(
            core::future::ready(Ok(())),
            &vram.pool,
            tables,
            BOARD,
            &links,
            sink,
            aux,
            test_pattern,
        )
        .await
    }
}

type Pred<'a> = (&'static str, &'a dyn Fn(&m::Write) -> bool);
/// Every milestone, in order, each strictly after the previous one.
fn in_order(log: &[m::Write], from: usize, steps: &[Pred<'_>]) -> Result<usize, &'static str> {
    let mut at = from;
    for (name, pred) in steps {
        match log[at..].iter().position(pred) {
            Some(i) => at += i + 1,
            None => return Err(name),
        }
    }
    Ok(at)
}
fn is(dword: u32) -> impl Fn(&m::Write) -> bool {
    move |w: &m::Write| w.dword == dword
}
fn set(dword: u32, mask: u32) -> impl Fn(&m::Write) -> bool {
    move |w: &m::Write| w.dword == dword && w.value & mask != 0
}
fn clear(dword: u32, mask: u32) -> impl Fn(&m::Write) -> bool {
    move |w: &m::Write| w.dword == dword && w.value & mask == 0
}
fn table(slot: u32, phy: Option<u8>, action: Option<u8>) -> impl Fn(&m::Write) -> bool {
    move |w: &m::Write| {
        w.dword == MARK + 16 * slot
            && phy.is_none_or(|p| w.value & 0xff == u32::from(p))
            && action.is_none_or(|a| (w.value >> 8) & 0xff == u32::from(a))
    }
}
fn dal(message: u32) -> impl Fn(&m::Write) -> bool {
    move |w: &m::Write| w.dword == m::MP1 + 0x28a && w.value == message
}

/// Linux's global order for one HDMI stream: dcn30_init_hw, prepare
/// bandwidth, dcn20_enable_stream_timing, link_set_dpms_on, then the front
/// end under the OTG lock.
fn hdmi_enable_order(log: &[m::Write], r: Route, tx: u8) -> Result<usize, &'static str> {
    let (p, f, t) = (u32::from(r.pipe), u32::from(r.stream), u32::from(tx));
    let ClockSource::Pll(pll) = r.clock else {
        return Err("route clock");
    };
    let resync = [0x40, 0x41, 0x42, 0x43, 0x4c, 0x7e][usize::from(pll)];
    let plane = |w: &m::Write| p == 5 || w.dword == d2(0x80 + 2 * (2 * p + 1));
    in_order(
        log,
        0,
        &[
            ("dccg2_init", &is(d1(0x7b))),
            ("bios_golden_init", &table(m::SLOT_POWER_GATING, None, None)),
            ("disable_vga", &is(d1(0x0c))),
            ("enc3_hw_init TMDS_CTL0", &set(d2(0x20de + t * 0x100), 1)),
            ("enable_power_gating_plane", &is(d2(0x80))),
            ("dal start", &dal(2)),
            ("update_clocks", &dal(0xe)),
            ("dentist", &is(d1(0x64))),
            ("program_watermarks", &is(d2(0x509))),
            ("enable_optc_clock input", &set(d2(0x1acf + p * 0x10), 2)),
            ("enable_optc_clock otg", &set(d2(0x1b86 + p * 0x80), 1)),
            (
                "program_pix_clk SetPixelClock",
                &table(m::SLOT_PIXEL_CLOCK, None, None),
            ),
            ("pixel_clk_resync", &is(d1(resync))),
            ("program_timing", &is(d2(0x1b2a + p * 0x80))),
            ("blank_pixel_data(true)", &set(d2(0x1854 + p * 0x5a), 1)),
            ("enable_crtc", &set(d2(0x1b41 + p * 0x80), 1)),
            ("dig_connect_to_otg", &is(d2(0x208b + f * 0x100))),
            ("link_enc setup HDMI", &|w: &m::Write| {
                w.dword == d2(0x20b0 + t * 0x100) && (w.value >> 16) & 7 == 3
            }),
            ("STREAM_SETUP", &|w: &m::Write| {
                w.dword == MARK + 16 * m::SLOT_STREAM_SETUP && w.value & 0xff == f
            }),
            ("hdmi_set_stream_attribute", &is(d2(0x2093 + f * 0x100))),
            ("AVI InfoFrame", &is(d2(0x2069 + f * 0x100))),
            (
                "enable_tmds_output",
                &table(m::SLOT_TRANSMITTER, Some(tx), Some(1)),
            ),
            (
                "connect_dig_be_to_fe",
                &set(d2(0x20b0 + t * 0x100), 1 << (8 + f)),
            ),
            ("AVMUTE released", &clear(d2(0x209d + f * 0x100), 1)),
            ("optc3_lock", &set(d2(0x1b8b + p * 0x80), 1)),
            ("blank_pixel_data(false)", &|w: &m::Write| {
                w.dword == d2(0x1854 + p * 0x5a) && w.value == 0
            }),
            ("power_on_plane", &plane),
            ("hubp_clk_cntl", &set(d2(0x5f4 + p * 0xdc), 1)),
            ("update_dpp_dto", &is(d1(0x99 + p))),
            ("dpp", &is(d2(0xcc5 + p * 0x16b))),
            ("mpcc", &is(d3(p * 0x20))),
            ("hubp surface", &is(d2(0x60a + p * 0xdc))),
            ("hubp set_blank(false)", &clear(d2(0x5f3 + p * 0xdc), 1)),
            ("optc1_unlock", &|w: &m::Write| {
                w.dword == d2(0x1b8b + p * 0x80) && w.value == 0
            }),
        ],
    )
}
fn hdmi_disable_order(
    log: &[m::Write],
    from: usize,
    r: Route,
    tx: u8,
) -> Result<usize, &'static str> {
    let (p, f, t) = (u32::from(r.pipe), u32::from(r.stream), u32::from(tx));
    in_order(
        log,
        from,
        &[
            ("blank_pixel_data(true)", &set(d2(0x1854 + p * 0x5a), 1)),
            ("mpcc removal", &|w: &m::Write| {
                w.dword == d3(0x580 + p * 4) && w.value & 0xf == 0xf
            }),
            ("hubp blank", &set(d2(0x5f3 + p * 0xdc), 1)),
            ("set_avmute(true)", &set(d2(0x209d + f * 0x100), 1)),
            ("stop_hdmi_info_packets", &|w: &m::Write| {
                w.dword == d2(0x209a + f * 0x100) && w.value == 0
            }),
            (
                "connect_dig_be_to_fe(false)",
                &clear(d2(0x20b0 + t * 0x100), 1 << (8 + f)),
            ),
            (
                "disable_output",
                &table(m::SLOT_TRANSMITTER, Some(tx), Some(0)),
            ),
            ("disable_crtc", &clear(d2(0x1b41 + p * 0x80), 1)),
            ("enable_optc_clock(false)", &clear(d2(0x1b86 + p * 0x80), 1)),
        ],
    )
}

fn navi22_modeset_resources_follow_the_dcn30_pool() -> TestResult {
    let hdmi = m::connector(Signal::Hdmi, 3, 3);
    let dp = |t| m::connector(Signal::DisplayPort, t, t);
    let mut pool = Resources::new();
    // First stream: pipe 0, its preferred engine DIG FE 3, PHY PLL0.
    if pool.acquire(&hdmi) != Ok(route(0, 3, Signal::Hdmi, 0)) {
        return TestResult::Fail("first HDMI stream");
    }
    // DP on transmitter 3 again: preferred FE taken, so the *last* free
    // frontend (5), and the DP DTO instead of a PLL.
    if pool.acquire(&dp(3)) != Ok(route(1, 5, Signal::DisplayPort, 0)) {
        return TestResult::Fail("fallback stream encoder");
    }
    let second_hdmi = pool.acquire(&hdmi);
    if second_hdmi != Ok(route(2, 4, Signal::Hdmi, 1)) {
        return TestResult::Fail("second PHY PLL");
    }
    for t in [0, 1, 2] {
        if pool.acquire(&dp(t)).map(|r| r.stream) != Ok(t) {
            return TestResult::Fail("preferred engines");
        }
    }
    if pool.acquire(&dp(0)) != Err(Error::Busy) {
        return TestResult::Fail("seventh stream admitted");
    }
    pool.release(second_hdmi.unwrap());
    if pool.acquire(&hdmi) != Ok(route(2, 4, Signal::Hdmi, 1)) {
        return TestResult::Fail("released resources reused");
    }
    // choose: HDMI first, else the first DP sink with EDID and DPCD.
    let report = |c: Connector, d: Detection| Report {
        connector: c,
        detection: d,
    };
    let dp_sink = m::sink(Signal::DisplayPort, Some(m::dpcd(0x12)));
    let mut no_dpcd = dp_sink.clone();
    no_dpcd.dpcd = None;
    let reports = [
        report(dp(0), Detection::Connected(no_dpcd)),
        report(dp(1), Detection::Connected(dp_sink.clone())),
        report(hdmi, Detection::Disconnected),
    ];
    if choose(&reports).map(|(c, _)| c) != Some(dp(1)) {
        return TestResult::Fail("DP sink choice");
    }
    let mut with_hdmi = reports.to_vec();
    with_hdmi[2].detection = Detection::Connected(m::sink(Signal::Hdmi, None));
    if choose(&with_hdmi).map(|(c, _)| c) != Some(hdmi) {
        return TestResult::Fail("HDMI preference");
    }
    // DP DTO: 25.175 MHz is a /1.001 video rate; 148.5 MHz is not in range.
    if dp_dto(25_175) != (25_200 * 1000, 730_000 * 1001)
        || dp_dto(148_500) != (148_500_000, 730_000_000)
    {
        return TestResult::Fail("dcn3_program_pix_clk DTO");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_resources_follow_the_dcn30_pool
);

fn navi22_modeset_hdmi_end_to_end_follows_linux_order() -> TestResult {
    for revision in [6, 7] {
        let bench = Bench::new();
        bench.set(m::MP1 + 0x274, 1);
        let vram = Vram::new(VRAM_BYTES);
        let image = m::vbios(revision);
        let tables = Tables::new(&image).unwrap();
        let connector = m::connector(Signal::Hdmi, 3, 3);
        let r = Resources::new().acquire(&connector).unwrap();
        let mut p = pipeline(&bench, connector, r);
        // The v1.7 pass also carries LPCM audio.
        let audio = revision == 7;
        let sink = m::sink_audio(Signal::Hdmi, None, audio);
        let output = match run(enable_with(&mut p, &vram, &tables, &sink, &mut NoAux)) {
            Ok(o) => o,
            Err(_) => return TestResult::Fail("HDMI enable"),
        };
        if p.state() != State::At(Step::Running)
            || output.timing.h_active != 640
            || output.inherited != Inherited::default()
            || output.link.is_some()
        {
            return TestResult::Fail("HDMI output");
        }
        let log = bench.log();
        let enabled = match hdmi_enable_order(&log, r, 3) {
            Ok(at) => at,
            Err(name) => return TestResult::Fail(name),
        };
        // Audio starts once pixels flow: the PME wake (DALSMC 0x11), then
        // AFMT audio samples on this frontend.
        let afmt = d2(0x2082 + u32::from(r.stream) * 0x100);
        let started = in_order(
            &log,
            0,
            &[
                ("unlock before audio", &|w: &m::Write| {
                    w.dword == d2(0x1b8b) && w.value == 0
                }),
                ("PME wake", &dal(0x11)),
                ("audio samples", &set(afmt, 1)),
            ],
        );
        if started.is_ok() != audio {
            return TestResult::Fail("audio start");
        }
        // Live: flushes go through HDP, underflow polling finds none.
        if p.flush().is_err() || p.check_underflow() != Ok(None) {
            return TestResult::Fail("live pipeline");
        }
        // SetPixelClock carried 25.175 MHz on PLL0 for OTG 0, and the
        // transmitter table HDMI mode on four lanes.
        let marker = |slot: u32, i: u32| bench.get(MARK + 16 * slot + i);
        // The DTD's 2517 x 10 kHz, in 100 Hz units.
        if marker(m::SLOT_PIXEL_CLOCK, 0) != output.timing.pixel_clock_khz * 10
            || output.timing.pixel_clock_khz != 25_170
            || marker(m::SLOT_PIXEL_CLOCK, 1) & 0xff != 20
            || marker(m::SLOT_TRANSMITTER, 0) >> 16 != 3 | 4 << 8
        {
            return TestResult::Fail("VBIOS parameter blocks");
        }
        if run(p.disable(&tables, &mut NoAux)).is_err() || p.state() != State::At(Step::Stopped) {
            return TestResult::Fail("HDMI disable");
        }
        let log = bench.log();
        if let Err(name) = hdmi_disable_order(&log, enabled, r, 3) {
            return TestResult::Fail(name);
        }
        // Audio is muted before the stream blanks.
        if audio
            && in_order(
                &log,
                enabled,
                &[
                    ("audio muted", &clear(afmt, 1)),
                    ("then blank", &set(d2(0x1854), 1)),
                ],
            )
            .is_err()
        {
            return TestResult::Fail("audio stop order");
        }
        // The PHY PLL is never "powered down" with a zero clock.
        if log[enabled..]
            .iter()
            .any(|w| w.dword == MARK + 16 * m::SLOT_PIXEL_CLOCK)
        {
            return TestResult::Fail("SetPixelClock(0) on disable");
        }
        // The scanout stays excluded from reuse after the stop.
        if p.scanout().is_none_or(|s| s.reusable_for_test()) {
            return TestResult::Fail("scanout released");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_hdmi_end_to_end_follows_linux_order
);

fn dp_order(log: &[m::Write], r: Route, tx: u8, rate: u8) -> Result<usize, &'static str> {
    let (p, f, t) = (u32::from(r.pipe), u32::from(r.stream), u32::from(tx));
    in_order(
        log,
        0,
        &[
            ("dccg2_init", &is(d1(0x7b))),
            ("enc3_hw_init", &set(d2(0x20de + t * 0x100), 1)),
            ("update_clocks", &dal(0xe)),
            ("program_watermarks", &is(d2(0x509))),
            ("enable_optc_clock", &set(d2(0x1b86 + p * 0x80), 1)),
            ("DP_DTO phase", &is(d1(0x81 + 4 * p))),
            ("DP_DTO modulo", &is(d1(0x82 + 4 * p))),
            ("DP_DTO enable", &set(d1(0x80 + 4 * p), 0x10)),
            ("program_timing", &is(d2(0x1b2a + p * 0x80))),
            ("enable_crtc", &set(d2(0x1b41 + p * 0x80), 1)),
            ("dig_connect_to_otg", &is(d2(0x208b + f * 0x100))),
            ("link_enc setup DP", &|w: &m::Write| {
                w.dword == d2(0x20b0 + t * 0x100) && (w.value >> 16) & 7 == 0
            }),
            ("MSA", &is(d2(0x214c + f * 0x100))),
            ("update_dp_info_packets", &is(d2(0x212b + f * 0x100))),
            ("notify_link_rate_change", &|w: &m::Write| {
                w.dword == m::MP1 + 0x28a && w.value == 9
            }),
            (
                "connect_dig_be_to_fe",
                &set(d2(0x20b0 + t * 0x100), 1 << (8 + f)),
            ),
            ("configure_encoder", &is(d2(0x210b + t * 0x100))),
            (
                "enable_dp_output",
                &table(m::SLOT_TRANSMITTER, Some(tx), Some(1)),
            ),
            ("DPCD power D0", &|w: &m::Write| {
                w.dword == m::AUX_WRITE | 0x600
            }),
            ("DPCD link rate", &|w: &m::Write| {
                w.dword == m::AUX_WRITE | 0x100 && w.value == u32::from(rate)
            }),
            ("TPS1", &|w: &m::Write| {
                w.dword == d2(0x2118 + t * 0x100) && w.value == 0
            }),
            (
                "lane settings",
                &table(m::SLOT_TRANSMITTER, Some(tx), Some(11)),
            ),
            ("lane status", &|w: &m::Write| {
                w.dword == m::AUX_READ | 0x202
            }),
            // TPS3 whenever the sink has it (decide_eq_training_pattern),
            // whatever the link rate.
            ("TPS3", &|w: &m::Write| {
                w.dword == d2(0x2118 + t * 0x100) && w.value == 2
            }),
            ("video idle", &set(d2(0x2113 + t * 0x100), 1 << 28)),
            ("training complete", &set(d2(0x2108 + t * 0x100), 1 << 4)),
            ("M/N", &is(d2(0x2112 + f * 0x100))),
            ("DIG_START pulse", &set(d2(0x208b + f * 0x100), 1 << 10)),
            ("DP_VID_STREAM_ENABLE", &set(d2(0x210c + f * 0x100), 1)),
            ("optc3_lock", &set(d2(0x1b8b + p * 0x80), 1)),
            ("hubp set_blank(false)", &clear(d2(0x5f3 + p * 0xdc), 1)),
            ("optc1_unlock", &|w: &m::Write| {
                w.dword == d2(0x1b8b + p * 0x80) && w.value == 0
            }),
        ],
    )
}
fn dp_disable_order(
    log: &[m::Write],
    from: usize,
    r: Route,
    tx: u8,
) -> Result<usize, &'static str> {
    let (p, f, t) = (u32::from(r.pipe), u32::from(r.stream), u32::from(tx));
    in_order(
        log,
        from,
        &[
            ("blank_pixel_data(true)", &set(d2(0x1854 + p * 0x5a), 1)),
            ("hubp blank", &set(d2(0x5f3 + p * 0xdc), 1)),
            ("dp_blank", &clear(d2(0x210c + f * 0x100), 1)),
            ("DPCD D3", &|w: &m::Write| {
                w.dword == m::AUX_WRITE | 0x600 && w.value == 2
            }),
            (
                "disable_output",
                &table(m::SLOT_TRANSMITTER, Some(tx), Some(0)),
            ),
            ("link_encoder_disable", &|w: &m::Write| {
                w.dword == d2(0x2118 + t * 0x100) && w.value == 0
            }),
            ("stop_dp_info_packets", &|w: &m::Write| {
                w.dword == d2(0x212b + f * 0x100) && w.value == 0
            }),
            (
                "connect_dig_be_to_fe(false)",
                &clear(d2(0x20b0 + t * 0x100), 1 << (8 + f)),
            ),
            ("disable_crtc", &clear(d2(0x1b41 + p * 0x80), 1)),
        ],
    )
}

/// Detection's destructive verification (with Linux's CR fallback: the rate
/// first) bounds the link; the stream then trains the least link that
/// carries its 640x480 mode (RBR x1, `decide_dp_link_settings`).
fn navi22_modeset_dp_sst_verifies_falls_back_and_follows_linux_order() -> TestResult {
    for (fail, revision, verified) in [(vec![], 0x12, 20), (vec![20], 0x14, 10)] {
        let want = 6;
        let bench = Bench::new();
        bench.set(m::MP1 + 0x274, 1);
        let vram = Vram::new(VRAM_BYTES);
        let image = m::vbios(7);
        let tables = Tables::new(&image).unwrap();
        let connector = m::connector(Signal::DisplayPort, 1, 1);
        let r = Resources::new().acquire(&connector).unwrap();
        let mut p = pipeline(&bench, connector, r);
        let sink = m::sink(Signal::DisplayPort, Some(m::dpcd(revision)));
        let mut aux = DpSink::new(bench.model.clone());
        aux.fail_rates = fail.clone();
        aux.caps = m::dpcd(revision);
        // DPCD 1.4 with extended caps: SST split SDP and VSC colorimetry.
        if revision == 0x14 {
            aux.caps[14] = 0x80;
        }
        aux.feature = 0x0a;
        let output = match run(enable_with(&mut p, &vram, &tables, &sink, &mut aux)) {
            Ok(o) => o,
            Err(_) => return TestResult::Fail("DP enable"),
        };
        if output.link
            != Some(DpLink {
                rate: want,
                lanes: 1,
            })
            || p.link_cap()
                != Some(DpLink {
                    rate: verified,
                    lanes: 4,
                })
        {
            return TestResult::Fail("verified or trained link");
        }
        let log = bench.log();
        let enabled = match dp_order(&log, r, 1, want) {
            Ok(at) => at,
            Err(name) => return TestResult::Fail(name),
        };
        // M/N: 0x8000 x 25175 / (rate x 27000).
        let m_vid = 0x8000 * output.timing.pixel_clock_khz / (u32::from(want) * 27_000);
        let f = u32::from(r.stream);
        if bench.get(d2(0x2112 + f * 0x100)) != m_vid
            || bench.get(d2(0x2111 + f * 0x100)) != 0x8000
            || bench.get(d2(0x210b + 0x100)) != 0
        {
            return TestResult::Fail("M/N or lane count");
        }
        // VSC for colorimetry only on the DPCD 1.4 sink with the cap.
        let gsp0 = bench.get(d2(0x212b + f * 0x100)) & 1 << 20 != 0;
        let misc1 = bench.get(d2(0x210e + f * 0x100)) & 0x40 != 0;
        if gsp0 != (revision == 0x14) || misc1 != (revision == 0x14) {
            return TestResult::Fail("VSC SDP colorimetry");
        }
        // A rate that failed verification was retired (disable_output)
        // before the next one.
        if !fail.is_empty()
            && in_order(
                &log,
                0,
                &[
                    ("first attempt", &|w: &m::Write| {
                        w.dword == m::AUX_WRITE | 0x100 && w.value == 20
                    }),
                    ("disable", &table(m::SLOT_TRANSMITTER, Some(1), Some(0))),
                    ("fallback", &|w: &m::Write| {
                        w.dword == m::AUX_WRITE | 0x100 && w.value == 10
                    }),
                ],
            )
            .is_err()
        {
            return TestResult::Fail("rate fallback");
        }
        if run(p.disable(&tables, &mut aux)).is_err() {
            return TestResult::Fail("DP disable");
        }
        if let Err(name) = dp_disable_order(&bench.log(), enabled, r, 1) {
            return TestResult::Fail(name);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_dp_sst_verifies_falls_back_and_follows_linux_order
);

/// The first write of each enable step in a clean HDMI run, by step.
fn step_marks(log: &[m::Write], r: Route) -> Vec<(Step, usize)> {
    let p = u32::from(r.pipe);
    let f = u32::from(r.stream);
    let first = |pred: &dyn Fn(&m::Write) -> bool| log.iter().position(pred).unwrap();
    vec![
        (Step::InitHw, first(&is(d1(0x7b)))),
        (Step::Clocks, first(&dal(0xe))),
        (Step::Watermarks, first(&is(d2(0x509)))),
        (Step::PixelClock, first(&set(d2(0x1acf + p * 0x10), 2))),
        (Step::Timing, first(&is(d2(0x1b2a + p * 0x80)))),
        (Step::Start, first(&set(d2(0x528 + p), 1 << 31))),
        (Step::Link, first(&is(d2(0x208b + f * 0x100)))),
        (Step::Plane, first(&is(d2(0x1b92 + p * 0x80)))),
    ]
}
fn clean_marks() -> (Route, Vec<(Step, usize)>) {
    let bench = Bench::new();
    bench.set(m::MP1 + 0x274, 1);
    let vram = Vram::new(VRAM_BYTES);
    let image = m::vbios(6);
    let tables = Tables::new(&image).unwrap();
    let connector = m::connector(Signal::Hdmi, 3, 3);
    let r = Resources::new().acquire(&connector).unwrap();
    let mut p = pipeline(&bench, connector, r);
    run(enable_with(
        &mut p,
        &vram,
        &tables,
        &m::sink(Signal::Hdmi, None),
        &mut NoAux,
    ))
    .unwrap();
    (r, step_marks(&bench.log(), r))
}

fn step_name(step: Step) -> &'static str {
    match step {
        Step::InitHw => "InitHw failure not retained",
        Step::Clocks => "Clocks failure not retained",
        Step::Watermarks => "Watermarks failure not retained",
        Step::PixelClock => "PixelClock failure not retained",
        Step::Timing => "Timing failure not retained",
        Step::Start => "Start failure not retained",
        Step::Link => "Link failure not retained",
        Step::Plane => "Plane failure not retained",
        _ => "failure not retained",
    }
}
fn navi22_modeset_failure_at_each_step_is_retained_without_retry() -> TestResult {
    let (r, marks) = clean_marks();
    for (step, at) in marks {
        let bench = Bench::new();
        bench.set(m::MP1 + 0x274, 1);
        let vram = Vram::new(VRAM_BYTES);
        let image = m::vbios(6);
        let tables = Tables::new(&image).unwrap();
        let mut p = pipeline(&bench, m::connector(Signal::Hdmi, 3, 3), r);
        // The device drops off the bus right after this step's first write.
        bench.die_after(at + 1);
        let sink = m::sink(Signal::Hdmi, None);
        let result = run(enable_with(&mut p, &vram, &tables, &sink, &mut NoAux));
        match (result, p.state()) {
            (Err(error), State::Failed { step: s, error: e }) if s == step && e == error => {}
            _ => return TestResult::Fail(step_name(step)),
        }
        // Owners and the published scanout are kept; nothing is replayed.
        if step >= Step::Clocks && p.scanout().is_none_or(|s| s.reusable_for_test()) {
            return TestResult::Fail("scanout released after failure");
        }
        bench.revive();
        let writes = bench.writes();
        if run(enable_with(&mut p, &vram, &tables, &sink, &mut NoAux)).err() != Some(Error::Busy)
            || run(p.disable(&tables, &mut NoAux)) != Err(Error::Busy)
            || bench.writes() != writes
        {
            return TestResult::Fail("failed pipeline replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_failure_at_each_step_is_retained_without_retry
);

fn navi22_modeset_cancellation_at_each_step_is_retained() -> TestResult {
    use core::task::{Context, Waker};
    let (r, marks) = clean_marks();
    let mark = |step| marks.iter().find(|(s, _)| *s == step).unwrap().1;
    let (p0, f) = (u32::from(r.pipe), u32::from(r.stream));
    // For every step with an await, the acknowledgement withheld so the
    // bring-up is pending inside it. Watermarks and Timing are synchronous
    // and cannot be cancelled part-way.
    /// (step, cancel after this write, withheld ack (dword, mask, value), GOP lit).
    type Point = (Step, usize, Option<(u32, u32, u32)>, bool);
    let points: [Point; 7] = [
        // A live GOP OTG whose blank never latches (dcn20_init_blank).
        (
            Step::InitHw,
            mark(Step::InitHw),
            Some((d2(0x185b), 1, 1)),
            true,
        ),
        (
            Step::Clocks,
            mark(Step::Clocks),
            Some((m::MP1 + 0x274, u32::MAX, 0)),
            false,
        ),
        (
            Step::PixelClock,
            mark(Step::PixelClock),
            Some((d2(0x1acf + p0 * 0x10), 4, 0)),
            false,
        ),
        (Step::Start, mark(Step::Start), None, false),
        (
            Step::Link,
            mark(Step::Link),
            Some((d2(0x206c + f * 0x100), 2, 2)),
            false,
        ),
        (
            Step::Plane,
            mark(Step::Plane),
            Some((d2(0x83 + 4 * p0), 0xc000_0000, 0xc000_0000)),
            false,
        ),
        (Step::Verify, 0, None, false),
    ];
    for (step, at, stall, gop) in points {
        let bench = Bench::new();
        bench.set(m::MP1 + 0x274, 1);
        if gop {
            bench.set(d2(0x1b41), 1);
        }
        if let Some((dword, mask, forced)) = stall {
            bench.stall(at, dword, mask, forced);
        }
        let vram = Vram::new(VRAM_BYTES);
        let image = m::vbios(6);
        let tables = Tables::new(&image).unwrap();
        let mut p = pipeline(&bench, m::connector(Signal::Hdmi, 3, 3), r);
        let sink = m::sink(Signal::Hdmi, None);
        let unlock = |w: &m::Write| w.dword == d2(0x1b8b + p0 * 0x80) && w.value == 0;
        let mut none = NoAux;
        {
            let mut future = core::pin::pin!(enable_with(&mut p, &vram, &tables, &sink, &mut none));
            let deadline = narf_time::Deadline::after_ms(5000);
            loop {
                if future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_ready()
                {
                    return TestResult::Fail("finished before the cancellation point");
                }
                let reached = if step == Step::Verify {
                    bench.log().iter().any(unlock)
                } else {
                    bench.writes() > at
                };
                if reached {
                    break;
                }
                if deadline.expired() {
                    return TestResult::Fail("cancellation point never reached");
                }
            }
            // Dropped while pending inside the step.
        }
        bench.unstall();
        if p.state() != State::At(step) {
            return TestResult::Fail("cancelled step not retained");
        }
        if run(enable_with(&mut p, &vram, &tables, &sink, &mut NoAux)).err() != Some(Error::Busy) {
            return TestResult::Fail("cancelled bring-up replayed");
        }
        // The retained owner can still retire what started.
        if run(p.disable(&tables, &mut NoAux)).is_err() || p.state() != State::At(Step::Stopped) {
            return TestResult::Fail("cancelled pipeline not retired");
        }
        if !gop && bench.get(d2(0x1b41 + p0 * 0x80)) & 1 != 0 {
            return TestResult::Fail("OTG left running");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_cancellation_at_each_step_is_retained
);

fn navi22_modeset_models_every_pipe_and_dig_route() -> TestResult {
    for i in 0..6u8 {
        for signal in [Signal::Hdmi, Signal::DisplayPort] {
            let bench = Bench::new();
            bench.set(m::MP1 + 0x274, 1);
            let vram = Vram::new(VRAM_BYTES);
            let image = m::vbios(6);
            let tables = Tables::new(&image).unwrap();
            let (pipe, tx) = match signal {
                Signal::Hdmi => (i, (i + 2) % 6),
                Signal::DisplayPort => ((i + 3) % 6, i),
            };
            let connector = m::connector(signal, tx, tx);
            // Earlier streams hold the lower pipes and PLLs.
            let mut pool = Resources::new();
            for other in 0..pipe {
                let filler = m::connector(Signal::Hdmi, (tx + 1 + other) % 6, 0);
                pool.acquire(&filler).unwrap();
            }
            let r = pool.acquire(&connector).unwrap();
            if r.pipe != pipe {
                return TestResult::Fail("pipe allocation");
            }
            let mut p = pipeline(&bench, connector, r);
            let sink = match signal {
                Signal::Hdmi => m::sink(Signal::Hdmi, None),
                Signal::DisplayPort => m::sink(Signal::DisplayPort, Some(m::dpcd(0x12))),
            };
            let mut aux = DpSink::new(bench.model.clone());
            if run(enable_with(&mut p, &vram, &tables, &sink, &mut aux)).is_err() {
                return TestResult::Fail("route enable");
            }
            let log = bench.log();
            let order = match signal {
                Signal::Hdmi => hdmi_enable_order(&log, r, tx),
                Signal::DisplayPort => dp_order(&log, r, tx, 6),
            };
            if let Err(name) = order {
                return TestResult::Fail(name);
            }
            // Pipe 5's power domains (10, 11) are never power gated.
            if log.iter().any(|w| {
                (w.dword == d2(0x80 + 20) || w.dword == d2(0x80 + 22)) && w.value & 1 << 8 != 0
            }) {
                return TestResult::Fail("pipe 5 power gated");
            }
            // Nothing landed on another pipe's OTG or another DIG's backend.
            let other_otg = (0..6u32)
                .filter(|&o| o != u32::from(pipe))
                .any(|o| log.iter().any(|w| w.dword == d2(0x1b2a + o * 0x80)));
            let other_be = (0..6u32)
                .filter(|&o| o != u32::from(tx))
                .any(|o| log.iter().any(|w| w.dword == d2(0x20b0 + o * 0x100)));
            if other_otg || other_be {
                return TestResult::Fail("write to a foreign instance");
            }
            if run(p.disable(&tables, &mut aux)).is_err() {
                return TestResult::Fail("route disable");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_models_every_pipe_and_dig_route
);

fn navi22_modeset_underflow_turns_black_and_quarantines() -> TestResult {
    let bench = Bench::new();
    bench.set(m::MP1 + 0x274, 1);
    let vram = Vram::new(VRAM_BYTES);
    let image = m::vbios(6);
    let tables = Tables::new(&image).unwrap();
    let connector = m::connector(Signal::Hdmi, 3, 3);
    let r = Resources::new().acquire(&connector).unwrap();
    let mut p = pipeline(&bench, connector, r);
    bench.underflow_on_unlock(r.pipe);
    let sink = m::sink(Signal::Hdmi, None);
    let expect = Underflow { otg: true, hubp: 0 };
    let result = run(enable_with(&mut p, &vram, &tables, &sink, &mut NoAux));
    if result.err() != Some(Error::Underflow(expect))
        || p.state()
            != (State::Failed {
                step: Step::Verify,
                error: Error::Underflow(expect),
            })
        || p.underflow() != Some(expect)
    {
        return TestResult::Fail("bring-up underflow");
    }
    // Black (DPG on) before anything else after the unlock.
    let log = bench.log();
    let unlock = log
        .iter()
        .rposition(|w| w.dword == d2(0x1b8b) && w.value == 0)
        .unwrap();
    if log[unlock + 1..]
        .iter()
        .find(|w| w.dword != d2(0x1857) && w.dword != d2(0x1858) && w.dword != d2(0x1859))
        .is_none_or(|w| w.dword != d2(0x1854) || w.value & 1 == 0)
    {
        return TestResult::Fail("not black first");
    }
    // A live pipeline that later underflows is quarantined by the poll.
    let bench = Bench::new();
    bench.set(m::MP1 + 0x274, 1);
    let vram = Vram::new(VRAM_BYTES);
    let mut p = pipeline(&bench, connector, r);
    if run(enable_with(&mut p, &vram, &tables, &sink, &mut NoAux)).is_err() {
        return TestResult::Fail("second enable");
    }
    bench.set(d2(0x5f3), 2 << 28);
    let late = Underflow {
        otg: false,
        hubp: 2,
    };
    if p.check_underflow() != Ok(Some(late))
        || p.state() != State::Quarantined(late)
        || p.flush() != Err(Error::Busy)
        || bench.get(d2(0x1854)) & 1 == 0
    {
        return TestResult::Fail("live underflow quarantine");
    }
    if run(p.disable(&tables, &mut NoAux)).is_err() || p.underflow() != Some(late) {
        return TestResult::Fail("quarantined stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_underflow_turns_black_and_quarantines
);

fn navi22_modeset_retires_the_live_gop_stream_like_dcn30_init_hw() -> TestResult {
    let bench = Bench::new();
    bench.set(m::MP1 + 0x274, 1);
    // The GOP: OTG 1 running 1920x1080 through OPP 1, HUBP 1 clocked, DIG
    // backend 3 enabled in HDMI mode from frontend 1.
    bench.set(d2(0x1b41 + 0x80), 1);
    bench.set(d2(0x1acb + 0x10), 1 << 8);
    bench.set(d2(0x1b2b + 0x80), 2020 | 100 << 16);
    bench.set(d2(0x1b36 + 0x80), 1100 | 20 << 16);
    bench.set(d2(0x5f4 + 0xdc), 1);
    bench.set(d2(0x20b1 + 0x300), 1);
    bench.set(d2(0x20b0 + 0x300), 3 << 16 | 1 << 9);
    bench.set(d3(0x20 + 2), 1);
    let vram = Vram::new(VRAM_BYTES);
    let image = m::vbios(6);
    let tables = Tables::new(&image).unwrap();
    let connector = m::connector(Signal::Hdmi, 3, 3);
    let r = Resources::new().acquire(&connector).unwrap();
    let mut p = pipeline(&bench, connector, r);
    let sink = m::sink(Signal::Hdmi, None);
    let output = match run(enable_with(&mut p, &vram, &tables, &sink, &mut NoAux)) {
        Ok(o) => o,
        Err(_) => return TestResult::Fail("enable over the GOP"),
    };
    if output.inherited
        != (Inherited {
            otgs: 1 << 1,
            digs: 1 << 3,
        })
    {
        return TestResult::Fail("inherited state");
    }
    let log = bench.log();
    let order = in_order(
        &log,
        0,
        &[
            ("golden init", &table(m::SLOT_POWER_GATING, None, None)),
            ("disable_vga", &is(d1(0x0c))),
            ("init_blank DPG size", &|w: &m::Write| {
                w.dword == d2(0x1856 + 0x5a) && w.value == 1080 | 1920 << 16
            }),
            ("init_blank DPG", &set(d2(0x1854 + 0x5a), 1)),
            ("lock", &set(d2(0x1b8b + 0x80), 1)),
            ("mpc init", &|w: &m::Write| {
                w.dword == d3(0x20) && w.value == 0xf
            }),
            ("opp mux parked", &|w: &m::Write| {
                w.dword == d3(0x580 + 4) && w.value & 0xf == 0xf
            }),
            ("unlock", &|w: &m::Write| {
                w.dword == d2(0x1b8b + 0x80) && w.value == 0
            }),
            ("hubp blank", &set(d2(0x5f3 + 0xdc), 1)),
            ("hubp clock off", &clear(d2(0x5f4 + 0xdc), 1)),
            ("dpp power gate", &set(d2(0x80 + 2 * 3), 1 << 8)),
            ("tg_init", &is(d2(0x1b5b + 0x80))),
            ("power_down_encoders", &|w: &m::Write| {
                table(m::SLOT_TRANSMITTER, Some(3), Some(0))(w)
            }),
            ("power_down_controllers", &clear(d2(0x1b41 + 0x80), 1)),
            ("native bring-up", &dal(2)),
        ],
    );
    if let Err(name) = order {
        return TestResult::Fail(name);
    }
    // power_down_encoders sends SIGNAL_TYPE_NONE (DVI digmode 2) for the
    // HDMI connector object (12).
    let disable = log
        .iter()
        .position(|w| table(m::SLOT_TRANSMITTER, Some(3), Some(0))(w))
        .unwrap();
    let connobj = log[disable..]
        .iter()
        .find(|w| w.dword == MARK + 16 * m::SLOT_TRANSMITTER + 2)
        .map(|w| (w.value >> 16) & 0xff);
    if (log[disable].value >> 16) & 0xff != 2 || connobj != Some(12) {
        return TestResult::Fail("power-down transmitter parameters");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_retires_the_live_gop_stream_like_dcn30_init_hw
);

/// DP offers follow `dp_validate_mode_timing` against the verified link (the
/// receiver caps until verified); a request outside them is refused.
fn navi22_modeset_dp_offers_follow_the_verified_link() -> TestResult {
    let mut dp = sink(false, 0);
    dp.dpcd = Some(m::dpcd(0x12));
    let (uhd, fhd) = {
        let t = crate::amdgpu_navi48_boot::edid_timings(&dp.edid);
        (t[0], t[1])
    };
    let unverified = offered_on(&dp, &soc(), 3_650_000, None);
    let hbr4 = offered_on(&dp, &soc(), 3_650_000, Some(DpLink { rate: 10, lanes: 4 }));
    let safe = offered_on(&dp, &soc(), 3_650_000, Some(dp_link::FAIL_SAFE));
    if hbr4 != [fhd] || !safe.is_empty() || !unverified.contains(&fhd) {
        return TestResult::Fail("offers against the verified link");
    }
    // 4K60 needs more than HBR x4: never offered on it, and refused.
    if hbr4.contains(&uhd)
        || select_dp_on(
            &dp,
            &soc(),
            3_650_000,
            Some(uhd),
            Some(DpLink { rate: 10, lanes: 4 }),
        )
        .err()
            != Some(Error::NoMode)
    {
        return TestResult::Fail("mode beyond the verified link");
    }
    if select_dp_on(
        &dp,
        &soc(),
        3_650_000,
        None,
        Some(DpLink { rate: 10, lanes: 4 }),
    )
    .map(|r| r.0)
        != Ok(fhd)
    {
        return TestResult::Fail("preferred mode within the link");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_dp_offers_follow_the_verified_link
);

fn lit_dp(bench: &Bench, vram: &Vram, tables: &Tables<'_>, aux: &mut DpSink) -> Option<Pipeline> {
    let connector = m::connector(Signal::DisplayPort, 1, 1);
    let r = Resources::new().acquire(&connector).unwrap();
    let mut p = pipeline(bench, connector, r);
    let sink = m::sink(Signal::DisplayPort, Some(m::dpcd(0x12)));
    run(enable_with(&mut p, vram, tables, &sink, aux)).ok()?;
    Some(p)
}

/// Link loss (`dp_handle_link_loss`): the check sees lost lock with the sink
/// in D0; the retrain stops and retrains only the link (blank, D3, PHY off,
/// TPS1 at the same setting, unblank) while the front end keeps running.
fn navi22_modeset_dp_link_loss_retrains_the_link_only() -> TestResult {
    let bench = Bench::new();
    bench.set(m::MP1 + 0x274, 1);
    let vram = Vram::new(VRAM_BYTES);
    let image = m::vbios(7);
    let tables = Tables::new(&image).unwrap();
    let mut aux = DpSink::new(bench.model.clone());
    let Some(mut p) = lit_dp(&bench, &vram, &tables, &mut aux) else {
        return TestResult::Fail("DP enable");
    };
    if run(p.check_dp_link(&mut aux)) != Ok(RxEvent::None) {
        return TestResult::Fail("healthy link reported lost");
    }
    aux.fail_rates = vec![6];
    if !matches!(run(p.check_dp_link(&mut aux)), Ok(RxEvent::LinkLoss(_))) {
        return TestResult::Fail("link loss missed");
    }
    aux.fail_rates.clear();
    let from = bench.log().len();
    if run(p.retrain(&tables, &mut aux)) != Ok(DpLink { rate: 6, lanes: 1 })
        || p.state() != State::At(Step::Running)
    {
        return TestResult::Fail("retrain");
    }
    let log = bench.log();
    let (f, t) = (u32::from(p.route().stream), 1u32);
    if let Err(name) = in_order(
        &log,
        from,
        &[
            ("dp_blank", &clear(d2(0x210c + f * 0x100), 1)),
            ("DPCD D3", &|w: &m::Write| {
                w.dword == m::AUX_WRITE | 0x600 && w.value == 2
            }),
            (
                "disable_output",
                &table(m::SLOT_TRANSMITTER, Some(1), Some(0)),
            ),
            (
                "enable_dp_output",
                &table(m::SLOT_TRANSMITTER, Some(1), Some(1)),
            ),
            ("DPCD link rate", &|w: &m::Write| {
                w.dword == m::AUX_WRITE | 0x100 && w.value == 6
            }),
            ("TPS1", &|w: &m::Write| {
                w.dword == d2(0x2118 + t * 0x100) && w.value == 0
            }),
            ("DP_VID_STREAM_ENABLE", &set(d2(0x210c + f * 0x100), 1)),
        ],
    ) {
        return TestResult::Fail(name);
    }
    let p0 = u32::from(p.route().pipe);
    if log[from..].iter().any(|w| {
        (w.dword == d2(0x1b41 + p0 * 0x80) && w.value & 1 == 0)
            || (w.dword == d2(0x5f3 + p0 * 0xdc) && w.value & 1 != 0)
    }) {
        return TestResult::Fail("retrain touched the OTG or HUBP");
    }
    // A retrain that cannot train leaves the link down for disable.
    aux.fail_rates = vec![6];
    if !matches!(run(p.retrain(&tables, &mut aux)), Err(Error::Training(_)))
        || p.state() != State::At(Step::Link)
    {
        return TestResult::Fail("failed retrain state");
    }
    if run(p.disable(&tables, &mut aux)).is_err() || p.state() != State::At(Step::Stopped) {
        return TestResult::Fail("disable after a failed retrain");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_dp_link_loss_retrains_the_link_only
);

/// After the sink left, teardown issues no AUX transaction at all.
fn navi22_modeset_dp_unplug_teardown_sends_no_aux() -> TestResult {
    let bench = Bench::new();
    bench.set(m::MP1 + 0x274, 1);
    let vram = Vram::new(VRAM_BYTES);
    let image = m::vbios(7);
    let tables = Tables::new(&image).unwrap();
    let mut aux = DpSink::new(bench.model.clone());
    let Some(mut p) = lit_dp(&bench, &vram, &tables, &mut aux) else {
        return TestResult::Fail("DP enable");
    };
    let from = bench.log().len();
    if run(p.disable_unplugged(&tables, &mut aux)).is_err() || p.state() != State::At(Step::Stopped)
    {
        return TestResult::Fail("unplugged disable");
    }
    let log = bench.log();
    if log[from..]
        .iter()
        .any(|w| w.dword & (m::AUX_READ | m::AUX_WRITE) != 0)
    {
        return TestResult::Fail("AUX after unplug");
    }
    let r = p.route();
    if let Err(name) = in_order(
        &log,
        from,
        &[
            (
                "disable_output",
                &table(m::SLOT_TRANSMITTER, Some(1), Some(0)),
            ),
            (
                "disable_crtc",
                &clear(d2(0x1b41 + u32::from(r.pipe) * 0x80), 1),
            ),
        ],
    ) {
        return TestResult::Fail(name);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22-modeset",
    navi22_modeset_dp_unplug_teardown_sends_no_aux
);

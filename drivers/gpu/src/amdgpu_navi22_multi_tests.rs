//! Multi-stream register-model tests: the DCN3.0 pool for several
//! streams, and whole contexts lit end to end on the combined model
//! (`amdgpu_navi22_modeset_model`): HDMI + DP, a shared PHY PLL, ODM 2:1,
//! DSC on DP SST with FEC, and two DP MST streams on one link.
use super::*;
use crate::amdgpu_navi22_modeset_model::{self as m, d1, d2, d3, Bench, DpSink, Vram, MARK};
use crate::dp_mst_mgr::{tests::Hub, MstAux as _};
use alloc::{collections::BTreeMap, vec, vec::Vec};
use narf_kernel_test::{kernel_test_in, TestResult};

const BOARD: Board = Board {
    crystal_khz: 100_000,
    channels: 12,
    channel_width_bytes: 2,
};

fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}

#[allow(clippy::too_many_arguments)]
fn timing(
    pclk: u32,
    hact: u32,
    htotal: u32,
    hfp: u32,
    hsync: u32,
    vact: u32,
    vtotal: u32,
    vfp: u32,
    vsync: u32,
) -> Timing {
    Timing {
        pixel_clock_khz: pclk,
        h_active: hact,
        h_total: htotal,
        h_front_porch: hfp,
        h_sync_width: hsync,
        v_active: vact,
        v_total: vtotal,
        v_front_porch: vfp,
        v_sync_width: vsync,
        h_sync_positive: true,
        v_sync_positive: true,
    }
}

// ── The pool ───────────────────────────────────────────────────────────

fn navi22_multi_resources_share_plls_and_split_odm_from_the_top() -> TestResult {
    let hdmi_a = m::connector(Signal::Hdmi, 3, 3);
    let hdmi_b = m::connector(Signal::Hdmi, 4, 4);
    let dp = m::connector(Signal::DisplayPort, 0, 0);
    let t1080 = timing(148_500, 1920, 2200, 88, 44, 1080, 1125, 4, 5);
    let t720 = timing(74_250, 1280, 1650, 110, 40, 720, 750, 5, 5);
    let t480 = timing(25_175, 640, 800, 16, 96, 480, 525, 10, 2);
    let mut pool = Resources::new();
    let (Ok(a), Ok(b), Ok(c)) = (
        pool.acquire_stream(&hdmi_a, &t1080, Odm::None, false),
        pool.acquire_stream(&hdmi_b, &t1080, Odm::None, false),
        pool.acquire_stream(&hdmi_b, &t720, Odm::None, false),
    ) else {
        return TestResult::Fail("three HDMI streams refused");
    };
    // resource_find_used_clk_src_for_sharing: identical timings share PLL0;
    // another timing takes the next free PLL. Pipes and frontends as for
    // one stream (frontend 4 taken: the last free, 5).
    if a.route.clock != ClockSource::Pll(0)
        || b.route.clock != ClockSource::Pll(0)
        || c.route.clock != ClockSource::Pll(1)
        || (a.route.pipe, b.route.pipe, c.route.pipe) != (0, 1, 2)
        || (a.route.stream, b.route.stream, c.route.stream) != (3, 4, 5)
    {
        return TestResult::Fail("HDMI PLL sharing");
    }
    // The shared PLL outlives its first user, and frees with its last.
    pool.release_stream(&a);
    if pool
        .acquire_stream(&hdmi_a, &t720, Odm::None, false)
        .map(|d| d.route.clock)
        != Ok(ClockSource::Pll(1))
    {
        return TestResult::Fail("a released sharer freed the PLL");
    }
    pool.release_stream(&b);
    if pool
        .acquire_stream(&hdmi_b, &t480, Odm::None, false)
        .map(|e| e.route.clock)
        != Ok(ClockSource::Pll(0))
    {
        return TestResult::Fail("PLL0 not freed by its last sharer");
    }
    // ODM: the secondary from the top of the pool (dcn30_find_split_pipe),
    // DSC n for each pipe n; DP never shares (DP DTO).
    let mut pool = Resources::new();
    let (Ok(odm), Ok(next)) = (
        pool.acquire_stream(&dp, &t1080, Odm::TwoToOne, true),
        pool.acquire_stream(&hdmi_a, &t1080, Odm::None, false),
    ) else {
        return TestResult::Fail("ODM stream refused");
    };
    if odm.route.pipe != 0
        || odm.odm_pipe != Some(5)
        || odm.route.clock != ClockSource::DpDto
        || next.route.pipe != 1
        || odm.pipes().collect::<Vec<_>>() != vec![0, 5]
    {
        return TestResult::Fail("ODM pipes");
    }
    // All or nothing: a refused stream leaves the pool as it was.
    let mut full = pool;
    for t in 0..4u8 {
        let _ = full.acquire_stream(
            &m::connector(Signal::DisplayPort, t, 0),
            &t1080,
            Odm::None,
            false,
        );
    }
    let before = full;
    if full
        .acquire_stream(&dp, &t1080, Odm::TwoToOne, false)
        .is_ok()
        || full != before
    {
        return TestResult::Fail("pool exhaustion");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-multi",
    navi22_multi_resources_share_plls_and_split_odm_from_the_top
);

// ── End-to-end contexts ────────────────────────────────────────────────

/// Each link's sink: a DP sink model with optional DPCD overrides (DSC/FEC
/// caps), and an MST hub for one link's branch traffic.
struct TestLinks {
    model: alloc::sync::Arc<m::Model>,
    sinks: BTreeMap<usize, DpSink>,
    extra: BTreeMap<u32, u8>,
    hub: Option<(usize, Hub)>,
}
fn mst_address(a: u32) -> bool {
    matches!(a, 0x21 | 0x111 | 0x1c0..=0x1c2 | 0x2c0 | 0x2003) || (0x1000..0x1800).contains(&a)
}
impl Links for TestLinks {
    async fn read(&mut self, link: usize, address: u32, data: &mut [u8]) -> Result<(), Error> {
        if let Some((l, hub)) = self.hub.as_mut() {
            if *l == link && mst_address(address) {
                hub.read(address, data).await.map_err(|_| Error::Aux)?;
                if address == 0x2c0 {
                    // ACT handled: the source triggers every allocation.
                    data[0] |= 2;
                }
                return Ok(());
            }
        }
        let sink = self.sinks.get_mut(&link).ok_or(Error::Aux)?;
        Aux::read(sink, address, data).await?;
        for (i, b) in data.iter_mut().enumerate() {
            if let Some(v) = self.extra.get(&(address + i as u32)) {
                *b = *v;
            }
        }
        Ok(())
    }
    async fn write(&mut self, link: usize, address: u32, data: &[u8]) -> Result<(), Error> {
        if let Some((l, hub)) = self.hub.as_mut() {
            if *l == link && mst_address(address) {
                {
                    let mut s = self.model.0.lock();
                    for (i, &b) in data.iter().enumerate() {
                        s.log.push(m::Write {
                            dword: m::AUX_WRITE | (address + i as u32),
                            value: u32::from(b),
                        });
                    }
                }
                return hub.write(address, data).await.map_err(|_| Error::Aux);
            }
        }
        let sink = self.sinks.get_mut(&link).ok_or(Error::Aux)?;
        Aux::write(sink, address, data).await
    }
    /// An HDMI 2.0 sink's SCDC: Sink_Version 1, writes logged.
    async fn scdc_read(&mut self, _: usize, offset: u8) -> Result<u8, Error> {
        Ok(u8::from(offset == 1))
    }
    async fn scdc_write(&mut self, _: usize, offset: u8, value: u8) -> Result<(), Error> {
        self.model.0.lock().log.push(m::Write {
            dword: SCDC_WRITE | u32::from(offset),
            value: u32::from(value),
        });
        Ok(())
    }
}
/// SCDC writes in the model log: `SCDC_WRITE | offset` = value.
const SCDC_WRITE: u32 = 0x2000_0000;

/// A sink whose preferred (only) mode is `dtd`.
fn sink_with(signal: Signal, dpcd: Option<[u8; 16]>, dtd: [u8; 18]) -> Sink {
    let mut s = m::sink(signal, dpcd);
    s.edid[54..72].copy_from_slice(&dtd);
    let sum = s.edid[..127].iter().fold(0u8, |a, b| a.wrapping_add(*b));
    s.edid[127] = 0u8.wrapping_sub(sum);
    s
}
/// 1920x1080@173 at 399.79 MHz (reduced blanking): past one 350 MHz pipe.
const DTD_1080P173: [u8; 18] = [
    0x2b, 0x9c, 0x80, 0xa0, 0x70, 0x38, 0x1f, 0x40, 0x30, 0x20, 0x35, 0x00, 0, 0, 0, 0, 0, 0x1e,
];
/// 1920x1080@60 at 148.5 MHz (CTA timing).
const DTD_1080P60: [u8; 18] = [
    0x02, 0x3a, 0x80, 0x18, 0x71, 0x38, 0x2d, 0x40, 0x58, 0x2c, 0x45, 0x00, 0, 0, 0, 0, 0, 0x1e,
];

fn request(link: usize, connector: Connector, sink: Sink) -> Request {
    Request {
        link,
        connector,
        sink,
        want: None,
        hdmi_settings: Default::default(),
        mst: None,
    }
}

/// Light `requests` on `vram_mib` of model VRAM, then (when that worked)
/// stop them again and return the scanouts.
async fn light(
    bench: &Bench,
    requests: &[Request],
    links: &mut TestLinks,
    vram_mib: usize,
) -> (Group, Result<Vec<Output>, Error>, Result<(), Error>) {
    // The SMU's DAL interface answers (as the modeset tests' benches).
    bench.set(m::MP1 + 0x274, 1);
    let image = m::vbios(6);
    let tables = Tables::new(&image).unwrap();
    let vram = Vram::new(vram_mib << 20);
    let board: Vec<Connector> = requests.iter().map(|r| r.connector).collect();
    // SAFETY: the bench's model owns every register the group reaches.
    let mut group = unsafe { Group::new(&bench.gpu, Cap::bootstrap(), requests) }.unwrap();
    // SAFETY: model-backed owners and a heap-backed pool.
    let result = unsafe {
        group
            .enable(
                core::future::ready(Ok(())),
                &vram.pool,
                &tables,
                BOARD,
                &board,
                links,
                |_, _, row| row.fill(0x00ff_00ff),
            )
            .await
    };
    if let Err(e) = &result {
        use core::fmt::Write;
        let _ = writeln!(
            narf_console::Writer,
            "navi22-multi: {e:?} in {:?}",
            group.state()
        );
    }
    let stopped = if result.is_ok() {
        group.disable(&tables, links).await
    } else {
        Ok(())
    };
    if result.is_ok() && stopped.is_ok() {
        for m in group.members_mut() {
            // SAFETY: stopped; no CPU view of the model surfaces remains.
            let _ = unsafe { m.release_scanout() };
        }
    } else {
        // A failed context keeps its surfaces reserved: keep the memory.
        core::mem::forget(vram);
    }
    (group, result, stopped)
}

fn last(log: &[m::Write], dword: u32) -> Option<u32> {
    log.iter().rev().find(|w| w.dword == dword).map(|w| w.value)
}
fn any(log: &[m::Write], f: impl Fn(&m::Write) -> bool) -> bool {
    log.iter().any(f)
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

fn navi22_multi_hdmi_and_dp_share_init_clocks_and_watermarks() -> TestResult {
    let bench = Bench::new();
    let hdmi = m::connector(Signal::Hdmi, 3, 3);
    let dp = m::connector(Signal::DisplayPort, 0, 0);
    let mut links = TestLinks {
        model: bench.model.clone(),
        sinks: BTreeMap::from([(1, DpSink::new(bench.model.clone()))]),
        extra: BTreeMap::new(),
        hub: None,
    };
    let requests = [
        request(0, hdmi, m::sink(Signal::Hdmi, None)),
        request(1, dp, m::sink(Signal::DisplayPort, Some(m::dpcd(0x12)))),
    ];
    let (group, result, stopped) = run(light(&bench, &requests, &mut links, 4));
    let Ok(outputs) = result else {
        return TestResult::Fail("HDMI + DP context refused");
    };
    if stopped.is_err() {
        return TestResult::Fail("HDMI + DP teardown failed");
    }
    let log = bench.log();
    if outputs.len() != 2 || group.leases().len() != 2 {
        return TestResult::Fail("two outputs");
    }
    let (a, b) = (group.leases()[0].route, group.leases()[1].route);
    if (a.pipe, b.pipe) != (0, 1) || b.clock != ClockSource::DpDto {
        return TestResult::Fail("routes");
    }
    // dcn30_init_hw and the DAL start once; one watermark set for both.
    let count = |f: &dyn Fn(&m::Write) -> bool| log.iter().filter(|w| f(w)).count();
    if count(&|w| w.dword == d1(0x7b)) != 1
        || count(&|w| w.dword == m::MP1 + 0x28a && w.value == 2) != 1
        || count(&|w| w.dword == d2(0x509)) != 1
    {
        return TestResult::Fail("shared init/clocks/watermarks not once");
    }
    if !log.windows(2).any(|pair| {
        pair[0].dword == m::MP1 + 0x273
            && pair[0].value == 2
            && pair[1].dword == m::MP1 + 0x28a
            && pair[1].value == 0xe
    }) {
        return TestResult::Fail("joint clocks did not report two active streams");
    }
    let Some(joint) = group.joint() else {
        return TestResult::Fail("no joint plan");
    };
    // Set A is the joint plan's, and each HUBP carries its own plane's
    // DLG/TTU from the same plan.
    if last(&log, d2(0x509)).map(|v| v & 0x3fff) != Some(joint.hubbub.urgent) {
        return TestResult::Fail("watermark set A is not the joint plan's");
    }
    for (k, pipe) in [(0usize, 0u32), (1, 1)] {
        let Some(left) = joint.planes[k].pipes[0] else {
            return TestResult::Fail("plane without a pipe");
        };
        let ttu = left.registers.ttu;
        if last(&log, d2(0x62b + pipe * 0xdc)).map(|v| v & 0x0fff_ffff) != Some(ttu.min_ttu_vblank)
        {
            return TestResult::Fail("a HUBP's TTU is not its plane's");
        }
        // hubp2_vtg_sel: each HUBP follows its own OTG.
        if !any(&log, |w| {
            w.dword == d2(0x5f3 + pipe * 0xdc) && (w.value >> 4) & 0xf == pipe
        }) {
            return TestResult::Fail("HUBP VTG select");
        }
    }
    // Both OTGs ran; both front ends latched together: both locks taken
    // before either surface address, both released after.
    let pos = |f: &dyn Fn(&m::Write) -> bool| log.iter().position(f);
    let lock = |p: u32| pos(&|w| w.dword == d2(0x1b8b + p * 0x80) && w.value & 1 != 0);
    let surface = |p: u32| pos(&|w| w.dword == d2(0x60a + p * 0xdc));
    let unlock = |p: u32| pos(&|w| w.dword == d2(0x1b8b + p * 0x80) && w.value == 0);
    match (
        lock(0),
        lock(1),
        surface(0),
        surface(1),
        unlock(0),
        unlock(1),
    ) {
        (Some(l0), Some(l1), Some(s0), Some(s1), Some(u0), Some(u1))
            if l0.max(l1) < s0.min(s1) && s0.max(s1) < u0.min(u1) => {}
        _ => return TestResult::Fail("front ends not latched together"),
    }
    if !(0..2u32).all(|p| {
        any(&log, |w| {
            w.dword == d2(0x1b41 + p * 0x80) && w.value & 1 != 0
        })
    }) {
        return TestResult::Fail("OTG not started");
    }
    if !(0..2u32).all(|p| last(&log, d2(0x1b41 + p * 0x80)).is_some_and(|v| v & 1 == 0)) {
        return TestResult::Fail("OTG left running");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-multi",
    navi22_multi_hdmi_and_dp_share_init_clocks_and_watermarks
);

fn navi22_multi_identical_hdmi_timings_share_one_phy_pll() -> TestResult {
    let bench = Bench::new();
    let mut links = TestLinks {
        model: bench.model.clone(),
        sinks: BTreeMap::new(),
        extra: BTreeMap::new(),
        hub: None,
    };
    let requests = [
        request(
            0,
            m::connector(Signal::Hdmi, 3, 3),
            m::sink(Signal::Hdmi, None),
        ),
        request(
            1,
            m::connector(Signal::Hdmi, 4, 4),
            m::sink(Signal::Hdmi, None),
        ),
    ];
    let (group, result, stopped) = run(light(&bench, &requests, &mut links, 4));
    if result.is_err() || stopped.is_err() {
        return TestResult::Fail("two HDMI streams refused");
    }
    let leases = group.leases();
    if leases[0].route.clock != ClockSource::Pll(0) || leases[1].route.clock != ClockSource::Pll(0)
    {
        return TestResult::Fail("identical timings did not share PLL0");
    }
    // dcn3_program_pix_clk runs for each OTG on the shared PLL: two
    // SetPixelClock calls, one PLL, OTG 0 and 1.
    let log = bench.log();
    // Power-downs (pixclk 0, CRT mode) aside: the first stream's PLL is
    // powered down once before it is programmed, never between sharers.
    let word1 = MARK + 16 * m::SLOT_PIXEL_CLOCK + 1;
    let is_down = |w: &m::Write| (w.value >> 16) & 0xff == 0x0f;
    let programs: Vec<usize> = (0..log.len())
        .filter(|&i| log[i].dword == word1 && !is_down(&log[i]))
        .collect();
    let downs_before = (0..programs.first().copied().unwrap_or(0))
        .filter(|&i| log[i].dword == word1 && is_down(&log[i]))
        .count();
    let downs_between = programs
        .windows(2)
        .any(|p| (p[0]..p[1]).any(|i| log[i].dword == word1 && is_down(&log[i])));
    if downs_before == 0 || downs_between {
        return TestResult::Fail("shared PLL powered down between sharers");
    }
    let calls: Vec<(u32, u32)> = log
        .iter()
        .enumerate()
        .filter(|(_, w)| w.dword == word1 && !is_down(w))
        .map(|(i, w)| {
            (
                w.value & 0xff,
                log.get(i + 1).map_or(0xff, |n| n.value & 0xff),
            )
        })
        .collect();
    if calls.len() != 2 || calls[0].0 != calls[1].0 || calls[0].1 == calls[1].1 {
        return TestResult::Fail("SetPixelClock per OTG on one PLL");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-multi",
    navi22_multi_identical_hdmi_timings_share_one_phy_pll
);

fn navi22_multi_odm_combines_two_pipes_for_one_stream() -> TestResult {
    let bench = Bench::new();
    // DISPCLK/DPPCLK capped at 350 MHz: 1080p173 needs both halves.
    bench.display_cap(350);
    let mut links = TestLinks {
        model: bench.model.clone(),
        sinks: BTreeMap::from([(0, DpSink::new(bench.model.clone()))]),
        extra: BTreeMap::new(),
        hub: None,
    };
    let requests = [request(
        0,
        m::connector(Signal::DisplayPort, 0, 0),
        sink_with(Signal::DisplayPort, Some(m::dpcd(0x12)), DTD_1080P173),
    )];
    let (group, result, stopped) = run(light(&bench, &requests, &mut links, 10));
    if result.is_err() || stopped.is_err() {
        return TestResult::Fail("1080p173 on ODM refused");
    }
    let lease = group.leases()[0];
    let log = bench.log();
    if lease.odm_pipe != Some(5) || group.joint().map(|j| j.planes[0].odm) != Some(Odm::TwoToOne) {
        return TestResult::Fail("no ODM lease");
    }
    // optc3_set_odm_combine: two segments from OPP 0 and 5, both pairs of
    // memories, the segment width, H timing divided by two.
    if !(any(&log, |w| w.dword == d2(0x1acb) && w.value == 1 | 5 << 12)
        && any(&log, |w| {
            w.dword == d2(0x1ad0) && w.value == 0x3 | 0x3 << 10
        })
        && any(&log, |w| w.dword == d2(0x1ace) && w.value & 0x1fff == 960)
        && any(&log, |w| w.dword == d2(0x1b2e) && w.value == 1))
    {
        return TestResult::Fail("ODM combine registers");
    }
    // get_pixel_clock_parameters halves the request for 2:1: the DTO
    // drives an OTG that takes two pixels per clock.
    let pixel_khz = group.plans()[0].timing.pixel_clock_khz;
    let (half, _) = dp_dto(pixel_khz / 2);
    let (full, _) = dp_dto(pixel_khz);
    if !any(&log, |w| w.dword == d1(0x81) && w.value == half)
        || any(&log, |w| w.dword == d1(0x81) && w.value == full)
    {
        return TestResult::Fail("ODM DP DTO not at the halved OTG rate");
    }
    // The right half: HUBP 5 on OTG 0's timing from pixel 960, OPP 5
    // blanking only its half, MPCC 5 into OPP 5.
    if !(any(&log, |w| {
        w.dword == d2(0x5f3 + 5 * 0xdc) && (w.value >> 4) & 0xf == 0
    }) && any(&log, |w| w.dword == d2(0x5e9 + 5 * 0xdc) && w.value == 960)
        && any(&log, |w| {
            w.dword == d2(0x1856 + 5 * 0x5a) && w.value == 1080 | 960 << 16
        })
        && any(&log, |w| w.dword == d3(0x580 + 5 * 4) && w.value & 0xf == 5))
    {
        return TestResult::Fail("ODM slice front end");
    }
    if last(&log, d2(0x1acb)).is_none_or(|v| v & 0x3 != 0) {
        return TestResult::Fail("ODM bypass not restored");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-multi",
    navi22_multi_odm_combines_two_pipes_for_one_stream
);

/// DPCD 0x60..0x6F: DSC 1.2, 1/2/4 slices, 13-bit line buffer, block
/// prediction, up to 24 bpp, RGB 8 bpc, 900 MP/s per slice, 5120-wide
/// slices; FEC capable at 0x90.
fn dsc_caps() -> BTreeMap<u32, u8> {
    let caps = [
        1u8, 0x21, 0, 0x0f, 0x0b, 4, 1, 0x80, 0x01, 1, 2, 0x0c, 0x10, 0, 0, 0,
    ];
    let mut m: BTreeMap<u32, u8> = caps
        .iter()
        .enumerate()
        .map(|(i, &v)| (0x60 + i as u32, v))
        .collect();
    m.insert(0x90, 1);
    m
}

fn navi22_multi_dsc_on_dp_sst_with_fec_like_link_set_dpms_on() -> TestResult {
    let bench = Bench::new();
    // HBR on one lane: 1080p60 needs DSC.
    let mut caps = m::dpcd(0x12);
    caps[1] = 0x0a;
    caps[2] = 0x80 | 0x40 | 1;
    let mut sink = DpSink::new(bench.model.clone());
    sink.caps = caps;
    let mut links = TestLinks {
        model: bench.model.clone(),
        sinks: BTreeMap::from([(0, sink)]),
        extra: dsc_caps(),
        hub: None,
    };
    let requests = [request(
        0,
        m::connector(Signal::DisplayPort, 0, 0),
        sink_with(Signal::DisplayPort, Some(caps), DTD_1080P60),
    )];
    let (group, result, stopped) = run(light(&bench, &requests, &mut links, 10));
    if result.is_err() || stopped.is_err() {
        return TestResult::Fail("DSC stream refused");
    }
    let Some(cfg) = group.plans()[0].dsc else {
        return TestResult::Fail("no DSC chosen");
    };
    if cfg.bpp_x16 >= 24 * 16 || !group.leases()[0].dsc {
        return TestResult::Fail("DSC config");
    }
    let log = bench.log();
    let aux = |a: u32, v: u32| move |w: &m::Write| w.dword == m::AUX_WRITE | a && w.value == v;
    let order = in_order(
        &log,
        0,
        &[
            ("dsc_pg_control on", &|w: &m::Write| {
                w.dword == d2(0xa1) && w.value & 1 << 8 == 0
            }),
            ("dsc2_set_config", &|w: &m::Write| w.dword == d2(0x300e)),
            ("dsc2_enable from OPP 0", &|w: &m::Write| {
                w.dword == d2(0x1a64) && w.value & 0x71 == 1
            }),
            ("enc3_dp_set_dsc_config", &|w: &m::Write| {
                w.dword == d2(0x2152) && w.value & 3 == 1
            }),
            ("optc3_set_dsc_config", &|w: &m::Write| {
                w.dword == d2(0x1acc) && w.value & 0x30 == 0x10
            }),
            ("FEC_READY on the sink", &aux(0x120, 1)),
            ("enc2_fec_set_ready", &|w: &m::Write| {
                w.dword == d2(0x2117) && w.value & 1 << 5 != 0
            }),
            ("training", &aux(0x102, 0x21)),
            ("enc2_fec_set_enable", &|w: &m::Write| {
                w.dword == d2(0x2117) && w.value & 1 << 4 != 0
            }),
            ("dp_set_dsc_on_rx", &aux(0x160, 1)),
            ("PPS SDP on GSP11", &|w: &m::Write| {
                w.dword == d2(0x2161) && w.value & 1 << 4 != 0
            }),
            ("unblank", &|w: &m::Write| {
                w.dword == d2(0x210c) && w.value & 1 != 0
            }),
        ],
    );
    if order.is_err() {
        return TestResult::Fail("DSC/FEC order differs from link_set_dpms_on");
    }
    // The PPS goes out on VPG generic 11..14.
    if !(11..15u32).all(|i| any(&log, |w| w.dword == d2(0x2068) && w.value & 0xff == i * 9)) {
        return TestResult::Fail("PPS SDP packets");
    }
    // Teardown: FEC and DSC off, the engine unclocked.
    if last(&log, d2(0x2117)).is_some_and(|v| v & 0x30 != 0)
        || last(&log, d2(0x3000)).is_some_and(|v| v & 1 != 0)
        || last(&log, d2(0x1a64)).is_some_and(|v| v & 1 != 0)
    {
        return TestResult::Fail("DSC/FEC left on");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-multi",
    navi22_multi_dsc_on_dp_sst_with_fec_like_link_set_dpms_on
);

fn navi22_multi_mst_two_streams_share_one_8b10b_link() -> TestResult {
    let bench = Bench::new();
    let dp = m::connector(Signal::DisplayPort, 0, 0);
    let mut links = TestLinks {
        model: bench.model.clone(),
        sinks: BTreeMap::from([(0, DpSink::new(bench.model.clone()))]),
        extra: BTreeMap::new(),
        hub: Some((0, Hub::new())),
    };
    let device = |branch, port| Request {
        link: 0,
        connector: dp,
        sink: m::sink(Signal::DisplayPort, Some(m::dpcd(0x12))),
        want: None,
        hdmi_settings: Default::default(),
        mst: Some(dp_mst_mgr::Sink { branch, port }),
    };
    let requests = [device(0, 1), device(1, 1)];
    let (group, result, stopped) = run(light(&bench, &requests, &mut links, 4));
    if result.is_err() || stopped.is_err() {
        return TestResult::Fail("MST context refused");
    }
    let (a, b) = (group.leases()[0].route, group.leases()[1].route);
    if (a.pipe, b.pipe) != (0, 1) || a.stream == b.stream {
        return TestResult::Fail("MST routes");
    }
    let log = bench.log();
    // One MST link: transmitter ENABLE once in DP MST mode (DIGMODE 5); the
    // backend in MST mode feeding both frontends.
    let mst_enables = log
        .iter()
        .filter(|w| {
            w.dword == MARK + 16 * m::SLOT_TRANSMITTER
                && (w.value >> 8) & 0xff == 1
                && (w.value >> 16) & 0xff == 5
        })
        .count();
    if mst_enables != 1 {
        return TestResult::Fail("MST link not enabled exactly once in MST mode");
    }
    if !any(&log, |w| {
        w.dword == d2(0x20b0)
            && (w.value >> 16) & 7 == 5
            && w.value & 1 << (8 + a.stream) != 0
            && w.value & 1 << (8 + b.stream) != 0
    }) {
        return TestResult::Fail("MST backend with both frontends");
    }
    // dcn10_link_encoder_update_mst_stream_allocation_table: two rows,
    // each frontend with its slots; then each stream's VC rate.
    let p = group.plans();
    let slots = |k: usize| p[k].mst.map_or(0, |m| u32::from(m.1));
    let sat = u32::from(a.stream) | slots(0) << 8 | (u32::from(b.stream) | slots(1) << 8) << 16;
    if !any(&log, |w| w.dword == d2(0x213a) && w.value == sat)
        || !any(&log, |w| {
            w.dword == d2(0x2137 + u32::from(a.stream) * 0x100) && w.value != 0
        })
        || !any(&log, |w| {
            w.dword == d2(0x2137 + u32::from(b.stream) * 0x100) && w.value != 0
        })
    {
        return TestResult::Fail("SAT rows or VC rates");
    }
    // The branch saw both ALLOCATE_PAYLOADs and both removals.
    let Some((_, hub)) = links.hub.as_ref() else {
        return TestResult::Fail("hub");
    };
    let allocs = hub
        .requests
        .iter()
        .filter(|r| r.2 == crate::dp_mst::ALLOCATE_PAYLOAD)
        .count();
    if allocs != 4 {
        return TestResult::Fail("ALLOCATE_PAYLOAD add/remove");
    }
    if last(&log, d2(0x213a)) != Some(0) {
        return TestResult::Fail("SAT not cleared");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-multi",
    navi22_multi_mst_two_streams_share_one_8b10b_link
);

fn navi22_multi_pll_sharing_includes_tmds_encoding_depth_and_target() -> TestResult {
    use crate::amdgpu_dcn30_hdmi::tests::{edid, vsdb, DTD_1080P};
    use crate::amdgpu_dcn30_hdmi::{stream_for, Depth as HdmiDepth, Limits};
    let e = edid(DTD_1080P, &[vsdb(0x30, 68)]);
    let t = crate::amdgpu_navi48_boot::edid_timings(&e)[0];
    let a = stream_for(&e, &t, 8, false, Limits::DEFAULT).unwrap();
    let b = stream_for(&e, &t, 12, false, Limits::DEFAULT).unwrap();
    let c = crate::amdgpu_dcn30_hdmi::Stream {
        format: crate::amdgpu_dcn30_hdmi::Format {
            depth: HdmiDepth::Bpc12,
            encoding: crate::amdgpu_hdr::PixelEncoding::Ycbcr422,
            ..a.format
        },
        ..a
    };
    let mut resources = Resources::new();
    let connectors = [
        m::connector(Signal::Hdmi, 0, 0),
        m::connector(Signal::Hdmi, 1, 1),
        m::connector(Signal::Hdmi, 2, 2),
        m::connector(Signal::Hdmi, 3, 3),
    ];
    let mut clocks = Vec::new();
    for (connector, stream) in connectors.iter().zip([a, b, c, a]) {
        match resources.acquire_stream_format(connector, &t, Odm::None, false, Some(&stream)) {
            Ok(lease) => clocks.push(lease.route.clock),
            Err(_) => return TestResult::Fail("format-specific PLL allocation"),
        }
    }
    if clocks
        != [
            ClockSource::Pll(0),
            ClockSource::Pll(1),
            ClockSource::Pll(2),
            ClockSource::Pll(0),
        ]
    {
        return TestResult::Fail(
            "incompatible TMDS streams shared PLL or equal streams did not share",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-multi",
    navi22_multi_pll_sharing_includes_tmds_encoding_depth_and_target
);

/// 1280x720 CEA geometry at 371.25 MHz: a scrambled HDMI 2.0 stream.
const DTD_720P_371: [u8; 18] = [
    0x05, 0x91, 0x00, 0x72, 0x51, 0xd0, 0x1e, 0x20, 0x6e, 0x28, 0x55, 0x00, 0, 0, 0, 0, 0, 0x1e,
];

fn navi22_multi_hdmi_odm_keeps_combine_through_hdmi_format() -> TestResult {
    use crate::amdgpu_dcn30_hdmi::tests::{edid, hf_vsdb, vsdb};
    let bench = Bench::new();
    // DISPCLK capped at 350 MHz: one pipe cannot carry 371.25 MHz.
    bench.display_cap(350);
    let mut links = TestLinks {
        model: bench.model.clone(),
        sinks: BTreeMap::new(),
        extra: BTreeMap::new(),
        hub: None,
    };
    let sink = Sink {
        edid: edid(DTD_720P_371, &[vsdb(0, 68), hf_vsdb(120, 0x88)]),
        preferred: None,
        hdmi: true,
        dpcd: None,
    };
    let requests = [request(0, m::connector(Signal::Hdmi, 3, 3), sink)];
    let (group, result, stopped) = run(light(&bench, &requests, &mut links, 10));
    if result.is_err() || stopped.is_err() {
        return TestResult::Fail("scrambled HDMI on ODM refused");
    }
    if group.leases()[0].odm_pipe != Some(5) {
        return TestResult::Fail("no ODM lease");
    }
    let log = bench.log();
    // The scrambled link's TMDS_Config reached the sink through Links.
    if !any(&log, |w| w.dword == SCDC_WRITE | 0x20 && w.value == 3) {
        return TestResult::Fail("SCDC TMDS_Config not forwarded");
    }
    // optc3_set_odm_combine's divide-by-two is the last H timing write
    // before the teardown's bypass: the HDMI format stage must not undo it.
    let combine = log
        .iter()
        .position(|w| w.dword == d2(0x1acb) && w.value == 1 | 5 << 12);
    let bypass = combine.and_then(|c| {
        log[c..]
            .iter()
            .position(|w| w.dword == d2(0x1acb) && w.value & 0x3 == 0)
            .map(|b| c + b)
    });
    let (Some(c), Some(b)) = (combine, bypass) else {
        return TestResult::Fail("ODM combine/bypass not programmed");
    };
    let h_timing = |w: &&m::Write| w.dword == d2(0x1b2e);
    let divided = log[c..b]
        .iter()
        .position(|w| h_timing(&w) && w.value & 0x3 == 1);
    let cleared = divided.is_some_and(|d| {
        log[c + d..b]
            .iter()
            .any(|w| h_timing(&w) && w.value & 0x3 != 1)
    });
    if divided.is_none() || cleared {
        return TestResult::Fail("HDMI format cleared the ODM H divider");
    }
    // The halved OTG rate for SetPixelClock; slice OPP format as the master.
    if !any(&log, |w| {
        w.dword == MARK + 16 * m::SLOT_PIXEL_CLOCK && w.value == 1_856_250
    }) || bench.get(d3(0x599 + 5 * 0xd)) != bench.get(d3(0x599))
        || bench.get(d2(0x1845 + 5 * 0x5a)) != bench.get(d2(0x1845))
    {
        return TestResult::Fail("ODM HDMI clock or slice format");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi22-multi",
    navi22_multi_hdmi_odm_keeps_combine_through_hdmi_format
);

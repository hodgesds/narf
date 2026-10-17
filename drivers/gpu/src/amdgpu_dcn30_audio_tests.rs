//! Register-model tests for the DCN3.0 audio owner. Literal offsets are the
//! `dcn_3_0_0_offset.h` ids for the instance under test.
use super::*;
use crate::amdgpu_dcn401_otg::AudioMode;
use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::{
    pin::pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

struct Fake {
    regs: BTreeMap<Reg, u32>,
    /// Indirect endpoint space, indexed [endpoint][ix].
    ep: [[u32; 0x80]; 8],
    index: [u32; 8],
    log: Vec<(Reg, u32)>,
    writes: Arc<AtomicUsize>,
    gone: Option<Reg>,
}
fn endpoint_of(reg: Reg) -> Option<(usize, bool)> {
    let Reg::Bank2(r) = reg else {
        return None;
    };
    if !(AZ_ENDPOINT_INDEX..AZ_ENDPOINT_INDEX + 8 * AZ_ENDPOINT_STRIDE).contains(&r) {
        return None;
    }
    let off = r - AZ_ENDPOINT_INDEX;
    match off % AZ_ENDPOINT_STRIDE {
        0 => Some(((off / AZ_ENDPOINT_STRIDE) as usize, false)),
        1 => Some(((off / AZ_ENDPOINT_STRIDE) as usize, true)),
        _ => None,
    }
}
impl Io for Fake {
    fn read(&mut self, reg: Reg) -> u32 {
        if self.gone == Some(reg) {
            return u32::MAX;
        }
        match endpoint_of(reg) {
            Some((e, true)) => self.ep[e][self.index[e] as usize & 0x7f],
            Some((e, false)) => self.index[e],
            None => self.regs.get(&reg).copied().unwrap_or(0),
        }
    }
    fn write(&mut self, reg: Reg, value: u32) {
        self.log.push((reg, value));
        self.writes.fetch_add(1, Ordering::Relaxed);
        match endpoint_of(reg) {
            Some((e, true)) => self.ep[e][self.index[e] as usize & 0x7f] = value,
            Some((e, false)) => self.index[e] = value,
            None => {
                self.regs.insert(reg, value);
            }
        }
    }
}
impl Fake {
    fn reg(&self, reg: Reg) -> u32 {
        self.regs.get(&reg).copied().unwrap_or(0)
    }
    fn b2(&self, r: u64) -> u32 {
        self.reg(Reg::Bank2(r))
    }
    /// Log position of the first write of `value & mask` to `reg`.
    fn first(&self, reg: Reg, mask: u32, value: u32) -> Option<usize> {
        self.log
            .iter()
            .position(|&(r, v)| r == reg && v & mask == value)
    }
    /// Position of the first endpoint data write to `ix` on `e`.
    fn az_first(&self, e: u8, ix: u32, mask: u32, value: u32) -> Option<usize> {
        let data = Engine::<Fake>::az_data(e);
        let index = Engine::<Fake>::az_index(e);
        let mut latched = None;
        for (i, &(r, v)) in self.log.iter().enumerate() {
            if r == index {
                latched = Some(v);
            } else if r == data && latched == Some(ix) && v & mask == value {
                return Some(i);
            }
        }
        None
    }
}

/// Counts the PME workaround and remembers how many writes preceded each.
struct Wake {
    writes: Arc<AtomicUsize>,
    at: Vec<usize>,
    pending: bool,
}
impl AzaliaWake for Wake {
    fn wake_azalia(&mut self) -> impl Future<Output = ()> + Send {
        self.at.push(self.writes.load(Ordering::Relaxed));
        let pending = self.pending;
        async move {
            if pending {
                core::future::pending::<()>().await;
            }
        }
    }
}

fn engine() -> (Engine<Fake>, Wake) {
    let writes = Arc::new(AtomicUsize::new(0));
    let fake = Fake {
        regs: BTreeMap::new(),
        ep: [[0; 0x80]; 8],
        index: [0; 8],
        log: Vec::new(),
        writes: writes.clone(),
        gone: None,
    };
    let mut e = Engine::new_with(fake, Cap::bootstrap());
    // The host's codec: every port pin a jack (Pin Default 0x185600f0).
    for ep in 0..8 {
        e.io.ep[ep][AZ_CONFIG_DEFAULT as usize] = 0x1856_00f0;
    }
    (
        e,
        Wake {
            writes,
            at: Vec::new(),
            pending: false,
        },
    )
}
/// OTG `otg` running with DIG `dig` routed to it, as the video owner leaves it.
fn live(e: &mut Engine<Fake>, otg: u8, dig: u8) {
    e.io.regs.insert(otg_control(otg), OTG_MASTER_EN);
    e.io.regs.insert(dig_reg(dig, DIG_FE_CNTL), u32::from(otg));
}
fn timing(pixel_clock_khz: u32, h: (u32, u32), v: (u32, u32)) -> Timing {
    Timing {
        pixel_clock_khz,
        h_active: h.0,
        h_total: h.1,
        h_front_porch: 88,
        h_sync_width: 44,
        v_active: v.0,
        v_total: v.1,
        v_front_porch: 4,
        v_sync_width: 5,
        h_sync_positive: true,
        v_sync_positive: true,
    }
}
fn p1080() -> Timing {
    timing(148_500, (1920, 2200), (1080, 1125))
}
fn vga() -> Timing {
    timing(25_175, (640, 800), (480, 525))
}
/// 7.1 LPCM (16/20/24-bit, every rate) and 5.1 AC-3 at 640 kbit/s, speakers
/// FL/FR LFE FC RL/RR RLC/RRC with Supports_AI, named "DELL".
fn sink() -> AudioInfo {
    let mut modes = [AudioMode::default(); 16];
    modes[0] = AudioMode {
        format: 1,
        channels: 8,
        rates: 0x7f,
        byte2: 7,
    };
    modes[1] = AudioMode {
        format: 2,
        channels: 6,
        rates: 0x07,
        byte2: 0x50,
    };
    let mut name = [0u8; 18];
    name[..4].copy_from_slice(b"DELL");
    AudioInfo {
        manufacturer_id: 0xac10,
        product_id: 0x4321,
        name,
        speakers: 0x80 | 0x4f,
        modes,
        mode_count: 2,
        video_latency: 21,
        audio_latency: 1,
    }
}
fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}

fn dcn30_audio_hdmi_lpcm_follows_linux_order() -> TestResult {
    let (mut e, mut wake) = engine();
    live(&mut e, 1, 2);
    let Ok(a) = run(e.start(AudioStream::hdmi(1, 2, p1080()), sink(), &mut wake)) else {
        return TestResult::Fail("HDMI audio start");
    };
    if a.endpoint != 2 || a.dp || a.channels != 0xff || !a.hbr {
        return TestResult::Fail("endpoint follows the DIG; 7.1 with HBR");
    }
    let f = &e.io;
    // dce_aud_hw_init on endpoint 0's globals.
    if f.b2(0x40b) & 0xfff != 0x70 || f.b2(0x40d) & 0xc000_0000 != 0xc000_0000 {
        return TestResult::Fail("hw_init rate capabilities and power states");
    }
    // DTO0 from OTG1's 148.5 MHz: source select 1, DTO_SEL 0, module in
    // 100 Hz, 24 MHz phase.
    if f.reg(Reg::Bank1(0xab)) & 0x37 != 1
        || f.reg(Reg::Bank1(0xad)) != 1_485_000
        || f.reg(Reg::Bank1(0xac)) != 240_000
    {
        return TestResult::Fail("DTO0");
    }
    // DIG2/AFMT2: clock, channel status, delay, ACR auto with the 148.5
    // table row, endpoint 2 as the source, all eight channels.
    if f.b2(0x22af) & 1 != 1
        || f.b2(0x2282) & AFMT_60958_CS_UPDATE == 0
        || f.b2(0x2278) & 0x30f0_0000 != 0x0010_0000
        || f.b2(0x2279) & 0x00f0_0000 != 0x0020_0000
        || f.b2(0x227f) & 0x00ff_ffff != 0x0087_6543
        || f.b2(0x2295) & 0x30 != 0x10
        || f.b2(0x2296) & ACR_CONTROL != 0x1000
        || f.b2(0x22a7) != 148_500 << 12
        || f.b2(0x22a8) != 4096
        || f.b2(0x22a9) != 165_000 << 12
        || f.b2(0x22aa) != 6272
        || f.b2(0x22ab) != 148_500 << 12
        || f.b2(0x22ac) != 6144
        || f.b2(0x2285) != 2
        || f.b2(0x2275) & 0xff00 != 0xff00
    {
        return TestResult::Fail("HDMI AFMT and ACR");
    }
    // Audio InfoFrame sent on line 2, AUDIO_INFO latched.
    if f.b2(0x2298) & 0x10 == 0 || f.b2(0x2299) & 0x3f00 != 0x200 || f.b2(0x2283) & 0x80 == 0 {
        return TestResult::Fail("audio InfoFrame");
    }
    // Endpoint 2: what the codec turns into the ELD.
    let ep = &f.ep[2];
    if ep[0x25] != 0x4f | HDMI_CONNECTION
        || ep[0x27] & 0x40 == 0
        || ep[0x28] != 0x7f07_7f07
        || ep[0x29] != 0x0050_0705
        || ep[0x2a..0x36].iter().any(|w| *w != 0)
        || ep[0x37] != 21 | 1 << 8
        || ep[0x38] & 1 != 1
        || ep[0x3a] != 0xac10 | 0x4321 << 16
        || ep[0x3b] != 5
        || ep[0x3c] != PORT_ID[0]
        || ep[0x3d] != PORT_ID[1]
        || ep[0x3e] != u32::from_le_bytes(*b"DELL")
        || ep[0x54] & (AUDIO_ENABLED | CLOCK_GATING_DISABLE) != AUDIO_ENABLED
        || f.b2(0x40c) != 5
    {
        return TestResult::Fail("Azalia endpoint");
    }
    // Other endpoints untouched beyond the scan.
    if f.ep[0][0x25] != 0 || f.ep[3][0x54] != 0 {
        return TestResult::Fail("foreign endpoint written");
    }
    // Order: DTO select → module → phase → encoder → endpoint → InfoFrame
    // → PME workaround → AUDIO_ENABLED → unmute (sample send) last.
    let order = [
        f.first(Reg::Bank1(0xab), 0x37, 1),
        f.first(Reg::Bank1(0xad), u32::MAX, 1_485_000),
        f.first(Reg::Bank1(0xac), u32::MAX, 240_000),
        f.first(Reg::Bank2(0x22af), 1, 1),
        f.first(Reg::Bank2(0x2285), 7, 2),
        f.az_first(2, 0x3e, u32::MAX, u32::from_le_bytes(*b"DELL")),
        f.first(Reg::Bank2(0x2298), 0x10, 0x10),
        wake.at.first().copied(),
        f.az_first(2, 0x54, AUDIO_ENABLED, AUDIO_ENABLED),
        f.first(Reg::Bank2(0x2282), 1, 1),
    ];
    if order.iter().any(Option::is_none) || !order.is_sorted() || wake.at.len() != 1 {
        return TestResult::Fail("Linux enable order");
    }
    if e.record(2).map(|r| r.state) != Some(State::Running) {
        return TestResult::Fail("record running");
    }
    if run(e.start(AudioStream::hdmi(1, 2, p1080()), sink(), &mut wake)) != Err(Error::Busy) {
        return TestResult::Fail("double start");
    }
    // Stop: mute, AFMT clock off, PME, InfoFrame off, then the endpoint.
    let before = e.io.log.len();
    if run(e.stop(2, &mut wake)).is_err() || e.record(2).is_some() {
        return TestResult::Fail("stop");
    }
    let f = &e.io;
    let mute = f.log[before..]
        .iter()
        .position(|&(r, v)| r == Reg::Bank2(0x2282) && v & 1 == 0);
    let clock = f.log[before..]
        .iter()
        .position(|&(r, v)| r == Reg::Bank2(0x22af) && v & 1 == 0);
    if mute.is_none()
        || clock.is_none_or(|c| mute.is_some_and(|m| m > c))
        || wake.at.len() != 2
        || f.b2(0x2298) & 0x30 != 0
        || f.ep[2][0x54] & (AUDIO_ENABLED | CLOCK_GATING_DISABLE) != 0
    {
        return TestResult::Fail("stop order and state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-audio",
    dcn30_audio_hdmi_lpcm_follows_linux_order
);

fn dcn30_audio_filters_rates_and_picks_endpoints_like_dc() -> TestResult {
    let (mut e, mut wake) = engine();
    // Endpoint 3 has no physical connection: DC's pool stops at three.
    e.io.ep[3][AZ_CONFIG_DEFAULT as usize] = 1 << 30 | 0x56_00f0;
    live(&mut e, 0, 4);
    live(&mut e, 2, 0);
    // 640x480: 8-channel LPCM keeps only 32/44.1/48 kHz, no HBR; the
    // 25.175 MHz ACR row.
    let Ok(a) = run(e.start(AudioStream::hdmi(0, 4, vga()), sink(), &mut wake)) else {
        return TestResult::Fail("VGA start");
    };
    if a.endpoint != 0 || a.hbr || a.descriptors[0] != 0x0707_0707 {
        return TestResult::Fail("DIG4 beyond the pool takes endpoint 0, rates filtered");
    }
    if e.io.b2(0x24a7) != 28_125 << 12 || e.io.b2(0x24a8) != 4576 || e.io.b2(0x2485) != 0 {
        return TestResult::Fail("25.175 MHz ACR and source");
    }
    // DIG0's own endpoint is taken: the first free one.
    let Ok(b) = run(e.start(AudioStream::hdmi(2, 0, p1080()), sink(), &mut wake)) else {
        return TestResult::Fail("second stream");
    };
    if b.endpoint != 1 || e.io.b2(0x2085) != 1 {
        return TestResult::Fail("first free endpoint");
    }
    // The lowest HDMI pipe (OTG0, VGA) keeps the wall clock.
    if e.io.reg(Reg::Bank1(0xab)) & 0x37 != 0 || e.io.reg(Reg::Bank1(0xad)) != 251_750 {
        return TestResult::Fail("wall clock from the lowest HDMI pipe");
    }
    live(&mut e, 3, 5);
    let mut no_lpcm = sink();
    no_lpcm.modes[0] = no_lpcm.modes[1];
    no_lpcm.mode_count = 1;
    let writes = e.io.log.len();
    if run(e.start(AudioStream::hdmi(3, 5, p1080()), no_lpcm, &mut wake)) != Err(Error::NoLpcm)
        || run(e.start(AudioStream::hdmi(4, 3, p1080()), sink(), &mut wake))
            != Err(Error::NotRunning)
        || e.io.log.len() != writes
    {
        return TestResult::Fail("rejections before any write");
    }
    // Endpoints 0..2 taken: none left in the pool.
    live(&mut e, 4, 2);
    let _ = run(e.start(AudioStream::dp(4, 2, p1080()), sink(), &mut wake));
    if run(e.start(AudioStream::hdmi(3, 5, p1080()), sink(), &mut wake)) != Err(Error::NoEndpoint) {
        return TestResult::Fail("pool exhausted");
    }
    // Stopping VGA hands the clock to OTG2.
    if run(e.stop(4, &mut wake)).is_err()
        || e.io.reg(Reg::Bank1(0xab)) & 0x37 != 2
        || e.io.reg(Reg::Bank1(0xad)) != 1_485_000
    {
        return TestResult::Fail("wall clock moves on stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-audio",
    dcn30_audio_filters_rates_and_picks_endpoints_like_dc
);

fn dcn30_audio_dp_sst_uses_dto1_and_secondary_packets() -> TestResult {
    let (mut e, mut wake) = engine();
    live(&mut e, 0, 1);
    // The video owner sends GSP0 (VSC) without the master enable yet.
    e.io.regs.insert(dig_reg(1, DP_SEC_CNTL), 1 << 20);
    let Ok(a) = run(e.start(AudioStream::dp(0, 1, vga()), sink(), &mut wake)) else {
        return TestResult::Fail("DP start");
    };
    let f = &e.io;
    // DP SST over 8b/10b: no rate filter even at 640x480; HBR capable.
    if !a.dp || a.endpoint != 1 || a.descriptors[0] != 0x7f07_7f07 || !a.hbr {
        return TestResult::Fail("DP descriptors");
    }
    // DTO1 from the 730 MHz DPREFCLK with 512 Fs, DTO_SEL 1.
    let src = f.reg(Reg::Bank1(0xab));
    if src & 0x30 != 0x10
        || src & DTO2_USE_512FBR_DTO == 0
        || f.reg(Reg::Bank1(0xaf)) != 7_300_000
        || f.reg(Reg::Bank1(0xae)) != 240_000
        || f.reg(Reg::Bank1(0xad)) != 0
    {
        return TestResult::Fail("DTO1");
    }
    // DP1: AUD_N default, auto timestamps, packets, no HDMI ACR or
    // InfoFrame writes; endpoint says DP.
    if f.b2(0x2231) != 0x8000
        || f.b2(0x2235) != 1
        || f.b2(0x222b) != 1 << 20 | 0x1111
        || f.b2(0x21af) & 1 != 1
        || f.b2(0x2185) != 1
        || f.b2(0x2182) & 1 != 1
        || f.b2(0x2196) != 0
        || f.b2(0x2198) != 0
        || f.ep[1][0x25] != 0x4f | DP_CONNECTION
    {
        return TestResult::Fail("DP secondary packets");
    }
    // enc1_se_enable_dp_audio: ASP, then ATP+AIP, then the master.
    let sec = Reg::Bank2(0x222b);
    let order = [
        f.first(sec, 0x1111, 0x0010),
        f.first(sec, 0x1111, 0x1110),
        f.first(sec, 0x1111, 0x1111),
    ];
    let enabled = f.az_first(1, 0x54, AUDIO_ENABLED, AUDIO_ENABLED);
    if order.iter().any(Option::is_none)
        || !order.is_sorted()
        || enabled.is_none_or(|en| order[0].is_some_and(|o| o < en))
    {
        return TestResult::Fail("DP enable order");
    }
    // An HDMI display joins: the wall clock switches to its DTO0.
    live(&mut e, 2, 3);
    if run(e.start(AudioStream::hdmi(2, 3, p1080()), sink(), &mut wake)).is_err()
        || e.io.reg(Reg::Bank1(0xab)) & 0x37 != 2
    {
        return TestResult::Fail("HDMI takes the wall clock");
    }
    // DP stop keeps the master on for the video's GSP0, clears the audio.
    if run(e.stop(1, &mut wake)).is_err()
        || e.io.b2(0x222b) != 1 << 20 | 1
        || e.io.b2(0x21af) & 1 != 0
        || e.io.ep[1][0x54] & AUDIO_ENABLED != 0
    {
        return TestResult::Fail("DP stop");
    }
    // HDMI gone: DP-only would select DTO1 again; none left keeps it.
    if run(e.stop(3, &mut wake)).is_err() || e.io.reg(Reg::Bank1(0xab)) & 0x37 != 2 {
        return TestResult::Fail("no audio leaves the clock");
    }
    // A DP stream whose audio packets are already on is not claimed.
    e.io.regs.insert(dig_reg(1, DP_SEC_CNTL), DP_SEC_ASP_ENABLE);
    if run(e.start(AudioStream::dp(0, 1, vga()), sink(), &mut wake)) != Err(Error::Busy) {
        return TestResult::Fail("live DP audio claimed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-audio",
    dcn30_audio_dp_sst_uses_dto1_and_secondary_packets
);

fn dcn30_audio_failure_and_cancellation_retain_the_record() -> TestResult {
    let (mut e, mut wake) = engine();
    live(&mut e, 0, 0);
    // The InfoFrame line register reads as a vanished device.
    e.io.gone = Some(Reg::Bank2(0x2099));
    if run(e.start(AudioStream::hdmi(0, 0, p1080()), sink(), &mut wake)) != Err(Error::DeviceGone) {
        return TestResult::Fail("failure surfaces");
    }
    if e.record(0).map(|r| r.state)
        != Some(State::Failed {
            step: Step::InfoFrame,
            error: Error::DeviceGone,
        })
    {
        return TestResult::Fail("failed record retained with its step");
    }
    let writes = e.io.log.len();
    if run(e.start(AudioStream::hdmi(0, 0, p1080()), sink(), &mut wake)) != Err(Error::Busy)
        || e.io.log.len() != writes
        || !wake.at.is_empty()
    {
        return TestResult::Fail("no replay");
    }
    // Another stream still starts beside the retained record.
    live(&mut e, 1, 1);
    match run(e.start(AudioStream::hdmi(1, 1, p1080()), sink(), &mut wake)) {
        Ok(a) if a.endpoint == 1 => {}
        _ => return TestResult::Fail("second stream"),
    }
    let _ = run(e.stop(1, &mut wake));
    // Stop quiesces the failed record; with the fault gone it releases it.
    e.io.gone = None;
    if run(e.stop(0, &mut wake)).is_err() || e.record(0).is_some() {
        return TestResult::Fail("stop releases a failed record");
    }
    // A stop that hits a fault keeps going: the endpoint is still disabled.
    let _ = run(e.start(AudioStream::hdmi(0, 0, p1080()), sink(), &mut wake));
    e.io.gone = Some(Reg::Bank2(0x20af));
    if run(e.stop(0, &mut wake)) != Err(Error::DeviceGone)
        || e.io.ep[0][0x54] & AUDIO_ENABLED != 0
        || e.io.b2(0x2082) & 1 != 0
        || e.record(0).map(|r| r.state)
            != Some(State::Failed {
                step: Step::Disable,
                error: Error::DeviceGone,
            })
    {
        return TestResult::Fail("stop past a failing step");
    }
    e.io.gone = None;
    let _ = run(e.stop(0, &mut wake));
    // Cancelled at the PME workaround: retained in Programming(Enable),
    // endpoint never enabled; stop still works afterwards.
    wake.pending = true;
    {
        let mut fut = pin!(e.start(AudioStream::hdmi(0, 0, p1080()), sink(), &mut wake));
        let mut cx = Context::from_waker(Waker::noop());
        if fut.as_mut().poll(&mut cx) != Poll::Pending {
            return TestResult::Fail("pending wake");
        }
    }
    wake.pending = false;
    if e.record(0).map(|r| r.state) != Some(State::Programming(Step::Enable))
        || e.io.ep[0][0x54] & AUDIO_ENABLED != 0
    {
        return TestResult::Fail("cancellation retained");
    }
    if run(e.stop(0, &mut wake)).is_err() || e.record(0).is_some() {
        return TestResult::Fail("stop after cancellation");
    }
    // Revoked authority: nothing is written.
    let (mut e, mut wake) = engine();
    live(&mut e, 0, 0);
    let cap = Cap::bootstrap();
    e.authority = cap;
    cap.revoke();
    if run(e.start(AudioStream::hdmi(0, 0, p1080()), sink(), &mut wake)) != Err(Error::Revoked)
        || !e.io.log.is_empty()
    {
        return TestResult::Fail("revoked");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-audio",
    dcn30_audio_failure_and_cancellation_retain_the_record
);

fn dcn30_audio_sink_without_audio_assigns_nothing() -> TestResult {
    // A base-only EDID: no CTA audio block, so no endpoint (Linux leaves
    // stream_res.audio NULL).
    let mut edid = [0u8; 128];
    edid[..8].copy_from_slice(&[0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0]);
    if crate::amdgpu_navi48_boot::sink_audio_info(&edid).is_some() {
        return TestResult::Fail("audio from a base EDID");
    }
    let (_, ac3) = match plan(&AudioStream::hdmi(0, 0, p1080()), &sink(), 0) {
        Ok(p) => p,
        Err(_) => return TestResult::Fail("plan"),
    };
    if !ac3 {
        return TestResult::Fail("AC-3 flag");
    }
    let mut empty = sink();
    empty.mode_count = 0;
    if plan(&AudioStream::hdmi(0, 0, p1080()), &empty, 0) != Err(Error::Invalid) {
        return TestResult::Fail("empty audio info");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn30-audio",
    dcn30_audio_sink_without_audio_assigns_nothing
);

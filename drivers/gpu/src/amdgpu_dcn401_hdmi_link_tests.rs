use super::*;
use crate::{
    amdgpu_dcn_inventory::{Connector, Path},
    amdgpu_dmub_navi48 as dmub,
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

const ENABLED: u8 = 1;
const DISABLED: u8 = 2;

fn dio(p: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(p) * 0x124) * 4
}
fn phy(p: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(p) * 0xd8) * 4
}
fn resync(p: u8) -> u64 {
    (0x16240 + u64::from(p)) * 4
}
fn path(p: u8) -> Path {
    Path {
        connector: Connector::HdmiTypeA,
        connector_instance: 1,
        transmitter: p,
        aux: Some(p),
        hpd: (p + 1) % 4 + 1,
        device_tag: 2,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Command {
    Clock(Path, u8, u32),
    Setup(u8, u32),
    Enable(Path, u32),
    Disable(Path),
}
struct Firmware {
    ready: bool,
    /// Each command with the number of register writes before it.
    commands: Vec<(Command, usize)>,
    event: Arc<AtomicU8>,
    writes: Arc<AtomicUsize>,
    fail: Option<(usize, dmub::Error)>,
}
impl Firmware {
    fn issue(&mut self, c: Command, event: u8) -> Result<(), dmub::Error> {
        self.commands.push((c, self.writes.load(Ordering::SeqCst)));
        if let Some((n, e)) = self.fail {
            if n + 1 == self.commands.len() {
                return Err(e);
            }
        }
        if event != 0 {
            self.event.store(event, Ordering::SeqCst);
        }
        Ok(())
    }
}
impl crate::amdgpu_dcn401_otg::hdmi_link::Firmware for Firmware {
    fn ready(&self) -> bool {
        self.ready
    }
    async fn pixel_clock(&mut self, path: Path, pipe: u8, khz: u32) -> Result<(), dmub::Error> {
        self.issue(Command::Clock(path, pipe, khz), 0)
    }
    async fn stream_setup(&mut self, stream: u8, khz: u32) -> Result<(), dmub::Error> {
        self.issue(Command::Setup(stream, khz), 0)
    }
    async fn enable(&mut self, path: Path, khz: u32) -> Result<(), dmub::Error> {
        self.issue(Command::Enable(path, khz), ENABLED)
    }
    async fn disable(&mut self, path: Path) -> Result<(), dmub::Error> {
        self.issue(Command::Disable(path), DISABLED)
    }
}
/// Firmware-owned transmitter effects and the frontend clock/FIFO handshakes.
struct TmdsIo {
    inner: Fake,
    phy: u8,
    stream: u8,
    event: Arc<AtomicU8>,
    writes: Arc<AtomicUsize>,
    on: bool,
    /// The transmitter never reports its lanes.
    dead: bool,
}
impl TmdsIo {
    fn reg(&self, at: u64) -> u32 {
        self.inner.regs.get(&at).copied().unwrap_or(0)
    }
    fn set(&mut self, at: u64, clear: u32, set: u32) {
        let v = (self.reg(at) & !clear) | set;
        self.inner.regs.insert(at, v);
    }
}
impl Io for TmdsIo {
    fn read(&mut self, at: u64) -> u32 {
        let (p, s) = (self.phy, self.stream);
        match self.event.swap(0, Ordering::SeqCst) {
            ENABLED if !self.dead => {
                self.on = true;
                self.set(phy(p, 0x2943), 0x3f3f3f3f, 0x0c0c0c0c);
                self.set(phy(p, 0x2931), 0, 0x6f0);
                if self.reg(dio(p, 0x20bb)) & 0x10 != 0 {
                    self.set(dio(p, 0x20bb), 0, 0x2800);
                }
                if self.reg(dio(s, 0x2094)) & 0x10 != 0 {
                    self.set(dio(s, 0x2094), 0, 0x2800);
                }
            }
            DISABLED => {
                self.on = false;
                self.set(dio(p, 0x20bd), 1, 0);
                self.set(dio(p, 0x20bb), 0x3870, 0);
                self.set(phy(p, 0x2943), 0x3f3f3f3f, 0x02020202);
                self.set(phy(p, 0x2931), 0x6f0, 0);
                self.set(dio(s, 0x2094), 0x2800, 0);
            }
            _ => {}
        }
        if at == dio(s, 0x209b) && self.reg(dio(s, 0x2094)) & 0x800 != 0 {
            let done = (self.reg(at) & 2) << 19;
            self.set(at, 0x100000, done);
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.write(at, value);
        // VPG GSP memory leaves light sleep once sleep is disabled.
        if at == dio(self.stream, 0x206d) && value & 1 != 0 {
            self.set(at, 0x100, 0);
        }
        if at == dio(self.stream, 0x2094) {
            if value & 0x10 != 0 {
                let symclk = if self.on { 0x800 } else { 0 };
                self.set(at, 0, 0x400 | symclk);
            } else {
                self.set(at, 0x2c00, 0);
            }
        }
    }
}
fn tmds_clock(pipe: u8, khz: u32, divider: dccg::TmdsDivider) -> (Request, dccg::Applied) {
    let mut req = request(pipe);
    req.signal = Signal::Tmds;
    req.timing.pixel_clock_khz = khz;
    let mut c = clock(req);
    c.request.pixel = dccg::PixelClock::Tmds { divider };
    (req, c)
}
fn fixture(p: u8, stream: u8, pipe: u8) -> (Engine<TmdsIo>, Firmware, dccg::Applied) {
    fixture_with(
        p,
        stream,
        pipe,
        148_500,
        ColorDepth::Bpc8,
        dccg::TmdsDivider::By4,
    )
}
fn fixture_with(
    p: u8,
    stream: u8,
    pipe: u8,
    khz: u32,
    depth: ColorDepth,
    divider: dccg::TmdsDivider,
) -> (Engine<TmdsIo>, Firmware, dccg::Applied) {
    let mut e = engine();
    let (req, c) = tmds_clock(pipe, khz, divider);
    run(e.prepare(req, c)).unwrap();
    run(e.prepare_blank(BlankRequest { pipe, depth }, c)).unwrap();
    for i in 0..4 {
        e.io.regs.insert(phy(i, 0x2943), 0x03030303);
    }
    e.io.regs.insert(dio(p, 0x20bc), 3 << 28); // stale HPD select, no frontend
    e.io.regs.insert(resync(p), 0x30);
    // Power-gated HUBPs: no fetcher can run under the black video.
    for i in 0..4u64 {
        e.io.regs.insert(BASE + (0x80 + 2 * i) * 4, 0x100);
        e.io.regs.insert(BASE + (0x81 + 2 * i) * 4, 0x80000000);
    }
    e.io.encoder_stall = 1 << stream; // TmdsIo supplies the clock witnesses
    let event = Arc::new(AtomicU8::new(0));
    let writes = Arc::new(AtomicUsize::new(0));
    let fw = Firmware {
        ready: true,
        commands: Vec::new(),
        event: event.clone(),
        writes: writes.clone(),
        fail: None,
    };
    let engine = Engine {
        io: TmdsIo {
            inner: e.io,
            phy: p,
            stream,
            event,
            writes,
            on: false,
            dead: false,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
    };
    (engine, fw, c)
}
fn link(stream: u8, pipe: u8) -> HdmiLinkRequest {
    HdmiLinkRequest { stream, pipe }
}

fn dcn401_hdmi_link_programs_native_order_registers_and_commands() -> TestResult {
    for (p, stream, pipe) in [(0, 0, 0), (1, 3, 2), (2, 1, 3), (3, 2, 1)] {
        let (mut e, mut fw, c) = fixture(p, stream, pipe);
        let ready = run(e.prepare_hdmi_link(&mut fw, path(p), link(stream, pipe), c)).unwrap();
        if e.status.state != State::HdmiLinkReady(p) || e.status.hdmi_link_ready != Some(ready) {
            return TestResult::Fail("state");
        }
        let cmds: Vec<Command> = fw.commands.iter().map(|c| c.0).collect();
        if cmds
            != [
                Command::Clock(path(p), pipe, 148_500),
                Command::Setup(stream, 148_500),
                Command::Enable(path(p), 148_500),
            ]
        {
            return TestResult::Fail("firmware commands");
        }
        // PHY PLL first, before any register write; the stream setup follows
        // the link encoder setup; the transmitter comes last.
        let at: Vec<usize> = fw.commands.iter().map(|c| c.1).collect();
        if at[0] != 0 || !(at[0] < at[1] && at[1] < at[2]) {
            return TestResult::Fail("command order");
        }
        let r = |at| e.io.inner.regs.get(&at).copied().unwrap_or(0);
        let hpd = u32::from(path(p).hpd - 1) << 28;
        for (at, mask, value) in [
            (BASE + (0x179a + 3 * u64::from(p)) * 4, 3, 0),
            (dio(p, 0x20bc), 0x70007f01, hpd | 0x100 << stream),
            (dio(p, 0x20bb), 0x817, 0x813), // HDMI mode, clock on
            (dio(p, 0x20bd), 1, 1),
            (dio(p, 0x20eb), 1, 1),
            (resync(p), 0x30, 0),
            (dio(stream, 0x2093), 0x177, (u32::from(pipe) * 0x11) | 0x100),
            (dio(stream, 0x2094), 0xc37, 0xc13),
            (dio(stream, 0x2095), 1, 1),
            (dio(stream, 0x209b), 0x1003ff, 0x1d), // enabled, start level 7, 1 ppc
            (BASE + (0x1f0d + u64::from(stream)) * 4, 7, u32::from(p)),
            (dio(stream, 0x209e), 0x3100701f, 0x19),
            (dio(stream, 0x20a2), 0x1031, 0x31),
            (dio(stream, 0x20a8), 1, 0),
            (phy(p, 0x2931), 0x6f0, 0x6f0),
            (BASE + (0x1b43 + 0x80 * u64::from(pipe)) * 4, 0x10001, 0),
        ] {
            if r(at) & mask != value {
                return TestResult::Fail("register");
            }
        }
        // The AVI InfoFrame went to VPG packet 0 as nine data words, then
        // packet 0 is sent every frame on line 2 with double buffering off.
        let words: Vec<u32> =
            e.io.inner
                .writes
                .iter()
                .filter(|w| w.0 == dio(stream, 0x2069))
                .map(|w| w.1)
                .collect();
        if words != [0x000d0282, 0x80081ebe, 0, 0x466, 0x899, 0, 0, 0, 0]
            || r(dio(stream, 0x20a5)) != 3
            || r(dio(stream, 0x20a9)) & 0xffff != 2
            || r(dio(stream, 0x20b1)) & 0x1000 == 0
            || r(dio(stream, 0x206b)) & 1 != 1
            || r(dio(stream, 0x2068)) & 0xff != 0
        {
            return TestResult::Fail("AVI InfoFrame");
        }
        // Linux leaves the DCCG frontend symclk route alone for TMDS.
        if r(e.layout.dio_clock + u64::from(stream) * 4) != 0 {
            return TestResult::Fail("symclk route touched");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_hdmi_link_programs_native_order_registers_and_commands
);

fn dcn401_hdmi_link_refuses_unsupported_or_busy_requests_without_writes() -> TestResult {
    type Case = fn(&mut Engine<TmdsIo>, &mut Firmware, &mut Path, &mut dccg::Applied);
    let cases: [(Case, Error); 9] = [
        (
            |_, _, p, _| p.connector = Connector::DisplayPort,
            Error::Unsupported,
        ),
        (|_, _, p, _| p.hpd = 0, Error::Invalid),
        (|_, fw, _, _| fw.ready = false, Error::Busy),
        (
            |e, _, _, _| {
                e.io.inner.regs.insert(phy(1, 0x2943), 0x0c0c0c0c);
            },
            Error::Readback(phy(1, 0x2943)),
        ),
        (
            |e, _, _, _| {
                e.io.inner.regs.insert(dio(1, 0x20bc), 0x400);
            },
            Error::Busy,
        ),
        (
            |e, _, _, _| {
                e.io.inner.regs.insert(dio(3, 0x20bc), 0x100 << 2);
            },
            Error::Busy,
        ),
        (
            |e, _, _, _| {
                let at = e.layout.dio_clock + 2 * 4;
                e.io.inner.regs.insert(at, 0x110);
            },
            Error::Busy,
        ),
        (
            |e, _, _, _| {
                e.io.inner.regs.insert(dio(2, 0x20a5), 1);
            },
            Error::Busy,
        ),
        (
            |e, _, _, _| {
                e.io.inner.regs.insert(dio(1, 0x20bd), 1);
            },
            Error::Busy,
        ),
    ];
    for (case, expected) in cases {
        let (mut e, mut fw, mut c) = fixture(1, 2, 3);
        let mut p = path(1);
        case(&mut e, &mut fw, &mut p, &mut c);
        let writes = e.io.inner.writes.len();
        let state = e.status.state;
        let result = run(e.prepare_hdmi_link(&mut fw, p, link(2, 3), c));
        if result != Err(expected) {
            return TestResult::Fail("refusal");
        }
        if e.io.inner.writes.len() != writes || e.status.state != state || !fw.commands.is_empty() {
            return TestResult::Fail("refusal wrote");
        }
    }
    // Deep colour, a YCbCr 4:2:0 divider and modes beyond 340 MHz (which
    // need SCDC scrambling) are refused before any write.
    for (khz, depth, divider) in [
        (594_000, ColorDepth::Bpc8, dccg::TmdsDivider::By4),
        (148_500, ColorDepth::Bpc10, dccg::TmdsDivider::By4),
        (148_500, ColorDepth::Bpc8, dccg::TmdsDivider::By2),
        (20_000, ColorDepth::Bpc8, dccg::TmdsDivider::By4),
    ] {
        let (mut e, mut fw, c) = fixture_with(0, 0, 0, khz, depth, divider);
        let writes = e.io.inner.writes.len();
        if run(e.prepare_hdmi_link(&mut fw, path(0), link(0, 0), c)) != Err(Error::Unsupported)
            || e.io.inner.writes.len() != writes
        {
            return TestResult::Fail("unsupported mode");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_hdmi_link_refuses_unsupported_or_busy_requests_without_writes
);

fn dcn401_hdmi_video_mutes_stops_and_the_link_stops_and_restarts() -> TestResult {
    let (p, stream, pipe) = (2, 1, 0);
    let (mut e, mut fw, c) = fixture(p, stream, pipe);
    run(e.prepare_hdmi_link(&mut fw, path(p), link(stream, pipe), c)).unwrap();
    // AVMUTE was cleared by the stream setup; video releases it again.
    let running = run(e.start_hdmi_video(path(p), c)).unwrap();
    let r = |e: &Engine<TmdsIo>, at| e.io.inner.regs.get(&at).copied().unwrap_or(0);
    let otg = BASE + (0x1b43 + 0x80 * u64::from(pipe)) * 4;
    if e.status.state != State::HdmiVideoRunning(stream)
        || running.link.request != link(stream, pipe)
        || r(&e, otg) & 0x10001 != 0x10001
        || r(&e, dio(stream, 0x20a8)) & 1 != 0
        || r(&e, dio(stream, 0x209b)) & 0x100003 != 1
    {
        return TestResult::Fail("video running");
    }
    // Scanout may start on HDMI video exactly as on DP video.
    if e.running_video() != Ok((stream, pipe)) {
        return TestResult::Fail("video for scanout");
    }
    // Video is the only state that may stop video; the link cannot stop under it.
    assert_eq!(run(e.stop_hdmi_link(&mut fw, path(p))), Err(Error::Busy));
    run(e.stop_hdmi_video(path(p))).unwrap();
    if e.status.state != State::HdmiLinkReady(p)
        || r(&e, otg) & 0x10001 != 0
        || r(&e, dio(stream, 0x20a8)) & 1 != 1
        || e.status.hdmi_video_running.is_some()
    {
        return TestResult::Fail("video stopped");
    }
    run(e.stop_hdmi_link(&mut fw, path(p))).unwrap();
    if e.status.state != State::HdmiLinkStopped
        || !e.status.state.reusable()
        || fw.commands.last().map(|c| c.0) != Some(Command::Disable(path(p)))
        || r(&e, dio(p, 0x20bd)) & 1 != 0
        || r(&e, dio(p, 0x20bc)) & 0x7f00 != 0
        || r(&e, dio(stream, 0x2094)) & 0x2c10 != 0
        || r(&e, dio(stream, 0x2095)) & 1 != 0
        || r(&e, dio(stream, 0x209b)) & 0x301 != 0
        || r(&e, dio(stream, 0x209e)) & 0x0100001f != 0x11
        || r(&e, dio(stream, 0x20a5)) != 0
        || r(&e, dio(stream, 0x20a9)) & 0xffff != 0
    {
        return TestResult::Fail("link stopped");
    }
    // The stopped link is reusable: the same port relights from scratch.
    fw.commands.clear();
    run(e.prepare_hdmi_link(&mut fw, path(p), link(stream, pipe), c)).unwrap();
    run(e.start_hdmi_video(path(p), c)).unwrap();
    if fw.commands.len() != 3 || e.status.state != State::HdmiVideoRunning(stream) {
        return TestResult::Fail("relight");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_hdmi_video_mutes_stops_and_the_link_stops_and_restarts
);

fn dcn401_hdmi_link_failures_quarantine_the_owner() -> TestResult {
    // A refused firmware command, then a transmitter that never reports lanes.
    for n in 0..3 {
        let (mut e, mut fw, c) = fixture(0, 0, 1);
        fw.fail = Some((n, dmub::Error::Busy));
        let result = run(e.prepare_hdmi_link(&mut fw, path(0), link(0, 1), c));
        let failed = Error::Firmware(dmub::Error::Busy);
        if result != Err(failed) || e.status.state != State::Failed(failed) {
            return TestResult::Fail("firmware failure");
        }
        if fw.commands.len() != n + 1 {
            return TestResult::Fail("commands after failure");
        }
    }
    let (mut e, mut fw, c) = fixture(0, 0, 1);
    e.io.dead = true;
    let result = run(e.prepare_hdmi_link(&mut fw, path(0), link(0, 1), c));
    if result != Err(Error::Timeout(phy(0, 0x2943))) || !matches!(e.status.state, State::Failed(_))
    {
        return TestResult::Fail("dead transmitter");
    }
    // A failed owner never starts video or stops the link.
    assert_eq!(run(e.start_hdmi_video(path(0), c)), Err(Error::Invalid));
    assert_eq!(run(e.stop_hdmi_link(&mut fw, path(0))), Err(Error::Invalid));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_hdmi_link_failures_quarantine_the_owner
);

fn dcn401_hdmi_avi_infoframe_matches_linux_fields_and_checksum() -> TestResult {
    let t = request(0).timing;
    let p = crate::amdgpu_dcn401_otg::hdmi_link::avi_infoframe(&t);
    // CTA-861: the header and payload sum to zero.
    let sum = p[..3]
        .iter()
        .chain(&p[4..18])
        .fold(0u8, |s, b| s.wrapping_add(*b));
    if p[..4] != [0x82, 2, 13, 0]
        || sum != 0
        || p[4] != 0xbe
        || p[5..9] != [0x1e, 0x08, 0x80, 0]
        || p[9] != 0
        || p[12..14] != 1126u16.to_le_bytes()
        || p[16..18] != 2201u16.to_le_bytes()
        || p[18..].iter().any(|b| *b != 0)
    {
        return TestResult::Fail("AVI bytes");
    }
    // A powered-down VPG memory is woken before the packet write.
    let (mut e, mut fw, c) = fixture(1, 1, 1);
    e.io.inner.regs.insert(dio(1, 0x206d), 0x100);
    run(e.prepare_hdmi_link(&mut fw, path(1), link(1, 1), c)).unwrap();
    let wake = e.io.inner.writes.iter().position(|w| w.0 == dio(1, 0x206d));
    let data = e.io.inner.writes.iter().position(|w| w.0 == dio(1, 0x2069));
    if !matches!((wake, data), (Some(a), Some(b)) if a < b) {
        return TestResult::Fail("VPG power-on order");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_hdmi_avi_infoframe_matches_linux_fields_and_checksum
);

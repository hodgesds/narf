use super::*;
use crate::{
    amdgpu_dcn_inventory::{Connector, Path},
    amdgpu_dmub_navi48 as dmub,
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

const ENABLED: u8 = 1;
const DISABLED: u8 = 2;

pub(in crate::amdgpu_dcn401_otg::tests) fn dio(p: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(p) * 0x124) * 4
}
pub(in crate::amdgpu_dcn401_otg::tests) fn phy(p: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(p) * 0xd8) * 4
}
pub(in crate::amdgpu_dcn401_otg::tests) fn resync(p: u8) -> u64 {
    (0x16240 + u64::from(p)) * 4
}
pub(in crate::amdgpu_dcn401_otg::tests) fn path(p: u8) -> Path {
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
pub(in crate::amdgpu_dcn401_otg::tests) enum Command {
    Clock(Path, u8, u32, dmub::TmdsDepth),
    Setup(u8, u32),
    Enable(Path, u32),
    Disable(Path),
}
pub(in crate::amdgpu_dcn401_otg::tests) struct Firmware {
    pub(in crate::amdgpu_dcn401_otg::tests) ready: bool,
    /// Each command with the number of register writes before it.
    pub(in crate::amdgpu_dcn401_otg::tests) commands: Vec<(Command, usize)>,
    pub(in crate::amdgpu_dcn401_otg::tests) event: Arc<AtomicU8>,
    pub(in crate::amdgpu_dcn401_otg::tests) writes: Arc<AtomicUsize>,
    pub(in crate::amdgpu_dcn401_otg::tests) fail: Option<(usize, dmub::Error)>,
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
    async fn pixel_clock(
        &mut self,
        path: Path,
        pipe: u8,
        khz: u32,
        depth: dmub::TmdsDepth,
    ) -> Result<(), dmub::Error> {
        self.issue(Command::Clock(path, pipe, khz, depth), 0)
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
pub(in crate::amdgpu_dcn401_otg::tests) struct TmdsIo {
    pub(in crate::amdgpu_dcn401_otg::tests) inner: Fake,
    pub(in crate::amdgpu_dcn401_otg::tests) phy: u8,
    pub(in crate::amdgpu_dcn401_otg::tests) stream: u8,
    pub(in crate::amdgpu_dcn401_otg::tests) event: Arc<AtomicU8>,
    pub(in crate::amdgpu_dcn401_otg::tests) writes: Arc<AtomicUsize>,
    pub(in crate::amdgpu_dcn401_otg::tests) on: bool,
    /// The transmitter never reports its lanes.
    pub(in crate::amdgpu_dcn401_otg::tests) dead: bool,
    /// Azalia endpoint index/data windows: (endpoint, index) -> value.
    pub(in crate::amdgpu_dcn401_otg::tests) az: alloc::collections::BTreeMap<(u8, u32), u32>,
    pub(in crate::amdgpu_dcn401_otg::tests) az_index: [u32; 4],
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
fn az(e: u8) -> u64 {
    BASE + (0x386 + 6 * u64::from(e)) * 4
}
impl Io for TmdsIo {
    fn read(&mut self, at: u64) -> u32 {
        for e in 0..4u8 {
            if at == az(e) + 4 {
                let i = self.az_index[usize::from(e)];
                return self.az.get(&(e, i)).copied().unwrap_or(0);
            }
        }
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
        for e in 0..4u8 {
            if at == az(e) {
                self.az_index[usize::from(e)] = value;
                return;
            }
            if at == az(e) + 4 {
                self.az.insert((e, self.az_index[usize::from(e)]), value);
                return;
            }
        }
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
pub(in crate::amdgpu_dcn401_otg::tests) fn fixture(
    p: u8,
    stream: u8,
    pipe: u8,
) -> (Engine<TmdsIo>, Firmware, dccg::Applied) {
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
    let (req, c) = tmds_clock(pipe, khz, divider);
    fixture_req(p, stream, pipe, req, c, depth)
}
/// The fixture on a given timing request and its TMDS clock.
fn fixture_req(
    p: u8,
    stream: u8,
    pipe: u8,
    req: Request,
    c: dccg::Applied,
    depth: ColorDepth,
) -> (Engine<TmdsIo>, Firmware, dccg::Applied) {
    let mut e = engine();
    run(e.prepare(req, c)).unwrap();
    run(e.prepare_blank(
        BlankRequest {
            pipe,
            depth,
            limited: false,
            ycbcr420: req.ycbcr420,
        },
        c,
    ))
    .unwrap();
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
            az: alloc::collections::BTreeMap::new(),
            az_index: [0; 4],
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    };
    (engine, fw, c)
}
pub(in crate::amdgpu_dcn401_otg::tests) fn link(stream: u8, pipe: u8) -> HdmiLinkRequest {
    HdmiLinkRequest {
        stream,
        pipe,
        avi: Default::default(),
    }
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
                Command::Clock(path(p), pipe, 148_500, dmub::TmdsDepth::Bpc8),
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
    // Deep colour, a YCbCr 4:2:0 divider and sub-25 MHz modes are refused
    // before any write.
    for (khz, depth, divider) in [
        (594_000, ColorDepth::Bpc10, dccg::TmdsDivider::By4), // 742.5 MHz TMDS
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
    let p =
        crate::amdgpu_dcn401_otg::hdmi_link::avi_infoframe(&t, Default::default(), false, false);
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
    // VIC 16, 16:9, range selectable: SB2 M, SB3 Q and SB4 VIC, still
    // summing to zero. Q is full for full range and limited for limited.
    let avi = crate::amdgpu_dcn401_otg::Avi {
        vic: 16,
        aspect: 2,
        qs: true,
        hdmi_vic: 0,
    };
    let p = crate::amdgpu_dcn401_otg::hdmi_link::avi_infoframe(&t, avi, false, false);
    let sum = |p: &[u8; 36]| {
        p[..3]
            .iter()
            .chain(&p[4..18])
            .fold(0u8, |s, b| s.wrapping_add(*b))
    };
    if p[..4] != [0x82, 2, 13, 0] || p[5..9] != [0x1e, 0x28, 0x88, 16] || sum(&p) != 0 {
        return TestResult::Fail("AVI VIC, aspect and range");
    }
    let p = crate::amdgpu_dcn401_otg::hdmi_link::avi_infoframe(&t, avi, true, false);
    if p[7] != 0x84 || sum(&p) != 0 {
        return TestResult::Fail("AVI limited range");
    }
    // Without QS the range stays at the format's default either way.
    let no_qs = crate::amdgpu_dcn401_otg::Avi { qs: false, ..avi };
    let p = crate::amdgpu_dcn401_otg::hdmi_link::avi_infoframe(&t, no_qs, true, false);
    if p[7] != 0x80 || sum(&p) != 0 {
        return TestResult::Fail("AVI default range");
    }
    // VICs from 128 need version 3.
    let p = crate::amdgpu_dcn401_otg::hdmi_link::avi_infoframe(
        &t,
        crate::amdgpu_dcn401_otg::Avi { vic: 200, ..avi },
        false,
        false,
    );
    if p[1] != 3 || p[8] != 200 || sum(&p) != 0 {
        return TestResult::Fail("AVI version 3");
    }
    // YCbCr 4:2:0 (COLOR_SPACE_YCBCR709): Y 3, C BT.709, Q default even
    // with QS (an RGB range), YQ limited.
    let p = crate::amdgpu_dcn401_otg::hdmi_link::avi_infoframe(&t, avi, false, true);
    if p[5..10] != [0x7e, 0xa8, 0x80, 16, 0] || sum(&p) != 0 {
        return TestResult::Fail("AVI YCbCr 4:2:0");
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

/// A 4K mode with an HDMI 1.4b VIC sends the HDMI vendor InfoFrame
/// (mod_build_hf_vsif_infopacket) in generic packet 1 beside the AVI in 0,
/// every frame on line 2; without an HDMI VIC none is sent, and stopping
/// the video stops both.
fn dcn401_hdmi_vendor_infoframe_carries_the_hdmi_vic() -> TestResult {
    use crate::amdgpu_dcn401_otg::{hdmi_link::vendor_infoframe, Avi};
    let mut uhd = request(1).timing;
    (uhd.pixel_clock_khz, uhd.h_active, uhd.h_total) = (297_000, 3840, 4400);
    (uhd.h_front_porch, uhd.h_sync_width) = (176, 88);
    (
        uhd.v_active,
        uhd.v_total,
        uhd.v_front_porch,
        uhd.v_sync_width,
    ) = (2160, 2250, 8, 10);
    let avi = Avi {
        aspect: 2,
        hdmi_vic: 1,
        ..Default::default()
    };
    // HB0-2, checksum, IEEE OUI 00-0C-03 (LSB first), HDMI_Video_Format 1.
    let Some(p) = vendor_infoframe(&uhd, avi) else {
        return TestResult::Fail("no vendor InfoFrame for an HDMI VIC");
    };
    if p[..10] != [0x81, 1, 5, 0, 0x49, 0x03, 0x0c, 0x00, 0x20, 1]
        || p[10..].iter().any(|b| *b != 0)
    {
        return TestResult::Fail("vendor InfoFrame bytes");
    }
    if vendor_infoframe(&uhd, Avi::default()).is_some()
        || vendor_infoframe(&request(1).timing, avi).is_some()
    {
        return TestResult::Fail("vendor InfoFrame without a 4K HDMI VIC");
    }
    // On the link: packet 1 at data index 9, latched, sent on line 2.
    let mut req = request(1);
    req.signal = Signal::Tmds;
    req.timing = uhd;
    let mut c = clock(req);
    c.request.pixel = dccg::PixelClock::Tmds {
        divider: dccg::TmdsDivider::By4,
    };
    let (mut e, mut fw, c) = fixture_req(1, 1, 1, req, c, ColorDepth::Bpc8);
    let mut request = link(1, 1);
    request.avi = avi;
    if run(e.prepare_hdmi_link(&mut fw, path(1), request, c)).is_err() {
        return TestResult::Fail("4K HDMI link");
    }
    let writes = &e.io.inner.writes;
    let index = writes
        .iter()
        .filter(|w| w.0 == dio(1, 0x2068))
        .map(|w| w.1 & 0xff)
        .collect::<Vec<_>>();
    let latched = writes
        .iter()
        .filter(|w| w.0 == dio(1, 0x206b))
        .fold(0, |acc, w| acc | w.1);
    let vendor_words: Vec<u32> = {
        let at = writes.iter().rposition(|w| w.0 == dio(1, 0x2068)).unwrap();
        writes[at..]
            .iter()
            .filter(|w| w.0 == dio(1, 0x2069))
            .map(|w| w.1)
            .take(3)
            .collect()
    };
    let regs = &e.io.inner.regs;
    if index != [0, 9]
        || latched & 3 != 3
        || vendor_words != [0x0005_0181, 0x000c_0349, 0x0000_0120]
        || regs[&dio(1, 0x20a5)] & 0x33 != 0x33
        || regs[&dio(1, 0x20a9)] != 0x0002_0002
    {
        return TestResult::Fail("vendor packet on the link");
    }
    // A link without an HDMI VIC writes only the AVI.
    let (mut e, mut fw, c) = fixture(1, 1, 1);
    run(e.prepare_hdmi_link(&mut fw, path(1), link(1, 1), c)).unwrap();
    if e.io.inner.regs[&dio(1, 0x20a5)] & 0x30 != 0 || e.io.inner.regs[&dio(1, 0x20a9)] >> 16 != 0 {
        return TestResult::Fail("vendor packet without an HDMI VIC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_hdmi_vendor_infoframe_carries_the_hdmi_vic
);

fn dcn401_hdmi_link_scrambles_above_340_mhz_and_stops_unscrambled() -> TestResult {
    for (khz, bits) in [(340_000, 0), (340_001, 6), (594_000, 6)] {
        let (mut e, mut fw, c) =
            fixture_with(0, 2, 1, khz, ColorDepth::Bpc8, dccg::TmdsDivider::By4);
        let ready = run(e.prepare_hdmi_link(&mut fw, path(0), link(2, 1), c)).unwrap();
        let control = e.io.inner.regs[&dio(2, 0x209e)];
        if ready.scrambled != (bits != 0) || control & 0x0100001f != 0x19 | bits {
            return TestResult::Fail("scrambler and clock-channel rate");
        }
        // The PHY PLL and transmitter take the full pixel rate; firmware
        // applies the 1/4 clock channel, as for Linux's callers.
        if fw.commands[0].0 != Command::Clock(path(0), 1, khz, dmub::TmdsDepth::Bpc8)
            || fw.commands[2].0 != Command::Enable(path(0), khz)
        {
            return TestResult::Fail("scrambled clocks");
        }
        run(e.stop_hdmi_link(&mut fw, path(0))).unwrap();
        if e.io.inner.regs[&dio(2, 0x209e)] & 0x0100001f != 0x11 {
            return TestResult::Fail("scrambler left on");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_hdmi_link_scrambles_above_340_mhz_and_stops_unscrambled
);

fn dcn401_hdmi_link_deep_colour_scales_the_character_clock() -> TestResult {
    use dmub::TmdsDepth::{Bpc10, Bpc12};
    for (depth, tmds, code, khz) in [
        (ColorDepth::Bpc10, Bpc10, 1, 185_625),
        (ColorDepth::Bpc12, Bpc12, 2, 222_750),
    ] {
        let (mut e, mut fw, c) = fixture_with(3, 0, 2, 148_500, depth, dccg::TmdsDivider::By4);
        let ready = run(e.prepare_hdmi_link(&mut fw, path(3), link(0, 2), c)).unwrap();
        let cmds: Vec<Command> = fw.commands.iter().map(|c| c.0).collect();
        // SET_PIXEL_CLOCK takes the pixel clock and ratio; the DIG setup and
        // transmitter take Linux's phy_pix_clk.
        if ready.character_khz != khz
            || ready.scrambled
            || cmds
                != [
                    Command::Clock(path(3), 2, 148_500, tmds),
                    Command::Setup(0, khz),
                    Command::Enable(path(3), khz),
                ]
        {
            return TestResult::Fail("deep-colour clocks");
        }
        let r = |at| e.io.inner.regs.get(&at).copied().unwrap_or(0);
        if r(dio(0, 0x209e)) & 0x3100001f != code << 28 | 0x0100_0000 | 0x19
            || r(resync(3)) & 0x30 != code << 4
        {
            return TestResult::Fail("deep-colour registers");
        }
        run(e.stop_hdmi_link(&mut fw, path(3))).unwrap();
        if e.io.inner.regs[&dio(0, 0x209e)] & 0x0100001f != 0x11 {
            return TestResult::Fail("deep colour left enabled");
        }
    }
    // 297 MHz at 12 bpc is 445.5 MHz TMDS: scrambled.
    let (mut e, mut fw, c) =
        fixture_with(0, 0, 0, 297_000, ColorDepth::Bpc12, dccg::TmdsDivider::By4);
    let ready = run(e.prepare_hdmi_link(&mut fw, path(0), link(0, 0), c)).unwrap();
    if !ready.scrambled || ready.character_khz != 445_500 {
        return TestResult::Fail("deep-colour scrambling");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_hdmi_link_deep_colour_scales_the_character_clock
);

pub(in crate::amdgpu_dcn401_otg::tests) fn audio_info() -> AudioInfo {
    let mut info = AudioInfo {
        manufacturer_id: 0x4c2d,
        product_id: 0x0f99,
        name: [0; 18],
        speakers: 0x0b, // FL/FR, LFE, RL/RR
        modes: [AudioMode::default(); 16],
        mode_count: 2,
        video_latency: 0,
        audio_latency: 0,
    };
    info.name[..2].copy_from_slice(b"TV");
    info.modes[0] = AudioMode {
        format: 1,
        channels: 2,
        rates: 0x07,
        byte2: 0x07,
    };
    info.modes[1] = AudioMode {
        format: 2,
        channels: 6,
        rates: 0x07,
        byte2: 0x50,
    };
    info
}

fn dcn401_hdmi_audio_programs_dto_acr_afmt_and_the_endpoint_like_linux() -> TestResult {
    let (p, stream, pipe) = (1, 2, 3);
    let (mut e, mut fw, c) = fixture(p, stream, pipe);
    run(e.prepare_hdmi_link(&mut fw, path(p), link(stream, pipe), c)).unwrap();
    // Audio follows running video, as Linux's post-enable does.
    assert_eq!(
        run(e.start_hdmi_audio(path(p), audio_info())),
        Err(Error::Busy)
    );
    run(e.start_hdmi_video(path(p), c)).unwrap();
    let a = run(e.start_hdmi_audio(path(p), audio_info())).unwrap();
    let r = |e: &Engine<TmdsIo>, at| e.io.inner.regs.get(&at).copied().unwrap_or(0);
    let bank1 = |reg: u64| (0x16200 + reg) * 4;
    // DTO0 from the pixel clock, phase 24 MHz, sourced by this OTG.
    if r(&e, bank1(0xab)) & 0x37 != u32::from(pipe)
        || r(&e, bank1(0xad)) != 1_485_000
        || r(&e, bank1(0xac)) != 240_000
    {
        return TestResult::Fail("audio DTO");
    }
    // ACR: 148.5 MHz table row, automatic send, hardware CTS.
    for (reg, value) in [
        (0x20b2, 148_500 << 12),
        (0x20b3, 4096),
        (0x20b4, 165_000 << 12),
        (0x20b5, 6272),
        (0x20b6, 148_500 << 12),
        (0x20b7, 6144),
    ] {
        if r(&e, dio(stream, reg)) != value {
            return TestResult::Fail("ACR N/CTS");
        }
    }
    for (reg, mask, value) in [
        (0x20ba, 1, 1),                        // AFMT audio clock
        (0x20a1, 0x8000_1100, 0x1000),         // ACR auto, HW CTS
        (0x20a0, 0x30, 0x10),                  // audio delay
        (0x2085, u32::MAX, u32::from(stream)), // endpoint = stream
        (0x2075, 0x1000_ff01, 0x3700),         // FL FR LFE RL RR enabled
        (0x2078, 0x30f0_0000, 0x0010_0000),
        (0x2079, 0x00f0_0000, 0x0020_0000),
        (0x207f, 0x00ff_ffff, 0x0087_6543),
        (0x2082, 0x0400_0001, 0x0400_0001), // CS update, samples sent
        (0x20a3, 0x30, 0x10),               // Audio InfoFrame
        (0x20a4, 0x3f00, 0x200),            // on line 2
        (0x2087, 0x30, 0),
    ] {
        if r(&e, dio(stream, reg)) & mask != value {
            return TestResult::Fail("encoder audio");
        }
    }
    let az = |e: &Engine<TmdsIo>, i: u32| e.io.az.get(&(stream, i)).copied();
    if az(&e, 0x54) != Some(0x8000_0000)
        || az(&e, 0x25).map(|v| v & 0x37f7f) != Some(0x1_000b)
        || az(&e, 0x28) != Some(1 | 0x700 | 0x7 << 16 | 0x07 << 24)
        || az(&e, 0x29) != Some(5 | 0x700 | 0x50 << 16)
        || az(&e, 0x30).is_some() // one-bit audio (9) is never written
        || az(&e, 0x2a) != Some(0)
        || az(&e, 0x38).map(|v| v & 1) != Some(1)
        || az(&e, 0x3a) != Some(0x0f99_4c2d)
        || az(&e, 0x3b) != Some(3)
        || az(&e, 0x3c) != Some(0x5558_859e)
        || az(&e, 0x3e) != Some(u32::from_le_bytes(*b"TV\0\0"))
        || r(&e, BASE + 0x40c * 4) != 5 // AC-3 present
        || a.endpoint != stream
    {
        return TestResult::Fail("Azalia endpoint");
    }
    // AFMT clock-on witnesses are this owner's while audio runs.
    let fe = dio(stream, 0x2094);
    let v = r(&e, fe);
    e.io.inner.regs.insert(fe, v | 0x5000);
    let live = e.status.hdmi_video_running.unwrap().link;
    if e.hdmi_link_verify(live, true).is_err() {
        return TestResult::Fail("audio clocks refused");
    }
    e.io.inner.regs.insert(fe, v);
    assert_eq!(
        run(e.start_hdmi_audio(path(p), audio_info())),
        Err(Error::Busy)
    );
    assert_eq!(run(e.stop_hdmi_video(path(p))), Err(Error::Busy));
    run(e.stop_hdmi_audio(path(p))).unwrap();
    if r(&e, dio(stream, 0x2082)) & 1 != 0
        || r(&e, dio(stream, 0x20ba)) & 1 != 0
        || r(&e, dio(stream, 0x20a3)) & 0x30 != 0
        || az(&e, 0x54) != Some(0)
        || e.status.hdmi_audio.is_some()
    {
        return TestResult::Fail("audio stop");
    }
    run(e.stop_hdmi_video(path(p))).unwrap();
    run(e.stop_hdmi_link(&mut fw, path(p))).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_hdmi_audio_programs_dto_acr_afmt_and_the_endpoint_like_linux
);

fn dcn401_hdmi_audio_tables_bandwidth_and_refusals() -> TestResult {
    use crate::amdgpu_dcn401_otg::hdmi_link::audio::{acr, channels, hdmi_rates};
    use dmub::TmdsDepth::{Bpc10, Bpc12, Bpc8};
    if acr(Bpc8, 148_500) != [4096, 148_500, 6272, 165_000, 6144, 148_500]
        || acr(Bpc10, 148_500) != acr(Bpc8, 148_500) // Linux: 30 bpc uses 24
        || acr(Bpc12, 148_500) != [4096, 222_750, 6272, 247_500, 6144, 222_750]
        || acr(Bpc8, 241_500) != [4096, 241_500, 6272, 241_500, 6144, 241_500]
    {
        return TestResult::Fail("ACR tables");
    }
    // 5.1 with rear centre: RC moves to channel 5 without RL/RR.
    if channels(0x01) != 0x03 || channels(0x0f) != 0x3f || channels(0x17) != 0x1f {
        return TestResult::Fail("channel enables");
    }
    // 480p blanking carries at most 48 kHz (56,640 samples/s by Linux's
    // estimate) for any channel count; 1080p carries up to 192 kHz.
    let hd = request(0).timing;
    if hdmi_rates(&hd, Bpc8, 8, 0x7f) != 0x7f {
        return TestResult::Fail("1080p audio bandwidth");
    }
    let mut t = hd;
    (
        t.pixel_clock_khz,
        t.h_active,
        t.h_total,
        t.v_active,
        t.v_total,
    ) = (27_000, 720, 858, 480, 525);
    if hdmi_rates(&t, Bpc8, 8, 0x7f) != 0x07 || hdmi_rates(&t, Bpc8, 2, 0x7f) != 0x07 {
        return TestResult::Fail("audio bandwidth");
    }
    // No LPCM mode: nothing for the codec to stream.
    let (mut e, mut fw, c) = fixture(0, 0, 0);
    run(e.prepare_hdmi_link(&mut fw, path(0), link(0, 0), c)).unwrap();
    run(e.start_hdmi_video(path(0), c)).unwrap();
    let mut info = audio_info();
    info.modes[0] = info.modes[1];
    info.mode_count = 1;
    assert_eq!(
        run(e.start_hdmi_audio(path(0), info)),
        Err(Error::Unsupported)
    );
    info.mode_count = 0;
    assert_eq!(run(e.start_hdmi_audio(path(0), info)), Err(Error::Invalid));
    if e.status.hdmi_audio.is_some() || e.status.state != State::HdmiVideoRunning(0) {
        return TestResult::Fail("refusal changed state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_hdmi_audio_tables_bandwidth_and_refusals
);

/// An HDMI link starts next to another display's running link and timing
/// (transmitter 0, stream 0, pipe 1), which are refused as foreign without
/// that display; the other display's stream is never taken.
fn dcn401_hdmi_link_starts_beside_another_display() -> TestResult {
    let theirs = Siblings {
        pipes: 1 << 1,
        det: 1 << 1,
        transmitters: 1 << 0,
        streams: 1 << 0,
        live: [None; 4],
    };
    let running = |e: &mut Engine<TmdsIo>| {
        let l = e.layout;
        for (at, value) in [
            (l.otg(1, CONTROL), 0x10001),
            (l.otg(1, CLOCK), 0x10103),
            (dio(0, 0x20bb), 0x2810),
            (dio(0, 0x20bc), 0x100), // backend 0 carries stream 0
            (dio(0, 0x20bd), 1),
            (phy(0, 0x2943), 0x03030303),
            (phy(0, 0x2931), 0x6f0),
            (dio(0, 0x2094), 0x2c10),
            (dio(0, 0x2095), 1),
            (dio(0, 0x209b), 1),
            (l.dio_clock, 0x10),
        ] {
            e.io.inner.regs.insert(at, value);
        }
    };
    let (mut e, mut fw, c) = fixture(1, 2, 3);
    running(&mut e);
    if run(e.prepare_hdmi_link(&mut fw, path(1), link(2, 3), c)) != Err(Error::Busy) {
        return TestResult::Fail("foreign running link ignored");
    }
    let (mut e, mut fw, c) = fixture(1, 2, 3);
    running(&mut e);
    e.displays.siblings = theirs;
    if run(e.prepare_hdmi_link(&mut fw, path(1), link(2, 3), c)).is_err()
        || run(e.start_hdmi_video(path(1), c)).is_err()
        || e.status.state != State::HdmiVideoRunning(2)
    {
        return TestResult::Fail("link beside another display");
    }
    let (mut e, mut fw, c) = fixture(1, 0, 3);
    e.displays.siblings = theirs;
    if run(e.prepare_hdmi_link(&mut fw, path(1), link(0, 3), c)) != Err(Error::Busy)
        || !fw.commands.is_empty()
    {
        return TestResult::Fail("another display's stream taken");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_hdmi_link_starts_beside_another_display
);

/// YCbCr 4:2:0 over TMDS: the DCCG divides by two, the link runs at half
/// the pixel clock (PHY PLL, stream setup and transmitter, as dcn401's
/// requested_pix_clk), so 4K60 needs no scrambling; the DIG FIFO takes two
/// pixels per cycle and the AVI InfoFrame says Y 4:2:0, C BT.709. A
/// divide-by-four clock for 4:2:0 is refused.
fn dcn401_hdmi_link_carries_ycbcr420_at_half_rate() -> TestResult {
    let mut req = request(1);
    req.signal = Signal::Tmds;
    req.ycbcr420 = true;
    (
        req.timing.pixel_clock_khz,
        req.timing.h_active,
        req.timing.h_total,
    ) = (594_000, 3840, 4400);
    (req.timing.h_front_porch, req.timing.h_sync_width) = (176, 88);
    (req.timing.v_active, req.timing.v_total) = (2160, 2250);
    (req.timing.v_front_porch, req.timing.v_sync_width) = (8, 10);
    let by = |divider| {
        let mut c = clock(req);
        c.request.pixel = dccg::PixelClock::Tmds { divider };
        c
    };
    // RGB's divide-by-four on 4:2:0 timing.
    let (mut e, mut fw, c) =
        fixture_req(1, 1, 1, req, by(dccg::TmdsDivider::By2), ColorDepth::Bpc8);
    let mut wrong = c;
    wrong.request.pixel = dccg::PixelClock::Tmds {
        divider: dccg::TmdsDivider::By4,
    };
    if run(e.prepare_hdmi_link(&mut fw, path(1), link(1, 1), wrong)).is_ok() {
        return TestResult::Fail("divide-by-four 4:2:0 link");
    }
    let (mut e, mut fw, c) =
        fixture_req(1, 1, 1, req, by(dccg::TmdsDivider::By2), ColorDepth::Bpc8);
    let Ok(ready) = run(e.prepare_hdmi_link(&mut fw, path(1), link(1, 1), c)) else {
        return TestResult::Fail("4:2:0 link");
    };
    let commands: Vec<_> = fw.commands.iter().map(|c| c.0).collect();
    if (ready.pixel_khz, ready.character_khz, ready.scrambled) != (297_000, 297_000, false)
        || commands[..3]
            != [
                Command::Clock(path(1), 1, 297_000, dmub::TmdsDepth::Bpc8),
                Command::Setup(1, 297_000),
                Command::Enable(path(1), 297_000),
            ]
    {
        return TestResult::Fail("half-rate TMDS link");
    }
    let regs = &e.io.inner.regs;
    let avi_words: Vec<u32> =
        e.io.inner
            .writes
            .iter()
            .filter(|w| w.0 == dio(1, 0x2069))
            .map(|w| w.1)
            .take(3)
            .collect();
    // SB1 Y = 3 (0x60 over 0x1e), SB2 C = BT.709 (0x80 over 0x08).
    if regs[&dio(1, 0x209b)] & 0x300 != 0x100 || avi_words[1] >> 8 & 0xffff != 0x887e {
        return TestResult::Fail("two pixels per cycle and 4:2:0 AVI");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_hdmi_link_carries_ycbcr420_at_half_rate
);

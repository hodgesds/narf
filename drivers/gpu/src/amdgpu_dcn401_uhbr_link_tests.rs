use super::super::super::super::dp_phy::training::uhbr::UhbrTransport;
use super::*;
use crate::amdgpu_dcn401_otg::{UhbrRate, UhbrSettings};

#[path = "amdgpu_dcn401_uhbr_audio_tests.rs"]
mod audio;

const LINK: u8 = 1;
fn hpo(link: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(link) * 0xd4) * 4
}
fn mux(p: u8) -> u64 {
    BASE + (0x179a + 3 * u64::from(p)) * 4
}
const LE_ROOT: u64 = 0x16266 * 4;

/// The firmware's half of a 128b/132b link, as the registers show it: on
/// ENABLE the PHY lanes and TX clocks, the PHY mux to the HPO link encoder,
/// its SYMCLK32_LE route, clock and DPHY; on DISABLE the lanes and clocks
/// off. The encoder's status and clock-on follow its host-written enables.
struct UhbrIo {
    inner: Fake,
    phy: u8,
    lanes: u8,
    event: Arc<AtomicU8>,
    /// Encoder MODE as set when each DPCD write was issued.
    mode: Arc<AtomicU8>,
}
impl Io for UhbrIo {
    fn read(&mut self, at: u64) -> u32 {
        let p = self.phy;
        match self.event.swap(0, Ordering::SeqCst) {
            1 => {
                let mut lanes = 0;
                for n in 0..4 {
                    lanes |= (if self.lanes & 1 << n != 0 { 0xc } else { 3 }) << (8 * n);
                }
                let r = &mut self.inner.regs;
                r.insert(phy(p, 0x2943), lanes);
                r.insert(phy(p, 0x2931), 0x600 | u32::from(self.lanes) << 4);
                r.insert(mux(p), u32::from(LINK) << 8 | 2);
                *r.entry(LE_ROOT).or_default() |= (u32::from(p) | 8) << (4 * LINK);
                r.insert(hpo(LINK, 0x369f), 0x11);
                *r.entry(hpo(LINK, 0x36b4)).or_default() |= 1;
                r.insert(hpo(LINK, 0x36b5), 1);
            }
            2 => {
                let r = &mut self.inner.regs;
                r.insert(phy(p, 0x2943), 0x03030303);
                r.insert(phy(p, 0x2931), 0);
            }
            _ => {}
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        assert_ne!(at, phy(self.phy, 0x2943));
        assert_ne!(at, phy(self.phy, 0x2931));
        // DC never routes the PHY or starts the encoder's DPHY itself.
        assert_ne!(at, mux(self.phy));
        self.inner.write(at, value);
        if at == hpo(LINK, 0x36b4) {
            self.mode.store((value >> 4 & 3) as u8, Ordering::SeqCst);
            if value & 1 == 0 {
                self.inner.regs.insert(hpo(LINK, 0x36b5), 0);
            }
        }
        if at == hpo(LINK, 0x369f) && value & 1 == 0 {
            self.inner.regs.insert(hpo(LINK, 0x369f), 0);
        }
        // HPO stream encoders: reset-done and video status follow their
        // requests.
        for s in 0..4 {
            for (reg, from, to) in [
                (0x365d, 0x10, 0x100),
                (0x365e, 0x10, 0x100),
                (0x3626, 0x10, 0x10_0000),
                (0x3685, 1, 0x100),
            ] {
                if at == hpo(s, reg) {
                    let v = self.inner.regs[&at];
                    let done = if v & from != 0 { to } else { 0 };
                    self.inner.regs.insert(at, (v & !to) | done);
                }
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    /// A DPCD write: address, bytes, encoder MODE at the time.
    Write(u32, Vec<u8>, u8),
    Enable(u8),
    Ffe(u8),
    Disable,
}
/// A 128b/132b sink: DPCD bytes, scripted lane status/adjust blocks
/// (0x202..0x207) for successive status reads, and the commands seen.
struct Sink {
    path: inventory::Path,
    settings: UhbrSettings,
    bytes: BTreeMap<u32, u8>,
    status: VecDeque<[u8; 6]>,
    steps: Vec<Step>,
    event: Arc<AtomicU8>,
    mode: Arc<AtomicU8>,
    lttpr: Option<[u8; 10]>,
}
impl super::super::super::super::dp_phy::Firmware for Sink {
    fn ready(&self) -> bool {
        true
    }
    async fn enable(
        &mut self,
        _path: inventory::Path,
        _settings: DpPhySettings,
    ) -> Result<(), dmub::Error> {
        panic!("8b/10b enable on a 128b/132b link")
    }
    async fn disable(&mut self, _path: inventory::Path, _mst: bool) -> Result<(), dmub::Error> {
        panic!("8b/10b disable on a 128b/132b link")
    }
}
impl Transport for Sink {
    async fn aux(
        &mut self,
        instance: u8,
        action: u8,
        address: u32,
        data: &mut [u8],
    ) -> Result<(), dmub::Error> {
        assert_eq!(Some(instance), self.path.aux);
        match action {
            0x80 => {
                let mode = self.mode.load(Ordering::SeqCst);
                self.steps.push(Step::Write(address, data.to_vec(), mode));
                for (i, b) in data.iter().enumerate() {
                    self.bytes.insert(address + i as u32, *b);
                }
                // A new VC payload allocation: table updated, ACT handled.
                if address == 0x1c2 {
                    self.bytes.insert(0x2c0, 3);
                }
            }
            0x90 => {
                if address == 0xf0000 {
                    let Some(caps) = self.lttpr else {
                        return Err(dmub::Error::Aux(1));
                    };
                    data.copy_from_slice(&caps);
                    return Ok(());
                }
                if address == 0x202 {
                    if let Some(next) = self.status.pop_front() {
                        for (i, b) in next.iter().enumerate() {
                            self.bytes.insert(0x202 + i as u32, *b);
                        }
                    }
                }
                for (i, b) in data.iter_mut().enumerate() {
                    *b = self.bytes.get(&(address + i as u32)).copied().unwrap_or(0);
                }
            }
            _ => panic!("unexpected AUX action"),
        }
        Ok(())
    }
    async fn drive(
        &mut self,
        _path: inventory::Path,
        _settings: DpPhySettings,
        _drive: DpDriveSettings,
    ) -> Result<(), dmub::Error> {
        panic!("8b/10b drive on a 128b/132b link")
    }
    async fn delay(&mut self, _us: u64) {}
}
impl UhbrTransport for Sink {
    async fn enable_uhbr(
        &mut self,
        path: inventory::Path,
        settings: UhbrSettings,
        link: u8,
    ) -> Result<(), dmub::Error> {
        assert_eq!((path, settings), (self.path, self.settings));
        self.steps.push(Step::Enable(link));
        self.event.store(1, Ordering::SeqCst);
        Ok(())
    }
    async fn uhbr_ffe(
        &mut self,
        path: inventory::Path,
        settings: UhbrSettings,
        preset: u8,
    ) -> Result<(), dmub::Error> {
        assert_eq!((path, settings), (self.path, self.settings));
        self.steps.push(Step::Ffe(preset));
        Ok(())
    }
    async fn disable_uhbr(&mut self, path: inventory::Path) -> Result<(), dmub::Error> {
        assert_eq!(path, self.path);
        // Sink D3 and the encoder stopped before the firmware disable.
        assert!(self.bytes.get(&0x600) != Some(&1));
        self.steps.push(Step::Disable);
        self.event.store(2, Ordering::SeqCst);
        Ok(())
    }
}
/// A 4-lane UHBR20 sink on PHY `p`, the link on HPO encoder `LINK`.
fn uhbr_fixture(p: u8, settings: UhbrSettings) -> (Engine<UhbrIo>, Sink) {
    let mut e = engine();
    for i in 0..4 {
        e.io.regs.insert(phy(i, 0x2943), 0x03030303);
    }
    let event = Arc::new(AtomicU8::new(0));
    let mode = Arc::new(AtomicU8::new(0));
    let lanes = match settings.lanes {
        1 => 1,
        2 => 3,
        _ => 0xf,
    };
    let mut sink = Sink {
        path: path(p),
        settings,
        bytes: BTreeMap::new(),
        status: VecDeque::new(),
        steps: Vec::new(),
        event: event.clone(),
        mode: mode.clone(),
        lttpr: None,
    };
    // DPCD 1.4 base caps pointing at DP 2.1 extended caps with 128b/132b.
    let mut caps = [0u8; 16];
    caps[..7].copy_from_slice(&[0x14, 0x1e, 0x84, 1, 0, 0, 1]);
    caps[14] = 0x80;
    let mut extended = caps;
    (extended[0], extended[6]) = (0x21, 3);
    for (i, b) in caps.iter().enumerate() {
        sink.bytes.insert(i as u32, *b);
    }
    for (i, b) in extended.iter().enumerate() {
        sink.bytes.insert(0x2200 + i as u32, *b);
    }
    sink.bytes.insert(0x2215, 7);
    sink.bytes.insert(0x2216, 0x81); // 2 x 1 ms
    let io = UhbrIo {
        inner: e.io,
        phy: p,
        lanes,
        event,
        mode,
    };
    (
        Engine {
            io,
            authority: e.authority,
            layout: e.layout,
            status: e.status,
            displays: e.displays,
        },
        sink,
    )
}
/// Lane status/adjust: every active lane at `lane` status bits, alignment
/// byte `align`, the per-lane preset requests `presets`.
fn status(lane: u8, align: u8, presets: [u8; 4]) -> [u8; 6] {
    [
        lane | lane << 4,
        lane | lane << 4,
        align,
        0,
        presets[0] | presets[1] << 4,
        presets[2] | presets[3] << 4,
    ]
}
fn writes(sink: &Sink) -> Vec<(u32, Vec<u8>, u8)> {
    sink.steps
        .iter()
        .filter_map(|s| match s {
            Step::Write(at, data, mode) => Some((*at, data.clone(), *mode)),
            _ => None,
        })
        .collect()
}

/// Linux's 128b/132b training on a firmware-enabled HPO link: D0, training
/// exit, coding 2, the link settings, TPS1 with the encoder in TPS1, the
/// highest requested preset to the transmitter and the per-lane requests
/// to the sink in one TPS2 burst, a second round at the new requests, EQ
/// alignment, the CDS pattern until symbol lock and CDS alignment, exit,
/// the encoder active. Stop puts the sink in D3, stops the encoder, then
/// the firmware disables the PHY and the SYMCLK32_LE route is parked.
fn dcn401_uhbr_link_trains_like_linux_128b_132b() -> TestResult {
    let settings = UhbrSettings {
        lanes: 4,
        rate: UhbrRate::Uhbr20,
    };
    let (mut e, mut sink) = uhbr_fixture(2, settings);
    sink.status = VecDeque::from([
        status(0, 0, [3, 5, 2, 1]),   // before TPS2
        status(1, 0, [7, 5, 2, 1]),   // EQ round 1: not done
        status(3, 0, [7, 5, 2, 1]),   // EQ round 2: EQ done, not aligned
        status(3, 4, [7, 5, 2, 1]),   // EQ interlane alignment
        status(7, 0xd, [7, 5, 2, 1]), // CDS: symbol lock and alignment
    ]);
    let trained = match run(e.train_uhbr_link(&mut sink, path(2), settings, LINK)) {
        Ok(t) => t,
        Err(err) => panic!("UHBR training: {err:?}"),
    };
    if (
        trained.preset,
        trained.eq_loops,
        trained.physical_lanes,
        trained.link,
    ) != (7, 2, 0xf, LINK)
        || e.status.state != State::UhbrLinkTrained(2)
        || e.io.inner.regs[&hpo(LINK, 0x36b4)] & 0x33 != 0x21
    {
        return TestResult::Fail("trained link");
    }
    let firmware: Vec<Step> = sink
        .steps
        .iter()
        .filter(|s| !matches!(s, Step::Write(..)))
        .cloned()
        .collect();
    if firmware != [Step::Enable(LINK), Step::Ffe(5), Step::Ffe(7)] {
        return TestResult::Fail("firmware commands");
    }
    let want: Vec<(u32, Vec<u8>, u8)> = vec![
        (0x600, vec![1], 0),
        (0x102, vec![0], 0),
        (0x108, vec![2], 0),
        (0x107, vec![0x10], 0),
        (0x101, vec![4], 0),
        (0x100, vec![2], 0),
        (0x102, vec![1], 0),
        (0x102, vec![2, 3, 5, 2, 1], 1),
        (0x103, vec![7, 5, 2, 1], 1),
        (0x102, vec![3], 1),
        (0x102, vec![0], 1),
    ];
    if writes(&sink) != want {
        return TestResult::Fail("DPCD sequence");
    }
    sink.steps.clear();
    run(e.stop_uhbr_link(&mut sink, path(2))).unwrap();
    let r = &e.io.inner.regs;
    if sink.steps != [Step::Write(0x600, vec![2], 2), Step::Disable]
        || r[&hpo(LINK, 0x36b4)] & 1 != 0
        || r[&hpo(LINK, 0x369f)] & 0x11 != 0
        || r[&LE_ROOT] >> (4 * LINK) & 0xf != 0
        || e.status.state != State::DpPhyDisabled
        || e.status.uhbr_link.is_some()
    {
        return TestResult::Fail("stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_uhbr_link_trains_like_linux_128b_132b
);

/// Two lanes zero-pad the TPS2 burst; LT_FAILED during EQ is a refusal
/// that exits training and leaves the link for stop; 20 EQ rounds without
/// EQ are one too.
fn dcn401_uhbr_link_refusals_exit_training() -> TestResult {
    let settings = UhbrSettings {
        lanes: 2,
        rate: UhbrRate::Uhbr10,
    };
    let (mut e, mut sink) = uhbr_fixture(0, settings);
    sink.status = VecDeque::from([status(0, 0, [4, 6, 9, 9]), status(1, 0x10, [4, 6, 9, 9])]);
    assert_eq!(
        run(e.train_uhbr_link(&mut sink, path(0), settings, LINK)),
        Err(Error::DpTraining(DpTrainingError::Equalization))
    );
    let w = writes(&sink);
    if !w.contains(&(0x102, vec![2, 4, 6, 0, 0], 1))
        || w.last() != Some(&(0x102, vec![0], 1))
        || e.status.state != State::UhbrLinkRefused(0)
    {
        return TestResult::Fail("LT_FAILED refusal");
    }
    run(e.stop_uhbr_link(&mut sink, path(0))).unwrap();
    // Twenty EQ rounds, then the loop limit.
    let (mut e, mut sink) = uhbr_fixture(0, settings);
    sink.status = VecDeque::from([status(1, 0, [0; 4])]);
    assert_eq!(
        run(e.train_uhbr_link(&mut sink, path(0), settings, LINK)),
        Err(Error::DpTraining(DpTrainingError::Equalization))
    );
    let rounds = writes(&sink).iter().filter(|w| w.0 == 0x103).count();
    if rounds != 19 || e.status.uhbr_link.map(|l| l.eq_loops) != Some(20) {
        return TestResult::Fail("EQ loop limit");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_uhbr_link_refusals_exit_training
);

/// Caps refused before the PHY: no 128b/132b coding, a rate above the
/// sink's best, UHBR13.5 unlisted, too many lanes, a revision 1.4 repeater
/// chain without the rate. A chain that carries it is set non-transparent
/// after its count and transparent mode.
fn dcn401_uhbr_link_checks_caps_before_the_phy() -> TestResult {
    let settings = |lanes, rate| UhbrSettings { lanes, rate };
    for (coding, rates, s) in [
        (1u8, 7u8, settings(4, UhbrRate::Uhbr10)),
        (3, 1, settings(4, UhbrRate::Uhbr20)),
        (3, 3, settings(4, UhbrRate::Uhbr13_5)),
    ] {
        let (mut e, mut sink) = uhbr_fixture(1, s);
        sink.bytes.insert(0x2206, coding);
        sink.bytes.insert(0x2215, rates);
        assert_eq!(
            run(e.train_uhbr_link(&mut sink, path(1), s, LINK)),
            Err(Error::Unsupported)
        );
        if sink.steps.iter().any(|s| !matches!(s, Step::Write(..))) || !e.status.state.reusable() {
            return TestResult::Fail("refused caps touched the PHY");
        }
    }
    let s = settings(4, UhbrRate::Uhbr20);
    let (mut e, mut sink) = uhbr_fixture(1, s);
    sink.lttpr = Some([0x14, 0x1e, 0x80, 0x55, 4, 0, 1, 0x01, 0, 0]);
    assert_eq!(
        run(e.train_uhbr_link(&mut sink, path(1), s, LINK)),
        Err(Error::Unsupported)
    );
    let (mut e, mut sink) = uhbr_fixture(1, s);
    sink.lttpr = Some([0x14, 0x1e, 0x80, 0x55, 4, 0, 1, 0x07, 0, 0]);
    sink.status = VecDeque::from([status(7, 0xd, [0; 4])]);
    let trained = run(e.train_uhbr_link(&mut sink, path(1), s, LINK)).unwrap();
    let w = writes(&sink);
    let at = |x: &(u32, Vec<u8>, u8)| w.iter().position(|y| y == x);
    let order = [
        at(&(0xf000a, vec![0x80], 0)),
        at(&(0xf0003, vec![0x55], 0)),
        at(&(0xf0003, vec![0xaa], 0)),
        at(&(0x108, vec![2], 0)),
    ];
    if trained.repeaters != 1 || order.iter().any(Option::is_none) || !order.is_sorted() {
        return TestResult::Fail("repeater chain");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_uhbr_link_checks_caps_before_the_phy
);

/// Linux's worked example: 3840x2160@60 RGB on 4 x UHBR10 averages
/// 23.65896 slots per MTP: 24 slots, VC rate X 23 / Y 0x15162C1, and 105
/// blanking symbols. 1366 pixels pad to whole symbols.
fn dcn401_uhbr_payload_matches_linux_sst_allocation() -> TestResult {
    use super::super::super::super::dp_phy::training::uhbr::video::uhbr_payload;
    let mut t = request(0).timing;
    (t.pixel_clock_khz, t.h_active, t.h_total) = (594_000, 3840, 4400);
    let s = UhbrSettings {
        lanes: 4,
        rate: UhbrRate::Uhbr10,
    };
    match uhbr_payload(&t, 8, s) {
        Some(p) if (p.slots, p.vc_rate, p.hblank_symbols) == (24, 0x2f51_62c1, 105) => {}
        other => panic!("4K60 payload {other:?}"),
    }
    // 1080p60 on the same link: 5.91 slots, 52 blanking symbols.
    let p = uhbr_payload(&request(0).timing, 8, s).unwrap();
    if p.slots != 6 || p.vc_rate >> 25 != 5 || p.hblank_symbols != 52 {
        return TestResult::Fail("1080p payload");
    }
    // Beyond 64 slots there is no allocation.
    t.pixel_clock_khz = 1_700_000;
    if uhbr_payload(&t, 8, s).is_some() {
        return TestResult::Fail("over-subscribed link");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_uhbr_payload_matches_linux_sst_allocation
);

/// 128b/132b video as Linux brings it up on a trained link: stream
/// attributes (pixel format, MSA), the stream encoder's reset handshake and
/// enable, its mapping to the link encoder, the SDP path, the timing
/// running, the sink's VC payload table then the encoder's allocation and
/// ACT, VC rate and blanking width, then unblank from the OTG. Stop
/// reverses it down to the trained link with the allocation empty.
fn dcn401_uhbr_video_starts_and_stops_like_linux() -> TestResult {
    let (p, stream, pipe) = (2, 1, 3);
    let settings = UhbrSettings {
        lanes: 4,
        rate: UhbrRate::Uhbr10,
    };
    let (mut e, mut sink) = uhbr_fixture(p, settings);
    let req = request(pipe);
    let c = clock(req);
    run(e.prepare(req, c)).unwrap();
    e.io.inner.retiring = [false; 4];
    run(e.prepare_blank(blank_request(pipe), c)).unwrap();
    // The clock owner's live DP DTO (DPREFCLK) behind the prepared timing.
    let bank1 = e.layout.dio_clock - 0xa0 * 4;
    e.io.inner
        .regs
        .insert(bank1 + (0x80 + 4 * u64::from(pipe)) * 4, 0x1090);
    e.io.inner.regs.insert(bank1 + 0x68 * 4, 4 << (pipe * 3));
    // Every fetcher stopped.
    for h in 0..4 {
        e.io.inner.regs.insert(BASE + (0x5f4 + h * 0xdc) * 4, 3);
    }
    sink.status = VecDeque::from([status(7, 0xd, [0; 4])]);
    run(e.train_uhbr_link(&mut sink, path(p), settings, LINK)).unwrap();
    // Before the clock owner routes the stream clocks, video is refused.
    assert_eq!(
        run(e.start_uhbr_video(&mut sink, path(p), stream, pipe, c)),
        Err(Error::Readback(LE_ROOT - (0x66 - 0x4a) * 4))
    );
    let shift = 4 * u32::from(stream);
    e.io.inner
        .regs
        .insert(LE_ROOT - (0x66 - 0x4a) * 4, (8 | u32::from(pipe)) << shift);
    e.io.inner
        .regs
        .insert(LE_ROOT - 4, (8 | u32::from(p)) << shift);
    e.status.state = State::UhbrLinkTrained(p);
    sink.steps.clear();
    let v = match run(e.start_uhbr_video(&mut sink, path(p), stream, pipe, c)) {
        Ok(v) => v,
        Err(err) => panic!("UHBR video: {err:?}"),
    };
    let r =
        |e: &Engine<UhbrIo>, reg: u64| e.io.inner.regs.get(&hpo(stream, reg)).copied().unwrap_or(0);
    // 1920x1080, h total 2200 (start 192), v total 1125 (start 41),
    // 148.5 MHz, +hsync -vsync, 8 bpc.
    let msa = [
        0,
        0,
        0x0800_0000,
        0xd907_0008,
        0xee80_c098,
        0x2004_0004,
        0x2038_2965,
        0x8000,
        0x052c,
    ];
    let msa_ok = (0..9).all(|i| r(&e, 0x3662 + i) == msa[i as usize]);
    if r(&e, 0x3661) & 0x331 != 0x100 || !msa_ok {
        let got: Vec<u32> = (0..9).map(|i| r(&e, 0x3662 + i)).collect();
        panic!("MSA {got:x?}");
    }
    let payload = v.payload;
    if (payload.slots, payload.hblank_symbols) != (6, 52)
        || !v.acknowledged
        || r(&e, 0x3623) & 1 != 1
        || r(&e, 0x365d) & 0x111 != 1
        || r(&e, 0x367b) & 1 != 1
        || r(&e, 0x3685) & 0x101 != 0x101
        || r(&e, 0x365e) & 0x111 != 1
        || r(&e, 0x3626) & 0x10_0011 != 1
        || r(&e, 0x3687) & 0x11 != 0x11
        || r(&e, 0x3624) & 7 != u32::from(pipe)
        || r(&e, 0x366b) != 52
        || e.io.inner.regs[&(MPC_BASE + (0xe56 + u64::from(stream)) * 4)] & 7 != u32::from(LINK)
        || e.io.inner.regs[&hpo(LINK, 0x36bf)] & 0x7f07 != u32::from(stream) | 6 << 8
        || e.io.inner.regs[&hpo(LINK, 0x36b9 + u64::from(stream))] != payload.vc_rate
        || e.status.state != State::UhbrVideoRunning(stream)
    {
        return TestResult::Fail("running HPO stream");
    }
    let w = writes(&sink);
    if w[..4]
        != [
            (0x2c0, vec![1], 2),
            (0x1c0, vec![1], 2),
            (0x1c1, vec![0], 2),
            (0x1c2, vec![6], 2),
        ]
    {
        return TestResult::Fail("payload table");
    }
    sink.steps.clear();
    run(e.stop_uhbr_video(&mut sink, path(p))).unwrap();
    if r(&e, 0x3685) & 0x101 != 0
        || r(&e, 0x365d) & 1 != 0
        || r(&e, 0x3623) & 1 != 0
        || r(&e, 0x367b) & 1 != 0
        || r(&e, 0x366b) != 0
        || e.io.inner.regs[&hpo(LINK, 0x36bf)] & 0x7f00 != 0
        || e.io.inner.regs[&hpo(LINK, 0x36b9 + u64::from(stream))] != 0
        || !writes(&sink).contains(&(0x1c2, vec![0], 2))
        || e.status.state != State::UhbrLinkTrained(p)
        || e.status.uhbr_video_running.is_some()
    {
        return TestResult::Fail("stopped HPO stream");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_uhbr_video_starts_and_stops_like_linux
);

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
    /// A DPCD address whose writes the sink ignores.
    deaf: Option<u32>,
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
                if Some(address) == self.deaf {
                    return Ok(());
                }
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
        // SST sink D3 (an MST branch stays powered) and the encoder
        // stopped before the firmware disable.
        assert!(self.settings.mst || self.bytes.get(&0x600) != Some(&1));
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
        deaf: None,
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
        mst: false,
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
        mst: false,
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
    let settings = |lanes, rate| UhbrSettings {
        lanes,
        rate,
        mst: false,
    };
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
        mst: false,
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
        mst: false,
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

/// allocate_mst_payload's 128b/132b source rate, against Linux's own
/// fixpt31_32 arithmetic (get_pbn_from_timing over get_pbn_per_slot,
/// set_throttled_vcp_size's 25-bit Y, set_hpo_dp_hblank_min_symbol_width)
/// compiled from its source for these timings and links.
fn dcn401_uhbr_mst_rate_matches_linux() -> TestResult {
    use crate::amdgpu_dcn401_otg::uhbr_mst_rate;
    let vectors = [
        // pixel kHz, h active, h total, rate, lanes, VC rate, width.
        (594_000, 3840, 4400, UhbrRate::Uhbr10, 4, 0x2f52_a470, 105),
        (148_500, 1920, 2200, UhbrRate::Uhbr10, 4, 0x0bd4_a91c, 52),
        (148_500, 1920, 2200, UhbrRate::Uhbr20, 4, 0x05ea_2c59, 52),
        (533_250, 3840, 4000, UhbrRate::Uhbr13_5, 2, 0x3ef2_8afb, 30),
        (1_188_000, 3840, 4400, UhbrRate::Uhbr20, 4, 0x2f51_62c1, 104),
        (241_500, 2560, 2720, UhbrRate::Uhbr10, 1, 0x4cf5_970d, 30),
    ];
    for (khz, active, total, rate, lanes, vc, width) in vectors {
        let mut t = request(0).timing;
        (t.pixel_clock_khz, t.h_active, t.h_total) = (khz, active, total);
        let s = UhbrSettings {
            lanes,
            rate,
            mst: true,
        };
        if uhbr_mst_rate(&t, 8, s) != Some((vc, width)) {
            panic!(
                "{khz} kHz on {lanes} x {rate:?}: {:x?}",
                uhbr_mst_rate(&t, 8, s)
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn401-otg", dcn401_uhbr_mst_rate_matches_linux);

/// A display's timing staged blank on `pipe` beside the live DP DTO.
fn stage_uhbr_timing(
    e: &mut Engine<UhbrIo>,
    pipe: u8,
) -> Option<crate::amdgpu_dcn401_dccg::Applied> {
    let req = request(pipe);
    let c = clock(req);
    run(e.prepare(req, c)).ok()?;
    e.io.inner.retiring = [false; 4];
    run(e.prepare_blank(blank_request(pipe), c)).ok()?;
    let bank1 = e.layout.dio_clock - 0xa0 * 4;
    let r = &mut e.io.inner.regs;
    r.insert(bank1 + (0x80 + 4 * u64::from(pipe)) * 4, 0x1090);
    *r.entry(bank1 + 0x68 * 4).or_default() |= 4 << (pipe * 3);
    Some(c)
}
/// The clock owner's routes for HPO stream `stream`: DPSTREAMCLK from
/// `pipe`, SYMCLK32_SE from PHY `p`.
fn route_uhbr_stream(e: &mut Engine<UhbrIo>, p: u8, stream: u8, pipe: u8) {
    let r = &mut e.io.inner.regs;
    let shift = 4 * u32::from(stream);
    *r.entry(LE_ROOT - (0x66 - 0x4a) * 4).or_default() |= (8 | u32::from(pipe)) << shift;
    *r.entry(LE_ROOT - 4).or_default() |= (8 | u32::from(p)) << shift;
}

/// The clock owner parking HPO stream `stream`'s routes after it stops.
fn unroute_uhbr_stream(e: &mut Engine<UhbrIo>, stream: u8) {
    let shift = 4 * u32::from(stream);
    for at in [LE_ROOT - (0x66 - 0x4a) * 4, LE_ROOT - 4] {
        if let Some(v) = e.io.inner.regs.get_mut(&at) {
            *v &= !(15 << shift);
        }
    }
}
/// The MST manager's source half for the selected display's blank stream:
/// the allocation `table` with ACT, then its recorded VC rate.
fn uhbr_mst_payload(e: &mut Engine<UhbrIo>, p: u8, table: &[MstAllocation]) -> Result<(), Error> {
    let v = e.status.uhbr_video_running.ok_or(Error::Invalid)?;
    run(e.update_uhbr_mst_allocation(p, table))?;
    let rate = v.payload.vc_rate;
    run(e.set_uhbr_mst_vc_rate(p, v.stream, (rate >> 25, rate & 0x1ff_ffff)))
}

/// Two MST streams on one 128b/132b link, as Linux's MST streams share the
/// HPO link encoder: display 0 trains the link (the manager set MST_EN
/// first, and the branch stays powered when it stops) and prepares its HPO
/// stream blank; the payload goes in while it is blank (allocation rows
/// from slot 0 with ACT, the VC rate and blanking width), then it
/// unblanks. Display 1 attaches to the running link, maps its own stream
/// to the same link encoder and joins the allocation. Display 1 leaves in
/// Linux's order: blank, payload out, stream off, detach; display 0 still
/// runs, and stops the link last.
fn dcn401_uhbr_mst_streams_share_one_link() -> TestResult {
    let (p, s0, p0, s1, p1) = (2u8, 1u8, 1u8, 3u8, 2u8);
    let settings = UhbrSettings {
        lanes: 4,
        rate: UhbrRate::Uhbr10,
        mst: true,
    };
    let (mut e, mut sink) = uhbr_fixture(p, settings);
    for h in 0..4 {
        e.io.inner.regs.insert(BASE + (0x5f4 + h * 0xdc) * 4, 3);
    }
    // Without MST_EN the branch is no MST sink; SST refuses an MST owner.
    sink.status = VecDeque::from([status(7, 0xd, [0; 4])]);
    if run(e.train_uhbr_link(&mut sink, path(p), settings, LINK)) != Err(Error::Invalid) {
        return TestResult::Fail("MST link without MST_EN");
    }
    sink.bytes.insert(0x111, 7);
    let sst = UhbrSettings {
        mst: false,
        ..settings
    };
    if run(e.train_uhbr_link(&mut sink, path(p), sst, LINK)) != Err(Error::Busy) {
        return TestResult::Fail("SST link on an MST branch");
    }
    let Some(c0) = stage_uhbr_timing(&mut e, p0) else {
        return TestResult::Fail("first timing");
    };
    if run(e.train_uhbr_link(&mut sink, path(p), settings, LINK)).is_err() {
        return TestResult::Fail("128b/132b MST training");
    }
    route_uhbr_stream(&mut e, p, s0, p0);
    // The SST start refuses an MST link.
    if run(e.start_uhbr_video(&mut sink, path(p), s0, p0, c0)) != Err(Error::Invalid) {
        return TestResult::Fail("SST video on an MST link");
    }
    let hpo_at = |s: u8, reg: u64| hpo(s, reg);
    let ready = match run(e.prepare_uhbr_mst_stream(path(p), s0, p0, c0, 6)) {
        Ok(ready) => ready,
        Err(_) => {
            return TestResult::Fail("first MST stream prepare");
        }
    };
    let regs = |e: &Engine<UhbrIo>, at: u64| e.io.inner.regs.get(&at).copied().unwrap_or(0);
    if e.status.state != State::UhbrStreamReady(s0)
        || regs(&e, hpo_at(s0, 0x3685)) & 0x101 != 0
        || regs(&e, hpo_at(s0, 0x365d)) & 1 != 1
        || regs(&e, hpo_at(LINK, 0x36bf)) & 0x7f00 != 0
        || regs(&e, MPC_BASE + (0xe56 + u64::from(s0)) * 4) & 7 != u32::from(LINK)
    {
        return TestResult::Fail("prepared blank MST stream");
    }
    // Unblanking needs the payload's rate first; a rate other than the
    // stream's own is refused.
    if run(e.start_uhbr_mst_video(path(p))).is_ok() {
        return TestResult::Fail("unblank before the payload");
    }
    let rate = ready.payload.vc_rate;
    if run(e.set_uhbr_mst_vc_rate(p, s0, ((rate >> 25) + 1, 0))) != Err(Error::Invalid) {
        return TestResult::Fail("foreign VC rate");
    }
    if e.status.state != State::UhbrStreamReady(s0) {
        return TestResult::Fail("refused unblank kept the prepared stream");
    }
    let first = [MstAllocation {
        stream: s0,
        slots: 6,
    }];
    if uhbr_mst_payload(&mut e, p, &first).is_err() || run(e.start_uhbr_mst_video(path(p))).is_err()
    {
        return TestResult::Fail("first MST stream");
    }
    if regs(&e, hpo_at(LINK, 0x36bf)) & 0x7f07 != u32::from(s0) | 6 << 8
        || regs(&e, hpo_at(LINK, 0x36b9 + u64::from(s0))) != rate
        || regs(&e, hpo_at(s0, 0x366b)) != u32::from(ready.payload.hblank_symbols)
        || regs(&e, hpo_at(s0, 0x3685)) & 0x101 != 0x101
        || e.status.state != State::UhbrVideoRunning(s0)
    {
        return TestResult::Fail("first MST stream running");
    }
    if e.select_display(1).is_err()
        || e.displays.siblings.mst != 1 << p
        || e.displays.siblings.hpo != 1 << s0
        || e.displays.siblings.hpo_links != 1 << LINK
    {
        return TestResult::Fail("UHBR MST link as sibling");
    }
    let Some(c1) = stage_uhbr_timing(&mut e, p1) else {
        return TestResult::Fail("second timing");
    };
    if e.attach_mst_link(p).is_err() {
        return TestResult::Fail("attach");
    }
    route_uhbr_stream(&mut e, p, s1, p1);
    if e.status.state != State::UhbrLinkTrained(p) || e.status.mst_owner != Some(0) {
        return TestResult::Fail("attached record");
    }
    if run(e.prepare_uhbr_mst_stream(path(p), s1, p1, c1, 6)).is_err() {
        return TestResult::Fail("second MST stream prepare");
    }
    let both = [
        MstAllocation {
            stream: s0,
            slots: 6,
        },
        MstAllocation {
            stream: s1,
            slots: 6,
        },
    ];
    if uhbr_mst_payload(&mut e, p, &both).is_err() || run(e.start_uhbr_mst_video(path(p))).is_err()
    {
        return TestResult::Fail("second MST video");
    }
    if regs(&e, hpo_at(LINK, 0x36c0)) & 0x7f07 != u32::from(s1) | 6 << 8
        || regs(&e, MPC_BASE + (0xe56 + u64::from(s1)) * 4) & 7 != u32::from(LINK)
        || regs(&e, hpo_at(s1, 0x3685)) & 0x101 != 0x101
    {
        return TestResult::Fail("second MST stream running");
    }
    // Display 1 leaves: blank, then its payload out (rate zero, its row
    // gone), and only then its stream.
    if run(e.blank_uhbr_mst_video(path(p))).is_err()
        || e.status.state != State::UhbrStreamReady(s1)
        || regs(&e, hpo_at(s1, 0x3685)) & 0x101 != 0
    {
        return TestResult::Fail("blanked second stream");
    }
    if run(e.stop_uhbr_mst_stream(path(p))) != Err(Error::Busy) {
        return TestResult::Fail("stream stopped under its payload");
    }
    if run(e.set_uhbr_mst_vc_rate(p, s1, (0, 0))).is_err()
        || run(e.stop_uhbr_mst_stream(path(p))) != Err(Error::Busy)
    {
        return TestResult::Fail("stream stopped under its allocation row");
    }
    if run(e.update_uhbr_mst_allocation(p, &both[..1])).is_err()
        || run(e.stop_uhbr_mst_stream(path(p))).is_err()
    {
        return TestResult::Fail("second stream stop");
    }
    unroute_uhbr_stream(&mut e, s1);
    if regs(&e, hpo_at(s1, 0x365d)) & 1 != 0
        || regs(&e, hpo_at(LINK, 0x36bf)) & 0x7f07 != u32::from(s0) | 6 << 8
        || regs(&e, hpo_at(LINK, 0x36c0)) & 0x7f00 != 0
        || e.status.state != State::UhbrLinkTrained(p)
    {
        return TestResult::Fail("second stream stopped");
    }
    if run(e.stop_uhbr_link(&mut sink, path(p))) != Err(Error::Busy)
        || e.detach_mst_link(p).is_err()
    {
        return TestResult::Fail("attached display and the link");
    }
    if e.select_display(0).is_err()
        || e.status
            .uhbr_video_running
            .is_none_or(|v| e.uhbr_video_verify_running(&v).is_err())
    {
        return TestResult::Fail("owner's stream after the second left");
    }
    if run(e.blank_uhbr_mst_video(path(p))).is_err()
        || run(e.set_uhbr_mst_vc_rate(p, s0, (0, 0))).is_err()
        || run(e.update_uhbr_mst_allocation(p, &[])).is_err()
        || run(e.stop_uhbr_mst_stream(path(p))).is_err()
    {
        return TestResult::Fail("owner's stream stop");
    }
    unroute_uhbr_stream(&mut e, s0);
    sink.steps.clear();
    if run(e.stop_uhbr_link(&mut sink, path(p))).is_err() {
        return TestResult::Fail("owner stops the link");
    }
    // The branch keeps D0 for its manager.
    if writes(&sink).iter().any(|w| w.0 == 0x600) || !sink.steps.contains(&Step::Disable) {
        return TestResult::Fail("MST link stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_uhbr_mst_streams_share_one_link
);

/// The 1080p60 DSC configuration the legacy DSC tests use: two slices,
/// 8 bpp.
fn hpo_dsc_config() -> crate::amdgpu_dsc::DscConfig {
    crate::amdgpu_dsc::DscConfig {
        slices_h: 2,
        slices_v: 10,
        bpp_x16: 128,
        block_pred: true,
        linebuf_depth: 11,
        version_minor: 2,
        ycbcr422_simple: false,
        frl: None,
    }
}
/// A trained 128b/132b link on PHY `p` with `pipe`'s timing staged
/// compressed by `cfg` and HPO stream `stream`'s clocks routed.
fn uhbr_dsc_fixture(
    p: u8,
    stream: u8,
    pipe: u8,
    settings: UhbrSettings,
    cfg: crate::amdgpu_dsc::DscConfig,
) -> (Engine<UhbrIo>, Sink, Request, dccg::Applied) {
    let (mut e, mut sink) = uhbr_fixture(p, settings);
    if settings.mst {
        sink.bytes.insert(0x111, 7);
    }
    let mut req = request(pipe);
    req.dsc = Some(cfg);
    let c = clock(req);
    run(e.prepare(req, c)).unwrap();
    e.io.inner.retiring = [false; 4];
    run(e.prepare_blank(blank_request(pipe), c)).unwrap();
    let bank1 = e.layout.dio_clock - 0xa0 * 4;
    e.io.inner
        .regs
        .insert(bank1 + (0x80 + 4 * u64::from(pipe)) * 4, 0x1090);
    e.io.inner.regs.insert(bank1 + 0x68 * 4, 4 << (pipe * 3));
    for h in 0..4 {
        e.io.inner.regs.insert(BASE + (0x5f4 + h * 0xdc) * 4, 3);
    }
    sink.status = VecDeque::from([status(7, 0xd, [0; 4])]);
    run(e.train_uhbr_link(&mut sink, path(p), settings, LINK)).unwrap();
    route_uhbr_stream(&mut e, p, stream, pipe);
    (e, sink, req, c)
}

/// A DSC stream on a trained 128b/132b link, in link_set_dpms_on's order:
/// the pipe's DSC and OPTC compress from the timing's staging
/// (link_set_dsc_on_stream does nothing more for HPO); the pixel format
/// is marked compressed; after enable_stream the sink decodes DSC
/// (DP_DSC_ENABLE 1, read back) and the PPS goes out as
/// dcn31_hpo_dp_stream_enc_set_dsc_pps_info_packet sends it: GSP11 in
/// 128-byte mode, the legacy PPS builder's 128 bytes in the stream's VPG
/// generic packets 11-14 (type 0x10, 127 bytes) latched immediately, GSP11
/// on line 2 and VBID[6] on line 3, then GSP11 and the SDP path on. Only
/// then the payload, sized for the compressed 1,222,560 kbps (8 bpp plus
/// two slices' overhead): 2.03 of 64 slots, so 3 slots, X 2, 18 blanking
/// symbols. Stop clears DP_DSC_ENABLE and the PPS after the encoder; the
/// DSC stays for a restart, which sends the PPS again.
fn dcn401_uhbr_dsc_stream_sends_pps_through_hpo_like_linux() -> TestResult {
    let (p, stream, pipe) = (2, 1, 3);
    let settings = UhbrSettings {
        lanes: 4,
        rate: UhbrRate::Uhbr10,
        mst: false,
    };
    let cfg = hpo_dsc_config();
    let (mut e, mut sink, req, c) = uhbr_dsc_fixture(p, stream, pipe, settings, cfg);
    // The pipe's DSC compresses from the staged timing, before the link.
    let forward = BASE + (0x1a64 + u64::from(pipe)) * 4;
    if e.io.inner.regs[&forward] & 1 != 1 {
        return TestResult::Fail("DSC staged with the timing");
    }
    sink.steps.clear();
    e.io.inner.writes.clear();
    let v = match run(e.start_uhbr_video(&mut sink, path(p), stream, pipe, c)) {
        Ok(v) => v,
        Err(err) => panic!("UHBR DSC video: {err:?}"),
    };
    let r =
        |e: &Engine<UhbrIo>, reg: u64| e.io.inner.regs.get(&hpo(stream, reg)).copied().unwrap_or(0);
    if r(&e, 0x3661) & 0x331 != 0x101 {
        return TestResult::Fail("compressed pixel encoding");
    }
    // The PPS words, exactly as the legacy (Linux-matched) builder packs
    // them, after each packet's header.
    let regs = crate::amdgpu_dcn401_otg::dsc_hw::dsc_registers(&req, &cfg).unwrap();
    let pps = crate::amdgpu_dsc::pack_pps(&regs.pps);
    let mut want = Vec::new();
    for chunk in pps.chunks_exact(32) {
        want.push(0x007f_1000);
        want.extend(
            chunk
                .chunks_exact(4)
                .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]])),
        );
    }
    let w = &e.io.inner.writes;
    let data: Vec<u32> = w
        .iter()
        .filter(|&&(at, _)| at == hpo(stream, 0x3652))
        .map(|&(_, v)| v)
        .collect();
    let index: Vec<u32> = w
        .iter()
        .filter(|&&(at, _)| at == hpo(stream, 0x3651))
        .map(|&(_, v)| v & 0xff)
        .collect();
    if data != want || index != [99, 108, 117, 126] || r(&e, 0x3654) & 0x7800 != 0x7800 {
        return TestResult::Fail("PPS in VPG generic packets 11-14");
    }
    if r(&e, 0x3677) & 0xffff_0061 != (2 << 16 | 3 << 5 | 1)
        || r(&e, 0x3684) & 0xffff_0001 != 3 << 16
        || r(&e, 0x367b) & 1 != 1
    {
        return TestResult::Fail("GSP11 and VBID[6]");
    }
    // Order: payload size before the packets, enable after them, all
    // before the VC rate; the sink decodes DSC before the payload table.
    let pos = |at: u64, f: &dyn Fn(u32) -> bool| w.iter().position(|&(a, v)| a == at && f(v));
    let size = pos(hpo(stream, 0x3677), &|v| v & 0x60 == 0x60).unwrap();
    let first = pos(hpo(stream, 0x3652), &|_| true).unwrap();
    let on = pos(hpo(stream, 0x3677), &|v| v & 1 == 1).unwrap();
    let last = w
        .iter()
        .rposition(|&(a, _)| a == hpo(stream, 0x3652))
        .unwrap();
    let rate = pos(hpo(LINK, 0x36b9 + u64::from(stream)), &|v| v != 0).unwrap();
    if !(size < first && last < on && on < rate) {
        return TestResult::Fail("PPS programming order");
    }
    let dpcd = writes(&sink);
    let enable = dpcd
        .iter()
        .position(|w| (w.0, &w.1[..]) == (0x160, &[1][..]));
    let table = dpcd.iter().position(|w| w.0 == 0x2c0);
    if enable.is_none() || enable >= table {
        return TestResult::Fail("DP_DSC_ENABLE before the payload");
    }
    let payload = v.payload;
    if (payload.slots, payload.vc_rate >> 25, payload.hblank_symbols) != (3, 2, 18)
        || dpcd[table.unwrap() + 3] != (0x1c2, vec![3], 2)
        || e.io.inner.regs[&hpo(LINK, 0x36bf)] & 0x7f07 != u32::from(stream) | 3 << 8
        || r(&e, 0x366b) != 18
    {
        panic!("compressed payload {payload:x?}");
    }
    // dc_dsc_stream_bandwidth_in_kbps (its slice overhead rounded up in
    // fixed point) x 64 / 38,564,000 = 2 + the remainder slots.
    let kbps = crate::amdgpu_dsc::dsc_kbps(
        &crate::amdgpu_dcn401_otg::dsc_hw::dsc_timing(&req.timing),
        128,
        2,
    );
    assert!((1_222_560..=1_222_561).contains(&kbps), "{kbps}");
    let y = ((u64::from(kbps) * 64 - 2 * 38_564_000) << 25).div_ceil(38_564_000) as u32;
    if payload.vc_rate != 2 << 25 | y {
        return TestResult::Fail("compressed VC rate");
    }
    sink.steps.clear();
    e.io.inner.writes.clear();
    run(e.stop_uhbr_video(&mut sink, path(p))).unwrap();
    let w = &e.io.inner.writes;
    let encoder_off = w
        .iter()
        .position(|&(a, v)| a == hpo(stream, 0x365d) && v & 1 == 0)
        .unwrap();
    let pps_off = w
        .iter()
        .position(|&(a, v)| a == hpo(stream, 0x3677) && v & 0x61 == 0)
        .unwrap();
    if sink.bytes.get(&0x160) != Some(&0)
        || r(&e, 0x3677) & 0x61 != 0
        || pps_off < encoder_off
        || e.status.state != State::UhbrLinkTrained(p)
    {
        return TestResult::Fail("DSC stop");
    }
    if e.io.inner.regs[&forward] & 1 != 1 {
        return TestResult::Fail("DSC kept for restart");
    }
    run(e.start_uhbr_video(&mut sink, path(p), stream, pipe, c)).unwrap();
    if sink.bytes.get(&0x160) != Some(&1) || r(&e, 0x3677) & 1 != 1 {
        return TestResult::Fail("DSC restart");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_uhbr_dsc_stream_sends_pps_through_hpo_like_linux
);

/// A sink that does not take DP_DSC_ENABLE fails the start before the
/// PPS or the payload.
fn dcn401_uhbr_dsc_refusals() -> TestResult {
    let (p, stream, pipe) = (2, 1, 3);
    let settings = UhbrSettings {
        lanes: 4,
        rate: UhbrRate::Uhbr10,
        mst: false,
    };
    let (mut e, mut sink, _, c) = uhbr_dsc_fixture(p, stream, pipe, settings, hpo_dsc_config());
    // The sink's DSC_ENABLE reads back 0 whatever is written.
    sink.deaf = Some(0x160);
    sink.steps.clear();
    let result = run(e.start_uhbr_video(&mut sink, path(p), stream, pipe, c));
    if result.is_ok()
        || e.io
            .inner
            .regs
            .get(&hpo(stream, 0x3677))
            .copied()
            .unwrap_or(0)
            & 1
            != 0
        || writes(&sink).iter().any(|w| w.0 == 0x2c0)
    {
        return TestResult::Fail("DSC refused by the sink");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn401-otg", dcn401_uhbr_dsc_refusals);

/// An MST DSC stream over 128b/132b, as link_set_dpms_on runs one: the
/// stream is prepared blank with its VC rate from the compressed
/// bandwidth (dc_dsc_stream_bandwidth_in_kbps, as amdgpu_dm's PBN), the
/// manager writes the payload, and the PPS goes out in the stream's own
/// GSP11 before it unblanks; stopping it turns GSP11 off. (The decoder's
/// DP_DSC_ENABLE is the MST manager's, through the branch.)
fn dcn401_uhbr_mst_dsc_stream_sends_its_own_pps() -> TestResult {
    let (p, stream, pipe) = (2, 1, 3);
    let settings = UhbrSettings {
        lanes: 4,
        rate: UhbrRate::Uhbr10,
        mst: true,
    };
    let cfg = hpo_dsc_config();
    let (mut e, _, req, c) = uhbr_dsc_fixture(p, stream, pipe, settings, cfg);
    let ready = match run(e.prepare_uhbr_mst_stream(path(p), stream, pipe, c, 3)) {
        Ok(ready) => ready,
        Err(err) => panic!("MST DSC prepare {err:?}"),
    };
    let r =
        |e: &Engine<UhbrIo>, reg: u64| e.io.inner.regs.get(&hpo(stream, reg)).copied().unwrap_or(0);
    let Some((rate, hblank)) =
        crate::amdgpu_dcn401_otg::uhbr_mst_dsc_rate(&req.timing, &cfg, settings)
    else {
        return TestResult::Fail("compressed MST rate");
    };
    if ready.payload.vc_rate != rate
        || ready.payload.hblank_symbols != hblank
        || rate >> 25 != 2
        || r(&e, 0x3677) & 1 != 0
    {
        panic!("prepared MST DSC stream {:x?}", ready.payload);
    }
    e.io.inner.writes.clear();
    let table = [MstAllocation { stream, slots: 3 }];
    if uhbr_mst_payload(&mut e, p, &table).is_err() || run(e.start_uhbr_mst_video(path(p))).is_err()
    {
        return TestResult::Fail("MST DSC video");
    }
    let w = &e.io.inner.writes;
    let headers = w
        .iter()
        .filter(|&&(at, v)| at == hpo(stream, 0x3652) && v == 0x007f_1000)
        .count();
    let on = w
        .iter()
        .position(|&(a, v)| a == hpo(stream, 0x3677) && v & 1 == 1);
    let unblank = w.iter().rposition(|&(a, _)| a == hpo(stream, 0x3685));
    if headers != 4
        || on.is_none()
        || unblank.is_none()
        || on > unblank
        || r(&e, 0x3685) & 0x101 != 0x101
    {
        panic!("PPS before unblank: {headers} headers, GSP11 on {on:?}, unblank {unblank:?}");
    }
    if run(e.blank_uhbr_mst_video(path(p))).is_err()
        || run(e.set_uhbr_mst_vc_rate(p, stream, (0, 0))).is_err()
        || run(e.update_uhbr_mst_allocation(p, &[])).is_err()
        || run(e.stop_uhbr_mst_stream(path(p))).is_err()
        || r(&e, 0x3677) & 0x61 != 0
    {
        return TestResult::Fail("MST DSC stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_uhbr_mst_dsc_stream_sends_its_own_pps
);

/// A 128b/132b stream's info packets as dcn31_hpo_dp_stream_enc_update_dp_info_packets
/// sends them: on a VSC-colorimetry sink with BT.2020 RGB and HDR metadata,
/// mod_build_vsc_infopacket's VSC SDP in VPG packet 0 and the HDR SDP in
/// packet 3 (each with an immediate update), GSP0 and GSP3 continuously
/// transmitting (GSP2/GSP5 off), MSA MISC1 bit 6, all before the unblank.
/// New metadata rewrites packet 3 only; stopping turns the GSPs off. The
/// MST prepare sends the same packets for its stream.
fn dcn401_uhbr_stream_sends_vsc_and_hdr_sdps_like_linux() -> TestResult {
    use crate::amdgpu_hdr::{
        hdr_info_packet, vsc_sdp, DcColorSpace, HdrConnector, HdrOutputMetadata, PixelEncoding,
    };
    let (p, stream, pipe) = (2, 1, 3);
    let settings = UhbrSettings {
        lanes: 4,
        rate: UhbrRate::Uhbr10,
        mst: false,
    };
    let mut blob = [0u8; 32];
    blob[4] = 2; // SMPTE ST 2084
    for (i, b) in blob[6..30].iter_mut().enumerate() {
        *b = 0x10 + i as u8;
    }
    let meta = HdrOutputMetadata::from_blob(&blob).unwrap();
    let hdr = hdr_info_packet(Some(&meta), HdrConnector::DisplayPort);
    let sdp = UhbrSdp {
        vsc_colorimetry: true,
        hdr: Some(hdr),
    };
    let (mut e, mut sink) = uhbr_fixture(p, settings);
    let req = request(pipe);
    let c = clock(req);
    run(e.prepare(req, c)).unwrap();
    e.io.inner.retiring = [false; 4];
    let blank = BlankRequest {
        colorspace: DcColorSpace::Rgb2020Full,
        ..blank_request(pipe)
    };
    run(e.prepare_blank(blank, c)).unwrap();
    let bank1 = e.layout.dio_clock - 0xa0 * 4;
    e.io.inner
        .regs
        .insert(bank1 + (0x80 + 4 * u64::from(pipe)) * 4, 0x1090);
    e.io.inner.regs.insert(bank1 + 0x68 * 4, 4 << (pipe * 3));
    for h in 0..4 {
        e.io.inner.regs.insert(BASE + (0x5f4 + h * 0xdc) * 4, 3);
    }
    sink.status = VecDeque::from([status(7, 0xd, [0; 4])]);
    run(e.train_uhbr_link(&mut sink, path(p), settings, LINK)).unwrap();
    route_uhbr_stream(&mut e, p, stream, pipe);
    e.io.inner.writes.clear();
    let v = run(e.start_uhbr_video_with(&mut sink, path(p), stream, pipe, c, sdp)).unwrap();
    assert_eq!(v.sdp, sdp);
    let r =
        |e: &Engine<UhbrIo>, reg: u64| e.io.inner.regs.get(&hpo(stream, reg)).copied().unwrap_or(0);
    let vsc = vsc_sdp(
        true,
        DcColorSpace::Rgb2020Full,
        PixelEncoding::Rgb,
        8,
        false,
    )
    .unwrap();
    // BT.2020 RGB colorimetry (6), 8 bpc (1), full range.
    assert_eq!((vsc.sb[16], vsc.sb[17]), (0x06, 0x01));
    let w = &e.io.inner.writes;
    let data: Vec<u32> = w
        .iter()
        .filter(|&&(at, _)| at == hpo(stream, 0x3652))
        .map(|&(_, v)| v)
        .collect();
    let index: Vec<u32> = w
        .iter()
        .filter(|&&(at, _)| at == hpo(stream, 0x3651))
        .map(|&(_, v)| v & 0xff)
        .collect();
    let mut want = vsc.words().to_vec();
    want.extend(hdr.words());
    assert_eq!(data, want);
    assert_eq!(index, [0, 27]);
    assert_eq!(r(&e, 0x3654) & 0x9, 0x9, "immediate updates");
    for (reg, on) in [
        (0x366c, 1),
        (0x366e, 0),
        (0x366f, 1),
        (0x3671, 0),
        (0x367b, 1),
    ] {
        assert_eq!(r(&e, reg) & 1, on, "GSP/SDP {reg:#x}");
    }
    // MSA6 lane 3 MISC0 (8 bpc, nothing for BT.2020), MSA7 lane 3 MISC1.
    assert_eq!(r(&e, 0x3668) >> 24, 0x20);
    assert_eq!(r(&e, 0x3669) >> 24, 0x40);
    assert_eq!(
        crate::amdgpu_hdr::hpo_msa_misc(DcColorSpace::Rgb2020Full, PixelEncoding::Rgb, 8, true),
        (0x20, 0x40)
    );
    // Packets before the unblank (VID_STREAM enable).
    let last_packet = w
        .iter()
        .rposition(|&(at, _)| at == hpo(stream, 0x3652))
        .unwrap();
    let unblank = w
        .iter()
        .position(|&(at, v)| at == hpo(stream, 0x3685) && v & 1 != 0)
        .unwrap();
    assert!(last_packet < unblank);
    // Live metadata: packet 3 only.
    let mut blob2 = blob;
    blob2[26] = 0x55;
    let hdr2 = hdr_info_packet(
        Some(&HdrOutputMetadata::from_blob(&blob2).unwrap()),
        HdrConnector::DisplayPort,
    );
    e.io.inner.writes.clear();
    run(e.uhbr_update_hdr(hdr2)).unwrap();
    let w = &e.io.inner.writes;
    assert_eq!(
        w.iter()
            .filter(|&&(at, _)| at == hpo(stream, 0x3652))
            .map(|&(_, v)| v)
            .collect::<Vec<_>>(),
        hdr2.words()
    );
    assert!(w
        .iter()
        .filter(|&&(at, _)| at == hpo(stream, 0x3651))
        .all(|&(_, v)| v & 0xff == 27));
    assert_eq!(e.status.uhbr_video_running.unwrap().sdp.hdr, Some(hdr2));
    assert_eq!(
        run(e.uhbr_update_hdr(crate::amdgpu_hdr::InfoPacket::default())),
        Err(Error::Invalid)
    );
    run(e.stop_uhbr_video(&mut sink, path(p))).unwrap();
    for reg in [0x366c, 0x366e, 0x366f, 0x3671] {
        assert_eq!(r(&e, reg) & 1, 0);
    }
    // Without HDR metadata, a stream refuses a metadata update.
    unroute_uhbr_stream(&mut e, stream);
    route_uhbr_stream(&mut e, p, stream, pipe);
    let plain = run(e.start_uhbr_video(&mut sink, path(p), stream, pipe, c)).unwrap();
    assert_eq!(plain.sdp, UhbrSdp::default());
    assert_eq!(r(&e, 0x3669) >> 24, 0);
    assert_eq!(run(e.uhbr_update_hdr(hdr)), Err(Error::Invalid));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_uhbr_stream_sends_vsc_and_hdr_sdps_like_linux
);

/// An MST stream on a 128b/132b link prepares with its own VSC/HDR SDPs
/// (enc401/dcn31 update_dp_info_packets per stream encoder): packets
/// 0 and 3 written and GSP0/GSP3 on while the stream is still blank.
fn dcn401_uhbr_mst_stream_sends_its_own_sdps() -> TestResult {
    use crate::amdgpu_hdr::{hdr_info_packet, HdrConnector, HdrOutputMetadata};
    let (p, s0, p0) = (2u8, 1u8, 1u8);
    let settings = UhbrSettings {
        lanes: 4,
        rate: UhbrRate::Uhbr10,
        mst: true,
    };
    let (mut e, mut sink) = uhbr_fixture(p, settings);
    for h in 0..4 {
        e.io.inner.regs.insert(BASE + (0x5f4 + h * 0xdc) * 4, 3);
    }
    sink.status = VecDeque::from([status(7, 0xd, [0; 4])]);
    sink.bytes.insert(0x111, 7);
    let c0 = stage_uhbr_timing(&mut e, p0).unwrap();
    run(e.train_uhbr_link(&mut sink, path(p), settings, LINK)).unwrap();
    route_uhbr_stream(&mut e, p, s0, p0);
    let mut blob = [0u8; 32];
    blob[4] = 3;
    let hdr = hdr_info_packet(
        Some(&HdrOutputMetadata::from_blob(&blob).unwrap()),
        HdrConnector::DisplayPort,
    );
    let sdp = UhbrSdp {
        vsc_colorimetry: false,
        hdr: Some(hdr),
    };
    e.io.inner.writes.clear();
    let ready = run(e.prepare_uhbr_mst_stream_with(path(p), s0, p0, c0, 6, sdp)).unwrap();
    assert_eq!(ready.sdp, sdp);
    let r = |e: &Engine<UhbrIo>, reg: u64| e.io.inner.regs.get(&hpo(s0, reg)).copied().unwrap_or(0);
    // No VSC (the sink takes no colorimetry in it): HDR only, MISC1 clear.
    for (reg, on) in [(0x366c, 0), (0x366f, 1), (0x367b, 1)] {
        assert_eq!(r(&e, reg) & 1, on);
    }
    assert_eq!(r(&e, 0x3669) >> 24, 0);
    let data: Vec<u32> =
        e.io.inner
            .writes
            .iter()
            .filter(|&&(at, _)| at == hpo(s0, 0x3652))
            .map(|&(_, v)| v)
            .collect();
    assert_eq!(data, hdr.words());
    assert_eq!(e.status.state, State::UhbrStreamReady(s0));
    // A drifted GSP fails the ready witness the payload steps recheck.
    let at = hpo(s0, 0x366f);
    let saved = e.io.inner.regs[&at];
    e.io.inner.regs.insert(at, saved & !1);
    assert_eq!(
        run(e.start_uhbr_mst_video(path(p))),
        Err(Error::Readback(at))
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_uhbr_mst_stream_sends_its_own_sdps
);

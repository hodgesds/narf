use super::*;
use crate::amdgpu_dcn401_otg::frl::link::{phy::Firmware as PhyFirmware, start::FrlFirmware};
use crate::amdgpu_dmub_navi48 as dmub;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, Ordering};

/// The firmware's half of an FRL link as the registers show it: ENABLE
/// brings up the lanes and TX clocks, routes the PHY to the HPO FRL
/// encoder, its character clock and forced input clock, and leaves the
/// encoder clocked and enabled in training (LTP1) on the lane count;
/// DISABLE takes lanes and clocks down. Clock-on follows the host's
/// encoder clock enable.
struct FrlIo {
    inner: Fake,
    phy: u8,
    lanes: u8,
    event: Arc<AtomicU8>,
}
fn phy_reg(p: u8, r: u64) -> u64 {
    BASE + (r + u64::from(p) * 0xd8) * 4
}
impl Io for FrlIo {
    fn read(&mut self, at: u64) -> u32 {
        let p = self.phy;
        match self.event.swap(0, Ordering::SeqCst) {
            1 => {
                let mask = (1u32 << self.lanes) - 1;
                let mut lanes = 0;
                for n in 0..4 {
                    lanes |= (if mask & 1 << n != 0 { 0xc } else { 3 }) << (8 * n);
                }
                let r = &mut self.inner.regs;
                r.insert(phy_reg(p, 0x2943), lanes);
                r.insert(phy_reg(p, 0x2931), 0x600 | mask << 4);
                r.insert(mux(p), 1);
                r.insert(BASE + 0x4a * 4, 1 | u32::from(p) << 4);
                r.insert(forced(p), 0x11);
                r.insert(frl(0x95b), 1);
                r.insert(frl(0x95c), 3);
                r.insert(frl(0x965), u32::from(self.lanes == 4) | 2);
            }
            2 => {
                self.inner.regs.insert(phy_reg(p, 0x2943), 0x0303_0303);
                self.inner.regs.insert(phy_reg(p, 0x2931), 0);
            }
            _ => {}
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        // DC never routes the PHY or brings up the character clock itself.
        assert_ne!(at, mux(self.phy));
        assert_ne!(at, forced(self.phy));
        self.inner.write(at, value);
        if at == frl(0x95c) && value & 1 == 0 {
            self.inner.regs.insert(at, 0);
        }
        // Tribyte encoder and ramp FIFO reset-done follow their requests.
        for (reg, from, to) in [(0x8df, 0x10, 0x100), (0x8d6, 0x10, 0x10_0000)] {
            if at == frl(reg) {
                let v = self.inner.regs[&at];
                let done = if v & from != 0 { to } else { 0 };
                self.inner.regs.insert(at, (v & !to) | done);
            }
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Step {
    Enable(u8, u32),
    Ffe(u8),
    Disable,
}
struct Fw {
    steps: alloc::vec::Vec<Step>,
    event: Arc<AtomicU8>,
}
impl PhyFirmware for Fw {
    fn ready(&self) -> bool {
        true
    }
    async fn disable(&mut self, _path: Path) -> Result<(), dmub::Error> {
        self.steps.push(Step::Disable);
        self.event.store(2, Ordering::SeqCst);
        Ok(())
    }
}
impl FrlFirmware for Fw {
    async fn enable_frl(
        &mut self,
        _path: Path,
        lanes: u8,
        character_khz: u32,
    ) -> Result<(), dmub::Error> {
        self.steps.push(Step::Enable(lanes, character_khz));
        self.event.store(1, Ordering::SeqCst);
        Ok(())
    }
    async fn frl_ffe(
        &mut self,
        _path: Path,
        _lanes: u8,
        _character_khz: u32,
        lane_set: u8,
    ) -> Result<(), dmub::Error> {
        self.steps.push(Step::Ffe(lane_set));
        Ok(())
    }
}

/// An FRL link from the firmware ENABLE through training patterns, TxFFE
/// and FRL output, then Linux's disable: patterns zero with training on,
/// encoder and clock off, RC compression restored, firmware DISABLE and the
/// character clock parked.
fn dcn401_frl_link_starts_trains_and_stops_like_linux() -> TestResult {
    let phy = 2;
    for lanes in [3u8, 4] {
        let event = Arc::new(AtomicU8::new(0));
        let mut e = engine();
        for p in 0..4 {
            e.io.regs.insert(phy_reg(p, 0x2943), 0x0303_0303);
        }
        let mut e = Engine {
            io: FrlIo {
                inner: e.io,
                phy,
                lanes,
                event: event.clone(),
            },
            authority: e.authority,
            layout: e.layout,
            status: e.status,
            displays: e.displays,
        };
        let mut fw = Fw {
            steps: alloc::vec::Vec::new(),
            event,
        };
        let link = run(e.start_frl_link(&mut fw, path(phy), lanes, 666_667)).unwrap();
        if link.lanes != lanes
            || link.patterns != [0; 4]
            || e.status.state != State::FrlLinkTraining(phy)
        {
            return TestResult::Fail("started FRL link");
        }
        // LTP2 on lanes 0-2, lane 3 left (8 and above).
        e.frl_training_pattern(path(phy), [1, 1, 1, 0xff]).unwrap();
        let config = e.io.inner.regs[&frl(0x965)];
        if config & 0xffff_0003 != 0x0111_0002 | u32::from(lanes == 4) {
            return TestResult::Fail("training patterns");
        }
        run(e.frl_ffe(&mut fw, path(phy), 0x21)).unwrap();
        e.frl_link_output(path(phy)).unwrap();
        if e.io.inner.regs[&frl(0x965)] & 2 != 0 || e.status.state != State::FrlLinkActive(phy) {
            return TestResult::Fail("FRL output");
        }
        run(e.stop_frl_link(&mut fw, path(phy))).unwrap();
        let r = &e.io.inner.regs;
        if fw.steps != [Step::Enable(lanes, 666_667), Step::Ffe(0x21), Step::Disable]
            || r[&frl(0x965)] & 0xffff_0002 != 2
            || r[&frl(0x95b)] & 1 != 0
            || r[&frl(0x95c)] & 3 != 0
            || r[&(BASE + 0x4a * 4)] & 0x71 != 0
            || e.status.frl_link.is_some()
            || e.status.state != State::FrlDisabled
        {
            return TestResult::Fail("FRL stop");
        }
    }
    // A routed FRL encoder elsewhere refuses a second link.
    let mut e = engine();
    e.io.regs.insert(mux(0), 1);
    let mut e = Engine {
        io: FrlIo {
            inner: e.io,
            phy,
            lanes: 4,
            event: Arc::new(AtomicU8::new(0)),
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    };
    let mut fw = Fw {
        steps: alloc::vec::Vec::new(),
        event: Arc::new(AtomicU8::new(0)),
    };
    assert_eq!(
        run(e.start_frl_link(&mut fw, path(phy), 4, 666_667)),
        Err(Error::Busy)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_link_starts_trains_and_stops_like_linux
);

/// FRL video as Linux brings it up on an active FRL link: the stream
/// attribute (RGB 8 bpc, active/blank, borrow from blank, packets per
/// line, general control and audio InfoFrame on line 2, AVMUTE off), the
/// AVI InfoFrame in VPG4 generic packet 0 on line 2, the encoder's reset
/// handshake, CRC, double-buffer disable and OTG input, the timing, then
/// the FIFO reset and enables. Stop: AVMUTE, blank, packets off, timing
/// off, the link left active for its own stop.
fn dcn401_frl_video_starts_and_stops_like_linux() -> TestResult {
    let (phy, pipe) = (2u8, 1u8);
    let event = Arc::new(AtomicU8::new(0));
    let mut e = engine();
    for p in 0..4 {
        e.io.regs.insert(phy_reg(p, 0x2943), 0x0303_0303);
    }
    let mut e = Engine {
        io: FrlIo {
            inner: e.io,
            phy,
            lanes: 4,
            event: event.clone(),
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    };
    let mut fw = Fw {
        steps: alloc::vec::Vec::new(),
        event,
    };
    let mut req = request(pipe);
    req.signal = Signal::HdmiFrl;
    let c = clock(req);
    run(e.prepare(req, c)).unwrap();
    e.io.inner.retiring = [false; 4];
    run(e.prepare_blank(blank_request(pipe), c)).unwrap();
    // The clock owner's DTBCLK-fed DTO, and every fetcher stopped.
    let bank1 = e.layout.dio_clock - 0xa0 * 4;
    e.io.inner
        .regs
        .insert(bank1 + (0x80 + 4 * u64::from(pipe)) * 4, 0x1090);
    e.io.inner.regs.insert(bank1 + 0x68 * 4, 6 << (pipe * 3));
    for h in 0..4 {
        e.io.inner.regs.insert(BASE + (0x5f4 + h * 0xdc) * 4, 3);
    }
    run(e.start_frl_link(&mut fw, path(phy), 4, 666_667)).unwrap();
    e.frl_link_output(path(phy)).unwrap();
    let request = FrlVideoRequest {
        pipe,
        audio_packets_line: 1,
        borrow_from_blank: true,
        avi: Avi {
            vic: 16,
            ..Avi::default()
        },
    };
    // HDMISTREAMCLK not routed yet.
    assert!(matches!(
        run(e.start_frl_video(path(phy), request, c)),
        Err(Error::Readback(_))
    ));
    e.status.state = State::FrlLinkActive(phy);
    e.io.inner.regs.insert(BASE + 0x59 * 4, 8 | u32::from(pipe));
    if let Err(err) = run(e.start_frl_video(path(phy), request, c)) {
        panic!("FRL video: {err:?}");
    }
    let r = |e: &Engine<FrlIo>, reg: u64| e.io.inner.regs.get(&frl(reg)).copied().unwrap_or(0);
    let checks = [
        (0x8e0, 0x3_0301, 0),
        (0x900, u32::MAX, 1920 | 280 << 16),
        (0x908, 3, 2),
        (0x8e1, 0x1f, 1),
        (0x8e3, 0x7fff_1103, 2 << 16 | 0x1003),
        (0x8e5, 1, 0),
        (0x8e6, 0x33, 3),
        (0x8e9, 0x7fff_7fff, 2),
        (0x8d3, 1, 1),
        (0x8df, 0x111, 1),
        (0x8d6, 0x10_0011, 1),
        (0x8d5, 7, u32::from(pipe)),
        (0x8f1, 0x1000, 0x1000),
        (0x903, 3, 3),
    ];
    if let Some(bad) = checks
        .iter()
        .find(|&&(reg, mask, value)| r(&e, reg) & mask != value)
    {
        panic!("FRL stream register {:#x}: {:#x}", bad.0, r(&e, bad.0));
    }
    if e.status.state != State::FrlVideoRunning(pipe) {
        return TestResult::Fail("FRL video state");
    }
    run(e.stop_frl_video(path(phy))).unwrap();
    if r(&e, 0x8e5) & 1 != 1
        || r(&e, 0x8d6) & 1 != 0
        || r(&e, 0x8df) & 1 != 0
        || r(&e, 0x8d3) & 1 != 0
        || r(&e, 0x8e6) != 0
        || r(&e, 0x8e9) != 0
        || e.status.state != State::FrlLinkActive(phy)
    {
        return TestResult::Fail("FRL video stop");
    }
    // The link stops with the stream's audio InfoFrame enable left set.
    run(e.stop_frl_link(&mut fw, path(phy))).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_video_starts_and_stops_like_linux
);

use super::*;
use crate::amdgpu_dcn401_otg::frl::link::{phy::Firmware as PhyFirmware, start::FrlFirmware};
use crate::amdgpu_dmub_navi48 as dmub;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, Ordering};
#[path = "amdgpu_dcn401_frl_audio_tests.rs"]
mod audio;
#[path = "amdgpu_dcn401_frl_dsc_tests.rs"]
mod dsc;

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
    drift_on_read: Option<(u64, u64, u32)>,
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
            3 => {
                self.inner.regs.insert(mux(p), 0);
            }
            4 => {
                self.inner.regs.insert(BASE + 0x59 * 4, 8);
            }
            _ => {}
        }
        let value = self.inner.read(at);
        if let Some((trigger, reg, value)) = self.drift_on_read {
            // Only after FRL unblank: timing enable has its own frame wait.
            if trigger == at && self.inner.regs.get(&frl(0x8d6)).is_some_and(|v| v & 1 != 0) {
                self.inner.regs.insert(reg, value);
                self.drift_on_read = None;
            }
        }
        value
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
                let v = self.inner.regs.get(&at).copied().unwrap_or(0);
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
    ffe_behavior: u8,
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
        match self.ffe_behavior {
            1 => Err(dmub::Error::CommandTimeout),
            2 => core::future::pending().await,
            3 | 4 => {
                self.event.store(self.ffe_behavior, Ordering::SeqCst);
                Ok(())
            }
            _ => Ok(()),
        }
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
                drift_on_read: None,
            },
            authority: e.authority,
            layout: e.layout,
            status: e.status,
            displays: e.displays,
        };
        let mut fw = Fw {
            ffe_behavior: 0,
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
            drift_on_read: None,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    };
    let mut fw = Fw {
        ffe_behavior: 0,
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
fn prepared_frl_video(
    ycbcr420: bool,
    depth: ColorDepth,
) -> (Engine<FrlIo>, Fw, FrlVideoRequest, dccg::Applied) {
    prepared_frl_video_rate(
        ycbcr420,
        depth,
        crate::amdgpu_navi48_boot::FrlRate::new(6).unwrap(),
    )
}
fn prepared_frl_video_rate(
    ycbcr420: bool,
    depth: ColorDepth,
    rate: crate::amdgpu_navi48_boot::FrlRate,
) -> (Engine<FrlIo>, Fw, FrlVideoRequest, dccg::Applied) {
    prepared_frl_video_dsc(ycbcr420, depth, rate, None)
}
/// An FRL link trained and a pipe-1 timing staged, compressed by `dsc`.
fn prepared_frl_video_dsc(
    ycbcr420: bool,
    depth: ColorDepth,
    rate: crate::amdgpu_navi48_boot::FrlRate,
    dsc: Option<crate::amdgpu_dsc::DscConfig>,
) -> (Engine<FrlIo>, Fw, FrlVideoRequest, dccg::Applied) {
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
            lanes: rate.lanes(),
            event: event.clone(),
            drift_on_read: None,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    };
    let mut fw = Fw {
        ffe_behavior: 0,
        steps: alloc::vec::Vec::new(),
        event,
    };
    let mut req = request(pipe);
    req.signal = Signal::HdmiFrl;
    req.ycbcr420 = ycbcr420;
    req.dsc = dsc;
    let c = clock(req);
    run(e.prepare(req, c)).unwrap();
    e.io.inner.retiring = [false; 4];
    run(e.prepare_blank(
        BlankRequest {
            ycbcr420,
            depth,
            colorspace: crate::amdgpu_dcn401_otg::BlankRequest::default_colorspace(false, ycbcr420),
            ..blank_request(pipe)
        },
        c,
    ))
    .unwrap();
    // The clock owner's DTBCLK-fed DTO, and every fetcher stopped.
    let bank1 = e.layout.dio_clock - 0xa0 * 4;
    e.io.inner
        .regs
        .insert(bank1 + (0x80 + 4 * u64::from(pipe)) * 4, 0x1090);
    e.io.inner.regs.insert(bank1 + 0x68 * 4, 6 << (pipe * 3));
    for h in 0..4 {
        e.io.inner.regs.insert(BASE + (0x5f4 + h * 0xdc) * 4, 3);
    }
    run(e.start_frl_link(&mut fw, path(phy), rate.lanes(), rate.character_khz())).unwrap();
    e.frl_link_output(path(phy)).unwrap();
    let request = FrlVideoRequest {
        pipe,
        audio_packets_line: 1,
        borrow: crate::amdgpu_frl_cap::FrlBorrow::FromBlank,
        hc_active: 0,
        hc_blank: 0,
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
    (e, fw, request, c)
}
fn live_frl_video_format(ycbcr420: bool, depth: ColorDepth) -> (Engine<FrlIo>, Fw) {
    let (mut e, fw, request, c) = prepared_frl_video(ycbcr420, depth);
    // Stale prior encoding/DSC fields must be replaced by uncompressed output.
    e.io.inner.regs.insert(frl(0x8e0), 0x0303_0301);
    e.io.inner.regs.insert(frl(0x8d6), 0x11100);
    if let Err(err) = run(e.start_frl_video(path(2), request, c)) {
        panic!("FRL video: {err:?}");
    }
    (e, fw)
}
fn live_frl_video() -> (Engine<FrlIo>, Fw) {
    live_frl_video_format(false, ColorDepth::Bpc8)
}
fn dcn401_frl_video_starts_and_stops_like_linux() -> TestResult {
    let (phy, pipe) = (2u8, 1u8);
    let (mut e, mut fw) = live_frl_video();
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

/// Live source tests retain the stream/timing and update both link records.
/// Normal teardown must still work with the link sending test patterns.
fn dcn401_frl_live_controls_retain_video() -> TestResult {
    let (mut e, mut fw) = live_frl_video();
    let before = e.status.frl_video_running.unwrap();
    let writes = e.io.inner.writes.len();
    assert_eq!(e.frl_training_pattern(path(1), [2; 4]), Err(Error::Invalid));
    assert_eq!(run(e.frl_ffe(&mut fw, path(2), 4)), Err(Error::Invalid));
    assert_eq!(e.io.inner.writes.len(), writes);
    assert_eq!(fw.steps.len(), 1);
    run(e.frl_ffe(&mut fw, path(2), 0x63)).unwrap();
    assert_eq!(e.frl_current_ffe(path(2)), Ok(3));
    assert!(!e.status.frl_link.unwrap().training);
    e.frl_training_pattern(path(2), [2, 7, 0xff, 1]).unwrap();
    assert_eq!(e.status.state, State::FrlVideoRunning(1));
    let after = e.status.frl_video_running.unwrap();
    assert_eq!(after.timing, before.timing);
    assert_eq!(after.request, before.request);
    assert_eq!(after.link, e.status.frl_link.unwrap());
    assert_eq!(after.link.patterns, [2, 7, 0, 1]);
    assert!(after.link.training);
    e.frl_video_verify_running(&after).unwrap();
    run(e.stop_frl_video(path(2))).unwrap();
    run(e.stop_frl_link(&mut fw, path(2))).unwrap();
    assert_eq!(e.status.state, State::FrlDisabled);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_live_controls_retain_video
);

/// Firmware failure or drift after a command is uncertain: keep every owner
/// and block another command/teardown. Preflight drift performs no mutation.
fn dcn401_frl_live_ffe_failures_retain_owners() -> TestResult {
    for behavior in [1, 3] {
        let (mut e, mut fw) = live_frl_video();
        let link = e.status.frl_link;
        let video = e.status.frl_video_running;
        fw.ffe_behavior = behavior;
        assert!(run(e.frl_ffe(&mut fw, path(2), 1)).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
        assert_eq!(e.status.frl_link, link);
        assert_eq!(e.status.frl_video_running, video);
        assert_eq!(run(e.stop_frl_video(path(2))), Err(Error::Busy));
        assert_eq!(e.frl_training_pattern(path(2), [0; 4]), Err(Error::Busy));
    }
    let (mut e, mut fw) = live_frl_video();
    fw.ffe_behavior = 4;
    assert_eq!(
        run(e.frl_ffe(&mut fw, path(2), 1)),
        Err(Error::Readback(BASE + 0x59 * 4))
    );
    assert!(matches!(e.status.state, State::Failed(_)));
    // Firmware acknowledged the new setting, but the stream route drifted.
    assert_eq!(e.status.frl_link.unwrap().lane_set, 1);
    assert_eq!(
        e.status.frl_video_running.unwrap().link,
        e.status.frl_link.unwrap()
    );
    let (mut e, mut fw) = live_frl_video();
    e.io.inner.regs.insert(BASE + 0x59 * 4, 8); // Another pipe's stream clock.
    let writes = e.io.inner.writes.len();
    assert!(matches!(
        run(e.frl_ffe(&mut fw, path(2), 1)),
        Err(Error::Readback(_))
    ));
    assert_eq!(fw.steps.len(), 1);
    assert_eq!(e.io.inner.writes.len(), writes);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_live_ffe_failures_retain_owners
);

fn dcn401_frl_cancelled_ffe_quarantines_live_video() -> TestResult {
    use core::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let (mut e, mut fw) = live_frl_video();
    let link = e.status.frl_link;
    let video = e.status.frl_video_running;
    fw.ffe_behavior = 2;
    {
        let mut future = core::pin::pin!(e.frl_ffe(&mut fw, path(2), 1));
        assert_eq!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
    }
    assert_eq!(e.status.state, State::UpdatingFrlLink(2));
    assert!(!e.status.state.settled());
    assert_eq!(e.select_display(3), Err(Error::Busy));
    assert_eq!(e.status.frl_link, link);
    assert_eq!(e.status.frl_video_running, video);
    assert_eq!(e.frl_current_ffe(path(2)), Err(Error::Busy));
    assert_eq!(e.frl_training_pattern(path(2), [0; 4]), Err(Error::Busy));
    assert_eq!(run(e.frl_ffe(&mut fw, path(2), 2)), Err(Error::Busy));
    assert_eq!(run(e.stop_frl_video(path(2))), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_cancelled_ffe_quarantines_live_video
);

/// Scanout controls require a matching retained fetch record and must leave
/// its allocation/deadline evidence intact, even when firmware is cancelled.
fn dcn401_frl_controls_bind_live_scanout() -> TestResult {
    use core::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let (mut e, mut fw) = live_frl_video();
    let scanout = ScanoutRunning {
        pipe: 1,
        odm: None,
        stream: 1,
        plan: dml::admit(
            &dml::Soc {
                umc_channels: 16,
                uclk_khz: 1_250_000,
                fclk_khz: [300_000, 2_500_000],
                dcfclk_khz: [200_000, 1_564_000],
                socclk_khz: 300_000,
                dispclk_max_khz: 2_000_000,
                dppclk_max_khz: 2_000_000,
                dentist_vco_khz: 4_500_000,
                dchub_refclk_khz: 50_000,
            },
            &dml::Mode {
                timing: request(1).timing,
                pitch: 1920,
                bytes_per_pixel: 4,
                ycbcr420: false,
                dsc: None,
                planes: [None; dml::MAX_PLANES],
            },
        )
        .unwrap(),
        address: 0x8_0010_0000,
        overlays: [None; crate::amdgpu_dcn401_otg::MAX_OVERLAYS],
        frame_before: 1,
        frame_after: 2,
    };
    e.status.state = State::ScanoutRunning(1);
    assert_eq!(e.frl_training_pattern(path(2), [1; 4]), Err(Error::Invalid));
    e.status.scanout = Some(ScanoutRunning {
        stream: 0,
        ..scanout
    });
    assert_eq!(e.frl_current_ffe(path(2)), Err(Error::Invalid));
    e.status.scanout = Some(scanout);
    e.frl_training_pattern(path(2), [1; 4]).unwrap();
    run(e.frl_ffe(&mut fw, path(2), 2)).unwrap();
    assert_eq!(e.status.state, State::ScanoutRunning(1));
    assert_eq!(e.status.scanout, Some(scanout));
    fw.ffe_behavior = 2;
    {
        let mut future = core::pin::pin!(e.frl_ffe(&mut fw, path(2), 3));
        assert_eq!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        );
    }
    assert_eq!(e.status.state, State::UpdatingFrlLink(2));
    assert_eq!(e.status.scanout, Some(scanout));
    assert_eq!(e.select_display(3), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_controls_bind_live_scanout
);

/// Linux's 4:2:0 stream attribute counts pixel pairs, keeps uncompressed
/// FIFO encoding, and tells the sink BT.709/limited 4:2:0 through VPG4.
fn dcn401_frl_420_stream_format_packets_and_retirement() -> TestResult {
    for (depth, pixel_format) in [
        (ColorDepth::Bpc8, 0x20000),
        (ColorDepth::Bpc10, 0x20101),
        (ColorDepth::Bpc12, 0x20201),
    ] {
        let (mut e, mut fw) = live_frl_video_format(true, depth);
        let r = &e.io.inner.regs;
        assert_eq!(r[&frl(0x8e0)] & 0x3030301, pixel_format);
        assert_eq!(r[&frl(0x8d6)] & 0x11100, 0x1000);
        assert_eq!(r[&frl(0x900)], 960 | 140 << 16);
        assert_eq!(r[&e.layout.otg(1, H_TIMING)] & 0x103, 1);
        assert_eq!(r[&e.layout.odm(1, FORMAT)] & 0x33, 2);
        // VPG4 generic packet 0, nine words: inspect the actual emitted AVI.
        let words: alloc::vec::Vec<u32> =
            e.io.inner
                .writes
                .iter()
                .filter_map(|&(a, v)| (a == frl(0x932)).then_some(v))
                .collect();
        assert_eq!(words.len(), 9);
        let bytes: alloc::vec::Vec<u8> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(&bytes[..3], &[0x82, 2, 13]);
        assert_eq!(bytes[5] >> 5, 3); // YCbCr420
        assert_eq!(bytes[6] >> 6, 2); // BT.709
        assert_eq!(bytes[7] & 0xc, 0); // RGB range unspecified
        assert_eq!(bytes[9] & 0xc0, 0); // YCbCr limited range
        assert_eq!(bytes.iter().fold(0u8, |sum, b| sum.wrapping_add(*b)), 0);
        e.frl_video_verify_running(&e.status.frl_video_running.unwrap())
            .unwrap();
        run(e.stop_frl_video(path(2))).unwrap();
        run(e.stop_frl_link(&mut fw, path(2))).unwrap();
        assert_eq!(e.status.state, State::FrlDisabled);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_420_stream_format_packets_and_retirement
);

/// Rejected format writes quarantine startup before video is published;
/// late encoding drift is detected by live checks, including source tests.
fn dcn401_frl_420_format_failures_retain_link() -> TestResult {
    for (nth, reg) in [(1, 0x8e0), (2, 0x8d6), (3, 0x900)] {
        let (mut e, _fw, req, c) = prepared_frl_video(true, ColorDepth::Bpc10);
        e.io.inner.reject = Some(e.io.inner.writes.len() + nth);
        let link = e.status.frl_link;
        assert_eq!(
            run(e.start_frl_video(path(2), req, c)),
            Err(Error::Readback(frl(reg)))
        );
        assert!(matches!(e.status.state, State::Failed(_)));
        assert_eq!(e.status.frl_link, link);
        assert!(e.status.frl_video_running.is_none());
        assert_eq!(run(e.start_frl_video(path(2), req, c)), Err(Error::Busy));
    }
    // The encoder can drift after unblank, while waiting for fresh frames.
    let (mut e, _fw, req, c) = prepared_frl_video(true, ColorDepth::Bpc10);
    let link = e.status.frl_link;
    e.io.drift_on_read = Some((e.layout.otg(req.pipe, 0x1b4d), frl(0x8e0), 0));
    if run(e.start_frl_video(path(2), req, c)) != Err(Error::Readback(frl(0x8e0))) {
        return TestResult::Fail("published FRL video after frame-wait format drift");
    }
    assert!(matches!(e.status.state, State::Failed(_)));
    assert_eq!(e.status.frl_link, link);
    assert!(e.status.frl_video_running.is_none());
    for (reg, bit) in [
        (0x8e0, 0x10000),
        (0x8e0, 0x1000000),
        (0x8d6, 0x1000),
        (0x8d6, 0x100),
        (0x900, 1),
    ] {
        let (mut e, mut fw) = live_frl_video_format(true, ColorDepth::Bpc8);
        *e.io.inner.regs.get_mut(&frl(reg)).unwrap() ^= bit;
        assert_eq!(
            e.frl_video_verify_running(&e.status.frl_video_running.unwrap()),
            Err(Error::Readback(frl(reg)))
        );
        let writes = e.io.inner.writes.len();
        assert_eq!(
            run(e.frl_ffe(&mut fw, path(2), 1)),
            Err(Error::Readback(frl(reg)))
        );
        assert_eq!(e.io.inner.writes.len(), writes);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_420_format_failures_retain_link
);

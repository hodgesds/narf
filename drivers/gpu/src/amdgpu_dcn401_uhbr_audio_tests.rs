use super::*;
use crate::amdgpu_dcn401_otg::tests::hdmi_link as hdmi;

struct AudioIo {
    inner: UhbrIo,
    az: BTreeMap<(u8, u32), u32>,
    index: [u32; 4],
    writes: Vec<(u64, u32)>,
    drop_at: Option<u64>,
    drop_disable: bool,
    stall: u8,
    pause: bool,
    drift: Option<(u64, u32)>,
}
fn az(e: u8) -> u64 {
    BASE + (0x386 + 6 * u64::from(e)) * 4
}
impl Io for AudioIo {
    fn read(&mut self, at: u64) -> u32 {
        for e in 0..4u8 {
            if at == az(e) + 4 {
                return self
                    .az
                    .get(&(e, self.index[usize::from(e)]))
                    .copied()
                    .unwrap_or(0);
            }
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        self.writes.push((at, value));
        if self.drop_at == Some(at) {
            return;
        }
        for e in 0..4u8 {
            if at == az(e) {
                self.index[usize::from(e)] = value;
                return;
            }
            if at == az(e) + 4 {
                let index = self.index[usize::from(e)];
                if !(self.drop_disable && index == 0x54 && value & 0x80000000 == 0) {
                    self.az.insert((e, index), value);
                }
                return;
            }
            if at == hpo(e, 0x3630) {
                self.inner.write(at, value);
                let asserting = value & 2 != 0;
                if self.stall & if asserting { 1 } else { 2 } == 0 {
                    self.inner
                        .inner
                        .regs
                        .insert(at, (value & !4) | if asserting { 4 } else { 0 });
                }
                if !asserting {
                    if let Some((reg, drift)) = self.drift.take() {
                        self.inner.inner.regs.insert(reg, drift);
                    }
                }
                return;
            }
        }
        self.inner.write(at, value);
    }
    fn wait_poll_limit(&self) -> Option<u32> {
        Some(0)
    }
    fn pause_wait(&self) -> bool {
        self.pause
    }
}
fn info() -> AudioInfo {
    let mut a = hdmi::audio_info();
    a.modes[0].channels = 8;
    a.modes[0].rates = 0x7f;
    a.speakers = 0x4f;
    a
}
fn fixture(stream: u8, pipe: u8, settings: UhbrSettings) -> (Engine<AudioIo>, Sink) {
    let p = 2;
    let (mut e, mut sink) = uhbr_fixture(p, settings);
    let req = request(pipe);
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
    if settings.mst {
        sink.bytes.insert(0x111, 7); // the manager's MST_EN
    }
    run(e.train_uhbr_link(&mut sink, path(p), settings, LINK)).unwrap();
    let shift = 4 * u32::from(stream);
    e.io.inner
        .regs
        .insert(LE_ROOT - (0x66 - 0x4a) * 4, (8 | u32::from(pipe)) << shift);
    e.io.inner
        .regs
        .insert(LE_ROOT - 4, (8 | u32::from(p)) << shift);
    if settings.mst {
        // The MST manager's half: blank stream, payload with ACT, unblank.
        run(e.prepare_uhbr_mst_stream(path(p), stream, pipe, c, 6)).unwrap();
        let table = [MstAllocation { stream, slots: 6 }];
        super::uhbr_mst_payload(&mut e, p, &table).unwrap();
        run(e.start_uhbr_mst_video(path(p))).unwrap();
    } else {
        run(e.start_uhbr_video(&mut sink, path(p), stream, pipe, c)).unwrap();
    }
    (
        Engine {
            io: AudioIo {
                inner: e.io,
                az: BTreeMap::new(),
                index: [0; 4],
                writes: Vec::new(),
                drop_at: None,
                drop_disable: false,
                stall: 0,
                pause: false,
                drift: None,
            },
            authority: e.authority,
            layout: e.layout,
            status: e.status,
            displays: e.displays,
        },
        sink,
    )
}
fn standard() -> (Engine<AudioIo>, Sink) {
    fixture(
        2,
        1,
        UhbrSettings {
            lanes: 4,
            rate: UhbrRate::Uhbr20,
            mst: false,
        },
    )
}
fn reg(e: &Engine<AudioIo>, stream: u8, r: u64) -> u32 {
    e.io.inner
        .inner
        .regs
        .get(&hpo(stream, r))
        .copied()
        .unwrap_or(0)
}
fn dcn401_uhbr_audio_programs_apg_endpoint_and_preserves_video() -> TestResult {
    for rate in UhbrRate::ALL {
        for lanes in [1, 2, 4] {
            for stream in 0..4u8 {
                let (mut e, mut sink) = fixture(
                    stream,
                    (stream + 1) % 4,
                    UhbrSettings {
                        lanes,
                        rate,
                        mst: false,
                    },
                );
                let video = e.status.uhbr_video_running;
                let a = run(e.start_dp_audio(path(2), info())).unwrap();
                assert_eq!(a.endpoint, stream);
                // Every 8-channel LPCM rate fits, so the 192-kHz HBR probe does.
                assert!(a.dp && a.hbr);
                assert_eq!(a.channels, 0xff);
                assert_eq!(a.info.mode_count, 2);
                assert_eq!(a.descriptors[0], 0x7f077f07);
                assert_eq!(a.descriptors[1], 0x0050_0705); // AC-3 passthrough
                assert!(a.descriptors[2..].iter().all(|w| *w == 0));
                assert_eq!(e.io.az[&(stream, 0x38)] & 1, 1);
                assert_eq!(e.io.az[&(stream, 0x29)], 0x0050_0705);
                assert_eq!(
                    e.io.inner.inner.regs.get(&(e.layout.base + 0x40c * 4)),
                    Some(&5)
                );
                for (r, mask, want) in [
                    (0x3625, 7, u32::from(stream)),
                    (0x3630, 6, 0),
                    (0x3631, 0x100ff01, 1),
                    (0x3632, 0xff00ff03, 0xff00),
                    (0x3644, 0x30, 0),
                    (0x367c, 0x3000001f, 7),
                    (0x367b, 1, 1),
                ] {
                    assert_eq!(reg(&e, stream, r) & mask, want);
                }
                assert_eq!(e.io.az[&(stream, 0x25)] & 0x30000, 0x20000);
                assert_eq!(e.io.az[&(stream, 0x54)], 0x80000000);
                let bank = e.layout.dio_clock - 0xa0 * 4;
                assert_eq!(
                    e.io.inner.inner.regs[&(bank + 0xab * 4)] & 0x100030,
                    0x100010
                );
                assert_eq!(e.io.inner.inner.regs[&(bank + 0xae * 4)], 240000);
                let writes = &e.io.writes;
                let reset = writes
                    .iter()
                    .position(|&(at, v)| at == hpo(stream, 0x3630) && v & 2 != 0)
                    .unwrap();
                let release = writes
                    .iter()
                    .position(|&(at, v)| at == hpo(stream, 0x3630) && v & 2 == 0)
                    .unwrap();
                let enable = writes
                    .iter()
                    .position(|&(at, v)| at == hpo(stream, 0x3631) && v & 1 != 0)
                    .unwrap();
                assert!(reset < release && release < enable);
                assert_eq!(run(e.stop_uhbr_video(&mut sink, path(2))), Err(Error::Busy));
                run(e.stop_dp_audio(path(2))).unwrap();
                assert_eq!(e.status.uhbr_video_running, video);
                assert_eq!(e.status.state, State::UhbrVideoRunning(stream));
                assert!(e.status.uhbr_audio.is_none());
                assert_eq!(reg(&e, stream, 0x367c) & 15, 0);
                assert_eq!(reg(&e, stream, 0x3631) & 1, 0);
                assert_eq!(reg(&e, stream, 0x367b) & 1, 1);
                assert_eq!(e.io.az[&(stream, 0x54)], 0);
                // HPO never programs legacy AFMT source or clocks.
                for p in 0..4 {
                    assert!(e.io.writes.iter().all(|&(at, _)| {
                        !(hdmi::dio(p, 0x2075)..=hdmi::dio(p, 0x20ba)).contains(&at)
                    }));
                }
                run(e.start_dp_audio(path(2), info())).unwrap();
                run(e.stop_dp_audio(path(2))).unwrap();
                run(e.stop_uhbr_video(&mut sink, path(2))).unwrap();
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-uhbr-audio",
    dcn401_uhbr_audio_programs_apg_endpoint_and_preserves_video
);

fn dcn401_uhbr_audio_rejects_inherited_or_changed_transport() -> TestResult {
    for (r, value, expected) in [
        (0x3630, 2, true),
        (0x3631, 1, true),
        (0x3632, 1, true),
        (0x367c, 1, true),
        (0x367c, 0x10000000, true),
        (0x366b, 1, false),
        (0x3661, 0, false),
    ] {
        let (mut e, _) = standard();
        e.io.inner.inner.regs.insert(hpo(2, r), value);
        let error = if expected {
            Error::Busy
        } else {
            Error::Readback(hpo(2, r))
        };
        assert_eq!(run(e.start_dp_audio(path(2), info())), Err(error));
        assert!(e.io.writes.is_empty());
        assert!(e.status.uhbr_audio.is_none());
    }
    let (mut e, _) = standard();
    assert_eq!(run(e.start_dp_audio(path(1), info())), Err(Error::Invalid));
    assert!(e.io.writes.is_empty());
    e.io.az.insert((2, 0x54), 0x80000000);
    assert_eq!(run(e.start_dp_audio(path(2), info())), Err(Error::Busy));
    assert_eq!(e.io.writes, [(az(2), 0x54)]);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-uhbr-audio",
    dcn401_uhbr_audio_rejects_inherited_or_changed_transport
);

fn dcn401_uhbr_audio_failed_writes_and_shutdown_retain_owners() -> TestResult {
    for r in [0x3625, 0x3632, 0x3631, 0x367c] {
        let (mut e, mut sink) = standard();
        let video = e.status.uhbr_video_running;
        e.io.drop_at = Some(hpo(2, r));
        assert!(run(e.start_dp_audio(path(2), info())).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
        assert!(e.status.uhbr_audio.is_some());
        assert_eq!(e.status.uhbr_video_running, video);
        assert_eq!(e.select_display(1), Err(Error::Busy));
        assert_eq!(run(e.stop_uhbr_video(&mut sink, path(2))), Err(Error::Busy));
    }
    for r in [0x3625, 0x3632, 0x3631, 0x367c, 0x366b] {
        let (mut e, _) = standard();
        let a = run(e.start_dp_audio(path(2), info())).unwrap();
        *e.io.inner.inner.regs.get_mut(&hpo(2, r)).unwrap() ^= 1;
        let before = e.io.writes.len();
        assert_eq!(
            run(e.stop_dp_audio(path(2))),
            Err(Error::Readback(hpo(2, r)))
        );
        assert_eq!(e.io.writes.len(), before);
        assert_eq!(e.status.uhbr_audio, Some(a));
    }
    for endpoint in [false, true] {
        let (mut e, mut sink) = standard();
        let a = run(e.start_dp_audio(path(2), info())).unwrap();
        if endpoint {
            e.io.drop_disable = true;
        } else {
            e.io.drop_at = Some(hpo(2, 0x3631));
        }
        assert!(run(e.stop_dp_audio(path(2))).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
        assert_eq!(e.status.uhbr_audio, Some(a));
        assert_eq!(run(e.stop_uhbr_video(&mut sink, path(2))), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-uhbr-audio",
    dcn401_uhbr_audio_failed_writes_and_shutdown_retain_owners
);

fn dcn401_uhbr_audio_reset_timeout_cancellation_and_drift_quarantine() -> TestResult {
    use core::{
        future::Future,
        task::{Context, Waker},
    };
    for stall in [1, 2] {
        let (mut e, _) = standard();
        e.io.stall = stall;
        assert_eq!(
            run(e.start_dp_audio(path(2), info())),
            Err(Error::Timeout(hpo(2, 0x3630)))
        );
        assert!(matches!(e.status.state, State::Failed(_)));
        assert!(e.status.uhbr_audio.is_some());
        assert_eq!(reg(&e, 2, 0x3631) & 1, 0);
    }
    for stall in [1, 2] {
        let (mut e, mut sink) = standard();
        e.io.stall = stall;
        e.io.pause = true;
        {
            let mut f = core::pin::pin!(e.start_dp_audio(path(2), info()));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.status.state, State::StartingUhbrAudio(2));
        assert!(e.status.uhbr_audio.is_some());
        assert_eq!(e.select_display(1), Err(Error::Busy));
        assert_eq!(run(e.start_dp_audio(path(2), info())), Err(Error::Busy));
        assert_eq!(run(e.stop_dp_audio(path(2))), Err(Error::Busy));
        assert_eq!(run(e.stop_uhbr_video(&mut sink, path(2))), Err(Error::Busy));
    }
    for r in [0x366b, 0x3661, 0x3624, 0x3625, 0x3632] {
        let (mut e, _) = standard();
        e.io.drift = Some((hpo(2, r), 0));
        assert_eq!(
            run(e.start_dp_audio(path(2), info())),
            Err(Error::Readback(hpo(2, r)))
        );
        assert!(e.status.uhbr_audio.is_some());
        assert_eq!(reg(&e, 2, 0x3631) & 1, 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-uhbr-audio",
    dcn401_uhbr_audio_reset_timeout_cancellation_and_drift_quarantine
);

fn dcn401_uhbr_audio_shares_dto_and_excludes_endpoint_collisions() -> TestResult {
    let (mut h, mut fw, c) = hdmi::fixture(0, 0, 0);
    run(h.prepare_hdmi_link(&mut fw, hdmi::path(0), hdmi::link(0, 0), c)).unwrap();
    run(h.start_hdmi_video(hdmi::path(0), c)).unwrap();
    run(h.start_hdmi_audio(hdmi::path(0), hdmi::audio_info())).unwrap();
    let (mut e, _) = standard();
    e.displays.selected = 1;
    e.displays.parked[0] = *h.status;
    let bank = e.layout.dio_clock - 0xa0 * 4;
    for hdmi_pipe in [0, 3] {
        e.displays.parked[0]
            .hdmi_video_running
            .as_mut()
            .unwrap()
            .link
            .request
            .pipe = hdmi_pipe;
        run(e.start_dp_audio(path(2), info())).unwrap();
        assert_eq!(
            e.io.inner.inner.regs[&(bank + 0xab * 4)] & 0x37,
            u32::from(hdmi_pipe)
        );
        assert_eq!(e.io.inner.inner.regs[&(bank + 0xad * 4)], 1_485_000);
        run(e.stop_dp_audio(path(2))).unwrap();
    }
    e.displays.parked[0].hdmi_audio = None;
    let a = run(e.start_dp_audio(path(2), info())).unwrap();
    assert_eq!(
        e.io.inner.inner.regs[&(bank + 0xab * 4)] & 0x100030,
        0x100010
    );
    run(e.stop_dp_audio(path(2))).unwrap();
    e.displays.parked[0].frl_audio = Some(a);
    let before = e.io.writes.len();
    assert_eq!(run(e.start_dp_audio(path(2), info())), Err(Error::Busy));
    assert_eq!(e.io.writes.len(), before);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-uhbr-audio",
    dcn401_uhbr_audio_shares_dto_and_excludes_endpoint_collisions
);

fn dcn401_uhbr_audio_filters_capabilities_and_binds_scanout() -> TestResult {
    let (mut e, _) = standard();
    let raw = info();
    let settings = e.status.uhbr_video_running.unwrap().link.settings;
    let mut timing = request(1).timing;
    // Narrow, slow blanking cannot carry even 32-kHz stereo (Linux vectors).
    timing.pixel_clock_khz = 25000;
    timing.h_total = 1936;
    assert!(uhbr_audio_info(raw, &timing, 8, settings).is_none());
    timing.h_total = 2200;
    timing.pixel_clock_khz = 148500;
    let supported = uhbr_audio_info(raw, &timing, 8, settings).unwrap();
    assert_eq!(supported.mode_count, 2);
    assert_eq!(supported.modes[0].rates, 127);
    // Compressed SADs are not rate-filtered (dce_aud_az_configure).
    assert_eq!(supported.modes[1], raw.modes[1]);
    for (clock, active, total) in [
        (0, 1920, 2200),
        (1, 1, 65535), // intermediate fixed-point overflow despite low link BW
        (6_000_001, 1920, 2200),
        (148500, 0, 2200),
        (148500, 1920, 1920),
        (148500, 1920, 1919),
        (148500, 1920, 65536),
    ] {
        let mut invalid = timing;
        invalid.pixel_clock_khz = clock;
        invalid.h_active = active;
        invalid.h_total = total;
        assert!(uhbr_audio_info(raw, &invalid, 8, settings).is_none());
    }
    for lanes in [0, 3, 5, 255] {
        assert!(uhbr_audio_info(raw, &timing, 8, UhbrSettings { lanes, ..settings }).is_none());
    }
    let mut no_lpcm = raw;
    no_lpcm.modes[0].format = 2;
    assert_eq!(
        run(e.start_dp_audio(path(2), no_lpcm)),
        Err(Error::Unsupported)
    );
    assert!(e.io.writes.is_empty());
    e.status.state = State::ScanoutRunning(1);
    assert_eq!(run(e.start_dp_audio(path(2), raw)), Err(Error::Invalid));
    assert!(e.io.writes.is_empty());
    let plan = dml::admit(
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
            timing,
            pitch: 1920,
            bytes_per_pixel: 4,
            ycbcr420: false,
            dsc: None,
            planes: [None; dml::MAX_PLANES],
        },
    )
    .unwrap();
    let scanout = ScanoutRunning {
        pipe: 1,
        odm: None,
        stream: 2,
        plan,
        address: 0x8_0010_0000,
        frame_before: 1,
        frame_after: 2,
    };
    e.status.scanout = Some(ScanoutRunning {
        stream: 0,
        ..scanout
    });
    assert_eq!(run(e.start_dp_audio(path(2), raw)), Err(Error::Invalid));
    e.status.scanout = Some(scanout);
    run(e.start_dp_audio(path(2), raw)).unwrap();
    run(e.stop_dp_audio(path(2))).unwrap();
    assert_eq!(e.status.state, State::ScanoutRunning(1));
    assert_eq!(e.status.scanout, Some(scanout));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-uhbr-audio",
    dcn401_uhbr_audio_filters_capabilities_and_binds_scanout
);

/// LPCM on a 128b/132b MST stream rides its completed payload, as legacy
/// MST audio does: the SST entry refuses it, a slot count other than the
/// stream's or a SAT row that disagrees is refused before any write, and
/// the running audio's checks include the stream's allocation row. The
/// APG, endpoint and packets are the SST ones, budgeted as Linux budgets
/// 128b/132b SST (the whole link and the timing's blank).
fn dcn401_uhbr_mst_audio_rides_a_completed_payload() -> TestResult {
    let settings = UhbrSettings {
        lanes: 4,
        rate: UhbrRate::Uhbr20,
        mst: true,
    };
    let (mut e, _sink) = fixture(2, 1, settings);
    let p = path(2);
    if run(e.start_dp_audio(p, info())) != Err(Error::Unsupported)
        || run(e.start_mst_audio(p, info(), 7)) != Err(Error::Invalid)
    {
        return TestResult::Fail("MST audio without its payload");
    }
    let sat = hpo(LINK, 0x36bf);
    let row = e.io.inner.inner.regs[&sat];
    e.io.inner.inner.regs.insert(sat, row & !0x7f00 | 5 << 8);
    let writes = e.io.writes.len();
    if run(e.start_mst_audio(p, info(), 6)) != Err(Error::Readback(sat))
        || e.io.writes.len() != writes
        || e.status.uhbr_audio.is_some()
    {
        return TestResult::Fail("disagreeing allocation row");
    }
    e.io.inner.inner.regs.insert(sat, row);
    let a = match run(e.start_mst_audio(p, info(), 6)) {
        Ok(a) => a,
        Err(_) => return TestResult::Fail("MST audio start"),
    };
    let v = e.status.uhbr_video_running.unwrap();
    let t = v.timing.blank.timing.request.timing;
    if a.endpoint != 2
        || Some(a.info) != uhbr_audio_info(info(), &t, 8, settings)
        || reg(&e, 2, 0x3631) & 1 != 1
        || reg(&e, 2, 0x367c) & 0x1f != 7
        || e.uhbr_audio_verify(&v, &a).is_err()
    {
        return TestResult::Fail("MST stream audio");
    }
    // Losing the stream's allocation row breaks the audio's witness.
    e.io.inner.inner.regs.insert(sat, 0);
    if e.uhbr_audio_verify(&v, &a).is_ok() {
        return TestResult::Fail("audio without an allocation row");
    }
    e.io.inner.inner.regs.insert(sat, row);
    if run(e.stop_dp_audio(p)).is_err()
        || e.status.uhbr_audio.is_some()
        || e.uhbr_audio_quiet(2).is_err()
    {
        return TestResult::Fail("MST audio stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_uhbr_mst_audio_rides_a_completed_payload
);

//! Native MST video plus an indexed (non-echoing) Azalia endpoint model.
use super::*;

struct MstIo {
    inner: AudioIo,
    writes: Vec<(u64, u32)>,
    drop: Option<u64>,
}
impl MstIo {
    fn fake(&mut self) -> &mut Fake {
        self.inner.inner.fake()
    }
}
impl Io for MstIo {
    fn read(&mut self, at: u64) -> u32 {
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        // Endpoint index selection is necessary for a read, not programming.
        if !(0..4).any(|e| at == az_at(e)) {
            self.writes.push((at, value));
        }
        if self.drop != Some(at) {
            self.inner.write(at, value);
        }
    }
}
fn info() -> AudioInfo {
    super::super::super::hdmi_link::audio_info()
}
fn set_payload(e: &mut Engine<MstIo>, rows: &[(u8, u8)]) {
    let f = e.status.dp_video_running.unwrap().frontend;
    let s = f.link.phy.settings;
    let raw = s.rate as u32 * 27_000 * 8 * u32::from(s.lanes);
    let kbps = if f.link.fec { raw / 100 * 97 } else { raw };
    let depth = match f.blank.request.depth {
        ColorDepth::Bpc8 => 8,
        ColorDepth::Bpc10 => 10,
        ColorDepth::Bpc12 => 12,
    };
    let (x, y) = vc_rate(
        f.blank.timing.request.timing.pixel_clock_khz * depth * 3,
        kbps,
    )
    .unwrap();
    let stream = f.request.stream;
    let phy = f.link.phy.path.transmitter;
    let mut words = [0u32; 2];
    for (i, &(stream, slots)) in rows.iter().enumerate() {
        words[i / 2] |= (u32::from(stream) | u32::from(slots) << 8) << (i % 2 * 16);
    }
    for (at, value) in [
        (dio(phy, 0x2150), words[0]),
        (dio(phy, 0x2151), words[1]),
        (dio(phy, 0x2153), 0),
        (dio(stream, 0x214f), 0),
        (dio(stream, 0x214d), x << 26 | y),
    ] {
        e.io.fake().regs.insert(at, value);
    }
}
fn fixture(stream: u8, depth: ColorDepth) -> (Engine<MstIo>, Link) {
    let (mut e, mut link, c) = fixture_mode(2, stream, (stream + 1) % 4, depth, None, None, true);
    start(&mut e, &mut link, c);
    let mut e = Engine {
        io: MstIo {
            inner: AudioIo {
                inner: e.io,
                az: BTreeMap::new(),
                index: [0; 4],
            },
            writes: Vec::new(),
            drop: None,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    };
    set_payload(&mut e, &[(stream, 24)]);
    (e, link)
}
fn start_audio(e: &mut Engine<MstIo>) -> DisplayAudio {
    run(e.start_mst_audio(path(2), info(), 24)).unwrap()
}
fn dcn401_mst_audio_streams_depths_and_roundtrip() -> TestResult {
    for stream in 0..4 {
        for depth in [ColorDepth::Bpc8, ColorDepth::Bpc10, ColorDepth::Bpc12] {
            let (mut e, mut link) = fixture(stream, depth);
            let registers = [
                dio(2, 0x2150),
                dio(2, 0x2151),
                dio(stream, 0x214d),
                dio(2, 0x20bc),
            ];
            let before = registers.map(|at| e.io.fake().regs[&at]);
            for _ in 0..2 {
                let a = start_audio(&mut e);
                assert!(a.dp && !a.hbr && a.endpoint == stream);
                assert!(a.info.modes[..usize::from(a.info.mode_count)]
                    .iter()
                    .all(|m| m.format == 1));
                assert!(a.descriptors[0] != 0 && a.descriptors[1..].iter().all(|&v| v == 0));
                for (reg, mask, want) in [
                    (0x2141, 0x1ff1_1111, 0x1111),
                    (0x2147, u32::MAX, 0x8000),
                    (0x214b, u32::MAX, 1),
                    (0x20ba, 1, 1),
                    (0x2085, 7, u32::from(stream)),
                    (0x2075, 0xff00, u32::from(a.channels) << 8),
                    (0x2082, 1, 1),
                ] {
                    assert_eq!(e.io.fake().regs[&dio(stream, reg)] & mask, want);
                }
                assert_eq!(e.io.inner.az[&(stream, 0x54)] & 0x8000_0001, 0x8000_0000);
                assert_eq!(e.io.inner.az[&(stream, 0x38)] & 1, 0);
                let writes = e.io.writes.len();
                assert_eq!(run(e.stop_dp_video(&mut link, path(2))), Err(Error::Busy));
                assert_eq!(e.io.writes.len(), writes);
                assert_eq!(run(e.start_dp_audio(path(2), info())), Err(Error::Busy));
                run(e.stop_dp_audio(path(2))).unwrap();
                assert!(e.status.dp_audio.is_none() && e.status.mst_audio_payload.is_none());
                assert_eq!(e.io.fake().regs[&dio(stream, 0x2141)] & 0x1ff1_1111, 0);
                assert_eq!(e.io.fake().regs[&dio(stream, 0x20ba)] & 1, 0);
                assert_eq!(e.io.inner.az[&(stream, 0x54)] & 0x8000_0001, 0);
                assert_eq!(registers.map(|at| e.io.fake().regs[&at]), before);
                assert!(!e.io.writes.iter().any(|(at, _)| registers.contains(at)));
            }
            run(e.stop_dp_video(&mut link, path(2))).unwrap();
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-mst-audio",
    dcn401_mst_audio_streams_depths_and_roundtrip
);

fn dcn401_mst_audio_rejects_unproven_payload_and_source_before_programming() -> TestResult {
    for case in 0..13 {
        let (mut e, _) = fixture(1, ColorDepth::Bpc8);
        match case {
            0 => {
                e.io.fake().regs.insert(dio(2, 0x2150), 0);
            }
            1 => {
                e.io.fake().regs.insert(dio(2, 0x2150), 1 | 23 << 8);
            }
            2 => {
                e.io.fake().regs.insert(dio(2, 0x2151), 1 | 24 << 8);
            }
            3 => {
                e.io.fake().regs.insert(dio(2, 0x2151), 3 | 10 << 8);
            }
            4 => {
                e.io.fake().regs.insert(dio(2, 0x2151), 5 | 10 << 8);
            }
            5 => {
                e.io.fake().regs.insert(dio(2, 0x2153), 0x100);
            }
            6 => {
                e.io.fake().regs.insert(dio(1, 0x214f), 1);
            }
            7 => {
                e.io.fake().regs.insert(dio(1, 0x214d), 0);
            }
            8 => {
                e.io.fake().regs.insert(dio(1, 0x2122), 0);
            }
            9 => {
                e.io.fake().regs.insert(dio(1, 0x2093), 0);
            }
            10 => {
                e.io.fake().regs.insert(dio(1, 0x2082), 1);
            }
            11 => {
                e.io.inner.az.insert((1, 0x54), 0x8000_0000);
            }
            _ => {
                e.status.state = State::ScanoutRunning(2);
            }
        }
        assert!(
            run(e.start_mst_audio(path(2), info(), 24)).is_err(),
            "case {case}"
        );
        assert!(e.io.writes.is_empty(), "preflight writes, case {case}");
        assert!(e.status.dp_audio.is_none() && e.status.mst_audio_payload.is_none());
    }
    let (mut e, _) = fixture(1, ColorDepth::Bpc8);
    for slots in [0, 1, 64] {
        assert!(run(e.start_mst_audio(path(2), info(), slots)).is_err());
        assert!(e.io.writes.is_empty());
    }
    assert_eq!(
        run(e.start_dp_audio(path(2), info())),
        Err(Error::Unsupported)
    );
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-mst-audio",
    dcn401_mst_audio_rejects_unproven_payload_and_source_before_programming
);

fn dcn401_mst_audio_partial_failures_retain_both_owners() -> TestResult {
    for stopping in [false, true] {
        let (mut e, mut link) = fixture(1, ColorDepth::Bpc8);
        if stopping {
            start_audio(&mut e);
        }
        e.io.drop = Some(if stopping {
            az_at(1) + 4
        } else {
            dio(1, 0x20ba)
        });
        let result = if stopping {
            run(e.stop_dp_audio(path(2)))
        } else {
            run(e.start_mst_audio(path(2), info(), 24)).map(|_| ())
        };
        assert!(matches!(result, Err(Error::Readback(_))));
        assert!(matches!(e.status.state, State::Failed(_)));
        assert!(e.status.dp_audio.is_some() && e.status.mst_audio_payload.is_some());
        let writes = e.io.writes.len();
        assert_eq!(e.select_display(1), Err(Error::Busy));
        assert_eq!(run(e.stop_dp_video(&mut link, path(2))), Err(Error::Busy));
        assert!(run(e.stop_dp_audio(path(2))).is_err());
        assert_eq!(e.io.writes.len(), writes);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-mst-audio",
    dcn401_mst_audio_partial_failures_retain_both_owners
);

fn dcn401_mst_audio_payload_drift_blocks_stop_without_writes() -> TestResult {
    let (mut e, _) = fixture(1, ColorDepth::Bpc8);
    let a = start_audio(&mut e);
    // Reordering the completed table is legitimate when another payload leaves.
    let row = e.io.fake().regs[&dio(2, 0x2150)];
    e.io.fake().regs.insert(dio(2, 0x2150), 0);
    e.io.fake().regs.insert(dio(2, 0x2151), row);
    let f = e.status.dp_video_running.unwrap().frontend;
    e.dp_audio_verify(&f, &a).unwrap();
    e.io.fake().regs.insert(dio(1, 0x214d), 0);
    let writes = e.io.writes.len();
    assert!(e.dp_audio_verify(&f, &a).is_err());
    assert!(run(e.stop_dp_audio(path(2))).is_err());
    assert_eq!(e.io.writes.len(), writes);
    assert_eq!(e.status.dp_audio, Some(a));
    assert!(e.status.mst_audio_payload.is_some());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-mst-audio",
    dcn401_mst_audio_payload_drift_blocks_stop_without_writes
);

fn dcn401_mst_audio_two_streams_survive_link_owner_handover() -> TestResult {
    let (mut e, mut link) = fixture(1, ColorDepth::Bpc8);
    let a0 = start_audio(&mut e);
    let bank1 = e.layout.dio_clock - 0xa0 * 4;
    assert_eq!(e.io.fake().regs[&(bank1 + 0xaf * 4)], 7_200_000);
    e.select_display(1).unwrap();
    let mut r = request(3);
    r.signal = Signal::DisplayPort;
    let c = clock(r);
    run(e.prepare(r, c)).unwrap();
    run(e.prepare_blank(
        BlankRequest {
            pipe: 3,
            depth: ColorDepth::Bpc8,
            limited: false,
            ycbcr420: false,
        },
        c,
    ))
    .unwrap();
    e.io.fake().regs.insert(bank1 + (0x80 + 4 * 3) * 4, 0x1090);
    let sources = e.io.fake().regs[&(bank1 + 0x68 * 4)];
    e.io.fake().regs.insert(bank1 + 0x68 * 4, sources | 4 << 9);
    e.attach_mst_link(2).unwrap();
    e.io.inner.inner.inner.stream = 3;
    e.io.inner.inner.pipe = 3;
    run(e.prepare_dp_frontend(&mut link, path(2), super::super::req(3, 3), c)).unwrap();
    run(e.start_dp_video(&mut link, path(2), c)).unwrap();
    set_payload(&mut e, &[(1, 24), (3, 24)]);
    let a1 = start_audio(&mut e);
    assert_eq!(a0.endpoint, 1);
    assert_eq!(a1.endpoint, 3);
    let other_audio = [
        dio(3, 0x20ba),
        dio(3, 0x2082),
        dio(3, 0x2141),
        dio(3, 0x2085),
        dio(3, 0x214d),
    ];
    let before = other_audio.map(|at| e.io.fake().regs[&at]);
    e.select_display(0).unwrap();
    e.io.inner.inner.inner.stream = 1;
    e.io.inner.inner.pipe = 2;
    let n = e.io.writes.len();
    run(e.stop_dp_audio(path(2))).unwrap();
    assert_eq!(e.io.inner.az[&(3, 0x54)] & 0x8000_0001, 0x8000_0000);
    assert_eq!(other_audio.map(|at| e.io.fake().regs[&at]), before);
    assert!(!e.io.writes[n..]
        .iter()
        .any(|(at, _)| other_audio.contains(at) || *at == az_at(3) + 4));
    assert_eq!(e.io.fake().regs[&(bank1 + 0xab * 4)] & 0x10_0030, 0x10_0010);
    assert_eq!(e.io.fake().regs[&(bank1 + 0xaf * 4)], 7_200_000);
    run(e.stop_dp_video(&mut link, path(2))).unwrap();
    // The manager removes this payload after video and before the frontend.
    e.io.fake().regs.insert(dio(2, 0x2150), 3 | 24 << 8);
    e.io.fake().regs.insert(dio(1, 0x214d), 0);
    run(e.stop_dp_frontend(path(2))).unwrap();
    e.hand_over_mst_link(2, 1).unwrap();
    e.select_display(1).unwrap();
    e.io.inner.inner.inner.stream = 3;
    e.io.inner.inner.pipe = 3;
    let f = e.status.dp_video_running.unwrap().frontend;
    e.dp_audio_verify(&f, &a1).unwrap();
    run(e.stop_dp_audio(path(2))).unwrap();
    run(e.stop_dp_video(&mut link, path(2))).unwrap();
    run(e.stop_dp_frontend(path(2))).unwrap();
    run(e.stop_dp_link(&mut link, path(2))).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-mst-audio",
    dcn401_mst_audio_two_streams_survive_link_owner_handover
);

fn dcn401_mst_audio_endpoint_collision_includes_other_transports() -> TestResult {
    for transport in 0..4 {
        let (mut e, _) = fixture(1, ColorDepth::Bpc8);
        let a = start_audio(&mut e);
        run(e.stop_dp_audio(path(2))).unwrap();
        let parked = &mut e.displays.parked[1];
        match transport {
            0 => parked.hdmi_audio = Some(a),
            1 => parked.dp_audio = Some(a),
            2 => parked.frl_audio = Some(a),
            _ => parked.uhbr_audio = Some(a),
        }
        let writes = e.io.writes.len();
        assert_eq!(
            run(e.start_mst_audio(path(2), info(), 24)),
            Err(Error::Busy)
        );
        assert_eq!(e.io.writes.len(), writes);
        assert!(e.status.dp_audio.is_none() && e.status.mst_audio_payload.is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-mst-audio",
    dcn401_mst_audio_endpoint_collision_includes_other_transports
);

fn dcn401_mst_audio_requires_matching_live_scanout_witnesses() -> TestResult {
    let (mut e, _) = fixture(1, ColorDepth::Bpc8);
    let t = e
        .status
        .dp_video_running
        .unwrap()
        .frontend
        .blank
        .timing
        .request
        .timing;
    let soc = dml::Soc {
        umc_channels: 16,
        uclk_khz: 1_250_000,
        fclk_khz: [300_000, 2_500_000],
        dcfclk_khz: [200_000, 1_564_000],
        socclk_khz: 300_000,
        dispclk_max_khz: 2_000_000,
        dppclk_max_khz: 2_000_000,
        dentist_vco_khz: 4_500_000,
        dchub_refclk_khz: 50_000,
    };
    let live = ScanoutRunning {
        pipe: 2,
        stream: 1,
        plan: dml::admit(
            &soc,
            &dml::Mode {
                timing: t,
                pitch: (t.h_active + 63) & !63,
                ycbcr420: false,
                dsc: None,
            },
        )
        .unwrap(),
        address: 0x8_0010_2000,
        frame_before: 2,
        frame_after: 3,
    };
    // Model the completed scanout owner's live registers, independently of
    // audio. The full surface/lock/VUPDATE sequence has its own chain tests.
    let h = |r: u64| BASE + (r + 2 * 0xdc) * 4;
    let m = |r: u64| MPC_BASE + (r + 2 * 0x15) * 4;
    let addr = live.address;
    for (at, value) in [
        (h(0x5f4), 0),
        (h(0x5f5), 1),
        (BASE + (0xcc5 + 2 * 0x16b) * 4, 0x10),
        (BASE + (0x1854 + 2 * 0x5a) * 4, 0),
        (h(0x60a), addr as u32),
        (h(0x60b), (addr >> 32) as u32),
        (h(0x61c), addr as u32),
        (h(0x61d), (addr >> 32) as u32),
        (m(0), 2),
        (m(1), 0xf),
        (m(2), 2),
        (m(5), 2),
        (m(0xe), 2),
        (MPC_BASE + (0x2f2 + 2 * 4) * 4, 2),
    ] {
        e.io.fake().regs.insert(at, value);
    }
    e.status.scanout = Some(live);
    e.status.state = State::ScanoutRunning(2);
    let a = start_audio(&mut e);
    e.dp_video_verify_scanout(live).unwrap();
    // Source loss and a mismatched retained scanout both block stop before
    // samples, packets or the endpoint can be changed.
    let n = e.io.writes.len();
    e.io.fake().regs.insert(h(0x61c), 0);
    assert!(run(e.stop_dp_audio(path(2))).is_err());
    assert_eq!(e.io.writes.len(), n);
    e.io.fake().regs.insert(h(0x61c), addr as u32);
    e.status.scanout.as_mut().unwrap().stream = 0;
    assert_eq!(run(e.stop_dp_audio(path(2))), Err(Error::Invalid));
    assert_eq!(e.io.writes.len(), n);
    assert_eq!(e.status.dp_audio, Some(a));
    e.status.scanout = Some(live);
    run(e.stop_dp_audio(path(2))).unwrap();
    e.dp_video_verify_scanout(live).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-mst-audio",
    dcn401_mst_audio_requires_matching_live_scanout_witnesses
);

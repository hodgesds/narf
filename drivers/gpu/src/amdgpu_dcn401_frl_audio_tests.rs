use super::*;
use crate::amdgpu_dcn401_otg::tests::hdmi_link as hdmi;
use crate::amdgpu_frl_cap::FrlCap;
use crate::amdgpu_navi48_boot::{frl_audio, frl_carries, FrlRate};

struct AudioIo {
    inner: FrlIo,
    az: alloc::collections::BTreeMap<(u8, u32), u32>,
    index: [u32; 4],
    writes: alloc::vec::Vec<(u64, u32)>,
    drop_at: Option<u64>,
    drop_disable: bool,
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
                if !(self.drop_disable && index == 0x54 && value & 0x8000_0000 == 0) {
                    self.az.insert((e, index), value);
                }
                return;
            }
        }
        self.inner.write(at, value);
    }
}
fn info() -> AudioInfo {
    let mut info = hdmi::audio_info();
    info.modes[0].channels = 8;
    info.modes[0].rates = 0x7f;
    info.speakers = 0x4f;
    info
}
fn fixture(rate: u8, y420: bool, depth: ColorDepth) -> (Engine<AudioIo>, Fw) {
    let rate = FrlRate::new(rate).unwrap();
    let (mut e, fw, mut request, clock) = prepared_frl_video_rate(y420, depth, rate);
    let blank = e.status.blanks[usize::from(request.pipe)].unwrap();
    let t = blank.timing.request.timing;
    let bpc = match depth {
        ColorDepth::Bpc8 => 8,
        ColorDepth::Bpc10 => 10,
        ColorDepth::Bpc12 => 12,
    };
    let a = frl_audio_info(info(), t.v_active).unwrap();
    let Some(FrlCap::Ok {
        audio_packets_line,
        borrow,
        ..
    }) = frl_carries(&t, bpc, y420, rate, frl_audio(Some(a), t.v_active))
    else {
        panic!("fixture FRL bandwidth");
    };
    request.audio_packets_line = audio_packets_line as u8;
    request.borrow = borrow;
    run(e.start_frl_video(path(2), request, clock)).unwrap();
    (
        Engine {
            io: AudioIo {
                inner: e.io,
                az: alloc::collections::BTreeMap::new(),
                index: [0; 4],
                writes: alloc::vec::Vec::new(),
                drop_at: None,
                drop_disable: false,
            },
            authority: e.authority,
            layout: e.layout,
            status: e.status,
            displays: e.displays,
        },
        fw,
    )
}
fn reg(e: &Engine<AudioIo>, r: u64) -> u32 {
    reg_at(e, frl(r))
}
fn reg_at(e: &Engine<AudioIo>, at: u64) -> u32 {
    e.io.inner.inner.regs.get(&at).copied().unwrap_or(0)
}

/// ACR rows from hpo_enc401's Linux table, at every FRL rate. The HDA
/// endpoint remains HDMI and, as dce_aud_az_configure does, carries the
/// sink's AC-3 SAD and HBR beside LPCM, independently of video depth.
fn dcn401_frl_audio_programs_afmt4_acr_endpoint_and_retires() -> TestResult {
    for (code, nc) in [
        (1, [4224, 171875, 5292, 156250, 5760, 156250]),
        (2, [4032, 328125, 5292, 312500, 6048, 328125]),
        (3, [4032, 328125, 5292, 312500, 6048, 328125]),
        (4, [4032, 437500, 3969, 312500, 6048, 437500]),
        (5, [3456, 468750, 3969, 390625, 5184, 468750]),
        (6, [3072, 500000, 3969, 468750, 4752, 515625]),
    ] {
        for (y420, depth) in [
            (false, ColorDepth::Bpc8),
            (true, ColorDepth::Bpc10),
            (true, ColorDepth::Bpc12),
        ] {
            let (mut e, mut fw) = fixture(code, y420, depth);
            let v = e.status.frl_video_running.unwrap();
            let a = run(e.start_hdmi_audio(path(2), info())).unwrap();
            assert_eq!(a.endpoint, v.request.pipe);
            // 8-channel 192-kHz LPCM fits, so the HBR probe passes too.
            assert!(!a.dp && a.hbr);
            assert_eq!(a.info.mode_count, 2);
            assert_eq!(a.descriptors[0], 0x7f07_7f07);
            assert_eq!(a.descriptors[1], 0x0050_0705); // AC-3, 6 channels
            assert!(a.descriptors[2..].iter().all(|d| *d == 0));
            assert_eq!(reg_at(&e, e.layout.base + 0x40c * 4), 5);
            assert_eq!(a.channels, 0xff);
            let bank = e.layout.dio_clock - 0xa0 * 4;
            assert_eq!(
                e.io.inner.inner.regs[&(bank + 0xab * 4)] & 0x10_0030,
                0x10_0010
            );
            assert_eq!(e.io.inner.inner.regs[&(bank + 0xae * 4)], 240_000);
            assert_eq!(
                e.io.inner.inner.regs[&(bank + 0xaf * 4)],
                v.timing.blank.timing.clock.reference_hz / 100
            );
            for (i, pair) in nc.chunks_exact(2).enumerate() {
                assert_eq!(reg(&e, 0x8f2 + 2 * i as u64), pair[1] << 12);
                assert_eq!(reg(&e, 0x8f3 + 2 * i as u64), pair[0]);
            }
            for (r, mask, want) in [
                (0x8e2, 0x8000_1103, 0x1000),
                (0x91d, 0x1000_ff01, 0xff00),
                (0x920, 0x30f0_0000, 0x0010_0000),
                (0x921, 0x00f0_0000, 0x0020_0000),
                (0x927, 0xffffff, 0x876543),
                (0x92a, 0x0400_0001, 0x0400_0001),
                (0x92d, 7, 1),
                (0x92f, 0x30, 0),
                (0x8e3, 0x7fff_7000, 2 << 16 | 0x1000),
            ] {
                assert_eq!(reg(&e, r) & mask, want);
            }
            assert_eq!(e.io.az[&(a.endpoint, 0x54)], 0x8000_0000);
            assert_eq!(e.io.az[&(a.endpoint, 0x25)] & 0x30000, 0x10000);
            assert_eq!(e.io.az[&(a.endpoint, 0x38)] & 1, 1);
            assert_eq!(e.io.az[&(a.endpoint, 0x29)], 0x0050_0705);
            assert_eq!(run(e.stop_frl_video(path(2))), Err(Error::Busy));
            run(e.frl_ffe(&mut fw, path(2), 1)).unwrap();
            assert_eq!(e.status.frl_audio, Some(a));
            run(e.stop_hdmi_audio(path(2))).unwrap();
            assert!(e.status.frl_audio.is_none());
            assert_eq!(reg(&e, 0x92a) & 1, 0);
            assert_eq!(reg(&e, 0x8e2) & 0x1003, 0);
            assert_eq!(reg(&e, 0x8e3) & 0x1000, 0x1000);
            assert_eq!(e.io.az[&(a.endpoint, 0x54)], 0);
            // AFMT4 never changes DIO AFMT clocks or packet/source registers.
            for p in 0..4 {
                assert!(e
                    .io
                    .writes
                    .iter()
                    .all(|&(at, _)| !(hdmi::dio(p, 0x2075)..=hdmi::dio(p, 0x20ba)).contains(&at)));
            }
            run(e.stop_frl_video(path(2))).unwrap();
            run(e.stop_frl_link(&mut fw, path(2))).unwrap();
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-audio",
    dcn401_frl_audio_programs_afmt4_acr_endpoint_and_retires
);

fn dcn401_frl_audio_refuses_unreserved_or_inherited_work() -> TestResult {
    let (mut e, _fw) = fixture(6, false, ColorDepth::Bpc8);
    assert_eq!(
        run(e.start_hdmi_audio(path(1), info())),
        Err(Error::Invalid)
    );
    assert!(e.io.writes.is_empty());
    e.status
        .frl_video_running
        .as_mut()
        .unwrap()
        .request
        .audio_packets_line = 1;
    assert_eq!(
        run(e.start_hdmi_audio(path(2), info())),
        Err(Error::Invalid)
    );
    assert!(e.io.writes.is_empty());
    for r in [0x92a, 0x8e2] {
        let (mut e, _fw) = fixture(6, false, ColorDepth::Bpc8);
        e.io.inner.inner.regs.insert(frl(r), 1);
        assert_eq!(run(e.start_hdmi_audio(path(2), info())), Err(Error::Busy));
        assert!(e.io.writes.is_empty());
        assert!(e.status.frl_audio.is_none());
    }
    let (mut e, _fw) = fixture(6, false, ColorDepth::Bpc8);
    e.io.az.insert((1, 0x54), 0x8000_0000);
    assert_eq!(run(e.start_hdmi_audio(path(2), info())), Err(Error::Busy));
    assert_eq!(e.io.writes, [(az(1), 0x54)]);
    assert!(e.status.frl_audio.is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-audio",
    dcn401_frl_audio_refuses_unreserved_or_inherited_work
);

fn dcn401_frl_audio_partial_writes_and_late_drift_retain_owners() -> TestResult {
    for r in [0x8e2, 0x8f2, 0x92d, 0x91d, 0x92a] {
        let (mut e, _fw) = fixture(6, false, ColorDepth::Bpc8);
        e.io.drop_at = Some(frl(r));
        let v = e.status.frl_video_running;
        assert!(run(e.start_hdmi_audio(path(2), info())).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
        assert!(e.status.frl_audio.is_some());
        assert_eq!(e.status.frl_video_running, v);
        assert_eq!(run(e.start_hdmi_audio(path(2), info())), Err(Error::Busy));
        assert_eq!(run(e.stop_frl_video(path(2))), Err(Error::Busy));
    }
    for r in [0x8f2, 0x92d, 0x91d, 0x8e1] {
        let (mut e, mut fw) = fixture(6, false, ColorDepth::Bpc8);
        run(e.start_hdmi_audio(path(2), info())).unwrap();
        *e.io.inner.inner.regs.get_mut(&frl(r)).unwrap() ^= if r == 0x91d {
            0x100
        } else if r == 0x8f2 {
            0x1000
        } else {
            1
        };
        let before = e.io.writes.len();
        assert_eq!(
            run(e.stop_hdmi_audio(path(2))),
            Err(Error::Readback(frl(r)))
        );
        assert_eq!(
            run(e.frl_ffe(&mut fw, path(2), 1)),
            Err(Error::Readback(frl(r)))
        );
        assert_eq!(e.io.writes.len(), before);
        assert!(e.status.frl_audio.is_some());
    }
    for endpoint in [false, true] {
        let (mut e, _fw) = fixture(6, false, ColorDepth::Bpc8);
        let a = run(e.start_hdmi_audio(path(2), info())).unwrap();
        if endpoint {
            e.io.drop_disable = true;
        } else {
            e.io.drop_at = Some(frl(0x8e2));
        }
        assert!(run(e.stop_hdmi_audio(path(2))).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
        assert_eq!(e.status.frl_audio, Some(a));
        assert_eq!(run(e.stop_frl_video(path(2))), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-audio",
    dcn401_frl_audio_partial_writes_and_late_drift_retain_owners
);

fn dcn401_frl_audio_shares_wall_clock_and_excludes_endpoint_collisions() -> TestResult {
    let (mut h, mut fw, hc) = hdmi::fixture(0, 0, 0);
    run(h.prepare_hdmi_link(&mut fw, hdmi::path(0), hdmi::link(0, 0), hc)).unwrap();
    run(h.start_hdmi_video(hdmi::path(0), hc)).unwrap();
    run(h.start_hdmi_audio(hdmi::path(0), hdmi::audio_info())).unwrap();
    let (mut e, _fw) = fixture(6, false, ColorDepth::Bpc8);
    e.displays.selected = 1;
    e.displays.parked[0] = *h.status;
    let a = run(e.start_hdmi_audio(path(2), info())).unwrap();
    let bank = e.layout.dio_clock - 0xa0 * 4;
    assert_eq!(e.io.inner.inner.regs[&(bank + 0xab * 4)] & 0x37, 0);
    assert_eq!(e.io.inner.inner.regs[&(bank + 0xad * 4)], 1_485_000);
    run(e.stop_hdmi_audio(path(2))).unwrap();
    // Earlier FRL takes DTO1 even with a later TMDS stream, like Linux's
    // first-HDMI-pipe walk (FRL has no audio DTBCLK DTO on DCN401).
    let mut sibling = e.displays.parked[0];
    sibling
        .hdmi_video_running
        .as_mut()
        .unwrap()
        .link
        .request
        .pipe = 3;
    e.displays.parked[0] = sibling;
    run(e.start_hdmi_audio(path(2), info())).unwrap();
    assert_eq!(e.io.inner.inner.regs[&(bank + 0xab * 4)] & 0x30, 0x10);
    run(e.stop_hdmi_audio(path(2))).unwrap();
    assert_eq!(e.io.inner.inner.regs[&(bank + 0xab * 4)] & 0x37, 3);
    e.displays.parked[0].hdmi_audio = Some(a); // endpoint already owned
    let before = e.io.writes.len();
    assert_eq!(run(e.start_hdmi_audio(path(2), info())), Err(Error::Busy));
    assert_eq!(e.io.writes.len(), before);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-audio",
    dcn401_frl_audio_shares_wall_clock_and_excludes_endpoint_collisions
);

fn dcn401_frl_audio_limits_sd_layout_and_rejects_invalid_lpcm() -> TestResult {
    let raw = info();
    for lines in [480, 576, 1080] {
        let normalized = frl_audio_info(raw, lines).unwrap();
        assert_eq!(normalized.mode_count, 2);
        assert_eq!(
            normalized.modes[0].channels,
            if lines <= 576 { 2 } else { 8 }
        );
        // Only LPCM is clamped; AC-3 passthrough keeps its six channels.
        assert_eq!(normalized.modes[1], raw.modes[1]);
        assert_eq!(
            normalized.speakers,
            if lines <= 576 { 1 } else { raw.speakers }
        );
        assert_eq!(
            frl_audio(Some(normalized), lines).layout,
            u8::from(lines > 576)
        );
    }
    for invalid in 0..7 {
        let mut a = raw;
        match invalid {
            0 => a.mode_count = 0,
            1 => a.mode_count = 17,
            2 => a.modes[0].format = 2,
            3 => a.modes[0].channels = 0,
            4 => a.modes[0].channels = 9,
            5 => a.modes[0].rates = 0x80,
            _ => a.modes[0].byte2 = 0xf8,
        }
        let (mut e, _fw) = fixture(6, false, ColorDepth::Bpc8);
        assert_eq!(run(e.start_hdmi_audio(path(2), a)), Err(Error::Unsupported));
        assert!(e.io.writes.is_empty());
        assert!(e.status.frl_audio.is_none());
    }
    // One-bit audio, DST, reserved codes and compressed SADs without
    // channels or rates never reach the endpoint.
    let mut a = raw;
    a.mode_count = 8;
    for (i, (format, channels, rates)) in [
        (9, 2, 7),
        (13, 2, 7),
        (15, 2, 7),
        (7, 0, 7),
        (7, 9, 7),
        (7, 6, 0x80),
    ]
    .into_iter()
    .enumerate()
    {
        a.modes[i] = AudioMode {
            format,
            channels,
            rates,
            byte2: 0,
        };
    }
    a.modes[7] = raw.modes[0];
    a.modes[6] = AudioMode {
        format: 10, // E-AC-3
        channels: 8,
        rates: 0x47,
        byte2: 1,
    };
    let kept = frl_audio_info(a, 1080).unwrap();
    assert_eq!(kept.mode_count, 2);
    assert_eq!(kept.modes[0].format, 10);
    assert_eq!(kept.modes[0].rates, 0x47);
    assert_eq!(kept.modes[1], raw.modes[0]);
    // Scanout state without its retained fetch witness cannot authorize audio.
    let (mut e, _fw) = fixture(6, false, ColorDepth::Bpc8);
    e.status.state = State::ScanoutRunning(1);
    assert_eq!(run(e.start_hdmi_audio(path(2), raw)), Err(Error::Invalid));
    assert!(e.io.writes.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-audio",
    dcn401_frl_audio_limits_sd_layout_and_rejects_invalid_lpcm
);

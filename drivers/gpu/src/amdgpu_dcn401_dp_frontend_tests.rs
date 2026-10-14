use super::*;
#[path = "amdgpu_dcn401_dp_video_tests.rs"]
mod video;

struct FrontendIo {
    inner: LinkIo,
    stream: u8,
    // Gate a native clock or FIFO acknowledgement, or delay each transition.
    stall: u8,
    delays: [u8; 3],
    transition: Option<usize>,
}
impl FrontendIo {
    fn fake(&mut self) -> &mut Fake {
        &mut self.inner.inner.inner
    }
}
impl Io for FrontendIo {
    fn read(&mut self, at: u64) -> u32 {
        if let Some(t) = self.transition {
            let target = dio(self.stream, if t == 0 { 0x2094 } else { 0x209b });
            if at == target && self.stall & (1 << t) == 0 {
                if self.delays[t] != 0 {
                    self.delays[t] -= 1;
                } else {
                    let value = self.fake().regs.get(&at).copied().unwrap_or(0);
                    let next = if t == 0 {
                        (value & !0xc00) | if value & 0x10 != 0 { 0xc00 } else { 0 }
                    } else {
                        (value & !0x100000) | if value & 2 != 0 { 0x100000 } else { 0 }
                    };
                    self.fake().regs.insert(at, next);
                    self.transition = None;
                }
            }
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        let old = self.fake().regs.get(&at).copied().unwrap_or(0);
        self.inner.write(at, value);
        if at == dio(self.stream, 0x2094) && (old ^ value) & 0x10 != 0 {
            self.transition = Some(0);
        }
        if at == dio(self.stream, 0x209b) && (old ^ value) & 2 != 0 {
            self.transition = Some(if value & 2 != 0 { 1 } else { 2 });
        }
    }
}
fn fixture(
    p: u8,
    stream: u8,
    pipe: u8,
    depth: ColorDepth,
) -> (Engine<FrontendIo>, Link, dccg::Applied) {
    fixture_range(p, stream, pipe, depth, false)
}
fn fixture_range(
    p: u8,
    stream: u8,
    pipe: u8,
    depth: ColorDepth,
    limited: bool,
) -> (Engine<FrontendIo>, Link, dccg::Applied) {
    let (mut e, mut io) = super::fixture(p, 4, LinkRate::Hbr3, TrainingPattern::Tps4);
    // Exercise the public engine sequence, including prepared timing before PHY
    // enable/training. No forged completion records or hand-built ready state.
    run(e.disable_dp_phy(&mut io, path(p))).unwrap();
    let mut req = request(pipe);
    req.signal = Signal::DisplayPort;
    let c = clock(req);
    run(e.prepare(req, c)).unwrap();
    run(e.prepare_blank(
        BlankRequest {
            pipe,
            depth,
            limited,
        },
        c,
    ))
    .unwrap();
    let bank1 = e.layout.dio_clock - 0xa0 * 4;
    e.io.inner
        .inner
        .regs
        .insert(bank1 + (0x80 + 4 * u64::from(pipe)) * 4, 0x1090);
    e.io.inner
        .inner
        .regs
        .insert(bank1 + 0x68 * 4, 4 << (pipe * 3));
    run(e.enable_dp_phy(&mut io, path(p), io_settings())).unwrap();
    run(e.train_dp_link(&mut io, path(p), false, false)).unwrap();
    let source = dio(stream, 0x2093);
    e.io.inner.inner.regs.insert(source, 0x80000176); // clear only native routing fields
    e.io.inner
        .inner
        .regs
        .insert(dio(stream, 0x211f), 0x80010731);
    e.io.inner
        .inner
        .regs
        .insert(dio(stream, 0x2120), 0x12345678);
    e.io.inner
        .inner
        .regs
        .insert(dio(stream, 0x2124), 0x123456c0);
    // Stable inherited steering reset; its release belongs to video unblank.
    e.io.inner.inner.regs.insert(dio(stream, 0x2123), 6);
    e.io.inner.inner.encoder_stall = 1 << stream; // FrontendIo supplies clock witnesses
    let engine = Engine {
        io: FrontendIo {
            inner: e.io,
            stream,
            stall: 0,
            delays: [0; 3],
            transition: None,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
    };
    (engine, io, c)
}
fn io_settings() -> DpPhySettings {
    DpPhySettings {
        lanes: 4,
        rate: LinkRate::Hbr3,
    }
}
fn req(stream: u8, pipe: u8) -> DpFrontendRequest {
    DpFrontendRequest { stream, pipe }
}
/// Limited-range RGB sets MSA MISC0 bit 3 (CEA dynamic range) beside the
/// component depth, as dcn10 stream encoders do for COLOR_SPACE_SRGB_LIMITED.
fn dcn401_dp_frontend_signals_limited_range_in_msa_misc0() -> TestResult {
    let (mut e, mut io, c) = fixture_range(1, 2, 3, ColorDepth::Bpc10, true);
    run(e.prepare_dp_frontend(&mut io, path(1), req(2, 3), c)).unwrap();
    if e.io.fake().regs[&dio(2, 0x2120)] != (2 << 5 | 8) << 24 {
        return TestResult::Fail("MSA MISC0 dynamic range");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_frontend_signals_limited_range_in_msa_misc0
);
fn dcn401_dp_frontend_programs_independent_routes_rgb_depth_and_native_msa() -> TestResult {
    for p in 0..4 {
        for stream in 0..4 {
            for pipe in 0..4 {
                for (depth, code) in [
                    (ColorDepth::Bpc8, 1),
                    (ColorDepth::Bpc10, 2),
                    (ColorDepth::Bpc12, 3),
                ] {
                    let (mut e, mut io, c) = fixture(p, stream, pipe, depth);
                    let first = e.io.fake().writes.len();
                    let ready =
                        run(e.prepare_dp_frontend(&mut io, path(p), req(stream, pipe), c)).unwrap();
                    assert_eq!(e.status.state, State::DpFrontendReady(stream));
                    assert!(!e.status.state.reusable());
                    assert_eq!(ready.pixels_per_cycle, 1);
                    let regs = &e.io.fake().regs;
                    assert_eq!(
                        regs[&dio(stream, 0x2093)],
                        0x80000100 | (u32::from(pipe) * 0x11)
                    );
                    assert_eq!(regs[&dio(stream, 0x211f)], 0x80000000 | code << 8);
                    assert_eq!(regs[&dio(stream, 0x2120)], code << 29);
                    assert_eq!(regs[&dio(stream, 0x2124)], 0x12345600);
                    assert_eq!(regs[&dio(stream, 0x2162)], 2200 << 16 | 1125);
                    assert_eq!(regs[&dio(stream, 0x2163)], 192 << 16 | 41);
                    assert_eq!(regs[&dio(stream, 0x2164)], 44 << 16 | 0x8005);
                    assert_eq!(regs[&dio(stream, 0x2165)], 1920 << 16 | 1080);
                    assert_eq!(regs[&dio(stream, 0x209b)] & 0x1003ff, 0x1d);
                    assert_eq!(regs[&dio(stream, 0x2094)] & 0x2c37, 0xc10);
                    assert_eq!(
                        regs[&(BASE + (0x1f0d + u64::from(stream)) * 4)] & 7,
                        u32::from(p)
                    );
                    assert_eq!(regs[&dio(p, 0x20bc)] & 0x7f00, 0x100 << stream);
                    let root = e.layout.dio_clock + u64::from(stream) * 4;
                    assert_eq!(e.io.fake().regs[&root] & 0x710, 0x10 | u32::from(p) << 8);
                    assert_eq!(run(e.stop_dp_link(&mut io, path(p))), Err(Error::Busy));
                    assert_eq!(
                        run(e.prepare_dp_frontend(&mut io, path(p), req(stream, pipe), c)),
                        Err(Error::Busy)
                    );
                    run(e.stop_dp_frontend(path(p))).unwrap();
                    assert_eq!(e.status.state, State::DpLinkTrained(p));
                    assert_eq!(e.status.dp_frontend_ready, Some(ready)); // history only
                    assert_eq!(e.io.fake().regs[&root] & 0x710, 0);
                    assert_eq!(e.io.fake().regs[&dio(p, 0x20bc)] & 0x7f00, 0);
                    // No video/timing enable, PHY firmware command or writes to unrelated encoders.
                    for &(at, _) in &e.io.fake().writes[first..] {
                        assert_ne!(at, dio(stream, 0x2122));
                        assert_ne!(at, BASE + (0x1b43 + u64::from(pipe) * 0x80) * 4);
                    }
                    run(e.stop_dp_link(&mut io, path(p))).unwrap();
                    assert_eq!(e.status.state, State::DpPhyDisabled);
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_frontend_programs_independent_routes_rgb_depth_and_native_msa
);

fn dcn401_dp_frontend_rejects_bad_owners_routes_and_inherited_work_before_writes() -> TestResult {
    for (at, value) in [
        (dio(1, 0x2094), 0xc00),
        (dio(1, 0x2094), 0x20),
        (dio(1, 0x209b), 0x80),
        (dio(1, 0x209b), 0x100000),
        (dio(1, 0x2123), 2),
        (dio(1, 0x2124), 1),
        (dio(1, 0x2122), 1),
        (dio(1, 0x2141), 1),
        (dio(1, 0x2091), 0x1000),
        (dio(1, 0x213d), 1),
        (dio(1, 0x213d), 0x10),
        (dio(1, 0x2170), 0x10),
        (dio(1, 0x2174), 0x1000),
        (dio(3, 0x20bc), 0x200),
        (dio(3, 0x20bc), 0x1000),
        (0x162a1 * 4, 0x10),
        (BASE + (0x1b89 + 2 * 0x80) * 4, 1),
        (BASE + (0x1b2a + 2 * 0x80) * 4, 123),
        (BASE + (0x1841 + 2 * 0x5a) * 4, 0),
    ] {
        let (mut e, mut io, c) = fixture(0, 1, 2, ColorDepth::Bpc8);
        e.io.fake().dp_stall = 1 << 9;
        e.io.fake().regs.insert(at, value);
        let before = e.io.fake().writes.len();
        let aux = io.events.len();
        assert!(
            run(e.prepare_dp_frontend(&mut io, path(0), req(1, 2), c)).is_err(),
            "accepted {at:#x} = {value:#x}"
        );
        assert_eq!(e.io.fake().writes.len(), before);
        assert_eq!(io.events.len(), aux);
        assert_eq!(e.status.state, State::DpLinkTrained(0));
    }
    for bad in 0..6 {
        let (mut e, mut io, mut c) = fixture(0, 1, 2, ColorDepth::Bpc8);
        let mut r = req(1, 2);
        let mut path = path(0);
        match bad {
            0 => r.stream = 4,
            1 => r.pipe = 4,
            2 => path.aux = Some(0),
            3 => c.global.display_khz += 1,
            4 => e.status.blanks[2] = None,
            _ => io.fw.ready = false,
        };
        let before = e.io.fake().writes.len();
        assert!(run(e.prepare_dp_frontend(&mut io, path, r, c)).is_err());
        assert_eq!(e.io.fake().writes.len(), before);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_frontend_rejects_bad_owners_routes_and_inherited_work_before_writes
);

fn dcn401_dp_frontend_partial_writes_revocation_and_device_loss_block_replay() -> TestResult {
    let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
    let first = e.io.fake().writes.len();
    let mut regs = e.io.fake().regs.clone();
    run(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c)).unwrap();
    let writes = e.io.fake().writes.clone();
    for (index, &(at, value)) in writes.iter().enumerate().skip(first) {
        for kind in 0..3 {
            if kind == 0 && regs.get(&at).copied().unwrap_or(0) == value {
                continue;
            }
            let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
            let cap = e.authority;
            match kind {
                0 => e.io.fake().reject = Some(index + 1),
                1 => e.io.fake().revoke = Some((index + 1, cap)),
                _ => e.io.fake().gone = Some(index + 1),
            };
            assert!(run(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c)).is_err());
            assert!(matches!(e.status.state, State::Failed(_)));
            assert!(e.status.dp_frontend_ready.is_none());
            assert_eq!(
                run(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c)),
                Err(Error::Busy)
            );
            assert_eq!(run(e.stop_dp_link(&mut io, path(2))), Err(Error::Busy));
        }
        regs.insert(at, value);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_frontend_partial_writes_revocation_and_device_loss_block_replay
);

fn dcn401_dp_frontend_checks_sink_and_cancellation_at_every_aux_wait() -> TestResult {
    let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
    let first = io.step;
    run(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c)).unwrap();
    let steps = io.step - first;
    assert_eq!(steps, 6);
    for step in 1..=steps {
        for cancel in [false, true] {
            let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
            if cancel {
                io.pending = Some(io.step + step);
            } else {
                io.fail = Some((io.step + step, dmub::Error::CommandTimeout));
            }
            if cancel {
                let mut f = core::pin::pin!(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c));
                assert!(f
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            } else {
                assert_eq!(
                    run(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c)),
                    Err(Error::Firmware(dmub::Error::CommandTimeout))
                );
            }
            assert_eq!(
                e.status.state,
                if cancel {
                    State::PreparingDpFrontend(1)
                } else {
                    State::Failed(Error::Firmware(dmub::Error::CommandTimeout))
                }
            );
            assert!(e.status.dp_frontend_ready.is_none());
            let writes = e.io.fake().writes.len();
            let events = io.events.len();
            assert_eq!(
                run(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c)),
                Err(Error::Busy)
            );
            assert_eq!(run(e.stop_dp_link(&mut io, path(2))), Err(Error::Busy));
            assert_eq!(e.io.fake().writes.len(), writes);
            assert_eq!(io.events.len(), events);
        }
    }
    for late in [false, true] {
        let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
        io.status = if late {
            VecDeque::from([[0x77, 0x77, 1, 0, 0, 0], [0; 6]])
        } else {
            VecDeque::from([[0; 6]])
        };
        assert_eq!(
            run(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c)),
            Err(Error::DpTraining(DpTrainingError::LinkLost))
        );
        assert!(e.status.dp_frontend_ready.is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_frontend_checks_sink_and_cancellation_at_every_aux_wait
);

fn dcn401_dp_frontend_clock_and_fifo_handshakes_are_bounded_and_cancellation_safe() -> TestResult {
    for stage in 0..3 {
        for cancel in [false, true] {
            let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
            e.io.stall = 1 << stage;
            if cancel {
                let mut f = core::pin::pin!(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c));
                assert!(f
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            } else {
                assert_eq!(
                    run(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c)),
                    Err(Error::Timeout(dio(
                        1,
                        if stage == 0 { 0x2094 } else { 0x209b }
                    )))
                );
            }
            assert!(!e.status.state.reusable());
            assert!(e.status.dp_frontend_ready.is_none());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_frontend_clock_and_fifo_handshakes_are_bounded_and_cancellation_safe
);

fn dcn401_dp_frontend_stop_requires_clock_off_before_route_detach() -> TestResult {
    for cancel in [false, true] {
        let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
        let ready = run(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c)).unwrap();
        e.io.stall = 1;
        if cancel {
            let mut f = core::pin::pin!(e.stop_dp_frontend(path(2)));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        } else {
            assert_eq!(
                run(e.stop_dp_frontend(path(2))),
                Err(Error::Timeout(dio(1, 0x2094)))
            );
        }
        assert_eq!(e.status.dp_frontend_ready, Some(ready));
        assert_eq!(e.io.fake().regs[&dio(2, 0x20bc)] & 0x7f00, 0x200);
        let root = e.layout.dio_clock + 4;
        assert_eq!(e.io.fake().regs[&root] & 0x710, 0x210);
        assert_eq!(run(e.stop_dp_frontend(path(2))), Err(Error::Busy));
        assert_eq!(run(e.stop_dp_link(&mut io, path(2))), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_frontend_stop_requires_clock_off_before_route_detach
);

fn dcn401_dp_frontend_derives_pixel_packing_and_rejects_insufficient_capacity() -> TestResult {
    for (reference, pixels) in [
        (148_500_000, 1),
        (148_499_999, 2),
        (74_249_999, 4),
        (37_124_999, 8),
    ] {
        let (mut e, mut io, mut c) = fixture(0, 1, 2, ColorDepth::Bpc12);
        c.reference_hz = reference;
        e.status.pipes[2].as_mut().unwrap().clock = c;
        e.status.blanks[2].as_mut().unwrap().timing.clock = c;
        let ready = run(e.prepare_dp_frontend(&mut io, path(0), req(1, 2), c)).unwrap();
        assert_eq!(ready.pixels_per_cycle, pixels);
        assert_eq!(
            (e.io.fake().regs[&dio(1, 0x209b)] >> 8) & 3,
            pixels.trailing_zeros()
        );
    }
    for ref_hz in [0, 1] {
        let (mut e, mut io, mut c) = fixture(0, 1, 2, ColorDepth::Bpc12);
        c.reference_hz = ref_hz;
        e.status.pipes[2].as_mut().unwrap().clock = c;
        e.status.blanks[2].as_mut().unwrap().timing.clock = c;
        let writes = e.io.fake().writes.len();
        assert!(run(e.prepare_dp_frontend(&mut io, path(0), req(1, 2), c)).is_err());
        assert_eq!(e.io.fake().writes.len(), writes);
    }
    // Retain the actual one-lane RBR link: 1.296 Gbit/s cannot carry 1080p RGB.
    let (mut e, mut io, c) = fixture(0, 1, 2, ColorDepth::Bpc8);
    run(e.stop_dp_link(&mut io, path(0))).unwrap();
    io.settings = DpPhySettings {
        lanes: 1,
        rate: LinkRate::Rbr,
    };
    e.io.inner.inner.lanes = 8;
    run(e.enable_dp_phy(&mut io, path(0), io_settings_low())).unwrap();
    run(e.train_dp_link(&mut io, path(0), false, false)).unwrap();
    let writes = e.io.fake().writes.len();
    assert_eq!(
        run(e.prepare_dp_frontend(&mut io, path(0), req(1, 2), c)),
        Err(Error::Unsupported)
    );
    assert_eq!(e.io.fake().writes.len(), writes);
    TestResult::Pass
}
fn io_settings_low() -> DpPhySettings {
    DpPhySettings {
        lanes: 1,
        rate: LinkRate::Rbr,
    }
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_frontend_derives_pixel_packing_and_rejects_insufficient_capacity
);

fn dcn401_dp_frontend_late_changes_never_publish_ready_or_detach_a_changed_route() -> TestResult {
    for (at, value) in [
        (dio(1, 0x2093), 0),
        (dio(1, 0x211f), 0),
        (dio(1, 0x2120), 0),
        (dio(1, 0x2163), 0),
        (dio(2, 0x20bc), 0),
        (0x162a1 * 4, 0),
        (BASE + 0x1f0e * 4, 0),
        (dio(1, 0x2141), 1),
        (dio(1, 0x209b), 0x10001d),
        (BASE + (0x1b43 + 3 * 0x80) * 4, 1),
        (dio(0, 0x2095), 1),
    ] {
        let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
        io.change_at = Some((io.step + 6, at, value));
        assert!(run(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c)).is_err());
        assert!(e.status.dp_frontend_ready.is_none());
        assert!(!e.status.state.reusable());
    }
    for (at, value) in [
        (dio(1, 0x2122), 0x10000),
        (dio(2, 0x20bc), 0),
        (0x162a1 * 4, 0),
        (dio(1, 0x2141), 1),
    ] {
        let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
        run(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c)).unwrap();
        e.io.fake().regs.insert(at, value);
        let writes = e.io.fake().writes.len();
        assert!(run(e.stop_dp_frontend(path(2))).is_err());
        assert_eq!(e.io.fake().writes.len(), writes);
        assert_eq!(e.status.state, State::DpFrontendReady(1));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_frontend_late_changes_never_publish_ready_or_detach_a_changed_route
);

fn dcn401_dp_frontend_stop_faults_keep_link_and_frontend_owned() -> TestResult {
    let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
    run(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c)).unwrap();
    let first = e.io.fake().writes.len();
    let mut regs = e.io.fake().regs.clone();
    run(e.stop_dp_frontend(path(2))).unwrap();
    let writes = e.io.fake().writes.clone();
    for (index, &(at, value)) in writes.iter().enumerate().skip(first) {
        for revoke in [false, true] {
            if !revoke && regs.get(&at).copied().unwrap_or(0) == value {
                continue;
            }
            let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
            run(e.prepare_dp_frontend(&mut io, path(2), req(1, 3), c)).unwrap();
            let cap = e.authority;
            if revoke {
                e.io.fake().revoke = Some((index + 1, cap));
            } else {
                e.io.fake().reject = Some(index + 1);
            }
            assert!(run(e.stop_dp_frontend(path(2))).is_err());
            assert!(matches!(e.status.state, State::Failed(_)));
            assert_eq!(run(e.stop_dp_frontend(path(2))), Err(Error::Busy));
            assert_eq!(run(e.stop_dp_link(&mut io, path(2))), Err(Error::Busy));
        }
        regs.insert(at, value);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_frontend_stop_faults_keep_link_and_frontend_owned
);

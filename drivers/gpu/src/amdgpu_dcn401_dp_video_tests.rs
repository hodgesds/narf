use super::*;

struct VideoIo {
    inner: FrontendIo,
    pipe: u8,
    // Video on/off, steering reset assert/deassert, with independent latency.
    stall: u8,
    delays: [u8; 4],
    video_written: bool,
    steer_written: bool,
    watch: Option<u64>,
    waited: Arc<AtomicU32>,
    freeze_after_video: bool,
}
impl VideoIo {
    fn fake(&mut self) -> &mut Fake {
        self.inner.fake()
    }
}
impl Io for VideoIo {
    fn read(&mut self, at: u64) -> u32 {
        let value = self.inner.read(at);
        if value == u32::MAX {
            return value;
        }
        let stream = self.inner.stream;
        if self.freeze_after_video && at == dio(stream, 0x2122) && value & 1 != 0 {
            self.fake().stall |= 256;
        }
        if self.watch == Some(at) {
            let p = u64::from(self.pipe);
            let ctrl = self
                .fake()
                .regs
                .get(&(BASE + (0x1b43 + p * 0x80) * 4))
                .copied()
                .unwrap_or(0);
            let waiting = if at == dio(stream, 0x2122) {
                (value & 1) != ((value >> 16) & 1)
            } else if at == dio(stream, 0x2123) {
                ((value >> 1) & 1) != ((value >> 2) & 1)
            } else if at == dio(stream, 0x209b) {
                ((value >> 1) & 1) != ((value >> 20) & 1)
            } else if at == BASE + (0x1b43 + p * 0x80) * 4 {
                (value & 1) != ((value >> 16) & 1)
            } else if at == BASE + (0x1b84 + p * 0x80) * 4 {
                self.fake().retiring[p as usize] && value & 0x10000 != 0
            } else {
                ctrl & 1 != 0
            };
            if waiting {
                self.waited.store(1, Ordering::SeqCst);
            }
        }
        let transition = if at == dio(stream, 0x2122) && self.video_written {
            Some((
                if value & 1 != 0 { 0 } else { 1 },
                0x10000,
                (value & 1) << 16,
            ))
        } else if at == dio(stream, 0x2123) && self.steer_written {
            Some((if value & 2 != 0 { 2 } else { 3 }, 4, (value & 2) << 1))
        } else {
            None
        };
        if let Some((slot, mask, expected)) = transition {
            if value & mask != expected && self.stall & (1 << slot) == 0 {
                if self.delays[slot] != 0 {
                    self.delays[slot] -= 1;
                } else {
                    let next = (value & !mask) | expected;
                    self.fake().regs.insert(at, next);
                    return next;
                }
            }
        }
        value
    }
    fn write(&mut self, at: u64, value: u32) {
        let s = self.inner.stream;
        let p = u64::from(self.pipe);
        let ctrl = BASE + (0x1b43 + p * 0x80) * 4;
        if at == dio(s, 0x2122) {
            self.video_written = true;
            if value & 1 != 0 {
                assert_eq!(self.fake().regs[&ctrl] & 0x10001, 0x10001);
                assert_eq!(self.fake().regs[&(BASE + (0x185b + p * 0x5a) * 4)] & 1, 0);
            }
        }
        if at == dio(s, 0x2123) {
            self.steer_written = true;
        }
        if (at == ctrl && value & 1 == 0)
            || (at == BASE + (0x1acb + p * 0x10) * 4 && value & 0xf0000 == 0xf0000)
        {
            assert_eq!(self.fake().regs[&dio(s, 0x2122)] & 0x10001, 0);
        }
        if at == ctrl && value & 1 != 0 {
            assert_eq!(
                self.fake().regs[&(BASE + (0x530 + p) * 4)] & 0x80000000,
                0x80000000
            );
        }
        self.inner.write(at, value);
        if at == ctrl && value & 1 != 0 {
            *self
                .fake()
                .regs
                .entry(BASE + (0x1b84 + p * 0x80) * 4)
                .or_default() |= 0x10000;
        }
    }
}
fn fixture(
    p: u8,
    stream: u8,
    pipe: u8,
    depth: ColorDepth,
) -> (Engine<VideoIo>, Link, dccg::Applied) {
    fixture_reference(p, stream, pipe, depth, None)
}
fn fixture_reference(
    p: u8,
    stream: u8,
    pipe: u8,
    depth: ColorDepth,
    reference: Option<u32>,
) -> (Engine<VideoIo>, Link, dccg::Applied) {
    let (mut e, mut io, mut c) = super::fixture(p, stream, pipe, depth);
    if let Some(reference) = reference {
        // Inject the clock owner's result; its native DTO checks have separate
        // DCCG models. Never forge a frontend/video completion in this fixture.
        c.reference_hz = reference;
        e.status.pipes[usize::from(pipe)].as_mut().unwrap().clock = c;
        e.status.blanks[usize::from(pipe)]
            .as_mut()
            .unwrap()
            .timing
            .clock = c;
    }
    e.io.fake().regs.insert(dio(stream, 0x2123), 0);
    e.io.fake().regs.insert(dio(stream, 0x2126), 0x0080c000);
    e.io.fake().regs.insert(dio(stream, 0x2127), 0x80000000);
    e.io.fake().regs.insert(dio(stream, 0x2128), 0x40000000);
    run(e.prepare_dp_frontend(&mut io, path(p), req(stream, pipe), c)).unwrap();
    // All fetchers are stopped; exercise power-gated HUBPs in a separate test.
    for h in 0..4 {
        e.io.fake().regs.insert(BASE + (0x5f4 + h * 0xdc) * 4, 3);
    }
    // This wrapper owns both directions of the video/steering acknowledgements.
    e.io.fake().dp_stall |= (1 << stream) | (1 << (stream + 8));
    (
        Engine {
            io: VideoIo {
                inner: e.io,
                pipe,
                stall: 0,
                delays: [0; 4],
                video_written: false,
                steer_written: false,
                watch: None,
                waited: Arc::new(AtomicU32::new(0)),
                freeze_after_video: false,
            },
            authority: e.authority,
            layout: e.layout,
            status: e.status,
            displays: e.displays,
        },
        io,
        c,
    )
}
fn start(e: &mut Engine<VideoIo>, io: &mut Link, c: dccg::Applied) -> DpVideoRunning {
    let p = io.path;
    run(e.start_dp_video(io, p, c)).unwrap_or_else(|error| {
        let s = e.io.inner.stream;
        let steer = e.io.fake().regs.get(&dio(s, 0x2123)).copied();
        panic!(
            "video start {error:?}, route {p:?}/{s}/{}, steering {steer:?}, delay {:?}",
            e.io.pipe, e.io.delays
        )
    })
}
fn cancel_at(f: impl Future, mut reached: impl FnMut() -> bool) {
    let mut f = core::pin::pin!(f);
    let deadline = narf_time::Deadline::after_us(100_000);
    run(core::future::poll_fn(|cx| {
        assert!(f.as_mut().poll(cx).is_pending());
        if reached() {
            core::task::Poll::Ready(())
        } else {
            assert!(!deadline.expired(), "cancellation phase not reached");
            cx.waker().wake_by_ref();
            core::task::Poll::Pending
        }
    }));
}
fn dcn401_dp_video_black_roundtrip_keeps_independent_routes_and_native_sequence() -> TestResult {
    for p in 0..4 {
        for s in 0..4 {
            for pipe in 0..4 {
                let (mut e, mut io, c) = fixture(p, s, pipe, ColorDepth::Bpc10);
                // Acknowledgements arrive after the write readback. Suspended
                // waits are exercised separately by the timeout/cancel models.
                e.io.delays = [1; 4];
                let first = e.io.fake().writes.len();
                let events = io.events.len();
                let running = start(&mut e, &mut io, c);
                assert_eq!(running.mvid, 6007); // floor(32768 * 148500 / 810000)
                assert_eq!(running.nvid, 0x8000);
                assert_ne!(running.timing.frame_before, running.timing.frame_after);
                assert_eq!(e.status.state, State::DpVideoRunning(s));
                assert!(!e.status.state.reusable());
                assert_eq!(e.io.fake().regs[&dio(s, 0x2126)], 0x00800100);
                assert_eq!(e.io.fake().regs[&dio(s, 0x2127)], 0x80008000);
                assert_eq!(e.io.fake().regs[&dio(s, 0x2128)], 0x40000000 | 6007);
                assert_eq!(e.io.fake().regs[&dio(s, 0x2122)] & 0x10301, 0x10201);
                assert_eq!(e.io.fake().regs[&dio(s, 0x2123)] & 7, 1);
                assert_eq!(
                    io.events[events..]
                        .iter()
                        .filter_map(|e| match e {
                            Event::Delay(us) => Some(*us),
                            _ => None,
                        })
                        .collect::<Vec<_>>(),
                    [10, 200, 100]
                );
                assert_eq!(run(e.stop_dp_frontend(path(p))), Err(Error::Busy));
                assert_eq!(run(e.stop_dp_link(&mut io, path(p))), Err(Error::Busy));
                assert_eq!(run(e.start_dp_video(&mut io, path(p), c)), Err(Error::Busy));
                run(e.stop_dp_video(path(p))).unwrap();
                assert_eq!(e.status.state, State::DpFrontendReady(s));
                assert_eq!(e.status.dp_video_running, Some(running));
                assert_eq!(e.io.fake().regs[&dio(s, 0x2122)] & 0x10301, 0x200);
                assert_eq!(e.io.fake().regs[&dio(s, 0x2123)] & 7, 6);
                assert_eq!(e.io.fake().regs[&dio(s, 0x209b)] & 0x100003, 1);
                // Only this stream and timing/ODM/VTG were written, never a HUBP,
                // packet generator, PHY or clock route. Black can restart.
                let l = e.layout;
                for &(at, _) in &e.io.fake().writes[first..] {
                    assert!(
                        [0x2122, 0x2123, 0x2126, 0x2127, 0x2128, 0x209b]
                            .iter()
                            .any(|&r| at == dio(s, r))
                            || at == l.otg(pipe, CONTROL)
                            || at == l.vtg(pipe)
                            || at == l.odm(pipe, SOURCE)
                            || at == l.odm(pipe, MEMORY)
                    );
                }
                start(&mut e, &mut io, c);
                run(e.stop_dp_video(path(p))).unwrap();
                run(e.stop_dp_frontend(path(p))).unwrap();
                run(e.stop_dp_link(&mut io, path(p))).unwrap();
                assert_eq!(e.status.state, State::DpPhyDisabled);
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_video_black_roundtrip_keeps_independent_routes_and_native_sequence
);

fn dcn401_dp_video_rejects_changed_owners_fetchers_and_inherited_mn_without_writes() -> TestResult {
    for (at, value) in [
        (dio(1, 0x2126), 0x10),
        (dio(1, 0x2126), 0x1000),
        (dio(1, 0x2126), 0x1000000),
        (dio(1, 0x2122), 0x10000),
        (dio(1, 0x2123), 2),
        (dio(1, 0x209b), 0x10001d),
        (dio(1, 0x2094), 0x10),
        (dio(1, 0x2141), 1),
        (dio(2, 0x20bc), 0),
        (dio(0, 0x2122), 1),
        (dio(0, 0x2095), 1),
        (BASE + 0x5f4 * 4, 0),
        (BASE + 0x5f5 * 4, 1),
        (BASE + 0x679 * 4, 1),
        (BASE + 0x685 * 4, 1),
        (BASE + 0x68a * 4, 1),
        (BASE + 0x5f7 * 4, 0x10),
        (BASE + 0x80 * 4, 0x100),
        (BASE + (0x1b43 + 3 * 0x80) * 4, 1),
        (BASE + (0x1854 + 3 * 0x5a) * 4, 0),
        (BASE + (0x1841 + 3 * 0x5a) * 4, 0),
        (0x162a1 * 4, 0),
    ] {
        let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
        e.io.fake().regs.insert(at, value);
        let writes = e.io.fake().writes.len();
        let events = io.events.len();
        assert!(run(e.start_dp_video(&mut io, path(2), c)).is_err());
        assert_eq!(e.io.fake().writes.len(), writes);
        assert_eq!(io.events.len(), events);
        assert_eq!(e.status.state, State::DpFrontendReady(1));
    }
    let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
    let writes = e.io.fake().writes.len();
    assert_eq!(
        run(e.start_dp_video(&mut io, path(0), c)),
        Err(Error::Invalid)
    );
    let mut bad = c;
    bad.phase += 1;
    assert_eq!(
        run(e.start_dp_video(&mut io, path(2), bad)),
        Err(Error::Invalid)
    );
    assert_eq!(e.io.fake().writes.len(), writes);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_video_rejects_changed_owners_fetchers_and_inherited_mn_without_writes
);

fn dcn401_dp_video_waits_for_every_ack_and_quarantines_cancellation() -> TestResult {
    for stage in 0..9 {
        for cancel in [false, true] {
            let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
            let at = match stage {
                0 => {
                    e.io.fake().stall = 32;
                    e.layout.otg(3, CONTROL)
                }
                1 => {
                    e.io.fake().stall = 64;
                    e.layout.opp(3, 0x185b)
                }
                2 => {
                    e.io.fake().stall = 128;
                    e.io.fake().regs.insert(e.layout.opp(3, 0x1840), 0x1000000);
                    e.layout.opp(3, 0x1840)
                }
                3 => {
                    e.io.fake().stall = 256;
                    e.layout.otg(3, 0x1b4d)
                }
                4 => {
                    e.io.stall = 4;
                    dio(1, 0x2123)
                }
                5 => {
                    e.io.stall = 8;
                    dio(1, 0x2123)
                }
                6 => {
                    e.io.inner.stall = 2;
                    dio(1, 0x209b)
                }
                7 => {
                    e.io.inner.stall = 4;
                    dio(1, 0x209b)
                }
                _ => {
                    e.io.stall = 1;
                    dio(1, 0x2122)
                }
            };
            if cancel {
                e.io.watch = Some(at);
                let waited = e.io.waited.clone();
                cancel_at(e.start_dp_video(&mut io, path(2), c), || {
                    waited.load(Ordering::SeqCst) != 0
                });
            } else {
                assert_eq!(
                    run(e.start_dp_video(&mut io, path(2), c)),
                    Err(Error::Timeout(at))
                );
            }
            assert_eq!(
                e.status.state,
                if cancel {
                    State::StartingDpVideo(1)
                } else {
                    State::Failed(Error::Timeout(at))
                }
            );
            assert!(e.status.dp_video_running.is_none());
            assert_eq!(run(e.start_dp_video(&mut io, path(2), c)), Err(Error::Busy));
            assert_eq!(run(e.stop_dp_frontend(path(2))), Err(Error::Busy));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_video_waits_for_every_ack_and_quarantines_cancellation
);

fn dcn401_dp_video_stop_never_cuts_timing_before_video_off() -> TestResult {
    for stage in 0..4 {
        for cancel in [false, true] {
            let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
            let running = start(&mut e, &mut io, c);
            let first = e.io.fake().writes.len();
            let at = match stage {
                0 => {
                    e.io.stall = 2;
                    dio(1, 0x2122)
                }
                1 => {
                    e.io.stall = 4;
                    dio(1, 0x2123)
                }
                2 => {
                    e.io.fake().stall = 4;
                    e.layout.otg(3, CONTROL)
                }
                _ => {
                    e.io.fake().stall = 8;
                    e.layout.otg(3, CLOCK)
                }
            };
            if cancel {
                e.io.watch = Some(at);
                let waited = e.io.waited.clone();
                cancel_at(e.stop_dp_video(path(2)), || {
                    waited.load(Ordering::SeqCst) != 0
                });
            } else {
                assert_eq!(run(e.stop_dp_video(path(2))), Err(Error::Timeout(at)));
            }
            assert_eq!(
                e.status.state,
                if cancel {
                    State::StoppingDpVideo(1)
                } else {
                    State::Failed(Error::Timeout(at))
                }
            );
            assert_eq!(e.status.dp_video_running, Some(running));
            if stage == 0 {
                assert!(e.io.fake().writes[first..]
                    .iter()
                    .all(|&(at, _)| at == dio(1, 0x2122)));
            }
            assert_eq!(run(e.stop_dp_video(path(2))), Err(Error::Busy));
            assert_eq!(run(e.stop_dp_frontend(path(2))), Err(Error::Busy));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_video_stop_never_cuts_timing_before_video_off
);

fn dcn401_dp_video_aux_delays_and_link_loss_retain_owners() -> TestResult {
    let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
    let first = io.step;
    start(&mut e, &mut io, c);
    let steps = io.step - first;
    assert_eq!(steps, 9);
    for step in 1..=steps {
        for revoke in [false, true] {
            let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
            let target = io.step + step;
            if revoke {
                io.revoke = Some((target, e.authority));
                assert_eq!(
                    run(e.start_dp_video(&mut io, path(2), c)),
                    Err(Error::Revoked)
                );
                assert_eq!(e.status.state, State::Failed(Error::Revoked));
            } else {
                io.pending = Some(target);
                let progress = io.progress.clone();
                cancel_at(e.start_dp_video(&mut io, path(2), c), || {
                    progress.load(Ordering::SeqCst) == target as u32
                });
                assert_eq!(io.step, target);
                assert_eq!(e.status.state, State::StartingDpVideo(1));
            }
            assert!(e.status.dp_video_running.is_none());
            let writes = e.io.fake().writes.len();
            assert_eq!(run(e.start_dp_video(&mut io, path(2), c)), Err(Error::Busy));
            assert_eq!(run(e.stop_dp_frontend(path(2))), Err(Error::Busy));
            assert_eq!(run(e.stop_dp_link(&mut io, path(2))), Err(Error::Busy));
            assert_eq!(e.io.fake().writes.len(), writes);
        }
        if !(4..=6).contains(&step) {
            let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
            io.fail = Some((io.step + step, dmub::Error::CommandTimeout));
            assert_eq!(
                run(e.start_dp_video(&mut io, path(2), c)),
                Err(Error::Firmware(dmub::Error::CommandTimeout))
            );
            assert!(e.status.dp_video_running.is_none());
        }
    }
    for late in [false, true] {
        let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
        io.status = if late {
            VecDeque::from([[0x77, 0x77, 1, 0, 0, 0], [0; 6]])
        } else {
            VecDeque::from([[0; 6]])
        };
        let first = e.io.fake().writes.len();
        assert_eq!(
            run(e.start_dp_video(&mut io, path(2), c)),
            Err(Error::DpTraining(DpTrainingError::LinkLost))
        );
        if !late {
            assert_eq!(e.io.fake().writes.len(), first);
        }
        assert!(e.status.dp_video_running.is_none());
        for (at, value) in [
            (0x100, 0),
            (0x101, 0),
            (0x102, 1),
            (0x107, 0x10),
            (0x108, 0),
            (0x600, 2),
        ] {
            let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
            io.sink_change = Some((io.step + if late { 7 } else { 1 }, at, value));
            assert!(run(e.start_dp_video(&mut io, path(2), c)).is_err());
            assert!(e.status.dp_video_running.is_none());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_video_aux_delays_and_link_loss_retain_owners
);

fn dcn401_dp_video_late_source_changes_and_frozen_frames_never_publish_running() -> TestResult {
    for step in [4, 5, 6, 9] {
        for (at, value) in [
            (dio(2, 0x20bc), 0),
            (0x162a1 * 4, 0),
            (dio(1, 0x2094), 0x10),
            (dio(1, 0x2095), 0),
            (dio(1, 0x209b), 0),
            (dio(1, 0x2141), 1),
            (dio(1, 0x2162), 0),
            (dio(1, 0x2126), 0),
            (dio(1, 0x2127), 0),
            (BASE + 0x1f0e * 4, 0),
            (BASE + 0x5f4 * 4, 0),
            (BASE + 0x679 * 4, 1),
            (BASE + (0x1b2a + 3 * 0x80) * 4, 0),
            (BASE + (0x1854 + 3 * 0x5a) * 4, 0),
            (BASE + 0x1b43 * 4, 1),
            (dio(0, 0x2122), 1),
        ] {
            let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
            io.change_at = Some((io.step + step, at, value));
            assert!(
                run(e.start_dp_video(&mut io, path(2), c)).is_err(),
                "missed drift at {at:x} step {step}"
            );
            assert!(matches!(e.status.state, State::Failed(_)));
            assert!(e.status.dp_video_running.is_none());
        }
    }
    let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
    e.io.freeze_after_video = true;
    assert_eq!(
        run(e.start_dp_video(&mut io, path(2), c)),
        Err(Error::Timeout(e.layout.otg(3, 0x1b4d)))
    );
    assert!(e.status.dp_video_running.is_none());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_video_late_source_changes_and_frozen_frames_never_publish_running
);

fn write_mask(l: Layout, at: u64) -> u32 {
    if at == dio(1, 0x2122) {
        0x301
    } else if at == dio(1, 0x2123) {
        3
    } else if at == dio(1, 0x209b) {
        0x3ff
    } else if at == dio(1, 0x2126) {
        0xff00f110
    } else if at == dio(1, 0x2127) || at == dio(1, 0x2128) {
        0xffffff
    } else if at == l.otg(3, CONTROL) {
        0x301
    } else {
        u32::MAX
    }
}
fn dcn401_dp_video_mmio_failures_never_reuse_uncertain_start_or_stop() -> TestResult {
    for stop in [false, true] {
        let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
        if stop {
            start(&mut e, &mut io, c);
        }
        let first = e.io.fake().writes.len();
        let mut regs = e.io.fake().regs.clone();
        if stop {
            run(e.stop_dp_video(path(2))).unwrap();
        } else {
            start(&mut e, &mut io, c);
        }
        let writes = e.io.fake().writes.clone();
        for (index, &(at, value)) in writes.iter().enumerate().skip(first) {
            let mask = write_mask(e.layout, at);
            for fault in 0..3 {
                if fault == 0 && regs.get(&at).copied().unwrap_or(0) & mask == value & mask {
                    continue;
                }
                let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc10);
                if stop {
                    start(&mut e, &mut io, c);
                }
                let history = e.status.dp_video_running;
                let fe = e.status.dp_frontend_ready;
                let cap = e.authority;
                match fault {
                    0 => e.io.fake().reject = Some(index + 1),
                    1 => e.io.fake().revoke = Some((index + 1, cap)),
                    _ => e.io.fake().gone = Some(index + 1),
                }
                let result = if stop {
                    run(e.stop_dp_video(path(2)))
                } else {
                    run(e.start_dp_video(&mut io, path(2), c)).map(|_| ())
                };
                assert!(
                    result.is_err(),
                    "accepted fault {fault}, stop={stop}, write {index} at {at:x}"
                );
                assert!(matches!(e.status.state, State::Failed(_)));
                assert_eq!(e.status.dp_video_running, history);
                assert_eq!(e.status.dp_frontend_ready, fe);
                assert_eq!(run(e.start_dp_video(&mut io, path(2), c)), Err(Error::Busy));
                assert_eq!(run(e.stop_dp_frontend(path(2))), Err(Error::Busy));
                assert_eq!(run(e.stop_dp_link(&mut io, path(2))), Err(Error::Busy));
            }
            regs.insert(at, value);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_video_mmio_failures_never_reuse_uncertain_start_or_stop
);

fn dcn401_dp_video_skips_powered_off_hubps_and_accepts_frame_wrap() -> TestResult {
    let (mut e, mut io, c) = fixture(2, 1, 3, ColorDepth::Bpc12);
    for h in 0..4 {
        e.io.fake().regs.insert(BASE + (0x80 + 2 * h) * 4, 0x100);
        e.io.fake()
            .regs
            .insert(BASE + (0x81 + 2 * h) * 4, 0x80000000);
    }
    e.io.fake().forbidden_hubps = 15;
    // Wrap specifically during the final frame proof, after the final AUX read.
    io.change_at = Some((io.step + 9, e.layout.otg(3, 0x1b4d), 0xfffffe));
    let running = start(&mut e, &mut io, c);
    assert_eq!(
        (running.timing.frame_before, running.timing.frame_after),
        (0xffffff, 0)
    );
    // M is an auto-measured value, not a constant completion witness.
    e.io.fake().regs.insert(dio(1, 0x2128), 6010);
    run(e.stop_dp_video(path(2))).unwrap();
    run(e.stop_dp_frontend(path(2))).unwrap();
    run(e.stop_dp_link(&mut io, path(2))).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_video_skips_powered_off_hubps_and_accepts_frame_wrap
);

fn dcn401_dp_video_mn_interval_tracks_pixel_packing_not_component_depth() -> TestResult {
    for depth in [ColorDepth::Bpc8, ColorDepth::Bpc10, ColorDepth::Bpc12] {
        for (reference, pixels, interval) in [
            (148_500_000, 1, 0),
            (148_499_999, 2, 1),
            (74_249_999, 4, 2),
            (37_124_999, 8, 3),
        ] {
            let (mut e, mut io, c) = fixture_reference(2, 1, 3, depth, Some(reference));
            // A stopped firmware frontend may retain auto measurement. Its
            // native disable/reseed sequence must not require a device reset.
            *e.io.fake().regs.get_mut(&dio(1, 0x2126)).unwrap() |= 0x100;
            let running = start(&mut e, &mut io, c);
            assert_eq!(running.frontend.pixels_per_cycle, pixels);
            assert_eq!(running.mvid, 6007);
            assert_eq!(
                e.io.fake().regs[&dio(1, 0x2126)] & 0xff00f110,
                0x100 | interval << 14
            );
            run(e.stop_dp_video(path(2))).unwrap();
            run(e.stop_dp_frontend(path(2))).unwrap();
            run(e.stop_dp_link(&mut io, path(2))).unwrap();
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_video_mn_interval_tracks_pixel_packing_not_component_depth
);

use super::*;

#[path = "amdgpu_dcn401_mst_audio_tests.rs"]
mod mst_audio;

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
    fn pause_wait(&self) -> bool {
        // Cancellation waits for the selected missing acknowledgement,
        // independently of whether a short host-clock timer yields.
        self.watch.is_some() && self.waited.load(Ordering::SeqCst) != 0
    }
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
    fixture_dsc(p, stream, pipe, depth, reference, None)
}
/// The fixture on an MST link.
fn fixture_mst(p: u8, stream: u8, pipe: u8) -> (Engine<VideoIo>, Link, dccg::Applied) {
    fixture_mode(p, stream, pipe, ColorDepth::Bpc8, None, None, true)
}
fn fixture_dsc(
    p: u8,
    stream: u8,
    pipe: u8,
    depth: ColorDepth,
    reference: Option<u32>,
    dsc: Option<crate::amdgpu_dsc::DscConfig>,
) -> (Engine<VideoIo>, Link, dccg::Applied) {
    fixture_mode(p, stream, pipe, depth, reference, dsc, false)
}
fn fixture_mode(
    p: u8,
    stream: u8,
    pipe: u8,
    depth: ColorDepth,
    reference: Option<u32>,
    dsc: Option<crate::amdgpu_dsc::DscConfig>,
    mst: bool,
) -> (Engine<VideoIo>, Link, dccg::Applied) {
    let (mut e, mut io, mut c) = super::fixture_with(p, stream, pipe, depth, false, dsc, mst);
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
                run(e.stop_dp_video(&mut io, path(p))).unwrap();
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
                run(e.stop_dp_video(&mut io, path(p))).unwrap();
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
                cancel_at(e.stop_dp_video(&mut io, path(2)), || {
                    waited.load(Ordering::SeqCst) != 0
                });
            } else {
                assert_eq!(
                    run(e.stop_dp_video(&mut io, path(2))),
                    Err(Error::Timeout(at))
                );
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
            assert_eq!(run(e.stop_dp_video(&mut io, path(2))), Err(Error::Busy));
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
            run(e.stop_dp_video(&mut io, path(2))).unwrap();
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
                    run(e.stop_dp_video(&mut io, path(2)))
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
    run(e.stop_dp_video(&mut io, path(2))).unwrap();
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
            run(e.stop_dp_video(&mut io, path(2))).unwrap();
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

/// The DP video fixture with an Azalia endpoint window: an index register
/// and the data port it addresses, written but never echoed.
struct AudioIo {
    inner: VideoIo,
    az: alloc::collections::BTreeMap<(u8, u32), u32>,
    index: [u32; 4],
}
fn az_at(e: u8) -> u64 {
    BASE + (0x386 + 6 * u64::from(e)) * 4
}
impl Io for AudioIo {
    fn read(&mut self, at: u64) -> u32 {
        for e in 0..4u8 {
            if at == az_at(e) + 4 {
                let i = self.index[usize::from(e)];
                return self.az.get(&(e, i)).copied().unwrap_or(0);
            }
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        for e in 0..4u8 {
            if at == az_at(e) {
                self.index[usize::from(e)] = value;
                return;
            }
            if at == az_at(e) + 4 {
                self.az.insert((e, self.index[usize::from(e)]), value);
                return;
            }
        }
        self.inner.write(at, value);
    }
}

/// DP SST audio as Linux's DIO path programs it: DTO1 from DPREFCLK with
/// the 512 Fs reference, the audio source and channel enables, an endpoint
/// that reports a DP connection with every LPCM rate (8b/10b SST is not
/// bandwidth-checked), then audio N, auto timestamps, channel status and
/// the secondary audio packets. The video owner's checks leave those
/// packets to audio; video cannot stop under it; stop clears it all.
fn dcn401_dp_audio_programs_dto1_secondary_packets_and_endpoint_like_linux() -> TestResult {
    let (p, stream, pipe) = (1, 2, 3);
    let (mut e, mut io, c) = fixture(p, stream, pipe, ColorDepth::Bpc8);
    start(&mut e, &mut io, c);
    let mut e = Engine {
        io: AudioIo {
            inner: e.io,
            az: alloc::collections::BTreeMap::new(),
            index: [0; 4],
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    };
    let info = super::super::hdmi_link::audio_info();
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
    let t = e
        .status
        .dp_video_running
        .unwrap()
        .frontend
        .blank
        .timing
        .request
        .timing;
    let live = ScanoutRunning {
        pipe,
        odm: SplitPipes::NONE,
        mpc: SplitPipes::NONE,
        stream,
        plan: dml::admit(
            &soc,
            &dml::Mode {
                timing: t,
                pitch: (t.h_active + 63) & !63,
                bytes_per_pixel: 4,
                ycbcr420: false,
                dsc: None,
                planes: [None; dml::MAX_PLANES],
            },
        )
        .unwrap(),
        address: 0,
        overlays: [None; crate::amdgpu_dcn401_otg::MAX_OVERLAYS],
        frame_before: 0,
        frame_after: 0,
    };
    let before = e.dp_video_verify_scanout(live);
    let a = run(e.start_dp_audio(path(p), info)).unwrap();
    let r = |e: &mut Engine<AudioIo>, at| e.io.inner.fake().regs.get(&at).copied().unwrap_or(0);
    let bank1 = |reg: u64| (0x16200 + reg) * 4;
    // DTO1 = DPREFCLK (720 MHz) in 100 Hz, phase 24 MHz; DTO select 1.
    if r(&mut e, bank1(0xab)) & 0x10_0030 != 0x10_0010
        || r(&mut e, bank1(0xaf)) != 7_200_000
        || r(&mut e, bank1(0xae)) != 240_000
    {
        return TestResult::Fail("DP audio DTO1");
    }
    for (reg, mask, value) in [
        (0x2141, 0x1ff1_1111, 0x1111),         // ASP, ATP, AIP, stream enable
        (0x2147, u32::MAX, 0x8000),            // audio N default
        (0x214b, u32::MAX, 1),                 // auto-calculated timestamps
        (0x20ba, 1, 1),                        // AFMT audio clock
        (0x2085, u32::MAX, u32::from(stream)), // endpoint = stream
        (0x2075, 0x1000_ff01, 0x3700),         // FL FR LFE RL RR enabled
        (0x2078, 0x3000_0000, 0),              // clock accuracy level II
        (0x2082, 0x0400_0001, 0x0400_0001),    // CS update, samples sent
        (0x2083, 0x80, 0x80),                  // AUDIO_INFO latched
        (0x2087, 0x30, 0),
        (0x20a3, 0x30, 0),   // no HDMI Audio InfoFrame
        (0x20a1, 0x1000, 0), // no HDMI ACR
    ] {
        if r(&mut e, dio(stream, reg)) & mask != value {
            return TestResult::Fail("DP encoder audio");
        }
    }
    let az = |e: &Engine<AudioIo>, i: u32| e.io.az.get(&(stream, i)).copied();
    if az(&e, 0x54) != Some(0x8000_0000)
        || az(&e, 0x25).map(|v| v & 0x37f7f) != Some(0x2_000b)
        || az(&e, 0x28) != Some(1 | 0x700 | 0x7 << 16 | 0x07 << 24)
        || az(&e, 0x38).map(|v| v & 1) != Some(1)
        || az(&e, 0x3a) != Some(0x0f99_4c2d)
        || !a.dp
        || a.endpoint != stream
    {
        return TestResult::Fail("DP Azalia endpoint");
    }
    // The running video's checks are unchanged by the audio packets, which
    // they would refuse from anyone but the audio owner.
    if before == Err(Error::Busy) || e.dp_video_verify_scanout(live) != before {
        return TestResult::Fail("audio packets refused by the video owner");
    }
    let owner = e.status.dp_audio.take();
    if e.dp_video_verify_scanout(live) != Err(Error::Busy) {
        return TestResult::Fail("foreign secondary packets accepted");
    }
    e.status.dp_audio = owner;
    assert_eq!(run(e.start_dp_audio(path(p), info)), Err(Error::Busy));
    if r(&mut e, dio(stream, 0x2141)) & 0x1111 != 0x1111 {
        return TestResult::Fail("second start disturbed audio");
    }
    run(e.stop_dp_audio(path(p))).unwrap();
    if r(&mut e, dio(stream, 0x2141)) != 0
        || r(&mut e, dio(stream, 0x2082)) & 1 != 0
        || r(&mut e, dio(stream, 0x20ba)) & 1 != 0
        || az(&e, 0x54) != Some(0)
        || e.status.dp_audio.is_some()
    {
        return TestResult::Fail("DP audio stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_audio_programs_dto1_secondary_packets_and_endpoint_like_linux
);

/// DP video cannot stop under its audio (Linux's link_set_dpms_off stops
/// audio first), and audio needs running video.
fn dcn401_dp_video_stops_only_after_its_audio() -> TestResult {
    let (p, stream, pipe) = (0, 1, 2);
    let (mut e, mut io, c) = fixture(p, stream, pipe, ColorDepth::Bpc8);
    start(&mut e, &mut io, c);
    let info = super::super::hdmi_link::audio_info();
    let a = DisplayAudio {
        info,
        dp: true,
        endpoint: stream,
        channels: 3,
        descriptors: [0; 14],
        hbr: true,
    };
    e.status.dp_audio = Some(a);
    assert_eq!(run(e.stop_dp_video(&mut io, path(p))), Err(Error::Busy));
    e.status.dp_audio = None;
    run(e.stop_dp_video(&mut io, path(p))).unwrap();
    assert_eq!(run(e.start_dp_audio(path(p), info)), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_video_stops_only_after_its_audio
);

/// dce110_setup_audio_dto: an HDMI display's audio keeps the wall clock on
/// its DTO0 while DP audio runs beside it, and DP takes DTO1 once that HDMI
/// audio is gone.
/// Another display's records: HDMI on pipe 0 with audio, as its owner left
/// them. Built in its own frame, apart from the DP engine's.
#[inline(never)]
fn hdmi_audio_display() -> alloc::boxed::Box<Status> {
    use super::super::hdmi_link as hdmi;
    let (mut h, mut fw, hc) = hdmi::fixture(0, 0, 0);
    run(h.prepare_hdmi_link(&mut fw, hdmi::path(0), hdmi::link(0, 0), hc)).unwrap();
    run(h.start_hdmi_video(hdmi::path(0), hc)).unwrap();
    run(h.start_hdmi_audio(hdmi::path(0), hdmi::audio_info())).unwrap();
    alloc::boxed::Box::new(*h.status)
}
fn dcn401_dp_audio_leaves_the_wall_clock_to_hdmi_audio() -> TestResult {
    use super::super::hdmi_link as hdmi;
    let hdmi_display = hdmi_audio_display();
    // The selected display: DP on pipe 3.
    let (p, stream, pipe) = (2, 3, 3);
    let (mut e, mut io, c) = fixture(p, stream, pipe, ColorDepth::Bpc8);
    start(&mut e, &mut io, c);
    let mut e = Engine {
        io: AudioIo {
            inner: e.io,
            az: alloc::collections::BTreeMap::new(),
            index: [0; 4],
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    };
    e.displays.parked[1] = *hdmi_display;
    let bank1 = |reg: u64| (0x16200 + reg) * 4;
    for (reg, value) in [(0xab, 0x37), (0xac, 1), (0xad, 2), (0xae, 3), (0xaf, 4)] {
        e.io.inner.fake().regs.insert(bank1(reg), value);
    }
    let r = |e: &mut Engine<AudioIo>, at| e.io.inner.fake().regs.get(&at).copied().unwrap_or(0);
    run(e.start_dp_audio(path(p), hdmi::audio_info())).unwrap();
    // DTO0 from the HDMI stream's 148.5 MHz, sourced by pipe 0; DTO1 untouched.
    if r(&mut e, bank1(0xab)) & 0x10_0037 != 0
        || r(&mut e, bank1(0xad)) != 1_485_000
        || r(&mut e, bank1(0xac)) != 240_000
        || r(&mut e, bank1(0xaf)) != 4
    {
        return TestResult::Fail("DP audio took the HDMI wall clock");
    }
    // The HDMI display's audio stops (its records, parked here).
    e.displays.parked[1].hdmi_audio = None;
    run(e.stop_dp_audio(path(p))).unwrap();
    // With no audio left the clock stays as it was.
    if r(&mut e, bank1(0xad)) != 1_485_000 {
        return TestResult::Fail("idle wall clock reprogrammed");
    }
    run(e.start_dp_audio(path(p), hdmi::audio_info())).unwrap();
    if r(&mut e, bank1(0xab)) & 0x10_0030 != 0x10_0010 || r(&mut e, bank1(0xaf)) != 7_200_000 {
        return TestResult::Fail("DP audio alone uses DTO1");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_audio_leaves_the_wall_clock_to_hdmi_audio
);

/// A DSC stream as link_set_dpms_on runs it: the frontend marks the stream
/// compressed; after the timing starts and before video, the sink is told
/// to decode DSC and the PPS goes out in VPG generic packets 11-14 (type
/// 0x10, 127 bytes) on line 2 with VBID[6] on line 3. Stop clears the
/// sink's DSC_ENABLE and the PPS; the DSC stays for a restart (timing
/// retirement turns it off).
fn dcn401_dp_video_sends_dsc_pps_like_linux() -> TestResult {
    use crate::amdgpu_dsc::DscConfig;
    let (stream, pipe) = (1u8, 2u8);
    let cfg = DscConfig {
        slices_h: 2,
        slices_v: 10,
        bpp_x16: 128,
        block_pred: true,
        linebuf_depth: 11,
        version_minor: 2,
        ycbcr422_simple: false,
        frl: None,
        bpc: 8,
    };
    let (mut e, mut io, c) = fixture_dsc(2, stream, pipe, ColorDepth::Bpc8, None, Some(cfg));
    if e.io.fake().regs[&dio(stream, 0x211f)] & 1 != 1 {
        return TestResult::Fail("compressed pixel encoding");
    }
    e.io.fake().writes.clear();
    start(&mut e, &mut io, c);
    let headers =
        e.io.fake()
            .writes
            .iter()
            .filter(|&&(at, v)| at == dio(stream, 0x2069) && v == 0x007f_1000)
            .count();
    let reg = |e: &mut Engine<VideoIo>, r: u64| {
        e.io.fake().regs.get(&dio(stream, r)).copied().unwrap_or(0)
    };
    if io.bytes.get(&0x160) != Some(&1)
        || headers != 4
        || reg(&mut e, 0x2177) & 0xffff_0010 != (2 << 16 | 0x10)
        || reg(&mut e, 0x2170) >> 16 != 3
        || reg(&mut e, 0x2169) & 0x1000_0000 == 0
        || reg(&mut e, 0x2141) & 1 != 1
    {
        return TestResult::Fail("DSC PPS SDP");
    }
    run(e.stop_dp_video(&mut io, path(2))).unwrap();
    if io.bytes.get(&0x160) != Some(&0)
        || reg(&mut e, 0x2177) & 0x10 != 0
        || reg(&mut e, 0x2169) & 0x1000_0000 != 0
    {
        return TestResult::Fail("DSC stop");
    }
    // The DSC stays configured for a restart, which sends the PPS again.
    let at = BASE + (0x1a64 + u64::from(pipe)) * 4;
    if e.io.fake().regs[&at] & 1 != 1 {
        return TestResult::Fail("DSC kept for restart");
    }
    start(&mut e, &mut io, c);
    if io.bytes.get(&0x160) != Some(&1) || reg(&mut e, 0x2177) & 0x10 == 0 {
        return TestResult::Fail("DSC restart");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_video_sends_dsc_pps_like_linux
);

fn dsc_audio_fixture(stream: u8, pipe: u8) -> (Engine<AudioIo>, Link) {
    let cfg = crate::amdgpu_dsc::DscConfig {
        slices_h: 2,
        slices_v: 10,
        bpp_x16: 128,
        block_pred: true,
        linebuf_depth: 11,
        version_minor: 2,
        ycbcr422_simple: false,
        frl: None,
        bpc: 8,
    };
    let (mut e, mut io, c) = fixture_dsc(2, stream, pipe, ColorDepth::Bpc8, None, Some(cfg));
    start(&mut e, &mut io, c);
    (
        Engine {
            io: AudioIo {
                inner: e.io,
                az: alloc::collections::BTreeMap::new(),
                index: [0; 4],
            },
            authority: e.authority,
            layout: e.layout,
            status: e.status,
            displays: e.displays,
        },
        io,
    )
}

fn dcn401_dp_audio_shares_dsc_pps_without_stopping_its_packets() -> TestResult {
    let info = super::super::hdmi_link::audio_info();
    for stream in 0..4 {
        let pipe = (stream + 1) % 4;
        let (mut e, mut io) = dsc_audio_fixture(stream, pipe);
        let packet_state = |e: &mut Engine<AudioIo>| {
            [0x2169, 0x2177, 0x2170].map(|r| e.io.inner.fake().regs[&dio(stream, r)])
        };
        let before = packet_state(&mut e);
        e.io.inner.fake().writes.clear();
        for _ in 0..2 {
            let audio = run(e.start_dp_audio(path(2), info)).unwrap();
            assert!(audio.dp);
            assert_eq!(packet_state(&mut e), before);
            assert_eq!(run(e.stop_dp_video(&mut io, path(2))), Err(Error::Busy));
            run(e.stop_dp_audio(path(2))).unwrap();
            let regs = &e.io.inner.fake().regs;
            assert_eq!(regs[&dio(stream, 0x2141)], 1, "PPS secondary master lost");
            assert_eq!(regs[&dio(stream, 0x20ba)] & 1, 1, "PPS clock lost");
            assert_eq!(regs[&dio(stream, 0x2082)] & 1, 0, "audio samples remain");
            assert_eq!(packet_state(&mut e), before);
            assert!(e.status.dp_audio.is_none());
            assert_eq!(e.io.az.get(&(stream, 0x54)), Some(&0));
        }
        assert!(!e
            .io
            .inner
            .fake()
            .writes
            .iter()
            .any(|&(at, _)| at == dio(stream, 0x2069)));
        assert!(
            e.io.inner.fake().writes.iter().all(|&(at, value)| {
                ![dio(stream, 0x2141), dio(stream, 0x20ba)].contains(&at) || value & 1 != 0
            }),
            "audio transiently disabled PPS's shared clock/master"
        );
        // PPS stops only when its video owner stops, after audio is gone.
        run(e.stop_dp_video(&mut io, path(2))).unwrap();
        assert_eq!(io.bytes.get(&0x160), Some(&0));
        assert_eq!(e.io.inner.fake().regs[&dio(stream, 0x2177)] & 0x10, 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_audio_shares_dsc_pps_without_stopping_its_packets
);

fn dcn401_dp_audio_requires_fresh_pps_witnesses_and_quiet_audio() -> TestResult {
    let (mut e, _) = dsc_audio_fixture(1, 2);
    let info = super::super::hdmi_link::audio_info();
    for (reg, mask) in [
        (0x20ba, 1),
        (0x2141, 1),
        (0x2169, 0x1000_0000),
        (0x2177, 0x10),
        (0x2170, 0xffff_0000),
    ] {
        let at = dio(1, reg);
        let saved = e.io.inner.fake().regs[&at];
        e.io.inner.fake().regs.insert(at, saved & !mask);
        let writes = e.io.inner.fake().writes.len();
        assert_eq!(
            run(e.start_dp_audio(path(2), info)),
            Err(Error::Readback(at))
        );
        assert_eq!(e.io.inner.fake().writes.len(), writes);
        assert!(e.status.dp_audio.is_none());
        e.io.inner.fake().regs.insert(at, saved);
    }
    for (reg, mask) in [(0x2141, 0x10), (0x2082, 1)] {
        let at = dio(1, reg);
        let saved = e.io.inner.fake().regs.get(&at).copied().unwrap_or(0);
        e.io.inner.fake().regs.insert(at, saved | mask);
        let writes = e.io.inner.fake().writes.len();
        assert_eq!(run(e.start_dp_audio(path(2), info)), Err(Error::Busy));
        assert_eq!(e.io.inner.fake().writes.len(), writes);
        assert!(e.status.dp_audio.is_none());
        e.io.inner.fake().regs.insert(at, saved);
    }
    run(e.start_dp_audio(path(2), info)).unwrap();
    let at = dio(1, 0x2177);
    let saved = e.io.inner.fake().regs[&at];
    e.io.inner.fake().regs.insert(at, saved & !0x10);
    let writes = e.io.inner.fake().writes.len();
    assert_eq!(run(e.stop_dp_audio(path(2))), Err(Error::Readback(at)));
    assert!(
        e.status.dp_audio.is_some(),
        "lost PPS discarded audio owner"
    );
    assert_eq!(e.io.inner.fake().writes.len(), writes);
    e.io.inner.fake().regs.insert(at, saved);
    run(e.stop_dp_audio(path(2))).unwrap();
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_audio_requires_fresh_pps_witnesses_and_quiet_audio
);

/// Two displays on one MST link, as Linux's MST streams share their link
/// encoder: display 0 trains the link and runs its stream (DIG_FE_MODE
/// 5); display 1 attaches to the running link, stages its timing and its
/// own frontend, which joins the backend's frontend selection beside
/// display 0's and leaves it alone on stop. The attached display can't
/// stop the link; it detaches, and display 0's video still runs.
fn dcn401_mst_displays_share_one_link() -> TestResult {
    let (t, s0, p0, s1, p1) = (2u8, 1u8, 1u8, 3u8, 2u8);
    let (mut e, mut io, c) = fixture_mst(t, s0, p0);
    start(&mut e, &mut io, c);
    let be = dio(t, 0x20bc);
    if e.io.fake().regs[&dio(s0, 0x2094)] & 7 != 5 || e.io.fake().regs[&be] & 0x7f00 != 0x100 << s0
    {
        return TestResult::Fail("first MST stream");
    }
    if e.select_display(1).is_err() || e.displays.siblings.mst != 1 << t {
        return TestResult::Fail("MST link as sibling");
    }
    let mut req = request(p1);
    req.signal = Signal::DisplayPort;
    let c1 = clock(req);
    run(e.prepare(req, c1)).unwrap();
    run(e.prepare_blank(
        BlankRequest {
            pipe: p1,
            depth: ColorDepth::Bpc8,
            limited: false,
            ycbcr420: false,
            colorspace: crate::amdgpu_dcn401_otg::BlankRequest::default_colorspace(false, false),
        },
        c1,
    ))
    .unwrap();
    let bank1 = e.layout.dio_clock - 0xa0 * 4;
    e.io.fake()
        .regs
        .insert(bank1 + (0x80 + 4 * u64::from(p1)) * 4, 0x1090);
    let sources =
        e.io.fake()
            .regs
            .get(&(bank1 + 0x68 * 4))
            .copied()
            .unwrap_or(0);
    e.io.fake()
        .regs
        .insert(bank1 + 0x68 * 4, sources | 4 << (p1 * 3));
    // Training the shared link is the owner's; attaching is not.
    if let Err(err) = e.attach_mst_link(t) {
        panic!("attach {err:?}");
    }
    e.io.inner.stream = s1;
    if let Err(err) = run(e.prepare_dp_frontend(&mut io, path(t), super::req(s1, p1), c1)) {
        panic!("second MST frontend {err:?}");
    }
    if e.io.fake().regs[&be] & 0x7f00 != (0x100 << s0 | 0x100 << s1)
        || e.io.fake().regs[&dio(s1, 0x2094)] & 7 != 5
    {
        return TestResult::Fail("second MST stream");
    }
    run(e.stop_dp_frontend(path(t))).unwrap();
    if e.io.fake().regs[&be] & 0x7f00 != 0x100 << s0 {
        return TestResult::Fail("second stream's selection removed alone");
    }
    if run(e.stop_dp_link(&mut io, path(t))) != Err(Error::Busy) || e.detach_mst_link(t).is_err() {
        return TestResult::Fail("attached display and the link");
    }
    // Display 1 rides the link again; the owner leaves first and hands it
    // over, and display 1 stops it last.
    if e.attach_mst_link(t).is_err() {
        return TestResult::Fail("attach again");
    }
    (e.io.inner.stream, e.io.pipe) = (s1, p1);
    run(e.prepare_dp_frontend(&mut io, path(t), super::req(s1, p1), c1)).unwrap();
    // A live sibling is allowed on the shared backend; an unowned
    // frontend must still be rejected, even when our own bit is intact.
    let routes = e.io.fake().regs[&be];
    e.io.fake().regs.insert(be, routes | 0x100);
    if run(e.stop_dp_frontend(path(t))).is_ok() {
        return TestResult::Fail("foreign frontend on the shared backend");
    }
    e.io.fake().regs.insert(be, routes);
    start(&mut e, &mut io, c1);
    (e.io.inner.stream, e.io.pipe) = (s0, p0);
    if let Err(err) = e.select_display(0) {
        panic!("owner beside the second {err:?}");
    }
    if let Err(err) = run(e.stop_dp_video(&mut io, path(t))) {
        panic!("owner's stream beside the second {err:?}");
    }
    run(e.stop_dp_frontend(path(t))).unwrap();
    if run(e.stop_dp_link(&mut io, path(t))).is_ok() {
        return TestResult::Fail("the owner stopped a shared link");
    }
    if e.hand_over_mst_link(t, 2) != Err(Error::Invalid) || e.hand_over_mst_link(t, 1).is_err() {
        return TestResult::Fail("hand over");
    }
    if e.io.fake().regs[&be] & 0x7f00 != 0x100 << s1 || e.select_display(1).is_err() {
        return TestResult::Fail("the second stream after the owner left");
    }
    (e.io.inner.stream, e.io.pipe) = (s1, p1);
    if let Err(err) = run(e.stop_dp_video(&mut io, path(t))) {
        panic!("second stream after the hand-over {err:?}");
    }
    run(e.stop_dp_frontend(path(t))).unwrap();
    if let Err(err) = run(e.stop_dp_link(&mut io, path(t))) {
        panic!("new owner stops the link {err:?}");
    }
    TestResult::Pass
}
kernel_test_in!("drivers/gpu/dcn401-otg", dcn401_mst_displays_share_one_link);

/// link_dpms.c enable_stream_features: after the stream runs,
/// DP_DOWNSPREAD_CTRL's IGNORE_MSA_TIMING_PARAM follows the stream's VRR
/// support by read-modify-write, written only when it changes, keeping the
/// link's spread bit; the link's own configuration checks ignore the bit.
fn dcn401_dp_stream_features_set_and_clear_ignore_msa() -> TestResult {
    let (mut e, mut io, c) = fixture(1, 2, 3, ColorDepth::Bpc8);
    let p = path(1);
    // Before video runs: Busy, without AUX traffic.
    let events = io.events.len();
    if run(e.dp_stream_features(&mut io, p, true)) != Err(Error::Busy) || io.events.len() != events
    {
        return TestResult::Fail("before video");
    }
    start(&mut e, &mut io, c);
    let spread = io.bytes.get(&0x107).copied().unwrap_or(0);
    let aux = |io: &Link, from: usize| -> Vec<(u8, u32, Vec<u8>)> {
        io.events[from..]
            .iter()
            .filter_map(|ev| match ev {
                Event::Aux(a, at, d) => Some((*a, *at, d.clone())),
                _ => None,
            })
            .collect()
    };
    let from = io.events.len();
    if run(e.dp_stream_features(&mut io, p, true)) != Ok(true)
        || aux(&io, from)
            != [
                (0x90, 0x107, alloc::vec![0]),
                (0x80, 0x107, alloc::vec![spread | 0x80]),
            ]
        || io.bytes.get(&0x107).copied() != Some(spread | 0x80)
    {
        return TestResult::Fail("set");
    }
    // Unchanged: read only.
    let from = io.events.len();
    if run(e.dp_stream_features(&mut io, p, true)) != Ok(false) || aux(&io, from).len() != 1 {
        return TestResult::Fail("unchanged");
    }
    // Another path is not this stream's.
    if run(e.dp_stream_features(&mut io, path(2), true)) != Err(Error::Invalid) {
        return TestResult::Fail("other path");
    }
    // The stream restarts with the bit set: the sink checks still pass.
    run(e.stop_dp_video(&mut io, p)).unwrap();
    start(&mut e, &mut io, c);
    if run(e.dp_stream_features(&mut io, p, false)) != Ok(true)
        || io.bytes.get(&0x107).copied() != Some(spread)
    {
        return TestResult::Fail("clear");
    }
    if e.status.state != State::DpVideoRunning(2) {
        return TestResult::Fail("state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_stream_features_set_and_clear_ignore_msa
);

/// enc3_stream_encoder_update_dp_info_packets before the unblank: the VSC
/// SDP in packets 0 and 1 with GSP0, the HDR SDP in packet 3 with GSP3,
/// the secondary master on; new metadata rewrites packet 3 live; stopping
/// the video turns both SDPs off.
fn dcn401_dp_video_sends_vsc_and_hdr_sdps_like_linux() -> TestResult {
    let (stream, pipe) = (1u8, 2u8);
    let (mut e, mut io, c) = fixture(2, stream, pipe, ColorDepth::Bpc8);
    let mut blob = [0u8; 32];
    blob[4] = 2;
    let meta = |b: &[u8; 32]| crate::amdgpu_hdr::HdrOutputMetadata::from_blob(b).unwrap();
    let hdr = crate::amdgpu_hdr::hdr_info_packet(
        Some(&meta(&blob)),
        crate::amdgpu_hdr::HdrConnector::DisplayPort,
    );
    // The frontend's request carries both, as the modeset builds it.
    {
        let f = e.status.dp_frontend_ready.as_mut().unwrap();
        f.request.vsc_colorimetry = true;
        f.request.hdr = Some(hdr);
    }
    e.io.fake().writes.clear();
    start(&mut e, &mut io, c);
    let vsc = crate::amdgpu_hdr::vsc_sdp(
        true,
        crate::amdgpu_hdr::DcColorSpace::Srgb,
        crate::amdgpu_hdr::PixelEncoding::Rgb,
        8,
        false,
    )
    .unwrap();
    let packet = |e: &mut Engine<VideoIo>, index: u32| -> alloc::vec::Vec<u32> {
        let w = &e.io.fake().writes;
        let Some(at) = w
            .iter()
            .position(|&(a, v)| a == dio(stream, 0x2068) && v & 0xff == index * 9)
        else {
            return alloc::vec::Vec::new();
        };
        w[at..]
            .iter()
            .filter(|&&(a, _)| a == dio(stream, 0x2069))
            .take(9)
            .map(|&(_, v)| v)
            .collect()
    };
    let sec = |e: &mut Engine<VideoIo>| e.io.fake().regs[&dio(stream, 0x2141)];
    if packet(&mut e, 0) != vsc.words()
        || packet(&mut e, 1) != vsc.words()
        || packet(&mut e, 3) != hdr.words()
        || sec(&mut e) & (1 << 20 | 1 << 23 | 1) != 1 << 20 | 1 << 23 | 1
    {
        return TestResult::Fail("VSC/HDR SDPs at start");
    }
    blob[26..28].copy_from_slice(&400u16.to_le_bytes());
    let brighter = crate::amdgpu_hdr::hdr_info_packet(
        Some(&meta(&blob)),
        crate::amdgpu_hdr::HdrConnector::DisplayPort,
    );
    e.io.fake().writes.clear();
    if run(e.dp_update_hdr(brighter)).is_err()
        || packet(&mut e, 3) != brighter.words()
        || !packet(&mut e, 0).is_empty()
    {
        return TestResult::Fail("live HDR SDP");
    }
    run(e.stop_dp_video(&mut io, path(2))).unwrap();
    if sec(&mut e) & (1 << 20 | 1 << 23 | 1) != 0 {
        return TestResult::Fail("SDPs after stop");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_video_sends_vsc_and_hdr_sdps_like_linux
);

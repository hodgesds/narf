use super::*;

fn staged(pipe: u8, signal: Signal) -> Engine<Fake> {
    let mut e = engine();
    let mut req = request(pipe);
    req.signal = signal;
    run(e.prepare(req, clock(req))).unwrap();
    run(e.prepare_blank(blank_request(pipe), clock(req))).unwrap();
    e.io.retiring = [false; 4];
    for p in 0..4 {
        e.io.regs.insert(BASE + (0x5f4 + 0xdc * p) * 4, 0x1003);
    }
    e.io.writes.clear();
    e
}
fn start(e: &mut Engine<Fake>, pipe: u8) -> Result<BlankRunning, Error> {
    let c = e.status.pipes[usize::from(pipe)].unwrap().clock;
    run(e.start_blank(pipe, c))
}

fn dcn401_blank_start_native_order_and_fresh_frame_wrap() -> TestResult {
    for pipe in 0..4 {
        for signal in [Signal::DisplayPort, Signal::HpoDisplayPort, Signal::HdmiFrl] {
            let mut e = staged(pipe, signal);
            let p = u64::from(pipe);
            let o = |r| BASE + (r + p * 0x80) * 4;
            let frame = o(0x1b4d);
            e.io.regs.insert(frame, 0xfffffe);
            e.io.regs.insert(BASE + (0x1840 + p * 0x5a) * 4, 0x1000000);
            let a = start(&mut e, pipe).unwrap();
            assert_eq!((a.frame_before, a.frame_after), (0xffffff, 0));
            assert!(a.blank.pending, "retain staged, not fabricated, history");
            assert_eq!(e.status.state, State::RunningBlank(pipe));
            assert_eq!(e.status.running_blank, Some(a));
            assert!(!e.status.state.reusable());
            let mux = match signal {
                Signal::DisplayPort => 0x1000,
                Signal::HpoDisplayPort => 0x201000,
                _ => 0x200000,
            };
            assert_eq!(
                e.io.writes,
                [
                    (
                        BASE + (0x1acb + p * 0x10) * 4,
                        0xfff00000 | u32::from(pipe) << 16
                    ),
                    (BASE + (0x530 + p) * 4, 0x80000000 | 1121 << 16 | 1),
                    (o(0x1b43), mux | 0x201),
                ]
            );
            e.io.writes.clear();
            assert_eq!(start(&mut e, pipe), Err(Error::Busy));
            assert_eq!(
                run(e.prepare(request(pipe), clock(request(pipe)))),
                Err(Error::Busy)
            );
            assert_eq!(
                run(e.prepare_blank(blank_request(pipe), clock(request(pipe)))),
                Err(Error::Busy)
            );
            assert_eq!(run(e.retire((pipe + 1) % 4)), Err(Error::Busy));
            assert!(e.io.writes.is_empty());
            // Only acknowledged retirement of the active pipe releases the
            // clock/timing owner for preparation, never its surface allocations.
            e.io.delay[usize::from(pipe)] = 3;
            run(e.retire(pipe)).unwrap();
            assert_eq!(e.status.state, State::Retired);
            assert!(e.status.running_blank.is_none());
            assert!(e.status.blanks[usize::from(pipe)].is_none());
            assert!(e.status.state.reusable());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-blank",
    dcn401_blank_start_native_order_and_fresh_frame_wrap
);

fn dcn401_blank_requires_positive_stopped_fetchers_on_every_pipe() -> TestResult {
    for pipe in 0..4 {
        for (r, value) in [
            (0x5f4, 0),      // powered-off/zero-filled MMIO is not retirement
            (0x5f4, 0x1002), // no blank
            (0x5f4, 0x1001), // outstanding requests
            (0x5f4, 0x0003), // TTU still enabled
            (0x5f4, 0x1007), // soft reset
            (0x5f5, 1),      // fetch clock enabled
            (0x679, 1),      // cursor
            (0x685, 1),
            (0x685, 2),
            (0x685, 4),
            (0x685, 1 << 16),
        ] {
            let mut e = staged(0, Signal::HpoDisplayPort);
            e.io.regs.insert(BASE + (r + pipe * 0xdc) * 4, value);
            assert_eq!(start(&mut e, 0), Err(Error::Busy));
            assert!(e.io.writes.is_empty());
            assert_eq!(e.status.state, State::BlankPrepared);
        }
    }
    for (at, mask) in engine().layout.idle {
        let mut e = staged(0, Signal::HpoDisplayPort);
        e.io.regs.insert(at, mask);
        assert_eq!(start(&mut e, 0), Err(Error::Busy));
        assert!(e.io.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-blank",
    dcn401_blank_requires_positive_stopped_fetchers_on_every_pipe
);

fn dcn401_blank_rechecks_prepared_timing_formatter_and_clock_snapshot() -> TestResult {
    // Corrupt independently chosen fields after staging. None may be hidden
    // by a cached Applied snapshot or corrected silently by start.
    for (r, bit) in [
        (0x1b2a, 1),
        (0x1b2b, 1),
        (0x1b2c, 1 << 16),
        (0x1b2d, 1),
        (0x1b2e, 0x100),
        (0x1b2f, 1),
        (0x1b30, 1),
        (0x1b31, 1),
        (0x1b33, 1),
        (0x1b38, 1),
        (0x1b39, 1 << 16),
        (0x1b3a, 1),
        (0x1b43, 0x1000),
        (0x1b45, 1),
        (0x1b85, 1),
        (0x1b86, 1),
        (0x1b87, 1),
        (0x1b9f, 1),
        (0x1acb, 1 << 16),
        (0x1acc, 1),
        (0x1ad1, 1),
        (0x530, 1),
        (0x530, 0x80000000),
        (0x188c, 0x10),
        (0x1849, 1),
        (0x1841, 1),
        (0x1842, 1),
        (0x1843, 1),
        (0x1844, 1),
        (0x1840, 0x100),
        (0x1845, 1),
        (0x183f, 1),
        (0x1856, 1),
        (0x185a, 1),
        (0x1859, 1),
        (0x1858, 1),
        (0x1857, 1),
        (0x1854, 1),
    ] {
        let mut e = staged(0, Signal::HpoDisplayPort);
        let at = BASE + r * 4;
        *e.io.regs.entry(at).or_default() ^= bit;
        assert_eq!(start(&mut e, 0), Err(Error::Readback(at)));
        assert!(e.io.writes.is_empty());
    }
    let mut e = staged(0, Signal::HpoDisplayPort);
    let mut c = clock(request(0));
    c.global.dpp_khz += 1;
    assert_eq!(run(e.start_blank(0, c)), Err(Error::Invalid));
    for pipe in [1, 4, 255] {
        assert_eq!(
            run(e.start_blank(pipe, clock(request(0)))),
            Err(Error::Invalid)
        );
    }
    e.status.blanks[0] = None;
    assert_eq!(start(&mut e, 0), Err(Error::Invalid));
    assert!(e.io.writes.is_empty());
    let mut e = staged(0, Signal::Tmds);
    assert_eq!(start(&mut e, 0), Err(Error::Unsupported));
    assert!(e.io.writes.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-blank",
    dcn401_blank_rechecks_prepared_timing_formatter_and_clock_snapshot
);

fn dcn401_blank_needs_current_master_latched_format_and_frame_progress() -> TestResult {
    for (stall, register) in [(32, 0x1b43), (64, 0x185b), (128, 0x1840), (256, 0x1b4d)] {
        let mut e = staged(0, Signal::HpoDisplayPort);
        e.io.stall = stall;
        e.io.regs.insert(BASE + 0x1840 * 4, 0x1000000);
        if stall == 256 {
            // Both pending bits already zero still cannot establish progress.
            e.io.regs.insert(BASE + 0x185b * 4, 0);
            e.io.regs.insert(BASE + 0x1840 * 4, 0);
        }
        let error = Error::Timeout(BASE + register * 4);
        assert_eq!(start(&mut e, 0), Err(error));
        assert_eq!(e.io.writes.len(), 3);
        assert_eq!(e.status.state, State::Failed(error));
        assert!(e.status.running_blank.is_none());
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-blank",
    dcn401_blank_needs_current_master_latched_format_and_frame_progress
);

fn dcn401_blank_partial_start_and_cancellation_quarantine_timing() -> TestResult {
    for n in 1..=3 {
        let mut e = staged(0, Signal::HpoDisplayPort);
        e.io.gone = Some(n);
        assert_eq!(start(&mut e, 0), Err(Error::DeviceGone));
        assert_eq!(e.status.state, State::Failed(Error::DeviceGone));
        assert_eq!(e.io.writes.len(), n);
        assert!(e.status.running_blank.is_none());
        let mut e = staged(0, Signal::HpoDisplayPort);
        e.io.revoke = Some((n, e.authority));
        assert_eq!(start(&mut e, 0), Err(Error::Revoked));
        assert_eq!(e.status.state, State::Failed(Error::Revoked));
        assert_eq!(e.io.writes.len(), n);
    }
    for (n, r) in [(2, 0x530), (3, 0x1b43)] {
        let mut e = staged(0, Signal::HpoDisplayPort);
        e.io.reject = Some(n);
        let error = Error::Readback(BASE + r * 4);
        assert_eq!(start(&mut e, 0), Err(error));
        assert_eq!(e.status.state, State::Failed(error));
        assert_eq!(e.io.writes.len(), n);
    }
    for stall in [32, 64, 128, 256] {
        let mut e = staged(0, Signal::HpoDisplayPort);
        e.io.stall = stall;
        e.io.regs.insert(BASE + 0x1840 * 4, 0x1000000);
        {
            let mut f = core::pin::pin!(e.start_blank(0, clock(request(0))));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.status.state, State::StartingBlank(0));
        assert!(e.status.running_blank.is_none());
        assert!(!e.status.state.reusable());
        assert_eq!(start(&mut e, 0), Err(Error::Busy));
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
        assert_eq!(e.io.writes.len(), 3);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-blank",
    dcn401_blank_partial_start_and_cancellation_quarantine_timing
);

fn dcn401_blank_rechecks_fetchers_streams_and_pattern_after_enable() -> TestResult {
    for (r, value, expected) in [
        (0x5f4, 0x1001, Error::Busy),
        (0x679, 1, Error::Busy),
        (0x685, 4, Error::Busy),
        (0x20bd, 1, Error::Busy),
        (0x1854, 0x1040, Error::Readback(BASE + 0x1854 * 4)),
        (0x530, 1121 << 16 | 1, Error::Readback(BASE + 0x530 * 4)),
    ] {
        let mut e = staged(0, Signal::HpoDisplayPort);
        e.io.after_enable = Some((BASE + r * 4, value));
        assert_eq!(start(&mut e, 0), Err(expected));
        assert_eq!(e.status.state, State::Failed(expected));
        assert!(e.status.running_blank.is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-blank",
    dcn401_blank_rechecks_fetchers_streams_and_pattern_after_enable
);

fn dcn401_blank_rejects_unbounded_modes_and_lost_authority_before_writes() -> TestResult {
    let mut e = staged(0, Signal::HpoDisplayPort);
    let timing = e.status.pipes[0].as_mut().unwrap();
    timing.request.timing.pixel_clock_khz = 1;
    timing.clock.request.pixel = dccg::PixelClock::DisplayPort { pixel_hz: 1000 };
    e.status.blanks[0].as_mut().unwrap().timing = *timing;
    assert_eq!(start(&mut e, 0), Err(Error::Invalid));
    assert!(e.io.writes.is_empty());
    let mut e = staged(0, Signal::HpoDisplayPort);
    e.authority.revoke();
    assert_eq!(start(&mut e, 0), Err(Error::Revoked));
    assert!(e.io.writes.is_empty());
    let mut e = staged(0, Signal::HpoDisplayPort);
    e.io.gone = Some(0);
    assert_eq!(start(&mut e, 0), Err(Error::DeviceGone));
    assert!(e.io.writes.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-blank",
    dcn401_blank_rejects_unbounded_modes_and_lost_authority_before_writes
);

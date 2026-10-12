use super::*;

fn at(stream: DpStream, reg: u64) -> u64 {
    let (p, stride) = match stream {
        DpStream::Dio(p) => (p, 0x124),
        DpStream::Hpo(p) => (p, 0xd4),
    };
    BASE + (reg + u64::from(p) * stride) * 4
}
fn live(stream: DpStream) -> Engine<Fake> {
    let mut e = engine();
    let registers: &[(u64, u32)] = match stream {
        DpStream::Dio(_) => &[
            (0x2094, 0x4c15), // MST frontend, clocks retained
            (0x2095, 0x101),
            (0x2122, 0x110101), // enable + status, HBLANK defer, keepout
            (0x2123, 0x81),
        ],
        DpStream::Hpo(_) => &[
            (0x3623, 0x11111),
            (0x3626, 0x1010101),
            (0x365d, 1),
            (0x365e, 0x1001),
            (0x367b, 0x111),
            (0x3685, 0x40000111),
        ],
    };
    for &(r, v) in registers {
        e.io.regs.insert(stream.at(e.layout, r), v);
    }
    // Deliberately independent live timing and PHYs. Blanking must neither
    // require their shutdown nor modify them, including a different OTG route.
    e.io.regs.insert(BASE + (0x1b43 + 3 * 0x80) * 4, 0x10001);
    e.io.regs.insert(BASE + 0x20bd * 4, 1);
    e.io.regs.insert(BASE + 0x369f * 4, 1);
    e.io.dp_delay = [3; 8];
    e
}
fn video(stream: DpStream) -> u64 {
    match stream {
        DpStream::Dio(_) => 0x2122,
        DpStream::Hpo(_) => 0x3685,
    }
}
fn writes(stream: DpStream) -> usize {
    match stream {
        DpStream::Dio(_) => 3,
        DpStream::Hpo(_) => 4,
    }
}
fn stall(stream: DpStream) -> u16 {
    match stream {
        DpStream::Dio(p) => 1 << p,
        DpStream::Hpo(p) => 1 << (p + 4),
    }
}

fn dcn401_dp_blank_all_native_instances_preserve_clocks_and_routing() -> TestResult {
    for p in 0..4 {
        for stream in [DpStream::Dio(p), DpStream::Hpo(p)] {
            let mut e = live(stream);
            let before = e.io.regs.clone();
            let result = run(e.blank_dp_stream(stream)).unwrap();
            assert_eq!(
                result,
                DpBlanked {
                    stream,
                    was_active: true
                }
            );
            assert_eq!(e.status.state, State::DpBlanked);
            assert!(e.status.state.reusable());
            assert_eq!(e.status.dp_blanked, Some(result));
            let expected: &[(u64, u32)] = match stream {
                DpStream::Dio(_) => &[(0x2122, 0x110201), (0x2122, 0x110200), (0x2123, 0x83)],
                DpStream::Hpo(_) => &[
                    (0x3685, 0x40000110),
                    (0x367b, 0x110),
                    (0x365e, 0x1000),
                    (0x3626, 0x1010100),
                ],
            };
            assert_eq!(
                e.io.writes,
                expected
                    .iter()
                    .map(|&(r, v)| (stream.at(e.layout, r), v))
                    .collect::<Vec<_>>()
            );
            for (at, value) in before {
                if !e.io.writes.iter().any(|&(w, _)| w == at) {
                    assert_eq!(e.io.regs.get(&at), Some(&value));
                }
            }
            assert_eq!(e.status.retired, 0);
            assert!(e.status.planes_retired.is_none());
            // A successful blank is insufficient for timing/plane/clock reuse
            // while retained PHYs remain enabled.
            assert_eq!(run(e.retire(0)), Err(Error::Busy));
            assert_eq!(run(e.retire_planes()), Err(Error::Busy));
            assert_eq!(
                run(e.prepare(request(0), clock(request(0)))),
                Err(Error::Busy)
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-stream",
    dcn401_dp_blank_all_native_instances_preserve_clocks_and_routing
);

fn dcn401_dp_blank_finishes_pending_disable_and_rechecks_idle_streams() -> TestResult {
    for stream in [DpStream::Dio(3), DpStream::Hpo(3)] {
        let mut e = live(stream);
        *e.io
            .regs
            .get_mut(&stream.at(e.layout, video(stream)))
            .unwrap() &= !1;
        let result = run(e.blank_dp_stream(stream)).unwrap();
        assert!(result.was_active); // enable=0 did not skip active hardware
        assert_eq!(e.io.writes.len(), writes(stream));
        e.io.writes.clear();
        assert!(!run(e.blank_dp_stream(stream)).unwrap().was_active);
        assert_eq!(
            e.io.writes.len(),
            if matches!(stream, DpStream::Dio(_)) {
                0
            } else {
                4
            }
        );

        let mut e = engine();
        let result = run(e.blank_dp_stream(stream)).unwrap();
        assert!(!result.was_active);
        assert!(e.io.writes.is_empty()); // disabled clocks stay disabled
        assert_eq!(e.status.state, State::DpBlanked);
    }
    // SDP/FIFOs without video are still disabled for an enabled HPO encoder.
    let stream = DpStream::Hpo(1);
    let mut e = live(stream);
    e.io.regs.insert(stream.at(e.layout, 0x3685), 0);
    assert!(!run(e.blank_dp_stream(stream)).unwrap().was_active);
    assert_eq!(e.io.writes.len(), 4);
    // An idle DIO DP block may share a currently HDMI-configured frontend;
    // no video means there is no DP transaction to change.
    let stream = DpStream::Dio(1);
    let mut e = engine();
    e.io.regs.insert(stream.at(e.layout, 0x2094), 0x13);
    run(e.blank_dp_stream(stream)).unwrap();
    assert!(e.io.writes.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-stream",
    dcn401_dp_blank_finishes_pending_disable_and_rechecks_idle_streams
);

fn dcn401_dp_blank_preflight_rejects_unowned_modes_resets_and_missing_clocks() -> TestResult {
    for p in [4, 255] {
        for stream in [DpStream::Dio(p), DpStream::Hpo(p)] {
            let mut e = engine();
            assert_eq!(run(e.blank_dp_stream(stream)), Err(Error::Invalid));
            assert!(e.io.writes.is_empty());
        }
    }
    for (stream, r, value, error) in [
        (DpStream::Dio(2), 0x2094, 0x12, Error::Unsupported),
        (DpStream::Dio(2), 0x2094, 0x13, Error::Unsupported),
        (DpStream::Dio(2), 0x2094, 0x17, Error::Unsupported),
        (DpStream::Dio(2), 0x2094, 0x30, Error::Busy),
        (DpStream::Dio(2), 0x2094, 0, Error::Busy),
        (DpStream::Dio(2), 0x2095, 0, Error::Busy),
        (DpStream::Dio(2), 0x2123, 2, Error::Busy),
        (DpStream::Dio(2), 0x2123, 4, Error::Busy),
        (DpStream::Dio(2), 0x2123, 6, Error::Busy),
        (DpStream::Hpo(2), 0x3623, 0, Error::Busy),
        (DpStream::Hpo(2), 0x365d, 0, Error::Busy),
        (DpStream::Hpo(2), 0x365d, 0x11, Error::Busy),
        (DpStream::Hpo(2), 0x365d, 0x101, Error::Busy),
        (DpStream::Hpo(2), 0x365e, 0x11, Error::Busy),
        (DpStream::Hpo(2), 0x365e, 0x101, Error::Busy),
        (DpStream::Hpo(2), 0x3626, 0x11, Error::Busy),
        (DpStream::Hpo(2), 0x3626, 0x100001, Error::Busy),
    ] {
        let mut e = live(stream);
        e.io.regs.insert(stream.at(e.layout, r), value);
        assert_eq!(run(e.blank_dp_stream(stream)), Err(error));
        assert!(e.io.writes.is_empty());
        assert_eq!(e.status.state, State::Ready);
    }
    for stream in [DpStream::Dio(0), DpStream::Hpo(0)] {
        let mut e = live(stream);
        e.authority.revoke();
        assert_eq!(run(e.blank_dp_stream(stream)), Err(Error::Revoked));
        assert!(e.io.writes.is_empty());
        let mut e = live(stream);
        e.io.gone = Some(0);
        assert_eq!(run(e.blank_dp_stream(stream)), Err(Error::DeviceGone));
        assert!(e.io.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-stream",
    dcn401_dp_blank_preflight_rejects_unowned_modes_resets_and_missing_clocks
);

fn dcn401_dp_blank_waits_for_status_and_reset_acknowledgements() -> TestResult {
    for stream in [DpStream::Dio(0), DpStream::Hpo(0)] {
        let mut e = live(stream);
        e.io.dp_stall = stall(stream);
        let error = Error::Timeout(stream.at(e.layout, video(stream)));
        assert_eq!(run(e.blank_dp_stream(stream)), Err(error));
        assert_eq!(e.status.state, State::Failed(error));
        assert!(e.status.dp_blanked.is_none());
        // No downstream FIFO or SDP write before real video acknowledgement.
        assert!(e
            .io
            .writes
            .iter()
            .all(|&(at, _)| at == stream.at(e.layout, video(stream))));
        assert_eq!(run(e.blank_dp_stream(stream)), Err(Error::Busy));
    }
    let stream = DpStream::Dio(0);
    let mut e = live(stream);
    e.io.dp_stall = 1 << 8;
    let error = Error::Timeout(stream.at(e.layout, 0x2123));
    assert_eq!(run(e.blank_dp_stream(stream)), Err(error));
    assert_eq!(e.status.state, State::Failed(error));
    assert_eq!(e.io.writes.len(), 3);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-stream",
    dcn401_dp_blank_waits_for_status_and_reset_acknowledgements
);

fn dcn401_dp_blank_partial_failure_never_replays_or_releases_resources() -> TestResult {
    for stream in [DpStream::Dio(1), DpStream::Hpo(1)] {
        for n in 1..=writes(stream) {
            for error in [Error::Revoked, Error::DeviceGone] {
                let mut e = live(stream);
                if error == Error::Revoked {
                    e.io.revoke = Some((n, e.authority));
                } else {
                    e.io.gone = Some(n);
                }
                assert_eq!(run(e.blank_dp_stream(stream)), Err(error));
                assert_eq!(e.io.writes.len(), n);
                assert_eq!(e.status.state, State::Failed(error));
                assert!(e.status.dp_blanked.is_none());
                assert_eq!(run(e.blank_dp_stream(stream)), Err(Error::Busy));
                assert_eq!(run(e.retire(0)), Err(Error::Busy));
                assert_eq!(run(e.retire_planes()), Err(Error::Busy));
            }
            let mut e = live(stream);
            e.io.reject = Some(n);
            assert!(matches!(
                run(e.blank_dp_stream(stream)),
                Err(Error::Readback(_))
            ));
            assert_eq!(e.io.writes.len(), n);
            assert!(!e.status.state.reusable());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-stream",
    dcn401_dp_blank_partial_failure_never_replays_or_releases_resources
);

fn dcn401_dp_blank_cancellation_retains_each_incomplete_handshake() -> TestResult {
    for (stream, stalled) in [
        (DpStream::Dio(0), 1),
        (DpStream::Hpo(0), 16),
        (DpStream::Dio(0), 256),
    ] {
        let mut e = live(stream);
        e.io.dp_delay = [0; 8];
        e.io.dp_stall = stalled;
        {
            let mut f = core::pin::pin!(e.blank_dp_stream(stream));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.status.state, State::BlankingDp(stream));
        assert!(e.status.dp_blanked.is_none());
        let count = e.io.writes.len();
        assert_eq!(run(e.blank_dp_stream(stream)), Err(Error::Busy));
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
        assert_eq!(run(e.retire_planes()), Err(Error::Busy));
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::Busy)
        );
        assert_eq!(e.io.writes.len(), count);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-stream",
    dcn401_dp_blank_cancellation_retains_each_incomplete_handshake
);

fn dcn401_dp_blank_rejects_late_clock_reset_and_video_changes() -> TestResult {
    for (stream, r, v) in [
        (DpStream::Dio(3), 0x2094, 0),
        (DpStream::Dio(3), 0x2094, 0x13),
        (DpStream::Dio(3), 0x2095, 0),
        (DpStream::Dio(3), 0x2122, 0x10001),
        (DpStream::Hpo(3), 0x3623, 0),
        (DpStream::Hpo(3), 0x365d, 0x11),
        (DpStream::Hpo(3), 0x365e, 0x100),
        (DpStream::Hpo(3), 0x367b, 1),
        (DpStream::Hpo(3), 0x3685, 0x101),
    ] {
        let mut e = live(stream);
        e.io.after_write = Some((writes(stream), at(stream, r), v));
        assert_eq!(
            run(e.blank_dp_stream(stream)),
            Err(Error::Readback(at(stream, r)))
        );
        assert!(e.status.dp_blanked.is_none());
        assert!(!e.status.state.reusable());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-stream",
    dcn401_dp_blank_rejects_late_clock_reset_and_video_changes
);

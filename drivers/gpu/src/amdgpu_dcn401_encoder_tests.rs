use super::*;

fn at(s: DpStream, reg: u64) -> u64 {
    let (p, stride) = match s {
        DpStream::Dio(p) => (p, 0x124),
        DpStream::Hpo(p) => (p, 0xd4),
    };
    BASE + (reg + u64::from(p) * stride) * 4
}
fn blanked(s: DpStream, routes: u8) -> Engine<Fake> {
    let mut e = super::stream::live(s);
    run(e.blank_dp_stream(s)).unwrap();
    e.io.writes.clear();
    // One pending read after the write readback, then acknowledge at the next
    // poll. A model tied to several reads would turn timer tick granularity
    // into a spurious timeout for a hardware handshake bounded to 1 ms.
    e.io.encoder_delay = [2; 8];
    if let DpStream::Dio(p) = s {
        e.io.regs.insert(at(s, 0x209b), 0x385);
        for b in 0..4 {
            let backend = DpStream::Dio(b);
            let selected = routes & (1 << b) != 0;
            e.io.regs.insert(
                at(backend, 0x20bc),
                0x30000003 | (0x100 << ((p + 1) % 4)) | if selected { 0x100 << p } else { 0 },
            );
            // Unrelated live backends must not prevent selected stream teardown.
            e.io.regs.insert(at(backend, 0x20bd), u32::from(!selected));
        }
    }
    e
}
fn count(s: DpStream) -> usize {
    if matches!(s, DpStream::Dio(_)) {
        6
    } else {
        2
    }
}
fn stall(s: DpStream) -> u8 {
    match s {
        DpStream::Dio(p) => 1 << p,
        DpStream::Hpo(p) => 1 << (p + 4),
    }
}

fn dcn401_encoder_native_order_and_all_cross_routes_preserve_other_outputs() -> TestResult {
    for p in 0..4 {
        for s in [DpStream::Dio(p), DpStream::Hpo(p)] {
            let mut e = blanked(s, 0xa);
            let before = e.io.regs.clone();
            let result = run(e.retire_dp_encoder(s)).unwrap();
            assert_eq!(
                result,
                DpEncoderRetired {
                    stream: s,
                    detached_backends: if matches!(s, DpStream::Dio(_)) {
                        0xa
                    } else {
                        0
                    }
                }
            );
            assert_eq!(e.status.state, State::DpEncoderRetired);
            assert_eq!(e.status.dp_encoder_retired, Some(result));
            let expected = if matches!(s, DpStream::Dio(_)) {
                vec![
                    (at(s, 0x209b), 0x384),
                    (at(s, 0x2095), 0x100),
                    (at(s, 0x2094), 0x4c05),
                    (at(s, 0x209b), 0x84),
                    (
                        at(DpStream::Dio(1), 0x20bc),
                        before[&at(DpStream::Dio(1), 0x20bc)] & !(0x100 << p),
                    ),
                    (
                        at(DpStream::Dio(3), 0x20bc),
                        before[&at(DpStream::Dio(3), 0x20bc)] & !(0x100 << p),
                    ),
                ]
            } else {
                vec![(at(s, 0x365d), 0), (at(s, 0x3623), 0x11110)]
            };
            assert_eq!(e.io.writes, expected);
            for (reg, value) in before {
                if !e.io.writes.iter().any(|&(w, _)| w == reg) {
                    assert_eq!(e.io.regs.get(&reg), Some(&value));
                }
            }
            assert!(e.status.dp_blanked.is_some());
            assert_eq!(e.status.retired, 0);
            assert!(e.status.planes_retired.is_none());
            // Stream retirement is not proof that independently retained PHYs
            // or their training clocks are off.
            assert_eq!(run(e.retire_planes()), Err(Error::Busy));
        }
        for routes in 0..16 {
            let s = DpStream::Dio(p);
            let mut e = blanked(s, routes);
            let result = run(e.retire_dp_encoder(s)).unwrap();
            assert_eq!(result.detached_backends, routes);
            for b in 0..4 {
                assert_eq!(
                    e.io.regs[&at(DpStream::Dio(b), 0x20bc)] & 0x7f00,
                    0x100 << ((p + 1) % 4)
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-encoder",
    dcn401_encoder_native_order_and_all_cross_routes_preserve_other_outputs
);

fn dcn401_encoder_rejects_video_packets_resets_and_live_connected_backends() -> TestResult {
    for s in [DpStream::Dio(4), DpStream::Hpo(255)] {
        let mut e = engine();
        assert_eq!(run(e.retire_dp_encoder(s)), Err(Error::Invalid));
        assert!(e.io.writes.is_empty());
    }
    for (s, r, v, error) in [
        (DpStream::Dio(2), 0x2094, 0x13, Error::Unsupported),
        (DpStream::Dio(2), 0x2094, 0x35, Error::Busy),
        (DpStream::Dio(2), 0x209b, 2, Error::Busy),
        (DpStream::Dio(2), 0x209b, 0x100000, Error::Busy),
        (DpStream::Dio(2), 0x2122, 1, Error::Busy),
        (DpStream::Dio(2), 0x2122, 0x10000, Error::Busy),
        (DpStream::Dio(2), 0x2141, 1, Error::Busy),
        (DpStream::Dio(2), 0x2141, 0x10, Error::Busy),
        (DpStream::Dio(2), 0x2141, 0x100000, Error::Busy),
        (DpStream::Dio(2), 0x2141, 0x10000000, Error::Busy),
        (DpStream::Dio(2), 0x2091, 0x10, Error::Busy),
        (DpStream::Dio(2), 0x2091, 0x1000, Error::Busy),
        (DpStream::Hpo(2), 0x3685, 1, Error::Busy),
        (DpStream::Hpo(2), 0x3685, 0x100, Error::Busy),
        (DpStream::Hpo(2), 0x367b, 1, Error::Busy),
        (DpStream::Hpo(2), 0x365e, 1, Error::Busy),
        (DpStream::Hpo(2), 0x3626, 1, Error::Busy),
        (DpStream::Hpo(2), 0x365d, 0x11, Error::Busy),
    ] {
        let mut e = blanked(s, 0xa);
        e.io.dp_written = 0; // preserve injected status; no pending blank handshake
        e.io.regs.insert(at(s, r), v);
        assert_eq!(run(e.retire_dp_encoder(s)), Err(error));
        assert!(e.io.writes.is_empty());
        assert_eq!(e.status.state, State::DpBlanked);
    }
    for r in 0x2174..=0x2177 {
        for bit in [1, 0x10, 0x80, 0x1000, 0x2000] {
            let s = DpStream::Dio(2);
            let mut e = blanked(s, 0xa);
            e.io.regs.insert(at(s, r), bit);
            assert_eq!(run(e.retire_dp_encoder(s)), Err(Error::Busy));
            assert!(e.io.writes.is_empty());
        }
    }
    for p in 0..4 {
        for b in 0..4 {
            let s = DpStream::Dio(p);
            let mut e = blanked(s, 1 << b);
            e.io.regs.insert(at(DpStream::Dio(b), 0x20bd), 1);
            assert_eq!(run(e.retire_dp_encoder(s)), Err(Error::Busy));
            assert!(e.io.writes.is_empty());
            let mut e = blanked(s, 0);
            *e.io.regs.get_mut(&at(DpStream::Dio(b), 0x20bc)).unwrap() |= 0x1000;
            assert_eq!(run(e.retire_dp_encoder(s)), Err(Error::Unsupported));
            assert!(e.io.writes.is_empty());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-encoder",
    dcn401_encoder_rejects_video_packets_resets_and_live_connected_backends
);

fn dcn401_encoder_clock_acknowledgement_is_required_before_detach() -> TestResult {
    for s in [DpStream::Dio(0), DpStream::Hpo(0)] {
        let mut e = blanked(s, 0xa);
        e.io.encoder_stall = stall(s);
        let clock = if matches!(s, DpStream::Dio(_)) {
            0x2094
        } else {
            0x3623
        };
        let error = Error::Timeout(at(s, clock));
        assert_eq!(run(e.retire_dp_encoder(s)), Err(error));
        assert_eq!(e.status.state, State::Failed(error));
        assert!(e.status.dp_encoder_retired.is_none());
        assert_eq!(
            e.io.writes.len(),
            if matches!(s, DpStream::Dio(_)) { 3 } else { 2 }
        );
        assert_eq!(run(e.retire_dp_encoder(s)), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-encoder",
    dcn401_encoder_clock_acknowledgement_is_required_before_detach
);

fn dcn401_encoder_cancelled_clock_wait_blocks_all_reuse() -> TestResult {
    for s in [DpStream::Dio(1), DpStream::Hpo(1)] {
        let mut e = blanked(s, 0xa);
        e.io.encoder_stall = stall(s);
        {
            let mut f = core::pin::pin!(e.retire_dp_encoder(s));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.status.state, State::RetiringDpEncoder(s));
        assert!(!e.status.state.reusable());
        assert!(e.status.dp_encoder_retired.is_none());
        assert_eq!(run(e.retire_dp_encoder(s)), Err(Error::Busy));
        assert_eq!(run(e.blank_dp_stream(s)), Err(Error::Busy));
        assert_eq!(run(e.retire_planes()), Err(Error::Busy));
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::Busy)
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-encoder",
    dcn401_encoder_cancelled_clock_wait_blocks_all_reuse
);

fn dcn401_encoder_revocation_device_loss_and_lost_writes_are_terminal() -> TestResult {
    for s in [DpStream::Dio(3), DpStream::Hpo(3)] {
        for n in 0..=count(s) {
            for error in [Error::DeviceGone, Error::Revoked] {
                let mut e = blanked(s, 0xa);
                if error == Error::DeviceGone {
                    e.io.gone = Some(n);
                } else if n == 0 {
                    e.authority.revoke();
                } else {
                    e.io.revoke = Some((n, e.authority));
                }
                assert_eq!(run(e.retire_dp_encoder(s)), Err(error), "{s:?}, write {n}");
                assert_eq!(e.io.writes.len(), n);
                assert!(e.status.dp_encoder_retired.is_none());
                if n != 0 {
                    assert_eq!(e.status.state, State::Failed(error));
                    assert_eq!(run(e.retire_dp_encoder(s)), Err(Error::Busy));
                }
            }
            if n != 0 {
                let mut e = blanked(s, 0xa);
                e.io.reject = Some(n);
                assert!(matches!(
                    run(e.retire_dp_encoder(s)),
                    Err(Error::Readback(_))
                ));
                assert_eq!(e.io.writes.len(), n);
                assert!(!e.status.state.reusable());
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-encoder",
    dcn401_encoder_revocation_device_loss_and_lost_writes_are_terminal
);

fn dcn401_encoder_revalidates_routes_and_consumers_after_clock_wait() -> TestResult {
    let s = DpStream::Dio(2);
    for (reg, value, error) in [
        (at(DpStream::Dio(1), 0x20bd), 1, Error::Busy),
        (
            at(DpStream::Dio(0), 0x20bc),
            0,
            Error::Readback(at(DpStream::Dio(0), 0x20bc)),
        ),
        (at(s, 0x2091), 0x10, Error::Busy),
        (at(s, 0x2141), 1, Error::Busy),
    ] {
        let mut e = blanked(s, 0xa);
        e.io.after_write = Some((3, reg, value));
        assert_eq!(run(e.retire_dp_encoder(s)), Err(error));
        assert_eq!(e.io.writes.len(), 3); // no route/pixel-mode changes after wait
        assert_eq!(e.status.state, State::Failed(error));
    }
    for (s, r, v) in [
        (DpStream::Dio(2), 0x2094, 0x23),
        (DpStream::Dio(2), 0x2095, 1),
        (DpStream::Dio(2), 0x209b, 0x100),
        (DpStream::Dio(2), 0x2122, 0x10001),
        (DpStream::Dio(2), 0x2174, 0x1000),
        (DpStream::Hpo(2), 0x365d, 1),
        (DpStream::Hpo(2), 0x367b, 1),
        (DpStream::Hpo(2), 0x3685, 0x101),
    ] {
        let mut e = blanked(s, 0xa);
        e.io.after_write = Some((count(s), at(s, r), v));
        assert!(run(e.retire_dp_encoder(s)).is_err());
        assert!(!e.status.state.reusable());
        assert!(e.status.dp_encoder_retired.is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-encoder",
    dcn401_encoder_revalidates_routes_and_consumers_after_clock_wait
);

fn dcn401_encoder_shutdown_composes_with_plane_retirement_after_phy_stop() -> TestResult {
    for s in [DpStream::Dio(0), DpStream::Hpo(0)] {
        let mut e = blanked(s, 0xa);
        run(e.retire_dp_encoder(s)).unwrap();
        // Repeating retirement is safe while it still checks current hardware.
        assert_eq!(run(e.retire_dp_encoder(s)).unwrap().detached_backends, 0);
        // Model the independent PHY owner's later shutdown; this operation
        // deliberately supplies no firmware/link-disable command itself.
        for b in 0..4 {
            e.io.regs.insert(at(DpStream::Dio(b), 0x20bd), 0);
        }
        e.io.regs.insert(BASE + 0x369f * 4, 0);
        assert_eq!(run(e.retire_planes()).unwrap().blanked, 0xf);
        run(e.retire(3)).unwrap();
        assert_eq!(e.status.retired, 8);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-encoder",
    dcn401_encoder_shutdown_composes_with_plane_retirement_after_phy_stop
);

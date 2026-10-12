use super::*;

fn planes(off: u8) -> Engine<Fake> {
    let mut e = engine();
    for p in 0..4 {
        let h = |r| BASE + (r + p * 0xdc) * 4;
        let m = |r| MPC_BASE + (r + p * 0x15) * 4;
        // Cross-routed, multi-layer inherited tree, all attached to OPP 2.
        e.io.regs
            .insert(MPC_BASE + (0x2f2 + p * 4) * 4, if p == 2 { 0 } else { 0xf });
        e.io.regs.insert(m(0), ((p + 2) % 4) as u32);
        e.io.regs
            .insert(m(1), if p == 3 { 0xf } else { p as u32 + 1 });
        e.io.regs.insert(m(2), 2);
        e.io.regs.insert(m(5), 2);
        e.io.regs.insert(m(0xe), 2);
        if off & (1 << p) != 0 {
            e.io.regs.insert(BASE + (0x80 + p * 2) * 4, 0x100);
            e.io.regs.insert(BASE + (0x81 + p * 2) * 4, 0x80000000);
        } else {
            e.io.regs.insert(h(0x5f4), 0x40000100); // unrelated underflow/ready fields
            e.io.regs.insert(h(0x5f5), 0x100011); // inherited forced clock bits
            e.io.regs.insert(h(0x679), 0x101); // keep request mode, clear enable
            e.io.regs.insert(h(0x5f7), 0x40000007); // cursor/plane MALL selection
            e.io.regs.insert(h(0x614), 0x400); // preserve triple buffering
        }
    }
    e.io.forbidden_hubps = off;
    e
}

fn dcn401_planes_disconnect_all_cross_routes_before_blanking_or_gating() -> TestResult {
    let mut e = planes(0);
    // Live timing can latch disconnects; this function never rewrites timing.
    e.io.regs.insert(BASE + (0x1b43 + 2 * 0x80) * 4, 0x10001);
    e.io.regs.insert(BASE + (0x1b84 + 2 * 0x80) * 4, 0x10100);
    e.io.plane_delay = [3; 4];
    let result = run(e.retire_planes()).unwrap();
    assert_eq!(
        result,
        PlanesRetired {
            blanked: 0xf,
            powered_off: 0
        }
    );
    assert_eq!(e.status.planes_retired, Some(result));
    assert_eq!(e.status.state, State::PlanesRetired);
    assert!(e.status.state.reusable());
    let mut expected = Vec::new();
    for p in 0..4 {
        expected.push((MPC_BASE + (0x2f2 + p * 4) * 4, 0xf));
    }
    for p in 0..4 {
        for r in [0, 1, 2, 5] {
            expected.push((MPC_BASE + (r + p * 0x15) * 4, 0xf));
        }
    }
    for p in 0..4 {
        expected.push((BASE + (0x679 + p * 0xdc) * 4, 0x100));
    }
    for p in 0..4 {
        for (r, value) in [(0x5f4, 0x40000103), (0x5f7, 0x40000008), (0x614, 0x400)] {
            expected.push((BASE + (r + p * 0xdc) * 4, value));
        }
    }
    for p in 0..4 {
        expected.push((BASE + (0x5f5 + p * 0xdc) * 4, 0x100010));
    }
    assert_eq!(e.io.writes, expected);
    assert_eq!(reg(&e, 0x1b43 + 2 * 0x80), 0x10001);
    assert_eq!(reg(&e, 0x1b84 + 2 * 0x80), 0x10100);
    // Inherited GPU/scanout backing is deliberately untouched.
    assert_eq!(e.status.retired, 0);
    assert!(e.status.pipes.iter().all(Option::is_none));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-fetch",
    dcn401_planes_disconnect_all_cross_routes_before_blanking_or_gating
);

fn dcn401_planes_use_power_acknowledgement_without_accessing_gated_hubps() -> TestResult {
    let mut e = planes(0xf);
    e.io.regs.insert(BASE + 0x80 * 4, 0x101); // forced on contradicts OFF
    assert_eq!(run(e.retire_planes()), Err(Error::Busy));
    assert!(e.io.writes.is_empty());
    for off in 0..16 {
        let mut e = planes(off);
        let r = run(e.retire_planes()).unwrap();
        assert_eq!(
            r,
            PlanesRetired {
                blanked: 0xf ^ off,
                powered_off: off
            }
        );
        assert_eq!(e.io.writes.len(), 20 + 5 * (4 - off.count_ones() as usize));
        // MPCC disabled is also a native drain witness, even with OTG stopped.
        for p in 0..4 {
            e.io.regs.insert(MPC_BASE + (0xe + p * 0x15) * 4, 4);
        }
        e.io.stall = 512;
        assert_eq!(run(e.retire_planes()), Ok(r));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-fetch",
    dcn401_planes_use_power_acknowledgement_without_accessing_gated_hubps
);

fn dcn401_planes_reject_active_auxiliary_loads_locks_and_power_transitions() -> TestResult {
    for p in 0..4 {
        let h = |r| BASE + (r + p * 0xdc) * 4;
        let o = |r| BASE + (r + p * 0x80) * 4;
        for (at, value) in [
            (h(0x685), 1),
            (h(0x685), 2),
            (h(0x685), 4),
            (h(0x685), 1 << 16),
            (h(0x68a), 1),
            (h(0x5f4), 4),
            (h(0x613), 1),
            (h(0x613), 0x100),
            (h(0x613), 0x200),
            (h(0x614), 0x100),
            (h(0x5f7), 0x10),
            (o(0x1b89), 1),
            (o(0x1b89), 0x100),
            (o(0x1b84), 0x10),
            (o(0x1b8a), 1),
            (o(0x1b8a), 2),
            (o(0x1b8a), 4),
            (o(0x1b8a), 8),
            (o(0x1b8a), 0x80000000),
            (MPC_BASE + (5 + p * 0x15) * 4, 0x10),
            (BASE + (0x80 + p * 2) * 4, 0x100), // requested off, still on
            (BASE + (0x81 + p * 2) * 4, 0x40000000),
            (BASE + (0x81 + p * 2) * 4, 0x80000000), // off without request
            (BASE + (0x81 + p * 2) * 4, 0xc0000000),
        ] {
            let mut e = planes(0);
            e.io.regs.insert(at, value);
            assert_eq!(run(e.retire_planes()), Err(Error::Busy));
            assert!(e.io.writes.is_empty());
            assert_eq!(e.status.state, State::Ready);
        }
    }
    for (at, mask) in engine().layout.idle {
        if (0..4)
            .any(|p| at == BASE + (0x1b43 + p * 0x80) * 4 || at == BASE + (0x1b84 + p * 0x80) * 4)
        {
            continue;
        }
        let mut e = planes(0);
        e.io.regs.insert(at, mask);
        assert_eq!(run(e.retire_planes()), Err(Error::Busy));
        assert!(e.io.writes.is_empty());
    }
    for at in [
        MPC_BASE,
        MPC_BASE + 4,
        MPC_BASE + 8,
        MPC_BASE + 20,
        MPC_BASE + 0x2f2 * 4,
    ] {
        let mut e = planes(0);
        e.io.regs.insert(at, 4);
        assert_eq!(run(e.retire_planes()), Err(Error::Unsupported));
        assert!(e.io.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-fetch",
    dcn401_planes_reject_active_auxiliary_loads_locks_and_power_transitions
);

fn dcn401_planes_do_not_gate_clocks_without_native_drain() -> TestResult {
    for (stall, at, count) in [
        (512, MPC_BASE + 0xe * 4, 24),
        (1024, BASE + 0x5f4 * 4, 24),
        (2048, BASE + 0x5f4 * 4, 36),
    ] {
        let mut e = planes(0);
        e.io.stall = stall;
        let error = Error::Timeout(at);
        assert_eq!(run(e.retire_planes()), Err(error));
        assert_eq!(e.status.state, State::Failed(error));
        assert!(e.status.planes_retired.is_none());
        assert_eq!(e.io.writes.len(), count);
        assert!(e
            .io
            .writes
            .iter()
            .all(|&(at, _)| (0..4).all(|p| at != BASE + (0x5f5 + p * 0xdc) * 4)));
        assert_eq!(run(e.retire_planes()), Err(Error::Busy));
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
    }
    // Neither zero status nor contradictory BUSY+IDLE/DISABLED can pass.
    for status in [0, 3, 6, 7] {
        let mut e = planes(0);
        e.io.regs.insert(MPC_BASE + 0xe * 4, status);
        e.io.stall = 512;
        assert_eq!(
            run(e.retire_planes()),
            Err(Error::Timeout(MPC_BASE + 0xe * 4))
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-fetch",
    dcn401_planes_do_not_gate_clocks_without_native_drain
);

fn dcn401_planes_revocation_device_loss_and_lost_writes_quarantine() -> TestResult {
    for n in 1..=40 {
        for revoke in [false, true] {
            let mut e = planes(0);
            if revoke {
                e.io.revoke = Some((n, e.authority));
            } else {
                e.io.gone = Some(n);
            }
            let error = if revoke {
                Error::Revoked
            } else {
                Error::DeviceGone
            };
            assert_eq!(run(e.retire_planes()), Err(error));
            assert_eq!(e.io.writes.len(), n);
            assert_eq!(e.status.state, State::Failed(error));
            assert!(e.status.planes_retired.is_none());
            assert_eq!(run(e.retire_planes()), Err(Error::Busy));
        }
    }
    // Every changed selector/enable is read back. Already-parked output muxes
    // and already-clear GSL writes are idempotent and need no fault assertion.
    for n in [
        3, 5, 6, 7, 8, 9, 13, 17, 21, 22, 23, 24, 25, 26, 28, 29, 31, 32, 34, 35, 37, 38, 39, 40,
    ] {
        let mut e = planes(0);
        e.io.reject = Some(n);
        assert!(matches!(run(e.retire_planes()), Err(Error::Readback(_))));
        assert_eq!(e.io.writes.len(), n);
        assert!(!e.status.state.reusable());
        assert!(e.status.planes_retired.is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-fetch",
    dcn401_planes_revocation_device_loss_and_lost_writes_quarantine
);

fn dcn401_planes_cancellation_and_late_changes_prevent_reuse() -> TestResult {
    for stall in [512, 1024, 2048] {
        let mut e = planes(0);
        e.io.stall = stall;
        {
            let mut future = core::pin::pin!(e.retire_planes());
            assert!(future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.status.state, State::RetiringPlanes);
        assert!(e.status.planes_retired.is_none());
        assert!(!e.status.state.reusable());
        let writes = e.io.writes.len();
        assert_eq!(run(e.retire_planes()), Err(Error::Busy));
        assert_eq!(
            run(e.prepare(request(0), clock(request(0)))),
            Err(Error::Busy)
        );
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
        assert_eq!(e.io.writes.len(), writes);
    }
    for (at, value) in [
        (BASE + 0x80 * 4, 0x100),
        (BASE + 0x68a * 4, 1),
        (BASE + 0x685 * 4, 4),
        (BASE + 0x5f7 * 4, 0x10),
        (BASE + 0x20bd * 4, 1),
        (MPC_BASE + 5 * 4, 0x1f),
    ] {
        let mut e = planes(0);
        e.io.after_write = Some((40, at, value));
        assert_eq!(run(e.retire_planes()), Err(Error::Busy));
        assert_eq!(e.status.state, State::Failed(Error::Busy));
        assert!(e.status.planes_retired.is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-fetch",
    dcn401_planes_cancellation_and_late_changes_prevent_reuse
);

fn dcn401_blank_accepts_native_ttu_and_powered_off_fetchers() -> TestResult {
    // The stopped predicate is also used before/after blank-timing activation.
    // Unlike hubp1, native hubp2 blanking intentionally leaves TTU_DISABLE=0.
    for off in 0..16 {
        let mut e = planes(off);
        run(e.retire_planes()).unwrap();
        run(e.prepare(request(0), clock(request(0)))).unwrap();
        run(e.prepare_blank(blank_request(0), clock(request(0)))).unwrap();
        e.io.retiring = [false; 4];
        let running = run(e.start_blank(0, clock(request(0)))).unwrap();
        assert_ne!(running.frame_before, running.frame_after);
        assert_eq!(e.status.state, State::RunningBlank(0));
        assert_eq!(run(e.retire_planes()), Err(Error::Busy));
    }
    // Zero register reads alone, even with a gate request, cannot prove OFF.
    let mut e = engine();
    assert_eq!(e.fetchers_stopped(), Err(Error::Busy));
    e.io.regs.insert(BASE + 0x80 * 4, 0x100);
    assert_eq!(e.fetchers_stopped(), Err(Error::Busy));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-fetch",
    dcn401_blank_accepts_native_ttu_and_powered_off_fetchers
);

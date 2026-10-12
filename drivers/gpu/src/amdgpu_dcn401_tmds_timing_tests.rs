use super::*;

fn otg(p: u8, r: u64) -> u64 {
    BASE + (r + u64::from(p) * 0x80) * 4
}
fn odm(p: u8, r: u64) -> u64 {
    BASE + (r + u64::from(p) * 0x10) * 4
}
fn dio(p: u8, r: u64) -> u64 {
    BASE + (r + u64::from(p) * 0x124) * 4
}
struct Model {
    inner: Fake,
    pipe: u8,
    stall: u8, // underflow clear, OTG clock-off, input clock-off
    gates: u8,
}
impl Io for Model {
    fn read(&mut self, at: u64) -> u32 {
        for (reg, gate, stall, on) in [
            (otg(self.pipe, 0x1b84), 1, 2, 0x100),
            (odm(self.pipe, 0x1ad0), 2, 4, 4),
        ] {
            if reg == at && self.gates & gate != 0 && self.stall & stall == 0 {
                *self.inner.regs.entry(reg).or_default() &= !on;
                self.gates &= !gate;
            }
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        if at == otg(self.pipe, 0x1b84) || at == odm(self.pipe, 0x1ad0) {
            assert_eq!(self.inner.regs[&otg(self.pipe, 0x1b43)] & 0x10001, 0);
            assert_eq!(self.inner.regs[&otg(self.pipe, 0x1b84)] & 0x10000, 0);
            assert_eq!(self.inner.regs[&odm(self.pipe, 0x1aca)] & 0x400, 0);
        }
        self.inner.write(at, value);
        if self.inner.writes.len() >= 5 {
            self.inner.retiring[usize::from(self.pipe)] = false;
        }
        if at == odm(self.pipe, 0x1aca)
            && self.stall & 1 == 0
            && self.inner.reject != Some(self.inner.writes.len())
        {
            *self.inner.regs.entry(at).or_default() &= !0x1c00;
        }
        if at == otg(self.pipe, 0x1b84) && value & 3 == 0 {
            self.gates |= 1;
        }
        if at == odm(self.pipe, 0x1ad0) && value & 3 == 0 {
            self.gates |= 2;
        }
    }
}
fn live(pipe: u8, links: u8) -> Engine<Model> {
    let mut e = engine();
    // Other timing generators remain active and untouched.
    for p in 0..4 {
        active(&mut e, p);
        e.io.regs.insert(odm(p, 0x1aca), 0xf00);
        e.io.regs.insert(odm(p, 0x1ad0), 0x87);
        e.io.regs.insert(dio(p, 0x20bc), u32::from(p) << 28 | 2);
        let enabled = links & (1 << p) != 0;
        e.io.regs
            .insert(dio(p, 0x20bb), if enabled { 0x2813 } else { 0 });
        e.io.regs.insert(dio(p, 0x20bd), u32::from(enabled));
        e.io.regs
            .insert(BASE + (0x179a + 3 * u64::from(p)) * 4, 0x430);
        e.io.regs.insert(
            BASE + (0x2931 + 0xd8 * u64::from(p)) * 4,
            if enabled { 0x6f0 } else { 0 },
        );
        e.io.regs.insert(
            BASE + (0x2943 + 0xd8 * u64::from(p)) * 4,
            if enabled { 0xc0c0c0c } else { 0x2020202 },
        );
    }
    Engine {
        io: Model {
            inner: e.io,
            pipe,
            stall: 0,
            gates: 0,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
    }
}

fn dcn401_tmds_timing_stops_all_pipes_with_every_retained_transmitter_combination() -> TestResult {
    for pipe in 0..4 {
        for links in 0..16 {
            let mut e = live(pipe, links);
            let before = e.io.inner.regs.clone();
            let result = run(e.retire_tmds_timing(pipe)).unwrap();
            assert_eq!(
                result,
                TmdsTimingRetired {
                    pipe,
                    retained_transmitters: links
                }
            );
            assert_eq!(e.status.state, State::TmdsTimingRetired);
            assert_eq!(e.status.tmds_timing_retired, Some(result));
            assert_eq!(e.status.retired, 1 << pipe);
            assert_eq!(
                e.io.inner.writes,
                [
                    (odm(pipe, 0x1acb), 0xffff0100),
                    (odm(pipe, 0x1ad1), 0xabcd0000),
                    (otg(pipe, 0x1b43), 0x210200),
                    (BASE + (0x530 + u64::from(pipe)) * 4, 0x55),
                    (odm(pipe, 0x1aca), 0x1f00),
                    (otg(pipe, 0x1b84), 0x100),
                    (odm(pipe, 0x1ad0), 0x84),
                ]
            );
            for (reg, value) in before {
                if !e.io.inner.writes.iter().any(|&(r, _)| r == reg) {
                    assert_eq!(e.io.inner.regs[&reg], value);
                }
            }
            assert_eq!(e.io.inner.regs[&otg(pipe, 0x1b84)], 0);
            assert_eq!(e.io.inner.regs[&odm(pipe, 0x1ad0)], 0x80);
            assert_eq!(e.io.inner.regs[&odm(pipe, 0x1aca)], 0x300);
            assert!(e.status.planes_retired.is_none());
            // Repeated retirement uses live register evidence, with no second
            // underflow clear when its status is already clear.
            e.io.inner.writes.clear();
            run(e.retire_tmds_timing(pipe)).unwrap();
            assert_eq!(e.io.inner.writes.len(), 6);
            if links != 0 {
                assert_eq!(
                    run(e.prepare(request(pipe), clock(request(pipe)))),
                    Err(Error::Busy)
                );
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-tmds-timing",
    dcn401_tmds_timing_stops_all_pipes_with_every_retained_transmitter_combination
);

fn dcn401_tmds_timing_rejects_live_frontends_foreign_links_and_transactions() -> TestResult {
    for (reg, value) in [
        (dio(1, 0x20bc), 0x100),
        (dio(1, 0x20bc), 1),
        (dio(1, 0x20bb), 0x2810),
        (dio(1, 0x20bb), 0x2833),
        (dio(1, 0x20bb), 0x2853),
        (BASE + (0x179a + 3) * 4, 1),
        (BASE + (0x179a + 3) * 4, 2),
        (BASE + (0x2943 + 0xd8) * 4, 0x10000000),
        (BASE + (0x2943 + 0xd8) * 4, 0x20),
        (dio(1, 0x2094), 0x1000),
        (dio(1, 0x2094), 0x4000),
        (dio(1, 0x2094), 0x20),
        (dio(1, 0x2091), 0x10),
        (dio(1, 0x2091), 0x1000),
        (dio(1, 0x209d), 1),
        (otg(2, 0x1b89), 1),
        (otg(2, 0x1b89), 0x100),
        (otg(2, 0x1b84), 0x10113),
        (odm(2, 0x1aca), 1),
        (odm(2, 0x1aca), 0x80000000),
    ] {
        let mut e = live(2, 0xf);
        e.io.inner.regs.insert(reg, value);
        assert!(run(e.retire_tmds_timing(2)).is_err(), "{reg:x}");
        assert!(e.io.inner.writes.is_empty());
        assert_eq!(e.status.state, State::Ready);
    }
    let baseline = live(2, 0xf);
    for (reg, mask) in baseline.layout.idle {
        if (0..4).any(|p| {
            reg == dio(p, 0x20bb)
                || reg == dio(p, 0x20bd)
                || reg == BASE + (0x2931 + u64::from(p) * 0xd8) * 4
                || reg == BASE + (0x2943 + u64::from(p) * 0xd8) * 4
        }) || (0..4).any(|p| reg == otg(p, 0x1b43) || reg == otg(p, 0x1b84))
        {
            continue;
        }
        for bit in (0..32).map(|b| 1u32 << b).filter(|b| b & mask != 0) {
            let mut e = live(2, 0xf);
            e.io.inner.regs.insert(reg, bit);
            assert_eq!(
                run(e.retire_tmds_timing(2)),
                Err(Error::Busy),
                "{reg:x}/{bit:x}"
            );
            assert!(e.io.inner.writes.is_empty());
        }
    }
    for p in [4, 255] {
        let mut e = live(0, 0xf);
        assert_eq!(run(e.retire_tmds_timing(p)), Err(Error::Invalid));
        assert!(e.io.inner.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-tmds-timing",
    dcn401_tmds_timing_rejects_live_frontends_foreign_links_and_transactions
);

fn dcn401_tmds_timing_requires_stop_underflow_and_both_clock_acknowledgements() -> TestResult {
    for stage in 0..5 {
        let mut e = live(0, 0xf);
        let (reg, count) = match stage {
            0 => {
                e.io.inner.stall = 4;
                (otg(0, 0x1b43), 4)
            }
            1 => {
                e.io.inner.stall = 8;
                (otg(0, 0x1b84), 4)
            }
            2 => {
                e.io.stall = 1;
                (odm(0, 0x1aca), 5)
            }
            3 => {
                e.io.stall = 2;
                (otg(0, 0x1b84), 7)
            }
            _ => {
                e.io.stall = 4;
                (odm(0, 0x1ad0), 7)
            }
        };
        let error = Error::Timeout(reg);
        assert_eq!(run(e.retire_tmds_timing(0)), Err(error));
        assert_eq!(e.io.inner.writes.len(), count);
        assert_eq!(e.status.state, State::Failed(error));
        assert!(e.status.tmds_timing_retired.is_none());
        assert_eq!(e.status.retired, 0);
        assert_eq!(run(e.retire_tmds_timing(0)), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-tmds-timing",
    dcn401_tmds_timing_requires_stop_underflow_and_both_clock_acknowledgements
);

fn dcn401_tmds_timing_cancellation_at_each_handshake_retains_ownership() -> TestResult {
    for stage in 0..5 {
        let mut e = live(0, 0xf);
        e.io.inner.delay[0] = 0;
        match stage {
            0 => e.io.inner.stall = 4,
            1 => e.io.inner.stall = 8,
            _ => e.io.stall = 1 << (stage - 2),
        }
        {
            let mut f = core::pin::pin!(e.retire_tmds_timing(0));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.io.inner.writes.len(), [4, 4, 5, 7, 7][stage]);
        assert_eq!(e.status.state, State::RetiringTmdsTiming(0));
        assert!(e.status.tmds_timing_retired.is_none());
        assert_eq!(e.status.retired, 0);
        assert_eq!(run(e.retire_tmds_timing(0)), Err(Error::Busy));
        assert_eq!(run(e.retire(0)), Err(Error::Busy));
        assert_eq!(run(e.retire_planes()), Err(Error::Busy));
        assert_eq!(run(e.retire_hdmi_tmds_encoder(0)), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-tmds-timing",
    dcn401_tmds_timing_cancellation_at_each_handshake_retains_ownership
);

fn dcn401_tmds_timing_lost_writes_revocation_and_device_loss_are_terminal() -> TestResult {
    for n in 0..=7 {
        for error in [Error::DeviceGone, Error::Revoked] {
            let mut e = live(3, 0xf);
            if error == Error::DeviceGone {
                e.io.inner.gone = Some(n);
            } else if n == 0 {
                e.authority.revoke();
            } else {
                e.io.inner.revoke = Some((n, e.authority));
            }
            assert_eq!(run(e.retire_tmds_timing(3)), Err(error));
            assert_eq!(e.io.inner.writes.len(), n);
            assert!(e.status.tmds_timing_retired.is_none());
            assert_eq!(e.status.retired, 0);
            if n != 0 {
                assert_eq!(e.status.state, State::Failed(error));
            }
        }
        if n != 0 {
            let mut e = live(3, 0xf);
            e.io.inner.reject = Some(n);
            assert!(run(e.retire_tmds_timing(3)).is_err());
            assert_eq!(e.io.inner.writes.len(), n);
            assert!(!e.status.state.reusable());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-tmds-timing",
    dcn401_tmds_timing_lost_writes_revocation_and_device_loss_are_terminal
);

fn dcn401_tmds_timing_rechecks_retained_links_before_gating_and_at_completion() -> TestResult {
    for n in [4, 5, 7] {
        for (reg, value) in [
            (dio(0, 0x2095), 1),
            (dio(0, 0x20bd), 0),
            (dio(1, 0x20bb), 3),
            (dio(1, 0x20bc), 0x20000000),
            (BASE + (0x179a + 3) * 4, 0x330),
            (BASE + (0x2943 + 0xd8) * 4, 0x2020202),
            (BASE + (0x2931 + 0xd8) * 4, 0),
            (otg(2, 0x1b89), 1),
        ] {
            let mut e = live(2, 0xf);
            e.io.inner.after_write = Some((n, reg, value));
            assert!(run(e.retire_tmds_timing(2)).is_err(), "{n}/{reg:x}");
            assert_eq!(e.io.inner.writes.len(), n);
            assert!(!e.status.state.reusable());
            assert_eq!(e.status.retired, 0);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-tmds-timing",
    dcn401_tmds_timing_rechecks_retained_links_before_gating_and_at_completion
);

fn dcn401_tmds_timing_reactivation_cannot_pass_clock_retirement() -> TestResult {
    for n in [5, 7] {
        for (reg, value) in [
            (otg(2, 0x1b43), 1),
            (otg(2, 0x1b43), 0x10000),
            (BASE + (0x530 + 2) * 4, 0x80000000),
            (odm(2, 0x1acb), 0),
            (odm(2, 0x1ad1), 1),
            (otg(2, 0x1b84), 0x10103),
        ] {
            let mut e = live(2, 0xf);
            e.io.inner.after_write = Some((n, reg, value));
            assert!(run(e.retire_tmds_timing(2)).is_err(), "{n}/{reg:x}");
            assert_eq!(e.io.inner.writes.len(), n);
            assert_eq!(e.status.retired, 0);
            assert!(!e.status.state.reusable());
        }
    }
    for reg in [odm(2, 0x1aca), otg(2, 0x1b84)] {
        let mut e = live(2, 0xf);
        let value = if reg == odm(2, 0x1aca) { 0x400 } else { 0x100 };
        e.io.inner.after_write = Some((7, reg, value));
        assert!(run(e.retire_tmds_timing(2)).is_err());
        assert_eq!(e.status.retired, 0);
    }
    // A clock-off HDMI frontend can still carry an unfinished packet update.
    for (reg, value) in [(0x20a5, 1), (0x20b0, 0x10000), (0x20b1, 1)] {
        let mut e = live(2, 0xf);
        e.io.inner.regs.insert(dio(1, 0x2094), 3);
        e.io.inner.regs.insert(dio(1, reg), value);
        assert!(run(e.retire_tmds_timing(2)).is_err());
        assert!(e.io.inner.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-tmds-timing",
    dcn401_tmds_timing_reactivation_cannot_pass_clock_retirement
);

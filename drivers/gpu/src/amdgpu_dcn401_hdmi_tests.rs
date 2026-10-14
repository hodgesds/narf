use super::*;

fn at(s: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(s) * 0x124) * 4
}
struct Model {
    inner: Fake,
    stream: u8,
    packet_stall: u32,
    db_stall: u32,
    attribute_stall: u32,
    packet_delay: u8,
    db_delay: u8,
}
impl Io for Model {
    fn read(&mut self, reg: u64) -> u32 {
        if self.inner.writes.len() >= 10 && reg == at(self.stream, 0x20b0) {
            if self.packet_delay == 0 {
                *self.inner.regs.entry(reg).or_default() &= !0x7fff0000;
                *self.inner.regs.entry(reg).or_default() |= self.packet_stall;
            } else {
                self.packet_delay -= 1;
            }
        }
        if !self.inner.writes.is_empty() && reg == at(self.stream, 0x20b1) {
            if self.db_delay == 0 {
                *self.inner.regs.entry(reg).or_default() &= !0x8001;
                *self.inner.regs.entry(reg).or_default() |= if self
                    .inner
                    .writes
                    .iter()
                    .any(|&(r, _)| r == at(self.stream, 0x209e))
                {
                    self.attribute_stall
                } else {
                    self.db_stall
                };
            } else {
                self.db_delay -= 1;
            }
        }
        self.inner.read(reg)
    }
    fn write(&mut self, reg: u64, value: u32) {
        if reg == at(self.stream, 0x209b) {
            assert_eq!(self.inner.regs[&at(self.stream, 0x20b0)] & 0x7fff0000, 0);
            assert_eq!(self.inner.regs[&at(self.stream, 0x20b1)] & 0x8101, 0);
        }
        self.inner.write(reg, value);
        if reg == at(self.stream, 0x20a5) || reg == at(self.stream, 0x20a6) {
            *self.inner.regs.entry(at(self.stream, 0x20b0)).or_default() |= 0x7fff0000;
        }
        if reg == at(self.stream, 0x20a5) || reg == at(self.stream, 0x209e) {
            *self.inner.regs.entry(at(self.stream, 0x20b1)).or_default() |= 0x8001;
            self.db_delay = 0;
        }
    }
}
fn live(s: u8, routes: u8) -> Engine<Model> {
    let mut e = engine();
    for (reg, value) in [
        (0x2093, 0x100 | u32::from((s + 1) % 4)),
        (0x2094, 0x2c13),
        (0x2095, 0x101),
        (0x209b, 0x385),
        (0x209e, 0x31100006),
        (0x20a5, 0x33333333),
        (0x20a6, 0x3333333),
        (0x20a9, 0x100020),
        (0x20aa, 0x300040),
        (0x20ab, 0x500060),
        (0x20ac, 0x700080),
        (0x20ad, 0x9000a0),
        (0x20ae, 0xb000c0),
        (0x20af, 0xd000e0),
        (0x20b0, 0x800000f0),
        (0x20b1, 0x1000),
        // Independent packet/audio configuration, resources and live timing
        // are left alone after their producers have been stopped by the owner.
        (0x20a1, 0x1003),
        (0x20a2, 0x31),
        (0x20a3, 0x30),
    ] {
        e.io.regs.insert(at(s, reg), value);
    }
    e.io.encoder_delay[usize::from(s)] = 2;
    for b in 0..4 {
        let selected = routes & (1 << b) != 0;
        e.io.regs.insert(
            at(b, 0x20bc),
            0x30000002 | (0x100 << if selected { s } else { (s + 1) % 4 }),
        );
        e.io.regs.insert(at(b, 0x20bb), 0x80002813);
        e.io.regs.insert(at(b, 0x20bd), 0x101);
        e.io.regs
            .insert(BASE + (0x179a + 3 * u64::from(b)) * 4, 0x430);
        e.io.regs
            .insert(BASE + (0x1b43 + 0x80 * u64::from(b)) * 4, 0x10001);
        e.io.regs
            .insert(BASE + (0x2931 + 0xd8 * u64::from(b)) * 4, 0x6f0);
    }
    Engine {
        io: Model {
            inner: e.io,
            stream: s,
            packet_stall: 0,
            db_stall: 0,
            attribute_stall: 0,
            packet_delay: 1,
            db_delay: 0,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    }
}

fn dcn401_hdmi_native_order_and_all_routes_preserve_live_timing_and_phys() -> TestResult {
    for s in 0..4 {
        for routes in 0u8..16 {
            let mut e = live(s, routes);
            let before = e.io.inner.regs.clone();
            let result = run(e.retire_hdmi_tmds_encoder(s)).unwrap();
            assert_eq!(
                result,
                HdmiTmdsRetired {
                    stream: s,
                    detached_backends: routes
                }
            );
            assert_eq!(e.status.state, State::HdmiTmdsRetired);
            assert_eq!(e.status.hdmi_tmds_retired, Some(result));
            let mut expected: Vec<_> = [
                0x20a5, 0x20a9, 0x20aa, 0x20ab, 0x20ac, 0x20a6, 0x20ad, 0x20ae, 0x20af,
            ]
            .into_iter()
            .map(|r| (at(s, r), 0))
            .collect();
            expected.extend([
                (at(s, 0x20b0), 0xffff0000),
                (at(s, 0x209e), 0x30100011),
                (at(s, 0x209b), 0x384),
                (at(s, 0x2095), 0x100),
                (at(s, 0x2094), 0x2c03),
                (at(s, 0x209b), 0x84),
            ]);
            for b in 0..4 {
                if routes & (1 << b) != 0 {
                    expected.push((at(b, 0x20bc), 0x30000002));
                }
            }
            assert_eq!(e.io.inner.writes, expected);
            for (reg, value) in before {
                if !expected.iter().any(|&(w, _)| w == reg) && reg != at(s, 0x20b1) {
                    assert_eq!(e.io.inner.regs[&reg], value);
                }
            }
            assert_eq!(e.status.retired, 0);
            assert!(e.status.planes_retired.is_none());
            assert_eq!(run(e.retire(0)), Err(Error::Busy));
            // A completed snapshot does not authorize a now DP-mode frontend.
            e.io.inner.regs.insert(at(s, 0x2094), 0);
            assert_eq!(run(e.retire_hdmi_tmds_encoder(s)), Err(Error::Unsupported));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hdmi",
    dcn401_hdmi_native_order_and_all_routes_preserve_live_timing_and_phys
);

fn dcn401_hdmi_preflight_rejects_wrong_modes_and_independent_producers() -> TestResult {
    for (reg, value, error) in [
        (0x2094, 0x10, Error::Unsupported),
        (0x2094, 0x12, Error::Unsupported),
        (0x2094, 0x2c33, Error::Busy),
        (0x2094, 0x3c13, Error::Busy),
        (0x2094, 0x6c13, Error::Busy),
        (0x2094, 3, Error::Busy),
        (0x2093, 4, Error::Unsupported),
        (0x2093, 0x100000, Error::Unsupported),
        (0x2095, 0, Error::Busy),
        (0x209b, 2, Error::Busy),
        (0x209b, 0x100000, Error::Busy),
        (0x2091, 0x10, Error::Busy),
        (0x2091, 0x1000, Error::Busy),
        (0x209d, 1, Error::Busy),
        (0x209e, 0x400, Error::Busy),
        (0x2122, 1, Error::Busy),
        (0x2122, 0x10000, Error::Busy),
        (0x20b1, 1, Error::Busy),
        (0x20b1, 0x100, Error::Busy),
        (0x20b1, 0x8000, Error::Busy),
        (0x20b0, 0x40000000, Error::Busy),
    ] {
        let mut e = live(2, 0xa);
        e.io.inner.regs.insert(at(2, reg), value);
        assert_eq!(run(e.retire_hdmi_tmds_encoder(2)), Err(error), "{reg:x}");
        assert!(e.io.inner.writes.is_empty());
        assert_eq!(e.status.state, State::Ready);
    }
    for bit in 0..30 {
        let mut e = live(2, 0xa);
        e.io.inner.regs.insert(at(2, 0x20a7), 1 << bit);
        assert_eq!(run(e.retire_hdmi_tmds_encoder(2)), Err(Error::Busy));
        assert!(e.io.inner.writes.is_empty());
    }
    for s in [4, 255] {
        let mut e = live(0, 1);
        assert_eq!(run(e.retire_hdmi_tmds_encoder(s)), Err(Error::Invalid));
        assert!(e.io.inner.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hdmi",
    dcn401_hdmi_preflight_rejects_wrong_modes_and_independent_producers
);

fn dcn401_hdmi_rejects_ambiguous_backend_routes_and_hpo_modes() -> TestResult {
    for s in 0..4 {
        for b in 0..4 {
            for (reg, value, error) in [
                (at(b, 0x20bc), (0x100 << s) | 1, Error::Unsupported),
                (
                    at(b, 0x20bc),
                    (0x100 << s) | (0x100 << ((s + 1) % 4)),
                    Error::Unsupported,
                ),
                (at(b, 0x20bc), (0x100 << s) | 0x1000, Error::Unsupported),
                (at(b, 0x20bb), 0x2810, Error::Unsupported),
                (at(b, 0x20bb), 0x2833, Error::Busy),
                (at(b, 0x20bb), 0x2853, Error::Busy),
                (
                    BASE + (0x179a + 3 * u64::from(b)) * 4,
                    1,
                    Error::Unsupported,
                ),
                (
                    BASE + (0x179a + 3 * u64::from(b)) * 4,
                    2,
                    Error::Unsupported,
                ),
            ] {
                let mut e = live(s, 1 << b);
                e.io.inner.regs.insert(reg, value);
                assert_eq!(run(e.retire_hdmi_tmds_encoder(s)), Err(error));
                assert!(e.io.inner.writes.is_empty());
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hdmi",
    dcn401_hdmi_rejects_ambiguous_backend_routes_and_hpo_modes
);

fn dcn401_hdmi_requires_every_packet_db_and_frontend_clock_acknowledgement() -> TestResult {
    for stage in 0..22 {
        let mut e = live(1, 0xa);
        let (reg, count) = if stage < 15 {
            e.io.packet_stall = 1 << (stage + 16);
            (0x20b0, 10)
        } else if stage < 17 {
            e.io.db_stall = if stage == 15 { 1 } else { 0x8000 };
            (0x20b1, 10)
        } else if stage < 19 {
            e.io.attribute_stall = if stage == 17 { 1 } else { 0x8000 };
            (0x20b1, 11)
        } else {
            e.io.inner.encoder_stall = 1 << 1;
            e.io.inner
                .regs
                .insert(at(1, 0x2094), 0x13 | (1 << [10, 11, 13][stage - 19]));
            (0x2094, 14)
        };
        let error = Error::Timeout(at(1, reg));
        assert_eq!(run(e.retire_hdmi_tmds_encoder(1)), Err(error));
        assert_eq!(e.io.inner.writes.len(), count);
        assert_eq!(e.status.state, State::Failed(error));
        assert!(e.status.hdmi_tmds_retired.is_none());
        assert_eq!(run(e.retire_hdmi_tmds_encoder(1)), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hdmi",
    dcn401_hdmi_requires_every_packet_db_and_frontend_clock_acknowledgement
);

fn dcn401_hdmi_cancellation_quarantines_packets_db_and_clock_transitions() -> TestResult {
    for stage in 0..4 {
        let mut e = live(2, 0xa);
        e.io.packet_delay = 0;
        e.io.inner.encoder_delay[2] = 0;
        match stage {
            0 => e.io.packet_stall = 0x10000,
            1 => e.io.db_stall = 1,
            2 => e.io.attribute_stall = 1,
            _ => e.io.inner.encoder_stall = 1 << 2,
        }
        {
            let mut f = core::pin::pin!(e.retire_hdmi_tmds_encoder(2));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.io.inner.writes.len(), [10, 10, 11, 14][stage]);
        assert_eq!(e.status.state, State::RetiringHdmiTmds(2));
        assert!(!e.status.state.reusable());
        assert!(e.status.hdmi_tmds_retired.is_none());
        assert_eq!(run(e.retire_hdmi_tmds_encoder(2)), Err(Error::Busy));
        assert_eq!(run(e.blank_dp_stream(DpStream::Dio(2))), Err(Error::Busy));
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
    "drivers/gpu/dcn401-hdmi",
    dcn401_hdmi_cancellation_quarantines_packets_db_and_clock_transitions
);

fn dcn401_hdmi_revocation_lost_writes_and_device_loss_block_reuse() -> TestResult {
    for n in 0..=17 {
        for error in [Error::DeviceGone, Error::Revoked] {
            let mut e = live(3, 0xa);
            if error == Error::DeviceGone {
                e.io.inner.gone = Some(n);
            } else if n == 0 {
                e.authority.revoke();
            } else {
                e.io.inner.revoke = Some((n, e.authority));
            }
            assert_eq!(run(e.retire_hdmi_tmds_encoder(3)), Err(error), "write {n}");
            assert_eq!(e.io.inner.writes.len(), n);
            assert!(e.status.hdmi_tmds_retired.is_none());
            if n != 0 {
                assert_eq!(e.status.state, State::Failed(error));
            }
        }
        if n != 0 {
            let mut e = live(3, 0xa);
            e.io.inner.reject = Some(n);
            assert!(
                matches!(run(e.retire_hdmi_tmds_encoder(3)), Err(Error::Readback(_))),
                "write {n}"
            );
            assert_eq!(e.io.inner.writes.len(), n);
            assert!(!e.status.state.reusable());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hdmi",
    dcn401_hdmi_revocation_lost_writes_and_device_loss_block_reuse
);

fn dcn401_hdmi_rechecks_routes_modes_packets_and_metadata_before_detach() -> TestResult {
    for after in [10, 11, 14, 17] {
        for (reg, value) in [
            (at(0, 0x20bc), 0),
            (at(1, 0x20bb), 0x2810),
            (at(1, 0x20bd), 0),
            (BASE + (0x179a + 3) * 4, 0x431),
            (at(2, 0x2093), 0),
            (at(2, 0x2094), 0),
            (at(2, 0x20a5), 1),
            (at(2, 0x20a6), 1),
            (at(2, 0x20af), 1),
            (at(2, 0x20a7), 1),
            (at(2, 0x2091), 0x10),
            (at(2, 0x209d), 1),
        ] {
            let mut e = live(2, 0xa);
            e.io.inner.after_write = Some((after, reg, value));
            assert!(
                run(e.retire_hdmi_tmds_encoder(2)).is_err(),
                "write {after} register {reg:x}"
            );
            assert_eq!(e.io.inner.writes.len(), after);
            assert!(!e.status.state.reusable());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hdmi",
    dcn401_hdmi_rechecks_routes_modes_packets_and_metadata_before_detach
);

fn dcn401_hdmi_repeated_retirement_rechecks_live_state_without_touching_phys() -> TestResult {
    for s in 0..4 {
        let mut e = live(s, 1 << s);
        run(e.retire_hdmi_tmds_encoder(s)).unwrap();
        let backend = e.io.inner.regs[&at(s, 0x20bb)];
        e.io.inner.writes.clear();
        e.io.inner.encoder_written = 0;
        assert_eq!(
            run(e.retire_hdmi_tmds_encoder(s))
                .unwrap()
                .detached_backends,
            0
        );
        assert_eq!(e.io.inner.regs[&at(s, 0x20bb)], backend);
        assert_eq!(e.io.inner.writes.len(), 15);
        e.io.inner.writes.clear();
        e.io.inner.regs.insert(at(s, 0x20a7), 1);
        assert_eq!(run(e.retire_hdmi_tmds_encoder(s)), Err(Error::Busy));
        assert!(e.io.inner.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hdmi",
    dcn401_hdmi_repeated_retirement_rechecks_live_state_without_touching_phys
);

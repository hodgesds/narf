use super::*;

fn frl(reg: u64) -> u64 {
    MPC_BASE + reg * 4
}
const SCHEDULE: [u64; 10] = [
    0x8e6, 0x8e9, 0x8ea, 0x8eb, 0x8ec, 0x8e7, 0x8ed, 0x8ee, 0x8ef, 0x8f0,
];
struct Model {
    inner: Fake,
    db_phase: u8,
    db_reads: u8,
    stall_db: u8,
    clock_reads: u8,
    clock_pending: bool,
    stall_clock: u32,
    immediate: bool,
    after_ack: Option<(u8, u64, u32)>,
}
impl Model {
    fn late(&mut self, phase: u8) {
        if let Some((p, at, v)) = self.after_ack {
            if p == phase {
                self.inner.regs.insert(at, v);
                self.after_ack = None;
            }
        }
    }
}
impl Io for Model {
    fn read(&mut self, at: u64) -> u32 {
        if at == frl(0x8f1) && self.db_phase != 0 && self.stall_db & self.db_phase == 0 {
            if self.db_reads != 0 {
                self.db_reads -= 1;
            } else {
                *self.inner.regs.entry(at).or_default() &= !0x8001;
                self.late(self.db_phase);
                self.db_phase = 0;
            }
        }
        if at == frl(0x8d3) && self.clock_pending {
            if self.clock_reads != 0 {
                self.clock_reads -= 1;
            } else {
                *self.inner.regs.entry(at).or_default() &= !0x1110;
                *self.inner.regs.entry(at).or_default() |= self.stall_clock;
                self.late(4);
                self.clock_pending = false;
            }
        }
        self.inner.read(at)
    }
    fn wait_poll_limit(&self) -> Option<u32> {
        self.inner.wait_poll_limit()
    }
    fn write(&mut self, at: u64, value: u32) {
        // Never write timing, link, PHY, AFMT/VPG, clock routing or metadata.
        assert!(
            SCHEDULE.iter().any(|&r| at == frl(r))
                || [0x8d6, 0x8df, 0x8d3].iter().any(|&r| at == frl(r))
        );
        if at == frl(0x8d3) {
            assert_eq!(self.inner.regs[&frl(0x8d6)] & 1, 0);
            assert_eq!(self.inner.regs[&frl(0x8df)] & 1, 0);
            assert_eq!(self.inner.regs[&frl(0x8f1)] & 0x8001, 0);
        }
        if at == frl(0x8d6) {
            assert_eq!(self.inner.regs[&frl(0x8f1)] & 0x8001, 0);
        }
        self.inner.write(at, value);
        if SCHEDULE.iter().any(|&r| at == frl(r)) || at == frl(0x8df) {
            self.db_phase = if at == frl(0x8df) { 2 } else { 1 };
            self.db_reads = if self.immediate { 0 } else { 2 };
            *self.inner.regs.entry(frl(0x8f1)).or_default() |= 0x8001;
        }
        if at == frl(0x8d3) && value & 1 == 0 {
            self.clock_pending = true;
            self.clock_reads = if self.immediate { 0 } else { 2 };
        }
    }
}
fn fixture(pipe: u8) -> Engine<Model> {
    let mut e = engine();
    for (r, v) in [
        (0x8d3, 0x80001111),
        (0x8d5, 0x100 | u32::from(pipe)),
        (0x8d6, 0x81011101), // upstream VIDEO_STREAM_ACTIVE may stay set
        (0x8df, 0x80000001),
        (0x8e2, 0x80010130), // inactive ACR configuration is retained
        (0x8e3, 0x01404043), // retained GC/AVMUTE, line/reference fields
        (0x8f1, 0x1100),
        (0x8ff, 0x10000110),
        (0x93c, 0x103),
        (0x95b, 0x80000001), // independent FRL link remains live
        (0x95c, 0x80000003),
        (0x965, 0x12345678),
    ] {
        e.io.regs.insert(frl(r), v);
    }
    e.io.regs
        .insert(BASE + 0x59 * 4, 0x100 | 8 | u32::from(pipe));
    for r in SCHEDULE {
        e.io.regs.insert(frl(r), 0x5a5aa5a5);
    }
    // Unrelated DIO and HPO outputs need not stop for this stream retirement.
    e.io.regs.insert(BASE + 0x2095 * 4, 1);
    e.io.regs.insert(BASE + 0x365d * 4, 1);
    Engine {
        io: Model {
            inner: e.io,
            db_phase: 0,
            db_reads: 0,
            stall_db: 0,
            clock_reads: 0,
            clock_pending: false,
            stall_clock: 0,
            immediate: false,
            after_ack: None,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    }
}

fn dcn401_frl_native_packet_fifo_tribyte_clock_order_preserves_other_owners() -> TestResult {
    for pipe in 0..4 {
        for db_disable in [0, 0x1000] {
            let mut e = fixture(pipe);
            e.io.inner.regs.insert(frl(0x8f1), 0x100 | db_disable);
            let before = e.io.inner.regs.clone();
            let result = run(e.retire_hdmi_frl_encoder()).unwrap();
            assert_eq!(
                result,
                FrlEncoderRetired {
                    pipe,
                    was_active: true
                }
            );
            assert_eq!(e.status.state, State::HdmiFrlRetired);
            assert_eq!(e.status.frl_encoder_retired, Some(result));
            let mut expected: Vec<_> = SCHEDULE.iter().map(|&r| (frl(r), 0)).collect();
            expected.extend([
                (frl(0x8d6), 0x81011100),
                (frl(0x8df), 0x80000000),
                (frl(0x8d3), 0x80001110),
            ]);
            assert_eq!(e.io.inner.writes, expected);
            assert_eq!(e.io.inner.regs[&frl(0x8d3)], 0x80000000);
            for (at, v) in before {
                if !expected.iter().any(|&(r, _)| r == at) {
                    assert_eq!(e.io.inner.regs[&at], v);
                }
            }
            e.io.inner.writes.clear();
            assert_eq!(
                run(e.retire_hdmi_frl_encoder()),
                Ok(FrlEncoderRetired {
                    pipe,
                    was_active: false
                })
            );
            assert!(e.io.inner.writes.is_empty());
            assert!(e.status.retired == 0 && e.status.planes_retired.is_none());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl",
    dcn401_frl_native_packet_fifo_tribyte_clock_order_preserves_other_owners
);

fn dcn401_frl_pending_audio_metadata_and_reset_work_rejects_before_writes() -> TestResult {
    for (reg, mask) in [
        (0x8d6, 0x100010u32),
        (0x8df, 0x110),
        (0x8e2, 0x1003),
        (0x8e3, 0x3130),
        (0x8e8, 0x3fffffff),
        (0x8f1, 0x8001),
        (0x8ff, 1),
        (0x93c, 0x1010),
    ] {
        for bit in (0..32).map(|i| 1 << i).filter(|v| mask & v != 0) {
            let mut e = fixture(1);
            *e.io.inner.regs.entry(frl(reg)).or_default() |= bit;
            assert_eq!(
                run(e.retire_hdmi_frl_encoder()),
                Err(Error::Busy),
                "{reg:x}/{bit:x}"
            );
            assert!(e.io.inner.writes.is_empty());
            assert_eq!(e.status.state, State::Ready);
        }
    }
    for (at, value) in [
        (frl(0x8d5), 4),
        (BASE + 0x59 * 4, 8 | 2),
        (BASE + 0x59 * 4, 1),
        (frl(0x8d3), 0),
        (frl(0x8d3), 0x1110),
        (frl(0x8d3), 1),
        (frl(0x8d3), 0x1011),
    ] {
        let mut e = fixture(1);
        e.io.inner.regs.insert(at, value);
        assert!(run(e.retire_hdmi_frl_encoder()).is_err(), "{at:x}");
        assert!(e.io.inner.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl",
    dcn401_frl_pending_audio_metadata_and_reset_work_rejects_before_writes
);

fn dcn401_frl_stopped_stream_never_wakes_or_replays_uncertain_work() -> TestResult {
    let mut e = fixture(3);
    for r in SCHEDULE.into_iter().chain([0x8d3, 0x8d6, 0x8df]) {
        e.io.inner.regs.insert(frl(r), 0);
    }
    assert_eq!(
        run(e.retire_hdmi_frl_encoder()),
        Ok(FrlEncoderRetired {
            pipe: 3,
            was_active: false
        })
    );
    assert!(e.io.inner.writes.is_empty());
    for (r, value) in [
        (0x8e6, 1),
        (0x8f0, 0x8000),
        (0x8d3, 0x10),
        (0x8df, 1),
        (0x8d6, 1),
    ] {
        e.io.inner.regs.insert(frl(r), value);
        assert!(run(e.retire_hdmi_frl_encoder()).is_err());
        assert!(e.io.inner.writes.is_empty());
        e.io.inner.regs.insert(frl(r), 0);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl",
    dcn401_frl_stopped_stream_never_wakes_or_replays_uncertain_work
);

fn dcn401_frl_requires_buffer_drain_and_each_clock_off_witness() -> TestResult {
    for (db, clock, count, at) in [
        (1, 0, 10, frl(0x8f1)),
        (2, 0, 12, frl(0x8f1)),
        (0, 0x10, 13, frl(0x8d3)),
        (0, 0x100, 13, frl(0x8d3)),
        (0, 0x1000, 13, frl(0x8d3)),
    ] {
        let mut e = fixture(0);
        e.io.stall_db = db;
        e.io.stall_clock = clock;
        let err = Error::Timeout(at);
        assert_eq!(run(e.retire_hdmi_frl_encoder()), Err(err));
        assert_eq!(e.status.state, State::Failed(err));
        assert_eq!(e.io.inner.writes.len(), count);
        assert!(e.status.frl_encoder_retired.is_none());
        assert_eq!(run(e.retire_hdmi_frl_encoder()), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl",
    dcn401_frl_requires_buffer_drain_and_each_clock_off_witness
);

fn dcn401_frl_cancelled_drains_and_clock_wait_keep_ownership() -> TestResult {
    for phase in [1, 2, 4] {
        let mut e = fixture(0);
        e.io.immediate = true;
        e.io.stall_db = phase & 3;
        if phase == 4 {
            e.io.stall_clock = 0x1110;
        }
        {
            let mut f = core::pin::pin!(e.retire_hdmi_frl_encoder());
            let mut cx = Context::from_waker(Waker::noop());
            assert!(f.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(
            e.io.inner.writes.len(),
            match phase {
                1 => 10,
                2 => 12,
                _ => 13,
            }
        );
        assert_eq!(e.status.state, State::RetiringHdmiFrl);
        assert_eq!(run(e.retire_hdmi_frl_encoder()), Err(Error::Busy));
        assert_eq!(run(e.retire_tmds_timing(0)), Err(Error::Busy));
        assert_eq!(run(e.retire_planes()), Err(Error::Busy));
        assert!(e.status.frl_encoder_retired.is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl",
    dcn401_frl_cancelled_drains_and_clock_wait_keep_ownership
);

fn dcn401_frl_write_loss_device_loss_and_revocation_are_terminal() -> TestResult {
    for n in 0..=13 {
        for revoke in [false, true] {
            let mut e = fixture(2);
            let err = if revoke {
                Error::Revoked
            } else {
                Error::DeviceGone
            };
            if !revoke {
                e.io.inner.gone = Some(n);
            } else if n == 0 {
                e.authority.revoke();
            } else {
                e.io.inner.revoke = Some((n, e.authority));
            }
            assert_eq!(run(e.retire_hdmi_frl_encoder()), Err(err));
            assert_eq!(e.io.inner.writes.len(), n);
            if n != 0 {
                assert_eq!(e.status.state, State::Failed(err));
            }
        }
        if n != 0 {
            let mut e = fixture(2);
            e.io.inner.reject = Some(n);
            assert!(matches!(
                run(e.retire_hdmi_frl_encoder()),
                Err(Error::Readback(_))
            ));
            assert_eq!(e.io.inner.writes.len(), n);
            assert!(!e.status.state.reusable());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl",
    dcn401_frl_write_loss_device_loss_and_revocation_are_terminal
);

fn dcn401_frl_late_routes_packets_and_consumers_never_publish_retirement() -> TestResult {
    for phase in [1, 2, 4] {
        for (at, value) in [
            (frl(0x8d5), 2),
            (BASE + 0x59 * 4, 0xa),
            (frl(0x8f1), 0x100), // unexpected DB-disable change
            (frl(0x8e7), 1),
            (frl(0x8e8), 1),
            (frl(0x8e3), 0x100),
            (frl(0x8ff), 1),
            (frl(0x93c), 0x10),
            (frl(0x8d6), 0x10),
            (frl(0x8df), 0x10),
        ] {
            let mut e = fixture(1);
            e.io.after_ack = Some((phase, at, value));
            assert!(run(e.retire_hdmi_frl_encoder()).is_err(), "{phase}/{at:x}");
            assert!(e.status.frl_encoder_retired.is_none());
            assert!(!e.status.state.reusable());
        }
    }
    for reg in [0x8d6, 0x8df, 0x8d3] {
        let mut e = fixture(1);
        e.io.after_ack = Some((4, frl(reg), 1));
        assert!(run(e.retire_hdmi_frl_encoder()).is_err());
        assert!(e.status.frl_encoder_retired.is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl",
    dcn401_frl_late_routes_packets_and_consumers_never_publish_retirement
);

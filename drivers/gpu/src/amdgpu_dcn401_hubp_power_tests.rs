use super::*;

const IP_REQUEST: u64 = BASE + 0xa0 * 4;
fn hubp(p: u8, r: u64) -> u64 {
    BASE + (r + u64::from(p) * 0xdc) * 4
}
fn pg(p: u8, status: bool) -> u64 {
    BASE + (0x80 + u64::from(p) * 2 + u64::from(status)) * 4
}
struct PowerIo {
    inner: Fake,
    pending: Option<(u8, bool)>,
    stall_power: bool,
    stall_drain: bool,
    stall_blank: bool,
    delay: u8,
    wake_dirty: Option<(u64, u32)>,
    pause_wait: bool,
}
impl Io for PowerIo {
    fn pause_wait(&self) -> bool {
        self.pause_wait
    }
    fn read(&mut self, at: u64) -> u32 {
        if let Some((p, powered)) = self.pending {
            if at == pg(p, true) && !self.stall_power {
                if self.delay != 0 {
                    self.delay -= 1;
                } else {
                    self.pending = None;
                    self.inner
                        .regs
                        .insert(at, if powered { 0 } else { 0x80000000 });
                    if powered {
                        self.inner.forbidden_hubps &= !(1 << p);
                        // An unconfigured HUBP, not a fabricated blank/drain
                        // witness. The driver must explicitly initialize it.
                        for r in 0x5f4..=0x68d {
                            self.inner.regs.insert(hubp(p, r), 0);
                        }
                        self.inner.regs.insert(hubp(p, 0x5f4), 0x1000);
                        self.inner.regs.insert(hubp(p, 0x5f7), 3);
                        self.inner.regs.insert(hubp(p, 0x614), 0x400);
                        if let Some((r, value)) = self.wake_dirty {
                            self.inner.regs.insert(hubp(p, r), value);
                        }
                    } else {
                        self.inner.forbidden_hubps |= 1 << p;
                    }
                }
            }
        }
        for p in 0..4 {
            if at == hubp(p, 0x5f4)
                && self.inner.forbidden_hubps & (1 << p) == 0
                && self.inner.regs.get(&hubp(p, 0x5f5)).copied().unwrap_or(0) & 1 != 0
                && !self.stall_drain
                && !(self.stall_blank && self.inner.regs.get(&at).copied().unwrap_or(0) & 1 != 0)
            {
                *self.inner.regs.entry(at).or_default() |= 2;
            }
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        for p in 0..4 {
            if at == pg(p, false) {
                assert_eq!(
                    self.inner.regs.get(&IP_REQUEST).copied().unwrap_or(0) & 1,
                    1
                );
                assert!(self.pending.is_none());
                if value & 0x100 != 0 {
                    assert_eq!(self.inner.regs[&hubp(p, 0x5f4)] & 7, 3);
                    assert_eq!(self.inner.regs[&hubp(p, 0x5f5)] & 1, 0);
                }
            }
        }
        if at == IP_REQUEST && value & 1 == 0 {
            assert!(
                self.pending.is_none(),
                "IP request dropped before PGFSM ack"
            );
        }
        self.inner.write(at, value);
        if self.inner.reject == Some(self.inner.writes.len()) {
            return;
        }
        for p in 0..4 {
            if at == pg(p, false) {
                self.pending = Some((p, value & 0x100 == 0));
                // Request readback must not masquerade as power acknowledgement.
                self.inner.regs.insert(pg(p, true), 0x40000000);
                self.inner.forbidden_hubps |= 1 << p;
            }
        }
    }
}
fn ready(off: u8) -> Engine<PowerIo> {
    let mut e = planes(off);
    run(e.retire_planes()).unwrap();
    e.io.writes.clear();
    e.io.stall = 512 | 1024; // preserve independently modelled idle/drain state
    Engine {
        io: PowerIo {
            inner: e.io,
            pending: None,
            stall_power: false,
            stall_drain: false,
            stall_blank: false,
            delay: 1,
            wake_dirty: None,
            pause_wait: false,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    }
}

fn dcn401_hubp_power_cycles_every_domain_without_accessing_gated_registers() -> TestResult {
    for off in 0..16 {
        for p in 0..4 {
            for ip in [0x80, 0x81] {
                let mut e = ready(off);
                e.io.inner.regs.insert(IP_REQUEST, ip);
                let unchanged = e.io.inner.regs.clone();
                for powered in [true, false, true, false] {
                    let applied = HubpPower { pipe: p, powered };
                    assert_eq!(run(e.set_hubp_power(p, powered)), Ok(applied));
                    assert_eq!(e.status.hubp_power[p as usize], Some(applied));
                    assert!(e.status.state.reusable());
                    assert_eq!(e.io.inner.regs[&IP_REQUEST], ip);
                    assert_eq!(e.io.inner.forbidden_hubps & (1 << p) == 0, powered);
                    if powered {
                        assert_eq!(e.io.inner.regs[&hubp(p, 0x5f4)] & 0x1007, 3);
                        assert_eq!(e.io.inner.regs[&hubp(p, 0x5f5)] & 1, 0);
                    }
                    // Repeating an acknowledged state is read-only.
                    let count = e.io.inner.writes.len();
                    assert_eq!(run(e.set_hubp_power(p, powered)), Ok(applied));
                    assert_eq!(e.io.inner.writes.len(), count);
                }
                for (at, value) in unchanged {
                    if at != IP_REQUEST
                        && at != pg(p, false)
                        && at != pg(p, true)
                        && !(hubp(p, 0x5f4)..=hubp(p, 0x68d)).contains(&at)
                    {
                        assert_eq!(e.io.inner.regs[&at], value);
                    }
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-fetch",
    dcn401_hubp_power_cycles_every_domain_without_accessing_gated_registers
);

fn dcn401_hubp_power_requires_fresh_disconnected_stopped_tree() -> TestResult {
    for p in 0..4 {
        for (at, value) in [
            (hubp(p, 0x5f4), 1), // requested blank without drain
            (hubp(p, 0x5f4), 2), // drained without blank
            (hubp(p, 0x5f4), 7), // soft reset
            (hubp(p, 0x5f5), 1),
            (hubp(p, 0x679), 1),
            (hubp(p, 0x613), 1),
            (hubp(p, 0x613), 0x100),
            (hubp(p, 0x613), 0x200),
            (hubp(p, 0x614), 0x100),
            (hubp(p, 0x685), 4),
            (hubp(p, 0x68a), 1),
            (hubp(p, 0x5f7), 0x10),
            (pg(p, false), 0x100),
            (pg(p, true), 0xc0000000),
            (MPC_BASE + (0x2f2 + u64::from(p) * 4) * 4, 0),
            (MPC_BASE + (5 + u64::from(p) * 0x15) * 4, 0x1f),
            (MPC_BASE + (0xe + u64::from(p) * 0x15) * 4, 3),
            (BASE + (0x1b8a + u64::from(p) * 0x80) * 4, 1),
        ] {
            for powered in [false, true] {
                let mut e = ready(0);
                e.io.inner.regs.insert(at, value);
                assert_eq!(
                    run(e.set_hubp_power((p + 1) % 4, powered)),
                    Err(Error::Busy)
                );
                assert!(e.io.inner.writes.is_empty());
                assert_eq!(e.status.state, State::PlanesRetired);
            }
        }
    }
    for (at, mask) in engine().layout.idle {
        let mut e = ready(0xf);
        e.io.inner.regs.insert(at, mask);
        assert_eq!(run(e.set_hubp_power(0, true)), Err(Error::Busy));
        assert!(e.io.inner.writes.is_empty());
    }
    let mut e = ready(0xf);
    assert_eq!(run(e.set_hubp_power(4, true)), Err(Error::Invalid));
    assert!(e.io.inner.writes.is_empty());
    // FORCEnON is cleared by the native full PG_CONFIG write on power-off.
    let mut e = ready(0);
    e.io.inner.regs.insert(pg(2, false), 1);
    run(e.set_hubp_power(2, false)).unwrap();
    assert_eq!(e.io.inner.regs[&pg(2, false)], 0x100);
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-fetch",
    dcn401_hubp_power_requires_fresh_disconnected_stopped_tree
);

fn dcn401_hubp_power_faults_quarantine_without_replay() -> TestResult {
    for powered in [false, true] {
        let count = if powered { 8 } else { 3 };
        for n in 1..=count {
            for revoke in [false, true] {
                let mut e = ready(if powered { 0xf } else { 0 });
                if revoke {
                    e.io.inner.revoke = Some((n, e.authority));
                } else {
                    e.io.inner.gone = Some(n);
                }
                let error = if revoke {
                    Error::Revoked
                } else {
                    Error::DeviceGone
                };
                assert_eq!(run(e.set_hubp_power(1, powered)), Err(error));
                assert_eq!(e.status.state, State::Failed(error));
                assert!(e.status.hubp_power[1].is_none());
                assert!(e.status.planes_retired.is_none());
                assert_eq!(run(e.set_hubp_power(1, powered)), Err(Error::Busy));
                assert_eq!(run(e.retire_planes()), Err(Error::Busy));
                assert_eq!(run(e.retire(0)), Err(Error::Busy));
                assert_eq!(e.io.inner.writes.len(), n);
            }
            if powered && n == 7 {
                continue;
            } // GSL already clear
            let mut e = ready(if powered { 0xf } else { 0 });
            e.io.inner.reject = Some(n);
            assert!(matches!(
                run(e.set_hubp_power(1, powered)),
                Err(Error::Readback(_))
            ));
            assert!(!e.status.state.reusable());
            assert_eq!(e.io.inner.writes.len(), n);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-fetch",
    dcn401_hubp_power_faults_quarantine_without_replay
);

fn dcn401_hubp_power_timeout_and_cancellation_retain_transition() -> TestResult {
    // Phase 0: PGFSM, 1: initial drain, 2: drain after asserting blank.
    for (powered, phase) in [(false, 0), (true, 0), (true, 1), (true, 2)] {
        for cancel in [false, true] {
            let mut e = ready(if powered { 0xf } else { 0 });
            e.io.delay = 0;
            e.io.stall_power = phase == 0;
            e.io.stall_drain = phase == 1;
            e.io.stall_blank = phase == 2;
            // Cancellation is an injected pending hardware acknowledgement,
            // not a race against a 1 us timer within the first poll.
            e.io.pause_wait = cancel;
            if phase == 2 {
                e.io.inner.stall |= 2048;
            }
            if cancel {
                {
                    let mut f = core::pin::pin!(e.set_hubp_power(3, powered));
                    assert!(f
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop()))
                        .is_pending());
                }
                assert_eq!(e.status.state, State::ChangingHubpPower(3));
            } else {
                let at = if phase == 0 {
                    pg(3, true)
                } else {
                    hubp(3, 0x5f4)
                };
                assert_eq!(run(e.set_hubp_power(3, powered)), Err(Error::Timeout(at)));
                assert_eq!(e.status.state, State::Failed(Error::Timeout(at)));
            }
            assert!(e.status.hubp_power[3].is_none());
            assert!(e.status.planes_retired.is_none());
            assert_eq!(e.io.inner.regs[&IP_REQUEST] & 1, u32::from(phase == 0));
            if phase != 0 {
                assert_eq!(e.io.inner.regs[&hubp(3, 0x5f5)] & 1, 1);
            }
            let count = e.io.inner.writes.len();
            assert_eq!(run(e.set_hubp_power(3, powered)), Err(Error::Busy));
            assert_eq!(
                run(e.prepare(request(0), clock(request(0)))),
                Err(Error::Busy)
            );
            assert_eq!(e.io.inner.writes.len(), count);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-fetch",
    dcn401_hubp_power_timeout_and_cancellation_retain_transition
);

fn dcn401_hubp_power_rechecks_wake_state_and_late_consumer_changes() -> TestResult {
    for (r, value) in [
        (0x679, 1),
        (0x685, 4),
        (0x68a, 1),
        (0x613, 0x100),
        (0x5f4, 4),
        (0x5f5, 1),
    ] {
        let mut e = ready(0xf);
        e.io.wake_dirty = Some((r, value));
        assert_eq!(run(e.set_hubp_power(0, true)), Err(Error::Busy));
        assert_eq!(e.io.inner.writes.len(), 3); // never enable fetch clock
        assert_eq!(e.status.state, State::Failed(Error::Busy));
    }
    for (at, value) in [
        (IP_REQUEST, 1),
        (pg(1, false), 0x101),
        (hubp(0, 0x68a), 1),
        (BASE + 0x20bd * 4, 1),
        (MPC_BASE + 5 * 4, 0x1f),
    ] {
        let mut e = ready(0xf);
        e.io.inner.after_write = Some((8, at, value));
        assert_eq!(run(e.set_hubp_power(0, true)), Err(Error::Busy));
        assert_eq!(e.status.state, State::Failed(Error::Busy));
        assert!(e.status.hubp_power[0].is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-fetch",
    dcn401_hubp_power_rechecks_wake_state_and_late_consumer_changes
);

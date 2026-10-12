use super::*;
use crate::amdgpu_dcn_inventory::{Connector, Path};

fn at(link: u8, r: u64) -> u64 {
    BASE + (r + u64::from(link) * 0xd4) * 4
}
fn mux(phy: u8) -> u64 {
    BASE + (0x179a + u64::from(phy) * 3) * 4
}
fn map(stream: u8) -> u64 {
    MPC_BASE + (0xe56 + u64::from(stream)) * 4
}
fn path(phy: u8) -> Path {
    Path {
        connector: Connector::DisplayPort,
        connector_instance: 1,
        transmitter: phy,
        aux: Some((phy + 2) % 4),
        hpd: (phy + 1) % 4 + 1,
        device_tag: 8,
    }
}
struct Model {
    inner: Fake,
    link: u8,
    pending_sat: bool,
    stopping: bool,
    stopping_clock: bool,
    stall: u8,
}
impl Io for Model {
    fn read(&mut self, addr: u64) -> u32 {
        if self.pending_sat && self.stall & 1 == 0 && addr == at(self.link, 0x36b5) {
            for row in 0..6 {
                let staged = self.inner.regs[&at(self.link, 0x36bf + row)] & 0x7f07;
                *self
                    .inner
                    .regs
                    .get_mut(&at(self.link, 0x36c5 + row))
                    .unwrap() = 0x40000000 | staged;
            }
            *self.inner.regs.get_mut(&addr).unwrap() &= !0x30000;
            self.pending_sat = false;
        }
        if self.stopping && self.stall & 2 == 0 && addr == at(self.link, 0x36b5) {
            *self.inner.regs.get_mut(&addr).unwrap() &= !0xc0001;
        }
        if self.stopping_clock && self.stall & 4 == 0 && addr == at(self.link, 0x369f) {
            *self.inner.regs.get_mut(&addr).unwrap() &= !0x10;
        }
        self.inner.read(addr)
    }
    fn write(&mut self, addr: u64, value: u32) {
        if addr == at(self.link, 0x36b4) {
            assert!(!self.pending_sat);
            for row in 0..6 {
                assert_eq!(self.inner.regs[&at(self.link, 0x36c5 + row)] & 0x7f00, 0);
            }
        }
        if addr == at(self.link, 0x369f) {
            assert_eq!(self.inner.regs[&at(self.link, 0x36b5)] & 0x1f1003, 0);
        }
        self.inner.write(addr, value);
        if self.inner.reject == Some(self.inner.writes.len()) {
            return;
        }
        if addr == at(self.link, 0x36b8) {
            assert_eq!(value & 3, 1);
            assert_eq!(self.inner.regs[&at(self.link, 0x36b4)] & 1, 1);
            assert_eq!(self.inner.regs[&at(self.link, 0x369f)] & 0x11, 0x11);
            for row in 0..6 {
                assert_eq!(self.inner.regs[&at(self.link, 0x36bf + row)] & 0x7f07, 0);
            }
            self.pending_sat = true;
            *self.inner.regs.get_mut(&addr).unwrap() &= !3; // self-clearing ACT
            *self.inner.regs.get_mut(&at(self.link, 0x36b5)).unwrap() |= 0x30000;
        }
        if addr == at(self.link, 0x36b4) && value & 1 == 0 {
            self.stopping = true;
        }
        if addr == at(self.link, 0x369f) && value & 1 == 0 {
            self.stopping_clock = true;
        }
    }
}
fn fixture(phy: u8, link: u8, streams: u8) -> Engine<Model> {
    let mut e = engine();
    e.io.regs
        .insert(e.layout.link_clock, (u32::from(phy) | 8) << (link * 4));
    for i in 0..4 {
        e.io.regs.insert(
            mux(i),
            if i == phy {
                0x1002 | u32::from(link) << 8
            } else {
                0x1000
            },
        );
        e.io.regs.insert(
            map(i),
            if streams & (1 << i) != 0 {
                u32::from(link)
            } else {
                u32::from((link + 1) % 4)
            },
        );
        // Unrelated streams deliberately remain active.
        if streams & (1 << i) == 0 {
            e.io.regs.insert(at(i, 0x3623), 0x11111);
            e.io.regs.insert(at(i, 0x3685), 0x101);
            e.io.regs.insert(at(i, 0x365d), 1);
        }
    }
    for row in 0..6u8 {
        let allocation = if row < 4 && streams & (1 << row) != 0 {
            u32::from(row) | (u32::from(row + 1) * 2) << 8
        } else {
            0
        };
        e.io.regs
            .insert(at(link, 0x36bf + u64::from(row)), 0x80000000 | allocation);
        e.io.regs
            .insert(at(link, 0x36c5 + u64::from(row)), 0x40000000 | allocation);
    }
    e.io.regs.insert(at(link, 0x36b4), 0x325);
    e.io.regs.insert(at(link, 0x36b5), 0x40021);
    e.io.regs.insert(at(link, 0x369f), 0x1011);
    e.io.regs.insert(at(link, 0x36b8), 0x100);
    Engine {
        io: Model {
            inner: e.io,
            link,
            pending_sat: false,
            stopping: false,
            stopping_clock: false,
            stall: 0,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
    }
}

fn dcn401_hpo_link_all_routes_and_stream_sets_drain_before_clock_stop() -> TestResult {
    for phy in 0..4 {
        for link in 0..4 {
            for streams in 0..16 {
                let mut e = fixture(phy, link, streams);
                let before = e.io.inner.regs.clone();
                let slots = (0..4)
                    .filter(|s| streams & (1 << s) != 0)
                    .map(|s| (s + 1) * 2)
                    .sum();
                let result = run(e.retire_hpo_link(path(phy))).unwrap();
                assert_eq!(
                    result,
                    HpoLinkRetired {
                        path: path(phy),
                        link,
                        streams,
                        removed_slots: slots
                    }
                );
                assert_eq!(e.status.state, State::HpoLinkRetired);
                assert_eq!(e.status.hpo_link_retired, Some(result));
                let mut golden = Vec::new();
                if slots != 0 {
                    for row in 0..6 {
                        golden.push((at(link, 0x36bf + row), 0x80000000));
                    }
                    golden.push((at(link, 0x36b8), 0x101));
                }
                golden.extend([(at(link, 0x36b4), 0x324), (at(link, 0x369f), 0x1010)]);
                assert_eq!(e.io.inner.writes, golden);
                for (addr, value) in before {
                    if ![0x369f, 0x36b4, 0x36b5, 0x36b8]
                        .iter()
                        .any(|r| addr == at(link, *r))
                        && !(at(link, 0x36bf)..=at(link, 0x36ca)).contains(&addr)
                    {
                        assert_eq!(e.io.inner.regs[&addr], value);
                    }
                }
                e.io.inner.writes.clear();
                let again = run(e.retire_hpo_link(path(phy))).unwrap();
                assert_eq!(again.removed_slots, 0);
                assert!(e.io.inner.writes.is_empty());
                // The retained PHY root clock still blocks clock/timing changes.
                assert!(e
                    .layout
                    .idle
                    .iter()
                    .any(|(a, m)| *a == e.layout.link_clock && e.io.inner.regs[a] & m != 0));
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hpo-link",
    dcn401_hpo_link_all_routes_and_stream_sets_drain_before_clock_stop
);

fn dcn401_hpo_link_preflight_refuses_ambiguous_routes_and_active_work() -> TestResult {
    let proto = fixture(2, 1, 4);
    let root = proto.layout.link_clock;
    for (addr, value) in [
        (mux(2), 0),
        (mux(2), 1),
        (mux(2), 0x402),
        (mux(3), 0x102),
        (map(2), 2),
        (at(2, 0x3623), 0x10000),
        (at(2, 0x365d), 1),
        (at(2, 0x3685), 0x100),
        (at(2, 0x367b), 1),
        (at(2, 0x365e), 1),
        (at(2, 0x3626), 1),
        (at(1, 0x36b4), 0x327),
        (at(1, 0x36b4), 0x305),
        (at(1, 0x36b5), 0x23),
        (at(1, 0x36b5), 0x10021),
        (at(1, 0x36b5), 0x1021),
        (at(1, 0x36b5), 0x100021),
        (at(1, 0x36b5), 0x11),
        (at(1, 0x36cb), 1),
        (at(1, 0x369f), 0x10),
        (root, 0),
        (root, 0x90),
        (at(1, 0x36c7), 0),
        (at(1, 0x36b5), u32::MAX),
    ] {
        let mut e = fixture(2, 1, 4);
        e.io.inner.regs.insert(addr, value);
        assert!(
            run(e.retire_hpo_link(path(2))).is_err(),
            "accepted {addr:x}={value:x}"
        );
        assert!(e.io.inner.writes.is_empty());
        assert_eq!(e.status.state, State::Ready);
    }
    for source in 4..8 {
        let mut e = fixture(2, 1, 4);
        for reg in [0x36c4, 0x36ca] {
            e.io.inner.regs.insert(at(1, reg), 0x100 | source);
        }
        assert_eq!(run(e.retire_hpo_link(path(2))), Err(Error::Unsupported));
        assert!(e.io.inner.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hpo-link",
    dcn401_hpo_link_preflight_refuses_ambiguous_routes_and_active_work
);

fn dcn401_hpo_link_pending_allocations_and_disable_witnesses_timeout() -> TestResult {
    for (stall, reg, writes) in [(1, 0x36c5, 7), (2, 0x36b5, 8), (4, 0x369f, 9)] {
        let mut e = fixture(2, 1, 4);
        e.io.stall = stall;
        assert_eq!(
            run(e.retire_hpo_link(path(2))),
            Err(Error::Timeout(at(1, reg)))
        );
        assert_eq!(e.io.inner.writes.len(), writes);
        assert!(e.status.hpo_link_retired.is_none());
        assert!(!e.status.state.reusable());
        assert_eq!(run(e.retire_hpo_link(path(2))), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hpo-link",
    dcn401_hpo_link_pending_allocations_and_disable_witnesses_timeout
);

fn dcn401_hpo_link_cancelled_sat_or_dphy_wait_quarantines_owner() -> TestResult {
    for stall in [1, 2] {
        let mut e = fixture(2, 1, 4);
        e.io.stall = stall;
        {
            let mut f = core::pin::pin!(e.retire_hpo_link(path(2)));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.status.state, State::RetiringHpoLink(1));
        assert_eq!(run(e.retire_hpo_link(path(2))), Err(Error::Busy));
        assert_eq!(run(e.retire_dp_encoder(DpStream::Hpo(2))), Err(Error::Busy));
        assert!(e.status.hpo_link_retired.is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hpo-link",
    dcn401_hpo_link_cancelled_sat_or_dphy_wait_quarantines_owner
);

fn dcn401_hpo_link_partial_writes_revocation_and_late_routes_fail_closed() -> TestResult {
    for n in 1..=9 {
        for fault in 0..3 {
            let mut e = fixture(2, 1, 15);
            match fault {
                0 => e.io.inner.reject = Some(n),
                1 => e.io.inner.revoke = Some((n, e.authority)),
                _ => e.io.inner.gone = Some(n),
            }
            // Rows 4/5 are zero already, so a dropped write there is harmless.
            let result = run(e.retire_hpo_link(path(2)));
            if fault == 0 && [5, 6].contains(&n) {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err(), "fault {fault} after write {n}");
                assert!(matches!(e.status.state, State::Failed(_)));
                assert_eq!(run(e.retire_hpo_link(path(2))), Err(Error::Busy));
            }
        }
    }
    for (addr, value) in [(mux(2), 0x202), (map(2), 3), (at(2, 0x3623), 1)] {
        let mut e = fixture(2, 1, 4);
        e.io.inner.after_write = Some((8, addr, value));
        assert!(run(e.retire_hpo_link(path(2))).is_err());
        assert_eq!(e.io.inner.writes.len(), 8);
        assert!(!e.status.state.reusable());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hpo-link",
    dcn401_hpo_link_partial_writes_revocation_and_late_routes_fail_closed
);

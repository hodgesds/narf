use super::*;
use crate::amdgpu_dcn_inventory::{Connector, Path};
#[path = "amdgpu_dcn401_frl_phy_tests.rs"]
mod phy;
#[path = "amdgpu_dcn401_frl_start_tests.rs"]
mod start;

fn frl(reg: u64) -> u64 {
    MPC_BASE + reg * 4
}
fn mux(phy: u8) -> u64 {
    BASE + (0x179a + u64::from(phy) * 3) * 4
}
fn dio(phy: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(phy) * 0x124) * 4
}
fn forced(phy: u8) -> u64 {
    BASE + (0x52 + u64::from(phy)) * 4
}
fn path(phy: u8) -> Path {
    Path {
        connector: Connector::HdmiTypeA,
        connector_instance: 1,
        transmitter: phy,
        aux: None,
        hpd: (phy + 1) % 4 + 1,
        device_tag: 1,
        max_speed_mhz: 0,
    }
}
struct Model {
    inner: Fake,
    clock_pending: bool,
    delay: u8,
    stalled: bool,
    after_clock: Option<(u64, u32)>,
}
impl Io for Model {
    fn read(&mut self, at: u64) -> u32 {
        if at == frl(0x95c) && self.clock_pending && !self.stalled {
            if self.delay != 0 {
                self.delay -= 1;
            } else {
                *self.inner.regs.entry(at).or_default() &= !2;
                self.clock_pending = false;
                if let Some((a, value)) = self.after_clock.take() {
                    self.inner.regs.insert(a, value);
                }
            }
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        assert!([0x965, 0x95b, 0x95c, 0x966].iter().any(|&r| at == frl(r)));
        if at == frl(0x95b) {
            assert_eq!(self.inner.regs[&frl(0x965)] & 0xffff0002, 2);
            assert_eq!(self.inner.regs[&frl(0x95c)] & 3, 3);
        }
        if at == frl(0x95c) {
            assert_eq!(self.inner.regs[&frl(0x95b)] & 0x11, 0);
        }
        if at == frl(0x966) {
            assert_eq!(self.inner.regs[&frl(0x95c)] & 3, 0);
        }
        self.inner.write(at, value);
        if at == frl(0x95c) && self.inner.reject != Some(self.inner.writes.len()) {
            self.clock_pending = true;
            // Keep CLOCK_ON through the posted-write readback. Explicit stalls
            // exercise async timeout/cancellation without depending on QEMU speed.
            self.delay = 1;
        }
    }
}
fn fixture(phy: u8, pipe: u8) -> Engine<Model> {
    let mut e = engine();
    for p in 0..4 {
        e.io.regs
            .insert(mux(p), 0x80000000 | if p == phy { 0x401 } else { 0x202 });
    }
    e.io.regs
        .insert(BASE + 0x4a * 4, 0x80000001 | u32::from(phy) << 4);
    e.io.regs.insert(forced(phy), 0x80000011);
    e.io.regs
        .insert(BASE + 0x59 * 4, 0x80000008 | u32::from(pipe));
    e.io.regs.insert(frl(0x8d5), 0x100 | u32::from(pipe));
    e.io.regs.insert(frl(0x8d6), 0x1000000); // independent upstream video indication
    e.io.regs.insert(frl(0x8f1), 0x1100);
    e.io.regs.insert(dio(phy, 0x20bb), 3);
    e.io.regs.insert(dio(phy, 0x20bc), 0x20000100);
    e.io.regs.insert(dio((phy + 1) % 4, 0x20bb), 0x2813);
    e.io.regs.insert(dio((phy + 1) % 4, 0x20bd), 1);
    e.io.regs
        .insert(BASE + (0x2943 + u64::from(phy) * 0xd8) * 4, 0x4c4c4c4c);
    e.io.regs
        .insert(BASE + (0x2931 + u64::from(phy) * 0xd8) * 4, 0x6f0);
    e.io.regs
        .insert(BASE + (0x1b43 + u64::from(pipe) * 0x80) * 4, 0x10001);
    e.io.regs.insert(frl(0x95b), 0x80000101);
    e.io.regs.insert(frl(0x95c), 0x80000103);
    e.io.regs.insert(frl(0x965), 0x76541001);
    e.io.regs.insert(frl(0x966), 0xea123b23);
    Engine {
        io: Model {
            inner: e.io,
            clock_pending: false,
            delay: 0,
            stalled: false,
            after_clock: None,
        },
        authority: e.authority,
        layout: e.layout,
        status: e.status,
        displays: e.displays,
    }
}

fn dcn401_frl_link_native_disable_preserves_phy_clocks_routes_and_other_outputs() -> TestResult {
    for phy in 0..4 {
        for pipe in 0..4 {
            for lanes in [3, 4] {
                for training in [0, 2] {
                    for rc in [0, 0x2000000] {
                        let mut e = fixture(phy, pipe);
                        let config = 0x76541000 | u32::from(lanes == 4) | training;
                        let config2 = 0xe8123b23 | rc;
                        e.io.inner.regs.insert(frl(0x965), config);
                        e.io.inner.regs.insert(frl(0x966), config2);
                        let before = e.io.inner.regs.clone();
                        let result = run(e.retire_frl_link(path(phy))).unwrap();
                        assert_eq!(
                            result,
                            FrlLinkRetired {
                                path: path(phy),
                                lanes,
                                was_enabled: true
                            }
                        );
                        assert_eq!(e.status.state, State::FrlLinkRetired);
                        assert_eq!(e.status.frl_link_retired, Some(result));
                        assert_eq!(
                            e.io.inner.writes,
                            [
                                (frl(0x965), (config & !0xffff0002) | 2),
                                (frl(0x95b), 0x80000100),
                                (frl(0x95c), 0x80000102),
                                (frl(0x966), config2 & !0x2000000),
                            ]
                        );
                        assert_eq!(e.io.inner.regs[&frl(0x95c)], 0x80000100);
                        for (at, value) in before {
                            if !e.io.inner.writes.iter().any(|&(r, _)| r == at) {
                                assert_eq!(e.io.inner.regs[&at], value);
                            }
                        }
                        assert!(e.status.frl_encoder_retired.is_none()); // live proof, not history
                        e.io.inner.writes.clear();
                        assert!(!run(e.retire_frl_link(path(phy))).unwrap().was_enabled);
                        assert!(e.io.inner.writes.is_empty());
                        assert!(e.status.planes_retired.is_none());
                    }
                }
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_link_native_disable_preserves_phy_clocks_routes_and_other_outputs
);

fn dcn401_frl_link_rejects_live_frontend_and_independent_work_before_writes() -> TestResult {
    for (reg, mask) in [
        (0x8d3, 0x1111u32),
        (0x8d6, 0x100011),
        (0x8df, 0x111),
        (0x8e2, 0x1003),
        (0x8e3, 0x3130),
        (0x8e8, 0x3fffffff),
        (0x8f1, 0x8001),
        (0x8ff, 1),
        (0x93c, 0x1010),
        (0x95b, 0x10),
        (0x966, 0x11000000),
    ] {
        for bit in (0..32).map(|i| 1 << i).filter(|v| mask & v != 0) {
            let mut e = fixture(1, 3);
            *e.io.inner.regs.entry(frl(reg)).or_default() |= bit;
            assert!(run(e.retire_frl_link(path(1))).is_err(), "{reg:x}/{bit:x}");
            assert!(e.io.inner.writes.is_empty());
            assert_eq!(e.status.state, State::Ready);
        }
    }
    for reg in [
        0x8e6, 0x8e7, 0x8e9, 0x8ea, 0x8eb, 0x8ec, 0x8ed, 0x8ee, 0x8ef, 0x8f0,
    ] {
        let mut e = fixture(1, 3);
        e.io.inner.regs.insert(frl(reg), 1);
        assert!(run(e.retire_frl_link(path(1))).is_err());
        assert!(e.io.inner.writes.is_empty());
    }
    for bit in [0x10, 0x20, 0x40, 0x800, 0x1000, 0x2000] {
        let mut e = fixture(0, 3);
        *e.io.inner.regs.entry(dio(0, 0x20bb)).or_default() |= bit;
        assert_eq!(run(e.retire_frl_link(path(0))), Err(Error::Busy));
        assert!(e.io.inner.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_link_rejects_live_frontend_and_independent_work_before_writes
);

fn dcn401_frl_link_rejects_ambiguous_phy_and_clock_routes() -> TestResult {
    for (at, value) in [
        (mux(2), 0),
        (mux(2), 2),
        (mux(2), 0x11),
        (mux(1), 0x301),
        (frl(0x8d5), 4),
        (BASE + 0x4a * 4, 0),
        (BASE + 0x4a * 4, 0x31),
        (forced(2), 0),
        (forced(2), 1),
        (forced(2), 0x21),
        (dio(2, 0x20bd), 1),
        (frl(0x95c), 0),
        (frl(0x95c), 1),
        (frl(0x95c), 2),
    ] {
        let mut e = fixture(2, 0);
        e.io.inner.regs.insert(at, value);
        assert!(run(e.retire_frl_link(path(2))).is_err(), "{at:x}/{value:x}");
        assert!(e.io.inner.writes.is_empty());
    }
    for config in [4, 0x80000, 0x800000, 0x8000000, 0x80000000] {
        let mut e = fixture(2, 0);
        *e.io.inner.regs.get_mut(&frl(0x965)).unwrap() |= config;
        assert_eq!(run(e.retire_frl_link(path(2))), Err(Error::Unsupported));
        assert!(e.io.inner.writes.is_empty());
    }
    for case in 0..4 {
        let mut e = fixture(2, 0);
        let mut p = path(2);
        match case {
            0 => p.transmitter = 4,
            1 => p.hpd = 0,
            2 => p.hpd = 5,
            _ => p.connector = Connector::DisplayPort,
        }
        assert!(run(e.retire_frl_link(p)).is_err());
        assert!(e.io.inner.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_link_rejects_ambiguous_phy_and_clock_routes
);

fn dcn401_frl_link_inherited_stopped_state_requires_complete_native_readback() -> TestResult {
    for parked in [false, true] {
        let mut e = fixture(3, 1);
        e.io.inner.regs.insert(frl(0x95b), 0);
        e.io.inner.regs.insert(frl(0x95c), 0);
        e.io.inner.regs.insert(frl(0x965), 3);
        e.io.inner.regs.insert(frl(0x966), 0);
        if parked {
            e.io.inner.regs.insert(BASE + 0x4a * 4, 0);
            e.io.inner.regs.insert(forced(3), 0);
        }
        assert!(!run(e.retire_frl_link(path(3))).unwrap().was_enabled);
        assert!(e.io.inner.writes.is_empty());
        for (reg, value, old) in [
            (0x95b, 1, 0),
            (0x95c, 3, 0),
            (0x965, 1, 3),
            (0x965, 0x10003, 3),
            (0x966, 0x2000000, 0),
        ] {
            e.io.inner.regs.insert(frl(reg), value);
            assert!(run(e.retire_frl_link(path(3))).is_err());
            assert!(e.io.inner.writes.is_empty());
            e.io.inner.regs.insert(frl(reg), old);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_link_inherited_stopped_state_requires_complete_native_readback
);

fn dcn401_frl_link_timeout_and_cancel_preserve_uncertain_owners() -> TestResult {
    for cancel in [false, true] {
        let mut e = fixture(1, 2);
        e.io.stalled = true;
        if cancel {
            let mut f = core::pin::pin!(e.retire_frl_link(path(1)));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        } else {
            assert_eq!(
                run(e.retire_frl_link(path(1))),
                Err(Error::Timeout(frl(0x95c)))
            );
        }
        assert_eq!(
            e.status.state,
            if cancel {
                State::RetiringFrlLink(1)
            } else {
                State::Failed(Error::Timeout(frl(0x95c)))
            }
        );
        assert_eq!(e.io.inner.writes.len(), 3);
        assert!(e.status.frl_link_retired.is_none());
        assert_eq!(e.io.inner.regs[&frl(0x966)] & 0x2000000, 0x2000000);
        assert_eq!(run(e.retire_frl_link(path(1))), Err(Error::Busy));
        assert_eq!(run(e.retire_hdmi_frl_encoder()), Err(Error::Busy));
        assert_eq!(run(e.retire_planes()), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_link_timeout_and_cancel_preserve_uncertain_owners
);

fn dcn401_frl_link_lost_writes_device_loss_and_revocation_never_publish() -> TestResult {
    for n in 0..=4 {
        for revoke in [false, true] {
            let mut e = fixture(2, 1);
            let error = if revoke {
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
            assert_eq!(run(e.retire_frl_link(path(2))), Err(error), "{n}/{revoke}");
            assert_eq!(e.io.inner.writes.len(), n);
            if n != 0 {
                assert_eq!(e.status.state, State::Failed(error));
            }
        }
        if n != 0 {
            let mut e = fixture(2, 1);
            e.io.inner.reject = Some(n);
            assert!(matches!(
                run(e.retire_frl_link(path(2))),
                Err(Error::Readback(_))
            ));
            assert_eq!(e.io.inner.writes.len(), n);
            assert!(e.status.frl_link_retired.is_none());
            assert!(!e.status.state.reusable());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_link_lost_writes_device_loss_and_revocation_never_publish
);

fn dcn401_frl_link_rechecks_routes_and_producers_before_cleanup_and_completion() -> TestResult {
    for (at, value) in [
        (mux(2), 0x501),
        (mux(1), 1),
        (BASE + 0x4a * 4, 0x11),
        (forced(2), 0),
        (BASE + 0x59 * 4, 0xb),
        (frl(0x8d5), 3),
        (frl(0x8d3), 1),
        (frl(0x8d6), 1),
        (frl(0x8df), 1),
        (frl(0x8e6), 1),
        (frl(0x8e8), 2),
        (frl(0x93c), 0x10),
        (frl(0x8f1), 0x100),
        (dio(2, 0x20bd), 1),
        (dio(2, 0x20bc), 0),
        (frl(0x965), 0x1001), // lane count preserved; training enable cleared
        (frl(0x966), 0xfb123b23),
    ] {
        for phase in [1, 2, 3, 4] {
            let mut e = fixture(2, 1);
            if phase == 3 {
                e.io.after_clock = Some((at, value));
            } else {
                e.io.inner.after_write = Some((phase, at, value));
            }
            assert!(run(e.retire_frl_link(path(2))).is_err(), "{at:x}/{phase}");
            assert!(e.status.frl_link_retired.is_none());
            assert!(!e.status.state.reusable());
            assert_eq!(e.io.inner.writes.len(), phase);
        }
    }
    for (at, value) in [(frl(0x95b), 1), (frl(0x95b), 0x10), (frl(0x95c), 3)] {
        let mut e = fixture(2, 1);
        e.io.after_clock = Some((at, value));
        assert!(run(e.retire_frl_link(path(2))).is_err());
        assert_eq!(e.io.inner.writes.len(), 3);
        assert!(e.status.frl_link_retired.is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-link",
    dcn401_frl_link_rechecks_routes_and_producers_before_cleanup_and_completion
);

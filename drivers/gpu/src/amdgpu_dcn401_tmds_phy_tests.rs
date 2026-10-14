use super::*;
use crate::{
    amdgpu_dcn_inventory::{Connector, Path},
    amdgpu_dmub_navi48 as dmub,
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

fn dio(p: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(p) * 0x124) * 4
}
fn phy(p: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(p) * 0xd8) * 4
}
fn root(p: u8) -> u64 {
    (0x162a0 + u64::from(p)) * 4
}
fn path(p: u8) -> Path {
    Path {
        connector: Connector::HdmiTypeA,
        connector_instance: 1,
        transmitter: p,
        aux: None,
        hpd: (p + 1) % 4 + 1,
        device_tag: 1,
    }
}
struct Firmware {
    ready: bool,
    commands: Vec<Path>,
    pending: bool,
    error: Option<dmub::Error>,
    revoke: Option<Cap<BusDeviceCap, Write>>,
    completed: Arc<AtomicBool>,
}
impl crate::amdgpu_dcn401_otg::tmds_phy::Firmware for Firmware {
    fn ready(&self) -> bool {
        self.ready
    }
    async fn disable(&mut self, path: Path) -> Result<(), dmub::Error> {
        self.commands.push(path);
        if self.pending {
            core::future::pending::<()>().await;
        }
        if let Some(error) = self.error {
            return Err(error);
        }
        if let Some(cap) = self.revoke {
            cap.revoke();
        }
        self.completed.store(true, Ordering::SeqCst);
        Ok(())
    }
}
struct Model {
    inner: Fake,
    phy: u8,
    completed: Arc<AtomicBool>,
    armed: bool,
    stage: usize,
    after: [u32; 4],
    late: Option<(u64, u32)>,
}
impl Io for Model {
    fn read(&mut self, at: u64) -> u32 {
        if self.completed.swap(false, Ordering::SeqCst) {
            self.armed = true;
            if let Some((a, v)) = self.late.take() {
                self.inner.regs.insert(a, v);
            }
        }
        let regs = [
            dio(self.phy, 0x20bd),
            dio(self.phy, 0x20bb),
            phy(self.phy, 0x2943),
            phy(self.phy, 0x2931),
        ];
        if self.armed && self.stage < 4 && at == regs[self.stage] {
            self.inner.regs.insert(at, self.after[self.stage]);
            self.stage += 1;
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        // The only host writes are frontend symclk routing. No backend or
        // firmware-owned RDPCS register may fabricate a completion witness.
        assert!((0..4).any(|p| at == root(p)));
        assert!(!self.armed);
        self.inner.write(at, value);
    }
}
fn fixture(p: u8, routes: u8) -> (Engine<Model>, Firmware) {
    let mut e = engine();
    for i in 0..4 {
        e.io.regs.insert(dio(i, 0x2094), 3);
        e.io.regs.insert(dio(i, 0x20bb), 0x80002813);
        e.io.regs.insert(dio(i, 0x20bd), 0x101);
        e.io.regs
            .insert(dio(i, 0x20bc), u32::from(path(i).hpd - 1) << 28 | 2);
        e.io.regs
            .insert(BASE + (0x179a + 3 * u64::from(i)) * 4, 0x430);
        e.io.regs.insert(phy(i, 0x2943), 0x4c4c4c4c);
        e.io.regs.insert(phy(i, 0x2931), 0x16f1);
        let source = if routes & (1 << i) != 0 {
            p
        } else {
            (p + 1) % 4
        };
        e.io.regs
            .insert(root(i), 0x80000011 | u32::from(source) << 8);
    }
    let completed = Arc::new(AtomicBool::new(false));
    let fw = Firmware {
        ready: true,
        commands: Vec::new(),
        pending: false,
        error: None,
        revoke: None,
        completed: completed.clone(),
    };
    (
        Engine {
            io: Model {
                inner: e.io,
                phy: p,
                completed,
                armed: false,
                stage: 0,
                after: [0x100, 0x80000003, 0x43434343, 0x1001],
                late: None,
            },
            authority: e.authority,
            layout: e.layout,
            status: e.status,
            displays: e.displays,
        },
        fw,
    )
}

fn dcn401_tmds_phy_parks_only_actual_routes_and_preserves_other_outputs() -> TestResult {
    for p in 0..4 {
        for routes in 0u8..16 {
            for mode in [0, 3] {
                let (mut e, mut fw) = fixture(p, routes);
                e.io.after[1] = 0x80000000 | mode;
                let before = e.io.inner.regs.clone();
                let result = run(e.disable_tmds(&mut fw, path(p))).unwrap();
                assert_eq!(
                    result,
                    TmdsDisabled {
                        path: path(p),
                        parked_frontends: routes,
                        command_sent: true
                    }
                );
                assert_eq!(fw.commands, [path(p)]);
                assert_eq!(e.status.state, State::TmdsDisabled);
                assert_eq!(e.status.tmds_disabled, Some(result));
                assert_eq!(e.io.stage, 4);
                let expected: Vec<_> = (0..4)
                    .filter(|i| routes & (1 << i) != 0)
                    .map(|i| (root(i), 0x80000001))
                    .collect();
                assert_eq!(e.io.inner.writes, expected);
                for (at, value) in before {
                    if !expected.iter().any(|&(r, _)| r == at)
                        && ![
                            dio(p, 0x20bd),
                            dio(p, 0x20bb),
                            phy(p, 0x2943),
                            phy(p, 0x2931),
                        ]
                        .contains(&at)
                    {
                        assert_eq!(e.io.inner.regs[&at], value);
                    }
                }
                e.io.inner.writes.clear();
                e.io.armed = false;
                let again = run(e.disable_tmds(&mut fw, path(p))).unwrap();
                assert!(!again.command_sent);
                assert_eq!(again.parked_frontends, 0);
                assert!(e.io.inner.writes.is_empty());
                assert_eq!(fw.commands.len(), 1);
                assert!(e.status.tmds_timing_retired.is_none()); // no historical proof required
                assert!(e.status.planes_retired.is_none());
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-tmds-phy",
    dcn401_tmds_phy_parks_only_actual_routes_and_preserves_other_outputs
);

fn dcn401_tmds_phy_rejects_all_timing_clock_users_and_pending_transactions() -> TestResult {
    for p in 0..4 {
        for (reg, mask) in [
            (BASE + (0x1b43 + 0x80 * p) * 4, 0x10001u32),
            (BASE + (0x1b84 + 0x80 * p) * 4, 0x10113),
            (BASE + (0x1b89 + 0x80 * p) * 4, 0x101),
            (BASE + (0x1ad0 + 0x10 * p) * 4, 7),
            (BASE + (0x1aca + 0x10 * p) * 4, 0x80000001),
            (BASE + (0x530 + p) * 4, 0x80000000),
            (dio(p as u8, 0x2094), 0x7c30),
            (dio(p as u8, 0x2095), 1),
            (dio(p as u8, 0x209b), 1),
            (dio(p as u8, 0x2091), 0x1010),
            (dio(p as u8, 0x209d), 1),
            (dio(p as u8, 0x20a7), 0x3fffffff),
            (0x16265 * 4, 0x8888),
            (0x16266 * 4, 0x8888),
        ] {
            for bit in (0..32).map(|n| 1 << n).filter(|bit| bit & mask != 0) {
                let (mut e, mut fw) = fixture(2, 0xf);
                let old = e.io.inner.regs.get(&reg).copied().unwrap_or(0);
                e.io.inner.regs.insert(reg, old | bit);
                assert!(
                    run(e.disable_tmds(&mut fw, path(2))).is_err(),
                    "{reg:x}/{bit:x}"
                );
                assert!(e.io.inner.writes.is_empty());
                assert!(fw.commands.is_empty());
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-tmds-phy",
    dcn401_tmds_phy_rejects_all_timing_clock_users_and_pending_transactions
);

fn dcn401_tmds_phy_rejects_wrong_board_routes_modes_and_inherited_partial_shutdown() -> TestResult {
    for (reg, value) in [
        (dio(2, 0x20bc), 0),
        (dio(2, 0x20bc), 0x30000100),
        (dio(2, 0x20bb), 0x2810),
        (dio(2, 0x20bb), 0x2833),
        (dio(2, 0x20bb), 0x2853),
        (dio(2, 0x20bd), 0),
        (BASE + (0x179a + 6) * 4, 1),
        (BASE + (0x179a + 6) * 4, 2),
        (BASE + 0x54 * 4, 1),
        (phy(2, 0x2943), 0x10),
        (phy(2, 0x2943), 0x20000000),
        (root(1), 0x710),
    ] {
        let (mut e, mut fw) = fixture(2, 0xf);
        e.io.inner.regs.insert(reg, value);
        assert!(run(e.disable_tmds(&mut fw, path(2))).is_err(), "{reg:x}");
        assert!(e.io.inner.writes.is_empty());
        assert!(fw.commands.is_empty());
    }
    for case in 0..5 {
        let (mut e, mut fw) = fixture(2, 0xf);
        let mut path = path(2);
        match case {
            0 => path.transmitter = 4,
            1 => path.hpd = 0,
            2 => path.hpd = 5,
            3 => path.connector = Connector::DisplayPort,
            _ => fw.ready = false,
        }
        assert!(run(e.disable_tmds(&mut fw, path)).is_err());
        assert!(e.io.inner.writes.is_empty());
        assert!(fw.commands.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-tmds-phy",
    dcn401_tmds_phy_rejects_wrong_board_routes_modes_and_inherited_partial_shutdown
);

fn dcn401_tmds_phy_requires_backend_lane_and_tx_clock_hardware_completion() -> TestResult {
    let mut cases = vec![(0, 0x101, dio(1, 0x20bd))];
    for bit in [0x10, 0x20, 0x40, 0x800, 0x2000] {
        cases.push((1, bit | 3, dio(1, 0x20bb)));
    }
    for lane in 0..4 {
        for bit in [2, 4, 8, 16, 32] {
            cases.push((
                2,
                if bit == 2 {
                    0x2020202 & !(2 << (lane * 8))
                } else {
                    0x2020202 | (bit << (lane * 8))
                },
                phy(1, 0x2943),
            ));
        }
    }
    for bit in [0x10, 0x20, 0x40, 0x80, 0x200, 0x400] {
        cases.push((3, bit, phy(1, 0x2931)));
    }
    for (stage, value, at) in cases {
        let (mut e, mut fw) = fixture(1, 0xa);
        e.io.after[stage] = value;
        let error = Error::Timeout(at);
        assert_eq!(run(e.disable_tmds(&mut fw, path(1))), Err(error));
        assert_eq!(e.status.state, State::Failed(error));
        assert!(e.status.tmds_disabled.is_none());
        assert_eq!(e.io.inner.writes.len(), 2);
        assert_eq!(run(e.disable_tmds(&mut fw, path(1))), Err(Error::Busy));
        assert_eq!(fw.commands.len(), 1);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-tmds-phy",
    dcn401_tmds_phy_requires_backend_lane_and_tx_clock_hardware_completion
);

fn dcn401_tmds_phy_cancelled_firmware_and_hardware_waits_never_release_ownership() -> TestResult {
    for stage in 0..5 {
        let (mut e, mut fw) = fixture(1, 0xa);
        if stage == 0 {
            fw.pending = true;
        } else {
            e.io.after[stage - 1] = [1, 0x2813, 0x4c4c4c4c, 0x6f0][stage - 1];
        }
        {
            let mut f = core::pin::pin!(e.disable_tmds(&mut fw, path(1)));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.status.state, State::DisablingTmds(1));
        assert!(e.status.tmds_disabled.is_none());
        assert_eq!(run(e.disable_tmds(&mut fw, path(1))), Err(Error::Busy));
        assert_eq!(run(e.retire_tmds_timing(0)), Err(Error::Busy));
        assert_eq!(run(e.retire_hdmi_tmds_encoder(0)), Err(Error::Busy));
        assert_eq!(run(e.retire_planes()), Err(Error::Busy));
        assert_eq!(fw.commands.len(), 1);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-tmds-phy",
    dcn401_tmds_phy_cancelled_firmware_and_hardware_waits_never_release_ownership
);

fn dcn401_tmds_phy_route_write_faults_and_firmware_failures_are_terminal() -> TestResult {
    for n in 0..=4 {
        for error in [Error::DeviceGone, Error::Revoked] {
            let (mut e, mut fw) = fixture(3, 0xf);
            if error == Error::DeviceGone {
                e.io.inner.gone = Some(n);
            } else if n == 0 {
                e.authority.revoke();
            } else {
                e.io.inner.revoke = Some((n, e.authority));
            }
            assert_eq!(run(e.disable_tmds(&mut fw, path(3))), Err(error));
            assert_eq!(e.io.inner.writes.len(), n);
            assert!(fw.commands.is_empty());
            if n != 0 {
                assert_eq!(e.status.state, State::Failed(error));
            }
        }
        if n != 0 {
            let (mut e, mut fw) = fixture(3, 0xf);
            e.io.inner.reject = Some(n);
            assert!(matches!(
                run(e.disable_tmds(&mut fw, path(3))),
                Err(Error::Readback(_))
            ));
            assert_eq!(e.io.inner.writes.len(), n);
            assert!(fw.commands.is_empty());
        }
    }
    for revoke in [false, true] {
        let (mut e, mut fw) = fixture(3, 0xf);
        let error = if revoke {
            fw.revoke = Some(e.authority);
            Error::Revoked
        } else {
            fw.error = Some(dmub::Error::CommandTimeout);
            Error::Firmware(dmub::Error::CommandTimeout)
        };
        assert_eq!(run(e.disable_tmds(&mut fw, path(3))), Err(error));
        assert_eq!(e.status.state, State::Failed(error));
        assert_eq!(fw.commands.len(), 1);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-tmds-phy",
    dcn401_tmds_phy_route_write_faults_and_firmware_failures_are_terminal
);

fn dcn401_tmds_phy_rechecks_routes_consumers_and_other_outputs_across_firmware() -> TestResult {
    for (at, value) in [
        (root(0), 0x210),
        (dio(2, 0x2095), 1),
        (dio(2, 0x20a7), 1),
        (BASE + 0x1b43 * 4, 1),
        (BASE + 0x1b84 * 4, 0x100),
        (BASE + 0x1ad0 * 4, 4),
        (dio(0, 0x20bd), 0),
        (dio(2, 0x20bc), 0),
        (BASE + (0x179a + 6) * 4, 0x330),
        (BASE + 0x54 * 4, 1),
    ] {
        for firmware in [false, true] {
            let (mut e, mut fw) = fixture(2, 0xf);
            if firmware {
                e.io.late = Some((at, value));
            } else {
                e.io.inner.after_write = Some((4, at, value));
            }
            assert!(
                run(e.disable_tmds(&mut fw, path(2))).is_err(),
                "{at:x}/{firmware}"
            );
            assert_eq!(fw.commands.len(), usize::from(firmware));
            assert!(!e.status.state.reusable());
            assert!(e.status.tmds_disabled.is_none());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-tmds-phy",
    dcn401_tmds_phy_rechecks_routes_consumers_and_other_outputs_across_firmware
);

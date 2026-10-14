use super::*;
use crate::{
    amdgpu_dcn_inventory as inventory, amdgpu_dmub_navi48 as dmub, dp_link_training::LinkRate,
};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, Ordering};
#[path = "amdgpu_dcn401_dp_training_tests.rs"]
mod training;

fn dio(p: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(p) * 0x124) * 4
}
fn phy(p: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(p) * 0xd8) * 4
}
fn path(p: u8) -> inventory::Path {
    inventory::Path {
        connector: inventory::Connector::DisplayPort,
        connector_instance: 1,
        transmitter: p,
        aux: Some((p + 2) % 4),
        hpd: (p + 1) % 4 + 1,
        device_tag: 8,
        max_speed_mhz: 0,
    }
}
fn settings(lanes: u8) -> DpPhySettings {
    DpPhySettings {
        lanes,
        rate: LinkRate::Hbr2,
    }
}
struct Firmware {
    completed: Arc<AtomicU8>,
    commands: Vec<(inventory::Path, Option<DpPhySettings>)>,
    ready: bool,
    pending: bool,
    error: Option<dmub::Error>,
    revoke: Option<Cap<BusDeviceCap, Write>>,
}
impl Firmware {
    async fn command(
        &mut self,
        path: inventory::Path,
        settings: Option<DpPhySettings>,
    ) -> Result<(), dmub::Error> {
        self.commands.push((path, settings));
        if self.pending {
            core::future::pending::<()>().await;
        }
        if let Some(e) = self.error {
            return Err(e);
        }
        if let Some(cap) = self.revoke {
            cap.revoke();
        }
        self.completed
            .store(if settings.is_some() { 1 } else { 2 }, Ordering::SeqCst);
        Ok(())
    }
}
impl super::super::dp_phy::Firmware for Firmware {
    fn ready(&self) -> bool {
        self.ready
    }
    async fn enable(
        &mut self,
        path: inventory::Path,
        settings: DpPhySettings,
    ) -> Result<(), dmub::Error> {
        self.command(path, Some(settings)).await
    }
    async fn disable(&mut self, path: inventory::Path) -> Result<(), dmub::Error> {
        self.command(path, None).await
    }
}
struct PhyIo {
    inner: Fake,
    completed: Arc<AtomicU8>,
    phy: u8,
    lanes: u8,
    stall: u8,
    transition: u8,
    delay: u8,
    done: bool,
    change: Option<(u64, u32)>,
    late: Option<(u64, usize, u64, u32)>,
}
impl Io for PhyIo {
    fn read(&mut self, at: u64) -> u32 {
        let event = self.completed.swap(0, Ordering::SeqCst);
        let p = self.phy;
        if event != 0 {
            self.transition = event;
            self.done = false;
            // Host setup must precede the firmware command. Firmware alone
            // supplies the independent RDPCS and backend clock-on witnesses.
            assert_eq!(self.inner.regs[&dio(p, 0x20bd)] & 1, 1);
            assert_eq!(self.inner.regs[&dio(p, 0x20bb)] & 0x77, 0x10);
            assert_eq!(
                self.inner.regs[&dio(p, 0x20bc)] & 0x70007f01,
                u32::from(path(p).hpd - 1) << 28
            );
        }
        if self.transition != 0 && !self.done {
            if self.delay != 0 {
                self.delay -= 1;
            } else {
                self.done = true;
                let enabled = self.transition == 1;
                if self.stall & 1 == 0 {
                    self.inner.regs.insert(dio(p, 0x20bd), u32::from(enabled));
                } else if enabled {
                    self.inner.regs.insert(dio(p, 0x20bd), 0);
                }
                if self.stall & 2 == 0 {
                    self.inner
                        .regs
                        .insert(dio(p, 0x20bb), if enabled { 0x810 } else { 0 });
                }
                if self.stall & 4 == 0 {
                    let mut lanes = 0;
                    for n in 0..4 {
                        lanes |= (if enabled && self.lanes & (1 << n) != 0 {
                            0xc
                        } else {
                            3
                        }) << (8 * n);
                    }
                    self.inner.regs.insert(phy(p, 0x2943), lanes);
                }
                if self.stall & 8 == 0 {
                    self.inner.regs.insert(
                        phy(p, 0x2931),
                        if enabled {
                            0x600 | u32::from(self.lanes) << 4
                        } else {
                            0
                        },
                    );
                }
                if let Some((r, v)) = self.change.take() {
                    self.inner.regs.insert(r, v);
                }
            }
        }
        if self.done {
            if let Some((trigger, count, target, value)) = self.late.as_mut() {
                if at == *trigger {
                    *count -= 1;
                    if *count == 0 {
                        self.inner.regs.insert(*target, *value);
                        self.late = None;
                    }
                }
            }
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        // No host writes to RDPCS lane status or TX clock witnesses.
        assert_ne!(at, phy(self.phy, 0x2943));
        assert_ne!(at, phy(self.phy, 0x2931));
        self.inner.write(at, value);
    }
}
fn fixture(p: u8, lanes: u8) -> (Engine<PhyIo>, Firmware) {
    let mut e = engine();
    for i in 0..4 {
        e.io.regs.insert(phy(i, 0x2943), 0x03030303);
    }
    // Inactive inherited configuration exercises full DP_CONFIG clearing and
    // preservation of unrelated mux/scrambler fields.
    e.io.regs
        .insert(BASE + (0x179a + u64::from(p) * 3) * 4, 0x272);
    e.io.regs.insert(dio(p, 0x20bb), 3);
    e.io.regs.insert(dio(p, 0x20bc), 2);
    e.io.regs.insert(dio(p, 0x2121), 0x12340002);
    e.io.regs.insert(dio(p, 0x2134), 0x01035500);
    let completed = Arc::new(AtomicU8::new(0));
    let firmware = Firmware {
        completed: completed.clone(),
        commands: Vec::new(),
        ready: true,
        pending: false,
        error: None,
        revoke: None,
    };
    (
        Engine {
            io: PhyIo {
                inner: e.io,
                completed,
                phy: p,
                lanes,
                stall: 0,
                transition: 0,
                delay: 2,
                done: false,
                change: None,
                late: None,
            },
            authority: e.authority,
            layout: e.layout,
            status: e.status,
            displays: e.displays,
        },
        firmware,
    )
}
fn dcn401_dp_phy_supports_all_phys_rates_and_physical_lane_mappings() -> TestResult {
    for p in 0..4 {
        for lanes in 1u8..16 {
            if !matches!(lanes.count_ones(), 1 | 2 | 4) {
                continue;
            }
            for rate in [LinkRate::Rbr, LinkRate::Hbr, LinkRate::Hbr2, LinkRate::Hbr3] {
                let (mut e, mut f) = fixture(p, lanes);
                let s = DpPhySettings {
                    lanes: lanes.count_ones() as u8,
                    rate,
                };
                let ready = run(e.enable_dp_phy(&mut f, path(p), s)).unwrap();
                assert_eq!(
                    (ready.path, ready.settings, ready.physical_lanes),
                    (path(p), s, lanes)
                );
                assert_eq!(e.status.state, State::DpPhyReady(p));
                assert!(!e.status.state.reusable());
                assert_eq!(e.status.dp_phy_ready, Some(ready));
                assert_eq!(f.commands, vec![(path(p), Some(s))]);
                assert_eq!(e.io.inner.writes.len(), 7);
                assert_eq!(e.io.inner.regs[&dio(p, 0x2121)], u32::from(s.lanes - 1));
                assert_eq!(e.io.inner.regs[&dio(p, 0x2134)], 0x01035510);
                assert_eq!(
                    e.io.inner.regs[&(BASE + (0x179a + u64::from(p) * 3) * 4)],
                    0x270
                );
                assert_eq!(run(e.enable_dp_phy(&mut f, path(p), s)), Err(Error::Busy));
                run(e.disable_dp_phy(&mut f, path(p))).unwrap();
                assert_eq!(e.status.state, State::DpPhyDisabled);
                assert!(e.status.state.reusable());
                assert_eq!(e.status.dp_phy_ready, Some(ready)); // history only
                assert_eq!(f.commands, vec![(path(p), Some(s)), (path(p), None)]);
                assert_eq!(e.io.inner.writes.len(), 10);
                assert_eq!(run(e.disable_dp_phy(&mut f, path(p))), Err(Error::Busy));
                assert!(run(e.enable_dp_phy(&mut f, path(p), s)).is_ok());
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_phy_supports_all_phys_rates_and_physical_lane_mappings
);

fn dcn401_dp_phy_preflight_rejects_invalid_paths_and_active_consumers_without_writes() -> TestResult
{
    let (mut e, mut f) = fixture(2, 3);
    for lanes in [0, 3, 5, 8, 255] {
        assert_eq!(
            run(e.enable_dp_phy(&mut f, path(2), settings(lanes))),
            Err(Error::Invalid)
        );
    }
    for (p, hpd, connector) in [
        (4, 1, inventory::Connector::DisplayPort),
        (2, 0, inventory::Connector::DisplayPort),
        (2, 5, inventory::Connector::DisplayPort),
        (2, 1, inventory::Connector::HdmiTypeA),
    ] {
        let mut path = path(p);
        path.hpd = hpd;
        path.connector = connector;
        assert!(run(e.enable_dp_phy(&mut f, path, settings(2))).is_err());
    }
    f.ready = false;
    assert_eq!(
        run(e.enable_dp_phy(&mut f, path(2), settings(2))),
        Err(Error::Busy)
    );
    assert!(f.commands.is_empty());
    assert!(e.io.inner.writes.is_empty());
    let mut busy = e.layout.idle.to_vec();
    busy.extend([
        (dio(2, 0x20bc), 0x100),
        (dio(2, 0x2134), 1),
        (dio(2, 0x212d), 0x010101ff),
        (dio(2, 0x211e), 0x10),
        (dio(2, 0x2125), 0x11),
        (dio(2, 0x212e), 3),
        (0x16265 * 4, 0x8888),
        (BASE + 0x54 * 4, 1),
        (e.layout.dio_clock, 0x10),
        (e.layout.otg(0, LOCK), 0x101),
        (e.layout.otg(0, CLOCK), 0x113),
        (e.layout.odm(0, INPUT_CLOCK), 7),
        (e.layout.vtg(0), 0x80000000),
        (dio(1, 0x2141), 0x1ff11111),
    ]);
    for (at, mask) in busy {
        for bit in 0..32 {
            if mask & (1 << bit) == 0 {
                continue;
            }
            let (mut e, mut f) = fixture(2, 3);
            *e.io.inner.regs.entry(at).or_default() |= 1 << bit;
            assert!(
                run(e.enable_dp_phy(&mut f, path(2), settings(2))).is_err(),
                "{at:x} {bit}"
            );
            assert_eq!(e.status.state, State::Ready);
            assert!(f.commands.is_empty());
            assert!(e.io.inner.writes.is_empty());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_phy_preflight_rejects_invalid_paths_and_active_consumers_without_writes
);

fn dcn401_dp_phy_keeps_prepared_timing_on_independent_dto() -> TestResult {
    for source in [4, 6] {
        let (mut e, mut f) = fixture(0, 8);
        for p in 0..4 {
            e.io.inner.regs.insert(e.layout.otg(p, CLOCK), 0x103);
            e.io.inner.regs.insert(e.layout.odm(p, INPUT_CLOCK), 7);
            e.io.inner
                .regs
                .insert(0x16200 * 4 + (0x80 + u64::from(p) * 4) * 4, 0x1090);
        }
        e.io.inner.regs.insert(
            0x16268 * 4,
            source | source << 3 | source << 6 | source << 9,
        );
        run(e.enable_dp_phy(&mut f, path(0), settings(1))).unwrap();
        run(e.disable_dp_phy(&mut f, path(0))).unwrap();
        for p in 0..4 {
            assert_eq!(e.io.inner.regs[&e.layout.otg(p, CLOCK)], 0x103);
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_phy_keeps_prepared_timing_on_independent_dto
);

fn dcn401_dp_phy_quarantines_failed_writes_firmware_and_capability_loss() -> TestResult {
    for write in 1..=7 {
        let (mut e, mut f) = fixture(1, 3);
        e.io.inner.reject = Some(write);
        assert!(run(e.enable_dp_phy(&mut f, path(1), settings(2))).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
        assert!(f.commands.is_empty());
        assert_eq!(e.io.inner.writes.len(), write);
    }
    for write in 0..=7 {
        let (mut e, mut f) = fixture(1, 3);
        e.io.inner.gone = Some(write);
        assert_eq!(
            run(e.enable_dp_phy(&mut f, path(1), settings(2))),
            Err(Error::DeviceGone)
        );
        assert_eq!(e.io.inner.writes.len(), write);
        assert!(f.commands.is_empty());
    }
    for write in 1..=7 {
        let (mut e, mut f) = fixture(1, 3);
        e.io.inner.revoke = Some((write, e.authority));
        assert_eq!(
            run(e.enable_dp_phy(&mut f, path(1), settings(2))),
            Err(Error::Revoked)
        );
        assert_eq!(e.io.inner.writes.len(), write);
        assert!(f.commands.is_empty());
    }
    for revoke in [false, true] {
        let (mut e, mut f) = fixture(1, 3);
        let expected = if revoke {
            f.revoke = Some(e.authority);
            Error::Revoked
        } else {
            f.error = Some(dmub::Error::CommandRejected(7));
            Error::Firmware(dmub::Error::CommandRejected(7))
        };
        assert_eq!(
            run(e.enable_dp_phy(&mut f, path(1), settings(2))),
            Err(expected)
        );
        assert_eq!(e.status.state, State::Failed(expected));
        assert_eq!(
            run(e.enable_dp_phy(&mut f, path(1), settings(2))),
            Err(Error::Busy)
        );
        assert_eq!(f.commands.len(), 1);
        assert!(e.status.dp_phy_ready.is_none());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_phy_quarantines_failed_writes_firmware_and_capability_loss
);

fn dcn401_dp_phy_requires_independent_hardware_witnesses_and_fresh_routes() -> TestResult {
    for (reg, value) in [
        (phy(3, 0x2943), 0x03030c0c), // wrong physical lanes for requested one lane
        (phy(3, 0x2943), 0x0303031c), // handshake request remains asserted
        (phy(3, 0x2943), 0x0303032c), // handshake acknowledgement remains asserted
        (phy(3, 0x2943), 0x0303030d), // reset remains asserted
        (phy(3, 0x2943), 0x0303030e), // lane remains disabled
        (phy(3, 0x2943), 0x03030308), // lane clock not ready
        (phy(3, 0x2943), 0x03030b0c), // unused lane data still enabled
        (phy(3, 0x2931), 0x210),      // TX clock-on missing
        (phy(3, 0x2931), 0x420),      // wrong lane request, TX request missing
        (dio(3, 0x20bb), 0x10),       // backend clock-on missing
    ] {
        let (mut e, mut f) = fixture(3, 1);
        e.io.change = Some((reg, value));
        assert_eq!(
            run(e.enable_dp_phy(&mut f, path(3), settings(1))),
            Err(Error::Timeout(reg))
        );
        assert!(matches!(e.status.state, State::Failed(_)));
        assert!(e.status.dp_phy_ready.is_none());
    }
    for (at, value) in [
        (dio(3, 0x20bc), 0x100),
        (dio(3, 0x2121), 3),
        (dio(3, 0x2134), 0),
        (dio(0, 0x2141), 1),
        (phy(3, 0x2943), 0x03030c03),
    ] {
        let (mut e, mut f) = fixture(3, 1);
        // Change state only after the lane wait, when the TX witness is read.
        e.io.late = Some((phy(3, 0x2931), 1, at, value));
        assert!(run(e.enable_dp_phy(&mut f, path(3), settings(1))).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
        assert!(e.status.dp_phy_ready.is_none());
        assert_eq!(e.io.inner.writes.len(), 7);
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_phy_requires_independent_hardware_witnesses_and_fresh_routes
);

fn dcn401_dp_phy_rechecks_selected_phy_before_firmware_and_after_shutdown() -> TestResult {
    for (at, value) in [
        (phy(1, 0x2943), 0x0303030c),
        (phy(1, 0x2931), 0x610),
        (dio(1, 0x20bc), 0x100),
    ] {
        let (mut e, mut f) = fixture(1, 3);
        e.io.inner.after_write = Some((7, at, value));
        assert!(run(e.enable_dp_phy(&mut f, path(1), settings(2))).is_err());
        assert!(f.commands.is_empty());
        assert!(matches!(e.status.state, State::Failed(_)));
    }
    for (at, value) in [
        (phy(1, 0x2943), 0x0303030c),
        (phy(1, 0x2931), 0x610),
        (dio(1, 0x20bc), 0x100),
        (dio(1, 0x20bd), 1),
    ] {
        let (mut e, mut f) = fixture(1, 3);
        run(e.enable_dp_phy(&mut f, path(1), settings(2))).unwrap();
        e.io.inner.after_write = Some((10, at, value));
        assert!(run(e.disable_dp_phy(&mut f, path(1))).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_phy_rechecks_selected_phy_before_firmware_and_after_shutdown
);

fn dcn401_dp_phy_cancelled_enable_or_disable_never_replays() -> TestResult {
    for disabling in [false, true] {
        for transport in [false, true] {
            let (mut e, mut f) = fixture(2, 3);
            if disabling {
                run(e.enable_dp_phy(&mut f, path(2), settings(2))).unwrap();
            }
            if transport {
                f.pending = true;
            } else {
                e.io.stall = 4;
            }
            if disabling {
                let mut future = core::pin::pin!(e.disable_dp_phy(&mut f, path(2)));
                assert!(future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            } else {
                let mut future = core::pin::pin!(e.enable_dp_phy(&mut f, path(2), settings(2)));
                assert!(future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop()))
                    .is_pending());
            }
            assert_eq!(
                e.status.state,
                if disabling {
                    State::DisablingDpPhy(2)
                } else {
                    State::EnablingDpPhy(2)
                }
            );
            assert!(!e.status.state.reusable());
            assert_eq!(
                run(e.enable_dp_phy(&mut f, path(2), settings(2))),
                Err(Error::Busy)
            );
            assert_eq!(run(e.disable_dp_phy(&mut f, path(2))), Err(Error::Busy));
            assert_eq!(f.commands.len(), if disabling { 2 } else { 1 });
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_phy_cancelled_enable_or_disable_never_replays
);

fn dcn401_dp_phy_disable_checks_ownership_and_all_off_witnesses() -> TestResult {
    for stall in [1, 2, 4, 8] {
        let (mut e, mut f) = fixture(2, 3);
        run(e.enable_dp_phy(&mut f, path(2), settings(2))).unwrap();
        let mut wrong = path(2);
        wrong.hpd = 1;
        assert_eq!(run(e.disable_dp_phy(&mut f, wrong)), Err(Error::Invalid));
        assert_eq!(run(e.disable_dp_phy(&mut f, path(1))), Err(Error::Busy));
        e.io.stall = stall;
        assert!(matches!(
            run(e.disable_dp_phy(&mut f, path(2))),
            Err(Error::Timeout(_))
        ));
        assert!(matches!(e.status.state, State::Failed(_)));
        assert_eq!(e.io.inner.writes.len(), 7); // cleanup must not run early
        assert_eq!(f.commands.len(), 2);
        assert_eq!(run(e.disable_dp_phy(&mut f, path(2))), Err(Error::Busy));
    }
    for at in [dio(2, 0x212e), dio(2, 0x211e), dio(2, 0x2125)] {
        let (mut e, mut f) = fixture(2, 3);
        run(e.enable_dp_phy(&mut f, path(2), settings(2))).unwrap();
        e.io.inner.after_write = Some((10, at, 0x11));
        assert!(run(e.disable_dp_phy(&mut f, path(2))).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_phy_disable_checks_ownership_and_all_off_witnesses
);

/// Another display's running pipe, transmitter and stream are its own:
/// their consumer registers do not block this PHY, the same registers are
/// still foreign without that display, and its transmitter is never taken.
fn dcn401_dp_phy_leaves_other_displays_consumers_to_them() -> TestResult {
    let theirs = Siblings {
        pipes: 1 << 0,
        det: 1 << 0,
        transmitters: 1 << 1,
        streams: 1 << 3,
        hpo: 0,
        live: [None; 4],
    };
    let running = |e: &mut Engine<PhyIo>| {
        let l = e.layout;
        for (at, value) in [
            (l.otg(0, CONTROL), 0x10001),
            (l.otg(0, CLOCK), 0x10103),
            (l.odm(0, INPUT_CLOCK), 7),
            (l.vtg(0), 0x80000000),
            // TMDS timing: the pixel clock comes from its PHY, not a DTO.
            (0x16200 * 4 + 0x80 * 4, 0),
            (dio(1, 0x20bb), 0x2810),
            (dio(1, 0x20bd), 1),
            (phy(1, 0x2943), 0x03030303),
            (phy(1, 0x2931), 0x6f0),
            (dio(3, 0x2094), 0x2c10),
            (dio(3, 0x2095), 1),
            (dio(3, 0x209b), 1),
            (dio(3, 0x2122), 0x10001),
            (dio(3, 0x2141), 0x1ff11111),
            (e.layout.dio_clock + 3 * 4, 0x10),
        ] {
            e.io.inner.regs.insert(at, value);
        }
    };
    let (mut e, mut f) = fixture(2, 3);
    running(&mut e);
    if run(e.enable_dp_phy(&mut f, path(2), settings(2))).is_ok() {
        return TestResult::Fail("foreign running consumers ignored");
    }
    let (mut e, mut f) = fixture(2, 3);
    running(&mut e);
    e.displays.siblings = theirs;
    if run(e.enable_dp_phy(&mut f, path(2), settings(2))).is_err()
        || run(e.disable_dp_phy(&mut f, path(2))).is_err()
    {
        return TestResult::Fail("another display's consumers blocked this PHY");
    }
    let (mut e, mut f) = fixture(1, 3);
    e.displays.siblings = theirs;
    if run(e.enable_dp_phy(&mut f, path(1), settings(2))) != Err(Error::Busy)
        || !f.commands.is_empty()
    {
        return TestResult::Fail("another display's transmitter taken");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-otg",
    dcn401_dp_phy_leaves_other_displays_consumers_to_them
);

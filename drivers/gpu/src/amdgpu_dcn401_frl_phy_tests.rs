use super::*;
use crate::amdgpu_dmub_navi48 as dmub;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

fn phy_at(phy: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(phy) * 0xd8) * 4
}
fn pixel(pipe: u8) -> u64 {
    (0x16280 + u64::from(pipe) * 4) * 4
}
const DTO: u64 = 0x16268 * 4;
const LE: u64 = 0x16266 * 4;
const SE: u64 = 0x16265 * 4;
const ROOT: u64 = BASE + 0x4a * 4;
fn frontend(p: u8) -> u64 {
    (0x162a0 + u64::from(p)) * 4
}
struct Firmware {
    done: Arc<AtomicBool>,
    ready: bool,
    pending: bool,
    error: Option<dmub::Error>,
    revoke: Option<Cap<BusDeviceCap, Write>>,
    commands: Vec<Path>,
}
impl crate::amdgpu_dcn401_otg::frl::link::phy::Firmware for Firmware {
    fn ready(&self) -> bool {
        self.ready
    }
    async fn disable(&mut self, path: Path) -> Result<(), dmub::Error> {
        self.commands.push(path);
        if self.pending {
            core::future::pending::<()>().await;
        }
        if let Some(e) = self.error {
            return Err(e);
        }
        if let Some(cap) = self.revoke {
            cap.revoke();
        }
        self.done.store(true, Ordering::SeqCst);
        Ok(())
    }
}
struct PhyIo {
    inner: Fake,
    done: Arc<AtomicBool>,
    phy: u8,
    pending: bool,
    lanes_done: bool,
    clock_done: bool,
    delay: u8,
    stalled: u8,
    lanes_after: u32,
    clock_after: u32,
    after_firmware: Option<(u64, u32)>,
    after_clock: Option<(u64, u32)>,
    gone_after_firmware: bool,
}
impl Io for PhyIo {
    fn read(&mut self, at: u64) -> u32 {
        if self.done.swap(false, Ordering::SeqCst) {
            self.pending = true;
            if self.gone_after_firmware {
                self.inner.gone = Some(0);
            }
            if let Some((a, v)) = self.after_firmware.take() {
                self.inner.regs.insert(a, v);
            }
        }
        if self.pending
            && !self.lanes_done
            && at == phy_at(self.phy, 0x2943)
            && self.stalled & 1 == 0
        {
            if self.delay != 0 {
                self.delay -= 1;
            } else {
                self.inner.regs.insert(at, self.lanes_after);
                self.lanes_done = true;
            }
        }
        if self.pending
            && self.lanes_done
            && !self.clock_done
            && at == phy_at(self.phy, 0x2931)
            && self.stalled & 2 == 0
        {
            self.inner.regs.insert(at, self.clock_after);
            self.clock_done = true;
            if let Some((a, v)) = self.after_clock.take() {
                self.inner.regs.insert(a, v);
            }
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        assert_eq!(at, ROOT); // host must not manufacture firmware's off witnesses
        assert_eq!(
            self.inner.regs[&phy_at(self.phy, 0x2943)] & 0x3e3e3e3e,
            0x02020202
        );
        assert_eq!(self.inner.regs[&phy_at(self.phy, 0x2931)] & 0x6f0, 0);
        self.inner.write(at, value);
    }
}
fn ready(phy: u8, pipe: u8) -> (Engine<PhyIo>, Firmware) {
    let mut e = fixture(phy, pipe);
    run(e.retire_frl_link(path(phy))).unwrap();
    e.io.inner.writes.clear();
    // Keep timing live on an acknowledged DTB DTO, independent of the FRL PHY.
    e.io.inner.regs.insert(pixel(pipe), 0x80001090);
    e.io.inner.regs.insert(DTO, 6 << (3 * pipe));
    let other = (phy + 1) % 4;
    e.io.inner
        .regs
        .insert(frontend(0), 0x80000011 | u32::from(other) << 8);
    e.io.inner.regs.insert(LE, 0x80000008 | u32::from(other));
    e.io.inner.regs.insert(phy_at(other, 0x2943), 0x4c4c4c4c);
    e.io.inner.regs.insert(phy_at(other, 0x2931), 0x6f0);
    let done = Arc::new(AtomicBool::new(false));
    let fw = Firmware {
        done: done.clone(),
        ready: true,
        pending: false,
        error: None,
        revoke: None,
        commands: Vec::new(),
    };
    (
        Engine {
            io: PhyIo {
                inner: e.io.inner,
                done,
                phy,
                pending: false,
                lanes_done: false,
                clock_done: false,
                delay: 1,
                stalled: 0,
                lanes_after: 0x43434343,
                clock_after: 0x1001,
                after_firmware: None,
                after_clock: None,
                gone_after_firmware: false,
            },
            authority: e.authority,
            layout: e.layout,
            status: e.status,
            displays: e.displays,
        },
        fw,
    )
}
fn dcn401_frl_phy_native_disable_waits_for_lanes_and_clocks_before_parking() -> TestResult {
    for phy in 0..4 {
        for pipe in 0..4 {
            for source in [4, 6] {
                let (mut e, mut fw) = ready(phy, pipe);
                e.io.inner.regs.insert(DTO, source << (3 * pipe));
                e.status.frl_link_retired = None; // live proof, never history
                let before = e.io.inner.regs.clone();
                let result = run(e.disable_frl(&mut fw, path(phy))).unwrap();
                assert_eq!(
                    result,
                    FrlDisabled {
                        path: path(phy),
                        command_sent: true
                    }
                );
                assert_eq!(e.status.state, State::FrlDisabled);
                assert_eq!(e.status.frl_disabled, Some(result));
                assert_eq!(fw.commands, [path(phy)]);
                assert_eq!(e.io.inner.writes, [(ROOT, 0x80000000)]);
                for (at, value) in before {
                    if ![ROOT, phy_at(phy, 0x2943), phy_at(phy, 0x2931)].contains(&at) {
                        assert_eq!(e.io.inner.regs[&at], value, "{at:x}");
                    }
                }
                e.io.inner.writes.clear();
                fw.commands.clear();
                assert!(!run(e.disable_frl(&mut fw, path(phy))).unwrap().command_sent);
                assert!(e.io.inner.writes.is_empty());
                assert!(fw.commands.is_empty());
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-phy",
    dcn401_frl_phy_native_disable_waits_for_lanes_and_clocks_before_parking
);

fn dcn401_frl_phy_preflight_rejects_live_work_and_shared_clock_consumers() -> TestResult {
    for (at, value) in [
        (frl(0x95b), 1),
        (frl(0x95c), 3),
        (frl(0x965), 1),
        (frl(0x966), 0x2000000),
        (frl(0x8d3), 1),
        (frl(0x8e6), 1),
        (frl(0x93c), 0x10),
        (mux(2), 2),
        (mux(0), 1),
        (ROOT, 0),
        (forced(2), 0),
        (dio(2, 0x20bd), 1),
        (dio(2, 0x20bb), 0x2000),
        (frontend(0), 0x210),
        (LE, 0xa),
        (SE, 8),
        (pixel(1), 0),
        (pixel(1), 0x1010),
        (pixel(1), 0x1080),
        (pixel(1), 0x90),
        (pixel(1), 0x1190),
        (pixel(1), 0x1290),
        (DTO, 5 << 3),
        (BASE + (0x1b84 + 0x80) * 4, 0x10),
        (BASE + (0x1b89 + 0x80) * 4, 1),
        (BASE + (0x1aca + 0x10) * 4, 1),
    ] {
        let (mut e, mut fw) = ready(2, 1);
        e.io.inner.regs.insert(at, value);
        assert!(
            run(e.disable_frl(&mut fw, path(2))).is_err(),
            "{at:x}/{value:x}"
        );
        assert!(fw.commands.is_empty());
        assert!(e.io.inner.writes.is_empty());
        assert_eq!(e.status.state, State::FrlLinkRetired);
    }
    for lane in 0..4 {
        for bit in [0x10, 0x20] {
            let (mut e, mut fw) = ready(2, 1);
            *e.io.inner.regs.get_mut(&phy_at(2, 0x2943)).unwrap() |= bit << (8 * lane);
            assert_eq!(run(e.disable_frl(&mut fw, path(2))), Err(Error::Busy));
            assert!(fw.commands.is_empty());
        }
    }
    let (mut e, mut fw) = ready(2, 1);
    fw.ready = false;
    assert_eq!(run(e.disable_frl(&mut fw, path(2))), Err(Error::Busy));
    assert!(fw.commands.is_empty());
    assert!(e.io.inner.writes.is_empty());
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-phy",
    dcn401_frl_phy_preflight_rejects_live_work_and_shared_clock_consumers
);

fn dcn401_frl_phy_requires_every_lane_and_tx_clock_witness() -> TestResult {
    for (at, mask) in [
        (phy_at(2, 0x2943), 0x3e3e3e3eu32),
        (phy_at(2, 0x2931), 0x6f0),
    ] {
        for bit in (0..32).map(|i| 1 << i).filter(|v| mask & v != 0) {
            let (mut e, mut fw) = ready(2, 1);
            if at == phy_at(2, 0x2943) {
                e.io.lanes_after ^= bit;
            } else {
                e.io.clock_after ^= bit;
            }
            assert_eq!(
                run(e.disable_frl(&mut fw, path(2))),
                Err(Error::Timeout(at))
            );
            assert_eq!(fw.commands, [path(2)]);
            assert!(e.io.inner.writes.is_empty());
            assert!(e.status.frl_disabled.is_none());
            assert_eq!(e.status.state, State::Failed(Error::Timeout(at)));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-phy",
    dcn401_frl_phy_requires_every_lane_and_tx_clock_witness
);

fn dcn401_frl_phy_inherited_off_does_not_replay_firmware() -> TestResult {
    for parked in [false, true] {
        let (mut e, mut fw) = ready(2, 1);
        e.io.inner.regs.insert(phy_at(2, 0x2943), 0x43434343);
        e.io.inner.regs.insert(phy_at(2, 0x2931), 0x1001);
        if parked {
            e.io.inner.regs.insert(ROOT, 0x80000000);
        }
        assert!(!run(e.disable_frl(&mut fw, path(2))).unwrap().command_sent);
        assert!(fw.commands.is_empty());
        assert_eq!(e.io.inner.writes.len(), usize::from(!parked));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-phy",
    dcn401_frl_phy_inherited_off_does_not_replay_firmware
);

fn dcn401_frl_phy_cancellation_retains_all_uncertain_owners() -> TestResult {
    for phase in 0..3 {
        let (mut e, mut fw) = ready(2, 1);
        fw.pending = phase == 0;
        e.io.stalled = if phase == 1 {
            1
        } else if phase == 2 {
            2
        } else {
            0
        };
        e.io.delay = 0;
        {
            let mut f = core::pin::pin!(e.disable_frl(&mut fw, path(2)));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.status.state, State::DisablingFrl(2));
        assert_eq!(fw.commands, [path(2)]);
        assert!(e.io.inner.writes.is_empty());
        assert!(e.status.frl_disabled.is_none());
        assert_eq!(run(e.disable_frl(&mut fw, path(2))), Err(Error::Busy));
        assert_eq!(run(e.retire_frl_link(path(2))), Err(Error::Busy));
        assert_eq!(run(e.retire_planes()), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-phy",
    dcn401_frl_phy_cancellation_retains_all_uncertain_owners
);

fn dcn401_frl_phy_firmware_errors_revocation_device_loss_and_lost_root_write() -> TestResult {
    for case in 0..7 {
        let (mut e, mut fw) = ready(2, 1);
        let error = match case {
            0 => {
                fw.error = Some(dmub::Error::CommandTimeout);
                Error::Firmware(dmub::Error::CommandTimeout)
            }
            1 => {
                fw.revoke = Some(e.authority);
                Error::Revoked
            }
            2 => {
                e.io.gone_after_firmware = true;
                Error::DeviceGone
            }
            3 => {
                e.io.inner.reject = Some(1);
                Error::Readback(ROOT)
            }
            4 => {
                e.io.inner.revoke = Some((1, e.authority));
                Error::Revoked
            }
            5 => {
                e.io.inner.gone = Some(1);
                Error::DeviceGone
            }
            _ => {
                e.authority.revoke();
                Error::Revoked
            }
        };
        assert_eq!(run(e.disable_frl(&mut fw, path(2))), Err(error), "{case}");
        assert!(e.status.frl_disabled.is_none());
        assert_eq!(
            e.io.inner.writes.len(),
            usize::from((3..=5).contains(&case))
        );
        assert_eq!(fw.commands.len(), usize::from(case != 6));
        if case != 6 {
            assert_eq!(e.status.state, State::Failed(error));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-phy",
    dcn401_frl_phy_firmware_errors_revocation_device_loss_and_lost_root_write
);

fn dcn401_frl_phy_late_routes_consumers_and_reactivation_block_success() -> TestResult {
    for (at, value) in [
        (mux(2), 0x501),
        (mux(0), 1),
        (ROOT, 0x11),
        (forced(2), 0),
        (frl(0x95b), 1),
        (frl(0x95c), 3),
        (frl(0x8d3), 1),
        (frl(0x8e6), 1),
        (frl(0x8f1), 0x100),
        (frl(0x965), 1),
        (frl(0x966), 0x2000000),
        (dio(2, 0x20bd), 1),
        (frontend(0), 0x210),
        (LE, 0xa),
        (SE, 8),
        (pixel(1), 0),
        (pixel(1), 0x1010),
        (DTO, 4 << 3),
    ] {
        for after_park in [false, true] {
            let (mut e, mut fw) = ready(2, 1);
            if after_park {
                e.io.inner.after_write = Some((1, at, value));
            } else {
                e.io.after_firmware = Some((at, value));
            }
            assert!(
                run(e.disable_frl(&mut fw, path(2))).is_err(),
                "{at:x}/{after_park}"
            );
            assert!(e.status.frl_disabled.is_none());
            assert!(!e.status.state.reusable());
            assert_eq!(e.io.inner.writes.len(), usize::from(after_park));
        }
    }
    for (at, value) in [(phy_at(2, 0x2943), 0x43434347), (phy_at(2, 0x2931), 0x1201)] {
        for after_park in [false, true] {
            let (mut e, mut fw) = ready(2, 1);
            if after_park {
                e.io.inner.after_write = Some((1, at, value));
            } else {
                e.io.after_clock = Some((at, value));
            }
            assert!(run(e.disable_frl(&mut fw, path(2))).is_err());
            assert!(e.status.frl_disabled.is_none());
            assert_eq!(e.io.inner.writes.len(), usize::from(after_park));
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-frl-phy",
    dcn401_frl_phy_late_routes_consumers_and_reactivation_block_success
);

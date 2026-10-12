use super::*;
use crate::amdgpu_dmub_navi48::{self as dmub, DpSignal};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

fn phy_at(phy: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(phy) * 0xd8) * 4
}
struct Firmware {
    completed: Arc<AtomicBool>,
    commands: Vec<(Path, DpSignal)>,
    ready: bool,
    pending: bool,
    error: Option<dmub::Error>,
    revoke: Option<Cap<BusDeviceCap, Write>>,
}
impl crate::amdgpu_dcn401_otg::hpo_link::phy::Firmware for Firmware {
    fn ready(&self) -> bool {
        self.ready
    }
    async fn disable(&mut self, path: Path, signal: DpSignal) -> Result<(), dmub::Error> {
        self.commands.push((path, signal));
        if self.pending {
            core::future::pending::<()>().await;
        }
        if let Some(e) = self.error {
            return Err(e);
        }
        if let Some(cap) = self.revoke {
            cap.revoke();
        }
        self.completed.store(true, Ordering::SeqCst);
        Ok(())
    }
}
struct PhyIo {
    inner: Model,
    completed: Arc<AtomicBool>,
    phy: u8,
    root: u64,
    pending: bool,
    lanes_done: bool,
    clock_done: bool,
    delay: u8,
    lanes_after: u32,
    clock_after: u32,
    after_firmware: Option<(u64, u32)>,
}
impl Io for PhyIo {
    fn read(&mut self, addr: u64) -> u32 {
        if self.completed.swap(false, Ordering::SeqCst) {
            self.pending = true;
            if let Some((a, v)) = self.after_firmware.take() {
                self.inner.inner.regs.insert(a, v);
            }
        }
        if self.pending && !self.lanes_done && addr == phy_at(self.phy, 0x2943) {
            if self.delay != 0 {
                self.delay -= 1;
            } else {
                self.inner.inner.regs.insert(addr, self.lanes_after);
                self.lanes_done = true;
            }
        }
        if self.pending && self.lanes_done && !self.clock_done && addr == phy_at(self.phy, 0x2931) {
            self.inner.inner.regs.insert(addr, self.clock_after);
            self.clock_done = true;
        }
        self.inner.read(addr)
    }
    fn write(&mut self, addr: u64, value: u32) {
        // The host may only park the HPO root route; PHY registers are firmware-owned.
        assert_eq!(addr, self.root);
        assert_eq!(
            self.inner.inner.regs[&phy_at(self.phy, 0x2943)] & 0x3e3e3e3e,
            0x02020202
        );
        assert_eq!(self.inner.inner.regs[&phy_at(self.phy, 0x2931)] & 0x6f0, 0);
        self.inner.write(addr, value);
    }
}
fn ready(phy: u8, link: u8) -> (Engine<PhyIo>, Firmware) {
    let mut e = fixture(phy, link, 4);
    run(e.retire_hpo_link(path(phy))).unwrap();
    e.io.inner.writes.clear();
    e.io.stopping = false;
    e.io.stopping_clock = false;
    let mut root = 0x80000000;
    let mut other = 1;
    for p in 0..4 {
        let source = if p == link {
            phy
        } else {
            let n = (phy + other) % 4;
            other += 1;
            n
        };
        root |= u32::from(source | 8) << (4 * p);
        // Independent outputs remain live through this operation.
        e.io.inner.regs.insert(phy_at(p, 0x2943), 0x4c4c4c4c);
        e.io.inner.regs.insert(phy_at(p, 0x2931), 0x16f1);
        e.io.inner.regs.insert(
            BASE + (0x20bd + u64::from(p) * 0x124) * 4,
            u32::from(p != phy),
        );
    }
    e.io.inner.regs.insert(e.layout.link_clock, root);
    let completed = Arc::new(AtomicBool::new(false));
    let fw = Firmware {
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
                phy,
                root: e.layout.link_clock,
                pending: false,
                lanes_done: false,
                clock_done: false,
                delay: 2,
                lanes_after: 0x43434343,
                clock_after: 0x1001,
                after_firmware: None,
            },
            authority: e.authority,
            layout: e.layout,
            status: e.status,
        },
        fw,
    )
}

fn dcn401_hpo_phy_routes_and_signals_stop_lanes_before_root_clock() -> TestResult {
    for phy in 0..4 {
        for link in 0..4 {
            for signal in [DpSignal::Sst, DpSignal::Mst] {
                let (mut e, mut fw) = ready(phy, link);
                let before = e.io.inner.inner.regs.clone();
                let result = run(e.disable_hpo_dp(&mut fw, path(phy), signal)).unwrap();
                assert_eq!(
                    result,
                    HpoDpDisabled {
                        path: path(phy),
                        link,
                        signal,
                        command_sent: true
                    }
                );
                assert_eq!(fw.commands, [(path(phy), signal)]);
                assert_eq!(e.status.state, State::HpoDpDisabled);
                assert_eq!(e.status.hpo_dp_disabled, Some(result));
                let root = e.layout.link_clock;
                assert_eq!(
                    e.io.inner.inner.writes,
                    [(root, before[&root] & !(0xf << (4 * link)))]
                );
                for (addr, value) in before {
                    if ![root, phy_at(phy, 0x2943), phy_at(phy, 0x2931)].contains(&addr) {
                        assert_eq!(
                            e.io.inner.inner.regs[&addr], value,
                            "unrelated register {addr:x}"
                        );
                    }
                }
                e.io.inner.inner.writes.clear();
                fw.commands.clear();
                let again = run(e.disable_hpo_dp(&mut fw, path(phy), signal)).unwrap();
                assert!(!again.command_sent);
                assert!(fw.commands.is_empty());
                assert!(e.io.inner.inner.writes.is_empty());
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hpo-phy",
    dcn401_hpo_phy_routes_and_signals_stop_lanes_before_root_clock
);

fn dcn401_hpo_phy_rejects_live_digital_work_and_shared_phy_before_command() -> TestResult {
    let (e, _) = ready(2, 1);
    let root = e.layout.link_clock;
    let saved = e.io.inner.inner.regs[&root];
    for (addr, value) in [
        (at(1, 0x36b4), 0x325),
        (at(1, 0x36b5), 1),
        (at(1, 0x369f), 0x10),
        (at(1, 0x36c7), 0x600),
        (at(1, 0x36b5), 0x40000),
        (at(2, 0x3623), 1),
        (mux(2), 0x202),
        (map(0), 1),
        (root, saved & !0xf0),
        (root, (saved & !0xf) | 0xa),
        (phy_at(2, 0x2943), 0x1c1c1c1c),
        (phy_at(2, 0x2943), 0x2c2c2c2c),
        (BASE + (0x20bd + 2 * 0x124) * 4, 1),
        (BASE + (0x20bb + 2 * 0x124) * 4, 0x2000),
        (phy_at(2, 0x2931), u32::MAX),
    ] {
        let (mut e, mut fw) = ready(2, 1);
        e.io.inner.inner.regs.insert(addr, value);
        assert!(
            run(e.disable_hpo_dp(&mut fw, path(2), DpSignal::Sst)).is_err(),
            "accepted {addr:x}={value:x}"
        );
        assert!(fw.commands.is_empty());
        assert!(e.io.inner.inner.writes.is_empty());
        assert_eq!(e.status.state, State::HpoLinkRetired);
    }
    for case in 0..5 {
        let (mut e, mut fw) = ready(2, 1);
        let mut p = path(2);
        match case {
            0 => p.transmitter = 4,
            1 => p.hpd = 0,
            2 => p.connector = Connector::EmbeddedDisplayPort,
            3 => fw.ready = false,
            _ => {
                e.authority.revoke();
            }
        }
        assert!(run(e.disable_hpo_dp(&mut fw, p, DpSignal::Sst)).is_err());
        assert!(fw.commands.is_empty());
        assert!(e.io.inner.inner.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hpo-phy",
    dcn401_hpo_phy_rejects_live_digital_work_and_shared_phy_before_command
);

fn dcn401_hpo_phy_requires_each_lane_and_clock_witness_after_firmware() -> TestResult {
    for lane in 0..4 {
        for bit in [1, 2, 3, 4, 5] {
            let (mut e, mut fw) = ready(2, 1);
            e.io.lanes_after ^= 1 << (lane * 8 + bit);
            assert_eq!(
                run(e.disable_hpo_dp(&mut fw, path(2), DpSignal::Sst)),
                Err(Error::Timeout(phy_at(2, 0x2943)))
            );
            assert!(e.io.inner.inner.writes.is_empty());
            assert!(!e.status.state.reusable());
            assert!(e.status.hpo_dp_disabled.is_none());
        }
    }
    for bit in [4, 5, 6, 7, 9, 10] {
        let (mut e, mut fw) = ready(2, 1);
        e.io.clock_after |= 1 << bit;
        assert_eq!(
            run(e.disable_hpo_dp(&mut fw, path(2), DpSignal::Sst)),
            Err(Error::Timeout(phy_at(2, 0x2931)))
        );
        assert!(e.io.inner.inner.writes.is_empty());
        assert!(!e.status.state.reusable());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hpo-phy",
    dcn401_hpo_phy_requires_each_lane_and_clock_witness_after_firmware
);

fn dcn401_hpo_phy_cancelled_firmware_or_hardware_wait_cannot_replay() -> TestResult {
    for stage in 0..3 {
        let (mut e, mut fw) = ready(2, 1);
        match stage {
            0 => fw.pending = true,
            1 => e.io.lanes_after |= 8,
            _ => e.io.clock_after |= 0x400,
        }
        {
            let mut f = core::pin::pin!(e.disable_hpo_dp(&mut fw, path(2), DpSignal::Mst));
            assert!(f
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.status.state, State::DisablingHpoDp(2));
        assert_eq!(
            run(e.disable_hpo_dp(&mut fw, path(2), DpSignal::Mst)),
            Err(Error::Busy)
        );
        assert_eq!(run(e.retire_hpo_link(path(2))), Err(Error::Busy));
        assert_eq!(fw.commands.len(), 1);
        assert!(e.io.inner.inner.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hpo-phy",
    dcn401_hpo_phy_cancelled_firmware_or_hardware_wait_cannot_replay
);

fn dcn401_hpo_phy_firmware_errors_revocation_and_late_drift_quarantine() -> TestResult {
    for case in 0..7 {
        let (mut e, mut fw) = ready(2, 1);
        match case {
            0 => fw.error = Some(dmub::Error::CommandTimeout),
            1 => fw.revoke = Some(e.authority),
            2 => e.io.inner.inner.reject = Some(1),
            3 => e.io.inner.inner.revoke = Some((1, e.authority)),
            4 => e.io.inner.inner.gone = Some(1),
            5 => e.io.after_firmware = Some((phy_at(2, 0x2931), u32::MAX)),
            _ => e.io.inner.inner.after_write = Some((1, phy_at(2, 0x2943), 0x4343434b)),
        }
        // Device removal must remain observable after the simulated completion.
        if case == 5 {
            e.io.clock_after = u32::MAX;
        }
        assert!(
            run(e.disable_hpo_dp(&mut fw, path(2), DpSignal::Sst)).is_err(),
            "accepted fault {case}"
        );
        assert!(matches!(e.status.state, State::Failed(_)));
        assert!(e.status.hpo_dp_disabled.is_none());
        assert_eq!(
            run(e.disable_hpo_dp(&mut fw, path(2), DpSignal::Sst)),
            Err(Error::Busy)
        );
    }
    let (e, _) = ready(2, 1);
    let root = e.layout.link_clock;
    let saved = e.io.inner.inner.regs[&root];
    for (addr, value) in [
        (mux(2), 0x202),
        (map(2), 2),
        (root, saved ^ 1),
        (at(2, 0x3623), 1),
        (at(1, 0x36b5), 1),
        (at(1, 0x36c5), 0x100),
    ] {
        for after_write in [false, true] {
            let (mut e, mut fw) = ready(2, 1);
            if after_write {
                e.io.inner.inner.after_write = Some((1, addr, value));
            } else {
                e.io.after_firmware = Some((addr, value));
            }
            assert!(run(e.disable_hpo_dp(&mut fw, path(2), DpSignal::Mst)).is_err());
            assert_eq!(e.io.inner.inner.writes.len(), usize::from(after_write));
            assert!(!e.status.state.reusable());
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-hpo-phy",
    dcn401_hpo_phy_firmware_errors_revocation_and_late_drift_quarantine
);

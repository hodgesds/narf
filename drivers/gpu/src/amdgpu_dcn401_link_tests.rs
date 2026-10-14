use super::*;
use crate::{amdgpu_dcn_inventory as inventory, amdgpu_dmub_navi48 as dmub};
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

fn dio(p: u8, reg: u64) -> u64 {
    BASE + (reg + u64::from(p) * 0x124) * 4
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
struct Firmware {
    completed: Arc<AtomicBool>,
    commands: Vec<inventory::Path>,
    ready: bool,
    pending: bool,
    error: Option<dmub::Error>,
    revoke: Option<Cap<BusDeviceCap, Write>>,
}
impl super::super::link::Firmware for Firmware {
    fn ready(&self) -> bool {
        self.ready
    }
    async fn disable(&mut self, path: inventory::Path) -> Result<(), dmub::Error> {
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
        self.completed.store(true, Ordering::SeqCst);
        Ok(())
    }
}
struct LinkIo {
    inner: Fake,
    completed: Arc<AtomicBool>,
    backend: u8,
    waiting: bool,
    delay: u8,
    stuck_enable: bool,
    stuck_clocks: u32,
}
impl Io for LinkIo {
    fn read(&mut self, at: u64) -> u32 {
        if self.completed.swap(false, Ordering::SeqCst) {
            self.waiting = true;
        }
        if self.waiting && at == dio(self.backend, 0x20bd) {
            if self.delay != 0 {
                self.delay -= 1;
            } else {
                self.waiting = false;
                self.inner.regs.insert(at, u32::from(self.stuck_enable));
                self.inner
                    .regs
                    .insert(dio(self.backend, 0x20bb), self.stuck_clocks);
            }
        }
        self.inner.read(at)
    }
    fn write(&mut self, at: u64, value: u32) {
        if [0x212e, 0x211e, 0x2125]
            .iter()
            .any(|r| at == dio(self.backend, *r))
        {
            assert!(!self.waiting);
            assert_eq!(self.inner.regs[&dio(self.backend, 0x20bd)] & 1, 0);
            assert_eq!(self.inner.regs[&dio(self.backend, 0x20bb)] & 0x3810, 0);
        }
        self.inner.write(at, value);
    }
}
fn fixture(p: u8, fe: u8) -> (Engine<LinkIo>, Firmware) {
    let mut e = engine();
    for (reg, value) in [(0x2094, 0x4c10), (0x2095, 1), (0x209b, 0x301), (0x2123, 6)] {
        e.io.regs.insert(dio(fe, reg), value);
    }
    for b in 0..4 {
        e.io.regs.insert(
            dio(b, 0x20bc),
            (u32::from(path(b).hpd - 1) << 28)
                | (0x100 << if b == p { fe } else { (fe + 1) % 4 })
                | 2,
        );
        e.io.regs
            .insert(dio(b, 0x20bb), if b == 0 { 0x3810 } else { 0x2810 });
        e.io.regs.insert(dio(b, 0x20bd), 1);
        e.io.regs.insert(dio(b, 0x212e), 0x103);
        e.io.regs.insert(dio(b, 0x211e), 0x110);
        e.io.regs.insert(dio(b, 0x2125), 0x111);
    }
    let completed = Arc::new(AtomicBool::new(false));
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
            io: LinkIo {
                inner: e.io,
                completed,
                backend: p,
                waiting: false,
                delay: 1,
                stuck_enable: false,
                stuck_clocks: 0,
            },
            authority: e.authority,
            layout: e.layout,
            status: e.status,
            displays: e.displays,
        },
        firmware,
    )
}

fn dcn401_sst_disable_resolves_board_routes_preserves_frontend_and_other_links() -> TestResult {
    for b in 0..4 {
        for fe in 0..4 {
            let (mut e, mut fw) = fixture(b, fe);
            let before = e.io.inner.regs.clone();
            let result = run(e.disable_dp_sst(&mut fw, path(b))).unwrap();
            assert_eq!(
                result,
                DpSstDisabled {
                    path: path(b),
                    frontend: fe,
                    command_sent: true
                }
            );
            assert_eq!(fw.commands, [path(b)]);
            assert_eq!(e.status.state, State::DpSstDisabled);
            assert_eq!(e.status.dp_sst_disabled, Some(result));
            assert_eq!(
                e.io.inner.writes,
                [
                    (dio(b, 0x212e), 0x100),
                    (dio(b, 0x211e), 0x100),
                    (dio(b, 0x2125), 0x100)
                ]
            );
            for (at, value) in before {
                if ![0x20bb, 0x20bd, 0x212e, 0x211e, 0x2125]
                    .iter()
                    .any(|r| at == dio(b, *r))
                {
                    assert_eq!(e.io.inner.regs[&at], value, "unrelated register {at:x}");
                }
            }
            // Backend-off now allows frontend retirement; the hardware model
            // still has the same frontend request/clock state until this call.
            run(e.retire_dp_encoder(DpStream::Dio(fe))).unwrap();
            assert_eq!(
                e.status.dp_encoder_retired.unwrap().detached_backends,
                1 << b
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-link",
    dcn401_sst_disable_resolves_board_routes_preserves_frontend_and_other_links
);

fn dcn401_sst_preflight_refuses_non_sst_live_packets_and_ambiguous_routes() -> TestResult {
    for (at, value) in [
        (dio(2, 0x20bb), 0x3813),
        (dio(2, 0x20bb), 0x3815),
        (dio(2, 0x20bb), 0x3830),
        (dio(2, 0x20bb), 0x3850),
        (dio(2, 0x20bb), 0x3800),
        (dio(2, 0x20bd), 0),
        (dio(2, 0x20bc), 0x30000000),
        (dio(2, 0x20bc), 0x30000300),
        (dio(2, 0x20bc), 0x30001000),
        (dio(2, 0x20bc), 0x30000201),
        (dio(2, 0x20bc), 0x20000200),
        (dio(2, 0x212d), 0x70),
        (dio(1, 0x2094), 0x15),
        (dio(1, 0x2094), 0),
        (dio(1, 0x2095), 0),
        (dio(1, 0x2123), 2),
        (dio(1, 0x2122), 0x10000),
        (dio(1, 0x2141), 1),
        (dio(1, 0x2091), 0x1000),
        (dio(1, 0x2177), 0x2000),
        (BASE + 0x369f * 4, 0x10),
        (BASE + 0x36b4 * 4, 1),
        (BASE + 0x36b5 * 4, 1),
        (MPC_BASE + 0x8df * 4, 1),
        (dio(2, 0x20bd), u32::MAX),
    ] {
        let (mut e, mut fw) = fixture(2, 1);
        e.io.inner.regs.insert(at, value);
        e.io.inner.dp_stall = 1 << 9; // retain injected incomplete steering reset
        assert!(
            run(e.disable_dp_sst(&mut fw, path(2))).is_err(),
            "accepted {at:x}={value:x}"
        );
        assert!(fw.commands.is_empty() && e.io.inner.writes.is_empty());
        assert_eq!(e.status.state, State::Ready);
    }
    for case in 0..7 {
        let (mut e, mut fw) = fixture(2, 1);
        let mut p = path(2);
        match case {
            0 => p.connector = inventory::Connector::HdmiTypeA,
            1 => p.connector = inventory::Connector::EmbeddedDisplayPort,
            2 => p.transmitter = 4,
            3 => p.hpd = 0,
            4 => p.hpd = 5,
            5 => fw.ready = false,
            _ => e.authority.revoke(),
        }
        assert!(run(e.disable_dp_sst(&mut fw, p)).is_err());
        assert!(fw.commands.is_empty() && e.io.inner.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-link",
    dcn401_sst_preflight_refuses_non_sst_live_packets_and_ambiguous_routes
);

fn dcn401_sst_disabled_links_do_not_reissue_phy_commands() -> TestResult {
    let (mut e, mut fw) = fixture(2, 1);
    e.io.inner.regs.insert(dio(2, 0x20bb), 0);
    e.io.inner.regs.insert(dio(2, 0x20bd), 0);
    let result = run(e.disable_dp_sst(&mut fw, path(2))).unwrap();
    assert!(!result.command_sent);
    assert!(e.io.inner.writes.is_empty() && fw.commands.is_empty());
    assert_eq!(run(e.disable_dp_sst(&mut fw, path(2))), Ok(result));
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-link",
    dcn401_sst_disabled_links_do_not_reissue_phy_commands
);

fn dcn401_sst_requires_hardware_off_after_firmware_consumes_disable() -> TestResult {
    for (enable, clocks) in [
        (true, 0),
        (false, 0x10),
        (false, 0x800),
        (false, 0x1000),
        (false, 0x2000),
    ] {
        let (mut e, mut fw) = fixture(0, 1);
        e.io.stuck_enable = enable;
        e.io.stuck_clocks = clocks;
        assert_eq!(
            run(e.disable_dp_sst(&mut fw, path(0))),
            Err(Error::Timeout(dio(0, if enable { 0x20bd } else { 0x20bb })))
        );
        assert_eq!(fw.commands.len(), 1);
        assert!(e.io.inner.writes.is_empty());
        assert!(!e.status.state.reusable());
        assert_eq!(run(e.disable_dp_sst(&mut fw, path(0))), Err(Error::Busy));
        assert_eq!(run(e.retire_dp_encoder(DpStream::Dio(1))), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-link",
    dcn401_sst_requires_hardware_off_after_firmware_consumes_disable
);

fn dcn401_sst_cancelled_firmware_or_hardware_wait_retains_owner() -> TestResult {
    for pending in [false, true] {
        let (mut e, mut fw) = fixture(2, 1);
        fw.pending = pending;
        e.io.stuck_enable = true; // cancellation must not depend on reads per poll
        {
            let mut future = core::pin::pin!(e.disable_dp_sst(&mut fw, path(2)));
            assert!(future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending());
        }
        assert_eq!(e.status.state, State::DisablingDpSst(2));
        assert!(e.status.dp_sst_disabled.is_none());
        assert_eq!(run(e.disable_dp_sst(&mut fw, path(2))), Err(Error::Busy));
        assert_eq!(run(e.retire_dp_encoder(DpStream::Dio(1))), Err(Error::Busy));
        assert!(e.io.inner.writes.is_empty());
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-link",
    dcn401_sst_cancelled_firmware_or_hardware_wait_retains_owner
);

fn dcn401_sst_failures_and_late_consumers_cannot_publish_success() -> TestResult {
    for case in 0..11 {
        let (mut e, mut fw) = fixture(2, 1);
        match case {
            0 => fw.error = Some(dmub::Error::CommandTimeout),
            1 => fw.revoke = Some(e.authority),
            2..=4 => e.io.inner.reject = Some(case - 1),
            5..=7 => e.io.inner.revoke = Some((case - 4, e.authority)),
            8 => e.io.inner.after_write = Some((3, dio(2, 0x20bc), 0x30000400)),
            9 => e.io.inner.after_write = Some((3, dio(1, 0x2122), 0x10000)),
            _ => e.io.inner.after_write = Some((3, dio(2, 0x20bd), 1)),
        }
        assert!(run(e.disable_dp_sst(&mut fw, path(2))).is_err());
        assert!(matches!(e.status.state, State::Failed(_)));
        assert!(e.status.dp_sst_disabled.is_none());
        assert_eq!(run(e.disable_dp_sst(&mut fw, path(2))), Err(Error::Busy));
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/dcn401-link",
    dcn401_sst_failures_and_late_consumers_cannot_publish_success
);

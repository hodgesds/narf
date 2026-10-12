use super::*;
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

fn run<T>(f: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(f)
}
fn report() -> Report {
    Report {
        smu: smu::Versions {
            firmware: 0x684c00,
            interface: 0x2e,
        },
        graphics: psp::GfxBootStatus {
            cp_stat: 0,
            rlc_bootload: 1 << 31,
        },
        power: smu::PowerStatus {
            allowed: 1,
            enabled: 1,
            gfx_min_mhz: 500,
            gfx_max_mhz: 3100,
        },
        media: psp::MediaFirmware {
            vcn: Some(0x800100000),
            dmcub: Some(0x800200000),
        },
    }
}
struct FakeBoot {
    log: Vec<Stage>,
    fail: Option<Stage>,
    stall: Option<Stage>,
}
impl Backend for FakeBoot {
    async fn step(&mut self, stage: Stage) -> Result<(), Error> {
        self.log.push(stage);
        if self.stall == Some(stage) {
            core::future::pending::<()>().await;
        }
        if self.fail == Some(stage) {
            Err(Error::Invalid)
        } else {
            Ok(())
        }
    }
    fn report(&self) -> Result<Report, Error> {
        Ok(report())
    }
}
fn sequence(fail: Option<Stage>, stall: Option<Stage>) -> Sequence<FakeBoot> {
    Sequence {
        backend: FakeBoot {
            log: Vec::new(),
            fail,
            stall,
        },
        state: State::Prepared,
    }
}
fn navi48_boot_order_failure_and_cancellation() -> TestResult {
    let mut s = sequence(None, None);
    if run(s.run()) != Ok(report()) || s.backend.log != STAGES || s.state != State::FirmwareReady {
        return TestResult::Fail("Navi48 firmware boot order/report");
    }
    if run(s.run()) != Err(Error::Busy) || s.backend.log.len() != STAGES.len() {
        return TestResult::Fail("completed cold boot replayed");
    }
    for (i, stage) in STAGES.into_iter().enumerate() {
        let mut s = sequence(Some(stage), None);
        if run(s.run()) != Err(Error::Invalid)
            || s.state != State::Failed(stage, Error::Invalid)
            || s.backend.log != STAGES[..=i]
            || run(s.run()) != Err(Error::Busy)
        {
            return TestResult::Fail("failed stage continued or replayed");
        }
        let mut s = sequence(None, Some(stage));
        {
            let mut f = core::pin::pin!(s.run());
            if f.as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("blocked stage completed");
            }
        }
        if s.state != State::Running(stage)
            || s.backend.log != STAGES[..=i]
            || run(s.run()) != Err(Error::Busy)
        {
            return TestResult::Fail("cancelled cold boot continued or replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48_boot",
    navi48_boot_order_failure_and_cancellation
);

struct Display {
    regs: [u32; 0x201],
    writes: Vec<(u32, u32)>,
    ack: bool,
    pwait: bool,
    ignore_reset: bool,
}
impl Display {
    fn new(running: bool) -> Self {
        let mut regs = [0; 0x201];
        regs[0x1f6] = if running { 1 << 16 } else { 0 };
        for r in 0x1af..=0x1b4 {
            regs[r] = 0x80003456;
        }
        Self {
            regs,
            writes: Vec::new(),
            ack: true,
            pwait: true,
            ignore_reset: false,
        }
    }
}
impl DisplayIo for Display {
    fn read(&mut self, r: u32) -> u32 {
        self.regs[r as usize]
    }
    fn write(&mut self, r: u32, v: u32) {
        self.writes.push((r, v));
        if r == 0x200 && self.ignore_reset {
            return;
        }
        self.regs[r as usize] = v;
        if r == 0x1f8 && v == 0x10020000 {
            self.regs[0x1ea] = 0xdeaddead;
            if self.ack {
                self.regs[0x1f8] = 0x20000;
            }
            if self.pwait {
                self.regs[0x1f6] |= 1 << 20;
            }
        }
    }
}
fn navi48_dmub_stop_preserves_secure_windows_and_uses_cntl2() -> TestResult {
    for running in [false, true] {
        let mut d = Display::new(running);
        if run(stop_dmub(&mut d, &Cap::bootstrap())).is_err() {
            return TestResult::Fail("DCN4 stop/reset failed");
        }
        if d.regs[0x200] & 1 == 0
            || d.regs[0x1f6] & ((1 << 16) | (1 << 17)) != 0
            || d.regs[0x1af..=0x1b4] != [0x3456; 6]
            || d.writes.iter().any(|(r, _)| {
                !matches!(
                    *r,
                    0x1af
                        ..=0x1b4
                            | 0x1d6
                            | 0x1d7
                            | 0x1da
                            | 0x1db
                            | 0x1de
                            | 0x1df
                            | 0x1e3
                            | 0x1f6
                            | 0x1f8
                            | 0x200
                )
            })
        {
            return TestResult::Fail("DCN4 reset touched secure/unrelated registers");
        }
        let reset = d.writes.iter().position(|(r, _)| *r == 0x200).unwrap();
        let disable = d.writes.iter().position(|(r, _)| *r == 0x1f6).unwrap();
        let windows = d.writes.iter().position(|(r, _)| *r == 0x1af).unwrap();
        if reset >= disable || disable >= windows {
            return TestResult::Fail("DCN4 reset/disable/window order");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48_boot",
    navi48_dmub_stop_preserves_secure_windows_and_uses_cntl2
);

fn navi48_dmub_stop_requires_ack_idle_authority_and_readback() -> TestResult {
    for (ack, pwait) in [(false, true), (true, false)] {
        let mut d = Display::new(true);
        d.ack = ack;
        d.pwait = pwait;
        if run(stop_dmub(&mut d, &Cap::bootstrap())) != Err(Error::DmubTimeout)
            || d.writes != [(0x1f8, 0x10020000)]
        {
            return TestResult::Fail("unacknowledged or non-idle DMUB reset");
        }
    }
    let mut d = Display::new(true);
    d.ack = false;
    let cap = Cap::bootstrap();
    {
        let mut f = core::pin::pin!(stop_dmub(&mut d, &cap));
        if f.as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("stop wait did not yield");
        }
        cap.revoke();
        if run(f) != Err(Error::Revoked) {
            return TestResult::Fail("revoked DMUB wait continued");
        }
    }
    if d.writes != [(0x1f8, 0x10020000)] {
        return TestResult::Fail("writes after revocation");
    }
    let mut d = Display::new(false);
    d.ignore_reset = true;
    if run(stop_dmub(&mut d, &Cap::bootstrap())) != Err(Error::DmubReadback)
        || d.writes.iter().any(|(r, _)| *r == 0x1af)
    {
        return TestResult::Fail("windows changed before reset readback");
    }
    let mut d = Display::new(false);
    d.regs[0x1f6] = u32::MAX;
    if run(stop_dmub(&mut d, &Cap::bootstrap())) != Err(Error::DeviceGone) || !d.writes.is_empty() {
        return TestResult::Fail("missing device wrote registers");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/navi48_boot",
    navi48_dmub_stop_requires_ack_idle_authority_and_readback
);

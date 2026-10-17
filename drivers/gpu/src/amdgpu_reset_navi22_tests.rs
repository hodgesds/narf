use super::*;
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    SaveQuiesce,
    Restore,
    Mp0(u32, u32),
    Mp1(u32, u32),
    Scratch(u32),
}

/// One posted Navi22: running SOS/PMFW until a mode1 reset drops config
/// space; restore brings decoding back and the bootloader up after polls.
struct Fake {
    sos: u32,
    smu_version: Option<u32>,
    mode1_status: u32,
    tos: u32,
    bootloader_polls: usize,
    memsize: u32,
    scratch: u32,
    decoding: bool,
    reset: bool,
    pending: Option<u32>,
    stray: usize,
    save_error: bool,
    restore_error: bool,
    events: Vec<Event>,
}
impl Fake {
    fn posted() -> Self {
        Self {
            sos: 0x0004_0021,
            smu_version: Some(0x003a_4f00),
            mode1_status: 1,
            tos: READY,
            bootloader_polls: 3,
            memsize: 12 << 10,
            scratch: 0x10,
            decoding: true,
            reset: false,
            pending: None,
            stray: 0,
            save_error: false,
            restore_error: false,
            events: Vec::new(),
        }
    }
    fn decode(&mut self) -> bool {
        if !self.decoding {
            self.stray += 1;
        }
        self.decoding
    }
}
impl Io for Fake {
    fn mp0(&mut self, register: u32) -> u32 {
        if !self.decode() {
            return u32::MAX;
        }
        match register {
            SOS if self.reset => 0,
            SOS => self.sos,
            TOS => self.tos,
            BOOTLOADER if self.reset && self.bootloader_polls == 0 => READY | 0x7f0000,
            BOOTLOADER if self.reset => {
                self.bootloader_polls -= 1;
                0
            }
            BOOTLOADER => READY,
            _ => 0,
        }
    }
    fn set_mp0(&mut self, register: u32, value: u32) {
        if !self.decode() {
            return;
        }
        self.events.push(Event::Mp0(register, value));
        if register == TOS && value == GFX_CTRL_CMD_ID_MODE1_RST {
            self.decoding = false;
            self.reset = true;
        }
    }
    fn mp1(&mut self, register: u32) -> u32 {
        if !self.decode() {
            return u32::MAX;
        }
        match (register, self.pending) {
            (RESPONSE, Some(GET_SMU_VERSION)) => {
                if self.smu_version.is_some() {
                    1
                } else {
                    0xfe
                }
            }
            (RESPONSE, Some(MODE1_RESET)) => {
                if self.mode1_status == 1 {
                    // Acknowledged, then the ASIC drops off the bus.
                    self.pending = None;
                    self.decoding = false;
                    self.reset = true;
                    return 1;
                }
                self.mode1_status
            }
            (ARGUMENT, Some(GET_SMU_VERSION)) => self.smu_version.unwrap_or(0),
            _ => 0,
        }
    }
    fn set_mp1(&mut self, register: u32, value: u32) {
        if !self.decode() {
            return;
        }
        self.events.push(Event::Mp1(register, value));
        if register == MESSAGE {
            self.pending = Some(value);
        }
    }
    fn scratch(&mut self) -> u32 {
        if !self.decode() {
            return u32::MAX;
        }
        self.scratch
    }
    fn set_scratch(&mut self, value: u32) {
        if !self.decode() {
            return;
        }
        self.events.push(Event::Scratch(value));
        self.scratch = value;
    }
    fn memsize(&mut self) -> u32 {
        if !self.decode() {
            return u32::MAX;
        }
        self.memsize
    }
    fn save_and_quiesce(&mut self, authority: &Cap<BusDeviceCap, Write>) -> Result<(), Error> {
        authority.check_live().map_err(|_| Error::Revoked)?;
        self.events.push(Event::SaveQuiesce);
        if self.save_error {
            return Err(Error::Pci);
        }
        Ok(())
    }
    fn restore(&mut self, authority: &Cap<BusDeviceCap, Write>) -> Result<(), Error> {
        authority.check_live().map_err(|_| Error::Revoked)?;
        self.events.push(Event::Restore);
        if self.restore_error {
            return Err(Error::Pci);
        }
        self.decoding = true;
        Ok(())
    }
}
fn engine(io: Fake) -> Engine<Fake> {
    Engine {
        io,
        authority: Cap::bootstrap(),
        state: State::Prepared,
        mode: Mode::OnInit,
    }
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

fn reset_navi22_cold_card_is_left_untouched() -> TestResult {
    let mut e = engine(Fake {
        sos: 0,
        ..Fake::posted()
    });
    if run(e.run()) != Ok(None) || e.state != State::NotRequired || !e.io.events.is_empty() {
        return TestResult::Fail("cold card was reset or written");
    }
    if run(e.run()) != Err(Error::Busy) {
        return TestResult::Fail("reset decision replayed");
    }
    let mut e = engine(Fake {
        sos: u32::MAX,
        ..Fake::posted()
    });
    if run(e.run()) != Err(Error::DeviceGone) || !e.io.events.is_empty() {
        return TestResult::Fail("absent device accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    reset_navi22_cold_card_is_left_untouched
);

fn reset_navi22_smu_mode1_follows_linux_order() -> TestResult {
    let mut e = engine(Fake::posted());
    let report = match run(e.run()) {
        Ok(Some(report)) => report,
        other => {
            let _ = other;
            return TestResult::Fail("posted card did not complete a mode1 reset");
        }
    };
    if report.method != Method::Smu
        || report.smu_version != Some(0x003a_4f00)
        || report.sos_before != 0x0004_0021
        || report.sos_after != 0
        || report.memsize != 12 << 10
        || e.state != State::Complete(report)
    {
        return TestResult::Fail("wrong reset evidence");
    }
    let expected = vec![
        Event::Scratch(0x10 | ATOM_S3_ASIC_GUI_ENGINE_HUNG),
        Event::SaveQuiesce,
        Event::Mp1(RESPONSE, 0),
        Event::Mp1(ARGUMENT, 0),
        Event::Mp1(MESSAGE, GET_SMU_VERSION),
        Event::Mp1(RESPONSE, 0),
        Event::Mp1(ARGUMENT, 0),
        Event::Mp1(MESSAGE, MODE1_RESET),
        Event::Restore,
        Event::Scratch(0x10),
    ];
    if e.io.events != expected {
        return TestResult::Fail("reset sequence differs from amdgpu_device_mode1_reset");
    }
    if e.io.stray != 0 {
        return TestResult::Fail("MMIO issued while config space was reset");
    }
    if run(e.run()) != Err(Error::Busy) {
        return TestResult::Fail("completed reset replayed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    reset_navi22_smu_mode1_follows_linux_order
);

fn reset_navi22_old_or_silent_pmfw_uses_psp_mode1() -> TestResult {
    for version in [Some(0x003a_19ff), None] {
        let mut e = engine(Fake {
            smu_version: version,
            ..Fake::posted()
        });
        let report = match run(e.run()) {
            Ok(Some(report)) => report,
            _ => return TestResult::Fail("PSP mode1 reset failed"),
        };
        if report.method != Method::Psp || report.smu_version != version {
            return TestResult::Fail("PMFW below 58.26 used SMU mode1");
        }
        if !e
            .io
            .events
            .contains(&Event::Mp0(TOS, GFX_CTRL_CMD_ID_MODE1_RST))
            || e.io.events.contains(&Event::Mp1(MESSAGE, MODE1_RESET))
            || e.io.stray != 0
        {
            return TestResult::Fail("wrong PSP mode1 command or MMIO during reset");
        }
    }
    let mut e = engine(Fake {
        smu_version: Some(0x0030_0000),
        tos: 0x0000_0001,
        ..Fake::posted()
    });
    if run(e.run()) != Err(Error::PspNotReady(1))
        || e.state != State::Failed
        || e.io
            .events
            .iter()
            .any(|event| matches!(event, Event::Mp0(..)))
    {
        return TestResult::Fail("PSP mode1 sent without TOS ready");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    reset_navi22_old_or_silent_pmfw_uses_psp_mode1
);

fn reset_navi22_failures_are_terminal() -> TestResult {
    let mut e = engine(Fake {
        mode1_status: 0xfd,
        ..Fake::posted()
    });
    if run(e.run()) != Err(Error::Rejected(0xfd))
        || e.state != State::Failed
        || e.io
            .events
            .contains(&Event::Mp0(TOS, GFX_CTRL_CMD_ID_MODE1_RST))
        || e.io.events.contains(&Event::Restore)
    {
        return TestResult::Fail("rejected SMU mode1 fell back or restored config");
    }
    if run(e.run()) != Err(Error::Busy) {
        return TestResult::Fail("failed reset replayed");
    }
    let mut e = engine(Fake {
        save_error: true,
        ..Fake::posted()
    });
    if run(e.run()) != Err(Error::Pci) || e.io.events.iter().any(|ev| matches!(ev, Event::Mp1(..)))
    {
        return TestResult::Fail("reset issued without cached config space");
    }
    let mut e = engine(Fake {
        restore_error: true,
        ..Fake::posted()
    });
    if run(e.run()) != Err(Error::Pci) || e.state != State::Failed {
        return TestResult::Fail("unrestored config space accepted");
    }
    let mut e = engine(Fake {
        bootloader_polls: usize::MAX,
        ..Fake::posted()
    });
    if run(e.run()) != Err(Error::Timeout) || e.state != State::Failed {
        return TestResult::Fail("bootloader wait lacked a bound");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    reset_navi22_failures_are_terminal
);

fn reset_navi22_cancellation_and_revocation() -> TestResult {
    let mut e = engine(Fake::posted());
    {
        let mut future = core::pin::pin!(e.run());
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("reset completed without settling");
        }
    }
    let events = e.io.events.len();
    if e.state != State::Resetting
        || run(e.run()) != Err(Error::Busy)
        || e.io.events.len() != events
    {
        return TestResult::Fail("cancelled reset replayed");
    }
    let mut e = engine(Fake::posted());
    e.authority.revoke();
    if run(e.run()) != Err(Error::Revoked) || !e.io.events.is_empty() {
        return TestResult::Fail("revoked authority touched the device");
    }
    let mut e = engine(Fake::posted());
    let authority = e.authority;
    {
        let mut future = core::pin::pin!(e.run());
        let _ = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        authority.revoke();
        if run(future) != Err(Error::Revoked) {
            return TestResult::Fail("revocation during settle ignored");
        }
    }
    if e.io.events.contains(&Event::Restore) {
        return TestResult::Fail("config restored after revocation");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    reset_navi22_cancellation_and_revocation
);

fn reset_navi22_recovery_mode_always_resets() -> TestResult {
    // Recovery never takes the cold-card shortcut, and runs the same core.
    let mut e = engine(Fake {
        sos: 0,
        ..Fake::posted()
    });
    e.mode = Mode::Recovery;
    match run(e.run()) {
        Ok(Some(report)) if report.method == Method::Smu && report.sos_before == 0 => {}
        _ => return TestResult::Fail("recovery skipped or failed the mode1 reset"),
    }
    if e.io.events.first() != Some(&Event::Scratch(0x10 | ATOM_S3_ASIC_GUI_ENGINE_HUNG))
        || !e.io.events.contains(&Event::Restore)
        || e.io.stray != 0
    {
        return TestResult::Fail("recovery reset sequence");
    }
    if run(e.run()) != Err(Error::Busy) {
        return TestResult::Fail("recovery reset replayed");
    }
    let mut e = engine(Fake {
        sos: u32::MAX,
        ..Fake::posted()
    });
    e.mode = Mode::Recovery;
    if run(e.run()) != Err(Error::DeviceGone) || !e.io.events.is_empty() {
        return TestResult::Fail("lost device reset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    reset_navi22_recovery_mode_always_resets
);

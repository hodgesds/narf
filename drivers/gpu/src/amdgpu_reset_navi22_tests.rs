use super::*;
use alloc::{collections::BTreeMap, vec, vec::Vec};
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
    Reg(u32, u32),
}

/// FirmwareInfo's bios_scratch_reg_startaddr in the synthetic image.
const SCRATCH: u32 = 0x4c;
const S3: u32 = SCRATCH + 3;
const S7: u32 = SCRATCH + 7;
const SCLK: u32 = 0x0001_d4c0;
const MCLK: u32 = 0x0002_bf20;

const ROM: usize = 0x100;
const CMD_DIR: usize = 0x200;
const DATA_DIR: usize = 0x300;
const FWI: usize = 0x400;
const IIO: usize = 0x480;
const ASIC_INIT_AT: usize = 0x500;

/// A VBIOS whose ASIC_Init (command table 0) stores PS[0]/PS[1], writes one
/// register through an IIO index/data program, delays 1 ms, calls an absent
/// table and finally ORs ATOM_S7_ASIC_INIT_COMPLETE into BIOS_SCRATCH_7's
/// second byte. `body` replaces that bytecode.
fn vbios(body: Option<&[u8]>) -> Vec<u8> {
    let mut image = vec![0u8; 0x800];
    image[..2].copy_from_slice(&[0x55, 0xaa]);
    image[0x48..0x4a].copy_from_slice(&(ROM as u16).to_le_bytes());
    image[ROM..ROM + 4].copy_from_slice(&[36, 0, 1, 1]);
    image[ROM + 4..ROM + 8].copy_from_slice(b"ATOM");
    image[ROM + 0x1e..ROM + 0x20].copy_from_slice(&(CMD_DIR as u16).to_le_bytes());
    image[ROM + 0x20..ROM + 0x22].copy_from_slice(&(DATA_DIR as u16).to_le_bytes());
    image[CMD_DIR..CMD_DIR + 2].copy_from_slice(&((4 + 2 * 81) as u16).to_le_bytes());
    image[CMD_DIR + 4..CMD_DIR + 6].copy_from_slice(&(ASIC_INIT_AT as u16).to_le_bytes());
    image[DATA_DIR..DATA_DIR + 2].copy_from_slice(&((4 + 2 * 34) as u16).to_le_bytes());
    for (index, at) in [(4usize, FWI), (23, IIO)] {
        image[DATA_DIR + 4 + 2 * index..DATA_DIR + 6 + 2 * index]
            .copy_from_slice(&(at as u16).to_le_bytes());
    }
    image[FWI..FWI + 4].copy_from_slice(&[0x50, 0, 3, 4]);
    image[FWI + 8..FWI + 12].copy_from_slice(&SCLK.to_le_bytes());
    image[FWI + 12..FWI + 16].copy_from_slice(&MCLK.to_le_bytes());
    image[FWI + 0x18..FWI + 0x1c].copy_from_slice(&SCRATCH.to_le_bytes());
    #[rustfmt::skip]
    let iio = [
        1, 0x81,             // IIO_START write program for port 1
        6, 32, 0, 0,         // MOVE_INDEX: temp = index
        3, 0x0e, 0x00,       // WRITE index register
        8, 32, 0, 0,         // MOVE_DATA: temp = data
        3, 0x0f, 0x00,       // WRITE data register
        9, 0, 0,             // END
    ];
    image[IIO + 4..IIO + 4 + iio.len()].copy_from_slice(&iio);
    #[rustfmt::skip]
    let init: &[u8] = &[
        1, 0x01, 0x00, 0x30, 0,                 // REG[0x3000] <- PS[0]
        1, 0x01, 0x01, 0x30, 1,                 // REG[0x3001] <- PS[1]
        55, 1, 0,                               // SET_ATI_PORT 1
        1, 0x05, 0x34, 0x12, 0xcd, 0xab, 0, 0,  // REG[0x1234] <- 0xabcd (IIO)
        55, 0, 0,                               // SET_ATI_PORT MM
        80, 1,                                  // DELAY_MILLISEC 1
        82, 5,                                  // CALL_TABLE 5 (absent)
        13, 0x65, S7 as u8, 0, 0x02,            // OR REG[S7].[15:8] |= 2
        91,
    ];
    let code = body.unwrap_or(init);
    let at = ASIC_INIT_AT;
    image[at..at + 2].copy_from_slice(&((6 + code.len()) as u16).to_le_bytes());
    image[at + 2..at + 4].copy_from_slice(&[2, 1]);
    image[at + 4] = 2; // WS
    image[at + 5] = 8; // PS bytes
    image[at + 6..at + 6 + code.len()].copy_from_slice(code);
    image
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
    scratch7: u32,
    /// Mode1 reset clears BIOS_SCRATCH_7 (and with it ASIC_INIT_COMPLETE).
    clears_s7: bool,
    regs: BTreeMap<u32, u32>,
    clock: u64,
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
            scratch7: 0x0001_0205,
            clears_s7: true,
            regs: BTreeMap::new(),
            clock: 0,
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
        if register == 0x76 {
            self.decoding = false;
            self.reset = true;
        }
    }
    fn reg(&mut self, dword: u32) -> u32 {
        if !self.decode() {
            return u32::MAX;
        }
        match dword {
            S3 => self.scratch,
            S7 => self.scratch7,
            _ => *self.regs.get(&dword).unwrap_or(&0),
        }
    }
    fn set_reg(&mut self, dword: u32, value: u32) {
        if !self.decode() {
            return;
        }
        self.events.push(Event::Reg(dword, value));
        match dword {
            S3 => self.scratch = value,
            S7 => self.scratch7 = value,
            _ => {
                self.regs.insert(dword, value);
            }
        }
    }
    fn now_ms(&mut self) -> u64 {
        self.clock += 1;
        self.clock
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
        if self.clears_s7 {
            self.scratch7 = 0x0001_0005;
        }
        Ok(())
    }
}
fn engine(io: Fake) -> Engine<Fake> {
    Engine {
        io,
        authority: Cap::bootstrap(),
        state: State::Prepared,
        mode: Mode::OnInit,
        navi48: false,
        vbios: Some(vbios(None)),
        scratch: SCRATCH,
        post: None,
    }
}
/// The register writes ASIC_Init makes on the synthetic VBIOS.
fn asic_init_writes() -> Vec<Event> {
    vec![
        Event::Reg(0x3000, SCLK),
        Event::Reg(0x3001, MCLK),
        Event::Reg(0x0e, 0x1234),
        Event::Reg(0x0f, 0xabcd),
        Event::Reg(S7, 0x0001_0205),
    ]
}
fn run<T>(future: impl Future<Output = T>) -> T {
    narf_scheduler::block_on_spin(future)
}

fn reset_navi22_cold_card_is_left_untouched() -> TestResult {
    // A GOP-posted cold card: SOS idle, ASIC_INIT_COMPLETE set. Neither
    // reset nor post (amdgpu_device_need_post is false).
    let mut e = engine(Fake {
        sos: 0,
        ..Fake::posted()
    });
    if run(e.run()) != Ok(None) || e.state != State::NotRequired || !e.io.events.is_empty() {
        return TestResult::Fail("cold card was reset or written");
    }
    match e.post {
        Some(post) if !post.ran && post.scratch7_before == 0x0001_0205 => {}
        _ => return TestResult::Fail("cold post decision not recorded"),
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
    let post = report.post;
    if !post.ran
        || post.scratch_base != SCRATCH
        || post.scratch7_before != 0x0001_0005
        || post.scratch7_after != 0x0001_0205
        || (post.sclk, post.mclk) != (SCLK, MCLK)
        || post.writes != 5
        || post.delay_us != 1000
        || post.anomalies != 0
    {
        return TestResult::Fail("ASIC_Init evidence after the reset");
    }
    let expected = [
        Event::Reg(S3, 0x10 | ATOM_S3_ASIC_GUI_ENGINE_HUNG),
        Event::SaveQuiesce,
        Event::Mp1(RESPONSE, 0),
        Event::Mp1(ARGUMENT, 0),
        Event::Mp1(MESSAGE, GET_SMU_VERSION),
        Event::Mp1(RESPONSE, 0),
        Event::Mp1(ARGUMENT, 0),
        Event::Mp1(MESSAGE, MODE1_RESET),
        Event::Restore,
        Event::Reg(S3, 0x10),
    ]
    .into_iter()
    .chain(asic_init_writes())
    .collect::<Vec<_>>();
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
    // A bootloader that needs ~2.5 s after the reset (one poll per ms) is
    // inside psp_v11_0_wait_for_bootloader's 20 x usec_timeout polls; the
    // old 2 s bound failed it.
    let mut e = engine(Fake {
        bootloader_polls: 2500,
        ..Fake::posted()
    });
    if BOOTLOADER_MS < crate::amdgpu_psp_boot::PSP11_BOOTLOADER_TIMEOUT_MS || run(e.run()).is_err()
    {
        return TestResult::Fail("post-reset bootloader wait shorter than Linux's PSP11 bound");
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
        clears_s7: false,
        ..Fake::posted()
    });
    e.mode = Mode::Recovery;
    // amdgpu_device_reinit_after_reset posts after every full reset, even
    // if BIOS_SCRATCH_7 survived.
    match run(e.run()) {
        Ok(Some(report))
            if report.method == Method::Smu && report.sos_before == 0 && report.post.ran => {}
        _ => return TestResult::Fail("recovery skipped or failed the mode1 reset"),
    }
    if e.io.events.first() != Some(&Event::Reg(S3, 0x10 | ATOM_S3_ASIC_GUI_ENGINE_HUNG))
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

fn reset_navi22_cold_card_without_init_complete_is_posted() -> TestResult {
    // amdgpu_device_need_post runs even when no reset was needed.
    let mut e = engine(Fake {
        sos: 0,
        scratch7: 0x0001_0005,
        ..Fake::posted()
    });
    if run(e.run()) != Ok(None) || e.state != State::NotRequired {
        return TestResult::Fail("cold unposted card");
    }
    if e.io.events != asic_init_writes() {
        return TestResult::Fail("cold card must post without a reset");
    }
    match e.post {
        Some(post) if post.ran && post.scratch7_after & ATOM_S7_ASIC_INIT_COMPLETE != 0 => {}
        _ => return TestResult::Fail("post evidence"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    reset_navi22_cold_card_without_init_complete_is_posted
);

fn reset_navi22_post_failures_are_terminal() -> TestResult {
    type Case = (Option<Vec<u8>>, fn(Error) -> bool);
    let cases: [Case; 2] = [
        // atom.c's 20 s same-jump guard on a table that never finishes.
        (Some(vbios(Some(&[67, 6, 0]))), |error| {
            matches!(
                error,
                Error::Post(PostError::Atom {
                    error: AtomError::Stuck,
                    ..
                })
            )
        }),
        (None, |error| error == Error::Post(PostError::NoVbios)),
    ];
    for (image, expected) in cases {
        let mut e = engine(Fake::posted());
        e.vbios = image;
        match run(e.run()) {
            Err(error) if expected(error) => {}
            _ => return TestResult::Fail("post failure not reported"),
        }
        if e.state != State::Failed || run(e.run()) != Err(Error::Busy) {
            return TestResult::Fail("failed post replayed");
        }
    }
    // FirmwareInfo without default clocks: amdgpu_atom_asic_init returns 1.
    let mut image = vbios(None);
    image[FWI + 8..FWI + 12].fill(0);
    let mut e = engine(Fake::posted());
    e.vbios = Some(image);
    if run(e.run()) != Err(Error::Post(PostError::NoClocks)) {
        return TestResult::Fail("missing default sclk accepted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    reset_navi22_post_failures_are_terminal
);

/// amdgpu_atomfirmware_asic_init returns amdgpu_atom_execute_table's result
/// and never re-reads BIOS_SCRATCH_7; atom.c ends a table at a bad opcode
/// with success. Both complete the post (logged), they do not fail it.
fn reset_navi22_post_completes_like_linux_without_s7_recheck() -> TestResult {
    // ASIC_Init returned without setting ASIC_INIT_COMPLETE.
    let mut e = engine(Fake::posted());
    e.vbios = Some(vbios(Some(&[91])));
    let report = match run(e.run()) {
        Ok(Some(report)) => report,
        _ => return TestResult::Fail("post failed on a clear S7 bit Linux never re-reads"),
    };
    if !matches!(e.state, State::Complete(_))
        || !report.post.ran
        || report.post.scratch7_after & ATOM_S7_ASIC_INIT_COMPLETE != 0
    {
        return TestResult::Fail("post evidence for a clear S7 bit");
    }
    // A table the VM cannot decode ends there (atom.c `else break;`).
    let mut e = engine(Fake::posted());
    e.vbios = Some(vbios(Some(&[0x7f, 91])));
    match run(e.run()) {
        Ok(Some(report))
            if report.post.anomalies == 1
                && report.post.first_anomaly == Some(Anomaly::BadOpcode(0x7f)) => {}
        _ => return TestResult::Fail("bad opcode aborted the post"),
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    reset_navi22_post_completes_like_linux_without_s7_recheck
);

fn reset_navi22_post_cancellation_and_revocation() -> TestResult {
    // A cold unposted card whose ASIC_Init begins with a 200 ms delay: the
    // first poll stops inside the post's cooperative sleep.
    let delayed = || {
        let mut e = engine(Fake {
            sos: 0,
            scratch7: 0,
            ..Fake::posted()
        });
        e.vbios = Some(vbios(Some(&[80, 200, 91])));
        e
    };
    let mut e = delayed();
    {
        let mut future = core::pin::pin!(e.run());
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("post finished without sleeping");
        }
    }
    if e.state != State::Posting || run(e.run()) != Err(Error::Busy) {
        return TestResult::Fail("cancelled post replayed");
    }
    let mut e = delayed();
    let authority = e.authority;
    {
        let mut future = core::pin::pin!(e.run());
        let _ = future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        authority.revoke();
        if run(future) != Err(Error::Revoked) {
            return TestResult::Fail("revocation during post ignored");
        }
    }
    if e.state != State::Failed {
        return TestResult::Fail("revoked post state");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/amdgpu/navi22",
    reset_navi22_post_cancellation_and_revocation
);

fn navi48_mode1_uses_debug_mailbox_then_pci_restore_and_atom_post() -> TestResult {
    let mut e = engine(Fake::posted());
    e.navi48 = true;
    e.mode = Mode::Recovery;
    let result = narf_scheduler::block_on_spin(e.run());
    if !matches!(
        result,
        Ok(Some(Report {
            method: Method::Smu,
            smu_version: None,
            post: Post { ran: true, .. },
            ..
        }))
    ) {
        return TestResult::Fail("Navi48 mode1 reset/post failed");
    }
    let messages: Vec<_> =
        e.io.events
            .iter()
            .filter(|e| matches!(e, Event::Mp1(..)))
            .copied()
            .collect();
    if messages
        != [
            Event::Mp1(0x75, 0),
            Event::Mp1(0x8b, 2),
            Event::Mp1(0x76, 0),
        ]
        || e.io.stray != 0
    {
        return TestResult::Fail("SMU14 mailbox order or MMIO before PCI restore");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/reset_navi22",
    navi48_mode1_uses_debug_mailbox_then_pci_restore_and_atom_post
);

fn navi48_mode1_cancellation_and_restore_failure_are_terminal() -> TestResult {
    for restore_error in [false, true] {
        let mut e = engine(Fake::posted());
        e.navi48 = true;
        e.mode = Mode::Recovery;
        e.io.restore_error = restore_error;
        if restore_error {
            if run(e.run()) != Err(Error::Pci) || e.state != State::Failed {
                return TestResult::Fail("reset continued after PCI restore failed");
            }
        } else {
            let mut future = core::pin::pin!(e.run());
            if future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_ready()
            {
                return TestResult::Fail("SMU14 reset omitted its settling wait");
            }
        }
        let writes = e.io.events.len();
        if e.io.stray != 0 || run(e.run()) != Err(Error::Busy) || e.io.events.len() != writes {
            return TestResult::Fail(
                "canceled/failed SMU14 reset retried or accessed missing BARs",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/gpu/reset_navi22",
    navi48_mode1_cancellation_and_restore_failure_are_terminal
);

use super::*;
use crate::rtw89::{
    fw::FwError,
    prepared::{self, Files, PreparedFirmware},
    secure::{Blacklist, Fuses},
};
use alloc::{vec, vec::Vec};
use core::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
fn put(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}
struct File(Vec<u8>);
impl Files for File {
    fn load(&mut self, _: &'static str) -> Result<Vec<u8>, FwError> {
        Ok(self.0.clone())
    }
}
fn prepare(bytes: Vec<u8>, chip: ChipId) -> PreparedFirmware {
    prepared::load(&mut File(bytes), chip, 1).unwrap()
}
// Independent literal packed layouts from Linux fw.h, not parser constants.
fn firmware(version: u8, security: usize, formatted: bool) -> Vec<u8> {
    let base = if version == 0 { 32 } else { 48 };
    let mut image = vec![0; base + 16 * (security + 1)];
    put(&mut image, 12, u32::from(version) << 24);
    put(&mut image, 24, ((security + 1) as u32) << 8);
    put(&mut image, 28, 0x8765);
    for index in 0..security {
        let descriptor = base + index * 16;
        put(&mut image, descriptor, 0x0010_0000 + index as u32 * 0x1000);
        put(&mut image, descriptor + 4, 0x0900_03c0);
        put(&mut image, descriptor + 8, if formatted { 255 } else { 2 });
        let content = image.len();
        image.resize(content + 960, 0x99);
        image[content + 32] = index as u8;
        image[content + 33] = 0;
        image[content + 58..content + 62].fill(0);
        if formatted {
            let pool = image.len();
            image.resize(pool + 32 + 256 + 2 * 512, 0);
            image[pool..pool + 8].copy_from_slice(b"MSSKPOOL");
            put(&mut image, pool + 8, 32);
            put(&mut image, pool + 12, 288);
            image[pool + 21] = 4;
            image[pool + 22..pool + 24].copy_from_slice(&2u16.to_le_bytes());
            image[pool + 24..pool + 26].copy_from_slice(&32u16.to_le_bytes());
            image[pool + 26..pool + 28].copy_from_slice(&16u16.to_le_bytes());
            // FuseFC:EF -> device0, customer0, key0. The first candidate's
            // bitmap doesn't match; the second matches at packed rank0.
            image[pool + 32] = if index == 0 { 0x82 } else { 0x81 };
            image[pool + 288..pool + 800].fill(0x41 + index as u8);
            image[pool + 800..].fill(0x51 + index as u8);
        } else {
            image.extend_from_slice(&vec![0x41 + index as u8; 512]);
            image.extend_from_slice(&vec![0x51 + index as u8; 512]);
        }
    }
    let descriptor = base + security * 16;
    put(&mut image, descriptor, 0x0020_0000);
    put(&mut image, descriptor + 4, 0x0100_0fd9); //4057 =>2020+2020+17.
    image.extend((0..4057).map(|n| (n % 251) as u8));
    image
}

struct Case {
    chip: ChipId,
    seed: u8,
    secure: bool,
    trace: &'static [(u8, u32, u32)],
}
include!("firmware_boot/golden.rs");
struct Model {
    chip: ChipId,
    ready: bool,
    regs: Vec<u8>,
    cpu_ctrl: u32,
    cpu_status: u32,
    trace: Vec<(u8, u32, u32)>,
    now: u64,
    operations: usize,
    fail: Option<usize>,
    sent: Vec<(Kind, Vec<u8>)>,
    ready_status: u8,
    stall_path: Option<u8>,
    pending_send: Option<usize>,
    fail_send: Option<usize>,
    pending_delay: Option<usize>,
    delays: usize,
    gone: bool,
}
impl Model {
    fn new(chip: ChipId, seed: u8) -> Self {
        Self {
            chip,
            ready: true,
            regs: vec![seed; 0x40004],
            cpu_ctrl: u32::from_le_bytes([seed; 4]),
            cpu_status: u32::from_le_bytes([seed; 4]),
            trace: Vec::new(),
            now: 0,
            operations: 0,
            fail: None,
            sent: Vec::new(),
            ready_status: 7,
            stall_path: None,
            pending_send: None,
            fail_send: None,
            pending_delay: None,
            delays: 0,
            gone: false,
        }
    }
    fn access(&mut self) -> Result<(), power::Error> {
        let at = self.operations;
        self.operations += 1;
        if self.fail == Some(at) {
            Err(power::Error::Access)
        } else {
            Ok(())
        }
    }
    fn word(&self, a: u32) -> u32 {
        u32::from_le_bytes(self.regs[a as usize..a as usize + 4].try_into().unwrap())
    }
}
impl Io for Model {
    fn read8(&mut self, a: u32) -> Result<u8, power::Error> {
        self.access()?;
        if a == 0x1e0 {
            if self.gone {
                return Ok(255);
            }
            let paths = if self.sent.is_empty() { 2 } else { 6 };
            return Ok((self.regs[a as usize] & 1)
                | paths & !self.stall_path.unwrap_or(0)
                | if self.now >= 5000 {
                    self.ready_status << 5
                } else {
                    0
                });
        }
        Ok(self.regs[a as usize])
    }
    fn read16(&mut self, a: u32) -> Result<u16, power::Error> {
        self.access()?;
        Ok(u16::from_le_bytes(
            self.regs[a as usize..a as usize + 2].try_into().unwrap(),
        ))
    }
    fn read32(&mut self, a: u32) -> Result<u32, power::Error> {
        self.access()?;
        if a == 0x40000 {
            match self.word(0xc04) {
                0x18003040 => return Ok(self.cpu_ctrl),
                0x18003044 => return Ok(self.cpu_status),
                _ => (),
            }
        }
        Ok(self.word(a))
    }
    fn write8(&mut self, _: u32, _: u8) -> Result<(), power::Error> {
        Err(power::Error::Unsupported)
    }
    fn write16(&mut self, a: u32, v: u16) -> Result<(), power::Error> {
        self.access()?;
        self.trace.push((16, a, u32::from(v)));
        self.regs[a as usize..a as usize + 2].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn write32(&mut self, a: u32, v: u32) -> Result<(), power::Error> {
        self.access()?;
        self.trace.push((32, a, v));
        if a == 0x40000 {
            match self.word(0xc04) {
                0x18003040 => self.cpu_ctrl = v,
                0x18003044 => self.cpu_status = v,
                _ => (),
            }
        }
        self.regs[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes());
        Ok(())
    }
    fn now_us(&self) -> u64 {
        self.now
    }
    async fn delay_us(&mut self, us: u64) {
        let delay = self.delays;
        self.delays += 1;
        if self.pending_delay == Some(delay) {
            core::future::pending::<()>().await;
        }
        self.now += us;
    }
    async fn read_ecv(&mut self) -> Result<Option<u8>, power::Error> {
        Err(power::Error::Unsupported)
    }
}
impl Transport for Model {
    type Registers = Self;
    fn chip(&self) -> ChipId {
        self.chip
    }
    fn prepared(&self) -> bool {
        self.ready
    }
    fn registers(&mut self) -> &mut Self {
        self
    }
    async fn send(&mut self, kind: Kind, bytes: &[u8]) -> Result<(), command_queue::Error> {
        self.sent.push((kind, bytes.to_vec()));
        if self.fail_send == Some(self.sent.len() - 1) {
            return Err(command_queue::Error::Publish);
        }
        if self.pending_send == Some(self.sent.len() - 1) {
            core::future::pending::<()>().await;
        }
        Ok(())
    }
}
fn plan(chip: ChipId, secure: bool) -> DownloadPlan {
    let mut bytes = firmware(0, usize::from(secure), false);
    put(&mut bytes, 28, (11 << 18) | 0x8765);
    DownloadPlan::new(
        prepare(bytes, chip),
        Fuses::decode(chip, 255, if secure { 0x6e } else { 255 }).unwrap(),
        Some(Blacklist::authenticated(0, [0; 32])),
    )
    .unwrap()
}
fn once<T>(future: impl Future<Output = T>) -> Option<T> {
    let mut future = pin!(future);
    match future
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}
fn smoke_rtw89_wcpu_linux_reset_boot_trace_and_exact_transfers() -> TestResult {
    for case in CASES {
        let plan = plan(case.chip, case.secure);
        let expected_header = plan.header_command(0).unwrap();
        let mut expected = vec![(Kind::Header, expected_header)];
        for section in 0..plan.section_count() {
            for offset in (0..plan.section_len(section).unwrap()).step_by(2020) {
                expected.push((Kind::Section, plan.chunk(section, offset).unwrap()));
            }
        }
        let mut owner = Firmware::new(Model::new(case.chip, case.seed), plan).unwrap();
        let mut expected_trace = case.trace.to_vec();
        expected_trace.extend_from_slice(&[(32, 0x160, 0), (32, 0x164, 0)]);
        if once(owner.start()) != Some(Ok(()))
            || owner.phase() != Phase::Running
            || owner.transport.sent != expected
            || owner.transport.trace != expected_trace
        {
            return TestResult::Fail(
                "AX WCPU Linux reset/enable trace or immutable command transfers",
            );
        }
        let operations = owner.transport.operations;
        if once(owner.start()) != Some(Err(Error::Terminal))
            || owner.transport.operations != operations
        {
            return TestResult::Fail("running WCPU owner replayed startup");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_wcpu_linux_reset_boot_trace_and_exact_transfers
);

fn smoke_rtw89_wcpu_failed_io_status_and_path_never_reopen() -> TestResult {
    for chip in [
        ChipId::Rtl8852A,
        ChipId::Rtl8852B,
        ChipId::Rtl8852C,
        ChipId::Rtl8851B,
    ] {
        let mut successful = Firmware::new(Model::new(chip, 0), plan(chip, false)).unwrap();
        if once(successful.start()) != Some(Ok(())) {
            return TestResult::Fail("baseline WCPU startup");
        }
        for fail in 0..successful.transport.operations {
            let mut model = Model::new(chip, 0);
            model.fail = Some(fail);
            let mut owner = Firmware::new(model, plan(chip, false)).unwrap();
            if once(owner.start()) != Some(Err(Error::Register(power::Error::Access)))
                || owner.phase() != Phase::Terminal
            {
                return TestResult::Fail("partial WCPU access did not close owner");
            }
            let operations = owner.transport.operations;
            if once(owner.start()) != Some(Err(Error::Terminal))
                || owner.transport.operations != operations
            {
                return TestResult::Fail("failed WCPU startup replayed registers");
            }
        }
        for status in [2, 3, 4, 5, 6] {
            let mut model = Model::new(chip, 0);
            model.ready_status = status;
            let mut owner = Firmware::new(model, plan(chip, false)).unwrap();
            let expected = if status == 6 {
                Error::Register(power::Error::Timeout)
            } else {
                Error::FirmwareStatus(status)
            };
            if once(owner.start()) != Some(Err(expected)) || owner.phase() != Phase::Terminal {
                return TestResult::Fail(
                    "download-ready/failure mistaken for firmware initialized",
                );
            }
        }
        for bit in [2, 4] {
            let mut model = Model::new(chip, 0);
            model.stall_path = Some(bit);
            let mut owner = Firmware::new(model, plan(chip, false)).unwrap();
            if once(owner.start()) != Some(Err(Error::Register(power::Error::Timeout)))
                || owner.phase() != Phase::Terminal
            {
                return TestResult::Fail("stalled WCPU path was accepted");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_wcpu_failed_io_status_and_path_never_reopen
);

fn smoke_rtw89_wcpu_cancelled_send_retains_progress_and_plan() -> TestResult {
    for pending in 0..4 {
        let mut model = Model::new(ChipId::Rtl8852B, 0);
        model.pending_send = Some(pending);
        let mut owner = Firmware::new(model, plan(ChipId::Rtl8852B, false)).unwrap();
        if once(owner.start()).is_some()
            || owner.transport.sent.len() != pending + 1
            || matches!(owner.phase(), Phase::Prepared | Phase::Running)
        {
            return TestResult::Fail("pending firmware command lost owner phase");
        }
        let operations = owner.transport.operations;
        if once(owner.start()) != Some(Err(Error::Terminal))
            || owner.transport.operations != operations
            || owner.transport.sent.len() != pending + 1
            || owner.plan.section_len(0) != Some(4057)
        {
            return TestResult::Fail("cancelled WCPU command was replayed or image released");
        }
    }
    let mut model = Model::new(ChipId::Rtl8852B, 0);
    model.ready = false;
    if !matches!(
        Firmware::new(model, plan(ChipId::Rtl8852B, false)),
        Err(Error::NotPrepared)
    ) {
        return TestResult::Fail("unprepared PCIe command transport entered WCPU progression");
    }
    if !matches!(
        Firmware::new(
            Model::new(ChipId::Rtl8852A, 0),
            plan(ChipId::Rtl8852B, false)
        ),
        Err(Error::ChipMismatch)
    ) {
        return TestResult::Fail("firmware/control chip mismatch");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_wcpu_cancelled_send_retains_progress_and_plan
);

fn smoke_rtw89_wcpu_cancelled_wait_and_uncertain_publish_stay_closed() -> TestResult {
    for (stall, pending, status, phase) in [
        (Some(2), 0, 7, Phase::Starting),
        (Some(4), 0, 7, Phase::Header),
        (None, 0, 7, Phase::ReadyWait),
        (None, 1, 6, Phase::ReadyWait),
    ] {
        let mut model = Model::new(ChipId::Rtl8852C, 0);
        model.stall_path = stall;
        model.pending_delay = Some(pending);
        model.ready_status = status;
        let mut owner = Firmware::new(model, plan(ChipId::Rtl8852C, true)).unwrap();
        if once(owner.start()).is_some() || owner.phase() != phase {
            return TestResult::Fail("cancelled ROM-path/FreeRTOS wait lost retained phase");
        }
        let accesses = owner.transport.operations;
        if once(owner.start()) != Some(Err(Error::Terminal))
            || owner.transport.operations != accesses
        {
            return TestResult::Fail("cancelled WCPU wait replayed hardware progression");
        }
    }
    for failed in 0..4 {
        let mut model = Model::new(ChipId::Rtl8852B, 0);
        model.fail_send = Some(failed);
        let mut owner = Firmware::new(model, plan(ChipId::Rtl8852B, false)).unwrap();
        if once(owner.start()) != Some(Err(Error::Transfer(command_queue::Error::Publish)))
            || owner.phase() != Phase::Terminal
            || owner.transport.sent.len() != failed + 1
        {
            return TestResult::Fail("ambiguous firmware command publication reopened owner");
        }
    }
    let mut model = Model::new(ChipId::Rtl8852B, 0);
    model.gone = true;
    let mut owner = Firmware::new(model, plan(ChipId::Rtl8852B, false)).unwrap();
    if once(owner.start()) != Some(Err(Error::Register(power::Error::Gone)))
        || !owner.transport.sent.is_empty()
    {
        return TestResult::Fail("all-ones firmware control admitted a header");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw89",
    smoke_rtw89_wcpu_cancelled_wait_and_uncertain_publish_stay_closed
);

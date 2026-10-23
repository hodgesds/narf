use super::*;
use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
#[derive(Debug, Clone)]
enum Op {
    Read(u16),
    Write(u16, Vec<u8>),
    Delay(u64),
}
struct Model {
    regs: Vec<u8>,
    pages: Vec<Vec<u8>>,
    ops: Vec<Op>,
    checksum: bool,
    ready: bool,
    fail_page: bool,
    pause_page: bool,
    stuck_gate: bool,
}
#[derive(Clone)]
struct Fake(Arc<IrqSafeSpinLock<Model>>);
impl Fake {
    fn new() -> Self {
        let mut regs = vec![0; 8192];
        regs[3] = 0xff;
        regs[0x82] = 0xf8;
        regs[0x100] = 0xff;
        Self(Arc::new(IrqSafeSpinLock::new(Model {
            regs,
            pages: vec![Vec::new(); 8],
            ops: Vec::new(),
            checksum: true,
            ready: true,
            fail_page: false,
            pause_page: false,
            stuck_gate: false,
        })))
    }
}
#[async_trait::async_trait]
impl Io for Fake {
    fn read8(&self, reg: u16) -> Result<u8, Error> {
        let mut m = self.0.lock();
        m.ops.push(Op::Read(reg));
        Ok(m.regs[reg as usize])
    }
    fn read32(&self, reg: u16) -> Result<u32, Error> {
        let mut m = self.0.lock();
        m.ops.push(Op::Read(reg));
        if reg == 0x1e0 {
            m.regs[usize::from(reg) + 3] &= 0x3f;
        }
        if reg == 0x80
            && m.regs[0x80] & 1 == 0
            && m.pages.iter().any(|p| !p.is_empty())
            && m.checksum
        {
            m.regs[0x80] |= 4;
        }
        if reg == 0x80 && m.regs[0x80] & 2 != 0 && m.ready {
            m.regs[0x80] |= 0x40;
        }
        Ok(u32::from_le_bytes(
            m.regs[reg as usize..reg as usize + 4].try_into().unwrap(),
        ))
    }
    fn write8(&self, reg: u16, value: u8) -> Result<(), Error> {
        let mut m = self.0.lock();
        m.ops.push(Op::Write(reg, vec![value]));
        if reg == 0x100 && m.stuck_gate {
            return Ok(());
        }
        m.regs[reg as usize] = value;
        if reg == 0x80 && value & 4 != 0 {
            m.regs[0x80] &= !4;
        }
        Ok(())
    }
    fn write32(&self, reg: u16, value: u32) -> Result<(), Error> {
        let mut m = self.0.lock();
        m.ops.push(Op::Write(reg, value.to_le_bytes().to_vec()));
        m.regs[reg as usize..reg as usize + 4].copy_from_slice(&value.to_le_bytes());
        Ok(())
    }
    fn write_bytes(&self, reg: u16, bytes: &[u8]) -> Result<(), Error> {
        let mut m = self.0.lock();
        m.ops.push(Op::Write(reg, bytes.to_vec()));
        if m.fail_page {
            return Err(Error::Access);
        }
        let page = (m.regs[0x82] & 7) as usize;
        if m.pages[page].len() != usize::from(reg - 0x1000) {
            return Err(Error::Access);
        }
        m.pages[page].extend_from_slice(bytes);
        Ok(())
    }
    async fn delay_us(&self, us: u64) {
        let pause = {
            let mut m = self.0.lock();
            m.ops.push(Op::Delay(us));
            us == 0 && m.pause_page
        };
        if pause {
            core::future::pending::<()>().await;
        }
    }
}
fn image(n: usize) -> Vec<u8> {
    let mut b = vec![0; 32 + n];
    b[..2].copy_from_slice(&[0xe1, 0x88]);
    b[4..7].copy_from_slice(&[0x34, 0x12, 5]);
    b[12..14].copy_from_slice(&(n as u16).to_le_bytes());
    for (i, x) in b[32..].iter_mut().enumerate() {
        *x = (i % 251) as u8;
    }
    b
}
fn smoke_rtlwifi_8188ee_exact_paged_firmware_and_8051() -> TestResult {
    let io = Fake::new();
    let owner = Owner::new(io.clone(), super::super::regs::RTL_DEV_8188EE);
    let b = image(4099);
    let info = narf_scheduler::block_on(owner.initialize(&b)).unwrap();
    let m = io.0.lock();
    if info
        != (Info {
            version: 0x1234,
            subversion: 5,
            payload: 4099,
        })
        || owner.status()
            != (Status {
                stage: Stage::Ready,
                error: None,
            })
        || m.pages[0] != b[32..32 + 4096]
        || m.pages[1] != [b[32 + 4096..].to_vec(), vec![0]].concat()
        || m.regs[0x82] != 0xf1
        || m.regs[3] != 0xff
        || m.regs[0x80] & 0x43 != 0x42
        || m.regs[0x100] != 0x30
        || m.regs[8] != 8
    {
        return TestResult::Fail("paged firmware/padding/reserved state/readiness wrong");
    }
    let resets = m
        .ops
        .iter()
        .filter(|op| matches!(op,Op::Write(3,v)if v==&[0xfb]))
        .count();
    if resets != 1 {
        return TestResult::Fail("8051 firmware-start reset not performed");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/fw",
    smoke_rtlwifi_8188ee_exact_paged_firmware_and_8051
);
fn smoke_rtlwifi_8188ee_rejects_profile_and_header_before_io() -> TestResult {
    for (did, mut b) in [
        (0x818b, image(17)),
        (super::super::regs::RTL_DEV_8188EE, image(0)),
        (super::super::regs::RTL_DEV_8188EE, image(32769)),
        (super::super::regs::RTL_DEV_8188EE, image(17)),
    ] {
        if b.len() == 49 && did == super::super::regs::RTL_DEV_8188EE {
            b[0] = 0xe0;
        }
        let io = Fake::new();
        let owner = Owner::new(io.clone(), did);
        if narf_scheduler::block_on(owner.initialize(&b)).is_ok() || !io.0.lock().ops.is_empty() {
            return TestResult::Fail("unsupported/malformed firmware accessed MMIO");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/fw",
    smoke_rtlwifi_8188ee_rejects_profile_and_header_before_io
);
fn smoke_rtlwifi_8188ee_checksum_start_and_write_failure_terminal() -> TestResult {
    for kind in 0..3 {
        let io = Fake::new();
        {
            let mut m = io.0.lock();
            m.checksum = kind != 0;
            m.ready = kind != 1;
            m.fail_page = kind == 2;
        }
        let owner = Owner::new(io.clone(), super::super::regs::RTL_DEV_8188EE);
        let expected = [Error::Checksum, Error::Start, Error::Access][kind];
        if narf_scheduler::block_on(owner.initialize(&image(17))) != Err(expected)
            || owner.status().error != Some(expected)
        {
            return TestResult::Fail("firmware failed stage reported ready");
        }
        let n = io.0.lock().ops.len();
        if narf_scheduler::block_on(owner.initialize(&image(17))) != Err(Error::AlreadyStarted)
            || io.0.lock().ops.len() != n
        {
            return TestResult::Fail("terminal firmware owner replayed I/O");
        }
        if kind == 2 && !matches!(io.0.lock().ops.last(), Some(Op::Write(0x1000, _))) {
            return TestResult::Fail("failed firmware write performed cleanup/start");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/fw",
    smoke_rtlwifi_8188ee_checksum_start_and_write_failure_terminal
);
fn smoke_rtlwifi_8188ee_cancel_after_payload_is_terminal() -> TestResult {
    let io = Fake::new();
    io.0.lock().pause_page = true;
    let owner = Owner::new(io.clone(), super::super::regs::RTL_DEV_8188EE);
    let b = image(5000);
    {
        let mut f = Box::pin(owner.initialize(&b));
        if !matches!(
            f.as_mut().poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) || io.0.lock().pages[0].len() != 256
            || owner.status().stage != Stage::Downloading
        {
            return TestResult::Fail("actual page publication did not precede cancellation");
        }
    }
    let n = io.0.lock().ops.len();
    if owner.status().error != Some(Error::Cancelled)
        || n == 0
        || narf_scheduler::block_on(owner.initialize(&b)) != Err(Error::AlreadyStarted)
        || io.0.lock().ops.len() != n
    {
        return TestResult::Fail("dropped page-writing owner restarted or reported ready");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/fw",
    smoke_rtlwifi_8188ee_cancel_after_payload_is_terminal
);

fn smoke_rtlwifi_8188ee_packet_gate_failure_prevents_firmware() -> TestResult {
    let io = Fake::new();
    io.0.lock().stuck_gate = true;
    let owner = Owner::new(io.clone(), super::super::regs::RTL_DEV_8188EE);
    if narf_scheduler::block_on(owner.initialize(&image(17))) != Err(Error::Gate)
        || owner.status().error != Some(Error::Gate)
        || io.0.lock().pages.iter().any(|p| !p.is_empty())
        || io
            .0
            .lock()
            .ops
            .iter()
            .any(|op| matches!(op, Op::Read(0x80) | Op::Write(0x80, _)))
    {
        return TestResult::Fail("packet engine gate failure allowed firmware I/O");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi/fw",
    smoke_rtlwifi_8188ee_packet_gate_failure_prevents_firmware
);

fn smoke_rtl8188ee_native_claim_is_exact_ready_and_one_shot() -> TestResult {
    let io = Fake::new();
    let owner = Arc::new(Owner::new(io.clone(), super::super::regs::RTL_DEV_8188EE));
    if !matches!(owner.claim_packet_io(), Err(Error::Gate)) || !io.0.lock().ops.is_empty() {
        return TestResult::Fail("native packet continuation escaped firmware readiness");
    }
    narf_scheduler::block_on(owner.initialize(&image(17))).unwrap();
    let packet = owner.claim_packet_io().unwrap();
    let before = io.0.lock().ops.len();
    if !matches!(owner.claim_packet_io(), Err(Error::AlreadyStarted))
        || io.0.lock().ops.len() != before
    {
        return TestResult::Fail("a second native owner could replace retained descriptors");
    }
    packet.write8(0x301, 0xff).unwrap();
    if io.0.lock().regs[0x301] != 0xff {
        return TestResult::Fail("native continuation was not bound to actual firmware transport");
    }
    drop(packet);
    let before = io.0.lock().ops.len();
    if !matches!(owner.claim_packet_io(), Err(Error::AlreadyStarted))
        || narf_scheduler::block_on(owner.initialize(&image(17))) != Err(Error::AlreadyStarted)
        || io.0.lock().ops.len() != before
    {
        return TestResult::Fail("native Drop permitted ring overwrite or firmware reset");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8188ee_native_claim_is_exact_ready_and_one_shot
);

fn smoke_rtl8188ee_actual_firmware_to_retained_llt_rings() -> TestResult {
    use super::super::prepare::{self, Memory, Prepared};
    struct Block {
        address: u64,
        bytes: Vec<u8>,
    }
    // SAFETY: independent inert model storage; addresses are never sent to a
    // physical device. The production outer owner governs publication/Drop.
    unsafe impl Memory for Block {
        fn address(&self) -> u64 {
            self.address
        }
        fn len(&self) -> usize {
            self.bytes.len()
        }
        fn write32(&mut self, at: usize, value: u32) -> Result<(), prepare::Error> {
            self.bytes
                .get_mut(at..at + 4)
                .ok_or(prepare::Error::Memory)?
                .copy_from_slice(&value.to_le_bytes());
            Ok(())
        }
        fn sync(&self) {}
    }
    let io = Fake::new();
    let owner = Arc::new(Owner::new(io.clone(), super::super::regs::RTL_DEV_8188EE));
    narf_scheduler::block_on(owner.initialize(&image(17))).unwrap();
    let port = owner.claim_packet_io().unwrap();
    let mut address = 0x10000u64;
    let mut prepared = Prepared::allocate(port, 4, |bytes| {
        address = (address + 255) & !255;
        let block = Block {
            address,
            bytes: vec![0xa5; bytes],
        };
        address += bytes as u64;
        Ok(block)
    })
    .unwrap();
    if narf_scheduler::block_on(prepared.prepare()) != Ok(())
        || prepared.phase() != prepare::Phase::Prepared
        || owner.status().stage != Stage::Ready
    {
        return TestResult::Fail(
            "actual successful firmware did not feed retained LLT/native owner",
        );
    }
    let m = io.0.lock();
    let read_base = |reg: usize| u32::from_le_bytes(m.regs[reg..reg + 4].try_into().unwrap());
    let mut bases = Vec::new();
    for reg in [0x308, 0x310, 0x318, 0x320, 0x328, 0x330, 0x338, 0x340] {
        let base = read_base(reg);
        if base == 0 || bases.contains(&base) {
            return TestResult::Fail("firmware continuation aliased native queue bases");
        }
        bases.push(base);
    }
    if m.regs[0x301] != 0xff
        || m.regs[0x100] & 0xcf != 0
        || read_base(0xb0) != 0
        || read_base(0xb8) != 0
    {
        return TestResult::Fail("firmware/LLT composition opened DMA/MAC/IRQ prematurely");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtlwifi",
    smoke_rtl8188ee_actual_firmware_to_retained_llt_rings
);

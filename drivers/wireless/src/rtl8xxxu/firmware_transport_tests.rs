use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::future::Future;
use core::task::{Context, Poll, Waker};

use narf_drivers_usb::device::UsbError;
use narf_kernel_test::{kernel_test_in, TestResult};
use narf_lib::sync::IrqSafeSpinLock;

use super::firmware_transport::{parse_image, ControlIo, Error, Owner, Stage};
use super::regs::*;

#[derive(Clone, Debug)]
enum Op {
    Read(u16, usize),
    Write(u16, Vec<u8>),
    Delay(u64),
}

struct Model {
    regs: Vec<u8>,
    pages: Vec<Vec<u8>>,
    ops: Vec<Op>,
    checksum: bool,
    init: bool,
    short_read: bool,
    short_page: bool,
    pending: bool,
    pending_page: bool,
    page_error: bool,
    active_td: bool,
    unsafe_reuses: usize,
    writes: usize,
}

impl Model {
    fn new() -> Self {
        let mut regs = vec![0; 0x2000];
        regs[REG_APS_FSMCO as usize + 2] = 2; // Power ready bit 17.
        regs[REG_SYS_FUNC as usize] = 0x7f;
        regs[REG_SYS_FUNC as usize + 1] = 0xa1;
        regs[REG_MCU_FW_DL as usize + 2] = 0xa8; // Reserved bits survive page selection.
        Self {
            regs,
            pages: vec![Vec::new(); 8],
            ops: Vec::new(),
            checksum: true,
            init: true,
            short_read: false,
            short_page: false,
            pending: false,
            pending_page: false,
            page_error: false,
            active_td: false,
            unsafe_reuses: 0,
            writes: 0,
        }
    }
}

#[derive(Clone)]
struct Fake(Arc<IrqSafeSpinLock<Model>>);
impl Fake {
    fn new() -> Self {
        Self(Arc::new(IrqSafeSpinLock::new(Model::new())))
    }
}

#[async_trait::async_trait]
impl ControlIo for Fake {
    async fn read(&self, addr: u16, out: &mut [u8]) -> Result<usize, UsbError> {
        let pending = { self.0.lock().pending };
        if pending {
            core::future::pending::<()>().await;
        }
        let mut g = self.0.lock();
        if g.active_td {
            g.unsafe_reuses += 1;
        }
        g.ops.push(Op::Read(addr, out.len()));
        if addr == REG_APS_FSMCO && out.len() == 4 {
            g.regs[addr as usize + 1] &= !1; // MAC enable handshake completes.
        }
        if addr == REG_MCU_FW_DL && g.regs[addr as usize] & MCU_FW_DL_ENABLE == 0 {
            if g.checksum && g.pages.iter().any(|page| !page.is_empty()) {
                g.regs[addr as usize] |= MCU_FW_DL_CSUM_REPORT;
            }
            if g.init && g.regs[addr as usize] & MCU_FW_DL_READY != 0 {
                g.regs[addr as usize] |= MCU_WINT_INIT_READY as u8;
            }
        }
        out.copy_from_slice(&g.regs[addr as usize..addr as usize + out.len()]);
        Ok(if g.short_read {
            out.len() - 1
        } else {
            out.len()
        })
    }

    async fn write(&self, addr: u16, bytes: &[u8]) -> Result<usize, UsbError> {
        let outcome = {
            let mut g = self.0.lock();
            if g.active_td {
                g.unsafe_reuses += 1;
            }
            g.ops.push(Op::Write(addr, bytes.to_vec()));
            g.writes += 1;
            if addr >= REG_FW_START_ADDRESS {
                let page = (g.regs[REG_MCU_FW_DL as usize + 2] & 7) as usize;
                let offset = (addr - REG_FW_START_ADDRESS) as usize;
                if bytes.len() > 196 || g.pages[page].len() != offset {
                    return Err(UsbError::Stall);
                }
                if g.pending_page {
                    // The TD was submitted and owns ctrl_data. Future Drop
                    // cannot establish endpoint stop/drain, just like xHCI.
                    g.active_td = true;
                    None
                } else if g.page_error {
                    // xHCI can return an error without proving TD retirement.
                    g.active_td = true;
                    Some(Err(UsbError::Stall))
                } else if g.short_page {
                    Some(Ok(bytes.len() - 1))
                } else {
                    g.pages[page].extend_from_slice(bytes);
                    Some(Ok(bytes.len()))
                }
            } else {
                g.regs[addr as usize..addr as usize + bytes.len()].copy_from_slice(bytes);
                if addr == REG_MCU_FW_DL && bytes[0] & MCU_FW_DL_CSUM_REPORT != 0 {
                    g.regs[addr as usize] &= !MCU_FW_DL_CSUM_REPORT; // W1C.
                }
                Some(Ok(bytes.len()))
            }
        };
        match outcome {
            Some(result) => result,
            None => core::future::pending().await,
        }
    }
    async fn delay_us(&self, us: u64) {
        self.0.lock().ops.push(Op::Delay(us));
    }
}

fn image(payload_len: usize) -> Vec<u8> {
    let mut blob = vec![0; 32 + payload_len];
    blob[..2].copy_from_slice(&0x88e1u16.to_le_bytes());
    blob[4..6].copy_from_slice(&0x1234u16.to_le_bytes());
    blob[6] = 5;
    blob[12..14].copy_from_slice(&(payload_len as u16).to_le_bytes());
    for (i, byte) in blob[32..].iter_mut().enumerate() {
        *byte = (i % 251) as u8;
    }
    blob
}

fn smoke_rtl8xxxu_live_firmware_header_preflight() -> TestResult {
    let valid = image(17);
    let parsed = match parse_image(ChipFamily::Rtl8188eu, &valid) {
        Ok((info, _)) => info,
        Err(_) => return TestResult::Fail("RTL8188EU rejected valid firmware header"),
    };
    if parsed.signature != 0x88e1
        || parsed.major != 0x1234
        || parsed.minor != 5
        || parsed.payload_bytes != 17
    {
        return TestResult::Fail("RTL8188EU firmware header fields wrong");
    }
    let mut wrong_chip = valid.clone();
    wrong_chip[0..2].copy_from_slice(&0x92e1u16.to_le_bytes());
    let mut wrong_size = valid.clone();
    wrong_size[12] = 18;
    for blob in [vec![], vec![0; 32], wrong_chip, wrong_size, image(32769)] {
        let io = Fake::new();
        let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
        if narf_scheduler::block_on(owner.initialize(&blob)) != Err(Error::InvalidImage)
            || !io.0.lock().ops.is_empty()
            || owner.status().stage != Stage::Failed
        {
            return TestResult::Fail("invalid RTL8188EU firmware touched USB or did not fail");
        }
    }
    for chip in [
        ChipFamily::Rtl8192eu,
        ChipFamily::Rtl8723bu,
        ChipFamily::Rtl8821cu,
        ChipFamily::Rtl8822bu,
        ChipFamily::Unknown,
    ] {
        let io = Fake::new();
        let owner = Owner::new(io.clone(), chip);
        if narf_scheduler::block_on(owner.initialize(&valid)) != Err(Error::UnsupportedChip)
            || !io.0.lock().ops.is_empty()
        {
            return TestResult::Fail("RTL8188EU firmware lifecycle accepted another family");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu",
    smoke_rtl8xxxu_live_firmware_header_preflight
);

fn smoke_rtl8xxxu_live_firmware_control_pages_and_ready() -> TestResult {
    let blob = image(2 * RTL_FW_PAGE_SIZE + 73);
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
    if narf_scheduler::block_on(owner.initialize(&blob)).is_err()
        || owner.status().stage != Stage::FirmwareReady
    {
        return TestResult::Fail("live RTL8188EU control firmware sequence did not reach ready");
    }
    let g = io.0.lock();
    if g.pages.concat() != blob[32..]
        || g.pages[0].len() != 4096
        || g.pages[1].len() != 4096
        || g.pages[2].len() != 73
        || g.regs[REG_MCU_FW_DL as usize + 2] != 0xa2
    {
        return TestResult::Fail("RTL8188EU control page bytes/selector preservation wrong");
    }
    if g.regs[REG_SYS_FUNC as usize] != 0x7c
        || g.regs[REG_SYS_FUNC as usize + 1] != 0xa5
        || g.regs[REG_CR as usize] & 0xc0 != 0
        || g.regs[REG_MCU_FW_DL as usize] & MCU_FW_DL_ENABLE != 0
    {
        return TestResult::Fail(
            "RTL8188EU clobbered SYS state, enabled MAC TX/RX, or left download enabled",
        );
    }
    if g.ops
        .iter()
        .any(|op| matches!(op, Op::Write(addr, _) if *addr == REG_HMTFR || *addr == 0x1f))
    {
        return TestResult::Fail("RTL8188EU used another chip's HMTFR/RF initialization");
    }
    drop(g);
    let before = io.0.lock().ops.len();
    if narf_scheduler::block_on(owner.initialize(&blob)) != Err(Error::AlreadyStarted)
        || io.0.lock().ops.len() != before
    {
        return TestResult::Fail("RTL8188EU replayed a one-shot firmware attempt");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu",
    smoke_rtl8xxxu_live_firmware_control_pages_and_ready
);

fn smoke_rtl8xxxu_live_firmware_short_transfer_and_checksum() -> TestResult {
    let blob = image(123);
    for (short_read, short_page, checksum, init, expected) in [
        (true, false, true, true, Error::ShortTransfer),
        (false, true, true, true, Error::ShortTransfer),
        (false, false, false, true, Error::ChecksumTimeout),
        (false, false, true, false, Error::StartTimeout),
    ] {
        let io = Fake::new();
        {
            let mut g = io.0.lock();
            g.short_read = short_read;
            g.short_page = short_page;
            g.checksum = checksum;
            g.init = init;
        }
        let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
        if narf_scheduler::block_on(owner.initialize(&blob)) != Err(expected)
            || owner.status().stage != Stage::Failed
            || owner.status().error != Some(expected)
        {
            return TestResult::Fail(
                "RTL8188EU did not preserve terminal transport/handshake failure",
            );
        }
        let g = io.0.lock();
        if (short_read && g.writes != 0)
            || (short_page
                && !matches!(g.ops.last(), Some(Op::Write(addr, _)) if *addr >= REG_FW_START_ADDRESS))
            || (!short_page && g.regs[REG_MCU_FW_DL as usize] & MCU_FW_DL_ENABLE != 0)
        {
            return TestResult::Fail(
                "RTL8188EU reused EP0 after failed transfer or invalid normal handshake",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu",
    smoke_rtl8xxxu_live_firmware_short_transfer_and_checksum
);

fn smoke_rtl8xxxu_live_firmware_cancel_is_terminal() -> TestResult {
    let blob = image(123);
    let io = Fake::new();
    io.0.lock().pending = true;
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
    {
        let mut future = Box::pin(owner.initialize(&blob));
        if !matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) {
            return TestResult::Fail("RTL8188EU cancellation fixture did not wait on USB");
        }
    }
    if owner.status().error != Some(Error::Cancelled)
        || narf_scheduler::block_on(owner.initialize(&blob)) != Err(Error::AlreadyStarted)
        || io.0.lock().writes != 0
    {
        return TestResult::Fail(
            "RTL8188EU cancellation did not retain a terminal, non-replayable owner",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu",
    smoke_rtl8xxxu_live_firmware_cancel_is_terminal
);

fn smoke_rtl8xxxu_live_firmware_active_td_poison() -> TestResult {
    let blob = image(123);
    for mode in 0..3 {
        let io = Fake::new();
        {
            let mut g = io.0.lock();
            g.pending_page = mode != 2;
            g.page_error = mode == 2;
        }
        let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
        let expected = match mode {
            0 => {
                // The timeout polls inner first: all actual control setup
                // runs, then the first submitted firmware TD stays pending.
                if narf_scheduler::block_on(
                    owner.initialize_before(&blob, narf_time::Deadline::after_ms(0)),
                ) != Err(Error::Deadline)
                {
                    return TestResult::Fail("active download did not reach outer deadline");
                }
                Error::Deadline
            }
            1 => {
                let mut future = Box::pin(owner.initialize(&blob));
                if !matches!(
                    future
                        .as_mut()
                        .poll(&mut Context::from_waker(Waker::noop())),
                    Poll::Pending
                ) {
                    return TestResult::Fail(
                        "active download cancellation fixture did not submit TD",
                    );
                }
                drop(future);
                Error::Cancelled
            }
            _ => {
                if narf_scheduler::block_on(owner.initialize(&blob))
                    != Err(Error::Usb(UsbError::Stall))
                {
                    return TestResult::Fail("ambiguous transport error was not retained");
                }
                Error::Usb(UsbError::Stall)
            }
        };
        let before = {
            let g = io.0.lock();
            if !g.active_td
                || g.writes == 0
                || g.unsafe_reuses != 0
                || !matches!(g.ops.last(), Some(Op::Write(addr, _)) if *addr == REG_FW_START_ADDRESS)
                || g.regs[REG_MCU_FW_DL as usize] & MCU_FW_DL_ENABLE == 0
            {
                return TestResult::Fail(
                    "firmware TD was not submitted or EP0 reused without drain",
                );
            }
            g.ops.len()
        };
        if owner.status().stage != Stage::Failed
            || owner.status().error != Some(expected)
            || narf_scheduler::block_on(owner.initialize(&blob)) != Err(Error::AlreadyStarted)
            || io.0.lock().ops.len() != before
        {
            return TestResult::Fail("poisoned EP0 owner replayed or lost terminal failure");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu",
    smoke_rtl8xxxu_live_firmware_active_td_poison
);

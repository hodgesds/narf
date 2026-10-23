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
pub(super) enum Op {
    Read(u16, usize),
    Write(u16, Vec<u8>),
    Delay(u64),
}

pub(super) struct Model {
    pub(super) regs: Vec<u8>,
    pages: Vec<Vec<u8>>,
    pub(super) ops: Vec<Op>,
    checksum: bool,
    init: bool,
    short_read: bool,
    short_page: bool,
    pending: bool,
    pending_page: bool,
    page_error: bool,
    pub(super) active_td: bool,
    pub(super) unsafe_reuses: usize,
    writes: usize,
    physical: [u8; 512],
    config: Vec<u8>,
    llt: Vec<(u8, u8)>,
    llt_stalled: bool,
    fail_write: Option<u16>,
    cam_stalled: bool,
    iq_failure: bool,
    rf_read: u8,
    rf: [u32; 256],
    pub(super) pending_write: Option<u16>,
}

impl Model {
    fn new() -> Self {
        let mut regs = vec![0; 0x10000];
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
            physical: factory_stream(),
            config: configuration(3),
            llt: Vec::new(),
            llt_stalled: false,
            fail_write: None,
            cam_stalled: false,
            iq_failure: false,
            rf_read: 0,
            rf: [0; 256],
            pending_write: None,
        }
    }
}

#[derive(Clone)]
pub(super) struct Fake(pub(super) Arc<IrqSafeSpinLock<Model>>);
impl Fake {
    fn new() -> Self {
        Self(Arc::new(IrqSafeSpinLock::new(Model::new())))
    }
}

#[async_trait::async_trait]
impl ControlIo for Fake {
    fn identity(&self) -> Option<(u16, u16)> {
        Some((0x0bda, 0x8179))
    }

    async fn configuration(&self, out: &mut [u8]) -> Result<usize, UsbError> {
        let g = self.0.lock();
        out[..g.config.len()].copy_from_slice(&g.config);
        Ok(g.config.len())
    }
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
        if addr == 0xe94 || addr == 0xea4 {
            out.copy_from_slice(&(0x100u32 << 16).to_le_bytes());
        } else if addr == 0xe9c {
            out.copy_from_slice(&(0x3ffu32 << 16).to_le_bytes());
        } else if addr == 0xeac {
            out.copy_from_slice(
                &(if g.iq_failure {
                    1u32 << 28 | 1 << 27
                } else {
                    2u32 << 16
                })
                .to_le_bytes(),
            );
        } else if (addr == 0x8a0 || addr == 0x8b8) && out.len() == 4 {
            out.copy_from_slice(&g.rf[g.rf_read as usize].to_le_bytes());
        } else if addr == 0x670 && out.len() == 4 && !g.cam_stalled {
            out.fill(0);
        } else if addr == 0x30 && out.len() == 4 {
            let address = (g.regs[0x31] as usize) | ((g.regs[0x32] as usize & 3) << 8);
            let value = 1 << 31 | ((address as u32) << 8) | g.physical[address] as u32;
            out.copy_from_slice(&value.to_le_bytes());
        } else if addr == 0x1e0 && out.len() == 4 && !g.llt_stalled {
            out.fill(0);
        } else {
            out.copy_from_slice(&g.regs[addr as usize..addr as usize + out.len()]);
        }
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
            if g.fail_write == Some(addr) && (addr != 0xe48 || bytes == 0xf9000000u32.to_le_bytes())
            {
                return Err(UsbError::Stall);
            }
            if addr == 0x1e0 {
                g.llt.push((bytes[1], bytes[0]));
            }
            if g.pending_write == Some(addr)
                && (addr != 0xe48 || bytes == 0xf9000000u32.to_le_bytes())
            {
                g.active_td = true;
                None
            } else if (REG_FW_START_ADDRESS..REG_FW_START_ADDRESS + 0x1000).contains(&addr) {
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
                let previous_hssi = u32::from_le_bytes(g.regs[0x824..0x828].try_into().unwrap());
                g.regs[addr as usize..addr as usize + bytes.len()].copy_from_slice(bytes);
                if addr == 0x840 && bytes.len() == 4 {
                    let v = u32::from_le_bytes(bytes.try_into().unwrap());
                    g.rf[(v >> 20) as usize] = v & 0xfffff;
                }
                if addr == 0x824 && bytes.len() == 4 {
                    let v = u32::from_le_bytes(bytes.try_into().unwrap());
                    if v & 0x80000000 != 0 && previous_hssi & 0x80000000 == 0 {
                        g.rf_read = ((v >> 23) & 0xff) as u8;
                    }
                }
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

fn configuration(out: u8) -> Vec<u8> {
    let total = 9 + 9 + 7 * (out as usize + 1);
    let mut bytes = vec![
        9,
        2,
        total as u8,
        0,
        1,
        1,
        0,
        0x80,
        50,
        9,
        4,
        0,
        0,
        out + 1,
        0xff,
        0xff,
        0xff,
        0,
        7,
        5,
        0x81,
        2,
        0,
        2,
        0,
    ];
    for index in 0..out {
        bytes.extend_from_slice(&[7, 5, index + 2, 2, 0, 2, 0]);
    }
    bytes
}

fn factory_stream() -> [u8; 512] {
    let mut logical = [0xff; 512];
    logical[..2].copy_from_slice(&[0x29, 0x81]);
    logical[0x10..0x1b].fill(0x20);
    logical[0xb8..0xbc].copy_from_slice(&[0x20, 0x20, 0x18, 0]);
    logical[0xc1] = 1;
    logical[0xd7..0xdd].copy_from_slice(&[2, 0xe0, 0x4c, 1, 2, 3]);
    let mut raw = [0xff; 512];
    let mut cursor = 0;
    for block in [0usize, 2, 3, 0x17, 0x18, 0x1a, 0x1b] {
        if block < 16 {
            raw[cursor] = (block << 4) as u8;
            cursor += 1;
        } else {
            raw[cursor] = (((block & 7) << 5) | 0xf) as u8;
            raw[cursor + 1] = ((block & 0x78) << 1) as u8;
            cursor += 2;
        }
        raw[cursor..cursor + 8].copy_from_slice(&logical[block * 8..block * 8 + 8]);
        cursor += 8;
    }
    raw
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

fn smoke_rtl8188eu_retained_factory_fifo_and_register_pipeline() -> TestResult {
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
    if narf_scheduler::block_on(owner.initialize_device(&image(123))).is_err()
        || owner.status().stage != Stage::RadioReady
    {
        return TestResult::Fail("RTL8188EU retained factory/MAC/BB/RF pipeline failed");
    }
    let factory = owner.factory().unwrap();
    if factory.mac != [2, 0xe0, 0x4c, 1, 2, 3]
        || factory.crystal_cap != 0x20
        || factory.cck_power != [0x20; 6]
        || factory.ht40_power != [0x20; 5]
    {
        return TestResult::Fail("RTL8188EU factory/calibration geometry wrong");
    }
    let g = io.0.lock();
    if g.llt.len() != 176
        || g.llt[169] != (169, 255)
        || g.llt[175] != (175, 170)
        || g.regs[0x100] & 0xc0 != 0
        || g.regs[0x116..0x118] != [0xff, 0x25]
    {
        return TestResult::Fail("FIFO/LLT boundary or disabled MAC TX/RX invariant");
    }
    // A real RF table entry above 0x1f must remain a distinct RF address.
    if !g.ops.iter().any(|op| {
        matches!(op, Op::Write(0x840, data)
        if data.len()==4 && u32::from_le_bytes(data[..].try_into().unwrap())>>20 == 0x57)
    }) {
        return TestResult::Fail("extended RF address was truncated");
    }
    let mut rf = false;
    for op in &g.ops {
        if matches!(op, Op::Write(0x840, _)) {
            rf = true;
        }
        if matches!(op, Op::Write(0x1e0, _)) && !rf {
            return TestResult::Fail("LLT ran before source-matched RF setup");
        }
        if let Op::Write(0x100, data) = op {
            if data[0] & 0xc0 != 0 {
                return TestResult::Fail("MAC started before calibration/packet owner");
            }
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu",
    smoke_rtl8188eu_retained_factory_fifo_and_register_pipeline
);

fn smoke_rtl8188eu_pipeline_stops_at_failed_register() -> TestResult {
    for fail in [0x31, 0x214, 0x421, 0x800, 0x840, 0x1e0] {
        let io = Fake::new();
        io.0.lock().fail_write = Some(fail);
        let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
        if narf_scheduler::block_on(owner.initialize_device(&image(123)))
            != Err(Error::Usb(UsbError::Stall))
            || owner.status().stage != Stage::Failed
        {
            return TestResult::Fail("pipeline did not preserve first transport failure");
        }
        let count = {
            let g = io.0.lock();
            if !matches!(g.ops.last(), Some(Op::Write(addr, _)) if *addr == fail) {
                return TestResult::Fail("pipeline attempted I/O after failed register write");
            }
            g.ops.len()
        };
        if narf_scheduler::block_on(owner.initialize_device(&image(123)))
            != Err(Error::AlreadyStarted)
            || io.0.lock().ops.len() != count
        {
            return TestResult::Fail("pipeline replayed a failed one-shot owner");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu",
    smoke_rtl8188eu_pipeline_stops_at_failed_register
);

fn smoke_rtl8188eu_descriptor_geometry_and_llt_failure() -> TestResult {
    use super::device_init::endpoints;
    for count in 1..=3 {
        let plan = endpoints(&configuration(count)).unwrap();
        if plan.output_count != count || plan.input != 0x81 || plan.output[0] != 2 {
            return TestResult::Fail("descriptor-derived endpoint plan wrong");
        }
    }
    let mut duplicate = configuration(3);
    duplicate[34] = 2;
    if endpoints(&duplicate).is_ok()
        || endpoints(&configuration(0)).is_ok()
        || endpoints(&configuration(4)).is_ok()
    {
        return TestResult::Fail("invalid endpoint geometry accepted");
    }
    let io = Fake::new();
    io.0.lock().llt_stalled = true;
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
    if narf_scheduler::block_on(owner.initialize_device(&image(123))) != Err(Error::LltTimeout)
        || io.0.lock().llt.len() != 1
        || io.0.lock().regs[0x100] & 0xc0 != 0
    {
        return TestResult::Fail("LLT timeout advanced or enabled MAC");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu",
    smoke_rtl8188eu_descriptor_geometry_and_llt_failure
);

fn smoke_rtl8188eu_pipeline_rejects_silicon_and_poisoned_tables() -> TestResult {
    for cfg in [u32::MAX, 1 << 23, 8 << 12] {
        let io = Fake::new();
        io.0.lock().regs[0xf0..0xf4].copy_from_slice(&cfg.to_le_bytes());
        let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
        if narf_scheduler::block_on(owner.initialize_device(&image(123)))
            != Err(Error::UnsupportedSilicon)
            || io.0.lock().writes != 0
        {
            return TestResult::Fail("unsupported silicon reached profile-specific writes");
        }
    }
    let io = Fake::new();
    io.0.lock().physical.fill(0xff);
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
    if narf_scheduler::block_on(owner.initialize_device(&image(123))) != Err(Error::BadEfuse)
        || io.0.lock().pages.iter().any(|page| !page.is_empty())
    {
        return TestResult::Fail("erased factory map reached firmware/RF stages");
    }
    let io = Fake::new();
    io.0.lock().pending_write = Some(0x840);
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
    {
        let blob = image(123);
        let mut future = Box::pin(owner.initialize_device(&blob));
        if !matches!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Pending
        ) || owner.status().stage != Stage::InitializingTables
        {
            return TestResult::Fail("post-firmware RF TD did not reach cancellable table stage");
        }
    }
    let g = io.0.lock();
    if owner.status().error != Some(Error::Cancelled)
        || g.unsafe_reuses != 0
        || !g.active_td
        || !matches!(g.ops.last(), Some(Op::Write(0x840, _)))
    {
        return TestResult::Fail(
            "post-firmware cancellation was mistaken for terminal firmware success",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu",
    smoke_rtl8188eu_pipeline_rejects_silicon_and_poisoned_tables
);

fn smoke_rtl8188eu_rf_read_edges_and_lc_restore() -> TestResult {
    for pi in [false, true] {
        let io = Fake::new();
        let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
        {
            let mut g = io.0.lock();
            g.rf[0xef] = 0xabcde;
            g.regs[0x820..0x824].copy_from_slice(&(if pi { 0x100u32 } else { 0 }).to_le_bytes());
        }
        if narf_scheduler::block_on(super::calibration::read_rf(&owner, 0xef)) != Ok(0xabcde) {
            return TestResult::Fail("RF read used wrong address/PI readback");
        }
        let g = io.0.lock();
        let expected = if pi { 0x8b8 } else { 0x8a0 };
        if !matches!(g.ops.last(),Some(Op::Read(reg,4)) if *reg==expected) || !g.ops.iter().any(|op|matches!(op,Op::Write(0x824,v) if u32::from_le_bytes(v[..].try_into().unwrap())==0xf7800000)) || !g.ops.iter().any(|op|matches!(op,Op::Delay(100))) {return TestResult::Fail("RF read edge/address/delay sequence");}
    }
    for continuous in [false, true] {
        let io = Fake::new();
        let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
        let lstf = if continuous {
            0x17000000u32
        } else {
            0x01000000
        };
        {
            let mut g = io.0.lock();
            g.regs[0xd00..0xd04].copy_from_slice(&lstf.to_le_bytes());
            g.regs[0x522] = 0xa5;
            g.rf[0] = 0x76543;
            g.rf[0x18] = 0x30004;
        }
        if narf_scheduler::block_on(super::calibration::lc(&owner)).is_err() {
            return TestResult::Fail("LC calibration failed");
        }
        let g = io.0.lock();
        if g.regs[0xd00..0xd04]!=lstf.to_le_bytes() || g.regs[0x522]!=0xa5 || continuous&&g.rf[0]!=0x76543 || !g.ops.iter().any(|op|matches!(op,Op::Delay(100000))) || !g.ops.iter().any(|op|matches!(op,Op::Write(0x840,v)if u32::from_le_bytes(v[..].try_into().unwrap())==0x1838004)){return TestResult::Fail("LC channel trigger or preexisting TX/continuous state lost");}
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu",
    smoke_rtl8188eu_rf_read_edges_and_lc_restore
);

fn smoke_rtl8188eu_post_table_core_and_iqk_coefficients() -> TestResult {
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
    if narf_scheduler::block_on(owner.initialize_device(&image(123))).is_err()
        || owner.status().stage != Stage::RadioReady
    {
        return TestResult::Fail("production sequence did not reach checked calibration");
    }
    let c = owner.calibration().unwrap();
    if (c.tx_x, c.tx_y, c.rx_x, c.rx_y) != (0x100, 0x3ff, 0x100, 2) {
        return TestResult::Fail("IQK coefficients not retained");
    }
    let g = io.0.lock();
    let word =
        |address: usize| u32::from_le_bytes(g.regs[address..address + 4].try_into().unwrap());
    if word(0xc80) & 0x003f03ff != 0x003f00e4
        || word(0xc94) >> 28 != 15
        || word(0xc14) & 0xffff != 0x900
        || g.regs[0x522] != 0
        || g.regs[0x680] != 0
        || g.regs[0x100] & 0xc0 != 0
    {
        return TestResult::Fail("IQK signed matrix, restore or MAC/security gates wrong");
    }
    if g.regs[0x60f] != 4
        || g.regs[0x610..0x616] != [2, 0xe0, 0x4c, 1, 2, 3]
        || g.regs[0xfe55] & 0x18 != 0x10
        || g.regs[0x10c] & 4 != 0
        || word(0xe00) != 0x20202020
        || g.regs[0x652] != 235
        || g.rf[0x42] != 0x37cf8
    {
        return TestResult::Fail(
            "post-table MAC/aggregation/factory gain/thermal setup incomplete",
        );
    }
    let triggers=g.ops.iter().filter(|op|matches!(op,Op::Write(0xe48,v)if u32::from_le_bytes(v[..].try_into().unwrap())==0xf8000000)).count();
    if triggers != 6 || !g.ops.iter().any(|op| matches!(op, Op::Delay(10000))) {
        return TestResult::Fail("full TX/RX IQK attempts were not triggered");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu",
    smoke_rtl8188eu_post_table_core_and_iqk_coefficients
);

fn smoke_rtl8188eu_cam_iqk_failure_remains_terminal() -> TestResult {
    for cam in [false, true] {
        let io = Fake::new();
        {
            let mut g = io.0.lock();
            g.cam_stalled = cam;
            g.iq_failure = !cam;
        }
        let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
        let expected = if cam {
            Error::CamTimeout
        } else {
            Error::Calibration
        };
        if narf_scheduler::block_on(owner.initialize_device(&image(123))) != Err(expected)
            || owner.status().error != Some(expected)
            || owner.calibration().is_some()
        {
            return TestResult::Fail("CAM/IQK failure accepted or fabricated calibration");
        }
        let count = io.0.lock().ops.len();
        if narf_scheduler::block_on(owner.initialize_device(&image(123)))
            != Err(Error::AlreadyStarted)
            || io.0.lock().ops.len() != count
        {
            return TestResult::Fail("failed radio owner restarted");
        }
        let g = io.0.lock();
        if g.regs[0x100] & 0xc0 != 0
            || cam
                && g.ops
                    .iter()
                    .any(|op| matches!(op, Op::Write(0xe48, v) if v==&0xf9000000u32.to_le_bytes()))
        {
            return TestResult::Fail("failed CAM gate reached IQK or opened MAC");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu",
    smoke_rtl8188eu_cam_iqk_failure_remains_terminal
);

fn smoke_rtl8188eu_calibration_cancel_and_transport_poison() -> TestResult {
    for cancel in [false, true] {
        let io = Fake::new();
        {
            let mut g = io.0.lock();
            if cancel {
                g.pending_write = Some(0xe48);
            } else {
                g.fail_write = Some(0xe48);
            }
        }
        let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
        let blob = image(123);
        if cancel {
            let mut future = Box::pin(owner.initialize_device(&blob));
            if !matches!(
                future
                    .as_mut()
                    .poll(&mut Context::from_waker(Waker::noop())),
                Poll::Pending
            ) || owner.status().stage != Stage::Calibrating
            {
                return TestResult::Fail("submitted IQK TD did not retain calibrating stage");
            }
            drop(future);
        } else if narf_scheduler::block_on(owner.initialize_device(&blob))
            != Err(Error::Usb(UsbError::Stall))
        {
            return TestResult::Fail("IQK transport failure ignored");
        }
        let g = io.0.lock();
        let error = if cancel {
            Error::Cancelled
        } else {
            Error::Usb(UsbError::Stall)
        };
        if owner.status().error != Some(error)
            || owner.calibration().is_some()
            || g.unsafe_reuses != 0
            || !matches!(g.ops.last(), Some(Op::Write(0xe48, _)))
        {
            return TestResult::Fail("IQK drop/error performed cleanup or published usable radio");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu",
    smoke_rtl8188eu_calibration_cancel_and_transport_poison
);

fn smoke_rtl8188eu_rejects_erased_gain_and_absent_radio() -> TestResult {
    let io = Fake::new();
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
    let factory = super::device_init::Factory {
        cut: 0,
        mac: [2, 0, 0, 0, 0, 1],
        cck_power: [0xff; 6],
        ht40_power: [0x20; 5],
        crystal_cap: 0x20,
        channel_plan: 0,
        thermal: 0,
        board_option: 0,
    };
    if narf_scheduler::block_on(super::radio_init::configure(&owner, factory))
        != Err(Error::BadEfuse)
        || !io.0.lock().ops.is_empty()
    {
        return TestResult::Fail("erased factory gains reached radio programming");
    }
    {
        let mut g = io.0.lock();
        g.regs[0x824..0x828].fill(0xff);
    }
    if narf_scheduler::block_on(super::calibration::read_rf(&owner, 0x18)) != Err(Error::RadioRead)
    {
        return TestResult::Fail("absent HSSI read was accepted");
    }
    let g = io.0.lock();
    if g.ops.len() != 1 || !matches!(g.ops[0], Op::Read(0x824, 4)) {
        return TestResult::Fail("absent radio triggered further register writes");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu",
    smoke_rtl8188eu_rejects_erased_gain_and_absent_radio
);

fn smoke_rtl8188eu_initial_channel20_and_factory_crystal() -> TestResult {
    let io = Fake::new();
    {
        let mut m = io.0.lock();
        m.regs[0x603] = 0xa0;
        m.regs[0x800..0x804].copy_from_slice(&0x12345679u32.to_le_bytes());
        m.regs[0x900..0x904].copy_from_slice(&0xfedcba99u32.to_le_bytes());
        m.regs[0x24..0x28].copy_from_slice(&0xf1234567u32.to_le_bytes());
        m.rf[0x18] = 0xf0781;
    }
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
    let f = super::device_init::Factory {
        cut: 0,
        mac: [2, 0, 0, 0, 0, 1],
        cck_power: [32; 6],
        ht40_power: [31; 5],
        crystal_cap: 0x23,
        channel_plan: 0,
        thermal: 0,
        board_option: 0,
    };
    if narf_scheduler::block_on(super::channel_runtime::initial20(&owner, f, 13)).is_err() {
        return TestResult::Fail("initial channel20 rejected");
    }
    let m = io.0.lock();
    let word = |r: usize| u32::from_le_bytes(m.regs[r..r + 4].try_into().unwrap());
    if m.regs[0x603] != 0xa4
        || word(0x800) != 0x12345678
        || word(0x900) != 0xfedcba98
        || m.rf[0x18] != 0xf0c0d
        || word(0x24) != 0xf1471d67
        || word(0x100) & 0xc0 != 0
    {
        return TestResult::Fail(
            "Linux first-channel width/RF/crystal or closed MAC contract differs",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/channel",
    smoke_rtl8188eu_initial_channel20_and_factory_crystal
);

fn smoke_rtl8188eu_initial_channel_rejects_invalid_or_live_mac() -> TestResult {
    for channel in [0, 14, 255] {
        let io = Fake::new();
        let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
        let f = super::device_init::Factory {
            cut: 0,
            mac: [2, 0, 0, 0, 0, 1],
            cck_power: [32; 6],
            ht40_power: [31; 5],
            crystal_cap: 0x23,
            channel_plan: 0,
            thermal: 0,
            board_option: 0,
        };
        if narf_scheduler::block_on(super::channel_runtime::initial20(&owner, f, channel))
            != Err(Error::BadEfuse)
            || !io.0.lock().ops.is_empty()
        {
            return TestResult::Fail("invalid initial channel touched USB");
        }
    }
    let io = Fake::new();
    io.0.lock().regs[0x100] = 0x80;
    let owner = Owner::new(io.clone(), ChipFamily::Rtl8188eu);
    let f = super::device_init::Factory {
        cut: 0,
        mac: [2, 0, 0, 0, 0, 1],
        cck_power: [32; 6],
        ht40_power: [31; 5],
        crystal_cap: 0x23,
        channel_plan: 0,
        thermal: 0,
        board_option: 0,
    };
    if narf_scheduler::block_on(super::channel_runtime::initial20(&owner, f, 1))
        != Err(Error::Calibration)
        || io
            .0
            .lock()
            .ops
            .iter()
            .any(|op| matches!(op, Op::Write(_, _)))
    {
        return TestResult::Fail("live RX was silently retuned or relabelled");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/channel",
    smoke_rtl8188eu_initial_channel_rejects_invalid_or_live_mac
);

#[derive(Default)]
pub(super) struct BulkState {
    next: u64,
    active: Option<u64>,
    pending_stop: bool,
    starts: usize,
    stops: usize,
    tx: Option<(u64, usize)>,
    pub(super) tx_pending: bool,
    pub(super) sent: Vec<(u8, Vec<u8>)>,
}
#[derive(Clone)]
pub(super) struct Bulk {
    control: Fake,
    pub(super) state: Arc<IrqSafeSpinLock<BulkState>>,
}
impl Bulk {
    fn new(control: Fake) -> Self {
        Self {
            control,
            state: Arc::new(IrqSafeSpinLock::new(BulkState::default())),
        }
    }
}
#[async_trait::async_trait]
impl super::packet_transport::Io for Bulk {
    type Receipt = u64;
    fn begin_receive(&self, dci: u8, length: usize) -> Result<u64, UsbError> {
        let mut m = self.state.lock();
        if m.active.is_some() || dci != 3 || length != 4096 {
            return Err(UsbError::Stall);
        }
        m.next += 1;
        let id = m.next;
        m.active = Some(id);
        m.starts += 1;
        self.control.0.lock().ops.push(Op::Write(0xfffe, vec![dci]));
        Ok(id)
    }
    fn poll_receive(&self, receipt: &u64, _: &mut [u8]) -> Result<Option<usize>, UsbError> {
        if self.state.lock().active == Some(*receipt) {
            Ok(None)
        } else {
            Err(UsbError::Stall)
        }
    }
    fn begin_send(&self, dci: u8, bytes: &[u8]) -> Result<u64, UsbError> {
        let mut m = self.state.lock();
        if m.tx.is_some() || dci != 4 {
            return Err(UsbError::Stall);
        }
        m.next += 1;
        let id = m.next;
        m.tx = Some((id, bytes.len()));
        m.sent.push((dci, bytes.to_vec()));
        self.control.0.lock().ops.push(Op::Write(0xfffc, vec![dci]));
        Ok(id)
    }
    fn poll_send(&self, receipt: &u64) -> Result<Option<usize>, UsbError> {
        let mut m = self.state.lock();
        let (id, length) = m.tx.ok_or(UsbError::Stall)?;
        if id != *receipt {
            return Err(UsbError::Stall);
        }
        if m.tx_pending {
            return Ok(None);
        }
        m.tx = None;
        Ok(Some(length))
    }
    async fn stop(&self, r: &u64) -> Result<(), UsbError> {
        let pending = {
            let mut m = self.state.lock();
            if m.active != Some(*r) {
                return Err(UsbError::Stall);
            }
            m.stops += 1;
            self.control.0.lock().ops.push(Op::Write(0xfffd, vec![]));
            m.pending_stop
        };
        if pending {
            core::future::pending::<()>().await;
        }
        self.state.lock().active = None;
        Ok(())
    }
}
fn receive_permission() -> super::receive_runtime::Permission {
    super::receive_runtime::Permission::from_domain(&narf_wireless::reg::RegulatoryDomain {
        country_code: *b"US",
        rules: vec![narf_wireless::reg::RegRule {
            freq_start_mhz: 2402,
            freq_end_mhz: 2422,
            max_bandwidth_mhz: 20,
            max_power_dbm: 0,
            flags: narf_wireless::reg::RegFlags::empty(),
        }],
    })
    .unwrap()
}
pub(super) fn prepared_receiver() -> (
    Fake,
    Arc<Owner<Fake>>,
    Bulk,
    super::receive_runtime::Receiver<Fake, Bulk>,
) {
    let control = Fake::new();
    let owner = Arc::new(Owner::new(control.clone(), ChipFamily::Rtl8188eu));
    narf_scheduler::block_on(owner.initialize_device(&image(123))).unwrap();
    let bulk = Bulk::new(control.clone());
    let receiver =
        super::receive_runtime::Receiver::new(owner.clone(), bulk.clone(), receive_permission())
            .unwrap();
    (control, owner, bulk, receiver)
}
fn smoke_rtl8188eu_receiver_composes_claim_rx_gate_and_proven_stop() -> TestResult {
    use super::receive_runtime::Phase;
    let (control, owner, bulk, mut receiver) = prepared_receiver();
    control.0.lock().ops.clear();
    if narf_scheduler::block_on(receiver.start()).is_err()
        || receiver.phase() != Phase::Receiving
        || owner.status().stage != Stage::Receiving
        || receiver.channel() != 1
    {
        return TestResult::Fail("composed radio/packet owner did not enter receiving");
    }
    for _ in 0..1000 {
        if receiver.poll() != Ok(None) {
            return TestResult::Fail("quiet RX cancelled or invented MPDU");
        }
    }
    {
        let m = control.0.lock();
        let posted = m
            .ops
            .iter()
            .position(|op| matches!(op, Op::Write(0xfffe, _)))
            .unwrap();
        let opened = m
            .ops
            .iter()
            .position(|op| matches!(op,Op::Write(0x100,v)if v[0]&0xc0==0x80))
            .unwrap();
        if posted >= opened || bulk.state.lock().starts != 1 || m.regs[0x100] & 0xc0 != 0x80 {
            return TestResult::Fail(
                "MAC RX opened before persistent buffer ownership or TX opened",
            );
        }
    }
    control.0.lock().ops.clear();
    if narf_scheduler::block_on(receiver.stop()).is_err()
        || receiver.phase() != Phase::Stopped
        || owner.status().stage != Stage::ReceiveStopped
        || bulk.state.lock().active.is_some()
    {
        return TestResult::Fail("successful host stop did not retain paused radio state");
    }
    {
        let m = control.0.lock();
        let closed = m
            .ops
            .iter()
            .position(|op| matches!(op,Op::Write(0x100,v)if v[0]&0xc0==0))
            .unwrap();
        let stopped = m
            .ops
            .iter()
            .position(|op| matches!(op, Op::Write(0xfffd, _)))
            .unwrap();
        if closed >= stopped {
            return TestResult::Fail("USB stop preceded MAC RX gate closure");
        }
    }
    if narf_scheduler::block_on(receiver.start()).is_err()
        || receiver.channel() != 1
        || bulk.state.lock().starts != 2
    {
        return TestResult::Fail("same-channel proven pause could not restart");
    }
    if super::receive_runtime::Receiver::new(owner, bulk, receive_permission()).is_ok() {
        return TestResult::Fail("second receiver acquired live radio controls");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/receive",
    smoke_rtl8188eu_receiver_composes_claim_rx_gate_and_proven_stop
);

fn smoke_rtl8188eu_receiver_cancel_after_real_rx_gate_td_is_terminal() -> TestResult {
    use super::receive_runtime::Phase;
    let (control, owner, bulk, mut receiver) = prepared_receiver();
    control.0.lock().pending_write = Some(0x100);
    {
        let mut f = Box::pin(receiver.start());
        if f.as_mut().poll(&mut Context::from_waker(Waker::noop())) != Poll::Pending
            || bulk.state.lock().active.is_none()
            || !control.0.lock().active_td
        {
            return TestResult::Fail("start cancellation did not reach submitted EP0 gate TD");
        }
    }
    let before = control.0.lock().ops.len();
    if receiver.phase() != Phase::Failed
        || owner.status().error != Some(Error::Cancelled)
        || narf_scheduler::block_on(receiver.start()).is_ok()
        || narf_scheduler::block_on(receiver.stop()).is_ok()
        || control.0.lock().ops.len() != before
        || bulk.state.lock().stops != 0
        || control.0.lock().unsafe_reuses != 0
    {
        return TestResult::Fail("cancelled EP0 activation performed cleanup or reused native RX");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/receive",
    smoke_rtl8188eu_receiver_cancel_after_real_rx_gate_td_is_terminal
);

fn smoke_rtl8188eu_receiver_cancel_after_mac_closed_and_stop_submitted() -> TestResult {
    use super::receive_runtime::Phase;
    let (control, owner, bulk, mut receiver) = prepared_receiver();
    narf_scheduler::block_on(receiver.start()).unwrap();
    bulk.state.lock().pending_stop = true;
    {
        let mut f = Box::pin(receiver.stop());
        if f.as_mut().poll(&mut Context::from_waker(Waker::noop())) != Poll::Pending
            || control.0.lock().regs[0x100] & 0xc0 != 0
            || bulk.state.lock().stops != 1
        {
            return TestResult::Fail("stop cancellation did not reach actual submitted host stop");
        }
    }
    let before = control.0.lock().ops.len();
    if receiver.phase() != Phase::Failed
        || owner.status().error != Some(Error::Cancelled)
        || bulk.state.lock().active.is_none()
        || narf_scheduler::block_on(receiver.start()).is_ok()
        || control.0.lock().ops.len() != before
    {
        return TestResult::Fail("cancelled host stop reclaimed receipt or reopened receive gate");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtl8xxxu/receive",
    smoke_rtl8188eu_receiver_cancel_after_mac_closed_and_stop_submitted
);

pub(super) fn initialized_firmware() -> (Fake, Arc<Owner<Fake>>) {
    let control = Fake::new();
    let owner = Arc::new(Owner::new(control.clone(), ChipFamily::Rtl8188eu));
    narf_scheduler::block_on(owner.initialize_device(&image(123))).unwrap();
    (control, owner)
}

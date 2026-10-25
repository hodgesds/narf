use super::*;
use alloc::{boxed::Box, vec, vec::Vec};
use core::{
    future::Future,
    task::{Context, Poll, Waker},
};
use narf_kernel_test::{kernel_test_in, TestResult};
type Operation = (u8, u8, u16, u32);
include!("golden.rs");
include!("rtl8821c_golden.rs");
include!("../factory/golden.rs");

pub(super) struct Model {
    pub(super) regs: Vec<u8>,
    pub(super) trace: Vec<Operation>,
    pub(super) fail: Option<usize>,
    parked: bool,
    mac_started: bool,
    ll_t_stall: bool,
    pub(super) suspend: bool,
    pub(super) suspend_at: Option<usize>,
    bad_h2c: u8,
    pub(super) phy_started: bool,
}
impl Model {
    pub(super) fn new(seed: u8, cut: u8) -> Self {
        let mut regs = (0..0x5000)
            .map(|i| {
                (i as u8)
                    .wrapping_mul(17)
                    .wrapping_add(seed.wrapping_mul(83))
            })
            .collect::<Vec<_>>();
        regs[0xf0..0xf4].copy_from_slice(&(u32::from(cut) << 12).to_le_bytes());
        Self {
            regs,
            trace: Vec::new(),
            fail: None,
            parked: false,
            mac_started: false,
            ll_t_stall: false,
            suspend: false,
            suspend_at: None,
            bad_h2c: 0,
            phy_started: false,
        }
    }
    fn access(&mut self, op: Operation) -> Result<(), Error> {
        let at = self.trace.len();
        self.trace.push(op);
        if self.fail == Some(at) {
            Err(Error::Access)
        } else {
            Ok(())
        }
    }
    fn read(&mut self, width: u8, reg: u16) -> Result<u32, Error> {
        self.access((0, width, reg, 0))?;
        let mut bytes = [0; 4];
        let at = usize::from(reg);
        bytes[..usize::from(width / 8)]
            .copy_from_slice(&self.regs[at..at + usize::from(width / 8)]);
        let mut value = u32::from_le_bytes(bytes);
        if reg == 0x208 && !self.ll_t_stall {
            value &= !1;
        }
        if reg == 0x1208 {
            value &= !(1 << 31);
        }
        if reg == 0x80 && value & (1 << 14) != 0 {
            value |= 1 << 15;
            if self.regs[0x1a0] == 0xfd {
                self.regs[0x1a0] = 0x19;
                self.regs[0x1a2..0x1af].fill(0);
                self.regs[0x1a6..0x1aa].copy_from_slice(
                    &((7u32 << 16) | (2 << 19) | (2 << 21) | (3 << 26)).to_le_bytes(),
                );
            }
        }
        Ok(value)
    }
    fn write(&mut self, width: u8, reg: u16, value: u32) -> Result<(), Error> {
        self.access((1, width, reg, value))?;
        let at = usize::from(reg);
        self.regs[at..at + usize::from(width / 8)]
            .copy_from_slice(&value.to_le_bytes()[..usize::from(width / 8)]);
        if self.mac_started
            && (reg == 0x100 && value & 0xcf != 0 || reg == 0x522 && value & 255 != 255)
        {
            return Err(Error::Prerequisite);
        }
        if reg == 0x254 && value & 4 != 0 {
            let address = match self.bad_h2c {
                0 => u32::from_le_bytes(self.regs[0x244..0x248].try_into().unwrap()) & 0x3ffff,
                1 => return Ok(()),
                _ => 0,
            };
            self.regs[0x10d0..0x10d4].copy_from_slice(&address.to_le_bytes());
            self.regs[0x10d4..0x10d8].copy_from_slice(&address.to_le_bytes());
        }
        Ok(())
    }
}
#[async_trait::async_trait]
// SAFETY: an inert device-side model. Native publication is represented by
// retained byte vectors and phase flags; no addresses reach physical hardware.
unsafe impl Io for Model {
    fn claim_pristine(&mut self) -> Result<(), Error> {
        self.access((2, 0, 0, 0))?;
        self.regs[0x1a0] = 0xfd;
        Ok(())
    }
    fn read8(&mut self, reg: u16) -> Result<u8, Error> {
        self.read(8, reg).map(|v| v as u8)
    }
    fn read16(&mut self, reg: u16) -> Result<u16, Error> {
        self.read(16, reg).map(|v| v as u16)
    }
    fn read32(&mut self, reg: u16) -> Result<u32, Error> {
        self.read(32, reg)
    }
    fn write8(&mut self, reg: u16, value: u8) -> Result<(), Error> {
        self.write(8, reg, u32::from(value))
    }
    fn write16(&mut self, reg: u16, value: u16) -> Result<(), Error> {
        self.write(16, reg, u32::from(value))
    }
    fn write32(&mut self, reg: u16, value: u32) -> Result<(), Error> {
        self.write(32, reg, value)
    }
    async fn reserved_page(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.access((3, 0, 0, bytes.len() as u32))
    }
    async fn lte_backup(&mut self) -> Result<u32, Error> {
        Ok(0x12345678)
    }
    async fn lte_restore(&mut self, value: u32) -> Result<(), Error> {
        self.access((4, 0, 0, value))
    }
    async fn finish_dma(&mut self) -> Result<(), Error> {
        self.access((5, 0, 0, 0))?;
        self.parked = true;
        Ok(())
    }
    fn begin_mac(&mut self) -> Result<(), Error> {
        self.access((6, 0, 0, 0))?;
        if !self.parked || self.mac_started {
            return Err(Error::State);
        }
        self.mac_started = true;
        self.parked = false;
        Ok(())
    }
    fn finish_mac(&mut self) -> Result<(), Error> {
        self.access((7, 0, 0, 0))?;
        if !self.mac_started || self.regs[0x100] & 0xcf != 0 || self.regs[0x522] != 255 {
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    fn begin_phy(&mut self) -> Result<(), Error> {
        self.access((9, 0, 0, 0))?;
        if !self.mac_started || self.phy_started {
            return Err(Error::State);
        }
        self.phy_started = true;
        Ok(())
    }
    fn finish_phy(&mut self) -> Result<(), Error> {
        self.access((10, 0, 0, 0))?;
        if !self.phy_started || self.regs[0x100] & 0xcf != 0 || self.regs[0x522] != 255 {
            return Err(Error::Prerequisite);
        }
        Ok(())
    }
    async fn delay_us(&mut self, us: u64) {
        self.trace.push((8, 0, 0, us as u32));
        if self.suspend || self.suspend_at == Some(self.trace.len() - 1) {
            core::future::pending::<()>().await;
        }
    }
}
pub(super) fn firmware() -> Vec<u8> {
    let mut bytes = vec![0; 64 + 9 + 9];
    bytes[..2].copy_from_slice(&[0x22, 0x88]);
    for (offset, value) in [
        (0x20, 0x80200000u32),
        (0x24, 1),
        (0x30, 1),
        (0x3c, 0x80030000),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}
pub(super) fn ready_8821c() -> Owner<Model> {
    let mut io = Model::new(0, 3);
    io.regs[0x1208..0x120c].fill(0);
    io.regs[0x80..0x84].fill(0);
    let mut bytes = firmware();
    bytes[..2].copy_from_slice(&[0x21, 0x88]);
    let mut owner = Owner::new(io, 0xc821);
    narf_scheduler::block_on(owner.download(&bytes)).unwrap();
    owner.io.regs[0x1a6..0x1aa]
        .copy_from_slice(&((7u32 << 16) | (1 << 19) | (1 << 21) | (3 << 26)).to_le_bytes());
    owner.io.trace.clear();
    owner
}

fn smoke_rtw8821ce_inactive_mac_matches_frozen_referenceship_and_fifo_traces() -> TestResult {
    for (seed, cut, expected) in [(0, 0, LINUX_8821C_MAC_0), (1, 3, LINUX_8821C_MAC_1)] {
        let mut io = Model::new(seed, cut);
        let info = match narf_scheduler::block_on(crate::rtw88::mac::prepare_for(&mut io, 0xc821)) {
            Ok(info) => info,
            Err(_) => return TestResult::Fail("8821C inactive MAC did not complete"),
        };
        if io.trace != expected
            || info.reserved_boundary != 460
            || info.h2c_page != 500
            || info.firmware_tx_page != 508
            || io.regs[0x100] & 0xcf != 0
            || io.regs[0x522] != 255
            || io.trace.iter().any(|op| op.0 == 1 && op.2 == 0x3fc)
        {
            return TestResult::Fail(
                "8821C FIFO/chip sequence differs from the frozen reference or used a C22 quirk",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_inactive_mac_matches_frozen_referenceship_and_fifo_traces
);

fn smoke_rtw8821ce_same_firmware_owner_mac_failures_and_no_wrong_phy() -> TestResult {
    let mut reference = ready_8821c();
    if narf_scheduler::block_on(reference.prepare_mac()).is_err()
        || reference.phase() != Phase::MacPrepared
        || reference
            .hardware_info()
            .is_none_or(|caps| caps.streams != 1 || caps.antennas != 1)
    {
        return TestResult::Fail("8821C same firmware owner lost hardware report/MAC completion");
    }
    let total = reference.io.trace.len();
    let mut wrong_factory = [255; 768];
    wrong_factory[0x120..0x126].copy_from_slice(&[2, 4, 6, 8, 10, 12]);
    let wrong_factory = crate::rtw88::efuse::Factory::for_test(wrong_factory).unwrap();
    if narf_scheduler::block_on(reference.prepare_phy_tables(&wrong_factory))
        != Err(Error::Unsupported)
        || reference.phase() != Phase::MacPrepared
        || reference.io.trace.len() != total
    {
        return TestResult::Fail(
            "8821C accepted C22 factory/PHY programming or lost parked checkpoint",
        );
    }
    for fail in 0..total {
        let mut owner = ready_8821c();
        owner.io.fail = Some(fail);
        if narf_scheduler::block_on(owner.prepare_mac()) != Err(Error::Access)
            || owner.phase() != Phase::Failed
            || owner.mac_info().is_some()
            || owner.io.trace.len() != fail + 1
        {
            return TestResult::Fail("8821C native MAC error advanced/reopened ownership");
        }
        let before = owner.io.trace.len();
        if narf_scheduler::block_on(owner.prepare_mac()) != Err(Error::State)
            || owner.io.trace.len() != before
        {
            return TestResult::Fail("8821C terminal native MAC work was replayed");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_same_firmware_owner_mac_failures_and_no_wrong_phy
);

fn smoke_rtw8821ce_llt_cancel_and_stale_hardware_report_remain_closed() -> TestResult {
    let mut missing = ready_8821c();
    missing.io.regs[0x1a0] = 0xfd;
    if narf_scheduler::block_on(missing.prepare_mac()) != Err(Error::Prerequisite)
        || missing.hardware_info().is_some()
        || missing.io.trace.iter().any(|op| op.0 == 1)
    {
        return TestResult::Fail("8821C used an unreceived hardware report");
    }
    let mut owner = ready_8821c();
    owner.io.ll_t_stall = true;
    owner.io.suspend = true;
    {
        let mut prepare = core::pin::pin!(owner.prepare_mac());
        if prepare
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            .is_ready()
        {
            return TestResult::Fail("8821C native LLT work failed to suspend after publication");
        }
    }
    let before = owner.io.trace.len();
    if owner.phase() != Phase::Failed
        || owner.mac_info().is_some()
        || narf_scheduler::block_on(owner.prepare_mac()) != Err(Error::State)
        || owner.io.trace.len() != before
    {
        return TestResult::Fail("8821C cancelled LLT work claimed MAC readiness or restarted");
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88/rtl8821c",
    smoke_rtw8821ce_llt_cancel_and_stale_hardware_report_remain_closed
);
pub(super) fn ready() -> Owner<Model> {
    let mut io = Model::new(0, 3);
    io.regs[0x1208..0x120c].fill(0);
    io.regs[0x80..0x84].fill(0);
    let mut owner = Owner::new(io, 0xc822);
    narf_scheduler::block_on(owner.download(&firmware())).unwrap();
    owner.io.trace.clear();
    owner
}
fn smoke_rtw8822ce_inactive_mac_matches_frozen_fifo_and_chip_setup() -> TestResult {
    for (word, fields) in LINUX_HW_FEATURES {
        let mut io = Model::new(0, 0);
        io.regs[0x1a0] = 0x19;
        io.regs[0x1a2..0x1af].fill(0);
        io.regs[0x1a6..0x1aa].copy_from_slice(&word.to_le_bytes());
        let report = match crate::rtw88::hardware::Features::read(&mut io) {
            Ok(r) => r,
            Err(_) => return TestResult::Fail("literal hardware feature report rejected"),
        };
        if [
            report.hci,
            report.bandwidth,
            report.streams,
            report.antennas,
            report.protocol,
        ] != *fields
            || report.raw[4..8] != word.to_le_bytes()
            || io.regs[0x1a0] != 0
            || io.trace.len() != 15
        {
            return TestResult::Fail(
                "hardware report differs from actual Linux packed field macros",
            );
        }
    }
    for (seed, cut, expected) in [(0, 0, LINUX_MAC_0), (1, 3, LINUX_MAC_1)] {
        let mut io = Model::new(seed, cut);
        let result = narf_scheduler::block_on(crate::rtw88::mac::prepare(&mut io));
        if result
            != Ok(crate::rtw88::mac::Info {
                cut,
                reserved_boundary: 1938,
                h2c_page: 1986,
                firmware_tx_page: 1994,
            })
            || io.trace != expected
        {
            return TestResult::Fail(
                "inactive MAC diverged from extracted Linux FIFO/LLT/chip trace",
            );
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_inactive_mac_matches_frozen_fifo_and_chip_setup
);

fn smoke_rtw8822ce_same_firmware_owner_mac_continuation_and_every_access_failure() -> TestResult {
    let mut reference = ready();
    let info = match narf_scheduler::block_on(reference.prepare_mac()) {
        Ok(v) => v,
        Err(_) => return TestResult::Fail("same firmware owner did not prepare inactive MAC"),
    };
    if reference.phase() != Phase::MacPrepared || reference.mac_info() != Some(info) {
        return TestResult::Fail("MAC completion state was not retained");
    }
    if reference
        .hardware_info()
        .is_none_or(|h| h.streams != 2 || h.antennas != 2 || h.bandwidth != 7 || h.protocol != 3)
        || reference.io.regs[0x1a0] != 0
    {
        return TestResult::Fail(
            "firmware hardware report not retained/acknowledged by exact owner",
        );
    }
    let before = reference.io.trace.len();
    if narf_scheduler::block_on(reference.prepare_mac()) != Err(Error::State)
        || reference.io.trace.len() != before
    {
        return TestResult::Fail("MAC prepared owner reconstructed native state");
    }
    for fail in 0..before {
        let mut owner = ready();
        owner.io.fail = Some(fail);
        if narf_scheduler::block_on(owner.prepare_mac()) != Err(Error::Access)
            || owner.phase() != Phase::Failed
            || owner.mac_info().is_some()
            || owner.io.trace.len() != fail + 1
        {
            return TestResult::Fail("MAC access failure continued or published readiness");
        }
        let calls = owner.io.trace.len();
        if narf_scheduler::block_on(owner.prepare_mac()) != Err(Error::State)
            || owner.io.trace.len() != calls
            || narf_scheduler::block_on(owner.download(&firmware())) != Err(Error::State)
        {
            return TestResult::Fail("failed MAC owner retried native state or firmware");
        }
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_same_firmware_owner_mac_continuation_and_every_access_failure
);

fn smoke_rtw8822ce_llt_cancellation_and_wrong_h2c_queue_never_claim_ready() -> TestResult {
    for id in [0, 0xfd, 0xff] {
        let mut owner = ready();
        owner.io.regs[0x1a0] = id;
        if narf_scheduler::block_on(owner.prepare_mac()) != Err(Error::Prerequisite)
            || owner.hardware_info().is_some()
            || owner.mac_info().is_some()
            || owner.io.trace.iter().any(|op| op.0 == 1)
        {
            return TestResult::Fail(
                "missing/unconsumed hardware report reached MAC configuration",
            );
        }
    }
    for bad in [1, 2] {
        let mut owner = ready();
        owner.io.bad_h2c = bad;
        if narf_scheduler::block_on(owner.prepare_mac()) != Err(Error::Prerequisite)
            || owner.phase() != Phase::Failed
            || owner.mac_info().is_some()
            || owner.io.trace.iter().any(|op| op.0 == 7)
        {
            return TestResult::Fail("invalid H2C queue pointers claimed MAC completion");
        }
    }
    let mut owner = ready();
    owner.io.ll_t_stall = true;
    owner.io.suspend = true;
    {
        let mut future = core::pin::pin!(owner.prepare_mac());
        if future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()))
            != Poll::Pending
        {
            return TestResult::Fail("LLT fixture did not suspend after publication");
        }
    }
    let calls = owner.io.trace.len();
    if owner.phase() != Phase::Failed
        || owner.mac_info().is_some()
        || !owner.io.mac_started
        || owner.io.parked
        || owner.io.trace.iter().any(|op| op.0 == 7)
        || narf_scheduler::block_on(owner.prepare_mac()) != Err(Error::State)
        || owner.io.trace.len() != calls
    {
        return TestResult::Fail(
            "cancelled LLT preparation reopened or claimed completed native state",
        );
    }
    TestResult::Pass
}
kernel_test_in!(
    "drivers/wireless/rtw88",
    smoke_rtw8822ce_llt_cancellation_and_wrong_h2c_queue_never_claim_ready
);

//! The SMU firmware mailbox that amd_pmc and amd_pmf share.
//!
//! AMD client SoCs expose PMFW mailboxes in one 4 KiB MMIO window whose
//! base two SMN registers report. Each driver owns a mailbox there — a
//! message, an argument and a response register at its own offsets —
//! and speaks the same protocol to it (`amd_pmc_send_cmd`,
//! `amd_pmf_send_cmd`): wait for the previous response, clear it, write
//! the argument and the message ID, wait up to 1 s for the new
//! response, and decode it.
//!
//! Ref: drivers/platform/x86/amd/pmc/pmc.c, drivers/platform/x86/amd/pmf/core.c.

/// The window size and its offset from the SMN-reported base
/// (`AMD_PMC_MAPPING_SIZE` / `AMD_PMF_MAPPING_SIZE`,
/// `*_BASE_ADDR_OFFSET`).
pub const MAPPING_SIZE: u64 = 0x1000;
pub const BASE_ADDR_OFFSET: u64 = 0x1_0000;
/// SMN registers holding the window base (`*_BASE_ADDR_LO` / `_HI`).
pub const BASE_ADDR_LO: u32 = 0x13b1_02e8;
pub const BASE_ADDR_HI: u32 = 0x13b1_02ec;
const BASE_ADDR_LO_MASK: u32 = 0xffff;
const BASE_ADDR_HI_MASK: u32 = 0xfff0_0000;

/// Response codes, identical for both mailboxes.
pub const RESULT_OK: u32 = 0x01;
pub const RESULT_CMD_REJECT_BUSY: u32 = 0xfc;
pub const RESULT_CMD_REJECT_PREREQ: u32 = 0xfd;
pub const RESULT_CMD_UNKNOWN: u32 = 0xfe;
pub const RESULT_FAILED: u32 = 0xff;

/// `readx_poll_timeout(..., MSG_DELAY_MIN_US, MSG_DELAY_MIN_US *
/// RESPONSE_REGISTER_LOOP_MAX)`: 50 µs × 20000 = 1 s, for both drivers.
pub const RESPONSE_TIMEOUT_NS: u64 = 50 * 20_000 * 1_000;

/// One mailbox's registers, as offsets in the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MailboxRegs {
    pub message: u32,
    pub argument: u32,
    pub response: u32,
}

/// A failed mailbox transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmuError {
    /// "failed to talk to SMU" / "SMU response timed out".
    Timeout,
    /// `RESULT_CMD_REJECT_BUSY` (Linux `-EBUSY`).
    Busy,
    /// `RESULT_CMD_UNKNOWN` (Linux `-EINVAL`).
    Unknown,
    /// Any other response, `RESULT_CMD_REJECT_PREREQ` and
    /// `RESULT_FAILED` included (Linux `-EIO`).
    Failed(u32),
}

/// Register access to the mailbox window, plus a clock for its waits.
pub trait SmuMailbox {
    fn read32(&mut self, offset: u32) -> u32;
    fn write32(&mut self, offset: u32, value: u32);
    /// Nanoseconds on a clock that runs while the caller spins.
    fn now_ns(&mut self) -> u64;
    /// `usleep_range`/`msleep`: spin `us` microseconds.
    fn delay_us(&mut self, us: u64) {
        let end = self.now_ns().saturating_add(us * 1000);
        while self.now_ns() < end {
            core::hint::spin_loop();
        }
    }
}

/// The window's physical base from the two SMN words, masked as Linux
/// masks them (the low word keeps bits 31:20, the high word bits 15:0),
/// plus the offset.
pub fn window(lo: u32, hi: u32) -> u64 {
    let base = (u64::from(hi & BASE_ADDR_LO_MASK) << 32) | u64::from(lo & BASE_ADDR_HI_MASK);
    base + BASE_ADDR_OFFSET
}

fn wait_response<M: SmuMailbox + ?Sized>(mb: &mut M, regs: &MailboxRegs) -> Result<u32, SmuError> {
    let deadline = mb.now_ns().saturating_add(RESPONSE_TIMEOUT_NS);
    loop {
        let value = mb.read32(regs.response);
        if value != 0 {
            return Ok(value);
        }
        if mb.now_ns() >= deadline {
            return Err(SmuError::Timeout);
        }
        core::hint::spin_loop();
    }
}

/// `*_send_cmd` without a data reply: wait for the previous response,
/// clear it, write the argument and the message, then wait for and
/// decode the new response.
pub fn send<M: SmuMailbox + ?Sized>(
    mb: &mut M,
    regs: &MailboxRegs,
    arg: u32,
    msg: u32,
) -> Result<(), SmuError> {
    wait_response(mb, regs)?;
    mb.write32(regs.response, 0);
    mb.write32(regs.argument, arg);
    mb.write32(regs.message, msg);
    match wait_response(mb, regs)? {
        RESULT_OK => Ok(()),
        RESULT_CMD_REJECT_BUSY => Err(SmuError::Busy),
        RESULT_CMD_UNKNOWN => Err(SmuError::Unknown),
        other => Err(SmuError::Failed(other)),
    }
}

/// `*_send_cmd` with a data reply: the argument register, read after
/// PMFW has had `settle_us` to fill it.
pub fn send_read<M: SmuMailbox + ?Sized>(
    mb: &mut M,
    regs: &MailboxRegs,
    arg: u32,
    msg: u32,
    settle_us: u64,
) -> Result<u32, SmuError> {
    send(mb, regs, arg, msg)?;
    mb.delay_us(settle_us);
    Ok(mb.read32(regs.argument))
}

/// The raw monotonic clock the mailbox waits run on.
pub fn raw_ns() -> u64 {
    narf_time::cycles_to_ns(narf_time::raw_cycles())
}

/// The mapped window.
#[derive(Debug)]
pub struct MmioMailbox {
    regs: u64,
}

impl MmioMailbox {
    /// `devm_ioremap` of the window at `phys`.
    pub fn map(phys: u64) -> Option<Self> {
        // SAFETY: the SMU mailbox window is device MMIO; Device attributes
        // keep the accesses uncached and ordered. The ioremap cache hands
        // a second driver the same mapping of the shared page.
        let mapping = unsafe {
            narf_memory::ioremap::ioremap(
                phys,
                MAPPING_SIZE,
                narf_memory::ioremap::MmioAttrs::Device,
            )
        }
        .ok()?;
        Some(Self { regs: mapping.va() })
    }

    /// The mapped base, for drivers that add their own registers.
    pub fn va(&self) -> u64 {
        self.regs
    }
}

impl SmuMailbox for MmioMailbox {
    fn read32(&mut self, offset: u32) -> u32 {
        debug_assert!(u64::from(offset) + 4 <= MAPPING_SIZE);
        // SAFETY: the window is a Device ioremap of MAPPING_SIZE bytes and
        // every mailbox offset is inside it.
        unsafe { core::ptr::read_volatile((self.regs + u64::from(offset)) as *const u32) }
    }
    fn write32(&mut self, offset: u32, value: u32) {
        debug_assert!(u64::from(offset) + 4 <= MAPPING_SIZE);
        // SAFETY: as for `read32`.
        unsafe { core::ptr::write_volatile((self.regs + u64::from(offset)) as *mut u32, value) }
    }
    fn now_ns(&mut self) -> u64 {
        raw_ns()
    }
}

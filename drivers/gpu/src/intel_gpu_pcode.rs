//! GT pcode mailbox codec — Gen12 display reads and the CDCLK
//! frequency-request write.
//!
//! The pcode (punit) mailbox is how the display engine asks the
//! power controller for platform data. Lane Q6 (#1024) needs two
//! reads from it: the memory-latency table that drives the
//! watermark algorithm, and the SAGV block time. The Gen12 CDCLK
//! change sequence (`intel_gpu_gen12_cdclk`) needs one write:
//! the display-engine frequency request that lets the punit set
//! the voltage for the new CDCLK before the PLL is reprogrammed.
//!
//! ## Protocol (i915 `display/intel_pcode.c::__snb_pcode_rw`)
//!
//! 1. If `GEN6_PCODE_MAILBOX.READY` is set, the mailbox is busy
//!    with someone else's transaction — fail, don't clobber it.
//! 2. Write the input dwords to `GEN6_PCODE_DATA0` / `DATA1`.
//! 3. Write `GEN6_PCODE_MAILBOX` = `READY | command |
//!    param1 << 8 | param2 << 16`.
//! 4. Poll until `READY` clears (i915 budgets 500 µs fast +
//!    20 ms slow for reads; this codec uses one 20 ms budget).
//! 5. Read the result dwords back from `DATA0` / `DATA1`.
//! 6. The low byte of the final mailbox word is the status:
//!    0 = success. i915's `gen7_check_mailbox_status` maps the
//!    documented codes to errors and treats *undocumented*
//!    nonzero codes as success-with-a-log-line; this codec does
//!    the same — a watermark computed from a read the punit
//!    rejected would be fiction, but an unrecognised status the
//!    reference driver accepts must not brick the modeset.
//!
//! ## Reference
//!
//! - Linux `drivers/gpu/drm/i915/display/intel_pcode.c`
//!   (`__snb_pcode_rw`, `gen7_check_mailbox_status`)
//! - Linux `drivers/gpu/drm/i915/display/intel_pcode_regs.h`
//!   (`GEN6_PCODE_*`, `GEN9_PCODE_READ_MEM_LATENCY`,
//!   `GEN12_PCODE_READ_SAGV_BLOCK_TIME_US`)
//! - Linux `drivers/gpu/drm/i915/i915_reg.h` v6.12
//!   (`GEN6_PCODE_MAILBOX` 0x138124, `GEN6_PCODE_DATA`
//!   0x138128, `GEN6_PCODE_DATA1` 0x13812C)

use core::sync::atomic::{compiler_fence, Ordering};
// Every current iGPU PCODE client (modeset and retained cursor/DSB profile)
// uses this port exclusion. BMG hwmon owns a different PCI function/port.
static TRANSACTION: narf_lib::mutex::Mutex<()> = narf_lib::mutex::Mutex::new(());

use crate::intel_gpu_aux::MmioWindow;

/// `GEN6_PCODE_MAILBOX` — command / status register.
pub const PCODE_MAILBOX: u64 = 0x0013_8124;
/// `GEN6_PCODE_DATA` (DATA0) — first data dword.
pub const PCODE_DATA0: u64 = 0x0013_8128;
/// `GEN6_PCODE_DATA1` — second data dword.
pub const PCODE_DATA1: u64 = 0x0013_812C;

/// `GEN6_PCODE_READY` — transaction-in-flight bit (bit 31).
pub const PCODE_READY: u32 = 1 << 31;

/// `GEN9_PCODE_READ_MEM_LATENCY` (0x6). DATA0-in selects the
/// level set: 0 → levels 0..3, 1 → levels 4..7. Each level is
/// one byte of the returned DATA0, level n at bits [8n+7:8n],
/// in microseconds.
pub const PCODE_CMD_READ_MEM_LATENCY: u32 = 0x06;

/// `GEN12_PCODE_READ_SAGV_BLOCK_TIME_US` (0x23). Returns the
/// SAGV block time in microseconds in DATA0.
pub const PCODE_CMD_READ_SAGV_BLOCK_TIME_US: u32 = 0x23;

/// `HSW_PCODE_DE_WRITE_FREQ_REQ` (0x17, `i915_reg.h`): the
/// display-engine frequency request. DATA0-in carries the
/// request: 0x80000000 for a pre-change notification (the punit
/// raises the voltage for the new CDCLK), or the target voltage
/// level for the post-change notification (`bxt_cdclk_pcode_pre_notify`
/// / `bxt_cdclk_pcode_post_notify` in `display/intel_cdclk.c`).
/// The punit answers with no data dwords.
pub const PCODE_CMD_DE_WRITE_FREQ_REQ: u32 = 0x17;

/// `SKL_PCODE_CDCLK_CONTROL` (0x7, `intel_pcode_regs.h`): the
/// Skylake CDCLK-control mailbox command used by
/// `skl_cdclk_pcode_pre_notify` / `skl_cdclk_pcode_post_notify`
/// in `display/intel_cdclk.c` — the notify protocol the Gen11
/// (`icl_cdclk_funcs` / `ehl_cdclk_funcs`) CDCLK change uses,
/// as opposed to the `HSW_PCODE_DE_WRITE_FREQ_REQ` protocol
/// the BXT/TGL funcs use. Pre-notify writes DATA0
/// `SKL_CDCLK_PREPARE_FOR_CHANGE` and the reply DATA0 must
/// carry `SKL_CDCLK_READY_FOR_CHANGE`; post-notify writes
/// DATA0 = the target voltage level.
pub const PCODE_CMD_CDCLK_CONTROL: u32 = 0x7;
/// `SKL_CDCLK_PREPARE_FOR_CHANGE` (0x3, `intel_pcode_regs.h`).
pub const SKL_CDCLK_PREPARE_FOR_CHANGE: u32 = 0x3;
/// `SKL_CDCLK_READY_FOR_CHANGE` (0x1, `intel_pcode_regs.h`).
pub const SKL_CDCLK_READY_FOR_CHANGE: u32 = 0x1;

/// Documented pcode status codes from `intel_pcode_regs.h`.
/// Codes not in this list fall through to success, mirroring
/// i915's `gen7_check_mailbox_status` default arm.
fn status_is_error(status: u8) -> bool {
    matches!(
        status,
        0x1 // GEN6_PCODE_ILLEGAL_CMD
        | 0x2 // GEN7_PCODE_TIMEOUT
        | 0x3 // GEN7_PCODE_ILLEGAL_DATA (GEN6_PCODE_TIMEOUT on gen6)
        | 0x4 // GEN11_PCODE_ILLEGAL_SUBCOMMAND
        | 0x6 // GEN11_PCODE_LOCKED
        | 0x10 // GEN7_PCODE_MIN_FREQ_TABLE_GT_RATIO_OUT_OF_RANGE
        | 0x11 // GEN11_PCODE_REJECTED
    )
}

/// Pcode transaction failure modes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PcodeError {
    /// READY was already set on entry — another agent owns the
    /// mailbox (i915 returns -EAGAIN here).
    Busy,
    /// READY never cleared inside the poll budget.
    Timeout,
    /// The punit completed the transaction with a documented
    /// error status in the mailbox low byte.
    Status(u8),
}

/// Compose a mailbox command word: READY | cmd | p1 | p2.
pub const fn mailbox_word(cmd: u32, param1: u32, param2: u32) -> u32 {
    PCODE_READY | (cmd & 0xFF) | ((param1 & 0xFF) << 8) | ((param2 & 0xFF) << 16)
}

/// Evaluate the final mailbox word after READY clears.
fn check_status(final_mailbox: u32) -> Result<(), PcodeError> {
    let status = (final_mailbox & 0xFF) as u8;
    if status != 0 && status_is_error(status) {
        return Err(PcodeError::Status(status));
    }
    Ok(())
}

/// Run one pcode read transaction: `data0_in` / `data1_in` are
/// the input dwords; returns the output `(DATA0, DATA1)` pair.
pub fn pcode_read<M: MmioWindow + ?Sized>(
    mmio: &M,
    cmd: u32,
    param1: u32,
    param2: u32,
    data0_in: u32,
    data1_in: u32,
) -> Result<(u32, u32), PcodeError> {
    let _transaction = TRANSACTION.try_lock().ok_or(PcodeError::Busy)?;
    if mmio.read32(PCODE_MAILBOX) & PCODE_READY != 0 {
        return Err(PcodeError::Busy);
    }
    mmio.write32(PCODE_DATA0, data0_in);
    mmio.write32(PCODE_DATA1, data1_in);
    mmio.write32(PCODE_MAILBOX, mailbox_word(cmd, param1, param2));
    compiler_fence(Ordering::SeqCst);

    // The port is polled and never depends on another executor task. Keep
    // the bounded source timeout while servicing the common console pumps.
    let mut final_mailbox = PCODE_READY;
    if !narf_scheduler::responsive_spin_until(
        || {
            final_mailbox = mmio.read32(PCODE_MAILBOX);
            final_mailbox & PCODE_READY == 0
        },
        narf_time::Deadline::after_ms(20),
    ) {
        return Err(PcodeError::Timeout);
    }
    check_status(final_mailbox)?;
    Ok((mmio.read32(PCODE_DATA0), mmio.read32(PCODE_DATA1)))
}

/// Run one pcode write transaction: `data0_in` / `data1_in` are
/// the input dwords; no data dwords come back. Same mailbox
/// protocol as [`pcode_read`], with the 2 ms budget Linux's
/// `intel_parent_pcode_write_timeout` uses
/// (`display/intel_pcode.c`).
pub fn pcode_write<M: MmioWindow + ?Sized>(
    mmio: &M,
    cmd: u32,
    param1: u32,
    param2: u32,
    data0_in: u32,
    data1_in: u32,
) -> Result<(), PcodeError> {
    let _transaction = TRANSACTION.try_lock().ok_or(PcodeError::Busy)?;
    if mmio.read32(PCODE_MAILBOX) & PCODE_READY != 0 {
        return Err(PcodeError::Busy);
    }
    mmio.write32(PCODE_DATA0, data0_in);
    mmio.write32(PCODE_DATA1, data1_in);
    mmio.write32(PCODE_MAILBOX, mailbox_word(cmd, param1, param2));
    compiler_fence(Ordering::SeqCst);

    // The port is polled and never depends on another executor task. Keep
    // the bounded source timeout while servicing the common console pumps.
    let mut final_mailbox = PCODE_READY;
    if !narf_scheduler::responsive_spin_until(
        || {
            final_mailbox = mmio.read32(PCODE_MAILBOX);
            final_mailbox & PCODE_READY == 0
        },
        narf_time::Deadline::after_ms(2),
    ) {
        return Err(PcodeError::Timeout);
    }
    check_status(final_mailbox)
}

/// Read the 8-entry memory-latency table (microseconds per
/// level) via `GEN9_PCODE_READ_MEM_LATENCY`. Two transactions:
/// DATA0-in 0 yields levels 0..3, DATA0-in 1 yields levels 4..7,
/// each level packed one byte per level, low byte first.
pub fn read_mem_latencies<M: MmioWindow + ?Sized>(mmio: &M) -> Result<[u16; 8], PcodeError> {
    let mut out = [0u16; 8];
    for set in 0..2u32 {
        let (data0, _) = pcode_read(mmio, PCODE_CMD_READ_MEM_LATENCY, 0, 0, set, 0)?;
        for level in 0..4usize {
            out[set as usize * 4 + level] = ((data0 >> (8 * level)) & 0xFF) as u16;
        }
    }
    Ok(out)
}

/// Read the SAGV block time in microseconds
/// (`GEN12_PCODE_READ_SAGV_BLOCK_TIME_US`).
pub fn read_sagv_block_time_us<M: MmioWindow + ?Sized>(mmio: &M) -> Result<u32, PcodeError> {
    let (data0, _) = pcode_read(mmio, PCODE_CMD_READ_SAGV_BLOCK_TIME_US, 0, 0, 0, 0)?;
    Ok(data0)
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// Scripted pcode endpoint: executing a command happens on
    /// the MAILBOX write (READY clears immediately); the latency
    /// model answers from the DATA0-in set selector, so a codec
    /// that swaps the two reads gets the wrong levels back.
    #[derive(Debug)]
    pub struct PcodeMmio {
        pub writes: RefCell<Vec<(u64, u32)>>,
        data0: RefCell<u32>,
        data1: RefCell<u32>,
        mailbox: RefCell<u32>,
        /// Latency levels this endpoint serves.
        pub latencies: [u16; 8],
        /// SAGV block time this endpoint serves.
        pub sagv_block_time: u32,
        /// When set, every command completes with this status.
        pub forced_status: Option<u8>,
        /// When true, READY never clears.
        pub stuck: bool,
    }

    impl PcodeMmio {
        pub fn new(latencies: [u16; 8], sagv_block_time: u32) -> Self {
            Self {
                writes: RefCell::new(Vec::new()),
                data0: RefCell::new(0),
                data1: RefCell::new(0),
                mailbox: RefCell::new(0),
                latencies,
                sagv_block_time,
                forced_status: None,
                stuck: false,
            }
        }
    }

    impl MmioWindow for PcodeMmio {
        fn read32(&self, off: u64) -> u32 {
            match off {
                PCODE_MAILBOX => *self.mailbox.borrow(),
                PCODE_DATA0 => *self.data0.borrow(),
                PCODE_DATA1 => *self.data1.borrow(),
                _ => 0,
            }
        }
        fn write32(&self, off: u64, val: u32) {
            self.writes.borrow_mut().push((off, val));
            match off {
                PCODE_DATA0 => *self.data0.borrow_mut() = val,
                PCODE_DATA1 => *self.data1.borrow_mut() = val,
                PCODE_MAILBOX => {
                    if val & PCODE_READY == 0 {
                        *self.mailbox.borrow_mut() = val;
                        return;
                    }
                    if self.stuck {
                        *self.mailbox.borrow_mut() = val;
                        return;
                    }
                    let cmd = val & 0xFF;
                    let status = match self.forced_status {
                        Some(s) => s,
                        None => match cmd {
                            PCODE_CMD_READ_MEM_LATENCY => {
                                let set = (*self.data0.borrow() & 1) as usize;
                                let mut packed = 0u32;
                                for level in 0..4usize {
                                    packed |=
                                        (self.latencies[set * 4 + level] as u32) << (8 * level);
                                }
                                *self.data0.borrow_mut() = packed;
                                0
                            }
                            PCODE_CMD_READ_SAGV_BLOCK_TIME_US => {
                                *self.data0.borrow_mut() = self.sagv_block_time;
                                0
                            }
                            PCODE_CMD_DE_WRITE_FREQ_REQ => {
                                // The frequency request is accepted;
                                // the punit answers with no data dwords.
                                0
                            }
                            _ => 0x1, // GEN6_PCODE_ILLEGAL_CMD
                        },
                    };
                    // READY clear, status in the low byte.
                    *self.mailbox.borrow_mut() = status as u32;
                }
                _ => {}
            }
        }
    }

    fn smoke_pcode_mailbox_word_layout() -> TestResult {
        // cmd 0x6, no params → READY | 0x6.
        if mailbox_word(0x6, 0, 0) != 0x8000_0006 {
            return TestResult::Fail("mailbox word for latency read wrong");
        }
        // Params land at bits [15:8] and [23:16].
        if mailbox_word(0x21, 0x3, 0x5) != 0x8005_0321 {
            return TestResult::Fail("mailbox param fields wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_pcode",
        smoke_pcode_mailbox_word_layout
    );

    fn smoke_pcode_latency_conversation_and_unpack() -> TestResult {
        let mmio = PcodeMmio::new([6, 9, 13, 18, 24, 31, 40, 52], 20);
        let lat = match read_mem_latencies(&mmio) {
            Ok(l) => l,
            Err(_) => return TestResult::Fail("latency read failed over scripted endpoint"),
        };
        if lat != [6, 9, 13, 18, 24, 31, 40, 52] {
            return TestResult::Fail("latency unpack wrong (set order or byte lanes)");
        }
        // Conversation shape: DATA0 written before each MAILBOX
        // write; two MAILBOX commands, both READ_MEM_LATENCY.
        let w = mmio.writes.borrow();
        let mailbox_writes: Vec<u32> = w
            .iter()
            .filter(|(o, _)| *o == PCODE_MAILBOX)
            .map(|(_, v)| *v)
            .collect();
        if mailbox_writes != alloc::vec![0x8000_0006, 0x8000_0006] {
            return TestResult::Fail("expected two latency-read commands");
        }
        // DATA0-in values were 0 then 1 (the set selector).
        let data0_writes: Vec<u32> = w
            .iter()
            .filter(|(o, _)| *o == PCODE_DATA0)
            .map(|(_, v)| *v)
            .collect();
        if data0_writes != alloc::vec![0, 1] {
            return TestResult::Fail("latency set selector writes wrong");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_pcode",
        smoke_pcode_latency_conversation_and_unpack
    );

    fn smoke_pcode_sagv_block_time() -> TestResult {
        let mmio = PcodeMmio::new([0; 8], 20);
        match read_sagv_block_time_us(&mmio) {
            Ok(20) => TestResult::Pass,
            _ => TestResult::Fail("SAGV block time read wrong"),
        }
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pcode", smoke_pcode_sagv_block_time);

    fn smoke_pcode_illegal_command_is_error() -> TestResult {
        let mmio = PcodeMmio::new([0; 8], 0);
        // Command 0x7E is not implemented by the endpoint → it
        // completes with GEN6_PCODE_ILLEGAL_CMD (0x1).
        match pcode_read(&mmio, 0x7E, 0, 0, 0, 0) {
            Err(PcodeError::Status(0x1)) => TestResult::Pass,
            _ => TestResult::Fail("illegal command must surface Status(0x1)"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_pcode",
        smoke_pcode_illegal_command_is_error
    );

    fn smoke_pcode_busy_and_timeout() -> TestResult {
        // Busy: READY already set before we start.
        let mmio = PcodeMmio::new([0; 8], 0);
        *mmio.mailbox.borrow_mut() = PCODE_READY;
        match pcode_read(&mmio, PCODE_CMD_READ_MEM_LATENCY, 0, 0, 0, 0) {
            Err(PcodeError::Busy) => {}
            _ => return TestResult::Fail("pre-set READY must surface Busy"),
        }
        // Timeout: endpoint accepts the command but never
        // clears READY — the codec must give up, not spin.
        let mut mmio = PcodeMmio::new([0; 8], 0);
        mmio.stuck = true;
        match pcode_read(&mmio, PCODE_CMD_READ_MEM_LATENCY, 0, 0, 0, 0) {
            Err(PcodeError::Timeout) => TestResult::Pass,
            _ => TestResult::Fail("stuck READY must surface Timeout"),
        }
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pcode", smoke_pcode_busy_and_timeout);

    fn smoke_pcode_write_freq_req() -> TestResult {
        let mmio = PcodeMmio::new([0; 8], 0);
        // Pre-change notify: DATA0 0x80000000.
        if pcode_write(&mmio, PCODE_CMD_DE_WRITE_FREQ_REQ, 0, 0, 0x8000_0000, 0).is_err() {
            return TestResult::Fail("frequency-request pre-notify must succeed");
        }
        // Post-change notify: DATA0 = voltage level 2.
        if pcode_write(&mmio, PCODE_CMD_DE_WRITE_FREQ_REQ, 0, 0, 2, 0).is_err() {
            return TestResult::Fail("frequency-request post-notify must succeed");
        }
        let w = mmio.writes.borrow();
        let mailbox_writes: Vec<u32> = w
            .iter()
            .filter(|(o, _)| *o == PCODE_MAILBOX)
            .map(|(_, v)| *v)
            .collect();
        if mailbox_writes != alloc::vec![0x8000_0017, 0x8000_0017] {
            return TestResult::Fail("expected two frequency-request commands (0x17)");
        }
        let data0_writes: Vec<u32> = w
            .iter()
            .filter(|(o, _)| *o == PCODE_DATA0)
            .map(|(_, v)| *v)
            .collect();
        if data0_writes != alloc::vec![0x8000_0000, 2] {
            return TestResult::Fail("frequency-request DATA0 values wrong");
        }
        // A refused request surfaces the status (forced 0x11).
        let mut mmio = PcodeMmio::new([0; 8], 0);
        mmio.forced_status = Some(0x11);
        match pcode_write(&mmio, PCODE_CMD_DE_WRITE_FREQ_REQ, 0, 0, 0x8000_0000, 0) {
            Err(PcodeError::Status(0x11)) => TestResult::Pass,
            _ => TestResult::Fail("rejected frequency request must surface Status(0x11)"),
        }
    }
    kernel_test_in!("drivers/gpu/intel_gpu_pcode", smoke_pcode_write_freq_req);
}

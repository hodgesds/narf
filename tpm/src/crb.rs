//! TPM 2.0 Command/Response Buffer (CRB) MMIO transport.
//!
//! CRB is the modern TPM 2.0 host interface, per TCG PC Client
//! Platform TPM Profile (PTP) §6. The TPM appears as a fixed
//! 4 KiB MMIO region — by ACPI / DSDT convention at base
//! `0xFED4_0000` on PCs — divided into a register window
//! (locality + control) followed by a command buffer the host
//! writes the TPM2_* command into and a response buffer the
//! TPM writes back to.
//!
//! Sequence (per PTP §6.5):
//!
//!   1. Acquire locality 0 by writing `LocalityRequest` (bit 0)
//!      to `LOC_CTRL`; poll `LOC_STATE` until `tpmEstablished`
//!      clears and `locAssigned` reflects locality 0.
//!   2. Write the 32-bit command size to `CMD_SIZE_REG` and the
//!      64-bit command-buffer phys to `CMD_LADDR` + `CMD_HADDR`.
//!      Write the response-buffer phys to `RSP_LADDR` +
//!      `RSP_HADDR` and the max response size to `RSP_SIZE_REG`.
//!   3. Copy the TPM2_* command bytes into the command buffer.
//!   4. Write 1 (Go) to `CTRL_START` — the TPM begins executing.
//!   5. Poll `CTRL_START` until the bit clears (TPM finished) OR
//!      cancel via `CTRL_CANCEL` if the deadline passes.
//!   6. Read the response from the response buffer; the first 6
//!      bytes are the standard TPM2 header (tag + size + rc).
//!   7. Release locality by writing `Relinquish` to `LOC_CTRL`.
//!
//! Reference: TCG PC Client Platform TPM Profile (PTP)
//! Specification for TPM 2.0, Family 2.0 Level 00 Rev 01.05
//! §6 (CRB Interface).

extern crate alloc;

// ── CRB register offsets (relative to the 4 KiB MMIO base) ─────────

/// `LOC_STATE` (locality state). Bit 0 = tpmEstablished;
/// bit 1 = locAssigned; bits [4:2] = activeLocality;
/// bit 7 = tpmRegValidSts.
pub const REG_LOC_STATE: usize = 0x000;
/// `LOC_CTRL` (locality control). Write bit 0 to request locality;
/// bit 1 to relinquish; bit 4 = resetEstablishmentBit (locality 3+).
pub const REG_LOC_CTRL: usize = 0x008;
/// `LOC_STS` (locality status).
pub const REG_LOC_STS: usize = 0x00C;
/// `INTF_ID` (interface identifier — confirms CRB vs FIFO).
pub const REG_INTF_ID: usize = 0x030;
/// `CTRL_REQ` (command go bit + cancellation request).
pub const REG_CTRL_REQ: usize = 0x040;
/// `CTRL_STS` (busy + error status of the executing command).
pub const REG_CTRL_STS: usize = 0x044;
/// `CTRL_CANCEL` — write 1 to abort the current command.
pub const REG_CTRL_CANCEL: usize = 0x048;
/// `CTRL_START` — write 1 to start; poll for self-clear on done.
pub const REG_CTRL_START: usize = 0x04C;
/// `CMD_SIZE_REG` — 32-bit size in bytes of the command buffer.
pub const REG_CMD_SIZE: usize = 0x080;
/// `CMD_LADDR` — low 32 bits of the command buffer phys address.
pub const REG_CMD_LADDR: usize = 0x084;
/// `CMD_HADDR` — high 32 bits.
pub const REG_CMD_HADDR: usize = 0x088;
/// `RSP_SIZE_REG`.
pub const REG_RSP_SIZE: usize = 0x090;
/// `RSP_LADDR`.
pub const REG_RSP_LADDR: usize = 0x094;
/// `RSP_HADDR`.
pub const REG_RSP_HADDR: usize = 0x098;

// ── LOC_CTRL bits ──────────────────────────────────────────────────

/// `LOC_CTRL` — request the locality whose register block we're in.
pub const LOC_CTRL_REQUEST: u32 = 1 << 0;
/// `LOC_CTRL` — relinquish locality on completion.
pub const LOC_CTRL_RELINQUISH: u32 = 1 << 1;

// ── LOC_STATE bits ─────────────────────────────────────────────────

/// `LOC_STATE` — the TPM has been physically re-secured (cleared
/// on PPI / reset; PCR 0 contents diverge before/after).
pub const LOC_STATE_TPM_ESTABLISHED: u32 = 1 << 0;
/// `LOC_STATE` — locality bit-0 register block is currently assigned.
pub const LOC_STATE_LOC_ASSIGNED: u32 = 1 << 1;
/// `LOC_STATE` — the rest of the LOC_STATE field is valid.
pub const LOC_STATE_VALID: u32 = 1 << 7;

// ── CTRL_START / CTRL_STS ──────────────────────────────────────────

/// `CTRL_START` — write to begin TPM execution; bit clears when done.
pub const CTRL_START_GO: u32 = 1 << 0;
/// `CTRL_STS` — bit 0 = error; bit 1 = idle (command-buffer ownership).
pub const CTRL_STS_ERROR: u32 = 1 << 0;
pub const CTRL_STS_IDLE: u32 = 1 << 1;

// ── Caller's MMIO interface ────────────────────────────────────────

/// Caller's view of the TPM MMIO region. Plugged in by the driver
/// so the protocol is unit-testable against a mock without
/// needing real silicon.
pub trait CrbMmio {
    /// Read a 32-bit register at `offset` bytes from the base.
    fn read32(&mut self, offset: usize) -> u32;
    /// Write a 32-bit register.
    fn write32(&mut self, offset: usize, value: u32);
}

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CrbError {
    /// `LOC_STATE.locAssigned` didn't go high within the poll budget.
    LocalityTimeout,
    /// `CTRL_START` didn't self-clear within the poll budget — TPM
    /// is wedged or doesn't actually exist at this MMIO base.
    CommandTimeout,
    /// `CTRL_STS.error` set after command completion.
    Failed(u32),
}

/// Iteration cap on the locality + command polls. On real silicon
/// a single MMIO read is ~1 µs; one million iterations is ~1 s,
/// safely above the longest legitimate TPM operation
/// (`TPM2_CreatePrimary` can take ~250 ms on slow parts).
pub const CRB_POLL_BUDGET: u32 = 1_000_000;

// ── Operations ─────────────────────────────────────────────────────

/// Acquire locality 0 — write `LocalityRequest` to `LOC_CTRL`
/// and poll `LOC_STATE` until `locAssigned` reflects locality 0.
pub fn acquire_locality<M: CrbMmio>(mmio: &mut M) -> Result<(), CrbError> {
    mmio.write32(REG_LOC_CTRL, LOC_CTRL_REQUEST);
    for _ in 0..CRB_POLL_BUDGET {
        let s = mmio.read32(REG_LOC_STATE);
        if s & LOC_STATE_LOC_ASSIGNED != 0 {
            return Ok(());
        }
    }
    Err(CrbError::LocalityTimeout)
}

/// Relinquish locality — write `Relinquish` to `LOC_CTRL`.
pub fn relinquish_locality<M: CrbMmio>(mmio: &mut M) {
    mmio.write32(REG_LOC_CTRL, LOC_CTRL_RELINQUISH);
}

/// Program the command-buffer and response-buffer base addresses
/// + sizes into the CRB registers. Called once per command-buffer
/// pair (typically the same DMA-coherent page across many commands).
pub fn program_buffers<M: CrbMmio>(
    mmio: &mut M,
    cmd_phys: u64,
    cmd_size: u32,
    rsp_phys: u64,
    rsp_size: u32,
) {
    mmio.write32(REG_CMD_SIZE, cmd_size);
    mmio.write32(REG_CMD_LADDR, cmd_phys as u32);
    mmio.write32(REG_CMD_HADDR, (cmd_phys >> 32) as u32);
    mmio.write32(REG_RSP_SIZE, rsp_size);
    mmio.write32(REG_RSP_LADDR, rsp_phys as u32);
    mmio.write32(REG_RSP_HADDR, (rsp_phys >> 32) as u32);
}

/// Kick off a command via `CTRL_START.Go = 1` and poll until the
/// bit self-clears (TPM finished). Returns the final `CTRL_STS`
/// for error-bit inspection by the caller.
pub fn run_command<M: CrbMmio>(mmio: &mut M) -> Result<u32, CrbError> {
    mmio.write32(REG_CTRL_START, CTRL_START_GO);
    for _ in 0..CRB_POLL_BUDGET {
        let s = mmio.read32(REG_CTRL_START);
        if s & CTRL_START_GO == 0 {
            let sts = mmio.read32(REG_CTRL_STS);
            if sts & CTRL_STS_ERROR != 0 {
                return Err(CrbError::Failed(sts));
            }
            return Ok(sts);
        }
    }
    // Wedged TPM — cancel and bail.
    mmio.write32(REG_CTRL_CANCEL, 1);
    Err(CrbError::CommandTimeout)
}

pub mod test_support {
    //! Mock MMIO for smokes — scripts CRB register reads + captures writes.
    use super::*;

    /// Mock CRB MMIO. Reads come from `regs` (init-zeroed); writes
    /// land in `regs` AND a separate trace so tests assert ordering.
    /// `pre_read_hook` lets the test simulate the TPM toggling bits
    /// in response to a host write (e.g. CTRL_START.Go self-clearing).
    #[derive(Debug)]
    pub struct MockCrb {
        pub regs: [u32; 256],
        pub writes: alloc::vec::Vec<(usize, u32)>,
        /// On every read of `offset`, this callback runs first to
        /// let the test mutate the underlying reg value. Indexed
        /// by offset/4. None = pass-through.
        pub read_hooks: [Option<fn(&mut [u32; 256])>; 256],
    }
    impl MockCrb {
        #[allow(dead_code)]
        pub fn new() -> Self {
            Self {
                regs: [0u32; 256],
                writes: alloc::vec::Vec::new(),
                read_hooks: [None; 256],
            }
        }
        #[allow(dead_code)]
        pub fn install_hook(&mut self, offset: usize, hook: fn(&mut [u32; 256])) {
            self.read_hooks[offset / 4] = Some(hook);
        }
    }
    impl CrbMmio for MockCrb {
        fn read32(&mut self, offset: usize) -> u32 {
            if let Some(h) = self.read_hooks[offset / 4] {
                h(&mut self.regs);
            }
            self.regs[offset / 4]
        }
        fn write32(&mut self, offset: usize, value: u32) {
            self.writes.push((offset, value));
            self.regs[offset / 4] = value;
        }
    }
}

pub use test_support::MockCrb;

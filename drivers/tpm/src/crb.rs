//! TPM 2.0 Command/Response Buffer (CRB) MMIO transport.
//!
//! The CRB interface is the modern TPM 2.0 host interface defined in
//! TCG PC Client Platform TPM Profile (PTP) Specification §6. On AMD
//! Zen 2 (Renoir/Lucienne) and Zen 4 (Phoenix/HawkPoint1) the fTPM
//! is exposed via CRB; the ACPI device HID is `MSFT0101` and the
//! control-area physical address is read from the TPM2 ACPI table
//! (`control_address` field — see `probe.rs`).
//!
//! ## CRB register map (relative to 4 KiB MMIO base)
//!
//! ```text
//! Offset  Register           Description
//! 0x000   LOC_STATE          Locality state (locAssigned, tpmEstablished)
//! 0x008   LOC_CTRL           Locality control (request/relinquish)
//! 0x00C   LOC_STS            Locality status (Granted, beenSeized)
//! 0x030   INTF_ID            Interface type + version
//! 0x040   CTRL_REQ           Command ready / go idle
//! 0x044   CTRL_STS           TPM idle / error status
//! 0x048   CTRL_CANCEL        Cancel current command
//! 0x04C   CTRL_START         Start command (self-clearing Go bit)
//! 0x080   CMD_SIZE           Command buffer size (bytes)
//! 0x084   CMD_LADDR          Command buffer phys addr low 32 bits
//! 0x088   CMD_HADDR          Command buffer phys addr high 32 bits
//! 0x090   RSP_SIZE           Response buffer size (bytes)
//! 0x094   RSP_LADDR          Response buffer phys addr low 32 bits
//! 0x098   RSP_HADDR          Response buffer phys addr high 32 bits
//! 0x0A0…  Data buffer        Command/response data (at least 4 KiB)
//! ```
//!
//! ## Command flow (PTP §6.5)
//!
//! 1. Write `LOC_CTRL.requestAccess = 1`; poll `LOC_STATE.locAssigned`.
//! 2. Program `CMD_SIZE/LADDR/HADDR` and `RSP_SIZE/LADDR/HADDR`.
//! 3. Copy TPM2 command bytes into the data buffer.
//! 4. Write `CTRL_START = 1`; poll until bit self-clears (TPM done).
//! 5. Read response from data buffer; check `CTRL_STS.error`.
//! 6. Write `LOC_CTRL.relinquish = 1`.
//!
//! ## References
//!
//! - TCG PTP Specification for TPM 2.0, Family 2.0 Level 00 Rev 01.05 §6.
//! - Linux `drivers/char/tpm/tpm_crb.c` (GPL-2.0-or-later).

extern crate alloc;

// ── Register offsets (relative to CRB MMIO base) ────────────────────
// Linux tpm_crb.c enumerates these as struct-field offsets; we keep
// them as byte offsets into a flat 32-bit register map so the mock
// and the real MMIO path share one interface.

/// `LOC_STATE` — locality state register.
/// Bit 0 = tpmEstablished; bit 1 = locAssigned; bits[4:2] = activeLocality;
/// bit 7 = tpmRegValidSts.
/// Linux tpm_crb.c: `priv->regs_h->loc_state`.
pub const REG_LOC_STATE: usize = 0x000;
/// `LOC_CTRL` — locality control.
/// Bit 0 = requestAccess; bit 1 = relinquish; bit 4 = resetEstablishment (≥L3).
/// Linux tpm_crb.c: `priv->regs_h->loc_ctrl`.
pub const REG_LOC_CTRL: usize = 0x008;
/// `LOC_STS` — locality status. Bit 0 = Granted; bit 1 = beenSeized.
pub const REG_LOC_STS: usize = 0x00C;
/// `INTF_ID` (64-bit, low word) — confirms CRB vs FIFO interface type.
pub const REG_INTF_ID: usize = 0x030;
/// `CTRL_REQ` — request command-ready / go-idle bits.
pub const REG_CTRL_REQ: usize = 0x040;
/// `CTRL_STS` — busy + error status while command is executing.
/// Bit 0 = tpmSts.error; bit 1 = tpmSts.idle.
pub const REG_CTRL_STS: usize = 0x044;
/// `CTRL_CANCEL` — write 1 to abort the in-flight command.
pub const REG_CTRL_CANCEL: usize = 0x048;
/// `CTRL_START` — write 1 to start; the bit self-clears when done.
pub const REG_CTRL_START: usize = 0x04C;
/// `CMD_SIZE_REG` — 32-bit command buffer size in bytes.
pub const REG_CMD_SIZE: usize = 0x058;
/// `CMD_LADDR` — low 32 bits of command buffer physical address.
pub const REG_CMD_LADDR: usize = 0x05C;
/// `CMD_HADDR` — high 32 bits of command buffer physical address.
pub const REG_CMD_HADDR: usize = 0x060;
/// `RSP_SIZE_REG` — 32-bit response buffer size in bytes.
pub const REG_RSP_SIZE: usize = 0x068;
/// `RSP_LADDR` — low 32 bits of response buffer physical address.
pub const REG_RSP_LADDR: usize = 0x06C;
/// `RSP_HADDR` — high 32 bits of response buffer physical address.
pub const REG_RSP_HADDR: usize = 0x070;

// ── LOC_STATE bits ───────────────────────────────────────────────────

/// `LOC_STATE` — tpmEstablished (physical presence / clear event).
pub const LOC_STATE_TPM_ESTABLISHED: u32 = 1 << 0;
/// `LOC_STATE` — locality assigned; the register block is in use.
/// Linux tpm_crb.c: `CRB_LOC_STATE_LOC_ASSIGNED = BIT(1)`.
pub const LOC_STATE_LOC_ASSIGNED: u32 = 1 << 1;
/// `LOC_STATE` — register contents are valid.
/// Linux tpm_crb.c: `CRB_LOC_STATE_TPM_REG_VALID_STS = BIT(7)`.
pub const LOC_STATE_VALID: u32 = 1 << 7;

// ── LOC_CTRL bits ────────────────────────────────────────────────────

/// `LOC_CTRL` — request locality 0.
/// Linux tpm_crb.c: `CRB_LOC_CTRL_REQUEST_ACCESS = BIT(0)`.
pub const LOC_CTRL_REQUEST: u32 = 1 << 0;
/// `LOC_CTRL` — relinquish locality on completion.
/// Linux tpm_crb.c: `CRB_LOC_CTRL_RELINQUISH = BIT(1)`.
pub const LOC_CTRL_RELINQUISH: u32 = 1 << 1;

// ── CTRL_STS bits ────────────────────────────────────────────────────

/// `CTRL_STS` — error bit; set if the TPM encountered a fault.
pub const CTRL_STS_ERROR: u32 = 1 << 0;
/// `CTRL_STS` — idle bit; set when the TPM is idle.
pub const CTRL_STS_IDLE: u32 = 1 << 1;

// ── CTRL_START bit ───────────────────────────────────────────────────

/// `CTRL_START` — write 1 to begin execution; self-clears on completion.
pub const CTRL_START_GO: u32 = 1 << 0;

// ── Poll budget ──────────────────────────────────────────────────────

/// Maximum MMIO poll iterations. On real silicon one MMIO read ≈ 1 µs;
/// 1 000 000 iterations ≈ 1 s, well above the worst-case TPM operation
/// (`TPM2_CreatePrimary` can take ~250 ms on slow fTPM parts).
pub const CRB_POLL_BUDGET: u32 = 1_000_000;

// ── MMIO abstraction ─────────────────────────────────────────────────

/// Caller's view of the CRB MMIO region. Implementations provide
/// the actual MMIO reads/writes; the mock in `test_support` feeds
/// back scripted register values without touching real silicon.
pub trait CrbMmio {
    /// Read a 32-bit register at `offset` bytes from the CRB base.
    fn read32(&mut self, offset: usize) -> u32;
    /// Write a 32-bit register at `offset` bytes from the CRB base.
    fn write32(&mut self, offset: usize, value: u32);
}

// ── Errors ───────────────────────────────────────────────────────────

/// Errors from the CRB transport layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CrbError {
    /// `LOC_STATE.locAssigned` did not assert within the poll budget.
    LocalityTimeout,
    /// `CTRL_START` did not self-clear within the poll budget — TPM
    /// is wedged or does not actually exist at this MMIO address.
    CommandTimeout,
    /// `CTRL_STS.error` was set after command completion; the raw
    /// `CTRL_STS` value is preserved for diagnostics.
    Failed(u32),
}

// ── Operations ───────────────────────────────────────────────────────

/// Acquire locality 0 — write `requestAccess` to `LOC_CTRL` and
/// poll `LOC_STATE` until `locAssigned` reflects locality 0.
///
/// Linux equivalent: `crb_request_locality()` in `tpm_crb.c:289`.
pub fn acquire_locality<M: CrbMmio>(mmio: &mut M) -> Result<(), CrbError> {
    mmio.write32(REG_LOC_CTRL, LOC_CTRL_REQUEST);
    for _ in 0..CRB_POLL_BUDGET {
        if mmio.read32(REG_LOC_STATE) & LOC_STATE_LOC_ASSIGNED != 0 {
            return Ok(());
        }
    }
    Err(CrbError::LocalityTimeout)
}

/// Relinquish locality — write `relinquish` to `LOC_CTRL`.
///
/// Linux equivalent: `crb_relinquish_locality()` in `tpm_crb.c:329`.
pub fn relinquish_locality<M: CrbMmio>(mmio: &mut M) {
    mmio.write32(REG_LOC_CTRL, LOC_CTRL_RELINQUISH);
}

/// Program command-buffer and response-buffer base addresses + sizes
/// into the six CRB registers. Called once per buffer pair (typically
/// the same DMA-coherent page pair re-used across many commands).
///
/// Linux equivalent: the `cmd_buf` + `resp_buf` setup in
/// `crb_cmd_ready()` and `crb_go_idle()` in `tpm_crb.c`.
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

/// Write `CTRL_START.Go = 1` and poll until the bit self-clears
/// (TPM finished the command). Returns the final `CTRL_STS` value
/// for the caller to inspect the idle/error bits.
///
/// Linux equivalent: `crb_do_cmd()` in `tpm_crb.c:459`.
pub fn run_command<M: CrbMmio>(mmio: &mut M) -> Result<u32, CrbError> {
    mmio.write32(REG_CTRL_START, CTRL_START_GO);
    for _ in 0..CRB_POLL_BUDGET {
        if mmio.read32(REG_CTRL_START) & CTRL_START_GO == 0 {
            let sts = mmio.read32(REG_CTRL_STS);
            if sts & CTRL_STS_ERROR != 0 {
                return Err(CrbError::Failed(sts));
            }
            return Ok(sts);
        }
    }
    // Cancel a wedged TPM.
    mmio.write32(REG_CTRL_CANCEL, 1);
    Err(CrbError::CommandTimeout)
}

// ── Test support (mock MMIO) ─────────────────────────────────────────

pub type ReadHook = Option<fn(&mut [u32; 256])>;

/// Mock MMIO registers for unit tests. Reads come from `regs`
/// (zero-initialised); writes land in `regs` AND are appended to
/// `writes` so tests can assert ordering. `read_hooks` lets a test
/// simulate the TPM toggling bits in response to a host write
/// (e.g. CTRL_START.Go self-clearing, locAssigned asserting).
#[derive(Debug)]
pub struct MockCrb {
    pub regs: [u32; 256],
    pub writes: alloc::vec::Vec<(usize, u32)>,
    /// Per-register read hook. Indexed by `offset / 4`. When present
    /// the hook is called before the read returns, allowing the test
    /// to flip simulated TPM bits into `regs`.
    pub read_hooks: [ReadHook; 256],
}

impl MockCrb {
    pub fn new() -> Self {
        Self {
            regs: [0u32; 256],
            writes: alloc::vec::Vec::new(),
            read_hooks: [None; 256],
        }
    }

    /// Install a hook that fires on every read of `offset`.
    pub fn install_hook(&mut self, offset: usize, hook: fn(&mut [u32; 256])) {
        self.read_hooks[offset / 4] = Some(hook);
    }
}

impl Default for MockCrb {
    fn default() -> Self {
        Self::new()
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

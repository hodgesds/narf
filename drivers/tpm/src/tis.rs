//! TPM Interface Spec (TIS) MMIO transport for discrete TPM chips.
//!
//! TIS is the classic LPC/MMIO interface used by discrete TPM chips
//! from Infineon, Nuvoton, Atmel, STMicro, etc. It predates CRB and
//! is still found on servers and legacy platforms.
//!
//! ## Memory map
//!
//! The TIS MMIO region is 0x5000 bytes (5 KiB). Five 1 KiB localities
//! (L0–L4) are stacked; each starts at `base + (locality × 0x1000)`.
//! Locality 0 starts at `0xFED4_0000` by convention. Only locality 0
//! is used here.
//!
//! Per-locality register offsets:
//!
//! ```text
//! Offset  Width  Register           Description
//! 0x000   1      TPM_ACCESS         requestUse, activeLocality, beenSeized
//! 0x008   4      TPM_INT_ENABLE     interrupt-enable mask
//! 0x00C   1      TPM_INT_VECTOR     interrupt vector
//! 0x010   4      TPM_INT_STATUS     interrupt-status bits
//! 0x014   4      TPM_INTF_CAPS      capability flags, burst-count cap
//! 0x018   4      TPM_STS            status (valid, ready, go, dataAvail, expect)
//! 0x024   1      TPM_DATA_FIFO      byte-at-a-time command/response FIFO
//! 0xF00   4      TPM_DID_VID        vendor (bits[31:16]) + device (bits[15:0]) ID
//! 0xF04   1      TPM_RID            revision ID
//! ```
//!
//! ## Command flow
//!
//! 1. Request locality: write `TPM_ACCESS.requestUse`; poll
//!    `TPM_ACCESS.activeLocality` and `TPM_ACCESS.valid`.
//! 2. Assert command-ready: write `TPM_STS.commandReady`; poll until set.
//! 3. Write command bytes to `TPM_DATA_FIFO`; burst-aware (burst count
//!    from `TPM_STS[23:8]`).
//! 4. Set `TPM_STS.tpmGo`.
//! 5. Poll `TPM_STS.dataAvail` (and `valid`).
//! 6. Drain response from `TPM_DATA_FIFO`.
//! 7. Release locality: write `TPM_ACCESS.activeLocality`.
//!
//! ## References
//!
//! - TCG PC Client Platform TPM Interface Spec Version 1.3 §6.
//! - Linux `drivers/char/tpm/tpm_tis_core.h` and
//!   `drivers/char/tpm/tpm_tis_core.c` (GPL-2.0-or-later).

extern crate alloc;

// ── Locality 0 base address ─────────────────────────────────────────

/// Default TIS MMIO base for locality 0 on PC platforms.
/// Linux tpm_tis_core.c: `TIS_MEM_BASE = 0xFED40000`.
pub const TIS_MMIO_BASE: u64 = 0xFED4_0000;

/// Size of the entire TIS MMIO region (5 × 1 KiB localities).
/// Linux tpm_tis_core.h: `TIS_MEM_LEN = 0x5000`.
pub const TIS_MEM_LEN: usize = 0x5000;

// ── Per-locality register offset helpers ────────────────────────────
// Linux tpm_tis_core.h defines these as macros that shift by
// (locality × 0x1000). We target locality 0 only, so offset = base.

/// `TPM_ACCESS(locality)` — byte-wide access register.
/// Linux tpm_tis_core.h: `#define TPM_ACCESS(l) (0x0000 | ((l) << 12))`.
pub const fn tpm_access(locality: u32) -> usize {
    (locality << 12) as usize
}
/// `TPM_INT_ENABLE(locality)` — 32-bit interrupt-enable mask.
pub const fn tpm_int_enable(locality: u32) -> usize {
    (0x0008 | (locality << 12)) as usize
}
/// `TPM_INT_VECTOR(locality)` — 8-bit IRQ vector.
pub const fn tpm_int_vector(locality: u32) -> usize {
    (0x000C | (locality << 12)) as usize
}
/// `TPM_INT_STATUS(locality)` — 32-bit interrupt-status.
pub const fn tpm_int_status(locality: u32) -> usize {
    (0x0010 | (locality << 12)) as usize
}
/// `TPM_INTF_CAPS(locality)` — 32-bit interface capabilities.
/// Linux tpm_tis_core.h: `#define TPM_INTF_CAPS(l) (0x0014 | ...)`.
pub const fn tpm_intf_caps(locality: u32) -> usize {
    (0x0014 | (locality << 12)) as usize
}
/// `TPM_STS(locality)` — 32-bit status register.
/// Linux tpm_tis_core.h: `#define TPM_STS(l) (0x0018 | ...)`.
pub const fn tpm_sts(locality: u32) -> usize {
    (0x0018 | (locality << 12)) as usize
}
/// `TPM_DATA_FIFO(locality)` — byte-at-a-time command/response FIFO.
/// Linux tpm_tis_core.h: `#define TPM_DATA_FIFO(l) (0x0024 | ...)`.
pub const fn tpm_data_fifo(locality: u32) -> usize {
    (0x0024 | (locality << 12)) as usize
}
/// `TPM_DID_VID(locality)` — 32-bit vendor+device ID register.
/// Linux tpm_tis_core.h: `#define TPM_DID_VID(l) (0x0F00 | ...)`.
pub const fn tpm_did_vid(locality: u32) -> usize {
    (0x0F00 | (locality << 12)) as usize
}
/// `TPM_RID(locality)` — 8-bit revision ID.
pub const fn tpm_rid(locality: u32) -> usize {
    (0x0F04 | (locality << 12)) as usize
}

// ── TPM_ACCESS bits ──────────────────────────────────────────────────
// Linux tpm_tis_core.h: `enum tis_access`.

/// `TPM_ACCESS.valid` — register contents are valid.
/// Linux: `TPM_ACCESS_VALID = 0x80`.
pub const ACCESS_VALID: u8 = 0x80;
/// `TPM_ACCESS.activeLocality` — this locality is active.
/// Linux: `TPM_ACCESS_ACTIVE_LOCALITY = 0x20`.
pub const ACCESS_ACTIVE_LOCALITY: u8 = 0x20;
/// `TPM_ACCESS.pendingRequest` — another locality has a pending request.
/// Linux: `TPM_ACCESS_REQUEST_PENDING = 0x04`.
pub const ACCESS_REQUEST_PENDING: u8 = 0x04;
/// `TPM_ACCESS.requestUse` — request this locality (write 1 to assert).
/// Linux: `TPM_ACCESS_REQUEST_USE = 0x02`.
pub const ACCESS_REQUEST_USE: u8 = 0x02;

// ── TPM_STS bits ─────────────────────────────────────────────────────
// Linux tpm_tis_core.h: `enum tis_status`.

/// `TPM_STS.valid` — status register contents are valid.
/// Linux: `TPM_STS_VALID = 0x80`.
pub const STS_VALID: u32 = 0x80;
/// `TPM_STS.commandReady` — TPM is ready to receive a new command.
/// Linux: `TPM_STS_COMMAND_READY = 0x40`.
pub const STS_COMMAND_READY: u32 = 0x40;
/// `TPM_STS.tpmGo` — write 1 to submit the command for execution.
/// Linux: `TPM_STS_GO = 0x20`.
pub const STS_GO: u32 = 0x20;
/// `TPM_STS.dataAvail` — response data is available in the FIFO.
/// Linux: `TPM_STS_DATA_AVAIL = 0x10`.
pub const STS_DATA_AVAIL: u32 = 0x10;
/// `TPM_STS.Expect` — TPM expects more data; do not set tpmGo yet.
/// Linux: `TPM_STS_DATA_EXPECT = 0x08`.
pub const STS_DATA_EXPECT: u32 = 0x08;
/// `TPM_STS.responseRetry` — re-send the last response.
/// Linux: `TPM_STS_RESPONSE_RETRY = 0x02`.
pub const STS_RESPONSE_RETRY: u32 = 0x02;
/// Burst count: bits [23:8] of `TPM_STS`. Number of bytes that can
/// be written/read at once without polling.
pub const STS_BURST_COUNT_MASK: u32 = 0x00FF_FF00;
pub const STS_BURST_COUNT_SHIFT: u32 = 8;

// ── TPM_INTF_CAPS bits ───────────────────────────────────────────────
// Linux tpm_tis_core.h: `enum tis_int_flags`.

pub const INTF_DATA_AVAIL_INT: u32 = 0x0000_0001;
pub const INTF_STS_VALID_INT: u32 = 0x0000_0002;
pub const INTF_LOCALITY_CHANGE_INT: u32 = 0x0000_0004;
pub const INTF_INT_LEVEL_HIGH: u32 = 0x0000_0008;
pub const INTF_INT_LEVEL_LOW: u32 = 0x0000_0010;
pub const INTF_INT_EDGE_RISING: u32 = 0x0000_0020;
pub const INTF_INT_EDGE_FALLING: u32 = 0x0000_0040;
pub const INTF_CMD_READY_INT: u32 = 0x0000_0080;
pub const INTF_BURST_COUNT_STATIC: u32 = 0x0000_0100;

// ── Poll budget ──────────────────────────────────────────────────────

/// Iteration cap for MMIO polling. Same rationale as CRB: 1 µs/read
/// × 1 000 000 = ~1 s, safely above worst-case TIS operation.
pub const TIS_POLL_BUDGET: u32 = 1_000_000;

// ── Errors ───────────────────────────────────────────────────────────

/// Errors from the TIS transport layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TisError {
    /// Locality request timed out (activeLocality never asserted).
    LocalityTimeout,
    /// `TPM_STS.commandReady` never asserted within the poll budget.
    ReadyTimeout,
    /// `TPM_STS.dataAvail` never asserted (response never arrived).
    DataTimeout,
    /// The response buffer was shorter than expected.
    TruncatedResponse,
}

// ── MMIO abstraction ─────────────────────────────────────────────────

/// Caller's view of the TIS MMIO region. The real implementation
/// does volatile MMIO reads/writes; the `MockTis` below replays
/// scripted values for unit tests.
pub trait TisMmio {
    /// Read one byte at `offset` from the TIS MMIO base.
    fn read8(&mut self, offset: usize) -> u8;
    /// Write one byte.
    fn write8(&mut self, offset: usize, value: u8);
    /// Read a little-endian 32-bit register.
    fn read32(&mut self, offset: usize) -> u32;
    /// Write a little-endian 32-bit register.
    fn write32(&mut self, offset: usize, value: u32);
}

// ── Operations ───────────────────────────────────────────────────────

/// Request locality 0 from the TIS chip.
///
/// Write `ACCESS.requestUse`; poll `TPM_ACCESS` until both
/// `ACCESS_ACTIVE_LOCALITY` and `ACCESS_VALID` are set.
///
/// Linux equivalent: `tpm_tis_request_locality()` in `tpm_tis_core.c`.
pub fn request_locality<M: TisMmio>(mmio: &mut M, locality: u32) -> Result<(), TisError> {
    let offset = tpm_access(locality);
    mmio.write8(offset, ACCESS_REQUEST_USE);
    for _ in 0..TIS_POLL_BUDGET {
        let v = mmio.read8(offset);
        if (v & (ACCESS_ACTIVE_LOCALITY | ACCESS_VALID)) == (ACCESS_ACTIVE_LOCALITY | ACCESS_VALID)
        {
            return Ok(());
        }
    }
    Err(TisError::LocalityTimeout)
}

/// Relinquish locality by writing `activeLocality` (self-clearing
/// the bit in the TIS chip).
pub fn relinquish_locality<M: TisMmio>(mmio: &mut M, locality: u32) {
    mmio.write8(tpm_access(locality), ACCESS_ACTIVE_LOCALITY);
}

/// Assert command-ready — write `STS_COMMAND_READY` to `TPM_STS`;
/// poll until the bit confirms.
///
/// Linux equivalent: `tpm_tis_ready()` in `tpm_tis_core.c:284`.
pub fn assert_command_ready<M: TisMmio>(mmio: &mut M, locality: u32) -> Result<(), TisError> {
    let offset = tpm_sts(locality);
    mmio.write32(offset, STS_COMMAND_READY);
    for _ in 0..TIS_POLL_BUDGET {
        if mmio.read32(offset) & STS_COMMAND_READY != 0 {
            return Ok(());
        }
    }
    Err(TisError::ReadyTimeout)
}

/// Write a command to the TIS FIFO byte-by-byte (simplified —
/// burst-aware scheduling is left for the full driver).
///
/// Linux equivalent: `tpm_tis_send_data()` in `tpm_tis_core.c`.
pub fn write_command<M: TisMmio>(mmio: &mut M, locality: u32, cmd: &[u8]) {
    let fifo = tpm_data_fifo(locality);
    for &b in cmd {
        mmio.write8(fifo, b);
    }
}

/// Set `TPM_STS.tpmGo` to submit the command.
///
/// Linux equivalent: `tpm_tis_send()` sets `TPM_STS_GO` at line 561.
pub fn set_go<M: TisMmio>(mmio: &mut M, locality: u32) {
    mmio.write32(tpm_sts(locality), STS_GO);
}

/// Poll `TPM_STS.dataAvail` until the response is ready.
///
/// Linux equivalent: `wait_for_tpm_stat(chip, TPM_STS_DATA_AVAIL | TPM_STS_VALID …)`
/// in `tpm_tis_core.c:570`.
pub fn wait_data_avail<M: TisMmio>(mmio: &mut M, locality: u32) -> Result<(), TisError> {
    let want = STS_DATA_AVAIL | STS_VALID;
    for _ in 0..TIS_POLL_BUDGET {
        if mmio.read32(tpm_sts(locality)) & want == want {
            return Ok(());
        }
    }
    Err(TisError::DataTimeout)
}

/// Drain the response FIFO into `buf`. Returns the number of bytes
/// read, bounded by the response-size field in the TPM2 header.
///
/// Linux equivalent: `tpm_tis_recv()` in `tpm_tis_core.c:290`.
pub fn read_response<M: TisMmio>(
    mmio: &mut M,
    locality: u32,
    buf: &mut alloc::vec::Vec<u8>,
) -> Result<usize, TisError> {
    let fifo = tpm_data_fifo(locality);

    // Read the 6-byte TPM2 header first to learn the total size.
    let mut hdr = [0u8; 6];
    for b in &mut hdr {
        *b = mmio.read8(fifo);
    }
    let total = u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]) as usize;
    if total < 6 {
        return Err(TisError::TruncatedResponse);
    }
    buf.extend_from_slice(&hdr);
    for _ in 6..total {
        buf.push(mmio.read8(fifo));
    }
    Ok(total)
}

// ── Mock TIS MMIO ────────────────────────────────────────────────────

/// Mock TIS MMIO for unit tests. The MMIO region is represented as a
/// flat 0x5000-byte array indexed by byte offset. Writes are also
/// traced in `writes` for ordering assertions.
pub struct MockTis {
    pub mem: alloc::vec::Vec<u8>,
    pub writes: alloc::vec::Vec<(usize, u32)>,
}

impl MockTis {
    /// Allocate a zero-filled 0x5000 mock TIS region.
    pub fn new() -> Self {
        Self {
            mem: alloc::vec![0u8; TIS_MEM_LEN],
            writes: alloc::vec::Vec::new(),
        }
    }
}

impl Default for MockTis {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for MockTis {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MockTis")
            .field("writes_len", &self.writes.len())
            .finish()
    }
}

impl TisMmio for MockTis {
    fn read8(&mut self, offset: usize) -> u8 {
        self.mem.get(offset).copied().unwrap_or(0)
    }
    fn write8(&mut self, offset: usize, value: u8) {
        self.writes.push((offset, value as u32));
        if offset < self.mem.len() {
            self.mem[offset] = value;
        }
    }
    fn read32(&mut self, offset: usize) -> u32 {
        if offset + 3 >= self.mem.len() {
            return 0;
        }
        u32::from_le_bytes([
            self.mem[offset],
            self.mem[offset + 1],
            self.mem[offset + 2],
            self.mem[offset + 3],
        ])
    }
    fn write32(&mut self, offset: usize, value: u32) {
        self.writes.push((offset, value));
        if offset + 3 < self.mem.len() {
            let b = value.to_le_bytes();
            self.mem[offset..offset + 4].copy_from_slice(&b);
        }
    }
}

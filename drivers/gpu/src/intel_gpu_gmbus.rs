//! GMBUS — Intel iGPU I²C controller for DDC / EDID — codec +
//! MMIO transport.
//!
//! References: **Tiger Lake PRM Vol. 12 §"GMBUS Programming"**
//! (register map + programming sequence), cross-checked against
//! the Alder Lake PRM (same offsets) and Linux i915's
//! `drivers/gpu/drm/i915/display/intel_gmbus_regs.h` +
//! `intel_gmbus.c` (`gmbus_xfer` / `gmbus_wait` /
//! `gmbus_wait_idle`), the authoritative implementation of the
//! same PRM text. Where this module's earlier codec-only shape
//! disagreed with that protocol, the protocol won — the
//! corrections are listed under "Register-map corrections"
//! below.
//!
//! ## Block layout
//!
//! GMBUS is a six-register block at MMIO `0xC5100`:
//!
//! | Offset | Register      | Purpose                             |
//! | ------ | ------------- | ----------------------------------- |
//! | +0x00  | `GMBUS0`      | Pin pair selection + bus rate       |
//! | +0x04  | `GMBUS1`      | Command + slave address             |
//! | +0x08  | `GMBUS2`      | Status + handshake                  |
//! | +0x0C  | `GMBUS3`      | Data port (4 bytes per FIFO entry)  |
//! | +0x10  | `GMBUS4`      | Interrupt mask                      |
//! | +0x20  | `GMBUS5`      | 2-byte index for byte-indexed reads |
//!
//! ## Register-map corrections (2026-10-27, #1018)
//!
//! The codec landed with four dormant errors — dormant only
//! because nothing performed MMIO through it:
//!
//! - `GMBUS_BASE` was `0xC510`, one nibble short of the PRM's
//!   `0xC5100` (the regions table and its smoke already said
//!   `0xC5100`). Every `GMBUSn` constant inherited the error.
//! - `GMBUS5` was at `+0x14`; the register is at `+0x20`.
//! - `GMBUS2_INUSE` was at bit 14; `INUSE` is bit 15. Bit 14 is
//!   `HW_WAIT_PHASE`, which the old map also carried as a
//!   duplicate constant `GMBUS2_HW_DONE` ("hardware completed
//!   without error") — dead, wrong, and now deleted.
//! - `GMBUS0_HOLD_TIME` was at bit 6; bit 6 is
//!   `BYTE_CNT_OVERRIDE`. The hold-time extension is bit 7
//!   (`GMBUS0_HOLD_EXT`).
//! - `GMBUS2` bit 10, previously named `NACK`, is `SATOER`
//!   (slave-address timeout error) — the status i915's
//!   `gmbus_wait` folds into every wait and reports as the
//!   NAK / no-such-slave outcome. Same bit, correct name.
//!
//! ## Transport protocol (implemented by [`GmbusBus`])
//!
//! One call = one I²C transfer, shaped after i915's
//! `do_gmbus_xfer` for a single message:
//!
//! 1. Write `GMBUS0` = rate | pin pair (bus select).
//! 2. (2-byte-index transfers only) write `GMBUS5` with
//!    [`GMBUS5_2BYTE_INDEX_EN`] + the index, before the program.
//! 3. Write transfers preload the first `GMBUS3` dword *before*
//!    the command (i915 `gmbus_xfer_write_chunk`); then write
//!    `GMBUS1` = `SW_RDY` | cycle | byte count | slave | dir.
//!    The data cycle is [`GMBUS1_CYCLE_WAIT`]; a 1-byte index
//!    rides in the same program as [`GMBUS1_CYCLE_INDEX`] with
//!    the index byte at `GMBUS1[15:8]` — the controller emits
//!    it as the write segment and repeated-STARTs into the
//!    data segment, which is the entire point of the INDEX
//!    cycle. (The codec's original single-program shape set
//!    `SW_CLR_INT` + `ENT` + the STOP cycle on the data
//!    program itself; none of the three belongs there —
//!    `SW_CLR_INT` is the post-NAK controller-reset toggle,
//!    i915 does not arm `ENT`, and STOP is its own trailing
//!    cycle so messages can chain.)
//! 4. Data phase: poll `GMBUS2` for `HW_RDY` (poll-counted
//!    budget, [`GMBUS_POLL_BUDGET`] — the #879 discipline:
//!    wall-clock budgets misfire under TCG), draining /
//!    filling `GMBUS3` little-endian per chunk (first byte in
//!    bits `[7:0]`). Every wait also watches `SATOER` (→
//!    [`GmbusError::SlaveNack`]) and `STALL_TIMEOUT` (→
//!    [`GmbusError::HardwareTimeout`]).
//! 5. Completion: poll for `HW_WAIT_PHASE`, then issue the
//!    STOP cycle (`GMBUS1` = [`GMBUS1_CYCLE_STOP`] |
//!    `SW_RDY`), wait for `ACTIVE` to clear (bus idle), and
//!    restore `GMBUS0` = 0.
//! 6. On `SATOER`: wait for idle first, then toggle
//!    `SW_CLR_INT` (`GMBUS1` = `SW_CLR_INT`, then `GMBUS1` =
//!    0) to reset the controller and clear the bus error, and
//!    restore `GMBUS0` = 0 (i915's `clear_err` path). On any
//!    other error, restore `GMBUS0` = 0 (i915's timeout path).
//!
//! [`GmbusStatus::classify`] is retained as the snapshot
//! decoder the codec documented; the transport polls the
//! status bits directly because its completion signal is
//! `HW_WAIT_PHASE`, which `classify` deliberately does not
//! model (a new variant would break exhaustive matches in
//! consumers of the codec).

use core::convert::TryFrom;
use core::sync::atomic::{compiler_fence, Ordering};

use crate::intel_gpu_aux::MmioWindow;
use crate::intel_gpu_ddi::Ddi;

// ── Register offsets (TGL PRM Vol. 12 §"GMBUS Registers") ────────

/// MMIO base of the GMBUS block on Gen12 iGPUs.
pub const GMBUS_BASE: u64 = 0x000C_5100;
/// Pin pair selection + clock rate.
pub const GMBUS0: u64 = GMBUS_BASE;
/// Command + slave address.
pub const GMBUS1: u64 = GMBUS_BASE + 0x04;
/// Status + handshake.
pub const GMBUS2: u64 = GMBUS_BASE + 0x08;
/// Data port — 4 bytes per FIFO entry.
pub const GMBUS3: u64 = GMBUS_BASE + 0x0C;
/// Interrupt mask.
pub const GMBUS4: u64 = GMBUS_BASE + 0x10;
/// 2-byte index for byte-indexed transfers.
pub const GMBUS5: u64 = GMBUS_BASE + 0x20;

// ── GMBUS0 — pin pair + rate (TGL PRM Vol. 12 §"GMBUS0") ─────────

/// Bus rate select bits[9:8] → 100 kHz (the conservative default
/// on every pin pair).
pub const GMBUS0_RATE_100KHZ: u32 = 0b000 << 8;
/// Bus rate select → 50 kHz (slow-recovery for marginal cables).
pub const GMBUS0_RATE_50KHZ: u32 = 0b001 << 8;
/// Bus rate select → 400 kHz.
pub const GMBUS0_RATE_400KHZ: u32 = 0b010 << 8;
/// Bus rate select → 1 MHz (DDR rate).
pub const GMBUS0_RATE_1MHZ: u32 = 0b011 << 8;

/// Hold-time extension bit (bit 7) — extends DATA hold by
/// ~300 ns when EDID monitors mis-sample.
pub const GMBUS0_HOLD_EXT: u32 = 1 << 7;
/// Byte-count override (bit 6) — used only by the >511-byte
/// burst-read sequence; the transport's transfers are ≤ 511
/// bytes and never set it.
pub const GMBUS0_BYTE_CNT_OVERRIDE: u32 = 1 << 6;

/// GMBUS pin pair encoding (bits[2:0] of `GMBUS0`). Each value
/// selects which DDI's I²C lines the controller drives.
///
/// Source: TGL PRM Vol. 12 §"GMBUS0 — Pin Pair Selection".
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PinPair {
    /// Disable GMBUS (default at reset).
    Disabled = 0,
    /// Dedicated CRT/VGA legacy I²C — pre-Gen11 only; reserved on
    /// TGL+. Listed for completeness.
    LegacyCrt = 1,
    /// DDI A (combo PHY pair 1).
    DdiA = 2,
    /// DDI B.
    DdiB = 3,
    /// DDI C.
    DdiC = 4,
    /// DDI D / TC1 on USB-C boards.
    DdiD = 5,
    /// DDI E / TC2.
    DdiE = 6,
    /// DDI F / TC3.
    DdiF = 7,
}

impl PinPair {
    /// Pack into bits[2:0] of `GMBUS0`.
    pub const fn encode(self) -> u32 {
        self as u32
    }
}

/// The GMBUS pin pair a DDI's DDC lines hang off (PRM Vol. 12
/// GMBUS0 pin-pair table: DDI A..F = pairs 2..7). DDI G/H have
/// no GMBUS-addressable DDC pair on Gen12 and return `None`.
pub fn pin_pair_for(ddi: Ddi) -> Option<PinPair> {
    Some(match ddi {
        Ddi::A => PinPair::DdiA,
        Ddi::B => PinPair::DdiB,
        Ddi::C => PinPair::DdiC,
        Ddi::D => PinPair::DdiD,
        Ddi::E => PinPair::DdiE,
        Ddi::F => PinPair::DdiF,
        _ => return None,
    })
}

// ── GMBUS1 — command (TGL PRM Vol. 12 §"GMBUS1") ─────────────────

/// Software clear-interrupt + reset (`GMBUS1[31]`). One-shot
/// write-only. In the transport this is *only* the post-NAK
/// recovery toggle — it resets the controller and clears a
/// latched bus error; it does not belong in transfer programs.
pub const GMBUS1_SW_CLR_INT: u32 = 1 << 31;
/// Software-ready flag (`GMBUS1[30]`). Set in every transfer
/// program; cleared by hardware on completion.
pub const GMBUS1_SW_RDY: u32 = 1 << 30;
/// ENT — "ENable Timeout" (`GMBUS1[29]`). When set, hardware
/// aborts a stalled transfer and latches
/// [`GMBUS2_STALL_TIMEOUT`]. The transport does not arm it —
/// i915 doesn't either; its waits are poll budgets, and the
/// stall-timeout status is still checked defensively.
pub const GMBUS1_ENT: u32 = 1 << 29;

/// Bus-cycle select field (`GMBUS1[27:25]`): no cycle — the
/// controller stays in direct software control.
pub const GMBUS1_CYCLE_NONE: u32 = 0 << 25;
/// Bus-cycle select: run the transfer, then hold the bus in
/// the wait phase (SCL held low) awaiting the next program.
/// The data cycle for every transport transfer.
pub const GMBUS1_CYCLE_WAIT: u32 = 1 << 25;
/// Bus-cycle select: INDEX — the controller first emits the
/// index byte in `GMBUS1[15:8]` as a write segment, then
/// repeated-STARTs into the data segment this program
/// describes. The byte-indexed transfer mechanism for 1-byte
/// indices (EDID block offsets, SCDC register addresses).
pub const GMBUS1_CYCLE_INDEX: u32 = 2 << 25;
/// Bus-cycle select: run the transfer, then drive an I²C STOP
/// condition. The transport issues this as a standalone
/// trailing program (`SW_RDY | CYCLE_STOP`, byte count 0) at
/// the end of every transfer — never folded into the data
/// program, so transfers can chain without an intervening
/// STOP.
pub const GMBUS1_CYCLE_STOP: u32 = 4 << 25;
/// The codec's original name for the STOP cycle encoding
/// (`1 << 27` — the same value as [`GMBUS1_CYCLE_STOP`], one
/// bit of the `[27:25]` cycle-select field, not a standalone
/// flag). Retained as an alias so existing compositions keep
/// their meaning; new code should use `GMBUS1_CYCLE_STOP`.
pub const GMBUS1_STO: u32 = GMBUS1_CYCLE_STOP;

/// Read direction bit (`GMBUS1[0]`). When set, the slave-address
/// byte's R/W bit is a read.
pub const GMBUS1_DIR_READ: u32 = 1;

/// Slave address sits in `GMBUS1[7:1]` — left-shifted by 1 from
/// the natural 7-bit address.
pub const fn gmbus1_slave_addr(addr_7bit: u8) -> u32 {
    ((addr_7bit as u32) & 0x7F) << 1
}

/// Byte count sits in `GMBUS1[24:16]` — up to 511 bytes per
/// transfer on Gen9+ (the field is 9 bits).
pub const fn gmbus1_byte_count(bytes: u16) -> u32 {
    ((bytes as u32) & 0x1FF) << 16
}

/// Index byte sits in `GMBUS1[15:8]` for
/// [`GMBUS1_CYCLE_INDEX`] programs.
pub const fn gmbus1_index_byte(index: u8) -> u32 {
    (index as u32) << 8
}

// ── GMBUS2 — status (TGL PRM Vol. 12 §"GMBUS2") ──────────────────

/// In use (`GMBUS2[15]`). Set while the bus is owned.
pub const GMBUS2_INUSE: u32 = 1 << 15;
/// Hardware wait phase (`GMBUS2[14]`). Set when a
/// [`GMBUS1_CYCLE_WAIT`] transfer has moved all its bytes and
/// the controller is holding the bus for the next program —
/// the transport's transfer-complete signal.
pub const GMBUS2_HW_WAIT_PHASE: u32 = 1 << 14;
/// Stall timeout (`GMBUS2[13]`). Latched when an
/// [`GMBUS1_ENT`]-armed transfer stalls past the hardware
/// timeout.
pub const GMBUS2_STALL_TIMEOUT: u32 = 1 << 13;
/// Interrupt status (`GMBUS2[12]`). The transport polls and
/// never enables GMBUS interrupts; listed for completeness.
pub const GMBUS2_INT: u32 = 1 << 12;
/// Hardware ready (`GMBUS2[11]`). Set when the controller has
/// data waiting in `GMBUS3` (read direction) or has consumed
/// the data we wrote (write direction).
pub const GMBUS2_HW_RDY: u32 = 1 << 11;
/// Slave-address timeout error (`GMBUS2[10]`). Set when the
/// addressed slave does not ACK — the NAK / no-such-slave
/// outcome. (Named `NACK` in this module's first revision;
/// `SATOER` is the PRM / i915 name for the bit.)
pub const GMBUS2_SATOER: u32 = 1 << 10;
/// Active bus (`GMBUS2[9]`). Set while a transfer owns the
/// bus; the idle wait polls for it to clear.
pub const GMBUS2_ACTIVE: u32 = 1 << 9;

// ── GMBUS5 — 2-byte index (TGL PRM Vol. 12 §"GMBUS5") ────────────

/// 2-byte index enable (`GMBUS5[31]`). With this set, the
/// controller emits the 16-bit index in `GMBUS5[15:0]` as the
/// write segment before the data segment (the INDEX mechanism
/// for indices that don't fit `GMBUS1[15:8]`). Software must
/// clear `GMBUS5` back to 0 after the transfer.
pub const GMBUS5_2BYTE_INDEX_EN: u32 = 1 << 31;

/// Pack a 2-byte index for [`GMBUS5`]: the first-emitted byte
/// (the index's high byte, e.g. an EDID block offset's MSB) in
/// bits `[15:8]`, the second in bits `[7:0]`.
pub const fn gmbus5_two_byte_index(first: u8, second: u8) -> u32 {
    GMBUS5_2BYTE_INDEX_EN | ((first as u32) << 8) | (second as u32)
}

// ── E-EDID DDC slave addresses ───────────────────────────────────

/// Standard DDC slave address for E-EDID readout (VESA E-EDID 1.4
/// §3.2.1). The DDC2B convention is universal across HDMI / DP /
/// DVI / VGA monitors.
pub const DDC_SLAVE_EDID: u8 = 0x50;
/// DDC2 segment-pointer slave for >256-byte EDID extension reads.
pub const DDC_SLAVE_SEGMENT: u8 = 0x30;

// ── Errors ───────────────────────────────────────────────────────

/// Errors produced by the codec encoders and the transport.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GmbusError {
    /// The pin pair is reserved or not present on this generation.
    InvalidPinPair,
    /// Transfer length is zero or exceeds the 511-byte
    /// per-transfer hardware limit.
    TooManyBytes,
    /// The addressed slave did not ACK (`GMBUS2_SATOER`) — no
    /// sink at that address, or not that slave.
    SlaveNack,
    /// A poll budget ran out before the controller reached the
    /// expected state.
    Timeout,
    /// The controller latched `GMBUS2_STALL_TIMEOUT`.
    HardwareTimeout,
}

// ── Encoded transaction shapes ───────────────────────────────────

/// One programmed EDID-read transaction: the `GMBUS0` and
/// `GMBUS1` register values to write, plus the byte count the
/// caller will pull out of `GMBUS3` after each `HW_RDY` pulse.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EdidReadProgram {
    pub gmbus0: u32,
    pub gmbus1: u32,
    pub byte_count: u16,
}

impl EdidReadProgram {
    /// Number of `GMBUS3` reads (4 bytes per read) needed to
    /// drain `byte_count` bytes from the FIFO. Rounded up.
    pub const fn fifo_reads(&self) -> u16 {
        self.byte_count.div_ceil(4)
    }
}

/// Encode the register values for "read `bytes` bytes of E-EDID
/// from `pin_pair` at 100 kHz".
///
/// The program is the data segment only, in the transport's
/// shape: `SW_RDY | CYCLE_WAIT` + byte count + slave + read.
/// Running it end-to-end (bus select, data phase, wait phase,
/// STOP cycle, idle) is [`GmbusBus::read_edid`]'s job; a caller
/// driving the registers by hand must reproduce that sequence
/// (see the module header's "Transport protocol").
pub fn build_edid_read(pin_pair: PinPair, bytes: u16) -> Result<EdidReadProgram, GmbusError> {
    if matches!(pin_pair, PinPair::Disabled | PinPair::LegacyCrt) {
        return Err(GmbusError::InvalidPinPair);
    }
    if bytes == 0 || bytes > 0x1FF {
        return Err(GmbusError::TooManyBytes);
    }
    let gmbus0 = GMBUS0_RATE_100KHZ | pin_pair.encode();
    let gmbus1 = GMBUS1_SW_RDY
        | GMBUS1_CYCLE_WAIT
        | gmbus1_byte_count(bytes)
        | gmbus1_slave_addr(DDC_SLAVE_EDID)
        | GMBUS1_DIR_READ;
    Ok(EdidReadProgram {
        gmbus0,
        gmbus1,
        byte_count: bytes,
    })
}

/// Decode a `GMBUS2` snapshot.
///
/// Returns `Ok(true)` when the transaction has completed and the
/// caller should drain the FIFO (or transaction has completed
/// cleanly with no further data). Returns `Err(_)` for NACK / bus
/// errors. Returns `Ok(false)` when the controller is still
/// servicing the request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GmbusStatus {
    /// Controller still servicing.
    Pending,
    /// New 4-byte chunk available in `GMBUS3`.
    DataReady,
    /// Transaction complete, no further data.
    Done,
    /// Slave NACKed its address (`GMBUS2_SATOER`).
    SlaveNack,
}

impl GmbusStatus {
    pub fn classify(gmbus2: u32) -> Self {
        if gmbus2 & GMBUS2_SATOER != 0 {
            return GmbusStatus::SlaveNack;
        }
        if gmbus2 & GMBUS2_HW_RDY != 0 {
            return GmbusStatus::DataReady;
        }
        if gmbus2 & GMBUS2_ACTIVE == 0 {
            return GmbusStatus::Done;
        }
        GmbusStatus::Pending
    }
}

impl TryFrom<u32> for PinPair {
    type Error = GmbusError;
    fn try_from(v: u32) -> Result<Self, Self::Error> {
        Ok(match v & 0x7 {
            0 => PinPair::Disabled,
            1 => PinPair::LegacyCrt,
            2 => PinPair::DdiA,
            3 => PinPair::DdiB,
            4 => PinPair::DdiC,
            5 => PinPair::DdiD,
            6 => PinPair::DdiE,
            7 => PinPair::DdiF,
            _ => return Err(GmbusError::InvalidPinPair),
        })
    }
}

// ── Transport ────────────────────────────────────────────────────

/// Poll budget for one GMBUS wait phase. Poll-counted, not
/// time-based (the #879 discipline: aarch64 cycle counters
/// crawl and x86 TSC leaps under TCG, so wall-clock budgets
/// misfire). 100 000 polls ≫ the ~50 ms the reference driver
/// allows a phase on silicon.
pub const GMBUS_POLL_BUDGET: u32 = 100_000;

/// MMIO transport for one GMBUS pin pair — the DDC/I²C engine
/// behind EDID reads and SCDC register traffic. Borrows the
/// BAR0 window (via the crate's shared [`MmioWindow`]) and
/// holds no state across transfers: every method runs one
/// complete transfer (select → program → data → wait phase →
/// STOP → idle) per the module header's protocol.
pub struct GmbusBus<'a, M: MmioWindow + ?Sized> {
    mmio: &'a M,
    pin: PinPair,
    rate: u32,
}

impl<'a, M: MmioWindow + ?Sized> core::fmt::Debug for GmbusBus<'a, M> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GmbusBus")
            .field("pin", &self.pin)
            .field("rate", &self.rate)
            .finish()
    }
}

impl<'a, M: MmioWindow + ?Sized> GmbusBus<'a, M> {
    /// Create a transport for `pin` over the BAR0 window
    /// `mmio`, at the default 100 kHz bus rate.
    pub fn new(mmio: &'a M, pin: PinPair) -> Self {
        Self {
            mmio,
            pin,
            rate: GMBUS0_RATE_100KHZ,
        }
    }

    /// Create a transport with an explicit `GMBUS0` rate field
    /// (one of the `GMBUS0_RATE_*` constants).
    pub fn with_rate(mmio: &'a M, pin: PinPair, rate: u32) -> Self {
        Self { mmio, pin, rate }
    }

    /// The pin pair this bus drives.
    pub fn pin(&self) -> PinPair {
        self.pin
    }

    fn check_len(len: usize) -> Result<(), GmbusError> {
        if len == 0 || len > 0x1FF {
            return Err(GmbusError::TooManyBytes);
        }
        Ok(())
    }

    /// Step 1 of every transfer: select this bus's pin pair +
    /// rate.
    fn select_bus(&self) {
        self.mmio.write32(GMBUS0, self.rate | self.pin.encode());
        compiler_fence(Ordering::SeqCst);
    }

    /// Park the controller: pin pair disabled. Written on every
    /// exit path, success or failure (i915 ends every `xfer`
    /// with `GMBUS0` = 0).
    fn idle_bus(&self) {
        self.mmio.write32(GMBUS0, 0);
        compiler_fence(Ordering::SeqCst);
    }

    /// Compose a data-segment program.
    fn program(&self, slave: u8, len: usize, read: bool, cycle: u32, index: Option<u8>) -> u32 {
        let mut gmbus1 =
            GMBUS1_SW_RDY | cycle | gmbus1_byte_count(len as u16) | gmbus1_slave_addr(slave);
        if let Some(index) = index {
            gmbus1 |= gmbus1_index_byte(index);
        }
        if read {
            gmbus1 |= GMBUS1_DIR_READ;
        }
        gmbus1
    }

    /// Poll `GMBUS2` until `mask` sets. `SATOER` and
    /// `STALL_TIMEOUT` pre-empt the wait (in that order — the
    /// reference driver's wait folds `SATOER` into every status
    /// mask and reports it even when data also arrived).
    fn wait_bits(&self, mask: u32) -> Result<u32, GmbusError> {
        let mut budget = GMBUS_POLL_BUDGET;
        loop {
            let status = self.mmio.read32(GMBUS2);
            if status & GMBUS2_SATOER != 0 {
                return Err(GmbusError::SlaveNack);
            }
            if status & GMBUS2_STALL_TIMEOUT != 0 {
                return Err(GmbusError::HardwareTimeout);
            }
            if status & mask != 0 {
                return Ok(status);
            }
            if budget == 0 {
                return Err(GmbusError::Timeout);
            }
            budget -= 1;
            core::hint::spin_loop();
        }
    }

    /// Poll `GMBUS2` until the bus goes idle (`ACTIVE` clear).
    fn wait_idle(&self) -> Result<(), GmbusError> {
        let mut budget = GMBUS_POLL_BUDGET;
        loop {
            let status = self.mmio.read32(GMBUS2);
            if status & GMBUS2_ACTIVE == 0 {
                return Ok(());
            }
            if budget == 0 {
                return Err(GmbusError::Timeout);
            }
            budget -= 1;
            core::hint::spin_loop();
        }
    }

    /// Route a failed transfer through its exit path: a NAK
    /// gets the controller-reset recovery; anything else just
    /// parks the bus.
    fn abort(&self, err: GmbusError) -> GmbusError {
        match err {
            GmbusError::SlaveNack => match self.nak_recovery() {
                Ok(()) => err,
                Err(recovery_err) => recovery_err,
            },
            _ => {
                self.idle_bus();
                err
            }
        }
    }

    /// The post-NAK recovery (i915 `clear_err`): wait for the
    /// bus to idle *before* clearing the NAK — clearing while
    /// the bus is still active leaves it active and poisons
    /// the next transfer — then toggle `SW_CLR_INT` to reset
    /// the controller, and park the bus. If the idle wait
    /// itself times out, that timeout replaces the NAK as the
    /// reported error, exactly as in the reference driver.
    fn nak_recovery(&self) -> Result<(), GmbusError> {
        let idle = self.wait_idle();
        self.mmio.write32(GMBUS1, GMBUS1_SW_CLR_INT);
        self.mmio.write32(GMBUS1, 0);
        compiler_fence(Ordering::SeqCst);
        self.idle_bus();
        idle
    }

    /// Success-path completion: wait phase → STOP cycle →
    /// idle wait → park.
    fn finish(&self) -> Result<(), GmbusError> {
        match self.wait_bits(GMBUS2_HW_WAIT_PHASE) {
            Ok(_) => {
                self.mmio.write32(GMBUS1, GMBUS1_CYCLE_STOP | GMBUS1_SW_RDY);
                compiler_fence(Ordering::SeqCst);
                let idle = self.wait_idle();
                self.idle_bus();
                idle
            }
            Err(e) => Err(self.abort(e)),
        }
    }

    /// Run a data phase, then the completion / abort routing
    /// shared by every transfer shape.
    fn run(&self, phase: Result<(), GmbusError>) -> Result<(), GmbusError> {
        match phase {
            Ok(()) => self.finish(),
            Err(e) => Err(self.abort(e)),
        }
    }

    /// The read data phase for an already-selected bus: issue
    /// `gmbus1`, then drain `GMBUS3` per `HW_RDY`, little-endian
    /// (first-received byte in bits `[7:0]`).
    fn read_data_phase(&self, gmbus1: u32, out: &mut [u8]) -> Result<(), GmbusError> {
        self.mmio.write32(GMBUS1, gmbus1);
        compiler_fence(Ordering::SeqCst);
        let mut received = 0usize;
        while received < out.len() {
            self.wait_bits(GMBUS2_HW_RDY)?;
            let dword = self.mmio.read32(GMBUS3);
            for b in 0..4 {
                if received < out.len() {
                    out[received] = (dword >> (8 * b)) as u8;
                    received += 1;
                }
            }
        }
        Ok(())
    }

    /// The write data phase for an already-selected bus: the
    /// first `GMBUS3` dword is preloaded *before* the program
    /// (the controller needs data in hand to start the write);
    /// each subsequent dword is written, then awaited.
    fn write_data_phase(&self, gmbus1: u32, data: &[u8]) -> Result<(), GmbusError> {
        let mut sent = 0usize;
        let mut dword = 0u32;
        for b in 0..4 {
            if sent < data.len() {
                dword |= (data[sent] as u32) << (8 * b);
                sent += 1;
            }
        }
        self.mmio.write32(GMBUS3, dword);
        compiler_fence(Ordering::SeqCst);
        self.mmio.write32(GMBUS1, gmbus1);
        compiler_fence(Ordering::SeqCst);
        while sent < data.len() {
            let mut dword = 0u32;
            for b in 0..4 {
                if sent < data.len() {
                    dword |= (data[sent] as u32) << (8 * b);
                    sent += 1;
                }
            }
            self.mmio.write32(GMBUS3, dword);
            compiler_fence(Ordering::SeqCst);
            self.wait_bits(GMBUS2_HW_RDY)?;
        }
        Ok(())
    }

    /// Read `out.len()` bytes from `slave`, starting at the
    /// slave's current internal pointer.
    pub fn read(&self, slave: u8, out: &mut [u8]) -> Result<(), GmbusError> {
        Self::check_len(out.len())?;
        self.select_bus();
        let gmbus1 = self.program(slave, out.len(), true, GMBUS1_CYCLE_WAIT, None);
        self.run(self.read_data_phase(gmbus1, out))
    }

    /// Read `out.len()` bytes from `slave` at byte `index`,
    /// via a [`GMBUS1_CYCLE_INDEX`] program (the controller
    /// emits `index` as the write segment, then repeated-STARTs
    /// into the read). This is the EDID block-offset and SCDC
    /// register-address mechanism.
    pub fn read_indexed(&self, slave: u8, index: u8, out: &mut [u8]) -> Result<(), GmbusError> {
        Self::check_len(out.len())?;
        self.select_bus();
        let gmbus1 = self.program(slave, out.len(), true, GMBUS1_CYCLE_INDEX, Some(index));
        self.run(self.read_data_phase(gmbus1, out))
    }

    /// Read `out.len()` bytes from `slave` at the 2-byte index
    /// `index` (first-emitted byte first), via `GMBUS5`. The
    /// register is cleared back to 0 after the transfer,
    /// whatever its outcome.
    pub fn read_indexed2(
        &self,
        slave: u8,
        index: [u8; 2],
        out: &mut [u8],
    ) -> Result<(), GmbusError> {
        Self::check_len(out.len())?;
        self.select_bus();
        self.mmio
            .write32(GMBUS5, gmbus5_two_byte_index(index[0], index[1]));
        compiler_fence(Ordering::SeqCst);
        let gmbus1 = self.program(slave, out.len(), true, GMBUS1_CYCLE_WAIT, None);
        let result = self.run(self.read_data_phase(gmbus1, out));
        self.mmio.write32(GMBUS5, 0);
        result
    }

    /// Write `data` to `slave`.
    pub fn write(&self, slave: u8, data: &[u8]) -> Result<(), GmbusError> {
        Self::check_len(data.len())?;
        self.select_bus();
        let gmbus1 = self.program(slave, data.len(), false, GMBUS1_CYCLE_WAIT, None);
        self.run(self.write_data_phase(gmbus1, data))
    }

    /// Write `data` to `slave` at byte `index`, via a
    /// [`GMBUS1_CYCLE_INDEX`] program.
    pub fn write_indexed(&self, slave: u8, index: u8, data: &[u8]) -> Result<(), GmbusError> {
        Self::check_len(data.len())?;
        self.select_bus();
        let gmbus1 = self.program(slave, data.len(), false, GMBUS1_CYCLE_INDEX, Some(index));
        self.run(self.write_data_phase(gmbus1, data))
    }

    /// Read one 128-byte E-EDID base block from this bus's pin
    /// pair — the codec's own [`build_edid_read`] program run
    /// through the full transport sequence. (The program's
    /// `GMBUS0` value is the 100 kHz default; a bus built with
    /// [`GmbusBus::with_rate`] selects its own rate instead —
    /// the `GMBUS1` program is rate-independent.)
    pub fn read_edid(&self, out: &mut [u8; 128]) -> Result<(), GmbusError> {
        let program = build_edid_read(self.pin, 128)?;
        self.select_bus();
        self.run(self.read_data_phase(program.gmbus1, out))
    }
}

/// Read `out.len()` bytes from DDC `slave` at byte `index`
/// over the pin pair `pin` — the free-function transfer shape
/// session code composes with. `index` up to `0xFF` rides a
/// [`GMBUS1_CYCLE_INDEX`] program; a wider index goes through
/// `GMBUS5` as a 2-byte index.
pub fn gmbus_read<M: MmioWindow + ?Sized>(
    mmio: &M,
    pin: PinPair,
    slave: u8,
    index: u16,
    out: &mut [u8],
) -> Result<(), GmbusError> {
    let bus = GmbusBus::new(mmio, pin);
    if index > 0xFF {
        bus.read_indexed2(slave, [(index >> 8) as u8, index as u8], out)
    } else {
        bus.read_indexed(slave, index as u8, out)
    }
}

/// Write `data` to DDC `slave` over the pin pair `pin` (an
/// SCDC register write is `[register, value]`; the E-DDC
/// segment pointer is one byte).
pub fn gmbus_write<M: MmioWindow + ?Sized>(
    mmio: &M,
    pin: PinPair,
    slave: u8,
    data: &[u8],
) -> Result<(), GmbusError> {
    GmbusBus::new(mmio, pin).write(slave, data)
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;
    use core::cell::RefCell;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // ── Codec smokes ─────────────────────────────────────────

    fn smoke_pin_pair_round_trip() -> TestResult {
        for v in 0u32..=7 {
            let pp = PinPair::try_from(v).expect("valid range");
            if pp.encode() != v {
                return TestResult::Fail("pin pair encode round-trip");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gmbus", smoke_pin_pair_round_trip);

    fn smoke_edid_read_program_layout() -> TestResult {
        let p = match build_edid_read(PinPair::DdiB, 128) {
            Ok(p) => p,
            Err(_) => return TestResult::Fail("clean inputs rejected"),
        };
        if p.gmbus0 & 0x7 != PinPair::DdiB.encode() {
            return TestResult::Fail("pin pair not in GMBUS0[2:0]");
        }
        if p.gmbus1 & GMBUS1_DIR_READ == 0 {
            return TestResult::Fail("read direction not set");
        }
        if p.gmbus1 & GMBUS1_SW_RDY == 0 {
            return TestResult::Fail("SW_RDY not set");
        }
        // The data program is a CYCLE_WAIT chunk in the
        // reference protocol's shape: no SW_CLR_INT (that is
        // the post-NAK recovery toggle), no ENT, and no STOP
        // cycle folded in (STOP is a trailing program).
        if p.gmbus1 & (0b111 << 25) != GMBUS1_CYCLE_WAIT {
            return TestResult::Fail("data program must select CYCLE_WAIT");
        }
        if p.gmbus1 & GMBUS1_SW_CLR_INT != 0 {
            return TestResult::Fail("SW_CLR_INT must not ride the data program");
        }
        if p.gmbus1 & GMBUS1_ENT != 0 {
            return TestResult::Fail("ENT must not ride the data program");
        }
        if (p.gmbus1 >> 16) & 0x1FF != 128 {
            return TestResult::Fail("byte count not encoded");
        }
        if (p.gmbus1 >> 1) & 0x7F != DDC_SLAVE_EDID as u32 {
            return TestResult::Fail("slave address not encoded");
        }
        if p.fifo_reads() != 32 {
            return TestResult::Fail("fifo_reads should round 128 → 32");
        }
        // The whole program, pinned against the value composed
        // by hand from intel_gmbus_regs.h field encodings:
        // SW_RDY | CYCLE_WAIT | 128<<16 | 0x50<<1 | READ.
        if p.gmbus1 != 0x4280_00A1 {
            return TestResult::Fail("program differs from the pinned reference shape");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gmbus",
        smoke_edid_read_program_layout
    );

    fn smoke_edid_read_rejects_disabled_pin_pair() -> TestResult {
        match build_edid_read(PinPair::Disabled, 128) {
            Err(GmbusError::InvalidPinPair) => TestResult::Pass,
            _ => TestResult::Fail("disabled pin pair must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gmbus",
        smoke_edid_read_rejects_disabled_pin_pair
    );

    fn smoke_edid_read_rejects_oversize() -> TestResult {
        match build_edid_read(PinPair::DdiB, 600) {
            Err(GmbusError::TooManyBytes) => TestResult::Pass,
            _ => TestResult::Fail("oversize byte count must be rejected"),
        }
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gmbus",
        smoke_edid_read_rejects_oversize
    );

    fn smoke_status_classify() -> TestResult {
        if GmbusStatus::classify(GMBUS2_SATOER) != GmbusStatus::SlaveNack {
            return TestResult::Fail("SATOER not classified");
        }
        if GmbusStatus::classify(GMBUS2_HW_RDY | GMBUS2_ACTIVE) != GmbusStatus::DataReady {
            return TestResult::Fail("HW_RDY not classified");
        }
        if GmbusStatus::classify(GMBUS2_ACTIVE) != GmbusStatus::Pending {
            return TestResult::Fail("ACTIVE alone is pending");
        }
        if GmbusStatus::classify(0) != GmbusStatus::Done {
            return TestResult::Fail("idle bus is done");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gmbus", smoke_status_classify);

    // ── Register-map pins (the #1018 corrections) ────────────

    fn smoke_gmbus_base_points_at_prm_block() -> TestResult {
        // TGL PRM Vol. 12: the GMBUS block starts at 0xC5100;
        // GMBUS5 is at +0x20, not +0x14.
        if GMBUS_BASE != 0x000C_5100 {
            return TestResult::Fail("GMBUS_BASE must be 0xC5100 (PRM Vol. 12)");
        }
        if GMBUS0 != GMBUS_BASE
            || GMBUS1 != GMBUS_BASE + 0x04
            || GMBUS2 != GMBUS_BASE + 0x08
            || GMBUS3 != GMBUS_BASE + 0x0C
            || GMBUS4 != GMBUS_BASE + 0x10
            || GMBUS5 != GMBUS_BASE + 0x20
        {
            return TestResult::Fail("register offsets differ from the PRM block layout");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gmbus",
        smoke_gmbus_base_points_at_prm_block
    );

    fn smoke_gmbus_bit_map_matches_reference() -> TestResult {
        // Every value below is transcribed from
        // intel_gmbus_regs.h (the i915 register header), not
        // read back from the transport that consumes them.
        if GMBUS2_INUSE != 1 << 15 {
            return TestResult::Fail("INUSE is GMBUS2[15]");
        }
        if GMBUS2_HW_WAIT_PHASE != 1 << 14 {
            return TestResult::Fail("HW_WAIT_PHASE is GMBUS2[14] (not a HW_DONE bit)");
        }
        if GMBUS2_STALL_TIMEOUT != 1 << 13 || GMBUS2_INT != 1 << 12 {
            return TestResult::Fail("STALL_TIMEOUT / INT are GMBUS2[13] / [12]");
        }
        if GMBUS2_HW_RDY != 1 << 11 || GMBUS2_SATOER != 1 << 10 || GMBUS2_ACTIVE != 1 << 9 {
            return TestResult::Fail("HW_RDY / SATOER / ACTIVE are GMBUS2[11] / [10] / [9]");
        }
        if GMBUS0_HOLD_EXT != 1 << 7 || GMBUS0_BYTE_CNT_OVERRIDE != 1 << 6 {
            return TestResult::Fail("HOLD_EXT is GMBUS0[7]; bit 6 is BYTE_CNT_OVERRIDE");
        }
        if GMBUS1_CYCLE_WAIT != 1 << 25
            || GMBUS1_CYCLE_INDEX != 2 << 25
            || GMBUS1_CYCLE_STOP != 4 << 25
            || GMBUS1_STO != GMBUS1_CYCLE_STOP
        {
            return TestResult::Fail("cycle-select field [27:25]: WAIT=1, INDEX=2, STOP=4");
        }
        if GMBUS5_2BYTE_INDEX_EN != 1 << 31 || gmbus5_two_byte_index(0x01, 0x80) != 0x8000_0180 {
            return TestResult::Fail("GMBUS5 2-byte index packing wrong");
        }
        if gmbus1_index_byte(0x80) != 0x8000 {
            return TestResult::Fail("GMBUS1 index byte sits at [15:8]");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gmbus",
        smoke_gmbus_bit_map_matches_reference
    );

    // ── Simulated GMBUS controller + DDC slaves ──────────────
    //
    // The fake models the *hardware side* of the PRM
    // conversation: it latches a transfer on a SW_RDY program,
    // ACKs or SATOERs the address phase by slave presence,
    // serves / sinks the data phase per the latched byte
    // count, enters the wait phase when the count is met,
    // and releases the bus (ACTIVE clear) only on the STOP
    // cycle. A SATOER latch keeps ACTIVE up for a few polls
    // (the aborted transfer quiescing) and then drops it,
    // staying latched until the SW_CLR_INT recovery toggle.

    /// SCDC slave address (HDMI SCDC, via `drm_scdc_helper`).
    const SCDC_ADDR: u8 = 0x54;

    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    enum Phase {
        Idle,
        Data,
        WaitPhase,
        Nak,
        Wedged,
        Stalled,
    }

    struct FakeState {
        gmbus0: u32,
        gmbus5: u32,
        phase: Phase,
        nak_active_polls: u32,
        serve: Vec<u8>,
        serve_pos: usize,
        sink: Vec<u8>,
        sink_addr: u8,
        sink_expected: usize,
        edid: [u8; 512],
        edid_present: bool,
        segment: usize,
        scdc: [u8; 256],
        scdc_present: bool,
        wedge: bool,
        stall: bool,
        writes: Vec<(u64, u32)>,
        gmbus3_reads: usize,
    }

    impl FakeState {
        fn new() -> Self {
            Self {
                gmbus0: 0,
                gmbus5: 0,
                phase: Phase::Idle,
                nak_active_polls: 0,
                serve: Vec::new(),
                serve_pos: 0,
                sink: Vec::new(),
                sink_addr: 0,
                sink_expected: 0,
                edid: test_edid_image(),
                edid_present: true,
                segment: 0,
                scdc: [0u8; 256],
                scdc_present: true,
                wedge: false,
                stall: false,
                writes: Vec::new(),
                gmbus3_reads: 0,
            }
        }

        fn status(&mut self) -> u32 {
            match self.phase {
                Phase::Idle => 0,
                Phase::Data => GMBUS2_ACTIVE | GMBUS2_HW_RDY,
                // HW_RDY reads as still latched in the wait
                // phase: it pulses when the controller consumes
                // the final GMBUS3 dword, and the transport's
                // post-write wait on it (the reference driver's
                // per-chunk wait) must observe it before the
                // wait-phase wait begins.
                Phase::WaitPhase => GMBUS2_ACTIVE | GMBUS2_HW_WAIT_PHASE | GMBUS2_HW_RDY,
                Phase::Nak => {
                    // The aborted transfer quiesces over a few
                    // polls; SATOER itself stays latched until
                    // the SW_CLR_INT toggle.
                    if self.nak_active_polls > 0 {
                        self.nak_active_polls -= 1;
                        GMBUS2_ACTIVE | GMBUS2_SATOER
                    } else {
                        GMBUS2_SATOER
                    }
                }
                Phase::Wedged => GMBUS2_ACTIVE,
                Phase::Stalled => GMBUS2_ACTIVE | GMBUS2_STALL_TIMEOUT,
            }
        }

        fn complete_write(&mut self) {
            match self.sink_addr {
                DDC_SLAVE_SEGMENT => {
                    if !self.sink.is_empty() {
                        self.segment = self.sink[0] as usize;
                    }
                }
                SCDC_ADDR => {
                    if self.sink.len() >= 2 {
                        let base = self.sink[0] as usize;
                        for (i, v) in self.sink[1..].iter().enumerate() {
                            self.scdc[(base + i) & 0xFF] = *v;
                        }
                    }
                }
                _ => {}
            }
            self.sink.clear();
            self.sink_expected = 0;
            self.phase = Phase::WaitPhase;
        }

        fn on_gmbus1(&mut self, val: u32) {
            if val & GMBUS1_SW_CLR_INT != 0 && val & GMBUS1_SW_RDY == 0 {
                // Recovery toggle: clears a latched SATOER.
                if self.phase == Phase::Nak {
                    self.phase = Phase::Idle;
                }
                return;
            }
            if val & GMBUS1_SW_RDY == 0 {
                return;
            }
            let cycle = val & (0b111 << 25);
            let count = ((val >> 16) & 0x1FF) as usize;
            if cycle == GMBUS1_CYCLE_STOP && count == 0 {
                if self.phase == Phase::WaitPhase {
                    self.phase = Phase::Idle;
                }
                return;
            }
            // A data program.
            let addr = ((val >> 1) & 0x7F) as u8;
            let read = val & GMBUS1_DIR_READ != 0;
            let present = match addr {
                DDC_SLAVE_EDID => self.edid_present,
                DDC_SLAVE_SEGMENT => true,
                SCDC_ADDR => self.scdc_present,
                _ => false,
            };
            if !present {
                self.sink.clear();
                self.phase = Phase::Nak;
                self.nak_active_polls = 3;
                return;
            }
            if self.wedge {
                self.sink.clear();
                self.phase = Phase::Wedged;
                return;
            }
            if self.stall {
                self.sink.clear();
                self.phase = Phase::Stalled;
                return;
            }
            if read {
                self.sink.clear();
                let index_byte = ((val >> 8) & 0xFF) as usize;
                let start = match addr {
                    DDC_SLAVE_EDID => {
                        if self.gmbus5 & GMBUS5_2BYTE_INDEX_EN != 0 {
                            ((self.gmbus5 >> 8) & 0xFF) * 256 + (self.gmbus5 & 0xFF) as usize
                        } else if cycle == GMBUS1_CYCLE_INDEX {
                            self.segment * 256 + index_byte
                        } else {
                            self.segment * 256
                        }
                    }
                    _ => {
                        if cycle == GMBUS1_CYCLE_INDEX {
                            index_byte
                        } else {
                            0
                        }
                    }
                };
                let mut serve = Vec::new();
                for i in 0..count {
                    serve.push(match addr {
                        DDC_SLAVE_EDID => self.edid[(start + i) % 512],
                        _ => self.scdc[(start + i) & 0xFF],
                    });
                }
                self.serve = serve;
                self.serve_pos = 0;
                self.phase = Phase::Data;
            } else {
                self.sink_addr = addr;
                self.sink_expected = count;
                if self.sink.len() >= count {
                    self.complete_write();
                } else {
                    self.phase = Phase::Data;
                }
            }
        }

        fn on_gmbus3_write(&mut self, val: u32) {
            for b in 0..4 {
                self.sink.push((val >> (8 * b)) as u8);
            }
            if self.phase == Phase::Data
                && self.sink_expected > 0
                && self.sink.len() >= self.sink_expected
            {
                self.complete_write();
            }
        }

        fn on_gmbus3_read(&mut self) -> u32 {
            self.gmbus3_reads += 1;
            let mut dword = 0u32;
            for b in 0..4 {
                if self.serve_pos + b < self.serve.len() {
                    dword |= (self.serve[self.serve_pos + b] as u32) << (8 * b);
                }
            }
            self.serve_pos += 4;
            if self.serve_pos >= self.serve.len() && self.phase == Phase::Data {
                self.phase = Phase::WaitPhase;
            }
            dword
        }

        fn read(&mut self, off: u64) -> u32 {
            match off {
                GMBUS0 => self.gmbus0,
                GMBUS2 => self.status(),
                GMBUS3 => self.on_gmbus3_read(),
                GMBUS5 => self.gmbus5,
                _ => 0,
            }
        }

        fn write(&mut self, off: u64, val: u32) {
            self.writes.push((off, val));
            match off {
                GMBUS0 => {
                    self.gmbus0 = val;
                    if val == 0 {
                        // Parking the bus abandons any latched
                        // transfer (but not a latched SATOER —
                        // that needs the recovery toggle).
                        if self.phase != Phase::Nak {
                            self.phase = Phase::Idle;
                        }
                        self.sink.clear();
                        self.sink_expected = 0;
                    }
                }
                GMBUS1 => self.on_gmbus1(val),
                GMBUS3 => self.on_gmbus3_write(val),
                GMBUS5 => self.gmbus5 = val,
                _ => {}
            }
        }
    }

    /// The fake controller + slaves behind the shared
    /// `MmioWindow` interface.
    pub struct FakeGmbus {
        state: RefCell<FakeState>,
    }

    impl FakeGmbus {
        fn new() -> Self {
            Self {
                state: RefCell::new(FakeState::new()),
            }
        }
        fn writes(&self) -> Vec<(u64, u32)> {
            self.state.borrow().writes.clone()
        }
        fn writes_to(&self, off: u64) -> Vec<u32> {
            self.state
                .borrow()
                .writes
                .iter()
                .filter(|(o, _)| *o == off)
                .map(|(_, v)| *v)
                .collect()
        }
        fn gmbus3_reads(&self) -> usize {
            self.state.borrow().gmbus3_reads
        }
        fn scdc_at(&self, reg: u8) -> u8 {
            self.state.borrow().scdc[reg as usize]
        }
        fn set_edid_present(&self, present: bool) {
            self.state.borrow_mut().edid_present = present;
        }
        fn set_wedge(&self, wedge: bool) {
            self.state.borrow_mut().wedge = wedge;
        }
        fn set_stall(&self, stall: bool) {
            self.state.borrow_mut().stall = stall;
        }
    }

    impl MmioWindow for FakeGmbus {
        fn read32(&self, off: u64) -> u32 {
            self.state.borrow_mut().read(off)
        }
        fn write32(&self, off: u64, val: u32) {
            self.state.borrow_mut().write(off, val)
        }
    }

    /// Set a 128-byte block's checksum byte (E-EDID rule: the
    /// block's bytes sum to 0 mod 256).
    fn fix_checksum(block: &mut [u8]) {
        let sum: u32 = block[..127].iter().map(|&b| b as u32).sum();
        block[127] = 0u8.wrapping_sub((sum % 256) as u8);
    }

    /// A spec-shaped 512-byte EDID device image: a valid
    /// E-EDID 1.4 base block (manufacturer "NAR", one CTA-861
    /// extension declared), the extension, and two raw blocks
    /// of distinct pattern bytes. Field layout per VESA
    /// E-EDID 1.4 §3.
    fn test_edid_image() -> [u8; 512] {
        let mut img = [0u8; 512];
        img[0..8].copy_from_slice(&[0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00]);
        // Manufacturer ID, packed (letter << shift) per §3.4:
        // 'N'=14 << 10 | 'A'=1 << 5 | 'R'=18, big-endian.
        img[8] = 0x38;
        img[9] = 0x32;
        img[10] = 0x34;
        img[11] = 0x12; // product code 0x1234, little-endian
        img[12] = 0x01; // serial, little-endian LSB
        img[16] = 42; // manufacture week
        img[17] = 36; // year = 1990 + 36
        img[18] = 1;
        img[19] = 4; // EDID structure 1.4
        img[20] = 0x80; // digital input
        img[21] = 52;
        img[22] = 30; // 52 cm × 30 cm
        img[23] = 0x78; // gamma 2.20
        img[24] = 0x0A; // feature support
        for i in 25..126 {
            img[i] = (i as u8) ^ 0xA5;
        }
        img[126] = 1; // one extension follows
        fix_checksum(&mut img[0..128]);
        // CTA-861 extension block.
        img[128] = 0x02; // CTA extension tag
        img[129] = 0x03; // revision 3
        img[130] = 0x04; // first DTD offset (no DTDs)
        img[131] = 0x00; // underscan / audio flags
        for i in 132..255 {
            img[i] = (i as u8) ^ 0x3C;
        }
        fix_checksum(&mut img[128..256]);
        // Blocks 2–3: raw device space with distinct bytes.
        for i in 256..512 {
            img[i] = (i as u8) ^ 0x5A;
        }
        img
    }

    // ── Transport smokes ─────────────────────────────────────

    fn smoke_transport_edid_base_block_read() -> TestResult {
        let fake = FakeGmbus::new();
        let bus = GmbusBus::new(&fake, PinPair::DdiB);
        let mut out = [0u8; 128];
        if bus.read_edid(&mut out).is_err() {
            return TestResult::Fail("base EDID read must succeed against the fake sink");
        }
        let image = test_edid_image();
        if out != image[0..128] {
            return TestResult::Fail("base block bytes must arrive unmolested");
        }
        // E-EDID checksum rule, checked independently of the
        // transport: the block sums to 0 mod 256.
        if out.iter().map(|&b| b as u32).sum::<u32>() % 256 != 0 {
            return TestResult::Fail("base block fails the E-EDID checksum rule");
        }
        if fake.gmbus3_reads() != 32 {
            return TestResult::Fail("128 bytes must drain as exactly 32 GMBUS3 reads");
        }
        // The complete register conversation, pinned:
        // select (100 kHz | DDI B) → program → STOP cycle → park.
        let expected: [(u64, u32); 4] = [
            (GMBUS0, 3),
            (GMBUS1, 0x4280_00A1),
            (GMBUS1, 0x4800_0000),
            (GMBUS0, 0),
        ];
        if fake.writes() != expected {
            return TestResult::Fail("EDID read conversation differs from the pinned sequence");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gmbus",
        smoke_transport_edid_base_block_read
    );

    fn smoke_transport_segment_and_index_reads() -> TestResult {
        // The masking-defeating case: a multi-block EDID read
        // where the segment pointer and the byte index must
        // compose — a transport that drops either lands on the
        // wrong block and the distinct block bytes expose it.
        let fake = FakeGmbus::new();
        let image = test_edid_image();
        // E-DDC segment pointer: block group 256..511 is
        // segment 1 (VESA E-EDID §"Segment Pointer").
        if gmbus_write(&fake, PinPair::DdiB, DDC_SLAVE_SEGMENT, &[1]).is_err() {
            return TestResult::Fail("segment pointer write must succeed");
        }
        let seg_writes: [(u64, u32); 5] = [
            (GMBUS0, 3),
            (GMBUS3, 0x0000_0001), // preload precedes the program
            (GMBUS1, 0x4201_0060),
            (GMBUS1, 0x4800_0000),
            (GMBUS0, 0),
        ];
        if fake.writes() != seg_writes {
            return TestResult::Fail("segment write conversation differs from the pinned sequence");
        }
        // Block 2 (image bytes 256..384): segment 1, index 0.
        let mut block2 = [0u8; 128];
        if gmbus_read(&fake, PinPair::DdiB, DDC_SLAVE_EDID, 0, &mut block2).is_err() {
            return TestResult::Fail("block 2 read must succeed");
        }
        if block2 != image[256..384] {
            return TestResult::Fail("block 2 must come from segment 1 + index 0");
        }
        // Block 3 (image bytes 384..512): segment persists,
        // index 128.
        let mut block3 = [0u8; 128];
        if gmbus_read(&fake, PinPair::DdiB, DDC_SLAVE_EDID, 128, &mut block3).is_err() {
            return TestResult::Fail("block 3 read must succeed");
        }
        if block3 != image[384..512] {
            return TestResult::Fail("block 3 must come from segment 1 + index 128");
        }
        // The index rode the GMBUS1 programs as CYCLE_INDEX
        // with the byte at [15:8] — and GMBUS5 was never
        // touched (a 1-byte index does not belong there).
        let programs = fake.writes_to(GMBUS1);
        if !programs.contains(&0x4480_00A1) || !programs.contains(&0x4480_80A1) {
            return TestResult::Fail("indexed reads must program CYCLE_INDEX + index byte");
        }
        if !fake.writes_to(GMBUS5).is_empty() {
            return TestResult::Fail("1-byte indexed reads must not write GMBUS5");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gmbus",
        smoke_transport_segment_and_index_reads
    );

    fn smoke_transport_two_byte_index_uses_gmbus5() -> TestResult {
        let fake = FakeGmbus::new();
        let bus = GmbusBus::new(&fake, PinPair::DdiB);
        let image = test_edid_image();
        let mut out = [0u8; 64];
        if bus
            .read_indexed2(DDC_SLAVE_EDID, [0x01, 0x80], &mut out)
            .is_err()
        {
            return TestResult::Fail("2-byte indexed read must succeed");
        }
        if out != image[0x180..0x180 + 64] {
            return TestResult::Fail("2-byte index 0x0180 must address device byte 0x180");
        }
        // GMBUS5 carries EN + the index before the program;
        // the program itself is a plain CYCLE_WAIT (no
        // CYCLE_INDEX); GMBUS5 is cleared after the transfer.
        let expected: [(u64, u32); 6] = [
            (GMBUS0, 3),
            (GMBUS5, 0x8000_0180),
            (GMBUS1, 0x4240_00A1),
            (GMBUS1, 0x4800_0000),
            (GMBUS0, 0),
            (GMBUS5, 0),
        ];
        if fake.writes() != expected {
            return TestResult::Fail("2-byte index conversation differs from the pinned sequence");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gmbus",
        smoke_transport_two_byte_index_uses_gmbus5
    );

    fn smoke_transport_nak_refusal_and_recovery() -> TestResult {
        let fake = FakeGmbus::new();
        fake.set_edid_present(false);
        let bus = GmbusBus::new(&fake, PinPair::DdiB);
        let mut out = [0u8; 128];
        match bus.read_edid(&mut out) {
            Err(GmbusError::SlaveNack) => {}
            _ => return TestResult::Fail("an absent slave must refuse as SlaveNack"),
        }
        // The recovery conversation, pinned: program, then —
        // after the idle wait — the SW_CLR_INT toggle, then
        // park. No STOP cycle is issued on the error path.
        let expected: [(u64, u32); 5] = [
            (GMBUS0, 3),
            (GMBUS1, 0x4280_00A1),
            (GMBUS1, GMBUS1_SW_CLR_INT),
            (GMBUS1, 0),
            (GMBUS0, 0),
        ];
        if fake.writes() != expected {
            return TestResult::Fail("NAK recovery conversation differs from the pinned sequence");
        }
        // The controller is usable again after recovery.
        fake.set_edid_present(true);
        if bus.read_edid(&mut out).is_err() {
            return TestResult::Fail("a read after NAK recovery must succeed");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gmbus",
        smoke_transport_nak_refusal_and_recovery
    );

    fn smoke_transport_bus_timeout() -> TestResult {
        let fake = FakeGmbus::new();
        fake.set_wedge(true);
        let bus = GmbusBus::new(&fake, PinPair::DdiB);
        let mut out = [0u8; 16];
        match bus.read(DDC_SLAVE_EDID, &mut out) {
            Err(GmbusError::Timeout) => {}
            _ => return TestResult::Fail("a wedged bus must refuse as Timeout"),
        }
        // Timeout exit path: the bus is parked, and no STOP
        // cycle was issued.
        let writes = fake.writes();
        if writes.last() != Some(&(GMBUS0, 0)) {
            return TestResult::Fail("timeout path must park the bus (GMBUS0 = 0)");
        }
        if writes.contains(&(GMBUS1, 0x4800_0000)) {
            return TestResult::Fail("timeout path must not issue a STOP cycle");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gmbus", smoke_transport_bus_timeout);

    fn smoke_transport_stall_timeout() -> TestResult {
        let fake = FakeGmbus::new();
        fake.set_stall(true);
        let bus = GmbusBus::new(&fake, PinPair::DdiB);
        let mut out = [0u8; 16];
        match bus.read(DDC_SLAVE_EDID, &mut out) {
            Err(GmbusError::HardwareTimeout) => {}
            _ => return TestResult::Fail("a latched STALL_TIMEOUT must refuse as HardwareTimeout"),
        }
        if fake.writes().last() != Some(&(GMBUS0, 0)) {
            return TestResult::Fail("stall path must park the bus (GMBUS0 = 0)");
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/gpu/intel_gpu_gmbus", smoke_transport_stall_timeout);

    fn smoke_transport_scdc_write_then_read() -> TestResult {
        // An SCDC-shaped conversation (slave 0x54, register
        // 0x20 TMDS_CONFIG — the drm_scdc_helper map the HDMI
        // session consumes): write [0x20, 0x03], read back.
        let fake = FakeGmbus::new();
        if gmbus_write(&fake, PinPair::DdiB, SCDC_ADDR, &[0x20, 0x03]).is_err() {
            return TestResult::Fail("SCDC register write must succeed");
        }
        if fake.scdc_at(0x20) != 0x03 {
            return TestResult::Fail("SCDC register 0x20 must hold the written value");
        }
        // Preload order pinned: the GMBUS3 dword (LE-packed
        // [0x20, 0x03]) is written BEFORE the GMBUS1 program.
        let writes = fake.writes();
        let preload_at = writes.iter().position(|&w| w == (GMBUS3, 0x0000_0320));
        let program_at = writes.iter().position(|&w| w == (GMBUS1, 0x4202_00A8));
        match (preload_at, program_at) {
            (Some(p), Some(g)) if p < g => {}
            _ => return TestResult::Fail("write preload must precede the GMBUS1 program"),
        }
        let mut out = [0u8; 1];
        if gmbus_read(&fake, PinPair::DdiB, SCDC_ADDR, 0x20, &mut out).is_err() {
            return TestResult::Fail("SCDC register read must succeed");
        }
        if out != [0x03] {
            return TestResult::Fail("SCDC readback must return the written value");
        }
        if !fake.writes_to(GMBUS1).contains(&0x4401_20A9) {
            return TestResult::Fail("SCDC read must program CYCLE_INDEX with index 0x20");
        }
        // A multi-chunk write (6 bytes = a preloaded dword plus
        // a waited dword) lands its payload across consecutive
        // SCDC registers.
        if gmbus_write(
            &fake,
            PinPair::DdiB,
            SCDC_ADDR,
            &[0x20, 0x03, 0xAA, 0xBB, 0xCC, 0xDD],
        )
        .is_err()
        {
            return TestResult::Fail("multi-chunk SCDC write must succeed");
        }
        if fake.scdc_at(0x20) != 0x03
            || fake.scdc_at(0x21) != 0xAA
            || fake.scdc_at(0x22) != 0xBB
            || fake.scdc_at(0x23) != 0xCC
            || fake.scdc_at(0x24) != 0xDD
        {
            return TestResult::Fail("multi-chunk write payload must land byte-exact");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gmbus",
        smoke_transport_scdc_write_then_read
    );

    fn smoke_transport_pin_pair_selection() -> TestResult {
        // DDI A..F map to pin pairs 2..7 (PRM Vol. 12 pin-pair
        // table); DDI G/H have no GMBUS pair.
        let table = [
            (Ddi::A, PinPair::DdiA),
            (Ddi::B, PinPair::DdiB),
            (Ddi::C, PinPair::DdiC),
            (Ddi::D, PinPair::DdiD),
            (Ddi::E, PinPair::DdiE),
            (Ddi::F, PinPair::DdiF),
        ];
        for (ddi, pair) in table {
            if pin_pair_for(ddi) != Some(pair) {
                return TestResult::Fail("DDI → pin pair mapping wrong");
            }
        }
        if pin_pair_for(Ddi::G).is_some() || pin_pair_for(Ddi::H).is_some() {
            return TestResult::Fail("DDI G/H must have no GMBUS pin pair");
        }
        // The select write carries rate | pair: DDI E at the
        // default rate is 6; DDI C at 400 kHz is 0x204.
        let fake = FakeGmbus::new();
        let bus = GmbusBus::new(&fake, PinPair::DdiE);
        let mut out = [0u8; 4];
        if bus.read(DDC_SLAVE_EDID, &mut out).is_err() {
            return TestResult::Fail("DDI E read must succeed");
        }
        if fake.writes().first() != Some(&(GMBUS0, 6)) {
            return TestResult::Fail("select write must be rate | DdiE (6)");
        }
        let fake2 = FakeGmbus::new();
        let bus2 = GmbusBus::with_rate(&fake2, PinPair::DdiC, GMBUS0_RATE_400KHZ);
        if bus2.read(DDC_SLAVE_EDID, &mut out).is_err() {
            return TestResult::Fail("DDI C read must succeed");
        }
        if fake2.writes().first() != Some(&(GMBUS0, 0x204)) {
            return TestResult::Fail("select write must be 400 kHz | DdiC (0x204)");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gmbus",
        smoke_transport_pin_pair_selection
    );
}

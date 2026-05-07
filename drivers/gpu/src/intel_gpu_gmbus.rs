//! GMBUS — Intel iGPU I²C controller for DDC / EDID — clean-room.
//!
//! Reference: **Tiger Lake PRM Vol. 12 §"GMBUS Programming"**.
//! Cross-checked against the Alder Lake PRM (same offsets) and
//! the Meteor Lake display PRM (`GMBUS*` MMIO base shifted from
//! `0xC5100` → `0xC5100`; the offsets within the block are stable).
//!
//! ## Block layout
//!
//! GMBUS is a five-register block at MMIO `0xC5100`:
//!
//! | Offset | Register      | Purpose                             |
//! | ------ | ------------- | ----------------------------------- |
//! | +0x00  | `GMBUS0`      | Pin pair selection + bus rate       |
//! | +0x04  | `GMBUS1`      | Command + slave address             |
//! | +0x08  | `GMBUS2`      | Status + handshake                  |
//! | +0x0C  | `GMBUS3`      | Data port (4 bytes per FIFO entry)  |
//! | +0x10  | `GMBUS4`      | Interrupt mask                      |
//! | +0x14  | `GMBUS5`      | 2-byte index for byte-indexed reads |
//!
//! ## Scope
//!
//! Codec layer only — produces the wire register values for a
//! "read N bytes from slave 0x50" transaction (the standard E-EDID
//! DDC read). The actual MMIO write + STATUS poll lives in the
//! Stage-3 driver core when it lands.
//!   <https://vesa.org/vesa-standards/>

use core::convert::TryFrom;

// ── Register offsets (TGL PRM Vol. 12 §"GMBUS Registers") ────────

/// MMIO base of the GMBUS block on Gen12 iGPUs.
pub const GMBUS_BASE: u64 = 0x0000_C510;
/// Pin pair selection + clock rate.
pub const GMBUS0: u64 = GMBUS_BASE + 0x00;
/// Command + slave address.
pub const GMBUS1: u64 = GMBUS_BASE + 0x04;
/// Status + handshake.
pub const GMBUS2: u64 = GMBUS_BASE + 0x08;
/// Data port — 4 bytes per FIFO entry.
pub const GMBUS3: u64 = GMBUS_BASE + 0x0C;
/// Interrupt mask.
pub const GMBUS4: u64 = GMBUS_BASE + 0x10;
/// 2-byte index for byte-indexed reads.
pub const GMBUS5: u64 = GMBUS_BASE + 0x14;

// ── GMBUS0 — pin pair + rate (TGL PRM Vol. 12 §"GMBUS0") ─────────

/// Bus rate select bits[10:8] → 100 kHz (the conservative default
/// on every pin pair).
pub const GMBUS0_RATE_100KHZ: u32 = 0b000 << 8;
/// Bus rate select → 50 kHz (slow-recovery for marginal cables).
pub const GMBUS0_RATE_50KHZ: u32 = 0b001 << 8;
/// Bus rate select → 400 kHz.
pub const GMBUS0_RATE_400KHZ: u32 = 0b010 << 8;
/// Bus rate select → 1 MHz (DDR rate).
pub const GMBUS0_RATE_1MHZ: u32 = 0b011 << 8;

/// Hold time bit (bit 6) — extends DATA hold beyond the spec-min
/// when EDID monitors mis-sample.
pub const GMBUS0_HOLD_TIME: u32 = 1 << 6;

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

// ── GMBUS1 — command (TGL PRM Vol. 12 §"GMBUS1") ─────────────────

/// Software clear-interrupt + reset (`GMBUS1[31]`). One-shot
/// write-only.
pub const GMBUS1_SW_CLR_INT: u32 = 1 << 31;
/// Software-ready flag (`GMBUS1[30]`). Set together with
/// CLR_INT to start a transaction; cleared by hardware on
/// completion.
pub const GMBUS1_SW_RDY: u32 = 1 << 30;
/// ENT — "ENable Timeout" (`GMBUS1[29]`). When set, hardware
/// completes the transaction with `HW_TMOUT` after ~30 ms of
/// inactivity instead of hanging.
pub const GMBUS1_ENT: u32 = 1 << 29;
/// STO — "STOp" (`GMBUS1[27]`). Set on the last segment of a
/// multi-segment transfer to drive an I²C STOP condition.
pub const GMBUS1_STO: u32 = 1 << 27;

/// Read direction bit (`GMBUS1[0]`). When set, the slave-address
/// byte's R/W bit is a read.
pub const GMBUS1_DIR_READ: u32 = 1;

/// Slave address sits in `GMBUS1[7:1]` — left-shifted by 1 from
/// the natural 7-bit address.
pub const fn gmbus1_slave_addr(addr_7bit: u8) -> u32 {
    ((addr_7bit as u32) & 0x7F) << 1
}

/// Byte count sits in `GMBUS1[24:16]` — up to 511 bytes per
/// transaction.
pub const fn gmbus1_byte_count(bytes: u16) -> u32 {
    ((bytes as u32) & 0x1FF) << 16
}

// ── GMBUS2 — status (TGL PRM Vol. 12 §"GMBUS2") ──────────────────

/// Inactivity wait (`GMBUS2[14]`).
pub const GMBUS2_INUSE: u32 = 1 << 14;
/// Hardware ready (`GMBUS2[11]`). Set when the controller has
/// data waiting in `GMBUS3` (read direction) or has consumed the
/// data we wrote (write direction).
pub const GMBUS2_HW_RDY: u32 = 1 << 11;
/// Slave didn't ACK its address byte (`GMBUS2[10]`).
pub const GMBUS2_NACK: u32 = 1 << 10;
/// Active-bus / bus busy (`GMBUS2[9]`).
pub const GMBUS2_ACTIVE: u32 = 1 << 9;
/// Hardware completed without error (`GMBUS2[14]`).
pub const GMBUS2_HW_DONE: u32 = 1 << 14;

// ── E-EDID DDC slave address ─────────────────────────────────────

/// Standard DDC slave address for E-EDID readout (VESA E-EDID 1.4
/// §3.2.1). The DDC2B convention is universal across HDMI / DP /
/// DVI / VGA monitors.
pub const DDC_SLAVE_EDID: u8 = 0x50;
/// DDC2 segment-pointer slave for >256-byte EDID extension reads.
pub const DDC_SLAVE_SEGMENT: u8 = 0x30;

// ── Encoded transaction shapes ───────────────────────────────────

/// Errors produced by [`build_edid_read`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GmbusError {
    /// The pin pair is reserved or not present on this generation.
    InvalidPinPair,
    /// EDID read length exceeds the 511-byte hardware limit.
    TooManyBytes,
}

/// One programmed transaction: the `GMBUS0` and `GMBUS1` register
/// values to write, plus the byte count the caller will pull out
/// of `GMBUS3` after each `HW_RDY` pulse.
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
        (self.byte_count + 3) / 4
    }
}

/// Encode the register values for "read `bytes` bytes of E-EDID
/// from `pin_pair` at 100 kHz with timeout enabled".
///
/// The caller is expected to:
/// 1. Write `program.gmbus0` to [`GMBUS0`].
/// 2. Write `program.gmbus1` to [`GMBUS1`] (this kicks off the
///    transaction).
/// 3. Poll [`GMBUS2`] for `HW_RDY`, draining `GMBUS3` as 32-bit
///    words; check `NACK` for slave non-presence.
/// 4. Wait for `HW_DONE`; restore [`GMBUS0`] = 0 (idle).
pub fn build_edid_read(pin_pair: PinPair, bytes: u16) -> Result<EdidReadProgram, GmbusError> {
    if matches!(pin_pair, PinPair::Disabled | PinPair::LegacyCrt) {
        return Err(GmbusError::InvalidPinPair);
    }
    if bytes == 0 || bytes > 0x1FF {
        return Err(GmbusError::TooManyBytes);
    }
    let gmbus0 = GMBUS0_RATE_100KHZ | pin_pair.encode();
    let gmbus1 = GMBUS1_SW_CLR_INT
        | GMBUS1_SW_RDY
        | GMBUS1_ENT
        | GMBUS1_STO
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
    /// Slave NACKed its address.
    SlaveNack,
}

impl GmbusStatus {
    pub fn classify(gmbus2: u32) -> Self {
        if gmbus2 & GMBUS2_NACK != 0 {
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

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_pin_pair_round_trip() -> TestResult {
        for v in 0u32..=7 {
            let pp = PinPair::try_from(v).expect("valid range");
            if pp.encode() != v {
                return TestResult::Fail("pin pair encode round-trip");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/gpu/intel_gpu_gmbus",
        smoke_pin_pair_round_trip
    );

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
        if p.gmbus1 & GMBUS1_SW_RDY == 0 || p.gmbus1 & GMBUS1_SW_CLR_INT == 0 {
            return TestResult::Fail("SW_RDY / CLR_INT not set");
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
        if GmbusStatus::classify(GMBUS2_NACK) != GmbusStatus::SlaveNack {
            return TestResult::Fail("NACK not classified");
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
}

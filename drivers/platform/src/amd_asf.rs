//! AMD ASF (Alert Standard Format) — SMBus-based out-of-band channel.
//!
//! ASF is an IPMI-like protocol layered over SMBus/I2C.  It provides
//! an out-of-band management channel for alerting a remote console
//! (BMC / IPMI-style) about events such as temperature thresholds,
//! fan failures, voltage excursions, and chassis intrusion.
//!
//! On AMD platform laptops the ASF controller sits inside the FCH
//! SMBus block and is exposed via ACPI device `AMDI001A`.  The Linux
//! driver (`i2c-amd-asf-plat.c`) adapts it as an I2C adapter using
//! the piix4 SMBus host path for master transactions and a separate
//! MMIO region for end-of-interrupt acknowledgement.
//!
//! ## Stage 0 scope
//!
//! This module provides:
//!
//! 1. The `AsfMessage` wire type (DMTF ASF 2.0 §2.2.1 alert frame).
//! 2. The `AsfController` trait — a transport abstraction so future
//!    SMBus, I2C, or loopback backends can be plugged in.
//! 3. A static slave-address table for well-known ASF endpoints.
//!
//! Full hardware integration (IRQ handler, target-mode receive, piix4
//! SMBus path) is deferred to Stage 1 when the SMBus driver grows an
//! ASF sub-driver.
//!
//! ## Register summary (from `i2c-amd-asf-plat.c`)
//!
//! All offsets relative to the piix4 SMBus base (`piix4_smba`):
//!
//! | offset | name           | description                         |
//! |--------|----------------|-------------------------------------|
//! | 0x07   | ASFINDEX       | Data/command index register         |
//! | 0x09   | ASFLISADDR     | Slave listen address                |
//! | 0x0A   | ASFSTA         | ASF status                          |
//! | 0x0D   | ASFSLVSTA      | Slave status                        |
//! | 0x11   | ASFDATARWPTR   | Data read/write pointer             |
//! | 0x12   | ASFSETDATARDPTR| Set data read pointer               |
//! | 0x13   | ASFDATABNKSEL  | Data bank select                    |
//! | 0x15   | ASFSLVEN       | Slave enable/control                |
//!
//! MMIO control bits (from the same source, relative to the MMIO
//! configuration word):
//!
//! | bit | name        | description                     |
//! |-----|-------------|---------------------------------|
//! |  0  | ASF_SLV_LISTN  | Slave listen enable           |
//! |  1  | ASF_SLV_INTR   | Slave interrupt enable        |
//! |  4  | ASF_SLV_RST    | Slave reset                   |
//! |  5  | ASF_PEC_SP     | PEC append enable             |
//! |  7  | ASF_DATA_EN    | Data capture enable           |
//! | 16  | ASF_MSTR_EN    | Master (controller) enable    |
//! | 17  | ASF_CLK_EN     | Clock enable                  |
//!
//! ## Wire format (DMTF ASF 2.0 §2.2.1)
//!
//! ```text
//! +-------+--------+--------+----------+-----+
//! | addr  | netfn  | cmd    | payload… | PEC |
//! | u8    | u8     | u8     | [u8; N]  | u8  |
//! +-------+--------+--------+----------+-----+
//! ```
//!
//! `addr` is the 7-bit I2C slave address left-shifted by 1 (R/W bit
//! = 0 for writes).  `netfn` mirrors IPMI NetFn/LUN encoding.
//!
//! Ref: DMTF DSP0136 "Alert Standard Format Specification 2.0";
//!      Linux `i2c-amd-asf-plat.c` (GPL-2.0-or-later).

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ── Wire constants ────────────────────────────────────────────────────

/// Maximum ASF block payload (from `ASF_BLOCK_MAX_BYTES` in Linux
/// `i2c-amd-asf-plat.c`; excludes address, command, and PEC).
pub const ASF_BLOCK_MAX_BYTES: usize = 72;

// ── ACPI device IDs ───────────────────────────────────────────────────

/// ACPI device ID for the AMD ASF platform device (from Linux
/// `amd_asf_acpi_ids[]`).
pub const ACPI_ID_AMD_ASF: &str = "AMDI001A";

// ── Slave address table ───────────────────────────────────────────────

/// Well-known ASF slave addresses (7-bit, as used in `ASFLISADDR`).
///
/// DMTF ASF 2.0 §7.3 defines the "Management Controller" at 0x2C and
/// reserves 0x28–0x2F for ASF management.  The AMD FCH datasheet
/// notes 0x61 as the default listen address for the on-die ASF
/// controller.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AsfSlaveAddr {
    /// DMTF-defined Management Controller address (§7.3).
    ManagementController = 0x2C,
    /// AMD FCH default ASF slave listen address.
    AmdFchDefault = 0x61,
}

// ── ASF register bit positions ────────────────────────────────────────
// (Mirrors the Linux `ASF_*` defines.)

/// Bit within ASFLISADDR/ASFSLVEN: slave listen enable.
pub const BIT_ASF_SLV_LISTN: u8 = 0;
/// Bit within ASFSLVEN: slave interrupt enable.
pub const BIT_ASF_SLV_INTR: u8 = 1;
/// Bit within ASFSLVEN: slave reset.
pub const BIT_ASF_SLV_RST: u8 = 4;
/// Bit within SMBHSTCNT: PEC append enable.
pub const BIT_ASF_PEC_SP: u8 = 5;
/// Bit within SMBHSTCNT / ASFDATABNKSEL: data capture enable.
pub const BIT_ASF_DATA_EN: u8 = 7;
/// Bit within MMIO word: master (controller) enable.
pub const BIT_ASF_MSTR_EN: u8 = 16;
/// Bit within MMIO word: clock enable.
pub const BIT_ASF_CLK_EN: u8 = 17;

// ── Message type ──────────────────────────────────────────────────────

/// An ASF alert message ready to be sent over the SMBus/ASF channel.
///
/// Field semantics follow DMTF DSP0136 §2.2.1:
/// - `addr`: 7-bit I2C target address.
/// - `netfn`: IPMI NetFn + LUN byte (e.g. `0x04` = Sensor/Event).
/// - `ipmi_cmd`: IPMI command code within the NetFn.
/// - `payload`: body bytes (max `ASF_BLOCK_MAX_BYTES`).
#[derive(Clone, Debug)]
pub struct AsfMessage {
    /// 7-bit I2C slave address of the intended recipient.
    pub addr: u8,
    /// IPMI NetFn/LUN (high 6 bits = NetFn; low 2 bits = LUN).
    pub netfn: u8,
    /// IPMI command code.
    pub ipmi_cmd: u8,
    /// Alert payload (at most `ASF_BLOCK_MAX_BYTES` bytes).
    pub payload: Vec<u8>,
}

impl AsfMessage {
    /// Construct a new ASF alert message.
    pub fn new(addr: u8, netfn: u8, ipmi_cmd: u8, payload: Vec<u8>) -> Self {
        Self {
            addr,
            netfn,
            ipmi_cmd,
            payload,
        }
    }

    /// Encode the message to a flat byte buffer in ASF wire format:
    ///
    /// ```text
    /// [ addr<<1, netfn, ipmi_cmd, payload..., length_prefix ]
    /// ```
    ///
    /// The returned buffer starts with `payload.len() as u8` (the
    /// piix4 block-write length prefix used by
    /// `amd_asf_access()` in Linux), followed by the IPMI-framed
    /// body (netfn, cmd, payload…).  PEC computation is left to
    /// the hardware.
    ///
    /// Returns `None` if the total body length exceeds
    /// `ASF_BLOCK_MAX_BYTES`.
    pub fn encode(&self) -> Option<Vec<u8>> {
        // body = [ netfn, ipmi_cmd, payload… ]
        let body_len = 2 + self.payload.len();
        if body_len > ASF_BLOCK_MAX_BYTES {
            return None;
        }
        let mut buf = Vec::with_capacity(1 + body_len);
        // Length prefix (piix4 block-write convention: first byte is count).
        buf.push(body_len as u8);
        buf.push(self.netfn);
        buf.push(self.ipmi_cmd);
        buf.extend_from_slice(&self.payload);
        Some(buf)
    }

    /// Wire address byte (7-bit addr left-shifted, write direction).
    #[inline]
    pub fn wire_addr(&self) -> u8 {
        self.addr << 1
    }
}

// ── Transport trait ───────────────────────────────────────────────────

/// Error variants for the ASF transport layer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AsfError {
    /// Payload exceeds `ASF_BLOCK_MAX_BYTES`.
    MessageTooLong,
    /// SMBus / I2C bus error during transmission.
    BusError,
    /// Controller is busy (piix4 `PIIX4_RESULT_BUSY`-equivalent).
    Busy,
    /// Operation not supported (e.g. read on ASF channel).
    Unsupported,
}

/// Transport abstraction for sending ASF alert messages.
///
/// Implementors wrap a concrete SMBus / I2C adapter.  The trait is
/// intentionally minimal for Stage 0; future additions (slave-mode
/// receive, IRQ-driven delivery) will extend it.
pub trait AsfController {
    /// Send an ASF alert message.
    ///
    /// On success, the message has been handed off to the hardware
    /// FIFO; acknowledgement is hardware-managed.
    fn send_alert(&self, msg: &AsfMessage) -> Result<(), AsfError>;
}

// ── No-op stub controller ─────────────────────────────────────────────

/// A no-op `AsfController` used during testing and on platforms where
/// the ASF hardware is absent.
#[derive(Debug)]
pub struct AsfStub;

impl AsfController for AsfStub {
    fn send_alert(&self, msg: &AsfMessage) -> Result<(), AsfError> {
        if msg.payload.len() + 2 > ASF_BLOCK_MAX_BYTES {
            return Err(AsfError::MessageTooLong);
        }
        // No hardware present — silently discard.
        Ok(())
    }
}

/// Best-effort initialisation.  Returns a stub on platforms where ASF
/// is absent; a real driver will replace this when the SMBus sub-driver
/// registers an ASF adapter.
pub fn init() {
    // Stage 0: no hardware access needed; the stub is always valid.
}

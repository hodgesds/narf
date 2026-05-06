//! Goodix GT911 capacitive-touch controller — clean-room.
//!
//! References (public-only):
//! - "GT911 Programming Guide, Version 0.1" (March 2014) —
//!   Goodix Technology. Public document distributed by panel
//!   integrators (Hantick, Waveshare, Adafruit) and mirrored on
//!   the silicon vendor's developer site.
//! - "GT911 Datasheet, Revision 0.9" — Goodix. Public document.
//!   §3.5 (I²C device addresses 0x5D and 0x14, 16-bit register
//!   addressing). §4.4 (Coordinate Reporting Layout — 5-touch
//!   data block at register 0x814E with 1-byte status + N×8-byte
//!   point records). §6 (Configuration register block 0x8047..
//!   0x8100 with the 8-bit checksum at 0x80FF and the 1-byte
//!   "config-fresh" trigger at 0x8100).
//!
//! No GPL Linux source consulted.
//!
//! ## Register map (high-level)
//!
//! ```text
//!   0x8040  Command register
//!   0x8047  Config_Version
//!   0x8048  X_Output_Max (LE 16-bit)
//!   0x804A  Y_Output_Max
//!   0x804C  Touch number (low nibble)
//!   …
//!   0x80FF  Config_Checksum (8-bit unsigned sum of 0x8047..0x80FE)
//!   0x8100  Config_Fresh (write 1 to apply)
//!   0x814E  Status byte (bit 7 buffer-status, bit 6 large-detect,
//!                          bits 3..0 = number of touch points 0..5)
//!   0x814F  First touch point (8 bytes per point: track-id, X-LE,
//!            Y-LE, size-LE, reserved)
//! ```
//!
//! Coordinates are little-endian 16-bit values. The native panel
//! resolution is whatever firmware programmed at 0x8048..0x804B; on
//! standard 7" 800×480 panels that's 0x0320 / 0x01E0.

/// Default I²C 7-bit address (when INT pin is low at reset).
pub const I2C_ADDR_PRIMARY: u8 = 0x5D;
/// Alternate I²C 7-bit address (when INT pin is high at reset).
pub const I2C_ADDR_SECONDARY: u8 = 0x14;

/// Maximum simultaneous touch points reported by GT911.
pub const MAX_TOUCH_POINTS: usize = 5;

// ── Register addresses (16-bit) ────────────────────────────────────

pub const REG_COMMAND: u16 = 0x8040;
pub const REG_CONFIG_VERSION: u16 = 0x8047;
pub const REG_X_OUTPUT_MAX: u16 = 0x8048;
pub const REG_Y_OUTPUT_MAX: u16 = 0x804A;
pub const REG_TOUCH_NUMBER: u16 = 0x804C;
pub const REG_CONFIG_CHECKSUM: u16 = 0x80FF;
pub const REG_CONFIG_FRESH: u16 = 0x8100;
pub const REG_PRODUCT_ID: u16 = 0x8140;
pub const REG_FIRMWARE_VERSION: u16 = 0x8144;
pub const REG_STATUS: u16 = 0x814E;
pub const REG_POINT_BASE: u16 = 0x814F;

// ── Command register values (§4.1) ─────────────────────────────────

pub const CMD_READ_COORD: u8 = 0x00;
pub const CMD_READ_GESTURE: u8 = 0x01;
pub const CMD_SOFT_RESET: u8 = 0x02;
pub const CMD_BASELINE_UPDATE: u8 = 0x03;
pub const CMD_CALIBRATION: u8 = 0x04;
pub const CMD_SCREEN_OFF: u8 = 0x05;

// ── Status byte bits (§4.4) ────────────────────────────────────────

/// Bit 7: 1 = data block ready, 0 = data not yet ready.
pub const STATUS_BUFFER_READY: u8 = 1 << 7;
/// Bit 6: large-area touch detected.
pub const STATUS_LARGE_DETECT: u8 = 1 << 6;
/// Bit 5: HaveKey — capacitive button activity.
pub const STATUS_HAVE_KEY: u8 = 1 << 5;
/// Low 4 bits: number of currently-tracked touch points.
pub const STATUS_TOUCH_COUNT_MASK: u8 = 0x0F;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GoodixError {
    Short,
    /// Status byte indicated more touch points than the buffer carries.
    BadCount,
    /// Config-block checksum byte (0x80FF) didn't bring the sum to zero.
    BadConfigChecksum,
}

// ── Coordinate Report ──────────────────────────────────────────────

/// One touch point (8 bytes per §4.4).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TouchPoint {
    pub track_id: u8,
    pub x: u16,
    pub y: u16,
    pub size: u16,
}

impl TouchPoint {
    pub const REPORT_SIZE: usize = 8;

    pub fn parse(buf: &[u8]) -> Self {
        Self {
            track_id: buf[0],
            x: u16::from_le_bytes([buf[1], buf[2]]),
            y: u16::from_le_bytes([buf[3], buf[4]]),
            size: u16::from_le_bytes([buf[5], buf[6]]),
        }
    }
}

/// Decoded multi-touch report.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoordReport {
    pub buffer_ready: bool,
    pub large_detect: bool,
    pub have_key: bool,
    pub points: alloc::vec::Vec<TouchPoint>,
}

impl CoordReport {
    /// Parse the bytes the host read from `REG_STATUS`. The buffer
    /// layout is: status_byte | N × TouchPoint::REPORT_SIZE bytes
    /// where N is the touch count.
    pub fn parse(buf: &[u8]) -> Result<Self, GoodixError> {
        if buf.is_empty() {
            return Err(GoodixError::Short);
        }
        let status = buf[0];
        let count = (status & STATUS_TOUCH_COUNT_MASK) as usize;
        if count > MAX_TOUCH_POINTS {
            return Err(GoodixError::BadCount);
        }
        let need = 1 + count * TouchPoint::REPORT_SIZE;
        if buf.len() < need {
            return Err(GoodixError::Short);
        }
        let mut points = alloc::vec::Vec::with_capacity(count);
        for i in 0..count {
            let off = 1 + i * TouchPoint::REPORT_SIZE;
            points.push(TouchPoint::parse(&buf[off..off + TouchPoint::REPORT_SIZE]));
        }
        Ok(Self {
            buffer_ready: (status & STATUS_BUFFER_READY) != 0,
            large_detect: (status & STATUS_LARGE_DETECT) != 0,
            have_key: (status & STATUS_HAVE_KEY) != 0,
            points,
        })
    }
}

// ── Configuration block ────────────────────────────────────────────

/// Compute the GT911 config-block checksum byte (the 1-byte
/// signed-add carry that must be set so the sum of bytes 0x8047..0x80FF
/// is zero modulo 256).
pub fn config_checksum_byte(config_block_no_checksum: &[u8]) -> u8 {
    let sum = config_block_no_checksum
        .iter()
        .fold(0u32, |acc, b| acc.wrapping_add(*b as u32));
    ((256 - (sum & 0xFF)) & 0xFF) as u8
}

/// Verify a complete config block (typically 0xB9 = 185 bytes for
/// GT911 configs at firmware revision 0xB1+). The block must be
/// exactly the same byte count as the host's view of registers
/// 0x8047..0x80FF — the trailing byte is the stored checksum.
pub fn verify_config(block: &[u8]) -> Result<(), GoodixError> {
    if block.len() < 2 {
        return Err(GoodixError::Short);
    }
    let want = block[block.len() - 1];
    let got = config_checksum_byte(&block[..block.len() - 1]);
    if want != got {
        return Err(GoodixError::BadConfigChecksum);
    }
    Ok(())
}

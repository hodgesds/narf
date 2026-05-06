//! DisplayPort AUX channel + DPCD register set (clean-room).
//!
//! References (public-only):
//! - "VESA DisplayPort Standard, Version 1.4a" — VESA. Public
//!   document. §2.9 (AUX channel transactions, command-byte
//!   layout), §2.9.7 (Native AUX read/write framing), §2.9.7.1.5
//!   (I²C-over-AUX), §3.2 (Link Training state machine), §3.6
//!   (DPCD register map: receiver capability field at 0x00000..,
//!   link configuration field at 0x00100..).
//! - "VESA DisplayPort Standard, Version 2.0" — surface for
//!   UHBR rates (10/13.5/20 Gbps). Linked here for forward
//!   compatibility constants only.
//!
//! No GPL Linux source consulted.
//!
//! ## AUX request framing (§2.9.7)
//!
//! The AUX channel carries 1 Mb/s Manchester-encoded transactions.
//! Above the line layer each transaction is an array of bytes the
//! source clocks out; the sink replies with its own array. We model
//! the bytestream (the line-encoder is a separate IP block):
//!
//! ```text
//!   Request:
//!     byte 0: bits[7..4] = command
//!                          0x8 Native AUX Write, 0x9 Native AUX Read,
//!                          0x0 I2C Write,        0x1 I2C Read,
//!                          0x4 I2C Write w/ MOT, 0x5 I2C Read w/ MOT
//!             bits[3..0] = address[19..16]
//!     byte 1: address[15..8]
//!     byte 2: address[7..0]
//!     byte 3: length - 1  (0..15 → 1..16 byte payload)
//!     byte 4..(4 + length): write payload (Native Write / I2C Write)
//!
//!   Reply:
//!     byte 0: bits[7..4] = reply code
//!                          0x0 AUX_ACK,    0x1 AUX_NACK,    0x2 AUX_DEFER
//!                          0x4 I2C_NACK,   0x8 I2C_DEFER
//!             bits[3..0] = 0 (RFU on natives, real for I2C reads)
//!     byte 1..: read payload (only on AUX_ACK + read transactions)
//! ```

use alloc::vec::Vec;

// ── AUX request commands (§2.9.7) ──────────────────────────────────

pub const AUX_CMD_I2C_WRITE: u8 = 0x0;
pub const AUX_CMD_I2C_READ: u8 = 0x1;
pub const AUX_CMD_I2C_WRITE_MOT: u8 = 0x4;
pub const AUX_CMD_I2C_READ_MOT: u8 = 0x5;
pub const AUX_CMD_NATIVE_WRITE: u8 = 0x8;
pub const AUX_CMD_NATIVE_READ: u8 = 0x9;

// ── Reply codes (§2.9.7) ───────────────────────────────────────────

pub const AUX_REPLY_ACK: u8 = 0x0;
pub const AUX_REPLY_NACK: u8 = 0x1;
pub const AUX_REPLY_DEFER: u8 = 0x2;
pub const AUX_REPLY_I2C_NACK: u8 = 0x4;
pub const AUX_REPLY_I2C_DEFER: u8 = 0x8;

/// Maximum Native-AUX payload per transaction (length field is 4 bits +1).
pub const AUX_MAX_PAYLOAD: usize = 16;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AuxError {
    Short,
    /// Length field exceeds 16 bytes.
    BadLength,
    /// Address upper bits (24..20) must be zero — DPCD addresses are 20 bits.
    BadAddress,
}

/// Build a Native AUX Write request bytestream.
pub fn build_native_write(address: u32, payload: &[u8]) -> Result<Vec<u8>, AuxError> {
    if payload.is_empty() || payload.len() > AUX_MAX_PAYLOAD {
        return Err(AuxError::BadLength);
    }
    if (address >> 20) != 0 {
        return Err(AuxError::BadAddress);
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.push((AUX_CMD_NATIVE_WRITE << 4) | (((address >> 16) & 0x0F) as u8));
    out.push((address >> 8) as u8);
    out.push(address as u8);
    out.push((payload.len() - 1) as u8);
    out.extend_from_slice(payload);
    Ok(out)
}

/// Build a Native AUX Read request bytestream.
pub fn build_native_read(address: u32, length: usize) -> Result<Vec<u8>, AuxError> {
    if length == 0 || length > AUX_MAX_PAYLOAD {
        return Err(AuxError::BadLength);
    }
    if (address >> 20) != 0 {
        return Err(AuxError::BadAddress);
    }
    Ok(alloc::vec![
        (AUX_CMD_NATIVE_READ << 4) | (((address >> 16) & 0x0F) as u8),
        (address >> 8) as u8,
        address as u8,
        (length - 1) as u8,
    ])
}

/// Build an I²C-over-AUX Read with Middle-Of-Transaction flag.
/// Used during EDID readback over DisplayPort: the source issues
/// one MOT-Write to set the byte offset, then a sequence of MOT-
/// Read transactions to drain 128 bytes of EDID.
pub fn build_i2c_read_mot(slave_addr: u8, length: usize) -> Result<Vec<u8>, AuxError> {
    if length == 0 || length > AUX_MAX_PAYLOAD {
        return Err(AuxError::BadLength);
    }
    Ok(alloc::vec![
        AUX_CMD_I2C_READ_MOT << 4,
        0,
        slave_addr,
        (length - 1) as u8,
    ])
}

/// Decode the leading byte of an AUX reply → (reply_code, lower-nibble).
/// On AUX_ACK + read, the read payload follows the reply byte.
pub fn parse_reply_byte(b: u8) -> (u8, u8) {
    ((b >> 4) & 0x0F, b & 0x0F)
}

// ── DPCD register map (DP 1.4a §2.9.3 + §3.6) ─────────────────────

/// **Receiver Capability** field (DPCD 0x00000..0x000FF).
pub mod dpcd {
    /// DPCD revision byte (0x12 = DP 1.2, 0x14 = DP 1.4a).
    pub const REV: u32 = 0x00000;
    /// Maximum Link Bandwidth.
    pub const MAX_LINK_RATE: u32 = 0x00001;
    /// Maximum Lane Count + ENHANCED_FRAME_CAP + TPS3_SUPPORTED bits.
    pub const MAX_LANE_COUNT: u32 = 0x00002;
    /// Max-Downspread support.
    pub const MAX_DOWNSPREAD: u32 = 0x00003;
    /// Number of receive ports (0=eDP/MST root, 1=branch).
    pub const NORP: u32 = 0x00004;
    pub const DOWNSTREAM_PORT_PRESENT: u32 = 0x00005;
    pub const MAIN_LINK_CHANNEL_CODING: u32 = 0x00006;
    pub const DOWN_STREAM_PORT_COUNT: u32 = 0x00007;

    /// Link configuration field (writable by the source).
    pub const LINK_BW_SET: u32 = 0x00100;
    pub const LANE_COUNT_SET: u32 = 0x00101;
    pub const TRAINING_PATTERN_SET: u32 = 0x00102;
    pub const TRAINING_LANE0_SET: u32 = 0x00103;
    pub const TRAINING_LANE1_SET: u32 = 0x00104;
    pub const TRAINING_LANE2_SET: u32 = 0x00105;
    pub const TRAINING_LANE3_SET: u32 = 0x00106;

    /// Sink Status field (read-only).
    pub const SINK_COUNT: u32 = 0x00200;
    pub const DEVICE_SERVICE_IRQ_VECTOR: u32 = 0x00201;
    pub const LANE0_1_STATUS: u32 = 0x00202;
    pub const LANE2_3_STATUS: u32 = 0x00203;
    pub const LANE_ALIGN_STATUS_UPDATED: u32 = 0x00204;
    pub const SINK_STATUS: u32 = 0x00205;

    /// Power state (sink power management).
    pub const SET_POWER: u32 = 0x00600;

    // SET_POWER values (§5.1.5).
    pub const SET_POWER_D0: u8 = 0x01; // normal operation
    pub const SET_POWER_D3: u8 = 0x02; // power-down
    pub const SET_POWER_D3_AUX_ON: u8 = 0x05; // DP 1.2+ — only AUX powered
}

/// MAX_LINK_RATE / LINK_BW_SET encoded values (DPCD 0x00001 / 0x00100).
/// Each is the raw `bw / 0.27 GHz` so the byte values divide cleanly
/// through the link-rate ladder.
pub mod link_rate {
    /// 1.62 Gbps per lane (Reduced Bit Rate, RBR).
    pub const RBR: u8 = 0x06;
    /// 2.7 Gbps per lane (HBR).
    pub const HBR: u8 = 0x0A;
    /// 5.4 Gbps per lane (HBR2).
    pub const HBR2: u8 = 0x14;
    /// 8.1 Gbps per lane (HBR3).
    pub const HBR3: u8 = 0x1E;
}

/// LANE_COUNT_SET fields (DPCD 0x00101).
pub mod lane_count {
    /// Mask for the lane-count field (bits 4..0). Real values 1, 2, 4.
    pub const COUNT_MASK: u8 = 0x1F;
    /// Bit 5 — Post-Link-Training Interlane Align Done.
    pub const POST_LT_ADJ_REQ_GRANTED: u8 = 1 << 5;
    /// Bit 7 — Enhanced framing.
    pub const ENHANCED_FRAME_EN: u8 = 1 << 7;
}

/// TRAINING_PATTERN_SET values (DPCD 0x00102).
pub mod tps {
    pub const NONE: u8 = 0x00;
    pub const PATTERN_1: u8 = 0x01;
    pub const PATTERN_2: u8 = 0x02;
    pub const PATTERN_3: u8 = 0x03;
    /// DP 1.3+ — used for HBR3.
    pub const PATTERN_4: u8 = 0x07;
    /// Bit 5 — disable scrambler during training.
    pub const SCRAMBLING_DISABLE: u8 = 1 << 5;
}

/// LANE0_1_STATUS / LANE2_3_STATUS bit masks (DPCD 0x00202..0x00203).
/// Each lane is 4 bits — high 4 bits = lane 1/3, low 4 = lane 0/2.
pub mod lane_status {
    pub const CR_DONE: u8 = 1 << 0;
    pub const CHANNEL_EQ_DONE: u8 = 1 << 1;
    pub const SYMBOL_LOCKED: u8 = 1 << 2;
    /// Helper: 0x77 = CR_DONE | CHANNEL_EQ_DONE | SYMBOL_LOCKED
    /// across both lanes in the byte.
    pub const ALL_LANES_TRAINED: u8 = 0x77;
}

/// LANE_ALIGN_STATUS_UPDATED bits (DPCD 0x00204).
pub mod align {
    pub const INTERLANE_ALIGN_DONE: u8 = 1 << 0;
    pub const DOWNSTREAM_PORT_STATUS_CHANGED: u8 = 1 << 6;
    pub const LINK_STATUS_UPDATED: u8 = 1 << 7;
}

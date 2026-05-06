//! ATOM encoder capability table walker — clean-room.
//!
//! Reference: AMD `AtomBios.h` (MIT-licensed structure shape).
//! The encoder-caps record (`ATOM_ENCODER_CAP_RECORD`) describes
//! what each encoder block supports — max DP link rate, max
//! HBR2/HBR3 lanes, eDP backlight control, output color bit
//! depth ceilings.
//!
//! Encoder records aren't a top-level data table; they live as
//! TLV-style records appended to display-object path entries
//! (see `amdgpu_atom_displayobj`'s object chain). Each record
//! starts with a 1-byte type discriminator + 1-byte length:
//!
//! ```text
//! +0x00   ucRecordType                    u8
//! +0x01   ucRecordSize                    u8
//! +0x02   payload                         (size - 2 bytes)
//! ```
//!
//! Record types (ATOM_OBJECT_RECORD_TYPE_*) we care about:
//!   - 0x06 = `ATOM_ENCODER_CAP_RECORD` (the one this walker decodes)
//!   - 0x09 = `ATOM_DP_CONN_CHANNEL_MAPPING_RECORD`
//!   - others (HPD ID, I2C ID, …) are documented but not yet
//!     consumed.
//!
//! ## Stage-9 scope
//!
//! Decode `ATOM_ENCODER_CAP_RECORD` payload + a generic
//! TLV-iter so callers can walk every record on a path's tail
//! without each one re-implementing the byte-walking.

use core::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum EncoderCapError {
    Truncated,
    UnknownRecordType(u8),
    /// `ucRecordSize` < 2 — record header itself is 2 bytes.
    BadRecordSize,
}

/// Discriminator for a record TLV.
pub const ATOM_RECORD_TYPE_HPD_INT_ID: u8 = 0x01;
pub const ATOM_RECORD_TYPE_I2C_ID: u8 = 0x02;
pub const ATOM_RECORD_TYPE_CONNECTOR_DEVICE: u8 = 0x05;
pub const ATOM_RECORD_TYPE_ENCODER_CAP: u8 = 0x06;
pub const ATOM_RECORD_TYPE_DP_CONN_CHANNEL_MAP: u8 = 0x09;
pub const ATOM_RECORD_TYPE_END: u8 = 0xFF;

/// Decoded `ATOM_ENCODER_CAP_RECORD` payload. `usEncoderCap` is
/// a 16-bit bitmap; we surface decoded booleans for the fields
/// modeset paths need.
#[derive(Copy, Clone, Debug)]
pub struct EncoderCaps {
    pub raw_caps: u16,
}

impl EncoderCaps {
    pub fn supports_hbr2(self) -> bool {
        self.raw_caps & (1 << 0) != 0
    }
    pub fn supports_hbr3(self) -> bool {
        self.raw_caps & (1 << 1) != 0
    }
    pub fn supports_dp_8b10b_loopback(self) -> bool {
        self.raw_caps & (1 << 2) != 0
    }
    /// 1 → encoder can drive 10-bit per channel HDR.
    pub fn supports_10bpc(self) -> bool {
        self.raw_caps & (1 << 3) != 0
    }
    /// 1 → encoder supports YCbCr 4:2:0 sub-sampling.
    pub fn supports_ycbcr420(self) -> bool {
        self.raw_caps & (1 << 4) != 0
    }
}

/// One TLV record from a path's record tail.
#[derive(Copy, Clone)]
pub struct Record<'a> {
    pub kind: u8,
    pub payload: &'a [u8],
}

impl<'a> fmt::Debug for Record<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Record")
            .field("kind", &self.kind)
            .field("len", &self.payload.len())
            .finish()
    }
}

/// Iterator over records appended past a path's object chain.
/// Each call to `next` returns the next TLV until the
/// `ATOM_RECORD_TYPE_END` (0xFF) sentinel.
#[derive(Debug)]
pub struct RecordIter<'a> {
    raw: &'a [u8],
    cursor: usize,
}

impl<'a> RecordIter<'a> {
    /// Wrap a slice that starts at the first TLV record.
    pub fn new(raw: &'a [u8]) -> Self {
        Self { raw, cursor: 0 }
    }
}

impl<'a> Iterator for RecordIter<'a> {
    type Item = Record<'a>;
    fn next(&mut self) -> Option<Record<'a>> {
        if self.cursor + 2 > self.raw.len() {
            return None;
        }
        let kind = self.raw[self.cursor];
        let size = self.raw[self.cursor + 1] as usize;
        if kind == ATOM_RECORD_TYPE_END {
            return None;
        }
        if size < 2 {
            return None;
        }
        if self.cursor + size > self.raw.len() {
            return None;
        }
        let payload = &self.raw[self.cursor + 2..self.cursor + size];
        self.cursor += size;
        Some(Record { kind, payload })
    }
}

/// Decode an `ATOM_ENCODER_CAP_RECORD` payload (the bytes after
/// the TLV header). The record carries `usEncoderCap` (u16) at
/// offset 0; some revisions add a u8 caps_extension at offset 2.
pub fn decode_encoder_caps(payload: &[u8]) -> Result<EncoderCaps, EncoderCapError> {
    if payload.len() < 2 {
        return Err(EncoderCapError::Truncated);
    }
    let raw_caps = u16::from_le_bytes([payload[0], payload[1]]);
    Ok(EncoderCaps { raw_caps })
}

/// Find + decode the first `ATOM_ENCODER_CAP_RECORD` in `tail`.
/// Returns `Ok(None)` when the path has no encoder-cap record.
pub fn find_encoder_caps(tail: &[u8]) -> Result<Option<EncoderCaps>, EncoderCapError> {
    for r in RecordIter::new(tail) {
        if r.kind == ATOM_RECORD_TYPE_ENCODER_CAP {
            return Ok(Some(decode_encoder_caps(r.payload)?));
        }
    }
    Ok(None)
}

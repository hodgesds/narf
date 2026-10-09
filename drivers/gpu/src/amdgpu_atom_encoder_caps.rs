//! ATOM encoder capability table walker — clean-room.
//!
//! Reference: `atomfirmware.h` — `enum atom_object_record_type_id`,
//! `struct atom_common_record_header`, `struct atom_encoder_caps_record`,
//! `enum atom_encoder_caps_def`.
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
//! Record types are `enum atom_object_record_type_id`; see
//! [`ATOM_ENCODER_CAP_RECORD_TYPE`] and its neighbours. The one this walker
//! decodes is 20.
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
    /// `record_size` < 2 — the record header itself is 2 bytes.
    BadRecordSize,
}

/// `enum atom_object_record_type_id` (`atomfirmware.h`).
///
/// LINUX-GAP: the set that stood here was `HPD_INT_ID = 0x01`, `I2C_ID = 0x02`,
/// `CONNECTOR_DEVICE = 0x05`, `ENCODER_CAP = 0x06`,
/// `DP_CONN_CHANNEL_MAP = 0x09`, cited as `ATOM_OBJECT_RECORD_TYPE_*` from
/// `AtomBios.h`. Against the real enum:
///
///   * I²C and HPD were **swapped** — I²C is 1 and HPD-int is 2.
///   * `ENCODER_CAP` is **20**, not 6. 6 is not a record type at all, so a
///     walk looking for encoder caps never matched and
///     [`find_encoder_caps`] always returned `None`.
///   * There is no `CONNECTOR_DEVICE` record; 3 is `CONNECTOR_CAP` and 4 is
///     `CONNECTOR_SPEED_UPTO`.
///   * There is no DP-channel-map record; 9 is `OBJECT_GPIO_CNTL`.
///
/// `amdgpu_dcn_inventory` carries `RECORD_HPD_INT = 2` and audited clean, so
/// this was the second of two copies and the wrong one.
pub const ATOM_I2C_RECORD_TYPE: u8 = 1;
pub const ATOM_HPD_INT_RECORD_TYPE: u8 = 2;
pub const ATOM_CONNECTOR_CAP_RECORD_TYPE: u8 = 3;
pub const ATOM_CONNECTOR_SPEED_UPTO: u8 = 4;
pub const ATOM_OBJECT_GPIO_CNTL_RECORD_TYPE: u8 = 9;
pub const ATOM_CONNECTOR_HPDPIN_LUT_RECORD_TYPE: u8 = 16;
pub const ATOM_CONNECTOR_AUXDDC_LUT_RECORD_TYPE: u8 = 17;
pub const ATOM_ENCODER_CAP_RECORD_TYPE: u8 = 20;
pub const ATOM_BRACKET_LAYOUT_RECORD_TYPE: u8 = 21;
pub const ATOM_CONNECTOR_FORCED_TMDS_CAP_RECORD_TYPE: u8 = 22;
pub const ATOM_DISP_CONNECTOR_CAPS_RECORD_TYPE: u8 = 23;
pub const ATOM_BRACKET_LAYOUT_V2_RECORD_TYPE: u8 = 25;
pub const ATOM_RECORD_END_TYPE: u8 = 0xFF;

/// `enum atom_encoder_caps_def`. The field is `encodercaps`, a **u32**.
///
/// LINUX-GAP: the previous decode read a `u16` and gave bits 0..4 the meanings
/// `hbr2`, `hbr3`, `dp_8b10b_loopback`, `10bpc`, `ycbcr420`. Only bit 0 is
/// close, and even that is the retired pre-SI reading — from SI onward bit 0
/// is `MST_EN`. HBR3 is bit **3**, and `dp_8b10b_loopback`, `10bpc` and
/// `ycbcr420` are not encoder-cap bits at all. Reading sixteen bits also
/// truncates `USB_C_TYPE`, which is bit 8 and the bit that says a DP connector
/// is a USB-C port — the one Phoenix's DPIA path cares about most.
pub const ATOM_ENCODER_CAP_RECORD_MST_EN: u32 = 0x001;
pub const ATOM_ENCODER_CAP_RECORD_HBR2_EN: u32 = 0x002;
pub const ATOM_ENCODER_CAP_RECORD_HDMI6GBPS_EN: u32 = 0x004;
pub const ATOM_ENCODER_CAP_RECORD_HBR3_EN: u32 = 0x008;
pub const ATOM_ENCODER_CAP_RECORD_DP2: u32 = 0x010;
pub const ATOM_ENCODER_CAP_RECORD_UHBR10_EN: u32 = 0x020;
pub const ATOM_ENCODER_CAP_RECORD_UHBR13_5_EN: u32 = 0x040;
pub const ATOM_ENCODER_CAP_RECORD_UHBR20_EN: u32 = 0x080;
pub const ATOM_ENCODER_CAP_RECORD_USB_C_TYPE: u32 = 0x100;

/// Decoded `struct atom_encoder_caps_record` payload: a single `u32`
/// `encodercaps` field after the two-byte record header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EncoderCaps {
    pub raw_caps: u32,
}

impl EncoderCaps {
    /// Bit 0. Named `HBR2` before SI and `MST_EN` from SI onward; on anything
    /// this driver targets it is the MST enable.
    pub fn mst_enabled(self) -> bool {
        self.raw_caps & ATOM_ENCODER_CAP_RECORD_MST_EN != 0
    }
    pub fn supports_hbr2(self) -> bool {
        self.raw_caps & ATOM_ENCODER_CAP_RECORD_HBR2_EN != 0
    }
    pub fn supports_hdmi_6gbps(self) -> bool {
        self.raw_caps & ATOM_ENCODER_CAP_RECORD_HDMI6GBPS_EN != 0
    }
    pub fn supports_hbr3(self) -> bool {
        self.raw_caps & ATOM_ENCODER_CAP_RECORD_HBR3_EN != 0
    }
    pub fn supports_dp2(self) -> bool {
        self.raw_caps & ATOM_ENCODER_CAP_RECORD_DP2 != 0
    }
    pub fn supports_uhbr10(self) -> bool {
        self.raw_caps & ATOM_ENCODER_CAP_RECORD_UHBR10_EN != 0
    }
    pub fn supports_uhbr13_5(self) -> bool {
        self.raw_caps & ATOM_ENCODER_CAP_RECORD_UHBR13_5_EN != 0
    }
    pub fn supports_uhbr20(self) -> bool {
        self.raw_caps & ATOM_ENCODER_CAP_RECORD_UHBR20_EN != 0
    }
    /// Bit 8: this DP connector is a USB-C port, so its output is a DPIA
    /// tunnel rather than a native DP PHY.
    pub fn is_usb_c(self) -> bool {
        self.raw_caps & ATOM_ENCODER_CAP_RECORD_USB_C_TYPE != 0
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
        if kind == ATOM_RECORD_END_TYPE {
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

/// Decode a `struct atom_encoder_caps_record` payload (the bytes after the
/// two-byte TLV header): one `u32` `encodercaps`.
pub fn decode_encoder_caps(payload: &[u8]) -> Result<EncoderCaps, EncoderCapError> {
    if payload.len() < 4 {
        return Err(EncoderCapError::Truncated);
    }
    let raw_caps = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    Ok(EncoderCaps { raw_caps })
}

/// Find + decode the first `ATOM_ENCODER_CAP_RECORD` in `tail`.
/// Returns `Ok(None)` when the path has no encoder-cap record.
pub fn find_encoder_caps(tail: &[u8]) -> Result<Option<EncoderCaps>, EncoderCapError> {
    for r in RecordIter::new(tail) {
        if r.kind == ATOM_ENCODER_CAP_RECORD_TYPE {
            return Ok(Some(decode_encoder_caps(r.payload)?));
        }
    }
    Ok(None)
}

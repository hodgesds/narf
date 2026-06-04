//! SDPCM and BCDC framing for the CYW43439.
//!
//! Once firmware is running, the host talks to the chip in two
//! layered framings over the F2 (WLAN) bulk-data path:
//!
//! - **SDPCM** ("Software Datapath Communication Protocol Manager")
//!   — every F2 frame begins with a 4-byte hardware header (length
//!   plus inverted-length checksum) followed by an 8-byte software
//!   header (sequence / channel / flow-control / data offset).
//! - **BCDC** ("Broadcom Common Data Channel") — control-channel
//!   frames (channel 0) carry a 16-byte BCDC header that wraps the
//!   IOCTL / IOVAR request and response.
//!
//! The SDPCM layout is described in the **CYW43439 datasheet
//! Rev. 03 §6.6** and in Infineon's **AN232689 Wi-Fi Software User
//! Guide**. The BCDC layout is the long-standing Broadcom IOCTL
//! framing also documented in AN232689. Cross-checked against
//! `soypat/cyw43439` (MIT) and Embassy `cyw43` (Apache-2.0 / MIT).
//! **No GPL `brcmfmac` / `bcmdhd` source consulted.**

use core::convert::TryInto;

// ── Channel numbering (datasheet §6.6) ────────────────────────────

/// Control-plane channel (IOCTL / IOVAR via BCDC).
pub const CHANNEL_CONTROL: u8 = 0;
/// Asynchronous events from chip → host.
pub const CHANNEL_EVENT: u8 = 1;
/// Data path — Ethernet frames.
pub const CHANNEL_DATA: u8 = 2;
/// Aggregated multi-frame "GLOM" channel.
pub const CHANNEL_GLOM: u8 = 3;

/// Total length of the SDPCM hardware header (datasheet §6.6).
pub const HW_HEADER_LEN: usize = 4;
/// Total length of the SDPCM software header (datasheet §6.6).
pub const SW_HEADER_LEN: usize = 8;
/// Total length of the BCDC IOCTL header (AN232689).
pub const BCDC_HEADER_LEN: usize = 16;

/// SDPCM hardware header — first four bytes of every F2 frame.
///
/// Layout (little-endian):
///
/// ```text
///   bytes 0-1: total frame length (incl. headers, padding)
///   bytes 2-3: bitwise NOT of bytes 0-1 (integrity check)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HwHeader {
    pub length: u16,
}

impl HwHeader {
    pub fn encode(self) -> [u8; HW_HEADER_LEN] {
        let inv = !self.length;
        [
            (self.length & 0xFF) as u8,
            (self.length >> 8) as u8,
            (inv & 0xFF) as u8,
            (inv >> 8) as u8,
        ]
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FramingError> {
        if bytes.len() < HW_HEADER_LEN {
            return Err(FramingError::ShortHeader);
        }
        let length = u16::from_le_bytes(bytes[0..2].try_into().unwrap());
        let inv = u16::from_le_bytes(bytes[2..4].try_into().unwrap());
        if !length != inv {
            return Err(FramingError::HwChecksum);
        }
        Ok(Self { length })
    }
}

/// SDPCM software header — bytes 4-11 of every F2 frame
/// (datasheet §6.6).
///
/// ```text
///   byte 0: sequence number (host increments per TX frame)
///   byte 1: channel + flags (low nibble channel, high nibble flags)
///   byte 2: next-frame length / 16 (rx hint, 0 if unused)
///   byte 3: data offset (bytes from start of HW header to payload)
///   byte 4: flow-control bits (rx)
///   byte 5: max sequence number host may use (rx)
///   byte 6-7: reserved (must be zero on TX)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwHeader {
    pub seq: u8,
    pub channel: u8,
    pub flags: u8,
    pub next_len_16: u8,
    pub data_offset: u8,
    pub fc_mask: u8,
    pub max_seq: u8,
}

/// Maximum value of a 4-bit channel field.
const CHANNEL_MASK: u8 = 0x0F;

impl SwHeader {
    pub fn encode(self) -> [u8; SW_HEADER_LEN] {
        let chan_byte = (self.channel & CHANNEL_MASK) | ((self.flags & 0x0F) << 4);
        [
            self.seq,
            chan_byte,
            self.next_len_16,
            self.data_offset,
            self.fc_mask,
            self.max_seq,
            0,
            0,
        ]
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FramingError> {
        if bytes.len() < SW_HEADER_LEN {
            return Err(FramingError::ShortHeader);
        }
        let chan_byte = bytes[1];
        Ok(Self {
            seq: bytes[0],
            channel: chan_byte & CHANNEL_MASK,
            flags: chan_byte >> 4,
            next_len_16: bytes[2],
            data_offset: bytes[3],
            fc_mask: bytes[4],
            max_seq: bytes[5],
        })
    }
}

/// BCDC IOCTL header (AN232689 + Broadcom CDC framing).
///
/// ```text
///   u32 cmd     — IOCTL command ID (e.g. WLC_GET_VAR / WLC_SET_VAR)
///   u32 len     — payload length (low 16) + flags2 (high 16)
///   u32 flags   — direction / IF / xact
///   u32 status  — set on response, zero on request
/// ```
///
/// All fields are little-endian on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BcdcHeader {
    pub cmd: u32,
    pub len: u32,
    pub flags: u32,
    pub status: u32,
}

// BCDC `flags` bit positions (cross-checked against soypat/Embassy
// permissive references; these positions are the long-standing
// Broadcom CDC convention).
pub mod bcdc_flag {
    /// Request is an error response (set by chip).
    pub const ERROR: u32 = 1 << 0;
    /// Request is a SET (write) — clear means GET (read).
    pub const SET: u32 = 1 << 1;
    /// Interface index field shift — bits 12-15.
    pub const IF_SHIFT: u32 = 12;
    pub const IF_MASK: u32 = 0xF << IF_SHIFT;
    /// Transaction ID field shift — bits 16-31. The host increments
    /// this per request and the chip echoes the value back in the
    /// response so the host can correlate out-of-order completions.
    pub const ID_SHIFT: u32 = 16;
    pub const ID_MASK: u32 = 0xFFFF << ID_SHIFT;
}

impl BcdcHeader {
    pub fn encode(self) -> [u8; BCDC_HEADER_LEN] {
        let mut buf = [0u8; BCDC_HEADER_LEN];
        buf[0..4].copy_from_slice(&self.cmd.to_le_bytes());
        buf[4..8].copy_from_slice(&self.len.to_le_bytes());
        buf[8..12].copy_from_slice(&self.flags.to_le_bytes());
        buf[12..16].copy_from_slice(&self.status.to_le_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FramingError> {
        if bytes.len() < BCDC_HEADER_LEN {
            return Err(FramingError::ShortHeader);
        }
        Ok(Self {
            cmd: u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            len: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            flags: u32::from_le_bytes(bytes[8..12].try_into().unwrap()),
            status: u32::from_le_bytes(bytes[12..16].try_into().unwrap()),
        })
    }

    /// Convenience: 16-bit transaction id (host increments per
    /// request, chip echoes in the response).
    pub fn xact_id(self) -> u16 {
        ((self.flags & bcdc_flag::ID_MASK) >> bcdc_flag::ID_SHIFT) as u16
    }

    /// Convenience: interface index.
    pub fn if_idx(self) -> u8 {
        ((self.flags & bcdc_flag::IF_MASK) >> bcdc_flag::IF_SHIFT) as u8
    }

    /// Convenience: this header is a SET (write) request/response.
    pub fn is_set(self) -> bool {
        self.flags & bcdc_flag::SET != 0
    }
}

/// Errors returned by [`HwHeader::decode`] / [`SwHeader::decode`] /
/// [`BcdcHeader::decode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramingError {
    /// Source slice is shorter than the relevant header length.
    ShortHeader,
    /// `HwHeader` length and inverted-length fields disagree.
    HwChecksum,
}

#[cfg(any(test, feature = "kernel-test"))]
pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_hw_header_round_trip() -> TestResult {
        let hdr = HwHeader { length: 0x1234 };
        let bytes = hdr.encode();
        if bytes != [0x34, 0x12, 0xCB, 0xED] {
            return TestResult::Fail("HW header byte layout wrong");
        }
        match HwHeader::decode(&bytes) {
            Ok(d) if d == hdr => {}
            _ => return TestResult::Fail("HW header decode failed"),
        }
        // Corrupted checksum must reject.
        let mut bad = bytes;
        bad[2] ^= 0xFF;
        if !matches!(HwHeader::decode(&bad), Err(FramingError::HwChecksum)) {
            return TestResult::Fail("HW header should reject checksum mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdpcm",
        smoke_hw_header_round_trip
    );

    fn smoke_sw_header_round_trip() -> TestResult {
        let hdr = SwHeader {
            seq: 7,
            channel: CHANNEL_CONTROL,
            flags: 0,
            next_len_16: 0,
            data_offset: 12,
            fc_mask: 0,
            max_seq: 16,
        };
        let bytes = hdr.encode();
        match SwHeader::decode(&bytes) {
            Ok(d) if d == hdr => {}
            _ => return TestResult::Fail("SW header decode mismatch"),
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdpcm",
        smoke_sw_header_round_trip
    );

    fn smoke_bcdc_round_trip() -> TestResult {
        let hdr = BcdcHeader {
            cmd: 263, // WLC_SET_VAR
            len: 32,
            flags: bcdc_flag::SET | (5u32 << bcdc_flag::ID_SHIFT),
            status: 0,
        };
        let bytes = hdr.encode();
        match BcdcHeader::decode(&bytes) {
            Ok(d) => {
                if d != hdr {
                    return TestResult::Fail("BCDC round-trip mismatch");
                }
                if d.xact_id() != 5 {
                    return TestResult::Fail("xact_id misdecoded");
                }
                if !d.is_set() {
                    return TestResult::Fail("SET bit lost");
                }
            }
            Err(_) => return TestResult::Fail("BCDC decode failed"),
        }
        TestResult::Pass
    }
    kernel_test_in!("drivers/wireless/cyw43439/sdpcm", smoke_bcdc_round_trip);

    fn smoke_short_header_rejected() -> TestResult {
        if !matches!(HwHeader::decode(&[0u8; 2]), Err(FramingError::ShortHeader)) {
            return TestResult::Fail("HW decode should reject short slice");
        }
        if !matches!(SwHeader::decode(&[0u8; 4]), Err(FramingError::ShortHeader)) {
            return TestResult::Fail("SW decode should reject short slice");
        }
        if !matches!(
            BcdcHeader::decode(&[0u8; 8]),
            Err(FramingError::ShortHeader)
        ) {
            return TestResult::Fail("BCDC decode should reject short slice");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "drivers/wireless/cyw43439/sdpcm",
        smoke_short_header_rejected
    );
}

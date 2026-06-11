//! MIPI CSI-2 host packet codec — clean-room.
//!
//! ## Sources (public only)
//!
//! - **MIPI Alliance Standard for Camera Serial Interface 2
//!   (CSI-2) Specification**, Version 1.3, October 2014. Public
//!   summary + packet-format excerpts at
//!   <https://www.mipi.org/specifications/csi-2>.
//! - **MIPI CSI-2 v3.0** — additional Data Type assignments
//!   (RAW16/RAW20, USL/Embedded Data); we cite v1.3 for the core
//!   packet shapes since those haven't changed.
//!
//! No GPL / Linux source consulted.
//!
//! ## What this is
//!
//! Encoders + decoders for the four-byte short / variable-length
//! long CSI-2 packet formats every camera receiver expects on the
//! D-PHY high-speed bus. Like DSI, CSI-2 packets carry:
//!
//! - 1 byte Data Identifier (`VC<<6 | DT`)
//! - 2 bytes Word Count (or short-data) little-endian
//! - 1 byte ECC (Hamming over the 24-bit header)
//! - For long packets: payload (`Word Count` bytes) + 16-bit
//!   CRC-CCITT-16 (poly 0x1021, init 0xFFFF)
//!
//! The short-packet variants are *control* — Frame Start / Frame
//! End / Line Start / Line End — and carry a 16-bit frame or line
//! number in the data field.

extern crate alloc;
use alloc::vec::Vec;

// ── Data Types (CSI-2 §10) ────────────────────────────────────────

pub mod dt {
    // Synchronization Short Packets (no payload).
    pub const FRAME_START: u8 = 0x00;
    pub const FRAME_END: u8 = 0x01;
    pub const LINE_START: u8 = 0x02;
    pub const LINE_END: u8 = 0x03;

    // Generic Short Packets (8 types).
    pub const GENERIC_SHORT_1: u8 = 0x08;
    pub const GENERIC_SHORT_2: u8 = 0x09;
    pub const GENERIC_SHORT_3: u8 = 0x0A;
    pub const GENERIC_SHORT_4: u8 = 0x0B;
    pub const GENERIC_SHORT_5: u8 = 0x0C;
    pub const GENERIC_SHORT_6: u8 = 0x0D;
    pub const GENERIC_SHORT_7: u8 = 0x0E;
    pub const GENERIC_SHORT_8: u8 = 0x0F;

    // Generic Long Packets.
    pub const NULL: u8 = 0x10;
    pub const BLANKING: u8 = 0x11;
    pub const EMBEDDED_NON_IMAGE: u8 = 0x12;
    pub const RESERVED_13: u8 = 0x13;
    pub const RESERVED_14: u8 = 0x14;
    pub const RESERVED_15: u8 = 0x15;
    pub const RESERVED_16: u8 = 0x16;
    pub const RESERVED_17: u8 = 0x17;

    // YUV image data.
    pub const YUV420_8: u8 = 0x18;
    pub const YUV420_10: u8 = 0x19;
    pub const YUV420_LEGACY_8: u8 = 0x1A;
    pub const YUV420_8_CSPS: u8 = 0x1C;
    pub const YUV420_10_CSPS: u8 = 0x1D;
    pub const YUV422_8: u8 = 0x1E;
    pub const YUV422_10: u8 = 0x1F;

    // RGB image data.
    pub const RGB444: u8 = 0x20;
    pub const RGB555: u8 = 0x21;
    pub const RGB565: u8 = 0x22;
    pub const RGB666: u8 = 0x23;
    pub const RGB888: u8 = 0x24;

    // RAW image data.
    pub const RAW6: u8 = 0x28;
    pub const RAW7: u8 = 0x29;
    pub const RAW8: u8 = 0x2A;
    pub const RAW10: u8 = 0x2B;
    pub const RAW12: u8 = 0x2C;
    pub const RAW14: u8 = 0x2D;
    /// CSI-2 v3.0 addition.
    pub const RAW16: u8 = 0x2E;
    /// CSI-2 v3.0 addition.
    pub const RAW20: u8 = 0x2F;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CsiError {
    Short,
    BadEcc,
    BadCrc,
    Truncated,
}

// ── Short Packet (CSI-2 §9.2) ────────────────────────────────────

/// Decoded short-packet header (4 bytes).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ShortPacket {
    pub virtual_channel: u8,
    pub data_type: u8,
    /// 16-bit short-data field — for Frame Start / Frame End this
    /// is the Frame Number; for Line Start / Line End it's the Line
    /// Number; for Generic Short Packets, vendor-defined.
    pub data: u16,
}

pub fn build_short(vc: u8, dt: u8, data: u16) -> [u8; 4] {
    let did = ((vc & 0x3) << 6) | (dt & 0x3F);
    let mut buf = [did, (data & 0xFF) as u8, ((data >> 8) & 0xFF) as u8, 0];
    buf[3] = ecc24(&buf[..3]);
    buf
}

pub fn decode_short(buf: &[u8]) -> Result<ShortPacket, CsiError> {
    if buf.len() < 4 {
        return Err(CsiError::Short);
    }
    if ecc24(&buf[..3]) != buf[3] {
        return Err(CsiError::BadEcc);
    }
    let did = buf[0];
    Ok(ShortPacket {
        virtual_channel: (did >> 6) & 0x3,
        data_type: did & 0x3F,
        data: (buf[1] as u16) | ((buf[2] as u16) << 8),
    })
}

/// `true` iff `dt` is one of the four synchronization short-packet
/// data types (Frame Start / Frame End / Line Start / Line End).
pub fn is_sync_short(dt: u8) -> bool {
    matches!(dt, dt::FRAME_START..=dt::LINE_END)
}

// ── Long Packet (CSI-2 §9.3) ─────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct LongHeader {
    pub virtual_channel: u8,
    pub data_type: u8,
    pub word_count: u16,
}

pub fn build_long(vc: u8, dt: u8, payload: &[u8]) -> Vec<u8> {
    let did = ((vc & 0x3) << 6) | (dt & 0x3F);
    let wc = payload.len() as u16;
    let mut buf = Vec::with_capacity(6 + payload.len());
    buf.push(did);
    buf.push((wc & 0xFF) as u8);
    buf.push(((wc >> 8) & 0xFF) as u8);
    buf.push(ecc24(&buf[..3]));
    buf.extend_from_slice(payload);
    let crc = crc16_ccitt(payload);
    buf.push((crc & 0xFF) as u8);
    buf.push(((crc >> 8) & 0xFF) as u8);
    buf
}

pub fn decode_long_payload(buf: &[u8]) -> Result<(LongHeader, &[u8]), CsiError> {
    if buf.len() < 6 {
        return Err(CsiError::Short);
    }
    if ecc24(&buf[..3]) != buf[3] {
        return Err(CsiError::BadEcc);
    }
    let did = buf[0];
    let wc = (buf[1] as u16) | ((buf[2] as u16) << 8);
    let total = 4 + wc as usize + 2;
    if buf.len() < total {
        return Err(CsiError::Truncated);
    }
    let payload = &buf[4..4 + wc as usize];
    let crc_got = (buf[4 + wc as usize] as u16) | ((buf[4 + wc as usize + 1] as u16) << 8);
    let crc_want = crc16_ccitt(payload);
    if crc_got != crc_want {
        return Err(CsiError::BadCrc);
    }
    Ok((
        LongHeader {
            virtual_channel: (did >> 6) & 0x3,
            data_type: did & 0x3F,
            word_count: wc,
        },
        payload,
    ))
}

// ── ECC + CRC helpers ───────────────────────────────────────────

/// 6-bit Hamming ECC over a 24-bit header (CSI-2 §9.4).
/// Bit-mask table is the same as DSI (`crate::dsi::ecc24`); the
/// two specs share the calculation.
pub fn ecc24(hdr: &[u8]) -> u8 {
    debug_assert!(hdr.len() == 3);
    let v = (hdr[0] as u32) | ((hdr[1] as u32) << 8) | ((hdr[2] as u32) << 16);
    const MASKS: [u32; 6] = [
        0b1110_1000_1000_1010_1011_1111,
        0b1101_1100_0100_1101_0101_1111,
        0b0011_1110_0010_0110_1110_0111,
        0b0010_0001_1111_0001_1110_1011,
        0b0001_0001_1111_1110_0001_1101,
        0b0000_1111_1111_1111_1110_0000,
    ];
    let mut ecc = 0u8;
    for (i, &m) in MASKS.iter().enumerate() {
        let p = (v & m).count_ones() as u8 & 1;
        ecc |= p << i;
    }
    ecc
}

/// CSI-2 §9.5 CRC-CCITT-16 (poly 0x1021, init 0xFFFF, no xor-out).
pub fn crc16_ccitt(buf: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in buf {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ── Reassembler — frame boundary tracking ────────────────────────

/// Stream-state aggregator. Feed every decoded short packet through
/// [`feed_short`]; the reassembler reports frame boundaries so the
/// host driver can flip the current scanout buffer.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Reassembler {
    pub current_frame_number: u16,
    pub current_line_number: u16,
    /// `true` between `Frame Start` and `Frame End`.
    pub in_frame: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StreamEvent {
    None,
    FrameBegan { frame: u16 },
    FrameEnded { frame: u16 },
    LineBegan { line: u16 },
    LineEnded { line: u16 },
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn feed_short(&mut self, p: ShortPacket) -> StreamEvent {
        match p.data_type {
            dt::FRAME_START => {
                self.in_frame = true;
                self.current_frame_number = p.data;
                StreamEvent::FrameBegan { frame: p.data }
            }
            dt::FRAME_END => {
                self.in_frame = false;
                StreamEvent::FrameEnded { frame: p.data }
            }
            dt::LINE_START => {
                self.current_line_number = p.data;
                StreamEvent::LineBegan { line: p.data }
            }
            dt::LINE_END => StreamEvent::LineEnded { line: p.data },
            _ => StreamEvent::None,
        }
    }
}

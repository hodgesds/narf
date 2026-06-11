//! MIPI DSI host packet codec — clean-room.
//!
//! ## Sources (public only)
//!
//! - **MIPI Alliance Standard for Display Serial Interface (DSI)
//!   Specification**, Version 1.3, 2014. Public summary +
//!   data-type / packet-format excerpts available at
//!   <https://www.mipi.org/specifications/dsi>.
//! - **MIPI Display Command Set (DCS)** — public command IDs
//!   (Sleep In/Out, Display On/Off, Set Address Mode, Set Pixel
//!   Format, etc.). Reference card / DCS quick-reference:
//!   <https://www.mipi.org/specifications/display-command-set>.
//! - **CRC-CCITT-16** (poly `0x1021`, init `0xFFFF`) for the
//!   long-packet payload checksum — same polynomial as Bluetooth
//!   H5 (`crate::bluetooth::h5`) and PPP, so we use a tiny inline
//!   table-free implementation here for layering.
//!
//! No GPL / Linux source consulted.
//!
//! ## What this module is
//!
//! Encoders + decoders for the four-byte short / variable-length
//! long DSI packet formats, plus DCS command builders for the
//! display-on / display-off / sleep-out sequences every panel needs
//! during boot. Also covers the 6-bit Hamming ECC over the 24-bit
//! header and the 16-bit CRC over the long-packet payload.
//!
//! Live attach (programming a SoC-specific DSI host controller's
//! TX FIFO + LP / HS state machine) lands when wiring this codec
//! into per-vendor display IP. The codec doesn't take a transport
//! dep — pack to bytes here, write bytes through whatever DSI host
//! you've got.

extern crate alloc;
use alloc::vec::Vec;

// ── Data Types (MIPI DSI 1.3 §8.7) ────────────────────────────────

pub mod dt {
    pub const V_SYNC_START: u8 = 0x01;
    pub const V_SYNC_END: u8 = 0x11;
    pub const H_SYNC_START: u8 = 0x21;
    pub const H_SYNC_END: u8 = 0x31;
    pub const COMPRESSION_MODE: u8 = 0x07;
    pub const END_OF_TRANSMISSION: u8 = 0x08;
    pub const COLOR_MODE_OFF: u8 = 0x02;
    pub const COLOR_MODE_ON: u8 = 0x12;
    pub const SHUT_DOWN_PERIPH: u8 = 0x22;
    pub const TURN_ON_PERIPH: u8 = 0x32;
    pub const GENERIC_SHORT_WRITE_0: u8 = 0x03;
    pub const GENERIC_SHORT_WRITE_1: u8 = 0x13;
    pub const GENERIC_SHORT_WRITE_2: u8 = 0x23;
    pub const GENERIC_READ_0: u8 = 0x04;
    pub const GENERIC_READ_1: u8 = 0x14;
    pub const GENERIC_READ_2: u8 = 0x24;
    pub const DCS_SHORT_WRITE_0: u8 = 0x05;
    pub const DCS_SHORT_WRITE_1: u8 = 0x15;
    pub const DCS_READ_0: u8 = 0x06;
    pub const SET_MAX_RETURN_PKT_SIZE: u8 = 0x37;
    pub const NULL_PACKET: u8 = 0x09;
    pub const BLANKING_PACKET: u8 = 0x19;
    pub const GENERIC_LONG_WRITE: u8 = 0x29;
    pub const DCS_LONG_WRITE: u8 = 0x39;
    pub const PACKED_PIXEL_30: u8 = 0x0D;
    pub const PACKED_PIXEL_36: u8 = 0x1D;
    pub const PACKED_PIXEL_YCBCR422_12: u8 = 0x3D;
    pub const PACKED_PIXEL_RGB565: u8 = 0x0E;
    pub const PACKED_PIXEL_RGB666: u8 = 0x1E;
    pub const LOOSELY_PACKED_PIXEL_RGB666: u8 = 0x2E;
    pub const PACKED_PIXEL_RGB888: u8 = 0x3E;
}

// ── DCS commands (MIPI DCS) ───────────────────────────────────────

pub mod dcs {
    pub const NOP: u8 = 0x00;
    pub const SOFT_RESET: u8 = 0x01;
    pub const GET_DISPLAY_POWER: u8 = 0x0A;
    pub const ENTER_SLEEP_MODE: u8 = 0x10;
    pub const EXIT_SLEEP_MODE: u8 = 0x11;
    pub const ENTER_PARTIAL_MODE: u8 = 0x12;
    pub const ENTER_NORMAL_MODE: u8 = 0x13;
    pub const EXIT_INVERT_MODE: u8 = 0x20;
    pub const ENTER_INVERT_MODE: u8 = 0x21;
    pub const SET_GAMMA_CURVE: u8 = 0x26;
    pub const SET_DISPLAY_OFF: u8 = 0x28;
    pub const SET_DISPLAY_ON: u8 = 0x29;
    pub const SET_COLUMN_ADDRESS: u8 = 0x2A;
    pub const SET_PAGE_ADDRESS: u8 = 0x2B;
    pub const WRITE_MEMORY_START: u8 = 0x2C;
    pub const SET_TEAR_OFF: u8 = 0x34;
    pub const SET_TEAR_ON: u8 = 0x35;
    pub const SET_ADDRESS_MODE: u8 = 0x36;
    pub const SET_PIXEL_FORMAT: u8 = 0x3A;
    pub const SET_BRIGHTNESS: u8 = 0x51;
    pub const SET_CONTROL_DISPLAY: u8 = 0x53;
    pub const SET_CABC: u8 = 0x55;
}

// ── Packet types ──────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DsiError {
    /// Packet length below the minimum for its type (4 short / 6+CRC long).
    Short,
    /// 6-bit Hamming ECC over the header bytes did not match.
    BadEcc,
    /// CRC-CCITT over a long-packet payload did not match.
    BadCrc,
    /// Word Count larger than the body present.
    Truncated,
}

/// Build a DSI Short Packet. `vc` is the Virtual Channel (0..=3).
/// `data0`, `data1` are the two payload bytes the spec lets a Short
/// Packet carry — meaning depends on the Data Type:
///
/// - **DCS Short Write 0-param** (`0x05`): `data0` = command, `data1` = 0
/// - **DCS Short Write 1-param** (`0x15`): `data0` = command, `data1` = parameter
/// - **Generic Short Write 0-param** (`0x03`): both 0
/// - **Generic Short Write 1-param** (`0x13`): `data0` = byte, `data1` = 0
/// - **Generic Short Write 2-param** (`0x23`): `data0`/`data1` = bytes
/// - **Set Maximum Return Packet Size** (`0x37`): `data0` = LSB, `data1` = MSB
pub fn build_short(vc: u8, dt: u8, data0: u8, data1: u8) -> [u8; 4] {
    let did = ((vc & 0x3) << 6) | (dt & 0x3F);
    let mut buf = [did, data0, data1, 0];
    buf[3] = ecc24(&buf[..3]);
    buf
}

/// Build a DSI Long Packet. The wire form is:
///
/// ```text
///   byte 0:        Data ID (VC<<6 | DT)
///   bytes 1..3:    Word Count (little-endian u16) | ECC (byte 3)
///   bytes 4..N:    payload (Word Count bytes)
///   bytes N..N+2:  CRC-CCITT-16 over the payload (LE)
/// ```
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

/// Decoded DSI packet header — the 4-byte preamble that precedes
/// every packet (short and long).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PacketHeader {
    pub virtual_channel: u8,
    pub data_type: u8,
    /// For Short packets: data byte 0 is here.
    /// For Long packets: low byte of Word Count.
    pub data0: u8,
    pub data1: u8,
}

/// Decode the 4-byte header. Verifies ECC; returns `BadEcc` if the
/// stored byte 3 doesn't match the 6-bit Hamming over bytes 0..3.
pub fn decode_header(buf: &[u8]) -> Result<PacketHeader, DsiError> {
    if buf.len() < 4 {
        return Err(DsiError::Short);
    }
    if ecc24(&buf[..3]) != buf[3] {
        return Err(DsiError::BadEcc);
    }
    let did = buf[0];
    Ok(PacketHeader {
        virtual_channel: (did >> 6) & 0x3,
        data_type: did & 0x3F,
        data0: buf[1],
        data1: buf[2],
    })
}

/// Decoded long-packet payload borrow + CRC validation.
pub fn decode_long_payload(buf: &[u8]) -> Result<(PacketHeader, &[u8]), DsiError> {
    let h = decode_header(buf)?;
    if !is_long_data_type(h.data_type) {
        return Err(DsiError::Truncated);
    }
    let wc = ((h.data1 as usize) << 8) | (h.data0 as usize);
    if buf.len() < 4 + wc + 2 {
        return Err(DsiError::Truncated);
    }
    let payload = &buf[4..4 + wc];
    let crc_got = u16::from_le_bytes([buf[4 + wc], buf[4 + wc + 1]]);
    let crc_want = crc16_ccitt(payload);
    if crc_got != crc_want {
        return Err(DsiError::BadCrc);
    }
    Ok((h, payload))
}

/// Quick check: is this Data Type a Long Packet?
///
/// Per MIPI DSI 1.3 §8.7, Long packets have bit 5 of the Data Type
/// set to indicate "Long" — except for the few Short types with bit
/// 5 set as part of their numeric assignment. We use the
/// authoritative table.
pub fn is_long_data_type(dt: u8) -> bool {
    matches!(
        dt,
        dt::NULL_PACKET
            | dt::BLANKING_PACKET
            | dt::GENERIC_LONG_WRITE
            | dt::DCS_LONG_WRITE
            | dt::PACKED_PIXEL_30
            | dt::PACKED_PIXEL_36
            | dt::PACKED_PIXEL_YCBCR422_12
            | dt::PACKED_PIXEL_RGB565
            | dt::PACKED_PIXEL_RGB666
            | dt::LOOSELY_PACKED_PIXEL_RGB666
            | dt::PACKED_PIXEL_RGB888
    )
}

// ── DCS command shortcuts ────────────────────────────────────────

/// Build the canonical "exit sleep + display on" boot sequence.
/// Returns three packets: exit-sleep (Short, 0-param), set-pixel-
/// format with the supplied DPI byte (Short, 1-param), display-on
/// (Short, 0-param). Caller transmits in order with the 5 ms wait
/// after exit-sleep that DCS requires (timing not encoded here —
/// that's a transport detail).
pub fn build_panel_init(vc: u8, pixel_format_byte: u8) -> [Vec<u8>; 3] {
    [
        build_short(vc, dt::DCS_SHORT_WRITE_0, dcs::EXIT_SLEEP_MODE, 0).to_vec(),
        build_short(
            vc,
            dt::DCS_SHORT_WRITE_1,
            dcs::SET_PIXEL_FORMAT,
            pixel_format_byte,
        )
        .to_vec(),
        build_short(vc, dt::DCS_SHORT_WRITE_0, dcs::SET_DISPLAY_ON, 0).to_vec(),
    ]
}

// ── ECC-24 (6-bit Hamming over a 24-bit header) ──────────────────

/// Compute the 6-bit Hamming ECC over a 24-bit header. Result is
/// returned as the low 6 bits of the byte; the high 2 bits are 0.
/// Algorithm per MIPI DSI 1.3 §10.2.4 ("ECC Generation").
pub fn ecc24(hdr: &[u8]) -> u8 {
    debug_assert!(hdr.len() == 3);
    // Build a 24-bit value little-endian: D0 = hdr[0] (LSB).
    let v = (hdr[0] as u32) | ((hdr[1] as u32) << 8) | ((hdr[2] as u32) << 16);
    // Per spec, parity-bit P_n is the XOR of a fixed subset of the
    // 24 data bits. The subsets are tabulated below as bit masks
    // (24-bit values selecting which Dxx bits feed each parity bit).
    const MASKS: [u32; 6] = [
        0b1110_1000_1000_1010_1011_1111, // P0
        0b1101_1100_0100_1101_0101_1111, // P1
        0b0011_1110_0010_0110_1110_0111, // P2
        0b0010_0001_1111_0001_1110_1011, // P3
        0b0001_0001_1111_1110_0001_1101, // P4
        0b0000_1111_1111_1111_1110_0000, // P5
    ];
    let mut ecc = 0u8;
    for (i, &m) in MASKS.iter().enumerate() {
        let p = (v & m).count_ones() as u8 & 1;
        ecc |= p << i;
    }
    ecc
}

// ── CRC-CCITT-16 (poly 0x1021, init 0xFFFF) ──────────────────────

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

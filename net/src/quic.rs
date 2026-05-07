//! QUIC v1 + HTTP/3 codec — clean-room.
//!
//! ## Sources (public only)
//!
//! - **RFC 9000** — *QUIC: A UDP-Based Multiplexed and Secure
//!   Transport*. May 2021. <https://datatracker.ietf.org/doc/html/rfc9000>
//!   - §16 — variable-length integer encoding.
//!   - §17.2 — long header packet format.
//!   - §17.3 — short header packet format (1-RTT).
//!   - §19 — frame types (PADDING, PING, ACK, RESET_STREAM, ...).
//! - **RFC 9001** — TLS 1.3 binding for QUIC (header-protection
//!   keys, packet-number encryption); referenced for completeness
//!   but the crypto operations live in `crypto/`.
//!   <https://datatracker.ietf.org/doc/html/rfc9001>
//! - **RFC 9114** — *HTTP/3*. June 2022.
//!   <https://datatracker.ietf.org/doc/html/rfc9114>
//!   - §7 — frame types (DATA, HEADERS, SETTINGS, GOAWAY, etc.).
//! - **RFC 9204** — *QPACK: Field Compression for HTTP/3*. June
//!   2022. Header-compression sister spec; we expose the static
//!   table size constant only — full QPACK lands as a future
//!   commit.
//!   <https://datatracker.ietf.org/doc/html/rfc9204>
//!
//! No GPL / Linux source consulted.

extern crate alloc;
use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QuicError {
    Short,
    /// Variable-length integer encoded as a 4- or 8-byte value
    /// when a smaller representation would have sufficed. Per RFC
    /// 9000 §16 this is *legal* (decoders accept it), but encoders
    /// must produce the minimum form. Used by tests.
    NonMinimalVarInt,
    /// Long header packet has an unrecognised packet type.
    BadPacketType,
}

// ── Variable-length integer (RFC 9000 §16) ────────────────────────

/// Encode an unsigned integer using the 2-bit-prefix variable-length
/// scheme. The two high bits of the first byte indicate the
/// encoding length:
///
/// ```text
///   00  →  1 byte,  6-bit  value (0 .. 63)
///   01  →  2 bytes, 14-bit value (0 .. 16_383)
///   10  →  4 bytes, 30-bit value (0 .. 1_073_741_823)
///   11  →  8 bytes, 62-bit value (0 .. 2^62 - 1)
/// ```
pub fn varint_encode(value: u64) -> Vec<u8> {
    if value < 1 << 6 {
        alloc::vec![value as u8]
    } else if value < 1 << 14 {
        let mut b = (value as u16).to_be_bytes().to_vec();
        b[0] |= 0b0100_0000;
        b
    } else if value < 1 << 30 {
        let mut b = (value as u32).to_be_bytes().to_vec();
        b[0] |= 0b1000_0000;
        b
    } else if value < 1u64 << 62 {
        let mut b = value.to_be_bytes().to_vec();
        b[0] |= 0b1100_0000;
        b
    } else {
        // Out-of-range — clamp to max representable.
        let mut b = ((1u64 << 62) - 1).to_be_bytes().to_vec();
        b[0] |= 0b1100_0000;
        b
    }
}

/// Decode the next variable-length integer. Returns `(value,
/// bytes_consumed)`.
pub fn varint_decode(buf: &[u8]) -> Result<(u64, usize), QuicError> {
    if buf.is_empty() {
        return Err(QuicError::Short);
    }
    let prefix = buf[0] >> 6;
    let len = 1usize << prefix;
    if buf.len() < len {
        return Err(QuicError::Short);
    }
    let mut v = (buf[0] & 0b0011_1111) as u64;
    for i in 1..len {
        v = (v << 8) | buf[i] as u64;
    }
    Ok((v, len))
}

// ── QUIC Long Header (RFC 9000 §17.2) ────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum LongPacketType {
    Initial = 0,
    ZeroRtt = 1,
    Handshake = 2,
    Retry = 3,
}

impl LongPacketType {
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => Self::Initial,
            1 => Self::ZeroRtt,
            2 => Self::Handshake,
            3 => Self::Retry,
            _ => return None,
        })
    }
}

/// First-byte fields of a long header packet (§17.2):
///
/// ```text
///   bit 7        Header Form (1 = long)
///   bit 6        Fixed Bit (must be 1)
///   bits[5:4]    Long Packet Type
///   bits[3:0]    Type-Specific Bits (PNL for Initial / 0-RTT /
///                                    Handshake; reserved for Retry)
/// ```
pub fn first_byte_long(ptype: LongPacketType, type_specific: u8) -> u8 {
    0x80 | 0x40 | ((ptype as u8) << 4) | (type_specific & 0x0F)
}

/// Decoded long-header fields (the parts a kernel-space router
/// needs without the encrypted packet number / payload).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LongHeader {
    pub packet_type: LongPacketType,
    pub type_specific: u8,
    pub version: u32,
    pub dest_cid: Vec<u8>,
    pub src_cid: Vec<u8>,
}

pub fn decode_long_header(buf: &[u8]) -> Result<(LongHeader, usize), QuicError> {
    if buf.len() < 7 {
        return Err(QuicError::Short);
    }
    let b0 = buf[0];
    if b0 & 0x80 == 0 || b0 & 0x40 == 0 {
        return Err(QuicError::BadPacketType);
    }
    let pt = LongPacketType::from_byte((b0 >> 4) & 0x3).ok_or(QuicError::BadPacketType)?;
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    let dcid_len = buf[5] as usize;
    if buf.len() < 6 + dcid_len + 1 {
        return Err(QuicError::Short);
    }
    let dest_cid = buf[6..6 + dcid_len].to_vec();
    let scid_off = 6 + dcid_len;
    let scid_len = buf[scid_off] as usize;
    if buf.len() < scid_off + 1 + scid_len {
        return Err(QuicError::Short);
    }
    let src_cid = buf[scid_off + 1..scid_off + 1 + scid_len].to_vec();
    let total = scid_off + 1 + scid_len;
    Ok((
        LongHeader {
            packet_type: pt,
            type_specific: b0 & 0x0F,
            version,
            dest_cid,
            src_cid,
        },
        total,
    ))
}

// ── QUIC frames (RFC 9000 §19) ────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    AckEcn = 0x03,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    /// STREAM frames are 0x08–0x0F (low 3 bits encode OFF/LEN/FIN).
    StreamMin = 0x08,
    StreamMax = 0x0F,
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreamsBidi = 0x12,
    MaxStreamsUni = 0x13,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    StreamsBlockedBidi = 0x16,
    StreamsBlockedUni = 0x17,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1A,
    PathResponse = 0x1B,
    ConnectionCloseQuic = 0x1C,
    ConnectionCloseApplication = 0x1D,
    HandshakeDone = 0x1E,
}

/// Build a CONNECTION_CLOSE (QUIC layer) frame. Error code +
/// (optional) frame type + reason phrase.
pub fn build_connection_close(error_code: u64, frame_type: u64, reason: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.push(FrameType::ConnectionCloseQuic as u8);
    buf.extend_from_slice(&varint_encode(error_code));
    buf.extend_from_slice(&varint_encode(frame_type));
    buf.extend_from_slice(&varint_encode(reason.len() as u64));
    buf.extend_from_slice(reason);
    buf
}

/// Build a PING frame (single byte 0x01).
pub fn build_ping() -> [u8; 1] {
    [FrameType::Ping as u8]
}

/// Build a STREAM frame for `stream_id`, `offset`, `data`. The low
/// 3 bits of the type byte encode flags:
///   bit 0 = FIN (last frame on this stream)
///   bit 1 = LEN (length field follows offset)
///   bit 2 = OFF (offset field present)
pub fn build_stream(
    stream_id: u64,
    offset: u64,
    data: &[u8],
    fin: bool,
    explicit_length: bool,
) -> Vec<u8> {
    let mut t = FrameType::StreamMin as u8;
    if fin {
        t |= 0x01;
    }
    if explicit_length {
        t |= 0x02;
    }
    if offset != 0 {
        t |= 0x04;
    }
    let mut buf = Vec::new();
    buf.push(t);
    buf.extend_from_slice(&varint_encode(stream_id));
    if offset != 0 {
        buf.extend_from_slice(&varint_encode(offset));
    }
    if explicit_length {
        buf.extend_from_slice(&varint_encode(data.len() as u64));
    }
    buf.extend_from_slice(data);
    buf
}

// ── HTTP/3 frame header (RFC 9114 §7) ────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum H3FrameType {
    Data = 0x00,
    Headers = 0x01,
    CancelPush = 0x03,
    Settings = 0x04,
    PushPromise = 0x05,
    Goaway = 0x07,
    MaxPushId = 0x0D,
}

/// Build a HTTP/3 frame: variable-length type + variable-length
/// length + payload.
pub fn build_h3_frame(frame_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&varint_encode(frame_type));
    buf.extend_from_slice(&varint_encode(payload.len() as u64));
    buf.extend_from_slice(payload);
    buf
}

/// Decode a HTTP/3 frame header. Returns `(frame_type, payload)`.
pub fn decode_h3_frame(buf: &[u8]) -> Result<(u64, &[u8]), QuicError> {
    let (ty, n1) = varint_decode(buf)?;
    let (len, n2) = varint_decode(&buf[n1..])?;
    let header_len = n1 + n2;
    if buf.len() < header_len + len as usize {
        return Err(QuicError::Short);
    }
    Ok((ty, &buf[header_len..header_len + len as usize]))
}

/// QPACK static-table size (RFC 9204 §2.1). Each entry is a
/// `(name, value)` HTTP header pair indexed 0..98 — the table
/// itself isn't carried on the wire, only references into it.
pub const QPACK_STATIC_TABLE_LEN: u64 = 99;

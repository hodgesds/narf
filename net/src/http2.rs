//! HTTP/2 frame layer — clean-room.
//!
//! References (public-only):
//! - RFC 9113 — HTTP/2 (M. Thomson & C. Benfield, June 2022).
//!   §4.1 Frame Format. §6 Frame Definitions (DATA, HEADERS,
//!   PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY,
//!   WINDOW_UPDATE, CONTINUATION). §3.4 (Connection Preface —
//!   24-byte client magic). §6.5 (SETTINGS parameters).
//!   §7 (Error Codes).
//!
//! No GPL Linux source consulted.
//!
//! ## Frame header (RFC 9113 §4.1)
//!
//! ```text
//!   bytes 0..2  Length (24-bit BE; ≤ initial SETTINGS_MAX_FRAME_SIZE 16384)
//!   byte  3     Type
//!   byte  4     Flags
//!   bytes 5..8  R bit (must be 0) | Stream Identifier (31 bits BE)
//!   bytes 9..N  payload (Length bytes)
//! ```

extern crate alloc;

use alloc::vec::Vec;

/// Frame header byte length.
pub const FRAME_HEADER_LEN: usize = 9;

/// Connection preface client sends first (RFC 9113 §3.4).
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

// ── Frame types (RFC 9113 §6) ──────────────────────────────────────

pub const FT_DATA: u8 = 0x0;
pub const FT_HEADERS: u8 = 0x1;
pub const FT_PRIORITY: u8 = 0x2;
pub const FT_RST_STREAM: u8 = 0x3;
pub const FT_SETTINGS: u8 = 0x4;
pub const FT_PUSH_PROMISE: u8 = 0x5;
pub const FT_PING: u8 = 0x6;
pub const FT_GOAWAY: u8 = 0x7;
pub const FT_WINDOW_UPDATE: u8 = 0x8;
pub const FT_CONTINUATION: u8 = 0x9;

// ── Common flag bits ───────────────────────────────────────────────

/// END_STREAM flag (DATA + HEADERS).
pub const FLAG_END_STREAM: u8 = 0x01;
/// END_HEADERS flag (HEADERS / CONTINUATION / PUSH_PROMISE).
pub const FLAG_END_HEADERS: u8 = 0x04;
/// PADDED flag (DATA / HEADERS / PUSH_PROMISE).
pub const FLAG_PADDED: u8 = 0x08;
/// PRIORITY flag (HEADERS).
pub const FLAG_PRIORITY: u8 = 0x20;
/// ACK flag (SETTINGS / PING).
pub const FLAG_ACK: u8 = 0x01;

// ── SETTINGS parameter IDs (RFC 9113 §6.5.2) ──────────────────────

pub const SETTINGS_HEADER_TABLE_SIZE: u16 = 0x1;
pub const SETTINGS_ENABLE_PUSH: u16 = 0x2;
pub const SETTINGS_MAX_CONCURRENT_STREAMS: u16 = 0x3;
pub const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x4;
pub const SETTINGS_MAX_FRAME_SIZE: u16 = 0x5;
pub const SETTINGS_MAX_HEADER_LIST_SIZE: u16 = 0x6;
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u16 = 0x8;
pub const SETTINGS_NO_RFC7540_PRIORITIES: u16 = 0x9;

// ── Error codes (RFC 9113 §7) ─────────────────────────────────────

pub const ERROR_NO_ERROR: u32 = 0x0;
pub const ERROR_PROTOCOL_ERROR: u32 = 0x1;
pub const ERROR_INTERNAL_ERROR: u32 = 0x2;
pub const ERROR_FLOW_CONTROL_ERROR: u32 = 0x3;
pub const ERROR_SETTINGS_TIMEOUT: u32 = 0x4;
pub const ERROR_STREAM_CLOSED: u32 = 0x5;
pub const ERROR_FRAME_SIZE_ERROR: u32 = 0x6;
pub const ERROR_REFUSED_STREAM: u32 = 0x7;
pub const ERROR_CANCEL: u32 = 0x8;
pub const ERROR_COMPRESSION_ERROR: u32 = 0x9;
pub const ERROR_CONNECT_ERROR: u32 = 0xA;
pub const ERROR_ENHANCE_YOUR_CALM: u32 = 0xB;
pub const ERROR_INADEQUATE_SECURITY: u32 = 0xC;
pub const ERROR_HTTP_1_1_REQUIRED: u32 = 0xD;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Http2Error {
    Short,
    /// Length field exceeds 24-bit cap or buffer.
    BadLength,
}

// ── Frame header ───────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameHeader {
    /// 24-bit length (max 2^24 - 1).
    pub length: u32,
    pub frame_type: u8,
    pub flags: u8,
    /// 31-bit stream identifier (high bit on the wire is reserved).
    pub stream_id: u32,
}

impl FrameHeader {
    pub fn encode(&self) -> [u8; FRAME_HEADER_LEN] {
        let mut out = [0u8; FRAME_HEADER_LEN];
        out[0] = ((self.length >> 16) & 0xFF) as u8;
        out[1] = ((self.length >> 8) & 0xFF) as u8;
        out[2] = (self.length & 0xFF) as u8;
        out[3] = self.frame_type;
        out[4] = self.flags;
        // The reserved high bit is always 0; mask just in case.
        let id = self.stream_id & 0x7FFF_FFFF;
        out[5..9].copy_from_slice(&id.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Http2Error> {
        if buf.len() < FRAME_HEADER_LEN {
            return Err(Http2Error::Short);
        }
        let length = ((buf[0] as u32) << 16) | ((buf[1] as u32) << 8) | (buf[2] as u32);
        if length > 0x00FF_FFFF {
            return Err(Http2Error::BadLength);
        }
        let stream_id = u32::from_be_bytes([buf[5], buf[6], buf[7], buf[8]]) & 0x7FFF_FFFF;
        Ok(Self {
            length,
            frame_type: buf[3],
            flags: buf[4],
            stream_id,
        })
    }
}

/// Build a complete frame: header + payload. Returns the encoded
/// byte vector.
pub fn build_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
    let h = FrameHeader {
        length: payload.len() as u32,
        frame_type,
        flags,
        stream_id,
    };
    out.extend_from_slice(&h.encode());
    out.extend_from_slice(payload);
    out
}

// ── SETTINGS frame ─────────────────────────────────────────────────

/// Build a SETTINGS frame body from a list of `(id, value)` pairs.
/// Each entry encodes as `id (BE u16) + value (BE u32)` per §6.5.1.
pub fn build_settings_payload(settings: &[(u16, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(settings.len() * 6);
    for (id, value) in settings {
        out.extend_from_slice(&id.to_be_bytes());
        out.extend_from_slice(&value.to_be_bytes());
    }
    out
}

/// Decode a SETTINGS frame body into `(id, value)` pairs.
pub fn parse_settings_payload(buf: &[u8]) -> Result<Vec<(u16, u32)>, Http2Error> {
    if buf.len() % 6 != 0 {
        return Err(Http2Error::BadLength);
    }
    let mut out = Vec::with_capacity(buf.len() / 6);
    for chunk in buf.chunks_exact(6) {
        let id = u16::from_be_bytes([chunk[0], chunk[1]]);
        let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
        out.push((id, value));
    }
    Ok(out)
}

// ── WINDOW_UPDATE / RST_STREAM / PING / GOAWAY ────────────────────

/// Build a WINDOW_UPDATE frame on `stream_id` (0 = connection-level).
/// The increment must be in 1..=2^31 - 1 per §6.9.
pub fn build_window_update(stream_id: u32, increment: u32) -> Vec<u8> {
    let payload = (increment & 0x7FFF_FFFF).to_be_bytes();
    build_frame(FT_WINDOW_UPDATE, 0, stream_id, &payload)
}

/// Build a RST_STREAM frame.
pub fn build_rst_stream(stream_id: u32, error_code: u32) -> Vec<u8> {
    let payload = error_code.to_be_bytes();
    build_frame(FT_RST_STREAM, 0, stream_id, &payload)
}

/// Build a PING frame. `data` must be exactly 8 bytes per §6.7.
pub fn build_ping(ack: bool, data: [u8; 8]) -> Vec<u8> {
    let flags = if ack { FLAG_ACK } else { 0 };
    build_frame(FT_PING, flags, 0, &data)
}

/// Build a GOAWAY frame (§6.8).
pub fn build_goaway(last_stream_id: u32, error_code: u32, debug_data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + debug_data.len());
    payload.extend_from_slice(&(last_stream_id & 0x7FFF_FFFF).to_be_bytes());
    payload.extend_from_slice(&error_code.to_be_bytes());
    payload.extend_from_slice(debug_data);
    build_frame(FT_GOAWAY, 0, 0, &payload)
}

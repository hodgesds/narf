//! Constrained Application Protocol — clean-room.
//!
//! References (public-only):
//! - RFC 7252 — The Constrained Application Protocol (Z. Shelby et
//!   al, June 2014). §3 Message Format. §3.1 Option Format
//!   (variable-length Delta + Length, with extended-byte / 16-bit
//!   forms when nibble = 13 / 14). §4 Message Transmission. §5
//!   Request/Response Semantics. §12.1 Message Codes (request
//!   methods 0.01..0.04 and response codes class.detail).
//! - RFC 7959 — CoAP Block-Wise Transfers (mentioned for the Block1
//!   / Block2 / Size1 / Size2 option numbers; the codec here doesn't
//!   tie to block semantics).
//! - RFC 8323 — CoAP over TCP / TLS / WebSockets (the byte format
//!   in this module is the UDP form; TCP layer adds a length prefix).
//!
//! No GPL Linux source consulted.
//!
//! ## Message header (RFC 7252 §3)
//!
//! ```text
//!   byte 0:
//!     bits 7..6  Version (must be 1)
//!     bits 5..4  Type (00 CON, 01 NON, 10 ACK, 11 RST)
//!     bits 3..0  Token Length (0..8; 9..15 reserved)
//!   byte 1     Code (request method or response code)
//!   bytes 2..3 Message ID (BE u16)
//!   bytes 4..(4+TKL) Token
//!   bytes …    Options (Delta + Length nibbles + extended bytes + value)
//!   byte 0xFF  Payload Marker (only present if a payload follows)
//!   bytes …    Payload
//! ```
//!
//! ## Option header (§3.1)
//!
//! Each option begins with one byte:
//!
//! ```text
//!   bits 7..4  Option Delta nibble  (0..12 literal, 13/14/15 extended)
//!   bits 3..0  Option Length nibble (same encoding)
//! ```
//!
//! When the nibble is 13 the next byte holds (delta - 13). When 14
//! the next two bytes hold (delta - 269) BE. 15 is reserved (used
//! only as the Payload Marker when both nibbles = 0xFF).

extern crate alloc;

use alloc::vec::Vec;

/// Payload Marker byte (RFC 7252 §3).
pub const PAYLOAD_MARKER: u8 = 0xFF;

// ── Type field (T, RFC 7252 §3) ────────────────────────────────────

pub const TYPE_CONFIRMABLE: u8 = 0;
pub const TYPE_NON_CONFIRMABLE: u8 = 1;
pub const TYPE_ACK: u8 = 2;
pub const TYPE_RST: u8 = 3;

// ── Request methods (Code with class=0; §12.1.1) ──────────────────

pub const METHOD_GET: u8 = 0x01;
pub const METHOD_POST: u8 = 0x02;
pub const METHOD_PUT: u8 = 0x03;
pub const METHOD_DELETE: u8 = 0x04;

// ── Response codes (§12.1.2) ──────────────────────────────────────
// Encoded as (class << 5) | detail.
pub const CODE_CREATED: u8 = (2 << 5) | 1; // 2.01
pub const CODE_DELETED: u8 = (2 << 5) | 2; // 2.02
pub const CODE_VALID: u8 = (2 << 5) | 3; // 2.03
pub const CODE_CHANGED: u8 = (2 << 5) | 4; // 2.04
pub const CODE_CONTENT: u8 = (2 << 5) | 5; // 2.05
pub const CODE_BAD_REQUEST: u8 = 4 << 5; // 4.00
pub const CODE_UNAUTHORIZED: u8 = (4 << 5) | 1; // 4.01
pub const CODE_BAD_OPTION: u8 = (4 << 5) | 2; // 4.02
pub const CODE_FORBIDDEN: u8 = (4 << 5) | 3; // 4.03
pub const CODE_NOT_FOUND: u8 = (4 << 5) | 4; // 4.04
pub const CODE_METHOD_NOT_ALLOWED: u8 = (4 << 5) | 5; // 4.05
pub const CODE_INTERNAL_SERVER_ERROR: u8 = 5 << 5; // 5.00
pub const CODE_NOT_IMPLEMENTED: u8 = (5 << 5) | 1;
pub const CODE_BAD_GATEWAY: u8 = (5 << 5) | 2;
pub const CODE_SERVICE_UNAVAILABLE: u8 = (5 << 5) | 3;

// ── Option numbers (RFC 7252 §5.10 + IANA) ────────────────────────

pub const OPT_IF_MATCH: u32 = 1;
pub const OPT_URI_HOST: u32 = 3;
pub const OPT_ETAG: u32 = 4;
pub const OPT_IF_NONE_MATCH: u32 = 5;
pub const OPT_URI_PORT: u32 = 7;
pub const OPT_LOCATION_PATH: u32 = 8;
pub const OPT_URI_PATH: u32 = 11;
pub const OPT_CONTENT_FORMAT: u32 = 12;
pub const OPT_MAX_AGE: u32 = 14;
pub const OPT_URI_QUERY: u32 = 15;
pub const OPT_ACCEPT: u32 = 17;
pub const OPT_LOCATION_QUERY: u32 = 20;
pub const OPT_BLOCK2: u32 = 23;
pub const OPT_BLOCK1: u32 = 27;
pub const OPT_SIZE2: u32 = 28;
pub const OPT_PROXY_URI: u32 = 35;
pub const OPT_PROXY_SCHEME: u32 = 39;
pub const OPT_SIZE1: u32 = 60;

// Content-Format values (§12.3, IANA).
pub const CF_TEXT_PLAIN: u16 = 0;
pub const CF_APPLICATION_LINK_FORMAT: u16 = 40;
pub const CF_APPLICATION_XML: u16 = 41;
pub const CF_APPLICATION_OCTET_STREAM: u16 = 42;
pub const CF_APPLICATION_JSON: u16 = 50;
pub const CF_APPLICATION_CBOR: u16 = 60;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CoapError {
    Short,
    Truncated,
    BadVersion(u8),
    BadTokenLength(u8),
    /// Option Delta or Length nibble = 15 outside the Payload Marker.
    BadOptionExtension,
}

// ── Header ─────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub typ: u8,
    pub code: u8,
    pub message_id: u16,
    pub token: Vec<u8>,
}

impl Header {
    /// Encode just the fixed 4-byte header + token (no options/payload).
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let tkl = self.token.len() as u8 & 0x0F;
        out.push(((self.version & 0x03) << 6) | ((self.typ & 0x03) << 4) | tkl);
        out.push(self.code);
        out.extend_from_slice(&self.message_id.to_be_bytes());
        out.extend_from_slice(&self.token);
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), CoapError> {
        if buf.len() < 4 {
            return Err(CoapError::Short);
        }
        let version = (buf[0] >> 6) & 0x03;
        if version != 1 {
            return Err(CoapError::BadVersion(version));
        }
        let typ = (buf[0] >> 4) & 0x03;
        let tkl = (buf[0] & 0x0F) as usize;
        if tkl > 8 {
            return Err(CoapError::BadTokenLength(tkl as u8));
        }
        if buf.len() < 4 + tkl {
            return Err(CoapError::Truncated);
        }
        let token = buf[4..4 + tkl].to_vec();
        Ok((
            Self {
                version,
                typ,
                code: buf[1],
                message_id: u16::from_be_bytes([buf[2], buf[3]]),
                token,
            },
            4 + tkl,
        ))
    }
}

// ── Option codec ──────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoapOption {
    pub number: u32,
    pub value: Vec<u8>,
}

fn encode_extended(out: &mut Vec<u8>, nibble: &mut u8, value: u32) {
    if value < 13 {
        *nibble = value as u8;
    } else if value < 269 {
        *nibble = 13;
        out.push((value - 13) as u8);
    } else {
        *nibble = 14;
        let v = (value - 269) as u16;
        out.push((v >> 8) as u8);
        out.push((v & 0xFF) as u8);
    }
}

fn decode_extended(nibble: u8, buf: &[u8], pos: &mut usize) -> Result<u32, CoapError> {
    match nibble {
        0..=12 => Ok(nibble as u32),
        13 => {
            if *pos >= buf.len() {
                return Err(CoapError::Short);
            }
            let v = buf[*pos] as u32 + 13;
            *pos += 1;
            Ok(v)
        }
        14 => {
            if *pos + 2 > buf.len() {
                return Err(CoapError::Short);
            }
            let v = u16::from_be_bytes([buf[*pos], buf[*pos + 1]]) as u32 + 269;
            *pos += 2;
            Ok(v)
        }
        _ => Err(CoapError::BadOptionExtension),
    }
}

/// Append one option to `out`. `last_number` carries the previous
/// option's number so the delta encoding stays monotonic; pass 0
/// for the first option.
pub fn append_option(out: &mut Vec<u8>, last_number: &mut u32, opt: &CoapOption) {
    let delta = opt.number - *last_number;
    *last_number = opt.number;
    let mut delta_nibble: u8 = 0;
    let mut length_nibble: u8 = 0;
    let mut extended_delta = Vec::new();
    let mut extended_length = Vec::new();
    encode_extended(&mut extended_delta, &mut delta_nibble, delta);
    encode_extended(&mut extended_length, &mut length_nibble, opt.value.len() as u32);
    out.push((delta_nibble << 4) | length_nibble);
    out.extend_from_slice(&extended_delta);
    out.extend_from_slice(&extended_length);
    out.extend_from_slice(&opt.value);
}

/// Walk options + payload starting at `buf[pos..]`. Returns
/// `(options, payload, total bytes consumed)`.
pub fn parse_options_and_payload(buf: &[u8]) -> Result<(Vec<CoapOption>, &[u8], usize), CoapError> {
    let mut options = Vec::new();
    let mut pos = 0;
    let mut number = 0u32;
    while pos < buf.len() {
        if buf[pos] == PAYLOAD_MARKER {
            pos += 1;
            return Ok((options, &buf[pos..], buf.len()));
        }
        let head = buf[pos];
        pos += 1;
        let delta_nibble = (head >> 4) & 0x0F;
        let length_nibble = head & 0x0F;
        let delta = decode_extended(delta_nibble, buf, &mut pos)?;
        let length = decode_extended(length_nibble, buf, &mut pos)? as usize;
        if pos + length > buf.len() {
            return Err(CoapError::Truncated);
        }
        number += delta;
        let value = buf[pos..pos + length].to_vec();
        pos += length;
        options.push(CoapOption { number, value });
    }
    Ok((options, &[], pos))
}

// ── Convenience ───────────────────────────────────────────────────

/// Build a complete CoAP UDP message: header + options + (payload).
pub fn build_message(
    header: &Header,
    options: &[CoapOption],
    payload: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + options.len() * 4);
    header.encode_into(&mut out);
    let mut last_number = 0u32;
    for opt in options {
        append_option(&mut out, &mut last_number, opt);
    }
    if let Some(p) = payload {
        if !p.is_empty() {
            out.push(PAYLOAD_MARKER);
            out.extend_from_slice(p);
        }
    }
    out
}

/// Build a GET request to a single Uri-Path segment (e.g. "well-known"
/// or "core"). Returns the message ID + Vec.
pub fn build_get_request(message_id: u16, token: &[u8], path_segments: &[&str]) -> Vec<u8> {
    let header = Header {
        version: 1,
        typ: TYPE_CONFIRMABLE,
        code: METHOD_GET,
        message_id,
        token: token.to_vec(),
    };
    let mut opts = Vec::new();
    for seg in path_segments {
        opts.push(CoapOption {
            number: OPT_URI_PATH,
            value: seg.as_bytes().to_vec(),
        });
    }
    build_message(&header, &opts, None)
}

/// Decode a Code byte → (class, detail) per §12.1.
pub const fn split_code(code: u8) -> (u8, u8) {
    ((code >> 5) & 0x07, code & 0x1F)
}

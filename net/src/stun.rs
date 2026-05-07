//! STUN message codec — clean-room.
//!
//! References (public-only):
//! - RFC 8489 — Session Traversal Utilities for NAT (STUN)
//!   (M. Petit-Huguenin et al, Feb 2020). §5 STUN Message Structure.
//!   §6 Base Attributes (MAPPED-ADDRESS, USERNAME, MESSAGE-INTEGRITY,
//!   MESSAGE-INTEGRITY-SHA256, ERROR-CODE, REALM, NONCE, USERHASH,
//!   SOFTWARE, ALTERNATE-SERVER, FINGERPRINT, XOR-MAPPED-ADDRESS,
//!   PASSWORD-ALGORITHMS, etc.). §14 STUN Method Numbering.
//!   <https://datatracker.ietf.org/doc/html/rfc8489>
//! - RFC 5780 — NAT Behavior Discovery extensions (referenced for
//!   the older method numbering still used in some classic clients).
//!   <https://datatracker.ietf.org/doc/html/rfc5780>
//!
//! No GPL Linux source consulted.
//!
//! ## Header (RFC 8489 §5)
//!
//! Fixed 20 bytes, big-endian:
//!
//! ```text
//!   bytes 0..1   Message Type (top 2 bits = 00, then class + method
//!                                 interleaved per §5):
//!                  bits 13..7 method[11..5], bit 8 = class[1] (C1),
//!                  bits 6..4 method[4..2], bit 4 = class[0] (C0),
//!                  bits 3..0 method[3..0].
//!                Class: 00 request, 01 indication, 10 success-resp,
//!                       11 error-resp.
//!   bytes 2..3   Message Length (excluding the 20-byte header)
//!   bytes 4..7   Magic Cookie 0x2112A442
//!   bytes 8..19  Transaction ID (96 bits)
//!   bytes 20..N  Attributes (TLV: 16-bit type + 16-bit length + body
//!                 padded to a 4-byte boundary)
//! ```

extern crate alloc;

use alloc::vec::Vec;

/// Magic cookie at offset 4..8 (RFC 8489 §6 / §5).
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

/// Header byte length.
pub const STUN_HDR_LEN: usize = 20;

// ── Methods (RFC 8489 §14) ────────────────────────────────────────

pub const METHOD_BINDING: u16 = 0x001;
pub const METHOD_SHARED_SECRET: u16 = 0x002;
// New methods are vendor-extension only beyond §14.

// ── Classes ───────────────────────────────────────────────────────

pub const CLASS_REQUEST: u16 = 0b00;
pub const CLASS_INDICATION: u16 = 0b01;
pub const CLASS_SUCCESS_RESPONSE: u16 = 0b10;
pub const CLASS_ERROR_RESPONSE: u16 = 0b11;

// ── Attribute types (RFC 8489 §6) ─────────────────────────────────
// Comprehension-required (0x0000..0x7FFF).
pub const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
pub const ATTR_USERNAME: u16 = 0x0006;
pub const ATTR_MESSAGE_INTEGRITY: u16 = 0x0008;
pub const ATTR_ERROR_CODE: u16 = 0x0009;
pub const ATTR_UNKNOWN_ATTRIBUTES: u16 = 0x000A;
pub const ATTR_REALM: u16 = 0x0014;
pub const ATTR_NONCE: u16 = 0x0015;
pub const ATTR_MESSAGE_INTEGRITY_SHA256: u16 = 0x001C;
pub const ATTR_PASSWORD_ALGORITHM: u16 = 0x001D;
pub const ATTR_USERHASH: u16 = 0x001E;
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
// Comprehension-optional (0x8000..0xFFFF).
pub const ATTR_PASSWORD_ALGORITHMS: u16 = 0x8002;
pub const ATTR_ALTERNATE_DOMAIN: u16 = 0x8003;
pub const ATTR_SOFTWARE: u16 = 0x8022;
pub const ATTR_ALTERNATE_SERVER: u16 = 0x8023;
pub const ATTR_FINGERPRINT: u16 = 0x8028;

// Address family bytes for *MAPPED-ADDRESS.
pub const FAMILY_IPV4: u8 = 0x01;
pub const FAMILY_IPV6: u8 = 0x02;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StunError {
    Short,
    BadCookie,
    Truncated,
    BadAddress,
}

// ── Header ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct StunHeader {
    pub method: u16,
    pub class: u16,
    pub message_length: u16,
    pub transaction_id: [u8; 12],
}

/// Pack the (method, class) pair into the 14-bit Message Type field.
pub const fn message_type(method: u16, class: u16) -> u16 {
    let m = method & 0x0FFF;
    let c = class & 0x3;
    let m_a = (m >> 9) & 0x1F; // method bits 11..7 → output bits 13..9
    let m_b = (m >> 5) & 0x07; // method bits  6..4 → output bits  7..5
    let m_c = m & 0x000F; //      method bits  3..0 → output bits  3..0
    let c1 = (c >> 1) & 0x1; // → bit 8
    let c0 = c & 0x1; //          → bit 4
    (m_a << 9) | (c1 << 8) | (m_b << 5) | (c0 << 4) | m_c
}

/// Inverse of `message_type` — returns (method, class).
pub const fn parse_message_type(mt: u16) -> (u16, u16) {
    let m_a = (mt >> 9) & 0x1F;
    let m_b = (mt >> 5) & 0x07;
    let m_c = mt & 0x000F;
    let method = (m_a << 7) | (m_b << 4) | m_c;
    let c1 = (mt >> 8) & 0x1;
    let c0 = (mt >> 4) & 0x1;
    let class = (c1 << 1) | c0;
    (method, class)
}

impl StunHeader {
    pub fn encode(&self) -> [u8; STUN_HDR_LEN] {
        let mt = message_type(self.method, self.class);
        let mut out = [0u8; STUN_HDR_LEN];
        out[0..2].copy_from_slice(&mt.to_be_bytes());
        out[2..4].copy_from_slice(&self.message_length.to_be_bytes());
        out[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out[8..20].copy_from_slice(&self.transaction_id);
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, StunError> {
        if buf.len() < STUN_HDR_LEN {
            return Err(StunError::Short);
        }
        let mt = u16::from_be_bytes([buf[0], buf[1]]);
        let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(StunError::BadCookie);
        }
        let (method, class) = parse_message_type(mt);
        let mut tid = [0u8; 12];
        tid.copy_from_slice(&buf[8..20]);
        Ok(Self {
            method,
            class,
            message_length: u16::from_be_bytes([buf[2], buf[3]]),
            transaction_id: tid,
        })
    }
}

// ── Attribute iterator + builders ─────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StunAttribute<'a> {
    pub typ: u16,
    pub data: &'a [u8],
}

/// Walk attributes in the body (i.e. `&buf[20..20+message_length]`).
/// Each TLV is `type(BE u16) + length(BE u16) + body padded to a
/// 4-byte multiple` per §6.
pub fn iter_attributes(mut buf: &[u8]) -> impl Iterator<Item = Result<StunAttribute<'_>, StunError>> {
    core::iter::from_fn(move || {
        if buf.is_empty() {
            return None;
        }
        if buf.len() < 4 {
            buf = &[];
            return Some(Err(StunError::Short));
        }
        let typ = u16::from_be_bytes([buf[0], buf[1]]);
        let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let padded = (len + 3) & !3;
        if 4 + padded > buf.len() {
            buf = &[];
            return Some(Err(StunError::Truncated));
        }
        let data = &buf[4..4 + len];
        buf = &buf[4 + padded..];
        Some(Ok(StunAttribute { typ, data }))
    })
}

/// Append a raw attribute (TLV + 4-byte alignment padding) to `out`.
pub fn append_attribute(out: &mut Vec<u8>, typ: u16, data: &[u8]) {
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

/// Encode a XOR-MAPPED-ADDRESS attribute (§6.2.2). The address bytes
/// are XORed with the magic cookie + (for IPv6) the transaction id.
pub fn encode_xor_mapped_ipv4(transaction_id: &[u8; 12], port: u16, ip: [u8; 4]) -> Vec<u8> {
    let _ = transaction_id;
    let mut body = Vec::with_capacity(8);
    body.push(0); // reserved
    body.push(FAMILY_IPV4);
    let xor_port = port ^ ((MAGIC_COOKIE >> 16) as u16);
    body.extend_from_slice(&xor_port.to_be_bytes());
    let mc = MAGIC_COOKIE.to_be_bytes();
    body.extend_from_slice(&[
        ip[0] ^ mc[0],
        ip[1] ^ mc[1],
        ip[2] ^ mc[2],
        ip[3] ^ mc[3],
    ]);
    body
}

/// Decode a XOR-MAPPED-ADDRESS attribute body into (port, ip).
pub fn decode_xor_mapped_ipv4(transaction_id: &[u8; 12], body: &[u8]) -> Result<(u16, [u8; 4]), StunError> {
    let _ = transaction_id;
    if body.len() < 8 {
        return Err(StunError::Short);
    }
    if body[1] != FAMILY_IPV4 {
        return Err(StunError::BadAddress);
    }
    let port = u16::from_be_bytes([body[2], body[3]]) ^ ((MAGIC_COOKIE >> 16) as u16);
    let mc = MAGIC_COOKIE.to_be_bytes();
    Ok((
        port,
        [
            body[4] ^ mc[0],
            body[5] ^ mc[1],
            body[6] ^ mc[2],
            body[7] ^ mc[3],
        ],
    ))
}

// ── ERROR-CODE attribute (§6.3.4) ─────────────────────────────────

/// Encode an ERROR-CODE attribute body. The error number is split
/// into a 3-bit class + 8-bit number per §6.3.4.
pub fn encode_error_code(error_code: u16, reason: &str) -> Vec<u8> {
    let class = (error_code / 100) & 0x07;
    let number = (error_code % 100) as u8;
    let mut body = Vec::with_capacity(4 + reason.len());
    body.push(0); // reserved
    body.push(0); // reserved
    body.push(class as u8);
    body.push(number);
    body.extend_from_slice(reason.as_bytes());
    body
}

/// Decode an ERROR-CODE attribute body → (error_code, reason).
pub fn decode_error_code<'a>(body: &'a [u8]) -> Result<(u16, &'a str), StunError> {
    if body.len() < 4 {
        return Err(StunError::Short);
    }
    let class = (body[2] & 0x07) as u16;
    let number = body[3] as u16;
    let reason = core::str::from_utf8(&body[4..]).unwrap_or("");
    Ok((class * 100 + number, reason))
}

// ── Convenience: Binding Request ──────────────────────────────────

/// Build a STUN Binding Request (method 0x001, class request) with
/// the given 12-byte transaction id and an optional SOFTWARE attr.
pub fn build_binding_request(transaction_id: [u8; 12], software: Option<&str>) -> Vec<u8> {
    let mut attrs = Vec::new();
    if let Some(s) = software {
        append_attribute(&mut attrs, ATTR_SOFTWARE, s.as_bytes());
    }
    let mut out = Vec::with_capacity(STUN_HDR_LEN + attrs.len());
    let header = StunHeader {
        method: METHOD_BINDING,
        class: CLASS_REQUEST,
        message_length: attrs.len() as u16,
        transaction_id,
    };
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(&attrs);
    out
}

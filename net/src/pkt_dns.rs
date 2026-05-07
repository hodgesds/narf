//! DNS message codec — clean-room.
//!
//! References (public-only):
//! - RFC 1035 — Domain Names — Implementation and Specification
//!   (P. Mockapetris, Nov 1987). §4 Messages.
//! - RFC 3596 — DNS Extensions to Support IP Version 6 (AAAA, type 28).
//! - RFC 6891 — Extension Mechanisms for DNS (EDNS(0), OPT pseudo-RR).
//!
//! No GPL Linux source consulted.
//!
//! ## Message header (RFC 1035 §4.1.1)
//!
//! 12 bytes, big-endian:
//!
//! ```text
//!   bytes 0..1   ID
//!   bytes 2..3   Flags:
//!     bit 15  QR (0=query, 1=response)
//!     bits 14..11 Opcode (0=standard query, 1=inverse, 4=notify, 5=update)
//!     bit 10  AA (Authoritative Answer)
//!     bit  9  TC (Truncated)
//!     bit  8  RD (Recursion Desired)
//!     bit  7  RA (Recursion Available)
//!     bits 6..4  Z reserved
//!     bits 3..0  RCODE (0=NOERROR, 2=SERVFAIL, 3=NXDOMAIN, 5=REFUSED)
//!   bytes 4..5   QDCOUNT (number of question section entries)
//!   bytes 6..7   ANCOUNT (answer)
//!   bytes 8..9   NSCOUNT (authority)
//!   bytes 10..11 ARCOUNT (additional)
//! ```
//!
//! ## Name compression (RFC 1035 §4.1.4)
//!
//! Each label is 1-byte length + that many bytes. A label whose top
//! 2 bits are `0b11` is a *pointer*: the low 14 bits of the byte +
//! the next byte form the BE 14-bit offset into the message at which
//! the rest of the name lives. Length 0 terminates an uncompressed
//! name.

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

/// Header size (RFC 1035 §4.1.1).
pub const DNS_HDR_LEN: usize = 12;

// Header flag bits.
pub const FLAG_QR: u16 = 1 << 15;
pub const FLAG_AA: u16 = 1 << 10;
pub const FLAG_TC: u16 = 1 << 9;
pub const FLAG_RD: u16 = 1 << 8;
pub const FLAG_RA: u16 = 1 << 7;

// Opcodes (RFC 1035 §4.1.1, RFC 1996, RFC 2136).
pub const OPCODE_QUERY: u8 = 0;
pub const OPCODE_INVERSE_QUERY: u8 = 1;
pub const OPCODE_STATUS: u8 = 2;
pub const OPCODE_NOTIFY: u8 = 4;
pub const OPCODE_UPDATE: u8 = 5;

// Response codes (RFC 1035 + RFC 6895).
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMAT_ERROR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

// QTYPE / TYPE values (RFC 1035 §3.2.2 + RFC 3596).
pub const TYPE_A: u16 = 1;
pub const TYPE_NS: u16 = 2;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_SOA: u16 = 6;
pub const TYPE_PTR: u16 = 12;
pub const TYPE_MX: u16 = 15;
pub const TYPE_TXT: u16 = 16;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_SRV: u16 = 33;
pub const TYPE_OPT: u16 = 41;
pub const TYPE_ANY: u16 = 255;

// CLASS values (RFC 1035 §3.2.4).
pub const CLASS_IN: u16 = 1;
pub const CLASS_CH: u16 = 3;
pub const CLASS_HS: u16 = 4;
pub const CLASS_ANY: u16 = 255;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DnsError {
    Short,
    Truncated,
    /// Compression-pointer loop or chain longer than 32 hops.
    BadName,
    /// Label exceeded 63 bytes (RFC 1035 §2.3.4).
    BadLabel,
}

// ── Header ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub fn encode(self) -> [u8; DNS_HDR_LEN] {
        let mut out = [0u8; DNS_HDR_LEN];
        out[0..2].copy_from_slice(&self.id.to_be_bytes());
        out[2..4].copy_from_slice(&self.flags.to_be_bytes());
        out[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        out[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        out[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        out[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, DnsError> {
        if buf.len() < DNS_HDR_LEN {
            return Err(DnsError::Short);
        }
        Ok(Self {
            id: u16::from_be_bytes([buf[0], buf[1]]),
            flags: u16::from_be_bytes([buf[2], buf[3]]),
            qdcount: u16::from_be_bytes([buf[4], buf[5]]),
            ancount: u16::from_be_bytes([buf[6], buf[7]]),
            nscount: u16::from_be_bytes([buf[8], buf[9]]),
            arcount: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }

    pub fn opcode(self) -> u8 {
        ((self.flags >> 11) & 0x0F) as u8
    }
    pub fn rcode(self) -> u8 {
        (self.flags & 0x0F) as u8
    }
    pub fn is_response(self) -> bool {
        (self.flags & FLAG_QR) != 0
    }
}

// ── Name encoding / decoding (with compression) ────────────────────

/// Encode a domain name in wire format (uncompressed). Empty string
/// produces just the terminating zero byte.
pub fn encode_name(out: &mut Vec<u8>, name: &str) -> Result<(), DnsError> {
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        if label.len() > 63 {
            return Err(DnsError::BadLabel);
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

/// Decode a (possibly-compressed) domain name starting at `pos` in
/// `msg`. Returns the decoded name plus the number of bytes consumed
/// from `pos` (counts the compression pointer as 2 bytes; does not
/// chase further bytes consumed by the pointer's target).
pub fn decode_name(msg: &[u8], pos: usize) -> Result<(String, usize), DnsError> {
    let mut name = String::new();
    let mut p = pos;
    let mut hops = 0usize;
    let mut consumed_at_first_pointer: Option<usize> = None;

    loop {
        if hops > 32 {
            return Err(DnsError::BadName);
        }
        if p >= msg.len() {
            return Err(DnsError::Short);
        }
        let b = msg[p];
        match b & 0xC0 {
            0xC0 => {
                if p + 1 >= msg.len() {
                    return Err(DnsError::Short);
                }
                let target = (((b & 0x3F) as usize) << 8) | (msg[p + 1] as usize);
                if consumed_at_first_pointer.is_none() {
                    consumed_at_first_pointer = Some(p + 2 - pos);
                }
                p = target;
                hops += 1;
            }
            0x00 => {
                let len = b as usize;
                if len == 0 {
                    let total = consumed_at_first_pointer.unwrap_or(p + 1 - pos);
                    return Ok((name, total));
                }
                if len > 63 || p + 1 + len > msg.len() {
                    return Err(DnsError::BadLabel);
                }
                if !name.is_empty() {
                    name.push('.');
                }
                let label = core::str::from_utf8(&msg[p + 1..p + 1 + len]).unwrap_or("");
                name.push_str(label);
                p += 1 + len;
            }
            _ => return Err(DnsError::BadName),
        }
    }
}

// ── Question + RR shapes ───────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl Question {
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<(), DnsError> {
        encode_name(out, &self.name)?;
        out.extend_from_slice(&self.qtype.to_be_bytes());
        out.extend_from_slice(&self.qclass.to_be_bytes());
        Ok(())
    }

    pub fn decode(msg: &[u8], pos: usize) -> Result<(Self, usize), DnsError> {
        let (name, used) = decode_name(msg, pos)?;
        let body = pos + used;
        if body + 4 > msg.len() {
            return Err(DnsError::Short);
        }
        Ok((
            Self {
                name,
                qtype: u16::from_be_bytes([msg[body], msg[body + 1]]),
                qclass: u16::from_be_bytes([msg[body + 2], msg[body + 3]]),
            },
            used + 4,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

impl ResourceRecord {
    pub fn decode(msg: &[u8], pos: usize) -> Result<(Self, usize), DnsError> {
        let (name, name_used) = decode_name(msg, pos)?;
        let head = pos + name_used;
        if head + 10 > msg.len() {
            return Err(DnsError::Short);
        }
        let rtype = u16::from_be_bytes([msg[head], msg[head + 1]]);
        let rclass = u16::from_be_bytes([msg[head + 2], msg[head + 3]]);
        let ttl = u32::from_be_bytes([msg[head + 4], msg[head + 5], msg[head + 6], msg[head + 7]]);
        let rdlength = u16::from_be_bytes([msg[head + 8], msg[head + 9]]) as usize;
        let rdata_off = head + 10;
        if rdata_off + rdlength > msg.len() {
            return Err(DnsError::Truncated);
        }
        Ok((
            Self {
                name,
                rtype,
                rclass,
                ttl,
                rdata: msg[rdata_off..rdata_off + rdlength].to_vec(),
            },
            name_used + 10 + rdlength,
        ))
    }
}

// ── Convenience: A query / response builders ───────────────────────

/// Build a standard recursive A-record query for `name`.
pub fn build_a_query(id: u16, name: &str) -> Result<Vec<u8>, DnsError> {
    let mut out = Vec::with_capacity(64);
    let header = DnsHeader {
        id,
        flags: FLAG_RD,
        qdcount: 1,
        ancount: 0,
        nscount: 0,
        arcount: 0,
    };
    out.extend_from_slice(&header.encode());
    let q = Question {
        name: String::from(name),
        qtype: TYPE_A,
        qclass: CLASS_IN,
    };
    q.encode(&mut out)?;
    Ok(out)
}

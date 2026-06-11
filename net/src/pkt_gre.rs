//! Generic Routing Encapsulation — clean-room.
//!
//! References (public-only):
//! - RFC 2784 — Generic Routing Encapsulation (D. Farinacci et al,
//!   March 2000). §2.1 Header layout (4-byte fixed header — flags
//!   + version + protocol type, optional 16-bit checksum + 16-bit
//!     reserved).
//!     <https://datatracker.ietf.org/doc/html/rfc2784>
//! - RFC 2890 — Key and Sequence Number Extensions to GRE (G. Dommety,
//!   September 2000). Adds the K and S flags (32-bit Key + 32-bit
//!   Sequence Number, when present).
//!   <https://datatracker.ietf.org/doc/html/rfc2890>
//! - IANA EtherTypes — referenced for the Protocol Type field
//!   (GRE encapsulation is most commonly used with 0x0800 IPv4 and
//!   0x86DD IPv6).
//!
//! No GPL Linux source consulted.
//!
//! ## Header layout (RFC 2784 + 2890)
//!
//! ```text
//!   byte 0:
//!     bit 7  C (Checksum present)
//!     bit 6  R (Routing present — RFC 1701, deprecated)
//!     bit 5  K (Key present — RFC 2890)
//!     bit 4  S (Sequence Number present — RFC 2890)
//!     bit 3  s (Strict Source Route — deprecated)
//!     bits 2..0  Recur (recursion-control, deprecated)
//!   byte 1:
//!     bit 7  A (Acknowledgement present — RFC 1701, deprecated)
//!     bits 6..3 reserved
//!     bits 2..0  Version (0)
//!   bytes 2..3   Protocol Type (BE EtherType, e.g. 0x0800 IPv4)
//!   bytes 4..5   Checksum (only if C=1)
//!   bytes 6..7   Reserved1 (only if C=1)
//!   bytes 8..11  Key (only if K=1; relative to the position right
//!                       after the optional Checksum block)
//!   bytes …      Sequence Number (only if S=1)
//! ```

extern crate alloc;

use alloc::vec::Vec;

use crate::pkt::ip_checksum;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GreError {
    Short,
    BadVersion(u8),
    BadChecksum,
}

// ── Flag bits ──────────────────────────────────────────────────────

pub const FLAG_CHECKSUM: u16 = 1 << 15;
pub const FLAG_ROUTING: u16 = 1 << 14;
pub const FLAG_KEY: u16 = 1 << 13;
pub const FLAG_SEQUENCE: u16 = 1 << 12;
pub const FLAG_STRICT_SOURCE: u16 = 1 << 11;

// ── Header ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GreHeader {
    pub flags_version: u16,
    pub protocol_type: u16,
    pub checksum: Option<u16>,
    pub key: Option<u32>,
    pub sequence: Option<u32>,
}

impl GreHeader {
    pub fn version(&self) -> u8 {
        (self.flags_version & 0x07) as u8
    }
    pub fn checksum_present(&self) -> bool {
        (self.flags_version & FLAG_CHECKSUM) != 0
    }
    pub fn key_present(&self) -> bool {
        (self.flags_version & FLAG_KEY) != 0
    }
    pub fn sequence_present(&self) -> bool {
        (self.flags_version & FLAG_SEQUENCE) != 0
    }

    /// Encode the GRE header into `out`. The checksum field, if
    /// present, is left at zero — the caller installs the value
    /// over (header + payload) bytes.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.flags_version.to_be_bytes());
        out.extend_from_slice(&self.protocol_type.to_be_bytes());
        if self.checksum_present() {
            out.extend_from_slice(&self.checksum.unwrap_or(0).to_be_bytes());
            out.extend_from_slice(&[0u8; 2]); // reserved1
        }
        if self.key_present() {
            out.extend_from_slice(&self.key.unwrap_or(0).to_be_bytes());
        }
        if self.sequence_present() {
            out.extend_from_slice(&self.sequence.unwrap_or(0).to_be_bytes());
        }
    }

    pub fn decode(buf: &[u8]) -> Result<(Self, usize), GreError> {
        if buf.len() < 4 {
            return Err(GreError::Short);
        }
        let flags_version = u16::from_be_bytes([buf[0], buf[1]]);
        let version = (flags_version & 0x07) as u8;
        if version != 0 {
            return Err(GreError::BadVersion(version));
        }
        let protocol_type = u16::from_be_bytes([buf[2], buf[3]]);
        let mut p = 4usize;
        let checksum = if (flags_version & FLAG_CHECKSUM) != 0 {
            if buf.len() < p + 4 {
                return Err(GreError::Short);
            }
            let cs = u16::from_be_bytes([buf[p], buf[p + 1]]);
            p += 4;
            Some(cs)
        } else {
            None
        };
        let key = if (flags_version & FLAG_KEY) != 0 {
            if buf.len() < p + 4 {
                return Err(GreError::Short);
            }
            let k = u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
            p += 4;
            Some(k)
        } else {
            None
        };
        let sequence = if (flags_version & FLAG_SEQUENCE) != 0 {
            if buf.len() < p + 4 {
                return Err(GreError::Short);
            }
            let s = u32::from_be_bytes([buf[p], buf[p + 1], buf[p + 2], buf[p + 3]]);
            p += 4;
            Some(s)
        } else {
            None
        };
        Ok((
            Self {
                flags_version,
                protocol_type,
                checksum,
                key,
                sequence,
            },
            p,
        ))
    }
}

/// Build a GRE-encapsulated packet — header (with optional Key /
/// Sequence / Checksum) + payload. When `compute_checksum` is true
/// the function fills in the 16-bit checksum over (header + payload)
/// after the header is fully laid out.
pub fn build(
    protocol_type: u16,
    key: Option<u32>,
    sequence: Option<u32>,
    payload: &[u8],
    compute_checksum: bool,
) -> Vec<u8> {
    let mut flags = 0u16;
    if compute_checksum {
        flags |= FLAG_CHECKSUM;
    }
    if key.is_some() {
        flags |= FLAG_KEY;
    }
    if sequence.is_some() {
        flags |= FLAG_SEQUENCE;
    }
    let header = GreHeader {
        flags_version: flags,
        protocol_type,
        checksum: if compute_checksum { Some(0) } else { None },
        key,
        sequence,
    };
    let mut out = Vec::with_capacity(payload.len() + 16);
    header.encode(&mut out);
    out.extend_from_slice(payload);
    if compute_checksum {
        let cs = ip_checksum(&out);
        out[4] = (cs >> 8) as u8;
        out[5] = (cs & 0xFF) as u8;
    }
    out
}

/// Verify the GRE checksum (when present) over (header + payload).
/// Returns `Ok(())` when the checksum field is absent.
pub fn verify(buf: &[u8]) -> Result<(), GreError> {
    let (h, _) = GreHeader::decode(buf)?;
    if !h.checksum_present() {
        return Ok(());
    }
    if ip_checksum(buf) != 0 {
        return Err(GreError::BadChecksum);
    }
    Ok(())
}

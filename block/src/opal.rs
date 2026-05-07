//! TCG OPAL 2.0 Self-Encrypting Drive codec — clean-room.
//!
//! ## Sources (public only)
//!
//! - **TCG Storage Architecture Core Specification, Version
//!   2.01**, Trusted Computing Group, Aug 5 2015. Public.
//!   <https://trustedcomputinggroup.org/resource/tcg-storage-architecture-core-specification/>
//!   - §3.2.4 — ComPacket / Packet / Sub-packet framing.
//!   - §3.2.2.3 — token (atom) encoding.
//! - **TCG Storage Security Subsystem Class: Opal, Version
//!   2.02**, March 2022.
//!   <https://trustedcomputinggroup.org/resource/storage-work-group-storage-security-subsystem-class-opal/>
//!   - §3.1 — Level 0 Discovery response layout + feature codes.
//!
//! No GPL / Linux source consulted.
//!
//! ## What this is
//!
//! Wire-format codec for the Opal control plane: ComPacket framing,
//! Sub-packet header layout, byte-level atom (tiny / short / medium
//! / long) encoder for the token stream a TCG method call sits in,
//! and the Level 0 Discovery feature-block walker that tells the
//! host which Opal features the drive implements.

extern crate alloc;
use alloc::vec::Vec;

// ── Level 0 Discovery (Opal SSC 2.02 §3.1) ───────────────────────

/// Feature codes carried in Level 0 Discovery responses.
pub mod feature {
    pub const TPER: u16 = 0x0001;
    pub const LOCKING: u16 = 0x0002;
    pub const GEOMETRY: u16 = 0x0003;
    pub const ENTERPRISE_SSC: u16 = 0x0100;
    pub const OPAL_V1: u16 = 0x0200;
    pub const SINGLE_USER_MODE: u16 = 0x0201;
    pub const DATA_STORE_TABLE: u16 = 0x0202;
    pub const OPAL_V2: u16 = 0x0203;
    pub const OPAL_LITE: u16 = 0x0301;
    pub const PYRITE_V1: u16 = 0x0302;
    pub const PYRITE_V2: u16 = 0x0303;
    pub const RUBY: u16 = 0x0304;
    pub const BLOCK_SID_AUTH: u16 = 0x0402;
    pub const NAMESPACE_LOCKING: u16 = 0x0403;
    pub const DATA_REMOVAL: u16 = 0x0404;
    pub const NAMESPACE_GEOMETRY: u16 = 0x0405;
}

/// Level 0 Discovery header — 48 bytes (§3.1.1.1).
///
/// ```text
///   0..4:    u32 BE Length of parameter data (size of body that follows)
///   4..8:    u32 BE Data Structure revision
///   8..40:   reserved
///   40..48:  u8[8]  Vendor specific
/// ```
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Level0DiscoveryHeader {
    pub parameter_length: u32,
    pub data_revision: u32,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum OpalError {
    Short,
    BadAtomTag,
    Truncated,
}

impl Level0DiscoveryHeader {
    pub fn decode(buf: &[u8]) -> Result<Self, OpalError> {
        if buf.len() < 48 {
            return Err(OpalError::Short);
        }
        Ok(Self {
            parameter_length: u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]),
            data_revision: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        })
    }
}

/// One Feature Descriptor inside a Level 0 Discovery response.
///
/// Header (4 bytes):
///   0..2: u16 BE Feature code
///   2:    u8  bits[7:4] = version, bits[3:0] = reserved
///   3:    u8  Length of body that follows
///
/// Followed by `length` bytes of feature-specific body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureDescriptor<'a> {
    pub feature_code: u16,
    pub version: u8,
    pub data: &'a [u8],
}

/// Walk every Feature Descriptor in a Level 0 Discovery response.
/// Caller passes the *entire* response buffer; we step past the
/// 48-byte header and yield each subsequent descriptor.
pub fn parse_level0_discovery<'a>(
    buf: &'a [u8],
) -> Result<(Level0DiscoveryHeader, Vec<FeatureDescriptor<'a>>), OpalError> {
    let h = Level0DiscoveryHeader::decode(buf)?;
    let total = 4 + h.parameter_length as usize;
    if buf.len() < total {
        return Err(OpalError::Short);
    }
    let mut out = Vec::new();
    let mut off = 48usize;
    while off + 4 <= total {
        let code = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let version = (buf[off + 2] >> 4) & 0xF;
        let len = buf[off + 3] as usize;
        if off + 4 + len > total {
            return Err(OpalError::Truncated);
        }
        out.push(FeatureDescriptor {
            feature_code: code,
            version,
            data: &buf[off + 4..off + 4 + len],
        });
        off += 4 + len;
    }
    Ok((h, out))
}

// ── ComPacket / Packet / Sub-packet framing (§3.2.4) ─────────────

/// 20-byte ComPacket header (TCG Core §3.2.4.1).
///
/// ```text
///   0..4:   reserved
///   4..6:   u16 BE  ComID
///   6..8:   u16 BE  ComID extension
///   8..12:  u32 BE  Outstanding Data
///   12..16: u32 BE  Min Transfer
///   16..20: u32 BE  Length (size of all Packets that follow)
/// ```
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ComPacketHeader {
    pub com_id: u16,
    pub com_id_ext: u16,
    pub outstanding_data: u32,
    pub min_transfer: u32,
    /// Length of the trailing Packets in bytes — does *not*
    /// include the 20-byte ComPacket header itself.
    pub length: u32,
}

impl ComPacketHeader {
    pub fn encode(self) -> [u8; 20] {
        let mut b = [0u8; 20];
        b[4..6].copy_from_slice(&self.com_id.to_be_bytes());
        b[6..8].copy_from_slice(&self.com_id_ext.to_be_bytes());
        b[8..12].copy_from_slice(&self.outstanding_data.to_be_bytes());
        b[12..16].copy_from_slice(&self.min_transfer.to_be_bytes());
        b[16..20].copy_from_slice(&self.length.to_be_bytes());
        b
    }
    pub fn decode(buf: &[u8]) -> Result<Self, OpalError> {
        if buf.len() < 20 {
            return Err(OpalError::Short);
        }
        Ok(Self {
            com_id: u16::from_be_bytes([buf[4], buf[5]]),
            com_id_ext: u16::from_be_bytes([buf[6], buf[7]]),
            outstanding_data: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
            min_transfer: u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
            length: u32::from_be_bytes([buf[16], buf[17], buf[18], buf[19]]),
        })
    }
}

/// 24-byte Packet header (TCG Core §3.2.4.2).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct PacketHeader {
    pub session: u64, // TPer Session ID + Host Session ID combined
    pub seq_number: u32,
    pub ack_type: u16,
    pub acknowledgement: u32,
    pub length: u32,
}

impl PacketHeader {
    pub fn encode(self) -> [u8; 24] {
        let mut b = [0u8; 24];
        b[0..8].copy_from_slice(&self.session.to_be_bytes());
        b[8..12].copy_from_slice(&self.seq_number.to_be_bytes());
        b[14..16].copy_from_slice(&self.ack_type.to_be_bytes());
        b[16..20].copy_from_slice(&self.acknowledgement.to_be_bytes());
        b[20..24].copy_from_slice(&self.length.to_be_bytes());
        b
    }
}

/// 12-byte Sub-packet header (TCG Core §3.2.4.3).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SubPacketHeader {
    pub kind: u16, // 0 = Data, 0x8000+ = Credit Control
    pub length: u32,
}

impl SubPacketHeader {
    pub fn encode(self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[6..8].copy_from_slice(&self.kind.to_be_bytes());
        b[8..12].copy_from_slice(&self.length.to_be_bytes());
        b
    }
}

// ── Token encoding (TCG Core §3.2.2.3) ───────────────────────────

/// Encode a small unsigned integer (0..=63) as a Tiny Atom — one
/// byte where bit 7 = 0, bit 6 = sign (0 for unsigned), bits[5:0]
/// = value.
pub fn encode_tiny_uint(v: u8) -> u8 {
    debug_assert!(v <= 63, "tiny uint must fit in 6 bits");
    v & 0x3F
}

/// Encode a Short Atom (1..=15 bytes of data). Header byte:
/// `0b10` prefix (bits[7:6]) + bit 5 = sign + bit 4 = bytes flag
/// (0 = continued integer, 1 = bytes), bits[3:0] = data length.
pub fn encode_short_atom(data: &[u8], signed: bool, bytes: bool) -> Vec<u8> {
    debug_assert!(data.len() <= 15, "short atom max 15 bytes");
    let mut out = Vec::with_capacity(1 + data.len());
    let mut hdr = 0b1000_0000u8 | (data.len() as u8 & 0x0F);
    if signed {
        hdr |= 1 << 4;
    }
    if bytes {
        hdr |= 1 << 5;
    }
    out.push(hdr);
    out.extend_from_slice(data);
    out
}

/// Encode a Medium Atom (0..=2047 bytes). 2-byte header.
pub fn encode_medium_atom(data: &[u8], signed: bool, bytes: bool) -> Vec<u8> {
    debug_assert!(data.len() <= 2047);
    let mut out = Vec::with_capacity(2 + data.len());
    let mut h0 = 0b1101_0000u8;
    if signed {
        h0 |= 1 << 4;
    }
    if bytes {
        h0 |= 1 << 5;
    }
    h0 |= ((data.len() >> 8) as u8) & 0x07;
    let h1 = (data.len() & 0xFF) as u8;
    out.push(h0);
    out.push(h1);
    out.extend_from_slice(data);
    out
}

/// Encode a Long Atom (0..=16777215 bytes). 4-byte header.
pub fn encode_long_atom(data: &[u8], signed: bool, bytes: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    let mut h0 = 0b1110_0000u8;
    if signed {
        h0 |= 1 << 0;
    }
    if bytes {
        h0 |= 1 << 1;
    }
    out.push(h0);
    out.push(((data.len() >> 16) & 0xFF) as u8);
    out.push(((data.len() >> 8) & 0xFF) as u8);
    out.push((data.len() & 0xFF) as u8);
    out.extend_from_slice(data);
    out
}

/// Method-call control bytes (TCG Core Table 9 + §5.1.3).
pub mod token {
    pub const START_LIST: u8 = 0xF0;
    pub const END_LIST: u8 = 0xF1;
    pub const START_NAME: u8 = 0xF2;
    pub const END_NAME: u8 = 0xF3;
    pub const CALL: u8 = 0xF8;
    pub const END_OF_DATA: u8 = 0xF9;
    pub const END_OF_SESSION: u8 = 0xFA;
    pub const START_TRANSACTION: u8 = 0xFB;
    pub const END_TRANSACTION: u8 = 0xFC;
    pub const EMPTY_ATOM: u8 = 0xFF;
}

/// Decode the leading atom from a token stream. Returns
/// `(payload_bytes, total_consumed)`. For Tiny Atoms the payload
/// is a single-byte slice into the input; for Short/Medium/Long
/// it's the data field after the header.
pub fn decode_atom(buf: &[u8]) -> Result<(&[u8], usize), OpalError> {
    if buf.is_empty() {
        return Err(OpalError::Short);
    }
    let b0 = buf[0];
    if b0 & 0x80 == 0 {
        // Tiny atom: 1 byte total, 6-bit data; we expose the
        // header byte itself as the "payload" since there's no
        // separate body.
        return Ok((&buf[..1], 1));
    }
    if b0 & 0xC0 == 0x80 {
        // Short atom: header byte + (b0 & 0xF) data bytes.
        let n = (b0 & 0xF) as usize;
        if buf.len() < 1 + n {
            return Err(OpalError::Truncated);
        }
        return Ok((&buf[1..1 + n], 1 + n));
    }
    if b0 & 0xE0 == 0xC0 {
        // Medium atom: 2 byte header + 11-bit length.
        if buf.len() < 2 {
            return Err(OpalError::Short);
        }
        let n = (((b0 & 0x07) as usize) << 8) | buf[1] as usize;
        if buf.len() < 2 + n {
            return Err(OpalError::Truncated);
        }
        return Ok((&buf[2..2 + n], 2 + n));
    }
    if b0 & 0xF0 == 0xE0 {
        // Long atom: 4 byte header + 24-bit length.
        if buf.len() < 4 {
            return Err(OpalError::Short);
        }
        let n =
            ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
        if buf.len() < 4 + n {
            return Err(OpalError::Truncated);
        }
        return Ok((&buf[4..4 + n], 4 + n));
    }
    // Token bytes (0xF0..=0xFF) are control codes, not atoms.
    Err(OpalError::BadAtomTag)
}

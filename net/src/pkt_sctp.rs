//! SCTP common header + chunk codec — clean-room.
//!
//! References (public-only):
//! - RFC 9260 — Stream Control Transmission Protocol (R. Stewart et
//!   al, June 2022). §3.1 SCTP Common Header (12 bytes: src port +
//!   dst port + verification tag + CRC32C checksum). §3.2 Chunk
//!   Field Descriptions. §3.3 SCTP Chunk Definitions: §3.3.1 DATA
//!   (Type 0), §3.3.2 INIT (Type 1), §3.3.3 INIT ACK (2), §3.3.4
//!   SACK (3), §3.3.5 HEARTBEAT (4), §3.3.6 HEARTBEAT ACK (5),
//!   §3.3.7 ABORT (6), §3.3.8 SHUTDOWN (7), §3.3.9 SHUTDOWN ACK (8),
//!   §3.3.10 ERROR (9), §3.3.11 COOKIE ECHO (10), §3.3.12 COOKIE
//!   ACK (11), §3.3.13 ECNE / CWR (12 / 13), §3.3.14 SHUTDOWN
//!   COMPLETE (14), §3.3.20 PAD (132).
//!   <https://datatracker.ietf.org/doc/html/rfc9260>
//! - RFC 3309 — SCTP Checksum (CRC32C, polynomial 0x1EDC6F41). The
//!   computation runs over the whole packet (common header + all
//!   chunks) with the checksum field zeroed.
//!   <https://datatracker.ietf.org/doc/html/rfc3309>
//!
//! No GPL Linux source consulted.
//!
//! ## Common header (RFC 9260 §3.1)
//!
//! ```text
//!   bytes 0..1   Source Port (BE)
//!   bytes 2..3   Destination Port (BE)
//!   bytes 4..7   Verification Tag (BE u32)
//!   bytes 8..11  CRC32C Checksum (BE u32; field zeroed during compute)
//! ```
//!
//! ## Chunk header (§3.2)
//!
//! ```text
//!   byte 0        Chunk Type
//!   byte 1        Chunk Flags
//!   bytes 2..3    Chunk Length (BE u16; covers the entire chunk
//!                                including this header, but
//!                                excluding any 4-byte alignment
//!                                padding the next chunk inherits).
//!   bytes 4..N    Chunk-specific value (length-4 bytes)
//! ```

extern crate alloc;

use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SctpError {
    Short,
    Truncated,
    /// Chunk Length < 4 (the header itself).
    BadChunkLength,
    BadChecksum,
}

// ── Common header ─────────────────────────────────────────────────

pub const COMMON_HDR_LEN: usize = 12;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct CommonHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub verification_tag: u32,
    pub checksum: u32,
}

impl CommonHeader {
    pub fn encode(&self) -> [u8; COMMON_HDR_LEN] {
        let mut out = [0u8; COMMON_HDR_LEN];
        out[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        out[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        out[4..8].copy_from_slice(&self.verification_tag.to_be_bytes());
        out[8..12].copy_from_slice(&self.checksum.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, SctpError> {
        if buf.len() < COMMON_HDR_LEN {
            return Err(SctpError::Short);
        }
        Ok(Self {
            src_port: u16::from_be_bytes([buf[0], buf[1]]),
            dst_port: u16::from_be_bytes([buf[2], buf[3]]),
            verification_tag: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
            checksum: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        })
    }
}

// ── Chunk types (§3.3) ────────────────────────────────────────────

pub const CHUNK_DATA: u8 = 0;
pub const CHUNK_INIT: u8 = 1;
pub const CHUNK_INIT_ACK: u8 = 2;
pub const CHUNK_SACK: u8 = 3;
pub const CHUNK_HEARTBEAT: u8 = 4;
pub const CHUNK_HEARTBEAT_ACK: u8 = 5;
pub const CHUNK_ABORT: u8 = 6;
pub const CHUNK_SHUTDOWN: u8 = 7;
pub const CHUNK_SHUTDOWN_ACK: u8 = 8;
pub const CHUNK_ERROR: u8 = 9;
pub const CHUNK_COOKIE_ECHO: u8 = 10;
pub const CHUNK_COOKIE_ACK: u8 = 11;
pub const CHUNK_ECNE: u8 = 12;
pub const CHUNK_CWR: u8 = 13;
pub const CHUNK_SHUTDOWN_COMPLETE: u8 = 14;
pub const CHUNK_AUTH: u8 = 15;
pub const CHUNK_PAD: u8 = 132;

// ── Chunk header ──────────────────────────────────────────────────

pub const CHUNK_HDR_LEN: usize = 4;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChunkHeader<'a> {
    pub typ: u8,
    pub flags: u8,
    /// Total length in bytes including the 4-byte header.
    pub length: u16,
    pub value: &'a [u8],
}

/// Iterate chunks past the common header. Each chunk is padded out
/// to a 4-byte boundary on the wire — the iterator skips those pad
/// bytes implicitly.
pub fn iter_chunks(mut buf: &[u8]) -> impl Iterator<Item = Result<ChunkHeader<'_>, SctpError>> {
    core::iter::from_fn(move || {
        if buf.is_empty() {
            return None;
        }
        if buf.len() < CHUNK_HDR_LEN {
            buf = &[];
            return Some(Err(SctpError::Short));
        }
        let typ = buf[0];
        let flags = buf[1];
        let length = u16::from_be_bytes([buf[2], buf[3]]);
        if (length as usize) < CHUNK_HDR_LEN {
            buf = &[];
            return Some(Err(SctpError::BadChunkLength));
        }
        if (length as usize) > buf.len() {
            buf = &[];
            return Some(Err(SctpError::Truncated));
        }
        let value = &buf[CHUNK_HDR_LEN..length as usize];
        let padded = (length as usize + 3) & !3;
        if padded <= buf.len() {
            buf = &buf[padded..];
        } else {
            buf = &buf[length as usize..];
        }
        Some(Ok(ChunkHeader {
            typ,
            flags,
            length,
            value,
        }))
    })
}

/// Append one chunk to `out` with 4-byte alignment padding (the
/// padding bytes are NOT counted in the length field per §3.2).
pub fn append_chunk(out: &mut Vec<u8>, typ: u8, flags: u8, value: &[u8]) {
    let length = (CHUNK_HDR_LEN + value.len()) as u16;
    out.push(typ);
    out.push(flags);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    while out.len() % 4 != 0 {
        out.push(0);
    }
}

// ── DATA chunk (§3.3.1) ───────────────────────────────────────────

/// DATA chunk flags (low 4 bits of byte 1).
pub const DATA_FLAG_E: u8 = 1 << 0; // ending fragment of a user message
pub const DATA_FLAG_B: u8 = 1 << 1; // beginning fragment
pub const DATA_FLAG_U: u8 = 1 << 2; // unordered delivery
pub const DATA_FLAG_I: u8 = 1 << 3; // immediate SACK request

/// Build a DATA chunk body (§3.3.1, header excluded — caller wraps
/// with `append_chunk(typ=CHUNK_DATA, flags, value)`):
///
/// ```text
///   bytes 0..3  TSN
///   bytes 4..5  Stream Identifier
///   bytes 6..7  Stream Sequence Number
///   bytes 8..11 Payload Protocol Identifier
///   bytes 12..N user data
/// ```
pub fn build_data_value(
    tsn: u32,
    stream_id: u16,
    stream_seq: u16,
    payload_protocol_id: u32,
    user_data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + user_data.len());
    out.extend_from_slice(&tsn.to_be_bytes());
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(&stream_seq.to_be_bytes());
    out.extend_from_slice(&payload_protocol_id.to_be_bytes());
    out.extend_from_slice(user_data);
    out
}

// ── CRC32C (RFC 3309) ─────────────────────────────────────────────

/// CRC-32C (Castagnoli) — polynomial 0x1EDC6F41 reversed = 0x82F63B78.
/// This is the Castagnoli variant used by SCTP and iSCSI; the running
/// computation is reflected and the output is XORed with 0xFFFFFFFF.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for byte in bytes {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// Compute the SCTP common-header checksum over the entire packet
/// (12-byte common header + chunks). The checksum field at bytes
/// 8..12 must be zeroed before calling.
pub fn compute_checksum(packet: &[u8]) -> u32 {
    crc32c(packet)
}

/// Build a complete SCTP packet: install the CRC32C over the full
/// (header + chunks) byte stream after temporarily zeroing the
/// checksum field.
pub fn build_packet(common: CommonHeader, chunks: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(COMMON_HDR_LEN + chunks.len());
    out.extend_from_slice(&common.encode());
    out.extend_from_slice(chunks);
    // Zero checksum, compute, install.
    out[8] = 0;
    out[9] = 0;
    out[10] = 0;
    out[11] = 0;
    let cs = crc32c(&out);
    // SCTP transmits CRC32C in *little-endian* on the wire (RFC 3309
    // §1.1: "checksum is sent in little-endian byte order").
    out[8..12].copy_from_slice(&cs.to_le_bytes());
    out
}

/// Verify a complete SCTP packet's CRC32C. Treats the 4-byte
/// little-endian checksum field at bytes 8..12 as the on-wire value.
pub fn verify_packet(buf: &[u8]) -> Result<(), SctpError> {
    if buf.len() < COMMON_HDR_LEN {
        return Err(SctpError::Short);
    }
    let on_wire = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
    let mut probe = buf.to_vec();
    probe[8] = 0;
    probe[9] = 0;
    probe[10] = 0;
    probe[11] = 0;
    if crc32c(&probe) != on_wire {
        return Err(SctpError::BadChecksum);
    }
    Ok(())
}

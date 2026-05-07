//! SPDM handshake messages — clean-room.
//!
//! References (public-only):
//! - DMTF DSP0274 "Security Protocol and Data Model (SPDM)
//!   Specification, Version 1.3" (Apr 2023). Public DMTF document.
//!   §10.4 GET_VERSION / VERSION, §10.5 GET_CAPABILITIES / CAPABILITIES,
//!   §10.6 NEGOTIATE_ALGORITHMS / ALGORITHMS, §10.7 GET_DIGESTS /
//!   DIGESTS, §10.8 GET_CERTIFICATE / CERTIFICATE, §10.9 CHALLENGE /
//!   CHALLENGE_AUTH.
//!   <https://www.dmtf.org/dsp/DSP0274>
//!
//! No GPL Linux source consulted.
//!
//! ## SPDM message header (§10.3, table 5)
//!
//! ```text
//!   byte 0  SPDMVersion        — 0x10 SPDM 1.0, 0x11 SPDM 1.1, 0x12 SPDM 1.2, 0x13 SPDM 1.3
//!   byte 1  RequestResponseCode — request/response opcode
//!   byte 2  Param1
//!   byte 3  Param2
//!   byte 4..N  payload (per opcode)
//! ```
//!
//! GET_VERSION must use SPDMVersion = 0x10 even when the eventual
//! negotiated version is higher. Subsequent messages echo the
//! negotiated version.

use alloc::vec::Vec;

use crate::messages::SpdmHeader;

// ── Request / response codes (DSP0274 §10.3, table 6) ──────────────

pub const REQ_GET_DIGESTS: u8 = 0x81;
pub const REQ_GET_CERTIFICATE: u8 = 0x82;
pub const REQ_CHALLENGE: u8 = 0x83;
pub const REQ_GET_VERSION: u8 = 0x84;
pub const REQ_GET_CAPABILITIES: u8 = 0xE1;
pub const REQ_NEGOTIATE_ALGORITHMS: u8 = 0xE3;
pub const REQ_GET_MEASUREMENTS: u8 = 0xE0;

pub const RSP_DIGESTS: u8 = 0x01;
pub const RSP_CERTIFICATE: u8 = 0x02;
pub const RSP_CHALLENGE_AUTH: u8 = 0x03;
pub const RSP_VERSION: u8 = 0x04;
pub const RSP_CAPABILITIES: u8 = 0x61;
pub const RSP_ALGORITHMS: u8 = 0x63;
pub const RSP_MEASUREMENTS: u8 = 0x60;
pub const RSP_ERROR: u8 = 0x7F;

// ── SPDM versions (§10.3) ──────────────────────────────────────────

pub const SPDM_VERSION_10: u8 = 0x10;
pub const SPDM_VERSION_11: u8 = 0x11;
pub const SPDM_VERSION_12: u8 = 0x12;
pub const SPDM_VERSION_13: u8 = 0x13;

// ── NEGOTIATE_ALGORITHMS Base Asym + Hash bitmasks (§10.6) ─────────

pub const ASYM_RSASSA_2048: u32 = 1 << 0;
pub const ASYM_RSAPSS_2048: u32 = 1 << 1;
pub const ASYM_RSASSA_3072: u32 = 1 << 2;
pub const ASYM_RSAPSS_3072: u32 = 1 << 3;
pub const ASYM_ECDSA_P256: u32 = 1 << 4;
pub const ASYM_RSASSA_4096: u32 = 1 << 5;
pub const ASYM_RSAPSS_4096: u32 = 1 << 6;
pub const ASYM_ECDSA_P384: u32 = 1 << 7;
pub const ASYM_ECDSA_P521: u32 = 1 << 8;
pub const ASYM_SM2_P256: u32 = 1 << 9;
pub const ASYM_EDDSA_25519: u32 = 1 << 10;
pub const ASYM_EDDSA_448: u32 = 1 << 11;

pub const HASH_SHA_256: u32 = 1 << 0;
pub const HASH_SHA_384: u32 = 1 << 1;
pub const HASH_SHA_512: u32 = 1 << 2;
pub const HASH_SHA3_256: u32 = 1 << 3;
pub const HASH_SHA3_384: u32 = 1 << 4;
pub const HASH_SHA3_512: u32 = 1 << 5;
pub const HASH_SM3_256: u32 = 1 << 6;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum HandshakeError {
    Short,
    Truncated,
    BadCode(u8),
    BadVersion(u8),
}

// ── GET_VERSION / VERSION (§10.4) ──────────────────────────────────

/// Build the GET_VERSION request. Per §10.4 GET_VERSION fixes the
/// SPDM version field at 0x10 regardless of what the responder will
/// later negotiate.
pub fn build_get_version() -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    SpdmHeader {
        version: SPDM_VERSION_10,
        code: REQ_GET_VERSION,
        param1: 0,
        param2: 0,
    }
    .encode(&mut out);
    out
}

/// Build a VERSION response carrying the supplied version list. The
/// responder advertises which SPDM versions it supports; each entry
/// is a 16-bit value in the layout defined by §10.4.1 table 8.
pub fn build_version_response(versions: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(6 + versions.len() * 2);
    SpdmHeader {
        version: SPDM_VERSION_10,
        code: RSP_VERSION,
        param1: 0,
        param2: 0,
    }
    .encode(&mut out);
    out.push(0); // reserved
    out.push(versions.len() as u8);
    for v in versions {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

/// Decode a VERSION response → list of 16-bit version values.
pub fn parse_version_response(buf: &[u8]) -> Result<Vec<u16>, HandshakeError> {
    if buf.len() < 6 {
        return Err(HandshakeError::Short);
    }
    if buf[1] != RSP_VERSION {
        return Err(HandshakeError::BadCode(buf[1]));
    }
    let count = buf[5] as usize;
    let need = 6 + count * 2;
    if buf.len() < need {
        return Err(HandshakeError::Truncated);
    }
    let mut versions = Vec::with_capacity(count);
    for chunk in buf[6..need].chunks_exact(2) {
        versions.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    Ok(versions)
}

// ── GET_CAPABILITIES / CAPABILITIES (§10.5) ────────────────────────

/// Build a GET_CAPABILITIES request. `ct_exponent` is the requester's
/// cryptographic-operation timeout exponent. `flags` carries the
/// requester capability bitmap (CERT_CAP, CHAL_CAP, MEAS_CAP_SIG,
/// CHUNK_CAP, etc. per table 12).
pub fn build_get_capabilities(version: u8, ct_exponent: u8, flags: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    SpdmHeader {
        version,
        code: REQ_GET_CAPABILITIES,
        param1: 0,
        param2: 0,
    }
    .encode(&mut out);
    out.push(0); // reserved
    out.push(ct_exponent);
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved
    out.extend_from_slice(&flags.to_le_bytes());
    if version >= SPDM_VERSION_12 {
        // SPDM 1.2 added DataTransferSize + MaxSPDMmsgSize (§10.5.1 table 11).
        out.extend_from_slice(&65535u32.to_le_bytes());
        out.extend_from_slice(&65535u32.to_le_bytes());
    }
    out
}

// ── NEGOTIATE_ALGORITHMS / ALGORITHMS (§10.6) ──────────────────────

/// Build a NEGOTIATE_ALGORITHMS request body. `measurement_specification`
/// is per §10.6 table 17 (1 = DMTF), `base_asym_algo` and
/// `base_hash_algo` carry bitmaps the requester supports. We only
/// emit the fixed-length core; AlgStruct table entries are added by
/// the caller via `with_alg_struct`.
pub fn build_negotiate_algorithms(
    version: u8,
    measurement_specification: u8,
    base_asym_algo: u32,
    base_hash_algo: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32);
    SpdmHeader {
        version,
        code: REQ_NEGOTIATE_ALGORITHMS,
        param1: 0, // Number of AlgStructs (filled in by `with_alg_struct`).
        param2: 0,
    }
    .encode(&mut out);
    // Length placeholder (filled at end). Length is the *total* size
    // of the request including header.
    out.extend_from_slice(&0u16.to_le_bytes());
    out.push(measurement_specification);
    out.push(0); // reserved
    out.extend_from_slice(&base_asym_algo.to_le_bytes());
    out.extend_from_slice(&base_hash_algo.to_le_bytes());
    out.extend_from_slice(&[0u8; 12]); // reserved
    out.push(0); // ExtAsymCount
    out.push(0); // ExtHashCount
    out.extend_from_slice(&0u16.to_le_bytes()); // reserved

    // Patch length field at offset 4..6.
    let len = out.len() as u16;
    out[4..6].copy_from_slice(&len.to_le_bytes());
    out
}

// ── GET_DIGESTS / DIGESTS (§10.7) ──────────────────────────────────

/// Build a GET_DIGESTS request. SPDM 1.0 has no operands beyond the
/// header.
pub fn build_get_digests(version: u8) -> Vec<u8> {
    let mut out = Vec::with_capacity(4);
    SpdmHeader {
        version,
        code: REQ_GET_DIGESTS,
        param1: 0,
        param2: 0,
    }
    .encode(&mut out);
    out
}

// ── GET_CERTIFICATE / CERTIFICATE (§10.8) ──────────────────────────

/// Build a GET_CERTIFICATE request. `slot_id` selects the certificate
/// chain (0..7), `offset` is the byte offset within the chain, and
/// `length` is the number of bytes to return (capped at 0xFFFF).
pub fn build_get_certificate(version: u8, slot_id: u8, offset: u16, length: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    SpdmHeader {
        version,
        code: REQ_GET_CERTIFICATE,
        param1: slot_id & 0x0F,
        param2: 0,
    }
    .encode(&mut out);
    out.extend_from_slice(&offset.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
    out
}

/// Decode a CERTIFICATE response →
/// (`slot_id`, `portion_length`, `remainder_length`, `portion_bytes`).
pub fn parse_certificate_response(buf: &[u8]) -> Result<(u8, u16, u16, Vec<u8>), HandshakeError> {
    if buf.len() < 8 {
        return Err(HandshakeError::Short);
    }
    if buf[1] != RSP_CERTIFICATE {
        return Err(HandshakeError::BadCode(buf[1]));
    }
    let slot_id = buf[2] & 0x0F;
    let portion_length = u16::from_le_bytes([buf[4], buf[5]]);
    let remainder_length = u16::from_le_bytes([buf[6], buf[7]]);
    let need = 8 + portion_length as usize;
    if buf.len() < need {
        return Err(HandshakeError::Truncated);
    }
    let portion = buf[8..need].to_vec();
    Ok((slot_id, portion_length, remainder_length, portion))
}

// ── CHALLENGE / CHALLENGE_AUTH (§10.9) ─────────────────────────────

/// Build a CHALLENGE request. `slot_id` selects the cert-chain
/// the requester wants the responder to authenticate with;
/// `measurement_summary_hash_type` per §10.9 table 25 (0 = none,
/// 1 = TCB, 0xFF = all).
pub fn build_challenge(
    version: u8,
    slot_id: u8,
    measurement_summary_hash_type: u8,
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(36);
    SpdmHeader {
        version,
        code: REQ_CHALLENGE,
        param1: slot_id & 0x0F,
        param2: measurement_summary_hash_type,
    }
    .encode(&mut out);
    out.extend_from_slice(nonce);
    out
}

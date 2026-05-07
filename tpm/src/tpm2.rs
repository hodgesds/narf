//! TPM 2.0 — message-header codec + selected commands (clean-room).
//!
//! References (public-only):
//! - "Trusted Platform Module Library Specification, Family 2.0,
//!   Level 00, Revision 1.59" (Nov 2019) — Trusted Computing Group.
//!   Public document.
//!   Part 1 §11.4 (TPM_ST tag values), §17 Boot/Startup commands.
//!   Part 2 §6 Constants — TPM_CC command codes; §10.4 TPMS_AUTH_*
//!   sessions; §10.5 TPMU_HA hash unions.
//!   Part 3 §9 (TPM2_Startup), §16 (TPM2_GetRandom), §22 (TPM2_PCR_Read,
//!   TPM2_PCR_Extend), §30 (TPM2_GetCapability).
//!
//! No GPL Linux source consulted.
//!
//! ## Message header (Part 1 §17, table 2)
//!
//! Every command + response shares the same 10-byte header:
//!
//! ```text
//!   bytes 0..1   tag       (TPM_ST_*)
//!   bytes 2..5   commandSize / responseSize (big-endian, total)
//!   bytes 6..9   commandCode / responseCode
//! ```
//!
//! Body follows. Commands with sessions inject an authorization area
//! after the handles (Part 1 §18.5).

use alloc::vec::Vec;

// ── Tags (Part 1 §11.4, table 17) ──────────────────────────────────

pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
pub const TPM_ST_SESSIONS: u16 = 0x8002;
pub const TPM_ST_NULL: u16 = 0x8000;

// ── Selected command codes (Part 2 §6.5.2) ─────────────────────────

pub const TPM_CC_FIRST: u32 = 0x0000_011F;
pub const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub const TPM_CC_SHUTDOWN: u32 = 0x0000_0145;
pub const TPM_CC_SELF_TEST: u32 = 0x0000_0143;
pub const TPM_CC_INCREMENTAL_SELF_TEST: u32 = 0x0000_0142;
pub const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017A;
pub const TPM_CC_GET_RANDOM: u32 = 0x0000_017B;
pub const TPM_CC_GET_TEST_RESULT: u32 = 0x0000_017C;
pub const TPM_CC_HASH: u32 = 0x0000_017D;
pub const TPM_CC_PCR_READ: u32 = 0x0000_017E;
pub const TPM_CC_PCR_EXTEND: u32 = 0x0000_0182;
pub const TPM_CC_PCR_RESET: u32 = 0x0000_013D;
pub const TPM_CC_READ_CLOCK: u32 = 0x0000_0181;

// ── TPM_SU values (Part 2 §6.9) — operand to TPM2_Startup ─────────

pub const TPM_SU_CLEAR: u16 = 0x0000;
pub const TPM_SU_STATE: u16 = 0x0001;

// ── Hash algorithm IDs (TPM_ALG_ID — Part 2 §6.3, partial) ────────

pub const TPM_ALG_ERROR: u16 = 0x0000;
pub const TPM_ALG_RSA: u16 = 0x0001;
pub const TPM_ALG_SHA1: u16 = 0x0004;
pub const TPM_ALG_HMAC: u16 = 0x0005;
pub const TPM_ALG_AES: u16 = 0x0006;
pub const TPM_ALG_KEYEDHASH: u16 = 0x0008;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_SHA384: u16 = 0x000C;
pub const TPM_ALG_SHA512: u16 = 0x000D;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_SM3_256: u16 = 0x0012;
pub const TPM_ALG_ECC: u16 = 0x0023;
pub const TPM_ALG_SHA3_256: u16 = 0x0027;
pub const TPM_ALG_SHA3_384: u16 = 0x0028;
pub const TPM_ALG_SHA3_512: u16 = 0x0029;

// ── TPM_CAP values (Part 2 §6.10) ─────────────────────────────────

pub const TPM_CAP_ALGS: u32 = 0x0000_0000;
pub const TPM_CAP_HANDLES: u32 = 0x0000_0001;
pub const TPM_CAP_COMMANDS: u32 = 0x0000_0002;
pub const TPM_CAP_PP_COMMANDS: u32 = 0x0000_0003;
pub const TPM_CAP_AUDIT_COMMANDS: u32 = 0x0000_0004;
pub const TPM_CAP_PCRS: u32 = 0x0000_0005;
pub const TPM_CAP_TPM_PROPERTIES: u32 = 0x0000_0006;
pub const TPM_CAP_PCR_PROPERTIES: u32 = 0x0000_0007;
pub const TPM_CAP_ECC_CURVES: u32 = 0x0000_0008;

// ── Common TPM_RC return codes (Part 2 §6.6) ──────────────────────

pub const TPM_RC_SUCCESS: u32 = 0x0000_0000;
pub const TPM_RC_BAD_TAG: u32 = 0x0000_001E;
pub const TPM_RC_INITIALIZE: u32 = 0x0000_0100;
pub const TPM_RC_FAILURE: u32 = 0x0000_0101;
pub const TPM_RC_DISABLED: u32 = 0x0000_0120;
pub const TPM_RC_NV_DEFINED: u32 = 0x0000_014C;
pub const TPM_RC_RETRY: u32 = 0x0000_0922;

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Tpm2Error {
    Short,
    Truncated,
    BadTag(u16),
}

// ── Header ─────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub tag: u16,
    pub size: u32,
    pub code: u32,
}

impl Header {
    pub fn encode(self) -> [u8; 10] {
        let mut out = [0u8; 10];
        out[0..2].copy_from_slice(&self.tag.to_be_bytes());
        out[2..6].copy_from_slice(&self.size.to_be_bytes());
        out[6..10].copy_from_slice(&self.code.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, Tpm2Error> {
        if buf.len() < 10 {
            return Err(Tpm2Error::Short);
        }
        let tag = u16::from_be_bytes([buf[0], buf[1]]);
        if tag != TPM_ST_NO_SESSIONS && tag != TPM_ST_SESSIONS && tag != TPM_ST_NULL {
            return Err(Tpm2Error::BadTag(tag));
        }
        Ok(Self {
            tag,
            size: u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]),
            code: u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]),
        })
    }
}

// ── Command builders ───────────────────────────────────────────────

/// Allocate a buffer with the 10-byte header reserved + write the
/// header. Returns the buffer; the caller appends parameters and
/// then calls `finalise` to patch in the size field.
pub fn begin_command(tag: u16, command_code: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&tag.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // size placeholder
    buf.extend_from_slice(&command_code.to_be_bytes());
    buf
}

/// Patch the 4-byte big-endian size field in bytes 2..6 to the
/// buffer's current length.
pub fn finalise(buf: &mut [u8]) {
    let n = buf.len() as u32;
    buf[2..6].copy_from_slice(&n.to_be_bytes());
}

/// Build a complete TPM2_Startup command (Part 3 §9.3).
pub fn startup(su: u16) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_STARTUP);
    buf.extend_from_slice(&su.to_be_bytes());
    finalise(&mut buf);
    buf
}

/// Build a complete TPM2_Shutdown command (Part 3 §9.4).
pub fn shutdown(su: u16) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_SHUTDOWN);
    buf.extend_from_slice(&su.to_be_bytes());
    finalise(&mut buf);
    buf
}

/// Build a complete TPM2_GetRandom command (Part 3 §16.1).
pub fn get_random(bytes_requested: u16) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_GET_RANDOM);
    buf.extend_from_slice(&bytes_requested.to_be_bytes());
    finalise(&mut buf);
    buf
}

/// Build a complete TPM2_GetCapability command (Part 3 §30.2).
/// `property` is the starting property (e.g. for `TPM_CAP_PCRS` it's
/// 0); `count` caps the number of returned values.
pub fn get_capability(capability: u32, property: u32, count: u32) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_GET_CAPABILITY);
    buf.extend_from_slice(&capability.to_be_bytes());
    buf.extend_from_slice(&property.to_be_bytes());
    buf.extend_from_slice(&count.to_be_bytes());
    finalise(&mut buf);
    buf
}

/// Build a TPM2_PCR_Read command (Part 3 §22.6) for the supplied
/// PCR-selection bitmap (`pcrs` — one byte per 8 PCRs, e.g. PCR 7
/// is bit 7 of byte 0). Selects a single hash algorithm.
pub fn pcr_read(hash_alg: u16, pcrs_bitmap: &[u8]) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ);
    // TPML_PCR_SELECTION: count(u32) + N × TPMS_PCR_SELECTION
    buf.extend_from_slice(&1u32.to_be_bytes()); // 1 selection
    buf.extend_from_slice(&hash_alg.to_be_bytes());
    buf.push(pcrs_bitmap.len() as u8);
    buf.extend_from_slice(pcrs_bitmap);
    finalise(&mut buf);
    buf
}

// ── Response decoders ──────────────────────────────────────────────

/// Decode a TPM2_GetRandom response payload. Returns the random
/// bytes the TPM produced. The caller has already validated the
/// header's response code.
pub fn parse_get_random_response(body: &[u8]) -> Result<&[u8], Tpm2Error> {
    if body.len() < 2 {
        return Err(Tpm2Error::Short);
    }
    let len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + len {
        return Err(Tpm2Error::Truncated);
    }
    Ok(&body[2..2 + len])
}

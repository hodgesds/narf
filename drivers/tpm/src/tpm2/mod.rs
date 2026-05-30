//! TPM 2.0 command set and wire-format codec.
//!
//! Implements the TPM 2.0 command/response wire format defined in
//! TCG Trusted Platform Module Library Specification, Family 2.0,
//! Level 00 Revision 1.59 (November 2019).
//!
//! ## Sub-modules
//!
//! - `commands` — command builders + response parsers
//! - `objects`  — TPM2B_PUBLIC/PRIVATE, key types (RSA, ECC P-256/P-384)
//! - `pcr`      — PCR allocation and extension model
//! - `nv`       — NV index management
//!
//! ## Message header (Part 1 §17, table 2)
//!
//! Every command and response shares a 10-byte header:
//!
//! ```text
//! bytes 0..1  tag          (TPM_ST_*)
//! bytes 2..5  commandSize / responseSize (big-endian, includes header)
//! bytes 6..9  commandCode / responseCode
//! ```

extern crate alloc;

pub mod commands;
pub mod nv;
pub mod objects;
pub mod pcr;

use alloc::vec::Vec;

// ── Structure tags (TPM_ST) — Part 1 §11.4 ──────────────────────────

/// `TPM_ST_NO_SESSIONS` — command has no session area.
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;
/// `TPM_ST_SESSIONS` — command includes an authorisation session area.
pub const TPM_ST_SESSIONS: u16 = 0x8002;
/// `TPM_ST_NULL` — null structure tag.
pub const TPM_ST_NULL: u16 = 0x8000;

// ── Command codes (TPM_CC) — Part 2 §6.5.2 ──────────────────────────

pub const TPM_CC_STARTUP: u32 = 0x0000_0144;
pub const TPM_CC_SHUTDOWN: u32 = 0x0000_0145;
pub const TPM_CC_SELF_TEST: u32 = 0x0000_0143;
pub const TPM_CC_GET_CAPABILITY: u32 = 0x0000_017A;
pub const TPM_CC_GET_RANDOM: u32 = 0x0000_017B;
pub const TPM_CC_GET_TEST_RESULT: u32 = 0x0000_017C;
pub const TPM_CC_STIR_RANDOM: u32 = 0x0000_0146;
pub const TPM_CC_PCR_READ: u32 = 0x0000_017E;
pub const TPM_CC_PCR_EXTEND: u32 = 0x0000_0182;
pub const TPM_CC_PCR_RESET: u32 = 0x0000_013D;
pub const TPM_CC_CREATE: u32 = 0x0000_0153;
pub const TPM_CC_LOAD: u32 = 0x0000_0157;
pub const TPM_CC_UNSEAL: u32 = 0x0000_015E;
pub const TPM_CC_NV_DEFINE_SPACE: u32 = 0x0000_012A;
pub const TPM_CC_NV_READ: u32 = 0x0000_014E;
pub const TPM_CC_NV_WRITE: u32 = 0x0000_0137;
pub const TPM_CC_NV_UNDEFINE_SPACE: u32 = 0x0000_0122;

// ── TPM_SU values — Part 2 §6.9 ─────────────────────────────────────

/// `TPM_SU_CLEAR` — full (power-on) startup.
pub const TPM_SU_CLEAR: u16 = 0x0000;
/// `TPM_SU_STATE` — startup with saved state (resume).
pub const TPM_SU_STATE: u16 = 0x0001;

// ── Algorithm IDs (TPM_ALG_ID) — Part 2 §6.3 ────────────────────────

pub const TPM_ALG_RSA: u16 = 0x0001;
pub const TPM_ALG_SHA1: u16 = 0x0004;
pub const TPM_ALG_AES: u16 = 0x0006;
pub const TPM_ALG_SHA256: u16 = 0x000B;
pub const TPM_ALG_SHA384: u16 = 0x000C;
pub const TPM_ALG_SHA512: u16 = 0x000D;
pub const TPM_ALG_NULL: u16 = 0x0010;
pub const TPM_ALG_ECC: u16 = 0x0023;

// ── ECC curve IDs (TPM_ECC_CURVE) — Part 2 §6.4 ─────────────────────

pub const TPM_ECC_NONE: u16 = 0x0000;
pub const TPM_ECC_NIST_P256: u16 = 0x0003;
pub const TPM_ECC_NIST_P384: u16 = 0x0004;

// ── Capability constants (TPM_CAP) — Part 2 §6.10 ───────────────────

pub const TPM_CAP_ALGS: u32 = 0x0000_0000;
pub const TPM_CAP_HANDLES: u32 = 0x0000_0001;
pub const TPM_CAP_COMMANDS: u32 = 0x0000_0002;
pub const TPM_CAP_PCRS: u32 = 0x0000_0005;
pub const TPM_CAP_TPM_PROPERTIES: u32 = 0x0000_0006;
pub const TPM_CAP_PCR_PROPERTIES: u32 = 0x0000_0007;

// ── Response codes (TPM_RC) — Part 2 §6.6 ───────────────────────────

pub const TPM_RC_SUCCESS: u32 = 0x0000_0000;
pub const TPM_RC_BAD_TAG: u32 = 0x0000_001E;
pub const TPM_RC_INITIALIZE: u32 = 0x0000_0100;
pub const TPM_RC_FAILURE: u32 = 0x0000_0101;
pub const TPM_RC_DISABLED: u32 = 0x0000_0120;
pub const TPM_RC_LOCKOUT: u32 = 0x0000_0921;
pub const TPM_RC_RETRY: u32 = 0x0000_0922;

// ── Well-known handles ───────────────────────────────────────────────

/// Password session pseudo-handle (`TPM_RS_PW`).
pub const TPM_RS_PW: u32 = 0x4000_0009;
/// TPM owner hierarchy handle.
pub const TPM_RH_OWNER: u32 = 0x4000_0001;
/// TPM platform hierarchy handle.
pub const TPM_RH_PLATFORM: u32 = 0x4000_000C;
/// Endorsement hierarchy handle.
pub const TPM_RH_ENDORSEMENT: u32 = 0x4000_000B;

// ── Codec errors ─────────────────────────────────────────────────────

/// Errors from the TPM 2.0 wire-format codec.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// Buffer shorter than the minimum header (10 bytes).
    Short,
    /// `size` field claims more bytes than the buffer contains.
    Truncated,
    /// Tag was not a recognised `TPM_ST_*` value.
    BadTag(u16),
}

// ── Header ────────────────────────────────────────────────────────────

/// 10-byte TPM 2.0 command/response header (Part 1 §17, table 2).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub tag: u16,
    pub size: u32,
    pub code: u32,
}

impl Header {
    /// Encode to the 10-byte big-endian wire format.
    pub fn encode(self) -> [u8; 10] {
        let mut out = [0u8; 10];
        out[0..2].copy_from_slice(&self.tag.to_be_bytes());
        out[2..6].copy_from_slice(&self.size.to_be_bytes());
        out[6..10].copy_from_slice(&self.code.to_be_bytes());
        out
    }

    /// Decode a header from a byte slice, validating the tag.
    pub fn decode(buf: &[u8]) -> Result<Self, CodecError> {
        if buf.len() < 10 {
            return Err(CodecError::Short);
        }
        let tag = u16::from_be_bytes([buf[0], buf[1]]);
        if tag != TPM_ST_NO_SESSIONS && tag != TPM_ST_SESSIONS && tag != TPM_ST_NULL {
            return Err(CodecError::BadTag(tag));
        }
        Ok(Self {
            tag,
            size: u32::from_be_bytes([buf[2], buf[3], buf[4], buf[5]]),
            code: u32::from_be_bytes([buf[6], buf[7], buf[8], buf[9]]),
        })
    }
}

// ── Command builder helpers ───────────────────────────────────────────

/// Allocate a buffer with a zeroed 10-byte header placeholder for
/// the given `tag` and `command_code`. Parameters are appended; call
/// `finalise()` to patch in the actual size.
pub fn begin_command(tag: u16, command_code: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&tag.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // size placeholder
    buf.extend_from_slice(&command_code.to_be_bytes());
    buf
}

/// Patch the 4-byte big-endian `size` field (bytes 2..6) to the
/// buffer's current length.
pub fn finalise(buf: &mut [u8]) {
    let n = buf.len() as u32;
    buf[2..6].copy_from_slice(&n.to_be_bytes());
}

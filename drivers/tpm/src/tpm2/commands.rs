//! TPM 2.0 command builders and response parsers.
//!
//! Each command builder function returns a fully-formed, size-patched
//! `Vec<u8>` ready to submit to the CRB or TIS transport. Response
//! parsers consume the raw response buffer returned by the transport.
//!
//! ## Commands implemented
//!
//! | Function              | Command code | TCG Part 3 §  |
//! |-----------------------|-------------|---------------|
//! | `startup`             | 0x144       | §9.3          |
//! | `shutdown`            | 0x145       | §9.4          |
//! | `self_test`           | 0x143       | §9.5          |
//! | `stir_random`         | 0x146       | §16.3         |
//! | `get_random`          | 0x17B       | §16.1         |
//! | `get_capability`      | 0x17A       | §30.2         |
//! | `get_test_result`     | 0x17C       | §9.7          |
//! | `pcr_read`            | 0x17E       | §22.6         |
//! | `pcr_extend`          | 0x182       | §22.2         |
//! | `create`              | 0x153       | §12.1         |
//! | `load`                | 0x157       | §12.4         |
//! | `unseal`              | 0x15E       | §12.7         |
//! | `nv_define_space`     | 0x12A       | §31.3         |
//! | `nv_read`             | 0x14E       | §31.13        |
//! | `nv_write`            | 0x137       | §31.9         |
//! | `nv_undefine_space`   | 0x122       | §31.5         |
//!
//! ## Reference
//!
//! TCG TPM Library Specification, Family 2.0, Level 00, Rev 1.59.
//! Public document: <https://trustedcomputinggroup.org/resource/tpm-library-specification/>

extern crate alloc;

use super::{
    begin_command, finalise, TPM_ALG_SHA256, TPM_CC_CREATE, TPM_CC_GET_CAPABILITY,
    TPM_CC_GET_RANDOM, TPM_CC_GET_TEST_RESULT, TPM_CC_LOAD, TPM_CC_NV_DEFINE_SPACE,
    TPM_CC_NV_READ, TPM_CC_NV_UNDEFINE_SPACE, TPM_CC_NV_WRITE, TPM_CC_PCR_EXTEND,
    TPM_CC_PCR_READ, TPM_CC_SELF_TEST, TPM_CC_SHUTDOWN, TPM_CC_STARTUP, TPM_CC_STIR_RANDOM,
    TPM_CC_UNSEAL, TPM_RH_OWNER, TPM_RS_PW, TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS, TPM_SU_CLEAR,
};
use alloc::vec::Vec;

// ── Startup / shutdown ────────────────────────────────────────────────

/// Build `TPM2_Startup(startupType)` — Part 3 §9.3.
///
/// `su` should be `TPM_SU_CLEAR` (0) for a fresh boot or
/// `TPM_SU_STATE` (1) to resume saved state.
pub fn startup(su: u16) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_STARTUP);
    buf.extend_from_slice(&su.to_be_bytes());
    finalise(&mut buf);
    buf
}

/// Shorthand: `TPM2_Startup(TPM_SU_CLEAR)`.
pub fn startup_clear() -> Vec<u8> {
    startup(TPM_SU_CLEAR)
}

/// Build `TPM2_Shutdown(startupType)` — Part 3 §9.4.
pub fn shutdown(su: u16) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_SHUTDOWN);
    buf.extend_from_slice(&su.to_be_bytes());
    finalise(&mut buf);
    buf
}

// ── Self-test ─────────────────────────────────────────────────────────

/// Build `TPM2_SelfTest(fullTest)` — Part 3 §9.5.
///
/// `full = true` tests all algorithms; `false` tests only the ones
/// not previously tested in this power cycle.
pub fn self_test(full: bool) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_SELF_TEST);
    buf.push(if full { 1 } else { 0 });
    finalise(&mut buf);
    buf
}

/// Build `TPM2_GetTestResult()` — Part 3 §9.7.
pub fn get_test_result() -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_GET_TEST_RESULT);
    finalise(&mut buf);
    buf
}

// ── Random number generation ──────────────────────────────────────────

/// Build `TPM2_GetRandom(bytesRequested)` — Part 3 §16.1.
pub fn get_random(bytes_requested: u16) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_GET_RANDOM);
    buf.extend_from_slice(&bytes_requested.to_be_bytes());
    finalise(&mut buf);
    buf
}

/// Build `TPM2_StirRandom(inData)` — Part 3 §16.3.
///
/// Stir the TPM's RNG with additional entropy from the caller.
pub fn stir_random(data: &[u8]) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_STIR_RANDOM);
    // TPM2B_SENSITIVE_DATA: u16 size prefix + data
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    finalise(&mut buf);
    buf
}

/// Parse a `TPM2_GetRandom` response body (bytes after the 10-byte
/// header). Returns the random bytes on success.
///
/// Wire layout: `TPM2B_DIGEST` = u16 size + bytes.
pub fn parse_get_random_response(body: &[u8]) -> Result<&[u8], &'static str> {
    if body.len() < 2 {
        return Err("get_random response too short");
    }
    let len = u16::from_be_bytes([body[0], body[1]]) as usize;
    if body.len() < 2 + len {
        return Err("get_random response truncated");
    }
    Ok(&body[2..2 + len])
}

// ── GetCapability ─────────────────────────────────────────────────────

/// Build `TPM2_GetCapability(capability, property, propertyCount)` —
/// Part 3 §30.2.
pub fn get_capability(capability: u32, property: u32, count: u32) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_GET_CAPABILITY);
    buf.extend_from_slice(&capability.to_be_bytes());
    buf.extend_from_slice(&property.to_be_bytes());
    buf.extend_from_slice(&count.to_be_bytes());
    finalise(&mut buf);
    buf
}

// ── PCR commands ─────────────────────────────────────────────────────

/// Build `TPM2_PCR_Read(pcrSelectionIn)` — Part 3 §22.6.
///
/// `hash_alg` selects the bank (e.g. `TPM_ALG_SHA256 = 0x000B`).
/// `pcrs_bitmap` is the raw `sizeofSelect` + bitmask bytes (3 bytes
/// for 24 PCRs; PCR N is bit `N % 8` of byte `N / 8`).
pub fn pcr_read(hash_alg: u16, pcrs_bitmap: &[u8]) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_PCR_READ);
    // TPML_PCR_SELECTION: count(u32) + 1 × TPMS_PCR_SELECTION
    buf.extend_from_slice(&1u32.to_be_bytes()); // selectionCount = 1
    buf.extend_from_slice(&hash_alg.to_be_bytes()); // hash
    buf.push(pcrs_bitmap.len() as u8); // sizeofSelect
    buf.extend_from_slice(pcrs_bitmap); // pcrSelect
    finalise(&mut buf);
    buf
}

/// Build `TPM2_PCR_Read` for a single PCR index using SHA-256.
pub fn pcr_read_single(pcr: u32) -> Vec<u8> {
    let mut mask = [0u8; 3];
    if pcr < 24 {
        mask[(pcr / 8) as usize] |= 1 << (pcr % 8);
    }
    pcr_read(TPM_ALG_SHA256, &mask)
}

/// Build `TPM2_PCR_Extend(pcrHandle, digests)` — Part 3 §22.2.
///
/// Uses an empty password session (`TPM_RS_PW`). `digest` must be
/// the correct length for `hash_alg` (32 bytes for SHA-256).
pub fn pcr_extend(pcr: u32, hash_alg: u16, digest: &[u8]) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_PCR_EXTEND);
    // pcrHandle
    buf.extend_from_slice(&pcr.to_be_bytes());
    // Authorization area: TPM_RS_PW session (9 bytes)
    // authorizationSize (u32) = 9
    buf.extend_from_slice(&9u32.to_be_bytes());
    buf.extend_from_slice(&TPM_RS_PW.to_be_bytes()); // sessionHandle
    buf.extend_from_slice(&0u16.to_be_bytes()); // nonceSize = 0
    buf.push(0u8); // sessionAttributes = 0
    buf.extend_from_slice(&0u16.to_be_bytes()); // hmacSize = 0
    // TPML_DIGEST_VALUES: count(u32) + TPMT_HA
    buf.extend_from_slice(&1u32.to_be_bytes()); // count = 1
    buf.extend_from_slice(&hash_alg.to_be_bytes()); // hashAlg
    buf.extend_from_slice(digest); // digest bytes
    finalise(&mut buf);
    buf
}

/// Shorthand: `pcr_extend` with SHA-256.
pub fn pcr_extend_sha256(pcr: u32, digest: &[u8; 32]) -> Vec<u8> {
    pcr_extend(pcr, TPM_ALG_SHA256, digest)
}

// ── Create / Load / Unseal ─────────────────────────────────────────────

/// Build a minimal `TPM2_Create` for an unrestricted decryption key
/// under the owner hierarchy — Part 3 §12.1.
///
/// This is a skeleton; full creation requires caller-supplied
/// `inSensitive` (auth, data) and `inPublic` (TPMT_PUBLIC).
/// Here we send an empty sensitive and a stub RSA-2048 template so
/// the wire length at least matches the spec's minimum command.
pub fn create_rsa2048_under_owner(auth_value: &[u8]) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_CREATE);
    // parentHandle = TPM_RH_OWNER
    buf.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
    // Authorization area: empty password session (9 bytes)
    buf.extend_from_slice(&9u32.to_be_bytes()); // authorizationSize
    buf.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // nonceSize
    buf.push(0u8); // sessionAttributes
    buf.extend_from_slice(&0u16.to_be_bytes()); // hmacSize
    // inSensitive (TPM2B_SENSITIVE_CREATE): size + TPMS_SENSITIVE_CREATE
    //   userAuth (TPM2B_AUTH): u16 size + bytes
    //   data (TPM2B_SENSITIVE_DATA): u16 size (0 = empty)
    let inner_size: u16 = 2 + auth_value.len() as u16 + 2;
    buf.extend_from_slice(&inner_size.to_be_bytes());
    buf.extend_from_slice(&(auth_value.len() as u16).to_be_bytes());
    buf.extend_from_slice(auth_value);
    buf.extend_from_slice(&0u16.to_be_bytes()); // data size = 0
    // inPublic (TPM2B_PUBLIC): u16 size + TPMT_PUBLIC stub
    // TPMT_PUBLIC: type(u16) + nameAlg(u16) + objectAttributes(u32) +
    //   authPolicy(TPM2B: u16 + 0 bytes) + parameters + unique
    // RSA-2048, RSAES, SHA256, restricted=0, decrypt=1
    let pub_inner: &[u8] = &[
        0x00, 0x01, // type = TPM_ALG_RSA
        0x00, 0x0B, // nameAlg = SHA256
        0x00, 0x02, 0x00, 0x00, // objectAttributes: decrypt only
        0x00, 0x00, // authPolicy size = 0
        0x00, 0x0B, // symmetric = TPM_ALG_AES (or NULL for key type)
        0x00, 0x80, // keyBits = 128 (inner symmetric key bits)
        0x00, 0x10, // mode = TPM_ALG_NULL
        0x00, 0x10, // scheme = TPM_ALG_NULL
        0x08, 0x00, // keyBits = 2048
        0x00, 0x00, 0x00, 0x01, // exponent = 0 (65537 default)
        0x00, 0x00, // unique (TPM2B size = 0 for new key)
    ];
    buf.extend_from_slice(&(pub_inner.len() as u16).to_be_bytes());
    buf.extend_from_slice(pub_inner);
    // outsideInfo (TPM2B_DATA): size = 0
    buf.extend_from_slice(&0u16.to_be_bytes());
    // creationPCR (TPML_PCR_SELECTION): count = 0
    buf.extend_from_slice(&0u32.to_be_bytes());
    finalise(&mut buf);
    buf
}

/// Build `TPM2_Load(parentHandle, inPrivate, inPublic)` — Part 3 §12.4.
///
/// `private` and `public` are the TPM2B-wrapped blobs from a prior
/// `TPM2_Create` response.
pub fn load(parent_handle: u32, private: &[u8], public: &[u8]) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_LOAD);
    buf.extend_from_slice(&parent_handle.to_be_bytes());
    // Empty password session (9 bytes)
    buf.extend_from_slice(&9u32.to_be_bytes());
    buf.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.push(0u8);
    buf.extend_from_slice(&0u16.to_be_bytes());
    // TPM2B_PRIVATE
    buf.extend_from_slice(&(private.len() as u16).to_be_bytes());
    buf.extend_from_slice(private);
    // TPM2B_PUBLIC
    buf.extend_from_slice(&(public.len() as u16).to_be_bytes());
    buf.extend_from_slice(public);
    finalise(&mut buf);
    buf
}

/// Build `TPM2_Unseal(itemHandle)` — Part 3 §12.7.
pub fn unseal(item_handle: u32) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_UNSEAL);
    buf.extend_from_slice(&item_handle.to_be_bytes());
    // Empty password session
    buf.extend_from_slice(&9u32.to_be_bytes());
    buf.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.push(0u8);
    buf.extend_from_slice(&0u16.to_be_bytes());
    finalise(&mut buf);
    buf
}

// ── NV storage ────────────────────────────────────────────────────────

/// Build `TPM2_NV_DefineSpace(authHandle, auth, publicInfo)` —
/// Part 3 §31.3.
///
/// `nv_index` is the caller-chosen NV index (e.g. `0x0150_0001`).
/// `nv_size` is the number of bytes to allocate.
/// `nv_attr` is the `TPMA_NV` attribute word (e.g. `0x4002` for
/// `TPMA_NV_PPWRITE | TPMA_NV_PPREAD | TPMA_NV_NO_DA`).
pub fn nv_define_space(nv_index: u32, nv_size: u16, nv_attr: u32) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_NV_DEFINE_SPACE);
    // authHandle = TPM_RH_OWNER
    buf.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
    // Empty password session
    buf.extend_from_slice(&9u32.to_be_bytes());
    buf.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.push(0u8);
    buf.extend_from_slice(&0u16.to_be_bytes());
    // auth (TPM2B_AUTH): 0-length
    buf.extend_from_slice(&0u16.to_be_bytes());
    // publicInfo (TPM2B_NV_PUBLIC): u16 size + TPMS_NV_PUBLIC
    //   nvIndex(u32) + nameAlg(u16) + attributes(u32) + authPolicy(TPM2B) + dataSize(u16)
    let nv_pub: &[u8] = &{
        let mut v = [0u8; 14];
        v[0..4].copy_from_slice(&nv_index.to_be_bytes());
        v[4..6].copy_from_slice(&0x000Bu16.to_be_bytes()); // nameAlg = SHA256
        v[6..10].copy_from_slice(&nv_attr.to_be_bytes());
        v[10..12].copy_from_slice(&0u16.to_be_bytes()); // authPolicy size = 0
        v[12..14].copy_from_slice(&nv_size.to_be_bytes());
        v
    };
    buf.extend_from_slice(&(nv_pub.len() as u16).to_be_bytes());
    buf.extend_from_slice(nv_pub);
    finalise(&mut buf);
    buf
}

/// Build `TPM2_NV_Read(authHandle, nvIndex, size, offset)` —
/// Part 3 §31.13.
pub fn nv_read(nv_index: u32, size: u16, offset: u16) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_NV_READ);
    // authHandle = nvIndex (self-auth)
    buf.extend_from_slice(&nv_index.to_be_bytes());
    // nvIndex
    buf.extend_from_slice(&nv_index.to_be_bytes());
    // Empty password session
    buf.extend_from_slice(&9u32.to_be_bytes());
    buf.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.push(0u8);
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&size.to_be_bytes());
    buf.extend_from_slice(&offset.to_be_bytes());
    finalise(&mut buf);
    buf
}

/// Build `TPM2_NV_Write(authHandle, nvIndex, data, offset)` —
/// Part 3 §31.9.
pub fn nv_write(nv_index: u32, data: &[u8], offset: u16) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_NV_WRITE);
    buf.extend_from_slice(&nv_index.to_be_bytes()); // authHandle
    buf.extend_from_slice(&nv_index.to_be_bytes()); // nvIndex
    // Empty password session
    buf.extend_from_slice(&9u32.to_be_bytes());
    buf.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.push(0u8);
    buf.extend_from_slice(&0u16.to_be_bytes());
    // TPM2B_MAX_NV_BUFFER: size + data
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf.extend_from_slice(&offset.to_be_bytes());
    finalise(&mut buf);
    buf
}

/// Build `TPM2_NV_UndefineSpace(authHandle, nvIndex)` — Part 3 §31.5.
pub fn nv_undefine_space(nv_index: u32) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_NV_UNDEFINE_SPACE);
    buf.extend_from_slice(&TPM_RH_OWNER.to_be_bytes());
    buf.extend_from_slice(&nv_index.to_be_bytes());
    // Empty password session
    buf.extend_from_slice(&9u32.to_be_bytes());
    buf.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.push(0u8);
    buf.extend_from_slice(&0u16.to_be_bytes());
    finalise(&mut buf);
    buf
}

// ── Response parsing ─────────────────────────────────────────────────

/// Validate a raw TPM 2.0 response buffer. Returns the body slice
/// (everything after the 10-byte header) on success, or an error
/// description if the buffer is malformed or the RC is non-zero.
pub fn parse_response(raw: &[u8]) -> Result<&[u8], &'static str> {
    if raw.len() < 10 {
        return Err("response too short");
    }
    let rc = u32::from_be_bytes([raw[6], raw[7], raw[8], raw[9]]);
    if rc != 0 {
        return Err("non-zero response code");
    }
    let size = u32::from_be_bytes([raw[2], raw[3], raw[4], raw[5]]) as usize;
    if size < 10 || size > raw.len() {
        return Err("response size field invalid");
    }
    Ok(&raw[10..size])
}

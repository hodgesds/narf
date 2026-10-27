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
//! | `evict_control`       | 0x120       | §27.2         |
//! | `clear`               | 0x126       | §24.4         |
//! | `clear_control`       | 0x127       | §24.3         |
//! | `create_primary`      | 0x131       | §12.2         |
//! | `flush_context`       | 0x165       | §11.4         |
//! | `start_auth_session`  | 0x176       | §11.1         |
//! | `policy_pcr`          | 0x19F       | §19.7         |
//!
//! Structured response parsers (the pre-#941 layer had only
//! GetRandom's): `parse_create_response`,
//! `parse_create_primary_response`, `parse_load_response`,
//! `parse_unseal_response`, `parse_nv_read_response`,
//! `parse_get_capability_response` (+ `parse_tagged_properties` /
//! `parse_pcr_selections` over its data),
//! `parse_get_test_result_response`,
//! `parse_start_auth_session_response`.
//!
//! The sealing-minimum completion (#1002) adds the builders the
//! suspend anchor's conversation stands on — `create_sealed_object`,
//! `unseal_with_session`, `policy_get_digest`, `nv_increment` —
//! plus `parse_policy_get_digest_response`,
//! `parse_pcr_read_response`, and the `response_rc` failure-class
//! reader; and fixes `parse_create_primary_response` to the
//! Part 3 §12.2 layout (CreatePrimary returns no `outPrivate`).
//!
//! The hierarchy/session/object commands and the parsers are the
//! #941 command-set completion: the audit found Clear without even
//! a command-code constant, CreatePrimary / EvictControl /
//! StartAuthSession / PolicyPCR absent everywhere (sessions were
//! password-only, so authPolicy-bound objects had no path), and
//! the one Create template malformed — its inline "template"
//! encoded the symmetric-alg field as TPM_ALG_SHA256 with stray
//! extra parameter words and exponent 1. `create` now builds its
//! inPublic from `objects::rsa2048_template`, the encoding the
//! object layer already had right.
//!
//! ## Reference
//!
//! TCG TPM Library Specification, Family 2.0, Level 00, Rev 1.59.
//! Public document: <https://trustedcomputinggroup.org/resource/tpm-library-specification/>

extern crate alloc;

use super::{
    begin_command, finalise, TPM_ALG_NULL, TPM_ALG_SHA256, TPM_CC_CLEAR, TPM_CC_CLEAR_CONTROL,
    TPM_CC_CREATE, TPM_CC_CREATE_PRIMARY, TPM_CC_EVICT_CONTROL, TPM_CC_FLUSH_CONTEXT,
    TPM_CC_GET_CAPABILITY, TPM_CC_GET_RANDOM, TPM_CC_GET_TEST_RESULT, TPM_CC_LOAD,
    TPM_CC_NV_DEFINE_SPACE, TPM_CC_NV_INCREMENT, TPM_CC_NV_READ, TPM_CC_NV_UNDEFINE_SPACE,
    TPM_CC_NV_WRITE, TPM_CC_PCR_EXTEND, TPM_CC_PCR_READ, TPM_CC_POLICY_GET_DIGEST,
    TPM_CC_POLICY_PCR, TPM_CC_SELF_TEST, TPM_CC_SHUTDOWN, TPM_CC_STARTUP,
    TPM_CC_START_AUTH_SESSION, TPM_CC_STIR_RANDOM, TPM_CC_UNSEAL, TPM_RH_OWNER, TPM_RH_PLATFORM,
    TPM_RS_PW, TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS, TPM_SU_CLEAR,
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

/// Build `TPM2_Create` for an unrestricted RSA-2048 decryption
/// key under the owner hierarchy — Part 3 §12.1.
///
/// `inSensitive` carries `auth_value` as the new object's auth and
/// no sealed data. `inPublic` is `objects::rsa2048_template` with
/// the standard child-key attributes (fixedTPM | stClear |
/// fixedParent | sensitiveDataOrigin | userWithAuth | decrypt) —
/// #941: the builder previously hand-encoded a malformed inline
/// template (symmetric-alg field = TPM_ALG_SHA256, stray parameter
/// words, exponent 1) that a real TPM rejects; the object layer's
/// encoder is the single source for the template now.
pub fn create_rsa2048_under_owner(auth_value: &[u8]) -> Vec<u8> {
    use super::objects::{
        OBJ_DECRYPT, OBJ_FIXED_PARENT, OBJ_FIXED_TPM, OBJ_SENSITIVE_DATA_ORIGIN, OBJ_ST_CLEAR,
        OBJ_USER_WITH_AUTH,
    };
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
                                                // inPublic (TPM2B_PUBLIC): u16 size + TPMT_PUBLIC
    let pub_inner = super::objects::rsa2048_template(
        OBJ_FIXED_TPM
            | OBJ_ST_CLEAR
            | OBJ_FIXED_PARENT
            | OBJ_SENSITIVE_DATA_ORIGIN
            | OBJ_USER_WITH_AUTH
            | OBJ_DECRYPT,
    );
    buf.extend_from_slice(&(pub_inner.len() as u16).to_be_bytes());
    buf.extend_from_slice(&pub_inner);
    // outsideInfo (TPM2B_DATA): size = 0
    buf.extend_from_slice(&0u16.to_be_bytes());
    // creationPCR (TPML_PCR_SELECTION): count = 0
    buf.extend_from_slice(&0u32.to_be_bytes());
    finalise(&mut buf);
    buf
}

/// Build `TPM2_Create` for a sealed data object under a loaded
/// parent — Part 3 §12.1. The suspend anchor's wrap act (#1002):
/// `data` becomes the object's sensitive contents and
/// `in_public_inner` is its `TPMT_PUBLIC` template
/// (`objects::keyedhash_seal_template`, carrying the PCR
/// `authPolicy`). The parent is authorized with the empty
/// password session; the new object gets an empty auth value —
/// its only authorization is the policy in its public area.
pub fn create_sealed_object(parent_handle: u32, data: &[u8], in_public_inner: &[u8]) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_CREATE);
    buf.extend_from_slice(&parent_handle.to_be_bytes());
    push_password_session(&mut buf);
    // inSensitive (TPM2B_SENSITIVE_CREATE): userAuth (empty) + data
    let inner_size: u16 = 2 + 2 + data.len() as u16;
    buf.extend_from_slice(&inner_size.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // userAuth size = 0
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    // inPublic (TPM2B_PUBLIC)
    buf.extend_from_slice(&(in_public_inner.len() as u16).to_be_bytes());
    buf.extend_from_slice(in_public_inner);
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

/// Build `TPM2_Unseal(itemHandle)` authorized by a policy
/// session — Part 3 §12.7, the suspend anchor's unwrap act
/// (#1002). The authorization area carries the policy session
/// itself with empty nonce/HMAC (an unbound, unsalted policy
/// session has no session key to HMAC with) and
/// `sessionAttributes = 0`: the session is flushed when the
/// command completes, so a resume ceremony cannot replay it.
/// Policy satisfaction is the TPM's check of the session's
/// policyDigest against the object's `authPolicy` — a mismatch
/// is `TPM_RC_POLICY_FAIL`, never a data return.
pub fn unseal_with_session(item_handle: u32, session_handle: u32) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_UNSEAL);
    buf.extend_from_slice(&item_handle.to_be_bytes());
    buf.extend_from_slice(&9u32.to_be_bytes()); // authorizationSize
    buf.extend_from_slice(&session_handle.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // nonceSize
    buf.push(0u8); // sessionAttributes = 0 (flush after use)
    buf.extend_from_slice(&0u16.to_be_bytes()); // hmacSize
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

// ── Hierarchy / session / object lifecycle (#941) ─────────────────────

/// Append the empty password-session authorization area used by
/// every builder in this section: authorizationSize(4) = 9 +
/// TPM_RS_PW(4) + nonceSize(2) = 0 + attributes(1) = 0 +
/// hmacSize(2) = 0.
fn push_password_session(buf: &mut Vec<u8>) {
    buf.extend_from_slice(&9u32.to_be_bytes());
    buf.extend_from_slice(&TPM_RS_PW.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.push(0u8);
    buf.extend_from_slice(&0u16.to_be_bytes());
}

/// Build `TPM2_Clear()` — Part 3 §24.4.
///
/// Flushes transient objects and sessions, resets the PCRs, and
/// clears the hierarchy auth values. The sole handle is
/// `TPM_RH_PLATFORM`, authorized with the empty password session —
/// this builder is the command the policy layer's
/// `TpmRight::Clear` always named but no code could submit (#941:
/// Clear had no builder and not even a command-code constant).
pub fn clear() -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_CLEAR);
    buf.extend_from_slice(&TPM_RH_PLATFORM.to_be_bytes());
    push_password_session(&mut buf);
    finalise(&mut buf);
    buf
}

/// Build `TPM2_ClearControl(disableClear)` — Part 3 §24.3.
///
/// `disable_clear = true` blocks TPM2_Clear until the next
/// Startup; platform handle, empty password session.
pub fn clear_control(disable_clear: bool) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_CLEAR_CONTROL);
    buf.extend_from_slice(&TPM_RH_PLATFORM.to_be_bytes());
    push_password_session(&mut buf);
    buf.push(u8::from(disable_clear)); // TPMI_YES_NO
    finalise(&mut buf);
    buf
}

/// Build `TPM2_CreatePrimary(inSensitive, inPublic, outsideInfo,
/// creationPCR)` — Part 3 §12.2.
///
/// `primary_handle` is the hierarchy (TPM_RH_OWNER /
/// TPM_RH_ENDORSEMENT / TPM_RH_PLATFORM), authorized with the
/// empty password session carrying `auth_value` as the
/// hierarchy's auth. `in_public_inner` is the raw TPMT_PUBLIC
/// template (the TPM2B wrapper is added here) — use
/// `objects::rsa2048_template` / `objects::ecc_template`, or the
/// `create_primary_rsa_storage` shorthand. `outsideInfo` is empty
/// and `creationPCR` selects nothing: creation data is not
/// consumed by any caller yet.
pub fn create_primary(primary_handle: u32, auth_value: &[u8], in_public_inner: &[u8]) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_CREATE_PRIMARY);
    buf.extend_from_slice(&primary_handle.to_be_bytes());
    push_password_session(&mut buf);
    // inSensitive (TPM2B_SENSITIVE_CREATE)
    let inner_size: u16 = 2 + auth_value.len() as u16 + 2;
    buf.extend_from_slice(&inner_size.to_be_bytes());
    buf.extend_from_slice(&(auth_value.len() as u16).to_be_bytes());
    buf.extend_from_slice(auth_value);
    buf.extend_from_slice(&0u16.to_be_bytes()); // data size = 0
                                                // inPublic (TPM2B_PUBLIC)
    buf.extend_from_slice(&(in_public_inner.len() as u16).to_be_bytes());
    buf.extend_from_slice(in_public_inner);
    // outsideInfo (TPM2B_DATA): size = 0
    buf.extend_from_slice(&0u16.to_be_bytes());
    // creationPCR (TPML_PCR_SELECTION): count = 0
    buf.extend_from_slice(&0u32.to_be_bytes());
    finalise(&mut buf);
    buf
}

/// Shorthand: `TPM2_CreatePrimary` for the RSA-2048 storage
/// primary under the owner hierarchy (the SRK shape) with an
/// empty hierarchy auth.
pub fn create_primary_rsa_storage() -> Vec<u8> {
    create_primary(
        TPM_RH_OWNER,
        &[],
        &super::objects::rsa2048_template(super::objects::OBJ_ATTR_STORAGE),
    )
}

/// Build `TPM2_EvictControl(authHandle, objectHandle,
/// persistentHandle)` — Part 3 §27.2.
///
/// Makes a loaded object persistent (or, when `object_handle`
/// names an existing persistent handle, evicts it). The auth
/// handle — owner or platform — is authorized with the empty
/// password session.
pub fn evict_control(auth_handle: u32, object_handle: u32, persistent_handle: u32) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_EVICT_CONTROL);
    buf.extend_from_slice(&auth_handle.to_be_bytes());
    buf.extend_from_slice(&object_handle.to_be_bytes());
    push_password_session(&mut buf);
    buf.extend_from_slice(&persistent_handle.to_be_bytes());
    finalise(&mut buf);
    buf
}

/// Build `TPM2_FlushContext(flushHandle)` — Part 3 §11.4.
///
/// The command-layer builder: the resource-manager bridge
/// previously kept a private copy of this frame in
/// `devfs_bridge`; it delegates here now so the encoding exists
/// exactly once. No sessions, no parameters.
pub fn flush_context(handle: u32) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_FLUSH_CONTEXT);
    buf.extend_from_slice(&handle.to_be_bytes());
    finalise(&mut buf);
    buf
}

/// Build `TPM2_StartAuthSession(tpmKey, bind, nonceCaller,
/// encryptedSalt, sessionType, symmetric, authHash)` — Part 3
/// §11.1.
///
/// This is the session family's front door — #941: sessions were
/// password-only before it, so objects bound to an `authPolicy`
/// had no execution path at all. `tpm_key` / `bind` are
/// `TPM_RH_NULL` for an unbound, unsalted session (the sealing
/// shape). Only the `TPM_ALG_NULL` symmetric definition is
/// encodable here (a TPMT_SYM_DEF is just its algorithm ID in
/// that case); parameter-encryption sessions are follow-up work.
pub fn start_auth_session(
    tpm_key: u32,
    bind: u32,
    nonce_caller: &[u8],
    encrypted_salt: &[u8],
    session_type: u8,
    auth_hash: u16,
) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_START_AUTH_SESSION);
    buf.extend_from_slice(&tpm_key.to_be_bytes());
    buf.extend_from_slice(&bind.to_be_bytes());
    // nonceCaller (TPM2B_NONCE)
    buf.extend_from_slice(&(nonce_caller.len() as u16).to_be_bytes());
    buf.extend_from_slice(nonce_caller);
    // encryptedSalt (TPM2B_ENCRYPTED_SECRET)
    buf.extend_from_slice(&(encrypted_salt.len() as u16).to_be_bytes());
    buf.extend_from_slice(encrypted_salt);
    buf.push(session_type); // TPM_SE
    buf.extend_from_slice(&TPM_ALG_NULL.to_be_bytes()); // symmetric
    buf.extend_from_slice(&auth_hash.to_be_bytes()); // authHash
    finalise(&mut buf);
    buf
}

/// Build `TPM2_PolicyPCR(policySession, pcrDigest, pcrs)` —
/// Part 3 §19.7.
///
/// Updates the session's policyDigest with the named PCRs'
/// expected composite digest; an empty `pcr_digest` means "the
/// PCRs' current values" (the TPM computes it). The authorization
/// area is the policy session itself with `continueSession` set —
/// a policy command is authorized by the session it extends.
pub fn policy_pcr(session_handle: u32, pcr_digest: &[u8], selections: &[(u16, &[u8])]) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_POLICY_PCR);
    buf.extend_from_slice(&session_handle.to_be_bytes());
    // Authorization area: the policy session, continueSession.
    buf.extend_from_slice(&9u32.to_be_bytes());
    buf.extend_from_slice(&session_handle.to_be_bytes());
    buf.extend_from_slice(&0u16.to_be_bytes()); // nonceSize
    buf.push(0x01); // sessionAttributes = continueSession
    buf.extend_from_slice(&0u16.to_be_bytes()); // hmacSize
                                                // pcrDigest (TPM2B_DIGEST)
    buf.extend_from_slice(&(pcr_digest.len() as u16).to_be_bytes());
    buf.extend_from_slice(pcr_digest);
    // TPML_PCR_SELECTION
    buf.extend_from_slice(&(selections.len() as u32).to_be_bytes());
    for (alg, mask) in selections {
        buf.extend_from_slice(&alg.to_be_bytes());
        buf.push(mask.len() as u8);
        buf.extend_from_slice(mask);
    }
    finalise(&mut buf);
    buf
}

/// Build `TPM2_PolicyGetDigest(policySession)` — Part 3
/// (PolicyGetDigest). Returns the session's current
/// policyDigest. Run against a *trial* session it is how an
/// `authPolicy` is computed before the object it will govern
/// exists (the suspend anchor's seal flow, #1002). The command
/// has no authorization area and no parameters — the session
/// handle is its only operand — so it is `TPM_ST_NO_SESSIONS`
/// framed despite naming a session.
pub fn policy_get_digest(session_handle: u32) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_NO_SESSIONS, TPM_CC_POLICY_GET_DIGEST);
    buf.extend_from_slice(&session_handle.to_be_bytes());
    finalise(&mut buf);
    buf
}

/// Build `TPM2_NV_Increment(authHandle, nvIndex)` — Part 3
/// §31.11. The only way a `TPMA_NV_COUNTER` index changes: each
/// successful call adds one and sets `TPMA_NV_WRITTEN` (so the
/// first increment both initializes and advances the counter).
/// `auth_handle` is the index itself (self-auth, empty password
/// session), mirroring `nv_read` / `nv_write`.
pub fn nv_increment(nv_index: u32) -> Vec<u8> {
    let mut buf = begin_command(TPM_ST_SESSIONS, TPM_CC_NV_INCREMENT);
    buf.extend_from_slice(&nv_index.to_be_bytes()); // authHandle
    buf.extend_from_slice(&nv_index.to_be_bytes()); // nvIndex
    push_password_session(&mut buf);
    finalise(&mut buf);
    buf
}

// ── Response parsing ─────────────────────────────────────────────────

/// The response code of a raw response frame, without
/// validating anything else. Callers that must branch on the
/// failure class (the suspend anchor maps `TPM_RC_POLICY_FAIL`
/// to a factor refusal, distinct from a malfunction) read it
/// here; `None` means the frame is too short to carry a code.
pub fn response_rc(raw: &[u8]) -> Option<u32> {
    if raw.len() < 10 {
        return None;
    }
    Some(u32::from_be_bytes([raw[6], raw[7], raw[8], raw[9]]))
}

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

// ── Structured response parsers (#941) ────────────────────────────────
//
// Before this section the layer could parse exactly one response
// (GetRandom); Create/Load/Unseal/NV_Read responses were consumed
// by nobody because nothing could read them. The parsers below
// follow the Part 3 response layouts, including the sessions-tag
// framing (parameterSize-delimited parameters, then the
// authorization area, which these parsers validate by bounds and
// otherwise ignore).

/// Big-endian cursor over a response parameter area.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], &'static str> {
        if self.pos + n > self.buf.len() {
            return Err("response parameter truncated");
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, &'static str> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, &'static str> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Read a TPM2B (u16 size + bytes), returning the inner bytes.
    fn tpm2b(&mut self) -> Result<&'a [u8], &'static str> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}

/// Split a response into `(handle, parameters)`: validates the
/// header/RC via `parse_response`, then, for a sessions-tagged
/// response, reads the response handle (when `has_handle`) and
/// bounds the parameters by `parameterSize`. For a no-sessions
/// response the whole body is the parameter area.
fn response_params(raw: &[u8], has_handle: bool) -> Result<(Option<u32>, &[u8]), &'static str> {
    let body = parse_response(raw)?;
    let tag = u16::from_be_bytes([raw[0], raw[1]]);
    if tag == TPM_ST_NO_SESSIONS {
        return Ok((None, body));
    }
    if tag != TPM_ST_SESSIONS {
        return Err("response tag not a TPM_ST value");
    }
    let mut r = Reader::new(body);
    let handle = if has_handle { Some(r.u32()?) } else { None };
    let psize = r.u32()? as usize;
    let params = r.take(psize)?;
    Ok((handle, params))
}

/// The outputs of `TPM2_Create` / `TPM2_CreatePrimary` (Part 3
/// §12.1/§12.2 share the parameter layout; CreatePrimary adds the
/// object handle in the response handle area).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateOutputs {
    /// TPM2B_PRIVATE — the encrypted sensitive area.
    pub out_private: Vec<u8>,
    /// TPM2B_PUBLIC inner bytes (TPMT_PUBLIC).
    pub out_public: Vec<u8>,
    /// TPM2B_CREATION_DATA inner bytes.
    pub creation_data: Vec<u8>,
    /// TPM2B_DIGEST — the creation hash.
    pub creation_hash: Vec<u8>,
    /// TPMT_TK_CREATION tag (TPM_ST_CREATION = 0x8021 on silicon).
    pub ticket_tag: u16,
    /// TPMT_TK_CREATION hierarchy.
    pub ticket_hierarchy: u32,
    /// TPMT_TK_CREATION digest (TPM2B inner bytes).
    pub ticket_digest: Vec<u8>,
}

fn parse_create_params(params: &[u8]) -> Result<CreateOutputs, &'static str> {
    let mut r = Reader::new(params);
    let out_private = r.tpm2b()?.to_vec();
    let out_public = r.tpm2b()?.to_vec();
    let creation_data = r.tpm2b()?.to_vec();
    let creation_hash = r.tpm2b()?.to_vec();
    let ticket_tag = r.u16()?;
    let ticket_hierarchy = r.u32()?;
    let ticket_digest = r.tpm2b()?.to_vec();
    Ok(CreateOutputs {
        out_private,
        out_public,
        creation_data,
        creation_hash,
        ticket_tag,
        ticket_hierarchy,
        ticket_digest,
    })
}

/// Parse a `TPM2_Create` response.
pub fn parse_create_response(raw: &[u8]) -> Result<CreateOutputs, &'static str> {
    let (_handle, params) = response_params(raw, false)?;
    parse_create_params(params)
}

/// The outputs of `TPM2_CreatePrimary` (Part 3 §12.2). Unlike
/// `TPM2_Create`, CreatePrimary has **no `outPrivate`**: the
/// primary is regenerated from its template on demand, so the
/// response is `outPublic` + creation data directly. (This
/// parser previously read the Create layout — outPrivate first —
/// and the fixture fake emitted the same wrong shape, so the
/// pair agreed with each other and not with Part 3; the
/// attestation lane found the same defect against the keystone
/// model. #1002 fixes the parser, the fake, and the parser
/// fixture together.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreatePrimaryOutputs {
    /// TPM2B_PUBLIC inner bytes (TPMT_PUBLIC).
    pub out_public: Vec<u8>,
    /// TPM2B_CREATION_DATA inner bytes.
    pub creation_data: Vec<u8>,
    /// TPM2B_DIGEST — the creation hash.
    pub creation_hash: Vec<u8>,
    /// TPMT_TK_CREATION tag (TPM_ST_CREATION = 0x8021).
    pub ticket_tag: u16,
    /// TPMT_TK_CREATION hierarchy.
    pub ticket_hierarchy: u32,
    /// TPMT_TK_CREATION digest (TPM2B inner bytes).
    pub ticket_digest: Vec<u8>,
}

/// Parse a `TPM2_CreatePrimary` response: the created object's
/// handle plus its creation outputs (Part 3 §12.2 layout — no
/// outPrivate; see [`CreatePrimaryOutputs`]).
pub fn parse_create_primary_response(
    raw: &[u8],
) -> Result<(u32, CreatePrimaryOutputs), &'static str> {
    let (handle, params) = response_params(raw, true)?;
    let handle = handle.ok_or("create_primary response missing its handle")?;
    let mut r = Reader::new(params);
    let out_public = r.tpm2b()?.to_vec();
    let creation_data = r.tpm2b()?.to_vec();
    let creation_hash = r.tpm2b()?.to_vec();
    let ticket_tag = r.u16()?;
    let ticket_hierarchy = r.u32()?;
    let ticket_digest = r.tpm2b()?.to_vec();
    Ok((
        handle,
        CreatePrimaryOutputs {
            out_public,
            creation_data,
            creation_hash,
            ticket_tag,
            ticket_hierarchy,
            ticket_digest,
        },
    ))
}

/// Parse a `TPM2_PolicyGetDigest` response: the session's
/// current policyDigest (`TPM2B_DIGEST`). The response is
/// no-sessions framed — its whole body is the one parameter.
pub fn parse_policy_get_digest_response(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    let (_handle, params) = response_params(raw, false)?;
    let mut r = Reader::new(params);
    Ok(r.tpm2b()?.to_vec())
}

/// The outputs of `TPM2_PCR_Read` (Part 3 §22.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PcrReadOutputs {
    /// TPMU_COUNTER_VALUE: increments on every PCR update.
    pub pcr_update_counter: u32,
    /// The selection list as returned (algorithm, mask) pairs.
    pub selections: Vec<(u16, Vec<u8>)>,
    /// One digest per selected PCR, in selection order.
    pub digests: Vec<Vec<u8>>,
}

/// Parse a `TPM2_PCR_Read` response (Part 3 §22.6): a u32
/// update counter, a `TPML_PCR_SELECTION`, then a `TPML_DIGEST`
/// of size-prefixed digests — the structural framing of #1065.
/// The extension surface previously had the builder with no
/// parser, so the anchor conversation had no way to read
/// current PCR values through this codec at all.
pub fn parse_pcr_read_response(raw: &[u8]) -> Result<PcrReadOutputs, &'static str> {
    let (_handle, params) = response_params(raw, false)?;
    let mut r = Reader::new(params);
    let pcr_update_counter = r.u32()?;
    let sel_count = r.u32()? as usize;
    let mut selections = Vec::with_capacity(sel_count);
    for _ in 0..sel_count {
        let alg = r.u16()?;
        let size = r.take(1)?[0] as usize;
        let mask = r.take(size)?.to_vec();
        selections.push((alg, mask));
    }
    let digest_count = r.u32()? as usize;
    let mut digests = Vec::with_capacity(digest_count);
    for _ in 0..digest_count {
        digests.push(r.tpm2b()?.to_vec());
    }
    Ok(PcrReadOutputs {
        pcr_update_counter,
        selections,
        digests,
    })
}

/// Parse a `TPM2_Load` response: `(objectHandle, name)`.
pub fn parse_load_response(raw: &[u8]) -> Result<(u32, Vec<u8>), &'static str> {
    let (handle, params) = response_params(raw, true)?;
    let handle = handle.ok_or("load response missing its handle")?;
    let mut r = Reader::new(params);
    let name = r.tpm2b()?.to_vec();
    Ok((handle, name))
}

/// Parse a `TPM2_Unseal` response: the unsealed `outData` bytes.
pub fn parse_unseal_response(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    let (_handle, params) = response_params(raw, false)?;
    let mut r = Reader::new(params);
    Ok(r.tpm2b()?.to_vec())
}

/// Parse a `TPM2_NV_Read` response: the data bytes.
pub fn parse_nv_read_response(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    let (_handle, params) = response_params(raw, false)?;
    let mut r = Reader::new(params);
    Ok(r.tpm2b()?.to_vec())
}

/// Parse a `TPM2_GetTestResult` response: `(outData, testResult)`.
pub fn parse_get_test_result_response(raw: &[u8]) -> Result<(Vec<u8>, u32), &'static str> {
    let (_handle, params) = response_params(raw, false)?;
    let mut r = Reader::new(params);
    let out_data = r.tpm2b()?.to_vec();
    let test_result = r.u32()?;
    Ok((out_data, test_result))
}

/// Parse a `TPM2_StartAuthSession` response: `(sessionHandle,
/// nonceTPM)`. The response is no-sessions framed: the handle
/// sits where a command's first parameter would.
pub fn parse_start_auth_session_response(raw: &[u8]) -> Result<(u32, Vec<u8>), &'static str> {
    let body = parse_response(raw)?;
    let mut r = Reader::new(body);
    let handle = r.u32()?;
    let nonce = r.tpm2b()?.to_vec();
    Ok((handle, nonce))
}

/// A parsed `TPM2_GetCapability` response envelope; `data` is the
/// capability-specific payload, decoded by
/// `parse_tagged_properties` / `parse_pcr_selections` (or the
/// canonical `narf_tpm` parsers — the framing is identical).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetCapabilityResponse {
    pub more_data: bool,
    pub capability: u32,
    pub data: Vec<u8>,
}

/// Parse a `TPM2_GetCapability` response envelope (Part 3 §30.2).
pub fn parse_get_capability_response(raw: &[u8]) -> Result<GetCapabilityResponse, &'static str> {
    let body = parse_response(raw)?;
    if body.len() < 5 {
        return Err("get_capability response too short");
    }
    Ok(GetCapabilityResponse {
        more_data: body[0] != 0,
        capability: u32::from_be_bytes([body[1], body[2], body[3], body[4]]),
        data: body[5..].to_vec(),
    })
}

/// Decode a TPML_TAGGED_TPM_PROPERTY payload (the `data` of a
/// TPM_CAP_TPM_PROPERTIES response) into `(tag, value)` pairs.
pub fn parse_tagged_properties(data: &[u8]) -> Result<Vec<(u32, u32)>, &'static str> {
    let mut r = Reader::new(data);
    let count = r.u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let tag = r.u32()?;
        let value = r.u32()?;
        out.push((tag, value));
    }
    Ok(out)
}

/// Decode a TPML_PCR_SELECTION payload (the `data` of a
/// TPM_CAP_PCRS response) into `(algorithm, pcrSelect)` pairs.
pub fn parse_pcr_selections(data: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, &'static str> {
    let mut r = Reader::new(data);
    let count = r.u32()? as usize;
    let mut out = Vec::with_capacity(count);
    for _ in 0..count {
        let alg = r.u16()?;
        let size = r.take(1)?[0] as usize;
        let mask = r.take(size)?.to_vec();
        out.push((alg, mask));
    }
    Ok(out)
}

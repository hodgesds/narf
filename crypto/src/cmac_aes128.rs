//! CMAC-AES128 (NIST SP 800-38B).
//!
//! CMAC is a block-cipher-based MAC that uses one block cipher
//! (AES-128 here) plus two subkeys K1, K2 derived once at key load.
//! The construction is RFC 4493 (which restates SP 800-38B verbatim
//! with AES bound in).
//!
//! ## References
//!
//! - NIST SP 800-38B §6 — CMAC algorithm specification.
//!   <https://csrc.nist.gov/publications/detail/sp/800-38b/final>
//! - RFC 4493 §2.3, §2.4 — AES-CMAC subkey + MAC generation.
//!   <https://datatracker.ietf.org/doc/html/rfc4493>
//! - FIPS 197 — AES block cipher.
//!   <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf>
//! - IEEE 802.11-2020 §12.5.4.1 — BIP-CMAC-128 cites SP 800-38B.
//!   <https://standards.ieee.org/ieee/802.11/7028/>
//!
//! Used by NARF for 802.11w BIP-CMAC-128 (Management Frame Protection;
//! see `crypto::bip_cmac`) and as the EAPOL-Key MIC AKM for WPA2-PSK
//! with AKM-3 (PSK-SHA256, key-information version `KI_VERSION_AES_128_CMAC`).
//!
//! No GPL Linux source consulted; SP 800-38B + RFC 4493 are the
//! authoritative public references and they're self-contained.

#![allow(dead_code)]

extern crate alloc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;
use alloc::vec::Vec;

/// AES block size in bytes (FIPS 197 §3.4).
pub const AES_BLOCK_LEN: usize = 16;

/// CMAC tag length (full block per SP 800-38B §5.5).
pub const CMAC_TAG_LEN: usize = AES_BLOCK_LEN;

/// GF(2^128) reduction constant for CMAC over AES (block size 128).
/// SP 800-38B §6.1 / RFC 4493 §2.3.
const RB: u8 = 0x87;

/// Compute the two CMAC subkeys (K1, K2) from `aes_key`.
///
/// RFC 4493 §2.3:
///
/// ```text
///     L = AES-128(K, 0^128)
///     if MSB1(L) == 0 then K1 = L << 1
///     else                 K1 = (L << 1) XOR Rb
///     if MSB1(K1) == 0 then K2 = K1 << 1
///     else                  K2 = (K1 << 1) XOR Rb
/// ```
///
/// Returns `(K1, K2)`.
pub fn derive_subkeys(aes_key: &[u8; 16]) -> ([u8; 16], [u8; 16]) {
    let cipher = Aes128::new(GenericArray::from_slice(aes_key));
    let mut l = [0u8; 16];
    let mut blk = GenericArray::clone_from_slice(&l);
    cipher.encrypt_block(&mut blk);
    l.copy_from_slice(blk.as_slice());
    let k1 = gf128_double(&l);
    let k2 = gf128_double(&k1);
    (k1, k2)
}

/// GF(2^128) multiply-by-x (the "double" used to derive K1, K2).
/// SP 800-38B §6.1 — left-shift by one with conditional Rb XOR.
fn gf128_double(b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut carry = 0u8;
    for i in (0..16).rev() {
        let new_carry = (b[i] >> 7) & 1;
        out[i] = (b[i] << 1) | carry;
        carry = new_carry;
    }
    if (b[0] >> 7) & 1 == 1 {
        out[15] ^= RB;
    }
    out
}

/// AES-CMAC. Returns the 16-byte tag over `data` keyed by `aes_key`.
///
/// RFC 4493 §2.4:
///
/// ```text
///     n = ceil(len / 16)
///     if n == 0:
///         n = 1; M_n = pad(empty); use K2
///     else if len is a multiple of 16:
///         M_n = last block; use K1
///     else:
///         M_n = pad(last block); use K2
///     X = 0
///     for i in 1..n-1:  X = AES(K, X XOR M_i)
///     T = AES(K, X XOR M_n XOR (K1 or K2))
/// ```
pub fn cmac_aes128(aes_key: &[u8; 16], data: &[u8]) -> [u8; CMAC_TAG_LEN] {
    let (k1, k2) = derive_subkeys(aes_key);
    cmac_aes128_with_subkeys(aes_key, &k1, &k2, data)
}

/// Variant of `cmac_aes128` that accepts precomputed subkeys, so a
/// caller doing many MACs under the same key pays the AES schedule
/// + subkey derivation cost once. BIP-CMAC's TX/RX paths use this.
pub fn cmac_aes128_with_subkeys(
    aes_key: &[u8; 16],
    k1: &[u8; 16],
    k2: &[u8; 16],
    data: &[u8],
) -> [u8; CMAC_TAG_LEN] {
    let cipher = Aes128::new(GenericArray::from_slice(aes_key));
    let n_blocks = data.len().div_ceil(AES_BLOCK_LEN);

    // RFC 4493 §2.4 step 3: detect "complete last block" case.
    let last_complete = n_blocks > 0 && data.len() % AES_BLOCK_LEN == 0;

    // Compute number of full blocks to feed before the last.
    let full_blocks = if n_blocks == 0 { 0 } else { n_blocks - 1 };

    // Working CBC-MAC state — RFC 4493 calls this X.
    let mut x = [0u8; AES_BLOCK_LEN];

    for i in 0..full_blocks {
        let m = &data[i * AES_BLOCK_LEN..(i + 1) * AES_BLOCK_LEN];
        for b in 0..AES_BLOCK_LEN {
            x[b] ^= m[b];
        }
        let mut blk = GenericArray::clone_from_slice(&x);
        cipher.encrypt_block(&mut blk);
        x.copy_from_slice(blk.as_slice());
    }

    // Build M_n with proper padding + subkey selection.
    let mut m_last = [0u8; AES_BLOCK_LEN];
    if n_blocks == 0 {
        // Empty input: pad ⟨10*⟩ then XOR with K2.
        m_last[0] = 0x80;
        for b in 0..AES_BLOCK_LEN {
            m_last[b] ^= k2[b];
        }
    } else if last_complete {
        let off = full_blocks * AES_BLOCK_LEN;
        m_last.copy_from_slice(&data[off..off + AES_BLOCK_LEN]);
        for b in 0..AES_BLOCK_LEN {
            m_last[b] ^= k1[b];
        }
    } else {
        let off = full_blocks * AES_BLOCK_LEN;
        let tail = &data[off..];
        m_last[..tail.len()].copy_from_slice(tail);
        m_last[tail.len()] = 0x80;
        for b in 0..AES_BLOCK_LEN {
            m_last[b] ^= k2[b];
        }
    }

    for b in 0..AES_BLOCK_LEN {
        x[b] ^= m_last[b];
    }
    let mut blk = GenericArray::clone_from_slice(&x);
    cipher.encrypt_block(&mut blk);
    let mut out = [0u8; CMAC_TAG_LEN];
    out.copy_from_slice(blk.as_slice());
    out
}

/// Constant-time tag comparison. RFC 4493 §3 / NIST SP 800-38B §6.3
/// requires the verify path to compare the computed tag against the
/// presented tag without short-circuiting on the first mismatched
/// byte, to avoid leaking timing.
pub fn verify_cmac_aes128(aes_key: &[u8; 16], data: &[u8], tag: &[u8]) -> bool {
    if tag.len() != CMAC_TAG_LEN {
        return false;
    }
    let computed = cmac_aes128(aes_key, data);
    let mut diff = 0u8;
    for i in 0..CMAC_TAG_LEN {
        diff |= computed[i] ^ tag[i];
    }
    diff == 0
}

/// Truncated CMAC tag — BIP-CMAC-128 specifies a Truncate-128
/// step (it's a no-op for AES-128 since the tag is already 16 bytes,
/// but the function is here so callers don't open-code length math
/// when extending to BIP-CMAC-64 or other variants).
pub fn cmac_aes128_truncated(aes_key: &[u8; 16], data: &[u8], out_len: usize) -> Vec<u8> {
    let full = cmac_aes128(aes_key, data);
    let n = out_len.min(CMAC_TAG_LEN);
    full[..n].to_vec()
}

// ── Tests ───────────────────────────────────────────────────────────

pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // SP 800-38B Appendix D.1 (RFC 4493 §4 Test Vector) — Key:
    //   2b7e1516 28aed2a6 abf71588 09cf4f3c
    const TEST_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];

    // RFC 4493 §4: K1 = fbeed618 35713366 7c85e08f 7236a8de
    fn smoke_cmac_subkey_k1_rfc4493() -> TestResult {
        let (k1, _k2) = derive_subkeys(&TEST_KEY);
        let expected: [u8; 16] = [
            0xfb, 0xee, 0xd6, 0x18, 0x35, 0x71, 0x33, 0x66, 0x7c, 0x85, 0xe0, 0x8f, 0x72, 0x36,
            0xa8, 0xde,
        ];
        if k1 != expected {
            return TestResult::Fail("K1 mismatch with RFC 4493 vector");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/cmac", smoke_cmac_subkey_k1_rfc4493);

    // RFC 4493 §4 / SP 800-38B D.1 Example 1: empty message →
    //   bb1d6929 e9593728 7fa37d12 9b756746
    fn smoke_cmac_empty_message() -> TestResult {
        let tag = cmac_aes128(&TEST_KEY, &[]);
        let expected: [u8; 16] = [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
            0x67, 0x46,
        ];
        if tag != expected {
            return TestResult::Fail("CMAC(empty) mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/cmac", smoke_cmac_empty_message);

    // RFC 4493 §4 Example 2: 16-byte message
    //   6bc1bee2 2e409f96 e93d7e11 7393172a →
    //   070a16b4 6b4d4144 f79bdd9d d04a287c
    fn smoke_cmac_one_block_message() -> TestResult {
        let msg: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let tag = cmac_aes128(&TEST_KEY, &msg);
        let expected: [u8; 16] = [
            0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a,
            0x28, 0x7c,
        ];
        if tag != expected {
            return TestResult::Fail("CMAC(1-block) mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/cmac", smoke_cmac_one_block_message);

    // RFC 4493 §4 Example 3: 40-byte message — partial last block.
    fn smoke_cmac_partial_last_block() -> TestResult {
        let msg: [u8; 40] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
        ];
        let tag = cmac_aes128(&TEST_KEY, &msg);
        let expected: [u8; 16] = [
            0xdf, 0xa6, 0x67, 0x47, 0xde, 0x9a, 0xe6, 0x30, 0x30, 0xca, 0x32, 0x61, 0x14, 0x97,
            0xc8, 0x27,
        ];
        if tag != expected {
            return TestResult::Fail("CMAC(40-byte) mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/cmac", smoke_cmac_partial_last_block);

    fn smoke_cmac_verify_constant_time_path() -> TestResult {
        let msg: [u8; 16] = [0x55u8; 16];
        let tag = cmac_aes128(&TEST_KEY, &msg);
        if !verify_cmac_aes128(&TEST_KEY, &msg, &tag) {
            return TestResult::Fail("verify rejected valid tag");
        }
        let mut bad = tag;
        bad[0] ^= 0x01;
        if verify_cmac_aes128(&TEST_KEY, &msg, &bad) {
            return TestResult::Fail("verify accepted tampered tag");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/cmac", smoke_cmac_verify_constant_time_path);
}

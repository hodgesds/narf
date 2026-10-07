//! AES-SIV (RFC 5297) deterministic authenticated encryption.
//!
//! Built from the AES-128-CMAC and AES-CTR primitives already in this crate.
//! WPA3 SAE-PK uses AES-SIV (with the SAE KEK, no associated data) to carry
//! the encrypted Modifier in the SAE-PK element, so only the 256-bit key case
//! (two 128-bit halves) is needed; the implementation is written for the
//! general single-plaintext / vector-of-AAD form so it can be validated
//! against the RFC 5297 Appendix A.1 test vector.

extern crate alloc;

use alloc::vec::Vec;

use crate::aes_ctr::ctr_apply;
use crate::cmac_aes128::cmac_aes128;

const BLOCK: usize = 16;

/// GF(2^128) doubling (RFC 5297 §2.3 `dbl`).
fn dbl(input: &[u8; BLOCK]) -> [u8; BLOCK] {
    let msb = input[0] >> 7;
    let mut out = [0u8; BLOCK];
    let mut carry = 0u8;
    for i in (0..BLOCK).rev() {
        out[i] = (input[i] << 1) | carry;
        carry = input[i] >> 7;
    }
    if msb == 1 {
        out[BLOCK - 1] ^= 0x87;
    }
    out
}

fn xor_block(dst: &mut [u8; BLOCK], src: &[u8; BLOCK]) {
    for (d, s) in dst.iter_mut().zip(src.iter()) {
        *d ^= *s;
    }
}

/// S2V (RFC 5297 §2.4) over the associated-data strings `aad` followed by the
/// `plaintext` as the final vector component. The 128-bit key half `k1` is the
/// CMAC key.
fn s2v(k1: &[u8; 16], aad: &[&[u8]], plaintext: &[u8]) -> [u8; BLOCK] {
    // S2V of the empty vector is CMAC(K, <one>).
    if aad.is_empty() && plaintext.is_empty() {
        let mut one = [0u8; BLOCK];
        one[BLOCK - 1] = 1;
        return cmac_aes128(k1, &one);
    }
    let mut d = cmac_aes128(k1, &[0u8; BLOCK]);
    for s in aad {
        let mut doubled = dbl(&d);
        xor_block(&mut doubled, &cmac_aes128(k1, s));
        d = doubled;
    }
    if plaintext.len() >= BLOCK {
        // T = plaintext xorend D (XOR D into the final block).
        let mut t = plaintext.to_vec();
        let off = t.len() - BLOCK;
        for (i, db) in d.iter().enumerate() {
            t[off + i] ^= *db;
        }
        cmac_aes128(k1, &t)
    } else {
        // T = dbl(D) XOR pad(plaintext).
        let mut t = dbl(&d);
        for (i, p) in plaintext.iter().enumerate() {
            t[i] ^= *p;
        }
        t[plaintext.len()] ^= 0x80;
        cmac_aes128(k1, &t)
    }
}

/// Mask the SIV (V) into the AES-CTR initial counter Q by clearing the top bit
/// of the last two 32-bit words (RFC 5297 §2.5/§2.6).
fn ctr_iv(v: &[u8; BLOCK]) -> [u8; BLOCK] {
    let mut q = *v;
    q[8] &= 0x7f;
    q[12] &= 0x7f;
    q
}

/// AES-SIV encrypt. `key` is 32 bytes (K1 = key[..16] for S2V, K2 = key[16..]
/// for CTR). Returns `V || ciphertext` (ciphertext is the plaintext length plus
/// the 16-byte synthetic IV).
pub fn encrypt(key: &[u8; 32], aad: &[&[u8]], plaintext: &[u8]) -> Vec<u8> {
    let k1: &[u8; 16] = key[..16].try_into().unwrap();
    let k2: &[u8; 16] = key[16..].try_into().unwrap();
    let v = s2v(k1, aad, plaintext);
    let mut buf = plaintext.to_vec();
    ctr_apply(k2, ctr_iv(&v), &mut buf);
    let mut out = Vec::with_capacity(BLOCK + buf.len());
    out.extend_from_slice(&v);
    out.extend_from_slice(&buf);
    out
}

/// AES-SIV decrypt. Returns the plaintext only when the synthetic IV verifies;
/// `None` on any authentication failure or malformed input.
pub fn decrypt(key: &[u8; 32], aad: &[&[u8]], input: &[u8]) -> Option<Vec<u8>> {
    if input.len() < BLOCK {
        return None;
    }
    let k1: &[u8; 16] = key[..16].try_into().unwrap();
    let k2: &[u8; 16] = key[16..].try_into().unwrap();
    let v: [u8; BLOCK] = input[..BLOCK].try_into().unwrap();
    let mut plaintext = input[BLOCK..].to_vec();
    ctr_apply(k2, ctr_iv(&v), &mut plaintext);
    let expected = s2v(k1, aad, &plaintext);
    // Constant-time tag comparison.
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(v.iter()) {
        diff |= a ^ b;
    }
    if diff == 0 {
        Some(plaintext)
    } else {
        None
    }
}

pub mod aes_siv_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // RFC 5297 Appendix A.1 deterministic authenticated-encryption vector.
    const KEY: [u8; 32] = [
        0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8, 0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1,
        0xf0, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd,
        0xfe, 0xff,
    ];
    const AD: [u8; 24] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    ];
    const PLAINTEXT: [u8; 14] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
    ];
    const OUTPUT: [u8; 30] = [
        0x85, 0x63, 0x2d, 0x07, 0xc6, 0xe8, 0xf3, 0x7f, 0x95, 0x0a, 0xcd, 0x32, 0x0a, 0x2e, 0xcc,
        0x93, 0x40, 0xc0, 0x2b, 0x96, 0x90, 0xc4, 0xdc, 0x04, 0xda, 0xef, 0x7f, 0x6a, 0xfe, 0x5c,
    ];

    fn smoke_aes_siv_rfc5297_a1() -> TestResult {
        let ct = encrypt(&KEY, &[&AD[..]], &PLAINTEXT);
        if ct != OUTPUT {
            return TestResult::Fail("AES-SIV encrypt mismatch vs RFC 5297 A.1");
        }
        match decrypt(&KEY, &[&AD[..]], &OUTPUT) {
            Some(pt) if pt == PLAINTEXT => {}
            _ => return TestResult::Fail("AES-SIV decrypt did not recover the plaintext"),
        }
        // A corrupted synthetic IV must fail authentication.
        let mut tampered = OUTPUT;
        tampered[0] ^= 0x01;
        if decrypt(&KEY, &[&AD[..]], &tampered).is_some() {
            return TestResult::Fail("AES-SIV accepted a tampered SIV");
        }
        // Wrong associated data must fail authentication.
        let mut bad_ad = AD;
        bad_ad[0] ^= 0x01;
        if decrypt(&KEY, &[&bad_ad[..]], &OUTPUT).is_some() {
            return TestResult::Fail("AES-SIV accepted wrong associated data");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/aes_siv", smoke_aes_siv_rfc5297_a1);

    fn smoke_aes_siv_no_aad_roundtrip() -> TestResult {
        // The SAE-PK usage: a single 16-byte plaintext (the Modifier), no AAD.
        let modifier = [0x5au8; 16];
        let ct = encrypt(&KEY, &[], &modifier);
        if ct.len() != 32 {
            return TestResult::Fail("SAE-PK AES-SIV output is not 32 bytes");
        }
        match decrypt(&KEY, &[], &ct) {
            Some(pt) if pt == modifier => TestResult::Pass,
            _ => TestResult::Fail("no-AAD AES-SIV round trip failed"),
        }
    }
    kernel_test_in!("crypto/aes_siv", smoke_aes_siv_no_aad_roundtrip);
}

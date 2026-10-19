//! AES Key Wrap (RFC 3394) with a 128-bit KEK.
//!
//! The EAPOL-Key Key Data encryption of IEEE 802.11-2020 §12.7.2 (Key
//! Descriptor Versions 2 and 3: "AES Key Wrap, defined in IETF RFC 3394")
//! — what wpa_supplicant's `aes_unwrap` / hostapd's `aes_wrap` do for the
//! GTK / IGTK KDEs of 4-way message 3 and Group Key message 1.
//!
//! ## References
//!
//! - RFC 3394 §2.2.1 (wrap), §2.2.2 (unwrap), §2.2.3.1 (default IV),
//!   §4.1 (the 128-bit KEK / 128-bit key data test vector).
//!   <https://datatracker.ietf.org/doc/html/rfc3394>
//! - NIST SP 800-38F §6.2 (KW).

extern crate alloc;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use alloc::vec::Vec;

/// RFC 3394 §2.2.3.1 default initial value.
pub const AES_KW_IV: [u8; 8] = [0xA6; 8];

/// RFC 3394 §2.2.1 `W`: wrap `plain` (a multiple of 8 bytes, at least
/// 16) under `kek`. `None` for an invalid length.
pub fn aes_wrap(kek: &[u8; 16], plain: &[u8]) -> Option<Vec<u8>> {
    if plain.len() < 16 || plain.len() % 8 != 0 {
        return None;
    }
    let cipher = Aes128::new(GenericArray::from_slice(kek));
    let n = plain.len() / 8;
    let mut a = AES_KW_IV;
    let mut r: Vec<[u8; 8]> = plain
        .chunks_exact(8)
        .map(|c| {
            let mut b = [0u8; 8];
            b.copy_from_slice(c);
            b
        })
        .collect();
    for j in 0..6u64 {
        for (i, ri) in r.iter_mut().enumerate() {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(ri);
            let blk = GenericArray::from_mut_slice(&mut b);
            cipher.encrypt_block(blk);
            let t = (n as u64) * j + i as u64 + 1;
            for (x, (y, z)) in a.iter_mut().zip(b[..8].iter().zip(t.to_be_bytes().iter())) {
                *x = y ^ z;
            }
            ri.copy_from_slice(&b[8..]);
        }
    }
    let mut out = Vec::with_capacity(8 + plain.len());
    out.extend_from_slice(&a);
    for b in r {
        out.extend_from_slice(&b);
    }
    Some(out)
}

/// RFC 3394 §2.2.2 `W⁻¹`: unwrap `wrapped` (a multiple of 8 bytes, at
/// least 24) under `kek`. `None` for an invalid length or when the
/// integrity check value is not [`AES_KW_IV`].
pub fn aes_unwrap(kek: &[u8; 16], wrapped: &[u8]) -> Option<Vec<u8>> {
    if wrapped.len() < 24 || wrapped.len() % 8 != 0 {
        return None;
    }
    let cipher = Aes128::new(GenericArray::from_slice(kek));
    let n = wrapped.len() / 8 - 1;
    let mut a = [0u8; 8];
    a.copy_from_slice(&wrapped[..8]);
    let mut r: Vec<[u8; 8]> = wrapped[8..]
        .chunks_exact(8)
        .map(|c| {
            let mut b = [0u8; 8];
            b.copy_from_slice(c);
            b
        })
        .collect();
    for j in (0..6u64).rev() {
        for i in (0..n).rev() {
            let t = (n as u64) * j + i as u64 + 1;
            let mut b = [0u8; 16];
            for (x, (y, z)) in b[..8].iter_mut().zip(a.iter().zip(t.to_be_bytes().iter())) {
                *x = y ^ z;
            }
            b[8..].copy_from_slice(&r[i]);
            let blk = GenericArray::from_mut_slice(&mut b);
            cipher.decrypt_block(blk);
            a.copy_from_slice(&b[..8]);
            r[i].copy_from_slice(&b[8..]);
        }
    }
    // Constant-time comparison of the integrity check value.
    let diff = a
        .iter()
        .zip(AES_KW_IV.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y));
    if diff != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(n * 8);
    for b in r {
        out.extend_from_slice(&b);
    }
    Some(out)
}

// ── Tests ───────────────────────────────────────────────────────────

pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    /// RFC 3394 §4.1: KEK 000102…0F, key data 00112233…FF.
    const KEK: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];
    const KEY_DATA: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    const CIPHERTEXT: [u8; 24] = [
        0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A, 0x7B,
        0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
    ];

    fn smoke_aes_kw_rfc3394_4_1() -> TestResult {
        if aes_wrap(&KEK, &KEY_DATA).as_deref() != Some(&CIPHERTEXT[..]) {
            return TestResult::Fail("RFC 3394 §4.1 wrap");
        }
        if aes_unwrap(&KEK, &CIPHERTEXT).as_deref() != Some(&KEY_DATA[..]) {
            return TestResult::Fail("RFC 3394 §4.1 unwrap");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/aes_kw", smoke_aes_kw_rfc3394_4_1);

    fn smoke_aes_kw_rejects() -> TestResult {
        let mut bad = CIPHERTEXT;
        bad[0] ^= 1;
        if aes_unwrap(&KEK, &bad).is_some() {
            return TestResult::Fail("tampered ICV accepted");
        }
        let mut k = KEK;
        k[15] ^= 1;
        if aes_unwrap(&k, &CIPHERTEXT).is_some() {
            return TestResult::Fail("wrong KEK accepted");
        }
        if aes_unwrap(&KEK, &CIPHERTEXT[..16]).is_some()
            || aes_unwrap(&KEK, &CIPHERTEXT[..23]).is_some()
            || aes_wrap(&KEK, &KEY_DATA[..8]).is_some()
            || aes_wrap(&KEK, &KEY_DATA[..12]).is_some()
        {
            return TestResult::Fail("invalid lengths accepted");
        }
        // Round trip of a 32-byte payload (GTK KDE + padding size).
        let p: Vec<u8> = (0u8..32).collect();
        let w = match aes_wrap(&KEK, &p) {
            Some(w) => w,
            None => return TestResult::Fail("wrap 32 bytes"),
        };
        if w.len() != 40 || aes_unwrap(&KEK, &w).as_deref() != Some(&p[..]) {
            return TestResult::Fail("32-byte round trip");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/aes_kw", smoke_aes_kw_rejects);
}

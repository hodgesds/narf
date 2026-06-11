//! # Cleanroom HKDF-SHA-256 Implementation
//!
//! Implementation of HMAC-based Key Derivation Function according to RFC 5869.
//! Reference: <https://datatracker.ietf.org/doc/html/rfc5869>

use crate::sha256::Sha256;

/// HMAC-SHA-256 implementation.
/// Reference: <https://datatracker.ietf.org/doc/html/rfc2104>
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let mut hasher = Sha256::new();
        hasher.update(key);
        let hash = hasher.finalize();
        k[..32].copy_from_slice(&hash);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0u32; 16];
    let mut opad = [0u32; 16];
    for i in 0..16 {
        let word = u32::from_ne_bytes([k[i * 4], k[i * 4 + 1], k[i * 4 + 2], k[i * 4 + 3]]);
        ipad[i] = word ^ 0x36363636;
        opad[i] = word ^ 0x5c5c5c5c;
    }

    // Note: The above XOR logic assumes 32-bit words for efficiency,
    // but we can just use bytes for simplicity and to match the RFC exactly.
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner_hasher = Sha256::new();
    inner_hasher.update(&ipad);
    inner_hasher.update(data);
    let inner_hash = inner_hasher.finalize();

    let mut outer_hasher = Sha256::new();
    outer_hasher.update(&opad);
    outer_hasher.update(&inner_hash);
    outer_hasher.finalize()
}

/// HKDF-Extract(salt, IKM) -> PRK
/// Reference: <https://datatracker.ietf.org/doc/html/rfc5869#section-2.2>
pub fn hkdf_extract(salt: Option<&[u8]>, ikm: &[u8]) -> [u8; 32] {
    let salt = salt.unwrap_or(&[0u8; 32]);
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand(PRK, info, L) -> OKM
/// Reference: <https://datatracker.ietf.org/doc/html/rfc5869#section-2.3>
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], l: usize) -> alloc::vec::Vec<u8> {
    let n = l.div_ceil(32);
    let mut okm = alloc::vec::Vec::with_capacity(n * 32);
    let mut t = alloc::vec::Vec::new();

    for i in 1..=(n as u8) {
        let mut data = alloc::vec::Vec::with_capacity(t.len() + info.len() + 1);
        data.extend_from_slice(&t);
        data.extend_from_slice(info);
        data.push(i);

        let hash = hmac_sha256(prk, &data);
        t = hash.to_vec();
        okm.extend_from_slice(&t);
    }

    okm.truncate(l);
    okm
}

//! # Cleanroom ChaCha20-Poly1305 AEAD Implementation
//!
//! Implementation of the ChaCha20-Poly1305 authenticated encryption with
//! associated data (AEAD) according to RFC 8439.
//! Reference: <https://datatracker.ietf.org/doc/html/rfc8439#section-2.8>
//! Reference: <https://en.wikipedia.org/wiki/Poly1305>

use crate::clean::chacha20::{chacha20_block, chacha20_init, chacha20_xor};
use crate::clean::poly1305::Poly1305;

/// ChaCha20-Poly1305 AEAD seal.
/// Reference: <https://datatracker.ietf.org/doc/html/rfc8439#section-2.8>
pub fn chacha20_poly1305_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &mut [u8],
) -> [u8; 16] {
    // 1. Generate Poly1305 key from ChaCha20 block 0
    let mut poly_key = [0u8; 64];
    let state = chacha20_init(key, nonce, 0);
    chacha20_block(&state, &mut poly_key);

    let mut poly = Poly1305::new(poly_key[..32].try_into().unwrap());

    // 2. Encrypt plaintext (starting from counter 1)
    chacha20_xor(key, nonce, 1, plaintext);

    // 3. Authenticate AAD, Ciphertext, and their lengths
    poly.update(aad);
    if aad.len() % 16 != 0 {
        poly.update(&[0u8; 16][..(16 - (aad.len() % 16))]);
    }

    poly.update(plaintext);
    if plaintext.len() % 16 != 0 {
        poly.update(&[0u8; 16][..(16 - (plaintext.len() % 16))]);
    }

    poly.update(&(aad.len() as u64).to_le_bytes());
    poly.update(&(plaintext.len() as u64).to_le_bytes());

    poly.finalize()
}

/// ChaCha20-Poly1305 AEAD open.
/// Reference: <https://datatracker.ietf.org/doc/html/rfc8439#section-2.8>
pub fn chacha20_poly1305_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &mut [u8],
    tag: &[u8; 16],
) -> bool {
    // 1. Generate Poly1305 key
    let mut poly_key = [0u8; 64];
    let state = chacha20_init(key, nonce, 0);
    chacha20_block(&state, &mut poly_key);

    let mut poly = Poly1305::new(poly_key[..32].try_into().unwrap());

    // 2. Authenticate
    poly.update(aad);
    if aad.len() % 16 != 0 {
        poly.update(&[0u8; 16][..(16 - (aad.len() % 16))]);
    }

    poly.update(ciphertext);
    if ciphertext.len() % 16 != 0 {
        poly.update(&[0u8; 16][..(16 - (ciphertext.len() % 16))]);
    }

    poly.update(&(aad.len() as u64).to_le_bytes());
    poly.update(&(ciphertext.len() as u64).to_le_bytes());

    let computed_tag = poly.finalize();

    // Constant-time comparison
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= computed_tag[i] ^ tag[i];
    }

    if diff == 0 {
        // 3. Decrypt on success
        chacha20_xor(key, nonce, 1, ciphertext);
        true
    } else {
        false
    }
}

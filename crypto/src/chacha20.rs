//! # Cleanroom ChaCha20 Implementation
//!
//! Implementation of the ChaCha20 stream cipher according to RFC 8439.
//! Reference: <https://datatracker.ietf.org/doc/html/rfc8439>

#![allow(dead_code)]

/// The ChaCha quarter-round function.
/// Reference: <https://datatracker.ietf.org/doc/html/rfc8439#section-2.1>
#[inline(always)]
fn quarter_round(a: &mut u32, b: &mut u32, c: &mut u32, d: &mut u32) {
    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(16);

    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(12);

    *a = a.wrapping_add(*b);
    *d ^= *a;
    *d = d.rotate_left(8);

    *c = c.wrapping_add(*d);
    *b ^= *c;
    *b = b.rotate_left(7);
}

/// The ChaCha20 block function.
/// Reference: <https://datatracker.ietf.org/doc/html/rfc8439#section-2.3>
///
/// Transforms a 64-byte state into a 64-byte keystream block.
pub fn chacha20_block(state: &[u32; 16], out: &mut [u8; 64]) {
    let mut x = *state;

    // 10 iterations of 8 quarter-rounds each (20 rounds total)
    // Reference: <https://datatracker.ietf.org/doc/html/rfc8439#section-2.3.1>
    for _ in 0..10 {
        // Column rounds
        let (mut a, mut b, mut c, mut d) = (x[0], x[4], x[8], x[12]);
        quarter_round(&mut a, &mut b, &mut c, &mut d);
        x[0] = a;
        x[4] = b;
        x[8] = c;
        x[12] = d;

        let (mut a, mut b, mut c, mut d) = (x[1], x[5], x[9], x[13]);
        quarter_round(&mut a, &mut b, &mut c, &mut d);
        x[1] = a;
        x[5] = b;
        x[9] = c;
        x[13] = d;

        let (mut a, mut b, mut c, mut d) = (x[2], x[6], x[10], x[14]);
        quarter_round(&mut a, &mut b, &mut c, &mut d);
        x[2] = a;
        x[6] = b;
        x[10] = c;
        x[14] = d;

        let (mut a, mut b, mut c, mut d) = (x[3], x[7], x[11], x[15]);
        quarter_round(&mut a, &mut b, &mut c, &mut d);
        x[3] = a;
        x[7] = b;
        x[11] = c;
        x[15] = d;

        // Diagonal rounds
        let (mut a, mut b, mut c, mut d) = (x[0], x[5], x[10], x[15]);
        quarter_round(&mut a, &mut b, &mut c, &mut d);
        x[0] = a;
        x[5] = b;
        x[10] = c;
        x[15] = d;

        let (mut a, mut b, mut c, mut d) = (x[1], x[6], x[11], x[12]);
        quarter_round(&mut a, &mut b, &mut c, &mut d);
        x[1] = a;
        x[6] = b;
        x[11] = c;
        x[12] = d;

        let (mut a, mut b, mut c, mut d) = (x[2], x[7], x[8], x[13]);
        quarter_round(&mut a, &mut b, &mut c, &mut d);
        x[2] = a;
        x[7] = b;
        x[8] = c;
        x[13] = d;

        let (mut a, mut b, mut c, mut d) = (x[3], x[4], x[9], x[14]);
        quarter_round(&mut a, &mut b, &mut c, &mut d);
        x[3] = a;
        x[4] = b;
        x[9] = c;
        x[14] = d;
    }

    // Add the original state to the result
    // Reference: <https://datatracker.ietf.org/doc/html/rfc8439#section-2.3>
    for i in 0..16 {
        let val = x[i].wrapping_add(state[i]);
        let bytes = val.to_le_bytes();
        out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
}

/// ChaCha20 state initialization.
/// Reference: <https://datatracker.ietf.org/doc/html/rfc8439#section-2.3>
pub fn chacha20_init(key: &[u8; 32], nonce: &[u8; 12], counter: u32) -> [u32; 16] {
    let mut state = [0u32; 16];

    // The first four words are constants: "expa", "nd 3", "2-by", "te k"
    // Reference: <https://datatracker.ietf.org/doc/html/rfc8439#section-2.3>
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    // The next eight words are taken from the 256-bit key
    for i in 0..8 {
        state[4 + i] =
            u32::from_le_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
    }

    // Word 12 is the block counter
    state[12] = counter;

    // Words 13, 14, and 15 are the nonce
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }

    state
}

/// ChaCha20 encryption/decryption function.
/// Reference: <https://datatracker.ietf.org/doc/html/rfc8439#section-2.4>
pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut state = chacha20_init(key, nonce, counter);
    let mut block = [0u8; 64];

    let chunks = data.chunks_mut(64);
    for chunk in chunks {
        chacha20_block(&state, &mut block);

        for i in 0..chunk.len() {
            chunk[i] ^= block[i];
        }

        // Increment the counter
        state[12] = state[12].wrapping_add(1);
    }
}

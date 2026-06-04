//! # Cleanroom Poly1305 Implementation
//!
//! Implementation of the Poly1305 message authentication code according to RFC 8439.
//! Reference: <https://datatracker.ietf.org/doc/html/rfc8439#section-2.5>
//! Reference: <https://en.wikipedia.org/wiki/Poly1305>
//!
//! Poly1305 is a one-time authenticator that computes a 128-bit tag for a message
//! using a 256-bit key. The key is split into two 128-bit parts: r and s.
//! The algorithm computes (h + s) mod 2^128, where h is the evaluation of a
//! polynomial in r modulo 2^130 - 5.

#![allow(dead_code)]

/// A field element in GF(2^130 - 5).
/// Represented as 5 26-bit limbs to prevent 64-bit overflow during multiplication.
/// Base field prime P = 2^130 - 5.
#[derive(Clone, Copy, Debug, Default)]
struct FieldElement([u32; 5]);

impl FieldElement {
    const ZERO: Self = FieldElement([0; 5]);

    /// Create a field element from a 16-byte little-endian array.
    fn from_bytes(bytes: &[u8; 16]) -> Self {
        let mut limbs = [0u32; 5];
        let t0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let t1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());

        // Extract 26-bit limbs from the 128-bit integer
        limbs[0] = (t0 & 0x3ffffff) as u32;
        limbs[1] = ((t0 >> 26) & 0x3ffffff) as u32;
        limbs[2] = ((t0 >> 52) | ((t1 & 0x3fff) << 12)) as u32;
        limbs[3] = ((t1 >> 14) & 0x3ffffff) as u32;
        limbs[4] = (t1 >> 40) as u32;

        FieldElement(limbs)
    }

    /// Create a field element from a 17-byte padded block.
    /// This handles the "1" bit appended to each message block.
    fn from_bytes_padded(bytes: &[u8; 17]) -> Self {
        let mut limbs = [0u32; 5];
        let t0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let t1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let t2 = bytes[16] as u64;

        limbs[0] = (t0 & 0x3ffffff) as u32;
        limbs[1] = ((t0 >> 26) & 0x3ffffff) as u32;
        limbs[2] = ((t0 >> 52) | ((t1 & 0x3fff) << 12)) as u32;
        limbs[3] = ((t1 >> 14) & 0x3ffffff) as u32;
        limbs[4] = ((t1 >> 40) | (t2 << 24)) as u32;

        FieldElement(limbs)
    }

    /// Convert the field element back to a 16-byte array.
    /// This performs a full reduction modulo 2^130 - 5 and conditional subtraction.
    fn to_bytes(self) -> [u8; 16] {
        let mut limbs = self.0;

        // Partial reduction: h = h mod 2^130 - 5
        let mut carry = limbs[0] >> 26;
        limbs[0] &= 0x3ffffff;
        limbs[1] += carry;
        carry = limbs[1] >> 26;
        limbs[1] &= 0x3ffffff;
        limbs[2] += carry;
        carry = limbs[2] >> 26;
        limbs[2] &= 0x3ffffff;
        limbs[3] += carry;
        carry = limbs[3] >> 26;
        limbs[3] &= 0x3ffffff;
        limbs[4] += carry;
        carry = limbs[4] >> 26;
        limbs[4] &= 0x3ffffff;
        limbs[0] += carry * 5;

        // Full reduction: ensuring h < P
        let mut carry = limbs[0] >> 26;
        limbs[0] &= 0x3ffffff;
        limbs[1] += carry;

        let mut g = [0u32; 5];
        g[0] = limbs[0] + 5;
        carry = g[0] >> 26;
        g[0] &= 0x3ffffff;
        g[1] = limbs[1] + carry;
        carry = g[1] >> 26;
        g[1] &= 0x3ffffff;
        g[2] = limbs[2] + carry;
        carry = g[2] >> 26;
        g[2] &= 0x3ffffff;
        g[3] = limbs[3] + carry;
        carry = g[3] >> 26;
        g[3] &= 0x3ffffff;
        g[4] = limbs[4] + carry;

        // Constant-time conditional selection: limbs = g if g >= 2^130 else limbs
        let mask = (g[4] >> 26).wrapping_neg();
        for i in 0..5 {
            limbs[i] = (limbs[i] & !mask) | (g[i] & mask);
        }
        limbs[4] &= 0x3ffffff;

        // Reconstruct 128 bits from 26-bit limbs
        let mut res = [0u8; 16];
        let t0 = limbs[0] as u64 | ((limbs[1] as u64) << 26) | ((limbs[2] as u64) << 52);
        let t1 = (limbs[2] >> 12) as u64 | ((limbs[3] as u64) << 14) | ((limbs[4] as u64) << 40);
        res[0..8].copy_from_slice(&t0.to_le_bytes());
        res[8..16].copy_from_slice(&t1.to_le_bytes());
        res
    }

    /// Field addition.
    fn add(self, rhs: Self) -> Self {
        let mut res = [0u32; 5];
        for i in 0..5 {
            res[i] = self.0[i] + rhs.0[i];
        }
        FieldElement(res)
    }

    /// Field multiplication modulo 2^130 - 5.
    fn mul(self, rhs: Self) -> Self {
        let mut r = [0u64; 9];
        // Full schoolbook multiplication
        for i in 0..5 {
            for j in 0..5 {
                r[i + j] += self.0[i] as u64 * rhs.0[j] as u64;
            }
        }

        // Modular reduction: 2^130 is 5 mod P
        let mut limbs = [0u32; 5];
        limbs[0] = (r[0] & 0x3ffffff) as u32;
        let mut carry = r[0] >> 26;
        r[1] += carry;
        limbs[1] = (r[1] & 0x3ffffff) as u32;
        carry = r[1] >> 26;
        r[2] += carry;
        limbs[2] = (r[2] & 0x3ffffff) as u32;
        carry = r[2] >> 26;
        r[3] += carry;
        limbs[3] = (r[3] & 0x3ffffff) as u32;
        carry = r[3] >> 26;
        r[4] += carry;
        limbs[4] = (r[4] & 0x3ffffff) as u32;
        carry = r[4] >> 26;

        // Limbs 5-8 represent bits above 2^130
        let mut r5 = r[5] + carry;
        let mut r6 = r[6] + (r5 >> 26);
        r5 &= 0x3ffffff;
        let mut r7 = r[7] + (r6 >> 26);
        r6 &= 0x3ffffff;
        let mut r8 = r[8] + (r7 >> 26);
        r7 &= 0x3ffffff;
        let r9 = r8 >> 26;
        r8 &= 0x3ffffff;

        // Multiply bits above 2^130 by 5 and add back
        limbs[0] = limbs[0].wrapping_add((r5 * 5) as u32);
        limbs[1] = limbs[1].wrapping_add((r6 * 5) as u32);
        limbs[2] = limbs[2].wrapping_add((r7 * 5) as u32);
        limbs[3] = limbs[3].wrapping_add((r8 * 5) as u32);
        limbs[4] = limbs[4].wrapping_add((r9 * 5) as u32);

        FieldElement(limbs)
    }
}

/// Poly1305 state machine.
#[derive(Debug)]
pub struct Poly1305 {
    h: FieldElement,
    r: FieldElement,
    s: [u32; 4],
    buffer: [u8; 16],
    buffer_len: usize,
}

impl Poly1305 {
    /// Initialize Poly1305 with a 32-byte key.
    /// The first 16 bytes are 'r', the second 16 bytes are 's'.
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r_bytes = [0u8; 16];
        r_bytes.copy_from_slice(&key[0..16]);

        // Clamping r as required by RFC 8439 Section 2.5
        r_bytes[3] &= 15;
        r_bytes[7] &= 15;
        r_bytes[11] &= 15;
        r_bytes[15] &= 15;
        r_bytes[4] &= 252;
        r_bytes[8] &= 252;
        r_bytes[12] &= 252;

        let r = FieldElement::from_bytes(&r_bytes);
        let mut s = [0u32; 4];
        for i in 0..4 {
            s[i] = u32::from_le_bytes(key[16 + i * 4..20 + i * 4].try_into().unwrap());
        }

        Self {
            h: FieldElement::ZERO,
            r,
            s,
            buffer: [0; 16],
            buffer_len: 0,
        }
    }

    /// Process a 16-byte block.
    fn process_block(&mut self, block: &[u8]) {
        let mut b = [0u8; 17];
        let len = block.len();
        b[..len].copy_from_slice(block);
        b[len] = 1; // Appending the "1" bit

        let msg = FieldElement::from_bytes_padded(&b);
        // h = ((h + m) * r) % P
        self.h = self.h.add(msg).mul(self.r);
    }

    /// Update the state with variable-length data.
    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;
        while pos < data.len() {
            let take = core::cmp::min(16 - self.buffer_len, data.len() - pos);
            self.buffer[self.buffer_len..self.buffer_len + take]
                .copy_from_slice(&data[pos..pos + take]);
            self.buffer_len += take;
            pos += take;
            if self.buffer_len == 16 {
                let buf = self.buffer;
                self.process_block(&buf);
                self.buffer_len = 0;
            }
        }
    }

    /// Finalize the authentication tag.
    pub fn finalize(mut self) -> [u8; 16] {
        if self.buffer_len > 0 {
            let b = self.buffer[..self.buffer_len].to_vec();
            self.process_block(&b);
        }

        let h = self.h.to_bytes();
        let mut tag = [0u8; 16];
        let mut carry = 0u64;

        // Final tag = (h + s) mod 2^128
        for i in 0..4 {
            let h_i = u32::from_le_bytes(h[i * 4..4 + i * 4].try_into().unwrap());
            let sum = h_i as u64 + self.s[i] as u64 + carry;
            tag[i * 4..4 + i * 4].copy_from_slice(&(sum as u32).to_le_bytes());
            carry = sum >> 32;
        }

        tag
    }
}

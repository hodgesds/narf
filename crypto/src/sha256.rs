//! # Cleanroom SHA-256 Implementation
//!
//! Implementation of the SHA-256 hash function according to FIPS 180-4.
//! Reference: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>

#![allow(dead_code)]

/// SHA-256 Constants (K)
/// Reference: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=11> (Section 4.2.2)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// SHA-256 Initial Hash Value (H)
/// Reference: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=14> (Section 5.3.3)
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Ch(x, y, z) function
/// Reference: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=10> (Section 4.1.2)
#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// Maj(x, y, z) function
/// Reference: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=10> (Section 4.1.2)
#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Big Sigma 0 function
/// Reference: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=10> (Section 4.1.2)
#[inline(always)]
fn sigma0_big(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// Big Sigma 1 function
/// Reference: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=10> (Section 4.1.2)
#[inline(always)]
fn sigma1_big(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// Small Sigma 0 function
/// Reference: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=10> (Section 4.1.2)
#[inline(always)]
fn sigma0_small(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

/// Small Sigma 1 function
/// Reference: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=10> (Section 4.1.2)
#[inline(always)]
fn sigma1_small(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// SHA-256 State
#[derive(Debug)]
pub struct Sha256 {
    h: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    total_len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Self {
        Self {
            h: H0,
            block: [0; 64],
            block_len: 0,
            total_len: 0,
        }
    }

    /// Process a 64-byte block
    /// Reference: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=22> (Section 6.2.2)
    fn process_block(&mut self) {
        let mut w = [0u32; 64];

        // 1. Prepare the message schedule, W
        for (i, word) in w.iter_mut().enumerate().take(16) {
            *word = u32::from_be_bytes([
                self.block[i * 4],
                self.block[i * 4 + 1],
                self.block[i * 4 + 2],
                self.block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            w[i] = sigma1_small(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(sigma0_small(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        // 2. Initialize the eight working variables
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        // 3. For t = 0 to 63
        for t in 0..64 {
            let t1 = h
                .wrapping_add(sigma1_big(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(K[t])
                .wrapping_add(w[t]);
            let t2 = sigma0_big(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        // 4. Compute the intermediate hash value
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut pos = 0;
        while pos < data.len() {
            let take = core::cmp::min(data.len() - pos, 64 - self.block_len);
            self.block[self.block_len..self.block_len + take]
                .copy_from_slice(&data[pos..pos + take]);
            self.block_len += take;
            pos += take;

            if self.block_len == 64 {
                self.process_block();
                self.block_len = 0;
            }
        }
        self.total_len += (data.len() as u64) * 8;
    }

    /// Finalize and return the 32-byte digest
    /// Reference: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf#page=13> (Section 5.1.1)
    pub fn finalize(mut self) -> [u8; 32] {
        // Padding
        let total_bits = self.total_len;

        // Append '1' bit
        self.block[self.block_len] = 0x80;
        self.block_len += 1;

        if self.block_len > 56 {
            while self.block_len < 64 {
                self.block[self.block_len] = 0;
                self.block_len += 1;
            }
            self.process_block();
            self.block_len = 0;
        }

        while self.block_len < 56 {
            self.block[self.block_len] = 0;
            self.block_len += 1;
        }

        // Append length in bits as 64-bit big-endian
        let len_bytes = total_bits.to_be_bytes();
        self.block[56..64].copy_from_slice(&len_bytes);
        self.process_block();

        let mut out = [0u8; 32];
        for i in 0..8 {
            out[i * 4..(i + 1) * 4].copy_from_slice(&self.h[i].to_be_bytes());
        }
        out
    }
}

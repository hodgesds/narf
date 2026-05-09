//! # Cleanroom SHA-512 Implementation
//!
//! Implementation of the SHA-512 cryptographic hash function according to FIPS 180-4.
//! Reference: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>
//!
//! SHA-512 produces a 512-bit (64-byte) message digest. It operates on 1024-bit 
//! blocks and uses 64-bit words for its internal state and operations.

#![allow(dead_code)]

/// SHA-512 round constants K.
/// These are the first 64 bits of the fractional parts of the cube roots of the 
/// first 80 prime numbers.
/// Reference: FIPS 180-4 Section 4.2.3
const K: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

/// Initial hash values H(0).
/// These are the first 64 bits of the fractional parts of the square roots of the 
/// first 8 prime numbers.
/// Reference: FIPS 180-4 Section 5.3.5
const H0: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

/// SHA-512 state tracker.
#[derive(Clone, Debug)]
pub struct Sha512 {
    h: [u64; 8],
    buffer: [u8; 128],
    buffer_len: usize,
    total_len: u128, // total message length in bits
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    /// Create a new SHA-512 instance with initial hash values.
    pub fn new() -> Self {
        Self {
            h: H0,
            buffer: [0; 128],
            buffer_len: 0,
            total_len: 0,
        }
    }

    /// Update the hash state with additional data.
    pub fn update(&mut self, data: &[u8]) {
        self.total_len += (data.len() as u128) * 8;
        let mut pos = 0;
        while pos < data.len() {
            let take = core::cmp::min(128 - self.buffer_len, data.len() - pos);
            self.buffer[self.buffer_len..self.buffer_len + take].copy_from_slice(&data[pos..pos + take]);
            self.buffer_len += take;
            pos += take;

            if self.buffer_len == 128 {
                let buf = self.buffer;
                self.compress(&buf);
                self.buffer_len = 0;
            }
        }
    }

    /// Finalize the hash and return the 64-byte digest.
    pub fn finalize(mut self) -> [u8; 64] {
        let bit_len = self.total_len;
        
        // Append padding bit '1' (0x80)
        self.update(&[0x80]);

        // If not enough space for the 128-bit length, process current block and start a new one
        if self.buffer_len > 112 {
            while self.buffer_len < 128 {
                self.buffer[self.buffer_len] = 0;
                self.buffer_len += 1;
            }
            let buf = self.buffer;
            self.compress(&buf);
            self.buffer_len = 0;
        }

        // Fill remaining buffer with zeros until length field
        while self.buffer_len < 112 {
            self.buffer[self.buffer_len] = 0;
            self.buffer_len += 1;
        }

        // Append length as a 128-bit big-endian integer
        self.buffer[112..128].copy_from_slice(&bit_len.to_be_bytes());
        let buf = self.buffer;
        self.compress(&buf);

        let mut result = [0u8; 64];
        for i in 0..8 {
            result[i * 8..(i + 1) * 8].copy_from_slice(&self.h[i].to_be_bytes());
        }
        result
    }

    /// SHA-512 compression function.
    /// Reference: FIPS 180-4 Section 6.4.2
    fn compress(&mut self, block: &[u8; 128]) {
        let mut w = [0u64; 80];
        // Prepare message schedule
        for i in 0..16 {
            w[i] = u64::from_be_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
        }

        for i in 16..80 {
            // sigma0(x) = ROTR1(x) ^ ROTR8(x) ^ SHR7(x)
            let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
            // sigma1(x) = ROTR19(x) ^ ROTR61(x) ^ SHR6(x)
            let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
            w[i] = s1.wrapping_add(w[i - 7]).wrapping_add(s0).wrapping_add(w[i - 16]);
        }

        // Initialize working variables
        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h = self.h[7];

        // 80 rounds of transformation
        for i in 0..80 {
            // Sigma1(x) = ROTR14(x) ^ ROTR18(x) ^ ROTR41(x)
            let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            
            // Sigma0(x) = ROTR28(x) ^ ROTR34(x) ^ ROTR39(x)
            let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        // Add transformed values back to hash state
        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h);
    }
}

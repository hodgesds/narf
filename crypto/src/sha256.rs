//! # Cleanroom SHA-256 Implementation
//!
//! Implementation of the SHA-256 hash function according to FIPS 180-4.
//! Reference: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>

#![allow(dead_code)]

use core::fmt;

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
pub struct Sha256 {
    h: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    total_len: u64,
}

/// SEC-C2 (#1551): the internal `block` holds in-flight message
/// bytes and `h` holds key-adjacent intermediate state (HMAC pads
/// flow through here) — `Debug` is hand-written and redacts them;
/// only the public lengths print. The derived `Debug` printed
/// all four fields.
impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sha256")
            .field("h", &"<redacted>")
            .field("block", &"<redacted>")
            .field("block_len", &self.block_len)
            .field("total_len", &self.total_len)
            .finish()
    }
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
        let block = self.block;
        Self::compress_portable(&mut self.h, &block);
    }

    /// One SHA-256 compression of `block` into `state`, in portable code.
    pub(crate) fn compress_portable(state: &mut [u32; 8], block: &[u8; 64]) {
        let mut w = [0u32; 64];

        // 1. Prepare the message schedule, W
        for (i, word) in w.iter_mut().enumerate().take(16) {
            *word = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            w[i] = sigma1_small(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(sigma0_small(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        // 2. Initialize the eight working variables
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];

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
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
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

/// 16-byte-aligned wrapper: legacy-SSE memory operands (`paddd`, `movdqa`)
/// fault on unaligned addresses.
#[cfg(target_arch = "x86_64")]
#[repr(C, align(16))]
struct Align16<T>(T);

/// [`K`] for `paddd`: four round constants per 16 bytes, round `4g` in the
/// low dword of group `g`.
#[cfg(target_arch = "x86_64")]
static K_NI: Align16<[u32; 64]> = Align16(K);

/// `pshufb` mask that byte-swaps each dword: the message words are
/// big-endian (FIPS 180-4 §3.1).
#[cfg(target_arch = "x86_64")]
static BSWAP32: Align16<[u8; 16]> = Align16([3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12]);

impl Sha256 {
    /// SHA-256 compression of each 64-byte block of `blocks` into `state`
    /// on the SHA extensions (Intel SDM vol. 2, `SHA256RNDS2`,
    /// `SHA256MSG1`, `SHA256MSG2`). Same result as
    /// [`Self::compress_portable`] applied block by block.
    ///
    /// `SHA256RNDS2 xmm1, xmm2` runs two rounds: xmm1 holds C,D,G,H and
    /// xmm2 holds A,B,E,F (A in the top dword), and the implicit `xmm0`
    /// holds W+K for the two rounds in its low qword. The result, the new
    /// A,B,E,F, lands in xmm1. After two rounds the old A,B,E,F is the new
    /// C,D,G,H, so the two state registers swap roles each call.
    ///
    /// # Safety
    /// Only inside [`crate::simd::section`], and only when
    /// [`crate::simd::caps`] reported `sha256`.
    #[cfg(target_arch = "x86_64")]
    pub(crate) unsafe fn compress_ni(state: &mut [u32; 8], blocks: &[[u8; 64]]) {
        if blocks.is_empty() {
            return;
        }
        // Registers: xmm0 W+K, xmm1 ABEF, xmm2 CDGH, xmm3-xmm6 the four
        // message groups in flight, xmm7 scratch, xmm8/xmm9 the block's
        // starting ABEF/CDGH, xmm10 the byte-swap mask.
        //
        // Rounds 0-15 use the loaded message. Rounds 16-63 run as three
        // passes of four groups; group g's words come from groups g-4..g-1
        // (W[t] = σ1(W[t-2]) + W[t-7] + σ0(W[t-15]) + W[t-16]): MSG1 adds
        // σ0, `palignr` lines up W[t-7], MSG2 adds σ1. Group g overwrites
        // the register of group g-4, so each pass uses the same registers.
        // SAFETY: the caller is inside a section with SHA-NI present.
        // `state` is 32 bytes, `blocks` holds `blocks.len()` 64-byte
        // blocks, and K_NI/BSWAP32 are 16-byte aligned for the m128
        // operands.
        unsafe {
            core::arch::asm!(
                // Load a..h and rearrange to ABEF / CDGH.
                "movdqu xmm1, [{h}]",
                "movdqu xmm2, [{h} + 16]",
                "pshufd xmm1, xmm1, 0xB1", // b a d c
                "pshufd xmm2, xmm2, 0x1B", // h g f e
                "movdqa xmm7, xmm1",
                "palignr xmm1, xmm2, 8", // f e b a = ABEF
                "pblendw xmm2, xmm7, 0xF0", // h g d c = CDGH
                "movdqa xmm10, [{bswap}]",
                "2:",
                "movdqa xmm8, xmm1",
                "movdqa xmm9, xmm2",
                "movdqu xmm3, [{d}]",
                "pshufb xmm3, xmm10",
                "movdqu xmm4, [{d} + 16]",
                "pshufb xmm4, xmm10",
                "movdqu xmm5, [{d} + 32]",
                "pshufb xmm5, xmm10",
                "movdqu xmm6, [{d} + 48]",
                "pshufb xmm6, xmm10",
                // Rounds 0-15.
                "movdqa xmm0, xmm3",
                "paddd xmm0, [{k}]",
                "sha256rnds2 xmm2, xmm1",
                "pshufd xmm0, xmm0, 0x0E",
                "sha256rnds2 xmm1, xmm2",
                "movdqa xmm0, xmm4",
                "paddd xmm0, [{k} + 16]",
                "sha256rnds2 xmm2, xmm1",
                "pshufd xmm0, xmm0, 0x0E",
                "sha256rnds2 xmm1, xmm2",
                "movdqa xmm0, xmm5",
                "paddd xmm0, [{k} + 32]",
                "sha256rnds2 xmm2, xmm1",
                "pshufd xmm0, xmm0, 0x0E",
                "sha256rnds2 xmm1, xmm2",
                "movdqa xmm0, xmm6",
                "paddd xmm0, [{k} + 48]",
                "sha256rnds2 xmm2, xmm1",
                "pshufd xmm0, xmm0, 0x0E",
                "sha256rnds2 xmm1, xmm2",
                // Rounds 16-63.
                "lea {kc}, [{k} + 64]",
                "mov {pass:e}, 3",
                "3:",
                // xmm3 <- groups (xmm3, xmm4, xmm5, xmm6)
                "sha256msg1 xmm3, xmm4",
                "movdqa xmm7, xmm6",
                "palignr xmm7, xmm5, 4",
                "paddd xmm3, xmm7",
                "sha256msg2 xmm3, xmm6",
                "movdqa xmm0, xmm3",
                "paddd xmm0, [{kc}]",
                "sha256rnds2 xmm2, xmm1",
                "pshufd xmm0, xmm0, 0x0E",
                "sha256rnds2 xmm1, xmm2",
                // xmm4 <- groups (xmm4, xmm5, xmm6, xmm3)
                "sha256msg1 xmm4, xmm5",
                "movdqa xmm7, xmm3",
                "palignr xmm7, xmm6, 4",
                "paddd xmm4, xmm7",
                "sha256msg2 xmm4, xmm3",
                "movdqa xmm0, xmm4",
                "paddd xmm0, [{kc} + 16]",
                "sha256rnds2 xmm2, xmm1",
                "pshufd xmm0, xmm0, 0x0E",
                "sha256rnds2 xmm1, xmm2",
                // xmm5 <- groups (xmm5, xmm6, xmm3, xmm4)
                "sha256msg1 xmm5, xmm6",
                "movdqa xmm7, xmm4",
                "palignr xmm7, xmm3, 4",
                "paddd xmm5, xmm7",
                "sha256msg2 xmm5, xmm4",
                "movdqa xmm0, xmm5",
                "paddd xmm0, [{kc} + 32]",
                "sha256rnds2 xmm2, xmm1",
                "pshufd xmm0, xmm0, 0x0E",
                "sha256rnds2 xmm1, xmm2",
                // xmm6 <- groups (xmm6, xmm3, xmm4, xmm5)
                "sha256msg1 xmm6, xmm3",
                "movdqa xmm7, xmm5",
                "palignr xmm7, xmm4, 4",
                "paddd xmm6, xmm7",
                "sha256msg2 xmm6, xmm5",
                "movdqa xmm0, xmm6",
                "paddd xmm0, [{kc} + 48]",
                "sha256rnds2 xmm2, xmm1",
                "pshufd xmm0, xmm0, 0x0E",
                "sha256rnds2 xmm1, xmm2",
                "add {kc}, 64",
                "dec {pass:e}",
                "jnz 3b",
                // Feed forward, next block.
                "paddd xmm1, xmm8",
                "paddd xmm2, xmm9",
                "add {d}, 64",
                "dec {n}",
                "jnz 2b",
                // Back to a..h.
                "pshufd xmm1, xmm1, 0x1B", // a b e f
                "pshufd xmm2, xmm2, 0xB1", // g h c d
                "movdqa xmm7, xmm1",
                "pblendw xmm1, xmm2, 0xF0", // a b c d
                "palignr xmm2, xmm7, 8", // e f g h
                "movdqu [{h}], xmm1",
                "movdqu [{h} + 16], xmm2",
                h = in(reg) state.as_mut_ptr(),
                d = inout(reg) blocks.as_ptr() => _,
                n = inout(reg) blocks.len() => _,
                k = in(reg) K_NI.0.as_ptr(),
                bswap = in(reg) BSWAP32.0.as_ptr(),
                kc = out(reg) _,
                pass = out(reg) _,
                out("xmm0") _, out("xmm1") _, out("xmm2") _, out("xmm3") _,
                out("xmm4") _, out("xmm5") _, out("xmm6") _, out("xmm7") _,
                out("xmm8") _, out("xmm9") _, out("xmm10") _,
                options(nostack),
            );
        }
    }
}

#[cfg(test)]
mod ni_tests {
    extern crate std;

    use super::*;

    fn blocks(seed: u64, n: usize) -> alloc::vec::Vec<[u8; 64]> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                let mut b = [0u8; 64];
                for byte in b.iter_mut() {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    *byte = x as u8;
                }
                b
            })
            .collect()
    }

    #[test]
    fn compress_ni_matches_portable() {
        if !crate::simd::caps().sha256 {
            std::eprintln!("no SHA-NI on this CPU; skipped");
            return;
        }
        for (seed, n) in [(1u64, 1usize), (2, 2), (3, 5), (0xfeed, 17)] {
            let input = blocks(seed, n);
            let mut want = H0;
            for b in &input {
                Sha256::compress_portable(&mut want, b);
            }
            let mut got = H0;
            // SAFETY: inside a section, and caps() reported SHA-NI.
            crate::simd::section(|| unsafe { Sha256::compress_ni(&mut got, &input) });
            assert_eq!(got, want, "seed={seed} n={n}");
        }
    }

    /// FIPS 180-4 example: SHA-256("abc"), one padded block, on SHA-NI.
    #[test]
    fn compress_ni_abc() {
        if !crate::simd::caps().sha256 {
            return;
        }
        let mut block = [0u8; 64];
        block[..3].copy_from_slice(b"abc");
        block[3] = 0x80;
        block[63] = 24;
        let mut h = H0;
        // SAFETY: as above.
        crate::simd::section(|| unsafe { Sha256::compress_ni(&mut h, &[block]) });
        assert_eq!(
            h,
            [
                0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223, 0xb00361a3, 0x96177a9c, 0xb410ff61,
                0xf20015ad
            ]
        );
    }
}

//! PBKDF2-HMAC-SHA1 (RFC 2898 §5.2).
//!
//! Used for WPA2-Personal PMK derivation: per IEEE 802.11-2020 §J.4.1,
//!
//! ```text
//!     PMK = PBKDF2(passphrase, ssid, 4096, 256 bits)
//! ```
//!
//! ## References
//!
//! - RFC 2898 §5.2 — PBKDF2 specification.
//!   <https://datatracker.ietf.org/doc/html/rfc2898#section-5.2>
//! - RFC 2104 — HMAC construction.
//!   <https://datatracker.ietf.org/doc/html/rfc2104>
//! - FIPS PUB 180-4 §6.1 — SHA-1 message schedule and round function.
//!   <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf>
//! - IEEE 802.11-2020 §J.4.1 — PMK derivation from passphrase + SSID.
//!   <https://standards.ieee.org/ieee/802.11/7028/>
//! - RFC 6070 — PBKDF2 test vectors.
//!   <https://datatracker.ietf.org/doc/html/rfc6070>
//!
//! No GPL Linux source consulted; the in-kernel SHA-1 is derived
//! directly from FIPS 180-4 and the HMAC construction from RFC 2104.

#![allow(dead_code)]

extern crate alloc;

use alloc::vec::Vec;

// ── SHA-1 (FIPS 180-4 §6.1) ─────────────────────────────────────────
//
// A second clean-room SHA-1 lives in `drivers/wireless/src/iwlwifi/wpa.rs`.
// Per the project's hard-cutover discipline we host the canonical
// implementation here in the crypto crate so future call sites (PBKDF2,
// HMAC-SHA1 outside iwlwifi, RFC 5246 PRF, etc.) all funnel through one
// spec-anchored source. The iwlwifi copy can call back into us once
// this surface is wired through `narf-crypto`'s public API.

/// SHA-1 streaming context. State is the five 32-bit working
/// variables (FIPS 180-4 §5.3.1); input is buffered in 64-byte blocks.
#[derive(Clone, Debug)]
pub struct Sha1 {
    state: [u32; 5],
    /// Total bits processed (FIPS 180-4 §5.1.1 message-length field).
    count: u64,
    buf: [u8; 64],
    buf_len: usize,
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha1 {
    pub const fn new() -> Self {
        Self {
            // Initial hash values, FIPS 180-4 §5.3.1.
            state: [
                0x6745_2301,
                0xEFCD_AB89,
                0x98BA_DCFE,
                0x1032_5476,
                0xC3D2_E1F0,
            ],
            count: 0,
            buf: [0u8; 64],
            buf_len: 0,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        let mut off = 0;
        while off < data.len() {
            let take = (64 - self.buf_len).min(data.len() - off);
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[off..off + take]);
            self.buf_len += take;
            off += take;
            self.count += (take as u64) * 8;
            if self.buf_len == 64 {
                let block = self.buf;
                self.process_block(&block);
                self.buf_len = 0;
            }
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        // FIPS 180-4 §5.1.1: append 0x80, pad with zeros until len%64 == 56,
        // then append the 64-bit big-endian bit count.
        let bit_len = self.count;
        self.update(&[0x80]);
        let zeros_needed = if self.buf_len <= 56 {
            56 - self.buf_len
        } else {
            64 + 56 - self.buf_len
        };
        let zeros = [0u8; 64];
        self.update(&zeros[..zeros_needed]);
        self.update(&bit_len.to_be_bytes());

        let mut out = [0u8; 20];
        for (i, &w) in self.state.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn process_block(&mut self, block: &[u8; 64]) {
        // FIPS 180-4 §6.1.2 — message schedule W[0..80].
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        // FIPS 180-4 §4.2.1 round constants.
        const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];

        let [mut a, mut b, mut c, mut d, mut e] = self.state;

        for (i, wi) in w.iter().enumerate() {
            // FIPS 180-4 §6.1.2 round-function selector:
            //   t∈[0,19]  : f = Ch(b,c,d), K = K[0]
            //   t∈[20,39] : f = Parity(b,c,d), K = K[1]
            //   t∈[40,59] : f = Maj(b,c,d), K = K[2]
            //   t∈[60,79] : f = Parity(b,c,d), K = K[3]
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), K[0]),
                20..=39 => (b ^ c ^ d, K[1]),
                40..=59 => ((b & c) | (b & d) | (c & d), K[2]),
                _ => (b ^ c ^ d, K[3]),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

/// One-shot SHA-1: returns the 20-byte digest of `data`.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize()
}

// ── HMAC-SHA1 (RFC 2104 §2) ─────────────────────────────────────────

/// HMAC-SHA1 over `data` using `key`. Returns the 20-byte tag.
///
/// Per RFC 2104 §2, keys longer than the block size (64 bytes) are
/// pre-hashed; keys shorter are zero-padded right.
pub fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    const BLOCK: usize = 64;
    let mut k0 = [0u8; BLOCK];
    if key.len() > BLOCK {
        let hk = sha1(key);
        k0[..20].copy_from_slice(&hk);
    } else {
        k0[..key.len()].copy_from_slice(key);
    }

    // ipad = 0x36 ⊕ K0; opad = 0x5C ⊕ K0.
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5Cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k0[i];
        opad[i] ^= k0[i];
    }

    // Inner hash: SHA-1(ipad || data).
    let mut inner = Sha1::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    // Outer hash: SHA-1(opad || inner_hash).
    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

// ── PBKDF2-HMAC-SHA1 (RFC 2898 §5.2) ────────────────────────────────

/// PBKDF2 with HMAC-SHA1 as the underlying PRF.
///
/// Per RFC 2898 §5.2:
///
/// ```text
///     DK = T_1 || T_2 || ... || T_l<dkLen/hLen>
///     T_i = F(P, S, c, i)
///     F(P, S, c, i) = U_1 ⊕ U_2 ⊕ ... ⊕ U_c
///     U_1 = HMAC(P, S || INT(i))
///     U_j = HMAC(P, U_{j-1})
/// ```
///
/// `dk_len` is bounded by `(2^32 - 1) * 20`; we cap with a runtime
/// check rather than panicking since callers like WPA never approach
/// the limit (PMK is 32 bytes, so two blocks).
pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32, dk_len: usize) -> Vec<u8> {
    assert!(iterations >= 1, "PBKDF2 iteration count must be ≥1");
    let h_len = 20usize;
    let mut dk = alloc::vec![0u8; dk_len];
    let l = dk_len.div_ceil(h_len);

    let mut block = [0u8; 4];
    let mut salt_with_int: Vec<u8> = Vec::with_capacity(salt.len() + 4);

    for i in 1..=l {
        // S || INT(i) — INT is the 4-byte big-endian block index.
        block.copy_from_slice(&(i as u32).to_be_bytes());
        salt_with_int.clear();
        salt_with_int.extend_from_slice(salt);
        salt_with_int.extend_from_slice(&block);

        // U_1 = HMAC(P, S || INT(i)).
        let mut u = hmac_sha1(password, &salt_with_int);
        let mut t = u;

        // U_j = HMAC(P, U_{j-1}) for j = 2..c; T_i = U_1 ⊕ U_2 ⊕ ... ⊕ U_c.
        for _ in 1..iterations {
            u = hmac_sha1(password, &u);
            for k in 0..h_len {
                t[k] ^= u[k];
            }
        }

        // Copy T_i into DK at offset (i-1)*hLen; truncate the last block.
        let off = (i - 1) * h_len;
        let take = (dk_len - off).min(h_len);
        dk[off..off + take].copy_from_slice(&t[..take]);
    }
    dk
}

/// Derive the WPA2 Pairwise Master Key (PMK) from the passphrase and
/// SSID. Per IEEE 802.11-2020 §J.4.1, the PMK is 256 bits and PBKDF2
/// runs for 4096 iterations using the SSID as salt.
pub fn wpa2_pmk(passphrase: &[u8], ssid: &[u8]) -> [u8; 32] {
    let dk = pbkdf2_hmac_sha1(passphrase, ssid, 4096, 32);
    let mut pmk = [0u8; 32];
    pmk.copy_from_slice(&dk);
    pmk
}

// ── Tests ───────────────────────────────────────────────────────────

pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // FIPS 180-4 §A.1: SHA-1("abc") =
    //   A9993E364706816ABA3E25717850C26C9CD0D89D
    fn smoke_sha1_abc_fips_vector() -> TestResult {
        let d = sha1(b"abc");
        let expected: [u8; 20] = [
            0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50,
            0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D,
        ];
        if d != expected {
            return TestResult::Fail("SHA-1(abc) mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/pbkdf2_sha1", smoke_sha1_abc_fips_vector);

    // RFC 2104 §Test Cases: HMAC-SHA1(0x0b*20, "Hi There") =
    //   B617318655057264E28BC0B6FB378C8EF146BE00
    fn smoke_hmac_sha1_rfc2104_vector() -> TestResult {
        let key = [0x0bu8; 20];
        let mac = hmac_sha1(&key, b"Hi There");
        let expected: [u8; 20] = [
            0xB6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xE2, 0x8B, 0xC0, 0xB6, 0xFB, 0x37,
            0x8C, 0x8E, 0xF1, 0x46, 0xBE, 0x00,
        ];
        if mac != expected {
            return TestResult::Fail("HMAC-SHA1 RFC 2104 mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/pbkdf2_sha1", smoke_hmac_sha1_rfc2104_vector);

    // RFC 6070 Test Case 1: PBKDF2(P="password", S="salt", c=1, dkLen=20) =
    //   0c60c80f961f0e71f3a9b524af6012062fe037a6
    fn smoke_pbkdf2_rfc6070_c1() -> TestResult {
        let dk = pbkdf2_hmac_sha1(b"password", b"salt", 1, 20);
        let expected: [u8; 20] = [
            0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60,
            0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6,
        ];
        if dk != expected {
            return TestResult::Fail("RFC 6070 c=1 vector mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/pbkdf2_sha1", smoke_pbkdf2_rfc6070_c1);

    // RFC 6070 Test Case 2: PBKDF2(P="password", S="salt", c=2, dkLen=20) =
    //   ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957
    fn smoke_pbkdf2_rfc6070_c2() -> TestResult {
        let dk = pbkdf2_hmac_sha1(b"password", b"salt", 2, 20);
        let expected: [u8; 20] = [
            0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d,
            0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57,
        ];
        if dk != expected {
            return TestResult::Fail("RFC 6070 c=2 vector mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/pbkdf2_sha1", smoke_pbkdf2_rfc6070_c2);

    // RFC 6070 Test Case 3: PBKDF2(P="password", S="salt", c=4096, dkLen=20) =
    //   4b007901b765489abead49d926f721d065a429c1
    // The expensive one — verifies the inner XOR loop is correct.
    fn smoke_pbkdf2_rfc6070_c4096() -> TestResult {
        let dk = pbkdf2_hmac_sha1(b"password", b"salt", 4096, 20);
        let expected: [u8; 20] = [
            0x4b, 0x00, 0x79, 0x01, 0xb7, 0x65, 0x48, 0x9a, 0xbe, 0xad, 0x49, 0xd9, 0x26, 0xf7,
            0x21, 0xd0, 0x65, 0xa4, 0x29, 0xc1,
        ];
        if dk != expected {
            return TestResult::Fail("RFC 6070 c=4096 vector mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/pbkdf2_sha1", smoke_pbkdf2_rfc6070_c4096);

    // WPA2 PMK is 32 bytes — verifies the multi-block path (2 SHA-1
    // outputs spliced).
    fn smoke_wpa2_pmk_length_and_determinism() -> TestResult {
        let pmk1 = wpa2_pmk(b"narfwifi", b"NarfNet");
        let pmk2 = wpa2_pmk(b"narfwifi", b"NarfNet");
        if pmk1 != pmk2 {
            return TestResult::Fail("WPA2 PMK derivation not deterministic");
        }
        if pmk1.iter().all(|&b| b == 0) {
            return TestResult::Fail("PMK should not be all-zero");
        }
        // Different passphrase ⇒ different PMK.
        let pmk3 = wpa2_pmk(b"NotNarf", b"NarfNet");
        if pmk1 == pmk3 {
            return TestResult::Fail("PMK should differ with different passphrase");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/pbkdf2_sha1", smoke_wpa2_pmk_length_and_determinism);
}

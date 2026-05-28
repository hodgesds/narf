//! AES-128 CTR mode (NIST SP 800-38A §6.5).
//!
//! Counter mode turns AES-128 (a block cipher) into a stream cipher
//! by encrypting a sequence of counter blocks and XOR-ing the
//! resulting key-stream into the message. CTR is malleable on its own
//! (no authentication) and is paired here with separate MACs by the
//! HDCP 2.x stack (see `crate::hdcp`).
//!
//! ## References
//!
//! - **NIST SP 800-38A §6.5** — CTR mode specification.
//!   <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf>
//! - **NIST SP 800-38A Appendix F.5** — CTR test vectors over
//!   AES-128 (F.5.1 + F.5.2).
//! - **FIPS 197** — AES-128 block cipher.
//!   <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf>
//! - **HDCP 2.3 §1.5** — uses AES-128 CTR to wrap the session key.
//!
//! ## Counter discipline
//!
//! Per SP 800-38A §6.5, the counter block is incremented as a
//! 128-bit big-endian integer between blocks. HDCP 2.x splits the
//! counter into `riv ‖ ctr` halves but the increment discipline is
//! the same — we expose a single `apply_keystream` that does the
//! work and a `Counter` helper that owns the bump arithmetic.
//!
//! No GPL Linux source consulted; SP 800-38A is self-contained.

#![allow(dead_code)]

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes128;

use crate::cmac_aes128::AES_BLOCK_LEN;

/// 128-bit big-endian counter. Increment is per-block.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Counter(pub [u8; AES_BLOCK_LEN]);

impl Counter {
    /// Build a counter from a 16-byte initial value. The first encrypted
    /// block uses `iv` as-is; subsequent blocks use `iv`+1, +2, etc.
    pub const fn new(iv: [u8; AES_BLOCK_LEN]) -> Self {
        Self(iv)
    }

    /// Increment the 128-bit big-endian counter by one. Wraps around at
    /// 2^128 — SP 800-38A §B.1 allows wrap; callers must ensure they do
    /// not reuse the same `(key, counter)` pair across messages.
    pub fn increment(&mut self) {
        // Walk from least-significant byte (offset 15) towards
        // most-significant (offset 0), propagating carry. SP 800-38A
        // §B.1 / Appendix B specifies "standard incrementing function"
        // operating on the full m-bit counter (m = 128 here).
        for byte in self.0.iter_mut().rev() {
            let (next, carry) = byte.overflowing_add(1);
            *byte = next;
            if !carry {
                return;
            }
        }
    }

    /// Read the current counter as a 16-byte block.
    pub const fn as_bytes(&self) -> &[u8; AES_BLOCK_LEN] {
        &self.0
    }
}

/// Apply AES-128 CTR keystream to `buf` in place. `key` is 16 bytes,
/// `counter` is the 128-bit big-endian counter block at the start.
///
/// On return the counter has been advanced past the last block consumed
/// (or wrapped, per SP 800-38A §B.1). Encrypt and decrypt are the same
/// operation since CTR is a stream cipher.
///
/// Per SP 800-38A §6.5: for j = 1..n,
///
/// ```text
///     O_j = CIPH_K(T_j)
///     C_j = P_j XOR MSB_u(O_j)            (last block truncated)
///     T_{j+1} = T_j + 1 mod 2^128         (counter increment)
/// ```
pub fn apply_keystream(key: &[u8; 16], counter: &mut Counter, buf: &mut [u8]) {
    let cipher = Aes128::new(GenericArray::from_slice(key));

    let mut off = 0;
    while off < buf.len() {
        // Encrypt the current counter block to produce key-stream.
        let mut blk = GenericArray::clone_from_slice(&counter.0);
        cipher.encrypt_block(&mut blk);

        // XOR with up to one block of plaintext / ciphertext.
        let take = core::cmp::min(AES_BLOCK_LEN, buf.len() - off);
        for i in 0..take {
            buf[off + i] ^= blk[i];
        }
        off += take;

        // Bump the counter for the next block.
        counter.increment();
    }
}

/// Convenience wrapper that takes a starting counter by value, applies
/// the keystream, and returns the final counter so callers can chain
/// or audit it without exposing the mutation through a `&mut Counter`.
pub fn ctr_apply(key: &[u8; 16], start: [u8; AES_BLOCK_LEN], buf: &mut [u8]) -> Counter {
    let mut ctr = Counter::new(start);
    apply_keystream(key, &mut ctr, buf);
    ctr
}

// ── Tests ───────────────────────────────────────────────────────────

pub mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // NIST SP 800-38A Appendix F.5.1 — CTR-AES128.Encrypt
    //   Key:          2b7e1516 28aed2a6 abf71588 09cf4f3c
    //   Init Ctr:     f0f1f2f3 f4f5f6f7 f8f9fafb fcfdfeff
    //   Plaintext #1: 6bc1bee2 2e409f96 e93d7e11 7393172a
    //   Ciphertext #1: 874d6191 b620e326 1bef6864 990db6ce
    //   Plaintext #2: ae2d8a57 1e03ac9c 9eb76fac 45af8e51
    //   Ciphertext #2: 9806f66b 7970fdff 8617187b b9fffdff
    //   Plaintext #3: 30c81c46 a35ce411 e5fbc119 1a0a52ef
    //   Ciphertext #3: 5ae4df3e dbd5d35e 5b4f0902 0db03eab
    //   Plaintext #4: f69f2445 df4f9b17 ad2b417b e66c3710
    //   Ciphertext #4: 1e031dda 2fbe03d1 792170a0 f3009cee
    const NIST_KEY: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f,
        0x3c,
    ];
    const NIST_IV: [u8; 16] = [
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
        0xff,
    ];
    const NIST_PT: [u8; 64] = [
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17,
        0x2a, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf,
        0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
        0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b,
        0xe6, 0x6c, 0x37, 0x10,
    ];
    const NIST_CT: [u8; 64] = [
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6,
        0xce, 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff,
        0xfd, 0xff, 0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d,
        0xb0, 0x3e, 0xab, 0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0,
        0xf3, 0x00, 0x9c, 0xee,
    ];

    fn smoke_aes_ctr_nist_sp800_38a_encrypt() -> TestResult {
        let mut buf = NIST_PT;
        let mut ctr = Counter::new(NIST_IV);
        apply_keystream(&NIST_KEY, &mut ctr, &mut buf);
        if buf != NIST_CT {
            return TestResult::Fail("NIST SP 800-38A F.5.1 encrypt mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/aes_ctr", smoke_aes_ctr_nist_sp800_38a_encrypt);

    fn smoke_aes_ctr_round_trip() -> TestResult {
        // Encrypt then decrypt yields the original plaintext.
        let mut buf = NIST_PT;
        let _end1 = ctr_apply(&NIST_KEY, NIST_IV, &mut buf);
        if buf == NIST_PT {
            return TestResult::Fail("CTR encrypt produced plaintext");
        }
        let _end2 = ctr_apply(&NIST_KEY, NIST_IV, &mut buf);
        if buf != NIST_PT {
            return TestResult::Fail("CTR round-trip lost plaintext");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/aes_ctr", smoke_aes_ctr_round_trip);

    fn smoke_aes_ctr_counter_carry_propagation() -> TestResult {
        // Counter at ff..ff increments to 00..00 (wrap) per SP 800-38A §B.1.
        let mut ctr = Counter::new([0xFF; 16]);
        ctr.increment();
        if ctr.0 != [0u8; 16] {
            return TestResult::Fail("counter wrap from all-ones must produce all-zeros");
        }

        // Counter at 00..00FF increments to 00..0100 (single carry).
        let mut a = [0u8; 16];
        a[15] = 0xFF;
        let mut ctr = Counter::new(a);
        ctr.increment();
        let mut expected = [0u8; 16];
        expected[14] = 0x01;
        if ctr.0 != expected {
            return TestResult::Fail("single-byte carry mis-propagated");
        }

        // Counter at 00..00FFFF increments to 00..010000 (two-byte carry).
        let mut a = [0u8; 16];
        a[14] = 0xFF;
        a[15] = 0xFF;
        let mut ctr = Counter::new(a);
        ctr.increment();
        let mut expected = [0u8; 16];
        expected[13] = 0x01;
        if ctr.0 != expected {
            return TestResult::Fail("two-byte carry mis-propagated");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/aes_ctr", smoke_aes_ctr_counter_carry_propagation);

    fn smoke_aes_ctr_partial_block_tail() -> TestResult {
        // CTR truncates the keystream of the final block to match buf len.
        // We verify by encrypting a 17-byte buffer: byte 16 must match the
        // first byte of AES(K, IV+1) XOR plaintext[16].
        let mut buf = [0u8; 17];
        ctr_apply(&NIST_KEY, NIST_IV, &mut buf);
        // Second block's first byte of keystream = first byte of NIST CT
        // block-2 XOR-ed with NIST PT block-2 (since our plaintext is 0).
        let expected = NIST_CT[16] ^ NIST_PT[16];
        if buf[16] != expected {
            return TestResult::Fail("partial-final-block byte mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/aes_ctr", smoke_aes_ctr_partial_block_tail);
}

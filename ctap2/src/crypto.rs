//! Cryptographic helpers for the CTAP2 PIN/UV auth protocol and
//! the `hmac-secret` extension, built only on `narf-crypto`
//! primitives plus the `aes` block cipher (the same RustCrypto
//! `aes` crate `narf-crypto` itself wraps).
//!
//! ## Spec sources
//!
//! - FIDO2 CTAP2 specification, PIN/UV auth protocol **one**:
//!   - `kdf(Z) = SHA-256(Z)` where `Z` is the ECDH shared secret's
//!     x-coordinate (the "shared secret" below is always this
//!     32-byte KDF output, never the raw ECDH value).
//!   - `encrypt(key, plaintext)`: AES-256-CBC with an all-zero IV.
//!     Protocol one defines its own padding at the call sites that
//!     need it (PINs); data that is already a multiple of 16
//!     (salts, hmac-secret outputs) is encrypted unpadded.
//!   - `authenticate(key, data) = HMAC-SHA-256(key, data)`.
//! - NIST SP 800-38A (CBC mode), RFC 2104 (HMAC), RFC 5869
//!   (HKDF — used by the enrollment layer, via `narf-crypto`).

extern crate alloc;

use alloc::vec::Vec;
use narf_crypto::p256::point::{scalar_mul, scalar_mul_base};
use narf_crypto::p256::{AffinePoint, Scalar};
use narf_crypto::sha256::Sha256;

use crate::{Error, RandomSource};

/// SHA-256 over the concatenation of `parts`.
pub fn sha256_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

/// SHA-256 of one slice.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    sha256_parts(&[data])
}

/// HMAC-SHA-256 (RFC 2104) over the concatenation of `parts`.
pub fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    // RFC 2104: keys longer than the 64-byte block are hashed first.
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        key_block[..32].copy_from_slice(&sha256(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0u8; 64];
    let mut opad = [0u8; 64];
    for i in 0..64 {
        ipad[i] = key_block[i] ^ 0x36;
        opad[i] = key_block[i] ^ 0x5C;
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    for p in parts {
        inner.update(p);
    }
    let inner_hash = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize()
}

/// HMAC-SHA-256 over one slice.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac_sha256_parts(key, &[data])
}

/// A P-256 ephemeral key pair for CTAP2 key agreement.
pub struct KeyPair {
    secret: Scalar,
    /// X || Y, 64 bytes (uncompressed point without the 0x04 tag,
    /// the form COSE carries in its -2/-3 members).
    pub public_encoded: [u8; 64],
}

impl KeyPair {
    /// Generate a fresh ephemeral pair from the caller's randomness.
    pub fn generate<R: RandomSource>(rng: &mut R) -> Result<Self, Error> {
        let mut seed = [0u8; 32];
        // Rejection-sample via reduce: a reduced scalar is zero with
        // probability ~2^-256, but never accept it (it would make
        // the public key the point at infinity and the ECDH void).
        loop {
            rng.fill_random(&mut seed)?;
            let scalar = Scalar::from_bytes_be_reduce(&seed);
            if !scalar.is_zero() {
                let public = scalar_mul_base(&scalar);
                let public_encoded = public.to_encoded().ok_or(Error::Crypto)?;
                return Ok(Self {
                    secret: scalar,
                    public_encoded,
                });
            }
        }
    }

    /// Construct from a fixed scalar — fixture/test use only, so the
    /// conversation can be pinned byte-for-byte against known keys.
    pub fn from_scalar_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let scalar = Scalar::from_bytes_be(bytes)?;
        if scalar.is_zero() {
            return None;
        }
        let public = scalar_mul_base(&scalar);
        let public_encoded = public.to_encoded()?;
        Some(Self {
            secret: scalar,
            public_encoded,
        })
    }

    /// PIN protocol one shared secret: `SHA-256(x)` where `x` is the
    /// x-coordinate of `secret * peer`.
    pub fn shared_secret(&self, peer_encoded: &[u8; 64]) -> Result<[u8; 32], Error> {
        let peer = AffinePoint::from_encoded(peer_encoded).ok_or(Error::Crypto)?;
        let shared = scalar_mul(&self.secret, &peer);
        let enc = shared.to_encoded().ok_or(Error::Crypto)?;
        let mut x = [0u8; 32];
        x.copy_from_slice(&enc[..32]);
        Ok(sha256(&x))
    }
}

/// AES-256-CBC encrypt with a zero IV (CTAP2 PIN protocol one).
/// `plaintext` must be a multiple of 16 bytes — padding is the
/// caller's, per the protocol definitions that need it. CBC
/// chains: each block is XORed with the previous *ciphertext*
/// block (the zero IV for the first) before encryption —
/// implemented explicitly because the `aes` crate exposes raw
/// blocks only.
pub fn aes256_cbc_encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::Aes256;
    if plaintext.is_empty() || !plaintext.len().is_multiple_of(16) {
        return Err(Error::Crypto);
    }
    let cipher = Aes256::new(key.into());
    let mut out = Vec::with_capacity(plaintext.len());
    let mut prev = [0u8; 16]; // zero IV
    for chunk in plaintext.chunks_exact(16) {
        let mut block = *aes::cipher::generic_array::GenericArray::from_slice(chunk);
        for i in 0..16 {
            block[i] ^= prev[i];
        }
        cipher.encrypt_block(&mut block);
        prev.copy_from_slice(&block);
        out.extend_from_slice(&block);
    }
    Ok(out)
}

/// AES-256-CBC decrypt with a zero IV. Note CBC chains: each block
/// XORs the previous *ciphertext* — implemented explicitly here
/// because the `aes` crate exposes raw blocks only.
pub fn aes256_cbc_decrypt(key: &[u8; 32], ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
    use aes::cipher::{BlockDecrypt, KeyInit};
    use aes::Aes256;
    if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return Err(Error::Crypto);
    }
    let cipher = Aes256::new(key.into());
    let mut out = Vec::with_capacity(ciphertext.len());
    let mut prev = [0u8; 16]; // zero IV
    for chunk in ciphertext.chunks_exact(16) {
        let mut block = *aes::cipher::generic_array::GenericArray::from_slice(chunk);
        cipher.decrypt_block(&mut block);
        let mut plain = [0u8; 16];
        for i in 0..16 {
            plain[i] = block[i] ^ prev[i];
        }
        out.extend_from_slice(&plain);
        prev.copy_from_slice(chunk);
    }
    Ok(out)
}

/// Constant-time equality for authentication-tag comparisons.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(any(test, feature = "kernel-test"))]
mod tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    macro_rules! check_eq {
        ($a:expr, $b:expr, $msg:expr) => {
            if $a != $b {
                return TestResult::Fail($msg);
            }
        };
    }
    macro_rules! try_ok {
        ($e:expr, $msg:expr) => {
            match $e {
                Ok(v) => v,
                Err(_) => return TestResult::Fail($msg),
            }
        };
    }
    macro_rules! try_some {
        ($e:expr, $msg:expr) => {
            match $e {
                Some(v) => v,
                None => return TestResult::Fail($msg),
            }
        };
    }

    fn smoke_hmac_rfc4231_case1() -> TestResult {
        // RFC 4231 test case 1: key = 20 * 0x0b, data = "Hi There".
        let out = hmac_sha256(&[0x0b; 20], b"Hi There");
        let expect: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        check_eq!(out, expect, "RFC 4231 case 1");
        TestResult::Pass
    }
    kernel_test_in!("ctap2/crypto", smoke_hmac_rfc4231_case1);

    fn smoke_aes256_cbc_sp800_38a_first_block() -> TestResult {
        // NIST SP 800-38A F.2.5 (CBC-AES256), first block, zero-IV
        // equivalence: with IV=0 the first CBC block equals the ECB
        // result for that block under the chain — use the published
        // IV from the vector and XOR it in manually instead: simpler
        // to pin raw AES-256 ECB here (F.1.5 block 1).
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let pt: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let ct = try_ok!(aes256_cbc_encrypt(&key, &pt), "cbc encrypt");
        // SP 800-38A F.2.5 output block 1 uses IV 000102...0f; with a
        // zero IV the expected ciphertext is the F.1.5 ECB result:
        let expect: [u8; 16] = [
            0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1,
            0x81, 0xf8,
        ];
        check_eq!(
            ct.as_slice(),
            expect.as_slice(),
            "AES-256 zero-IV first block"
        );
        let back = try_ok!(aes256_cbc_decrypt(&key, &ct), "cbc decrypt");
        check_eq!(back.as_slice(), pt.as_slice(), "CBC round trip");
        TestResult::Pass
    }
    kernel_test_in!("ctap2/crypto", smoke_aes256_cbc_sp800_38a_first_block);

    fn smoke_aes256_cbc_sp800_38a_full_chain() -> TestResult {
        // NIST SP 800-38A F.2.5 (CBC-AES256) — the FULL four-block
        // chain. The single-block pin above cannot see chaining
        // (block 1 is identical under ECB and zero-IV CBC); this
        // one exists because an unchained (ECB-shaped) encrypt
        // passed the first-block pin while garbling every later
        // block — the failure mode that broke PIN enrollment
        // (newPinEnc is four blocks). F.2.5's IV is folded into
        // the first input block, so this crate's fixed zero-IV
        // CBC must reproduce the published F.2.5 ciphertext
        // exactly, all four blocks.
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        // F.2.5 plaintext blocks with IV 000102...0f XORed into
        // block 1: 6bc1bee2... ^ 00010203... = 6bc0bce1....
        let pt: [u8; 64] = [
            0x6b, 0xc0, 0xbc, 0xe1, 0x2a, 0x45, 0x99, 0x91, 0xe1, 0x34, 0x74, 0x1a, 0x7f, 0x9e,
            0x19, 0x25, 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac,
            0x45, 0xaf, 0x8e, 0x51, 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb,
            0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef, 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
            0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10,
        ];
        // F.2.5 published ciphertext, all four blocks.
        let expect: [u8; 64] = [
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b,
            0xfb, 0xd6, 0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b,
            0xc6, 0x70, 0x2c, 0x7d, 0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30,
            0xe2, 0x63, 0x04, 0x23, 0x14, 0x61, 0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc,
            0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b,
        ];
        let ct = try_ok!(aes256_cbc_encrypt(&key, &pt), "cbc encrypt 4 blocks");
        check_eq!(
            ct.as_slice(),
            expect.as_slice(),
            "AES-256 CBC full chain (F.2.5)"
        );
        let back = try_ok!(aes256_cbc_decrypt(&key, &ct), "cbc decrypt 4 blocks");
        check_eq!(back.as_slice(), pt.as_slice(), "CBC 4-block round trip");
        TestResult::Pass
    }
    kernel_test_in!("ctap2/crypto", smoke_aes256_cbc_sp800_38a_full_chain);

    fn smoke_ecdh_rfc5903_vector() -> TestResult {
        // RFC 5903 §8.1 (values as pinned by narf-crypto's own
        // smoke_p256_ecdh_rfc5903_shared): initiator private i,
        // responder public gR, shared x-coordinate Z.
        let priv_a: [u8; 32] = [
            0xC8, 0x8F, 0x01, 0xF5, 0x10, 0xD9, 0xAC, 0x3F, 0x70, 0xA2, 0x92, 0xDA, 0xA2, 0x31,
            0x6D, 0xE5, 0x44, 0xE9, 0xAA, 0xB8, 0xAF, 0xE8, 0x40, 0x49, 0xC6, 0x2A, 0x9C, 0x57,
            0x86, 0x2D, 0x14, 0x33,
        ];
        let pub_b: [u8; 64] = [
            0xD1, 0x2D, 0xFB, 0x52, 0x89, 0xC8, 0xD4, 0xF8, 0x12, 0x08, 0xB7, 0x02, 0x70, 0x39,
            0x8C, 0x34, 0x22, 0x96, 0x97, 0x0A, 0x0B, 0xCC, 0xB7, 0x4C, 0x73, 0x6F, 0xC7, 0x55,
            0x44, 0x94, 0xBF, 0x63, 0x56, 0xFB, 0xF3, 0xCA, 0x36, 0x6C, 0xC2, 0x3E, 0x81, 0x57,
            0x85, 0x4C, 0x13, 0xC5, 0x8D, 0x6A, 0xAC, 0x23, 0xF0, 0x46, 0xAD, 0xA3, 0x0F, 0x83,
            0x53, 0xE7, 0x4F, 0x33, 0x03, 0x98, 0x72, 0xAB,
        ];
        let expect_z: [u8; 32] = [
            0xD6, 0x84, 0x0F, 0x6B, 0x42, 0xF6, 0xED, 0xAF, 0xD1, 0x31, 0x16, 0xE0, 0xE1, 0x25,
            0x65, 0x20, 0x2F, 0xEF, 0x8E, 0x9E, 0xCE, 0x7D, 0xCE, 0x03, 0x81, 0x24, 0x64, 0xD0,
            0x4B, 0x94, 0x42, 0xDE,
        ];
        let kp = try_some!(KeyPair::from_scalar_bytes(&priv_a), "keypair from scalar");
        let peer = try_some!(AffinePoint::from_encoded(&pub_b), "peer decode");
        let scalar = try_some!(Scalar::from_bytes_be(&priv_a), "scalar decode");
        let z = scalar_mul(&scalar, &peer);
        let z_enc = try_some!(z.to_encoded(), "z encode");
        check_eq!(&z_enc[..32], &expect_z[..], "RFC 5903 Z");
        let shared = try_ok!(kp.shared_secret(&pub_b), "shared secret");
        check_eq!(shared, sha256(&expect_z), "shared secret is SHA-256(Z)");
        TestResult::Pass
    }
    kernel_test_in!("ctap2/crypto", smoke_ecdh_rfc5903_vector);
}

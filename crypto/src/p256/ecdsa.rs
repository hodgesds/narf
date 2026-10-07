//! ECDSA signature verification over NIST P-256 (FIPS 186-4 §6.4).
//!
//! Used by WPA3 SAE-PK to authenticate an AP's public key. The inputs
//! (public key, signature, message digest) are all public, so the scalar
//! arithmetic (`Scalar::mul` / `Scalar::invert`) is variable-time by design.
//!
//! Validated against the Linux kernel's `p1363_ecdsa_nist_p256_tv_template`
//! known-answer vector (`crypto/testmgr.h`).

use super::point::{scalar_mul, AffinePoint};
use super::scalar::Scalar;

/// Verify an ECDSA/P-256 signature over a 32-byte message digest.
///
/// `pubkey` is the uncompressed point `0x04 || X || Y` (65 bytes); `r` and
/// `s` are the 32-byte big-endian signature components (P1363 form). Returns
/// `true` iff the signature is valid.
pub fn verify_p256(pubkey: &[u8], digest: &[u8; 32], r: &[u8; 32], s: &[u8; 32]) -> bool {
    if pubkey.len() != 65 || pubkey[0] != 0x04 {
        return false;
    }
    let q = match AffinePoint::from_encoded(&pubkey[1..65]) {
        Some(q) if !q.infinity && q.is_on_curve() => q,
        _ => return false,
    };
    // r, s must each lie in [1, n).
    let (r_scalar, s_scalar) = match (Scalar::from_bytes_be(r), Scalar::from_bytes_be(s)) {
        (Some(r), Some(s)) if !r.is_zero() && !s.is_zero() => (r, s),
        _ => return false,
    };
    // e = leftmost 256 bits of the digest, reduced mod n.
    let e = Scalar::from_bytes_be_reduce(digest);
    let w = s_scalar.invert();
    let u1 = e.mul(&w);
    let u2 = r_scalar.mul(&w);
    // R = u1·G + u2·Q.
    let point = scalar_mul(&u1, &AffinePoint::generator())
        .to_projective()
        .add_mixed(&scalar_mul(&u2, &q))
        .to_affine();
    if point.infinity {
        return false;
    }
    // Valid iff (R.x mod n) == r.
    Scalar::from_bytes_be_reduce(&point.x.to_bytes_be()) == r_scalar
}

/// RFC 6979 §3.2 deterministic-nonce generator for P-256 / SHA-256
/// (qlen = hlen = 256, so each HMAC output is one candidate).
#[cfg(feature = "ecdsa-sign")]
struct Rfc6979 {
    k: [u8; 32],
    v: [u8; 32],
}

#[cfg(feature = "ecdsa-sign")]
impl Rfc6979 {
    fn new(private_key: &[u8; 32], digest: &[u8; 32]) -> Self {
        use crate::hkdf::hmac_sha256;
        // int2octets(x) = private key; bits2octets(h1) = (h1 mod n) as octets.
        let bits2octets = Scalar::from_bytes_be_reduce(digest).to_bytes_be();
        let mut v = [0x01u8; 32];
        let mut k = [0x00u8; 32];
        // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1)); V = HMAC_K(V)
        let mut buf = [0u8; 97];
        let fill = |buf: &mut [u8; 97], v: &[u8; 32], sep: u8| {
            buf[..32].copy_from_slice(v);
            buf[32] = sep;
            buf[33..65].copy_from_slice(private_key);
            buf[65..97].copy_from_slice(&bits2octets);
        };
        fill(&mut buf, &v, 0x00);
        k = hmac_sha256(&k, &buf);
        v = hmac_sha256(&k, &v);
        fill(&mut buf, &v, 0x01);
        k = hmac_sha256(&k, &buf);
        v = hmac_sha256(&k, &v);
        Self { k, v }
    }

    /// Produce the next nonce candidate; reseeds and returns `None` when the
    /// raw `T` is out of `[1, n)` (the caller loops).
    fn next_candidate(&mut self) -> Option<Scalar> {
        use crate::hkdf::hmac_sha256;
        self.v = hmac_sha256(&self.k, &self.v);
        if let Some(k) = Scalar::from_bytes_be(&self.v).filter(|k| !k.is_zero()) {
            return Some(k);
        }
        // K = HMAC_K(V || 0x00); V = HMAC_K(V)
        let mut buf = [0u8; 33];
        buf[..32].copy_from_slice(&self.v);
        buf[32] = 0x00;
        self.k = hmac_sha256(&self.k, &buf);
        self.v = hmac_sha256(&self.k, &self.v);
        None
    }
}

/// Sign a 32-byte message digest with ECDSA/P-256 using an RFC 6979
/// deterministic nonce. `private_key` is the 32-byte big-endian scalar `d`
/// (`1 <= d < n`). Returns the signature as P1363-form `(r, s)` 32-byte
/// big-endian components, or `None` for an invalid key.
#[cfg(feature = "ecdsa-sign")]
pub fn sign_p256(private_key: &[u8; 32], digest: &[u8; 32]) -> Option<([u8; 32], [u8; 32])> {
    let d = Scalar::from_bytes_be(private_key).filter(|d| !d.is_zero())?;
    let e = Scalar::from_bytes_be_reduce(digest);
    let mut rng = Rfc6979::new(private_key, digest);
    // RFC 6979 makes repeated r==0 / s==0 vanishingly unlikely; bound anyway.
    for _ in 0..64 {
        let Some(k) = rng.next_candidate() else {
            continue;
        };
        let r_point = super::point::scalar_mul_base(&k);
        let r = Scalar::from_bytes_be_reduce(&r_point.x.to_bytes_be());
        if r.is_zero() {
            continue;
        }
        // s = k^-1 (e + r*d) mod n
        let s = k.invert().mul(&e.add(&r.mul(&d)));
        if s.is_zero() {
            continue;
        }
        return Some((r.to_bytes_be(), s.to_bytes_be()));
    }
    None
}

pub mod ecdsa_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    // Linux crypto/testmgr.h p1363_ecdsa_nist_p256_tv_template[0]:
    // secp256r1(sha256), uncompressed public key (0x04 || X || Y).
    const PUBKEY: [u8; 65] = [
        0x04, 0xf1, 0xea, 0xc4, 0x53, 0xf3, 0xb9, 0x0e, 0x9f, 0x7e, 0xad, 0xe3, 0xea, 0xd7, 0x0e,
        0x0f, 0xd6, 0x98, 0x9a, 0xca, 0x92, 0x4d, 0x0a, 0x80, 0xdb, 0x2d, 0x45, 0xc7, 0xec, 0x4b,
        0x97, 0x00, 0x2f, 0xe9, 0x42, 0x6c, 0x29, 0xdc, 0x55, 0x0e, 0x0b, 0x53, 0x12, 0x9b, 0x2b,
        0xad, 0x2c, 0xe9, 0x80, 0xe6, 0xc5, 0x43, 0xc2, 0x1d, 0x5e, 0xbb, 0x65, 0x21, 0x50, 0xb6,
        0x37, 0xb0, 0x03, 0x8e, 0xb8,
    ];
    // 32-byte message digest.
    const DIGEST: [u8; 32] = [
        0x8f, 0x43, 0x43, 0x46, 0x64, 0x8f, 0x6b, 0x96, 0xdf, 0x89, 0xdd, 0xa9, 0x01, 0xc5, 0x17,
        0x6b, 0x10, 0xa6, 0xd8, 0x39, 0x61, 0xdd, 0x3c, 0x1a, 0xc8, 0x8b, 0x59, 0xb2, 0xdc, 0x32,
        0x7a, 0xa4,
    ];
    // Signature r || s (P1363).
    const R: [u8; 32] = [
        0x08, 0x31, 0xfa, 0x74, 0x0d, 0x1d, 0x21, 0x5d, 0x09, 0xdc, 0x29, 0x63, 0xa8, 0x1a, 0xad,
        0xfc, 0xac, 0x44, 0xc3, 0xe8, 0x24, 0x11, 0x2d, 0xa4, 0x91, 0xdc, 0x02, 0x67, 0xdc, 0x0c,
        0xd0, 0x82,
    ];
    const S: [u8; 32] = [
        0xbd, 0xff, 0xce, 0xee, 0x42, 0xc3, 0x97, 0xff, 0xf9, 0xa9, 0x81, 0xac, 0x4a, 0x50, 0xd0,
        0x91, 0x0a, 0x6e, 0x1b, 0xc4, 0xaf, 0xe1, 0x83, 0xc3, 0x4f, 0x2a, 0x65, 0x35, 0x23, 0xe3,
        0x1d, 0xfa,
    ];

    fn smoke_ecdsa_p256_nist_kat() -> TestResult {
        if !verify_p256(&PUBKEY, &DIGEST, &R, &S) {
            return TestResult::Fail("valid NIST ECDSA-P256 vector rejected");
        }
        let mut bad_digest = DIGEST;
        bad_digest[0] ^= 0x01;
        if verify_p256(&PUBKEY, &bad_digest, &R, &S) {
            return TestResult::Fail("tampered digest accepted");
        }
        let mut bad_s = S;
        bad_s[31] ^= 0x01;
        if verify_p256(&PUBKEY, &DIGEST, &R, &bad_s) {
            return TestResult::Fail("tampered signature accepted");
        }
        // A zero signature component is out of range.
        if verify_p256(&PUBKEY, &DIGEST, &[0u8; 32], &S) {
            return TestResult::Fail("zero r accepted");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_ecdsa_p256_nist_kat);

    // RFC 6979 Appendix A.2.5 (P-256, SHA-256) deterministic-signature vectors.
    #[cfg(feature = "ecdsa-sign")]
    const RFC6979_KEY: [u8; 32] = [
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16, 0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6,
        0x93, 0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12, 0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f,
        0x67, 0x21,
    ];
    // Public key U = d*G, uncompressed (for the verify cross-check).
    #[cfg(feature = "ecdsa-sign")]
    const RFC6979_PUB: [u8; 65] = [
        0x04, 0x60, 0xfe, 0xd4, 0xba, 0x25, 0x5a, 0x9d, 0x31, 0xc9, 0x61, 0xeb, 0x74, 0xc6, 0x35,
        0x6d, 0x68, 0xc0, 0x49, 0xb8, 0x92, 0x3b, 0x61, 0xfa, 0x6c, 0xe6, 0x69, 0x62, 0x2e, 0x60,
        0xf2, 0x9f, 0xb6, 0x79, 0x03, 0xfe, 0x10, 0x08, 0xb8, 0xbc, 0x99, 0xa4, 0x1a, 0xe9, 0xe9,
        0x56, 0x28, 0xbc, 0x64, 0xf2, 0xf1, 0xb2, 0x0c, 0x2d, 0x7e, 0x9f, 0x51, 0x77, 0xa3, 0xc2,
        0x94, 0xd4, 0x46, 0x22, 0x99,
    ];

    #[cfg(feature = "ecdsa-sign")]
    fn smoke_ecdsa_p256_rfc6979_sign() -> TestResult {
        use crate::sha256::Sha256;
        // message = "sample"
        let mut h = Sha256::new();
        h.update(b"sample");
        let digest = h.finalize();
        let r_hex: [u8; 32] = [
            0xef, 0xd4, 0x8b, 0x2a, 0xac, 0xb6, 0xa8, 0xfd, 0x11, 0x40, 0xdd, 0x9c, 0xd4, 0x5e,
            0x81, 0xd6, 0x9d, 0x2c, 0x87, 0x7b, 0x56, 0xaa, 0xf9, 0x91, 0xc3, 0x4d, 0x0e, 0xa8,
            0x4e, 0xaf, 0x37, 0x16,
        ];
        let s_hex: [u8; 32] = [
            0xf7, 0xcb, 0x1c, 0x94, 0x2d, 0x65, 0x7c, 0x41, 0xd4, 0x36, 0xc7, 0xa1, 0xb6, 0xe2,
            0x9f, 0x65, 0xf3, 0xe9, 0x00, 0xdb, 0xb9, 0xaf, 0xf4, 0x06, 0x4d, 0xc4, 0xab, 0x2f,
            0x84, 0x3a, 0xcd, 0xa8,
        ];
        let (r, s) = match sign_p256(&RFC6979_KEY, &digest) {
            Some(sig) => sig,
            None => return TestResult::Fail("sign_p256 returned None for a valid key"),
        };
        if r != r_hex || s != s_hex {
            return TestResult::Fail("RFC 6979 P-256 sample signature mismatch");
        }
        // The produced signature verifies under the matching public key.
        if !verify_p256(&RFC6979_PUB, &digest, &r, &s) {
            return TestResult::Fail("self-signed signature failed verification");
        }
        // message = "test"
        let mut h = Sha256::new();
        h.update(b"test");
        let digest_t = h.finalize();
        let rt: [u8; 32] = [
            0xf1, 0xab, 0xb0, 0x23, 0x51, 0x83, 0x51, 0xcd, 0x71, 0xd8, 0x81, 0x56, 0x7b, 0x1e,
            0xa6, 0x63, 0xed, 0x3e, 0xfc, 0xf6, 0xc5, 0x13, 0x2b, 0x35, 0x4f, 0x28, 0xd3, 0xb0,
            0xb7, 0xd3, 0x83, 0x67,
        ];
        let st: [u8; 32] = [
            0x01, 0x9f, 0x41, 0x13, 0x74, 0x2a, 0x2b, 0x14, 0xbd, 0x25, 0x92, 0x6b, 0x49, 0xc6,
            0x49, 0x15, 0x5f, 0x26, 0x7e, 0x60, 0xd3, 0x81, 0x4b, 0x4c, 0x0c, 0xc8, 0x42, 0x50,
            0xe4, 0x6f, 0x00, 0x83,
        ];
        match sign_p256(&RFC6979_KEY, &digest_t) {
            Some((r, s)) if r == rt && s == st => TestResult::Pass,
            _ => TestResult::Fail("RFC 6979 P-256 test-message signature mismatch"),
        }
    }
    #[cfg(feature = "ecdsa-sign")]
    kernel_test_in!("crypto/p256", smoke_ecdsa_p256_rfc6979_sign);
}

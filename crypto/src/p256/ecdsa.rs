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
}

//! Hash-to-Curve for NIST P-256 — RFC 9380 §6.6.
//!
//! Implements `hash_to_curve` for the suite `P256_XMD:SHA-256_SSWU_RO_`
//! per RFC 9380 §8.2: expand_message_xmd with SHA-256 produces two
//! field elements, each mapped to the curve via the Simplified SWU
//! map for p ≡ 3 (mod 4) (RFC 9380 §6.6.2), then added.
//!
//! ## Why this exists in NARF
//!
//! IEEE 802.11-2020 §12.4.4.2.3 (SAE Hash-to-Element, "H2E") uses
//! `hash_to_curve` to derive the SAE Password Token (PT) once per
//! `(ssid, password)` and to convert PT to PWE per `(mac_a, mac_b)`.
//! H2E is the side-channel-safe replacement for the legacy
//! hunting-and-pecking loop (§12.4.4.2.2). This module is the curve
//! arithmetic underneath; the SAE-specific DST and PT/PWE flow live
//! in `narf-wireless::sae::pt`.
//!
//! ## References
//!
//! - RFC 9380 "Hashing to Elliptic Curves" §6.6.2 (SSWU map for
//!   p ≡ 3 mod 4) and §8.2 (the P-256 suite).
//!   <https://datatracker.ietf.org/doc/html/rfc9380>
//! - IEEE 802.11-2020 §12.4.4.2.3 — SAE Hash-to-Element.
//! - hostap `src/common/sae.c` `sae_h2e_pt_curve()` is the canonical
//!   reference implementation. NARF is GPL-2.0-or-later post
//!   2026-05-20, so the algorithmic structure can be (and is) cited
//!   directly. The code here is independently written.
//!
//! ## Constants for P-256 SSWU (RFC 9380 §8.2, Z = -10)
//!
//! For P-256:
//! - `a = -3 mod p` (curve parameter)
//! - `b` = CURVE_B
//! - `Z = -10 mod p`  (chosen per RFC 9380 §8.2 / Appendix F.2)
//!
//! The Simplified SWU map for `p ≡ 3 (mod 4)` (§6.6.2) is:
//! ```text
//!   tv1 = inv0(Z^2 * u^4 + Z * u^2)
//!   x1  = (-b / a) * (1 + tv1)
//!   if tv1 == 0:
//!       x1 = b / (Z * a)
//!   gx1 = x1^3 + a*x1 + b
//!   x2  = Z * u^2 * x1
//!   gx2 = x2^3 + a*x2 + b
//!   if gx1 is a square: (x, y) = (x1, sqrt(gx1))
//!   else:               (x, y) = (x2, sqrt(gx2))
//!   if sgn0(u) != sgn0(y): y = -y
//! ```
//! For NIST P-256, `clear_cofactor` is the identity (cofactor = 1) so
//! we omit the final cofactor multiplication.

use super::field::Fp;
use super::point::AffinePoint;
use crate::sha256::Sha256;
use alloc::vec::Vec;

/// L parameter for P-256 in RFC 9380 §5.3.1: `L = ceil((ceil(log2(p)) + k) / 8)`
/// with k = 128 (target security level). log2(p) ≈ 256, so L = 48.
const L_P256: usize = 48;

/// Output size of SHA-256 in bytes (`b_in_bytes` per RFC 9380 §5.3.1).
const B_IN_BYTES: usize = 32;
/// Input block size of SHA-256 (`s_in_bytes` per RFC 9380 §5.3.1).
const S_IN_BYTES: usize = 64;

/// `expand_message_xmd` with SHA-256 (RFC 9380 §5.3.1).
///
/// `dst` (Domain Separation Tag) must be ≤ 255 bytes. RFC 9380 §5.3.3
/// describes the longer-DST handling (`expand_message_xmd_dst_prime`)
/// — we enforce the ≤ 255 cap here since SAE DSTs are short.
fn expand_message_xmd(msg: &[u8], dst: &[u8], len_in_bytes: usize) -> Vec<u8> {
    debug_assert!(dst.len() <= 255, "DST too long; RFC 9380 §5.3.3");
    let ell = len_in_bytes.div_ceil(B_IN_BYTES);
    debug_assert!(ell <= 255, "expand_message_xmd output too long");

    // DST_prime = DST || I2OSP(len(DST), 1)
    let mut dst_prime: Vec<u8> = Vec::with_capacity(dst.len() + 1);
    dst_prime.extend_from_slice(dst);
    dst_prime.push(dst.len() as u8);

    // Z_pad = I2OSP(0, s_in_bytes)
    let z_pad = [0u8; S_IN_BYTES];
    // l_i_b_str = I2OSP(len_in_bytes, 2)
    let l_i_b_str = [(len_in_bytes >> 8) as u8, len_in_bytes as u8];

    // b_0 = H(Z_pad || msg || l_i_b_str || I2OSP(0, 1) || DST_prime)
    let mut h = Sha256::new();
    h.update(&z_pad);
    h.update(msg);
    h.update(&l_i_b_str);
    h.update(&[0u8]);
    h.update(&dst_prime);
    let b0 = h.finalize();

    // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
    let mut h = Sha256::new();
    h.update(&b0);
    h.update(&[1u8]);
    h.update(&dst_prime);
    let mut b_i = h.finalize();
    let mut out: Vec<u8> = Vec::with_capacity(ell * B_IN_BYTES);
    out.extend_from_slice(&b_i);

    // b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime)
    for i in 2..=(ell as u8) {
        let mut xored = [0u8; B_IN_BYTES];
        for j in 0..B_IN_BYTES {
            xored[j] = b0[j] ^ b_i[j];
        }
        let mut h = Sha256::new();
        h.update(&xored);
        h.update(&[i]);
        h.update(&dst_prime);
        b_i = h.finalize();
        out.extend_from_slice(&b_i);
    }

    out.truncate(len_in_bytes);
    out
}

/// `hash_to_field` for P-256 (RFC 9380 §5.3) — produces `count` field
/// elements. We always call it with count = 2 (SSWU-RO).
fn hash_to_field_p256(msg: &[u8], dst: &[u8], count: usize) -> Vec<Fp> {
    let len_in_bytes = count * L_P256;
    let uniform_bytes = expand_message_xmd(msg, dst, len_in_bytes);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let chunk = &uniform_bytes[i * L_P256..(i + 1) * L_P256];
        out.push(os2ip_mod_p(chunk));
    }
    out
}

/// OS2IP (big-endian byte string → integer) reduced mod p. The 48-byte
/// input is wider than the 32-byte representation, so we reduce by
/// splitting `bytes = hi || lo` (16 || 32) and computing
/// `(hi * 2^256 + lo) mod p` using `Fp` arithmetic.
///
/// `hi` is the most-significant 16 bytes. `2^256 mod p = 2^224 - 2^192 - 2^96 + 1`
/// — but rather than encode that as a constant, we just multiply `hi`'s
/// field representation by `2^256 mod p` via repeated doubling; the
/// 16-byte upper portion has at most 128 bits of magnitude so this is
/// cheap and avoids hand-coding a Solinas-style hi-limb reduction here.
fn os2ip_mod_p(bytes: &[u8]) -> Fp {
    debug_assert_eq!(bytes.len(), L_P256);
    // Build hi (16 bytes) and lo (32 bytes) as Fp by zero-extending each
    // to 32 BE bytes.
    let mut hi_be = [0u8; 32];
    hi_be[16..].copy_from_slice(&bytes[..16]);
    let hi = Fp::from_bytes_be(&hi_be).expect("hi < 2^128 < p");

    let mut lo_be = [0u8; 32];
    lo_be.copy_from_slice(&bytes[16..]);
    // `lo` may be >= p (extremely unlikely — p is just below 2^256, so
    // any 32-byte LO ≥ p means the top bits are nearly all-ones). Handle
    // by reducing once via Fp::add(0, lo) effectively; from_bytes_be
    // rejects ≥ p, so we fall back to a manual reduce in that case.
    let lo = Fp::from_bytes_be(&lo_be).unwrap_or_else(|| {
        // lo - p, since 2^256 - p < 2^256 and lo < 2^256 so lo - p fits.
        // Build (lo - p) as four limbs.
        let mut lo_limbs = [0u64; 4];
        for (i, limb) in lo_limbs.iter_mut().rev().enumerate() {
            let off = i * 8;
            *limb = u64::from_be_bytes([
                lo_be[off],
                lo_be[off + 1],
                lo_be[off + 2],
                lo_be[off + 3],
                lo_be[off + 4],
                lo_be[off + 5],
                lo_be[off + 6],
                lo_be[off + 7],
            ]);
        }
        // Subtract p limb-wise (input was >= p so no borrow).
        const P_LIMBS: [u64; 4] = [
            0xFFFF_FFFF_FFFF_FFFF,
            0x0000_0000_FFFF_FFFF,
            0x0000_0000_0000_0000,
            0xFFFF_FFFF_0000_0001,
        ];
        let mut out = [0u64; 4];
        let mut borrow: i128 = 0;
        for i in 0..4 {
            let d = (lo_limbs[i] as i128) - (P_LIMBS[i] as i128) - borrow;
            out[i] = d as u64;
            borrow = if d < 0 { 1 } else { 0 };
        }
        Fp::from_limbs(out)
    });

    // Multiply hi by 2^256 ≡ (2^224 - 2^192 - 2^96 + 1) (mod p).
    // We compute that by stepping `hi` through 256 squarings of 2 — or
    // more efficiently, by using the precomputed constant
    //   k = 2^256 mod p = 0x00000000FFFFFFFE_FFFFFFFFFFFFFFFF_FFFFFFFF00000000_0000000000000001
    // = 0xFFFFFFFE FFFFFFFF... Let's compute that explicitly:
    //   p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    //   so 2^256 mod p = (2^224 - 2^192 - 2^96 + 1) mod p
    //                  = 2^224 + (-2^192 mod p) + (-2^96 mod p) + 1.
    // But  it's easier and just as correct to compute by repeated doubling
    // of Fp::ONE 256 times: that is 256 field-additions, all cheap.
    let mut two_pow_256 = Fp::ONE;
    for _ in 0..256 {
        two_pow_256 = two_pow_256.add(&two_pow_256);
    }
    // Final result: hi * 2^256 + lo (mod p).
    hi.mul(&two_pow_256).add(&lo)
}

/// P-256 SSWU constant `Z = -10 mod p` (RFC 9380 §8.2 / Appendix F.2).
fn sswu_z() -> Fp {
    // 10 = 0x0A
    let ten = Fp::from_limbs([10, 0, 0, 0]);
    ten.neg()
}

/// P-256 curve `a = -3 mod p`.
fn curve_a() -> Fp {
    let three = Fp::from_limbs([3, 0, 0, 0]);
    three.neg()
}

/// Compute `gx = x^3 + a*x + b` for P-256 (a = -3, b = CURVE_B).
fn curve_eqn(x: &Fp) -> Fp {
    let x2 = x.square();
    let x3 = x2.mul(x);
    let three_x = x.add(x).add(x);
    let b = Fp::from_limbs(super::CURVE_B);
    x3.sub(&three_x).add(&b)
}

/// Simplified SWU map for `p ≡ 3 (mod 4)` (RFC 9380 §6.6.2).
///
/// Follows the reference 10-step listing verbatim:
///   tv1 = inv0(Z²u⁴ + Zu²)
///   x1  = (-B/A) * (1 + tv1)            // or B/(Z*A) if tv1 == 0
///   gx1 = x1³ + a·x1 + b
///   x2  = Z·u² · x1
///   gx2 = x2³ + a·x2 + b
///   (x, y) = (x1, sqrt(gx1)) if gx1 is a square, else (x2, sqrt(gx2))
///   if sgn0(u) != sgn0(y): y = -y
fn map_to_curve_sswu(u: &Fp) -> AffinePoint {
    let z = sswu_z();
    let a = curve_a();
    let b = Fp::from_limbs(super::CURVE_B);

    let z_u2 = z.mul(&u.square()); // Z·u²
    let z2_u4 = z_u2.square(); // Z²·u⁴
    let denom = z2_u4.add(&z_u2); // Z²u⁴ + Z u²

    // x1 = (-B / A) * (1 + inv0(denom)); exceptional path picks B/(Z·A).
    let x1 = if denom.is_zero() {
        b.mul(&z.mul(&a).invert())
    } else {
        let tv1 = denom.invert();
        b.neg().mul(&a.invert()).mul(&Fp::ONE.add(&tv1))
    };
    let gx1 = curve_eqn(&x1);
    let x2 = z_u2.mul(&x1);
    let gx2 = curve_eqn(&x2);

    let (x_out, y_pre) = if gx1.is_quadratic_residue() {
        (x1, gx1.sqrt())
    } else {
        // gx2 is guaranteed to be a QR when gx1 is not — RFC 9380 §6.6.2.
        (x2, gx2.sqrt())
    };

    // sgn0 for P-256 (RFC 9380 §4.1) is the LSB of the integer representative.
    let y_out = if u.lsb() == y_pre.lsb() {
        y_pre
    } else {
        y_pre.neg()
    };

    AffinePoint {
        x: x_out,
        y: y_out,
        infinity: false,
    }
}

/// `hash_to_curve` for the suite `P256_XMD:SHA-256_SSWU_RO_`
/// (RFC 9380 §8.2). Produces a point that decodes as on-curve and is
/// uniformly distributed over the group (modulo the SSWU map's
/// statistical properties — see RFC 9380 §6).
pub fn p256_hash_to_curve(msg: &[u8], dst: &[u8]) -> AffinePoint {
    let us = hash_to_field_p256(msg, dst, 2);
    let q0 = map_to_curve_sswu(&us[0]);
    let q1 = map_to_curve_sswu(&us[1]);
    // R = Q0 + Q1; clear_cofactor is identity for P-256.
    q0.to_projective().add_mixed(&q1).to_affine()
}

/// `encode_to_curve` for the suite `P256_XMD:SHA-256_SSWU_NU_` — same
/// pipeline but only one field element is mapped (RFC 9380 §3,
/// "non-uniform" encoding). Cheaper, but unsuitable wherever a
/// uniform distribution is required. SAE H2E uses the uniform RO
/// variant, so this is exposed only for completeness / tests.
pub fn p256_encode_to_curve(msg: &[u8], dst: &[u8]) -> AffinePoint {
    let us = hash_to_field_p256(msg, dst, 1);
    map_to_curve_sswu(&us[0])
}

// ── Tests ──────────────────────────────────────────────────────────

pub mod h2c_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_p256_h2c_produces_on_curve_point() -> TestResult {
        // The output of hash_to_curve must satisfy y^2 = x^3 - 3x + b
        // for any (msg, dst). RFC 9380 §7.
        let p = p256_hash_to_curve(b"abc", b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_");
        if !p.is_on_curve() {
            return TestResult::Fail("h2c output must be on curve");
        }
        if p.infinity {
            return TestResult::Fail("h2c output must not be infinity");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_h2c_produces_on_curve_point);

    fn smoke_p256_h2c_deterministic_on_inputs() -> TestResult {
        // Same (msg, dst) ⇒ same point. RFC 9380 hash_to_curve is a
        // deterministic function.
        let dst = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
        let p1 = p256_hash_to_curve(b"abc", dst);
        let p2 = p256_hash_to_curve(b"abc", dst);
        if p1.x != p2.x || p1.y != p2.y {
            return TestResult::Fail("h2c not deterministic");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_h2c_deterministic_on_inputs);

    fn smoke_p256_h2c_domain_separation_changes_output() -> TestResult {
        // Different DST ⇒ different point with overwhelming probability.
        // RFC 9380 §3.1 — DST is the principal domain-separation knob.
        let p1 = p256_hash_to_curve(b"hello", b"DST-A");
        let p2 = p256_hash_to_curve(b"hello", b"DST-B");
        if p1.x == p2.x && p1.y == p2.y {
            return TestResult::Fail("DST should change h2c output");
        }
        TestResult::Pass
    }
    kernel_test_in!(
        "crypto/p256",
        smoke_p256_h2c_domain_separation_changes_output
    );

    fn smoke_p256_h2c_message_changes_output() -> TestResult {
        // Same DST, different msg ⇒ different point.
        let dst = b"DST";
        let p1 = p256_hash_to_curve(b"msg1", dst);
        let p2 = p256_hash_to_curve(b"msg2", dst);
        if p1.x == p2.x && p1.y == p2.y {
            return TestResult::Fail("msg should change h2c output");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_h2c_message_changes_output);

    fn smoke_p256_h2c_sswu_alone_lands_on_curve() -> TestResult {
        // The SSWU map alone must produce on-curve points for any
        // field-element input. Exercise a handful.
        for seed in [0u64, 1, 2, 0xDEAD, 0xBEEF, 0xFFFFFFFF] {
            let u = Fp::from_limbs([seed, 0, 0, 0]);
            let p = map_to_curve_sswu(&u);
            if !p.is_on_curve() {
                return TestResult::Fail("SSWU output off curve");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_h2c_sswu_alone_lands_on_curve);

    fn smoke_p256_expand_message_xmd_length() -> TestResult {
        // expand_message_xmd's output length must equal len_in_bytes
        // (RFC 9380 §5.3.1). Verify on the L=48 path SAE/H2E uses.
        let out = expand_message_xmd(b"abc", b"DST", 48);
        if out.len() != 48 {
            return TestResult::Fail("expand_message_xmd length wrong");
        }
        let out2 = expand_message_xmd(b"abc", b"DST", 96);
        if out2.len() != 96 {
            return TestResult::Fail("expand_message_xmd 96-byte length wrong");
        }
        // Different lengths produce different prefixes — XMD is not
        // suffix-truncatable (it mixes len_in_bytes into b_0).
        if out2[..48] == out[..] {
            return TestResult::Fail("XMD outputs at different lengths must differ");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_expand_message_xmd_length);

    fn smoke_p256_h2c_encode_to_curve_on_curve() -> TestResult {
        // The non-uniform encode_to_curve variant must also land on curve.
        let p = p256_encode_to_curve(b"abc", b"DST-NU");
        if !p.is_on_curve() {
            return TestResult::Fail("encode_to_curve off curve");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_h2c_encode_to_curve_on_curve);
}

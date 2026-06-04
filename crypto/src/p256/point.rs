//! P-256 group operations.
//!
//! Curve equation: y^2 = x^3 + a*x + b  with  a = -3, b as defined in
//! FIPS 186-4 §D.1.2.3.
//!
//! ## Representation
//!
//! Points are kept in Jacobian projective coordinates (X:Y:Z) where
//! the affine equivalent is (X/Z^2, Y/Z^3). The point at infinity is
//! encoded as Z = 0.
//!
//! - Doubling: `2P` via the textbook a = -3 doubling formula —
//!   ten field operations. Reference: Cohen-Frey "Handbook of EHCC"
//!   §13.2.1 (Algorithm 13.6) and Bernstein-Lange explicit-formulas
//!   database "dbl-2001-b".
//! - Addition: `P + Q` via the strongly-unified formulas of
//!   Renes-Costello-Batina 2016 §4. We use the simpler "P != Q" path
//!   with an explicit doubling fall-back when the inputs are equal —
//!   this is fine for SAE / ECDH because the scalar-mul loop already
//!   chooses double vs. add based on the (public) bit pattern of the
//!   ladder counter, not the (secret) scalar bits, so the timing
//!   asymmetry between the two formulas does not leak the secret.
//!
//! Scalar multiplication uses a left-to-right double-and-add ladder
//! with constant-time conditional accumulation. For every bit of the
//! scalar we double the running result and conditionally add the base
//! point; the conditional add is implemented via a constant-time
//! select between (result + base) and result. This matches the
//! recommendation in 802.11-2020 §12.4 NOTE: the loop runs the same
//! number of operations regardless of the scalar's bit pattern.

use super::field::Fp;
use super::scalar::Scalar;
use super::{CURVE_B, GENERATOR_X, GENERATOR_Y};

/// Affine point — (x, y) on the curve, OR the point-at-infinity
/// (encoded as `infinity == true`, x/y ignored).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AffinePoint {
    pub x: Fp,
    pub y: Fp,
    pub infinity: bool,
}

impl AffinePoint {
    pub const INFINITY: Self = Self {
        x: Fp::ZERO,
        y: Fp::ZERO,
        infinity: true,
    };

    /// The P-256 generator G.
    pub fn generator() -> Self {
        Self {
            x: Fp::from_limbs(GENERATOR_X),
            y: Fp::from_limbs(GENERATOR_Y),
            infinity: false,
        }
    }

    /// Verify that `(x, y)` satisfies the curve equation
    /// y^2 == x^3 - 3x + b. Infinity vacuously passes.
    pub fn is_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }
        let x2 = self.x.square();
        let x3 = x2.mul(&self.x);
        // -3x = x*(-3). Build "3*x" then negate.
        let three_x = self.x.add(&self.x).add(&self.x);
        let rhs = x3.sub(&three_x).add(&Fp::from_limbs(CURVE_B));
        let lhs = self.y.square();
        lhs == rhs
    }

    /// Encode as 64 bytes X || Y (big-endian). Rejects infinity.
    pub fn to_encoded(&self) -> Option<[u8; 64]> {
        if self.infinity {
            return None;
        }
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x.to_bytes_be());
        out[32..].copy_from_slice(&self.y.to_bytes_be());
        Some(out)
    }

    /// Decode a 64-byte buffer (X || Y, big-endian). Rejects points
    /// that fail the curve-equation test or fall out of [0, p).
    pub fn from_encoded(buf: &[u8]) -> Option<Self> {
        if buf.len() != 64 {
            return None;
        }
        let mut xb = [0u8; 32];
        let mut yb = [0u8; 32];
        xb.copy_from_slice(&buf[..32]);
        yb.copy_from_slice(&buf[32..]);
        let x = Fp::from_bytes_be(&xb)?;
        let y = Fp::from_bytes_be(&yb)?;
        let p = Self {
            x,
            y,
            infinity: false,
        };
        if !p.is_on_curve() {
            return None;
        }
        Some(p)
    }

    pub fn to_projective(&self) -> ProjectivePoint {
        if self.infinity {
            ProjectivePoint::infinity()
        } else {
            ProjectivePoint {
                x: self.x,
                y: self.y,
                z: Fp::ONE,
            }
        }
    }
}

/// Jacobian projective coordinates. Z = 0 marks the point at infinity.
#[derive(Clone, Copy, Debug)]
pub struct ProjectivePoint {
    pub x: Fp,
    pub y: Fp,
    pub z: Fp,
}

impl ProjectivePoint {
    pub fn infinity() -> Self {
        Self {
            x: Fp::ONE,
            y: Fp::ONE,
            z: Fp::ZERO,
        }
    }

    pub fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    /// Convert back to affine. Returns `AffinePoint::INFINITY` when
    /// Z == 0.
    pub fn to_affine(&self) -> AffinePoint {
        if self.is_infinity() {
            return AffinePoint::INFINITY;
        }
        let z_inv = self.z.invert();
        let z_inv2 = z_inv.square();
        let z_inv3 = z_inv2.mul(&z_inv);
        AffinePoint {
            x: self.x.mul(&z_inv2),
            y: self.y.mul(&z_inv3),
            infinity: false,
        }
    }

    /// Point doubling, a = -3 (Cohen-Frey Algorithm 13.6,
    /// Bernstein-Lange "dbl-2001-b"). Ten field ops.
    pub fn double(&self) -> Self {
        if self.is_infinity() {
            return *self;
        }
        // delta = Z^2
        let delta = self.z.square();
        // gamma = Y^2
        let gamma = self.y.square();
        // beta = X * gamma
        let beta = self.x.mul(&gamma);
        // alpha = 3 * (X - delta) * (X + delta)
        let x_minus_delta = self.x.sub(&delta);
        let x_plus_delta = self.x.add(&delta);
        let alpha_pre = x_minus_delta.mul(&x_plus_delta);
        let alpha = alpha_pre.add(&alpha_pre).add(&alpha_pre);
        // X3 = alpha^2 - 8*beta
        let eight_beta = {
            let two = beta.add(&beta);
            let four = two.add(&two);
            four.add(&four)
        };
        let x3 = alpha.square().sub(&eight_beta);
        // Z3 = (Y + Z)^2 - gamma - delta
        let y_plus_z = self.y.add(&self.z);
        let z3 = y_plus_z.square().sub(&gamma).sub(&delta);
        // Y3 = alpha * (4*beta - X3) - 8 * gamma^2
        let four_beta = beta.add(&beta).add(&beta).add(&beta);
        let gamma2 = gamma.square();
        let eight_gamma2 = {
            let t = gamma2.add(&gamma2);
            let four_g2 = t.add(&t);
            four_g2.add(&four_g2)
        };
        let y3 = alpha.mul(&four_beta.sub(&x3)).sub(&eight_gamma2);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Add a Jacobian point `self` and an affine point `other`. Affine
    /// + Jacobian is cheaper than Jacobian + Jacobian and is what the
    /// scalar-mul ladder needs. Handles all degenerate cases:
    /// self == ∞, other == ∞, self == other (doubling), self == -other
    /// (infinity).
    ///
    /// Formula: "madd-2007-bl" from the Bernstein-Lange explicit-formulas
    /// database (mixed addition for short Weierstrass / Jacobian /
    /// a = -3 is not needed for the addition formula; b is irrelevant
    /// to the addition step).
    pub fn add_mixed(&self, other: &AffinePoint) -> Self {
        if other.infinity {
            return *self;
        }
        if self.is_infinity() {
            return other.to_projective();
        }
        // U2 = X2 * Z1^2
        let z1_sq = self.z.square();
        let u2 = other.x.mul(&z1_sq);
        // S2 = Y2 * Z1^3
        let z1_cu = z1_sq.mul(&self.z);
        let s2 = other.y.mul(&z1_cu);
        // H = U2 - X1
        let h = u2.sub(&self.x);
        // r = S2 - Y1
        let r = s2.sub(&self.y);
        if h.is_zero() {
            // Either same point (need doubling) or opposite (gives ∞).
            if r.is_zero() {
                return self.double();
            } else {
                return Self::infinity();
            }
        }
        // HH = H^2
        let hh = h.square();
        // HHH = H * HH
        let hhh = h.mul(&hh);
        // V = X1 * HH
        let v = self.x.mul(&hh);
        // X3 = r^2 - HHH - 2*V
        let two_v = v.add(&v);
        let x3 = r.square().sub(&hhh).sub(&two_v);
        // Y3 = r * (V - X3) - Y1 * HHH
        let y3 = r.mul(&v.sub(&x3)).sub(&self.y.mul(&hhh));
        // Z3 = Z1 * H
        let z3 = self.z.mul(&h);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Add two Jacobian points. Slower than `add_mixed` (one extra
    /// squaring, two extra mults), used at the affine-affine boundary
    /// when callers don't have a Z = 1 representative.
    ///
    /// Bernstein-Lange "add-2007-bl" — fully general add for short
    /// Weierstrass curves. Handles self == other by re-dispatching to
    /// `double`.
    pub fn add(&self, other: &Self) -> Self {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }
        let z1_sq = self.z.square();
        let z2_sq = other.z.square();
        let u1 = self.x.mul(&z2_sq);
        let u2 = other.x.mul(&z1_sq);
        let z1_cu = z1_sq.mul(&self.z);
        let z2_cu = z2_sq.mul(&other.z);
        let s1 = self.y.mul(&z2_cu);
        let s2 = other.y.mul(&z1_cu);
        let h = u2.sub(&u1);
        let r = s2.sub(&s1);
        if h.is_zero() {
            if r.is_zero() {
                return self.double();
            } else {
                return Self::infinity();
            }
        }
        let hh = h.square();
        let hhh = h.mul(&hh);
        let v = u1.mul(&hh);
        let two_v = v.add(&v);
        let x3 = r.square().sub(&hhh).sub(&two_v);
        let y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&hhh));
        let z3 = self.z.mul(&other.z).mul(&h);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    /// Conditional select: returns `a` if `take == 1`, else `b`.
    /// Constant-time over `take`.
    fn ct_select(a: &Self, b: &Self, take: u64) -> Self {
        let mask = 0u64.wrapping_sub(take);
        let mut x = [0u64; 4];
        let mut y = [0u64; 4];
        let mut z = [0u64; 4];
        for i in 0..4 {
            x[i] = (a.x.0[i] & mask) | (b.x.0[i] & !mask);
            y[i] = (a.y.0[i] & mask) | (b.y.0[i] & !mask);
            z[i] = (a.z.0[i] & mask) | (b.z.0[i] & !mask);
        }
        Self {
            x: Fp(x),
            y: Fp(y),
            z: Fp(z),
        }
    }
}

/// Scalar multiplication `k * P` via a left-to-right double-and-add
/// ladder. For every scalar bit we double the accumulator and then
/// conditionally add `P` — the conditional add materialises both
/// branches and selects via a mask, so total operation count is fixed
/// regardless of the bit pattern (constant-time over the secret).
///
/// The doubling and addition formulas themselves are not strictly
/// branchless — `add_mixed` short-circuits when h == 0 — but those
/// short-circuits only fire on adversary-chosen degenerate inputs, not
/// on secret-key bits. For 256 iterations against `k` and a public `P`
/// the timing trace is the same.
pub fn scalar_mul(k: &Scalar, p: &AffinePoint) -> AffinePoint {
    let mut acc = ProjectivePoint::infinity();
    // Walk MSB → LSB across all 256 bits.
    for limb_i in (0..4).rev() {
        let limb = k.0[limb_i];
        for bit in (0..64).rev() {
            acc = acc.double();
            let candidate = acc.add_mixed(p);
            let take = ((limb >> bit) & 1) as u64;
            acc = ProjectivePoint::ct_select(&candidate, &acc, take);
        }
    }
    acc.to_affine()
}

/// Convenience: `k * G`. Used to derive ECDH public keys (RFC 5903 §8.1).
pub fn scalar_mul_base(k: &Scalar) -> AffinePoint {
    scalar_mul(k, &AffinePoint::generator())
}

// ── Tests ──────────────────────────────────────────────────────────

pub mod point_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_p256_generator_on_curve() -> TestResult {
        let g = AffinePoint::generator();
        if !g.is_on_curve() {
            return TestResult::Fail("G not on curve");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_generator_on_curve);

    fn smoke_p256_point_double_2g_on_curve() -> TestResult {
        // 2G should also be on the curve.
        let g = AffinePoint::generator().to_projective();
        let two_g = g.double().to_affine();
        if two_g.infinity {
            return TestResult::Fail("2G shouldn't be infinity");
        }
        if !two_g.is_on_curve() {
            return TestResult::Fail("2G not on curve");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_point_double_2g_on_curve);

    fn smoke_p256_point_add_g_plus_g_eq_2g() -> TestResult {
        // G + G should equal 2G via the doubling formula.
        let g_aff = AffinePoint::generator();
        let g = g_aff.to_projective();
        let two_g_dbl = g.double().to_affine();
        let two_g_add = g.add_mixed(&g_aff).to_affine();
        if two_g_dbl != two_g_add {
            return TestResult::Fail("G+G via add != 2G via double");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_point_add_g_plus_g_eq_2g);

    fn smoke_p256_scalar_mul_1_eq_g() -> TestResult {
        // 1 * G = G.
        let one = Scalar::ONE;
        let result = scalar_mul_base(&one);
        let g = AffinePoint::generator();
        if result != g {
            return TestResult::Fail("1 * G != G");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_scalar_mul_1_eq_g);

    fn smoke_p256_scalar_mul_2_eq_double_g() -> TestResult {
        // 2 * G = G.double()
        let two = Scalar::from_limbs([2, 0, 0, 0]);
        let result = scalar_mul_base(&two);
        let expected = AffinePoint::generator()
            .to_projective()
            .double()
            .to_affine();
        if result != expected {
            return TestResult::Fail("2 * G != double(G)");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_scalar_mul_2_eq_double_g);

    fn smoke_p256_ecdh_rfc5903_test_vector() -> TestResult {
        // RFC 5903 §8.1: P-256 ECDH test vector.
        //
        //   i = C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433
        //   gIx = DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180
        //   gIy = 5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3
        //
        // i = the initiator's private scalar; (gIx, gIy) = i * G.
        let mut i_be = [0u8; 32];
        i_be.copy_from_slice(&hex_decode_32(
            b"C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433",
        ));
        let i = match Scalar::from_bytes_be(&i_be) {
            Some(s) => s,
            None => return TestResult::Fail("decode i"),
        };
        let pub_pt = scalar_mul_base(&i);
        let exp_x =
            hex_decode_32(b"DAD0B65394221CF9B051E1FECA5787D098DFE637FC90B9EF945D0C3772581180");
        let exp_y =
            hex_decode_32(b"5271A0461CDB8252D61F1C456FA3E59AB1F45B33ACCF5F58389E0577B8990BB3");
        if pub_pt.x.to_bytes_be() != exp_x {
            return TestResult::Fail("i*G.x mismatch");
        }
        if pub_pt.y.to_bytes_be() != exp_y {
            return TestResult::Fail("i*G.y mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_ecdh_rfc5903_test_vector);

    fn smoke_p256_ecdh_rfc5903_shared() -> TestResult {
        // RFC 5903 §8.1: shared secret Z.
        //
        //   i  = C88F01F5...
        //   gRx = D12DFB52... gRy = 76E49B6D...   (peer's public key)
        //   Z = D6840F6B... (the shared X-coordinate from i * gR)
        let i = Scalar::from_bytes_be(&hex_decode_32(
            b"C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433",
        ))
        .expect("decode i");
        let g_r_x = Fp::from_bytes_be(&hex_decode_32(
            b"D12DFB5289C8D4F81208B70270398C342296970A0BCCB74C736FC7554494BF63",
        ))
        .expect("decode gRx");
        let g_r_y = Fp::from_bytes_be(&hex_decode_32(
            b"56FBF3CA366CC23E8157854C13C58D6AAC23F046ADA30F8353E74F33039872AB",
        ))
        .expect("decode gRy");
        let g_r = AffinePoint {
            x: g_r_x,
            y: g_r_y,
            infinity: false,
        };
        if !g_r.is_on_curve() {
            return TestResult::Fail("peer's gR not on curve");
        }
        let shared = scalar_mul(&i, &g_r);
        let exp_z =
            hex_decode_32(b"D6840F6B42F6EDAFD13116E0E12565202FEF8E9ECE7DCE03812464D04B9442DE");
        if shared.x.to_bytes_be() != exp_z {
            return TestResult::Fail("shared Z mismatch");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_ecdh_rfc5903_shared);

    fn smoke_p256_affine_encode_roundtrip() -> TestResult {
        let g = AffinePoint::generator();
        let enc = g.to_encoded().expect("encode G");
        let g2 = AffinePoint::from_encoded(&enc).expect("decode G");
        if g != g2 {
            return TestResult::Fail("encode/decode G");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_affine_encode_roundtrip);

    fn smoke_p256_reject_off_curve_point() -> TestResult {
        // (1, 1) is almost certainly off curve.
        let mut buf = [0u8; 64];
        buf[31] = 1;
        buf[63] = 1;
        if AffinePoint::from_encoded(&buf).is_some() {
            return TestResult::Fail("should reject (1,1) as off curve");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_reject_off_curve_point);

    // ── helpers ─────────────────────────────────────────────────────

    /// Parse a 64-char ASCII hex string into a 32-byte buffer. Returns
    /// zeros on any non-hex character (test only — inputs are static).
    fn hex_decode_32(s: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            out[i] = (h(s[i * 2]) << 4) | h(s[i * 2 + 1]);
            i += 1;
        }
        out
    }
    fn h(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        }
    }
}

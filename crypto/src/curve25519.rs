//! # Cleanroom Curve25519 Implementation
//!
//! Implementation of Curve25519 field arithmetic and Twisted Edwards
//! curve (edwards25519) operations.
//!
//! Field: GF(2^255 - 19), represented as 5 radix-2^51 limbs in `i64`
//! per Bernstein's "Curve25519: new Diffie-Hellman speed records"
//! Section 4: <https://cr.yp.to/ecdh/curve25519-20060209.pdf>.
//!
//! Twisted Edwards form: -x^2 + y^2 = 1 + d*x^2*y^2 with
//! d = -121665/121666 mod p. Point operations use the extended
//! coordinates (X:Y:Z:T) of Hisil-Wong-Carter-Dawson
//! "Twisted Edwards Curves Revisited", Section 3.1
//! <https://eprint.iacr.org/2008/522.pdf>, matched against the
//! pseudocode in RFC 8032 §5.1.4.
//!
//! References:
//! - RFC 7748 (Curve25519/X25519): <https://datatracker.ietf.org/doc/html/rfc7748>
//! - RFC 8032 (Ed25519 / edwards25519): <https://datatracker.ietf.org/doc/html/rfc8032>
//! - Bernstein's Curve25519 paper: <https://cr.yp.to/ecdh/curve25519-20060209.pdf>
//! - Hisil et al. extended coords: <https://eprint.iacr.org/2008/522.pdf>

#![allow(dead_code)]

/// A field element in GF(2^255 - 19).
/// Represented as 5 51-bit limbs in i64.
#[derive(Clone, Copy, Debug, Default)]
pub struct FieldElement(pub(crate) [i64; 5]);

impl FieldElement {
    pub const ZERO: Self = FieldElement([0; 5]);
    pub const ONE: Self = FieldElement([1, 0, 0, 0, 0]);

    pub const fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0i64; 5];
        let mut bit_total: usize = 0;
        let mut byte_idx: usize = 0;
        // const fn doesn't allow `for` loops over Range; use `while`.
        while byte_idx < 32 {
            let byte = bytes[byte_idx] as u64;
            let mut bit_in_byte: u32 = 0;
            while bit_in_byte < 8 {
                if bit_total < 255 {
                    let limb_idx = bit_total / 51;
                    let bit_in_limb = bit_total % 51;
                    if (byte >> bit_in_byte) & 1 != 0 {
                        limbs[limb_idx] |= (1u64 << bit_in_limb) as i64;
                    }
                }
                bit_total += 1;
                bit_in_byte += 1;
            }
            byte_idx += 1;
        }

        // Mask all limbs to 51 bits
        limbs[0] &= 0x7ffffffffffff;
        limbs[1] &= 0x7ffffffffffff;
        limbs[2] &= 0x7ffffffffffff;
        limbs[3] &= 0x7ffffffffffff;
        limbs[4] &= 0x7ffffffffffff;
        FieldElement(limbs)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        let mut h = self;
        h.full_reduce();
        let t = h.0;
        let mut res = [0u8; 32];

        let mut bit_total = 0;
        for byte in res.iter_mut() {
            let mut val = 0u8;
            for bit_in_byte in 0..8 {
                let limb_idx = bit_total / 51;
                let bit_offset = bit_total % 51;
                if limb_idx < 5 && (t[limb_idx] & (1i64 << bit_offset)) != 0 {
                    val |= 1u8 << bit_in_byte;
                }
                bit_total += 1;
            }
            *byte = val;
        }
        res
    }

    fn weak_reduce(&mut self) {
        let mut carry = 0i64;
        for i in 0..5 {
            let val = self.0[i] + carry;
            self.0[i] = val & 0x7ffffffffffff;
            carry = val >> 51;
        }
        self.0[0] += carry * 19;
    }

    fn full_reduce(&mut self) {
        // Carry propagation
        let mut carry = 0i64;
        for i in 0..5 {
            let val = self.0[i] + carry;
            self.0[i] = val & 0x7ffffffffffff;
            carry = val >> 51;
        }
        self.0[0] += carry * 19;

        let mut carry = 0i64;
        for i in 0..5 {
            let val = self.0[i] + carry;
            self.0[i] = val & 0x7ffffffffffff;
            carry = val >> 51;
        }
        self.0[0] += carry * 19;

        // After two carry passes limbs[1..4] are < 2^51; limb 0 may
        // still have a tiny carry from the `+= carry*19` above, so do
        // one more bit-51 ripple into limb 1.
        let c = self.0[0] >> 51;
        self.0[0] &= 0x7ffffffffffff;
        self.0[1] += c;

        // Final conditional subtraction: trial-add 19 (so the result is
        // self + 19 mod 2^255) and check the carry out of limb 4. p =
        // 2^255 - 19, so self ≥ p iff self + 19 ≥ 2^255 iff bit 51 of
        // (limb 4 + carry-in) is set.
        let mut t = self.0;
        let mut c = 19i64;
        for limb in t.iter_mut().take(4) {
            let val = *limb + c;
            *limb = val & 0x7ffffffffffff;
            c = val >> 51;
        }
        let val4 = t[4] + c;
        t[4] = val4 & 0x7ffffffffffff;
        // mask = -1 if self ≥ p (need to swap to t = self - p), else 0.
        let mask = (val4 >> 51).wrapping_neg();

        for (limb, &ti) in self.0.iter_mut().zip(t.iter()) {
            *limb ^= mask & (*limb ^ ti);
        }
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let mut res = [0i64; 5];
        for (r, (&a, &b)) in res.iter_mut().zip(self.0.iter().zip(rhs.0.iter())) {
            *r = a + b;
        }
        let mut fe = FieldElement(res);
        fe.weak_reduce();
        fe
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        // Add 2*p limb-wise so every limb stays non-negative regardless
        // of the relative magnitudes of `self` and `rhs`. p in 51-bit
        // limbs is `(2^51 - 19, 2^51 - 1, 2^51 - 1, 2^51 - 1, 2^51 - 1)`,
        // so 2p limbs are `(2^52 - 38, 2^52 - 2, 2^52 - 2, 2^52 - 2,
        // 2^52 - 2)` — all fit in i64 and `weak_reduce` carries the
        // limb-4 overflow back into limb 0 via the `carry * 19` step.
        let mut res = [0i64; 5];
        res[0] = self.0[0] + 0xfffffffffffda - rhs.0[0]; // 2^52 - 38
        res[1] = self.0[1] + 0xffffffffffffe - rhs.0[1]; // 2^52 - 2
        res[2] = self.0[2] + 0xffffffffffffe - rhs.0[2];
        res[3] = self.0[3] + 0xffffffffffffe - rhs.0[3];
        res[4] = self.0[4] + 0xffffffffffffe - rhs.0[4]; // 2^52 - 2 (was 2^51 - 1 — half of 2*p)
        let mut fe = FieldElement(res);
        fe.weak_reduce();
        fe
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        let a = self.0;
        let b = rhs.0;
        let mut r = [0u128; 9];
        for i in 0..5 {
            for j in 0..5 {
                r[i + j] += (a[i] as u128) * (b[j] as u128);
            }
        }

        // Fold r[5..9] into r[0..4]
        // r[5] is 2^255 * ..., r[6] is 2^306 * ...
        let r0 = r[0] + r[5] * 19;
        let r1 = r[1] + r[6] * 19;
        let r2 = r[2] + r[7] * 19;
        let r3 = r[3] + r[8] * 19;
        let r4 = r[4];

        // Final reduction
        let mut rr = [0i64; 5];
        let mut carry = r0 >> 51;
        rr[0] = (r0 & 0x7ffffffffffff) as i64;
        let v1 = r1 + carry;
        carry = v1 >> 51;
        rr[1] = (v1 & 0x7ffffffffffff) as i64;
        let v2 = r2 + carry;
        carry = v2 >> 51;
        rr[2] = (v2 & 0x7ffffffffffff) as i64;
        let v3 = r3 + carry;
        carry = v3 >> 51;
        rr[3] = (v3 & 0x7ffffffffffff) as i64;
        let v4 = r4 + carry;
        carry = v4 >> 51;
        rr[4] = (v4 & 0x7ffffffffffff) as i64;
        rr[0] += (carry * 19) as i64;

        let mut fe = FieldElement(rr);
        fe.full_reduce();
        fe
    }

    pub fn square(&self) -> Self {
        self.mul(self)
    }

    pub fn invert(&self) -> Self {
        let mut res = FieldElement::ONE;
        let mut base = *self;
        // P-2 = 2^255 - 21
        let exp = [
            0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ];
        for byte in exp {
            for i in 0..8 {
                if (byte >> i) & 1 == 1 {
                    res = res.mul(&base);
                }
                base = base.square();
            }
        }
        res
    }

    pub fn is_negative(&self) -> bool {
        let mut h = *self;
        h.full_reduce();
        (h.0[0] & 1) != 0
    }

    pub fn sqrt(&self) -> Option<Self> {
        let mut x = FieldElement::ONE;
        let mut base = *self;
        // (p+3)/8
        let exp = [
            0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x0f,
        ];
        for byte in exp {
            for i in 0..8 {
                if (byte >> i) & 1 == 1 {
                    x = x.mul(&base);
                }
                base = base.square();
            }
        }
        if x.square() == *self {
            return Some(x);
        }
        // Try x * sqrt(-1). For p = 2^255 - 19, sqrt(-1) = 2^((p-1)/4)
        // mod p = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0
        // (LE-encoded below). See RFC 8032 §5.1.3 step 2 — for an
        // unsquared candidate root, multiplying by sqrt(-1) covers the
        // case where u/v is a non-residue square root of `self`.
        const SQRT_M1: FieldElement = FieldElement::from_bytes(&[
            0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18,
            0x43, 0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f,
            0x80, 0x24, 0x83, 0x2b,
        ]);
        let xi = x.mul(&SQRT_M1);
        if xi.square() == *self {
            return Some(xi);
        }
        None
    }
}

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for FieldElement {}

#[derive(Clone, Copy, Debug)]
pub struct Point {
    pub x: FieldElement,
    pub y: FieldElement,
    pub z: FieldElement,
    pub t: FieldElement,
}

impl PartialEq for Point {
    /// Projective equality: (X1:Y1:Z1) == (X2:Y2:Z2) iff
    /// X1*Z2 == X2*Z1 AND Y1*Z2 == Y2*Z1. The derived field-wise
    /// comparison would reject (4Bx, 4By, 4, …) ≠ (Bx, By, 1, …) even
    /// though both represent the base point — which would break the
    /// `[8]SB == [8](R + kA)` check in `ed25519_verify`.
    fn eq(&self, other: &Self) -> bool {
        self.x.mul(&other.z) == other.x.mul(&self.z) && self.y.mul(&other.z) == other.y.mul(&self.z)
    }
}

impl Eq for Point {}

impl Point {
    /// The edwards25519 base point B, encoded in extended coordinates.
    ///
    /// Canonical 32-byte little-endian encodings of x and y per RFC 8032
    /// §5.1.5 — y is `4 * inv(5) mod p` (the well-known 0x66…58 pattern)
    /// and x is the positive root of the curve equation at that y. The
    /// expected encoding `compress(B)` is `[0x58, 0x66, 0x66, …, 0x66]`
    /// (last byte 0x66 → sign bit clear → x positive), which is what
    /// `test_base_point` asserts.
    ///
    /// `t = ZERO` is deliberate. The addition formula uses the operand
    /// `T` only via `C = T1 * 2d * T2`. Scalar multiplication starts
    /// `res = IDENTITY` (T = 0), so the first `res.add(&BASE)` already
    /// zeroes `C` (IDENTITY.t = 0 ⇒ C = 0) and recovers the correct
    /// extended `T3 = E*H = (2*Bx)*(2*By) = 4*Bx*By`. Every later
    /// `base.double()` (which never reads `T`) produces a Point with a
    /// proper extended `T`, so the freshly-decoded BASE.t is never
    /// consulted on a subsequent add.
    pub const BASE: Self = Point {
        // Bx LE bytes (Bx = 15112221349535400772501151409588531511454012693041857206046113283949847762202).
        x: FieldElement::from_bytes(&[
            0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7,
            0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd,
            0xd3, 0x36, 0x69, 0x21,
        ]),
        // By LE bytes (By = 4 * inv(5) mod p).
        y: FieldElement::from_bytes(&[
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ]),
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    pub const IDENTITY: Self = Point {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    pub fn from_bytes_checked(bytes: &[u8; 32]) -> Option<Self> {
        let mut y_bytes = *bytes;
        let sign = (y_bytes[31] & 0x80) != 0;
        y_bytes[31] &= 0x7f;
        let y = FieldElement::from_bytes(&y_bytes);
        let y2 = y.square();
        let u = y2.sub(&FieldElement::ONE);
        let d = FieldElement::from_bytes(&[
            0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a,
            0x70, 0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b,
            0xee, 0x6c, 0x03, 0x52,
        ]);
        let v = d.mul(&y2).add(&FieldElement::ONE);
        let x2 = u.mul(&v.invert());
        let mut x = x2.sqrt()?;
        if x.is_negative() != sign {
            x = FieldElement::ZERO.sub(&x);
        }
        Some(Point {
            x,
            y,
            z: FieldElement::ONE,
            t: x.mul(&y),
        })
    }

    pub fn add(&self, rhs: &Self) -> Self {
        // Extended coordinates addition formula from RFC 8032 section 5.1.4
        // A = (Y1-X1)*(Y2-X2)
        // B = (Y1+X1)*(Y2+X2)
        // C = T1*2d*T2
        // D = Z1*2*Z2
        // E = B-A
        // F = D-C
        // G = D+C
        // H = B+A
        // X3 = E*F, Y3 = G*H, Z3 = F*G, T3 = E*H
        let a = self.y.sub(&self.x).mul(&rhs.y.sub(&rhs.x));
        let b = self.y.add(&self.x).mul(&rhs.y.add(&rhs.x));
        // 2*d mod p, with d = -121665/121666 mod p per RFC 8032 §5.1.
        // LE encoding of 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159.
        const D2: FieldElement = FieldElement::from_bytes(&[
            0x59, 0xf1, 0xb2, 0x26, 0x94, 0x9b, 0xd6, 0xeb, 0x56, 0xb1, 0x83, 0x82, 0x9a, 0x14,
            0xe0, 0x00, 0x30, 0xd1, 0xf3, 0xee, 0xf2, 0x80, 0x8e, 0x19, 0xe7, 0xfc, 0xdf, 0x56,
            0xdc, 0xd9, 0x06, 0x24,
        ]);
        let c = self.t.mul(&D2).mul(&rhs.t);
        let d = self.z.mul(&rhs.z);
        let d = d.add(&d); // D = 2*Z1*Z2

        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);

        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    pub fn double(&self) -> Self {
        // Extended coordinates doubling formula from RFC 8032 section 5.1.4
        // A = X1^2
        // B = Y1^2
        // C = 2*Z1^2
        // D = -A
        // J = X1+Y1
        // E = J^2-A-B
        // G = D+B
        // F = G-C
        // H = D-B
        // X3 = E*F, Y3 = G*H, Z3 = F*G, T3 = E*H
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square();
        let c = c.add(&c); // 2*Z1^2
        let d = FieldElement::ZERO.sub(&a);
        let j = self.x.add(&self.y);
        let e = j.square().sub(&a).sub(&b);
        let g = d.add(&b);
        let f = g.sub(&c);
        let h = d.sub(&b);

        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    pub fn mul(&self, scalar: &[u8; 32]) -> Self {
        let mut res = Point::IDENTITY;
        let mut base = *self;
        for byte in scalar {
            for i in 0..8 {
                if (byte >> i) & 1 == 1 {
                    res = res.add(&base);
                }
                base = base.double();
            }
        }
        res
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = self.x.mul(&zi);
        let y = self.y.mul(&zi);
        let mut bytes = y.to_bytes();
        if x.is_negative() {
            bytes[31] |= 0x80;
        }
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base_point() {
        let expected = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ];
        assert_eq!(Point::BASE.to_bytes(), expected);
    }
}

//! # Cleanroom Curve25519 Implementation
//!
//! Implementation of Curve25519 field arithmetic and Twisted Edwards curve operations.
//! Reference: <https://datatracker.ietf.org/doc/html/rfc7748>
//! Reference: <https://datatracker.ietf.org/doc/html/rfc8032>

#![allow(dead_code)]

/// A field element in GF(2^255 - 19).
/// Represented as 10 26-bit limbs (in u64 to allow for intermediate overflows).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FieldElement([u64; 10]);

impl FieldElement {
    pub const ZERO: Self = FieldElement([0; 10]);
    pub const ONE: Self = {
        let mut limbs = [0; 10];
        limbs[0] = 1;
        FieldElement(limbs)
    };

    pub const fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 10];
        
        let t0 = (bytes[0] as u64) | ((bytes[1] as u64) << 8) | ((bytes[2] as u64) << 16) | ((bytes[3] as u64) << 24) |
                 ((bytes[4] as u64) << 32) | ((bytes[5] as u64) << 40) | ((bytes[6] as u64) << 48) | ((bytes[7] as u64) << 56);
        let t1 = (bytes[8] as u64) | ((bytes[9] as u64) << 8) | ((bytes[10] as u64) << 16) | ((bytes[11] as u64) << 24) |
                 ((bytes[12] as u64) << 32) | ((bytes[13] as u64) << 40) | ((bytes[14] as u64) << 48) | ((bytes[15] as u64) << 56);
        let t2 = (bytes[16] as u64) | ((bytes[17] as u64) << 8) | ((bytes[18] as u64) << 16) | ((bytes[19] as u64) << 24) |
                 ((bytes[20] as u64) << 32) | ((bytes[21] as u64) << 40) | ((bytes[22] as u64) << 48) | ((bytes[23] as u64) << 56);
        let t3 = (bytes[24] as u64) | ((bytes[25] as u64) << 8) | ((bytes[26] as u64) << 16) | ((bytes[27] as u64) << 24) |
                 ((bytes[28] as u64) << 32) | ((bytes[29] as u64) << 40) | ((bytes[30] as u64) << 48) | ((bytes[31] as u64) << 56);

        limbs[0] = t0 & 0x3ffffff;
        limbs[1] = (t0 >> 26) & 0x3ffffff;
        limbs[2] = (t0 >> 52) | ((t1 & 0x3fff) << 12);
        limbs[3] = (t1 >> 14) & 0x3ffffff;
        limbs[4] = (t1 >> 40) | ((t2 & 0xff) << 24);
        limbs[5] = (t2 >> 8) & 0x3ffffff;
        limbs[6] = (t2 >> 34) & 0x3ffffff;
        limbs[7] = (t2 >> 60) | ((t3 & 0x1ffffff) << 4);
        limbs[8] = (t3 >> 21) & 0x3ffffff;
        limbs[9] = (t3 >> 47) & 0x1fffff;

        FieldElement(limbs)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        let mut h = self;
        h.reduce();
        h.reduce();

        let mut t = h.0;
        let mut g = t;
        g[0] += 19;
        let mut carry = g[0] >> 26; g[0] &= 0x3ffffff;
        for i in 1..9 { g[i] += carry; carry = g[i] >> 26; g[i] &= 0x3ffffff; }
        g[9] += carry;
        
        let mask = (g[9] >> 21).wrapping_neg();
        for i in 0..10 {
            t[i] = (t[i] & !mask) | (g[i] & mask);
        }
        t[9] &= 0x1fffff;

        let mut res = [0u8; 32];
        let r0 = t[0] | (t[1] << 26) | (t[2] << 52);
        let r1 = (t[2] >> 12) | (t[3] << 14) | (t[4] << 40);
        let r2 = (t[5] << 8) | (t[6] << 34) | (t[7] << 60);
        let r3 = (t[7] >> 4) | (t[8] << 21) | (t[9] << 47);
        
        res[0..8].copy_from_slice(&r0.to_le_bytes());
        res[8..16].copy_from_slice(&r1.to_le_bytes());
        res[16..24].copy_from_slice(&r2.to_le_bytes());
        res[24..32].copy_from_slice(&r3.to_le_bytes());
        res
    }

    fn reduce(&mut self) {
        for _ in 0..2 {
            let mut carry = 0u64;
            for i in 0..9 {
                self.0[i] += carry;
                carry = self.0[i] >> 26;
                self.0[i] &= 0x3ffffff;
            }
            self.0[9] += carry;
            carry = self.0[9] >> 21;
            self.0[9] &= 0x1fffff;
            self.0[0] += carry * 19;
        }
    }

    pub fn add(&self, rhs: &Self) -> Self {
        let mut res = [0u64; 10];
        for i in 0..10 {
            res[i] = self.0[i] + rhs.0[i];
        }
        let mut fe = FieldElement(res);
        fe.reduce();
        fe
    }

    pub fn sub(&self, rhs: &Self) -> Self {
        let mut res = [0u64; 10];
        // Add a large multiple of p to each limb
        // p limbs are at most 0x3ffffff. Adding 0x3ffffff * 8 is safe and sufficient.
        for i in 0..9 {
            res[i] = self.0[i] + (0x3ffffff * 8) - rhs.0[i];
        }
        res[9] = self.0[9] + (0x1fffff * 8) - rhs.0[9];
        let mut fe = FieldElement(res);
        fe.reduce();
        fe
    }

    pub fn mul(&self, rhs: &Self) -> Self {
        let mut r = [0u128; 19];
        for i in 0..10 {
            for j in 0..10 {
                r[i + j] += (self.0[i] as u128) * (rhs.0[j] as u128);
            }
        }

        for i in 10..19 {
            r[i - 10] += r[i] * 19;
        }

        let mut res = [0u64; 10];
        let mut carry = 0u128;
        for i in 0..9 {
            let val = r[i] + carry;
            res[i] = (val & 0x3ffffff) as u64;
            carry = val >> 26;
        }
        let val = r[9] + carry;
        res[9] = (val & 0x1fffff) as u64;
        carry = val >> 21;
        res[0] += (carry * 19) as u64;
        
        let mut fe = FieldElement(res);
        fe.reduce();
        fe
    }

    pub fn invert(&self) -> Self {
        self.pow_p_minus_2()
    }

    pub fn square(&self) -> Self {
        self.mul(self)
    }

    fn pow_p_minus_2(&self) -> Self {
        let exponent = [
            0xeb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ];
        let mut res = FieldElement::ONE;
        let mut base = *self;
        for byte in exponent {
            for i in 0..8 {
                if (byte >> i) & 1 == 1 {
                    res = res.mul(&base);
                }
                base = base.square();
            }
        }
        res
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl Point {
    pub const BASE: Self = Point {
        x: FieldElement::from_bytes(&[
            0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9,
            0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
            0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0,
            0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
        ]),
        y: FieldElement::from_bytes(&[
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        ]),
        z: FieldElement::ONE,
        t: FieldElement::from_bytes(&[
            0xa9, 0x6d, 0x76, 0x5c, 0xf5, 0xc2, 0xf0, 0xd5,
            0x88, 0x55, 0xe9, 0x90, 0xd3, 0x37, 0x3f, 0x7a,
            0xb6, 0x05, 0x94, 0x30, 0x7a, 0x94, 0xf7, 0x1b,
            0x46, 0xcb, 0x31, 0x83, 0xfc, 0x53, 0x53, 0x67,
        ]),
    };

    pub const IDENTITY: Self = Point {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    pub fn add(&self, rhs: &Self) -> Self {
        let a = self.y.sub(&self.x).mul(&rhs.y.sub(&rhs.x));
        let b = self.y.add(&self.x).mul(&rhs.y.add(&rhs.x));
        
        let d_fe = FieldElement::from_bytes(&[
            0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75,
            0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70, 0x00,
            0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c,
            0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c, 0x03, 0x52,
        ]);
        let d2 = d_fe.add(&d_fe);
        
        let c = self.t.mul(&d2).mul(&rhs.t);
        let d = self.z.mul(&rhs.z).add(&self.z.mul(&rhs.z));
        
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
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().add(&self.z.square());
        let d = FieldElement::ZERO.sub(&a);
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
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
}

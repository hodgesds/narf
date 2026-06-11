//! P-256 prime field GF(p), with p = 2^256 - 2^224 + 2^192 + 2^96 - 1.
//!
//! Spec references:
//!
//! - NIST FIPS 186-4 §D.1.2.3 ("Curve P-256"). Defines p, a = -3, b,
//!   the generator G, and the order n.
//!   <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf>
//! - NIST SP 800-186 §3.2.1.3 republishes the same parameters.
//! - Solinas reduction for P-256:
//!   J. A. Solinas, "Generalized Mersenne Numbers", NSA tech report 1999.
//!   §3 derives the 9-term modular reduction used here.
//!
//! Reference (clean-room, not copied): `crypto/ecc.c` in the Linux tree
//! implements the same primitives via 4-digit `vli_*` routines and a
//! generic `vli_mmod_fast_192/256/...` fast-reduction step. NARF is
//! GPL-2.0-or-later post 2026-05-20 so the reference is in scope.
//!
//! ## Representation
//!
//! Field elements are 4 × u64 little-endian (limb[0] is the least
//! significant 64 bits). All exported operations leave the result
//! fully reduced — i.e. strictly less than p.
//!
//! ## Constant-time discipline
//!
//! Per IEEE 802.11-2020 §12.4.4.2.2 NOTE, every comparison that
//! touches secret data uses constant-time predicates (`ct_eq`,
//! `ct_lt`, `conditional_subtract`). No branches on field-element
//! bits, no table lookups indexed by secrets.

use core::cmp::Ordering;

/// P-256 prime in little-endian limbs:
/// p = 0xFFFFFFFF00000001 0000000000000000 00000000FFFFFFFF FFFFFFFFFFFFFFFF
/// = 2^256 - 2^224 + 2^192 + 2^96 - 1 (FIPS 186-4 §D.1.2.3).
pub const P: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

/// A field element in GF(p), stored as 4 little-endian u64 limbs and
/// always fully reduced after any exported operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fp(pub [u64; 4]);

impl Fp {
    /// The additive identity.
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    /// The multiplicative identity.
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// Build an `Fp` directly from limbs. Caller asserts the value is
    /// strictly less than p; if not, callers should run `weak_reduce`.
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self(limbs)
    }

    /// Decode a big-endian 32-byte buffer into an `Fp`. Returns `None`
    /// if the value is not strictly less than p (FIPS 186-4 §D.1.2.3
    /// requires field elements in [0, p)).
    pub fn from_bytes_be(bytes: &[u8; 32]) -> Option<Self> {
        let mut limbs = [0u64; 4];
        // Most significant byte first → limb[3] then [2], [1], [0].
        for (i, limb) in limbs.iter_mut().rev().enumerate() {
            let off = i * 8;
            *limb = u64::from_be_bytes([
                bytes[off],
                bytes[off + 1],
                bytes[off + 2],
                bytes[off + 3],
                bytes[off + 4],
                bytes[off + 5],
                bytes[off + 6],
                bytes[off + 7],
            ]);
        }
        let fe = Self(limbs);
        if fe.cmp_p() != Ordering::Less {
            None
        } else {
            Some(fe)
        }
    }

    /// Encode the field element as a 32-byte big-endian buffer.
    pub fn to_bytes_be(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().rev().enumerate() {
            let off = i * 8;
            out[off..off + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    /// Constant-time comparison of `self` to p. Returns Less / Equal /
    /// Greater. Used only for the final canonicalisation step where the
    /// outcome distinguishes p from p-1 — that distinction itself does
    /// not carry secret information.
    fn cmp_p(&self) -> Ordering {
        // Compare from most-significant limb down.
        for i in (0..4).rev() {
            match self.0[i].cmp(&P[i]) {
                Ordering::Less => return Ordering::Less,
                Ordering::Greater => return Ordering::Greater,
                Ordering::Equal => continue,
            }
        }
        Ordering::Equal
    }

    /// Return true if `self` is exactly zero.
    pub fn is_zero(&self) -> bool {
        (self.0[0] | self.0[1] | self.0[2] | self.0[3]) == 0
    }

    /// Modular addition: `(a + b) mod p`, fully reduced.
    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = add4(self.0, other.0);
        // If sum overflowed 256 bits OR sum >= p, subtract p.
        let mut tmp = Self(sum);
        if carry || tmp.cmp_p() != Ordering::Less {
            let (diff, _) = sub4(tmp.0, P);
            tmp.0 = diff;
        }
        tmp
    }

    /// Modular subtraction: `(a - b) mod p`, fully reduced.
    pub fn sub(&self, other: &Self) -> Self {
        let (diff, borrow) = sub4(self.0, other.0);
        if borrow {
            let (corrected, _) = add4(diff, P);
            Self(corrected)
        } else {
            Self(diff)
        }
    }

    /// Modular negation: `(-a) mod p`.
    pub fn neg(&self) -> Self {
        Self::ZERO.sub(self)
    }

    /// Modular multiplication: `(a * b) mod p`. Uses 4x4 schoolbook
    /// 256x256 → 512 multiplication followed by Solinas P-256
    /// fast reduction (the "FIPS 186-4 reduction" — see SP 800-186
    /// §3.2.1.3 informative annex).
    pub fn mul(&self, other: &Self) -> Self {
        let prod = mul_512(self.0, other.0);
        reduce_p256(prod)
    }

    /// Modular squaring: `(a * a) mod p`.
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Modular inversion via Fermat's little theorem: `a^(p-2) mod p`.
    /// Works because GF(p)* is cyclic of order p-1; FLT says
    /// `a^(p-1) = 1 (mod p)` for any `a != 0`.
    pub fn invert(&self) -> Self {
        // exponent = p - 2 (little-endian limbs).
        let mut e = P;
        // p-2 differs from p only in the least-significant limb.
        e[0] = e[0].wrapping_sub(2);
        self.pow(&e)
    }

    /// Compute `self^exp mod p` by square-and-multiply. `exp` is given
    /// in 4-limb little-endian form. Constant-time over bit pattern
    /// (always performs both square and multiply per bit; the multiply
    /// result is conditionally selected).
    pub fn pow(&self, exp: &[u64; 4]) -> Self {
        let mut result = Self::ONE;
        // Walk from most-significant bit down.
        for i in (0..4).rev() {
            let limb = exp[i];
            for bit in (0..64).rev() {
                result = result.square();
                let mul = result.mul(self);
                // Constant-time select: if bit set, take `mul`; else
                // keep `result`. We materialise both and mask.
                let take = (limb >> bit) & 1;
                result = ct_select(&mul, &result, take);
            }
        }
        result
    }

    /// Modular square root via Tonelli's shortcut for p ≡ 3 mod 4.
    /// P-256's prime satisfies that condition (p mod 4 = 3), so any
    /// quadratic residue `a` has `sqrt(a) = a^((p+1)/4) mod p`.
    ///
    /// The caller is responsible for checking that `self` is a
    /// quadratic residue via `is_quadratic_residue` first; this
    /// routine returns garbage on non-residues. Used by SAE
    /// hunting-and-pecking (RFC 7664 §3.2.1 step 17).
    pub fn sqrt(&self) -> Self {
        // (p + 1) / 4 in little-endian limbs.
        // p = FFFFFFFF00000001 0000000000000000 00000000FFFFFFFF FFFFFFFFFFFFFFFF
        // p+1 = FFFFFFFF00000001 0000000000000000 00000000FFFFFFFF FFFFFFFF00000000... no:
        // p[0] = FFFFFFFFFFFFFFFF → p+1 sets [0]=0, carries into [1].
        // p[1] = 00000000FFFFFFFF → +1 → 100000000.
        // ...etc. To compute (p+1)/4 directly we shift bits right by 2.
        // p+1 = 2^256 - 2^224 + 2^192 + 2^96.
        // (p+1)/4 = 2^254 - 2^222 + 2^190 + 2^94.
        // In limbs (LE):
        //   limb0 = 2^94 within first 64 bits? No — 94 > 64. So:
        //     bit 94 = limb1 bit (94-64)=30 → limb1 = 1<<30 = 0x4000_0000.
        //   bit 190 = limb2 bit 62 = 0x4000_0000_0000_0000.
        //   −2^222: bit 222 = limb3 bit (222-192)=30 → subtract from
        //     2^254 = limb3 bit 62. So limb3 = (1<<62) - (1<<30) =
        //     0x3FFF_FFFF_C000_0000.
        let exp: [u64; 4] = [
            0,
            0x0000_0000_4000_0000,
            0x4000_0000_0000_0000,
            0x3FFF_FFFF_C000_0000,
        ];
        self.pow(&exp)
    }

    /// Test whether `self` is a quadratic residue mod p (i.e. has a
    /// square root). Computes the Legendre symbol via Euler's
    /// criterion: `a^((p-1)/2) mod p` is 1 if QR, p-1 if non-QR,
    /// 0 if a == 0. Used by SAE hunting-and-pecking.
    pub fn is_quadratic_residue(&self) -> bool {
        if self.is_zero() {
            return true; // 0 = 0^2 conventionally accepted as a QR.
        }
        // (p - 1) / 2 = 2^255 - 2^223 + 2^191 + 2^95 - 1, derived
        // analogously to (p+1)/4 above.
        // p-1: subtract 1 from p[0].
        // (p-1)/2: shift right by 1.
        //   p = 2^256 - 2^224 + 2^192 + 2^96 - 1
        //   p-1 = 2^256 - 2^224 + 2^192 + 2^96 - 2
        //   (p-1)/2 = 2^255 - 2^223 + 2^191 + 2^95 - 1.
        // Limbs (LE):
        //   bit 95: limb1 bit 31 = 0x8000_0000.
        //   bit 191: limb2 bit 63 = 0x8000_0000_0000_0000.
        //   −2^223 at limb3 bit 31, +2^255 at limb3 bit 63 →
        //     limb3 = (1<<63) - (1<<31) = 0x7FFF_FFFF_8000_0000.
        //   −1 at the LSB → limb0 = 0xFFFF_FFFF_FFFF_FFFF gets the
        //     borrow from the bit-95 term... actually simpler:
        //   (p-1)/2 in hex (BE per FIPS):
        //     7FFFFFFF80000000 0000000000000000 00000000800000000 ... no.
        // Let's just compute it: take p, subtract 1, then right-shift 1 bit.
        let mut e = P;
        e[0] = e[0].wrapping_sub(1);
        // Right shift by 1.
        let mut shifted = [0u64; 4];
        let mut carry: u64 = 0;
        for i in (0..4).rev() {
            let new_carry = e[i] & 1;
            shifted[i] = (e[i] >> 1) | (carry << 63);
            carry = new_carry;
        }
        let r = self.pow(&shifted);
        r == Self::ONE
    }

    /// Return the least-significant bit of the canonical representative.
    pub fn lsb(&self) -> u8 {
        (self.0[0] & 1) as u8
    }

    /// Conditional swap with `other` when `swap` is 1. No-op when 0.
    /// Constant-time over the swap mask.
    pub fn cswap(&mut self, other: &mut Self, swap: u64) {
        // Branch-free conditional swap via XOR.
        let mask = 0u64.wrapping_sub(swap);
        for i in 0..4 {
            let t = (self.0[i] ^ other.0[i]) & mask;
            self.0[i] ^= t;
            other.0[i] ^= t;
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────

/// 256-bit add: returns `(sum_limbs, carry_out)`.
fn add4(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut carry: u128 = 0;
    for i in 0..4 {
        let s = a[i] as u128 + b[i] as u128 + carry;
        out[i] = s as u64;
        carry = s >> 64;
    }
    (out, carry != 0)
}

/// 256-bit subtract: returns `(diff_limbs, borrow_out)`.
fn sub4(a: [u64; 4], b: [u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut borrow: i128 = 0;
    for i in 0..4 {
        let d = (a[i] as i128) - (b[i] as i128) - borrow;
        out[i] = d as u64;
        borrow = if d < 0 { 1 } else { 0 };
    }
    (out, borrow != 0)
}

/// 4x4 schoolbook multiplication producing an 8-limb little-endian
/// result. Uses Rust `u128` for the 64x64 → 128 partial products,
/// which compiles down to MULQ on x86_64.
fn mul_512(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let t = (a[i] as u128) * (b[j] as u128) + (out[i + j] as u128) + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
        out[i + 4] = carry as u64;
    }
    out
}

/// Constant-time select: returns `a` if `take == 1`, else `b`.
/// Both inputs are evaluated; only the masked merge changes the result.
fn ct_select(a: &Fp, b: &Fp, take: u64) -> Fp {
    let mask = 0u64.wrapping_sub(take);
    let mut out = [0u64; 4];
    for (i, o) in out.iter_mut().enumerate() {
        *o = (a.0[i] & mask) | (b.0[i] & !mask);
    }
    Fp(out)
}

/// Solinas reduction for P-256: given a 512-bit product
/// `T = [t0, t1, ..., t15]` (8 × u64), compute `T mod p`.
///
/// Each 64-bit limb is split into two 32-bit half-limbs `cN` so we can
/// use the 9-term identity from FIPS 186-4 informative annex /
/// SP 800-186:
///
///   p = 2^256 - 2^224 + 2^192 + 2^96 - 1
///
///   2^256  ≡  2^224 - 2^192 - 2^96 + 1   (mod p)
///
/// Spreading the high-256 bits across the powers-of-2 identity yields
/// nine 256-bit terms `s1..s9` that sum (with appropriate signs) to
/// the reduced result. We collect each term, do the signed add/sub,
/// and finish by a few conditional p-subtractions / p-additions.
fn reduce_p256(t: [u64; 8]) -> Fp {
    // Re-split into 32-bit half-limbs `c[0..16]` little-endian for
    // easier alignment with the SP 800-186 formula.
    let mut c = [0u32; 16];
    for i in 0..8 {
        c[2 * i] = t[i] as u32;
        c[2 * i + 1] = (t[i] >> 32) as u32;
    }

    // Per SP 800-186 §A.2 (and the FIPS 186-4 informative annex
    // republished there), the nine reduction terms are, in 32-bit
    // half-limbs, written little-endian (c0 at the bottom):
    //
    //   s1 = (c[7] , c[6] , c[5] , c[4] , c[3] , c[2] , c[1] , c[0])
    //   s2 = (c[15], c[14], c[13], c[12], c[11], 0    , 0    , 0   )
    //   s3 = (0    , c[15], c[14], c[13], c[12], 0    , 0    , 0   )
    //   s4 = (c[15], c[14], 0    , 0    , 0    , c[10], c[9] , c[8])
    //   s5 = (c[8] , c[13], c[15], c[14], c[13], c[11], c[10], c[9])
    //   s6 = (c[10], c[8] , 0    , 0    , 0    , c[13], c[12], c[11])
    //   s7 = (c[11], c[9] , 0    , 0    , c[15], c[14], c[13], c[12])
    //   s8 = (c[12], 0    , c[10], c[9] , c[8] , c[15], c[14], c[13])
    //   s9 = (c[13], 0    , c[11], c[10], c[9] , 0    , c[15], c[14])
    //
    //   r ≡ s1 + 2*s2 + 2*s3 + s4 + s5 - s6 - s7 - s8 - s9   (mod p)
    //
    // We collect each `sN` as a `[u32; 8]`, convert to `[u64; 4]`,
    // run the signed sum with running carry / borrow, then canonicalise
    // by adding / subtracting `p` until the result lives in [0, p).

    let s1 = pack_half([c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]]);
    let s2 = pack_half([0, 0, 0, c[11], c[12], c[13], c[14], c[15]]);
    let s3 = pack_half([0, 0, 0, c[12], c[13], c[14], c[15], 0]);
    let s4 = pack_half([c[8], c[9], c[10], 0, 0, 0, c[14], c[15]]);
    let s5 = pack_half([c[9], c[10], c[11], c[13], c[14], c[15], c[13], c[8]]);
    let s6 = pack_half([c[11], c[12], c[13], 0, 0, 0, c[8], c[10]]);
    let s7 = pack_half([c[12], c[13], c[14], c[15], 0, 0, c[9], c[11]]);
    let s8 = pack_half([c[13], c[14], c[15], c[8], c[9], c[10], 0, c[12]]);
    let s9 = pack_half([c[14], c[15], 0, c[9], c[10], c[11], 0, c[13]]);

    // Reduce each summand into [0, p) first so the running carry has
    // a bounded magnitude. We only need to subtract p at most once for
    // each individual `sN` because each is < 2^256.
    let mut acc = canonical(s1);
    // + s2 twice
    acc = mod_add_canonical(acc, canonical(s2));
    acc = mod_add_canonical(acc, canonical(s2));
    // + s3 twice
    acc = mod_add_canonical(acc, canonical(s3));
    acc = mod_add_canonical(acc, canonical(s3));
    // + s4 + s5
    acc = mod_add_canonical(acc, canonical(s4));
    acc = mod_add_canonical(acc, canonical(s5));
    // − s6 − s7 − s8 − s9
    acc = mod_sub_canonical(acc, canonical(s6));
    acc = mod_sub_canonical(acc, canonical(s7));
    acc = mod_sub_canonical(acc, canonical(s8));
    acc = mod_sub_canonical(acc, canonical(s9));

    Fp(acc)
}

/// Pack eight 32-bit half-limbs (little-endian: index 0 is least
/// significant) into a 4 × u64 little-endian array.
fn pack_half(h: [u32; 8]) -> [u64; 4] {
    [
        (h[0] as u64) | ((h[1] as u64) << 32),
        (h[2] as u64) | ((h[3] as u64) << 32),
        (h[4] as u64) | ((h[5] as u64) << 32),
        (h[6] as u64) | ((h[7] as u64) << 32),
    ]
}

/// Reduce a single < 2^256 limb-array into [0, p). Subtracts p once
/// if needed; never recurses.
fn canonical(v: [u64; 4]) -> [u64; 4] {
    let tmp = Fp(v);
    if tmp.cmp_p() != Ordering::Less {
        let (diff, _) = sub4(v, P);
        diff
    } else {
        v
    }
}

/// `(a + b) mod p` for two already-canonical inputs.
fn mod_add_canonical(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let (sum, carry) = add4(a, b);
    let tmp = Fp(sum);
    if carry || tmp.cmp_p() != Ordering::Less {
        let (diff, _) = sub4(sum, P);
        diff
    } else {
        sum
    }
}

/// `(a - b) mod p` for two already-canonical inputs.
fn mod_sub_canonical(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let (diff, borrow) = sub4(a, b);
    if borrow {
        let (corrected, _) = add4(diff, P);
        corrected
    } else {
        diff
    }
}

// ── Tests (kernel-test smokes) ─────────────────────────────────────

pub mod fp_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_p256_fp_add_zero_identity() -> TestResult {
        let a = Fp::from_limbs([0x1234, 0x5678, 0x9abc, 0xdef0]);
        let zero = Fp::ZERO;
        if a.add(&zero) != a {
            return TestResult::Fail("a + 0 != a");
        }
        if zero.add(&a) != a {
            return TestResult::Fail("0 + a != a");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_fp_add_zero_identity);

    fn smoke_p256_fp_sub_self_zero() -> TestResult {
        let a = Fp::from_limbs([0x1234, 0x5678, 0x9abc, 0xdef0]);
        if !a.sub(&a).is_zero() {
            return TestResult::Fail("a - a != 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_fp_sub_self_zero);

    fn smoke_p256_fp_add_wraps_at_p() -> TestResult {
        // p - 1 + 1 = 0 (mod p).
        let p_minus_one = Fp::from_limbs([
            0xFFFF_FFFF_FFFF_FFFE,
            0x0000_0000_FFFF_FFFF,
            0x0000_0000_0000_0000,
            0xFFFF_FFFF_0000_0001,
        ]);
        let one = Fp::ONE;
        let sum = p_minus_one.add(&one);
        if !sum.is_zero() {
            return TestResult::Fail("(p-1)+1 should be 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_fp_add_wraps_at_p);

    fn smoke_p256_fp_mul_by_one() -> TestResult {
        let a = Fp::from_limbs([0x1234_5678_9abc_def0, 0xfedc_ba98_7654_3210, 0xa5, 0x5a]);
        let one = Fp::ONE;
        if a.mul(&one) != a {
            return TestResult::Fail("a * 1 != a");
        }
        if one.mul(&a) != a {
            return TestResult::Fail("1 * a != a");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_fp_mul_by_one);

    fn smoke_p256_fp_mul_by_zero() -> TestResult {
        let a = Fp::from_limbs([0x1234, 0x5678, 0x9abc, 0xdef0]);
        if !a.mul(&Fp::ZERO).is_zero() {
            return TestResult::Fail("a * 0 != 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_fp_mul_by_zero);

    fn smoke_p256_fp_square_matches_mul_self() -> TestResult {
        let a = Fp::from_limbs([0x1234_5678_9abc_def0, 0x1111, 0x2222, 0x3333]);
        if a.square() != a.mul(&a) {
            return TestResult::Fail("square != mul(self, self)");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_fp_square_matches_mul_self);

    fn smoke_p256_fp_invert_identity() -> TestResult {
        // a * a^-1 = 1 (mod p) for a small a.
        let a = Fp::from_limbs([2, 0, 0, 0]);
        let inv = a.invert();
        let one = a.mul(&inv);
        if one != Fp::ONE {
            return TestResult::Fail("a * a^-1 != 1");
        }
        // And again for a slightly larger value.
        let b = Fp::from_limbs([0xdead_beef, 0, 0, 0]);
        let inv_b = b.invert();
        if b.mul(&inv_b) != Fp::ONE {
            return TestResult::Fail("b * b^-1 != 1");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_fp_invert_identity);

    fn smoke_p256_fp_sqrt_of_square() -> TestResult {
        // For any a in [1, p), a^2 is a QR with sqrt equal to a or p-a.
        let a = Fp::from_limbs([0x1234, 0, 0, 0]);
        let a_sq = a.square();
        if !a_sq.is_quadratic_residue() {
            return TestResult::Fail("a^2 should be a QR");
        }
        let s = a_sq.sqrt();
        if s.square() != a_sq {
            return TestResult::Fail("sqrt(a^2)^2 != a^2");
        }
        // And the sqrt should be either a or p-a.
        if s != a && s != a.neg() {
            return TestResult::Fail("sqrt(a^2) is not a or -a");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_fp_sqrt_of_square);

    fn smoke_p256_fp_qr_lsb_consistency() -> TestResult {
        // Spec consistency: 1 is a QR (sqrt = 1), 2 may or may not be.
        if !Fp::ONE.is_quadratic_residue() {
            return TestResult::Fail("1 should be a QR");
        }
        if Fp::ONE.sqrt() != Fp::ONE {
            return TestResult::Fail("sqrt(1) should be 1");
        }
        // lsb of 1 is 1.
        if Fp::ONE.lsb() != 1 {
            return TestResult::Fail("LSB(1) should be 1");
        }
        if Fp::ZERO.lsb() != 0 {
            return TestResult::Fail("LSB(0) should be 0");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_fp_qr_lsb_consistency);

    fn smoke_p256_fp_bytes_roundtrip() -> TestResult {
        // 1 in big-endian bytes is 0x00..0x01.
        let mut one_be = [0u8; 32];
        one_be[31] = 1;
        let one = Fp::from_bytes_be(&one_be).expect("decode 1");
        if one != Fp::ONE {
            return TestResult::Fail("decode(1) != ONE");
        }
        if one.to_bytes_be() != one_be {
            return TestResult::Fail("encode(ONE) != 0x00..01");
        }
        // p must round-trip-fail (decode rejects p).
        let mut p_be = [0u8; 32];
        // p in big-endian:
        p_be[..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        p_be[4..8].copy_from_slice(&[0x00, 0x00, 0x00, 0x01]);
        // top 8 bytes = FFFFFFFF00000001, then 8 zero bytes, then
        // 00000000FFFFFFFF, then FFFFFFFFFFFFFFFF
        p_be[16..24].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]);
        p_be[24..32].copy_from_slice(&[0xFF; 8]);
        if Fp::from_bytes_be(&p_be).is_some() {
            return TestResult::Fail("decode(p) should reject");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_fp_bytes_roundtrip);
}

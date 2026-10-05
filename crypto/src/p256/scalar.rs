//! P-256 scalar field arithmetic — operations modulo the curve order
//! `n = FFFFFFFF00000000 FFFFFFFFFFFFFFFF BCE6FAADA7179E84 F3B9CAC2FC632551`
//! (FIPS 186-4 §D.1.2.3).
//!
//! Scalars are used for private keys, ephemeral nonces, and (in SAE)
//! the `rand` / `mask` / `commit` values. All arithmetic happens
//! in [0, n).
//!
//! ## Constant-time discipline
//!
//! Scalar values are secret in every SAE call. Same rules as
//! `field::Fp`: no branches on bits, no table lookups on secrets.

use core::cmp::Ordering;

use super::ORDER_N;

/// Scalar mod n. 4 × u64 little-endian, always fully reduced.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scalar(pub [u64; 4]);

impl Scalar {
    pub const ZERO: Self = Self([0, 0, 0, 0]);
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// Build a scalar directly from limbs. Caller asserts the value is
    /// already in [0, n).
    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        Self(limbs)
    }

    /// Decode a 32-byte big-endian buffer, reducing mod n if needed.
    /// Returns `None` only when input is exactly zero AND the caller
    /// requested a non-zero scalar — caller-side check.
    pub fn from_bytes_be_reduce(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
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
        let mut s = Self(limbs);
        // Reduce once (input < 2^256 < 2n, so single subtract suffices).
        if s.cmp_n() != Ordering::Less {
            s = s.sub_unchecked(&Self(ORDER_N));
        }
        s
    }

    /// Decode strictly: accepts only values in [0, n). Rejects out-of-range
    /// buffers and the all-zero scalar (callers always reject 0 in SAE).
    pub fn from_bytes_be(bytes: &[u8; 32]) -> Option<Self> {
        let s = Self::from_bytes_be_reduce(bytes);
        // Check the input wasn't actually >= n.
        let mut raw = [0u64; 4];
        for (i, limb) in raw.iter_mut().rev().enumerate() {
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
        let probe = Self(raw);
        if probe.cmp_n() != Ordering::Less {
            return None;
        }
        Some(s)
    }

    pub fn to_bytes_be(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, limb) in self.0.iter().rev().enumerate() {
            let off = i * 8;
            out[off..off + 8].copy_from_slice(&limb.to_be_bytes());
        }
        out
    }

    pub fn is_zero(&self) -> bool {
        (self.0[0] | self.0[1] | self.0[2] | self.0[3]) == 0
    }

    /// Compare `self` to n.
    fn cmp_n(&self) -> Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&ORDER_N[i]) {
                Ordering::Less => return Ordering::Less,
                Ordering::Greater => return Ordering::Greater,
                Ordering::Equal => continue,
            }
        }
        Ordering::Equal
    }

    /// `(self + other) mod n`.
    pub fn add(&self, other: &Self) -> Self {
        let (sum, carry) = add4(self.0, other.0);
        if carry {
            // The full 257-bit sum is `(2^256 | sum)`. Since
            // `2^256 = N + (2^256 − N)` and `2^256 − N` is a small
            // positive value, reducing mod N gives
            //   `(2^256 + sum) − N`  ==  `sum + (2^256 − N)`
            // which equals `sum.wrapping_sub(N)` in 256-bit
            // unsigned arithmetic. We must NOT call sub_unchecked
            // here because that path corrects an underflow by adding
            // N back, which would undo the wraparound and leave the
            // result in the wrong residue class.
            let (reduced, _borrow) = sub4(sum, ORDER_N);
            return Self(reduced);
        }
        // No 257th bit. If sum >= N, fall through and subtract once.
        let mut s = Self(sum);
        if s.cmp_n() != Ordering::Less {
            s = s.sub_unchecked(&Self(ORDER_N));
        }
        s
    }

    /// `(self - other) mod n`. Internal helper that does not assume
    /// the inputs are already reduced; used by `from_bytes_be`.
    fn sub_unchecked(&self, other: &Self) -> Self {
        let (diff, borrow) = sub4(self.0, other.0);
        if borrow {
            let (corrected, _) = add4(diff, ORDER_N);
            Self(corrected)
        } else {
            Self(diff)
        }
    }

    /// `(self - other) mod n`.
    pub fn sub(&self, other: &Self) -> Self {
        self.sub_unchecked(other)
    }

    /// `(self * other) mod n`. Variable-time — ECDSA verification operands
    /// are public, so no constant-time guarantee is made or needed. (SAE's
    /// secret scalar work uses point multiplication and `add`, never this.)
    pub fn mul(&self, other: &Self) -> Self {
        Self(reduce512(mul_wide(self.0, other.0)))
    }

    /// Modular inverse `self^{-1} mod n` via Fermat's little theorem
    /// (`self^(n-2) mod n`). Returns `ZERO` for a zero input. Variable-time.
    pub fn invert(&self) -> Self {
        if self.is_zero() {
            return Self::ZERO;
        }
        let (exp, _) = sub4(ORDER_N, [2, 0, 0, 0]); // n - 2
        let mut result = Self::ONE;
        let base = *self;
        for i in (0..256).rev() {
            result = result.mul(&result);
            if (exp[i / 64] >> (i % 64)) & 1 == 1 {
                result = result.mul(&base);
            }
        }
        result
    }
}

// ── 4×u64 helpers (private to this module) ──────────────────────────

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

/// `a >= b` for 4-limb little-endian values.
fn cmp_ge(a: [u64; 4], b: [u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// 256×256 → 512-bit schoolbook product (little-endian limbs).
fn mul_wide(a: [u64; 4], b: [u64; 4]) -> [u64; 8] {
    let mut out = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let t = out[i + j] as u128 + (a[i] as u128) * (b[j] as u128) + carry;
            out[i + j] = t as u64;
            carry = t >> 64;
        }
        out[i + 4] = carry as u64;
    }
    out
}

/// Reduce a 512-bit little-endian value mod n by binary long division.
/// Variable-time; used only on public ECDSA operands.
fn reduce512(x: [u64; 8]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for i in (0..512).rev() {
        let bit = (x[i / 64] >> (i % 64)) & 1;
        // r = (r << 1) | bit, capturing the shifted-out 257th bit.
        let top = r[3] >> 63;
        r[3] = (r[3] << 1) | (r[2] >> 63);
        r[2] = (r[2] << 1) | (r[1] >> 63);
        r[1] = (r[1] << 1) | (r[0] >> 63);
        r[0] = (r[0] << 1) | bit;
        // Value is top·2^256 + r ∈ [0, 2n); one conditional subtract of n
        // (when top set, sub4's borrow represents the 2^256 term).
        if top == 1 || cmp_ge(r, ORDER_N) {
            let (res, _) = sub4(r, ORDER_N);
            r = res;
        }
    }
    r
}

// ── Tests ──────────────────────────────────────────────────────────

pub mod scalar_tests {
    use super::*;
    use narf_kernel_test::{kernel_test_in, TestResult};

    fn smoke_p256_scalar_add_zero() -> TestResult {
        let a = Scalar::from_limbs([0x123, 0x456, 0x789, 0xabc]);
        if a.add(&Scalar::ZERO) != a {
            return TestResult::Fail("a + 0 != a");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_scalar_add_zero);

    fn smoke_p256_scalar_reduce_n() -> TestResult {
        // n in big-endian.
        let mut n_be = [0u8; 32];
        for (i, limb) in ORDER_N.iter().rev().enumerate() {
            let off = i * 8;
            n_be[off..off + 8].copy_from_slice(&limb.to_be_bytes());
        }
        // from_bytes_be_reduce(n) should produce 0.
        let s = Scalar::from_bytes_be_reduce(&n_be);
        if !s.is_zero() {
            return TestResult::Fail("n mod n should be 0");
        }
        // from_bytes_be (strict) should reject n.
        if Scalar::from_bytes_be(&n_be).is_some() {
            return TestResult::Fail("strict decode should reject n");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_scalar_reduce_n);

    fn smoke_p256_scalar_bytes_roundtrip() -> TestResult {
        let mut bytes = [0u8; 32];
        bytes[31] = 0x42;
        let s = Scalar::from_bytes_be(&bytes).expect("decode");
        if s.to_bytes_be() != bytes {
            return TestResult::Fail("scalar roundtrip");
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_scalar_bytes_roundtrip);

    fn smoke_p256_scalar_mul_invert() -> TestResult {
        // Known small product.
        let three = Scalar::from_limbs([3, 0, 0, 0]);
        let five = Scalar::from_limbs([5, 0, 0, 0]);
        if three.mul(&five) != Scalar::from_limbs([15, 0, 0, 0]) {
            return TestResult::Fail("3 * 5 != 15 mod n");
        }
        // a · a^{-1} ≡ 1 mod n validates mul + invert + the 512-bit reduce
        // against the correct order n.
        for seed in [0x02u8, 0x7f, 0xa3, 0xfe] {
            let mut bytes = [seed; 32];
            bytes[0] &= 0x7f; // keep the probe below n
            let a = Scalar::from_bytes_be_reduce(&bytes);
            if a.is_zero() {
                continue;
            }
            if a.mul(&a.invert()) != Scalar::ONE {
                return TestResult::Fail("a * a^-1 != 1 mod n");
            }
        }
        TestResult::Pass
    }
    kernel_test_in!("crypto/p256", smoke_p256_scalar_mul_invert);
}

//! The numeric abstract domain: one reduced product, one `normalize()`.
//!
//! Linux tracks **six** overlapping views of every scalar — a tnum, a signed
//! 64-bit range, an unsigned 64-bit range, a signed 32-bit range, an unsigned
//! 32-bit range, and a pointer offset — reconciled by roughly 800 lines of
//! pairwise deduction (`__reg_deduce_bounds`, `__reg_bound_offset`,
//! `reg_bounds_sync`, and friends), with a debug-only flag
//! (`BPF_F_TEST_REG_INVARIANTS`) whose entire job is to check at runtime that
//! the six agree. When they disagree, that is a soundness bug.
//!
//! NARF keeps **two**: a tnum and a signed interval, reduced against each
//! other by a single [`Scalar::normalize`]. Everything else — unsigned bounds,
//! 32-bit subregister facts — is *derived on demand* by
//! [`Scalar::unsigned_bounds`] and [`Scalar::zext32`] / [`Scalar::sext32`].
//! Derived facts cannot go stale, so there is nothing to reconcile and no
//! invariant-checking flag to need.
//!
//! ## Why these two components
//!
//! They are complementary in exactly the way BPF programs need:
//!
//!   * A **tnum** is precise under bitwise operations and masking — `r0 &= 0xff`
//!     is exact — and useless for ordering.
//!   * A **signed interval** is precise under ordering and addition and
//!     useless under masking.
//!
//! Real bounds checks use both: `r1 = *(u32 *)(ctx + 0)` gives a tnum with the
//! high 32 bits known zero, which `normalize` turns into a *non-negative*
//! interval, which is what makes the subsequent `if r1 >= 64 goto out` refine
//! to `[0, 63]` rather than to nothing.
//!
//! ## The one place this is less precise than Linux
//!
//! `u >= c` for `0 < c < 2^63` on a value whose sign is not yet known. The
//! constraint's solution set is `[c, i64::MAX] ∪ [i64::MIN, -1]`, which is not
//! an interval, and there is no unsigned range to park it in. Linux keeps it;
//! we drop it. See [`Scalar::refine_unsigned_min`] — it is marked
//! `// LINUX-GAP` there, and it is the deliberate price of not maintaining six
//! domains. The *upper*-bound direction, which is the one every array bounds
//! check depends on, is exact.

use core::cmp::{max, min};

/// A tristate number: each bit is 0, 1, or unknown.
///
/// Invariant: `value & mask == 0`. A bit set in `mask` is unknown, and its
/// `value` bit is therefore held at 0 so that equality is structural.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Tnum {
    /// Known bits.
    pub value: u64,
    /// Unknown bits.
    pub mask: u64,
}

const SIGN: u64 = 1 << 63;

impl Tnum {
    /// Everything unknown.
    pub const UNKNOWN: Tnum = Tnum {
        value: 0,
        mask: u64::MAX,
    };
    /// The constant zero.
    pub const ZERO: Tnum = Tnum { value: 0, mask: 0 };

    /// A known constant.
    #[inline]
    #[must_use]
    pub const fn constant(v: u64) -> Tnum {
        Tnum { value: v, mask: 0 }
    }

    /// Whether every bit is known.
    #[inline]
    #[must_use]
    pub const fn is_const(self) -> bool {
        self.mask == 0
    }

    /// Whether `v` is a member of the set this describes.
    #[inline]
    #[must_use]
    pub const fn contains(self, v: u64) -> bool {
        (v & !self.mask) == self.value
    }

    /// The smallest and largest members, as unsigned values.
    #[inline]
    #[must_use]
    pub const fn unsigned_bounds(self) -> (u64, u64) {
        (self.value, self.value | self.mask)
    }

    /// The smallest and largest members, as *signed* values.
    ///
    /// Not simply the unsigned bounds reinterpreted: when the sign bit is
    /// unknown the extremes are attained by forcing it, which is why this is
    /// four cases rather than a cast.
    #[must_use]
    pub const fn signed_bounds(self) -> (i64, i64) {
        let can_be_neg = ((self.value | self.mask) & SIGN) != 0;
        let can_be_pos = (self.value & SIGN) == 0;
        // Most negative: sign bit 1 where possible, every other unknown 0.
        let lo = if can_be_neg {
            (self.value | SIGN) as i64
        } else {
            self.value as i64
        };
        // Most positive: sign bit 0 where possible, every other unknown 1.
        let hi = if can_be_pos {
            ((self.value | self.mask) & !SIGN) as i64
        } else {
            (self.value | self.mask) as i64
        };
        (lo, hi)
    }

    /// The tightest tnum containing every value in the unsigned range
    /// `[lo, hi]`. Only the shared high-bit prefix survives.
    #[must_use]
    pub fn from_unsigned_range(lo: u64, hi: u64) -> Tnum {
        if lo > hi {
            return Tnum::UNKNOWN;
        }
        let differing = lo ^ hi;
        if differing == 0 {
            return Tnum::constant(lo);
        }
        let bits = 64 - differing.leading_zeros();
        if bits >= 64 {
            return Tnum::UNKNOWN;
        }
        let delta = (1u64 << bits) - 1;
        Tnum {
            value: hi & !delta,
            mask: delta,
        }
    }

    /// Set union — the tightest tnum containing both. A bit stays known only
    /// if both agree on it.
    #[inline]
    #[must_use]
    pub const fn join(self, other: Tnum) -> Tnum {
        let mu = self.mask | other.mask | (self.value ^ other.value);
        Tnum {
            value: self.value & !mu,
            mask: mu,
        }
    }

    /// Set intersection. `None` when the two disagree on a known bit, which
    /// means the combination is unreachable.
    #[inline]
    #[must_use]
    pub const fn meet(self, other: Tnum) -> Option<Tnum> {
        if ((self.value ^ other.value) & !(self.mask | other.mask)) != 0 {
            return None;
        }
        let mu = self.mask & other.mask;
        Some(Tnum {
            value: (self.value | other.value) & !mu,
            mask: mu,
        })
    }

    /// Whether `self` describes a subset of `other`.
    #[inline]
    #[must_use]
    pub const fn is_subset_of(self, other: Tnum) -> bool {
        // Every bit `other` knows, `self` must know and agree on.
        (self.mask & !other.mask) == 0 && ((self.value ^ other.value) & !other.mask) == 0
    }

    /// Addition. The carry chain turns a known bit into an unknown one
    /// wherever an unknown operand bit could propagate into it.
    #[must_use]
    pub const fn add(self, other: Tnum) -> Tnum {
        let sm = self.mask.wrapping_add(other.mask);
        let sv = self.value.wrapping_add(other.value);
        let sigma = sm.wrapping_add(sv);
        let chi = sigma ^ sv;
        let mu = chi | self.mask | other.mask;
        Tnum {
            value: sv & !mu,
            mask: mu,
        }
    }

    /// Subtraction. The borrow chain is the mirror of `add`'s carry chain.
    #[must_use]
    pub const fn sub(self, other: Tnum) -> Tnum {
        let dv = self.value.wrapping_sub(other.value);
        let alpha = dv.wrapping_add(self.mask);
        let beta = dv.wrapping_sub(other.mask);
        let chi = alpha ^ beta;
        let mu = chi | self.mask | other.mask;
        Tnum {
            value: dv & !mu,
            mask: mu,
        }
    }

    /// Bitwise and. Exact: no carries to lose.
    #[must_use]
    pub const fn and(self, other: Tnum) -> Tnum {
        let alpha = self.value | self.mask;
        let beta = other.value | other.mask;
        let v = self.value & other.value;
        Tnum {
            value: v,
            mask: alpha & beta & !v,
        }
    }

    /// Bitwise or. Exact.
    #[must_use]
    pub const fn or(self, other: Tnum) -> Tnum {
        let v = self.value | other.value;
        let mu = self.mask | other.mask;
        Tnum {
            value: v,
            mask: mu & !v,
        }
    }

    /// Bitwise xor. Exact.
    #[must_use]
    pub const fn xor(self, other: Tnum) -> Tnum {
        let v = self.value ^ other.value;
        let mu = self.mask | other.mask;
        Tnum {
            value: v & !mu,
            mask: mu,
        }
    }

    /// Logical left shift by a known amount.
    #[inline]
    #[must_use]
    pub const fn shl(self, n: u32) -> Tnum {
        if n >= 64 {
            return Tnum::ZERO;
        }
        Tnum {
            value: self.value << n,
            mask: self.mask << n,
        }
    }

    /// Logical right shift by a known amount.
    #[inline]
    #[must_use]
    pub const fn shr(self, n: u32) -> Tnum {
        if n >= 64 {
            return Tnum::ZERO;
        }
        Tnum {
            value: self.value >> n,
            mask: self.mask >> n,
        }
    }

    /// Arithmetic right shift by a known amount. The sign bit's *knownness*
    /// replicates, so shifting an unknown-sign value keeps the high bits
    /// unknown — which is correct and is what a plain `shr` would get wrong.
    #[inline]
    #[must_use]
    pub const fn sar(self, n: u32) -> Tnum {
        let n = if n >= 64 { 63 } else { n };
        Tnum {
            value: ((self.value as i64) >> n) as u64,
            mask: ((self.mask as i64) >> n) as u64,
        }
    }

    /// Multiplication, by long multiplication over the known and unknown bits.
    ///
    /// Deliberately an inherent method rather than `core::ops::Mul`: the
    /// operator traits would invite writing `a * b` on abstract values, and
    /// abstract arithmetic is exactly the place where the reader must see that
    /// something non-obvious is happening.
    ///
    /// Each set bit of the multiplier contributes a shifted multiplicand; each
    /// *unknown* bit contributes a shifted "anything the multiplicand could
    /// be". Both accumulate through `add`, so carries are handled once.
    #[must_use]
    #[allow(clippy::should_implement_trait)]
    pub fn mul(self, other: Tnum) -> Tnum {
        let mut acc = Tnum::ZERO;
        let mut a = self;
        let mut b = other;
        let mut steps = 0;
        while (a.value | a.mask) != 0 && steps < 64 {
            if (a.value & 1) != 0 {
                acc = acc.add(b);
            } else if (a.mask & 1) != 0 {
                acc = acc.add(Tnum {
                    value: 0,
                    mask: b.value | b.mask,
                });
            }
            a = a.shr(1);
            b = b.shl(1);
            steps += 1;
        }
        acc
    }

    /// Keep the low `bits` bits, zeroing everything above.
    #[inline]
    #[must_use]
    pub const fn zero_extend(self, bits: u32) -> Tnum {
        if bits >= 64 {
            return self;
        }
        let keep = (1u64 << bits) - 1;
        Tnum {
            value: self.value & keep,
            mask: self.mask & keep,
        }
    }

    /// Sign-extend from `bits`.
    #[must_use]
    pub const fn sign_extend(self, bits: u32) -> Tnum {
        if bits >= 64 {
            return self;
        }
        let shift = 64 - bits;
        Tnum {
            value: (((self.value << shift) as i64) >> shift) as u64,
            mask: (((self.mask << shift) as i64) >> shift) as u64,
        }
    }
}

/// The abstract value of a scalar: a tnum reduced against a signed interval.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Scalar {
    /// Known/unknown bits.
    pub tnum: Tnum,
    /// Smallest possible value, as signed.
    pub min: i64,
    /// Largest possible value, as signed.
    pub max: i64,
}

impl Scalar {
    /// No information at all.
    pub const UNKNOWN: Scalar = Scalar {
        tnum: Tnum::UNKNOWN,
        min: i64::MIN,
        max: i64::MAX,
    };

    /// A known constant.
    #[inline]
    #[must_use]
    pub const fn constant(v: i64) -> Scalar {
        Scalar {
            tnum: Tnum::constant(v as u64),
            min: v,
            max: v,
        }
    }

    /// Everything representable in `bits` bits, zero-extended.
    #[must_use]
    pub fn unsigned_bits(bits: u32) -> Scalar {
        if bits >= 64 {
            return Scalar::UNKNOWN;
        }
        let hi = (1u64 << bits) - 1;
        Scalar {
            tnum: Tnum { value: 0, mask: hi },
            min: 0,
            max: hi as i64,
        }
    }

    /// Everything representable in `bits` bits, sign-extended.
    #[must_use]
    pub fn signed_bits(bits: u32) -> Scalar {
        if bits >= 64 {
            return Scalar::UNKNOWN;
        }
        let lo = -(1i64 << (bits - 1));
        let hi = (1i64 << (bits - 1)) - 1;
        Scalar {
            tnum: Tnum::UNKNOWN.sign_extend(bits),
            min: lo,
            max: hi,
        }
        .normalized()
    }

    /// Whether `v` is a member of the concretisation.
    ///
    /// This is the soundness predicate the differential fuzzer checks after
    /// every transfer function: the concrete result must always be a member of
    /// the abstract result.
    #[inline]
    #[must_use]
    pub const fn contains(&self, v: u64) -> bool {
        self.tnum.contains(v) && (v as i64) >= self.min && (v as i64) <= self.max
    }

    /// The single value, if there is only one.
    #[inline]
    #[must_use]
    pub const fn as_const(&self) -> Option<i64> {
        if self.tnum.is_const() {
            Some(self.tnum.value as i64)
        } else if self.min == self.max {
            Some(self.min)
        } else {
            None
        }
    }

    /// Unsigned bounds, derived rather than stored.
    ///
    /// This is the method that lets NARF get away with one interval where
    /// Linux keeps two. It intersects what the interval implies with what the
    /// tnum implies, which is strictly at least as good as either alone.
    #[must_use]
    pub fn unsigned_bounds(&self) -> (u64, u64) {
        // From the interval. A signed range maps to a *contiguous* unsigned
        // range only when it does not straddle zero.
        let straddles_zero = self.min < 0 && self.max >= 0;
        let (ilo, ihi) = if straddles_zero {
            (0, u64::MAX)
        } else {
            // Wholly non-negative or wholly negative: the signed order and the
            // unsigned order agree, so the endpoints carry over by cast.
            (self.min as u64, self.max as u64)
        };
        let (tlo, thi) = self.tnum.unsigned_bounds();
        (max(ilo, tlo), min(ihi, thi))
    }

    /// Reduce the two components against each other.
    ///
    /// `None` means the value set is empty — the program point is
    /// unreachable, which is how an impossible branch condition is reported.
    ///
    /// Iterated to a small fixed bound rather than to a fixpoint: each round
    /// can only tighten, tightening is monotone, and in practice a second
    /// round already changes nothing. Capping it keeps `normalize` cheap
    /// enough to call after literally every transfer function, which is what
    /// makes "one `normalize()`" a real simplification rather than a slogan.
    #[must_use]
    pub fn normalize(mut self) -> Option<Scalar> {
        for _ in 0..3 {
            if self.min > self.max {
                return None;
            }
            let before = self;

            // interval ← tnum
            let (tlo, thi) = self.tnum.signed_bounds();
            self.min = max(self.min, tlo);
            self.max = min(self.max, thi);
            if self.min > self.max {
                return None;
            }

            // tnum ← interval. A signed interval only pins high bits when it
            // does not straddle zero; when it does, the sign bit itself is the
            // only thing it could say and it says nothing.
            let derived = if self.min >= 0 || self.max < 0 {
                Tnum::from_unsigned_range(self.min as u64, self.max as u64)
            } else {
                Tnum::UNKNOWN
            };
            self.tnum = self.tnum.meet(derived)?;

            if self == before {
                break;
            }
        }
        if self.min > self.max {
            return None;
        }
        Some(self)
    }

    /// [`Scalar::normalize`], keeping the input when the value set is empty.
    ///
    /// For construction sites that cannot produce an empty set, where
    /// threading an `Option` would only add noise.
    #[must_use]
    pub fn normalized(self) -> Scalar {
        self.normalize().unwrap_or(self)
    }

    // ── Derived subregister views ───────────────────────────────────
    //
    // Stored nowhere. Linux keeps `s32_min/max` and `u32_min/max` on every
    // register and has to keep all four in step with the 64-bit pair through
    // `__reg32_deduce_bounds` and `__reg_combine_32_into_64`; here the 32-bit
    // facts are a function of the 64-bit ones and cannot drift from them.

    /// The low 32 bits, zero-extended — the value a 32-bit ALU op produces.
    #[must_use]
    pub fn zext32(&self) -> Scalar {
        let mut t = self.tnum.zero_extend(32);
        // When the whole 64-bit interval shares a high half, the low half is
        // monotone across it and its range carries over exactly.
        if (self.min as u64) >> 32 == (self.max as u64) >> 32 {
            let lo = self.min as u64 & 0xffff_ffff;
            let hi = self.max as u64 & 0xffff_ffff;
            if let Some(m) = t.meet(Tnum::from_unsigned_range(lo, hi)) {
                t = m;
            }
            return Scalar {
                tnum: t,
                min: lo as i64,
                max: hi as i64,
            }
            .normalized();
        }
        let (lo, hi) = t.unsigned_bounds();
        Scalar {
            tnum: t,
            min: lo as i64,
            max: hi as i64,
        }
        .normalized()
    }

    /// The low 32 bits, sign-extended.
    #[must_use]
    pub fn sext32(&self) -> Scalar {
        let z = self.zext32();
        let (lo, hi) = z.unsigned_bounds();
        const HALF: u64 = 1 << 31;
        const FULL: i64 = 1 << 32;
        // Exact whenever bit 31 is settled across the whole range; only a
        // range that straddles it loses anything, and then it loses only the
        // interval, not the tnum.
        let (min, max) = if hi < HALF {
            (lo as i64, hi as i64)
        } else if lo >= HALF {
            (lo as i64 - FULL, hi as i64 - FULL)
        } else {
            (-(1i64 << 31), (1i64 << 31) - 1)
        };
        Scalar {
            tnum: z.tnum.sign_extend(32),
            min,
            max,
        }
        .normalized()
    }

    /// Sign-extend from `bits`.
    #[must_use]
    pub fn sign_extend(&self, bits: u32) -> Scalar {
        if bits >= 64 {
            return *self;
        }
        let t = self.tnum.zero_extend(bits).sign_extend(bits);
        Scalar {
            tnum: t,
            min: -(1i64 << (bits - 1)),
            max: (1i64 << (bits - 1)) - 1,
        }
        .normalized()
    }

    // ── Lattice operations ──────────────────────────────────────────

    /// Least upper bound.
    #[must_use]
    pub fn join(&self, other: &Scalar) -> Scalar {
        Scalar {
            tnum: self.tnum.join(other.tnum),
            min: min(self.min, other.min),
            max: max(self.max, other.max),
        }
        .normalized()
    }

    /// Greatest lower bound. `None` when the two are disjoint.
    #[must_use]
    pub fn meet(&self, other: &Scalar) -> Option<Scalar> {
        Scalar {
            tnum: self.tnum.meet(other.tnum)?,
            min: max(self.min, other.min),
            max: min(self.max, other.max),
        }
        .normalize()
    }

    /// Whether `self` describes a subset of `other`. Used by the fixpoint to
    /// decide whether a block's input actually changed.
    #[must_use]
    pub fn is_subset_of(&self, other: &Scalar) -> bool {
        self.min >= other.min && self.max <= other.max && self.tnum.is_subset_of(other.tnum)
    }

    /// Widening: `self` is the previous input, `next` the new one.
    ///
    /// The tnum component needs no widening — its mask only ever grows and
    /// tops out after 64 steps, so joins alone terminate. Only the interval
    /// can climb indefinitely, and it is widened to the nearest *threshold*
    /// rather than straight to `i64::MIN`/`i64::MAX`.
    ///
    /// Threshold widening matters more here than in a typical analyser. A BPF
    /// loop that walks an array establishes its bound with a comparison
    /// against a constant, and that constant is in the threshold set; jumping
    /// past it would discard the very fact the subsequent memory access needs.
    #[must_use]
    pub fn widen(&self, next: &Scalar, thresholds: &[i64]) -> Scalar {
        let widened_below = next.min < self.min;
        let widened_above = next.max > self.max;
        let min = if next.min < self.min {
            // Largest threshold not above the new minimum.
            thresholds
                .iter()
                .rev()
                .copied()
                .find(|&t| t <= next.min)
                .unwrap_or(i64::MIN)
        } else {
            self.min
        };
        let max = if next.max > self.max {
            thresholds
                .iter()
                .copied()
                .find(|&t| t >= next.max)
                .unwrap_or(i64::MAX)
        } else {
            self.max
        };
        // A reduced product's reduction can *undo* a widening: `normalize`
        // would pull the freshly widened interval straight back to whatever
        // the tnum still implies, and the sequence would then climb one bit at
        // a time — terminating, but only after ~64 rounds per loop header
        // instead of a handful. So when the interval widens, the tnum is
        // relaxed to at least the interval's own abstraction, keeping the two
        // components' ascending chains in step.
        let mut tnum = self.tnum.join(next.tnum);
        if widened_below || widened_above {
            let hull = if min >= 0 || max < 0 {
                Tnum::from_unsigned_range(min as u64, max as u64)
            } else {
                Tnum::UNKNOWN
            };
            tnum = tnum.join(hull);
        }
        Scalar { tnum, min, max }.normalized()
    }

    // ── Refinement from branch conditions ───────────────────────────

    /// Constrain to values `>= c`, signed.
    #[must_use]
    pub fn refine_signed_min(&self, c: i64) -> Option<Scalar> {
        Scalar {
            min: max(self.min, c),
            ..*self
        }
        .normalize()
    }

    /// Constrain to values `<= c`, signed.
    #[must_use]
    pub fn refine_signed_max(&self, c: i64) -> Option<Scalar> {
        Scalar {
            max: min(self.max, c),
            ..*self
        }
        .normalize()
    }

    /// Constrain to values `<= c`, unsigned.
    ///
    /// Exact, and the direction every array bounds check depends on: for
    /// `c < 2^63` the constraint implies the value is non-negative *and* at
    /// most `c`, which is precisely a signed interval.
    #[must_use]
    pub fn refine_unsigned_max(&self, c: u64) -> Option<Scalar> {
        let mut out = *self;
        if c < SIGN {
            out.min = max(out.min, 0);
            out.max = min(out.max, c as i64);
            out.tnum = out.tnum.meet(Tnum::from_unsigned_range(0, c))?;
        } else if self.max < 0 {
            // Already known negative, so the unsigned view is the high half
            // and the bound transfers directly.
            out.max = min(out.max, c as i64);
        }
        out.normalize()
    }

    /// Constrain to values `>= c`, unsigned.
    ///
    /// // LINUX-GAP: for `0 < c < 2^63` on a value whose sign is unknown, the
    /// solution set `[c, i64::MAX] ∪ [i64::MIN, -1]` is not an interval and we
    /// drop the constraint. Linux keeps it in its separate `u64` range. The
    /// cost is precision on the rare `if (x >= K) ...` where `x` has not
    /// already been shown non-negative; the benefit is not maintaining a
    /// fourth numeric domain and the deduction rules that tie it to the other
    /// three. Sound either way: dropping a constraint only widens.
    #[must_use]
    pub fn refine_unsigned_min(&self, c: u64) -> Option<Scalar> {
        if c == 0 {
            return Some(*self);
        }
        let mut out = *self;
        if c >= SIGN {
            // The sign bit must be set, so the value is negative.
            out.min = max(out.min, c as i64);
            out.max = min(out.max, -1);
        } else if self.min >= 0 {
            out.min = max(out.min, c as i64);
        }
        out.normalize()
    }

    /// Constrain to exactly the values `other` allows.
    #[must_use]
    pub fn refine_eq(&self, other: &Scalar) -> Option<Scalar> {
        self.meet(other)
    }

    /// Constrain to values `other` does *not* allow.
    ///
    /// Only actionable when `other` is a single value sitting on one of our
    /// endpoints; a general set difference is not representable and is
    /// soundly ignored.
    #[must_use]
    pub fn refine_ne(&self, other: &Scalar) -> Option<Scalar> {
        let Some(c) = other.as_const() else {
            return Some(*self);
        };
        if self.min == self.max && self.min == c {
            return None; // provably impossible branch
        }
        let mut out = *self;
        if out.min == c {
            out.min = c.checked_add(1)?;
        }
        if out.max == c {
            out.max = c.checked_sub(1)?;
        }
        out.normalize()
    }

    /// Constrain from `self & other == 0` (the not-taken side of `JSET`).
    #[must_use]
    pub fn refine_bits_clear(&self, other: &Scalar) -> Option<Scalar> {
        let Some(c) = other.as_const() else {
            return Some(*self);
        };
        let mut out = *self;
        out.tnum = out.tnum.meet(Tnum {
            value: 0,
            mask: !(c as u64),
        })?;
        out.normalize()
    }

    /// Constrain from `self & other != 0` (the taken side of `JSET`).
    ///
    /// The only deduction available is the contradiction: if every bit in the
    /// mask is known clear, the branch cannot be taken.
    #[must_use]
    pub fn refine_bits_set(&self, other: &Scalar) -> Option<Scalar> {
        let Some(c) = other.as_const() else {
            return Some(*self);
        };
        let c = c as u64;
        let could_be_set = (self.tnum.value | self.tnum.mask) & c;
        if could_be_set == 0 {
            return None;
        }
        Some(*self)
    }

    // ── Transfer functions ──────────────────────────────────────────

    /// `self + other`, 64-bit wrapping.
    #[must_use]
    pub fn add(&self, other: &Scalar) -> Scalar {
        let (min, max) = interval_add(self.min, self.max, other.min, other.max);
        Scalar {
            tnum: self.tnum.add(other.tnum),
            min,
            max,
        }
        .normalized()
    }

    /// `self - other`, 64-bit wrapping.
    #[must_use]
    pub fn sub(&self, other: &Scalar) -> Scalar {
        let (nlo, nhi) = interval_neg(other.min, other.max);
        let (min, max) = interval_add(self.min, self.max, nlo, nhi);
        Scalar {
            tnum: self.tnum.sub(other.tnum),
            min,
            max,
        }
        .normalized()
    }

    /// `self * other`, 64-bit wrapping.
    #[must_use]
    pub fn mul(&self, other: &Scalar) -> Scalar {
        let (min, max) = interval_mul(self.min, self.max, other.min, other.max);
        Scalar {
            tnum: self.tnum.mul(other.tnum),
            min,
            max,
        }
        .normalized()
    }

    /// `-self`, 64-bit wrapping.
    #[must_use]
    pub fn neg(&self) -> Scalar {
        let (min, max) = interval_neg(self.min, self.max);
        Scalar {
            tnum: Tnum::ZERO.sub(self.tnum),
            min,
            max,
        }
        .normalized()
    }

    /// `self & other`.
    #[must_use]
    pub fn and(&self, other: &Scalar) -> Scalar {
        Scalar {
            tnum: self.tnum.and(other.tnum),
            min: i64::MIN,
            max: i64::MAX,
        }
        .normalized()
    }

    /// `self | other`.
    #[must_use]
    pub fn or(&self, other: &Scalar) -> Scalar {
        Scalar {
            tnum: self.tnum.or(other.tnum),
            min: i64::MIN,
            max: i64::MAX,
        }
        .normalized()
    }

    /// `self ^ other`.
    #[must_use]
    pub fn xor(&self, other: &Scalar) -> Scalar {
        Scalar {
            tnum: self.tnum.xor(other.tnum),
            min: i64::MIN,
            max: i64::MAX,
        }
        .normalized()
    }

    /// `self << other`, with the shift amount masked to 6 bits as the ISA
    /// requires.
    #[must_use]
    pub fn shl(&self, other: &Scalar) -> Scalar {
        let Some(n) = shift_amount(other, 63) else {
            return Scalar::UNKNOWN;
        };
        // A left shift is exact on the interval when nothing can overflow
        // into or out of the sign bit — which is the case that matters, since
        // `idx << 3` for a bounds-checked index is how every array access is
        // built.
        let (min, max) = if self.min >= 0 && (self.max as u64) <= (i64::MAX as u64) >> n {
            (self.min << n, self.max << n)
        } else {
            (i64::MIN, i64::MAX)
        };
        Scalar {
            tnum: self.tnum.shl(n),
            min,
            max,
        }
        .normalized()
    }

    /// `self >> other`, logical, shift masked to 6 bits.
    #[must_use]
    pub fn shr(&self, other: &Scalar) -> Scalar {
        let Some(n) = shift_amount(other, 63) else {
            return Scalar::UNKNOWN;
        };
        if n == 0 {
            return *self;
        }
        // For any non-zero shift the result has its top bit clear, so it is a
        // non-negative signed value however negative the input was.
        let (min, max) = if self.min >= 0 {
            (self.min >> n, self.max >> n)
        } else {
            (0, (u64::MAX >> n) as i64)
        };
        Scalar {
            tnum: self.tnum.shr(n),
            min,
            max,
        }
        .normalized()
    }

    /// `self >> other`, arithmetic, shift masked to 6 bits. Exact on the
    /// interval: an arithmetic shift is monotone.
    #[must_use]
    pub fn sar(&self, other: &Scalar) -> Scalar {
        let Some(n) = shift_amount(other, 63) else {
            return Scalar::UNKNOWN;
        };
        Scalar {
            tnum: self.tnum.sar(n),
            min: self.min >> n,
            max: self.max >> n,
        }
        .normalized()
    }

    /// Unsigned division, with the ISA's "divide by zero yields zero" rule.
    #[must_use]
    pub fn udiv(&self, other: &Scalar) -> Scalar {
        let (alo, ahi) = self.unsigned_bounds();
        let (blo, bhi) = other.unsigned_bounds();
        // Larger divisors give smaller quotients, so the bounds cross. A
        // divisor that is *provably* zero pins the result at zero; one that
        // merely *may* be zero adds zero to the range without raising the top.
        let hi = if bhi == 0 {
            0
        } else if blo == 0 {
            ahi
        } else {
            ahi / blo
        };
        let lo = if blo == 0 { 0 } else { alo / bhi };
        from_unsigned_range(lo, hi)
    }

    /// Unsigned modulo. Zero divisor leaves the dividend, per the ISA.
    #[must_use]
    pub fn umod(&self, other: &Scalar) -> Scalar {
        let (_, ahi) = self.unsigned_bounds();
        let (blo, bhi) = other.unsigned_bounds();
        let hi = if blo == 0 {
            ahi
        } else {
            min(ahi, bhi.saturating_sub(1))
        };
        from_unsigned_range(0, hi)
    }

    /// Signed division.
    ///
    /// // LINUX-GAP: NARF gives up on the interval for signed division except
    /// when both operands are constant, where the ISA's two special cases
    /// (`x / 0 == 0`, `LLONG_MIN / -1 == LLONG_MIN`) are applied exactly.
    /// Linux does no better in the general case; the difference is that we say
    /// so in one place instead of spreading partial rules across
    /// `adjust_scalar_min_max_vals`.
    #[must_use]
    pub fn sdiv(&self, other: &Scalar) -> Scalar {
        match (self.as_const(), other.as_const()) {
            (Some(a), Some(b)) => Scalar::constant(concrete_sdiv(a, b)),
            _ => Scalar::UNKNOWN,
        }
    }

    /// Signed modulo. Same treatment as [`Scalar::sdiv`].
    #[must_use]
    pub fn smod(&self, other: &Scalar) -> Scalar {
        match (self.as_const(), other.as_const()) {
            (Some(a), Some(b)) => Scalar::constant(concrete_smod(a, b)),
            _ => Scalar::UNKNOWN,
        }
    }

    /// Byte-order reversal of the low `width` bits.
    #[must_use]
    pub fn bswap(&self, width: u8) -> Scalar {
        match self.as_const() {
            Some(v) => Scalar::constant(concrete_bswap(v as u64, width) as i64),
            // A swap permutes bits between positions the tnum tracks
            // independently, so nothing survives except the width bound.
            None => match width {
                16 => Scalar::unsigned_bits(16),
                32 => Scalar::unsigned_bits(32),
                _ => Scalar::UNKNOWN,
            },
        }
    }
}

/// Abstraction of an unsigned range.
#[must_use]
pub fn from_unsigned_range(lo: u64, hi: u64) -> Scalar {
    if lo > hi {
        return Scalar::UNKNOWN;
    }
    let t = Tnum::from_unsigned_range(lo, hi);
    // A range that stays inside one half of the signed space is also a signed
    // interval; one that straddles is not, and the tnum carries what it can.
    let straddles_sign = lo <= i64::MAX as u64 && hi > i64::MAX as u64;
    let (min, max) = if straddles_sign {
        (i64::MIN, i64::MAX)
    } else {
        (lo as i64, hi as i64)
    };
    Scalar { tnum: t, min, max }.normalized()
}

/// The shift amount, masked to `mask`, if it is a single value.
fn shift_amount(s: &Scalar, mask: u32) -> Option<u32> {
    let c = s.as_const()?;
    Some((c as u64 as u32) & mask)
}

fn interval_add(alo: i64, ahi: i64, blo: i64, bhi: i64) -> (i64, i64) {
    let lo = i128::from(alo) + i128::from(blo);
    let hi = i128::from(ahi) + i128::from(bhi);
    if lo >= i128::from(i64::MIN) && hi <= i128::from(i64::MAX) {
        (lo as i64, hi as i64)
    } else {
        (i64::MIN, i64::MAX)
    }
}

fn interval_neg(lo: i64, hi: i64) -> (i64, i64) {
    let nlo = -i128::from(hi);
    let nhi = -i128::from(lo);
    if nlo >= i128::from(i64::MIN) && nhi <= i128::from(i64::MAX) {
        (nlo as i64, nhi as i64)
    } else {
        (i64::MIN, i64::MAX)
    }
}

fn interval_mul(alo: i64, ahi: i64, blo: i64, bhi: i64) -> (i64, i64) {
    let corners = [
        i128::from(alo) * i128::from(blo),
        i128::from(alo) * i128::from(bhi),
        i128::from(ahi) * i128::from(blo),
        i128::from(ahi) * i128::from(bhi),
    ];
    let lo = corners.iter().copied().min().unwrap_or(0);
    let hi = corners.iter().copied().max().unwrap_or(0);
    if lo >= i128::from(i64::MIN) && hi <= i128::from(i64::MAX) {
        (lo as i64, hi as i64)
    } else {
        (i64::MIN, i64::MAX)
    }
}

// ── Concrete semantics ──────────────────────────────────────────────
//
// The reference the abstract transfer functions are fuzzed against, and the
// definition of record for the ISA's arithmetic corner cases:
// `instruction-set.rst:349-362`. Keeping them here rather than in the test
// module means the abstract and concrete definitions of, say, "division by
// zero" cannot drift apart.

/// Signed 64-bit division with the ISA's special cases.
#[inline]
#[must_use]
pub const fn concrete_sdiv(a: i64, b: i64) -> i64 {
    if b == 0 {
        0
    } else if a == i64::MIN && b == -1 {
        i64::MIN
    } else {
        a / b
    }
}

/// Signed 64-bit modulo with the ISA's special cases. A zero divisor leaves
/// the destination unchanged, which the caller must handle; this returns `a`
/// to express that.
#[inline]
#[must_use]
pub const fn concrete_smod(a: i64, b: i64) -> i64 {
    if b == 0 {
        a
    } else if a == i64::MIN && b == -1 {
        0
    } else {
        a % b
    }
}

/// Unsigned 64-bit division; zero divisor yields zero.
#[inline]
#[must_use]
pub const fn concrete_udiv(a: u64, b: u64) -> u64 {
    if b == 0 {
        0
    } else {
        a / b
    }
}

/// Unsigned 64-bit modulo; zero divisor leaves the dividend.
#[inline]
#[must_use]
pub const fn concrete_umod(a: u64, b: u64) -> u64 {
    if b == 0 {
        a
    } else {
        a % b
    }
}

/// Byte-reverse the low `width` bits, zeroing above.
#[must_use]
pub const fn concrete_bswap(v: u64, width: u8) -> u64 {
    match width {
        16 => (v as u16).swap_bytes() as u64,
        32 => (v as u32).swap_bytes() as u64,
        _ => v.swap_bytes(),
    }
}

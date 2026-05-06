//! Fixed-capacity bitmap with arch-optimised scans.
//!
//! Spec: `lib/specification/spec.md` §3.3. Portable fallback here; arch-
//! specific scan paths (`tzcnt`/`lzcnt` on x86_64 with BMI1, `CLZ`/`RBIT` on
//! aarch64) land once `arch/` has its feature-detection wrappers.
//!
//! `DynBitmap` waits on `memory/`'s allocator (Stage 2).

use core::fmt;

/// Number of bits backing each storage word.
const WORD_BITS: usize = usize::BITS as usize;

/// Number of `usize` words needed to back `bits` bits.
#[doc(hidden)]
#[inline]
pub const fn word_count(bits: usize) -> usize {
    bits.div_ceil(WORD_BITS)
}

/// Fixed-capacity bitmap of `N` bits.
#[derive(Clone)]
pub struct Bitmap<const N: usize>
where
    [(); word_count(N)]:, // const generic arithmetic; requires generic_const_exprs
{
    words: [usize; word_count(N)],
}

impl<const N: usize> Bitmap<N>
where
    [(); word_count(N)]:,
{
    /// New empty bitmap (all bits clear).
    pub const fn new() -> Self {
        Self {
            words: [0; word_count(N)],
        }
    }

    /// New bitmap with all bits set.
    pub const fn new_full() -> Self {
        let mut b = Self {
            words: [usize::MAX; word_count(N)],
        };
        // Mask trailing bits above N in the final word.
        let tail_bits = N % WORD_BITS;
        if tail_bits != 0 && word_count(N) > 0 {
            let mask = (1usize << tail_bits) - 1;
            b.words[word_count(N) - 1] = mask;
        }
        b
    }

    /// Capacity in bits.
    pub const fn capacity() -> usize {
        N
    }

    /// Test whether bit `i` is set. Returns `false` for out-of-range.
    #[inline]
    pub fn get(&self, i: usize) -> bool {
        if i >= N {
            return false;
        }
        let (w, b) = (i / WORD_BITS, i % WORD_BITS);
        (self.words[w] >> b) & 1 == 1
    }

    /// Set bit `i`. Panics on out-of-range in debug; silently no-ops in release.
    #[inline]
    pub fn set(&mut self, i: usize) {
        debug_assert!(i < N, "Bitmap::set index out of range");
        if i >= N {
            return;
        }
        let (w, b) = (i / WORD_BITS, i % WORD_BITS);
        self.words[w] |= 1 << b;
    }

    /// Clear bit `i`. Debug-asserts range; release silently no-ops.
    #[inline]
    pub fn clear(&mut self, i: usize) {
        debug_assert!(i < N, "Bitmap::clear index out of range");
        if i >= N {
            return;
        }
        let (w, b) = (i / WORD_BITS, i % WORD_BITS);
        self.words[w] &= !(1 << b);
    }

    /// Flip bit `i` and return the previous value.
    #[inline]
    pub fn toggle(&mut self, i: usize) -> bool {
        debug_assert!(i < N, "Bitmap::toggle index out of range");
        if i >= N {
            return false;
        }
        let (w, b) = (i / WORD_BITS, i % WORD_BITS);
        let prev = (self.words[w] >> b) & 1 == 1;
        self.words[w] ^= 1 << b;
        prev
    }

    /// Index of the first set bit.
    pub fn first_set(&self) -> Option<usize> {
        for (wi, &w) in self.words.iter().enumerate() {
            if w != 0 {
                let bit = w.trailing_zeros() as usize;
                let idx = wi * WORD_BITS + bit;
                if idx < N {
                    return Some(idx);
                }
            }
        }
        None
    }

    /// Index of the first clear bit.
    pub fn first_clear(&self) -> Option<usize> {
        for (wi, &w) in self.words.iter().enumerate() {
            if w != usize::MAX {
                let bit = (!w).trailing_zeros() as usize;
                let idx = wi * WORD_BITS + bit;
                if idx < N {
                    return Some(idx);
                }
            }
        }
        None
    }

    /// Count of set bits.
    pub fn count_ones(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Iterator over set-bit indices in ascending order.
    pub fn iter_set(&self) -> IterSet<'_, N>
    where
        [(); word_count(N)]:,
    {
        IterSet {
            bitmap: self,
            word_idx: 0,
            word: self.words.first().copied().unwrap_or(0),
        }
    }
}

impl<const N: usize> Default for Bitmap<N>
where
    [(); word_count(N)]:,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> fmt::Debug for Bitmap<N>
where
    [(); word_count(N)]:,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Bitmap")
            .field("capacity", &N)
            .field("set", &self.count_ones())
            .finish()
    }
}

/// Iterator over set bit indices.
pub struct IterSet<'a, const N: usize>
where
    [(); word_count(N)]:,
{
    bitmap: &'a Bitmap<N>,
    word_idx: usize,
    word: usize,
}

impl<const N: usize> Iterator for IterSet<'_, N>
where
    [(); word_count(N)]:,
{
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        loop {
            if self.word != 0 {
                let bit = self.word.trailing_zeros() as usize;
                self.word &= self.word - 1; // clear low bit
                let idx = self.word_idx * WORD_BITS + bit;
                if idx < N {
                    return Some(idx);
                } else {
                    return None;
                }
            }
            self.word_idx += 1;
            if self.word_idx >= word_count(N) {
                return None;
            }
            self.word = self.bitmap.words[self.word_idx];
        }
    }
}

impl<const N: usize> fmt::Debug for IterSet<'_, N>
where
    [(); word_count(N)]:,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IterSet").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_has_no_bits() {
        let b: Bitmap<64> = Bitmap::new();
        assert_eq!(b.count_ones(), 0);
        assert_eq!(b.first_set(), None);
        assert_eq!(b.first_clear(), Some(0));
    }

    #[test]
    fn set_get_clear() {
        let mut b: Bitmap<128> = Bitmap::new();
        b.set(0);
        b.set(64);
        b.set(127);
        assert!(b.get(0));
        assert!(b.get(64));
        assert!(b.get(127));
        assert!(!b.get(1));
        assert_eq!(b.count_ones(), 3);
        assert_eq!(b.first_set(), Some(0));
        b.clear(0);
        assert_eq!(b.first_set(), Some(64));
    }

    #[test]
    fn iter_set_yields_in_order() {
        let mut b: Bitmap<70> = Bitmap::new();
        b.set(3);
        b.set(5);
        b.set(64);
        b.set(69);
        let v: heapless_vec::Vec = b.iter_set().collect();
        assert_eq!(v.as_slice(), &[3, 5, 64, 69]);
    }

    #[test]
    fn full_bitmap_wraps_trailing_bits() {
        let b: Bitmap<3> = Bitmap::new_full();
        assert!(b.get(0));
        assert!(b.get(1));
        assert!(b.get(2));
        assert!(!b.get(3)); // out of range
        assert_eq!(b.count_ones(), 3);
        assert_eq!(b.first_clear(), None);
    }

    /// Minimal in-module test Vec to avoid dragging in `alloc` for unit tests.
    /// (real callers use `alloc` or an intrusive iterator consumer.)
    mod heapless_vec {
        pub struct Vec {
            buf: [usize; 16],
            len: usize,
        }
        impl Vec {
            pub fn as_slice(&self) -> &[usize] {
                &self.buf[..self.len]
            }
        }
        impl FromIterator<usize> for Vec {
            fn from_iter<I: IntoIterator<Item = usize>>(iter: I) -> Self {
                let mut v = Vec {
                    buf: [0; 16],
                    len: 0,
                };
                for x in iter {
                    assert!(v.len < 16);
                    v.buf[v.len] = x;
                    v.len += 1;
                }
                v
            }
        }
    }
}

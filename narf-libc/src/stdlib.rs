//! `<stdlib.h>` numeric + sort surface: `atoi`, `atol`,
//! `strtol`, `strtoul`, `qsort`, `bsearch`.
//!
//! Pure user-side — no kernel syscalls. The numeric parsers follow
//! C99 §7.20.1: skip leading whitespace, optional sign, optional
//! `0x`/`0X` for base-16 (and `0` for base-8 when `base == 0`),
//! consume digits until the first invalid character.
//!
//! `qsort` is a textbook insertion sort. Stage-4 callers operate on
//! tiny slices (validate probes use ≤16 elements); the O(n²) cost
//! is irrelevant at that scale and the implementation is half the
//! size of a quicksort. Swap by raw byte loop because we don't know
//! the element type at compile time.

#![allow(non_camel_case_types)]

use crate::posix::{c_char, c_int, c_void};

pub type c_long  = i64;
pub type c_ulong = u64;

/// Whitespace per C99 isspace: space, \t, \n, \v, \f, \r.
#[inline]
fn is_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r')
}

/// Digit value in `base`; returns `None` if `b` isn't a digit in
/// that base. Accepts both upper and lower hex letters.
#[inline]
fn digit_value(b: u8, base: u32) -> Option<u32> {
    let v = match b {
        b'0'..=b'9' => (b - b'0') as u32,
        b'a'..=b'z' => 10 + (b - b'a') as u32,
        b'A'..=b'Z' => 10 + (b - b'A') as u32,
        _ => return None,
    };
    if v < base { Some(v) } else { None }
}

/// Walk a NUL-terminated C string, skipping leading whitespace and
/// optional sign. Returns `(remaining_ptr, sign, base, after_prefix)`.
/// `after_prefix` advances past `0x`/`0X` if `base == 16` and the
/// prefix is present, or past `0` if `base == 0` and the leading
/// digit is `0`. When `base == 0` on entry the function infers it
/// from the prefix (0x = 16, 0 = 8, otherwise 10).
///
/// # Safety
/// `s` must point at a valid NUL-terminated C string.
unsafe fn parse_prefix(
    s: *const c_char,
    base: c_int,
) -> (*const c_char, i64, u32) {
    let mut p = s;
    // Skip whitespace.
    // SAFETY: caller contract.
    while unsafe { *p } != 0 && is_space(unsafe { *p } as u8) {
        // SAFETY: walked past in-string bytes only.
        p = unsafe { p.add(1) };
    }
    // Sign.
    let sign: i64 = match unsafe { *p } as u8 {
        b'+' => { p = unsafe { p.add(1) }; 1 }
        b'-' => { p = unsafe { p.add(1) }; -1 }
        _ => 1,
    };
    // Base inference + 0x prefix consume.
    let mut b = if base == 0 { 10 } else { base as u32 };
    if unsafe { *p } as u8 == b'0' {
        let next = unsafe { *p.add(1) } as u8;
        if (next == b'x' || next == b'X') && (base == 0 || base == 16) {
            b = 16;
            p = unsafe { p.add(2) };
        } else if base == 0 {
            // C99: leading 0 (without x) implies octal when base==0.
            b = 8;
            // Don't consume the 0 — it's the first digit.
        }
    }
    (p, sign, b)
}

/// `strtol(*const char, **mut char, int base)` — C99 numeric parse.
/// Stores a pointer past the last consumed character into `*endptr`
/// when `endptr` is non-null. Returns 0 if no digits were consumed.
///
/// Out-of-range overflow saturates (LONG_MAX or LONG_MIN). errno is
/// not set today — relibc-shape callers can read the saturated
/// sentinel value.
///
/// # Safety
/// `nptr` must be a valid NUL-terminated C string; `endptr` (if
/// non-null) must be a writable pointer-to-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtol(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_long {
    if nptr.is_null() {
        return 0;
    }
    // SAFETY: caller contract on nptr.
    let (mut p, sign, base) = unsafe { parse_prefix(nptr, base) };
    let mut acc: i64 = 0;
    let mut consumed = false;
    let mut overflowed = false;
    loop {
        // SAFETY: walking past in-string bytes only; NUL terminates.
        let b = unsafe { *p };
        if b == 0 {
            break;
        }
        let d = match digit_value(b as u8, base) {
            Some(v) => v as i64,
            None    => break,
        };
        // Saturate on overflow.
        let next = acc
            .checked_mul(base as i64)
            .and_then(|x| x.checked_add(if sign < 0 { -d } else { d }));
        acc = match next {
            Some(v) => v,
            None    => {
                overflowed = true;
                if sign < 0 { i64::MIN } else { i64::MAX }
            }
        };
        consumed = true;
        // SAFETY: same.
        p = unsafe { p.add(1) };
        if overflowed {
            // Drain the rest of the digits so endptr lands past them.
            // SAFETY: same.
            while {
                let b2 = unsafe { *p };
                b2 != 0 && digit_value(b2 as u8, base).is_some()
            } {
                p = unsafe { p.add(1) };
            }
            break;
        }
    }
    if !endptr.is_null() {
        // SAFETY: caller-supplied endptr — write through.
        unsafe {
            *endptr = if consumed {
                p as *mut c_char
            } else {
                nptr as *mut c_char
            };
        }
    }
    acc
}

/// `strtoul(*const char, **mut char, int base)` — unsigned form.
/// Same shape as [`strtol`] minus signed-overflow handling.
///
/// # Safety
/// See [`strtol`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtoul(
    nptr: *const c_char,
    endptr: *mut *mut c_char,
    base: c_int,
) -> c_ulong {
    if nptr.is_null() {
        return 0;
    }
    // SAFETY: caller contract.
    let (mut p, sign, base) = unsafe { parse_prefix(nptr, base) };
    let mut acc: u64 = 0;
    let mut consumed = false;
    loop {
        // SAFETY: walking past in-string bytes only.
        let b = unsafe { *p };
        if b == 0 {
            break;
        }
        let d = match digit_value(b as u8, base) {
            Some(v) => v as u64,
            None    => break,
        };
        acc = acc.saturating_mul(base as u64).saturating_add(d);
        consumed = true;
        // SAFETY: same.
        p = unsafe { p.add(1) };
    }
    if !endptr.is_null() {
        // SAFETY: caller-supplied endptr.
        unsafe {
            *endptr = if consumed {
                p as *mut c_char
            } else {
                nptr as *mut c_char
            };
        }
    }
    if sign < 0 {
        // C99: strtoul of "-N" returns the two's-complement wrap.
        // Keeps the libc convention so `(unsigned long)-1` survives.
        acc.wrapping_neg()
    } else {
        acc
    }
}

/// `atoi(*const char)` — equivalent to `strtol(s, NULL, 10)`
/// truncated to `int`. C99 leaves overflow undefined; we reuse
/// strtol's saturation.
///
/// # Safety
/// See [`strtol`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atoi(nptr: *const c_char) -> c_int {
    // SAFETY: caller contract.
    unsafe { strtol(nptr, core::ptr::null_mut(), 10) as c_int }
}

/// `atol(*const char)` — `strtol(s, NULL, 10)`.
///
/// # Safety
/// See [`strtol`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atol(nptr: *const c_char) -> c_long {
    // SAFETY: caller contract.
    unsafe { strtol(nptr, core::ptr::null_mut(), 10) }
}

/// C-shaped comparator: `int (*cmp)(const void *a, const void *b)`.
pub type cmp_fn = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

/// Swap `size` bytes between `a` and `b`. Used by [`qsort`].
///
/// # Safety
/// Both `a` and `b` must point to writable regions of at least
/// `size` bytes; the regions must not overlap.
unsafe fn swap_bytes(a: *mut u8, b: *mut u8, size: usize) {
    for i in 0..size {
        // SAFETY: both regions are at least `size` bytes per caller.
        unsafe {
            let tmp = *a.add(i);
            *a.add(i) = *b.add(i);
            *b.add(i) = tmp;
        }
    }
}

/// `qsort(base, nmemb, size, cmp)` — in-place insertion sort. O(n²)
/// worst-case but small-code, zero-alloc, and adequate for the
/// validate-grade workload (≤16 elements). Swap by raw byte loop
/// since the element type is opaque.
///
/// # Safety
/// `base` must point to `nmemb * size` writable bytes; `cmp` must
/// be a valid C-shaped comparator that doesn't unwind.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn qsort(
    base: *mut c_void,
    nmemb: usize,
    size: usize,
    cmp: cmp_fn,
) {
    if nmemb < 2 || size == 0 {
        return;
    }
    let base = base as *mut u8;
    for i in 1..nmemb {
        let mut j = i;
        while j > 0 {
            // SAFETY: both indices are < nmemb so the offsets are in-bounds.
            let a = unsafe { base.add((j - 1) * size) };
            let b = unsafe { base.add(j * size) };
            // SAFETY: caller-supplied comparator with the same byte
            // pointers we passed it.
            let ord = unsafe { cmp(a as *const c_void, b as *const c_void) };
            if ord <= 0 {
                break;
            }
            // SAFETY: a and b are disjoint (j != j-1) regions of `size` bytes.
            unsafe { swap_bytes(a, b, size); }
            j -= 1;
        }
    }
}

/// `bsearch(key, base, nmemb, size, cmp)` — binary search over a
/// sorted array. Returns a pointer to the matching element or null.
///
/// # Safety
/// `base` must point to `nmemb * size` readable bytes already sorted
/// per `cmp`; `key` must point at a `size`-byte readable region;
/// `cmp` must be a valid C-shaped comparator.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bsearch(
    key: *const c_void,
    base: *const c_void,
    nmemb: usize,
    size: usize,
    cmp: cmp_fn,
) -> *mut c_void {
    if nmemb == 0 || size == 0 {
        return core::ptr::null_mut();
    }
    let base = base as *const u8;
    let mut lo = 0usize;
    let mut hi = nmemb;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        // SAFETY: mid < nmemb so the offset is in-bounds.
        let mid_ptr = unsafe { base.add(mid * size) };
        // SAFETY: caller-supplied comparator.
        let ord = unsafe { cmp(key, mid_ptr as *const c_void) };
        if ord == 0 {
            return mid_ptr as *mut c_void;
        } else if ord < 0 {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    core::ptr::null_mut()
}

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

/// `atoll(*const char)` — `strtoll(s, NULL, 10)`. C99 `long long`
/// form. On a 64-bit target this aliases [`atol`] result-wise.
///
/// # Safety
/// See [`strtol`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atoll(nptr: *const c_char) -> i64 {
    // SAFETY: caller contract.
    unsafe { strtol(nptr, core::ptr::null_mut(), 10) }
}

/// `strtoll(nptr, endptr, base)` — C99 `long long` parse. Aliases
/// [`strtol`] under the 64-bit `c_long`.
///
/// # Safety
/// See [`strtol`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtoll(
    nptr:   *const c_char,
    endptr: *mut *mut c_char,
    base:   c_int,
) -> i64 {
    // SAFETY: forwarded.
    unsafe { strtol(nptr, endptr, base) }
}

/// `strtoull(nptr, endptr, base)` — C99 `unsigned long long` parse.
/// Aliases [`strtoul`] under the 64-bit `c_ulong`.
///
/// # Safety
/// See [`strtoul`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtoull(
    nptr:   *const c_char,
    endptr: *mut *mut c_char,
    base:   c_int,
) -> u64 {
    // SAFETY: forwarded.
    unsafe { strtoul(nptr, endptr, base) }
}

/// Minimal `strtod(nptr, endptr)` — parse a leading decimal float.
/// Honours optional sign, integer part, fractional part, and a
/// `[eE][+-]?digits` exponent. No hex-float, no INF / NAN tokens
/// (a real implementation lives in `core::str::FromStr<f64>` but
/// we can't `unwrap` a `&str` cleanly across a raw pointer without
/// re-validating UTF-8).
///
/// Reference: musl `src/stdlib/strtod.c` — full musl form parses
/// hex floats and special tokens too; this is the subset NARF
/// consumers reach for.
///
/// # Safety
/// `nptr` must be a valid NUL-terminated C string. `endptr`, when
/// non-null, must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtod(
    nptr:   *const c_char,
    endptr: *mut *mut c_char,
) -> f64 {
    if nptr.is_null() { return 0.0; }
    // SAFETY: caller contract — walk bytes until invalid.
    let mut p = nptr as *const u8;
    // Skip whitespace.
    unsafe {
        while *p != 0 && matches!(*p, b' ' | b'\t' | b'\n' | b'\r' | 0x0B | 0x0C) {
            p = p.add(1);
        }
    }
    // Sign.
    let sign: f64 = match unsafe { *p } {
        b'+' => { unsafe { p = p.add(1); } 1.0 }
        b'-' => { unsafe { p = p.add(1); } -1.0 }
        _ => 1.0,
    };
    let mut value = 0.0f64;
    let mut any = false;
    // Integer part.
    unsafe {
        while *p >= b'0' && *p <= b'9' {
            value = value * 10.0 + (*p - b'0') as f64;
            p = p.add(1);
            any = true;
        }
        // Fractional part.
        if *p == b'.' {
            p = p.add(1);
            let mut scale = 0.1f64;
            while *p >= b'0' && *p <= b'9' {
                value += (*p - b'0') as f64 * scale;
                scale *= 0.1;
                p = p.add(1);
                any = true;
            }
        }
        // Exponent.
        if any && (*p == b'e' || *p == b'E') {
            p = p.add(1);
            let esign: i32 = match *p {
                b'+' => { p = p.add(1); 1 }
                b'-' => { p = p.add(1); -1 }
                _ => 1,
            };
            let mut exp_val = 0i32;
            while *p >= b'0' && *p <= b'9' {
                exp_val = exp_val.saturating_mul(10).saturating_add((*p - b'0') as i32);
                p = p.add(1);
            }
            let exp_val = esign * exp_val;
            let mut mult = 1.0f64;
            let abs_e = exp_val.unsigned_abs();
            for _ in 0..abs_e { mult *= 10.0; }
            if exp_val < 0 { value /= mult; } else { value *= mult; }
        }
    }
    if !endptr.is_null() {
        // SAFETY: caller-asserted writable.
        unsafe { *endptr = p as *mut c_char; }
    }
    if !any { return 0.0; }
    sign * value
}

/// `strtof(nptr, endptr)` — C99 `float` form. Forwards to
/// [`strtod`] and narrows.
///
/// # Safety
/// See [`strtod`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtof(
    nptr:   *const c_char,
    endptr: *mut *mut c_char,
) -> f32 {
    // SAFETY: forwarded.
    unsafe { strtod(nptr, endptr) as f32 }
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

// ── abs / labs / div / ldiv ─────────────────────────────────────────
//
// Pure value math — no allocation, no errno setting. C99 leaves
// `abs(INT_MIN)` and `labs(LONG_MIN)` undefined; we wrap them via
// `wrapping_abs` so the result is well-defined (returns the input
// unchanged at the negative-extreme). That matches what every modern
// libc actually does.

/// `<stdlib.h>` `div_t` shape. Two `int` fields per C99 §7.20.6.2.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct div_t {
    pub quot: c_int,
    pub rem:  c_int,
}

/// `<stdlib.h>` `ldiv_t` shape. Two `long` fields per C99 §7.20.6.2.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct ldiv_t {
    pub quot: c_long,
    pub rem:  c_long,
}

/// `abs(j)` — magnitude of a C `int`. `INT_MIN` is wrapped (returns
/// itself) rather than triggering UB.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn abs(j: c_int) -> c_int {
    j.wrapping_abs()
}

/// `labs(j)` — magnitude of a C `long`. Same wrapping semantics as
/// [`abs`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn labs(j: c_long) -> c_long {
    j.wrapping_abs()
}

/// `div(num, denom)` — quotient + remainder. Behaviour with
/// `denom == 0` follows the C99 rule: undefined. We saturate the
/// quotient to 0 and the remainder to the numerator instead of
/// trapping the divide.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn div(num: c_int, denom: c_int) -> div_t {
    if denom == 0 {
        return div_t { quot: 0, rem: num };
    }
    div_t {
        quot: num.wrapping_div(denom),
        rem:  num.wrapping_rem(denom),
    }
}

/// `ldiv(num, denom)` — long-int variant of [`div`]. Same saturation
/// rule on `denom == 0`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ldiv(num: c_long, denom: c_long) -> ldiv_t {
    if denom == 0 {
        return ldiv_t { quot: 0, rem: num };
    }
    ldiv_t {
        quot: num.wrapping_div(denom),
        rem:  num.wrapping_rem(denom),
    }
}

// ── rand / srand ────────────────────────────────────────────────────
//
// C99 only requires deterministic per-seed output and `rand()` to
// return a value in `[0, RAND_MAX]`. We ship a Park-Miller minimal
// standard LCG (`x' = x * 48271 mod (2^31 - 1)`) which has full
// period 2^31 - 2, no zero-seed degenerate, and one multiplication +
// one modulo per call. RAND_MAX matches glibc's value (0x7FFF_FFFF)
// because the LCG output already lives in that range.

/// C99 / glibc-compatible upper bound on `rand()` results.
pub const RAND_MAX: c_int = 0x7FFF_FFFF;

/// LCG state. Initial value = 1 per C99: `srand(1)` is the implicit
/// pre-seed. Single-threaded user mode keeps this race-free.
static mut RAND_STATE: u32 = 1;

/// `srand(seed)` — reseed the deterministic generator. A zero seed
/// would lock the LCG at zero forever, so we substitute 1 instead
/// (matching glibc's behaviour).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn srand(seed: u32) {
    let s = if seed == 0 { 1 } else { seed & 0x7FFF_FFFF };
    // SAFETY: single-threaded user-mode invariant; access is
    // serialised by execution order.
    unsafe { RAND_STATE = if s == 0 { 1 } else { s }; }
}

/// `rand()` — Park-Miller minimal standard LCG. Returns the next
/// pseudo-random integer in `[0, RAND_MAX]`. Determinism per seed is
/// the only contract; do not use this for cryptography.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rand() -> c_int {
    // SAFETY: single-threaded invariant — see `srand`.
    unsafe {
        // Park-Miller in 64-bit arithmetic to avoid overflow.
        let next = ((RAND_STATE as u64) * 48271) % 0x7FFF_FFFF;
        RAND_STATE = next as u32;
        next as c_int
    }
}

// ── sscanf-shim (integer-only) ──────────────────────────────────────
//
// Real `sscanf` would parse a varadic format string with type-
// dispatched assignment targets. We can't ship that on stable Rust.
// What real callers need most often is "pull one or two integers
// from a string" — `sscanf(s, "%d %d", &a, &b)` or
// `sscanf(s, "%x", &x)`. We expose a Rust-shaped helper that returns
// up to N parsed integers in a caller buffer, so consumers don't
// have to reach for strtol's endptr by hand.

/// Parse decimal/hex integers from `s`, storing up to `out.len()`
/// values into `out`. Whitespace separates fields; an `0x`/`0X`
/// prefix triggers hex on a per-field basis. Returns the number of
/// successfully parsed values.
///
/// # Safety
/// `s` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sscanf_ints(s: *const c_char, out: &mut [i64]) -> usize {
    if s.is_null() || out.is_empty() { return 0; }
    let mut p = s;
    let mut n = 0usize;
    while n < out.len() {
        // Skip whitespace.
        // SAFETY: NUL-bounded walk per caller contract.
        unsafe {
            while *p != 0 && is_space(*p as u8) {
                p = p.add(1);
            }
            if *p == 0 { break; }
        }
        // Detect optional sign + base prefix; reuse parse_prefix.
        // SAFETY: `p` still in the caller's NUL-terminated string.
        let (mut q, sign, base) = unsafe { parse_prefix(p, 0) };
        // Need at least one digit for a successful parse.
        // SAFETY: NUL-bounded read.
        let first = unsafe { *q } as u8;
        if digit_value(first, base).is_none() {
            break;
        }
        let mut acc: i64 = 0;
        loop {
            // SAFETY: NUL-bounded.
            let b = unsafe { *q } as u8;
            let d = match digit_value(b, base) {
                Some(v) => v as i64,
                None    => break,
            };
            let signed_d = if sign < 0 { -d } else { d };
            acc = acc
                .checked_mul(base as i64)
                .and_then(|x| x.checked_add(signed_d))
                .unwrap_or(if sign < 0 { i64::MIN } else { i64::MAX });
            // SAFETY: NUL-bounded.
            q = unsafe { q.add(1) };
        }
        out[n] = acc;
        n += 1;
        p = q;
    }
    n
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

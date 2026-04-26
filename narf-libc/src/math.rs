//! `<math.h>` — minimum-viable IEEE-754 math surface.
//!
//! Stage-4 scope (no libm dependency, no_std-friendly):
//! - Sign + magnitude: `fabs`, `copysign`, `signbit`
//! - Rounding: `floor`, `ceil`, `trunc`, `round`
//! - Modulo + min/max: `fmod`, `fmin`, `fmax`
//! - Roots: `sqrt` (single instruction on both arches)
//! - Predicates: `isnan`, `isinf`, `isfinite`
//!
//! All three-letter / four-letter doubles ship with `f`-suffixed
//! single-precision twins. Integer rounding uses bit-twiddling on
//! the IEEE-754 layout (no libm needed); `sqrt` uses the arch's
//! native instruction (`sqrtsd` on x86_64 SSE2, `fsqrt` on aarch64).
//!
//! Transcendentals (`sin`/`cos`/`exp`/`log`/`pow`) deliberately
//! aren't included — they'd need polynomial-approximation tables
//! that grow this module substantially. They land alongside a real
//! libm port, when something needs them.

#![allow(non_camel_case_types)]

// ── bitwise sign + magnitude ───────────────────────────────────────

/// `fabs(x)` — magnitude (clear sign bit).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fabs(x: f64) -> f64 {
    f64::from_bits(x.to_bits() & !(1u64 << 63))
}

/// `fabsf(x)` — single-precision magnitude.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fabsf(x: f32) -> f32 {
    f32::from_bits(x.to_bits() & !(1u32 << 31))
}

/// `copysign(x, y)` — magnitude of `x`, sign of `y`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn copysign(x: f64, y: f64) -> f64 {
    let mag  = x.to_bits() & !(1u64 << 63);
    let sign = y.to_bits() &  (1u64 << 63);
    f64::from_bits(mag | sign)
}

/// `copysignf(x, y)` — single-precision sign copy.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn copysignf(x: f32, y: f32) -> f32 {
    let mag  = x.to_bits() & !(1u32 << 31);
    let sign = y.to_bits() &  (1u32 << 31);
    f32::from_bits(mag | sign)
}

/// `signbit(x)` — non-zero iff the sign bit is set (handles -0).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signbit(x: f64) -> i32 {
    ((x.to_bits() >> 63) & 1) as i32
}

// ── predicates ─────────────────────────────────────────────────────

/// `isnan(x)` — non-zero iff `x` is NaN.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isnan(x: f64) -> i32 {
    let bits = x.to_bits();
    let exp  = (bits >> 52) & 0x7FF;
    let frac =  bits        & ((1u64 << 52) - 1);
    (exp == 0x7FF && frac != 0) as i32
}

/// `isinf(x)` — `+1` for +inf, `-1` for -inf, `0` otherwise. The
/// libc convention is non-zero on infinity; signed sentinels match
/// glibc.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isinf(x: f64) -> i32 {
    let bits = x.to_bits();
    let exp  = (bits >> 52) & 0x7FF;
    let frac =  bits        & ((1u64 << 52) - 1);
    if exp == 0x7FF && frac == 0 {
        if (bits >> 63) & 1 == 1 { -1 } else { 1 }
    } else {
        0
    }
}

/// `isfinite(x)` — non-zero iff `x` is neither NaN nor infinite.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isfinite(x: f64) -> i32 {
    let exp = (x.to_bits() >> 52) & 0x7FF;
    (exp != 0x7FF) as i32
}

// ── rounding (bit-twiddled, no libm) ───────────────────────────────
//
// IEEE-754 layout for f64:  [sign:1][exp:11][frac:52].
// Unbiased exponent E = exp - 1023.
// - E < 0:  |x| < 1 → trunc/floor/ceil produce 0 or ±1.
// - E >= 52: integer already → return x.
// - 0 <= E < 52: mask off the low (52 - E) frac bits.

fn trunc_f64(x: f64) -> f64 {
    let bits = x.to_bits();
    let exp  = ((bits >> 52) & 0x7FF) as i32 - 1023;
    if exp < 0 {
        // |x| < 1 → round toward zero is just ±0.0.
        f64::from_bits(bits & (1u64 << 63))
    } else if exp >= 52 {
        x
    } else {
        let mask = !((1u64 << (52 - exp as u32)) - 1);
        f64::from_bits(bits & mask)
    }
}

fn trunc_f32(x: f32) -> f32 {
    let bits = x.to_bits();
    let exp  = ((bits >> 23) & 0xFF) as i32 - 127;
    if exp < 0 {
        f32::from_bits(bits & (1u32 << 31))
    } else if exp >= 23 {
        x
    } else {
        let mask = !((1u32 << (23 - exp as u32)) - 1);
        f32::from_bits(bits & mask)
    }
}

/// `trunc(x)` — round toward zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn trunc(x: f64) -> f64 { trunc_f64(x) }

/// `truncf(x)` — single-precision trunc.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn truncf(x: f32) -> f32 { trunc_f32(x) }

/// `floor(x)` — round toward `-inf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn floor(x: f64) -> f64 {
    let t = trunc_f64(x);
    if t == x || x >= 0.0 { t } else { t - 1.0 }
}

/// `floorf(x)` — single-precision floor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn floorf(x: f32) -> f32 {
    let t = trunc_f32(x);
    if t == x || x >= 0.0 { t } else { t - 1.0 }
}

/// `ceil(x)` — round toward `+inf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ceil(x: f64) -> f64 {
    let t = trunc_f64(x);
    if t == x || x <= 0.0 { t } else { t + 1.0 }
}

/// `ceilf(x)` — single-precision ceil.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ceilf(x: f32) -> f32 {
    let t = trunc_f32(x);
    if t == x || x <= 0.0 { t } else { t + 1.0 }
}

/// `round(x)` — round half away from zero (C99).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn round(x: f64) -> f64 {
    let bias = if x.to_bits() >> 63 == 1 { -0.5 } else { 0.5 };
    trunc_f64(x + bias)
}

/// `roundf(x)` — single-precision round-half-away-from-zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn roundf(x: f32) -> f32 {
    let bias = if x.to_bits() >> 31 == 1 { -0.5 } else { 0.5 };
    trunc_f32(x + bias)
}

// ── min / max / fmod ───────────────────────────────────────────────

/// `fmin(x, y)` — IEEE 754-2008 minNum: NaN-quieting (the non-NaN
/// argument wins if exactly one is NaN).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fmin(x: f64, y: f64) -> f64 {
    // SAFETY: pure value math.
    if unsafe { isnan(x) != 0 } { y }
    else if unsafe { isnan(y) != 0 } { x }
    else if x < y { x } else { y }
}

/// `fmax(x, y)` — IEEE 754-2008 maxNum.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fmax(x: f64, y: f64) -> f64 {
    // SAFETY: pure value math.
    if unsafe { isnan(x) != 0 } { y }
    else if unsafe { isnan(y) != 0 } { x }
    else if x > y { x } else { y }
}

/// `fminf` / `fmaxf` — single-precision twins.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fminf(x: f32, y: f32) -> f32 {
    if x.is_nan() { y } else if y.is_nan() { x }
    else if x < y { x } else { y }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fmaxf(x: f32, y: f32) -> f32 {
    if x.is_nan() { y } else if y.is_nan() { x }
    else if x > y { x } else { y }
}

/// `fmod(x, y)` — IEEE remainder via repeated subtraction of scaled
/// `y`. Handles the common cases; degenerate inputs (0, NaN, inf,
/// y==0) follow the C99 contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fmod(x: f64, y: f64) -> f64 {
    // SAFETY: pure value math; helpers are no-mangle wrappers.
    let nan = f64::from_bits(0x7FF8_0000_0000_0000);
    if unsafe { isnan(x) != 0 || isnan(y) != 0 } { return nan; }
    if y == 0.0 || unsafe { isinf(x) != 0 } { return nan; }
    if unsafe { isinf(y) != 0 } { return x; }
    let neg = x < 0.0;
    let mut a = unsafe { fabs(x) };
    let b = unsafe { fabs(y) };
    if a < b {
        return if neg { -a } else { a };
    }
    // Doubling subtraction: scale `b` up while it fits, then peel
    // off the largest multiple at each step. O(log(x/y)) iterations.
    while a >= b {
        let mut t = b;
        while t * 2.0 <= a {
            t *= 2.0;
        }
        a -= t;
    }
    if neg { -a } else { a }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fmodf(x: f32, y: f32) -> f32 {
    // SAFETY: forwarding to f64 is fine for the value range we
    // handle; the cast is exact for the integer-shaped reductions.
    unsafe { fmod(x as f64, y as f64) as f32 }
}

// ── sqrt — software Newton-Raphson ─────────────────────────────────
//
// The natural implementation is one `sqrtsd` / `fsqrt` instruction,
// but the narf-libc rlib's target (kernel `x86_64-unknown-none` /
// `aarch64-unknown-none`) ships without the SSE / FP feature so the
// inline-asm `xmm_reg` / `vreg` register classes can't be named.
// Instead we run Newton's method on `g <- 0.5 * (g + x/g)`, which
// converges quadratically — 16 iterations from `x * 0.5` is more
// than enough for f64 across the IEEE range we care about. The
// initial guess is bit-twiddled to halve the exponent so the loop
// starts within a factor of √2 of the correct answer (one of the
// standard tricks for software sqrt).

#[inline]
fn sqrt_initial_guess(x: f64) -> f64 {
    // Halve the exponent: bias = 1023, target_exp = (exp + bias) / 2.
    // Strip sign (always 0 here — caller filtered negatives) and
    // shift the exponent + bias half-rounded.
    let bits = x.to_bits();
    let exp = ((bits >> 52) & 0x7FF) as i64 - 1023;
    let new_exp = ((exp + 1023) / 2 + 1023 / 2) as u64;
    let mantissa = bits & ((1u64 << 52) - 1);
    f64::from_bits((new_exp & 0x7FF) << 52 | mantissa)
}

/// `sqrt(x)` — Newton-Raphson `g <- 0.5 * (g + x/g)` to f64
/// precision. Returns NaN for negative inputs; preserves +0 / +inf.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqrt(x: f64) -> f64 {
    let nan = f64::from_bits(0x7FF8_0000_0000_0000);
    if x < 0.0 { return nan; }
    if x == 0.0 || !x.is_finite() { return x; }
    let mut g = sqrt_initial_guess(x);
    // 16 iterations is overkill — 6 typically suffices for f64 —
    // but keeps the worst-case-input bound generous.
    let mut i = 0;
    while i < 16 {
        let next = 0.5 * (g + x / g);
        if next == g {
            break;
        }
        g = next;
        i += 1;
    }
    g
}

/// `sqrtf(x)` — single-precision sqrt via the f64 path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sqrtf(x: f32) -> f32 {
    // SAFETY: pure forwarding; `sqrt` returns a f64 in the f32 range
    // for any in-range f32 input.
    unsafe { sqrt(x as f64) as f32 }
}

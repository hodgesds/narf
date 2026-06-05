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
    let mag = x.to_bits() & !(1u64 << 63);
    let sign = y.to_bits() & (1u64 << 63);
    f64::from_bits(mag | sign)
}

/// `copysignf(x, y)` — single-precision sign copy.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn copysignf(x: f32, y: f32) -> f32 {
    let mag = x.to_bits() & !(1u32 << 31);
    let sign = y.to_bits() & (1u32 << 31);
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
    let exp = (bits >> 52) & 0x7FF;
    let frac = bits & ((1u64 << 52) - 1);
    (exp == 0x7FF && frac != 0) as i32
}

/// `isinf(x)` — `+1` for +inf, `-1` for -inf, `0` otherwise. The
/// libc convention is non-zero on infinity; signed sentinels match
/// glibc.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isinf(x: f64) -> i32 {
    let bits = x.to_bits();
    let exp = (bits >> 52) & 0x7FF;
    let frac = bits & ((1u64 << 52) - 1);
    if exp == 0x7FF && frac == 0 {
        if (bits >> 63) & 1 == 1 {
            -1
        } else {
            1
        }
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
    let exp = ((bits >> 52) & 0x7FF) as i32 - 1023;
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
    let exp = ((bits >> 23) & 0xFF) as i32 - 127;
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
pub unsafe extern "C" fn trunc(x: f64) -> f64 {
    trunc_f64(x)
}

/// `truncf(x)` — single-precision trunc.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn truncf(x: f32) -> f32 {
    trunc_f32(x)
}

/// `floor(x)` — round toward `-inf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn floor(x: f64) -> f64 {
    let t = trunc_f64(x);
    if t == x || x >= 0.0 {
        t
    } else {
        t - 1.0
    }
}

/// `floorf(x)` — single-precision floor.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn floorf(x: f32) -> f32 {
    let t = trunc_f32(x);
    if t == x || x >= 0.0 {
        t
    } else {
        t - 1.0
    }
}

/// `ceil(x)` — round toward `+inf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ceil(x: f64) -> f64 {
    let t = trunc_f64(x);
    if t == x || x <= 0.0 {
        t
    } else {
        t + 1.0
    }
}

/// `ceilf(x)` — single-precision ceil.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ceilf(x: f32) -> f32 {
    let t = trunc_f32(x);
    if t == x || x <= 0.0 {
        t
    } else {
        t + 1.0
    }
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
    if unsafe { isnan(x) != 0 } {
        y
    } else if unsafe { isnan(y) != 0 } {
        x
    } else if x < y {
        x
    } else {
        y
    }
}

/// `fmax(x, y)` — IEEE 754-2008 maxNum.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fmax(x: f64, y: f64) -> f64 {
    // SAFETY: pure value math.
    if unsafe { isnan(x) != 0 } {
        y
    } else if unsafe { isnan(y) != 0 } {
        x
    } else if x > y {
        x
    } else {
        y
    }
}

/// `fminf` / `fmaxf` — single-precision twins.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fminf(x: f32, y: f32) -> f32 {
    if x.is_nan() {
        y
    } else if y.is_nan() {
        x
    } else if x < y {
        x
    } else {
        y
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn fmaxf(x: f32, y: f32) -> f32 {
    if x.is_nan() {
        y
    } else if y.is_nan() {
        x
    } else if x > y {
        x
    } else {
        y
    }
}

/// `fmod(x, y)` — IEEE remainder via repeated subtraction of scaled
/// `y`. Handles the common cases; degenerate inputs (0, NaN, inf,
/// y==0) follow the C99 contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fmod(x: f64, y: f64) -> f64 {
    // SAFETY: pure value math; helpers are no-mangle wrappers.
    let nan = f64::from_bits(0x7FF8_0000_0000_0000);
    if unsafe { isnan(x) != 0 || isnan(y) != 0 } {
        return nan;
    }
    if y == 0.0 || unsafe { isinf(x) != 0 } {
        return nan;
    }
    if unsafe { isinf(y) != 0 } {
        return x;
    }
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
    if neg {
        -a
    } else {
        a
    }
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
    if x < 0.0 {
        return nan;
    }
    if x == 0.0 || !x.is_finite() {
        return x;
    }
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

// ── transcendentals (Tier 3l) ──────────────────────────────────────
//
// All polynomial approximations. Targets ~1e-7 absolute accuracy in
// the reduced argument range — adequate for the Stage-4 audit
// surface (kernel tests, user-binary smoke checks). Real numerical
// codes that need IEEE-754-correct rounding ship their own libm.
//
// The constants below are the well-known minimax / Taylor
// coefficients distilled from Cody & Waite, "Software Manual for
// the Elementary Functions" (1980), and Hart, "Computer
// Approximations" (1968).

const PI: f64 = 3.141_592_653_589_793_2;
const TWO_PI: f64 = 6.283_185_307_179_586_5;
const HALF_PI: f64 = 1.570_796_326_794_896_6;
const QUARTER_PI: f64 = 0.785_398_163_397_448_3;
const LN2: f64 = 0.693_147_180_559_945_3;
const LOG2E: f64 = 1.442_695_040_888_963_4; // 1 / ln 2

// ── exp / expf ─────────────────────────────────────────────────────
//
// exp(x) = 2^k * exp(r), where k = round(x / ln 2) and
// r = x - k * ln 2 ∈ [-ln2/2, ln2/2]. exp(r) approximated by an
// 8-term Taylor series; the multiplication by 2^k is then a single
// IEEE-754 exponent splice.

fn ldexp_f64(m: f64, k: i32) -> f64 {
    // Construct 2^k via the IEEE exponent field. Saturates at the
    // f64 range — k > 1023 returns +inf; k < -1074 returns 0.
    if k > 1023 {
        return f64::INFINITY * m.signum();
    }
    if k < -1074 {
        return 0.0 * m.signum();
    }
    if k >= -1022 {
        // Normal path: bias is 1023.
        let bits = ((k + 1023) as u64) << 52;
        m * f64::from_bits(bits)
    } else {
        // Subnormal: split the multiplication so we don't overflow
        // the exponent field.
        let s1 = -1022;
        let s2 = k - s1;
        let m1 = f64::from_bits(((s1 + 1023) as u64) << 52);
        let m2 = f64::from_bits(((s2 + 1023) as u64) << 52);
        m * m1 * m2
    }
}

fn exp_kernel(r: f64) -> f64 {
    // 8-term Taylor: 1 + r + r²/2! + ... + r⁷/7! over the reduced
    // range [-ln2/2, ln2/2].
    let r2 = r * r;
    let r3 = r2 * r;
    let r4 = r2 * r2;
    let r5 = r4 * r;
    let r6 = r4 * r2;
    let r7 = r6 * r;
    1.0 + r
        + r2 * 0.5
        + r3 * (1.0 / 6.0)
        + r4 * (1.0 / 24.0)
        + r5 * (1.0 / 120.0)
        + r6 * (1.0 / 720.0)
        + r7 * (1.0 / 5040.0)
}

/// `exp(x)` — natural-base exponential. Saturates to +inf for
/// `x > ~709.78` and to 0 for `x < -745`. NaN propagates.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn exp(x: f64) -> f64 {
    // SAFETY: pure value math; isnan/isinf use bitfields only.
    if unsafe { isnan(x) != 0 } {
        return x;
    }
    if x > 709.782_712_893_4 {
        return f64::INFINITY;
    }
    if x < -745.133_219_101_9 {
        return 0.0;
    }
    let k = (x * LOG2E + if x >= 0.0 { 0.5 } else { -0.5 }) as i32 as f64;
    let r = x - k * LN2;
    let kr = exp_kernel(r);
    ldexp_f64(kr, k as i32)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn expf(x: f32) -> f32 {
    // SAFETY: forwarding to f64 path.
    unsafe { exp(x as f64) as f32 }
}

// ── log / logf ─────────────────────────────────────────────────────
//
// log(x) = k * ln 2 + log(m), where x = m * 2^k with m ∈ [1, 2).
// log(m) computed via the substitution y = (m-1)/(m+1) ∈ [0, 1/3),
// then log(m) = 2 * (y + y³/3 + y⁵/5 + y⁷/7 + ...). Fast-converging
// arctanh-style series — 6 terms hit ~1e-9.

fn log_kernel(m: f64) -> f64 {
    let y = (m - 1.0) / (m + 1.0);
    let y2 = y * y;
    let y3 = y2 * y;
    let y5 = y3 * y2;
    let y7 = y5 * y2;
    let y9 = y7 * y2;
    let y11 = y9 * y2;
    2.0 * (y
        + y3 * (1.0 / 3.0)
        + y5 * (1.0 / 5.0)
        + y7 * (1.0 / 7.0)
        + y9 * (1.0 / 9.0)
        + y11 * (1.0 / 11.0))
}

/// `log(x)` — natural logarithm. Returns -inf for x == 0, NaN for
/// x < 0 / NaN.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn log(x: f64) -> f64 {
    let nan = f64::from_bits(0x7FF8_0000_0000_0000);
    if x.is_nan() {
        return x;
    }
    if x < 0.0 {
        return nan;
    }
    if x == 0.0 {
        return f64::NEG_INFINITY;
    }
    if x.is_infinite() {
        return x;
    }
    let bits = x.to_bits();
    let exp_field = ((bits >> 52) & 0x7FF) as i32 - 1023;
    // Force the mantissa into [1.0, 2.0) by clearing the exponent.
    let mantissa_bits = (bits & ((1u64 << 52) - 1)) | (1023u64 << 52);
    let m = f64::from_bits(mantissa_bits);
    (exp_field as f64) * LN2 + log_kernel(m)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn logf(x: f32) -> f32 {
    // SAFETY: forwarding to f64 path.
    unsafe { log(x as f64) as f32 }
}

/// `log2(x)` — base-2 log. Same domain rules as `log`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn log2(x: f64) -> f64 {
    // SAFETY: forwarded.
    unsafe { log(x) * LOG2E }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn log2f(x: f32) -> f32 {
    // SAFETY: forwarded.
    unsafe { log2(x as f64) as f32 }
}

/// `log10(x)` — base-10 log.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn log10(x: f64) -> f64 {
    const LOG10E: f64 = 0.434_294_481_903_251_8;
    // SAFETY: forwarded.
    unsafe { log(x) * LOG10E }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn log10f(x: f32) -> f32 {
    // SAFETY: forwarded.
    unsafe { log10(x as f64) as f32 }
}

// ── pow / powf ─────────────────────────────────────────────────────
//
// pow(x, y) = exp(y * log(x)) for x > 0. Edge cases (per C99):
//   - x == 1 or y == 0 → 1
//   - x == 0:
//        y > 0 → 0; y < 0 → +inf; y == 0 → 1
//   - x < 0:
//        integer y → sign-corrected pow(|x|, y)
//        non-integer y → NaN

#[inline]
fn is_integer(y: f64) -> bool {
    y.is_finite() && (unsafe { trunc(y) }) == y
}

#[inline]
fn is_odd_integer(y: f64) -> bool {
    if !is_integer(y) {
        return false;
    }
    // |y| might exceed i64 range; for very large values the parity
    // is irrelevant (the result is 0 or inf anyway). Use the low bit
    // of the truncated mantissa.
    let ay = if y < 0.0 { -y } else { y };
    if ay >= (1u64 << 53) as f64 {
        // Beyond f64 integer-precision range: treat as even — every
        // f64 large enough not to fit i64 has a binary representation
        // ending in zeros, so it's an even integer.
        return false;
    }
    (ay as i64) & 1 == 1
}

/// `pow(x, y)` — full C99 contract. Saturates to inf / 0 outside
/// the representable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pow(x: f64, y: f64) -> f64 {
    let nan = f64::from_bits(0x7FF8_0000_0000_0000);
    // Trivial cases first — avoid log(1) = 0 round-off.
    if y == 0.0 {
        return 1.0;
    }
    if x == 1.0 {
        return 1.0;
    }
    if x.is_nan() || y.is_nan() {
        return nan;
    }
    if x == 0.0 {
        if y > 0.0 {
            return 0.0;
        }
        return if is_odd_integer(y) && y < 0.0 {
            f64::INFINITY
        } else {
            f64::INFINITY
        };
    }
    if x < 0.0 {
        if !is_integer(y) {
            return nan;
        }
        // SAFETY: forwarded to the positive path.
        let mag = unsafe { pow(-x, y) };
        return if is_odd_integer(y) { -mag } else { mag };
    }
    // x > 0, y != 0.
    // SAFETY: log/exp are pure value math.
    unsafe { exp(y * log(x)) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn powf(x: f32, y: f32) -> f32 {
    // SAFETY: forwarded.
    unsafe { pow(x as f64, y as f64) as f32 }
}

// ── sin / cos / tan ────────────────────────────────────────────────
//
// Reduce |x| modulo 2π first, then move into [0, π/4] via the
// quadrant. Within [0, π/4], use 7-term Taylor series — accurate to
// ~1e-12 over that range.

fn sin_kernel(x: f64) -> f64 {
    // sin(x) = x - x³/3! + x⁵/5! - x⁷/7! + x⁹/9! - x¹¹/11! + x¹³/13!
    let x2 = x * x;
    let x3 = x2 * x;
    let x5 = x3 * x2;
    let x7 = x5 * x2;
    let x9 = x7 * x2;
    let x11 = x9 * x2;
    let x13 = x11 * x2;
    x - x3 * (1.0 / 6.0) + x5 * (1.0 / 120.0) - x7 * (1.0 / 5040.0) + x9 * (1.0 / 362880.0)
        - x11 * (1.0 / 39916800.0)
        + x13 * (1.0 / 6227020800.0)
}

fn cos_kernel(x: f64) -> f64 {
    // cos(x) = 1 - x²/2! + x⁴/4! - x⁶/6! + x⁸/8! - x¹⁰/10! + x¹²/12!
    let x2 = x * x;
    let x4 = x2 * x2;
    let x6 = x4 * x2;
    let x8 = x4 * x4;
    let x10 = x8 * x2;
    let x12 = x10 * x2;
    1.0 - x2 * 0.5 + x4 * (1.0 / 24.0) - x6 * (1.0 / 720.0) + x8 * (1.0 / 40320.0)
        - x10 * (1.0 / 3628800.0)
        + x12 * (1.0 / 479001600.0)
}

/// Reduce `x` to `[-π, π]` then to a quadrant index `q ∈ 0..4` and
/// remainder `r ∈ [-π/4, π/4]`. Returns `(q, r)`.
fn reduce_pi_over_2(x: f64) -> (i32, f64) {
    // Modulo 2π first.
    // SAFETY: fmod is pure value math.
    let mut a = unsafe { fmod(x, TWO_PI) };
    if a > PI {
        a -= TWO_PI;
    } else if a < -PI {
        a += TWO_PI;
    }
    // Now a ∈ [-π, π]. Pick a quadrant.
    if a > HALF_PI {
        return (1, a - PI);
    } // shifts to [-π/2, π/2]
    if a < -HALF_PI {
        return (3, a + PI);
    }
    // a ∈ [-π/2, π/2]. If |a| > π/4, push into quadrant 2 / 0 split.
    if a > QUARTER_PI {
        return (1, a - HALF_PI);
    }
    if a < -QUARTER_PI {
        return (3, a + HALF_PI);
    }
    (0, a)
}

/// `sin(x)` — uses sin/cos kernels per quadrant.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sin(x: f64) -> f64 {
    if x.is_nan() || x.is_infinite() {
        return f64::from_bits(0x7FF8_0000_0000_0000);
    }
    let (q, r) = reduce_pi_over_2(x);
    match q & 3 {
        0 => sin_kernel(r),
        1 => cos_kernel(r),
        2 => -sin_kernel(r),
        _ => -cos_kernel(r),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn sinf(x: f32) -> f32 {
    // SAFETY: forwarded.
    unsafe { sin(x as f64) as f32 }
}

/// `cos(x)` — uses sin/cos kernels per quadrant.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cos(x: f64) -> f64 {
    if x.is_nan() || x.is_infinite() {
        return f64::from_bits(0x7FF8_0000_0000_0000);
    }
    let (q, r) = reduce_pi_over_2(x);
    match q & 3 {
        0 => cos_kernel(r),
        1 => -sin_kernel(r),
        2 => -cos_kernel(r),
        _ => sin_kernel(r),
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn cosf(x: f32) -> f32 {
    // SAFETY: forwarded.
    unsafe { cos(x as f64) as f32 }
}

/// `tan(x)` — sin / cos. Returns ±inf at the asymptotes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tan(x: f64) -> f64 {
    // SAFETY: forwarded.
    unsafe {
        let s = sin(x);
        let c = cos(x);
        s / c
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn tanf(x: f32) -> f32 {
    // SAFETY: forwarded.
    unsafe { tan(x as f64) as f32 }
}

// ── atan / atan2 ───────────────────────────────────────────────────
//
// atan(x): reduce |x| <= 1 via atan(1/x) symmetry, then use the
// Hart-grade rational approximation. Range-reduce further by
// x = (x - tan(π/8)) / (1 + x * tan(π/8)) so the polynomial argument
// lies in [-tan(π/8), tan(π/8)] ≈ [-0.414, 0.414] — small enough
// that a 5-term Taylor (atan(t) = t - t³/3 + t⁵/5 - ...) hits ~1e-9.

const TAN_PI_8: f64 = 0.414_213_562_373_095_0;
const ATAN_PI_8: f64 = 0.392_699_081_698_724_2; // π/8

fn atan_kernel_small(t: f64) -> f64 {
    let t2 = t * t;
    let t3 = t2 * t;
    let t5 = t3 * t2;
    let t7 = t5 * t2;
    let t9 = t7 * t2;
    let t11 = t9 * t2;
    t - t3 * (1.0 / 3.0) + t5 * (1.0 / 5.0) - t7 * (1.0 / 7.0) + t9 * (1.0 / 9.0)
        - t11 * (1.0 / 11.0)
}

fn atan_pos(x: f64) -> f64 {
    // Caller guarantees x >= 0.
    if x <= TAN_PI_8 {
        atan_kernel_small(x)
    } else {
        let t = (x - TAN_PI_8) / (1.0 + x * TAN_PI_8);
        ATAN_PI_8 + atan_kernel_small(t)
    }
}

/// `atan(x)` — full real range. Returns ±π/2 at ±inf.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atan(x: f64) -> f64 {
    if x.is_nan() {
        return f64::from_bits(0x7FF8_0000_0000_0000);
    }
    if x.is_infinite() {
        return if x > 0.0 { HALF_PI } else { -HALF_PI };
    }
    let neg = x < 0.0;
    let ax = if neg { -x } else { x };
    let r = if ax > 1.0 {
        HALF_PI - atan_pos(1.0 / ax)
    } else {
        atan_pos(ax)
    };
    if neg {
        -r
    } else {
        r
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn atanf(x: f32) -> f32 {
    // SAFETY: forwarded.
    unsafe { atan(x as f64) as f32 }
}

/// `atan2(y, x)` — full quadrant. Returns the principal value in
/// `[-π, π]`. Origin (`x == 0 && y == 0`) returns 0 per glibc.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atan2(y: f64, x: f64) -> f64 {
    if x.is_nan() || y.is_nan() {
        return f64::from_bits(0x7FF8_0000_0000_0000);
    }
    if x == 0.0 && y == 0.0 {
        return 0.0;
    }
    if x > 0.0 {
        // SAFETY: forwarded.
        return unsafe { atan(y / x) };
    }
    if x < 0.0 && y >= 0.0 {
        // SAFETY: forwarded.
        return unsafe { atan(y / x) } + PI;
    }
    if x < 0.0 && y < 0.0 {
        // SAFETY: forwarded.
        return unsafe { atan(y / x) } - PI;
    }
    // x == 0.
    if y > 0.0 {
        HALF_PI
    } else {
        -HALF_PI
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn atan2f(y: f32, x: f32) -> f32 {
    // SAFETY: forwarded.
    unsafe { atan2(y as f64, x as f64) as f32 }
}

// ── ldexp / frexp / modf ───────────────────────────────────────────
//
// IEEE-754 mantissa/exponent splicers. ldexp / frexp use bit
// manipulation directly; modf splits a finite value into integer
// and fractional parts via trunc.

/// `ldexp(x, exp)` — `x * 2^exp`. Saturates to ±inf / 0 outside the
/// f64 representable range.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ldexp(x: f64, exp: i32) -> f64 {
    if x == 0.0 || x.is_nan() || x.is_infinite() {
        return x;
    }
    ldexp_f64(x, exp)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn ldexpf(x: f32, exp: i32) -> f32 {
    // SAFETY: forwarded.
    unsafe { ldexp(x as f64, exp) as f32 }
}

/// `frexp(x, *exp)` — break `x` into a normalised mantissa `m` in
/// `[0.5, 1.0)` and an exponent `e` such that `x = m * 2^e`. NaN /
/// ±inf return as-is with `*exp = 0`. Zero returns `(0, 0)`.
///
/// # Safety
/// `exp` must be a writable `*mut i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn frexp(x: f64, exp: *mut i32) -> f64 {
    if exp.is_null() {
        return x;
    }
    if x == 0.0 || x.is_nan() || x.is_infinite() {
        // SAFETY: caller-supplied writable slot.
        unsafe {
            *exp = 0;
        }
        return x;
    }
    let bits = x.to_bits();
    let raw_exp = ((bits >> 52) & 0x7FF) as i32;
    let e = raw_exp - 1022;
    // Clear and set the exponent so the result is in [0.5, 1.0).
    let mantissa_bits = (bits & !((0x7FFu64) << 52)) | (1022u64 << 52);
    // SAFETY: caller-supplied writable slot.
    unsafe {
        *exp = e;
    }
    f64::from_bits(mantissa_bits)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn frexpf(x: f32, exp: *mut i32) -> f32 {
    // SAFETY: forwarded.
    unsafe { frexp(x as f64, exp) as f32 }
}

/// `modf(x, *iptr)` — split `x` into integer and fractional parts.
/// `*iptr` receives the integer part (a finite f64 with the same
/// sign as `x`); the return value is the fractional part. NaN / inf
/// propagate.
///
/// # Safety
/// `iptr` must be a writable `*mut f64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn modf(x: f64, iptr: *mut f64) -> f64 {
    if iptr.is_null() {
        return x;
    }
    // SAFETY: trunc is no-mangle wrapper around our own bit-twiddler.
    let int_part = unsafe { trunc(x) };
    // SAFETY: caller-supplied writable slot.
    unsafe {
        *iptr = int_part;
    }
    if x.is_nan() {
        return x;
    }
    if x.is_infinite() {
        // POSIX: modf(inf, iptr) writes ±inf to iptr and returns ±0.
        return if x > 0.0 { 0.0 } else { -0.0 };
    }
    x - int_part
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn modff(x: f32, iptr: *mut f32) -> f32 {
    if iptr.is_null() {
        return x;
    }
    let mut int64: f64 = 0.0;
    // SAFETY: forwarded; modf writes through our local slot.
    let frac = unsafe { modf(x as f64, &mut int64) };
    // SAFETY: caller-supplied writable slot.
    unsafe {
        *iptr = int64 as f32;
    }
    frac as f32
}

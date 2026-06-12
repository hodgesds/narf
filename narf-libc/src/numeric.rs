//! `<complex.h>` + `<fenv.h>` minimum-viable surface.
//!
//! C99 complex types (`double _Complex`, `float _Complex`,
//! `long double _Complex`) and the floating-point environment
//! (rounding mode, exception flags). NARF doesn't change FPU state
//! at runtime — every target boots with `FE_TONEAREST` rounding
//! and exceptions masked. We surface the API entries so consumers
//! that probe them at startup link cleanly; runtime-mode changes
//! return success but don't take effect.

#![allow(non_camel_case_types)]

use crate::posix::c_int;

// ── <fenv.h> — rounding modes + exception flags ─────────────────────

pub const FE_TONEAREST: c_int = 0;
pub const FE_DOWNWARD: c_int = 1;
pub const FE_UPWARD: c_int = 2;
pub const FE_TOWARDZERO: c_int = 3;

pub const FE_INVALID: c_int = 0x01;
pub const FE_DIVBYZERO: c_int = 0x04;
pub const FE_OVERFLOW: c_int = 0x08;
pub const FE_UNDERFLOW: c_int = 0x10;
pub const FE_INEXACT: c_int = 0x20;
pub const FE_ALL_EXCEPT: c_int = 0x3D;

pub type fexcept_t = u32;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct fenv_t {
    pub _opaque: [u8; 32],
}

impl Default for fenv_t {
    fn default() -> Self {
        Self { _opaque: [0; 32] }
    }
}

/// `fegetround()` — always reports `FE_TONEAREST`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fegetround() -> c_int {
    FE_TONEAREST
}

/// `fesetround(mode)` — accepts and ignores. Returns 0 only for
/// `FE_TONEAREST` (the only honoured value); other modes return
/// non-zero per the C99 contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fesetround(mode: c_int) -> c_int {
    if mode == FE_TONEAREST {
        0
    } else {
        -1
    }
}

/// `feclearexcept(excepts)` — no-op (we don't track raised flags).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn feclearexcept(_excepts: c_int) -> c_int {
    0
}

/// `feraiseexcept(excepts)` — no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn feraiseexcept(_excepts: c_int) -> c_int {
    0
}

/// `fetestexcept(excepts)` — always reports zero raised flags.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fetestexcept(_excepts: c_int) -> c_int {
    0
}

/// `fegetenv(env)` — zero the supplied env. We have no live state
/// to record.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fegetenv(env: *mut fenv_t) -> c_int {
    if env.is_null() {
        return -1;
    }
    // SAFETY: caller-asserted writable struct.
    unsafe {
        *env = fenv_t::default();
    }
    0
}

/// `fesetenv(env)` — no-op success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fesetenv(_env: *const fenv_t) -> c_int {
    0
}

// ── <complex.h> — C99 _Complex shape + algebra ──────────────────────
//
// The C99 `_Complex double` is a value type whose layout matches
// `struct { double real, imag }`. We surface that shape as
// `complex_double` and ship the conversion / algebra helpers a
// realistic C consumer reaches for: `creal` / `cimag` / `conj` /
// `cabs` / `cadd` / `csub` / `cmul` / `cdiv`.
//
// The `_Imaginary_I` extension and full `<complex.h>` macros (e.g.
// `CMPLX(re, im)`) aren't in scope — they require compiler-level
// support narf-libc can't synthesise. Real C consumers that touch
// `cabs` etc. import them as ordinary functions (which is what we
// expose).

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct complex_double {
    pub real: f64,
    pub imag: f64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct complex_float {
    pub real: f32,
    pub imag: f32,
}

/// `creal(z)` — real part.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn creal(z: complex_double) -> f64 {
    z.real
}

/// `cimag(z)` — imaginary part.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cimag(z: complex_double) -> f64 {
    z.imag
}

/// `conj(z)` — complex conjugate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn conj(z: complex_double) -> complex_double {
    complex_double {
        real: z.real,
        imag: -z.imag,
    }
}

/// `cabs(z)` — Euclidean magnitude. Computed via the existing
/// `sqrt` (Newton-Raphson) so we don't import another libm path.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cabs(z: complex_double) -> f64 {
    // SAFETY: math::sqrt is `unsafe extern "C"` for ABI shape only;
    // body is pure value math.
    // SAFETY: Valid memory or trusted environment
    unsafe { crate::math::sqrt(z.real * z.real + z.imag * z.imag) }
}

/// Complex addition.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cadd(a: complex_double, b: complex_double) -> complex_double {
    complex_double {
        real: a.real + b.real,
        imag: a.imag + b.imag,
    }
}

/// Complex subtraction.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn csub(a: complex_double, b: complex_double) -> complex_double {
    complex_double {
        real: a.real - b.real,
        imag: a.imag - b.imag,
    }
}

/// Complex multiplication.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cmul(a: complex_double, b: complex_double) -> complex_double {
    complex_double {
        real: a.real * b.real - a.imag * b.imag,
        imag: a.real * b.imag + a.imag * b.real,
    }
}

/// Complex division. Returns `(NaN, NaN)` if the divisor magnitude
/// is zero.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cdiv(a: complex_double, b: complex_double) -> complex_double {
    let denom = b.real * b.real + b.imag * b.imag;
    if denom == 0.0 {
        let nan = f64::from_bits(0x7FF8_0000_0000_0000);
        return complex_double {
            real: nan,
            imag: nan,
        };
    }
    complex_double {
        real: (a.real * b.real + a.imag * b.imag) / denom,
        imag: (a.imag * b.real - a.real * b.imag) / denom,
    }
}

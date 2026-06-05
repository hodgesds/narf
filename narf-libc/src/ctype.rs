//! `<ctype.h>` — character classification + case folding.
//!
//! C99 §7.4: each function takes an `int` whose value is either an
//! `unsigned char` cast to `int` or `EOF` (-1). We mirror that
//! contract with `c_int` arguments and 1/0 (or the converted value)
//! returns. POSIX.1-2017 specifies these as LC_CTYPE-aware, but
//! Stage-4 NARF has no locale support — we implement the C/POSIX
//! locale only, matching what an early-boot consumer expects.
//!
//! Pure user-side; no kernel syscalls. Tiny enough that every
//! function is `#[inline]`-able into the caller. All exports are
//! `extern "C"` so a C source file links against them by name.

use crate::posix::c_int;

/// Returns non-zero iff `c` is in `0..=0x7F` (ASCII).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isascii(c: c_int) -> c_int {
    (c & !0x7F == 0) as c_int
}

/// Returns non-zero iff `c` is a digit `0..=9`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isdigit(c: c_int) -> c_int {
    (c >= b'0' as c_int && c <= b'9' as c_int) as c_int
}

/// Returns non-zero iff `c` is a lowercase letter `a..=z`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn islower(c: c_int) -> c_int {
    (c >= b'a' as c_int && c <= b'z' as c_int) as c_int
}

/// Returns non-zero iff `c` is an uppercase letter `A..=Z`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isupper(c: c_int) -> c_int {
    (c >= b'A' as c_int && c <= b'Z' as c_int) as c_int
}

/// Returns non-zero iff `c` is alphabetic (upper or lower).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isalpha(c: c_int) -> c_int {
    // SAFETY: forwarding to the case checks; pure value computation.
    unsafe { (islower(c) != 0 || isupper(c) != 0) as c_int }
}

/// Returns non-zero iff `c` is alphanumeric.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isalnum(c: c_int) -> c_int {
    // SAFETY: forwarding to other classifiers.
    unsafe { (isalpha(c) != 0 || isdigit(c) != 0) as c_int }
}

/// Returns non-zero iff `c` is a hex digit.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isxdigit(c: c_int) -> c_int {
    let d = c as u32;
    let lo = d.wrapping_sub(b'a' as u32);
    let hi = d.wrapping_sub(b'A' as u32);
    let dec = d.wrapping_sub(b'0' as u32);
    (dec < 10 || lo < 6 || hi < 6) as c_int
}

/// Returns non-zero iff `c` is a blank character (POSIX 2001:
/// space or horizontal tab). A strict subset of [`isspace`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isblank(c: c_int) -> c_int {
    (c == b' ' as c_int || c == b'\t' as c_int) as c_int
}

/// Returns non-zero iff `c` is whitespace per C99 (space, \t, \n,
/// \v, \f, \r). Locale-independent.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isspace(c: c_int) -> c_int {
    matches!(c as u8, b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r') as c_int
}

/// Returns non-zero iff `c` is a printable non-space char (0x21..=0x7E).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isgraph(c: c_int) -> c_int {
    (c > 0x20 && c < 0x7F) as c_int
}

/// Returns non-zero iff `c` is printable including space (0x20..=0x7E).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isprint(c: c_int) -> c_int {
    (c >= 0x20 && c < 0x7F) as c_int
}

/// Returns non-zero iff `c` is a control character.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iscntrl(c: c_int) -> c_int {
    ((c >= 0 && c < 0x20) || c == 0x7F) as c_int
}

/// Returns non-zero iff `c` is punctuation per C99 (printable but
/// not alphanumeric and not space).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ispunct(c: c_int) -> c_int {
    // SAFETY: forwarding to other classifiers.
    unsafe {
        let g = isgraph(c) != 0;
        let an = isalnum(c) != 0;
        (g && !an) as c_int
    }
}

/// `tolower(c)` — fold uppercase to lower; pass-through otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tolower(c: c_int) -> c_int {
    // SAFETY: pure arithmetic on the c_int value.
    if unsafe { isupper(c) != 0 } {
        c + (b'a' as c_int - b'A' as c_int)
    } else {
        c
    }
}

/// `toupper(c)` — fold lowercase to upper; pass-through otherwise.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn toupper(c: c_int) -> c_int {
    // SAFETY: pure arithmetic.
    if unsafe { islower(c) != 0 } {
        c - (b'a' as c_int - b'A' as c_int)
    } else {
        c
    }
}

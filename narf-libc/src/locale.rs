//! `<locale.h>` + `<langinfo.h>` + `<iconv.h>` + minimal wide-char
//! surface.
//!
//! NARF has no locale model and no character-set conversion engine
//! today. Real C programs nevertheless reach for `setlocale("",
//! "")` very early in `main()`; refusing to link is worse than
//! silently returning the canonical C locale string. So we ship
//! the entry points with no-op behaviour, and document the ABI gap
//! at the call sites.

#![allow(non_camel_case_types)]

use crate::posix::{c_char, c_int};

// ── locale ───────────────────────────────────────────────────────────

pub const LC_ALL: c_int = 6;
pub const LC_COLLATE: c_int = 3;
pub const LC_CTYPE: c_int = 0;
pub const LC_MESSAGES: c_int = 5;
pub const LC_MONETARY: c_int = 4;
pub const LC_NUMERIC: c_int = 1;
pub const LC_TIME: c_int = 2;

static C_LOCALE: [u8; 2] = [b'C', 0];

/// `setlocale(category, locale)` — returns the active locale name
/// for the given category. NARF supports only the `"C"` locale; we
/// accept any `locale` argument and return the constant `"C"`
/// pointer. Callers that compare the returned string against `"C"`
/// or `""` therefore see the expected match.
///
/// # Safety
/// `locale`, when non-null, must be a valid NUL-terminated C string
/// — we don't read past the first byte but the contract still applies.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setlocale(_category: c_int, _locale: *const c_char) -> *mut c_char {
    C_LOCALE.as_ptr() as *mut c_char
}

// ── nl_langinfo (subset) ────────────────────────────────────────────
//
// Each `nl_item` selects a piece of locale data (decimal point,
// weekday name, currency symbol, etc.). We surface the load-bearing
// items used by library code without any locale machinery: every
// call returns a `'static` ASCII string that matches the C locale.

pub type nl_item = c_int;

pub const D_T_FMT: nl_item = 1;
pub const D_FMT: nl_item = 2;
pub const T_FMT: nl_item = 3;
pub const T_FMT_AMPM: nl_item = 4;
pub const AM_STR: nl_item = 5;
pub const PM_STR: nl_item = 6;
pub const RADIXCHAR: nl_item = 0x10000;
pub const THOUSEP: nl_item = 0x10001;
pub const CRNCYSTR: nl_item = 0x20000;
pub const CODESET: nl_item = 0x30000;

/// `nl_langinfo(item)` — return a pointer to the C-locale string
/// for `item`. Unknown items return a static empty string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nl_langinfo(item: nl_item) -> *mut c_char {
    static D_T: [u8; 21] = *b"%a %b %e %H:%M:%S %Y\0";
    static D: [u8; 9] = *b"%m/%d/%y\0";
    static T: [u8; 9] = *b"%H:%M:%S\0";
    static TAMP: [u8; 12] = *b"%I:%M:%S %p\0";
    static AM: [u8; 3] = *b"AM\0";
    static PM: [u8; 3] = *b"PM\0";
    static DOT: [u8; 2] = [b'.', 0];
    static EMPTY: [u8; 1] = [0];
    static UTF8: [u8; 6] = *b"UTF-8\0";

    let p: *const u8 = match item {
        D_T_FMT => D_T.as_ptr(),
        D_FMT => D.as_ptr(),
        T_FMT => T.as_ptr(),
        T_FMT_AMPM => TAMP.as_ptr(),
        AM_STR => AM.as_ptr(),
        PM_STR => PM.as_ptr(),
        RADIXCHAR => DOT.as_ptr(),
        THOUSEP => EMPTY.as_ptr(),
        CRNCYSTR => EMPTY.as_ptr(),
        CODESET => UTF8.as_ptr(),
        _ => EMPTY.as_ptr(),
    };
    p as *mut c_char
}

// ── iconv stubs ─────────────────────────────────────────────────────
//
// Real iconv requires a character-set conversion table machine. We
// haven't shipped one, so all calls fail with `errno = EILSEQ`-
// equivalent. The entry points exist so a link succeeds.

pub const EILSEQ: c_int = 84;

pub type iconv_t = *mut core::ffi::c_void;

/// `iconv_open(tocode, fromcode)` — always returns `-1` cast to
/// `iconv_t`, signalling "unsupported conversion" per POSIX.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iconv_open(_tocode: *const c_char, _fromcode: *const c_char) -> iconv_t {
    crate::errno::set_errno(EILSEQ);
    !0usize as iconv_t
}

/// `iconv(cd, *inbuf, *inbytesleft, *outbuf, *outbytesleft)` —
/// stub that immediately reports illegal sequence.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iconv(
    _cd: iconv_t,
    _inbuf: *mut *mut c_char,
    _inbytesleft: *mut usize,
    _outbuf: *mut *mut c_char,
    _outbytesleft: *mut usize,
) -> usize {
    crate::errno::set_errno(EILSEQ);
    !0usize
}

/// `iconv_close(cd)` — paired with `iconv_open`. Stub always
/// succeeds (the descriptor was synthetic anyway).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn iconv_close(_cd: iconv_t) -> c_int {
    0
}

// ── wide-char minimal surface ───────────────────────────────────────
//
// We don't carry a `<wchar.h>` implementation — these are link-only
// stubs that treat input as ASCII. wcslen / wcscmp walk u32-sized
// elements; mbtowc / wctomb pass through bytes 0..127 unchanged.

pub type wchar_t = u32;

/// `wcslen(s)` — count u32 elements until a zero terminator.
///
/// # Safety
/// `s` must point to a sequence of `wchar_t` ending with 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcslen(s: *const wchar_t) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut n = 0usize;
    // SAFETY: caller-asserted zero terminator.
    unsafe {
        while *s.add(n) != 0 {
            n += 1;
        }
    }
    n
}

/// `wcscmp(a, b)` — element-wise compare of two wide strings.
///
/// # Safety
/// Both arguments must be valid zero-terminated wide-char strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wcscmp(a: *const wchar_t, b: *const wchar_t) -> c_int {
    if a.is_null() || b.is_null() {
        return 0;
    }
    // SAFETY: caller-asserted.
    unsafe {
        let mut i = 0usize;
        loop {
            let ax = *a.add(i);
            let bx = *b.add(i);
            if ax != bx {
                return if ax < bx { -1 } else { 1 };
            }
            if ax == 0 {
                return 0;
            }
            i += 1;
        }
    }
}

/// `mbtowc(pwc, s, n)` — convert one multi-byte sequence at `s`
/// into a wide character. Stage-4 simplification: treat the byte as
/// ASCII (only 0..127 round-trip; bytes >= 128 surface as -1 with
/// `errno = EILSEQ`). Returns 0 for a NUL terminator, 1 on a valid
/// ASCII byte, -1 on invalid input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mbtowc(pwc: *mut wchar_t, s: *const c_char, n: usize) -> c_int {
    if s.is_null() {
        return 0;
    }
    if n == 0 {
        return -1;
    }
    // SAFETY: caller-asserted readable byte.
    let b = unsafe { *s } as u8;
    if b > 0x7F {
        crate::errno::set_errno(EILSEQ);
        return -1;
    }
    if !pwc.is_null() {
        // SAFETY: caller-supplied writable wchar_t slot.
        unsafe {
            *pwc = b as wchar_t;
        }
    }
    if b == 0 {
        0
    } else {
        1
    }
}

/// `wctomb(s, wc)` — render `wc` as a single byte (only 0..127
/// round-trip per the ASCII-only simplification).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wctomb(s: *mut c_char, wc: wchar_t) -> c_int {
    if s.is_null() {
        return 0;
    }
    if wc > 0x7F {
        crate::errno::set_errno(EILSEQ);
        return -1;
    }
    // SAFETY: caller-supplied writable byte.
    unsafe {
        *s = wc as c_char;
    }
    1
}

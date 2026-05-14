//! `<regex.h>` POSIX regex skeleton.
//!
//! NARF doesn't ship a regex engine in narf-libc — full POSIX BRE/
//! ERE support would more than double this crate's audit surface.
//! Real consumers that reach for `regcomp` early (sed/grep, perl
//! variants, some build tools) need the call to *link*, but their
//! code paths almost always hit `regexec` and check the return
//! value. We oblige with a stub that returns `REG_NOMATCH` for
//! every match attempt — the consumer either falls back to plain
//! string ops or surfaces the failure.
//!
//! When a real engine lands, swap the bodies; the API shape is
//! POSIX-correct.

#![allow(non_camel_case_types)]

use crate::posix::{c_char, c_int};

// Compile / exec flags (numeric values per the SUSv4 `<regex.h>` ABI).
pub const REG_EXTENDED: c_int = 0o00001;
pub const REG_ICASE:    c_int = 0o00002;
pub const REG_NOSUB:    c_int = 0o00004;
pub const REG_NEWLINE:  c_int = 0o00010;
pub const REG_NOTBOL:   c_int = 0o00001;
pub const REG_NOTEOL:   c_int = 0o00002;

// Error codes.
pub const REG_NOERROR:    c_int = 0;
pub const REG_NOMATCH:    c_int = 1;
pub const REG_BADPAT:     c_int = 2;
pub const REG_ECOLLATE:   c_int = 3;
pub const REG_ECTYPE:     c_int = 4;
pub const REG_EESCAPE:    c_int = 5;
pub const REG_ESUBREG:    c_int = 6;
pub const REG_EBRACK:     c_int = 7;
pub const REG_EPAREN:     c_int = 8;
pub const REG_EBRACE:     c_int = 9;
pub const REG_BADBR:      c_int = 10;
pub const REG_ERANGE:     c_int = 11;
pub const REG_ESPACE:     c_int = 12;
pub const REG_BADRPT:     c_int = 13;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct regex_t {
    /// Internal buffer pointer. We never allocate; the field is
    /// retained for ABI compatibility with code that copies the
    /// struct around.
    pub buffer:    usize,
    pub allocated: usize,
    pub used:      usize,
    pub syntax:    u64,
    pub fastmap:   usize,
    pub translate: usize,
    pub re_nsub:   usize,
    pub flags:     u32,
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct regmatch_t {
    pub rm_so: i64,
    pub rm_eo: i64,
}

/// `regcomp(*compiled, pattern, cflags)` — record the flags into
/// the supplied buffer and return success. The pattern itself is
/// not parsed; we lean on `regexec` to surface mismatch.
///
/// # Safety
/// `preg` must be a writable `*mut regex_t`; `pattern` must be a
/// valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn regcomp(
    preg:    *mut regex_t,
    _pattern:*const c_char,
    cflags:  c_int,
) -> c_int {
    if preg.is_null() { return REG_BADPAT; }
    // SAFETY: caller-supplied writable buffer.
    unsafe {
        *preg = regex_t::default();
        (*preg).flags = cflags as u32;
    }
    REG_NOERROR
}

/// `regexec(*compiled, string, nmatch, *pmatch, eflags)` — always
/// returns `REG_NOMATCH`. When `nmatch > 0` we zero the first
/// match slot (POSIX requires the caller's match array to be in a
/// known state on no-match; conventional impls clear `rm_so / rm_eo` to -1).
///
/// # Safety
/// `pmatch`, when non-null and `nmatch > 0`, must be writable for
/// `nmatch` entries.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn regexec(
    _preg:    *const regex_t,
    _string:  *const c_char,
    nmatch:   usize,
    pmatch:   *mut regmatch_t,
    _eflags:  c_int,
) -> c_int {
    if !pmatch.is_null() && nmatch > 0 {
        // SAFETY: caller-asserted writable region.
        unsafe {
            for i in 0..nmatch {
                *pmatch.add(i) = regmatch_t { rm_so: -1, rm_eo: -1 };
            }
        }
    }
    REG_NOMATCH
}

/// `regerror(errcode, *preg, errbuf, size)` — render a human
/// description of `errcode` into `errbuf`. Returns the byte count
/// (excluding NUL) needed to hold the full message.
///
/// # Safety
/// `errbuf` must be writable for `size` bytes if non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn regerror(
    errcode: c_int,
    _preg:   *const regex_t,
    errbuf:  *mut c_char,
    size:    usize,
) -> usize {
    let msg: &[u8] = match errcode {
        REG_NOERROR  => b"Success",
        REG_NOMATCH  => b"No match",
        REG_BADPAT   => b"Invalid regular expression",
        REG_ESPACE   => b"Out of memory",
        _            => b"Regex error",
    };
    if !errbuf.is_null() && size > 0 {
        // SAFETY: caller-asserted writable region.
        unsafe {
            let dst = core::slice::from_raw_parts_mut(errbuf as *mut u8, size);
            let copy = msg.len().min(size - 1);
            dst[..copy].copy_from_slice(&msg[..copy]);
            dst[copy] = 0;
        }
    }
    msg.len()
}

/// `regfree(*preg)` — no-op (we never allocated).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn regfree(_preg: *mut regex_t) {}

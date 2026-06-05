//! `<unistd.h>` — `getopt` argv parser.
//!
//! POSIX `getopt(argc, argv, optstring)` walks argv looking for
//! single-letter options. Each call returns one option char (or
//! its value when `optstring` lists it followed by `:` for an
//! arg-bearing option), or -1 when arguments are exhausted.
//!
//! Globals (POSIX-mandated names):
//! - `optarg`: pointer into argv for the most recent arg-bearing
//!   option; null otherwise.
//! - `optind`: index in argv of the next element to be processed;
//!   starts at 1, advances as options are consumed.
//! - `opterr`: when non-zero, getopt prints a diagnostic to stderr
//!   on bad input. Default 1.
//! - `optopt`: holds the offending option char on '?' / ':' return.
//!
//! Stage-4 simplifications:
//! - No `+` / `-` mode prefixes (POSIX leading-flag tweaks).
//! - No GNU-style argument permutation: arguments are processed in
//!   place; the first non-option terminates the scan.
//! - Single-character options only — `getopt_long` is a follow-up.

#![allow(non_camel_case_types)]

use crate::posix::{c_char, c_int};

/// Pointer into argv for the most recent arg-bearing option.
#[unsafe(no_mangle)]
pub static mut optarg: *mut c_char = core::ptr::null_mut();

/// Index of the next argv element. POSIX-mandated initial value: 1.
#[unsafe(no_mangle)]
pub static mut optind: c_int = 1;

/// Whether to emit diagnostics on bad input.
#[unsafe(no_mangle)]
pub static mut opterr: c_int = 1;

/// Holds the offending option char on `?` / `:` return.
#[unsafe(no_mangle)]
pub static mut optopt: c_int = 0;

/// Internal cursor within the current argv element. When non-zero,
/// the previous getopt call returned an option from a clustered
/// block (`-abc`) and we still have more chars to consume.
static mut NEXTCHAR: usize = 0;

/// `getopt(argc, argv, optstring)`. See module doc.
///
/// # Safety
/// `argv` must point at `argc` valid pointers, each either null or
/// a NUL-terminated C string. `optstring` must be a NUL-terminated
/// C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getopt(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
) -> c_int {
    if argv.is_null() || optstring.is_null() {
        return -1;
    }
    // SAFETY: all three statics are touched single-threaded under
    // Stage-4 user mode.
    unsafe {
        // If we're mid-cluster, advance within the current element.
        if NEXTCHAR == 0 {
            if optind >= argc {
                return -1;
            }
            let cur = *argv.offset(optind as isize);
            if cur.is_null() {
                return -1;
            }
            // Must start with `-` to be an option.
            if *cur != b'-' as c_char {
                return -1;
            }
            // `--` ends the scan (POSIX); skip past it.
            if *cur.add(1) == b'-' as c_char && *cur.add(2) == 0 {
                optind += 1;
                return -1;
            }
            // Bare `-` is a non-option (POSIX: stdin marker).
            if *cur.add(1) == 0 {
                return -1;
            }
            NEXTCHAR = 1;
        }
        let cur = *argv.offset(optind as isize);
        let opt_byte = *cur.add(NEXTCHAR);
        if opt_byte == 0 {
            // End of cluster — advance to next argv slot.
            optind += 1;
            NEXTCHAR = 0;
            return getopt(argc, argv, optstring);
        }
        let opt = opt_byte as c_int;
        NEXTCHAR += 1;

        // Find the option in optstring.
        let needle = optstring_find(optstring, opt_byte);
        if needle.is_none() {
            optopt = opt;
            if opterr != 0 {
                emit_diag(argv, "illegal option", opt_byte as u8);
            }
            return b'?' as c_int;
        }
        let (idx, takes_arg) = needle.unwrap();
        let _ = idx;
        if takes_arg {
            // Argument either follows in the same element or is the
            // next argv element.
            let rest_in_cluster = *cur.add(NEXTCHAR) != 0;
            if rest_in_cluster {
                optarg = cur.add(NEXTCHAR) as *mut c_char;
                optind += 1;
                NEXTCHAR = 0;
            } else {
                optind += 1;
                NEXTCHAR = 0;
                if optind >= argc {
                    optopt = opt;
                    if opterr != 0 {
                        emit_diag(argv, "option requires an argument", opt_byte as u8);
                    }
                    // POSIX: return ':' when optstring leads with ':',
                    // else '?'. Stage-4 returns '?' uniformly.
                    return b'?' as c_int;
                }
                optarg = *argv.offset(optind as isize);
                optind += 1;
            }
        } else {
            optarg = core::ptr::null_mut();
        }
        opt
    }
}

/// Find `byte` in the NUL-terminated `optstring`. Returns `(index,
/// takes_arg)` where `takes_arg` is true iff the next character in
/// `optstring` after the match is `:`.
unsafe fn optstring_find(optstring: *const c_char, byte: c_char) -> Option<(usize, bool)> {
    let mut i = 0usize;
    // SAFETY: caller contract on optstring.
    unsafe {
        while *optstring.add(i) != 0 {
            if *optstring.add(i) == byte {
                let takes_arg = *optstring.add(i + 1) == b':' as c_char;
                return Some((i, takes_arg));
            }
            i += 1;
        }
    }
    None
}

// ── getopt_long (GNU long options) ──────────────────────────────────
//
// `option` table entries (mirrors `<getopt.h>`):
//   name     — long-option name (NUL-terminated; `NULL` sentinel
//              ends the table).
//   has_arg  — 0 = no_argument, 1 = required_argument,
//              2 = optional_argument.
//   flag     — when non-null, getopt_long sets `*flag = val` and
//              returns 0 instead of `val`.
//   val      — the short-option char (if also wanted in optstring)
//              or any caller-defined return value.
//
// Stage-4 simplifications:
//   - Optional arguments (`has_arg = 2`) are honoured only in the
//     `--name=value` form; `--name` followed by a separate token is
//     treated as no-arg (per the C99 rule that ambiguity favours the
//     shorter form).
//   - No abbreviated long matches (caller must spell it in full).
//   - `longindex` is honoured.

pub const NO_ARGUMENT: c_int = 0;
pub const REQUIRED_ARGUMENT: c_int = 1;
pub const OPTIONAL_ARGUMENT: c_int = 2;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct option {
    pub name: *const c_char,
    pub has_arg: c_int,
    pub flag: *mut c_int,
    pub val: c_int,
}

unsafe fn cstr_eq(a: *const c_char, b: &[u8]) -> bool {
    // Compare NUL-terminated `a` against bytes `b` exactly (no
    // partial matches; b's length must equal a's strlen).
    // SAFETY: caller-asserted NUL-terminator on `a`.
    unsafe {
        for (i, &bx) in b.iter().enumerate() {
            let ax = *a.add(i) as u8;
            if ax != bx {
                return false;
            }
        }
        *a.add(b.len()) == 0
    }
}

/// `getopt_long(argc, argv, optstring, longopts, longindex)` —
/// GNU long-option parser. See module doc for the simplifications.
///
/// # Safety
/// `argv` and `optstring` per [`getopt`]; `longopts` must be a
/// pointer to a `[option; N+1]` table whose final entry has
/// `name = NULL`. `longindex`, when non-null, is written with the
/// matched-table index.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getopt_long(
    argc: c_int,
    argv: *const *mut c_char,
    optstring: *const c_char,
    longopts: *const option,
    longindex: *mut c_int,
) -> c_int {
    if argv.is_null() || longopts.is_null() {
        // SAFETY: forwarded.
        return unsafe { getopt(argc, argv, optstring) };
    }
    // SAFETY: single-threaded user mode for the statics.
    unsafe {
        // Mid-cluster short option? Defer to plain getopt.
        if NEXTCHAR != 0 {
            return getopt(argc, argv, optstring);
        }
        if optind >= argc {
            return -1;
        }
        let cur = *argv.offset(optind as isize);
        if cur.is_null() || *cur != b'-' as c_char {
            return -1;
        }
        if *cur.add(1) != b'-' as c_char {
            // Single-`-` short option(s). Plain getopt handles it.
            return getopt(argc, argv, optstring);
        }
        if *cur.add(2) == 0 {
            // Bare `--` terminates option scan.
            optind += 1;
            return -1;
        }
        // Long option. Format: `--name` or `--name=value`.
        let name_start = cur.add(2);
        // Find `=` (if any) within the name.
        let mut nlen = 0usize;
        while *name_start.add(nlen) != 0 && *name_start.add(nlen) != b'=' as c_char {
            nlen += 1;
        }
        let has_eq = *name_start.add(nlen) == b'=' as c_char;
        let name_bytes = core::slice::from_raw_parts(name_start as *const u8, nlen);
        // Walk the longopts table.
        let mut idx = 0i32;
        loop {
            let entry = &*longopts.offset(idx as isize);
            if entry.name.is_null() {
                break;
            }
            if cstr_eq(entry.name, name_bytes) {
                // Match. Record longindex.
                if !longindex.is_null() {
                    *longindex = idx;
                }
                // Argument handling.
                let mut got_arg: *mut c_char = core::ptr::null_mut();
                if has_eq {
                    got_arg = name_start.add(nlen + 1) as *mut c_char;
                }
                let needs_arg = entry.has_arg == REQUIRED_ARGUMENT
                    || (entry.has_arg == OPTIONAL_ARGUMENT && has_eq);
                if entry.has_arg == REQUIRED_ARGUMENT && got_arg.is_null() {
                    // Argument must be in next argv element.
                    optind += 1;
                    if optind >= argc {
                        optopt = entry.val;
                        if opterr != 0 {
                            emit_diag(argv, "option requires an argument", b'-');
                        }
                        return b'?' as c_int;
                    }
                    got_arg = *argv.offset(optind as isize);
                }
                optarg = if needs_arg {
                    got_arg
                } else {
                    core::ptr::null_mut()
                };
                optind += 1;
                // flag handling: if entry.flag is non-null, set
                // *flag = val and return 0; else return val directly.
                if !entry.flag.is_null() {
                    *entry.flag = entry.val;
                    return 0;
                }
                return entry.val;
            }
            idx += 1;
        }
        // No match — emit diag, advance, return '?'.
        optind += 1;
        if opterr != 0 {
            emit_diag(argv, "unrecognized option", b'-');
        }
        b'?' as c_int
    }
}

/// Print a getopt diagnostic to stderr in the `program: msg -- X`
/// shape SUSv4 specifies.
unsafe fn emit_diag(argv: *const *mut c_char, msg: &str, opt: u8) {
    // SAFETY: caller contract — argv[0] (when non-null) is a C
    // string with the program name.
    unsafe {
        let prog_ptr = *argv;
        let prog = if prog_ptr.is_null() {
            "narf-libc"
        } else {
            // Walk to NUL.
            let mut n = 0usize;
            while *prog_ptr.add(n) != 0 {
                n += 1;
            }
            core::str::from_utf8(core::slice::from_raw_parts(prog_ptr as *const u8, n))
                .unwrap_or("narf-libc")
        };
        crate::fprintf_str(
            2,
            "%s: %s -- %c\n",
            &[
                crate::Arg::Str(prog),
                crate::Arg::Str(msg),
                crate::Arg::Char(opt),
            ],
        );
    }
}

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

/// Print a getopt diagnostic to stderr in the `program: msg -- X`
/// shape glibc uses.
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
            core::str::from_utf8(core::slice::from_raw_parts(
                prog_ptr as *const u8,
                n,
            ))
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

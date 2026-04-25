//! Minimum libc string/memory primitives. Plain `unsafe extern "C"`
//! so a C consumer (or LLVM-emitted memcpy intrinsic call) can link
//! against them.
//!
//! Stage-4 ships only the four routines `printf_str` actually
//! needs internally (`memcpy`, `memset`, `strlen`) plus two
//! comparison helpers a future POSIX-shaped consumer expects
//! (`strcmp`, `strncmp`). No optimisation tricks — straight byte
//! loops; the validate binary doesn't move enough bytes for SSE
//! variants to matter.

/// Copy `n` bytes from `src` to `dst`. Returns `dst`.
///
/// # Safety
/// `dst` and `src` must each point to at least `n` valid bytes,
/// the regions must not overlap (POSIX: behaviour undefined on
/// overlap; use `memmove` for that case — not yet implemented).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: per the function-level contract.
    unsafe {
        for i in 0..n {
            *dst.add(i) = *src.add(i);
        }
    }
    dst
}

/// Fill `n` bytes at `dst` with `byte`. Returns `dst`.
///
/// # Safety
/// `dst` must point to at least `n` valid bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut u8, byte: i32, n: usize) -> *mut u8 {
    let v = byte as u8;
    // SAFETY: per the function-level contract.
    unsafe {
        for i in 0..n {
            *dst.add(i) = v;
        }
    }
    dst
}

/// Length of the NUL-terminated C string at `s`.
///
/// # Safety
/// `s` must point to a NUL-terminated string within a single valid
/// allocation; the scan stops at the first 0 byte.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    let mut n = 0usize;
    // SAFETY: per the function-level contract — read until a NUL
    // terminator is found, then return the count.
    unsafe {
        while *s.add(n) != 0 {
            n += 1;
        }
    }
    n
}

/// Lexicographic compare of two NUL-terminated strings.
/// Negative / 0 / positive per POSIX.
///
/// # Safety
/// Both `a` and `b` must be NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcmp(a: *const u8, b: *const u8) -> i32 {
    let mut i = 0usize;
    // SAFETY: per the function-level contract — read both strings
    // in lockstep until a divergence or a NUL on either side.
    unsafe {
        loop {
            let ca = *a.add(i);
            let cb = *b.add(i);
            if ca != cb {
                return ca as i32 - cb as i32;
            }
            if ca == 0 {
                return 0;
            }
            i += 1;
        }
    }
}

/// Lexicographic compare of up to `n` bytes.
///
/// # Safety
/// `a` and `b` must each point to at least `n` valid bytes (or be
/// NUL-terminated within `n`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    // SAFETY: per the function-level contract.
    unsafe {
        for i in 0..n {
            let ca = *a.add(i);
            let cb = *b.add(i);
            if ca != cb {
                return ca as i32 - cb as i32;
            }
            if ca == 0 {
                return 0;
            }
        }
    }
    0
}

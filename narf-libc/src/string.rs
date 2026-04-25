//! Minimum libc string/memory primitives. Plain `unsafe extern "C"`
//! so a C consumer (or LLVM-emitted memcpy intrinsic call) can link
//! against them.
//!
//! Stage-4 round 2 surface: the original `memcpy/memset/strlen` plus
//! `strcmp/strncmp` are now joined by `memmove`, `memcmp`, the
//! `strcpy/strncpy/strcat/strchr/strrchr/strstr/strdup` battery —
//! enough that real Rust no_std programs reaching for these don't
//! fail to link. Algorithms are intentionally naive (e.g. `strstr`
//! is O(n*m)) — the validate binary doesn't move enough bytes for
//! KMP or SSE variants to matter, and we'd rather keep the audit
//! surface small.

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

/// Copy `n` bytes from `src` to `dst`, handling overlap. Returns
/// `dst`. Direction-aware: when `dst > src` and the regions overlap
/// we walk backwards so the still-unread tail isn't clobbered before
/// it's read.
///
/// # Safety
/// `dst` and `src` must each point to at least `n` valid bytes
/// inside the same (or compatible) allocation. Overlap is permitted;
/// disjoint regions also work (and are slightly faster, but we don't
/// optimise for that — the branch on `dst > src` already chooses the
/// safe direction).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if n == 0 {
        return dst;
    }
    // SAFETY: per the function-level contract.
    unsafe {
        // Direction matters only when dst > src AND the ranges
        // overlap; the conservative rule "if dst > src, walk
        // backwards" is correct for both overlap and disjoint cases.
        if (dst as usize) > (src as usize) {
            let mut i = n;
            while i > 0 {
                i -= 1;
                *dst.add(i) = *src.add(i);
            }
        } else {
            for i in 0..n {
                *dst.add(i) = *src.add(i);
            }
        }
    }
    dst
}

/// Compare `n` bytes byte-wise. Returns negative / 0 / positive per
/// POSIX (mismatched byte difference, or 0 if all `n` bytes match).
///
/// # Safety
/// `a` and `b` must each point to at least `n` valid bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    // SAFETY: per the function-level contract.
    unsafe {
        for i in 0..n {
            let ca = *a.add(i);
            let cb = *b.add(i);
            if ca != cb {
                return ca as i32 - cb as i32;
            }
        }
    }
    0
}

/// Copy NUL-terminated string `src` to `dst`, including the
/// terminating NUL. Returns `dst`.
///
/// # Safety
/// Buffer-overflow risk: `dst` must be large enough for the entire
/// `src` plus its NUL. POSIX inherits this footgun; new code should
/// prefer `strncpy` (or, better, a length-aware Rust API).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcpy(dst: *mut u8, src: *const u8) -> *mut u8 {
    // SAFETY: per the function-level contract.
    unsafe {
        let mut i = 0usize;
        loop {
            let c = *src.add(i);
            *dst.add(i) = c;
            if c == 0 {
                break;
            }
            i += 1;
        }
    }
    dst
}

/// Copy at most `n` bytes from `src` to `dst`. Per POSIX:
/// - If `src`'s NUL is found before `n`, the remainder is NUL-
///   padded out to `n`.
/// - If `src` is at least `n` bytes long, `dst` is NOT NUL-
///   terminated. Callers must handle this themselves.
/// Returns `dst`.
///
/// # Safety
/// `dst` must point to at least `n` valid writable bytes; `src`
/// must be either NUL-terminated or have at least `n` valid bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: per the function-level contract.
    unsafe {
        let mut i = 0usize;
        // Phase 1: copy until NUL or `n` reached.
        while i < n {
            let c = *src.add(i);
            *dst.add(i) = c;
            if c == 0 {
                i += 1;
                break;
            }
            i += 1;
        }
        // Phase 2: NUL-pad the remainder. POSIX requires this even
        // though it's the most surprising part of the contract —
        // hence the comment.
        while i < n {
            *dst.add(i) = 0;
            i += 1;
        }
    }
    dst
}

/// Append NUL-terminated `src` onto NUL-terminated `dst` (at the
/// existing NUL). Returns `dst`.
///
/// # Safety
/// Buffer-overflow risk identical to `strcpy`. `dst` must have room
/// for `strlen(dst) + strlen(src) + 1` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcat(dst: *mut u8, src: *const u8) -> *mut u8 {
    // SAFETY: per the function-level contract.
    unsafe {
        // Walk to dst's NUL, then strcpy from there.
        let mut d = 0usize;
        while *dst.add(d) != 0 {
            d += 1;
        }
        let mut s = 0usize;
        loop {
            let c = *src.add(s);
            *dst.add(d + s) = c;
            if c == 0 {
                break;
            }
            s += 1;
        }
    }
    dst
}

/// Find first occurrence of byte `c` (taken modulo 256) in NUL-
/// terminated `s`. Per POSIX, the terminating NUL counts as part of
/// the string — `strchr(s, 0)` returns the NUL's address.
///
/// # Safety
/// `s` must be NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strchr(s: *const u8, c: i32) -> *mut u8 {
    let target = c as u8;
    // SAFETY: per the function-level contract.
    unsafe {
        let mut i = 0usize;
        loop {
            let v = *s.add(i);
            if v == target {
                return s.add(i) as *mut u8;
            }
            if v == 0 {
                return core::ptr::null_mut();
            }
            i += 1;
        }
    }
}

/// Find LAST occurrence of byte `c` in NUL-terminated `s`. Same
/// semantics as `strchr` regarding the NUL.
///
/// # Safety
/// `s` must be NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strrchr(s: *const u8, c: i32) -> *mut u8 {
    let target = c as u8;
    // SAFETY: per the function-level contract.
    unsafe {
        let mut found: *mut u8 = core::ptr::null_mut();
        let mut i = 0usize;
        loop {
            let v = *s.add(i);
            if v == target {
                found = s.add(i) as *mut u8;
            }
            if v == 0 {
                return found;
            }
            i += 1;
        }
    }
}

/// Find first occurrence of `needle` in `haystack`. Both must be
/// NUL-terminated. Returns `haystack` if `needle` is empty (POSIX),
/// or NULL if not found.
///
/// Algorithm: naive O(n*m). KMP would be faster on adversarial
/// inputs, but the validate binary feeds tiny strings; we keep the
/// audit surface small.
///
/// # Safety
/// Both arguments must be NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strstr(haystack: *const u8, needle: *const u8) -> *mut u8 {
    // SAFETY: per the function-level contract.
    unsafe {
        // Empty needle → match at start (POSIX).
        if *needle == 0 {
            return haystack as *mut u8;
        }
        let mut h = 0usize;
        loop {
            // Try to match needle starting at haystack[h..].
            let mut i = 0usize;
            loop {
                let nc = *needle.add(i);
                if nc == 0 {
                    // Matched all of needle.
                    return haystack.add(h) as *mut u8;
                }
                let hc = *haystack.add(h + i);
                if hc == 0 {
                    // Hit haystack's NUL before completing needle.
                    return core::ptr::null_mut();
                }
                if hc != nc {
                    break;
                }
                i += 1;
            }
            // No match here; advance haystack by 1.
            if *haystack.add(h) == 0 {
                return core::ptr::null_mut();
            }
            h += 1;
        }
    }
}

/// Allocate a fresh copy of NUL-terminated `s` via `malloc`. The
/// caller owns the returned pointer (currently a no-op `free`; see
/// `heap.rs`). Returns NULL if allocation fails.
///
/// # Safety
/// `s` must be NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strdup(s: *const u8) -> *mut u8 {
    // SAFETY: per the function-level contract.
    let len = unsafe { strlen(s) };
    // SAFETY: malloc is `unsafe extern "C"` to match the C-ABI
    // shape exposed in heap.rs; passing a non-zero size is fine.
    let buf = unsafe { crate::heap::malloc(len + 1) };
    if buf.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: `buf` is `len + 1` writable bytes; copy len + NUL.
    unsafe {
        for i in 0..len {
            *buf.add(i) = *s.add(i);
        }
        *buf.add(len) = 0;
    }
    buf
}

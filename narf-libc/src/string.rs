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

/// Find first occurrence of byte `c` in the first `n` bytes of `s`.
/// Returns a pointer to the matching byte, or NULL if no match in
/// the bounded region. Unlike `strchr`, the scan is length-bounded
/// and does not stop at a NUL byte (NUL is just another value of
/// `c` here).
///
/// # Safety
/// `s` must point to at least `n` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memchr(s: *const u8, c: i32, n: usize) -> *mut u8 {
    let target = c as u8;
    // SAFETY: per the function-level contract.
    unsafe {
        for i in 0..n {
            if *s.add(i) == target {
                return s.add(i) as *mut u8;
            }
        }
    }
    core::ptr::null_mut()
}

/// `strnlen(s, max)` — strlen with a hard upper bound. Returns the
/// shorter of `strlen(s)` and `max`. Used by code that doesn't
/// fully trust the input string's NUL-termination.
///
/// # Safety
/// `s` must be readable for at least `min(strlen(s), max)` bytes —
/// in practice "either NUL-terminated within `max` bytes, or
/// readable for the full `max` bytes".
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strnlen(s: *const u8, max: usize) -> usize {
    if s.is_null() { return 0; }
    let mut n = 0usize;
    // SAFETY: per the function-level contract.
    unsafe {
        while n < max && *s.add(n) != 0 {
            n += 1;
        }
    }
    n
}

/// `strndup(s, max)` — `strdup` with a length cap. The returned
/// pointer is always NUL-terminated.
///
/// # Safety
/// `s` must satisfy [`strnlen`]'s contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strndup(s: *const u8, max: usize) -> *mut u8 {
    if s.is_null() { return core::ptr::null_mut(); }
    // SAFETY: caller contract.
    let len = unsafe { strnlen(s, max) };
    // SAFETY: malloc is `unsafe extern "C"`; size > 0.
    let buf = unsafe { crate::heap::malloc(len + 1) };
    if buf.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: buf has len + 1 writable bytes.
    unsafe {
        for i in 0..len {
            *buf.add(i) = *s.add(i);
        }
        *buf.add(len) = 0;
    }
    buf
}

/// `memmem(haystack, hlen, needle, nlen)` — find the first
/// occurrence of `needle` (length `nlen`) inside `haystack`
/// (length `hlen`). Returns a pointer inside `haystack` on
/// success, NULL otherwise. Length-bounded (no NUL stop).
///
/// Algorithm: naive O(h*n). Stage-4 callers feed tiny strings;
/// KMP / SSE variants are not worth the audit surface.
///
/// # Safety
/// `haystack` must be readable for `hlen` bytes; `needle` for
/// `nlen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmem(
    haystack: *const u8,
    hlen:     usize,
    needle:   *const u8,
    nlen:     usize,
) -> *mut u8 {
    if needle.is_null() || nlen == 0 {
        // POSIX-ish: a zero-length needle matches at start.
        return haystack as *mut u8;
    }
    if haystack.is_null() || hlen < nlen {
        return core::ptr::null_mut();
    }
    // SAFETY: caller-bounded buffers.
    unsafe {
        for i in 0..=hlen - nlen {
            let mut matched = true;
            for j in 0..nlen {
                if *haystack.add(i + j) != *needle.add(j) {
                    matched = false;
                    break;
                }
            }
            if matched {
                return haystack.add(i) as *mut u8;
            }
        }
    }
    core::ptr::null_mut()
}

/// Lowercase byte fold for ASCII a-z; passes other bytes through.
#[inline]
fn ascii_to_lower(b: u8) -> u8 {
    if (b'A'..=b'Z').contains(&b) { b + 32 } else { b }
}

/// `strcasecmp(a, b)` — case-insensitive compare for ASCII; non-
/// ASCII bytes compare verbatim (no locale-folding).
///
/// # Safety
/// Both arguments must be NUL-terminated C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcasecmp(a: *const u8, b: *const u8) -> i32 {
    // SAFETY: per the function-level contract.
    unsafe {
        let mut i = 0usize;
        loop {
            let av = ascii_to_lower(*a.add(i));
            let bv = ascii_to_lower(*b.add(i));
            if av != bv { return (av as i32) - (bv as i32); }
            if av == 0  { return 0; }
            i += 1;
        }
    }
}

/// `strncasecmp(a, b, n)` — bounded case-insensitive compare.
///
/// # Safety
/// `a` and `b` must each be readable for `min(strlen, n)` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncasecmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    // SAFETY: per the function-level contract.
    unsafe {
        for i in 0..n {
            let av = ascii_to_lower(*a.add(i));
            let bv = ascii_to_lower(*b.add(i));
            if av != bv { return (av as i32) - (bv as i32); }
            if av == 0  { return 0; }
        }
    }
    0
}

/// `strcoll(a, b)` — locale-aware compare. NARF only supports the
/// `"C"` locale, so this aliases [`strcmp`] verbatim.
///
/// # Safety
/// See [`strcmp`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcoll(a: *const u8, b: *const u8) -> i32 {
    // SAFETY: forwarded.
    unsafe { strcmp(a, b) }
}

/// `strxfrm(dest, src, n)` — locale transform. Under the `"C"`
/// locale this is a plain bounded copy of `src` into `dest`.
/// Returns the source length (excluding NUL) per POSIX.
///
/// # Safety
/// `src` must be NUL-terminated. `dest` must be writable for `n`
/// bytes (or NULL when `n == 0`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strxfrm(dest: *mut u8, src: *const u8, n: usize) -> usize {
    if src.is_null() { return 0; }
    // SAFETY: caller-asserted NUL-termination.
    let len = unsafe { strlen(src) };
    if !dest.is_null() && n > 0 {
        // SAFETY: caller-asserted writable region.
        unsafe {
            let copy = if len + 1 < n { len + 1 } else { n };
            for i in 0..copy {
                *dest.add(i) = *src.add(i);
            }
            // Always NUL-terminate within bounds.
            if copy > 0 {
                *dest.add(copy - 1) = if copy <= len { *src.add(copy - 1) } else { 0 };
                if copy <= n - 1 || *dest.add(copy - 1) != 0 {
                    let term = copy.min(n - 1);
                    *dest.add(term) = 0;
                }
            }
        }
    }
    len
}

// ── *_chk fortified shims ──────────────────────────────────────────
//
// glibc emits `__memcpy_chk`, `__strcpy_chk`, etc. when a binary is
// compiled with `-D_FORTIFY_SOURCE=2`. Each takes a "destination
// length" argument that the runtime checks against the requested
// copy size; on overrun, it aborts. We're not in a position to
// enforce the bound (we don't know the destination's true size
// outside the supplied parameter), so we simply forward to the
// unfortified primitive after a soft check that aborts on overflow.

/// `__memcpy_chk(dest, src, len, destlen)` — fortified memcpy.
/// # Safety
/// As [`memcpy`] plus `destlen >= len`. We `abort` on violation so
/// the unsafe block doesn't silently overflow.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __memcpy_chk(
    dest:    *mut u8,
    src:     *const u8,
    len:     usize,
    destlen: usize,
) -> *mut u8 {
    if len > destlen {
        // SAFETY: abort never returns.
        unsafe { crate::process::abort(); }
    }
    // SAFETY: caller-asserted via memcpy contract.
    unsafe { memcpy(dest, src, len) }
}

/// `__memmove_chk(dest, src, len, destlen)` — fortified memmove.
/// # Safety
/// As [`memmove`] plus `destlen >= len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __memmove_chk(
    dest:    *mut u8,
    src:     *const u8,
    len:     usize,
    destlen: usize,
) -> *mut u8 {
    if len > destlen {
        // SAFETY: abort never returns.
        unsafe { crate::process::abort(); }
    }
    // SAFETY: caller-asserted via memmove contract.
    unsafe { memmove(dest, src, len) }
}

/// `__memset_chk(dest, byte, len, destlen)` — fortified memset.
/// # Safety
/// As [`memset`] plus `destlen >= len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __memset_chk(
    dest:    *mut u8,
    byte:    i32,
    len:     usize,
    destlen: usize,
) -> *mut u8 {
    if len > destlen {
        // SAFETY: abort never returns.
        unsafe { crate::process::abort(); }
    }
    // SAFETY: caller-asserted via memset contract.
    unsafe { memset(dest, byte, len) }
}

/// `__strcpy_chk(dest, src, destlen)` — fortified strcpy.
/// # Safety
/// As [`strcpy`] plus `strlen(src) < destlen`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __strcpy_chk(
    dest:    *mut u8,
    src:     *const u8,
    destlen: usize,
) -> *mut u8 {
    // SAFETY: caller-asserted NUL-termination.
    let len = unsafe { strlen(src) };
    if len + 1 > destlen {
        // SAFETY: abort never returns.
        unsafe { crate::process::abort(); }
    }
    // SAFETY: forwarded.
    unsafe { strcpy(dest, src) }
}

/// Test whether byte `b` appears in NUL-terminated `set`. Helper
/// shared by `strspn`/`strcspn`/`strpbrk`. O(|set|) per probe.
///
/// # Safety
/// `set` must be NUL-terminated.
#[inline]
unsafe fn byte_in_set(b: u8, set: *const u8) -> bool {
    // SAFETY: caller contract — walk to NUL.
    unsafe {
        let mut i = 0usize;
        loop {
            let v = *set.add(i);
            if v == 0 { return false; }
            if v == b { return true; }
            i += 1;
        }
    }
}

/// `strspn(s, accept)` — length of the initial run of bytes in `s`
/// that are all members of `accept`. Both NUL-terminated.
///
/// # Safety
/// Both arguments must be NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strspn(s: *const u8, accept: *const u8) -> usize {
    let mut n = 0usize;
    // SAFETY: caller contract.
    unsafe {
        loop {
            let b = *s.add(n);
            if b == 0 || !byte_in_set(b, accept) {
                return n;
            }
            n += 1;
        }
    }
}

/// `strcspn(s, reject)` — length of the initial run of bytes in `s`
/// that are NOT members of `reject`. Both NUL-terminated.
///
/// # Safety
/// Both arguments must be NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strcspn(s: *const u8, reject: *const u8) -> usize {
    let mut n = 0usize;
    // SAFETY: caller contract.
    unsafe {
        loop {
            let b = *s.add(n);
            if b == 0 || byte_in_set(b, reject) {
                return n;
            }
            n += 1;
        }
    }
}

/// `strpbrk(s, accept)` — pointer to the first byte of `s` that
/// also appears in `accept`, or NULL if none. Both NUL-terminated.
///
/// # Safety
/// Both arguments must be NUL-terminated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strpbrk(s: *const u8, accept: *const u8) -> *mut u8 {
    // SAFETY: caller contract.
    unsafe {
        let mut i = 0usize;
        loop {
            let b = *s.add(i);
            if b == 0 { return core::ptr::null_mut(); }
            if byte_in_set(b, accept) {
                return s.add(i) as *mut u8;
            }
            i += 1;
        }
    }
}

/// `strtok_r(str, delim, saveptr)` — reentrant tokeniser. On the
/// first call, `str` is the string to scan; on subsequent calls,
/// pass NULL and the same `saveptr` to continue. The function
/// rewrites the byte after each token to NUL and stashes its
/// position in `*saveptr`. Returns NULL when no further tokens
/// remain.
///
/// We deliberately ship the `_r` variant only — the stateful
/// `strtok` would need a process-wide static save slot, which is
/// trivially racy and not worth the surface for the validate-grade
/// workload. Most modern callers use `_r` directly.
///
/// # Safety
/// On the first call `str` must be writable and NUL-terminated;
/// `delim` must be NUL-terminated; `saveptr` must be a writable
/// pointer-to-pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtok_r(
    s: *mut u8,
    delim: *const u8,
    saveptr: *mut *mut u8,
) -> *mut u8 {
    if saveptr.is_null() { return core::ptr::null_mut(); }
    // SAFETY: caller-supplied `saveptr` is a writable slot.
    let mut p = if s.is_null() {
        unsafe { *saveptr }
    } else {
        s
    };
    if p.is_null() { return core::ptr::null_mut(); }

    // Skip leading delimiters.
    // SAFETY: `p` points into the original NUL-terminated input;
    // bytes past it are read-only walked.
    unsafe {
        while *p != 0 && byte_in_set(*p, delim) {
            p = p.add(1);
        }
        if *p == 0 {
            *saveptr = p;
            return core::ptr::null_mut();
        }
    }

    let token = p;
    // Walk until the next delimiter / NUL.
    // SAFETY: same in-bounds reasoning.
    unsafe {
        while *p != 0 && !byte_in_set(*p, delim) {
            p = p.add(1);
        }
        if *p != 0 {
            // Punch a NUL to terminate the token, then advance.
            *p = 0;
            *saveptr = p.add(1);
        } else {
            *saveptr = p;
        }
    }
    token
}

/// Static saveptr backing the non-reentrant `strtok`. Single-threaded
/// user mode keeps this race-free; threading will need to migrate
/// callers to `strtok_r`.
static mut STRTOK_SAVEPTR: *mut u8 = core::ptr::null_mut();

/// `strtok(s, delim)` — POSIX non-reentrant tokeniser. Maintains a
/// static save-pointer between calls. Use [`strtok_r`] in any code
/// that may run from multiple threads.
///
/// Reference: musl `src/string/strtok.c`.
///
/// # Safety
/// On the first call `s` must be writable and NUL-terminated;
/// `delim` must be NUL-terminated. Subsequent calls pass NULL for
/// `s` to continue tokenising the saved string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strtok(s: *mut u8, delim: *const u8) -> *mut u8 {
    // SAFETY: forwarded; STRTOK_SAVEPTR access is race-free under
    // the single-threaded user-mode invariant.
    unsafe { strtok_r(s, delim, &raw mut STRTOK_SAVEPTR) }
}

/// `strncat(dst, src, n)` — append at most `n` bytes from NUL-
/// terminated `src` onto NUL-terminated `dst`, then NUL-terminate.
/// Returns `dst`.
///
/// Reference: musl `src/string/strncat.c`.
///
/// # Safety
/// `dst` must have room for `strlen(dst) + min(strlen(src), n) + 1`
/// bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strncat(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    // SAFETY: caller contract.
    unsafe {
        // Walk to dst's NUL.
        let mut d = 0usize;
        while *dst.add(d) != 0 { d += 1; }
        let mut i = 0usize;
        while i < n {
            let c = *src.add(i);
            if c == 0 { break; }
            *dst.add(d + i) = c;
            i += 1;
        }
        *dst.add(d + i) = 0;
    }
    dst
}

/// `strerror_r(errnum, buf, buflen)` — POSIX/XSI thread-safe form.
/// Returns 0 on success and writes the message into `buf`; returns
/// ERANGE (34) on a too-small buffer.
///
/// Reference: musl `src/string/strerror_r.c`.
///
/// # Safety
/// `buf` must be writable for `buflen` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn strerror_r(errnum: i32, buf: *mut u8, buflen: usize) -> i32 {
    if buf.is_null() || buflen == 0 { return 22; } // EINVAL
    // SAFETY: forwarded to crate::errno::strerror — returns a
    // pointer to a static NUL-terminated byte array.
    let src = unsafe { crate::errno::strerror(errnum) };
    // Walk to find length.
    let mut len = 0usize;
    while unsafe { *src.add(len) } != 0 { len += 1; }
    // Need len + 1 for NUL.
    if len + 1 > buflen {
        // Copy what fits, NUL-terminate, return ERANGE.
        let copy = buflen - 1;
        // SAFETY: bounded copy.
        unsafe {
            core::ptr::copy_nonoverlapping(src, buf, copy);
            *buf.add(copy) = 0;
        }
        return 34; // ERANGE
    }
    // SAFETY: bounded copy + NUL.
    unsafe {
        core::ptr::copy_nonoverlapping(src, buf, len);
        *buf.add(len) = 0;
    }
    0
}

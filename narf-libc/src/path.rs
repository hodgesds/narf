//! Path-handling surface: `<libgen.h>` `basename`/`dirname` and
//! `<fnmatch.h>` glob-style pattern matching.
//!
//! All entries are pure value math over caller-supplied buffers —
//! no kernel calls, no allocation. The classic gotcha with glibc's
//! `basename` (two incompatible declarations from `<libgen.h>` vs
//! `<string.h>`) is sidestepped here: we ship only the POSIX
//! `<libgen.h>` form, which writes through the input buffer and
//! returns a pointer inside it.

#![allow(non_camel_case_types)]

use crate::posix::{c_char, c_int};

// ── basename / dirname ──────────────────────────────────────────────

/// `basename(path)` — return the final path component. The classic
/// POSIX form: returns a pointer inside `path` (or a static
/// `"."` / `"/"` for trivial inputs). May modify `path` (POSIX
/// permits stripping trailing slashes); we leave it unchanged.
///
/// # Safety
/// `path` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn basename(path: *mut c_char) -> *mut c_char {
    static DOT: [u8; 2]   = [b'.', 0];
    static SLASH: [u8; 2] = [b'/', 0];
    if path.is_null() {
        return DOT.as_ptr() as *mut c_char;
    }
    // SAFETY: caller-asserted NUL-terminator.
    unsafe {
        // Empty string → ".".
        if *path == 0 {
            return DOT.as_ptr() as *mut c_char;
        }
        // Walk to NUL.
        let mut end = 0usize;
        while *path.add(end) != 0 { end += 1; }
        // Strip trailing slashes (but leave at least one byte).
        while end > 1 && *path.add(end - 1) == b'/' as c_char {
            end -= 1;
        }
        // All slashes? → "/".
        if end == 1 && *path == b'/' as c_char {
            return SLASH.as_ptr() as *mut c_char;
        }
        // Find the last `/` before `end`.
        let mut last_slash: Option<usize> = None;
        for i in 0..end {
            if *path.add(i) == b'/' as c_char {
                last_slash = Some(i);
            }
        }
        match last_slash {
            Some(p) => path.add(p + 1),
            None    => path,
        }
    }
}

/// `dirname(path)` — return everything up to (and excluding) the
/// last `/` of `path`. Same caveat as [`basename`] re: in-place
/// modification — we DO punch a NUL into `path` at the slash so
/// the returned pointer is a valid C string.
///
/// # Safety
/// `path` must be a valid, **writable**, NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn dirname(path: *mut c_char) -> *mut c_char {
    static DOT: [u8; 2]   = [b'.', 0];
    static SLASH: [u8; 2] = [b'/', 0];
    if path.is_null() {
        return DOT.as_ptr() as *mut c_char;
    }
    // SAFETY: caller-asserted NUL-terminator + writability.
    unsafe {
        if *path == 0 {
            return DOT.as_ptr() as *mut c_char;
        }
        let mut end = 0usize;
        while *path.add(end) != 0 { end += 1; }
        while end > 1 && *path.add(end - 1) == b'/' as c_char {
            end -= 1;
        }
        // No slash → ".".
        let mut last_slash: Option<usize> = None;
        for i in 0..end {
            if *path.add(i) == b'/' as c_char {
                last_slash = Some(i);
            }
        }
        match last_slash {
            None => DOT.as_ptr() as *mut c_char,
            Some(0) => SLASH.as_ptr() as *mut c_char,
            Some(p) => {
                // Strip trailing slashes from the parent itself.
                let mut q = p;
                while q > 1 && *path.add(q - 1) == b'/' as c_char {
                    q -= 1;
                }
                *path.add(q) = 0;
                path
            }
        }
    }
}

// ── fnmatch ─────────────────────────────────────────────────────────
//
// Subset of POSIX fnmatch supporting `*`, `?`, and `[set]` /
// `[!set]` / `[^set]` character classes (no collating elements, no
// equivalence classes — those need a locale we don't have).
// `FNM_PATHNAME`, `FNM_PERIOD`, `FNM_NOESCAPE` are recognised flags.

pub const FNM_NOMATCH:  c_int = 1;
pub const FNM_PATHNAME: c_int = 1 << 0;
pub const FNM_NOESCAPE: c_int = 1 << 1;
pub const FNM_PERIOD:   c_int = 1 << 2;

fn match_class(pat: &[u8], i: &mut usize, ch: u8) -> Option<bool> {
    // Caller has consumed `[`; we walk until the closing `]`. The
    // match outcome is returned as Some(matched); on malformed
    // input (no closing bracket) we return None and the caller
    // treats the `[` as a literal.
    let mut idx = *i;
    let len = pat.len();
    if idx >= len { return None; }
    let negate = if pat[idx] == b'!' || pat[idx] == b'^' {
        idx += 1; true
    } else {
        false
    };
    let start = idx;
    let mut matched = false;
    while idx < len {
        // POSIX: a `]` as the very first character (after `!`) is
        // taken literally, not as the close.
        if pat[idx] == b']' && idx > start {
            *i = idx + 1;
            return Some(matched ^ negate);
        }
        // Range a-z?
        if idx + 2 < len && pat[idx + 1] == b'-' && pat[idx + 2] != b']' {
            let lo = pat[idx];
            let hi = pat[idx + 2];
            if ch >= lo && ch <= hi { matched = true; }
            idx += 3;
        } else {
            if pat[idx] == ch { matched = true; }
            idx += 1;
        }
    }
    None
}

fn fnmatch_walk(pat: &[u8], name: &[u8], flags: c_int) -> bool {
    // Recursive backtrack with explicit i/j cursors. Bounded by
    // pattern length (each `*` retry advances `name` by at least 1).
    let pathname = (flags & FNM_PATHNAME) != 0;
    let period = (flags & FNM_PERIOD) != 0;
    let noescape = (flags & FNM_NOESCAPE) != 0;

    let mut i = 0usize;
    let mut j = 0usize;
    let mut star_i: Option<usize> = None;
    let mut star_j: usize = 0;

    while j < name.len() {
        let nc = name[j];
        if i < pat.len() {
            let pc = pat[i];
            // FNM_PERIOD: leading `.` only matches an explicit `.`.
            let is_leading = j == 0
                || (pathname && j > 0 && name[j - 1] == b'/');
            if period && is_leading && nc == b'.' && pc != b'.' {
                if let Some(si) = star_i {
                    i = si + 1;
                    star_j += 1;
                    j = star_j;
                    continue;
                }
                return false;
            }
            match pc {
                b'?' => {
                    if pathname && nc == b'/' {
                        // Reset via *.
                        if let Some(si) = star_i {
                            i = si + 1;
                            star_j += 1;
                            j = star_j;
                            continue;
                        }
                        return false;
                    }
                    i += 1; j += 1;
                    continue;
                }
                b'*' => {
                    // Collapse runs of `*`.
                    while i < pat.len() && pat[i] == b'*' { i += 1; }
                    if i == pat.len() {
                        // Trailing `*` — matches the rest unless
                        // PATHNAME bans `/`.
                        if pathname {
                            return !name[j..].contains(&b'/');
                        }
                        return true;
                    }
                    star_i = Some(i - 1);
                    star_j = j;
                    continue;
                }
                b'[' => {
                    let mut k = i + 1;
                    if let Some(ok) = match_class(pat, &mut k, nc) {
                        if ok {
                            if pathname && nc == b'/' {
                                // bracket can't span /
                                if let Some(si) = star_i {
                                    i = si + 1;
                                    star_j += 1;
                                    j = star_j;
                                    continue;
                                }
                                return false;
                            }
                            i = k; j += 1;
                            continue;
                        } else {
                            // Bracket didn't match — fall through to
                            // backtrack via star or fail.
                        }
                    } else {
                        // Malformed class — `[` literal.
                        if nc == b'[' { i += 1; j += 1; continue; }
                    }
                    if let Some(si) = star_i {
                        i = si + 1;
                        star_j += 1;
                        j = star_j;
                        continue;
                    }
                    return false;
                }
                b'\\' if !noescape && i + 1 < pat.len() => {
                    if pat[i + 1] == nc { i += 2; j += 1; continue; }
                    if let Some(si) = star_i {
                        i = si + 1;
                        star_j += 1;
                        j = star_j;
                        continue;
                    }
                    return false;
                }
                _ => {
                    if pc == nc {
                        if pathname && pc == b'/' && star_i.is_some() {
                            // A `/` cannot be matched by an earlier *.
                            star_i = None;
                        }
                        i += 1; j += 1;
                        continue;
                    }
                    if let Some(si) = star_i {
                        // `/` always blocks * backtracking under
                        // PATHNAME — reject if the candidate slot
                        // crosses a slash.
                        if pathname && nc == b'/' { return false; }
                        i = si + 1;
                        star_j += 1;
                        j = star_j;
                        continue;
                    }
                    return false;
                }
            }
        }
        // Pattern exhausted but name has more.
        if let Some(si) = star_i {
            if pathname && nc == b'/' { return false; }
            i = si + 1;
            star_j += 1;
            j = star_j;
            continue;
        }
        return false;
    }
    // Tail of pattern: only trailing `*` are acceptable.
    while i < pat.len() && pat[i] == b'*' { i += 1; }
    i == pat.len()
}

/// `fnmatch(pattern, string, flags)` — return 0 on match, otherwise
/// `FNM_NOMATCH` (1).
///
/// # Safety
/// `pattern` and `string` must each be valid NUL-terminated C
/// strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fnmatch(
    pattern: *const c_char,
    string:  *const c_char,
    flags:   c_int,
) -> c_int {
    if pattern.is_null() || string.is_null() {
        return FNM_NOMATCH;
    }
    // SAFETY: caller-asserted NUL-termination.
    unsafe {
        let mut pl = 0usize;
        while *pattern.add(pl) != 0 { pl += 1; }
        let mut sl = 0usize;
        while *string.add(sl) != 0 { sl += 1; }
        let pat = core::slice::from_raw_parts(pattern as *const u8, pl);
        let nm  = core::slice::from_raw_parts(string  as *const u8, sl);
        if fnmatch_walk(pat, nm, flags) { 0 } else { FNM_NOMATCH }
    }
}

// ── opendir / readdir / closedir — stubs ────────────────────────────
//
// The kernel doesn't expose a readdir syscall yet (no DirOps::iter
// surface). We ship the entry points so a consumer's link succeeds
// and `errno = ENOSYS` lets it know to fall back. When the kernel
// grows readdir these become real.

pub const ENOSYS: c_int = 38;

#[repr(C)]
pub struct DIR {
    // Opaque to callers. We never construct one — the stub returns
    // NULL — so the field shape doesn't matter for ABI.
    _opaque: [u8; 0],
}

#[repr(C)]
pub struct dirent {
    pub d_ino:    u64,
    pub d_off:    u64,
    pub d_reclen: u16,
    pub d_type:   u8,
    pub d_name:   [c_char; 256],
}

/// `opendir(path)` — stub returning NULL with `errno = ENOSYS`.
///
/// # Safety
/// `path` must be a valid NUL-terminated C string (or NULL — we
/// just return NULL either way).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn opendir(_path: *const c_char) -> *mut DIR {
    crate::errno::set_errno(ENOSYS);
    core::ptr::null_mut()
}

/// `readdir(dirp)` — stub returning NULL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn readdir(_dirp: *mut DIR) -> *mut dirent {
    crate::errno::set_errno(ENOSYS);
    core::ptr::null_mut()
}

/// `closedir(dirp)` — stub returning -1.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn closedir(_dirp: *mut DIR) -> c_int {
    crate::errno::set_errno(ENOSYS);
    -1
}

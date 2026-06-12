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
    static DOT: [u8; 2] = [b'.', 0];
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
        while *path.add(end) != 0 {
            end += 1;
        }
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
            None => path,
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
    static DOT: [u8; 2] = [b'.', 0];
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
        while *path.add(end) != 0 {
            end += 1;
        }
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

pub const FNM_NOMATCH: c_int = 1;
pub const FNM_PATHNAME: c_int = 1 << 0;
pub const FNM_NOESCAPE: c_int = 1 << 1;
pub const FNM_PERIOD: c_int = 1 << 2;

fn match_class(pat: &[u8], i: &mut usize, ch: u8) -> Option<bool> {
    // Caller has consumed `[`; we walk until the closing `]`. The
    // match outcome is returned as Some(matched); on malformed
    // input (no closing bracket) we return None and the caller
    // treats the `[` as a literal.
    let mut idx = *i;
    let len = pat.len();
    if idx >= len {
        return None;
    }
    let negate = if pat[idx] == b'!' || pat[idx] == b'^' {
        idx += 1;
        true
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
            if ch >= lo && ch <= hi {
                matched = true;
            }
            idx += 3;
        } else {
            if pat[idx] == ch {
                matched = true;
            }
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
            let is_leading = j == 0 || (pathname && j > 0 && name[j - 1] == b'/');
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
                    i += 1;
                    j += 1;
                    continue;
                }
                b'*' => {
                    // Collapse runs of `*`.
                    while i < pat.len() && pat[i] == b'*' {
                        i += 1;
                    }
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
                            i = k;
                            j += 1;
                            continue;
                        } else {
                            // Bracket didn't match — fall through to
                            // backtrack via star or fail.
                        }
                    } else {
                        // Malformed class — `[` literal.
                        if nc == b'[' {
                            i += 1;
                            j += 1;
                            continue;
                        }
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
                    if pat[i + 1] == nc {
                        i += 2;
                        j += 1;
                        continue;
                    }
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
                        i += 1;
                        j += 1;
                        continue;
                    }
                    if let Some(si) = star_i {
                        // `/` always blocks * backtracking under
                        // PATHNAME — reject if the candidate slot
                        // crosses a slash.
                        if pathname && nc == b'/' {
                            return false;
                        }
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
            if pathname && nc == b'/' {
                return false;
            }
            i = si + 1;
            star_j += 1;
            j = star_j;
            continue;
        }
        return false;
    }
    // Tail of pattern: only trailing `*` are acceptable.
    while i < pat.len() && pat[i] == b'*' {
        i += 1;
    }
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
    string: *const c_char,
    flags: c_int,
) -> c_int {
    if pattern.is_null() || string.is_null() {
        return FNM_NOMATCH;
    }
    // SAFETY: caller-asserted NUL-termination.
    unsafe {
        let mut pl = 0usize;
        while *pattern.add(pl) != 0 {
            pl += 1;
        }
        let mut sl = 0usize;
        while *string.add(sl) != 0 {
            sl += 1;
        }
        let pat = core::slice::from_raw_parts(pattern as *const u8, pl);
        let nm = core::slice::from_raw_parts(string as *const u8, sl);
        if fnmatch_walk(pat, nm, flags) {
            0
        } else {
            FNM_NOMATCH
        }
    }
}

// ── opendir / readdir / closedir ────────────────────────────────────
//
// Backed by `narf_user_runtime::listdir`, which serialises one
// directory entry per syscall in `[name_len: u32][file_type: u32]
// [name bytes...]` format. opendir records the absolute path + a
// cursor in the heap-allocated DIR struct; readdir advances the
// cursor and decodes one entry into the embedded dirent slot;
// closedir frees the DIR.
//
// The dirent returned by readdir is a pointer INTO the DIR
// (matching POSIX: subsequent readdir overwrites the same slot).
// Callers stashing the pointer across readdir calls will see the
// next entry's bytes — that's the platform contract.

pub const ENOSYS: c_int = 38;
const ENOMEM: c_int = 12;

const DIR_PATH_MAX: usize = 256;

/// Open directory handle. The real shape lives behind a heap
/// allocation; opendir returns a pointer to it; readdir mutates
/// the cursor + slot in place; closedir frees it. The path is
/// fixed at opendir time (POSIX permits opendir to capture the
/// path; we don't honour rename mid-walk).
#[repr(C)]
pub struct DIR {
    /// NUL-terminated absolute path captured at opendir time.
    pub path: [c_char; DIR_PATH_MAX],
    /// Length of `path` excluding the NUL terminator.
    pub path_len: usize,
    /// Cursor into the underlying directory's entry list. Advances
    /// by one on every successful readdir.
    pub cursor: u64,
    /// End-of-directory latched after the first end-of-list signal
    /// from the kernel — subsequent readdir calls return NULL
    /// without re-issuing the syscall.
    pub eof: bool,
    /// Reusable dirent slot returned to the caller. Overwritten on
    /// every successful readdir.
    pub entry: dirent,
}

/// glibc-shaped `struct dirent`. `d_name` is fixed at 256 bytes —
/// the kernel rejects names longer than 255 (255 + NUL = 256).
#[repr(C)]
#[derive(Copy, Clone)]
pub struct dirent {
    pub d_ino: u64,
    pub d_off: u64,
    pub d_reclen: u16,
    pub d_type: u8,
    pub d_name: [c_char; 256],
}

// d_type values per Linux/glibc.
pub const DT_UNKNOWN: u8 = 0;
pub const DT_FIFO: u8 = 1;
pub const DT_CHR: u8 = 2;
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;

/// Translate the wire FileType ordinal (0=File, 1=Dir, 2=Symlink,
/// 3=Special) into the POSIX `d_type`.
fn wire_to_dtype(ft: u32) -> u8 {
    match ft {
        0 => DT_REG,
        1 => DT_DIR,
        2 => DT_LNK,
        3 => DT_CHR,
        _ => DT_UNKNOWN,
    }
}

/// `opendir(path)` — capture the absolute path into a heap-
/// allocated DIR and return a pointer. NULL on alloc failure or
/// path-too-long.
///
/// # Safety
/// `path` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn opendir(path: *const c_char) -> *mut DIR {
    if path.is_null() {
        crate::errno::set_errno(EINVAL);
        return core::ptr::null_mut();
    }
    // SAFETY: caller-asserted NUL-terminator.
    let mut len = 0usize;
    // SAFETY: Valid memory or trusted environment
    unsafe {
        while *path.add(len) != 0 {
            len += 1;
            if len >= DIR_PATH_MAX {
                crate::errno::set_errno(EINVAL);
                return core::ptr::null_mut();
            }
        }
    }
    // SAFETY: malloc is `unsafe extern "C"`; size > 0.
    let p = unsafe { crate::heap::malloc(core::mem::size_of::<DIR>()) } as *mut DIR;
    if p.is_null() {
        crate::errno::set_errno(ENOMEM);
        return core::ptr::null_mut();
    }
    // SAFETY: malloc returned a sizeof(DIR)-byte writable region.
    unsafe {
        // Initialise via core::ptr::write so we don't read the
        // uninitialised bytes.
        core::ptr::write(
            p,
            DIR {
                path: [0; DIR_PATH_MAX],
                path_len: len,
                cursor: 0,
                eof: false,
                entry: dirent {
                    d_ino: 0,
                    d_off: 0,
                    d_reclen: 0,
                    d_type: DT_UNKNOWN,
                    d_name: [0; 256],
                },
            },
        );
        for i in 0..len {
            (*p).path[i] = *path.add(i);
        }
    }
    p
}

const EINVAL: c_int = 22;

/// `readdir(dirp)` — fetch the next entry. Returns a pointer into
/// `dirp.entry` (overwritten on each call), or NULL at end-of-
/// directory / on error.
///
/// # Safety
/// `dirp` must be a pointer previously returned by `opendir`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn readdir(dirp: *mut DIR) -> *mut dirent {
    if dirp.is_null() {
        crate::errno::set_errno(EINVAL);
        return core::ptr::null_mut();
    }
    // SAFETY: caller asserts dirp.
    let dir = unsafe { &mut *dirp };
    if dir.eof {
        return core::ptr::null_mut();
    }
    // Stack scratch for the kernel's wire payload (8-byte header +
    // up to 255-byte name + 1-byte slack).
    let mut wire: [u8; 264] = [0; 264];
    // SAFETY: `dir.path[0..dir.path_len]` is a valid UTF-8 prefix
    // captured at opendir time. We pass it as a `&str` into the
    // user-runtime helper.
    let path_bytes: &[u8] =
        // SAFETY: Valid memory or trusted environment
        unsafe { core::slice::from_raw_parts(dir.path.as_ptr() as *const u8, dir.path_len) };
    let path = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => {
            crate::errno::set_errno(EINVAL);
            dir.eof = true;
            return core::ptr::null_mut();
        }
    };
    let n = narf_user_runtime::listdir(path, dir.cursor, &mut wire);
    if n < 0 {
        crate::errno::set_errno(EINVAL);
        dir.eof = true;
        return core::ptr::null_mut();
    }
    if n == 0 {
        dir.eof = true;
        return core::ptr::null_mut();
    }
    let n = n as usize;
    if n < 8 {
        crate::errno::set_errno(EINVAL);
        dir.eof = true;
        return core::ptr::null_mut();
    }
    // Decode the wire header.
    let name_len = u32::from_le_bytes(match wire[0..4].try_into() {
        Ok(a) => a,
        Err(_) => return core::ptr::null_mut(),
    }) as usize;
    let ftype = u32::from_le_bytes(match wire[4..8].try_into() {
        Ok(a) => a,
        Err(_) => return core::ptr::null_mut(),
    });
    if 8 + name_len > n || name_len >= 256 {
        crate::errno::set_errno(EINVAL);
        dir.eof = true;
        return core::ptr::null_mut();
    }
    // Populate the dirent slot.
    dir.entry.d_ino = dir.cursor + 1; // synthetic; sequential
    dir.entry.d_off = (dir.cursor + 1) as u64;
    dir.entry.d_reclen = (8 + name_len) as u16;
    dir.entry.d_type = wire_to_dtype(ftype);
    // Zero the name slot, then copy in the wire bytes + NUL.
    for i in 0..256 {
        dir.entry.d_name[i] = 0;
    }
    for i in 0..name_len {
        dir.entry.d_name[i] = wire[8 + i] as c_char;
    }
    dir.cursor += 1;
    &mut dir.entry as *mut dirent
}

/// `closedir(dirp)` — release the heap allocation. Returns 0 on
/// success, -1 on null input.
///
/// # Safety
/// `dirp` must be a pointer previously returned by `opendir` (and
/// not previously closed).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn closedir(dirp: *mut DIR) -> c_int {
    if dirp.is_null() {
        crate::errno::set_errno(EINVAL);
        return -1;
    }
    // SAFETY: matched alloc/free pair.
    unsafe {
        crate::heap::free(dirp as *mut u8);
    }
    0
}

/// `rewinddir(dirp)` — reset the cursor to 0 and clear the EOF
/// latch. POSIX shape; the next readdir starts the directory walk
/// over.
///
/// # Safety
/// `dirp` must be a valid open DIR.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rewinddir(dirp: *mut DIR) {
    if dirp.is_null() {
        return;
    }
    // SAFETY: caller asserts dirp.
    unsafe {
        (*dirp).cursor = 0;
        (*dirp).eof = false;
    }
}

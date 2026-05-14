//! POSIX-shaped fd-control helpers — `dup` / `dup2` / `fcntl` /
//! `pipe` / `stat` / `fstat`.
//!
//! Path-B scope (Stage 4 round 2): mirror the POSIX.1-2017 surface
//! real C programs reach for after they have a working `open` / `read`
//! / `write` / `close`. Every entry delegates to
//! [`narf_user_runtime`] for the actual syscall — this layer only
//! adds the i32 vs u32 fd-shape coercion and the POSIX `pipefd[2]`
//! out-pointer convention.
//!
//! The kernel-side `flags` field we expose through `fcntl` is a
//! Stage-4 minimum: `FD_CLOEXEC` is the only bit the kernel
//! actually consults today, but `F_GETFL` / `F_SETFL` accept the
//! call (returning 0) so callers that probe the file-flag word
//! during init don't see a spurious error.

use crate::errno::set_errno;

pub use narf_user_runtime::{
    F_GETFD, F_GETFL, F_SETFD, F_SETFL, FD_CLOEXEC, StatBuf,
};

/// Sentinel errno: bad fd. Matches Linux's EBADF so consumers that
/// check `errno == 9` work without touching `errno.h`.
const EBADF: i32 = 9;

/// `dup(fd)` — duplicate `fd` to the lowest free slot ≥ 3. Returns
/// the new fd, or `-1` on failure (with `errno` set to `EBADF`).
///
/// # Safety
/// `fd` is taken at face value — passing a negative value short-
/// circuits to `-1` without a kernel call.
pub unsafe fn dup(fd: i32) -> i32 {
    if fd < 0 {
        set_errno(EBADF);
        return -1;
    }
    match narf_user_runtime::dup(fd as u32) {
        Some(n) => n as i32,
        None    => { set_errno(EBADF); -1 }
    }
}

/// `dup2(oldfd, newfd)` — install a clone of `oldfd` at exactly
/// `newfd`. Returns `newfd` on success, `-1` on failure.
///
/// # Safety
/// Same fd-shape contract as [`dup`].
pub unsafe fn dup2(oldfd: i32, newfd: i32) -> i32 {
    if oldfd < 0 || newfd < 0 {
        set_errno(EBADF);
        return -1;
    }
    match narf_user_runtime::dup2(oldfd as u32, newfd as u32) {
        Some(n) => n as i32,
        None    => { set_errno(EBADF); -1 }
    }
}

/// `fcntl(fd, cmd, arg)` — `F_GETFD` / `F_SETFD` / `F_GETFL` /
/// `F_SETFL`. Returns the kernel result (or 0 for the no-op
/// commands), `-1` on bad-fd / unsupported-cmd.
///
/// # Safety
/// The third argument is `i64` rather than the C-variadic `...`
/// because `core::ffi::VaList` is still unstable; callers that
/// would normally pass an `int` cast it up to `i64`.
pub unsafe fn fcntl(fd: i32, cmd: i32, arg: i64) -> i64 {
    if fd < 0 {
        set_errno(EBADF);
        return -1;
    }
    let r = narf_user_runtime::fcntl(fd as u32, cmd as u32, arg as u64);
    if r < 0 {
        set_errno(EBADF);
    }
    r
}

/// `pipe(pipefd)` — fill `pipefd[0]` (read fd) and `pipefd[1]`
/// (write fd) with a fresh pipe pair. Returns 0 on success, `-1`
/// otherwise.
///
/// # Safety
/// `pipefd` must point to at least two writable `i32`s.
pub unsafe fn pipe(pipefd: *mut i32) -> i32 {
    if pipefd.is_null() {
        set_errno(EBADF);
        return -1;
    }
    match narf_user_runtime::pipe() {
        Some((r, w)) => {
            // SAFETY: caller asserts pipefd has room for two i32s.
            unsafe {
                *pipefd         = r as i32;
                *pipefd.add(1) = w as i32;
            }
            0
        }
        None => { set_errno(EBADF); -1 }
    }
}

/// `memfd_create(name, flags)` — Linux memfd_create(2). Returns
/// a fresh fd backing an anonymous in-memory file, or -1 on
/// failure. `name` is debug-only; not visible via any FS path.
///
/// # Safety
/// `name` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memfd_create(name: *const i8, flags: u32) -> i32 {
    if name.is_null() { return -1; }
    // SAFETY: caller-asserted NUL-terminator. Walk to find length.
    let mut len = 0usize;
    unsafe {
        while *name.add(len) != 0 { len += 1; }
    }
    // SAFETY: in-bounds `len` per the walk above.
    let bytes = unsafe { core::slice::from_raw_parts(name as *const u8, len) };
    let s = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    narf_user_runtime::memfd_create(s, flags)
}

/// `pipe2(pipefd, flags)` — Linux-shaped pipe with atomic flag
/// set. Honoured: `O_CLOEXEC` (0x80000) stamps FD_CLOEXEC on both
/// halves. `O_NONBLOCK` accepted and ignored.
///
/// # Safety
/// As [`pipe`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pipe2(pipefd: *mut i32, flags: i32) -> i32 {
    if pipefd.is_null() {
        set_errno(EBADF);
        return -1;
    }
    match narf_user_runtime::pipe2(flags as u32) {
        Some((r, w)) => {
            // SAFETY: caller asserts pipefd has room for two i32s.
            unsafe {
                *pipefd         = r as i32;
                *pipefd.add(1) = w as i32;
            }
            0
        }
        None => { set_errno(EBADF); -1 }
    }
}

/// `stat(path, &mut out)` — fill `out` with the stat result for
/// the absolute path. Returns 0 on success, `-1` on failure.
///
/// # Safety
/// `path` must be a NUL-terminated C string; `out` must point at
/// a writable [`StatBuf`].
pub unsafe fn stat(path: *const u8, out: *mut StatBuf) -> i32 {
    if path.is_null() || out.is_null() {
        set_errno(EBADF);
        return -1;
    }
    // SAFETY: caller-asserted NUL-terminated string. Walk to find
    // length without going past the terminator.
    let mut len = 0usize;
    // Bound the walk at 4 KiB so a missing NUL doesn't read into
    // unmapped territory; longer absolute paths are vanishingly rare.
    while len < 4096 {
        if unsafe { *path.add(len) } == 0 { break; }
        len += 1;
    }
    let path_bytes = unsafe { core::slice::from_raw_parts(path, len) };
    let path_str = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => { set_errno(EBADF); return -1; }
    };
    // SAFETY: caller asserts `out` is writable.
    let out_ref = unsafe { &mut *out };
    if narf_user_runtime::stat(path_str, out_ref) == 0 {
        0
    } else {
        set_errno(EBADF);
        -1
    }
}

/// `fstatat(dirfd, path, *out, flags)` — Linux *at variant.
/// dirfd is ignored; path must be absolute.
///
/// # Safety
/// `path` must be a NUL-terminated C string; `out` must be a
/// writable `*mut StatBuf`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fstatat(
    dirfd: i32,
    path:  *const u8,
    out:   *mut StatBuf,
    flags: i32,
) -> i32 {
    if path.is_null() || out.is_null() {
        set_errno(EBADF);
        return -1;
    }
    // Walk path NUL-bounded, capped at 4 KiB.
    let mut len = 0usize;
    while len < 4096 {
        if unsafe { *path.add(len) } == 0 { break; }
        len += 1;
    }
    let bytes = unsafe { core::slice::from_raw_parts(path, len) };
    let s = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => { set_errno(EBADF); return -1; }
    };
    let out_ref = unsafe { &mut *out };
    if narf_user_runtime::fstatat(dirfd, s, out_ref, flags) == 0 {
        0
    } else {
        set_errno(EBADF);
        -1
    }
}

/// `lstat(path, &mut out)` — like [`stat`] but doesn't follow
/// symlinks. NARF has no symlinks; this aliases stat.
///
/// # Safety
/// See [`stat`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lstat(path: *const u8, out: *mut StatBuf) -> i32 {
    if path.is_null() || out.is_null() {
        set_errno(EBADF);
        return -1;
    }
    let mut len = 0usize;
    while len < 4096 {
        if unsafe { *path.add(len) } == 0 { break; }
        len += 1;
    }
    let path_bytes = unsafe { core::slice::from_raw_parts(path, len) };
    let path_str = match core::str::from_utf8(path_bytes) {
        Ok(s) => s,
        Err(_) => { set_errno(EBADF); return -1; }
    };
    let out_ref = unsafe { &mut *out };
    if narf_user_runtime::lstat(path_str, out_ref) == 0 {
        0
    } else {
        set_errno(EBADF);
        -1
    }
}

/// `fstat(fd, &mut out)` — fill `out` with the stat result for an
/// open fd. Returns 0 on success, `-1` on failure.
///
/// # Safety
/// `out` must point at a writable [`StatBuf`].
pub unsafe fn fstat(fd: i32, out: *mut StatBuf) -> i32 {
    if fd < 0 || out.is_null() {
        set_errno(EBADF);
        return -1;
    }
    // SAFETY: caller asserts `out` is writable.
    let out_ref = unsafe { &mut *out };
    if narf_user_runtime::fstat(fd as u32, out_ref) == 0 {
        0
    } else {
        set_errno(EBADF);
        -1
    }
}

/// `isatty(fd)` — POSIX-shaped TTY check. Stage-4: stdin / stdout
/// / stderr (fds 0/1/2) are wired to the kernel console, so they
/// return 1; every other fd returns 0. Real device-aware probing
/// lands when the kernel models a tty driver distinct from the
/// console writer.
///
/// # Safety
/// Pure read of the fd argument; `extern "C"` shape for C-link.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn isatty(fd: i32) -> i32 {
    matches!(fd, 0 | 1 | 2) as i32
}

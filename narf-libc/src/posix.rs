//! Raw POSIX fd C-ABI: `open` / `close` / `read` / `write` /
//! `lseek` / `unlink`.
//!
//! These are the C-linkable shapes a real C consumer expects to find
//! by these exact names. The narf-libc crate already exposes
//! Rust-shaped helpers in `fd.rs` and `stdio.rs`; this module is the
//! `extern "C"` mirror so a C source file can `#include <unistd.h>`-
//! shaped declarations and link straight against narf-libc.
//!
//! Each entry delegates into `narf_user_runtime`. None of them honour
//! `flags` / `mode` yet — open(2) ignores both and routes to the
//! absolute-path opener, matching what the kernel currently models.
//!
//! Pointer-shaped path arguments are walked as NUL-terminated C
//! strings via `cstr_len` — narf-libc cannot rely on Rust's `&str`
//! shape across a C boundary.

#![allow(non_camel_case_types)]

pub type c_char  = i8;
pub type c_int   = i32;
pub type c_void  = core::ffi::c_void;
pub type ssize_t = isize;
pub type off_t   = i64;
pub type mode_t  = u32;

// SEEK_* whence constants. Mirrors `<unistd.h>`.
pub const SEEK_SET: c_int = 0;
pub const SEEK_CUR: c_int = 1;
pub const SEEK_END: c_int = 2;

// Open flags. Numeric values match Linux so a libc consumer's
// `<fcntl.h>` lines up. Today the kernel only honours `O_CREAT`;
// the rest are accepted and ignored.
pub const O_RDONLY: c_int = 0o0;
pub const O_WRONLY: c_int = 0o1;
pub const O_RDWR:   c_int = 0o2;
pub const O_CREAT:  c_int = 0o100;
pub const O_TRUNC:  c_int = 0o1000;
pub const O_APPEND: c_int = 0o2000;

/// Walk `p` until the NUL terminator and return the byte length.
/// Caller is responsible for ensuring `p` is a valid C string.
#[inline]
unsafe fn cstr_len(p: *const c_char) -> usize {
    let mut n = 0usize;
    // SAFETY: caller contract — `p` is a NUL-terminated C string,
    // so the walk terminates within the string's allocation.
    unsafe {
        while *p.add(n) != 0 {
            n += 1;
        }
    }
    n
}

/// Build a `&str` view over a C string. Returns an empty slice if
/// the bytes aren't valid UTF-8 — that surfaces as a kernel
/// rejection on path-shaped syscalls, which matches the relibc
/// "garbage in, EINVAL out" behaviour.
///
/// # Safety
/// `p` must be a valid NUL-terminated C string for the duration of
/// the returned borrow.
#[inline]
unsafe fn cstr_to_str<'a>(p: *const c_char) -> &'a str {
    if p.is_null() {
        return "";
    }
    // SAFETY: caller contract — see fn doc.
    let len = unsafe { cstr_len(p) };
    // SAFETY: same — `p` points at `len` valid bytes.
    let bytes = unsafe { core::slice::from_raw_parts(p as *const u8, len) };
    core::str::from_utf8(bytes).unwrap_or("")
}

/// `open(path, flags, mode)` — routes to the absolute-path opener
/// in the kernel; `O_CREAT` is honoured (the kernel asks the parent
/// directory to `create()` the leaf when missing). Other flags are
/// accepted and ignored. `mode` is reserved for permission bits and
/// currently unused by the kernel. Returns the fd on success or -1.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn open(
    path: *const c_char,
    flags: c_int,
    _mode: mode_t,
) -> c_int {
    // SAFETY: caller contract — `path` is a NUL-terminated C string.
    let s = unsafe { cstr_to_str(path) };
    match narf_user_runtime::open_flags(s, "", flags as u64) {
        Some(fd) => fd as c_int,
        None     => -1,
    }
}

/// `close(fd)` — POSIX-shaped. Returns 0 on success, -1 on failure.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn close(fd: c_int) -> c_int {
    if fd < 0 {
        return -1;
    }
    match narf_user_runtime::close(fd as u32) {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

/// `read(fd, buf, count)` — POSIX-shaped. Returns the number of
/// bytes read, or -1 on bad fd. The kernel surface returns a usize
/// today; we cast to ssize_t so `-1` is representable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn read(
    fd: c_int,
    buf: *mut c_void,
    count: usize,
) -> ssize_t {
    if fd < 0 || buf.is_null() {
        return -1;
    }
    // SAFETY: caller-supplied buffer of `count` bytes.
    let slice = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count) };
    narf_user_runtime::read(fd as u32, slice) as ssize_t
}

/// `write(fd, buf, count)` — POSIX-shaped. Returns the number of
/// bytes written.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn write(
    fd: c_int,
    buf: *const c_void,
    count: usize,
) -> ssize_t {
    if fd < 0 || buf.is_null() {
        return -1;
    }
    // SAFETY: caller-supplied buffer of `count` bytes.
    let slice = unsafe { core::slice::from_raw_parts(buf as *const u8, count) };
    narf_user_runtime::write(fd as u32, slice) as ssize_t
}

/// `lseek(fd, offset, whence)` — POSIX-shaped. Returns the new
/// offset on success or -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lseek(
    fd: c_int,
    offset: off_t,
    whence: c_int,
) -> off_t {
    if fd < 0 {
        return -1;
    }
    narf_user_runtime::lseek(fd as u32, offset, whence as u32)
}

/// `unlink(path)` — POSIX-shaped. Returns 0 on success, -1 on
/// failure. Routes through the kernel to `DirOps::unlink` on the
/// parent directory; FSes that don't implement removal surface -1.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unlink(path: *const c_char) -> c_int {
    // SAFETY: caller contract — `path` is a NUL-terminated C string.
    let s = unsafe { cstr_to_str(path) };
    narf_user_runtime::unlink(s)
}

/// `mkdir(path, mode)` — POSIX-shaped. Returns 0 / -1. `mode` is
/// accepted and ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mkdir(path: *const c_char, mode: mode_t) -> c_int {
    // SAFETY: caller contract — `path` is a NUL-terminated C string.
    let s = unsafe { cstr_to_str(path) };
    narf_user_runtime::mkdir(s, mode)
}

/// `rmdir(path)` — POSIX-shaped. Returns 0 / -1.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rmdir(path: *const c_char) -> c_int {
    // SAFETY: caller contract.
    let s = unsafe { cstr_to_str(path) };
    narf_user_runtime::rmdir(s)
}

/// `access(path, mode)` — test whether `path` is reachable. The
/// `mode` bitmask (`F_OK = 0`, `R_OK = 4`, `W_OK = 2`, `X_OK = 1`)
/// is accepted but only `F_OK` is honoured today: NARF has no
/// per-file permission bits in the kernel surface, so `R_OK` /
/// `W_OK` / `X_OK` are treated as `F_OK` (existence implies all
/// access). Returns 0 if reachable, -1 otherwise.
///
/// # Safety
/// `path` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn access(path: *const c_char, _mode: c_int) -> c_int {
    if path.is_null() { return -1; }
    // SAFETY: caller-asserted NUL-terminated string.
    let s = unsafe { cstr_to_str(path) };
    let mut sb = crate::fd::StatBuf::default();
    if narf_user_runtime::stat(s, &mut sb) == 0 { 0 } else { -1 }
}

/// `getpagesize()` — POSIX-deprecated but still common. NARF uses
/// 4 KiB pages on every target.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpagesize() -> c_int {
    4096
}

/// `ftruncate(fd, len)` — resize the file backing `fd` to `len`
/// bytes. Returns 0 on success, -1 on bad fd or read-only FS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftruncate(fd: c_int, len: off_t) -> c_int {
    if fd < 0 || len < 0 { return -1; }
    narf_user_runtime::ftruncate(fd as u32, len as u64)
}

/// `pread(fd, buf, count, offset)` — read at the explicit offset
/// without changing the fd's per-position cursor.
///
/// # Safety
/// `buf` must be writable for `count` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pread(
    fd:     c_int,
    buf:    *mut c_void,
    count:  usize,
    offset: off_t,
) -> ssize_t {
    if fd < 0 || buf.is_null() || offset < 0 { return -1; }
    // SAFETY: caller-supplied writable region.
    let slice = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, count) };
    narf_user_runtime::pread(fd as u32, slice, offset as u64) as ssize_t
}

/// `pwrite(fd, buf, count, offset)` — write at the explicit offset.
///
/// # Safety
/// `buf` must be readable for `count` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn pwrite(
    fd:     c_int,
    buf:    *const c_void,
    count:  usize,
    offset: off_t,
) -> ssize_t {
    if fd < 0 || buf.is_null() || offset < 0 { return -1; }
    // SAFETY: caller-supplied readable region.
    let slice = unsafe { core::slice::from_raw_parts(buf as *const u8, count) };
    narf_user_runtime::pwrite(fd as u32, slice, offset as u64) as ssize_t
}

/// `truncate(path, len)` — open(path, O_WRONLY) + ftruncate + close.
/// Convenience wrapper to match POSIX surface.
///
/// # Safety
/// `path` must be a NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn truncate(path: *const c_char, len: off_t) -> c_int {
    if path.is_null() || len < 0 { return -1; }
    // SAFETY: caller-asserted NUL-terminator.
    let s = unsafe { cstr_to_str(path) };
    let fd = match narf_user_runtime::open_abs(s) {
        Some(f) => f,
        None    => return -1,
    };
    let r = narf_user_runtime::ftruncate(fd, len as u64);
    let _ = narf_user_runtime::close(fd);
    r
}

/// `gethostname(buf, len)` — copy the kernel hostname, NUL-
/// terminated, into `buf`. Returns 0 on success, -1 if `len` is
/// too small for the name + NUL.
///
/// # Safety
/// `buf` must be writable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gethostname(buf: *mut c_char, len: usize) -> c_int {
    if buf.is_null() || len == 0 { return -1; }
    // SAFETY: caller-supplied writable buffer.
    let slice = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
    if narf_user_runtime::gethostname(slice) < 0 { -1 } else { 0 }
}

/// `sethostname(buf, len)` — replace the kernel hostname.
///
/// # Safety
/// `buf` must be readable for `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sethostname(buf: *const c_char, len: usize) -> c_int {
    if buf.is_null() || len == 0 { return -1; }
    // SAFETY: caller-supplied readable buffer.
    let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, len) };
    let s = match core::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    narf_user_runtime::sethostname(s)
}

// ── sysconf ──────────────────────────────────────────────────────
//
// Glibc enumerates dozens of `_SC_*` codes; we honour the load-
// bearing handful and return -1 for everything else (POSIX-correct
// for "value indeterminate").

pub const _SC_PAGESIZE:    c_int = 30;
pub const _SC_PAGE_SIZE:   c_int = 30; // glibc alias
pub const _SC_OPEN_MAX:    c_int = 4;
pub const _SC_CLK_TCK:     c_int = 2;
pub const _SC_NPROCESSORS_ONLN: c_int = 84;
pub const _SC_NPROCESSORS_CONF: c_int = 83;
pub const _SC_PHYS_PAGES:  c_int = 85;

/// `sysconf(name)` — runtime configurable-system-value query.
/// Returns -1 for unsupported codes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sysconf(name: c_int) -> i64 {
    match name {
        _SC_PAGESIZE | _SC_PAGE_SIZE => 4096,
        _SC_OPEN_MAX                  => 256,
        _SC_CLK_TCK                   => 100,
        _SC_NPROCESSORS_ONLN
        | _SC_NPROCESSORS_CONF        => 1,
        _SC_PHYS_PAGES                => -1,
        _ => -1,
    }
}

/// `rename(old, new)` — POSIX-shaped. Returns 0 / -1. Cross-
/// directory rename is unsupported (kernel rejects with -1 unless
/// both paths share the same parent directory).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rename(
    oldpath: *const c_char,
    newpath: *const c_char,
) -> c_int {
    // SAFETY: caller contract.
    let o = unsafe { cstr_to_str(oldpath) };
    let n = unsafe { cstr_to_str(newpath) };
    narf_user_runtime::rename(o, n)
}

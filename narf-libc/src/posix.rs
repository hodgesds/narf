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

//! `<termios.h>` + `<sys/ioctl.h>` + file-time stubs.
//!
//! NARF's kernel exposes neither a terminal-attribute interface nor
//! generic ioctls. Real C programs nevertheless probe `tcgetattr`
//! during init (raw-input editors, password readers, autocompletion
//! libraries) — refusing to link breaks them; surfacing -1 with
//! `errno = ENOTTY` lets them fall back to the line-buffered path.
//!
//! Same pattern for `flock`, `utime`, and friends: accept and report
//! success / a "not a tty" error per the call.

#![allow(non_camel_case_types)]

use crate::posix::{c_char, c_int};

pub const ENOTTY: c_int = 25;

// ── termios shapes ──────────────────────────────────────────────────

pub type tcflag_t = u32;
pub type cc_t = u8;
pub type speed_t = u32;

/// Number of c_cc[] slots — matches glibc's NCCS.
pub const NCCS: usize = 32;

/// `<termios.h>` `struct termios` — fields and array size match
/// glibc on x86_64 so a binary compiled against glibc headers
/// links cleanly.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct termios {
    pub c_iflag: tcflag_t,
    pub c_oflag: tcflag_t,
    pub c_cflag: tcflag_t,
    pub c_lflag: tcflag_t,
    pub c_line: cc_t,
    pub c_cc: [cc_t; NCCS],
    pub c_ispeed: speed_t,
    pub c_ospeed: speed_t,
}

impl Default for termios {
    fn default() -> Self {
        Self {
            c_iflag: 0,
            c_oflag: 0,
            c_cflag: 0,
            c_lflag: 0,
            c_line: 0,
            c_cc: [0; NCCS],
            c_ispeed: 0,
            c_ospeed: 0,
        }
    }
}

// optional_actions for tcsetattr
pub const TCSANOW: c_int = 0;
pub const TCSADRAIN: c_int = 1;
pub const TCSAFLUSH: c_int = 2;

/// `tcgetattr(fd, *out)` — read terminal attributes. Round-trips
/// the kernel-side per-task termios store so a subsequent
/// `tcsetattr` value is observed.
///
/// # Safety
/// `t` must be a writable `*mut termios` if non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcgetattr(fd: c_int, t: *mut termios) -> c_int {
    if t.is_null() {
        return -1;
    }
    if unsafe { crate::fd::isatty(fd) } == 0 {
        crate::errno::set_errno(ENOTTY);
        return -1;
    }
    // SAFETY: kernel writes the 60-byte KTermios shape into the
    // user buffer. The libc `termios` struct matches the same
    // layout (4*tcflag + line + 32 cc + 2 speed).
    let r = unsafe { narf_user_runtime::syscall2_raw(218, fd as u64, t as u64) };
    if (r as i64) < 0 {
        -1
    } else {
        0
    }
}

/// `tcsetattr(fd, action, *t)` — write terminal attributes.
///
/// # Safety
/// `t` must be a valid `*const termios` if non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcsetattr(fd: c_int, action: c_int, t: *const termios) -> c_int {
    if unsafe { crate::fd::isatty(fd) } == 0 {
        crate::errno::set_errno(ENOTTY);
        return -1;
    }
    if t.is_null() {
        return -1;
    }
    let r = unsafe { narf_user_runtime::syscall3_raw(219, fd as u64, action as u64, t as u64) };
    if (r as i64) < 0 {
        -1
    } else {
        0
    }
}

/// `tcflush(fd, what)` — accept-and-ignore drain request.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcflush(fd: c_int, _what: c_int) -> c_int {
    if unsafe { crate::fd::isatty(fd) } == 0 {
        crate::errno::set_errno(ENOTTY);
        return -1;
    }
    0
}

/// `tcdrain(fd)` — wait for output to drain. Stage-4 tty is
/// unbuffered (everything goes straight to the kernel console), so
/// drain is always a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tcdrain(fd: c_int) -> c_int {
    if unsafe { crate::fd::isatty(fd) } == 0 {
        crate::errno::set_errno(ENOTTY);
        return -1;
    }
    0
}

// ── ioctl ───────────────────────────────────────────────────────────

/// `ioctl(fd, request, ...)` — generic device-control surface.
/// NARF has no kernel ioctl dispatch; we surface -1 with
/// `errno = ENOTTY`. The variadic argument is not consumed.
///
/// We don't take a `...` parameter because Rust's `extern "C"`
/// variadics are gated on nightly-only `c_variadic`. Real glibc
/// emits `ioctl` with a fixed third argument anyway (the fourth +
/// is rare); a single `*mut c_void` is enough for the link.
///
/// # Safety
/// Pointer arguments are not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ioctl(_fd: c_int, _request: u64, _arg: *mut core::ffi::c_void) -> c_int {
    crate::errno::set_errno(ENOTTY);
    -1
}

// ── flock ───────────────────────────────────────────────────────────

pub const LOCK_SH: c_int = 1;
pub const LOCK_EX: c_int = 2;
pub const LOCK_NB: c_int = 4;
pub const LOCK_UN: c_int = 8;

/// `flock(fd, op)` — advisory file lock. NARF doesn't have a real
/// FS lock layer; we report success for any valid `op` against an
/// open fd. Programs that depend on lock contention to coordinate
/// across processes won't get correctness here, but single-process
/// users (the common case) work as expected.
///
/// # Safety
/// `fd` is taken at face value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn flock(fd: c_int, op: c_int) -> c_int {
    let r = unsafe { narf_user_runtime::syscall2_raw(235, fd as u64, op as u64) };
    r as c_int
}

// ── utime / utimes / futimens ───────────────────────────────────────

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct utimbuf {
    pub actime: i64,
    pub modtime: i64,
}

/// `utime(path, buf)` — accept and ignore. NARF has no kernel
/// surface for setting mtime/atime; we acknowledge success when
/// the path exists, -1 otherwise.
///
/// # Safety
/// `path` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn utime(path: *const c_char, _buf: *const utimbuf) -> c_int {
    // SAFETY: `access` walks the C string under the same contract.
    unsafe { crate::posix::access(path, 0) }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct timeval64 {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

/// `utimes(path, times)` — POSIX two-`timeval` form. Same accept-
/// and-ignore semantics as [`utime`].
///
/// # Safety
/// `path` must be a valid NUL-terminated C string. `times`, when
/// non-null, must be a `[timeval64; 2]`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn utimes(path: *const c_char, _times: *const timeval64) -> c_int {
    // SAFETY: forwarded.
    unsafe { crate::posix::access(path, 0) }
}

/// `futimens(fd, times)` — fd-keyed variant. We don't validate
/// `fd` against the open-fd table; just report success.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn futimens(_fd: c_int, _times: *const timeval64) -> c_int {
    0
}

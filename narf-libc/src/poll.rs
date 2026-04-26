//! `<poll.h>` + `<sys/select.h>` + `<sys/epoll.h>` + `<sys/eventfd.h>`
//! + `<sys/timerfd.h>` + `<sys/signalfd.h>` — I/O multiplexing.
//!
//! NARF has no kernel-side I/O multiplexing surface today — the
//! `narf-ring` IPC story is async-direct (futures register wakers
//! directly with the ring producers/consumers) and bypasses the
//! POSIX `poll`/`select` machinery entirely.
//!
//! This module surfaces the standard call shapes as ENOSYS stubs so
//! a binary that mentions them links cleanly. Real consumers tend
//! to have a `#ifdef` fallback when they detect the failure; without
//! the link symbols those consumers can't even build.
//!
//! When the kernel grows a `poll`-style waker, drop in real bodies
//! one entry at a time — the ABI shapes here match Linux verbatim.

#![allow(non_camel_case_types)]

use crate::posix::{c_int, c_void};

pub const ENOSYS: c_int = 38;

#[inline]
unsafe fn enosys_minus_one() -> c_int {
    crate::errno::set_errno(ENOSYS);
    -1
}

// ── poll ────────────────────────────────────────────────────────────

pub type nfds_t = u64;

pub const POLLIN:    i16 = 0x0001;
pub const POLLPRI:   i16 = 0x0002;
pub const POLLOUT:   i16 = 0x0004;
pub const POLLERR:   i16 = 0x0008;
pub const POLLHUP:   i16 = 0x0010;
pub const POLLNVAL:  i16 = 0x0020;
pub const POLLRDHUP: i16 = 0x2000;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct pollfd {
    pub fd:      c_int,
    pub events:  i16,
    pub revents: i16,
}

/// `poll(*fds, nfds, timeout)` — refuse with ENOSYS.
///
/// # Safety
/// Pointer arguments are not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poll(
    _fds:     *mut pollfd,
    _nfds:    nfds_t,
    _timeout: c_int,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { enosys_minus_one() }
}

// ── select ──────────────────────────────────────────────────────────
//
// The `fd_set` shape is the standard 1024-bit bitmap (128 bytes on
// 8-byte words). We surface the macros as no_mangle helpers so a C
// consumer can use the standard names.

pub const FD_SETSIZE: usize = 1024;
const FDS_BITS_LEN: usize = FD_SETSIZE / 64; // 16 u64 words

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct fd_set {
    pub fds_bits: [u64; FDS_BITS_LEN],
}

impl Default for fd_set {
    fn default() -> Self { Self { fds_bits: [0; FDS_BITS_LEN] } }
}

/// `FD_ZERO(set)` — clear every bit. C macros aren't an option
/// across the FFI boundary; we ship as no_mangle fns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn FD_ZERO(set: *mut fd_set) {
    if set.is_null() { return; }
    // SAFETY: caller-supplied writable struct.
    unsafe { *set = fd_set::default(); }
}

/// `FD_SET(fd, set)` — set bit `fd`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn FD_SET(fd: c_int, set: *mut fd_set) {
    if set.is_null() || fd < 0 || fd as usize >= FD_SETSIZE { return; }
    let i = (fd as usize) / 64;
    let b = (fd as usize) % 64;
    // SAFETY: caller-supplied writable struct; index in-range.
    unsafe { (*set).fds_bits[i] |= 1u64 << b; }
}

/// `FD_CLR(fd, set)` — clear bit `fd`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn FD_CLR(fd: c_int, set: *mut fd_set) {
    if set.is_null() || fd < 0 || fd as usize >= FD_SETSIZE { return; }
    let i = (fd as usize) / 64;
    let b = (fd as usize) % 64;
    // SAFETY: caller-supplied writable struct.
    unsafe { (*set).fds_bits[i] &= !(1u64 << b); }
}

/// `FD_ISSET(fd, set)` — non-zero iff bit `fd` is set.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn FD_ISSET(fd: c_int, set: *const fd_set) -> c_int {
    if set.is_null() || fd < 0 || fd as usize >= FD_SETSIZE { return 0; }
    let i = (fd as usize) / 64;
    let b = (fd as usize) % 64;
    // SAFETY: caller-supplied readable struct.
    let bit = unsafe { ((*set).fds_bits[i] >> b) & 1 };
    bit as c_int
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct timeval_select {
    pub tv_sec:  i64,
    pub tv_usec: i64,
}

/// `select(nfds, *readfds, *writefds, *exceptfds, *timeout)` —
/// refuse with ENOSYS.
///
/// # Safety
/// Pointer arguments are not dereferenced.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn select(
    _nfds:      c_int,
    _readfds:   *mut fd_set,
    _writefds:  *mut fd_set,
    _exceptfds: *mut fd_set,
    _timeout:   *mut timeval_select,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { enosys_minus_one() }
}

// ── epoll ───────────────────────────────────────────────────────────

pub const EPOLL_CTL_ADD: c_int = 1;
pub const EPOLL_CTL_DEL: c_int = 2;
pub const EPOLL_CTL_MOD: c_int = 3;

pub const EPOLLIN:  u32 = 0x0001;
pub const EPOLLOUT: u32 = 0x0004;
pub const EPOLLERR: u32 = 0x0008;
pub const EPOLLHUP: u32 = 0x0010;

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct epoll_data {
    pub u64_field: u64,
}

#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default)]
pub struct epoll_event {
    pub events: u32,
    pub data:   epoll_data,
}

/// `epoll_create(size)` — refuse with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_create(_size: c_int) -> c_int {
    // SAFETY: forwarded.
    unsafe { enosys_minus_one() }
}

/// `epoll_create1(flags)` — refuse with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_create1(_flags: c_int) -> c_int {
    // SAFETY: forwarded.
    unsafe { enosys_minus_one() }
}

/// `epoll_ctl(epfd, op, fd, *event)` — refuse with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_ctl(
    _epfd:  c_int,
    _op:    c_int,
    _fd:    c_int,
    _event: *mut epoll_event,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { enosys_minus_one() }
}

/// `epoll_wait(epfd, *events, maxevents, timeout)` — refuse with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_wait(
    _epfd:      c_int,
    _events:    *mut epoll_event,
    _maxevents: c_int,
    _timeout:   c_int,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { enosys_minus_one() }
}

// ── eventfd / timerfd / signalfd ────────────────────────────────────

/// `eventfd(initval, flags)` — refuse with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eventfd(_initval: u32, _flags: c_int) -> c_int {
    // SAFETY: forwarded.
    unsafe { enosys_minus_one() }
}

/// `timerfd_create(clockid, flags)` — refuse with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn timerfd_create(_clockid: c_int, _flags: c_int) -> c_int {
    // SAFETY: forwarded.
    unsafe { enosys_minus_one() }
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct itimerspec {
    pub it_interval: crate::time::timespec,
    pub it_value:    crate::time::timespec,
}

/// `timerfd_settime(fd, flags, *new, *old)` — refuse with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn timerfd_settime(
    _fd:    c_int,
    _flags: c_int,
    _new:   *const itimerspec,
    _old:   *mut itimerspec,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { enosys_minus_one() }
}

/// `timerfd_gettime(fd, *cur)` — refuse with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn timerfd_gettime(_fd: c_int, _cur: *mut itimerspec) -> c_int {
    // SAFETY: forwarded.
    unsafe { enosys_minus_one() }
}

/// `signalfd(fd, *mask, flags)` — refuse with ENOSYS. The `mask`
/// is taken as a `*const c_void` because we don't ship sigset_t in
/// this module.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signalfd(
    _fd:    c_int,
    _mask:  *const c_void,
    _flags: c_int,
) -> c_int {
    // SAFETY: forwarded.
    unsafe { enosys_minus_one() }
}

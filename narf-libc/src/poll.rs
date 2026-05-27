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

/// `poll(*fds, nfds, timeout)` — wait for events on the given fds.
///
/// The kernel side does single-shot polls + parks the task ~1ms
/// when nothing is ready; we loop here until either an event
/// arrives or the user-supplied timeout elapses. This mirrors how
/// libc::pthread_join wraps narf_user_runtime::futex_wait.
///
/// # Safety
/// `fds` must point at a writable array of `nfds` `pollfd` records.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn poll(
    fds:     *mut pollfd,
    nfds:    nfds_t,
    timeout: c_int,
) -> c_int {
    if fds.is_null() && nfds != 0 {
        crate::errno::set_errno(22 /* EINVAL */);
        return -1;
    }
    // Compute an absolute deadline if a positive timeout was given;
    // -1 = block forever, 0 = single non-blocking poll, > 0 = ms.
    let mut ts = crate::time::timespec { tv_sec: 0, tv_nsec: 0 };
    let _ = unsafe { crate::time::clock_gettime(1 /* CLOCK_MONOTONIC */, &mut ts as *mut _) };
    let now_ns = (ts.tv_sec as u64).saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64);
    let deadline_ns: Option<u64> = match timeout {
        n if n < 0 => None,
        0 => Some(now_ns), // immediate
        n => Some(now_ns.saturating_add((n as u64).saturating_mul(1_000_000))),
    };
    loop {
        // Single-shot kernel poll — returns the count of ready fds
        // (>= 0) or -1 on error. The kernel itself parks the task
        // ~1ms when nothing's ready; that yield is what lets other
        // tasks make progress.
        let r = narf_user_runtime::poll(fds as *mut u8, nfds as usize, 0);
        if r > 0 {
            return r;
        }
        if r < 0 {
            crate::errno::set_errno(22);
            return -1;
        }
        // r == 0: nothing ready. Check the user-side timeout.
        if let Some(dl) = deadline_ns {
            let mut ts = crate::time::timespec { tv_sec: 0, tv_nsec: 0 };
            let _ = unsafe { crate::time::clock_gettime(1, &mut ts as *mut _) };
            let now = (ts.tv_sec as u64).saturating_mul(1_000_000_000)
                .saturating_add(ts.tv_nsec as u64);
            if now >= dl {
                return 0;
            }
        }
        // Yield ~1ms so the parked task gets de-prioritised.
        let _ = unsafe { crate::process::usleep(1000) };
    }
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
/// translate to a `poll()` call. Builds a temporary pollfd array
/// covering [0..nfds), maps fd_set bits to POLLIN/POLLOUT/POLLPRI,
/// then writes the result back into the fd_sets.
///
/// # Safety
/// All non-NULL arguments must point at valid storage of the
/// declared shape.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn select(
    nfds:      c_int,
    readfds:   *mut fd_set,
    writefds:  *mut fd_set,
    exceptfds: *mut fd_set,
    timeout:   *mut timeval_select,
) -> c_int {
    if nfds < 0 || nfds as usize > FD_SETSIZE {
        crate::errno::set_errno(22 /* EINVAL */);
        return -1;
    }
    let n = nfds as usize;
    // Build pollfd[].
    let mut pf = [pollfd { fd: 0, events: 0, revents: 0 }; FD_SETSIZE];
    let mut count: usize = 0;
    for fd in 0..n {
        let want_r = !readfds.is_null() && unsafe { FD_ISSET(fd as c_int, readfds) } != 0;
        let want_w = !writefds.is_null() && unsafe { FD_ISSET(fd as c_int, writefds) } != 0;
        let want_e = !exceptfds.is_null() && unsafe { FD_ISSET(fd as c_int, exceptfds) } != 0;
        if !want_r && !want_w && !want_e { continue; }
        let mut events = 0i16;
        if want_r { events |= POLLIN; }
        if want_w { events |= POLLOUT; }
        if want_e { events |= POLLPRI; }
        pf[count] = pollfd { fd: fd as c_int, events, revents: 0 };
        count += 1;
    }
    let timeout_ms: c_int = if timeout.is_null() {
        -1
    } else {
        // SAFETY: caller-provided timeval pointer.
        let t = unsafe { *timeout };
        let total_us = t.tv_sec.saturating_mul(1_000_000).saturating_add(t.tv_usec);
        ((total_us / 1000) as c_int).max(0)
    };
    let r = narf_user_runtime::poll(pf.as_mut_ptr() as *mut u8, count, timeout_ms);
    if r < 0 {
        crate::errno::set_errno(22 /* EINVAL */);
        return -1;
    }
    // Clear the user fd_sets and re-populate from revents.
    if !readfds.is_null() { unsafe { FD_ZERO(readfds); } }
    if !writefds.is_null() { unsafe { FD_ZERO(writefds); } }
    if !exceptfds.is_null() { unsafe { FD_ZERO(exceptfds); } }
    let mut hits = 0;
    for i in 0..count {
        let p = pf[i];
        if p.revents == 0 { continue; }
        if (p.revents & POLLIN) != 0 && !readfds.is_null() {
            unsafe { FD_SET(p.fd, readfds); }
        }
        if (p.revents & POLLOUT) != 0 && !writefds.is_null() {
            unsafe { FD_SET(p.fd, writefds); }
        }
        if (p.revents & POLLPRI) != 0 && !exceptfds.is_null() {
            unsafe { FD_SET(p.fd, exceptfds); }
        }
        hits += 1;
    }
    hits
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

/// `epoll_create(size)` — `size` is ignored per Linux 2.6.8+;
/// equivalent to `epoll_create1(0)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_create(_size: c_int) -> c_int {
    narf_user_runtime::epoll_create(0)
}

/// `epoll_create1(flags)` — create a new epoll fd.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_create1(flags: c_int) -> c_int {
    narf_user_runtime::epoll_create(flags as u32)
}

/// `epoll_ctl(epfd, op, fd, *event)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_ctl(
    epfd:  c_int,
    op:    c_int,
    fd:    c_int,
    event: *mut epoll_event,
) -> c_int {
    let r = narf_user_runtime::epoll_ctl(epfd, op as u32, fd, event as *const u8);
    if r < 0 { crate::errno::set_errno(22); }
    r
}

/// `epoll_wait(epfd, *events, maxevents, timeout)`. Loops the
/// kernel single-shot epoll_wait + user-side timeout the same way
/// `poll()` does.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn epoll_wait(
    epfd:      c_int,
    events:    *mut epoll_event,
    maxevents: c_int,
    timeout:   c_int,
) -> c_int {
    let mut ts = crate::time::timespec { tv_sec: 0, tv_nsec: 0 };
    let _ = unsafe { crate::time::clock_gettime(1, &mut ts as *mut _) };
    let now_ns = (ts.tv_sec as u64).saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64);
    let deadline_ns: Option<u64> = match timeout {
        n if n < 0 => None,
        0 => Some(now_ns),
        n => Some(now_ns.saturating_add((n as u64).saturating_mul(1_000_000))),
    };
    loop {
        let r = narf_user_runtime::epoll_wait(epfd, events as *mut u8, maxevents, 0);
        if r > 0 { return r; }
        if r < 0 { crate::errno::set_errno(22); return -1; }
        if let Some(dl) = deadline_ns {
            let mut ts = crate::time::timespec { tv_sec: 0, tv_nsec: 0 };
            let _ = unsafe { crate::time::clock_gettime(1, &mut ts as *mut _) };
            let now = (ts.tv_sec as u64).saturating_mul(1_000_000_000)
                .saturating_add(ts.tv_nsec as u64);
            if now >= dl { return 0; }
        }
        let _ = unsafe { crate::process::usleep(1000) };
    }
}

// ── eventfd / timerfd / signalfd ────────────────────────────────────

/// `eventfd(initval, flags)` — counter-backed event fd.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eventfd(initval: u32, flags: c_int) -> c_int {
    narf_user_runtime::eventfd(initval as u64, flags as u32)
}

/// `timerfd_create(clockid, flags)` — timer-backed fd.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn timerfd_create(clockid: c_int, flags: c_int) -> c_int {
    narf_user_runtime::timerfd_create(clockid as u32, flags as u32)
}

#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct itimerspec {
    pub it_interval: crate::time::timespec,
    pub it_value:    crate::time::timespec,
}

/// `timerfd_settime(fd, flags, *new, *old)` — arm the timer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn timerfd_settime(
    fd:    c_int,
    flags: c_int,
    new:   *const itimerspec,
    old:   *mut itimerspec,
) -> c_int {
    let r = narf_user_runtime::timerfd_settime(
        fd,
        flags as u32,
        new as *const u8,
        old as *mut u8,
    );
    if r < 0 { crate::errno::set_errno(22); }
    r
}

/// `timerfd_gettime(fd, *cur)` — refuse with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn timerfd_gettime(_fd: c_int, _cur: *mut itimerspec) -> c_int {
    // SAFETY: forwarded.
    unsafe { enosys_minus_one() }
}

/// `signalfd(fd, *mask, flags)` — receive signals via an fd.
/// `mask` is a `sigset_t`-shaped 8-byte bitmask.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signalfd(
    fd:    c_int,
    mask:  *const c_void,
    flags: c_int,
) -> c_int {
    let r = narf_user_runtime::signalfd(
        fd,
        mask as *const u64,
        8,
        flags as u32,
    );
    if r < 0 { crate::errno::set_errno(22); }
    r
}

/// `signalfd4(fd, mask, sizemask, flags)` — Linux explicit-size
/// variant (the SYS_SIGNALFD wire ABI). musl/glibc both keep
/// signalfd() as a wrapper that passes 8 for sizemask. We expose
/// the explicit form so a consumer can call it directly.
///
/// Reference: musl `src/signal/signalfd.c`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signalfd4(
    fd:       c_int,
    mask:     *const c_void,
    sizemask: usize,
    flags:    c_int,
) -> c_int {
    let r = narf_user_runtime::signalfd(
        fd,
        mask as *const u64,
        sizemask,
        flags as u32,
    );
    if r < 0 { crate::errno::set_errno(22); }
    r
}

/// `eventfd2(initval, flags)` — Linux explicit-flags variant. The
/// glibc `eventfd()` wrapper passes 0 for flags; eventfd2 lets the
/// caller pass EFD_CLOEXEC / EFD_NONBLOCK / EFD_SEMAPHORE through.
///
/// Reference: musl `src/linux/eventfd.c`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn eventfd2(initval: u32, flags: c_int) -> c_int {
    narf_user_runtime::eventfd(initval as u64, flags as u32)
}

// ── POSIX timers (timer_create / settime / gettime / delete) ────

/// `timer_t` — opaque handle. Internally an index into a small
/// per-process table; the table entry stores the backing timerfd
/// + the sigevent metadata.
pub type timer_t = i32;

/// `<signal.h>` `union sigval` — opaque pointer/int.
#[repr(C)]
#[derive(Copy, Clone)]
pub union sigval {
    pub sival_int: c_int,
    pub sival_ptr: *mut core::ffi::c_void,
}

impl Default for sigval {
    fn default() -> Self { Self { sival_int: 0 } }
}

/// `<signal.h>` `struct sigevent` — describes how the timer
/// notifies the process on expiry.
#[repr(C)]
pub struct sigevent {
    pub sigev_value:    sigval,
    pub sigev_signo:    c_int,
    pub sigev_notify:   c_int,
    pub sigev_pad:      [u8; 52],
}

pub const SIGEV_SIGNAL: c_int = 0;
pub const SIGEV_NONE:   c_int = 1;
pub const SIGEV_THREAD: c_int = 2;

/// Per-process timer table. Each slot holds the kernel timerfd
/// + the signum to deliver on expiry (or 0 for SIGEV_NONE).
struct PosixTimer {
    timerfd: c_int,
    signum:  c_int,
}

const MAX_POSIX_TIMERS: usize = 32;
static mut POSIX_TIMERS: [Option<PosixTimer>; MAX_POSIX_TIMERS] =
    [const { None }; MAX_POSIX_TIMERS];

/// `timer_create(clockid, evp, timerid)` — allocate a timer.
///
/// # Safety
/// `timerid` must be writable; `evp` (when non-null) must point at
/// a valid sigevent.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn timer_create(
    clockid: c_int,
    evp:     *const sigevent,
    timerid: *mut timer_t,
) -> c_int {
    if timerid.is_null() {
        return -1;
    }
    let signum = if evp.is_null() {
        14 /* SIGALRM — POSIX default for timer_create */
    } else {
        unsafe {
            if (*evp).sigev_notify == SIGEV_NONE {
                0
            } else {
                (*evp).sigev_signo
            }
        }
    };
    // Allocate the underlying timerfd kernel-side.
    let tfd = narf_user_runtime::timerfd_create(clockid as u32, 0);
    if tfd < 0 {
        return -1;
    }
    // Take the next free slot.
    // SAFETY: single-threaded user mode invariant.
    let slot = unsafe {
        let mut found: Option<usize> = None;
        for i in 0..MAX_POSIX_TIMERS {
            if POSIX_TIMERS[i].is_none() {
                POSIX_TIMERS[i] = Some(PosixTimer { timerfd: tfd, signum });
                found = Some(i);
                break;
            }
        }
        found
    };
    let id = match slot {
        Some(i) => i as timer_t,
        None => {
            crate::errno::set_errno(11); // EAGAIN
            return -1;
        }
    };
    unsafe { *timerid = id; }
    0
}

/// `timer_settime(timerid, flags, new_value, old_value)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn timer_settime(
    timerid: timer_t,
    flags:   c_int,
    new_value: *const itimerspec,
    old_value: *mut itimerspec,
) -> c_int {
    if (timerid as usize) >= MAX_POSIX_TIMERS {
        return -1;
    }
    let tfd = unsafe {
        match &POSIX_TIMERS[timerid as usize] {
            Some(t) => t.timerfd,
            None => return -1,
        }
    };
    narf_user_runtime::timerfd_settime(
        tfd,
        flags as u32,
        new_value as *const u8,
        old_value as *mut u8,
    )
}

/// `timer_gettime(timerid, cur)` — query remaining time. Stage-1
/// returns zeros (the kernel doesn't yet expose timerfd_gettime).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn timer_gettime(
    _timerid: timer_t,
    cur:      *mut itimerspec,
) -> c_int {
    if cur.is_null() { return -1; }
    unsafe { *cur = itimerspec::default(); }
    0
}

/// `timer_delete(timerid)` — release.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn timer_delete(timerid: timer_t) -> c_int {
    if (timerid as usize) >= MAX_POSIX_TIMERS {
        return -1;
    }
    let tfd = unsafe {
        match POSIX_TIMERS[timerid as usize].take() {
            Some(t) => t.timerfd,
            None => return -1,
        }
    };
    let _ = unsafe { crate::posix::close(tfd) };
    0
}

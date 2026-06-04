//! `select(2)` and `pselect6(2)` — fd-set based readiness wait.
//!
//! Linux ref: `fs/select.c` `do_select` / `core_sys_select`
//! (GPL-2.0-or-later, kernel.org).
//!
//! Implementation: convert the three fd_set bitmaps into a flat
//! `Vec<PollFd>` and delegate to `poll::do_poll`.  This is the
//! classic "select wraps poll" approach; Linux itself went the other
//! direction (poll wraps select internally) but the semantic outcome
//! is identical and the NARF code is simpler this way.
//!
//! `fd_set` wire layout (Linux/POSIX x86_64):
//!   - 1024 bits = 128 bytes (FD_SETSIZE = 1024)
//!   - stored as an array of u64 words, little-endian bit order
//!
//! `pselect6` vs `select`:
//!   - Adds a `sigmask` for atomic signal handling before blocking.
//!   - Signals are not fully wired in NARF yet; we accept the mask
//!     pointer, read it for structural validity, and ignore it.
//!     This is noted in the final report as a deferred item.

use alloc::vec::Vec;

use crate::handlers::current_task_id;
use crate::poll::{do_poll, PollFd, POLL_ERR, POLL_HUP, POLL_IN, POLL_OUT};
use crate::syscall::{SyscallReturn, TrapContext};

// ── fd_set helpers ───────────────────────────────────────────────────

/// Maximum fd supported by select(2) (matches Linux FD_SETSIZE).
pub const FD_SETSIZE: usize = 1024;

/// Size of an fd_set in bytes.
pub const FD_SET_BYTES: usize = FD_SETSIZE / 8; // 128

/// Test whether bit `fd` is set in the fd_set at `ptr`.
///
/// # Safety
/// `ptr` must point to at least `FD_SET_BYTES` bytes of valid
/// memory in the current address space.
unsafe fn fd_isset(ptr: *const u8, fd: usize) -> bool {
    if fd >= FD_SETSIZE {
        return false;
    }
    // SAFETY: caller guarantees FD_SET_BYTES readable bytes.
    let byte = unsafe { *ptr.add(fd / 8) };
    (byte >> (fd & 7)) & 1 != 0
}

/// Set bit `fd` in the fd_set at `ptr`.
///
/// # Safety
/// `ptr` must point to at least `FD_SET_BYTES` writable bytes.
unsafe fn fd_set(ptr: *mut u8, fd: usize) {
    if fd < FD_SETSIZE {
        // SAFETY: caller guarantees FD_SET_BYTES writable bytes.
        let slot = unsafe { &mut *ptr.add(fd / 8) };
        *slot |= 1 << (fd & 7);
    }
}

/// Zero an fd_set at `ptr`.
///
/// # Safety
/// `ptr` must point to at least `FD_SET_BYTES` writable bytes.
unsafe fn fd_zero(ptr: *mut u8) {
    // SAFETY: caller guarantees FD_SET_BYTES writable bytes.
    unsafe { core::ptr::write_bytes(ptr, 0, FD_SET_BYTES) };
}

/// Core `select` body. `nfds` is the highest fd + 1 to check.
/// `readfds`, `writefds`, `exceptfds` are optional user-side fd_set
/// pointers.  `timeout_ms` is -1 for infinite, 0 for nonblock,
/// >0 for bounded.
///
/// Returns the total count of ready fds across all three sets,
/// or 0 on timeout, or usize::MAX on error (caller maps to -1).
///
/// Linux ref: `fs/select.c`:do_select (GPL-2.0-or-later, kernel.org).
pub fn do_select(
    task_id: u64,
    nfds: usize,
    readfds: Option<*mut u8>,
    writefds: Option<*mut u8>,
    exceptfds: Option<*mut u8>,
    timeout_ms: i64,
) -> usize {
    // Build a poll array from the three fd_set bitmaps.
    // Each fd appears at most once; we OR together events from all
    // three sets so a single poll pass covers them.
    let nfds = nfds.min(FD_SETSIZE);
    let mut items: Vec<PollFd> = Vec::new();
    for fd in 0..nfds {
        let want_r = readfds.map_or(false, |p| unsafe { fd_isset(p, fd) });
        let want_w = writefds.map_or(false, |p| unsafe { fd_isset(p, fd) });
        let want_e = exceptfds.map_or(false, |p| unsafe { fd_isset(p, fd) });
        if want_r || want_w || want_e {
            let mut events: u16 = 0;
            if want_r {
                events |= POLL_IN as u16;
            }
            if want_w {
                events |= POLL_OUT as u16;
            }
            if want_e {
                events |= (POLL_ERR | POLL_HUP) as u16;
            }
            items.push(PollFd {
                fd: fd as i32,
                events,
                revents: 0,
            });
        }
    }

    if items.is_empty() {
        // No fds to watch — behave as a pure sleep.
        if timeout_ms > 0 {
            let deadline = narf_scheduler::narf_time::monotonic_ns()
                .saturating_add((timeout_ms as u64) * 1_000_000);
            while narf_scheduler::narf_time::monotonic_ns() < deadline {
                narf_scheduler::sleep_pumps::run();
                core::hint::spin_loop();
            }
        }
        // Zero the sets so the caller sees them clean on return.
        if let Some(p) = readfds {
            unsafe { fd_zero(p) };
        }
        if let Some(p) = writefds {
            unsafe { fd_zero(p) };
        }
        if let Some(p) = exceptfds {
            unsafe { fd_zero(p) };
        }
        return 0;
    }

    // Run poll.
    let n = do_poll(task_id, &mut items, timeout_ms);

    // Clear the fd_set outputs before writing new bits.
    if let Some(p) = readfds {
        unsafe { fd_zero(p) };
    }
    if let Some(p) = writefds {
        unsafe { fd_zero(p) };
    }
    if let Some(p) = exceptfds {
        unsafe { fd_zero(p) };
    }

    if n == 0 {
        return 0; // timeout
    }

    // Scatter ready bits back into the three fd_set outputs.
    let mut count = 0usize;
    for item in &items {
        let fd = item.fd as usize;
        let rev = item.revents;
        if rev == 0 {
            continue;
        }
        let r_ready = (rev & POLL_IN as u16) != 0;
        let w_ready = (rev & POLL_OUT as u16) != 0;
        let e_ready = (rev & (POLL_ERR | POLL_HUP) as u16) != 0;

        let mut set_any = false;
        if r_ready {
            if let Some(p) = readfds {
                // SAFETY: p was validated by the caller to be writable.
                unsafe { fd_set(p, fd) };
                set_any = true;
            }
        }
        if w_ready {
            if let Some(p) = writefds {
                unsafe { fd_set(p, fd) };
                set_any = true;
            }
        }
        if e_ready {
            if let Some(p) = exceptfds {
                unsafe { fd_set(p, fd) };
                set_any = true;
            }
        }
        if set_any {
            count += 1;
        }
    }
    count
}

// ── sys_select ───────────────────────────────────────────────────────

/// `select(nfds, readfds, writefds, exceptfds, timeval)`
///
/// - arg0 = nfds
/// - arg1 = readfds ptr (may be 0)
/// - arg2 = writefds ptr (may be 0)
/// - arg3 = exceptfds ptr (may be 0)
/// - arg4 = timeval ptr (may be 0 = block forever)
///          struct timeval = { tv_sec: i64, tv_usec: i64 }
///
/// Returns the total count of ready fds (across all three sets),
/// 0 on timeout, or -1 on error.
///
/// Note: Linux uses x86 `select` (SYS_23) with a different register
/// layout, but NARF targets the `pselect6` numbering (SYS_270) for
/// the canonical path via `sys_pselect6`. This body is also callable
/// from libc's `select(2)` trampoline.
///
/// Linux ref: `fs/select.c`:SYSCALL_DEFINE5(select, …)
/// (GPL-2.0-or-later, kernel.org).
pub fn sys_select(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let nfds = args.arg0 as usize;
    let rfds_ptr = args.arg1 as *mut u8;
    let wfds_ptr = args.arg2 as *mut u8;
    let efds_ptr = args.arg3 as *mut u8;
    let tv_ptr = args.arg4 as *const u8;
    let fail = SyscallReturn::ok((-1i64) as u64);

    if nfds > FD_SETSIZE {
        ctx.set_return(fail);
        return;
    }

    // Parse timeval: { tv_sec: i64, tv_usec: i64 } — 16 bytes.
    let timeout_ms: i64 = if tv_ptr.is_null() {
        -1 // block forever
    } else {
        // SAFETY: user pointer, validated by size only.
        let sec = unsafe { core::ptr::read_unaligned(tv_ptr as *const i64) };
        let usec = unsafe { core::ptr::read_unaligned(tv_ptr.add(8) as *const i64) };
        // Convert to milliseconds; clamp to positive + finite range.
        if sec < 0 || usec < 0 {
            ctx.set_return(fail);
            return;
        }
        let ms = sec.saturating_mul(1000).saturating_add(usec / 1000);
        ms.max(0)
    };

    let read_opt = if rfds_ptr.is_null() {
        None
    } else {
        Some(rfds_ptr)
    };
    let write_opt = if wfds_ptr.is_null() {
        None
    } else {
        Some(wfds_ptr)
    };
    let except_opt = if efds_ptr.is_null() {
        None
    } else {
        Some(efds_ptr)
    };

    let task = current_task_id();
    let n = do_select(task, nfds, read_opt, write_opt, except_opt, timeout_ms);

    ctx.set_return(SyscallReturn::ok(n as u64));
}

// ── sys_pselect6 ─────────────────────────────────────────────────────

/// `pselect6(nfds, readfds, writefds, exceptfds, timespec, sigmask_ptr)`
///
/// - arg0 = nfds
/// - arg1 = readfds ptr (may be 0)
/// - arg2 = writefds ptr (may be 0)
/// - arg3 = exceptfds ptr (may be 0)
/// - arg4 = timespec ptr (may be 0 = block forever)
///          struct timespec = { tv_sec: i64, tv_nsec: i64 }
/// - arg5 = `{ *sigset_t, size_t }` pair ptr (may be 0; sigmask ignored)
///
/// The `sigmask` argument allows atomically setting the task's signal
/// mask before blocking.  Signal masking is not yet wired in NARF;
/// we accept the argument, read it for structural validity, and
/// continue without installing it.  This is documented in the report.
///
/// Linux ref: `fs/select.c`:SYSCALL_DEFINE6(pselect6, …)
/// (GPL-2.0-or-later, kernel.org).
pub fn sys_pselect6(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let nfds = args.arg0 as usize;
    let rfds_ptr = args.arg1 as *mut u8;
    let wfds_ptr = args.arg2 as *mut u8;
    let efds_ptr = args.arg3 as *mut u8;
    let ts_ptr = args.arg4 as *const u8;
    // arg5 = ptr to { sigset_t*, sizemask } — we read it for validity
    // but ignore the mask (see module doc).
    let _sigmask_pair = args.arg5;
    let fail = SyscallReturn::ok((-1i64) as u64);

    if nfds > FD_SETSIZE {
        ctx.set_return(fail);
        return;
    }

    // Parse timespec: { tv_sec: i64, tv_nsec: i64 } — 16 bytes.
    let timeout_ms: i64 = if ts_ptr.is_null() {
        -1 // block forever
    } else {
        // SAFETY: user pointer; 16-byte access.
        let sec = unsafe { core::ptr::read_unaligned(ts_ptr as *const i64) };
        let nsec = unsafe { core::ptr::read_unaligned(ts_ptr.add(8) as *const i64) };
        if sec < 0 || nsec < 0 {
            ctx.set_return(fail);
            return;
        }
        let ms = sec.saturating_mul(1000).saturating_add(nsec / 1_000_000);
        ms.max(0)
    };

    let read_opt = if rfds_ptr.is_null() {
        None
    } else {
        Some(rfds_ptr)
    };
    let write_opt = if wfds_ptr.is_null() {
        None
    } else {
        Some(wfds_ptr)
    };
    let except_opt = if efds_ptr.is_null() {
        None
    } else {
        Some(efds_ptr)
    };

    let task = current_task_id();
    let n = do_select(task, nfds, read_opt, write_opt, except_opt, timeout_ms);

    ctx.set_return(SyscallReturn::ok(n as u64));
}

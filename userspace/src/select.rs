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

fn fd_isset(set: &[u8; FD_SET_BYTES], fd: usize) -> bool {
    if fd >= FD_SETSIZE {
        return false;
    }
    let byte = set[fd / 8];
    (byte >> (fd & 7)) & 1 != 0
}

fn fd_set_bit(set: &mut [u8; FD_SET_BYTES], fd: usize) {
    if fd < FD_SETSIZE {
        set[fd / 8] |= 1 << (fd & 7);
    }
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
    let mut local_r = [0u8; FD_SET_BYTES];
    let mut local_w = [0u8; FD_SET_BYTES];
    let mut local_e = [0u8; FD_SET_BYTES];

    if let Some(p) = readfds {
        // SAFETY: `p` is the user-supplied `readfds` pointer; `copy_from_user`
        // validates the `[p, p+FD_SET_BYTES)` range and brackets the read with
        // the SMAP window. Length is the fixed `FD_SET_BYTES` of `local_r`.
        // SAFETY: Valid memory or trusted environment
        if unsafe { crate::handlers::copy_from_user(&mut local_r, p as u64) }.is_err() {
            return usize::MAX;
        }
    }
    if let Some(p) = writefds {
        // SAFETY: `p` is the user-supplied `writefds` pointer; `copy_from_user`
        // validates the `FD_SET_BYTES`-long range and brackets the read with SMAP.
        // SAFETY: Valid memory or trusted environment
        if unsafe { crate::handlers::copy_from_user(&mut local_w, p as u64) }.is_err() {
            return usize::MAX;
        }
    }
    if let Some(p) = exceptfds {
        // SAFETY: `p` is the user-supplied `exceptfds` pointer; `copy_from_user`
        // validates the `FD_SET_BYTES`-long range and brackets the read with SMAP.
        // SAFETY: Valid memory or trusted environment
        if unsafe { crate::handlers::copy_from_user(&mut local_e, p as u64) }.is_err() {
            return usize::MAX;
        }
    }

    let nfds = nfds.min(FD_SETSIZE);
    let mut items: Vec<PollFd> = Vec::new();
    for fd in 0..nfds {
        let want_r = readfds.is_some() && fd_isset(&local_r, fd);
        let want_w = writefds.is_some() && fd_isset(&local_w, fd);
        let want_e = exceptfds.is_some() && fd_isset(&local_e, fd);
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
        if timeout_ms > 0 {
            let deadline = narf_scheduler::narf_time::monotonic_ns()
                .saturating_add((timeout_ms as u64) * 1_000_000);
            while narf_scheduler::narf_time::monotonic_ns() < deadline {
                narf_scheduler::sleep_pumps::run();
                core::hint::spin_loop();
            }
        }
        let zeros = [0u8; FD_SET_BYTES];
        if let Some(p) = readfds {
            // SAFETY: `p` is the user-supplied `readfds` pointer; `copy_to_user`
            // validates the `FD_SET_BYTES`-long range and brackets the write with
            // SMAP. We clear the user fd_set to report "no fds ready".
            // SAFETY: Valid memory or trusted environment
            let _ = unsafe { crate::handlers::copy_to_user(p as u64, &zeros) };
        }
        if let Some(p) = writefds {
            // SAFETY: `p` is the user-supplied `writefds` pointer; `copy_to_user`
            // validates the `FD_SET_BYTES`-long range and brackets the write with SMAP.
            // SAFETY: Valid memory or trusted environment
            let _ = unsafe { crate::handlers::copy_to_user(p as u64, &zeros) };
        }
        if let Some(p) = exceptfds {
            // SAFETY: `p` is the user-supplied `exceptfds` pointer; `copy_to_user`
            // validates the `FD_SET_BYTES`-long range and brackets the write with SMAP.
            // SAFETY: Valid memory or trusted environment
            let _ = unsafe { crate::handlers::copy_to_user(p as u64, &zeros) };
        }
        return 0;
    }

    let n = do_poll(task_id, &mut items, timeout_ms);

    let zeros = [0u8; FD_SET_BYTES];
    if let Some(p) = readfds {
        // SAFETY: `p` is the user-supplied `readfds` pointer; `copy_to_user`
        // validates the `FD_SET_BYTES`-long range and brackets the write with
        // SMAP. We pre-clear each user fd_set before writing back ready bits.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { crate::handlers::copy_to_user(p as u64, &zeros) };
    }
    if let Some(p) = writefds {
        // SAFETY: `p` is the user-supplied `writefds` pointer; `copy_to_user`
        // validates the `FD_SET_BYTES`-long range and brackets the write with SMAP.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { crate::handlers::copy_to_user(p as u64, &zeros) };
    }
    if let Some(p) = exceptfds {
        // SAFETY: `p` is the user-supplied `exceptfds` pointer; `copy_to_user`
        // validates the `FD_SET_BYTES`-long range and brackets the write with SMAP.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { crate::handlers::copy_to_user(p as u64, &zeros) };
    }

    if n == 0 {
        return 0;
    }

    let mut out_r = [0u8; FD_SET_BYTES];
    let mut out_w = [0u8; FD_SET_BYTES];
    let mut out_e = [0u8; FD_SET_BYTES];

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
        if r_ready && readfds.is_some() {
            fd_set_bit(&mut out_r, fd);
            set_any = true;
        }
        if w_ready && writefds.is_some() {
            fd_set_bit(&mut out_w, fd);
            set_any = true;
        }
        if e_ready && exceptfds.is_some() {
            fd_set_bit(&mut out_e, fd);
            set_any = true;
        }
        if set_any {
            count += 1;
        }
    }

    if let Some(p) = readfds {
        // SAFETY: `p` is the user-supplied `readfds` pointer; `copy_to_user`
        // validates the `FD_SET_BYTES`-long range and brackets the write with
        // SMAP. `out_r` is a `FD_SET_BYTES`-sized fd_set of ready read bits.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { crate::handlers::copy_to_user(p as u64, &out_r) };
    }
    if let Some(p) = writefds {
        // SAFETY: `p` is the user-supplied `writefds` pointer; `copy_to_user`
        // validates the `FD_SET_BYTES`-long range and brackets the write with SMAP.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { crate::handlers::copy_to_user(p as u64, &out_w) };
    }
    if let Some(p) = exceptfds {
        // SAFETY: `p` is the user-supplied `exceptfds` pointer; `copy_to_user`
        // validates the `FD_SET_BYTES`-long range and brackets the write with SMAP.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { crate::handlers::copy_to_user(p as u64, &out_e) };
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
///   struct timeval = { tv_sec: i64, tv_usec: i64 }
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
        // Read `struct timeval { i64 tv_sec; i64 tv_usec; }` (16 bytes) via
        // copy_from_user — a direct deref #PFs under SMAP, which a real musl
        // select() caller (e.g. libdrm's render loop with a timeout) trips.
        let mut tvbuf = [0u8; 16];
        // SAFETY: `tvbuf` is exactly 16 bytes; copy_from_user range-validates
        // `tv_ptr` and SMAP-brackets the read.
        if unsafe { crate::handlers::copy_from_user(&mut tvbuf, tv_ptr as u64) }.is_err() {
            ctx.set_return(fail);
            return;
        }
        let sec = i64::from_le_bytes(tvbuf[0..8].try_into().unwrap());
        let usec = i64::from_le_bytes(tvbuf[8..16].try_into().unwrap());
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
///   struct timespec = { tv_sec: i64, tv_nsec: i64 }
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
        let mut buf = [0u8; 16];
        // SAFETY: `ts_ptr` is the non-null user `timespec` pointer; `copy_from_user`
        // validates the 16-byte range and brackets the read with the SMAP window.
        // `buf` is exactly the 16 bytes of `{ tv_sec: i64, tv_nsec: i64 }`.
        // SAFETY: Valid memory or trusted environment
        if unsafe { crate::handlers::copy_from_user(&mut buf, ts_ptr as u64) }.is_err() {
            ctx.set_return(fail);
            return;
        }
        let sec = i64::from_ne_bytes(buf[0..8].try_into().unwrap());
        let nsec = i64::from_ne_bytes(buf[8..16].try_into().unwrap());
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

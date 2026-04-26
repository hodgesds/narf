//! `<signal.h>` — `signal(2)` user-side handler installation.
//!
//! The kernel's synchronous signal-delivery path (see
//! `userspace::handlers::default_sync_signal_delivery`) and the
//! `Sigaction` syscall (152) are already wired. This module adds
//! the C-shaped `signal()` accessor a real consumer expects.
//!
//! `sigaction()` proper (with the `struct sigaction` shape carrying
//! mask + flags) is a follow-up — relibc programs typically call
//! the simpler `signal()` and let libc translate. We expose
//! `signal()` directly against the kernel's `Sigaction` syscall so
//! a downstream binary can install a handler in one call.

#![allow(non_camel_case_types)]

use crate::posix::c_int;

pub type sighandler_t = unsafe extern "C" fn(c_int);

/// `SIG_DFL` — restore default disposition. Wire value 0 so the
/// kernel's Sigaction handler clears the slot.
pub const SIG_DFL_RAW: usize = 0;

/// `SIG_IGN` — discard signals. Today the kernel doesn't have a
/// dedicated "ignore" sentinel; we surface the value so callers can
/// install it and the kernel's default-delivery path falls through
/// silently. A future kernel may special-case the value.
pub const SIG_IGN_RAW: usize = 1;

/// POSIX signal numbers we expose. The kernel's vector→signum
/// mapping in `sys_signal_dispatch` already uses these values.
pub const SIGHUP:  c_int = 1;
pub const SIGINT:  c_int = 2;
pub const SIGQUIT: c_int = 3;
pub const SIGILL:  c_int = 4;
pub const SIGABRT: c_int = 6;
pub const SIGFPE:  c_int = 8;
pub const SIGKILL: c_int = 9;
pub const SIGSEGV: c_int = 11;
pub const SIGPIPE: c_int = 13;
pub const SIGALRM: c_int = 14;
pub const SIGTERM: c_int = 15;
pub const SIGCHLD: c_int = 17;

/// `signal(signum, handler) -> prior_handler`. Returns the prior
/// handler value (raw `usize`) cast back to `sighandler_t`. The
/// caller compares against `SIG_DFL_RAW` / `SIG_IGN_RAW` to detect
/// the special slots.
///
/// # Safety
/// `handler` must remain a valid code-page entry-point address for
/// the lifetime of the program (or `SIG_DFL_RAW` / `SIG_IGN_RAW`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal(signum: c_int, handler: usize) -> usize {
    if signum < 0 {
        return 0;
    }
    // SAFETY: caller contract on `handler`; the runtime wrapper
    // forwards into `SYS_SIGACTION` and writes the prior value.
    unsafe { narf_user_runtime::sigaction(signum as u32, handler) }
}

/// `kill(pid, signum)`. Returns 0 on success, -1 on failure.
///
/// # Safety
/// Pure delegate to the kernel; no in-process invariants violated.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn kill(pid: i64, signum: c_int) -> c_int {
    if signum < 0 {
        return -1;
    }
    match narf_user_runtime::kill(pid as u64, signum as u32) {
        Ok(()) => 0,
        Err(()) => -1,
    }
}

/// `raise(signum)` — POSIX shortcut for `kill(getpid(), signum)`.
///
/// # Safety
/// Pure delegate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn raise(signum: c_int) -> c_int {
    let pid = narf_user_runtime::getpid();
    // SAFETY: getpid result is a valid wire pid.
    unsafe { kill(pid as i64, signum) }
}

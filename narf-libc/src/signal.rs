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

/// Maximum signal number we keep a per-task slot for. Matches the
/// kernel's NSIG = 32 (POSIX-2017 § <signal.h>).
const NSIG: usize = 32;

/// User-installed handler table. Indexed by signum; `None` means
/// SIG_DFL (no handler — kernel default disposition). The kernel
/// itself sees `__libc_signal_trampoline` as the registered
/// handler for every signum a user installs; the trampoline reads
/// this table to dispatch to the user's actual handler.
///
/// Single-threaded user-mode invariant: only one task touches this
/// table per process, so the static-mut access is race-free.
static mut HANDLERS: [usize; NSIG] = [SIG_DFL_RAW; NSIG];

/// Trampoline registered with the kernel as the per-signal handler.
/// Runs at user-mode CPL=3 with rdi=signum, rsi=&SigContext (per
/// the kernel's deliver_signal contract). Dispatches to the
/// user-installed handler from HANDLERS, then calls sys_sigreturn
/// with the SigContext vaddr in arg0. The kernel restores the
/// trap frame and resumes the user at the trapping instruction
/// with full register state.
///
/// The sigcontext address arrives in RSI from deliver_signal; we
/// stash it in a local before the user-handler call (which may
/// clobber rsi as a caller-saved reg) and reload it for the
/// sys_sigreturn invocation.
///
/// # Safety
/// Reached only via the kernel signal-delivery path. The handler
/// being dispatched must have a valid `sighandler_t` shape.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_signal_trampoline(signum: c_int, sigctx: usize) -> ! {
    let s = signum as usize;
    if s < NSIG {
        // SAFETY: single-threaded user mode; HANDLERS reads/writes
        // are race-free with the rest of this crate's signal table.
        let h = unsafe { HANDLERS[s] };
        if h != SIG_DFL_RAW && h != SIG_IGN_RAW {
            // SAFETY: caller installed h via signal/sigaction; the
            // value is a valid C function pointer.
            let f: sighandler_t = unsafe { core::mem::transmute(h) };
            unsafe { f(signum) };
        }
    }
    // Restore trap frame from the SigContext at `sigctx` (passed
    // as arg0 to SYS_SIGRETURN). Never returns through the syscall
    // ABI — the kernel-side sys_sigreturn rewrites the trap frame
    // and the iretq lands the user at the trapping instruction
    // with full register state restored.
    unsafe {
        narf_user_runtime::sigreturn_with(sigctx as u64);
    }
    // Unreachable; satisfies the `-> !` return type if a buggy
    // kernel returns through.
    loop {
        core::hint::spin_loop();
    }
}

/// `signal(signum, handler) -> prior_handler`. Returns the prior
/// handler value (raw `usize`) cast back to `sighandler_t`. The
/// caller compares against `SIG_DFL_RAW` / `SIG_IGN_RAW` to detect
/// the special slots.
///
/// libc keeps the user-installed handler in a per-signal slot and
/// registers `__libc_signal_trampoline` with the kernel. The
/// trampoline dispatches to the user's handler then calls
/// sys_sigreturn so the trapping context resumes cleanly.
///
/// # Safety
/// `handler` must remain a valid code-page entry-point address for
/// the lifetime of the program (or `SIG_DFL_RAW` / `SIG_IGN_RAW`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn signal(signum: c_int, handler: usize) -> usize {
    if signum < 0 || (signum as usize) >= NSIG {
        return 0;
    }
    let s = signum as usize;
    // SAFETY: single-threaded user-mode invariant per HANDLERS.
    let prior = unsafe { HANDLERS[s] };
    unsafe {
        HANDLERS[s] = handler;
    }
    let kernel_handler = if handler == SIG_DFL_RAW {
        // Clear: kernel-side slot becomes 0 (SIG_DFL).
        0usize
    } else {
        __libc_signal_trampoline as usize
    };
    // SAFETY: forwards into SYS_SIGACTION; the prior value the
    // kernel returns is the previously-registered trampoline addr,
    // which is uninteresting to the caller — we hand back our own
    // tracked prior instead.
    let _kprior = unsafe {
        narf_user_runtime::sigaction(signum as u32, kernel_handler)
    };
    prior
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

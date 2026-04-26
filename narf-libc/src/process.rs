//! Process-control surface: `exit`, `abort`, `atexit`, `getpid`,
//! `getppid`, `getuid`.
//!
//! Each kernel-shaped entry is a thin delegate into
//! `narf_user_runtime` — this crate exists to *shape* the surface
//! (libc-style return types, relibc-shaped naming) rather than
//! re-implement syscalls. The atexit registration table is owned
//! locally (POSIX requires up to 32 entries; we match that).
//!
//! NARF doesn't model POSIX uids (capabilities replace that
//! authority), so `getuid` returns 0 — matches the runtime's stub
//! and what relibc's musl-fork hands back when run on a kernel
//! without a uid model.

/// Maximum atexit callbacks. POSIX guarantees at least 32; we match
/// rather than over-provision because each slot is an 8-byte fn
/// pointer and the table lives in `.bss`.
const ATEXIT_MAX: usize = 32;

/// Atexit callback table. Indexed `[0..ATEXIT_COUNT)` are valid;
/// the rest are `None`. Single-threaded user-mode invariant: only
/// one task touches this table, so the `static mut` access pattern
/// is sound.
static mut ATEXIT_CBS: [Option<extern "C" fn()>; ATEXIT_MAX] = [None; ATEXIT_MAX];

/// Number of registered callbacks. Monotonically increases until
/// `ATEXIT_MAX` is hit, then `atexit` returns -1.
static mut ATEXIT_COUNT: usize = 0;

/// Register a callback to run on `exit`. POSIX guarantees up to 32
/// entries; we match. Returns 0 on success, -1 if the table is full.
///
/// Last-registered runs first (POSIX). See [`exit`].
///
/// # Safety
/// Single-threaded user mode: no other task may concurrently touch
/// the atexit table while this is running. Stage-4 user mode is
/// single-threaded, so the invariant holds. `cb` must remain valid
/// until `exit` is called (in practice: be a `'static` function).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn atexit(cb: extern "C" fn()) -> i32 {
    // SAFETY: single-threaded user mode; static mut access here is
    // race-free against the rest of the crate's atexit/exit pair.
    let count = unsafe { ATEXIT_COUNT };
    if count >= ATEXIT_MAX {
        return -1;
    }
    // SAFETY: index in-range by the prior bounds check.
    unsafe {
        ATEXIT_CBS[count] = Some(cb);
        ATEXIT_COUNT = count + 1;
    }
    0
}

/// Terminate the calling task. On NARF this routes through
/// `SYS_EXIT_TASK`; the kernel-side handler unwinds the trap frame
/// to a kernel-mode landing pad, so this never returns. The `code`
/// argument is reserved for a future `exit_with_status` syscall —
/// today it is recorded only via the kernel's debug-exit machinery
/// for the user-mode-testbin runner.
///
/// Atexit callbacks run in REVERSE registration order (POSIX:
/// "last-registered runs first") before the syscall. Callbacks
/// themselves are not allowed to register new callbacks during
/// shutdown — we capture `count` at entry and walk only that
/// snapshot, but a re-entrant `atexit` would mutate the underlying
/// array. POSIX is silent on this; we don't promise re-entrancy.
///
/// # Safety
/// `extern "C"` shape so a C consumer can call this directly. There
/// are no in-process invariants to violate — exit doesn't return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn exit(_code: i32) -> ! {
    // SAFETY: single-threaded user mode; the snapshot read of
    // `ATEXIT_COUNT` races nothing.
    let count = unsafe { ATEXIT_COUNT };
    for i in (0..count).rev() {
        // SAFETY: index < count is in-range by the snapshot.
        let entry = unsafe { ATEXIT_CBS[i] };
        if let Some(cb) = entry {
            cb();
        }
    }
    narf_user_runtime::exit_task()
}

/// `_exit(2)` — terminate WITHOUT running atexit callbacks. POSIX
/// distinguishes the two; we honour that by routing straight to the
/// syscall. C consumers expect this name.
///
/// # Safety
/// See [`exit`]; same shape.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn _exit(_code: i32) -> ! {
    narf_user_runtime::exit_task()
}

/// Abnormal termination. POSIX `abort(3)` raises `SIGABRT`; in NARF
/// user mode signal self-delivery is a follow-up, so we instead
/// write a recognisable marker to stderr and call into the exit
/// syscall directly (skipping atexit, per POSIX abort semantics).
///
/// The marker is the documented contract: callers (kernel logs,
/// validate harnesses) can grep for `narf-libc: abort` to detect an
/// abort path even without a SIGABRT delivery mechanism.
///
/// # Safety
/// `extern "C"` shape — never returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn abort() -> ! {
    let _written = narf_user_runtime::write(2, b"narf-libc: abort\n");
    narf_user_runtime::exit_task()
}

/// Calling task's monotonic id.
///
/// # Safety
/// Pure read — `extern "C"` shape for C linkability.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpid() -> i32 {
    narf_user_runtime::getpid() as i32
}

/// Parent task id, or 0 if none. Stage-4 kernel always returns 0.
///
/// # Safety
/// Pure read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getppid() -> i32 {
    narf_user_runtime::getppid() as i32
}

/// POSIX-shaped uid query. NARF maps this to capability authority
/// rather than POSIX uids; the runtime returns 0 (root-equivalent
/// in the stub) so the libc surface mirrors that.
///
/// # Safety
/// Pure read.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getuid() -> i32 {
    narf_user_runtime::getuid() as i32
}

/// POSIX `sleep(3)`: suspend the calling task for `seconds`. The
/// kernel-side handler today spin-waits in trap context (see
/// `sys_sleep`), so this fundamentally burns the calling CPU
/// until the deadline passes. Returns 0 (POSIX `sleep` returns
/// the number of seconds left if interrupted by a signal; we
/// don't yet interrupt sleeps mid-flight, so always 0).
///
/// # Safety
/// `extern "C"` shape; the argument is plain by-value u32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn sleep(seconds: u32) -> u32 {
    let ns = (seconds as u64).saturating_mul(1_000_000_000);
    let _ = narf_user_runtime::nanosleep(ns);
    0
}

/// POSIX `usleep(3)`: suspend for `us` microseconds. Returns 0
/// on success, -1 on error. Same caveat as [`sleep`] applies —
/// the kernel handler spin-waits in trap context.
///
/// # Safety
/// See [`sleep`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn usleep(us: u32) -> i32 {
    let ns = (us as u64).saturating_mul(1_000);
    narf_user_runtime::nanosleep(ns)
}

// ── fork / exec / wait — ENOSYS stubs ───────────────────────────────
//
// NARF doesn't expose fork/exec to user mode (the userspace daemon
// model spawns processes via a privileged supervisor instead). The
// libc entries exist so a binary that mentions them in a never-taken
// branch links cleanly.

const ENOSYS: i32 = 38;

/// `fork()` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fork() -> i32 {
    crate::errno::set_errno(ENOSYS);
    -1
}

/// `vfork()` — same as [`fork`] under our model.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vfork() -> i32 {
    crate::errno::set_errno(ENOSYS);
    -1
}

/// `execve(path, argv, envp)` — refuses with ENOSYS.
///
/// # Safety
/// All arguments are taken at face value; we don't dereference.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execve(
    _path: *const i8,
    _argv: *const *const i8,
    _envp: *const *const i8,
) -> i32 {
    crate::errno::set_errno(ENOSYS);
    -1
}

/// `execv(path, argv)` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execv(_path: *const i8, _argv: *const *const i8) -> i32 {
    crate::errno::set_errno(ENOSYS);
    -1
}

/// `execvp(file, argv)` — refuses with ENOSYS.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execvp(_file: *const i8, _argv: *const *const i8) -> i32 {
    crate::errno::set_errno(ENOSYS);
    -1
}

/// `waitpid(pid, *status, options)` — no children to wait on; we
/// report -1 with ECHILD.
const ECHILD: i32 = 10;

/// # Safety
/// `status`, when non-null, must be a writable `*mut i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn waitpid(_pid: i32, status: *mut i32, _options: i32) -> i32 {
    if !status.is_null() {
        // SAFETY: caller-supplied writable slot.
        unsafe { *status = 0; }
    }
    crate::errno::set_errno(ECHILD);
    -1
}

/// `wait(*status)` — same as `waitpid(-1, status, 0)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wait(status: *mut i32) -> i32 {
    // SAFETY: forwarded.
    unsafe { waitpid(-1, status, 0) }
}

// ── session / process group stubs ───────────────────────────────────
//
// Single-process model: every "id" coalesces to the calling task's
// pid. We surface the function shapes so init scripts that call
// `setsid()` don't fail to link.

/// `getpgrp()` — process group; coalesces to pid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpgrp() -> i32 {
    // SAFETY: forwarded.
    unsafe { getpid() }
}

/// `getpgid(pid)` — process group of `pid`. Reports the calling
/// task's pid for any input.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpgid(_pid: i32) -> i32 {
    // SAFETY: forwarded.
    unsafe { getpid() }
}

/// `getsid(pid)` — session id of `pid`. Reports the calling task's pid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getsid(_pid: i32) -> i32 {
    // SAFETY: forwarded.
    unsafe { getpid() }
}

/// `setsid()` — create a new session. We don't track sessions; just
/// report the calling task's pid as the session id.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setsid() -> i32 {
    // SAFETY: forwarded.
    unsafe { getpid() }
}

/// `setpgid(pid, pgid)` — accept and ignore.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setpgid(_pid: i32, _pgid: i32) -> i32 {
    0
}

/// `setuid(uid)` — accept and ignore. NARF maps to capabilities,
/// not uids.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setuid(_uid: u32) -> i32 {
    0
}

/// `setgid(gid)` — accept and ignore.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setgid(_gid: u32) -> i32 {
    0
}

/// `getgid()` — always 0 (matches getuid).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getgid() -> i32 {
    narf_user_runtime::getgid() as i32
}

/// `geteuid()` / `getegid()` — same as their non-effective cousins.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn geteuid() -> i32 {
    // SAFETY: forwarded.
    unsafe { getuid() }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn getegid() -> i32 {
    // SAFETY: forwarded.
    unsafe { getgid() }
}

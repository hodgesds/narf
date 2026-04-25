//! Process-control surface: `exit`, `getpid`, `getppid`, `getuid`.
//!
//! Each entry is a thin delegate into `narf_user_runtime` — this
//! crate exists to *shape* the surface (libc-style return types,
//! relibc-shaped naming) rather than re-implement syscalls.
//!
//! NARF doesn't model POSIX uids (capabilities replace that
//! authority), so `getuid` returns 0 — matches the runtime's stub
//! and what relibc's musl-fork hands back when run on a kernel
//! without a uid model.

/// Terminate the calling task. On NARF this routes through
/// `SYS_EXIT_TASK`; the kernel-side handler unwinds the trap frame
/// to a kernel-mode landing pad, so this never returns. The `code`
/// argument is reserved for a future `exit_with_status` syscall —
/// today it is recorded only via the kernel's debug-exit machinery
/// for the user-mode-testbin runner.
#[inline]
pub fn exit(_code: i32) -> ! {
    narf_user_runtime::exit_task()
}

/// Calling task's monotonic id.
#[inline]
pub fn getpid() -> i32 {
    narf_user_runtime::getpid() as i32
}

/// Parent task id, or 0 if none. Stage-4 kernel always returns 0.
#[inline]
pub fn getppid() -> i32 {
    narf_user_runtime::getppid() as i32
}

/// POSIX-shaped uid query. NARF maps this to capability authority
/// rather than POSIX uids; the runtime returns 0 (root-equivalent
/// in the stub) so the libc surface mirrors that.
#[inline]
pub fn getuid() -> i32 {
    narf_user_runtime::getuid() as i32
}

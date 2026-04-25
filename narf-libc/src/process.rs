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
#[inline]
pub fn exit(_code: i32) -> ! {
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

/// Abnormal termination. POSIX `abort(3)` raises `SIGABRT`; in NARF
/// user mode signal self-delivery is a follow-up, so we instead
/// write a recognisable marker to stderr and call into the exit
/// syscall directly (skipping atexit, per POSIX abort semantics).
///
/// The marker is the documented contract: callers (kernel logs,
/// validate harnesses) can grep for `narf-libc: abort` to detect an
/// abort path even without a SIGABRT delivery mechanism.
pub fn abort() -> ! {
    let _written = narf_user_runtime::write(2, b"narf-libc: abort\n");
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

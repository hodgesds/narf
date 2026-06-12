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
    // SAFETY: Valid memory or trusted environment
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
    // SAFETY: Valid memory or trusted environment
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

/// Linux `gettid(2)` — return the calling thread's distinct
/// kernel id. NARF is single-threaded per process today, so
/// gettid coincides with getpid; the surface exists so the libc
/// shim's ABI is right for when threading arrives.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn gettid() -> i32 {
    narf_user_runtime::gettid() as i32
}

// ── prctl ───────────────────────────────────────────────────────────

pub const PR_SET_NAME: i32 = 15;
pub const PR_GET_NAME: i32 = 16;
pub const PR_SET_DUMPABLE: i32 = 4;
pub const PR_GET_DUMPABLE: i32 = 3;
pub const PR_SET_NO_NEW_PRIVS: i32 = 38;
pub const PR_GET_NO_NEW_PRIVS: i32 = 39;

/// `prctl(op, arg2, arg3, arg4, arg5)` — Linux signature. We
/// honour the most-reached-for subops; everything else returns
/// -1 with errno = EINVAL.
///
/// Note: the C signature is variadic in glibc; we expose the
/// fixed three-arg form because it covers every honoured op.
///
/// # Safety
/// When `op` is PR_SET_NAME or PR_GET_NAME, `arg2` must be a
/// valid 16-byte buffer (read or write per direction).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn prctl(op: i32, arg2: u64, arg3: u64) -> i32 {
    if op < 0 {
        return -1;
    }
    let r = narf_user_runtime::prctl(op as u32, arg2, arg3);
    if r == -1 {
        crate::errno::set_errno(22); // EINVAL
        return -1;
    }
    r as i32
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

// ── fork / exec / wait ──────────────────────────────────────────────

/// `fork()` — create an independent copy of the calling process.
///
/// Routes to `Syscall::Fork` (wire number 57 on x86_64, matching
/// Linux's `arch/x86/entry/syscalls/syscall_64.tbl`). The kernel
/// copies the calling task's address space (COW), fd table, brk,
/// signal handlers, pgid, and sid into a new task; pending signals
/// in the child are reset per POSIX.
///
/// Return convention (POSIX):
///   parent — the child's pid (positive)
///   child  — 0
///   error  — -1 + errno set (EAGAIN on resource exhaustion, ENOMEM
///             on AS-copy failure)
///
/// Reference: musl `src/process/fork.c`; Linux `kernel/fork.c`.
///
/// # Safety
/// `extern "C"` shape — pure syscall delegation, no invariants to
/// uphold in the calling task.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn fork() -> i32 {
    match narf_user_runtime::fork() {
        Ok(pid) => pid as i32,
        Err(()) => {
            // EAGAIN: kernel couldn't allocate the child task (the
            // most common failure — resource limit or AS-copy OOM).
            // POSIX allows either EAGAIN or ENOMEM; we pick EAGAIN
            // matching the Linux default (glibc fork.c).
            crate::errno::set_errno(11); // EAGAIN
            -1
        }
    }
}

/// `vfork()` — POSIX permits aliasing to `fork()`; we do so because
/// NARF doesn't implement the optimised-stack-sharing semantics of
/// the original BSD vfork (which requires the child to avoid using
/// the parent's stack until exec/exit). Callers that rely on vfork's
/// COW-skip optimisation get correct behaviour, just without the
/// allocation savings.
///
/// Reference: musl `src/process/vfork.c` (aliases fork on platforms
/// without vfork support).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn vfork() -> i32 {
    // SAFETY: forwarded to fork() which is sound.
    unsafe { fork() }
}

/// `execve(path, argv, envp)` — re-image the calling task with the
/// program at `path`. POSIX shape: `argv` and `envp` are
/// NULL-terminated arrays of NUL-terminated C strings. argv[0]
/// conventionally repeats the basename of `path`.
///
/// Implementation:
///   1. open(path, O_RDONLY); fstat-equivalent via lseek-end to
///      get the size; read into a heap buffer; close.
///   2. Pack argv into a single concatenated NUL-separated buffer
///      (each string ends with NUL; the whole pack is `argv_len`
///      bytes). Same for envp. Empty input → empty pack.
///   3. Hand off to `narf_user_runtime::execve` which issues the
///      kernel SYS_EXECVE. On success the kernel rewrites the
///      task's address space + entry point and resumes user mode
///      at the new image — this call NEVER returns.
///
/// On failure (file not found, ELF parse error, OOM): returns -1
/// with errno set, the calling task continues running its old
/// image.
///
/// # Safety
/// `path` must be a valid NUL-terminated C string. `argv` /
/// `envp` must be NULL-terminated arrays of valid NUL-terminated
/// C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execve(
    path: *const i8,
    argv: *const *const i8,
    envp: *const *const i8,
) -> i32 {
    if path.is_null() {
        crate::errno::set_errno(crate::errno::EINVAL);
        return -1;
    }
    // Linux ABI cutover: hand the user's path / argv / envp
    // pointers straight to the kernel. The kernel resolves the
    // path through the VFS and reads the ELF bytes server-side,
    // so we don't need the old user-side `read_file_to_vec` +
    // argv/envp pack step. Empty argv (NULL ptr) and empty envp
    // (NULL ptr) are both legal — execve handles them.
    // SAFETY: Valid memory or trusted environment
    match unsafe {
        narf_user_runtime::execve(
            path as *const u8,
            argv as *const *const u8,
            envp as *const *const u8,
        )
    } {
        Ok(()) => {
            // Unreachable on success — kernel resumes new image
            // directly. If we get here, surface ENOEXEC.
            crate::errno::set_errno(8); // ENOEXEC
            -1
        }
        Err(()) => {
            crate::errno::set_errno(8); // ENOEXEC
            -1
        }
    }
}

/// `execv(path, argv)` — `execve(path, argv, environ)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execv(path: *const i8, argv: *const *const i8) -> i32 {
    // SAFETY: forwarded; ENVIRON is the libc-published env array.
    // Read as *const *const u8 (the canonical declaration), cast
    // to *const *const i8 for execve's signature.
    // SAFETY: Valid memory or trusted environment
    let envp = unsafe { crate::env::ENVIRON } as *const *const i8;
    // SAFETY: Valid memory or trusted environment
    unsafe { execve(path, argv, envp) }
}

/// `execvp(file, argv)` — like `execv` but searches `$PATH` if
/// `file` doesn't contain a slash. The minimal shape: if `file`
/// contains a `/`, treat as a literal path; otherwise prepend
/// `"/bin/"` and try once. Real PATH-searching can land later.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn execvp(file: *const i8, argv: *const *const i8) -> i32 {
    if file.is_null() {
        crate::errno::set_errno(crate::errno::EINVAL);
        return -1;
    }
    // SAFETY: Valid memory or trusted environment
    let s = match unsafe { c_str_to_str(file) } {
        Some(s) => s,
        None => {
            crate::errno::set_errno(crate::errno::EINVAL);
            return -1;
        }
    };
    if s.contains('/') {
        // SAFETY: forwarded.
        return unsafe { execv(file, argv) };
    }
    // /bin/<file> fallback. Build a NUL-terminated path on the
    // stack — capped at 256 bytes to keep the stack frame bounded.
    let mut buf = [0u8; 256];
    let prefix = b"/bin/";
    if prefix.len() + s.len() + 1 > buf.len() {
        crate::errno::set_errno(crate::errno::EINVAL);
        return -1;
    }
    buf[..prefix.len()].copy_from_slice(prefix);
    buf[prefix.len()..prefix.len() + s.len()].copy_from_slice(s.as_bytes());
    // SAFETY: NUL-terminated by the zero-init above.
    unsafe { execv(buf.as_ptr() as *const i8, argv) }
}

const ECHILD: i32 = 10;

/// `waitpid(pid, *status, options)` — block (or poll under
/// WNOHANG) until a child of the calling task exits. Maps to
/// SYS_WAIT4 with rusage = NULL. Returns the reaped child pid
/// on success, 0 on WNOHANG-with-no-exited-child, -1 + ECHILD
/// on no-children / timeout.
///
/// # Safety
/// `status`, when non-null, must be a writable `*mut i32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32 {
    // SAFETY: forwarded; runtime issues SYS_WAIT4.
    match unsafe {
        narf_user_runtime::wait4(pid as i64, status, options as u32, core::ptr::null_mut())
    } {
        Ok(reaped) => reaped as i32,
        Err(()) => {
            crate::errno::set_errno(ECHILD);
            -1
        }
    }
}

/// `wait(*status)` — same as `waitpid(-1, status, 0)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wait(status: *mut i32) -> i32 {
    // SAFETY: forwarded.
    unsafe { waitpid(-1, status, 0) }
}

/// Walk a NUL-terminated C string, returning a `&str` view if it
/// holds valid UTF-8 (capped at 4 KiB to bound a runaway pointer).
///
/// # Safety
/// `p` must be either NULL or a NUL-terminated C string in the
/// calling task's AS.
unsafe fn c_str_to_str<'a>(p: *const i8) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    let mut len = 0usize;
    while len < 4096 {
        // SAFETY: caller asserted NUL-terminated.
        let b = unsafe { *p.add(len) };
        if b == 0 {
            break;
        }
        len += 1;
    }
    // SAFETY: bytes [0..len) read above without faulting.
    let bytes = unsafe { core::slice::from_raw_parts(p as *const u8, len) };
    core::str::from_utf8(bytes).ok()
}

// ── session / process group stubs ───────────────────────────────────
//
// Single-process model: every "id" coalesces to the calling task's
// pid. We surface the function shapes so init scripts that call
// `setsid()` don't fail to link.

/// `getpgrp()` — POSIX process-group id of the caller. Routes
/// through SYS_GETPGID with pid = 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpgrp() -> i32 {
    narf_user_runtime::getpgid(0) as i32
}

/// `getpgid(pid)` — POSIX. Returns the target's pgid (or its pid
/// if no setpgid has yet stuck).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpgid(pid: i32) -> i32 {
    narf_user_runtime::getpgid(pid as u64) as i32
}

/// `getsid(pid)` — POSIX. `pid = 0` → self.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getsid(pid: i32) -> i32 {
    narf_user_runtime::getsid(pid as u64) as i32
}

/// `setsid()` — POSIX. Caller becomes a new session leader.
/// Returns the new sid (= caller's pid).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setsid() -> i32 {
    narf_user_runtime::setsid() as i32
}

/// `setpgid(pid, pgid)` — POSIX. `pid = 0` → self;
/// `pgid = 0` → target's pid.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setpgid(pid: i32, pgid: i32) -> i32 {
    narf_user_runtime::setpgid(pid as u64, pgid as u64)
}

/// `setuid(uid)` — record the caller's uid in the kernel uid/gid
/// table. NARF's authority is capabilities (the table is structural
/// state with no security implication), so the call always
/// succeeds; consumers that care about the value see it stick
/// across subsequent `getuid()` reads.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setuid(uid: u32) -> i32 {
    narf_user_runtime::setuid(uid)
}

/// `setgid(gid)` — see [`setuid`].
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setgid(gid: u32) -> i32 {
    narf_user_runtime::setgid(gid)
}

// ── nice / priority ─────────────────────────────────────────────────

/// `<sys/resource.h>` `which` values for [`getpriority`] /
/// [`setpriority`]. NARF only honours `PRIO_PROCESS`; the others
/// return -1 with errno = EINVAL.
pub const PRIO_PROCESS: i32 = 0;
pub const PRIO_PGRP: i32 = 1;
pub const PRIO_USER: i32 = 2;

/// `getpriority(which, who)` — read the nice value (-20..=19) of
/// the target task. POSIX returns the value directly; on error
/// the function sets errno to a non-zero value and returns -1.
/// Callers must clear errno before the call to disambiguate a
/// real -1 from an error since -1 is a valid nice value.
///
/// # Safety
/// Pure value math.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getpriority(which: i32, who: u32) -> i32 {
    if which < 0 {
        return -1;
    }
    let r = narf_user_runtime::getpriority(which as u32, who);
    if r == -1 {
        crate::errno::set_errno(22); // EINVAL
        return -1;
    }
    r as i32
}

/// `setpriority(which, who, prio)` — record a new nice value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn setpriority(which: i32, who: u32, prio: i32) -> i32 {
    if which < 0 {
        return -1;
    }
    narf_user_runtime::setpriority(which as u32, who, prio)
}

/// `nice(inc)` — adjust the calling task's nice value by `inc`.
/// Returns the new nice value on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn nice(inc: i32) -> i32 {
    let cur = narf_user_runtime::getpriority(0, 0) as i32;
    let new = (cur + inc).clamp(-20, 19);
    let r = narf_user_runtime::setpriority(0, 0, new);
    if r == 0 {
        new
    } else {
        -1
    }
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

/// `unshare(flags)` — Linux/POSIX2008 unshare(2). Today only
/// CLONE_NEWNS (0x00020000) has effect — snapshots the calling
/// task's view of the mount table into a private namespace. Other
/// flag bits accepted for ABI compatibility, ignored.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn unshare(flags: u32) -> i32 {
    match narf_user_runtime::unshare(flags) {
        Ok(()) => 0,
        Err(()) => {
            crate::errno::set_errno(crate::errno::EINVAL);
            -1
        }
    }
}

// ── `_Exit` / `wait4` / `tgkill` / `clone` ─────────────────────────
//
// C11 / POSIX-2008 / Linux extensions.

/// C11 `_Exit(status)` — like `_exit` but explicitly skips
/// atexit handlers. Identical implementation under our model
/// (`_exit` already doesn't walk the atexit chain).
///
/// Reference: musl `src/exit/_Exit.c`.
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn _Exit(code: i32) -> ! {
    // SAFETY: forwarded; never returns.
    unsafe { _exit(code) }
}

/// `wait4(pid, status, options, rusage)` — Linux/BSD extended wait.
/// `rusage` is currently ignored (NARF doesn't track per-task
/// resource usage on exit). Returns the reaped pid, 0 on
/// WNOHANG-with-no-exited-child, -1 + ECHILD on no children.
///
/// Reference: glibc `sysdeps/unix/sysv/linux/wait4.c`.
///
/// # Safety
/// `status` / `rusage` (when non-null) must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn wait4(
    pid: i32,
    status: *mut i32,
    options: i32,
    rusage: *mut crate::sys::rusage,
) -> i32 {
    let r =
        // SAFETY: Valid memory or trusted environment
        unsafe { narf_user_runtime::wait4(pid as i64, status, options as u32, rusage as *mut _) };
    match r {
        Ok(reaped) => reaped as i32,
        Err(()) => {
            crate::errno::set_errno(ECHILD);
            -1
        }
    }
}

/// `tgkill(tgid, tid, signum)` — Linux per-thread signal delivery.
/// Forwards to the kernel SYS_TGKILL.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tgkill(tgid: i32, tid: i32, signum: i32) -> i32 {
    if signum < 0 {
        return -1;
    }
    let r = narf_user_runtime::tgkill(tgid as i64, tid as u64, signum as u32);
    if r != 0 {
        crate::errno::set_errno(crate::errno::EINVAL);
        return -1;
    }
    0
}

/// `tkill(tid, signum)` — Linux deprecated single-thread kill.
/// Implemented as `tgkill(-1, tid, signum)` per kernel docs.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tkill(tid: i32, signum: i32) -> i32 {
    // SAFETY: forwarded.
    unsafe { tgkill(-1, tid, signum) }
}

/// `clone(fn, stack, flags, arg, ...)` — Linux clone(2). The
/// canonical glibc shape is `int clone(int (*fn)(void *), void
/// *stack, int flags, void *arg, ...)`. We honour the four-arg
/// form; trailing arguments (`ptid`, `tls`, `ctid`) are ignored
/// today.
///
/// Reference: glibc `sysdeps/unix/sysv/linux/x86_64/clone.S`.
///
/// # Safety
/// `entry_fn` must remain alive for the new thread's lifetime;
/// `stack` must point to the top of a writable stack.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn clone(
    entry_fn: Option<unsafe extern "C" fn(*mut core::ffi::c_void) -> i32>,
    stack: *mut core::ffi::c_void,
    _flags: i32,
    arg: *mut core::ffi::c_void,
) -> i32 {
    let entry = match entry_fn {
        Some(f) => f as usize as u64,
        None => return -1,
    };
    match narf_user_runtime::clone(entry, stack as u64, arg as u64, 0) {
        Ok(tid) => tid as i32,
        Err(()) => {
            crate::errno::set_errno(crate::errno::EINVAL);
            -1
        }
    }
}

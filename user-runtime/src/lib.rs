//! narf-user-runtime — typed user-side SDK for NARF syscalls.
//!
//! Phase-4 user binaries (and the eventual relibc shim) build
//! against this crate instead of hand-rolling `int 0x80` / `svc #0`
//! sequences. The crate is `no_std` + no-alloc + has zero kernel
//! dependencies so it can be reused by any user binary built for
//! `x86_64-unknown-none` or `aarch64-unknown-none`.
//!
//! Wire compatibility:
//! - Syscall numbers mirror `narf_userspace::syscall::Syscall` —
//!   keep the `SYS_*` constants below in sync if that enum changes.
//! - [`BootstrapHeader`] mirrors the kernel-side struct in
//!   `userspace/src/handlers.rs`. Layout is `#[repr(C)]` and is
//!   considered wire-stable; updates must land on both sides.
//!
//! The x86_64 syscall ABI is `int 0x80` with rax = number, rdi /
//! rsi / rdx / r10 / r8 / r9 = args, rax = return value, and RDX
//! is also written by the kernel as the status word. Every wrapper
//! that takes ≥3 args declares RDX as `inout` so rustc doesn't
//! assume RDX is preserved across the trap (this is a real
//! correctness issue — without the clobber rustc may keep a value
//! it expected in RDX live across the syscall and read garbage).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![allow(clippy::missing_safety_doc)]

use core::fmt;

pub mod graphics;
pub mod shmem;

// ── Syscall numbers ────────────────────────────────────────────────
//
// Mirror of `narf_userspace::syscall::Syscall`. NARF reserves 100+
// to avoid collisions with Linux conventions during dual-target
// development with relibc. If the kernel-side enum gains numbers,
// add them here too.

pub const SYS_SUBMIT:         u64 = 100;
pub const SYS_BOOTSTRAP:      u64 = 101;
pub const SYS_WAIT_COMPL:     u64 = 102;
pub const SYS_EXIT_TASK:      u64 = 103;
pub const SYS_YIELD:          u64 = 104;
pub const SYS_SLEEP:          u64 = 105;
pub const SYS_OPEN:           u64 = 110;
pub const SYS_READ:           u64 = 111;
pub const SYS_WRITE:          u64 = 112;
pub const SYS_CLOSE:          u64 = 113;
// Tier-2 fd-table breadth + path resolution + pipe (115..=117 reserved).
pub const SYS_GETRANDOM:      u64 = 200;
pub const SYS_READLINK:       u64 = 193;
pub const SYS_SYMLINK:        u64 = 194;
pub const SYS_LISTDIR:        u64 = 195;
pub const SYS_GETDENTS64:     u64 = 196;
pub const SYS_STAT:           u64 = 115;
pub const SYS_LSTAT:          u64 = 133;
pub const SYS_FSTAT:          u64 = 116;
pub const SYS_PIPE:           u64 = 117;
pub const SYS_MMAP:           u64 = 120;
pub const SYS_MUNMAP:         u64 = 121;
pub const SYS_FB_CONNECT:     u64 = 240;
pub const SYS_FB_INFO:        u64 = 241;
pub const SYS_FB_RING_MAP:    u64 = 242;
pub const SYS_FB_FLUSH_WAIT:  u64 = 243;
pub const SYS_FB_DISCONNECT:  u64 = 244;
pub const SYS_SHMEM_CREATE:   u64 = 250;
pub const SYS_SHMEM_MAP:      u64 = 251;
pub const SYS_SHMEM_DESTROY:  u64 = 252;
pub const SYS_RING_KICK:      u64 = 130;
pub const SYS_GETPID:         u64 = 140;
pub const SYS_GETPPID:        u64 = 141;
pub const SYS_GETUID:         u64 = 142;
pub const SYS_GETGID:         u64 = 143;
pub const SYS_SETUID:         u64 = 144;
pub const SYS_SETGID:         u64 = 145;
pub const SYS_GETPGID:        u64 = 224;
pub const SYS_SETPGID:        u64 = 225;
pub const SYS_GETSID:         u64 = 226;
pub const SYS_SETSID:         u64 = 227;
pub const SYS_FTRUNCATE:      u64 = 118;
pub const SYS_TRUNCATE:       u64 = 132;
pub const SYS_PREAD64:        u64 = 119;
pub const SYS_PWRITE64:       u64 = 122;
pub const SYS_FSYNC:          u64 = 123;
pub const SYS_FDATASYNC:      u64 = 124;
pub const SYS_PIPE2:          u64 = 125;
pub const SYS_FALLOCATE:      u64 = 126;
pub const SYS_COPY_FILE_RANGE: u64 = 127;
pub const SYS_MEMFD_CREATE:   u64 = 128;
pub const SYS_FCHMOD:         u64 = 129;
pub const SYS_FCHOWN:         u64 = 131;
pub const SYS_FCHMODAT:       u64 = 134;
pub const SYS_FCHOWNAT:       u64 = 135;
pub const SYS_FACCESSAT:      u64 = 136;
pub const SYS_OPENAT:         u64 = 137;
pub const SYS_NEWFSTATAT:     u64 = 138;
pub const SYS_UNLINKAT:       u64 = 139;
pub const SYS_MKDIRAT:        u64 = 228;
pub const SYS_RENAMEAT:       u64 = 229;
pub const SYS_SYMLINKAT:      u64 = 230;
pub const SYS_READLINKAT:     u64 = 231;
pub const SYS_ACCESS:         u64 = 232;
pub const SYS_CHMOD:          u64 = 233;
pub const SYS_CHOWN:          u64 = 234;
pub const SYS_GETHOSTNAME:    u64 = 146;
pub const SYS_SETHOSTNAME:    u64 = 147;
pub const SYS_GETRLIMIT:      u64 = 148;
pub const SYS_SETRLIMIT:      u64 = 149;
pub const SYS_PRLIMIT64:      u64 = 178;
pub const SYS_UMASK:          u64 = 155;
pub const SYS_GETPRIORITY:    u64 = 156;
pub const SYS_GETCPU:         u64 = 165;
pub const SYS_SCHED_GETAFFINITY: u64 = 166;
pub const SYS_SCHED_SETAFFINITY: u64 = 167;
pub const SYS_SCHED_GET_PRIORITY_MAX: u64 = 220;
pub const SYS_SCHED_GET_PRIORITY_MIN: u64 = 221;
pub const SYS_SCHED_GETPARAM:    u64 = 222;
pub const SYS_SCHED_SETPARAM:    u64 = 223;
pub const SYS_GETTID:         u64 = 168;
pub const SYS_PRCTL:          u64 = 169;
pub const SYS_TGKILL:         u64 = 175;
pub const SYS_FUTEX:          u64 = 177;
pub const SYS_SETPRIORITY:    u64 = 157;
pub const SYS_TIMES:          u64 = 158;
pub const SYS_GETRUSAGE:      u64 = 159;
pub const SYS_BRK:            u64 = 150;
pub const SYS_CLOCK_GETTIME:  u64 = 151;
pub const SYS_CLOCK_SETTIME:  u64 = 176;
pub const SYS_SIGACTION:      u64 = 152;
pub const SYS_KILL:           u64 = 153;
pub const SYS_SIGPROCMASK:    u64 = 154;
// Dup family + fcntl (160..=163 reserved).
pub const SYS_DUP:            u64 = 160;
pub const SYS_DUP2:           u64 = 161;
pub const SYS_DUP3:           u64 = 162;
pub const SYS_FCNTL:          u64 = 163;
// Cwd state (170/171).
pub const SYS_CHDIR:          u64 = 170;
pub const SYS_GETCWD:         u64 = 171;

pub const SYS_LSEEK:          u64 = 164;
pub const SYS_UNLINK:         u64 = 180;
pub const SYS_MKDIR:          u64 = 190;
pub const SYS_RMDIR:          u64 = 191;
pub const SYS_RENAME:         u64 = 192;

/// `fcntl` command constants — match Linux numbering for the subset
/// NARF supports today (FD_CLOEXEC + the file-flag query/set pair).
pub const F_GETFD:    u32 = 1;
pub const F_SETFD:    u32 = 2;
pub const F_GETFL:    u32 = 3;
pub const F_SETFL:    u32 = 4;
/// `FD_CLOEXEC` flag bit — the only `flags` bit NARF currently
/// stamps onto an fd entry.
pub const FD_CLOEXEC: u32 = 1;

/// `sigprocmask` how-flags — match POSIX.
pub const SIG_BLOCK:   u32 = 0;
pub const SIG_UNBLOCK: u32 = 1;
pub const SIG_SETMASK: u32 = 2;

/// "NARF" little-endian — first u32 of the bootstrap config page.
pub const NARF_MAGIC: u32 = 0x4E_41_52_46;

/// ABI version the kernel currently writes into [`BootstrapHeader::version`].
pub const BOOTSTRAP_ABI_VERSION: u32 = 3;

/// Depth the kernel uses for the user-mappable SharedRing pair.
/// Mirrors `BOOTSTRAP_SHARED_RING_DEPTH` in `userspace/src/handlers.rs`.
pub const BOOTSTRAP_SHARED_RING_DEPTH: u32 = 16;

// ── Per-arch syscall asm primitives ────────────────────────────────
//
// Every wrapper that takes ≥3 register args MUST declare RDX as
// `inout` (or `out`) on x86_64: the kernel writes the status word
// into RDX even when only the rax payload is observed, so rustc
// must treat RDX as clobbered. Missing this clobber is silent UB.

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall0(num: u64) -> u64 {
    let mut rax = num;
    // SAFETY: int-0x80 is the registered NARF user gate; rcx + r11
    // are trap-clobbered, rdx is also kernel-written even on a
    // 0-arg call.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("rax") rax,
            out("rcx") _, out("r11") _, out("rdx") _,
            options(nostack, preserves_flags),
        );
    }
    rax
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall1(num: u64, a0: u64) -> u64 {
    let mut rax = num;
    // SAFETY: see `syscall0`.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("rax") rax,
            in("rdi") a0,
            out("rcx") _, out("r11") _, out("rdx") _,
            options(nostack, preserves_flags),
        );
    }
    rax
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall2(num: u64, a0: u64, a1: u64) -> u64 {
    let mut rax = num;
    // SAFETY: see `syscall0`.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("rax") rax,
            in("rdi") a0, in("rsi") a1,
            out("rcx") _, out("r11") _, out("rdx") _,
            options(nostack, preserves_flags),
        );
    }
    rax
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall3(num: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let mut rax = num;
    // SAFETY: int-0x80 with three args; RDX carries `a2` in and the
    // kernel status word out — declare as inout so rustc doesn't
    // expect any prior RDX value to survive.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("rax") rax,
            in("rdi") a0, in("rsi") a1, inout("rdx") a2 => _,
            out("rcx") _, out("r11") _,
            options(nostack, preserves_flags),
        );
    }
    rax
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall4(num: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let mut rax = num;
    // SAFETY: r10 is the 4th-arg register (NARF mirrors Linux's
    // amd64 kernel convention; see `syscall3` for the RDX rationale).
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("rax") rax,
            in("rdi") a0, in("rsi") a1, inout("rdx") a2 => _, in("r10") a3,
            out("rcx") _, out("r11") _,
            options(nostack, preserves_flags),
        );
    }
    rax
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall5(
    num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64,
) -> u64 {
    let mut rax = num;
    // SAFETY: r8 is the 5th-arg register (NARF mirrors Linux's
    // amd64 kernel convention; see `syscall3` for the RDX rationale).
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("rax") rax,
            in("rdi") a0, in("rsi") a1, inout("rdx") a2 => _,
            in("r10") a3, in("r8") a4,
            out("rcx") _, out("r11") _,
            options(nostack, preserves_flags),
        );
    }
    rax
}

#[cfg(target_arch = "x86_64")]
#[inline(always)]
unsafe fn syscall6(
    num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
) -> u64 {
    let mut rax = num;
    // SAFETY: r9 is the 6th-arg register per the kernel convention.
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("rax") rax,
            in("rdi") a0, in("rsi") a1, inout("rdx") a2 => _,
            in("r10") a3, in("r8") a4, in("r9") a5,
            out("rcx") _, out("r11") _,
            options(nostack, preserves_flags),
        );
    }
    rax
}

// aarch64: x8 = number, x0..x5 = args, return in x0. svc #0 enters
// the lower-EL sync vector which routes via
// `rust_aarch64_sync_dispatch`.
#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall0(num: u64) -> u64 {
    let mut ret: u64;
    // SAFETY: svc #0 is the registered NARF user gate.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") num,
            lateout("x0") ret,
            options(nostack, preserves_flags),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall1(num: u64, a0: u64) -> u64 {
    let mut ret: u64;
    // SAFETY: see `syscall0`.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") num,
            inout("x0") a0 => ret,
            options(nostack, preserves_flags),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall2(num: u64, a0: u64, a1: u64) -> u64 {
    let mut ret: u64;
    // SAFETY: see `syscall0`.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") num,
            inout("x0") a0 => ret,
            in("x1") a1,
            options(nostack, preserves_flags),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall3(num: u64, a0: u64, a1: u64, a2: u64) -> u64 {
    let mut ret: u64;
    // SAFETY: see `syscall0`.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") num,
            inout("x0") a0 => ret,
            in("x1") a1, in("x2") a2,
            options(nostack, preserves_flags),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall4(num: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> u64 {
    let mut ret: u64;
    // SAFETY: see `syscall0`.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") num,
            inout("x0") a0 => ret,
            in("x1") a1, in("x2") a2, in("x3") a3,
            options(nostack, preserves_flags),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall5(
    num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64,
) -> u64 {
    let mut ret: u64;
    // SAFETY: see `syscall0`.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") num,
            inout("x0") a0 => ret,
            in("x1") a1, in("x2") a2, in("x3") a3, in("x4") a4,
            options(nostack, preserves_flags),
        );
    }
    ret
}

#[cfg(target_arch = "aarch64")]
#[inline(always)]
unsafe fn syscall6(
    num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64,
) -> u64 {
    let mut ret: u64;
    // SAFETY: see `syscall0`.
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") num,
            inout("x0") a0 => ret,
            in("x1") a1, in("x2") a2, in("x3") a3, in("x4") a4, in("x5") a5,
            options(nostack, preserves_flags),
        );
    }
    ret
}

// ── Process control ────────────────────────────────────────────────

/// Terminate the calling task. The kernel-side handler unwinds the
/// trap frame back to a kernel-mode landing pad and never returns
/// to the caller; the trailing `loop` is a fallback for the case
/// where the redirect somehow fails to ensure the `-> !` contract
/// holds.
#[inline]
pub fn exit_task() -> ! {
    // SAFETY: SYS_EXIT_TASK takes no args and never returns on
    // success; on failure we spin (we have no console + no panic
    // handler in this crate).
    unsafe { syscall0(SYS_EXIT_TASK); }
    loop { core::hint::spin_loop(); }
}

/// Yield the CPU; returns when rescheduled.
#[inline]
pub fn yield_now() {
    // SAFETY: SYS_YIELD takes no args and returns normally.
    unsafe { syscall0(SYS_YIELD); }
}

/// Calling task's monotonic id.
#[inline]
pub fn getpid() -> u64 {
    // SAFETY: SYS_GETPID takes no args.
    unsafe { syscall0(SYS_GETPID) }
}

/// Calling task's parent id, or 0 if none. Stage-4 kernel always
/// returns 0 (parentage isn't tracked yet).
#[inline]
pub fn getppid() -> u64 {
    // SAFETY: SYS_GETPPID takes no args.
    unsafe { syscall0(SYS_GETPPID) }
}

/// POSIX-shaped uid query. NARF doesn't model POSIX uid (capabilities
/// replace it); always returns 0.
#[inline]
pub fn getuid() -> u64 {
    // SAFETY: SYS_GETUID takes no args.
    unsafe { syscall0(SYS_GETUID) }
}

/// POSIX-shaped gid query — see [`getuid`].
#[inline]
pub fn getgid() -> u64 {
    // SAFETY: SYS_GETGID takes no args.
    unsafe { syscall0(SYS_GETGID) }
}

/// `setuid(uid)` — update the calling task's uid in the kernel
/// uid/gid table. Always succeeds and returns 0; capabilities
/// still gate every privileged operation.
#[inline]
pub fn setuid(uid: u32) -> i32 {
    // SAFETY: SYS_SETUID takes one arg (uid).
    let r = unsafe { syscall1(SYS_SETUID, uid as u64) };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `setgid(gid)` — update the calling task's gid; see [`setuid`].
#[inline]
pub fn setgid(gid: u32) -> i32 {
    // SAFETY: SYS_SETGID takes one arg (gid).
    let r = unsafe { syscall1(SYS_SETGID, gid as u64) };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `getpgid(pid)` — POSIX process-group id query. `pid = 0` →
/// self. Default pgid = pid (each task is its own group leader).
#[inline]
pub fn getpgid(pid: u64) -> u64 {
    // SAFETY: SYS_GETPGID signature: (pid).
    unsafe { syscall1(SYS_GETPGID, pid) }
}

/// `setpgid(pid, pgid)` — set the target task's pgid. `pid = 0` →
/// self. `pgid = 0` → target's pid. Returns 0 on success.
#[inline]
pub fn setpgid(pid: u64, pgid: u64) -> i32 {
    // SAFETY: SYS_SETPGID signature: (pid, pgid).
    let r = unsafe { syscall2(SYS_SETPGID, pid, pgid) };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `getsid(pid)` — POSIX session id query. `pid = 0` → self.
#[inline]
pub fn getsid(pid: u64) -> u64 {
    // SAFETY: SYS_GETSID signature: (pid).
    unsafe { syscall1(SYS_GETSID, pid) }
}

/// `setsid()` — POSIX. Caller becomes a new session leader.
/// Returns the new sid (= caller's pid).
#[inline]
pub fn setsid() -> u64 {
    // SAFETY: SYS_SETSID takes no args.
    unsafe { syscall0(SYS_SETSID) }
}

/// `ftruncate(fd, len)` — resize the file backing `fd` to exactly
/// `len` bytes. Returns 0 on success, -1 on read-only fs / bad fd.
#[inline]
pub fn ftruncate(fd: u32, len: u64) -> i32 {
    // SAFETY: SYS_FTRUNCATE signature: (fd, len).
    let r = unsafe { syscall2(SYS_FTRUNCATE, fd as u64, len) };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `truncate(path, len)` — path-based resize. Returns 0 on
/// success, -1 on bad path / read-only FS.
#[inline]
pub fn truncate(path: &str, len: u64) -> i32 {
    if path.is_empty() { return -1; }
    // SAFETY: SYS_TRUNCATE signature: (path_ptr, path_len, len).
    let r = unsafe {
        syscall3(SYS_TRUNCATE, path.as_ptr() as u64, path.len() as u64, len)
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `pread(fd, buf, offset)` — read at the explicit offset without
/// touching the per-fd cursor. Returns the byte count read, -1 on
/// error.
#[inline]
pub fn pread(fd: u32, buf: &mut [u8], offset: u64) -> isize {
    if buf.is_empty() { return 0; }
    // SAFETY: SYS_PREAD64 signature: (fd, buf_ptr, len, offset).
    let r = unsafe {
        syscall4(
            SYS_PREAD64, fd as u64,
            buf.as_mut_ptr() as u64, buf.len() as u64,
            offset,
        )
    };
    r as isize
}

/// `pwrite(fd, buf, offset)` — write at the explicit offset.
#[inline]
pub fn pwrite(fd: u32, buf: &[u8], offset: u64) -> isize {
    if buf.is_empty() { return 0; }
    // SAFETY: SYS_PWRITE64 signature: (fd, buf_ptr, len, offset).
    let r = unsafe {
        syscall4(
            SYS_PWRITE64, fd as u64,
            buf.as_ptr() as u64, buf.len() as u64,
            offset,
        )
    };
    r as isize
}

/// `fsync(fd)` — flush buffered writes for `fd`. Stub for in-
/// memory filesystems; returns 0 for an open fd, -1 for an
/// unknown fd.
#[inline]
pub fn fsync(fd: u32) -> i32 {
    // SAFETY: SYS_FSYNC takes a single arg (fd).
    let r = unsafe { syscall1(SYS_FSYNC, fd as u64) };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `fdatasync(fd)` — like [`fsync`] but only metadata-omitted.
/// Same handler as `fsync`; the FS surface doesn't distinguish.
#[inline]
pub fn fdatasync(fd: u32) -> i32 {
    // SAFETY: SYS_FDATASYNC takes a single arg (fd).
    let r = unsafe { syscall1(SYS_FDATASYNC, fd as u64) };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `times(buf)` — write `[utime, stime, cutime, cstime]` (POSIX
/// `struct tms` shape, in 100Hz clock ticks) into `buf` and
/// return the wall-clock ticks since boot. -1 on error.
#[inline]
pub fn times(buf: &mut [i64; 4]) -> i64 {
    // SAFETY: SYS_TIMES signature: (out_ptr).
    let r = unsafe { syscall1(SYS_TIMES, buf.as_mut_ptr() as u64) };
    r as i64
}

/// `getrusage(who, buf)` — fill the 18-i64 rusage struct (two
/// timevals + 14 stat fields). Returns 0 on success, -1 on bad
/// pointer.
#[inline]
pub fn getrusage(who: i32, buf: &mut [i64; 18]) -> i32 {
    // SAFETY: SYS_GETRUSAGE signature: (who, out_ptr).
    let r = unsafe {
        syscall2(SYS_GETRUSAGE, who as u64, buf.as_mut_ptr() as u64)
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `umask(new_mask)` — set the file-creation mask and return the
/// previous value. Only the low 9 bits are honoured.
#[inline]
pub fn umask(new_mask: u32) -> u32 {
    // SAFETY: SYS_UMASK signature: (new_mask).
    unsafe { syscall1(SYS_UMASK, new_mask as u64) as u32 }
}

/// `tgkill(tgid, tid, sig)` — Linux thread-group kill. Falls back
/// to single-target kill on NARF (single-threaded per process).
/// Returns 0 on success, -1 on bad signum / unknown tid.
#[inline]
pub fn tgkill(tgid: i64, tid: u64, signum: u32) -> i32 {
    // SAFETY: SYS_TGKILL signature: (tgid, tid, signum).
    let r = unsafe {
        syscall3(SYS_TGKILL, tgid as u64, tid, signum as u64)
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `futex(uaddr, op, val, timeout, uaddr2, val3)` — Linux futex(2).
/// Stage-4 NARF honours only FUTEX_WAIT (0) and FUTEX_WAKE (1)
/// (with optional FUTEX_PRIVATE and FUTEX_CLOCK_REALTIME bits);
/// every other op returns -1.
#[inline]
pub fn futex(
    uaddr:   *mut u32,
    op:      u32,
    val:     u32,
    timeout: u64,
    uaddr2:  u64,
    val3:    u32,
) -> i64 {
    // SAFETY: SYS_FUTEX signature mirrors Linux:
    //   (uaddr, op, val, timeout/uaddr2, uaddr2, val3).
    let r = unsafe {
        syscall6(
            SYS_FUTEX,
            uaddr as u64, op as u64, val as u64,
            timeout, uaddr2, val3 as u64,
        )
    };
    r as i64
}

/// `prctl(op, arg_a, arg_b)` — Linux per-task settings switchboard.
/// `op` selects the subop (PR_SET_NAME = 15, PR_GET_NAME = 16,
/// PR_SET_DUMPABLE = 4, PR_GET_DUMPABLE = 3, etc.). Returns 0 on
/// success or the requested value (PR_GET_*); -1 on bad op.
#[inline]
pub fn prctl(op: u32, arg_a: u64, arg_b: u64) -> i64 {
    // SAFETY: SYS_PRCTL signature: (op, arg_a, arg_b).
    let r = unsafe { syscall3(SYS_PRCTL, op as u64, arg_a, arg_b) };
    r as i64
}

/// `gettid()` — Linux thread id. NARF is single-threaded per
/// process so this aliases getpid; the surface exists so a libc
/// shim has the right ABI for when threading lands.
#[inline]
pub fn gettid() -> u64 {
    // SAFETY: SYS_GETTID takes no args.
    unsafe { syscall0(SYS_GETTID) }
}

/// `sched_get_priority_max(policy)` — POSIX scheduler bound.
/// Returns the highest sched_priority valid for `policy`, or -1
/// for an unknown policy.
#[inline]
pub fn sched_get_priority_max(policy: u32) -> i32 {
    // SAFETY: SYS_SCHED_GET_PRIORITY_MAX signature: (policy).
    let r = unsafe { syscall1(SYS_SCHED_GET_PRIORITY_MAX, policy as u64) };
    r as i32
}

/// `sched_get_priority_min(policy)` — POSIX scheduler bound.
#[inline]
pub fn sched_get_priority_min(policy: u32) -> i32 {
    // SAFETY: SYS_SCHED_GET_PRIORITY_MIN signature: (policy).
    let r = unsafe { syscall1(SYS_SCHED_GET_PRIORITY_MIN, policy as u64) };
    r as i32
}

/// `sched_getparam(pid)` — read the calling task's
/// `sched_priority`. Pass `pid=0` for self.
#[inline]
pub fn sched_getparam(pid: u64) -> i32 {
    let mut prio: i32 = 0;
    // SAFETY: SYS_SCHED_GETPARAM signature: (pid, out_ptr).
    let r = unsafe {
        syscall2(SYS_SCHED_GETPARAM, pid, &mut prio as *mut i32 as u64)
    };
    if r as i64 == -1 { -1 } else { prio }
}

/// `sched_setparam(pid, prio)` — set sched_priority.
#[inline]
pub fn sched_setparam(pid: u64, prio: i32) -> i32 {
    let val: i32 = prio;
    // SAFETY: SYS_SCHED_SETPARAM signature: (pid, in_ptr).
    let r = unsafe {
        syscall2(SYS_SCHED_SETPARAM, pid, &val as *const i32 as u64)
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `sched_getaffinity(pid, mask)` — fill `mask` with the CPU
/// affinity bitmap of `pid` (0 = self). Returns the byte count
/// written on success, -1 on bad input.
#[inline]
pub fn sched_getaffinity(pid: u32, mask: &mut [u8]) -> isize {
    if mask.is_empty() { return -1; }
    // SAFETY: SYS_SCHED_GETAFFINITY signature: (pid, size, mask_ptr).
    let r = unsafe {
        syscall3(
            SYS_SCHED_GETAFFINITY,
            pid as u64, mask.len() as u64, mask.as_mut_ptr() as u64,
        )
    };
    r as isize
}

/// `sched_setaffinity(pid, mask)` — record a desired affinity
/// bitmap. NARF doesn't pin tasks; the bitmap is read but ignored.
/// Returns 0 on success, -1 on bad input.
#[inline]
pub fn sched_setaffinity(pid: u32, mask: &[u8]) -> i32 {
    if mask.is_empty() { return -1; }
    // SAFETY: SYS_SCHED_SETAFFINITY signature: (pid, size, mask_ptr).
    let r = unsafe {
        syscall3(
            SYS_SCHED_SETAFFINITY,
            pid as u64, mask.len() as u64, mask.as_ptr() as u64,
        )
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `getcpu(*cpu, *node)` — write the current CPU id and NUMA
/// node id through the out-pointers (either may be null). Always
/// returns 0; NARF user mode is single-CPU so both write 0.
#[inline]
pub fn getcpu() -> (u32, u32) {
    let mut cpu: u32  = !0;
    let mut node: u32 = !0;
    // SAFETY: SYS_GETCPU signature: (cpu_ptr, node_ptr).
    let _ = unsafe {
        syscall2(SYS_GETCPU, &mut cpu as *mut u32 as u64, &mut node as *mut u32 as u64)
    };
    (cpu, node)
}

/// `getpriority(which, who)` — read the calling task's nice value.
/// Linux convention: returns the value shifted by +20 (so the
/// caller subtracts 20 to recover the signed nice). Returns -1 on
/// bad `which`.
#[inline]
pub fn getpriority(which: u32, who: u32) -> i64 {
    // SAFETY: SYS_GETPRIORITY signature: (which, who).
    let r = unsafe { syscall2(SYS_GETPRIORITY, which as u64, who as u64) };
    if r as i64 == -1 { -1 } else { (r as i64) - 20 }
}

/// `setpriority(which, who, prio)` — record a new nice value
/// (-20..=19). Returns 0 on success, -1 on bad `which` or
/// out-of-range prio.
#[inline]
pub fn setpriority(which: u32, who: u32, prio: i32) -> i32 {
    // SAFETY: SYS_SETPRIORITY signature: (which, who, prio).
    let r = unsafe {
        syscall3(SYS_SETPRIORITY, which as u64, who as u64, prio as u64)
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `getrlimit(resource, out)` — read the calling task's
/// `rlim { cur, max }` pair for `resource`. `out` receives two
/// u64s: rlim_cur, rlim_max. Returns 0 on success, -1 on bad
/// pointer / out-of-range resource.
#[inline]
pub fn getrlimit(resource: u32, out: &mut [u64; 2]) -> i32 {
    // SAFETY: SYS_GETRLIMIT signature: (resource, out_ptr).
    let r = unsafe {
        syscall2(SYS_GETRLIMIT, resource as u64, out.as_mut_ptr() as u64)
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `setrlimit(resource, val)` — record `val = [cur, max]`.
#[inline]
pub fn setrlimit(resource: u32, val: &[u64; 2]) -> i32 {
    // SAFETY: SYS_SETRLIMIT signature: (resource, in_ptr).
    let r = unsafe {
        syscall2(SYS_SETRLIMIT, resource as u64, val.as_ptr() as u64)
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `prlimit64(pid, resource, new, old)` — combined Linux get-and-
/// set. Pass `pid = 0` for self. `new` / `old` may each be `None`.
/// Returns 0 on success, -1 on bad input.
#[inline]
pub fn prlimit64(
    pid:      u64,
    resource: u32,
    new_val:  Option<&[u64; 2]>,
    old_out:  Option<&mut [u64; 2]>,
) -> i32 {
    let new_ptr = new_val.map(|v| v.as_ptr() as u64).unwrap_or(0);
    let old_ptr = old_out.map(|v| v.as_mut_ptr() as u64).unwrap_or(0);
    // SAFETY: SYS_PRLIMIT64 signature: (pid, resource, new_ptr, old_ptr).
    let r = unsafe {
        syscall4(SYS_PRLIMIT64, pid, resource as u64, new_ptr, old_ptr)
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `gethostname(buf)` — copy the kernel-wide hostname into `buf`,
/// NUL-terminated. Returns the byte length excluding the NUL on
/// success, -1 on `buf.len() < name_len + 1`.
#[inline]
pub fn gethostname(buf: &mut [u8]) -> i32 {
    if buf.is_empty() { return -1; }
    // SAFETY: SYS_GETHOSTNAME signature: (buf_ptr, buf_len).
    let r = unsafe {
        syscall2(SYS_GETHOSTNAME, buf.as_mut_ptr() as u64, buf.len() as u64)
    };
    if r as i64 == -1 { -1 } else { r as i32 }
}

/// `sethostname(s)` — replace the kernel-wide hostname.
#[inline]
pub fn sethostname(s: &str) -> i32 {
    if s.is_empty() { return -1; }
    // SAFETY: SYS_SETHOSTNAME signature: (buf_ptr, buf_len).
    let r = unsafe {
        syscall2(SYS_SETHOSTNAME, s.as_ptr() as u64, s.len() as u64)
    };
    if r as i64 == -1 { -1 } else { 0 }
}

// ── Memory ─────────────────────────────────────────────────────────

/// Map `len` bytes near `hint` with `flags`. Returns the mapped
/// vaddr, or [`core::ptr::null_mut`] on failure (the kernel signals
/// failure with `0` or `!0u64`).
///
/// # Safety
/// The returned pointer is valid for `len` bytes only on success;
/// callers must check for null before dereferencing. The mapping's
/// permissions and lifetime are governed by `flags` + the kernel's
/// per-task address-space rules.
#[inline]
pub unsafe fn mmap(hint: usize, len: usize, flags: u32) -> *mut u8 {
    // SAFETY: SYS_MMAP signature: arg0 hint, arg1 len, arg2 flags.
    let r = unsafe { syscall3(SYS_MMAP, hint as u64, len as u64, flags as u64) };
    if r == 0 || r == !0u64 {
        core::ptr::null_mut()
    } else {
        r as *mut u8
    }
}

/// Geometry + format of a connected scanout. Filled by [`fb_info`].
/// Layout matches the kernel-side `[u32; 6]` wire format.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct FbInfo {
    pub width:        u32,
    pub height:       u32,
    pub stride_bytes: u32,
    /// `1 = XRGB8888`. New formats add new tags; this is not a
    /// bitfield.
    pub format:       u32,
    pub scanout_id:   u32,
    pub _resv:        u32,
}

/// Format tag returned in `FbInfo::format` for XRGB8888 scanouts.
pub const FB_FORMAT_XRGB8888: u32 = 1;

/// Open an FB connection to `scanout_id` (`0` for the active
/// scanout). Returns a non-zero handle on success, `0` on failure.
///
/// # Safety
/// Pure syscall — no preconditions.
#[inline]
pub unsafe fn fb_connect(scanout_id: u32) -> u64 {
    // SAFETY: SYS_FB_CONNECT takes (scanout_id) in arg0.
    unsafe { syscall1(SYS_FB_CONNECT, scanout_id as u64) }
}

/// Query the connected scanout's geometry. Returns `Ok` on success,
/// `Err` on bad handle / bad pointer.
///
/// # Safety
/// `handle` must be a live handle from [`fb_connect`].
#[inline]
pub unsafe fn fb_info(handle: u64) -> Result<FbInfo, ()> {
    let mut out = FbInfo::default();
    // SAFETY: SYS_FB_INFO writes 6 u32s through the user pointer;
    // FbInfo is repr(C) and 24 bytes (u32 × 6).
    let r = unsafe {
        syscall2(SYS_FB_INFO, handle, &mut out as *mut FbInfo as u64)
    };
    if r == 0 { Ok(out) } else { Err(()) }
}

/// Map the connection's draw-ring into the caller's VA. Returns the
/// 4 KiB region's base, or `null_mut` on failure.
///
/// # Safety
/// `handle` must be a live handle from [`fb_connect`]. The
/// returned VA aliases kernel-owned memory; the caller upholds the
/// SharedRing SPSC contract on the producer side.
#[inline]
pub unsafe fn fb_ring_map(handle: u64) -> *mut u8 {
    // SAFETY: SYS_FB_RING_MAP signature: arg0 handle.
    let r = unsafe { syscall1(SYS_FB_RING_MAP, handle) };
    if r == 0 || r == !0u64 { core::ptr::null_mut() } else { r as *mut u8 }
}

/// Snapshot the cumulative drain count for `handle`. Today this is
/// non-blocking; the contract leaves room for vsync / backpressure
/// blocking in the future.
///
/// # Safety
/// `handle` must be a live handle from [`fb_connect`].
#[inline]
pub unsafe fn fb_flush_wait(handle: u64) -> u64 {
    // SAFETY: SYS_FB_FLUSH_WAIT signature: arg0 handle.
    unsafe { syscall1(SYS_FB_FLUSH_WAIT, handle) }
}

/// Tear down a connection. Auto-called on process exit; explicit
/// calls are for graceful shutdown.
///
/// # Safety
/// `handle` must be a live handle from [`fb_connect`]; the caller
/// must not retain any pointer derived from [`fb_ring_map`] past
/// this call.
#[inline]
pub unsafe fn fb_disconnect(handle: u64) -> Result<(), ()> {
    // SAFETY: SYS_FB_DISCONNECT signature: arg0 handle.
    let r = unsafe { syscall1(SYS_FB_DISCONNECT, handle) };
    if r == 0 { Ok(()) } else { Err(()) }
}

/// Unmap a previously [`mmap`]-returned region. Returns Ok on
/// success; the kernel returns 0 on success, non-zero on error.
///
/// # Safety
/// `addr` must be a pointer previously returned from [`mmap`] (or
/// the kernel-side equivalent) and not already unmapped.
#[inline]
pub unsafe fn munmap(addr: *mut u8) -> Result<(), ()> {
    // SAFETY: SYS_MUNMAP signature: arg0 addr.
    let r = unsafe { syscall1(SYS_MUNMAP, addr as u64) };
    if r == 0 { Ok(()) } else { Err(()) }
}

/// Query (`new_break == 0`) or resize the per-task heap break.
/// Returns the (post-call) break value. POSIX brk(2) semantics:
/// failure returns the unchanged break.
#[inline]
pub fn brk(new_break: usize) -> usize {
    // SAFETY: SYS_BRK signature: arg0 new break (0 = query).
    unsafe { syscall1(SYS_BRK, new_break as u64) as usize }
}

// ── Working directory ─────────────────────────────────────────────

/// Update the calling task's current working directory. Stage-4
/// first cut: absolute paths only (must start with `/`); the
/// kernel rejects relative paths until `*at(2)` lands. Returns 0
/// on success, -1 on error (matching POSIX `chdir(3)` shape).
#[inline]
pub fn chdir(path: &str) -> i32 {
    // SAFETY: SYS_CHDIR signature: (path_ptr, path_len). Pointer
    // stays valid across the call because `&str` borrows outlive
    // the syscall.
    let r = unsafe {
        syscall2(SYS_CHDIR, path.as_ptr() as u64, path.len() as u64)
    };
    if r == 0 { 0 } else { -1 }
}

/// Read the calling task's current working directory into `buf`.
/// On success returns the byte length of the path (excluding the
/// NUL terminator), matching the kernel's return-on-success shape.
/// On any error (buffer too small, no cwd table) returns -1; the
/// libc wrapper then translates to ERANGE.
#[inline]
pub fn getcwd(buf: &mut [u8]) -> i32 {
    // SAFETY: SYS_GETCWD signature: (buf_ptr, buf_len). The kernel
    // writes ≤ buf.len() bytes (NUL-terminated) when buf is large
    // enough; otherwise returns InvalidOp and we don't trust the
    // buffer state.
    let r = unsafe {
        syscall2(SYS_GETCWD, buf.as_mut_ptr() as u64, buf.len() as u64)
    };
    // The kernel returns the byte length on success; treat the
    // sentinel `!0u64` (InvalidOp's payload) as failure as well so
    // callers don't observe a 64-bit length when truncated.
    if r == !0u64 { -1 } else { r as i32 }
}

// ── Sleep ──────────────────────────────────────────────────────────

/// Sleep for at least `ns` nanoseconds. The kernel-side handler
/// today spin-waits in trap context (see `sys_sleep` in
/// `userspace/src/handlers.rs`); long sleeps therefore burn the
/// calling CPU. This wrapper just plumbs the request through —
/// the user-visible contract is "blocks for ≥ ns wall time".
/// Returns 0 on success.
#[inline]
pub fn nanosleep(ns: u64) -> i32 {
    // SAFETY: SYS_SLEEP signature: arg0 ns.
    let r = unsafe { syscall1(SYS_SLEEP, ns) };
    if r == 0 { 0 } else { -1 }
}

// ── VFS ────────────────────────────────────────────────────────────

/// Open `path` under `mount`. Returns the fd on success, `None`
/// on failure (kernel returns `!0u64`). Convenience for the
/// `flags = 0` (read-existing) case; see [`open_flags`] for
/// `O_CREAT` / `O_TRUNC`-style usage.
#[inline]
pub fn open(path: &str, mount: &str) -> Option<u32> {
    open_flags(path, mount, 0)
}

/// `O_CREAT` — create the file if missing. Numeric value matches
/// Linux so a libc shim can re-use `<fcntl.h>` constants verbatim.
pub const O_CREAT: u64 = 0o100;

/// Open `path` under `mount` with explicit flags. The kernel
/// honours `O_CREAT` on the absolute-path form (mount = "")
/// today; other flags are accepted and ignored.
#[inline]
pub fn open_flags(path: &str, mount: &str, flags: u64) -> Option<u32> {
    // SAFETY: SYS_OPEN takes (path_ptr, path_len, mount_ptr, mount_len, flags).
    // The pointers stay valid for the trap because `&str` borrows
    // outlive the call.
    let r = unsafe {
        syscall5(
            SYS_OPEN,
            path.as_ptr() as u64, path.len() as u64,
            mount.as_ptr() as u64, mount.len() as u64,
            flags,
        )
    };
    if r == !0u64 { None } else { Some(r as u32) }
}

/// Read up to `buf.len()` bytes from `fd` into `buf`. Returns the
/// byte count.
#[inline]
pub fn read(fd: u32, buf: &mut [u8]) -> usize {
    // SAFETY: SYS_READ signature: (fd, buf_ptr, buf_len).
    unsafe {
        syscall3(SYS_READ, fd as u64, buf.as_mut_ptr() as u64, buf.len() as u64) as usize
    }
}

/// Write `buf` to `fd`. Returns the byte count.
#[inline]
pub fn write(fd: u32, buf: &[u8]) -> usize {
    // SAFETY: SYS_WRITE signature: (fd, buf_ptr, buf_len).
    unsafe {
        syscall3(SYS_WRITE, fd as u64, buf.as_ptr() as u64, buf.len() as u64) as usize
    }
}

/// Close `fd`. The kernel returns 0 on success.
#[inline]
pub fn close(fd: u32) -> Result<(), ()> {
    // SAFETY: SYS_CLOSE signature: (fd).
    let r = unsafe { syscall1(SYS_CLOSE, fd as u64) };
    if r == 0 { Ok(()) } else { Err(()) }
}

/// Open `path` as an absolute path, with the kernel walking its
/// mount table to find the longest matching prefix. Returns the
/// fd on success, `None` on failure. Equivalent to calling
/// [`open`] with an empty `mount` argument; provided as a named
/// helper so the absolute-path-only call site reads naturally.
#[inline]
pub fn open_abs(path: &str) -> Option<u32> {
    open(path, "")
}

// ── Dup family + fcntl ─────────────────────────────────────────────

/// `dup(oldfd)` — install a clone of `oldfd` at the lowest free
/// slot ≥ 3. Returns the new fd, or `None` when the kernel rejects
/// the call (e.g. `oldfd` not open).
#[inline]
pub fn dup(oldfd: u32) -> Option<u32> {
    // SAFETY: SYS_DUP signature: (oldfd).
    let r = unsafe { syscall1(SYS_DUP, oldfd as u64) };
    if r == !0u64 { None } else { Some(r as u32) }
}

/// `dup2(oldfd, newfd)` — install a clone at exactly `newfd`,
/// closing whatever was there. Returns `newfd` on success.
#[inline]
pub fn dup2(oldfd: u32, newfd: u32) -> Option<u32> {
    // SAFETY: SYS_DUP2 signature: (oldfd, newfd).
    let r = unsafe { syscall2(SYS_DUP2, oldfd as u64, newfd as u64) };
    if r == !0u64 { None } else { Some(r as u32) }
}

/// `dup3(oldfd, newfd, flags)` — like [`dup2`] but `flags` controls
/// `FD_CLOEXEC` on the new fd. `dup3(fd, fd, 0)` is an error per
/// Linux — pass `dup2` for the same-fd no-op.
#[inline]
pub fn dup3(oldfd: u32, newfd: u32, flags: u32) -> Option<u32> {
    // SAFETY: SYS_DUP3 signature: (oldfd, newfd, flags). RDX must be
    // declared inout per the ≥3-arg convention (commit b3c6517).
    let r = unsafe { syscall3(SYS_DUP3, oldfd as u64, newfd as u64, flags as u64) };
    if r == !0u64 { None } else { Some(r as u32) }
}

/// `fcntl(fd, cmd, arg)` — supports `F_GETFD` / `F_SETFD` /
/// `F_GETFL` / `F_SETFL`. Other commands surface as `-1` (the
/// invalid-op return).
#[inline]
pub fn fcntl(fd: u32, cmd: u32, arg: u64) -> i64 {
    // SAFETY: SYS_FCNTL signature: (fd, cmd, arg). 3 args → RDX inout.
    let r = unsafe { syscall3(SYS_FCNTL, fd as u64, cmd as u64, arg) };
    if r == !0u64 { -1 } else { r as i64 }
}

// ── Stat / Fstat / Pipe ────────────────────────────────────────────

/// Wire-stable stat output. Mirrors the kernel-side struct in
/// `userspace/src/handlers.rs::StatBuf` exactly. **Wire-stable** —
/// updates must land on both sides simultaneously. `mode` carries
/// the FileType in the high bits (`0o100000` file, `0o040000` dir)
/// and the perm triplet in the low 9 bits.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct StatBuf {
    pub size:         u64,
    pub blocks:       u64,
    pub mode:         u32,
    pub _pad:         u32,
    pub mtime_cycles: u64,
}

/// `stat(path, &mut out)` — write the stat result for the file at
/// the given absolute path. Returns 0 on success, -1 on failure.
#[inline]
pub fn stat(path: &str, out: &mut StatBuf) -> i32 {
    // SAFETY: SYS_STAT signature: (path_ptr, path_len, out_ptr).
    let r = unsafe {
        syscall3(
            SYS_STAT,
            path.as_ptr() as u64,
            path.len() as u64,
            out as *mut StatBuf as u64,
        )
    };
    if r == 0 { 0 } else { -1 }
}

/// `lstat(path, &mut out)` — like [`stat`] but doesn't follow
/// symlinks. NARF has no symlink support, so behaviour is
/// identical to `stat`.
#[inline]
pub fn lstat(path: &str, out: &mut StatBuf) -> i32 {
    // SAFETY: SYS_LSTAT signature mirrors SYS_STAT.
    let r = unsafe {
        syscall3(
            SYS_LSTAT,
            path.as_ptr() as u64,
            path.len() as u64,
            out as *mut StatBuf as u64,
        )
    };
    if r == 0 { 0 } else { -1 }
}

/// `fstat(fd, &mut out)` — write the stat result for the open fd.
/// Returns 0 on success, -1 on failure.
#[inline]
pub fn fstat(fd: u32, out: &mut StatBuf) -> i32 {
    // SAFETY: SYS_FSTAT signature: (fd, out_ptr).
    let r = unsafe {
        syscall2(SYS_FSTAT, fd as u64, out as *mut StatBuf as u64)
    };
    if r == 0 { 0 } else { -1 }
}

/// `lseek(fd, offset, whence)` — update the per-fd offset and
/// return the new value as i64. `whence` is 0=SET, 1=CUR, 2=END.
/// Returns -1 on kernel-side failure (out-of-range fd, negative
/// resulting offset, etc.); the C `off_t` shape preserves the i64
/// width so callers can distinguish the sentinel from a valid
/// large offset by the kernel `status` channel — but at the libc
/// surface the only signal is the value itself.
#[inline]
pub fn lseek(fd: u32, offset: i64, whence: u32) -> i64 {
    // SAFETY: SYS_LSEEK signature: (fd, offset, whence). The asm
    // wrapper preserves the rdx clobber convention — see the
    // `inout("rdx") a2 => _` clause in `syscall3`.
    let r = unsafe {
        syscall3(SYS_LSEEK, fd as u64, offset as u64, whence as u64)
    };
    r as i64
}

/// `unlink(path)` — remove a file by absolute path. Returns 0 on
/// success, -1 on failure. The kernel routes through
/// `DirOps::unlink` on the parent directory; FSes that don't
/// implement removal (initramfs, virtiofs skeleton) surface -1.
#[inline]
pub fn unlink(path: &str) -> i32 {
    // SAFETY: SYS_UNLINK signature: (path_ptr, path_len). Failure
    // sentinel is `-1` cast to u64 because the asm wrapper observes
    // only the value register, not the status.
    let r = unsafe {
        syscall2(SYS_UNLINK, path.as_ptr() as u64, path.len() as u64)
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `mkdir(path, mode)` — create a directory. Returns 0 / -1.
/// `mode` is accepted and ignored today.
#[inline]
pub fn mkdir(path: &str, mode: u32) -> i32 {
    // SAFETY: SYS_MKDIR signature: (path_ptr, path_len, mode).
    let r = unsafe {
        syscall3(
            SYS_MKDIR,
            path.as_ptr() as u64, path.len() as u64,
            mode as u64,
        )
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `rmdir(path)` — remove an empty directory. Returns 0 / -1.
#[inline]
pub fn rmdir(path: &str) -> i32 {
    // SAFETY: SYS_RMDIR signature: (path_ptr, path_len).
    let r = unsafe {
        syscall2(SYS_RMDIR, path.as_ptr() as u64, path.len() as u64)
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `rename(old, new)` — same-directory rename. Returns 0 / -1.
/// Cross-directory rename is unsupported today.
#[inline]
pub fn rename(old_path: &str, new_path: &str) -> i32 {
    // SAFETY: SYS_RENAME signature:
    //   (old_ptr, old_len, new_ptr, new_len).
    let r = unsafe {
        syscall4(
            SYS_RENAME,
            old_path.as_ptr() as u64, old_path.len() as u64,
            new_path.as_ptr() as u64, new_path.len() as u64,
        )
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `readlink(path, buf)` — read a symlink target. Backed by
/// SYS_READLINK / SYS_SYMLINK; NARF supports symlinks via MemFs.
/// Returns the byte count copied on success, -1 on lookup failure.
#[inline]
pub fn readlink(path: &str, buf: &mut [u8]) -> isize {
    if path.is_empty() || buf.is_empty() { return -1; }
    // SAFETY: SYS_READLINK signature: (path_ptr, path_len, buf_ptr, buf_len).
    let r = unsafe {
        syscall4(
            SYS_READLINK,
            path.as_ptr() as u64, path.len() as u64,
            buf.as_mut_ptr() as u64, buf.len() as u64,
        )
    };
    r as isize
}

/// `symlink(target, link)` — create a symlink. Backed by
/// SYS_READLINK / SYS_SYMLINK; NARF supports symlinks via MemFs.
/// Returns 0 on success, -1 on duplicate or unmounted parent.
#[inline]
pub fn symlink(target: &str, link: &str) -> i32 {
    if target.is_empty() || link.is_empty() { return -1; }
    // SAFETY: SYS_SYMLINK signature:
    //   (target_ptr, target_len, link_ptr, link_len).
    let r = unsafe {
        syscall4(
            SYS_SYMLINK,
            target.as_ptr() as u64, target.len() as u64,
            link.as_ptr() as u64, link.len() as u64,
        )
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `getdents64(path, cursor, out)` — batched directory read.
/// Writes as many `linux_dirent64` records as fit into `out`,
/// returning the total bytes written. The caller advances
/// `cursor` by counting entries off the records' `d_off` fields.
/// Returns 0 on end-of-directory, -1 on error.
#[inline]
pub fn getdents64(path: &str, cursor: u64, out: &mut [u8]) -> isize {
    if path.is_empty() || out.is_empty() { return -1; }
    // SAFETY: SYS_GETDENTS64 signature: (path_ptr, path_len, cursor,
    // out_ptr, out_len).
    let r = unsafe {
        syscall5(
            SYS_GETDENTS64,
            path.as_ptr() as u64, path.len() as u64,
            cursor,
            out.as_mut_ptr() as u64, out.len() as u64,
        )
    };
    r as isize
}

/// `listdir(path, cursor, out)` — read one directory entry at the
/// given cursor position into `out`. Wire format inside `out` is
/// `[name_len: u32][file_type: u32][name bytes...]`. Returns the
/// number of bytes written on success, 0 at end-of-directory, -1
/// on error. Buffer must be at least 8 bytes (the header) — for a
/// safe maximum, give it 264 bytes (8 header + 256 max name).
///
/// `file_type` values: 0=File, 1=Dir, 2=Symlink, 3=Special.
#[inline]
pub fn listdir(path: &str, cursor: u64, out: &mut [u8]) -> isize {
    if path.is_empty() || out.is_empty() { return -1; }
    // SAFETY: SYS_LISTDIR signature:
    //   (path_ptr, path_len, cursor, out_ptr, out_len).
    let r = unsafe {
        syscall5(
            SYS_LISTDIR,
            path.as_ptr() as u64,
            path.len() as u64,
            cursor,
            out.as_mut_ptr() as u64,
            out.len() as u64,
        )
    };
    r as isize
}

/// `getrandom(buf, flags)` — fill `buf` with up-to `buf.len()`
/// pseudo-random bytes. Stage-4 backing is a Park-Miller LCG
/// seeded from `monotonic_ns()` mixed with the cycle counter —
/// **not cryptographically secure**. Returns the byte count
/// written, or -1 on error. `flags` is accepted-and-ignored
/// (Linux's GRND_RANDOM / GRND_NONBLOCK / GRND_INSECURE have no
/// distinction at this seed quality).
#[inline]
pub fn getrandom(buf: &mut [u8], flags: u32) -> isize {
    if buf.is_empty() { return 0; }
    // SAFETY: SYS_GETRANDOM signature: (buf_ptr, buf_len, flags).
    let r = unsafe {
        syscall3(
            SYS_GETRANDOM,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            flags as u64,
        )
    };
    r as isize
}

/// `pipe()` — allocate a fresh pipe and install both halves in the
/// calling task's fd table. Returns `(read_fd, write_fd)` on success.
/// On failure (kernel returns non-zero), returns `None`.
#[inline]
pub fn pipe() -> Option<(u32, u32)> {
    let mut fds: [i32; 2] = [-1, -1];
    // SAFETY: SYS_PIPE signature: (out_ptr). The kernel writes two
    // i32s through the pointer; `fds` lives on this function's stack
    // for the duration of the syscall.
    let r = unsafe { syscall1(SYS_PIPE, fds.as_mut_ptr() as u64) };
    if r != 0 || fds[0] < 0 || fds[1] < 0 {
        None
    } else {
        Some((fds[0] as u32, fds[1] as u32))
    }
}

/// `fchmod(fd, mode)` — fd-keyed permission setter. NARF doesn't
/// enforce mode bits; the call succeeds on a known fd, fails on
/// closed.
#[inline]
pub fn fchmod(fd: u32, mode: u32) -> i32 {
    // SAFETY: SYS_FCHMOD signature: (fd, mode).
    let r = unsafe { syscall2(SYS_FCHMOD, fd as u64, mode as u64) };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `fchown(fd, uid, gid)` — fd-keyed owner setter. Same
/// accept-and-record semantics as [`fchmod`].
#[inline]
pub fn fchown(fd: u32, uid: u32, gid: u32) -> i32 {
    // SAFETY: SYS_FCHOWN signature: (fd, uid, gid).
    let r = unsafe { syscall3(SYS_FCHOWN, fd as u64, uid as u64, gid as u64) };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `unlinkat(dirfd, path, flags)` — Linux *at variant. flags
/// honoured: AT_REMOVEDIR (0x200) routes to rmdir.
#[inline]
pub fn unlinkat(dirfd: i32, path: &str, flags: i32) -> i32 {
    if path.is_empty() { return -1; }
    // SAFETY: SYS_UNLINKAT signature: (dirfd, path_ptr, path_len, flags).
    let r = unsafe {
        syscall4(
            SYS_UNLINKAT, dirfd as u64,
            path.as_ptr() as u64, path.len() as u64, flags as u64,
        )
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `mkdirat(dirfd, path, mode)` — Linux *at variant.
#[inline]
pub fn mkdirat(dirfd: i32, path: &str, mode: u32) -> i32 {
    if path.is_empty() { return -1; }
    // SAFETY: SYS_MKDIRAT signature: (dirfd, path_ptr, path_len, mode).
    let r = unsafe {
        syscall4(
            SYS_MKDIRAT, dirfd as u64,
            path.as_ptr() as u64, path.len() as u64, mode as u64,
        )
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `renameat(old_dirfd, old, new_dirfd, new)` — Linux *at variant.
#[inline]
pub fn renameat(old_dirfd: i32, old: &str, new_dirfd: i32, new: &str) -> i32 {
    if old.is_empty() || new.is_empty() { return -1; }
    // SAFETY: SYS_RENAMEAT signature: (old_dirfd, old_ptr, old_len,
    // new_dirfd, new_ptr, new_len).
    let r = unsafe {
        syscall6(
            SYS_RENAMEAT, old_dirfd as u64,
            old.as_ptr() as u64, old.len() as u64,
            new_dirfd as u64,
            new.as_ptr() as u64, new.len() as u64,
        )
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `access(path, mode)` — legacy POSIX accessibility check.
/// Forwards to the SYS_ACCESS body (which reshapes onto the
/// faccessat handler). Returns 0 if the path resolves, -1
/// otherwise.
#[inline]
pub fn access(path: &str, mode: i32) -> i32 {
    if path.is_empty() { return -1; }
    // SAFETY: SYS_ACCESS signature: (path_ptr, path_len, mode).
    let r = unsafe {
        syscall3(
            SYS_ACCESS,
            path.as_ptr() as u64, path.len() as u64,
            mode as u64,
        )
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `chmod(path, mode)` — legacy POSIX mode set. Forwards to the
/// SYS_CHMOD body (which reshapes onto the fchmodat handler).
/// Mode bits aren't enforced; we only verify the path resolves.
#[inline]
pub fn chmod(path: &str, mode: u32) -> i32 {
    if path.is_empty() { return -1; }
    // SAFETY: SYS_CHMOD signature: (path_ptr, path_len, mode).
    let r = unsafe {
        syscall3(
            SYS_CHMOD,
            path.as_ptr() as u64, path.len() as u64,
            mode as u64,
        )
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `chown(path, uid, gid)` — legacy POSIX owner set. Forwards
/// to the SYS_CHOWN body (which reshapes onto the fchownat
/// handler). uid/gid aren't enforced; we only verify the path
/// resolves.
#[inline]
pub fn chown(path: &str, uid: u32, gid: u32) -> i32 {
    if path.is_empty() { return -1; }
    // SAFETY: SYS_CHOWN signature: (path_ptr, path_len, uid, gid).
    let r = unsafe {
        syscall4(
            SYS_CHOWN,
            path.as_ptr() as u64, path.len() as u64,
            uid as u64, gid as u64,
        )
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `symlinkat(target, dirfd, link)` — Linux *at variant of
/// symlink. dirfd is ignored; link must be absolute. Returns
/// 0 on success, -1 on failure.
#[inline]
pub fn symlinkat(target: &str, dirfd: i32, link: &str) -> i32 {
    if target.is_empty() || link.is_empty() { return -1; }
    // SAFETY: SYS_SYMLINKAT signature: (target_ptr, target_len, dirfd,
    // link_ptr, link_len).
    let r = unsafe {
        syscall5(
            SYS_SYMLINKAT,
            target.as_ptr() as u64, target.len() as u64,
            dirfd as u64,
            link.as_ptr() as u64, link.len() as u64,
        )
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `readlinkat(dirfd, path, buf)` — Linux *at variant of
/// readlink. dirfd is ignored; path must be absolute. Returns
/// the byte count copied on success, -1 on lookup failure.
#[inline]
pub fn readlinkat(dirfd: i32, path: &str, buf: &mut [u8]) -> isize {
    if path.is_empty() || buf.is_empty() { return -1; }
    // SAFETY: SYS_READLINKAT signature: (dirfd, path_ptr, path_len,
    // buf_ptr, buf_len).
    let r = unsafe {
        syscall5(
            SYS_READLINKAT, dirfd as u64,
            path.as_ptr() as u64, path.len() as u64,
            buf.as_mut_ptr() as u64, buf.len() as u64,
        )
    };
    r as isize
}

/// `fstatat(dirfd, path, stat_out, flags)` — Linux *at variant
/// of stat. Returns 0 on success, -1 on failure.
#[inline]
pub fn fstatat(
    dirfd: i32,
    path:  &str,
    out:   &mut StatBuf,
    flags: i32,
) -> i32 {
    if path.is_empty() { return -1; }
    // SAFETY: SYS_NEWFSTATAT signature: (dirfd, path_ptr, path_len,
    // stat_out, flags).
    let r = unsafe {
        syscall5(
            SYS_NEWFSTATAT, dirfd as u64,
            path.as_ptr() as u64, path.len() as u64,
            out as *mut StatBuf as u64, flags as u64,
        )
    };
    if r == 0 { 0 } else { -1 }
}

/// `openat(dirfd, path, flags, mode)` — Linux *at variant of
/// open. dirfd is ignored; path must be absolute. Returns the
/// new fd on success or `None` on failure.
#[inline]
pub fn openat(dirfd: i32, path: &str, flags: u64, mode: u32) -> Option<u32> {
    if path.is_empty() { return None; }
    // SAFETY: SYS_OPENAT signature: (dirfd, path_ptr, path_len, flags, mode).
    let r = unsafe {
        syscall5(
            SYS_OPENAT, dirfd as u64,
            path.as_ptr() as u64, path.len() as u64,
            flags, mode as u64,
        )
    };
    if r == !0u64 { None } else { Some(r as u32) }
}

/// `faccessat(dirfd, path, mode, flags)` — Linux *at variant of
/// access. NARF treats dirfd as ignored and requires an absolute
/// path; mode is structural-only (no permission enforcement).
#[inline]
pub fn faccessat(dirfd: i32, path: &str, mode: u32, flags: i32) -> i32 {
    if path.is_empty() { return -1; }
    // SAFETY: SYS_FACCESSAT signature: (dirfd, path_ptr, path_len, mode, flags).
    let r = unsafe {
        syscall5(
            SYS_FACCESSAT, dirfd as u64,
            path.as_ptr() as u64, path.len() as u64,
            mode as u64, flags as u64,
        )
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `fchmodat(dirfd, path, mode, flags)` — Linux *at variant.
/// Path must be absolute; dirfd is ignored.
#[inline]
pub fn fchmodat(dirfd: i32, path: &str, mode: u32, flags: i32) -> i32 {
    if path.is_empty() { return -1; }
    // SAFETY: SYS_FCHMODAT signature: (dirfd, path_ptr, path_len, mode, flags).
    let r = unsafe {
        syscall5(
            SYS_FCHMODAT, dirfd as u64,
            path.as_ptr() as u64, path.len() as u64,
            mode as u64, flags as u64,
        )
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `fchownat(dirfd, path, uid, gid, flags)` — Linux *at variant.
#[inline]
pub fn fchownat(dirfd: i32, path: &str, uid: u32, gid: u32, flags: i32) -> i32 {
    if path.is_empty() { return -1; }
    // SAFETY: SYS_FCHOWNAT signature: (dirfd, path_ptr, path_len, uid, gid, flags).
    let r = unsafe {
        syscall6(
            SYS_FCHOWNAT, dirfd as u64,
            path.as_ptr() as u64, path.len() as u64,
            uid as u64, gid as u64, flags as u64,
        )
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `memfd_create(name, flags)` — create an anonymous in-memory
/// file. Returns a fresh fd or -1.
#[inline]
pub fn memfd_create(name: &str, flags: u32) -> i32 {
    // SAFETY: SYS_MEMFD_CREATE signature: (name_ptr, name_len, flags).
    let r = unsafe {
        syscall3(
            SYS_MEMFD_CREATE,
            name.as_ptr() as u64, name.len() as u64, flags as u64,
        )
    };
    if r as i64 == -1 { -1 } else { r as i32 }
}

/// `copy_file_range(fd_in, fd_out, off_in, off_out, len, flags)` —
/// in-kernel copy between two open files. `off_in` and `off_out`
/// of `!0` mean "use the per-fd cursor"; any other value is the
/// explicit offset to start at and leaves the cursor alone.
/// flags must be 0.
#[inline]
pub fn copy_file_range(
    fd_in:  u32,
    fd_out: u32,
    off_in:  u64,
    off_out: u64,
    len:     usize,
    flags:   u32,
) -> isize {
    // SAFETY: SYS_COPY_FILE_RANGE signature:
    //   (fd_in, fd_out, off_in, off_out, len, flags).
    let r = unsafe {
        syscall6(
            SYS_COPY_FILE_RANGE,
            fd_in as u64, fd_out as u64,
            off_in, off_out, len as u64, flags as u64,
        )
    };
    r as isize
}

/// `fallocate(fd, mode, offset, len)` — preallocate file space.
/// Mode 0 ensures the file is at least `offset + len` bytes.
/// `FALLOC_FL_ZERO_RANGE` (0x10) additionally zeros the range.
#[inline]
pub fn fallocate(fd: u32, mode: u32, offset: u64, len: u64) -> i32 {
    // SAFETY: SYS_FALLOCATE signature: (fd, mode, offset, len).
    let r = unsafe {
        syscall4(SYS_FALLOCATE, fd as u64, mode as u64, offset, len)
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// `pipe2(flags)` — pipe + atomic flag set. `O_CLOEXEC` (bit
/// 0x80000) stamps FD_CLOEXEC on both halves; `O_NONBLOCK` is
/// accepted and ignored.
#[inline]
pub fn pipe2(flags: u32) -> Option<(u32, u32)> {
    let mut fds: [i32; 2] = [-1, -1];
    // SAFETY: SYS_PIPE2 signature: (out_ptr, flags).
    let r = unsafe {
        syscall2(SYS_PIPE2, fds.as_mut_ptr() as u64, flags as u64)
    };
    if r != 0 || fds[0] < 0 || fds[1] < 0 {
        None
    } else {
        Some((fds[0] as u32, fds[1] as u32))
    }
}

// ── Time / signal ──────────────────────────────────────────────────

/// Read `clock_id` and return the (sec, nsec) tuple. Internally
/// allocates a stack-local timespec and lets the kernel write into
/// it.
#[inline]
pub fn clock_gettime(clock_id: u32) -> (i64, i64) {
    let mut ts: [i64; 2] = [0, 0];
    // SAFETY: SYS_CLOCK_GETTIME signature: (clock_id, timespec_ptr).
    // `ts` lives on this function's stack for the duration of the
    // syscall.
    let _ = unsafe { syscall2(SYS_CLOCK_GETTIME, clock_id as u64, ts.as_mut_ptr() as u64) };
    (ts[0], ts[1])
}

/// `clock_settime(clock_id, sec, nsec)` — set the wall clock when
/// `clock_id == CLOCK_REALTIME` (0). Returns 0 on success, -1
/// when the clock isn't settable or the timespec is malformed.
#[inline]
pub fn clock_settime(clock_id: u32, sec: i64, nsec: i64) -> i32 {
    let ts: [i64; 2] = [sec, nsec];
    // SAFETY: SYS_CLOCK_SETTIME signature: (clock_id, timespec_ptr).
    let r = unsafe {
        syscall2(SYS_CLOCK_SETTIME, clock_id as u64, ts.as_ptr() as u64)
    };
    if r as i64 == -1 { -1 } else { 0 }
}

/// Install or clear a signal handler. Returns the prior handler
/// (0 if none was installed).
///
/// # Safety
/// `handler` must be a valid code-page entry-point address (or 0
/// to clear). Subsequent calls to [`kill`] against this task will
/// rewrite the trap-return frame to land at `handler`; the
/// handler must therefore be a valid `extern "C" fn(u32)`.
#[inline]
pub unsafe fn sigaction(signum: u32, handler: usize) -> usize {
    let mut old: u64 = 0;
    // SAFETY: SYS_SIGACTION signature: (signum, handler, old_out).
    // `old` lives on this function's stack across the call.
    unsafe {
        syscall4(
            SYS_SIGACTION,
            signum as u64,
            handler as u64,
            &mut old as *mut u64 as u64,
            0,
        );
    }
    old as usize
}

/// Mark `signum` pending on `target_pid`. The signal is delivered
/// the next time the target task returns to user mode through the
/// trap gate (which for a self-targeted kill happens on the very
/// next syscall trap-return). Returns `Ok(())` on success, `Err(())`
/// when the kernel rejects the request (e.g. signum out of range).
#[inline]
pub fn kill(target_pid: u64, signum: u32) -> Result<(), ()> {
    // SAFETY: SYS_KILL signature: (target_pid, signum).
    let r = unsafe { syscall2(SYS_KILL, target_pid, signum as u64) };
    if r == 0 { Ok(()) } else { Err(()) }
}

/// Update the calling task's signal-block mask and return the
/// previous mask. `how` is one of [`SIG_BLOCK`], [`SIG_UNBLOCK`],
/// [`SIG_SETMASK`].
#[inline]
pub fn sigprocmask(how: u32, set: u32) -> u32 {
    // SAFETY: SYS_SIGPROCMASK signature: (how, set). The kernel
    // returns the previous mask in the rax payload.
    unsafe { syscall2(SYS_SIGPROCMASK, how as u64, set as u64) as u32 }
}

// ── Bootstrap / rings ──────────────────────────────────────────────

/// Bootstrap header laid out at the start of the per-task config
/// page. **Wire-stable** — mirrors the `BootstrapHeader` struct in
/// `userspace/src/handlers.rs`. Both sides must update together if
/// fields are added or reordered.
#[repr(C)]
#[derive(Debug)]
pub struct BootstrapHeader {
    /// "NARF" little-endian (`NARF_MAGIC`).
    pub magic:    u32,
    /// ABI version (`BOOTSTRAP_ABI_VERSION` today).
    pub version:  u32,
    /// Calling task's monotonic id.
    pub task_id:  u64,
    /// Capslot id naming the SQ producer the kernel-side dispatcher
    /// is bound to.
    pub sq_cap:   u64,
    /// Capslot id naming the CQ consumer.
    pub cq_cap:   u64,
    /// Kernel-only Arc<Ring> depth for the SQ.
    pub sq_depth: u32,
    /// Kernel-only Arc<Ring> depth for the CQ.
    pub cq_depth: u32,
    /// User vaddr of the shared SubmissionRing page.
    pub shared_sq_vaddr: u64,
    /// User vaddr of the shared CompletionRing page.
    pub shared_cq_vaddr: u64,
    /// Depth for the SharedRing pair (must equal
    /// `BOOTSTRAP_SHARED_RING_DEPTH`).
    pub shared_depth: u32,
    /// Padding so the struct is `u64`-aligned at the tail.
    pub _pad: u32,
}

/// Mint per-task SQ + CQ rings + a config page. Returns the user
/// vaddr of the config page (cast to `*const BootstrapHeader`) on
/// success, `None` if the kernel returns 0 or `!0u64`.
///
/// # Safety
/// On success the kernel guarantees the returned pointer is valid
/// for at least `size_of::<BootstrapHeader>()` bytes and outlives
/// the calling task. Callers must check the magic word matches
/// [`NARF_MAGIC`] before trusting the rest of the header.
#[inline]
pub unsafe fn bootstrap() -> Option<*const BootstrapHeader> {
    // SAFETY: SYS_BOOTSTRAP takes no args.
    let r = unsafe { syscall0(SYS_BOOTSTRAP) };
    if r == 0 || r == !0u64 {
        None
    } else {
        Some(r as *const BootstrapHeader)
    }
}

/// Kick the kernel-side dispatcher to drain the calling task's
/// shared SubmissionRing and post Completions to the shared
/// CompletionRing. Returns the number of submissions processed.
#[inline]
pub fn ring_kick() -> u64 {
    // SAFETY: SYS_RING_KICK takes no args.
    unsafe { syscall0(SYS_RING_KICK) }
}

// ── Thread-local-storage ───────────────────────────────────────────
//
// SysV-AMD64 uses `fs` as the thread pointer; the kernel programs
// `IA32_FS_BASE` before each user-mode entry (see
// `narf_userspace::tls::stage_tls`). The TCB self-pointer at
// `*(fs:0)` equals `fs_base` itself — relibc / `narf-libc` reads it
// to discover the canonical TCB address without depending on the
// per-arch wrfsbase instruction.

/// Read the SysV-AMD64 thread pointer (`fs:[0]` on x86_64). Returns
/// the kernel-staged TCB self-pointer; for an inhabited TLS block
/// this equals the FS base.
///
/// On aarch64 the equivalent is `tpidr_el0`.
#[cfg(target_arch = "x86_64")]
#[inline]
pub fn thread_pointer() -> *mut u8 {
    let tp: u64;
    // SAFETY: `mov rax, fs:[0]` has no memory effect outside loading
    // 8 bytes from a mapped TLS slot — when no TLS is staged the
    // load reads whatever the previous task's FS base pointed at,
    // which is a kernel bug, not a UB hazard at this call site.
    // Reading from the segment base never traps if the base is a
    // valid canonical address (the TLS staging path enforces that).
    unsafe {
        core::arch::asm!(
            "mov {tp}, fs:[0]",
            tp = out(reg) tp,
            options(nostack, preserves_flags, readonly),
        );
    }
    tp as *mut u8
}

/// aarch64 equivalent reads `TPIDR_EL0` (the architectural thread
/// pointer; mirrors what the kernel programs on EL0 entry).
#[cfg(target_arch = "aarch64")]
#[inline]
pub fn thread_pointer() -> *mut u8 {
    let tp: u64;
    // SAFETY: TPIDR_EL0 is unconditionally readable at EL0; the
    // kernel writes it on each user-mode entry the same way x86_64
    // writes IA32_FS_BASE.
    unsafe {
        core::arch::asm!(
            "mrs {tp}, tpidr_el0",
            tp = out(reg) tp,
            options(nostack, preserves_flags),
        );
    }
    tp as *mut u8
}

// ── Output convenience ─────────────────────────────────────────────

/// `core::fmt::Write` adapter for stdout (`fd = 1`). Use with
/// `write!` / `writeln!` for formatted output.
#[derive(Debug, Default, Clone, Copy)]
pub struct Stdout;

impl fmt::Write for Stdout {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        // SYS_WRITE returns the byte count; partial writes count as
        // success for `fmt::Write` purposes (it can't surface a
        // short-write error anyway).
        write(1, s.as_bytes());
        Ok(())
    }
}

/// `core::fmt::Write` adapter for stderr (`fd = 2`).
#[derive(Debug, Default, Clone, Copy)]
pub struct Stderr;

impl fmt::Write for Stderr {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        write(2, s.as_bytes());
        Ok(())
    }
}

/// One-shot raw write of `s` to fd 1. Convenience for callers that
/// want to skip the `fmt::Write` plumbing for a static byte slice.
#[inline]
pub fn print_str(s: &str) {
    write(1, s.as_bytes());
}

//! The i386 system-call table (`arch/x86/entry/syscalls/syscall_32.tbl`).
//!
//! [`super::dispatch`] reaches this after seccomp and the TLS calls; it
//! owns nothing but the number → handler mapping. An i386 call whose
//! arguments match a native handler's is served with [`forward`]; one that
//! needs converting (64-bit argument pairs, compat structs) gets its own
//! handler. Unlisted numbers answer -ENOSYS (`sys_ni_syscall`).
//!
//! Each arm names the Linux entry point it mirrors. Handlers shared with
//! the native table pick the i386 layout themselves from
//! `TrapContext::in_ia32_syscall()` (Linux `in_compat_syscall()`: iovecs,
//! `struct stat64`, `struct compat_sigaction`, the robust-list head) or,
//! where one handler serves several i386 entry points, from the
//! [`Ia32Abi`] this table attaches ([`forward_abi`]). Arguments that are a
//! signed C type are sign-extended first ([`forward_sx`]), as the
//! `__ia32_sys_*` wrappers' `__SC_COMPAT_CAST` does; everything else —
//! pointers above all (`compat_ptr`) — stays zero-extended.

use narf_memory::AddressSpace;

use super::conv;
use super::ctx::Ia32ArgsCtx;
use crate::errno::{to_ret, EBADF, EINVAL, ENOMEM, ENOTTY};
use crate::syscall::Ia32Flock;
use crate::syscall::{Ia32Abi, Syscall, SyscallArgs, SyscallReturn, TrapContext};

/// i386 system-call numbers (`syscall_32.tbl`).
pub mod nr {
    pub const EXIT: u32 = 1;
    pub const READ: u32 = 3;
    pub const WRITE: u32 = 4;
    pub const OPEN: u32 = 5;
    pub const CLOSE: u32 = 6;
    pub const UNLINK: u32 = 10;
    pub const CHDIR: u32 = 12;
    pub const LSEEK: u32 = 19;
    pub const GETPID: u32 = 20;
    pub const GETUID: u32 = 24;
    pub const ACCESS: u32 = 33;
    pub const KILL: u32 = 37;
    pub const RENAME: u32 = 38;
    pub const MKDIR: u32 = 39;
    pub const RMDIR: u32 = 40;
    pub const DUP: u32 = 41;
    pub const PIPE: u32 = 42;
    pub const BRK: u32 = 45;
    pub const GETGID: u32 = 47;
    pub const GETEUID: u32 = 49;
    pub const GETEGID: u32 = 50;
    pub const IOCTL: u32 = 54;
    pub const FCNTL: u32 = 55;
    pub const UMASK: u32 = 60;
    pub const DUP2: u32 = 63;
    pub const GETPPID: u32 = 64;
    pub const READLINK: u32 = 85;
    pub const MMAP: u32 = 90;
    pub const MUNMAP: u32 = 91;
    pub const UNAME: u32 = 122;
    pub const MPROTECT: u32 = 125;
    pub const PERSONALITY: u32 = 136;
    pub const LLSEEK: u32 = 140;
    pub const READV: u32 = 145;
    pub const WRITEV: u32 = 146;
    pub const SCHED_YIELD: u32 = 158;
    pub const MREMAP: u32 = 163;
    pub const RT_SIGACTION: u32 = 174;
    pub const RT_SIGPROCMASK: u32 = 175;
    pub const PREAD64: u32 = 180;
    pub const PWRITE64: u32 = 181;
    pub const GETCWD: u32 = 183;
    pub const MMAP2: u32 = 192;
    pub const STAT64: u32 = 195;
    pub const LSTAT64: u32 = 196;
    pub const FSTAT64: u32 = 197;
    pub const GETUID32: u32 = 199;
    pub const GETGID32: u32 = 200;
    pub const GETEUID32: u32 = 201;
    pub const GETEGID32: u32 = 202;
    pub const GETRESUID32: u32 = 209;
    pub const GETRESGID32: u32 = 211;
    pub const MADVISE: u32 = 219;
    pub const GETDENTS64: u32 = 220;
    pub const FCNTL64: u32 = 221;
    pub const GETTID: u32 = 224;
    pub const TKILL: u32 = 238;
    pub const FUTEX: u32 = 240;
    pub const SCHED_GETAFFINITY: u32 = 242;
    pub const EXIT_GROUP: u32 = 252;
    pub const SET_TID_ADDRESS: u32 = 258;
    pub const CLOCK_GETTIME: u32 = 265;
    pub const TGKILL: u32 = 270;
    pub const OPENAT: u32 = 295;
    pub const MKDIRAT: u32 = 296;
    pub const FSTATAT64: u32 = 300;
    pub const UNLINKAT: u32 = 301;
    pub const READLINKAT: u32 = 305;
    pub const FACCESSAT: u32 = 307;
    pub const SET_ROBUST_LIST: u32 = 311;
    pub const DUP3: u32 = 330;
    pub const PIPE2: u32 = 331;
    pub const PRLIMIT64: u32 = 340;
    pub const GETRANDOM: u32 = 355;
    pub const STATX: u32 = 383;
    pub const ARCH_PRCTL: u32 = 384;
    pub const RSEQ: u32 = 386;
    pub const CLOCK_GETTIME64: u32 = 403;
    pub const FUTEX_TIME64: u32 = 422;
    pub const FACCESSAT2: u32 = 439;
}

/// i386 `exit`.
pub const NR_EXIT: u32 = nr::EXIT;
/// i386 `getpid`.
pub const NR_GETPID: u32 = nr::GETPID;
/// i386 `uname` (`sys_newuname`; `struct new_utsname` is ABI-identical).
pub const NR_UNAME: u32 = nr::UNAME;
/// i386 `sched_yield`.
pub const NR_SCHED_YIELD: u32 = nr::SCHED_YIELD;
/// i386 `gettid`.
pub const NR_GETTID: u32 = nr::GETTID;
/// i386 `exit_group`.
pub const NR_EXIT_GROUP: u32 = nr::EXIT_GROUP;

/// Serve i386 system call `nr` on `ctx`. Returns the native syscall that
/// served it, if any: [`super::dispatch`] classifies restartability by it
/// when the call parks to be re-executed.
pub fn dispatch(nr: u32, ctx: &mut dyn TrapContext) -> Option<Syscall> {
    use nr::*;
    // Bit i of a mask: argument i is a signed C type (`int`, `pid_t`,
    // `clockid_t`, ...) and is sign-extended.
    match nr {
        // kernel/exit.c
        EXIT => forward(ctx, Syscall::ExitTask),
        EXIT_GROUP => forward(ctx, Syscall::ExitGroup),
        // fs/read_write.c, fs/open.c, fs/pipe.c, fs/file.c
        READ => forward(ctx, Syscall::Read),
        WRITE => forward(ctx, Syscall::Write),
        // `sys_readv`/`sys_writev`: `import_iovec` reads compat_iovecs under
        // `in_compat_syscall()`.
        READV => forward(ctx, Syscall::Readv),
        WRITEV => forward(ctx, Syscall::Writev),
        // `compat_sys_open`/`compat_sys_openat`: `do_sys_open` without the
        // 64-bit O_LARGEFILE force.
        OPEN => forward(ctx, Syscall::OpenFile),
        OPENAT => forward_sx(ctx, Syscall::Openat, 0b101),
        CLOSE => forward(ctx, Syscall::Close),
        PIPE => forward(ctx, Syscall::Pipe),
        PIPE2 => forward(ctx, Syscall::Pipe2),
        DUP => forward(ctx, Syscall::Dup),
        DUP2 => forward(ctx, Syscall::Dup2),
        DUP3 => forward(ctx, Syscall::Dup3),
        IOCTL => compat_sys_ioctl(ctx),
        CHDIR => forward(ctx, Syscall::Chdir),
        GETCWD => forward(ctx, Syscall::Getcwd),
        UMASK => forward(ctx, Syscall::Umask),
        // `compat_sys_lseek` takes a `compat_off_t`; `sys_llseek` and the
        // `sys_ia32_p{read,write}64` wrappers carry a 64-bit offset in two
        // registers.
        LSEEK => forward_sx(ctx, Syscall::Lseek, 0b10),
        LLSEEK => sys_llseek(ctx),
        PREAD64 => sys_ia32_pread_pwrite(ctx, Syscall::Pread64),
        PWRITE64 => sys_ia32_pread_pwrite(ctx, Syscall::Pwrite64),
        GETDENTS64 => forward(ctx, Syscall::Getdents64),
        // `compat_sys_fcntl64` / `compat_sys_fcntl` (`do_compat_fcntl64`).
        FCNTL64 => compat_sys_fcntl64(ctx, true),
        FCNTL => compat_sys_fcntl64(ctx, false),
        // fs/stat.c via `cp_stat64` (`put_linux_stat` under
        // `in_ia32_syscall()`): `compat_sys_ia32_{stat,lstat,fstat,fstatat}64`.
        STAT64 => forward(ctx, Syscall::Stat),
        LSTAT64 => forward(ctx, Syscall::Lstat),
        FSTAT64 => forward(ctx, Syscall::Fstat),
        FSTATAT64 => forward_sx(ctx, Syscall::Newfstatat, 0b1),
        STATX => forward_sx(ctx, Syscall::Statx, 0b1),
        ACCESS => forward(ctx, Syscall::Access),
        FACCESSAT => forward_sx(ctx, Syscall::Faccessat, 0b1),
        FACCESSAT2 => forward_sx(ctx, Syscall::Faccessat2, 0b1),
        READLINK => forward(ctx, Syscall::Readlink),
        READLINKAT => forward_sx(ctx, Syscall::Readlinkat, 0b1001),
        UNLINK => forward(ctx, Syscall::Unlink),
        UNLINKAT => forward_sx(ctx, Syscall::Unlinkat, 0b101),
        MKDIR => forward(ctx, Syscall::Mkdir),
        MKDIRAT => forward_sx(ctx, Syscall::Mkdirat, 0b1),
        RMDIR => forward(ctx, Syscall::Rmdir),
        RENAME => forward(ctx, Syscall::Rename),
        // mm/
        BRK => forward(ctx, Syscall::Brk),
        MMAP2 => sys_mmap_pgoff(ctx),
        MMAP => compat_sys_ia32_mmap(ctx),
        MUNMAP => forward(ctx, Syscall::Munmap),
        MPROTECT => forward(ctx, Syscall::MProtect),
        MADVISE => forward(ctx, Syscall::Madvise),
        MREMAP => forward(ctx, Syscall::Mremap),
        // kernel/sys.c, kernel/exec_domain.c
        UNAME => forward(ctx, Syscall::Uname),
        PERSONALITY => forward(ctx, Syscall::Personality),
        GETPID => forward(ctx, Syscall::GetPid),
        GETPPID => forward(ctx, Syscall::GetPpid),
        GETTID => forward(ctx, Syscall::Gettid),
        GETUID32 => forward(ctx, Syscall::GetUid),
        GETGID32 => forward(ctx, Syscall::GetGid),
        GETEUID32 => forward(ctx, Syscall::Geteuid),
        GETEGID32 => forward(ctx, Syscall::Getegid),
        GETRESUID32 => forward(ctx, Syscall::Getresuid),
        GETRESGID32 => forward(ctx, Syscall::Getresgid),
        // The 16-bit uid calls (`sys_getuid16`, ...): `high2lowuid`.
        GETUID => uid16(ctx, Syscall::GetUid),
        GETGID => uid16(ctx, Syscall::GetGid),
        GETEUID => uid16(ctx, Syscall::Geteuid),
        GETEGID => uid16(ctx, Syscall::Getegid),
        // kernel/sys.c, kernel/resource: `struct rlimit64` is two u64s in
        // both ABIs.
        PRLIMIT64 => forward_sx(ctx, Syscall::Prlimit64, 0b1),
        GETRANDOM => forward(ctx, Syscall::GetRandom),
        // `compat_sys_sched_getaffinity`: the length unit is
        // `compat_ulong_t` (the native handler checks `in_ia32_syscall`).
        SCHED_GETAFFINITY => forward_sx(ctx, Syscall::SchedGetaffinity, 0b1),
        ARCH_PRCTL => sys_arch_prctl(ctx),
        // NARF has no IA-32 rseq ABI (a `struct rseq` registered from compat
        // mode needs the 32-bit `rseq_cs` handling); -ENOSYS is what a kernel
        // without CONFIG_RSEQ answers, and glibc then runs without rseq.
        RSEQ => {
            ctx.set_return(SyscallReturn::not_implemented());
            None
        }
        // kernel/fork.c, kernel/sched/syscalls.c, kernel/signal.c
        SET_TID_ADDRESS => forward(ctx, Syscall::SetTidAddress),
        SCHED_YIELD => forward(ctx, Syscall::Yield),
        KILL => forward_sx(ctx, Syscall::Kill, 0b11),
        TKILL => forward_sx(ctx, Syscall::Tkill, 0b11),
        TGKILL => forward_sx(ctx, Syscall::Tgkill, 0b111),
        // kernel/signal.c: `compat_sys_rt_sigaction` reads a
        // `struct compat_sigaction` (the native handler checks
        // `in_ia32_syscall`); a `compat_sigset_t` is the same 8 bytes as
        // `sigset_t` on little-endian x86, so `rt_sigprocmask` is unchanged.
        RT_SIGACTION => forward(ctx, Syscall::RtSigaction),
        RT_SIGPROCMASK => forward_sx(ctx, Syscall::Sigprocmask, 0b1),
        // kernel/futex/syscalls.c: `sys_futex_time32` reads an
        // `old_timespec32` timeout, `sys_futex` (futex_time64) a
        // `__kernel_timespec`; `compat_sys_set_robust_list` takes the 12-byte
        // compat head (the native handler checks `in_ia32_syscall`).
        FUTEX => forward_abi(ctx, Syscall::Futex, 0, TIME32),
        FUTEX_TIME64 => forward(ctx, Syscall::Futex),
        SET_ROBUST_LIST => forward(ctx, Syscall::SetRobustList),
        // kernel/time/posix-timers.c: `clock_gettime32` writes an
        // `old_timespec32`, `clock_gettime` (the time64 entry) a
        // `__kernel_timespec`.
        CLOCK_GETTIME => forward_abi(ctx, Syscall::ClockGetTime, 0b1, TIME32),
        CLOCK_GETTIME64 => forward_sx(ctx, Syscall::ClockGetTime, 0b1),
        _ => {
            ctx.set_return(SyscallReturn::not_implemented());
            None
        }
    }
}

/// The y2038-limited entry points' layout choice.
const TIME32: Ia32Abi = Ia32Abi {
    time32: true,
    flock: crate::syscall::Ia32Flock::Native,
};

/// Serve an i386 call with the native handler for `variant`: the context's
/// six arguments are already ebx, ecx, edx, esi, edi, ebp zero-extended.
pub fn forward(ctx: &mut dyn TrapContext, variant: Syscall) -> Option<Syscall> {
    crate::syscall::dispatch_native(variant, ctx);
    Some(variant)
}

/// [`forward`] with the arguments `signed` names sign-extended.
fn forward_sx(ctx: &mut dyn TrapContext, variant: Syscall, signed: u8) -> Option<Syscall> {
    forward_abi(ctx, variant, signed, Ia32Abi::default())
}

/// [`forward_sx`] that also tells the native handler which i386 layout to
/// use where `in_ia32_syscall()` alone does not decide it.
fn forward_abi(
    ctx: &mut dyn TrapContext,
    variant: Syscall,
    signed: u8,
    abi: Ia32Abi,
) -> Option<Syscall> {
    let args = signed_args(ctx.args(), signed);
    forward_args(ctx, variant, args, abi)
}

/// Serve an i386 call with `variant`'s native handler on `args`.
fn forward_args(
    ctx: &mut dyn TrapContext,
    variant: Syscall,
    args: SyscallArgs,
    abi: Ia32Abi,
) -> Option<Syscall> {
    let mut native = Ia32ArgsCtx::forwarding(ctx, args, abi);
    crate::syscall::dispatch_native(variant, &mut native);
    Some(variant)
}

/// Run `variant`'s native handler on `args` and hand back its return
/// without writing it to `ctx` (`None`: it set none and parked to
/// re-execute the call).
fn call_native(
    ctx: &mut dyn TrapContext,
    variant: Syscall,
    args: SyscallArgs,
    abi: Ia32Abi,
) -> Option<SyscallReturn> {
    let mut native = Ia32ArgsCtx::capturing(ctx, args, abi);
    crate::syscall::dispatch_native(variant, &mut native);
    native.take_return()
}

/// `args` with the arguments `signed` names sign-extended from 32 bits.
fn signed_args(args: &SyscallArgs, signed: u8) -> SyscallArgs {
    let pick = |i: u8, v: u64| {
        if signed & (1 << i) != 0 {
            conv::sext(v)
        } else {
            v
        }
    };
    SyscallArgs {
        arg0: pick(0, args.arg0),
        arg1: pick(1, args.arg1),
        arg2: pick(2, args.arg2),
        arg3: pick(3, args.arg3),
        arg4: pick(4, args.arg4),
        arg5: pick(5, args.arg5),
    }
}

/// Is `ret` a success (not an errno)?
#[inline]
fn succeeded(ret: &SyscallReturn) -> bool {
    ret.status == SyscallReturn::OK && (ret.value as i64) >= 0
}

// ── mm ───────────────────────────────────────────────────────────────

/// `mmap2(addr, len, prot, flags, fd, pgoff)` (i386 192, `sys_mmap_pgoff`):
/// the offset is in 4096-byte units, which is what lets a 32-bit task map
/// past 4 GiB of a file. `fd` is `unsigned long` there; -1 is 0xFFFFFFFF.
fn sys_mmap_pgoff(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let a = *ctx.args();
    compat_mmap(ctx, a.arg0, a.arg1, a.arg2, a.arg3, a.arg4, a.arg5 << 12)
}

/// `mmap(struct mmap_arg_struct32 *arg)` (i386 90,
/// `compat_sys_ia32_mmap`): the pre-mmap2 entry, six 32-bit words in user
/// memory because i386 once had only four syscall argument registers.
///
/// ```text
/// if (copy_from_user(&a, arg, sizeof(a))) return -EFAULT;
/// if (a.offset & ~PAGE_MASK) return -EINVAL;
/// return ksys_mmap_pgoff(a.addr, a.len, a.prot, a.flags, a.fd,
///                        a.offset >> PAGE_SHIFT);
/// ```
fn compat_sys_ia32_mmap(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let mut raw = [0u8; 24];
    if let Err(errno) = conv::read_user(ctx.args().arg0, &mut raw) {
        ctx.set_return(to_ret(errno));
        return None;
    }
    let w = |i| u64::from(conv::word(&raw, i));
    let offset = w(5);
    if offset & 0xFFF != 0 {
        ctx.set_return(to_ret(EINVAL));
        return None;
    }
    compat_mmap(ctx, w(0), w(1), w(2), w(3), w(4), offset)
}

/// The shared tail of the two i386 mmap entries: the native mmap with a
/// byte offset, inside `TASK_SIZE_32`.
///
/// Linux's `__get_unmapped_area` uses `TASK_SIZE`, which is `TASK_SIZE_32`
/// for the task (`TIF_ADDR32`): a fixed range past it is ENOMEM, and a hint
/// that cannot hold the mapping is ignored (`mmap_address_hint_valid`).
/// Inside an IA-32 address space the native placement already stays below
/// 4 GiB; a 64-bit task issuing `int 0x80` has no such window, so an
/// address it is handed above `TASK_SIZE_32` (unrepresentable in eax) is
/// unmapped again and the call answers ENOMEM. (Linux would place that
/// mapping from `mmap_compat_base` instead.)
fn compat_mmap(
    ctx: &mut dyn TrapContext,
    addr: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: u64,
    offset: u64,
) -> Option<Syscall> {
    const MAP_FIXED: u64 = 0x10;
    const MAP_FIXED_NOREPLACE: u64 = 0x10_0000;
    let task_size = AddressSpace::COMPAT32_TASK_SIZE;
    let fixed = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
    let len_pages = len.saturating_add(0xFFF) & !0xFFF;
    if len != 0 && fixed && addr.saturating_add(len_pages) > task_size {
        ctx.set_return(to_ret(ENOMEM));
        return Some(Syscall::Mmap);
    }
    let hint = if !fixed && addr.saturating_add(len_pages) > task_size {
        0
    } else {
        addr
    };
    let args = SyscallArgs {
        arg0: hint,
        arg1: len,
        arg2: prot,
        arg3: flags,
        arg4: conv::sext(fd),
        arg5: offset,
    };
    let Some(ret) = call_native(ctx, Syscall::Mmap, args, Ia32Abi::default()) else {
        return Some(Syscall::Mmap);
    };
    if succeeded(&ret) && ret.value.saturating_add(len_pages) > task_size {
        let undo = SyscallArgs {
            arg0: ret.value,
            arg1: len_pages,
            ..SyscallArgs::default()
        };
        let _ = call_native(ctx, Syscall::Munmap, undo, Ia32Abi::default());
        ctx.set_return(to_ret(ENOMEM));
    } else {
        ctx.set_return(ret);
    }
    Some(Syscall::Mmap)
}

// ── files ────────────────────────────────────────────────────────────

/// `_llseek(fd, offset_high, offset_low, loff_t *result, whence)` (i386 140,
/// `sys_llseek`):
///
/// ```text
/// offset = vfs_llseek(fd_file(f), ((loff_t) offset_high << 32) | offset_low,
///                     whence);
/// retval = (int)offset;
/// if (offset >= 0) {
///         retval = -EFAULT;
///         if (!copy_to_user(result, &offset, sizeof(offset)))
///                 retval = 0;
/// }
/// ```
fn sys_llseek(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let a = *ctx.args();
    let args = SyscallArgs {
        arg0: a.arg0,
        arg1: (a.arg1 << 32) | (a.arg2 & 0xFFFF_FFFF),
        arg2: a.arg4,
        ..SyscallArgs::default()
    };
    let Some(ret) = call_native(ctx, Syscall::Lseek, args, Ia32Abi::default()) else {
        return Some(Syscall::Lseek);
    };
    if !succeeded(&ret) {
        ctx.set_return(ret);
        return Some(Syscall::Lseek);
    }
    match conv::write_user(a.arg3, &ret.value.to_le_bytes()) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(errno) => ctx.set_return(to_ret(errno)),
    }
    Some(Syscall::Lseek)
}

/// `sys_ia32_pread64(fd, buf, count, poslo, poshi)` and its pwrite twin
/// (`arch/x86/kernel/sys_ia32.c`): the position is
/// `((u64)poshi << 32) | poslo`.
fn sys_ia32_pread_pwrite(ctx: &mut dyn TrapContext, variant: Syscall) -> Option<Syscall> {
    let a = *ctx.args();
    let args = SyscallArgs {
        arg0: a.arg0,
        arg1: a.arg1,
        arg2: a.arg2,
        arg3: (a.arg4 << 32) | (a.arg3 & 0xFFFF_FFFF),
        ..SyscallArgs::default()
    };
    forward_args(ctx, variant, args, Ia32Abi::default())
}

/// `compat_sys_fcntl64(fd, cmd, arg)` / `compat_sys_fcntl` (`fs/fcntl.c`,
/// `do_compat_fcntl64`). The record-lock commands carry an i386 structure:
/// F_GETLK/F_SETLK/F_SETLKW a `struct compat_flock` (32-bit offsets),
/// F_GETLK64/F_SETLK64/F_SETLKW64 (12-14, renamed to 5-7 by
/// `convert_fcntl_cmd`) and the F_OFD_* commands a packed
/// `struct compat_flock64`. The plain `fcntl` (55) refuses the 64-bit lock
/// commands with EINVAL. `F_SETOWN`'s argument is an `int` (a negative one
/// names a process group); every other argument passes as the register.
fn compat_sys_fcntl64(ctx: &mut dyn TrapContext, fcntl64: bool) -> Option<Syscall> {
    const F_GETLK: u32 = 5;
    const F_SETLK: u32 = 6;
    const F_SETLKW: u32 = 7;
    const F_SETOWN: u32 = 8;
    const F_GETLK64: u32 = 12;
    const F_SETLK64: u32 = 13;
    const F_SETLKW64: u32 = 14;
    const F_OFD_GETLK: u32 = 36;
    const F_OFD_SETLK: u32 = 37;
    const F_OFD_SETLKW: u32 = 38;
    let cmd = ctx.args().arg1 as u32;
    let (native_cmd, flock) = match cmd {
        F_GETLK | F_SETLK | F_SETLKW => (cmd, Ia32Flock::Compat),
        F_GETLK64 | F_SETLK64 | F_SETLKW64 => (cmd - (F_GETLK64 - F_GETLK), Ia32Flock::Compat64),
        F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW => (cmd, Ia32Flock::Compat64),
        _ => (cmd, Ia32Flock::Native),
    };
    if !fcntl64 && flock == Ia32Flock::Compat64 {
        ctx.set_return(to_ret(EINVAL));
        return Some(Syscall::Fcntl);
    }
    let mut args = *ctx.args();
    args.arg1 = u64::from(native_cmd);
    if native_cmd == F_SETOWN {
        args.arg2 = conv::sext(args.arg2);
    }
    let abi = Ia32Abi {
        time32: false,
        flock,
    };
    forward_args(ctx, Syscall::Fcntl, args, abi)
}

// ── identity and arch ────────────────────────────────────────────────

/// `DEFAULT_OVERFLOWUID` / `DEFAULT_OVERFLOWGID`: what a 16-bit uid call
/// reports for an id that does not fit 16 bits.
const OVERFLOW_ID: u64 = 65534;

/// `sys_getuid16` and its siblings: the 32-bit answer through
/// `high2lowuid` / `high2lowgid`.
fn uid16(ctx: &mut dyn TrapContext, variant: Syscall) -> Option<Syscall> {
    let args = *ctx.args();
    let Some(ret) = call_native(ctx, variant, args, Ia32Abi::default()) else {
        return Some(variant);
    };
    if succeeded(&ret) && ret.value > 0xFFFF {
        ctx.set_return(SyscallReturn::ok(OVERFLOW_ID));
    } else {
        ctx.set_return(ret);
    }
    Some(variant)
}

/// `arch_prctl(option, arg2)` from an i386 call (`arch/x86/kernel/
/// process.c`): the CPUID-faulting and XSTATE-permission options are
/// served as for a 64-bit task; everything else — the FS/GS base
/// operations above all — is `-EINVAL` when `in_ia32_syscall()`.
fn sys_arch_prctl(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    const ARCH_GET_CPUID: u64 = 0x1011;
    const ARCH_SET_CPUID: u64 = 0x1012;
    const ARCH_GET_XCOMP_SUPP: u64 = 0x1021;
    const ARCH_GET_XCOMP_PERM: u64 = 0x1022;
    const ARCH_REQ_XCOMP_PERM: u64 = 0x1023;
    const ARCH_GET_XCOMP_GUEST_PERM: u64 = 0x1024;
    const ARCH_REQ_XCOMP_GUEST_PERM: u64 = 0x1025;
    match ctx.args().arg0 {
        ARCH_GET_CPUID
        | ARCH_SET_CPUID
        | ARCH_GET_XCOMP_SUPP
        | ARCH_GET_XCOMP_PERM
        | ARCH_REQ_XCOMP_PERM
        | ARCH_GET_XCOMP_GUEST_PERM
        | ARCH_REQ_XCOMP_GUEST_PERM => forward(ctx, Syscall::ArchPrctl),
        _ => {
            ctx.set_return(to_ret(EINVAL));
            Some(Syscall::ArchPrctl)
        }
    }
}

// ── ioctl ────────────────────────────────────────────────────────────

/// `FS_IOC32_GETFLAGS` / `FS_IOC32_SETFLAGS`: the i386 spelling of the
/// inode-flags ioctls, whose `long` size field is 4 there.
const FS_IOC32_GETFLAGS: u32 = 0x8004_6601;
const FS_IOC32_SETFLAGS: u32 = 0x4004_6602;
const FS_IOC_GETFLAGS: u32 = 0x8008_6601;
const FS_IOC_SETFLAGS: u32 = 0x4008_6602;

/// `compat_sys_ioctl(fd, cmd, arg)` (`fs/ioctl.c`): the inode-flags pair is
/// renamed to its 64-bit numbers, the commands whose argument has the same
/// layout in both ABIs go to the native handler, and anything else — whose
/// structure would have to be converted by a `compat_ioctl` NARF does not
/// have yet (DRM, evdev, sockets, ...) — is ENOTTY, after the EBADF check
/// `CLASS(fd, f)` makes first.
fn compat_sys_ioctl(ctx: &mut dyn TrapContext) -> Option<Syscall> {
    let cmd = ctx.args().arg1 as u32;
    let native_cmd = match cmd {
        FS_IOC32_GETFLAGS => FS_IOC_GETFLAGS,
        FS_IOC32_SETFLAGS => FS_IOC_SETFLAGS,
        c if ioctl_layout_compatible(c) => c,
        _ => {
            let fd = ctx.args().arg0 as u32;
            let open =
                crate::fd::with_table(crate::handlers::current_task_id(), |t| t.get(fd).is_some())
                    .unwrap_or(false);
            ctx.set_return(to_ret(if open { ENOTTY } else { EBADF }));
            return Some(Syscall::Ioctl);
        }
    };
    let mut args = *ctx.args();
    args.arg1 = u64::from(native_cmd);
    forward_args(ctx, Syscall::Ioctl, args, Ia32Abi::default())
}

/// Commands `compat_sys_ioctl` serves unchanged: `do_vfs_ioctl`'s generic
/// file commands and the tty/termios family (`tty_compat_ioctl` passes these
/// to `tty_ioctl`), whose arguments are ints, `struct termio(s|s2)` or
/// `struct winsize` — identical on i386 and x86_64. `TIOCGSERIAL`/
/// `TIOCSSERIAL` (0x541E/0x541F) are not: `struct serial_struct` holds a
/// pointer.
fn ioctl_layout_compatible(cmd: u32) -> bool {
    matches!(
        cmd,
        // TCGETS .. TIOCCONS
        0x5401..=0x541D
        // TIOCPKT, FIONBIO, TIOCNOTTY, TIOCSETD, TIOCGETD, TCSBRKP,
        // TIOCSBRK, TIOCCBRK, TIOCGSID
        | 0x5420..=0x5429
        // TCGETS2, TCSETS2, TCSETSW2, TCSETSF2
        | 0x802C_542A
        | 0x402C_542B
        | 0x402C_542C
        | 0x402C_542D
        // TIOCGPTN, TIOCSPTLCK, TIOCGDEV, TIOCSIG, TIOCVHANGUP, TIOCGPKT,
        // TIOCGPTLCK, TIOCGEXCL, TIOCGPTPEER
        | 0x8004_5430
        | 0x4004_5431
        | 0x8004_5432
        | 0x4004_5436
        | 0x5437
        | 0x8004_5438
        | 0x8004_5439
        | 0x8004_5440
        | 0x5441
        // FIONCLEX, FIOCLEX, FIOASYNC, FIOQSIZE
        | 0x5450
        | 0x5451
        | 0x5452
        | 0x5460
        // FIBMAP, FIGETBSZ, FIFREEZE, FITHAW, FICLONE
        | 0x0000_0001
        | 0x0000_0002
        | 0xC004_5877
        | 0xC004_5878
        | 0x4004_9409
    )
}

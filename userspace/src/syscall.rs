//! Syscall table + dispatch.
//!
//! Spec: `userspace/specification/spec.md` + `abi/specification/spec.md`
//! §3. relibc enters the kernel via a platform-specific instruction
//! (`syscall` on x86_64, `svc #0` on aarch64). The arch trap entry
//! (in `frame/`) saves registers, reads the syscall number + args
//! out of the saved frame, and calls `kernel_syscall_entry(num, args)`
//! below. The asm stub has not landed yet on either arch — it's the
//! one remaining deep piece between this surface and running a user
//! binary — but the Rust-side dispatch is complete and tested
//! independently.
//!
//! Lifecycle:
//! 1. Each subsystem calls `SyscallTable::install(n, handler)` for
//!    the syscalls it implements at boot.
//! 2. `install_global(table)` publishes the assembled table as the
//!    kernel-wide dispatcher.
//! 3. The arch trap stub (once it lands) calls
//!    `kernel_syscall_entry(num, args)`.
//! 4. `kernel_syscall_entry` consults the global table, routes to
//!    the registered handler, and returns a `SyscallReturn`.
//!
//! Unregistered numbers surface `NarfStatus::InvalidOp` (value =
//! 1 on the wire — `InvalidOp` discriminant in `abi::NarfStatus`).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicPtr, Ordering};
use narf_abi as abi;

// ── TrapContext trait ───────────────────────────────────────────────
//
// Arch-neutral view onto the arch-specific TrapFrame for syscalls.
// The arch trap handler constructs an impl of this trait around its
// TrapFrame + extracted args, then calls `kernel_syscall_entry(num,
// &mut ctx)`. Raw handlers receive `&mut dyn TrapContext` and can
// both read args and write the return — plus `redirect_to_kernel`
// for handlers that want to unwind into kernel state instead of
// iretq-ing back to user (e.g. cleanup-and-exit paths).

/// Per-call context handed to raw syscall handlers. Normal
/// `SyscallHandler`s only see `args()`; raw handlers see the full
/// interface.
pub trait TrapContext {
    /// Arguments the user supplied in registers.
    fn args(&self) -> &SyscallArgs;

    /// Set the return value + status that the caller will observe
    /// in the arch's return registers.
    fn set_return(&mut self, ret: SyscallReturn);

    /// Get the current user stack pointer (RSP on x86_64).
    fn user_rsp(&self) -> u64;

    /// Get the current user instruction pointer (RIP on x86_64).
    fn rip(&self) -> u64;

    /// Set the user instruction pointer.
    fn set_rip(&mut self, rip: u64);

    /// Redirect the upcoming return so it lands at `rip` on `rsp`
    /// in kernel mode with kernel selectors, instead of iretq-ing
    /// back to user. Returns `true` when the arch supports this
    /// (x86_64 today); returns `false` on arches where the trap
    /// path can't yet rewrite the EL/CPL target. Callers should
    /// check the return and fall back to `set_return` if `false`.
    fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool;

    /// Redirect to a fresh user-mode image (execve path).
    fn redirect_to_user(&mut self, _entry_rip: u64, _entry_rsp: u64) -> bool {
        false
    }

    /// Save the trapping user-mode CPU state (GPRs, RIP, RSP,
    /// RFLAGS) to `out` so a later resume path can re-enter user
    /// mode at exactly the next instruction. Returns `true` on
    /// arches that have a `UserState` shape (x86_64 today);
    /// `false` elsewhere. The pointer is `*mut u8` because the
    /// concrete `UserState` type is arch-specific — callers cast.
    ///
    /// # Safety
    /// `out` must point at a writable region of at least
    /// `UserState`-sized bytes for the calling arch.
    unsafe fn save_user_state(&self, _out: *mut u8) -> bool {
        false
    }

    /// True if the context is returning to user mode (CPL=3).
    fn returning_to_user(&self) -> bool {
        false
    }

    /// Lay down a signal delivery frame (Classic or SA_SIGINFO) on
    /// the user stack and rewrite the context's RIP/RSP to land
    /// at the handler entry. Returns true on success.
    fn deliver_signal(&mut self, _params: &SigDeliveryParams) -> bool {
        false
    }

    /// Restore register state from a SigContext / ucontext_t frame
    /// on the user stack. Returns true on success.
    fn perform_sigreturn(&mut self, _sc_vaddr: u64) -> bool {
        false
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub struct UserStateCtx<'a> {
    pub state: &'a mut narf_scheduler::UserState,
    pub args: SyscallArgs,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl<'a> core::fmt::Debug for UserStateCtx<'a> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UserStateCtx")
            .field("args", &self.args)
            .finish_non_exhaustive()
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl<'a> TrapContext for UserStateCtx<'a> {
    fn args(&self) -> &SyscallArgs {
        &self.args
    }
    fn set_return(&mut self, ret: SyscallReturn) {
        #[cfg(target_arch = "x86_64")]
        {
            self.state.rax = ret.value;
            self.state.rdx = ret.status as u64;
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.state.x[0] = ret.value;
            self.state.x[1] = ret.status as u64;
        }
    }
    fn user_rsp(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.state.rsp
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.state.sp
        }
    }
    fn rip(&self) -> u64 {
        #[cfg(target_arch = "x86_64")]
        {
            self.state.rip
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.state.pc
        }
    }
    fn set_rip(&mut self, rip: u64) {
        #[cfg(target_arch = "x86_64")]
        {
            self.state.rip = rip;
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.state.pc = rip;
        }
    }
    fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
        false
    }
    fn redirect_to_user(&mut self, entry_rip: u64, entry_rsp: u64) -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            self.state.rip = entry_rip;
            self.state.rsp = entry_rsp;
        }
        #[cfg(target_arch = "aarch64")]
        {
            self.state.pc = entry_rip;
            self.state.sp = entry_rsp;
        }
        true
    }
    unsafe fn save_user_state(&self, _out: *mut u8) -> bool {
        false
    }
    fn returning_to_user(&self) -> bool {
        true
    }
    fn deliver_signal(&mut self, _params: &SigDeliveryParams) -> bool {
        false
    }
    fn perform_sigreturn(&mut self, _sc_vaddr: u64) -> bool {
        false
    }
}

// ── Signal-delivery params ──────────────────────────────────────────
//
// Arch-neutral bundle for `TrapContext::deliver_signal`. Carries the
// per-`SigAction` flags + a snapshot of the per-task altstack +
// whether the outer trap is a restartable syscall trap (so SA_RESTART
// can rewind the syscall-instruction RIP).
//
// Lives here rather than in `handlers.rs` because `narf-frame` (which
// holds the arch trap impls) doesn't depend on `narf-userspace`'s
// handler internals — only on the `TrapContext` trait surface and
// the structs the trait method takes.

/// Linux `sa_flags` bits NARF interprets at delivery time.
/// `SA_SIGINFO`, `SA_RESTART`, `SA_ONSTACK` are honoured by the arch
/// `deliver_signal` impl. `SA_NODEFER` and `SA_RESETHAND` are
/// post-delivery bookkeeping owned by the signal-hook layer.
///
/// Wire values match Linux `<asm-generic/signal.h>` (the same values
/// the relibc shim writes when calling `sigaction(2)`).
pub const SA_SIGINFO: u32 = 0x00_00_00_04;
pub const SA_ONSTACK: u32 = 0x08_00_00_00;
pub const SA_RESTART: u32 = 0x10_00_00_00;
pub const SA_NODEFER: u32 = 0x40_00_00_00;
pub const SA_RESETHAND: u32 = 0x80_00_00_00;

/// Per-call signal-delivery parameters. Built by the signal-delivery
/// hook from the looked-up `SigAction` + the per-task altstack +
/// trap context, then passed to the arch `deliver_signal`.
#[derive(Copy, Clone, Debug, Default)]
pub struct SigDeliveryParams {
    /// User vaddr of the handler the kernel jumps to on iretq.
    /// For `SA_SIGINFO` handlers this is the 3-arg
    /// `void(int, siginfo_t *, void *)` shape; otherwise the
    /// classical 1-arg `void(int)` shape.
    pub handler: u64,
    /// User vaddr of the restorer trampoline (for Linux ABI).
    pub restorer: u64,
    /// Signal number (`SIGSEGV`, `SIGUSR1`, ...). Delivered as the
    /// SysV first integer arg (RDI on x86_64).
    pub signum: u32,
    /// `sa_flags` bits from the matching `SigAction`. The arch
    /// inspects `SA_SIGINFO` / `SA_ONSTACK` / `SA_RESTART`; the
    /// post-delivery bits (`SA_NODEFER`, `SA_RESETHAND`) are read
    /// by the hook layer, not the arch.
    pub flags: u32,
    /// Base of the configured altstack, or 0 if no altstack is
    /// installed or `SS_DISABLE` is set. The arch ignores this
    /// field unless `flags & SA_ONSTACK != 0`.
    pub altstack_sp: u64,
    /// Size in bytes of the configured altstack. The arch lays
    /// the sigframe at `altstack_sp + altstack_size - sizeof
    /// sigframe` so the stack grows down into it.
    pub altstack_size: u64,
    /// `true` when the outer trap is an int 0x80 / syscall trap
    /// whose syscall number is in the restartable set. The arch
    /// rewinds the saved-RIP by the syscall-instruction length
    /// when `flags & SA_RESTART != 0 && restartable_syscall`.
    pub restartable_syscall: bool,
    /// `si_code` for the synthesised `siginfo_t` when
    /// `SA_SIGINFO` is set. Async signals (kill/tkill) use
    /// `SI_USER = 0`; sync signals (#GP, #PF) use a CPU-specific
    /// `SEGV_MAPERR`/`SEGV_ACCERR`/`ILL_ILLOPC`/etc. The arch
    /// stamps this verbatim into the user-visible siginfo
    /// without further interpretation.
    pub si_code: i32,
    /// `si_addr` (faulting address) for synchronous signals.
    /// 0 for async signals where it has no meaning. The arch
    /// only writes this when `SA_SIGINFO` is set.
    pub si_addr: u64,
    /// `si_value` (the `sigval` union) for queued signals
    /// (`rt_sigqueueinfo` / `sigqueue`). 0 for everything else. The arch
    /// writes it at the `_sifields._rt.si_sigval` offset (24) of the
    /// user `siginfo_t` when `SA_SIGINFO` is set; harmless for other
    /// signals since that union slot is unused by them.
    pub si_value: u64,
}

// ── Numbers ─────────────────────────────────────────────────────────

/// Canonical syscall numbers.
///
/// **Wire numbering** is per-arch and matches Linux:
/// - x86_64 follows `arch/x86/entry/syscalls/syscall_64.tbl`
/// - aarch64 follows the Generic ABI in
///   `include/uapi/asm-generic/unistd.h`
///
/// NARF-specific syscalls (no Linux equivalent — ring submit, cap
/// bootstrap, FB/shmem handles, firmware install) live in the
/// dedicated `0x4000..=0x40FF` range (256 slots) on every arch.
///
/// The `Syscall` enum variants are the names; the wire numbers come
/// from the per-arch `LINUX_TABLE` + the shared `NARF_EXTENSION_TABLE`
/// (consulted by `Syscall::raw` / `Syscall::from_raw`). Variant
/// discriminants are unpinned — `.raw()` is a runtime table lookup,
/// not a transmute.
#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Syscall {
    /// Submit a single `abi::Submission` from inline registers.
    /// Equivalent to pushing it to the SQ ring; the implementation
    /// uses the per-task SQ under the hood. NARF extension (no
    /// Linux equivalent); wire number in the `0x4000+` range.
    Submit,

    /// Bootstrap: mint the per-task SQ+CQ and config-page caps.
    /// NARF extension.
    Bootstrap,

    /// Block until a new completion arrives on the per-task CQ.
    /// NARF extension.
    WaitCompl,

    /// Exit the current task. Linux `exit` (x86_64=60, aarch64=93).
    ExitTask,

    /// Yield the CPU. Returns when rescheduled. Linux `sched_yield`
    /// (x86_64=24, aarch64=124).
    Yield,

    /// Sleep for `arg0` nanoseconds. Linux `nanosleep`
    /// (x86_64=35, aarch64=101). Single-arg shape; the full
    /// `struct timespec` variant is `clock_nanosleep` (not yet
    /// wired).
    Sleep,

    /// Open a file by path (zero-terminated string pointer in
    /// arg0). Returns a file descriptor. Linux `open`
    /// (x86_64=2). On aarch64 the generic ABI dropped `open`, so
    /// the kernel routes via the `openat` number (56) for the
    /// aarch64 wire form; userspace should call `openat` directly
    /// when running aarch64.
    OpenFile,

    /// Read `arg1` bytes from file `arg0` into buffer at `arg2`.
    /// Linux `read` (x86_64=0, aarch64=63).
    Read,

    /// Write `arg1` bytes to file `arg0` from buffer at `arg2`.
    /// Linux `write` (x86_64=1, aarch64=64).
    Write,

    /// Gather-write `arg2` iovecs at `arg1` to file `arg0`. Each
    /// iovec is `{ void *iov_base; size_t iov_len; }` (16 bytes).
    /// Returns total bytes written, or a negative errno on error.
    /// Linux `writev` (x86_64=20, aarch64=66). musl's
    /// `__stdio_write` calls this for every buffered-stdio flush.
    Writev,

    /// Close file `arg0`. Linux `close` (x86_64=3, aarch64=57).
    Close,

    // ── Tier-2 fd-table breadth + VFS path resolution + pipe(2) ────
    //
    // Slots 114..=117 are reserved for the second wave of POSIX-shaped
    // fd surface that lands alongside `Open`'s absolute-path support.
    // Co-agent C uses disjoint numbers for cwd / signal / sleep work;
    // do not re-use these here without coordination.
    /// Stat by absolute path. `arg0 = path_ptr, arg1 = path_len,
    /// arg2 = stat_out_ptr`. Writes a NARF [`StatBuf`] (see
    /// `handlers::StatBuf`) to `*stat_out_ptr`. Returns 0 on success.
    Stat,

    /// Stat by fd. `arg0 = fd, arg1 = stat_out_ptr`. Same shape as
    /// [`Stat`] otherwise.
    Fstat,

    /// `arg0 = path_ptr, arg1 = path_len, arg2 = stat_out_ptr`.
    /// Linux lstat(2): like stat but doesn't follow the final
    /// symlink. NARF has no symlinks; this aliases sys_stat.
    Lstat,

    /// Create a pipe pair. `arg0 = pipefd_out_ptr` — kernel writes
    /// two `i32`s (read fd, write fd) to that pointer. Returns 0
    /// on success.
    Pipe,

    /// `arg0 = fd`, `arg1 = len` (u64). Resize the underlying file
    /// to exactly `len` bytes — zero-fill on grow, truncate on
    /// shrink. Returns 0 on success, -1 on read-only FS / bad fd.
    /// Touches the file directly via `FileOps::truncate`; no fd
    /// offset state is altered (POSIX: ftruncate doesn't move the
    /// per-fd cursor).
    Ftruncate,

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = len`. Path-
    /// based truncate (POSIX truncate(2)). Resolves the absolute
    /// path and calls `FileOps::truncate` directly — no fd table
    /// involvement. Returns 0 on success, -1 on bad path / read-
    /// only FS.
    Truncate,

    /// `arg0 = fd`, `arg1 = buf_ptr`, `arg2 = len`, `arg3 = offset`
    /// (u64). Read at the explicit offset without altering the
    /// per-fd cursor. Returns the byte count read on success
    /// (possibly short), -1 on bad fd / null buffer.
    Pread64,

    /// `arg0 = fd`, `arg1 = buf_ptr`, `arg2 = len`, `arg3 = offset`
    /// (u64). Write at the explicit offset without altering the
    /// per-fd cursor. Returns the byte count written on success.
    Pwrite64,

    /// `arg0 = fd`. Flush buffered writes for the file. NARF FSes
    /// are in-memory so this is a structural no-op that succeeds
    /// for any open fd, fails (-1) for an unknown fd. The entry
    /// exists so consumer code that error-checks fsync sees a sane
    /// return.
    Fsync,

    /// `arg0 = fd`. Like Fsync but only metadata-omitted. Mapped
    /// to the same handler — the FS surface has no metadata-only
    /// flush distinction.
    Fdatasync,

    /// `arg0 = fd`, `arg1 = mode`, `arg2 = offset`, `arg3 = len`
    /// (all u64). Linux fallocate(2): preallocate file space.
    /// Honoured modes: 0 (default — extend the file to at least
    /// offset + len bytes, zero-fill new tail) and FALLOC_FL_
    /// ZERO_RANGE = 0x10 (zero the given range without changing
    /// size unless extending). Returns 0 on success, -1 on bad fd
    /// or read-only FS.
    Fallocate,

    /// `arg0 = fd_in`, `arg1 = fd_out`, `arg2 = off_in` (u64,
    /// `!0` = use cur), `arg3 = off_out` (u64, `!0` = use cur),
    /// `arg4 = len`, `arg5 = flags` (must be 0). Linux
    /// copy_file_range(2): in-kernel copy between two file
    /// descriptors. NARF executes a chunked read-then-write
    /// loop. Returns the byte count copied on success, -1 on
    /// bad fd / non-zero flags.
    CopyFileRange,

    /// `arg0 = name_ptr`, `arg1 = name_len` (debug only),
    /// `arg2 = flags` (accepted-and-ignored). Linux
    /// memfd_create(2): create an unnamed in-memory file and
    /// install it in the calling task's fd table. Returns the
    /// new fd on success, -1 on bad input or fd-table exhaustion.
    /// The name is recorded only for debug introspection (no
    /// directory entry), matching the spec.
    MemfdCreate,

    /// `arg0 = fd`, `arg1 = mode`. fchmod(2). NARF doesn't
    /// enforce permission bits; the call succeeds on a known fd
    /// (-1 on closed fd). Round-trip is structural.
    Fchmod,

    /// `arg0 = fd`, `arg1 = uid`, `arg2 = gid`. fchown(2). Same
    /// accept-and-record semantics as fchmod.
    Fchown,

    /// `arg0 = dirfd` (ignored — NARF has no directory-fd type),
    /// `arg1 = path_ptr`, `arg2 = path_len`, `arg3 = mode`,
    /// `arg4 = flags` (ignored). Linux fchmodat(2). The path
    /// must be absolute. Returns 0 on a reachable path, -1
    /// otherwise (consumer code error-checks the chmod return).
    Fchmodat,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = uid`, `arg4 = gid`, `arg5 = flags`. fchownat(2).
    /// Same path-must-be-absolute simplification as fchmodat.
    Fchownat,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = mode`, `arg4 = flags`. Linux faccessat(2).
    /// dirfd ignored; path must be absolute. Routes to the same
    /// existence probe as SYS_OPEN (open + close).
    Faccessat,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = flags`, `arg4 = mode`. Linux openat(2).
    /// dirfd ignored; path must be absolute. Returns the new fd
    /// or `!0u64` on failure (matching SYS_OPEN's convention so
    /// the user-runtime wrapper distinguishes consistently).
    Openat,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = stat_out_ptr`, `arg4 = flags`. Linux newfstatat(2)
    /// / fstatat(2). dirfd ignored; path must be absolute. Routes
    /// to the same handler as SYS_STAT.
    Newfstatat,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = flags`. Linux unlinkat(2). dirfd ignored;
    /// AT_REMOVEDIR (0x200) flag routes to rmdir, otherwise to
    /// unlink. Returns 0 / -1.
    Unlinkat,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = mode`. Linux mkdirat(2). dirfd ignored; routes
    /// through SYS_MKDIR.
    Mkdirat,

    /// `arg0 = old_dirfd`, `arg1 = old_path_ptr`,
    /// `arg2 = old_path_len`, `arg3 = new_dirfd`,
    /// `arg4 = new_path_ptr`, `arg5 = new_path_len`. Linux
    /// renameat(2). Both dirfds ignored; both paths must be
    /// absolute.
    Renameat,

    /// `arg0 = target_ptr`, `arg1 = target_len`, `arg2 = dirfd`,
    /// `arg3 = link_ptr`, `arg4 = link_len`. Linux symlinkat(2).
    /// dirfd ignored; link path must be absolute. Forwards to
    /// the SYS_SYMLINK body.
    Symlinkat,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = buf_ptr`, `arg4 = buf_len`. Linux readlinkat(2).
    /// dirfd ignored; path must be absolute. Forwards to the
    /// SYS_READLINK body.
    Readlinkat,

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = mode`. Linux
    /// access(2): legacy entry point that forwards to the
    /// faccessat body with `dirfd = AT_FDCWD`. Path must be
    /// absolute (NARF has no per-task cwd-relative resolution at
    /// the syscall layer). Returns 0 if the path resolves, -1
    /// otherwise.
    Access,

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = mode`. Linux
    /// chmod(2): legacy entry point that forwards to the
    /// fchmodat body. Mode bits aren't enforced; we only verify
    /// the path resolves.
    Chmod,

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = uid`,
    /// `arg3 = gid`. Linux chown(2): legacy entry point that
    /// forwards to the fchownat body. uid/gid aren't enforced;
    /// we only verify the path resolves.
    Chown,

    /// `arg0 = pipefd_out_ptr`, `arg1 = flags`. Linux pipe2(2):
    /// pipe + atomic flag set. Honoured flag: O_CLOEXEC (bit
    /// 0x80000) — both ends get FD_CLOEXEC stamped at install
    /// time. O_NONBLOCK is accepted and ignored (NARF pipes have
    /// no blocking model worth toggling — read on an empty pipe
    /// already short-returns).
    Pipe2,

    /// Map memory: `arg0` addr hint, `arg1` length, `arg2` flags.
    Mmap,

    /// Unmap memory.
    Munmap,

    /// Change protection on a memory range. arg0 = base addr,
    /// arg1 = length in bytes, arg2 = POSIX-shape prot bitmask
    /// (1 = READ, 2 = WRITE, 4 = EXEC). Walks the calling AS's
    /// region table and rewrites every page's PTE in place via
    /// `AddressSpace::change_perms_range`. Returns Ok(0) on
    /// success, InvalidOp if no region intersects the requested
    /// range or the AS lookup failed.
    MProtect,

    /// `mlock(addr, len)` — force-back every lazy (demand-paged)
    /// page in `[addr, addr + len)` and set the LOCKED flag so
    /// future swap/reclaim passes leave the region alone.
    /// arg0 = base addr, arg1 = length in bytes. Ok(0) on
    /// success, InvalidOp on no-region / OOM.
    MLock,

    /// `munlock(addr, len)` — clear the LOCKED flag. Frames stay
    /// backed (no swap exists yet to reclaim them). arg0 = base
    /// addr, arg1 = length in bytes. Ok(0) on success, InvalidOp
    /// on no-region.
    MUnlock,

    /// `madvise(addr, len, advice)` — Linux syscall 28. Honoured
    /// advice values: MADV_DONTNEED (4) and MADV_FREE (8) both
    /// release the backing frames in `[addr, addr+len)` and mark
    /// the slots demand-paged so the next access reads zero.
    /// All other advice values (MADV_WILLNEED, MADV_HUGEPAGE,
    /// MADV_DONTFORK, …) return Ok(0) — `madvise` is a hint, not
    /// a contract. arg0 = base, arg1 = length, arg2 = advice.
    /// Wave-66. Gated by the `linux-compat` feature on the kernel
    /// side; the variant exists on every build so the wire number
    /// stays stable.
    Madvise,

    /// `execve(elf_buf, elf_len, argv_pack, argv_len, envp_pack,
    /// envp_len)` — re-image the calling task with a freshly-
    /// loaded program while preserving pid / fd table / brk top /
    /// signal handlers. The user-side libc shim opens the program
    /// file, reads bytes into a buffer, packs argv/envp into
    /// concatenated NUL-separated strings, and issues this
    /// syscall. The kernel-side handler copies the buffers into
    /// kernel memory, parses the ELF, builds a new AddressSpace +
    /// stack via `process::load_user_process_with`, and longjmps
    /// the polling routine via the EXECVE hook so the future's
    /// UserProcess gets swapped to the new image.
    ///
    /// Doesn't return on success — the next user-mode resume
    /// lands at the new image's entry. Returns InvalidOp on bad
    /// args, ELF parse failure, or out-of-task-context call.
    Execve,

    /// `wait4(pid, &status, options, &rusage)` — block (or
    /// poll under WNOHANG) until a child of the calling task
    /// exits, then reap its exit status. arg0 = pid (signed —
    /// >0 specific child, -1 any), arg1 = status user-pointer
    /// > (may be 0), arg2 = options bitmask (low bit = WNOHANG),
    /// > arg3 = rusage user-pointer (zeroed; no per-process
    /// > resource accounting yet). Returns the reaped child pid
    /// > on success, 0 on WNOHANG with no exited child, InvalidOp
    /// > on no-children / timeout.
    Wait4,

    /// `pause()` — block until a signal is delivered.
    Pause,

    /// `mount(source, target, fstype, flags, data)` — mount the
    /// filesystem named by `fstype` (a packed string like "fat" or
    /// "ext2") at the absolute path `target`, backed by the
    /// block-device path `source`. arg0 = source ptr, arg1 = source
    /// len, arg2 = target ptr, arg3 = target len, arg4 = packed
    /// (fstype_ptr<<32 | fstype_len). flags + data passed via the
    /// extended-args ABI. Returns 0 on success, !0u64 on failure
    /// (POSIX -1 + errno path; libc maps to errno).
    Mount,

    /// `umount2(target, flags)` — unmount the filesystem mounted at
    /// the absolute path `target`. arg0 = target ptr, arg1 = target
    /// len, arg2 = flags (currently ignored — POSIX MNT_FORCE et al.
    /// land later). Returns 0 on success, !0u64 on failure.
    Umount2,

    /// `statfs(path, &buf)` — fill `buf` (struct statvfs-shaped) with
    /// stats about the filesystem covering `path`. arg0 = path ptr,
    /// arg1 = path len, arg2 = buf ptr (must point at a 64-byte
    /// region in user memory). Returns 0 on success, !0u64 on
    /// failure.
    Statfs,

    /// `fstatfs(fd, &buf)` — same as `statfs` but addressed by an
    /// open fd. arg0 = fd, arg1 = buf ptr. Returns 0 / !0u64.
    Fstatfs,

    /// `unshare(flags)` — POSIX 2008 / Linux unshare(2) shape. The
    /// only flag honoured today is CLONE_NEWNS (0x00020000): the
    /// calling task snapshots the global mount table into a private
    /// MountNamespace, after which its mount/umount calls only
    /// affect its own view. Other flags are accepted but ignored.
    /// Returns 0 on success, !0u64 on failure.
    Unshare,

    /// `chroot(path)` — Linux 161 (x86_64) / 51 (aarch64). Rebind the
    /// calling task's notion of `/` to `path`. After chroot, every
    /// absolute path the task hands to a path-resolving syscall is
    /// transparently rewritten under `path` before resolution.
    /// arg0 = path ptr, arg1 = path len. Returns 0 / !0u64.
    /// Gated behind `linux-compat`.
    Chroot,

    /// `pivot_root(new_root, put_old)` — Linux 155 (x86_64) / 41
    /// (aarch64). Atomically swap the calling task's root with
    /// `new_root`; the previous root becomes accessible at
    /// `put_old` (an absolute path under the new root). Used by
    /// container-init to drop the bootstrap root after mounting
    /// the new image. arg0 = new_root ptr, arg1 = new_root len,
    /// arg2 = put_old ptr, arg3 = put_old len. Returns 0 / !0u64.
    /// Gated behind `linux-compat` + `container`.
    PivotRoot,

    /// `sigreturn()` — restore the calling task's user-mode trap
    /// context from a SigContext frame at the current RSP. Called
    /// from a libc-provided signal trampoline after the user's
    /// handler returns. Never returns through the syscall ABI; the
    /// handler instead resumes execution at the saved RIP with all
    /// GP registers, RSP, and RFLAGS restored to their pre-delivery
    /// values. Linux numbering is 15 (32-bit) / 313 (64-bit
    /// rt_sigreturn); we pick 187 to keep the recently-added range
    /// contiguous.
    Sigreturn,

    /// `ptrace(request, pid, addr, data)` — POSIX ptrace(2). Used
    /// by debuggers to observe and control the execution of another
    /// process (the "tracee"), and examine and change the tracee's
    /// memory and registers.
    Ptrace,

    // ── Sockets (197-209) ─────────────────────────────────────────
    //
    // The kernel exposes BOTH a POSIX-shaped surface (one syscall
    // per BSD socket call) AND a ring-opcode dispatcher path. Both
    // entry shapes route through the same `SocketOp` dispatcher in
    // `userspace::socket` — POSIX syscalls copy buffers across the
    // ABI boundary; the ZC opcodes (208/209) reference pre-pinned
    // buffer slots from a registered pool. libc defaults to POSIX;
    // hot paths opt into ZC via `narf_register_buffer()`.
    /// `socket(domain, type, protocol)` → fd. arg0 = domain
    /// (AF_UNIX = 1, AF_INET, AF_INET6 = 10), arg1 = type
    /// (SOCK_STREAM = 1, SOCK_DGRAM = 2), arg2 = protocol (0 for
    /// the family default). Returns the new fd; -1 on failure.
    SocketOpen,

    /// `bind(fd, addr, addrlen)`. arg0 = fd, arg1 = addr ptr,
    /// arg2 = addrlen. addr layout per `narf_socket::SockAddr`
    /// (family u16 + body bytes); libc translates POSIX
    /// sockaddr_in / sockaddr_un / sockaddr_in6 in/out.
    SocketBind,

    /// `listen(fd, backlog)`. arg0 = fd, arg1 = backlog.
    SocketListen,

    /// `accept(fd, addr_out, addrlen_out)` → fd. arg0 = listening
    /// fd, arg1 = addr_out (may be 0), arg2 = addrlen_out (may be
    /// 0). Blocks until a connection arrives; returns the new
    /// connected fd.
    SocketAccept,

    /// `connect(fd, addr, addrlen)`. arg0 = fd, arg1 = addr ptr,
    /// arg2 = addrlen. Blocks until peer accepts (for SOCK_STREAM).
    SocketConnect,

    /// `sendto(fd, buf, len, flags, addr, addrlen)`. The 6-arg
    /// shape covers both `send()` (addr=NULL, addrlen=0) and
    /// `sendto()`. arg0 = fd, arg1 = buf ptr, arg2 = len,
    /// arg3 = flags (POSIX MSG_*), arg4 = addr ptr, arg5 = addrlen.
    SocketSend,

    /// `recvfrom(fd, buf, len, flags, addr_out, addrlen_out)`.
    /// Mirror of SocketSend. arg0 = fd, arg1 = buf, arg2 = len,
    /// arg3 = flags, arg4 = addr_out, arg5 = addrlen_out.
    SocketRecv,

    /// `shutdown(fd, how)`. how: 0 = SHUT_RD, 1 = SHUT_WR,
    /// 2 = SHUT_RDWR.
    SocketShutdown,

    /// `getsockopt(fd, level, opt, buf, len_out)`. arg0 = fd,
    /// arg1 = level, arg2 = optname, arg3 = buf ptr, arg4 = len
    /// in/out u32 ptr.
    SocketGetSockOpt,

    /// `setsockopt(fd, level, opt, buf, len)`.
    SocketSetSockOpt,

    /// `getsockname(fd, addr_out, addrlen_inout)` — return the
    /// socket's locally-bound address.
    SocketGetSockName,

    /// `getpeername(fd, addr_out, addrlen_inout)` — return the
    /// remote peer's address on a connected socket.
    SocketGetPeerName,

    /// `sendmsg(fd, msghdr, flags)` — scatter send with optional
    /// destination address (carried inside the msghdr).
    SocketSendMsg,

    /// `recvmsg(fd, msghdr, flags)` — gather receive with optional
    /// source-address writeback.
    SocketRecvMsg,

    /// ZC fast path: register a user buffer for zerocopy I/O.
    /// `register_buffer(ptr, len) → buf_id`. The kernel pins the
    /// pages and assigns an opaque id usable in `SockSendZc`.
    /// Lifetime: until `unregister_buffer` (not yet wired) or task
    /// exit. arg0 = ptr, arg1 = len. Returns buf_id (u32) or -1.
    SockRegisterBuf,

    /// ZC fast path: send a registered buffer slice.
    /// `send_zc(fd, buf_id, off, len, flags)`. arg0 = fd,
    /// arg1 = buf_id, arg2 = offset within buffer, arg3 = byte
    /// length, arg4 = flags. The user must not modify the buffer
    /// region until completion fires through the per-task
    /// completion ring (today: completion is synchronous —
    /// completion-ring delivery lands when the kernel-side NIC
    /// path goes async).
    SockSendZc,

    // ── I/O multiplexing (210-219) ────────────────────────────────
    /// `poll(pollfds, n, timeout_ms)`. arg0 = ptr to a packed
    /// array of `[fd: i32, events: u16, revents: u16]` triples,
    /// arg1 = element count, arg2 = timeout in ms (-1 = block
    /// indefinitely, 0 = non-blocking, >0 = bounded wait). The
    /// kernel writes `revents` for each entry. Returns the
    /// number of entries with non-zero revents, 0 on timeout,
    /// !0u64 on error. select(2) and pselect(2) are libc-side
    /// translations to this syscall.
    Poll,

    /// `select(nfds, readfds, writefds, exceptfds, timeval)`.
    /// arg0 = nfds, arg1..=arg4 = fd_set ptrs + timeval ptr.
    /// Converts fd_set bitmaps to poll internally; see `select.rs`.
    /// Linux x86_64 number 23; aarch64 has no direct select — maps
    /// to ppoll (73) via pselect6.
    Select,

    /// `pselect6(nfds, readfds, writefds, exceptfds, timespec,
    /// sigmask_ptr)`. Linux x86_64 number 270; aarch64 72.
    /// Sigmask is accepted and ignored (no signal masking yet).
    Pselect6,

    /// `epoll_create1(flags)` — create an epoll instance fd.
    /// arg0 = flags (only EPOLL_CLOEXEC = 0x80000 honoured).
    EpollCreate,

    /// `epoll_ctl(epfd, op, fd, &event)`. arg0 = epfd,
    /// arg1 = op (EPOLL_CTL_ADD = 1, MOD, DEL = 2),
    /// arg2 = target fd, arg3 = event ptr (events u32 + data u64).
    EpollCtl,

    /// `epoll_wait(epfd, events_out, maxevents, timeout_ms)`.
    /// arg0 = epfd, arg1 = events_out ptr, arg2 = max,
    /// arg3 = timeout_ms.
    EpollWait,

    /// Linux `epoll_pwait`.
    EpollPwait,

    /// `eventfd2(initval, flags)` — semaphore-shaped fd.
    /// arg0 = initial counter value, arg1 = flags.
    Eventfd,

    /// `timerfd_create(clockid, flags)` — timer-backed fd.
    /// arg0 = clockid (0 = CLOCK_REALTIME, 1 = CLOCK_MONOTONIC),
    /// arg1 = flags.
    TimerfdCreate,

    /// `timerfd_settime(fd, flags, &new_value, &old_value)` —
    /// arm the timer. arg0 = fd, arg1 = flags, arg2 = new_value
    /// itimerspec ptr, arg3 = old_value out (may be 0).
    TimerfdSettime,

    /// Wave-64: `timerfd_gettime(fd, &curr_value)` — read the
    /// timer's current setting. arg0 = fd, arg1 = itimerspec out
    /// ptr (32 bytes). Linux x86_64 number 287; aarch64 87.
    TimerfdGettime,

    /// `signalfd4(fd, &mask, sizemask, flags)` — receive signals
    /// via an fd. arg0 = fd (-1 = create new), arg1 = sigmask
    /// ptr, arg2 = sizemask, arg3 = flags.
    Signalfd,

    /// `tcgetattr(fd, &termios)` — read terminal attributes.
    /// arg0 = fd, arg1 = termios out ptr (60 bytes per glibc
    /// shape). Returns 0 on success, !0u64 on error.
    Tcgetattr,

    /// `tcsetattr(fd, action, &termios)` — write terminal attributes.
    /// arg0 = fd, arg1 = action, arg2 = termios in ptr.
    Tcsetattr,

    /// `flock(fd, op)` — POSIX advisory file lock. arg0 = fd,
    /// arg1 = op (LOCK_SH=1, LOCK_EX, LOCK_UN, LOCK_NB=4
    /// OR'd in for non-blocking). Per-file (Arc-keyed) lock state
    /// kept in a kernel-side map; conflicting acquires block via
    /// the same yield-on-no-progress path sys_futex uses.
    Flock,

    /// Open an FB connection to a scanout. `arg0` = scanout id (0
    /// for the active scanout). Returns a non-zero `FbHandleId` on
    /// success, 0 on failure (no backend / OOM / not authorised).
    /// Auto-closed on process exit.
    FbConnect,

    /// Query the connected scanout's geometry + format. `arg0` =
    /// `FbHandleId`, `arg1` = userspace pointer to a 24-byte
    /// `FbInfo` (`{u32 width, height, stride, format, scanout_id, _resv}`).
    /// Returns 0 on success, !0 on bad handle / bad pointer.
    FbInfo,

    /// Map the connection's draw-ring into the caller's VA. `arg0`
    /// = `FbHandleId`. Returns the user VA (4 KiB region) or 0 on
    /// failure. The mapping is RW; userspace constructs a
    /// `SharedProducer<DrawCmd>` over it.
    FbRingMap,

    /// Block (or report) until the kernel drain task has consumed
    /// at least one command past the caller's prior wait point.
    /// `arg0` = `FbHandleId`. Returns the current drain count
    /// snapshot. Today this is non-blocking — it returns immediately
    /// — but the contract leaves room for vsync / backpressure
    /// blocking once the scheduler-aware drain lands.
    FbFlushWait,

    /// Tear down a connection. `arg0` = `FbHandleId`. Frees the
    /// ring, removes the mapping, and reaps the kernel-side
    /// consumer. Returns 0 on success, !0 on bad handle. Also
    /// auto-called on process exit; explicit calls are for
    /// graceful shutdown.
    FbDisconnect,

    /// Allocate a fresh shared-memory region. `arg0` = byte length
    /// (rounded up to a page). Returns a non-zero `ShmemHandleId`
    /// on success, 0 on OOM / oversize / no kernel support. The
    /// region is page-aligned, zero-filled, and owned by the
    /// calling process; auto-reaped on exit.
    ShmemCreate,

    /// Map a shmem region into the caller's VA. `arg0` =
    /// `ShmemHandleId`. Returns the user VA (page-aligned) or 0 on
    /// failure (bad handle, foreign owner, OOM). The mapping is RW
    /// and contiguous in VA even though the backing frames are
    /// scattered.
    ShmemMap,

    /// Tear down a shmem region. `arg0` = `ShmemHandleId`. The
    /// userspace mapping stays installed for now (page-table
    /// teardown lands when shmem grows a `Drop` path that walks
    /// + unmaps the user VA range). Returns 0 on success, !0 on
    ///   bad handle / not-owner.
    ShmemDestroy,

    /// Install (or replace) a firmware blob in the kernel firmware
    /// registry. `arg0 = name_ptr`, `arg1 = name_len` (the
    /// canonical name, e.g. `"qcom/qcnfa765/amss.bin"`),
    /// `arg2 = bytes_ptr`, `arg3 = bytes_len` (the raw blob with
    /// the signature trailer described in
    /// `firmware/specification/spec.md` §6).
    ///
    /// Cap-gated against the calling task holding a
    /// `Cap<FirmwareRegistry, Write>`. The privileged firmware-
    /// load daemon owns one such cap; ordinary tasks see
    /// `SyscallReturn::invalid_op()`. On success the blob lands
    /// at `BlobSource::HotInstall` priority and overrides any
    /// initramfs / in-tree entry of the same name.
    ///
    /// Returns 0 on success, `!0u64` on any failure.
    FirmwareInstall,

    /// Kick the kernel-side dispatcher to drain the calling task's
    /// shared SubmissionRing and post Completions to the shared
    /// CompletionRing. Returns the number of submissions processed.
    RingKick,

    /// Return the calling task's monotonic id. POSIX-shaped surface
    /// for relibc's `getpid()` / `gettid()` (we don't yet
    /// distinguish PID from TID — single-thread-per-process at
    /// Stage 4).
    GetPid,
    /// Return the calling task's parent id, or 0 if none. Stage 4
    /// stub: returns 0 unconditionally; real ppid lands once the
    /// scheduler tracks parentage.
    GetPpid,

    /// POSIX-shaped uid/gid query. NARF's authority model is
    /// capabilities; the per-task uid/gid table is structural
    /// state only (no security implication). Default identity
    /// is (0, 0); `SetUid` / `SetGid` mutate it.
    GetUid,
    GetGid,

    /// Set the calling task's uid (`arg0`) / gid (`arg0`). Both
    /// always succeed and return 0; capabilities still gate every
    /// privileged operation.
    SetUid,
    SetGid,

    /// `arg0 = pid` (0 = self). Linux getpgid(2): return the
    /// process-group id of `pid`. NARF tracks pgids per-task in
    /// a structural BTreeMap (no actual session/process-group
    /// scheduling). Default pgid = pid (each task is its own
    /// group leader). Returns the pgid on success, -1 on
    /// unknown pid.
    Getpgid,

    /// `arg0 = pid` (0 = self), `arg1 = pgid` (0 = use pid).
    /// Linux setpgid(2): record the new pgid for the target
    /// task. Always succeeds.
    Setpgid,

    /// `arg0 = pid` (0 = self). POSIX getsid(2): return the
    /// session id of `pid`. NARF tracks sids per-task in a
    /// structural BTreeMap; default sid = pid.
    Getsid,

    /// No args. POSIX setsid(2): the calling task creates a new
    /// session with itself as the leader. Records sid = pid +
    /// pgid = pid in their respective tables; returns pid.
    Setsid,

    /// `arg0 = buf_ptr`, `arg1 = buf_len`. Copy the kernel-wide
    /// hostname (NUL-terminated UTF-8) into the user buffer.
    /// Returns the byte length excluding the NUL on success, -1 on
    /// `buf_len < name_len + 1`.
    GetHostname,

    /// `arg0 = buf_ptr`, `arg1 = buf_len`. Replace the kernel-wide
    /// hostname with the supplied bytes. Stage-4 simplification:
    /// any task can set the hostname (no cap gate yet — landing
    /// alongside the cap-table integration). Returns 0 on success,
    /// -1 on rejection (length cap, malformed UTF-8).
    SetHostname,

    /// `arg0 = resource` (POSIX RLIMIT_*), `arg1 = rlimit_out_ptr`.
    /// Write the current task's `rlimit { cur, max }` pair into the
    /// user buffer. Returns 0 on success, -1 on bad pointer / out-
    /// of-range resource. NARF tracks rlimits as structural state
    /// only — capabilities still gate every privileged operation.
    Getrlimit,

    /// `arg0 = resource`, `arg1 = rlimit_in_ptr`. Update the
    /// current task's `rlimit` for `resource`. Returns 0 on
    /// success, -1 on rejection.
    Setrlimit,

    /// `arg0 = pid` (0 = self), `arg1 = resource`,
    /// `arg2 = new_in_ptr`, `arg3 = old_out_ptr`. Linux
    /// prlimit64(2): combined get-and-set. If `new` is non-null,
    /// write the [cur, max] pair. If `old` is non-null, return
    /// the prior value into it. Both null is a no-op-success.
    /// Returns 0 on success, -1 on bad pointer / out-of-range.
    Prlimit64,

    /// `arg0 = which` (PRIO_PROCESS=0 only honoured), `arg1 = who`
    /// (0 = self). Returns the current task's nice value (-20..=19),
    /// shifted by +20 so the wire value is 0..=39 (matches Linux's
    /// pre-shift convention so user code can subtract 20 without
    /// caring about negatives crossing the wire). -1 on bad which.
    Getpriority,

    /// `arg0 = which`, `arg1 = who`, `arg2 = prio` (-20..=19,
    /// already user-side). Stores the new nice value. Returns 0
    /// on success, -1 on bad which / out-of-range prio.
    Setpriority,

    /// `arg0 = tms_out_ptr`. POSIX times(2): write the calling
    /// task's `struct tms { i64 utime, stime, cutime, cstime }`
    /// (in CLK_TCK = 100Hz ticks) and return the elapsed wall-
    /// clock ticks since boot. NARF doesn't track per-task
    /// user/system splits yet — `utime` synthesises to monotonic
    /// ticks, `stime` and child fields are zero — but the surface
    /// round-trips so `clock(3)` and `time(1)`-shaped consumers
    /// see a calibratable wall clock.
    Times,

    /// `arg0 = who` (RUSAGE_SELF=0; RUSAGE_CHILDREN=-1 returns
    /// zeroed struct), `arg1 = rusage_out_ptr`. Writes the
    /// glibc-shaped 16-i64 rusage struct: ru_utime.tv_sec /
    /// ru_utime.tv_usec from monotonic_ns, every other field
    /// zero. Returns 0 on success, -1 on bad pointer.
    Getrusage,

    /// `arg0 = new_mask` (only the low 9 bits — POSIX 0o777). Sets
    /// the calling task's file-creation mask and returns the
    /// previous value. Stage-4 simplification: NARF doesn't yet
    /// enforce mode bits at file creation, so the mask is
    /// structural state — but the round-trip lets `umask(0o077)`
    /// followed by `umask(0o022)` see the prior value, which is
    /// what consumer init code expects.
    Umask,

    /// `arg0 = cpu_out_ptr`, `arg1 = node_out_ptr`. Linux getcpu(2):
    /// write the calling CPU id + NUMA node id to the supplied
    /// out-pointers (each may be null). NARF user mode is
    /// single-CPU today — both return 0. Returns 0 on success.
    Getcpu,

    /// `arg0 = pid` (0 = self), `arg1 = mask_size` (bytes),
    /// `arg2 = mask_out_ptr`. Linux sched_getaffinity(2): write
    /// a CPU-set bitmap for the target task. NARF is single-CPU
    /// in user mode; we always return a 1-bit mask (CPU 0 set,
    /// every other bit clear). Returns the byte count written
    /// on success (= `mask_size` rounded down to a multiple of 8),
    /// -1 on bad pointer or oversized request.
    SchedGetaffinity,

    /// `arg0 = pid`, `arg1 = mask_size` (bytes),
    /// `arg2 = mask_in_ptr`. sched_setaffinity(2). NARF doesn't
    /// pin tasks (single-CPU model); the bitmap is read but
    /// ignored. Returns 0 on success, -1 on bad pointer.
    SchedSetaffinity,

    /// `arg0 = policy`. Linux sched_get_priority_max(2): return
    /// the maximum valid `sched_priority` for `policy`.
    /// SCHED_OTHER (0) / SCHED_BATCH (3) / SCHED_IDLE (5) → 0;
    /// SCHED_FIFO (1) / SCHED_RR (2) → 99. Bad policy → -1.
    SchedGetPriorityMax,

    /// `arg0 = policy`. sched_get_priority_min(2). Mirrors max
    /// with the inverse: 0 / 1 / -1 by policy.
    SchedGetPriorityMin,

    /// `arg0 = pid` (0 = self), `arg1 = sched_param_out_ptr`.
    /// Linux sched_getparam(2): write a single-field
    /// `struct sched_param { int sched_priority }` (POSIX).
    /// Returns 0 on success, -1 on bad pointer.
    SchedGetparam,

    /// `arg0 = pid`, `arg1 = sched_param_in_ptr`. Read the
    /// `sched_priority` field, store on the task. Returns 0.
    SchedSetparam,

    /// Linux gettid(2): return the calling thread's distinct kernel
    /// task id. With `Clone` (56) wired, multi-threaded processes
    /// observe distinct tids per thread; the value is the
    /// scheduler's `TaskId.raw()` for the running task.
    Gettid,

    /// Linux clone(2) — minimal viable thread spawn. NARF doesn't
    /// implement the full `flags / ptid / ctid / tls` surface;
    /// instead it takes a four-argument shape that creates one new
    /// task sharing the caller's address space:
    ///
    /// - `arg0 = entry_pc`  : user vaddr the new task starts at
    /// - `arg1 = stack_top` : user RSP the new task starts on
    ///   (caller-allocated; kernel does NOT
    ///   validate that the page is mapped)
    /// - `arg2 = arg`       : opaque u64 passed in RDI to `entry_pc`
    /// - `arg3 = fs_base`   : if non-zero, value the kernel writes
    ///   into the new task's `IA32_FS_BASE` so
    ///   it can find its own TLS block. Zero
    ///   means "inherit parent's fs_base"
    ///   (suitable for child code that does
    ///   not touch TLS).
    ///
    /// Returns the new task's tid on success (non-zero), or
    /// `SyscallReturn::invalid_op` if the parent's address space
    /// could not be resolved (no AS lookup installed → not a real
    /// userspace boot).
    ///
    /// Future work (tracked in MEMORY): clone3-shaped flags,
    /// per-thread TLS allocation from PT_TLS template, futex /
    /// thread-group bookkeeping. For now, two threads can exist in
    /// one address space, gettid distinguishes them, and the
    /// scheduler's per-task UserState/JmpBuf/FS_BASE machinery
    /// already supports them.
    Clone,

    /// Linux fork(2) — duplicate-process counterpart to `Clone`.
    /// Where `Clone` shares the parent's `Arc<AddressSpace>` so a new
    /// task runs alongside in the same memory map (POSIX threads),
    /// `Fork` walks the parent's regions, allocates fresh physical
    /// frames for each, copies the parent's bytes through the
    /// low-4-GiB identity map, and produces an entirely independent
    /// address space for the child. POSIX semantics: child sees `0`
    /// in the return register, parent sees the child's tid.
    ///
    /// Inheritance per POSIX:
    ///   - address space  : copied (independent on either side)
    ///   - fd table       : copied (entries share underlying file
    ///     Arcs via Arc::clone)
    ///   - cwd / brk / sigaction / signal_mask / uid+gid /
    ///     pgid / sid    : copied
    ///   - pending signals: reset (POSIX)
    ///
    /// No flags / no clone3-shaped surface — just a bare fork. The
    /// child trap-frame's RAX is rewritten to `0` before its first
    /// poll re-enters user mode (see `sys_fork` doc-comment for the
    /// pre-seeded UserState mechanism).
    ///
    /// Copy-on-write: `clone_for_fork` shares the parent's frames
    /// with the child via `narf_memory::frame::cow::inc_ref` and
    /// strips WRITE on both regions. The first user-mode write
    /// faults into `frame::*::trap`'s page-fault handler which
    /// calls `AddressSpace::cow_split_on_write` + `remap_page` to
    /// allocate a private frame, memcpy the bytes, and restore
    /// WRITE — all without burning RAM upfront.
    Fork,

    /// Linux clone3(2) — modern `clone_args`-shaped task spawn.
    /// Single user argument: a pointer to `struct clone_args`
    /// (see `man 2 clone3`). The kernel reads `flags`, `stack`,
    /// `stack_size`, `tls`, `parent_tid`, `child_tid`, and
    /// `exit_signal` from it; everything else is treated as zero.
    ///
    /// Honoured `CLONE_*` flags (Wave-65):
    ///   - `CLONE_VM`              child shares parent's AS via Arc.
    ///   - `CLONE_THREAD`          child joins parent's thread group
    ///     (same getpid(), distinct gettid()).
    ///   - `CLONE_SIGHAND`         share sigaction table (accepted).
    ///   - `CLONE_FS`              share cwd table.
    ///   - `CLONE_FILES`           share fd table.
    ///   - `CLONE_SYSVSEM`         accepted-and-ignored (no SysV sem).
    ///   - `CLONE_PARENT_SETTID`   on success, write child TID to
    ///     `*parent_tid`.
    ///   - `CLONE_CHILD_CLEARTID`  on thread exit, zero `*child_tid`
    ///     and FUTEX_WAKE one waiter there.
    ///   - `CLONE_SETTLS`          program child's `IA32_FS_BASE` to
    ///     `args.tls` on first dispatch.
    ///
    /// Unsupported flags (CLONE_NEWPID, CLONE_NEWNS, etc.) are
    /// silently accepted today; container support lands in Wave-67.
    /// Returns the child's TID (which equals its PID when
    /// CLONE_THREAD is unset, or shares the parent's PID when set).
    Clone3,

    /// Linux set_tid_address(2). Sets the calling task's
    /// `clear_child_tid` user pointer, used by `CLONE_CHILD_CLEARTID`
    /// on thread exit. `arg0 = tidptr`. Returns the caller's TID
    /// (POSIX: returns the calling thread's TID).
    SetTidAddress,

    /// Linux arch_prctl(2) (x86_64 only — wire 158). musl's
    /// `__init_libc` calls this near the top of process startup
    /// to install its TLS thread pointer:
    ///   `arch_prctl(ARCH_SET_FS, tls_self_ptr)`.
    /// Without it musl bails via `a_crash()` and the process #UDs
    /// before reaching `main`. Sub-codes:
    ///   `ARCH_SET_GS = 0x1001`
    ///   `ARCH_SET_FS = 0x1002`  ← the one musl actually emits
    ///   `ARCH_GET_FS = 0x1003`
    ///   `ARCH_GET_GS = 0x1004`
    /// `arg0 = code`, `arg1 = addr` (for SET) or user-pointer to
    /// receive the value (for GET).
    ArchPrctl,

    /// Linux tkill(2) / tgkill(2): like kill but targets a specific
    /// thread within a process group. NARF is single-threaded per
    /// process — tgkill aliases sys_kill. `arg0 = tgid` (-1 = any),
    /// `arg1 = tid`, `arg2 = signum`. Returns 0 on success.
    Tgkill,

    /// Linux futex(2) minimal scaffold. `arg0 = uaddr_ptr`,
    /// `arg1 = op`, `arg2 = val`, `arg3 = timeout/uaddr2`,
    /// `arg4 = val3`. Honoured ops:
    ///   - FUTEX_WAIT (0): if `*uaddr == val`, would block. NARF
    ///     is single-threaded so no other task can
    ///     wake us — we return 0 (spurious wakeup
    ///     allowed by spec) so consumer code falls
    ///     into its loop.
    ///   - FUTEX_WAKE (1): would wake up to `val` waiters; we have
    ///     none, so return 0.
    ///   - FUTEX_PRIVATE (0x80) and FUTEX_CLOCK_REALTIME (0x100)
    ///     bits are accepted-and-ignored.
    ///
    /// Other ops return -1.
    Futex,

    /// Linux prctl(2): per-task settings switchboard. `arg0 = op`,
    /// `arg1 = argA`, `arg2 = argB`. Honoured ops:
    ///   - PR_SET_NAME  (15): argA = pointer to up-to-15-byte
    ///     UTF-8 name; bytes copied into the
    ///     kernel-side name slot, NUL-padded
    ///     to 16. Returns 0.
    ///   - PR_GET_NAME  (16): argA = writable 16-byte buffer;
    ///     kernel writes the recorded name +
    ///     NUL. Returns 0.
    ///   - PR_SET_DUMPABLE (4) / PR_GET_DUMPABLE (3): round-trip
    ///     the boolean.
    ///   - PR_SET_NO_NEW_PRIVS (38) / PR_GET_NO_NEW_PRIVS (39):
    ///     round-trip the boolean.
    ///
    /// Everything else returns -1.
    Prctl,

    /// Set or query the per-task heap break.
    /// `arg0 = 0` → return current break; `arg0 != 0` → resize.
    /// POSIX `brk(2)` semantics: failure returns the unchanged break.
    Brk,

    /// Write monotonic time to the user buffer at `arg1` for clock id
    /// `arg0`. Buffer is `struct timespec { tv_sec: i64, tv_nsec: i64 }`.
    /// Returns 0 on success.
    ClockGetTime,

    /// `arg0 = clock_id`, `arg1 = timespec_ptr` (read). Linux
    /// clock_settime(2): set the wall clock for CLOCK_REALTIME
    /// (clock_id = 0). NARF computes the monotonic→wall offset
    /// from the requested wall + current monotonic, then stores
    /// it via `time::set_wall_offset_uncapped`. Other clock_ids
    /// (CLOCK_MONOTONIC = 1, CLOCK_BOOTTIME, ...) return -1.
    ClockSetTime,

    /// Install a signal-handler stub. `arg0 = signum`,
    /// `arg1 = handler-vaddr` (0 to clear), `arg2 = old-out-ptr`
    /// (may be null). The recorded handler is fired on the
    /// trap-return path of any subsequent int-0x80 from this
    /// task that observes a pending signal; see `Kill` /
    /// `Sigprocmask`. Returns 0.
    Sigaction,

    /// Mark `signum` pending on the task identified by
    /// `arg0 = target_pid`. `arg1 = signum`. Returns 0; the
    /// signal is delivered the next time the target task
    /// returns to user mode through the int-0x80 / svc-0 trap
    /// gate (see `handlers::deliver_pending_signals`). Stage-4
    /// stub: any task can signal any other; cap-gating lands
    /// later.
    Kill,

    /// Linux `rt_sigaction` surface (pointer-to-struct).
    RtSigaction,

    /// Update the calling task's signal-block mask.
    /// `arg0 = how` (0 = BLOCK, 1 = UNBLOCK, 2 = SETMASK),
    /// `arg1 = set` (32-bit bitmap). Returns the **previous**
    /// mask in the syscall return value.
    Sigprocmask,

    // ── Dup family + fcntl ────────────────────────────────────────
    //
    // Slots 160..=163 are the second-wave fd-control surface real
    // libc programs reach for. POSIX `dup`/`dup2`/`dup3`/`fcntl`.
    // Numbers chosen above the signal block (152..=154) so signal
    // and dup work can land independently without renumbering.
    /// Duplicate `arg0 = oldfd` into the lowest free slot ≥ 3.
    /// Returns the new fd in the syscall return value.
    Dup,

    /// Duplicate `arg0 = oldfd` to `arg1 = newfd`. Closes `newfd`
    /// first if it's open. Returns `newfd`.
    Dup2,

    /// Like `Dup2` but `arg2 = flags` controls `FD_CLOEXEC` on the
    /// duplicate. `dup3(fd, fd, 0)` is an error (per Linux); use
    /// `Dup2` for the same-fd no-op.
    Dup3,

    /// `arg0 = fd, arg1 = cmd, arg2 = arg`. Supported commands:
    /// F_GETFD / F_SETFD / F_GETFL / F_SETFL.
    Fcntl,

    /// `arg0 = fd`, `arg1 = cmd` (u32), `arg2 = arg` (usize — typically
    /// a user-pointer to an inout struct). Linux `ioctl(2)`
    /// (x86_64 = 16, aarch64 = 29). Dispatches through `FileOps::ioctl`
    /// on the per-fd op vtable.
    ///
    /// The `cmd` word follows Linux's `_IOC` encoding (dir | size |
    /// type | nr); the per-FileOps impl decides which numbers it
    /// recognises. The default `FileOps::ioctl` returns
    /// `FsError::Unsupported` which surfaces as `-ENOTTY` (25) at this
    /// syscall layer — matching Linux's behaviour for fds whose driver
    /// has no ioctl handler.
    ///
    /// Wave 36 wires this so `/dev/dri/card<N>` + `/dev/dri/renderD<N>`
    /// dispatch the `DRM_IOCTL_*` set via
    /// `drivers/gpu/src/drm/ioctl.rs::dispatch`.
    ///
    /// Linux ref: `fs/ioctl.c::SYSCALL_DEFINE3(ioctl, ...)` +
    /// `include/uapi/asm-generic/ioctl.h` for the `_IOC` macro.
    Ioctl,

    // ── Working-directory state ────────────────────────────────────
    //
    // Slots 170/171 sit above the dup family (160..=163) so the cwd
    // and fd-control surfaces evolve independently without colliding.
    /// Update the calling task's current working directory.
    /// `arg0 = path_ptr`, `arg1 = path_len`. Stage-4 first cut:
    /// absolute paths only (path must start with `/`); relative-
    /// path support lands alongside the `*at(2)` family. Path text
    /// is required to be valid UTF-8. Returns 0 on success,
    /// `InvalidOp` on malformed input.
    Chdir,

    /// Copy the calling task's current working directory into the
    /// caller's buffer. `arg0 = buf_ptr`, `arg1 = buf_len`. The
    /// kernel writes a NUL-terminated UTF-8 string; the return
    /// value is the byte length **excluding** the terminator. If
    /// `buf_len < cwd.len() + 1` the call returns `InvalidOp` —
    /// a real libc translates that to ERANGE; the syscall return
    /// shape doesn't yet carry an errno channel.
    Getcwd,

    // ── Tier-2.5 fd extensions ─────────────────────────────────────
    //
    // Slots 164/180 reserved for `lseek(2)` and `unlink(2)`. Numbers
    // chosen to leave the dup family + cwd block contiguous and to
    // give unlink room for a follow-on `rename(2)` at 181.
    /// `arg0 = fd`, `arg1 = offset (i64)`, `arg2 = whence`
    /// (0 = SEEK_SET, 1 = SEEK_CUR, 2 = SEEK_END). Updates the
    /// per-fd offset and returns the new value as the syscall's
    /// `value`. `InvalidOp` on out-of-range fd or negative result.
    Lseek,

    /// `arg0 = path_ptr`, `arg1 = path_len`. Removes a file from the
    /// VFS via `DirOps::unlink` on the parent directory. Returns
    /// `value = 0` on success and `value = -1` on failure (the user-
    /// runtime asm wrapper observes only the value register, not the
    /// status word, so the value channel must distinguish).
    Unlink,

    // ── Tier-3b directory mutation ─────────────────────────────────
    //
    // mkdir / rmdir / rename. Each routes through
    // `VfsRegistry::resolve_parent_absolute` and dispatches on the
    // parent `DirOps`. The default trait impls for FSes that don't
    // implement these return `Unsupported`; the handler then
    // surfaces `value = -1`. POSIX-shaped 0/-1 return convention.
    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = mode (ignored)`.
    /// Creates an empty subdirectory at the absolute path's leaf.
    Mkdir,

    /// `arg0 = path_ptr`, `arg1 = path_len`. Removes an empty
    /// subdirectory.
    Rmdir,

    /// `arg0 = old_path_ptr`, `arg1 = old_path_len`,
    /// `arg2 = new_path_ptr`, `arg3 = new_path_len`. Cross-
    /// directory rename is unsupported today; both paths must
    /// resolve to the same parent directory or the syscall returns
    /// failure.
    Rename,

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = buf_ptr`,
    /// `arg3 = buf_len`. Path-based symlink read / create over MemFs
    /// symlink entries. Resolves `path` via `resolve_parent_absolute`,
    /// checks the leaf's `FileType::Symlink`, and copies up to
    /// `buf_len` target-bytes into the caller's buffer. Returns the
    /// byte count on success; -1 if the path doesn't resolve, the
    /// entry isn't a symlink, or the user pointers are bad.
    Readlink,

    /// `arg0 = target_ptr`, `arg1 = target_len`, `arg2 = link_ptr`,
    /// `arg3 = link_len`. Path-based symlink read / create over MemFs
    /// symlink entries. Resolves `link_path`'s parent and inserts an
    /// `Entry::Symlink` whose target is the verbatim `target` string.
    /// Returns 0 on success, -1 on duplicate or bad input.
    Symlink,

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = cursor` (entry
    /// index, 0-based), `arg3 = out_buf_ptr`, `arg4 = out_buf_len`.
    /// Resolve the absolute path to a directory and serialise the
    /// `cursor`-th entry into the caller's buffer in
    /// `[name_len: u32][file_type: u32][name bytes...]` format
    /// (8-byte header + name).
    /// Returns the number of bytes written on success, 0 if the
    /// cursor is past the directory's last entry, and -1 on error
    /// (path not a directory, buf too small for the header + name,
    /// path lookup failure). The libc `<dirent.h>` shim drives
    /// this once per `readdir` call with a monotonically-increasing
    /// cursor; the kernel re-snapshots each call.
    Listdir,

    /// `arg0 = image_ptr`, `arg1 = image_len`, `arg2 = params_ptr`
    /// (currently ignored). Linux `init_module(2)` (x86_64=175,
    /// aarch64 generic ABI has no direct number — NARF wires both
    /// to the same handler). Loads a kernel module from an in-memory
    /// image. The kernel copies the image into kernel space, parses
    /// the ELF, applies relocations, and calls `narf_module_init`.
    /// Returns 0 on success, negative errno on failure (see
    /// `narf_modules::syscalls::ModuleSyscallError::to_errno`).
    InitModule,

    /// `arg0 = fd`, `arg1 = params_ptr`, `arg2 = flags`. Linux
    /// `finit_module(2)` (x86_64=313, aarch64=273). Like InitModule
    /// but reads the image from an open file descriptor.
    FinitModule,

    /// `arg0 = name_ptr`, `arg1 = name_len`, `arg2 = flags`. Linux
    /// `delete_module(2)` (x86_64=176, aarch64=106). Unloads the
    /// module named `name` if its refcount is zero, otherwise
    /// returns -EBUSY.
    DeleteModule,

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = cursor`,
    /// `arg3 = out_buf_ptr`, `arg4 = out_buf_len`. Batched
    /// directory read: serialise as many entries as fit into the
    /// caller's buffer in the Linux `linux_dirent64` wire format
    /// `{ d_ino: u64, d_off: u64, d_reclen: u16, d_type: u8, d_name }`.
    /// Each record is padded to 8-byte alignment. Returns the total
    /// bytes written on success, 0 on end-of-directory, -1 on error.
    Getdents64,

    // ── Tier-3z entropy ────────────────────────────────────────────
    //
    // Slot 200 sits above the directory-mutation block to leave room
    // for future fs syscalls (read-link, sync, fdatasync, ...).
    /// `arg0 = buf_ptr`, `arg1 = buf_len`, `arg2 = flags (ignored)`.
    /// Fill the user buffer with up-to `buf_len` random bytes.
    /// Returns the byte count actually written; -1 on bad pointer or
    /// length. Stage-4 backing source is a Park-Miller LCG seeded
    /// from `monotonic_ns()` mixed with the cycle counter — NOT
    /// cryptographically secure. The seed quality matches
    /// `crypto::per_task_rng()` so callers wanting real entropy
    /// must also gate on a future `arch::has_hw_entropy()` probe.
    GetRandom,

    // ── Signal gap-fills (Phase 2) ────────────────────────────────
    //
    // Linux signal surface needed for relibc to bind directly.
    // Numbering follows the per-arch `LINUX_TABLE` below.
    /// `sigaltstack(ss, old_ss)` — install an alternate signal
    /// stack used when a handler has `SA_ONSTACK`. arg0 = `stack_t*`
    /// (may be 0 = query-only), arg1 = `stack_t*` old (may be 0).
    /// Linux `sigaltstack` (x86_64=131, aarch64=132).
    Sigaltstack,

    /// `rt_sigtimedwait(set, info, timeout, sigsetsize)` — block
    /// until one of the signals in `set` is delivered (or `timeout`
    /// expires). arg0 = signal set ptr, arg1 = siginfo out (may be
    /// 0), arg2 = timespec timeout (may be 0 = indefinite), arg3 =
    /// sigsetsize. Returns the delivered signum on success, -1 on
    /// timeout / bad input. Linux `rt_sigtimedwait` (x86_64=128,
    /// aarch64=137).
    RtSigtimedwait,

    /// `tkill(tid, sig)` — thread-targeted kill. arg0 = tid, arg1 =
    /// signum. Returns 0 on success, -1 on unknown tid. Linux
    /// `tkill` (x86_64=200, aarch64=130).
    Tkill,

    /// `rt_sigsuspend(set, sigsetsize)` — atomically swap the
    /// signal mask to `set`, block until a signal NOT in the new
    /// mask is delivered, then restore the prior mask. arg0 = set
    /// ptr, arg1 = sigsetsize. Always returns -1 (after a signal
    /// arrives). Linux `rt_sigsuspend` (x86_64=130, aarch64=133).
    RtSigsuspend,

    /// `rt_sigpending(set, sigsetsize)` — fill `set` with the
    /// pending-but-blocked signals. arg0 = set out ptr, arg1 =
    /// sigsetsize. Returns 0 on success. Linux `rt_sigpending`
    /// (x86_64=127, aarch64=136).
    RtSigpending,

    /// Wave-61: `pidfd_open(pid, flags)` — return a new fd whose
    /// `poll(POLLIN)` becomes ready when the target ProcessId exits.
    /// `arg0 = pid`, `arg1 = flags` (ignored — PIDFD_NONBLOCK only).
    /// Returns the fd on success or `-1` on failure (pid 0 or fd
    /// table full).
    ///
    /// Linux `pidfd_open` (x86_64=434, aarch64=434). The signal-
    /// sending sibling `pidfd_send_signal` (424) and the waitid
    /// P_PIDFD variant are Wave-62 follow-ups.
    PidfdOpen,

    /// Wave-67 — `setns(target, nstype)`. Linux x86_64=308; on
    /// Linux, `target` is a fd referring to `/proc/[pid]/ns/<type>`
    /// (or, on newer kernels, a pidfd). NARF doesn't yet plumb
    /// /proc/[pid]/ns/* — until that lands, the NARF surface accepts
    /// `target` as the outer TaskId / outer ProcessId of a task
    /// whose namespace the caller wants to join. `nstype` is the
    /// CLONE_NEW* bit identifying which namespace family to attach.
    /// CLONE_NEWPID (0x20000000) attaches the caller's task to the
    /// target's PID namespace; CLONE_NEWNS (0x00020000) attaches to
    /// the target's mount namespace.
    ///
    /// Returns 0 on success, !0u64 on failure (target task has no
    /// such namespace, or unsupported nstype).
    Setns,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = flags`, `arg4 = mask`, `arg5 = statxbuf_ptr`.
    /// Linux statx(2). Fills a 256-byte `struct statx` honouring
    /// `mask` and `flags` (AT_EMPTY_PATH, AT_SYMLINK_NOFOLLOW,
    /// AT_NO_AUTOMOUNT, AT_STATX_SYNC_*). Returns 0 / -1.
    Statx,

    /// Wave-72 — `uname(buf)`. arg0 = utsname-out ptr. Fills the
    /// 6×UTSNAME_LEN fields (sysname/nodename/release/version/
    /// machine/domainname) from the calling task's UTS namespace.
    /// Returns 0 / -1. Gated `container`.
    Uname,

    /// Wave-72 — `setdomainname(buf, len)`. arg0 = buf ptr, arg1 =
    /// len. Replaces the domainname of the calling task's UTS
    /// namespace. Returns 0 / -1. Gated `container`.
    Setdomainname,

    /// Wave-72 — `shmget(key, size, flags)`. arg0 = key, arg1 =
    /// size (ignored — segments are stubbed), arg2 = flags
    /// (ignored). Returns the per-NS id for `key`. Gated `container`.
    Shmget,

    /// Wave-72 — `semget(key, nsems, flags)`. Same shape as shmget.
    /// Gated `container`.
    Semget,

    /// Wave-72 — `msgget(key, flags)`. arg0 = key, arg1 = flags
    /// (ignored). Returns the per-NS id for `key`. Gated `container`.
    Msgget,
    // ── Wave-73: POSIX per-process timers + clock cleanup ──────────
    //
    // POSIX `timer_*` family + `clock_nanosleep`. Signal-delivered
    // sibling of `timerfd_*`. Gated under `linux-compat` so the
    // table only carries them when relibc-shaped binaries need
    // them; the kernel core stays lean otherwise.
    /// `timer_create(clockid, sigevent, timerid_out)` — register a
    /// POSIX per-task timer. arg0 = clockid, arg1 = sigevent ptr
    /// (may be 0 → SIGALRM default), arg2 = u32 timerid out ptr.
    /// Linux `timer_create` (x86_64=222, aarch64=107).
    TimerCreate,
    /// `timer_settime(timerid, flags, new, old)` — arm or disarm.
    /// arg0 = timerid, arg1 = flags (1 = `TIMER_ABSTIME`),
    /// arg2 = `itimerspec*` in, arg3 = `itimerspec*` out (may be 0).
    /// Linux `timer_settime` (x86_64=223, aarch64=110).
    TimerSettime,
    /// `timer_gettime(timerid, cur)` — read remaining + interval.
    /// arg0 = timerid, arg1 = `itimerspec*` out.
    /// Linux `timer_gettime` (x86_64=224, aarch64=108).
    TimerGettime,
    /// `timer_delete(timerid)` — destroy the timer.
    /// Linux `timer_delete` (x86_64=226, aarch64=111).
    TimerDelete,
    /// `clock_nanosleep(clockid, flags, request, remain)` —
    /// timed sleep against a named clock. arg0 = clockid,
    /// arg1 = flags (1 = `TIMER_ABSTIME`), arg2 = request `timespec*`,
    /// arg3 = remain `timespec*` (may be 0).
    /// Linux `clock_nanosleep` (x86_64=230, aarch64=115).
    ClockNanosleep,

    /// `socketpair(domain, type, protocol, int sv[2])` — create a
    /// connected pair of AF_UNIX sockets. arg0 = domain, arg1 = type
    /// (SOCK_STREAM, optionally OR'd with SOCK_CLOEXEC/SOCK_NONBLOCK),
    /// arg2 = protocol, arg3 = user `int sv[2]` out-pointer.
    /// Linux `socketpair` (x86_64=53, aarch64=199).
    SocketPair,

    /// `accept4(fd, addr, addrlen, flags)` — like accept(2) but with
    /// SOCK_CLOEXEC / SOCK_NONBLOCK applied to the returned fd.
    /// arg0 = fd, arg1 = addr out, arg2 = addrlen out, arg3 = flags.
    /// Linux `accept4` (x86_64=288, aarch64=242).
    SocketAccept4,

    /// `sendfile(out_fd, in_fd, off*, count)` — copy up to `count`
    /// bytes from `in_fd` to `out_fd`. arg0 = out_fd, arg1 = in_fd,
    /// arg2 = `off_t*` (may be 0 → use in_fd's offset), arg3 = count.
    /// Linux `sendfile` (x86_64=40, aarch64=71).
    Sendfile,

    /// `mremap(old, old_len, new_len, flags, new_addr)` — resize an
    /// existing anonymous mapping (in-place grow). arg0 = old addr,
    /// arg1 = old len, arg2 = new len, arg3 = flags.
    /// Linux `mremap` (x86_64=25, aarch64=216).
    Mremap,

    /// `waitid(idtype, id, infop, options, rusage)` — wait for a child
    /// returning a `siginfo_t`. arg0 = idtype (P_ALL/P_PID/P_PGID),
    /// arg1 = id, arg2 = `siginfo_t*`, arg3 = options.
    /// Linux `waitid` (x86_64=247, aarch64=95).
    Waitid,

    /// `getgroups(size, list)` / `setgroups(size, list)` — supplementary
    /// group list. NARF carries no supplementary groups, so getgroups
    /// returns 0 and setgroups is accepted. Linux getgroups
    /// (x86_64=115, aarch64=158), setgroups (x86_64=116, aarch64=159).
    Getgroups,
    Setgroups,

    /// `getresuid(r,e,s)` / `setresuid(r,e,s)` — real/effective/saved
    /// uid triple. NARF tracks a single uid, surfaced as all three.
    /// Linux getresuid (x86_64=118, aarch64=148), setresuid
    /// (x86_64=117, aarch64=147).
    Getresuid,
    Setresuid,

    /// `getresgid(r,e,s)` / `setresgid(r,e,s)` — gid triple, mirrors
    /// the uid forms. Linux getresgid (x86_64=120, aarch64=150),
    /// setresgid (x86_64=119, aarch64=149).
    Getresgid,
    Setresgid,

    /// `ppoll(fds, nfds, timespec*, sigmask, sigsetsize)` — poll(2)
    /// with a `timespec` timeout (NULL = block) and an ignored
    /// sigmask. Linux `ppoll` (x86_64=271, aarch64=73 — the generic
    /// ABI has no plain poll).
    Ppoll,

    /// `sysinfo(struct sysinfo*)` — system statistics (uptime, RAM).
    /// Linux `sysinfo` (x86_64=99, aarch64=179).
    Sysinfo,

    /// `splice(fd_in, off_in*, fd_out, off_out*, len, flags)` — move
    /// data between two fds (one a pipe) without a userspace copy.
    /// Linux `splice` (x86_64=275, aarch64=76).
    Splice,

    /// `membarrier(cmd, flags, cpu_id)` — process-wide memory barrier.
    /// QUERY returns the supported-command mask; barrier commands are
    /// no-ops on the cooperative single-CPU kernel. Linux `membarrier`
    /// (x86_64=324, aarch64=283).
    Membarrier,

    /// `clock_getres(clockid, timespec*)` — report a clock's
    /// resolution. Linux `clock_getres` (x86_64=229, aarch64=114).
    ClockGetres,

    /// `close_range(first, last, flags)` — close every open fd in
    /// `[first, last]` (or set FD_CLOEXEC with CLOSE_RANGE_CLOEXEC).
    /// Linux `close_range` (436 on both arches).
    CloseRange,

    /// `sched_getscheduler(pid)` — report the scheduling policy
    /// (always SCHED_OTHER here). Linux (x86_64=145, aarch64=120).
    SchedGetScheduler,

    /// `sched_setscheduler(pid, policy, param)` — accept a normal
    /// policy. Linux (x86_64=144, aarch64=119).
    SchedSetScheduler,

    /// `sched_rr_get_interval(pid, timespec*)` — RR quantum (0 for the
    /// cooperative policy). Linux (x86_64=148, aarch64=127).
    SchedRrGetInterval,

    /// `msync(addr, len, flags)` — flush a mapping. Anonymous mappings
    /// have nothing to write back. Linux (x86_64=26, aarch64=227).
    Msync,

    /// `mincore(addr, len, vec)` — report page residency for a mapped
    /// range. Linux (x86_64=27, aarch64=232).
    Mincore,

    /// `sync()` — flush all filesystems (no-op). Linux
    /// (x86_64=162, aarch64=81).
    Sync,

    /// `syncfs(fd)` — flush one filesystem (no-op). Linux
    /// (x86_64=306, aarch64=267).
    Syncfs,

    /// `personality(persona)` — report/accept the execution domain
    /// (always PER_LINUX). Linux (x86_64=135, aarch64=92).
    Personality,

    /// `fadvise64(fd, offset, len, advice)` — access-pattern hint
    /// (accepted, no-op). Linux (x86_64=221, aarch64=223).
    Fadvise64,

    /// `mlock2(addr, len, flags)` — like mlock with MLOCK_ONFAULT.
    /// Linux (x86_64=325, aarch64=284).
    Mlock2,

    /// `set_robust_list(head, len)` — register the per-thread robust
    /// futex list head. Linux (x86_64=273, aarch64=99).
    SetRobustList,

    /// `get_robust_list(pid, head_ptr, len_ptr)` — read it back.
    /// Linux (x86_64=274, aarch64=100).
    GetRobustList,

    /// `renameat2(olddirfd, old, newdirfd, new, flags)` — rename with
    /// RENAME_NOREPLACE / RENAME_EXCHANGE. Linux (x86_64=316,
    /// aarch64=276).
    Renameat2,

    /// `pidfd_send_signal(pidfd, sig, info, flags)` — deliver a signal
    /// to the process referenced by `pidfd`. Linux (424 on both
    /// arches).
    PidfdSendSignal,

    /// `sendmmsg(fd, mmsghdr*, vlen, flags)` — send multiple messages
    /// in one call. Linux (x86_64=307, aarch64=269).
    Sendmmsg,

    /// `recvmmsg(fd, mmsghdr*, vlen, flags, timeout)` — receive
    /// multiple messages in one call. Linux (x86_64=299, aarch64=243).
    Recvmmsg,

    /// `openat2(dirfd, path, open_how*, size)` — openat with the
    /// extensible `open_how` struct. Linux (437 on both arches).
    Openat2,

    /// `preadv(fd, iov, iovcnt, offset)` — positioned vectored read.
    /// Linux (x86_64=295, aarch64=69).
    Preadv,

    /// `pwritev(fd, iov, iovcnt, offset)` — positioned vectored write.
    /// Linux (x86_64=296, aarch64=70).
    Pwritev,

    /// `capget(hdrp, datap)` — read a task's capability sets.
    /// Linux (x86_64=125, aarch64=90).
    Capget,

    /// `capset(hdrp, datap)` — set a task's capability sets.
    /// Linux (x86_64=126, aarch64=91).
    Capset,

    /// `setitimer(which, new, old)` — arm an interval timer (ITIMER_REAL
    /// delivers SIGALRM). Linux (x86_64=38, aarch64=103).
    Setitimer,

    /// `getitimer(which, cur)` — read an interval timer.
    /// Linux (x86_64=36, aarch64=102).
    Getitimer,

    /// `alarm(seconds)` — arm ITIMER_REAL for SIGALRM after `seconds`.
    /// Linux (x86_64=37); not in the aarch64 generic ABI.
    Alarm,

    /// `setxattr(path, name, value, size, flags)` — set an extended
    /// attribute. Linux (x86_64=188, aarch64=5).
    Setxattr,

    /// `getxattr(path, name, value, size)` — read an extended attribute.
    /// Linux (x86_64=191, aarch64=8).
    Getxattr,

    /// `listxattr(path, list, size)` — list extended-attribute names.
    /// Linux (x86_64=194, aarch64=11).
    Listxattr,

    /// `readahead(fd, offset, count)` — populate the page cache (no-op).
    /// Linux (x86_64=187, aarch64=213).
    Readahead,

    /// `sync_file_range(fd, offset, nbytes, flags)` — flush a file range
    /// (no-op). Linux (x86_64=277, aarch64=84).
    SyncFileRange,

    /// `mq_open(name, oflag, mode, attr)` — open/create a POSIX message
    /// queue. Linux (x86_64=240, aarch64=180).
    MqOpen,

    /// `mq_unlink(name)` — remove a named message queue.
    /// Linux (x86_64=241, aarch64=181).
    MqUnlink,

    /// `mq_timedsend(mqd, msg, len, prio, timeout)` — enqueue a message.
    /// Linux (x86_64=242, aarch64=182).
    MqTimedsend,

    /// `mq_timedreceive(mqd, msg, len, prio, timeout)` — dequeue the
    /// highest-priority message. Linux (x86_64=243, aarch64=183).
    MqTimedreceive,

    /// `mq_getsetattr(mqd, newattr, oldattr)` — read/replace queue attrs.
    /// Linux (x86_64=245, aarch64=185).
    MqGetsetattr,

    /// `inotify_init1(flags)` — create an inotify instance fd.
    /// Linux (x86_64=294, aarch64=26).
    InotifyInit1,

    /// `inotify_add_watch(fd, path, mask)` — add/modify a watch.
    /// Linux (x86_64=254, aarch64=27).
    InotifyAddWatch,

    /// `inotify_rm_watch(fd, wd)` — remove a watch.
    /// Linux (x86_64=255, aarch64=28).
    InotifyRmWatch,

    /// `pkey_mprotect(addr, len, prot, pkey)` — mprotect tagging a range
    /// with a protection key. Linux (x86_64=329, aarch64=288).
    PkeyMprotect,

    /// `pkey_alloc(flags, access_rights)` — allocate a protection key.
    /// Linux (x86_64=330, aarch64=289).
    PkeyAlloc,

    /// `pkey_free(pkey)` — free a protection key.
    /// Linux (x86_64=331, aarch64=290).
    PkeyFree,

    /// `process_vm_readv(pid, liov, liovcnt, riov, riovcnt, flags)` —
    /// copy from a target process's address space into local iovecs.
    /// Linux (x86_64=310, aarch64=270).
    ProcessVmReadv,

    /// `process_vm_writev(pid, liov, liovcnt, riov, riovcnt, flags)` —
    /// copy local iovecs into a target process's address space.
    /// Linux (x86_64=311, aarch64=271).
    ProcessVmWritev,

    /// `mbind(addr, len, mode, nodemask, maxnode, flags)` — set a NUMA
    /// memory policy for a range. Linux (x86_64=237, aarch64=235).
    Mbind,

    /// `set_mempolicy(mode, nodemask, maxnode)` — set the task's default
    /// NUMA policy. Linux (x86_64=238, aarch64=237).
    SetMempolicy,

    /// `get_mempolicy(mode, nodemask, maxnode, addr, flags)` — query a
    /// NUMA policy. Linux (x86_64=239, aarch64=236).
    GetMempolicy,

    /// `sched_setattr(pid, attr, flags)` — set extended scheduling attrs.
    /// Linux (x86_64=314, aarch64=274).
    SchedSetattr,

    /// `sched_getattr(pid, attr, size, flags)` — read extended scheduling
    /// attrs. Linux (x86_64=315, aarch64=275).
    SchedGetattr,

    /// `adjtimex(timex)` — read/adjust kernel clock discipline.
    /// Linux (x86_64=159, aarch64=171).
    Adjtimex,

    /// `clock_adjtime(clockid, timex)` — per-clock adjtimex.
    /// Linux (x86_64=305, aarch64=266).
    ClockAdjtime,

    /// `pidfd_getfd(pidfd, targetfd, flags)` — clone an fd out of the
    /// process referenced by `pidfd`. Linux (x86_64=438, aarch64=438).
    PidfdGetfd,

    /// `kcmp(pid1, pid2, type, idx1, idx2)` — compare whether two
    /// processes share a kernel resource. Linux (x86_64=312, aarch64=272).
    Kcmp,

    /// `readv(fd, iov, iovcnt)` — vectored read at the file offset.
    /// Linux (x86_64=19, aarch64=65).
    Readv,

    /// `preadv2(fd, iov, iovcnt, pos_l, pos_h, flags)` — positioned
    /// vectored read with flags. Linux (x86_64=327, aarch64=286).
    Preadv2,

    /// `pwritev2(fd, iov, iovcnt, pos_l, pos_h, flags)` — positioned
    /// vectored write with flags. Linux (x86_64=328, aarch64=287).
    Pwritev2,

    /// `tee(fd_in, fd_out, len, flags)` — copy between two pipes without
    /// consuming the input. Linux (x86_64=276, aarch64=77).
    Tee,

    /// `vmsplice(fd, iov, nr_segs, flags)` — splice user memory to/from a
    /// pipe. Linux (x86_64=278, aarch64=75).
    Vmsplice,

    /// `semop(semid, sops, nsops)` — System V semaphore operations.
    /// Linux (x86_64=65, aarch64=193).
    Semop,

    /// `semctl(semid, semnum, cmd, arg)` — System V semaphore control.
    /// Linux (x86_64=66, aarch64=191).
    Semctl,

    /// `semtimedop(semid, sops, nsops, timeout)` — `semop` with a timeout.
    /// Linux (x86_64=220, aarch64=192).
    Semtimedop,

    /// `msgsnd(msqid, msgp, msgsz, msgflg)` — send a System V message.
    /// Linux (x86_64=69, aarch64=189).
    Msgsnd,

    /// `msgrcv(msqid, msgp, msgsz, msgtyp, msgflg)` — receive a System V
    /// message. Linux (x86_64=70, aarch64=188).
    Msgrcv,

    /// `msgctl(msqid, cmd, buf)` — System V message-queue control.
    /// Linux (x86_64=71, aarch64=187).
    Msgctl,

    /// `shmat(shmid, shmaddr, shmflg)` — attach a System V shared-memory
    /// segment into the address space. Linux (x86_64=30, aarch64=196).
    Shmat,

    /// `shmdt(shmaddr)` — detach a shared-memory segment.
    /// Linux (x86_64=67, aarch64=197).
    Shmdt,

    /// `shmctl(shmid, cmd, buf)` — System V shared-memory control.
    /// Linux (x86_64=31, aarch64=195).
    Shmctl,

    /// `lsetxattr(path, name, value, size, flags)` — set an xattr without
    /// following a final symlink. Linux (x86_64=189, aarch64=6).
    Lsetxattr,

    /// `fsetxattr(fd, name, value, size, flags)` — set an xattr by fd.
    /// Linux (x86_64=190, aarch64=7).
    Fsetxattr,

    /// `lgetxattr(path, name, value, size)`. Linux (x86_64=192, aarch64=9).
    Lgetxattr,

    /// `fgetxattr(fd, name, value, size)`. Linux (x86_64=193, aarch64=10).
    Fgetxattr,

    /// `llistxattr(path, list, size)`. Linux (x86_64=195, aarch64=12).
    Llistxattr,

    /// `flistxattr(fd, list, size)`. Linux (x86_64=196, aarch64=13).
    Flistxattr,

    /// `removexattr(path, name)`. Linux (x86_64=197, aarch64=14).
    Removexattr,

    /// `lremovexattr(path, name)`. Linux (x86_64=198, aarch64=15).
    Lremovexattr,

    /// `fremovexattr(fd, name)`. Linux (x86_64=199, aarch64=16).
    Fremovexattr,

    /// `creat(path, mode)` — create+open for writing (legacy; aarch64
    /// uses openat). Linux (x86_64=85).
    Creat,

    /// `lchown(path, uid, gid)` — chown without following a final
    /// symlink (legacy). Linux (x86_64=94).
    Lchown,

    /// `utime(path, times)` — set file access/modification times
    /// (legacy). Linux (x86_64=132).
    Utime,

    /// `utimes(path, times)` — set file times with microsecond
    /// granularity (legacy). Linux (x86_64=235).
    Utimes,

    /// `utimensat(dirfd, path, times, flags)` — set file times; modern
    /// musl routes utime/utimes/futimens through this. Linux
    /// (x86_64=280, aarch64=88).
    Utimensat,

    /// `geteuid()` — effective uid (== real uid in NARF).
    /// Linux (x86_64=107, aarch64=175).
    Geteuid,

    /// `getegid()` — effective gid. Linux (x86_64=108, aarch64=177).
    Getegid,

    /// `getpgrp()` — the calling process's process-group id (legacy).
    /// Linux (x86_64=111).
    Getpgrp,

    /// `setreuid(ruid, euid)`. Linux (x86_64=113, aarch64=145).
    Setreuid,

    /// `setregid(rgid, egid)`. Linux (x86_64=114, aarch64=143).
    Setregid,

    /// `setfsuid(fsuid)` — set filesystem uid, return the previous one.
    /// Linux (x86_64=122, aarch64=151).
    Setfsuid,

    /// `setfsgid(fsgid)` — set filesystem gid, return the previous one.
    /// Linux (x86_64=123, aarch64=152).
    Setfsgid,

    /// `rt_sigqueueinfo(pid, sig, info)` — queue a signal (with siginfo)
    /// to a process. Linux (x86_64=129, aarch64=138).
    RtSigqueueinfo,

    /// `rt_tgsigqueueinfo(tgid, tid, sig, info)` — queue a signal to a
    /// specific thread. Linux (x86_64=297, aarch64=240).
    RtTgsigqueueinfo,

    /// `mlockall(flags)` — lock the whole address space.
    /// Linux (x86_64=151, aarch64=230).
    Mlockall,

    /// `munlockall()` — unlock the whole address space.
    /// Linux (x86_64=152, aarch64=231).
    Munlockall,

    /// `memfd_secret(flags)` — anonymous fd-backed secret memory.
    /// Linux (x86_64=447, aarch64=447).
    MemfdSecret,

    /// `process_madvise(pidfd, iov, iovcnt, advice, flags)` — madvise on
    /// another process's memory. Linux (x86_64=440, aarch64=233).
    ProcessMadvise,

    /// `move_pages(pid, count, pages, nodes, status, flags)` — query or
    /// move pages between NUMA nodes. Linux (x86_64=279, aarch64=239).
    MovePages,

    /// `set_mempolicy_home_node(addr, len, home_node, flags)` — set the
    /// home NUMA node for a range. Linux (x86_64=450, aarch64=450).
    SetMempolicyHomeNode,

    /// `migrate_pages(pid, maxnode, old_nodes, new_nodes)` — migrate a
    /// process's pages between node sets. Linux (x86_64=256, aarch64=238).
    MigratePages,

    /// `vfork()` — like fork; NARF aliases it to fork (a well-behaved
    /// vfork child only execs or _exits). Linux (x86_64=58).
    Vfork,

    /// `execveat(dirfd, path, argv, envp, flags)` — execve relative to a
    /// dirfd. Linux (x86_64=322, aarch64=281).
    Execveat,

    /// `rseq(rseq, len, flags, sig)` — register a restartable-sequence
    /// area. Linux (x86_64=334, aarch64=293).
    Rseq,

    /// `faccessat2(dirfd, path, mode, flags)` — faccessat with a flags
    /// word. Linux (x86_64=439, aarch64=439).
    Faccessat2,

    /// `fchmodat2(dirfd, path, mode, flags)` — fchmodat with a flags
    /// word. Linux (x86_64=452, aarch64=452).
    Fchmodat2,

    /// `futex_waitv(waiters, nr_futexes, flags, timeout, clockid)` — wait
    /// on several futexes at once. Linux (x86_64=449, aarch64=449).
    FutexWaitv,

    /// `futex_wake(uaddr, mask, nr, flags)` — futex2 wake.
    /// Linux (x86_64=454, aarch64=454).
    FutexWake,

    /// `futex_wait(uaddr, val, mask, flags, timeout, clockid)` — futex2
    /// wait. Linux (x86_64=455, aarch64=455).
    FutexWait,

    /// `futex_requeue(waiters, flags, nr_wake, nr_requeue)` — futex2
    /// requeue. Linux (x86_64=456, aarch64=456).
    FutexRequeue,

    /// `add_key(type, description, payload, plen, keyring)` — add a key to
    /// the in-kernel key store. Linux (x86_64=248, aarch64=217).
    AddKey,

    /// `request_key(type, description, callout_info, dest_keyring)` — look
    /// a key up by type+description. Linux (x86_64=249, aarch64=218).
    RequestKey,

    /// `keyctl(operation, arg2, arg3, arg4, arg5)` — operate on a key by
    /// serial (read/update/revoke/describe/...).
    /// Linux (x86_64=250, aarch64=219).
    Keyctl,

    /// `fanotify_init(flags, event_f_flags)` — create a fanotify group fd.
    /// Linux (x86_64=300, aarch64=262).
    FanotifyInit,

    /// `fanotify_mark(fd, flags, mask, dirfd, pathname)` — add/remove/flush
    /// a fanotify mark. Linux (x86_64=301, aarch64=263).
    FanotifyMark,

    /// `landlock_create_ruleset(attr, size, flags)` — create a Landlock
    /// ruleset fd. Linux (x86_64=444, aarch64=444).
    LandlockCreateRuleset,

    /// `landlock_add_rule(ruleset_fd, rule_type, rule_attr, flags)` — add a
    /// path_beneath rule. Linux (x86_64=445, aarch64=445).
    LandlockAddRule,

    /// `landlock_restrict_self(ruleset_fd, flags)` — apply a ruleset to the
    /// calling task (irreversible). Linux (x86_64=446, aarch64=446).
    LandlockRestrictSelf,

    /// `lsm_get_self_attr(attr, ctx, size, flags)` — read a task security
    /// attribute. Linux (x86_64=459, aarch64=459).
    LsmGetSelfAttr,

    /// `lsm_set_self_attr(attr, ctx, size, flags)` — set a task security
    /// attribute. Linux (x86_64=460, aarch64=460).
    LsmSetSelfAttr,

    /// `lsm_list_modules(ids, size, flags)` — list active LSM ids.
    /// Linux (x86_64=461, aarch64=461).
    LsmListModules,

    /// `name_to_handle_at(dirfd, path, handle, mount_id, flags)` — encode a
    /// file into an opaque handle. Linux (x86_64=303, aarch64=264).
    NameToHandleAt,

    /// `open_by_handle_at(mount_fd, handle, flags)` — open a file from a
    /// handle produced by name_to_handle_at.
    /// Linux (x86_64=304, aarch64=265).
    OpenByHandleAt,
}

// ── Per-arch + NARF-extension number tables ─────────────────────────

/// Linux x86_64 wire numbers per `arch/x86/entry/syscalls/syscall_64.tbl`.
/// Sources: kernel.org (GPL-2.0-or-later). NARF re-uses these numbers
/// 1:1 so a libc compiled for Linux x86_64 binds against the NARF
/// kernel without an ABI shim.
#[cfg(target_arch = "x86_64")]
const LINUX_TABLE: &[(Syscall, u32)] = &[
    // 0..=11: I/O + memory
    (Syscall::Read, 0),
    (Syscall::Write, 1),
    (Syscall::OpenFile, 2),
    (Syscall::Close, 3),
    (Syscall::Stat, 4),
    (Syscall::Fstat, 5),
    (Syscall::Lstat, 6),
    (Syscall::Poll, 7),
    (Syscall::Select, 23),
    (Syscall::Lseek, 8),
    (Syscall::Mmap, 9),
    (Syscall::MProtect, 10),
    (Syscall::Munmap, 11),
    (Syscall::Brk, 12),
    (Syscall::RtSigaction, 13), // rt_sigaction
    (Syscall::Sigprocmask, 14), // rt_sigprocmask
    (Syscall::Sigreturn, 15),   // rt_sigreturn
    (Syscall::Ioctl, 16),
    (Syscall::Pread64, 17),
    (Syscall::Pwrite64, 18),
    (Syscall::Writev, 20),
    (Syscall::Access, 21),
    (Syscall::Pipe, 22),
    (Syscall::Yield, 24), // sched_yield
    (Syscall::Dup, 32),
    (Syscall::Dup2, 33),
    (Syscall::Pause, 34), // pause
    (Syscall::Sleep, 35), // nanosleep
    (Syscall::GetPid, 39),
    (Syscall::SocketOpen, 41), // socket
    (Syscall::SocketConnect, 42),
    (Syscall::SocketAccept, 43),
    (Syscall::SocketSend, 44), // sendto
    (Syscall::SocketRecv, 45), // recvfrom
    (Syscall::SocketSendMsg, 46),
    (Syscall::SocketRecvMsg, 47),
    (Syscall::SocketShutdown, 48),
    (Syscall::SocketBind, 49),
    (Syscall::SocketListen, 50),
    (Syscall::SocketGetSockName, 51),
    (Syscall::SocketGetPeerName, 52),
    (Syscall::SocketPair, 53),
    (Syscall::SocketAccept4, 288),
    (Syscall::Sendfile, 40),
    (Syscall::Mremap, 25),
    (Syscall::Waitid, 247),
    (Syscall::Getgroups, 115),
    (Syscall::Setgroups, 116),
    (Syscall::Setresuid, 117),
    (Syscall::Getresuid, 118),
    (Syscall::Setresgid, 119),
    (Syscall::Getresgid, 120),
    (Syscall::Ppoll, 271),
    (Syscall::Sysinfo, 99),
    (Syscall::Splice, 275),
    (Syscall::Membarrier, 324),
    (Syscall::ClockGetres, 229),
    (Syscall::CloseRange, 436),
    (Syscall::SchedGetScheduler, 145),
    (Syscall::SchedSetScheduler, 144),
    (Syscall::SchedRrGetInterval, 148),
    (Syscall::Msync, 26),
    (Syscall::Mincore, 27),
    (Syscall::Sync, 162),
    (Syscall::Syncfs, 306),
    (Syscall::Personality, 135),
    (Syscall::Fadvise64, 221),
    (Syscall::Mlock2, 325),
    (Syscall::SetRobustList, 273),
    (Syscall::GetRobustList, 274),
    (Syscall::Renameat2, 316),
    (Syscall::PidfdSendSignal, 424),
    (Syscall::Sendmmsg, 307),
    (Syscall::Recvmmsg, 299),
    (Syscall::Openat2, 437),
    (Syscall::Preadv, 295),
    (Syscall::Pwritev, 296),
    (Syscall::Capget, 125),
    (Syscall::Capset, 126),
    (Syscall::Setitimer, 38),
    (Syscall::Getitimer, 36),
    (Syscall::Alarm, 37),
    (Syscall::Setxattr, 188),
    (Syscall::Getxattr, 191),
    (Syscall::Listxattr, 194),
    (Syscall::Readahead, 187),
    (Syscall::SyncFileRange, 277),
    (Syscall::MqOpen, 240),
    (Syscall::MqUnlink, 241),
    (Syscall::MqTimedsend, 242),
    (Syscall::MqTimedreceive, 243),
    (Syscall::MqGetsetattr, 245),
    (Syscall::InotifyInit1, 294),
    (Syscall::InotifyAddWatch, 254),
    (Syscall::InotifyRmWatch, 255),
    (Syscall::PkeyMprotect, 329),
    (Syscall::PkeyAlloc, 330),
    (Syscall::PkeyFree, 331),
    (Syscall::ProcessVmReadv, 310),
    (Syscall::ProcessVmWritev, 311),
    (Syscall::Mbind, 237),
    (Syscall::SetMempolicy, 238),
    (Syscall::GetMempolicy, 239),
    (Syscall::SchedSetattr, 314),
    (Syscall::SchedGetattr, 315),
    (Syscall::Adjtimex, 159),
    (Syscall::ClockAdjtime, 305),
    (Syscall::PidfdGetfd, 438),
    (Syscall::Kcmp, 312),
    (Syscall::Readv, 19),
    (Syscall::Preadv2, 327),
    (Syscall::Pwritev2, 328),
    (Syscall::Tee, 276),
    (Syscall::Vmsplice, 278),
    (Syscall::Semop, 65),
    (Syscall::Semctl, 66),
    (Syscall::Semtimedop, 220),
    (Syscall::Msgsnd, 69),
    (Syscall::Msgrcv, 70),
    (Syscall::Msgctl, 71),
    (Syscall::Shmat, 30),
    (Syscall::Shmdt, 67),
    (Syscall::Shmctl, 31),
    (Syscall::Lsetxattr, 189),
    (Syscall::Fsetxattr, 190),
    (Syscall::Lgetxattr, 192),
    (Syscall::Fgetxattr, 193),
    (Syscall::Llistxattr, 195),
    (Syscall::Flistxattr, 196),
    (Syscall::Removexattr, 197),
    (Syscall::Lremovexattr, 198),
    (Syscall::Fremovexattr, 199),
    (Syscall::Creat, 85),
    (Syscall::Lchown, 94),
    (Syscall::Utime, 132),
    (Syscall::Utimes, 235),
    (Syscall::Utimensat, 280),
    (Syscall::Geteuid, 107),
    (Syscall::Getegid, 108),
    (Syscall::Getpgrp, 111),
    (Syscall::Setreuid, 113),
    (Syscall::Setregid, 114),
    (Syscall::Setfsuid, 122),
    (Syscall::Setfsgid, 123),
    (Syscall::RtSigqueueinfo, 129),
    (Syscall::RtTgsigqueueinfo, 297),
    (Syscall::Mlockall, 151),
    (Syscall::Munlockall, 152),
    (Syscall::MemfdSecret, 447),
    (Syscall::ProcessMadvise, 440),
    (Syscall::MovePages, 279),
    (Syscall::SetMempolicyHomeNode, 450),
    (Syscall::MigratePages, 256),
    (Syscall::Vfork, 58),
    (Syscall::Execveat, 322),
    (Syscall::Rseq, 334),
    (Syscall::Faccessat2, 439),
    (Syscall::Fchmodat2, 452),
    (Syscall::FutexWaitv, 449),
    (Syscall::FutexWake, 454),
    (Syscall::FutexWait, 455),
    (Syscall::FutexRequeue, 456),
    (Syscall::AddKey, 248),
    (Syscall::RequestKey, 249),
    (Syscall::Keyctl, 250),
    (Syscall::FanotifyInit, 300),
    (Syscall::FanotifyMark, 301),
    (Syscall::LandlockCreateRuleset, 444),
    (Syscall::LandlockAddRule, 445),
    (Syscall::LandlockRestrictSelf, 446),
    (Syscall::LsmGetSelfAttr, 459),
    (Syscall::LsmSetSelfAttr, 460),
    (Syscall::LsmListModules, 461),
    (Syscall::NameToHandleAt, 303),
    (Syscall::OpenByHandleAt, 304),
    // musl's signalfd() wrapper issues signalfd4 (289), like eventfd2;
    // map it to the same handler so signalfd is reachable on x86_64.
    (Syscall::Signalfd, 289),
    (Syscall::SocketSetSockOpt, 54),
    (Syscall::SocketGetSockOpt, 55),
    (Syscall::Clone, 56),
    (Syscall::Fork, 57),
    (Syscall::SetTidAddress, 218),
    (Syscall::Clone3, 435),
    (Syscall::Execve, 59),
    (Syscall::ExitTask, 60), // exit
    (Syscall::Wait4, 61),
    (Syscall::Kill, 62),
    (Syscall::Fcntl, 72),
    (Syscall::Flock, 73),
    (Syscall::Fsync, 74),
    (Syscall::Fdatasync, 75),
    (Syscall::Truncate, 76),
    (Syscall::Ftruncate, 77),
    (Syscall::Getcwd, 79),
    (Syscall::Chdir, 80),
    (Syscall::Rename, 82),
    (Syscall::Mkdir, 83),
    (Syscall::Rmdir, 84),
    (Syscall::Unlink, 87),
    (Syscall::Symlink, 88),
    (Syscall::Readlink, 89),
    (Syscall::Chmod, 90),
    (Syscall::Fchmod, 91),
    (Syscall::Chown, 92),
    (Syscall::Fchown, 93),
    (Syscall::Umask, 95),
    (Syscall::Getrlimit, 97),
    (Syscall::Getrusage, 98),
    (Syscall::Times, 100),
    (Syscall::Ptrace, 101),
    (Syscall::GetUid, 102),
    (Syscall::GetGid, 104),
    (Syscall::SetUid, 105),
    (Syscall::SetGid, 106),
    (Syscall::Setpgid, 109),
    (Syscall::GetPpid, 110),
    (Syscall::Setsid, 112),
    (Syscall::Getpgid, 121),
    (Syscall::Getsid, 124),
    (Syscall::RtSigpending, 127),
    (Syscall::RtSigtimedwait, 128),
    (Syscall::RtSigsuspend, 130),
    (Syscall::Sigaltstack, 131),
    (Syscall::Statfs, 137),
    (Syscall::Fstatfs, 138),
    (Syscall::Getpriority, 140),
    (Syscall::Setpriority, 141),
    (Syscall::SchedSetparam, 142),
    (Syscall::SchedGetparam, 143),
    (Syscall::SchedGetPriorityMax, 146),
    (Syscall::SchedGetPriorityMin, 147),
    (Syscall::MLock, 149),
    (Syscall::MUnlock, 150),
    (Syscall::Madvise, 28),
    (Syscall::Prctl, 157),
    (Syscall::Setrlimit, 160),
    #[cfg(feature = "linux-compat")]
    (Syscall::Chroot, 161),
    #[cfg(all(feature = "linux-compat", feature = "container"))]
    (Syscall::PivotRoot, 155),
    (Syscall::Mount, 165),
    (Syscall::Umount2, 166),
    (Syscall::SetHostname, 170),
    (Syscall::Gettid, 186),
    (Syscall::Tkill, 200),
    (Syscall::Futex, 202),
    (Syscall::SchedSetaffinity, 203),
    (Syscall::SchedGetaffinity, 204),
    (Syscall::EpollCreate, 213),
    (Syscall::Getdents64, 217),
    (Syscall::ClockSetTime, 227),
    (Syscall::ClockGetTime, 228),
    (Syscall::Tgkill, 234),
    (Syscall::Openat, 257),
    (Syscall::Mkdirat, 258),
    (Syscall::Pselect6, 270),
    (Syscall::Fchownat, 260),
    (Syscall::Newfstatat, 262),
    (Syscall::Unlinkat, 263),
    (Syscall::Renameat, 264),
    (Syscall::Symlinkat, 266),
    (Syscall::Readlinkat, 267),
    (Syscall::Fchmodat, 268),
    (Syscall::Faccessat, 269),
    (Syscall::Unshare, 272),
    // Wave-67 — Linux x86_64 setns = 308.
    (Syscall::Setns, 308),
    (Syscall::Signalfd, 282), // signalfd / signalfd4 share name
    (Syscall::TimerfdCreate, 283),
    (Syscall::Eventfd, 284), // eventfd (legacy 1-arg form)
    // eventfd2(initval, flags) is a DIFFERENT x86_64 number (290) from
    // the legacy eventfd (284). glibc/musl's `eventfd()` wrapper always
    // issues eventfd2, so map 290 to the same (eventfd2-shaped) handler.
    (Syscall::Eventfd, 290),
    (Syscall::Fallocate, 285),
    (Syscall::TimerfdSettime, 286),
    (Syscall::TimerfdGettime, 287),
    (Syscall::EpollWait, 232), // epoll_wait
    (Syscall::EpollPwait, 281),
    (Syscall::EpollCtl, 233),
    (Syscall::ArchPrctl, 158),   // arch_prctl (x86_64 only)
    (Syscall::EpollCreate, 291), // epoll_create1
    // Linux 231 = exit_group. Glibc/musl emit exit_group out of
    // __libc_start_main's exit path; mapping it to the same
    // handler as plain exit (60 → ExitTask) lets a real
    // musl-static binary terminate cleanly. NARF doesn't have
    // thread groups yet, so exit_group ≡ exit for a single-thread
    // task; once clone(CLONE_THREAD) lands, exit_group will need
    // to fan out to siblings — that's a follow-up.
    // Placed AFTER (ExitTask, 60) so `Syscall::ExitTask.raw()`
    // (which returns the first match) still resolves to 60 for
    // in-tree callers; only `from_raw(231)` finds this row.
    (Syscall::ExitTask, 231), // exit_group
    (Syscall::Pipe2, 293),
    (Syscall::Dup3, 292),
    (Syscall::Prlimit64, 302),
    (Syscall::Getcpu, 309),
    (Syscall::GetRandom, 318),
    (Syscall::MemfdCreate, 319),
    (Syscall::CopyFileRange, 326),
    (Syscall::Statx, 332),
    (Syscall::PidfdOpen, 434),
    // Loadable kernel modules — Linux x86_64 numbers.
    // init_module = 175, delete_module = 176, finit_module = 313.
    (Syscall::InitModule, 175),
    (Syscall::DeleteModule, 176),
    (Syscall::FinitModule, 313),
    // POSIX uname(2) — always present. UTS-namespace mutation
    // (sethostname / setdomainname) is gated `container` because
    // it requires the per-task NS infrastructure; reading the
    // uts struct works on every NARF build.
    (Syscall::Uname, 63),
    // setdomainname works on every build (global domainname slot).
    (Syscall::Setdomainname, 171),
    // SysV IPC get-by-key: the container build backs these with the IPC
    // namespace; the linux-compat build backs them (plus the full op
    // surface) with the self-contained `sysvipc` module.
    #[cfg(any(feature = "container", feature = "linux-compat"))]
    (Syscall::Shmget, 29),
    #[cfg(any(feature = "container", feature = "linux-compat"))]
    (Syscall::Semget, 64),
    #[cfg(any(feature = "container", feature = "linux-compat"))]
    (Syscall::Msgget, 68),
    // Wave-73 POSIX timers + clock_nanosleep (linux-compat).
    #[cfg(feature = "linux-compat")]
    (Syscall::TimerCreate, 222),
    #[cfg(feature = "linux-compat")]
    (Syscall::TimerSettime, 223),
    #[cfg(feature = "linux-compat")]
    (Syscall::TimerGettime, 224),
    #[cfg(feature = "linux-compat")]
    (Syscall::TimerDelete, 226),
    #[cfg(feature = "linux-compat")]
    (Syscall::ClockNanosleep, 230),
    // tcgetattr/tcsetattr are libc-only on Linux (ioctl(TCGETS) backed);
    // we keep them as direct syscalls and place them in the NARF range.
    // gethostname is libc-only on Linux too.
];

/// aarch64 / Generic ABI wire numbers per
/// `include/uapi/asm-generic/unistd.h`. Sources: kernel.org
/// (GPL-2.0-or-later). The Generic ABI dropped `open`/`stat`/`pipe`
/// etc. in favour of the `*at` family — NARF mirrors the same choice
/// on aarch64 by routing the legacy variants to the `*at` numbers
/// when the kernel sees them on this arch. Userspace targeting
/// aarch64 should call the `*at` syscalls directly.
#[cfg(target_arch = "aarch64")]
const LINUX_TABLE: &[(Syscall, u32)] = &[
    (Syscall::Getcwd, 17),
    (Syscall::Eventfd, 19),     // eventfd2
    (Syscall::EpollCreate, 20), // epoll_create1
    (Syscall::EpollCtl, 21),
    (Syscall::EpollWait, 22), // epoll_pwait
    (Syscall::Dup, 23),
    (Syscall::Dup3, 24),
    (Syscall::Fcntl, 25),
    (Syscall::Ioctl, 29),
    (Syscall::Flock, 32),
    (Syscall::Mkdirat, 34),
    (Syscall::Unlinkat, 35),
    (Syscall::Symlinkat, 36),
    (Syscall::Renameat, 38),
    (Syscall::Umount2, 39),
    (Syscall::Mount, 40),
    #[cfg(all(feature = "linux-compat", feature = "container"))]
    (Syscall::PivotRoot, 41),
    #[cfg(feature = "linux-compat")]
    (Syscall::Chroot, 51),
    (Syscall::Fallocate, 47),
    (Syscall::Faccessat, 48),
    (Syscall::Chdir, 49),
    (Syscall::Fchmod, 52),
    (Syscall::Fchmodat, 53),
    (Syscall::Fchownat, 54),
    (Syscall::Fchown, 55),
    (Syscall::Openat, 56),
    (Syscall::OpenFile, 56), // legacy open → openat on aarch64
    (Syscall::Close, 57),
    (Syscall::Pipe2, 59),
    (Syscall::Pipe, 59), // legacy pipe → pipe2 on aarch64
    (Syscall::Getdents64, 61),
    (Syscall::Lseek, 62),
    (Syscall::Read, 63),
    (Syscall::Write, 64),
    (Syscall::Writev, 66),
    (Syscall::Pread64, 67),
    (Syscall::Pwrite64, 68),
    (Syscall::Signalfd, 74), // signalfd4
    (Syscall::Readlinkat, 78),
    (Syscall::Newfstatat, 79),
    (Syscall::Fstat, 80),
    (Syscall::Stat, 79),  // legacy stat → newfstatat on aarch64
    (Syscall::Lstat, 79), // ditto
    (Syscall::Fsync, 82),
    (Syscall::Fdatasync, 83),
    (Syscall::TimerfdCreate, 85),
    (Syscall::TimerfdSettime, 86),
    (Syscall::TimerfdGettime, 87),
    (Syscall::ExitTask, 93), // exit
    // Linux aarch64 94 = exit_group. See x86_64 commentary above
    // the (ExitTask, 231) row for rationale. `raw(ExitTask)` still
    // returns 93 since this row sits after the 93 row.
    (Syscall::ExitTask, 94), // exit_group
    (Syscall::Unshare, 97),
    // Wave-67 — Linux aarch64 setns = 268.
    (Syscall::Setns, 268),
    (Syscall::Futex, 98),
    (Syscall::Sleep, 101), // nanosleep
    (Syscall::ClockSetTime, 112),
    (Syscall::ClockGetTime, 113),
    (Syscall::Ptrace, 117),
    (Syscall::SchedSetparam, 118),
    (Syscall::SchedGetparam, 121),
    (Syscall::SchedSetaffinity, 122),
    (Syscall::SchedGetaffinity, 123),
    (Syscall::Yield, 124), // sched_yield
    (Syscall::SchedGetPriorityMax, 125),
    (Syscall::SchedGetPriorityMin, 126),
    (Syscall::Kill, 129),
    (Syscall::Tkill, 130),
    (Syscall::Tgkill, 131),
    (Syscall::Sigaltstack, 132),
    (Syscall::RtSigsuspend, 133),
    (Syscall::RtSigaction, 134), // rt_sigaction
    (Syscall::Sigprocmask, 135), // rt_sigprocmask
    (Syscall::RtSigpending, 136),
    (Syscall::RtSigtimedwait, 137),
    (Syscall::Sigreturn, 139), // rt_sigreturn
    (Syscall::Setpriority, 140),
    (Syscall::Getpriority, 141),
    (Syscall::SetGid, 144),
    (Syscall::SetUid, 146),
    (Syscall::Times, 153),
    (Syscall::Setpgid, 154),
    (Syscall::Getpgid, 155),
    (Syscall::Getsid, 156),
    (Syscall::Setsid, 157),
    (Syscall::SetHostname, 161),
    (Syscall::Getrlimit, 163),
    (Syscall::Setrlimit, 164),
    (Syscall::Getrusage, 165),
    (Syscall::Umask, 166),
    (Syscall::Prctl, 167),
    (Syscall::Getcpu, 168),
    (Syscall::GetPid, 172),
    (Syscall::GetPpid, 173),
    (Syscall::GetUid, 174),
    (Syscall::GetGid, 176),
    (Syscall::Gettid, 178),
    (Syscall::SocketOpen, 198), // socket
    (Syscall::SocketBind, 200),
    (Syscall::SocketListen, 201),
    (Syscall::SocketAccept, 202),
    (Syscall::SocketConnect, 203),
    (Syscall::SocketGetSockName, 204),
    (Syscall::SocketGetPeerName, 205),
    (Syscall::SocketSend, 206), // sendto
    (Syscall::SocketRecv, 207), // recvfrom
    (Syscall::SocketSetSockOpt, 208),
    (Syscall::SocketGetSockOpt, 209),
    (Syscall::SocketShutdown, 210),
    (Syscall::SocketSendMsg, 211),
    (Syscall::SocketRecvMsg, 212),
    (Syscall::SocketPair, 199),
    (Syscall::SocketAccept4, 242),
    (Syscall::Sendfile, 71),
    (Syscall::Mremap, 216),
    (Syscall::Waitid, 95),
    (Syscall::Getgroups, 158),
    (Syscall::Setgroups, 159),
    (Syscall::Setresuid, 147),
    (Syscall::Getresuid, 148),
    (Syscall::Setresgid, 149),
    (Syscall::Getresgid, 150),
    (Syscall::Sysinfo, 179),
    (Syscall::Splice, 76),
    (Syscall::Membarrier, 283),
    (Syscall::ClockGetres, 114),
    (Syscall::CloseRange, 436),
    (Syscall::SchedGetScheduler, 120),
    (Syscall::SchedSetScheduler, 119),
    (Syscall::SchedRrGetInterval, 127),
    (Syscall::Msync, 227),
    (Syscall::Mincore, 232),
    (Syscall::Sync, 81),
    (Syscall::Syncfs, 267),
    (Syscall::Personality, 92),
    (Syscall::Fadvise64, 223),
    (Syscall::Mlock2, 284),
    (Syscall::SetRobustList, 99),
    (Syscall::GetRobustList, 100),
    (Syscall::Renameat2, 276),
    (Syscall::PidfdSendSignal, 424),
    (Syscall::Sendmmsg, 269),
    (Syscall::Recvmmsg, 243),
    (Syscall::Openat2, 437),
    (Syscall::Preadv, 69),
    (Syscall::Pwritev, 70),
    (Syscall::Capget, 90),
    (Syscall::Capset, 91),
    (Syscall::Setitimer, 103),
    (Syscall::Getitimer, 102),
    // alarm has no aarch64 generic-ABI number; libc emulates it via
    // setitimer, so NARF maps no wire number for it on aarch64.
    (Syscall::Setxattr, 5),
    (Syscall::Getxattr, 8),
    (Syscall::Listxattr, 11),
    (Syscall::Readahead, 213),
    (Syscall::SyncFileRange, 84),
    (Syscall::MqOpen, 180),
    (Syscall::MqUnlink, 181),
    (Syscall::MqTimedsend, 182),
    (Syscall::MqTimedreceive, 183),
    (Syscall::MqGetsetattr, 185),
    (Syscall::InotifyInit1, 26),
    (Syscall::InotifyAddWatch, 27),
    (Syscall::InotifyRmWatch, 28),
    (Syscall::PkeyMprotect, 288),
    (Syscall::PkeyAlloc, 289),
    (Syscall::PkeyFree, 290),
    (Syscall::ProcessVmReadv, 270),
    (Syscall::ProcessVmWritev, 271),
    (Syscall::Mbind, 235),
    (Syscall::SetMempolicy, 237),
    (Syscall::GetMempolicy, 236),
    (Syscall::SchedSetattr, 274),
    (Syscall::SchedGetattr, 275),
    (Syscall::Adjtimex, 171),
    (Syscall::ClockAdjtime, 266),
    (Syscall::PidfdGetfd, 438),
    (Syscall::Kcmp, 272),
    (Syscall::Readv, 65),
    (Syscall::Preadv2, 286),
    (Syscall::Pwritev2, 287),
    (Syscall::Tee, 77),
    (Syscall::Vmsplice, 75),
    (Syscall::Semop, 193),
    (Syscall::Semctl, 191),
    (Syscall::Semtimedop, 192),
    (Syscall::Msgsnd, 189),
    (Syscall::Msgrcv, 188),
    (Syscall::Msgctl, 187),
    (Syscall::Shmat, 196),
    (Syscall::Shmdt, 197),
    (Syscall::Shmctl, 195),
    (Syscall::Lsetxattr, 6),
    (Syscall::Fsetxattr, 7),
    (Syscall::Lgetxattr, 9),
    (Syscall::Fgetxattr, 10),
    (Syscall::Llistxattr, 12),
    (Syscall::Flistxattr, 13),
    (Syscall::Removexattr, 14),
    (Syscall::Lremovexattr, 15),
    (Syscall::Fremovexattr, 16),
    (Syscall::Utimensat, 88),
    (Syscall::Geteuid, 175),
    (Syscall::Getegid, 177),
    (Syscall::Setreuid, 145),
    (Syscall::Setregid, 143),
    (Syscall::Setfsuid, 151),
    (Syscall::Setfsgid, 152),
    (Syscall::RtSigqueueinfo, 138),
    (Syscall::RtTgsigqueueinfo, 240),
    (Syscall::Mlockall, 230),
    (Syscall::Munlockall, 231),
    (Syscall::MemfdSecret, 447),
    (Syscall::ProcessMadvise, 233),
    (Syscall::MovePages, 239),
    (Syscall::SetMempolicyHomeNode, 450),
    (Syscall::MigratePages, 238),
    (Syscall::Execveat, 281),
    (Syscall::Rseq, 293),
    (Syscall::Faccessat2, 439),
    (Syscall::Fchmodat2, 452),
    (Syscall::FutexWaitv, 449),
    (Syscall::FutexWake, 454),
    (Syscall::FutexWait, 455),
    (Syscall::FutexRequeue, 456),
    (Syscall::AddKey, 217),
    (Syscall::RequestKey, 218),
    (Syscall::Keyctl, 219),
    (Syscall::FanotifyInit, 262),
    (Syscall::FanotifyMark, 263),
    (Syscall::LandlockCreateRuleset, 444),
    (Syscall::LandlockAddRule, 445),
    (Syscall::LandlockRestrictSelf, 446),
    (Syscall::LsmGetSelfAttr, 459),
    (Syscall::LsmSetSelfAttr, 460),
    (Syscall::LsmListModules, 461),
    (Syscall::NameToHandleAt, 264),
    (Syscall::OpenByHandleAt, 265),
    (Syscall::Brk, 214),
    (Syscall::Munmap, 215),
    (Syscall::Clone, 220),
    (Syscall::SetTidAddress, 96),
    (Syscall::Clone3, 435),
    (Syscall::Execve, 221),
    (Syscall::Mmap, 222),
    (Syscall::MProtect, 226),
    (Syscall::MLock, 228),
    (Syscall::MUnlock, 229),
    (Syscall::Madvise, 233),
    (Syscall::Wait4, 260),
    (Syscall::Prlimit64, 261),
    (Syscall::GetRandom, 278),
    (Syscall::MemfdCreate, 279),
    (Syscall::CopyFileRange, 285),
    (Syscall::Statx, 291),
    (Syscall::PidfdOpen, 434),
    (Syscall::Statfs, 43),
    (Syscall::Fstatfs, 44),
    (Syscall::Pselect6, 72), // pselect6
    (Syscall::Ppoll, 73),    // ppoll (generic ABI has no plain poll)
    // Loadable kernel modules — aarch64 generic ABI numbers.
    // init_module = 105, delete_module = 106, finit_module = 273.
    (Syscall::InitModule, 105),
    (Syscall::DeleteModule, 106),
    (Syscall::FinitModule, 273),
    // Wave-72 — UTS/IPC syscalls (gated `container`).
    (Syscall::Uname, 160),
    (Syscall::Setdomainname, 162),
    #[cfg(any(feature = "container", feature = "linux-compat"))]
    (Syscall::Shmget, 194),
    #[cfg(any(feature = "container", feature = "linux-compat"))]
    (Syscall::Semget, 190),
    #[cfg(any(feature = "container", feature = "linux-compat"))]
    (Syscall::Msgget, 186),
    // Wave-73 POSIX timers + clock_nanosleep (linux-compat).
    #[cfg(feature = "linux-compat")]
    (Syscall::TimerCreate, 107),
    #[cfg(feature = "linux-compat")]
    (Syscall::TimerGettime, 108),
    #[cfg(feature = "linux-compat")]
    (Syscall::TimerSettime, 110),
    #[cfg(feature = "linux-compat")]
    (Syscall::TimerDelete, 111),
    #[cfg(feature = "linux-compat")]
    (Syscall::ClockNanosleep, 115),
];

/// NARF-only extension numbers — single shared range on every arch.
/// `0x4000..0x40FF` (256 slots) reserved for syscalls without a
/// Linux equivalent (ring submission, cap bootstrap, FB/shmem
/// handles, firmware install). A Linux-compiled libc never reaches
/// here on its own; only NARF-aware callers issue these numbers.
const NARF_EXTENSION_TABLE: &[(Syscall, u32)] = &[
    (Syscall::Submit, 0x4000),
    (Syscall::Bootstrap, 0x4001),
    (Syscall::WaitCompl, 0x4002),
    (Syscall::RingKick, 0x4003),
    (Syscall::FbConnect, 0x4010),
    (Syscall::FbInfo, 0x4011),
    (Syscall::FbRingMap, 0x4012),
    (Syscall::FbFlushWait, 0x4013),
    (Syscall::FbDisconnect, 0x4014),
    (Syscall::ShmemCreate, 0x4020),
    (Syscall::ShmemMap, 0x4021),
    (Syscall::ShmemDestroy, 0x4022),
    (Syscall::FirmwareInstall, 0x4030),
    (Syscall::SockRegisterBuf, 0x4040),
    (Syscall::SockSendZc, 0x4041),
    // Tcgetattr / Tcsetattr are libc-only on Linux (backed by
    // `ioctl(TCGETS)`). NARF exposes them as direct syscalls.
    (Syscall::Tcgetattr, 0x4050),
    (Syscall::Tcsetattr, 0x4051),
    // gethostname is libc-only on Linux (reads `_utsname.nodename`).
    (Syscall::GetHostname, 0x4052),
    // listdir is a NARF-only convenience (the libc reads via
    // `getdents64` directly).
    (Syscall::Listdir, 0x4053),
    // Legacy 3-arg `sigaction` (handler vaddr in a register). Linux
    // wire 13/134 now route to `RtSigaction` (pointer-to-struct), so
    // this NARF-internal form needs its own number to stay
    // dispatchable for narf-libc and the in-kernel signal tests.
    (Syscall::Sigaction, 0x4060),
];

impl Syscall {
    /// Wire number for this syscall on the calling architecture.
    /// Returns the per-arch Linux number for Linux-equivalent
    /// syscalls and the `0x4000+` NARF extension number for
    /// NARF-only ones. Panics if the variant is absent from both
    /// tables — that's a programmer error (forgot to add a row).
    #[inline]
    pub const fn raw(self) -> u32 {
        let mut i = 0;
        while i < LINUX_TABLE.len() {
            if (LINUX_TABLE[i].0 as u32) == (self as u32) {
                return LINUX_TABLE[i].1;
            }
            i += 1;
        }
        let mut j = 0;
        while j < NARF_EXTENSION_TABLE.len() {
            if (NARF_EXTENSION_TABLE[j].0 as u32) == (self as u32) {
                return NARF_EXTENSION_TABLE[j].1;
            }
            j += 1;
        }
        // A variant with no table row on this arch (e.g. `Clone` where
        // only `Clone3` is wired) maps to an out-of-range sentinel.
        // `from_raw` returns `None` for it, so a stray dispatch surfaces
        // `InvalidOp` rather than crashing. Panicking here would turn
        // any runtime `.raw()` on an unwired variant — including from
        // the in-kernel test suite — into a kernel panic.
        u32::MAX
    }

    /// Reverse lookup: return the canonical `Syscall` variant for
    /// the arch-specific wire number `n`. Returns `None` if `n` is
    /// not mapped (surfaces InvalidOp to the user).
    #[inline]
    pub const fn from_raw(n: u32) -> Option<Self> {
        let mut i = 0;
        while i < LINUX_TABLE.len() {
            if LINUX_TABLE[i].1 == n {
                return Some(LINUX_TABLE[i].0);
            }
            i += 1;
        }
        let mut j = 0;
        while j < NARF_EXTENSION_TABLE.len() {
            if NARF_EXTENSION_TABLE[j].1 == n {
                return Some(NARF_EXTENSION_TABLE[j].0);
            }
            j += 1;
        }
        None
    }
}

// ── Shared entry point (called by frame/ after trap entry) ──────────

/// Look up and execute the handler for syscall `num` with `args`.
/// If `num` is unknown, returns `NarfStatus::InvalidOp`.
pub fn kernel_syscall_entry(num: u32, ctx: &mut dyn TrapContext) {
    let p = GLOBAL_TABLE.load(Ordering::Acquire);
    if p.is_null() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // SAFETY: `p` is the non-null pointer just loaded (Acquire) from
    // `GLOBAL_TABLE`, published by `install_global` via `Box::into_raw`
    // (Release). The Box is leaked and never freed while a table is
    // installed, so the `&SyscallTable` is valid for this dispatch.
    // SAFETY: Valid memory or trusted environment
    let table = unsafe { &*p };
    let version = syscall_version(num);
    let raw_n = syscall_number(num);
    if let Some(variant) = Syscall::from_raw(raw_n) {
        table.dispatch_ctx_versioned(variant, version, ctx);
    } else {
        ctx.set_return(SyscallReturn::invalid_op());
    }
}

#[inline]
pub fn kernel_syscall_entry_plain(num: u32, args: &SyscallArgs) -> SyscallReturn {
    kernel_syscall_entry_plain_with_state(num, args, core::ptr::null_mut())
}

pub fn kernel_syscall_entry_plain_with_state(
    num: u32,
    args: &SyscallArgs,
    user_state: *mut u8,
) -> SyscallReturn {
    let n = match Syscall::from_raw(num) {
        Some(v) => v,
        None => return SyscallReturn::invalid_op(),
    };
    let p = GLOBAL_TABLE.load(Ordering::Acquire);
    if p.is_null() {
        return SyscallReturn::invalid_op();
    }
    // SAFETY: `p` is the non-null pointer just loaded (Acquire) from
    // `GLOBAL_TABLE`, published by `install_global` via `Box::into_raw`
    // (Release). The Box is leaked and never freed while a table is
    // installed, so the `&SyscallTable` is valid for this dispatch.
    // SAFETY: Valid memory or trusted environment
    let table = unsafe { &*p };
    let mut ctx = ArgsOnlyCtx::new(*args, user_state);
    table.dispatch(n, &mut ctx);
    ctx.ret
}

struct ArgsOnlyCtx {
    args: SyscallArgs,
    ret: SyscallReturn,
    user_state: *mut u8,
}

// `ArgsOnlyCtx`'s register accessors index the kernel-stack
// `UserState` snapshot by u64 slot: rax@14, rip@15, rsp@17. The
// syscall-instruction exit asm in `frame/src/x86_64/syscall.rs`
// reloads RIP from `[rsp+120]` and RSP from `[rsp+136]` using the
// same offsets. Guard them so a `UserState` field reshuffle fails the
// build here rather than silently steering `sysretq` to the wrong PC.
#[cfg(target_arch = "x86_64")]
const _: () = {
    use narf_scheduler::UserState;
    assert!(core::mem::offset_of!(UserState, rax) == 14 * 8);
    assert!(core::mem::offset_of!(UserState, rip) == 15 * 8);
    assert!(core::mem::offset_of!(UserState, rsp) == 17 * 8);
};

impl ArgsOnlyCtx {
    #[inline]
    fn new(args: SyscallArgs, user_state: *mut u8) -> Self {
        Self {
            args,
            ret: SyscallReturn::invalid_op(),
            user_state,
        }
    }
}

impl TrapContext for ArgsOnlyCtx {
    #[inline]
    fn args(&self) -> &SyscallArgs {
        &self.args
    }
    #[inline]
    fn set_return(&mut self, ret: SyscallReturn) {
        self.ret = ret;
        // Mirror the return value into the snapshot's rax slot
        // (index 14). For an ordinary syscall the exit asm overrides
        // rax via the status fold so this is inert, but for a
        // park-and-resume handler (sys_sleep) the resume path
        // re-enters user mode straight from this snapshot, so the
        // return value must live in the saved rax. Handlers that
        // park to *re-execute* the syscall (epoll_wait rewinding RIP)
        // deliberately never call `set_return`, leaving the original
        // syscall number in rax so the re-run dispatches correctly.
        if !self.user_state.is_null() {
            // SAFETY: `user_state` is non-null (checked above) and points
            // at the `[u64; 19]` kernel-stack `UserState` snapshot the
            // syscall-entry asm built; slot 14 is `rax` (offset asserted
            // by the `const _` guard above), in bounds and `u64`-aligned.
            // SAFETY: Valid memory or trusted environment
            unsafe { *(self.user_state as *mut u64).add(14) = ret.value }
        }
    }
    // The kernel-stack `UserState` snapshot the syscall-instruction
    // asm built is `[u64; 19]` in field order (see
    // `narf_arch::x86_64::user_mode::UserState`): rax@14, rip@15,
    // rflags@16, rsp@17. The exit asm reloads RIP/RSP/regs from these
    // slots, so writing them here steers where `sysretq` lands —
    // load-bearing for the polling-syscall park/resume + signal paths.
    #[inline]
    fn user_rsp(&self) -> u64 {
        if self.user_state.is_null() {
            return 0;
        }
        // SAFETY: `user_state` is non-null (checked above) and points at
        // the `[u64; 19]` kernel-stack `UserState` snapshot; slot 17 is
        // `rsp` (offset asserted by the `const _` guard above), in bounds
        // and `u64`-aligned.
        // SAFETY: Valid memory or trusted environment
        unsafe { *(self.user_state as *const u64).add(17) }
    }
    #[inline]
    fn rip(&self) -> u64 {
        if self.user_state.is_null() {
            return 0;
        }
        // SAFETY: `user_state` is non-null (checked above) and points at
        // the `[u64; 19]` kernel-stack `UserState` snapshot; slot 15 is
        // `rip` (offset asserted by the `const _` guard above), in bounds
        // and `u64`-aligned.
        // SAFETY: Valid memory or trusted environment
        unsafe { *(self.user_state as *const u64).add(15) }
    }
    #[inline]
    fn set_rip(&mut self, rip: u64) {
        if self.user_state.is_null() {
            return;
        }
        // SAFETY: `user_state` is non-null (checked above) and points at
        // the `[u64; 19]` kernel-stack `UserState` snapshot; slot 15 is
        // `rip` (offset asserted by the `const _` guard above), in bounds
        // and `u64`-aligned. The exit asm reloads RIP from this slot, so
        // the write steers where `sysretq` lands.
        // SAFETY: Valid memory or trusted environment
        unsafe { *(self.user_state as *mut u64).add(15) = rip }
    }
    #[inline]
    fn returning_to_user(&self) -> bool {
        !self.user_state.is_null()
    }
    #[inline]
    fn redirect_to_kernel(&mut self, _rip: u64, _rsp: u64) -> bool {
        false
    }
    unsafe fn save_user_state(&self, out: *mut u8) -> bool {
        if self.user_state.is_null() || out.is_null() {
            return false;
        }
        // SAFETY: both pointers are non-null (checked above). `user_state`
        // points at the 152-byte (`[u64; 19]`) kernel-stack `UserState`
        // snapshot; the caller guarantees `out` has at least 152 bytes of
        // writable, non-overlapping storage (this fn's `# Safety` contract).
        // SAFETY: Valid memory or trusted environment
        unsafe {
            // Copy the snapshot verbatim. The rax slot already holds
            // the right value: `set_return` mirrors a return value
            // into it, and a park-to-re-execute handler leaves the
            // original syscall number there (needed so the rewound
            // RIP re-dispatches the same syscall).
            core::ptr::copy_nonoverlapping(self.user_state, out, 152);
        }
        true
    }

    // Signal delivery on the `syscall`-instruction path. Unlike the
    // `int 0x80` trap path (which owns a live `TrapFrame`), here we
    // rewrite the kernel-stack `UserState` snapshot that the exit asm
    // reloads — so a handler entry / sigreturn takes effect on the
    // `sysretq`. Musl tasks reach signals only through this path.
    #[cfg(target_arch = "x86_64")]
    fn deliver_signal(&mut self, params: &SigDeliveryParams) -> bool {
        if self.user_state.is_null() {
            return false;
        }
        // SAFETY: snapshot is a valid `[u64; 19]` UserState on the
        // kernel stack for the duration of this syscall.
        // SAFETY: Valid memory or trusted environment
        let state = unsafe { &mut *(self.user_state as *mut narf_scheduler::UserState) };
        sigframe::deliver_signal_into_state(state, params)
    }

    #[cfg(target_arch = "x86_64")]
    fn perform_sigreturn(&mut self, sc_vaddr: u64) -> bool {
        if self.user_state.is_null() {
            return false;
        }
        // SAFETY: as above.
        let state = unsafe { &mut *(self.user_state as *mut narf_scheduler::UserState) };
        match sigframe::perform_sigreturn_from_state(state, sc_vaddr) {
            Some(restored_rax) => {
                // The exit asm derives the user-visible RAX from the
                // dispatcher return value (the status fold), not the
                // snapshot slot, so surface the restored RAX as the
                // syscall's "return" too.
                self.ret = SyscallReturn::ok(restored_rax);
                true
            }
            None => false,
        }
    }
}

/// x86_64 signal-frame construction/teardown that operates on a
/// [`narf_scheduler::UserState`] snapshot rather than a live trap
/// frame. Mirrors the `rt_sigframe` layout in
/// `frame/src/x86_64/trap.rs` so a frame delivered on either path can
/// be torn down on either path.
#[cfg(target_arch = "x86_64")]
mod sigframe {
    use super::SigDeliveryParams;
    use narf_scheduler::UserState;

    const SA_SIGINFO: u32 = 0x00_00_00_04;
    const SA_ONSTACK: u32 = 0x08_00_00_00;
    const SA_RESTART: u32 = 0x10_00_00_00;
    const SYSV_RED_ZONE: u64 = 128;
    /// IF | TF | CF — the only RFLAGS bits a sigreturn may restore.
    const SAFE_RFLAGS: u64 = (1 << 9) | (1 << 8) | (1 << 0);

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct McContext {
        r8: u64,
        r9: u64,
        r10: u64,
        r11: u64,
        r12: u64,
        r13: u64,
        r14: u64,
        r15: u64,
        rdi: u64,
        rsi: u64,
        rbp: u64,
        rbx: u64,
        rdx: u64,
        rax: u64,
        rcx: u64,
        rsp: u64,
        rip: u64,
        rflags: u64,
        cs: u16,
        gs: u16,
        fs: u16,
        ss: u16,
        err: u64,
        trapno: u64,
        oldmask: u64,
        cr2: u64,
        fpstate: u64,
        reserved: [u64; 8],
    }

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct UContext {
        uc_flags: u64,
        uc_link: u64,
        uc_stack_sp: u64,
        uc_stack_flags: i32,
        uc_stack_size: u64,
        uc_mcontext: McContext,
        uc_sigmask: u64,
    }

    // `uc_mcontext` sits 40 bytes into `UContext`; the siginfo block
    // is 128 bytes and precedes the ucontext. `rt_sigreturn` is
    // entered with RSP pointing at the siginfo (the handler's `ret`
    // popped the 8-byte restorer cookie), so mcontext = RSP + 168.
    const SIGINFO_BYTES: u64 = 128;
    const MCONTEXT_FROM_SIGINFO: u64 = SIGINFO_BYTES + 40;

    // Guard the layout this offset arithmetic assumes against silent
    // struct drift. Must stay in lockstep with the `rt_sigframe`
    // layout the `int 0x80` path builds in `frame/src/x86_64/trap.rs`,
    // so a frame delivered on one path tears down correctly on the
    // other.
    const _: () = {
        assert!(core::mem::offset_of!(UContext, uc_mcontext) == 40);
        assert!(MCONTEXT_FROM_SIGINFO == 168);
    };

    unsafe fn as_bytes<T: Copy>(v: &T) -> &[u8] {
        // SAFETY: `v` is a live `&T`, so its pointer is non-null, aligned
        // and valid for `size_of::<T>()` bytes; `T: Copy` (POD `#[repr(C)]`
        // here) has no padding invariants that reading raw bytes violates.
        // The returned slice borrows `v` for the same lifetime.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            core::slice::from_raw_parts(v as *const T as *const u8, core::mem::size_of::<T>())
        }
    }

    /// Lay an `rt_sigframe` on the user stack and rewrite `state` to
    /// enter the handler. Returns false if the frame couldn't be
    /// written to user memory.
    pub fn deliver_signal_into_state(state: &mut UserState, params: &SigDeliveryParams) -> bool {
        let want_siginfo = (params.flags & SA_SIGINFO) != 0;
        let want_altstack = (params.flags & SA_ONSTACK) != 0 && params.altstack_sp != 0;
        let force_rt = params.restorer != 0;

        let fallback_return = if params.restorer != 0 {
            params.restorer
        } else {
            state.rip
        };
        let saved_rip = if (params.flags & SA_RESTART) != 0 && params.restartable_syscall {
            state.rip.wrapping_sub(2)
        } else {
            state.rip
        };

        let stack_top = if want_altstack {
            params.altstack_sp.wrapping_add(params.altstack_size)
        } else {
            state.rsp.wrapping_sub(SYSV_RED_ZONE)
        };

        if want_siginfo || force_rt {
            let frame_size = 8 + 128 + core::mem::size_of::<UContext>() as u64;
            let raw_rsp = stack_top.wrapping_sub(frame_size);
            let new_rsp = (raw_rsp & !0xFu64) | 0x8;
            let siginfo_vaddr = new_rsp + 8;
            let uctx_vaddr = siginfo_vaddr + 128;

            let uctx = UContext {
                uc_flags: 0,
                uc_link: 0,
                uc_stack_sp: params.altstack_sp,
                uc_stack_flags: if want_altstack { 1 } else { 0 },
                uc_stack_size: params.altstack_size,
                uc_mcontext: McContext {
                    r8: state.r8,
                    r9: state.r9,
                    r10: state.r10,
                    r11: state.r11,
                    r12: state.r12,
                    r13: state.r13,
                    r14: state.r14,
                    r15: state.r15,
                    rdi: state.rdi,
                    rsi: state.rsi,
                    rbp: state.rbp,
                    rbx: state.rbx,
                    rdx: state.rdx,
                    rax: state.rax,
                    rcx: state.rcx,
                    rsp: state.rsp,
                    rip: saved_rip,
                    rflags: state.rflags,
                    cs: 0,
                    gs: 0,
                    fs: 0,
                    ss: 0,
                    err: 0,
                    trapno: 0,
                    oldmask: 0,
                    cr2: params.si_addr,
                    fpstate: 0,
                    reserved: [0; 8],
                },
                uc_sigmask: 0,
            };

            let mut siginfo = [0u8; 128];
            siginfo[0..4].copy_from_slice(&(params.signum as i32).to_ne_bytes());
            siginfo[8..12].copy_from_slice(&params.si_code.to_ne_bytes());
            siginfo[16..24].copy_from_slice(&params.si_addr.to_ne_bytes());
            // _sifields._rt.si_sigval (sigqueue payload) at offset 24.
            siginfo[24..32].copy_from_slice(&params.si_value.to_ne_bytes());

            // SAFETY: the active CR3 is the trapping task's; copy_to_user
            // brackets the writes with SMAP and faults user-side on a
            // bad address.
            // SAFETY: Valid memory or trusted environment
            let ok = unsafe {
                crate::handlers::copy_to_user(new_rsp, &fallback_return.to_ne_bytes()).is_ok()
                    && crate::handlers::copy_to_user(siginfo_vaddr, &siginfo).is_ok()
                    && crate::handlers::copy_to_user(uctx_vaddr, as_bytes(&uctx)).is_ok()
            };
            if !ok {
                return false;
            }

            state.rsp = new_rsp;
            state.rdi = params.signum as u64;
            state.rsi = siginfo_vaddr;
            state.rdx = uctx_vaddr;
            state.rip = params.handler;
            true
        } else {
            // Naive handler (no SA_SIGINFO, no restorer): minimal
            // `[saved_rip, signum]` push; the handler `ret`s straight
            // back to `saved_rip` without calling sigreturn.
            let raw_rsp = stack_top.wrapping_sub(16);
            let new_rsp = (raw_rsp & !0xFu64) | 0x8;
            // SAFETY: the active CR3 is the trapping task's; copy_to_user
            // brackets each write with SMAP and faults user-side on a bad
            // address. `new_rsp` / `new_rsp + 8` are 16-byte-aligned user
            // stack slots derived from the task's RSP.
            // SAFETY: Valid memory or trusted environment
            let ok = unsafe {
                crate::handlers::copy_to_user(new_rsp, &saved_rip.to_ne_bytes()).is_ok()
                    && crate::handlers::copy_to_user(
                        new_rsp + 8,
                        &(params.signum as u64).to_ne_bytes(),
                    )
                    .is_ok()
            };
            if !ok {
                return false;
            }
            state.rsp = new_rsp;
            state.rdi = params.signum as u64;
            state.rip = params.handler;
            true
        }
    }

    /// Restore `state` from an `rt_sigframe` at `sc_vaddr` (the value
    /// of RSP on entry to `rt_sigreturn`). Returns the restored RAX so
    /// the caller can surface it as the syscall return, or None if the
    /// frame couldn't be read.
    pub fn perform_sigreturn_from_state(state: &mut UserState, sc_vaddr: u64) -> Option<u64> {
        if sc_vaddr == 0 {
            return None;
        }
        let mut mc = McContext::default();
        let mc_vaddr = sc_vaddr + MCONTEXT_FROM_SIGINFO;
        // SAFETY: user-supplied vaddr; copy_from_user brackets SMAP
        // and faults user-side on a bad address.
        // SAFETY: Valid memory or trusted environment
        let dst = unsafe {
            core::slice::from_raw_parts_mut(
                &mut mc as *mut McContext as *mut u8,
                core::mem::size_of::<McContext>(),
            )
        };
        // SAFETY: `mc_vaddr` is a user vaddr; `dst` borrows the local
        // `mc` for `size_of::<McContext>()` bytes. copy_from_user brackets
        // the read with SMAP and faults user-side on a bad address, so an
        // invalid `mc_vaddr` returns Err rather than reading kernel memory.
        // SAFETY: Valid memory or trusted environment
        if unsafe { crate::handlers::copy_from_user(dst, mc_vaddr) }.is_err() {
            return None;
        }

        state.r8 = mc.r8;
        state.r9 = mc.r9;
        state.r10 = mc.r10;
        state.r11 = mc.r11;
        state.r12 = mc.r12;
        state.r13 = mc.r13;
        state.r14 = mc.r14;
        state.r15 = mc.r15;
        state.rdi = mc.rdi;
        state.rsi = mc.rsi;
        state.rbp = mc.rbp;
        state.rbx = mc.rbx;
        state.rdx = mc.rdx;
        state.rcx = mc.rcx;
        state.rax = mc.rax;
        state.rsp = mc.rsp;
        state.rip = mc.rip;
        // Restore only the safe RFLAGS bits; keep the rest of the
        // snapshot's flags (kernel-controlled).
        state.rflags = (mc.rflags & SAFE_RFLAGS) | (state.rflags & !SAFE_RFLAGS);
        Some(mc.rax)
    }
}

pub const SYS_VERSION_SHIFT: u32 = 24;
pub const SYS_NUMBER_MASK: u32 = 0x00FF_FFFF;
pub const SYS_VERSION_MASK: u32 = 0xFF00_0000;

#[inline]
pub const fn syscall_pack(version: u8, num: Syscall) -> u32 {
    ((version as u32) << SYS_VERSION_SHIFT) | (num.raw() & SYS_NUMBER_MASK)
}

#[inline]
pub const fn syscall_version(raw: u32) -> u8 {
    ((raw & SYS_VERSION_MASK) >> SYS_VERSION_SHIFT) as u8
}

#[inline]
pub const fn syscall_number(raw: u32) -> u32 {
    raw & SYS_NUMBER_MASK
}

// ── Wire-stable argument and return shapes ──────────────────────────

/// In-register arguments for a single syscall. Carries exactly what
/// the CPU provided at trap entry.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct SyscallArgs {
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
}

/// The two-register return result from any syscall.
/// `value` lands in RAX/X0, `status` in RDX/X1.
/// status=0 => success, status=1 => invalid operation, etc.
#[repr(C)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SyscallReturn {
    pub value: u64,
    pub status: abi::NarfStatus,
}

impl SyscallReturn {
    pub const OK: abi::NarfStatus = abi::NarfStatus::Ok;
    pub const INVALID_OP: abi::NarfStatus = abi::NarfStatus::InvalidOp;

    pub const fn ok(value: u64) -> Self {
        Self {
            value,
            status: abi::NarfStatus::Ok,
        }
    }
    pub const fn invalid_op() -> Self {
        Self {
            value: 0,
            status: abi::NarfStatus::InvalidOp,
        }
    }
    pub const fn oom() -> Self {
        Self {
            value: 0,
            status: abi::NarfStatus::Unsupported,
        }
    }
}

impl From<SyscallReturn> for u64 {
    fn from(r: SyscallReturn) -> Self {
        r.value
    }
}

// ── Wire-ABI layout guard ───────────────────────────────────────────
//
// `SyscallReturn` is returned from the C dispatcher as a SysV 16-byte
// struct: the first eightbyte (offset 0) lands in RAX, the second
// (offset 8) in RDX. The hand-written `syscall`-instruction return
// asm in `frame/src/x86_64/syscall.rs` reads those registers directly
// — it folds `RDX` (status) and keeps `RAX` (value). If this layout
// ever drifts (field reorder, or `status` growing past 8 bytes), that
// asm silently mangles every syscall return for `syscall`-instruction
// binaries (musl). Static binaries can mask it because their output is
// a side effect of the handler, but dynamic (ld-musl) binaries break.
// These const asserts fail the build at the source of the dependency.
const _: () = {
    assert!(core::mem::offset_of!(SyscallReturn, value) == 0);
    assert!(core::mem::offset_of!(SyscallReturn, status) == 8);
    assert!(core::mem::size_of::<SyscallReturn>() == 16);
};

// ── Dispatcher ──────────────────────────────────────────────────────

/// The global syscall table. Stored as an AtomicPtr for fast
/// lock-free lookup during traps. `install_global` takes ownership
/// of a Box'd table and publishes it.
static GLOBAL_TABLE: AtomicPtr<SyscallTable> = AtomicPtr::new(core::ptr::null_mut());

/// Initialize and publish the global syscall table.
pub fn install_global(table: SyscallTable) {
    let ptr = Box::into_raw(Box::new(table));
    GLOBAL_TABLE.store(ptr, Ordering::Release);
}

#[derive(Debug)]
pub struct SyscallEntry {
    pub number: Syscall,
    pub name: &'static str,
}

/// A collection of registered syscall handlers.
pub struct SyscallTable {
    handlers: Vec<Option<Box<dyn SyscallHandler>>>,
    versioned_handlers: Vec<(Syscall, u8, Box<dyn SyscallHandler>)>,
    names: Vec<(Syscall, &'static str)>,
}

impl core::fmt::Debug for SyscallTable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SyscallTable")
            .field("names", &self.names)
            .finish_non_exhaustive()
    }
}

impl Default for SyscallTable {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallTable {
    pub fn new() -> Self {
        Self {
            handlers: Vec::new(),
            versioned_handlers: Vec::new(),
            names: Vec::new(),
        }
    }

    pub fn register(&mut self, variant: Syscall, name: &'static str) {
        self.names.retain(|&(v, _)| v != variant);
        self.names.push((variant, name));
    }

    pub fn name_of(&self, variant: Syscall) -> Option<&'static str> {
        self.names
            .iter()
            .find(|&&(v, _)| v == variant)
            .map(|&(_, name)| name)
    }

    pub fn len(&self) -> usize {
        self.names.len()
    }

    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Register `handler` for `variant`. If `variant` already has a
    /// handler, it is replaced.
    pub fn install(&mut self, variant: Syscall, handler: Box<dyn SyscallHandler>) {
        let idx = variant as usize;
        if idx >= self.handlers.len() {
            self.handlers.resize_with(idx + 1, || None);
        }
        self.handlers[idx] = Some(handler);
    }

    pub fn install_raw<H: SyscallHandler + 'static>(
        &mut self,
        variant: Syscall,
        name: &'static str,
        handler: H,
    ) {
        self.register(variant, name);
        self.install(variant, Box::new(handler));
    }

    pub fn install_raw_fn<F>(&mut self, variant: Syscall, name: &'static str, f: F)
    where
        F: Fn(&mut dyn TrapContext) + Send + Sync + 'static,
    {
        self.install_raw(variant, name, RawFnHandler(f));
    }

    pub fn install_fn<F>(&mut self, variant: Syscall, name: &'static str, f: F)
    where
        F: Fn(&SyscallArgs) -> SyscallReturn + Send + Sync + 'static,
    {
        self.register(variant, name);
        self.install(variant, Box::new(FnHandler(f)));
    }

    pub fn install_raw_versioned<H: SyscallHandler + 'static>(
        &mut self,
        variant: Syscall,
        version: u8,
        handler: H,
    ) {
        if version == 0 {
            self.install(variant, Box::new(handler));
        } else {
            self.versioned_handlers
                .retain(|&(v, ver, _)| v != variant || ver != version);
            self.versioned_handlers
                .push((variant, version, Box::new(handler)));
        }
    }

    /// Lookup and execute handler for `variant`.
    pub fn dispatch(&self, variant: Syscall, ctx: &mut dyn TrapContext) {
        self.dispatch_ctx_versioned(variant, 0, ctx);
    }

    pub fn dispatch_ctx_versioned(&self, variant: Syscall, version: u8, ctx: &mut dyn TrapContext) {
        if version != 0 {
            if let Some((_, _, handler)) = self
                .versioned_handlers
                .iter()
                .find(|&&(v, ver, _)| v == variant && ver == version)
            {
                handler.handle(ctx);
                return;
            }
        }
        let idx = variant as usize;
        if let Some(Some(handler)) = self.handlers.get(idx) {
            handler.handle(ctx);
        } else {
            ctx.set_return(SyscallReturn::invalid_op());
        }
    }
}

/// Trait for syscall implementations.
pub trait SyscallHandler: Send + Sync {
    fn handle(&self, ctx: &mut dyn TrapContext);
}

pub trait RawSyscallHandler: SyscallHandler {}
impl<T: SyscallHandler> RawSyscallHandler for T {}

pub struct RawFnHandler<F>(pub F);

impl<F> core::fmt::Debug for RawFnHandler<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawFnHandler").finish_non_exhaustive()
    }
}

impl<F> SyscallHandler for RawFnHandler<F>
where
    F: Fn(&mut dyn TrapContext) + Send + Sync + 'static,
{
    fn handle(&self, ctx: &mut dyn TrapContext) {
        (self.0)(ctx);
    }
}

pub struct FnHandler<F>(pub F);

impl<F> core::fmt::Debug for FnHandler<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FnHandler").finish_non_exhaustive()
    }
}

impl<F> SyscallHandler for FnHandler<F>
where
    F: Fn(&SyscallArgs) -> SyscallReturn + Send + Sync + 'static,
{
    fn handle(&self, ctx: &mut dyn TrapContext) {
        let r = (self.0)(ctx.args());
        ctx.set_return(r);
    }
}

// ── Test stubs ──────────────────────────────────────────────────────

#[doc(hidden)]
pub fn __test_clear_global() {
    let ptr = GLOBAL_TABLE.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !ptr.is_null() {
        // SAFETY: `ptr` is the non-null pointer atomically swapped out of
        // `GLOBAL_TABLE`; it originated from `install_global`'s
        // `Box::into_raw(Box::new(SyscallTable))`. The swap gives us
        // exclusive ownership (no other thread can observe it now), so
        // reconstituting and dropping the Box frees it exactly once.
        // SAFETY: Valid memory or trusted environment
        unsafe { drop(Box::from_raw(ptr)) };
    }
}

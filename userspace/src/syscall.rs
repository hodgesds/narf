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

    /// Redirect the upcoming return so it lands at `rip` on `rsp`
    /// in kernel mode with kernel selectors, instead of iretq-ing
    /// back to user. Returns `true` when the arch supports this
    /// (x86_64 today); returns `false` on arches where the trap
    /// path can't yet rewrite the EL/CPL target. Callers should
    /// check the return and fall back to `set_return` if `false`.
    fn redirect_to_kernel(&mut self, rip: u64, rsp: u64) -> bool;

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
    unsafe fn save_user_state(&self, _out: *mut u8) -> bool { false }

    /// Rewrite the trap frame to deliver `handler_vaddr` with
    /// `signum` to user mode. Pushes a synthetic `[saved_rip,
    /// signum]` pair onto the user's RSP so the handler can
    /// `ret` back into the trapped code, sets the first SysV
    /// integer-arg register to `signum`, and points the trap
    /// frame's instruction pointer at `handler_vaddr`.
    ///
    /// Default: returns `false` — arches without a delivery
    /// implementation skip the rewrite, leaving the frame
    /// untouched. x86_64 overrides.
    fn deliver_signal(&mut self, _handler_vaddr: u64, _signum: u32) -> bool { false }

    /// Whether the trap is about to return to user mode. The
    /// signal-delivery hook only fires on user-bound returns;
    /// kernel-bound returns (e.g. from a `redirect_to_kernel`
    /// raw handler) skip delivery so we don't synthesize a
    /// signal frame onto a kernel stack. Default: `false`
    /// (treat as kernel-bound) so non-x86_64 arches without a
    /// CPL/EL accessor behave conservatively.
    fn returning_to_user(&self) -> bool { false }
}

// ── Numbers ─────────────────────────────────────────────────────────

/// Canonical syscall numbers. NARF starts these at 100 so there's
/// no chance of accidentally colliding with Linux conventions
/// during relibc's dual-target development.
#[non_exhaustive]
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Syscall {
    /// Submit a single `abi::Submission` from inline registers.
    /// Equivalent to pushing it to the SQ ring; the implementation
    /// uses the per-task SQ under the hood.
    Submit       = 100,

    /// Bootstrap: mint the per-task SQ+CQ and config-page caps.
    Bootstrap    = 101,

    /// Block until a new completion arrives on the per-task CQ.
    WaitCompl    = 102,

    /// Exit the current task. No completion is emitted; the
    /// scheduler drops the slot.
    ExitTask     = 103,

    /// Yield the CPU. Returns when rescheduled.
    Yield        = 104,

    /// Sleep for `arg0` nanoseconds.
    Sleep        = 105,

    /// Open a file by path (zero-terminated string pointer in
    /// arg0). Returns a file descriptor on the per-task CQ.
    OpenFile     = 110,

    /// Read `arg1` bytes from file `arg0` into buffer at `arg2`.
    Read         = 111,

    /// Write `arg1` bytes to file `arg0` from buffer at `arg2`.
    Write        = 112,

    /// Close file `arg0`.
    Close        = 113,

    // ── Tier-2 fd-table breadth + VFS path resolution + pipe(2) ────
    //
    // Slots 114..=117 are reserved for the second wave of POSIX-shaped
    // fd surface that lands alongside `Open`'s absolute-path support.
    // Co-agent C uses disjoint numbers for cwd / signal / sleep work;
    // do not re-use these here without coordination.

    /// Stat by absolute path. `arg0 = path_ptr, arg1 = path_len,
    /// arg2 = stat_out_ptr`. Writes a NARF [`StatBuf`] (see
    /// `handlers::StatBuf`) to `*stat_out_ptr`. Returns 0 on success.
    Stat         = 115,

    /// Stat by fd. `arg0 = fd, arg1 = stat_out_ptr`. Same shape as
    /// [`Stat`] otherwise.
    Fstat        = 116,

    /// Create a pipe pair. `arg0 = pipefd_out_ptr` — kernel writes
    /// two `i32`s (read fd, write fd) to that pointer. Returns 0
    /// on success.
    Pipe         = 117,

    /// `arg0 = fd`, `arg1 = len` (u64). Resize the underlying file
    /// to exactly `len` bytes — zero-fill on grow, truncate on
    /// shrink. Returns 0 on success, -1 on read-only FS / bad fd.
    /// Touches the file directly via `FileOps::truncate`; no fd
    /// offset state is altered (POSIX: ftruncate doesn't move the
    /// per-fd cursor).
    Ftruncate    = 118,

    /// `arg0 = fd`, `arg1 = buf_ptr`, `arg2 = len`, `arg3 = offset`
    /// (u64). Read at the explicit offset without altering the
    /// per-fd cursor. Returns the byte count read on success
    /// (possibly short), -1 on bad fd / null buffer.
    Pread64      = 119,

    /// `arg0 = fd`, `arg1 = buf_ptr`, `arg2 = len`, `arg3 = offset`
    /// (u64). Write at the explicit offset without altering the
    /// per-fd cursor. Returns the byte count written on success.
    Pwrite64     = 122,

    /// `arg0 = fd`. Flush buffered writes for the file. NARF FSes
    /// are in-memory so this is a structural no-op that succeeds
    /// for any open fd, fails (-1) for an unknown fd. The entry
    /// exists so consumer code that error-checks fsync sees a sane
    /// return.
    Fsync        = 123,

    /// `arg0 = fd`. Like Fsync but only metadata-omitted. Mapped
    /// to the same handler — the FS surface has no metadata-only
    /// flush distinction.
    Fdatasync    = 124,

    /// `arg0 = pipefd_out_ptr`, `arg1 = flags`. Linux pipe2(2):
    /// pipe + atomic flag set. Honoured flag: O_CLOEXEC (bit
    /// 0x80000) — both ends get FD_CLOEXEC stamped at install
    /// time. O_NONBLOCK is accepted and ignored (NARF pipes have
    /// no blocking model worth toggling — read on an empty pipe
    /// already short-returns).
    Pipe2        = 125,

    /// Map memory: `arg0` addr hint, `arg1` length, `arg2` flags.
    Mmap         = 120,

    /// Unmap memory.
    Munmap       = 121,

    /// Kick the kernel-side dispatcher to drain the calling task's
    /// shared SubmissionRing and post Completions to the shared
    /// CompletionRing. Returns the number of submissions processed.
    RingKick     = 130,

    /// Return the calling task's monotonic id. POSIX-shaped surface
    /// for relibc's `getpid()` / `gettid()` (we don't yet
    /// distinguish PID from TID — single-thread-per-process at
    /// Stage 4).
    GetPid       = 140,
    /// Return the calling task's parent id, or 0 if none. Stage 4
    /// stub: returns 0 unconditionally; real ppid lands once the
    /// scheduler tracks parentage.
    GetPpid      = 141,

    /// POSIX-shaped uid/gid query. NARF's authority model is
    /// capabilities; the per-task uid/gid table is structural
    /// state only (no security implication). Default identity
    /// is (0, 0); `SetUid` / `SetGid` mutate it.
    GetUid       = 142,
    GetGid       = 143,

    /// Set the calling task's uid (`arg0`) / gid (`arg0`). Both
    /// always succeed and return 0; capabilities still gate every
    /// privileged operation.
    SetUid       = 144,
    SetGid       = 145,

    /// `arg0 = buf_ptr`, `arg1 = buf_len`. Copy the kernel-wide
    /// hostname (NUL-terminated UTF-8) into the user buffer.
    /// Returns the byte length excluding the NUL on success, -1 on
    /// `buf_len < name_len + 1`.
    GetHostname  = 146,

    /// `arg0 = buf_ptr`, `arg1 = buf_len`. Replace the kernel-wide
    /// hostname with the supplied bytes. Stage-4 simplification:
    /// any task can set the hostname (no cap gate yet — landing
    /// alongside the cap-table integration). Returns 0 on success,
    /// -1 on rejection (length cap, malformed UTF-8).
    SetHostname  = 147,

    /// `arg0 = resource` (POSIX RLIMIT_*), `arg1 = rlimit_out_ptr`.
    /// Write the current task's `rlimit { cur, max }` pair into the
    /// user buffer. Returns 0 on success, -1 on bad pointer / out-
    /// of-range resource. NARF tracks rlimits as structural state
    /// only — capabilities still gate every privileged operation.
    Getrlimit    = 148,

    /// `arg0 = resource`, `arg1 = rlimit_in_ptr`. Update the
    /// current task's `rlimit` for `resource`. Returns 0 on
    /// success, -1 on rejection.
    Setrlimit    = 149,

    /// `arg0 = which` (PRIO_PROCESS=0 only honoured), `arg1 = who`
    /// (0 = self). Returns the current task's nice value (-20..=19),
    /// shifted by +20 so the wire value is 0..=39 (matches Linux's
    /// pre-shift convention so user code can subtract 20 without
    /// caring about negatives crossing the wire). -1 on bad which.
    Getpriority  = 156,

    /// `arg0 = which`, `arg1 = who`, `arg2 = prio` (-20..=19,
    /// already user-side). Stores the new nice value. Returns 0
    /// on success, -1 on bad which / out-of-range prio.
    Setpriority  = 157,

    /// `arg0 = tms_out_ptr`. POSIX times(2): write the calling
    /// task's `struct tms { i64 utime, stime, cutime, cstime }`
    /// (in CLK_TCK = 100Hz ticks) and return the elapsed wall-
    /// clock ticks since boot. NARF doesn't track per-task
    /// user/system splits yet — `utime` synthesises to monotonic
    /// ticks, `stime` and child fields are zero — but the surface
    /// round-trips so `clock(3)` and `time(1)`-shaped consumers
    /// see a calibratable wall clock.
    Times        = 158,

    /// `arg0 = who` (RUSAGE_SELF=0; RUSAGE_CHILDREN=-1 returns
    /// zeroed struct), `arg1 = rusage_out_ptr`. Writes the
    /// glibc-shaped 16-i64 rusage struct: ru_utime.tv_sec /
    /// ru_utime.tv_usec from monotonic_ns, every other field
    /// zero. Returns 0 on success, -1 on bad pointer.
    Getrusage    = 159,

    /// `arg0 = new_mask` (only the low 9 bits — POSIX 0o777). Sets
    /// the calling task's file-creation mask and returns the
    /// previous value. Stage-4 simplification: NARF doesn't yet
    /// enforce mode bits at file creation, so the mask is
    /// structural state — but the round-trip lets `umask(0o077)`
    /// followed by `umask(0o022)` see the prior value, which is
    /// what consumer init code expects.
    Umask        = 155,

    /// `arg0 = cpu_out_ptr`, `arg1 = node_out_ptr`. Linux getcpu(2):
    /// write the calling CPU id + NUMA node id to the supplied
    /// out-pointers (each may be null). NARF user mode is
    /// single-CPU today — both return 0. Returns 0 on success.
    Getcpu       = 165,

    /// `arg0 = pid` (0 = self), `arg1 = mask_size` (bytes),
    /// `arg2 = mask_out_ptr`. Linux sched_getaffinity(2): write
    /// a CPU-set bitmap for the target task. NARF is single-CPU
    /// in user mode; we always return a 1-bit mask (CPU 0 set,
    /// every other bit clear). Returns the byte count written
    /// on success (= `mask_size` rounded down to a multiple of 8),
    /// -1 on bad pointer or oversized request.
    SchedGetaffinity = 166,

    /// `arg0 = pid`, `arg1 = mask_size` (bytes),
    /// `arg2 = mask_in_ptr`. sched_setaffinity(2). NARF doesn't
    /// pin tasks (single-CPU model); the bitmap is read but
    /// ignored. Returns 0 on success, -1 on bad pointer.
    SchedSetaffinity = 167,

    /// Set or query the per-task heap break.
    /// `arg0 = 0` → return current break; `arg0 != 0` → resize.
    /// POSIX `brk(2)` semantics: failure returns the unchanged break.
    Brk          = 150,

    /// Write monotonic time to the user buffer at `arg1` for clock id
    /// `arg0`. Buffer is `struct timespec { tv_sec: i64, tv_nsec: i64 }`.
    /// Returns 0 on success.
    ClockGetTime = 151,

    /// Install a signal-handler stub. `arg0 = signum`,
    /// `arg1 = handler-vaddr` (0 to clear), `arg2 = old-out-ptr`
    /// (may be null). The recorded handler is fired on the
    /// trap-return path of any subsequent int-0x80 from this
    /// task that observes a pending signal; see `Kill` /
    /// `Sigprocmask`. Returns 0.
    Sigaction    = 152,

    /// Mark `signum` pending on the task identified by
    /// `arg0 = target_pid`. `arg1 = signum`. Returns 0; the
    /// signal is delivered the next time the target task
    /// returns to user mode through the int-0x80 / svc-0 trap
    /// gate (see `handlers::deliver_pending_signals`). Stage-4
    /// stub: any task can signal any other; cap-gating lands
    /// later.
    Kill         = 153,

    /// Update the calling task's signal-block mask.
    /// `arg0 = how` (0 = BLOCK, 1 = UNBLOCK, 2 = SETMASK),
    /// `arg1 = set` (32-bit bitmap). Returns the **previous**
    /// mask in the syscall return value.
    Sigprocmask  = 154,

    // ── Dup family + fcntl ────────────────────────────────────────
    //
    // Slots 160..=163 are the second-wave fd-control surface real
    // libc programs reach for. POSIX `dup`/`dup2`/`dup3`/`fcntl`.
    // Numbers chosen above the signal block (152..=154) so signal
    // and dup work can land independently without renumbering.

    /// Duplicate `arg0 = oldfd` into the lowest free slot ≥ 3.
    /// Returns the new fd in the syscall return value.
    Dup          = 160,

    /// Duplicate `arg0 = oldfd` to `arg1 = newfd`. Closes `newfd`
    /// first if it's open. Returns `newfd`.
    Dup2         = 161,

    /// Like `Dup2` but `arg2 = flags` controls `FD_CLOEXEC` on the
    /// duplicate. `dup3(fd, fd, 0)` is an error (per Linux); use
    /// `Dup2` for the same-fd no-op.
    Dup3         = 162,

    /// `arg0 = fd, arg1 = cmd, arg2 = arg`. Supported commands:
    /// F_GETFD / F_SETFD / F_GETFL / F_SETFL.
    Fcntl        = 163,

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
    Chdir        = 170,

    /// Copy the calling task's current working directory into the
    /// caller's buffer. `arg0 = buf_ptr`, `arg1 = buf_len`. The
    /// kernel writes a NUL-terminated UTF-8 string; the return
    /// value is the byte length **excluding** the terminator. If
    /// `buf_len < cwd.len() + 1` the call returns `InvalidOp` —
    /// a real libc translates that to ERANGE; the syscall return
    /// shape doesn't yet carry an errno channel.
    Getcwd       = 171,

    // ── Tier-2.5 fd extensions ─────────────────────────────────────
    //
    // Slots 164/180 reserved for `lseek(2)` and `unlink(2)`. Numbers
    // chosen to leave the dup family + cwd block contiguous and to
    // give unlink room for a follow-on `rename(2)` at 181.

    /// `arg0 = fd`, `arg1 = offset (i64)`, `arg2 = whence`
    /// (0 = SEEK_SET, 1 = SEEK_CUR, 2 = SEEK_END). Updates the
    /// per-fd offset and returns the new value as the syscall's
    /// `value`. `InvalidOp` on out-of-range fd or negative result.
    Lseek        = 164,

    /// `arg0 = path_ptr`, `arg1 = path_len`. Removes a file from the
    /// VFS via `DirOps::unlink` on the parent directory. Returns
    /// `value = 0` on success and `value = -1` on failure (the user-
    /// runtime asm wrapper observes only the value register, not the
    /// status word, so the value channel must distinguish).
    Unlink       = 180,

    // ── Tier-3b directory mutation ─────────────────────────────────
    //
    // mkdir / rmdir / rename. Each routes through
    // `VfsRegistry::resolve_parent_absolute` and dispatches on the
    // parent `DirOps`. The default trait impls for FSes that don't
    // implement these return `Unsupported`; the handler then
    // surfaces `value = -1`. POSIX-shaped 0/-1 return convention.

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = mode (ignored)`.
    /// Creates an empty subdirectory at the absolute path's leaf.
    Mkdir        = 190,

    /// `arg0 = path_ptr`, `arg1 = path_len`. Removes an empty
    /// subdirectory.
    Rmdir        = 191,

    /// `arg0 = old_path_ptr`, `arg1 = old_path_len`,
    /// `arg2 = new_path_ptr`, `arg3 = new_path_len`. Cross-
    /// directory rename is unsupported today; both paths must
    /// resolve to the same parent directory or the syscall returns
    /// failure.
    Rename       = 192,

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = buf_ptr`,
    /// `arg3 = buf_len`. POSIX readlink. NARF has no symlink
    /// implementation; we always return -1 (the user's libc shim
    /// translates that to EINVAL "not a symlink"). Wired so a
    /// utility that probes optional symlink expansion sees a sane
    /// failure rather than a hang.
    Readlink     = 193,

    /// `arg0 = target_ptr`, `arg1 = target_len`, `arg2 = link_ptr`,
    /// `arg3 = link_len`. POSIX symlink. Stub returning -1.
    Symlink      = 194,

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
    Listdir      = 195,

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
    GetRandom    = 200,
}

impl Syscall {
    /// Raw wire number.
    #[inline]
    pub const fn raw(self) -> u32 { self as u32 }

    /// Parse from a raw number.
    pub const fn from_raw(n: u32) -> Option<Self> {
        Some(match n {
            100 => Syscall::Submit,
            101 => Syscall::Bootstrap,
            102 => Syscall::WaitCompl,
            103 => Syscall::ExitTask,
            104 => Syscall::Yield,
            105 => Syscall::Sleep,
            110 => Syscall::OpenFile,
            111 => Syscall::Read,
            112 => Syscall::Write,
            113 => Syscall::Close,
            115 => Syscall::Stat,
            116 => Syscall::Fstat,
            117 => Syscall::Pipe,
            118 => Syscall::Ftruncate,
            119 => Syscall::Pread64,
            122 => Syscall::Pwrite64,
            123 => Syscall::Fsync,
            124 => Syscall::Fdatasync,
            125 => Syscall::Pipe2,
            120 => Syscall::Mmap,
            121 => Syscall::Munmap,
            130 => Syscall::RingKick,
            140 => Syscall::GetPid,
            141 => Syscall::GetPpid,
            142 => Syscall::GetUid,
            143 => Syscall::GetGid,
            144 => Syscall::SetUid,
            145 => Syscall::SetGid,
            146 => Syscall::GetHostname,
            147 => Syscall::SetHostname,
            148 => Syscall::Getrlimit,
            149 => Syscall::Setrlimit,
            155 => Syscall::Umask,
            165 => Syscall::Getcpu,
            166 => Syscall::SchedGetaffinity,
            167 => Syscall::SchedSetaffinity,
            156 => Syscall::Getpriority,
            157 => Syscall::Setpriority,
            158 => Syscall::Times,
            159 => Syscall::Getrusage,
            150 => Syscall::Brk,
            151 => Syscall::ClockGetTime,
            152 => Syscall::Sigaction,
            153 => Syscall::Kill,
            154 => Syscall::Sigprocmask,
            160 => Syscall::Dup,
            161 => Syscall::Dup2,
            162 => Syscall::Dup3,
            163 => Syscall::Fcntl,
            170 => Syscall::Chdir,
            171 => Syscall::Getcwd,
            164 => Syscall::Lseek,
            180 => Syscall::Unlink,
            190 => Syscall::Mkdir,
            191 => Syscall::Rmdir,
            192 => Syscall::Rename,
            193 => Syscall::Readlink,
            194 => Syscall::Symlink,
            195 => Syscall::Listdir,
            200 => Syscall::GetRandom,
            _   => return None,
        })
    }
}

// ── Args + Return ───────────────────────────────────────────────────

/// Syscall arguments in register-passing order. Six arguments
/// matches the x86_64 syscall convention (rdi/rsi/rdx/r10/r8/r9)
/// and is wide enough for aarch64 (x0..=x5).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SyscallArgs {
    pub arg0: u64, pub arg1: u64, pub arg2: u64,
    pub arg3: u64, pub arg4: u64, pub arg5: u64,
}

/// Return value for a syscall. Mirrors `abi::NarfStatus` + one
/// `u64` payload register.
///
/// `status` values match `abi::NarfStatus` wire tags so downstream
/// tooling shares a vocabulary:
/// - `0` = Ok
/// - `1` = InvalidOp
/// - `2` = Cancelled
/// - `3` = CancelRequested
/// - `4` = CapRevoked
/// ... (see `abi::NarfStatus`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SyscallReturn {
    pub status: u32,
    pub value:  u64,
}

impl SyscallReturn {
    pub const OK:         u32 = 0;
    pub const INVALID_OP: u32 = 1;

    #[inline]
    pub const fn ok(value: u64) -> Self { Self { status: Self::OK, value } }

    #[inline]
    pub const fn invalid_op() -> Self { Self { status: Self::INVALID_OP, value: 0 } }
}

// ── Handler + table ─────────────────────────────────────────────────

/// Dispatch target for a single syscall. Kernel subsystems
/// implement this and register themselves with a `SyscallTable`
/// at boot.
pub trait SyscallHandler: Send + Sync + 'static {
    fn invoke(&self, args: &SyscallArgs) -> SyscallReturn;
}

/// Raw variant of `SyscallHandler`. Receives the full
/// `TrapContext`, can read args + set return, and additionally can
/// call `redirect_to_kernel` to unwind into kernel state instead
/// of returning to the caller's user context.
///
/// Use for syscalls that need direct control over the return path
/// (exit, fork, exec, longjmp-style unwinds); use plain
/// `SyscallHandler` for everything else.
pub trait RawSyscallHandler: Send + Sync + 'static {
    fn invoke(&self, ctx: &mut dyn TrapContext);
}

/// Convenience wrapper so `impl Fn(&SyscallArgs) -> SyscallReturn`
/// works as a handler without a manual struct.
pub struct FnHandler<F: Fn(&SyscallArgs) -> SyscallReturn + Send + Sync + 'static>(pub F);

impl<F> core::fmt::Debug for FnHandler<F>
where F: Fn(&SyscallArgs) -> SyscallReturn + Send + Sync + 'static {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FnHandler").finish_non_exhaustive()
    }
}

impl<F> SyscallHandler for FnHandler<F>
where F: Fn(&SyscallArgs) -> SyscallReturn + Send + Sync + 'static {
    fn invoke(&self, args: &SyscallArgs) -> SyscallReturn { (self.0)(args) }
}

/// One table slot: the diagnostic name + zero/one handler of each
/// kind. Raw handler wins when both are installed.
pub struct SyscallEntry {
    pub number:      Syscall,
    pub name:        &'static str,
    pub handler:     Option<Box<dyn SyscallHandler>>,
    pub raw_handler: Option<Box<dyn RawSyscallHandler>>,
}

impl core::fmt::Debug for SyscallEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SyscallEntry")
            .field("number",      &self.number)
            .field("name",        &self.name)
            .field("has_handler", &self.handler.is_some())
            .field("has_raw",     &self.raw_handler.is_some())
            .finish()
    }
}

/// In-kernel syscall table. Constructed at boot, handed to
/// `install_global` once every subsystem has registered.
#[derive(Debug)]
pub struct SyscallTable {
    entries: Vec<SyscallEntry>,
}

impl SyscallTable {
    pub const fn new() -> Self { Self { entries: Vec::new() } }

    /// Register a diagnostic name against a syscall number (no
    /// handler body). Useful when a subsystem wants the name to
    /// show up in tracing while implementation is pending.
    pub fn register(&mut self, n: Syscall, name: &'static str) {
        self.entries.push(SyscallEntry {
            number: n, name, handler: None, raw_handler: None,
        });
    }

    /// Register a live plain handler for `n`. Replaces any prior
    /// plain handler for the same number so Stage-4 subsystems can
    /// take over stubs landed earlier. A raw handler registered
    /// separately still wins on dispatch.
    pub fn install<H: SyscallHandler + 'static>(
        &mut self, n: Syscall, name: &'static str, handler: H,
    ) {
        self.install_slot(n, name, Some(Box::new(handler) as Box<dyn SyscallHandler>), None);
    }

    /// Register a raw handler for `n`. A raw handler receives the
    /// full `TrapContext` (args + return setter + redirect-to-
    /// kernel) and is chosen over a plain handler when both are
    /// installed.
    pub fn install_raw<H: RawSyscallHandler + 'static>(
        &mut self, n: Syscall, name: &'static str, handler: H,
    ) {
        self.install_slot(n, name, None, Some(Box::new(handler) as Box<dyn RawSyscallHandler>));
    }

    fn install_slot(
        &mut self,
        n: Syscall,
        name: &'static str,
        plain: Option<Box<dyn SyscallHandler>>,
        raw:   Option<Box<dyn RawSyscallHandler>>,
    ) {
        if let Some(slot) = self.entries.iter_mut().find(|e| e.number == n) {
            slot.name = name;
            if plain.is_some() { slot.handler     = plain; }
            if raw.is_some()   { slot.raw_handler = raw; }
        } else {
            self.entries.push(SyscallEntry {
                number: n, name, handler: plain, raw_handler: raw,
            });
        }
    }

    /// Shorthand: install a closure as a plain handler.
    pub fn install_fn<F>(&mut self, n: Syscall, name: &'static str, f: F)
    where F: Fn(&SyscallArgs) -> SyscallReturn + Send + Sync + 'static {
        self.install(n, name, FnHandler(f));
    }

    /// Shorthand: install a closure as a raw handler.
    pub fn install_raw_fn<F>(&mut self, n: Syscall, name: &'static str, f: F)
    where F: Fn(&mut dyn TrapContext) + Send + Sync + 'static {
        self.install_raw(n, name, RawFnHandler(f));
    }

    /// Look up the diagnostic name for `n`.
    pub fn name_of(&self, n: Syscall) -> Option<&'static str> {
        self.entries.iter().find(|e| e.number == n).map(|e| e.name)
    }

    /// Legacy dispatch: fires only plain handlers, returns
    /// `None` if no plain handler is installed. Kept for the
    /// existing tests; the arch trap path uses `dispatch_ctx` so
    /// it can honour raw handlers.
    pub fn dispatch(&self, n: Syscall, args: &SyscallArgs) -> Option<SyscallReturn> {
        let slot = self.entries.iter().find(|e| e.number == n)?;
        let h = slot.handler.as_ref()?;
        Some(h.invoke(args))
    }

    /// Raw-aware dispatch. If a raw handler is installed, call it
    /// with `ctx` (it's responsible for `set_return` /
    /// `redirect_to_kernel`). Otherwise fall back to the plain
    /// handler. Absence of both means `SyscallReturn::invalid_op`.
    pub fn dispatch_ctx(&self, n: Syscall, ctx: &mut dyn TrapContext) {
        if let Some(slot) = self.entries.iter().find(|e| e.number == n) {
            if let Some(h) = slot.raw_handler.as_ref() {
                h.invoke(ctx);
                return;
            }
            if let Some(h) = slot.handler.as_ref() {
                let ret = h.invoke(ctx.args());
                ctx.set_return(ret);
                return;
            }
        }
        ctx.set_return(SyscallReturn::invalid_op());
    }

    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
}

/// Closure-backed raw handler shim.
pub struct RawFnHandler<F: Fn(&mut dyn TrapContext) + Send + Sync + 'static>(pub F);

impl<F> core::fmt::Debug for RawFnHandler<F>
where F: Fn(&mut dyn TrapContext) + Send + Sync + 'static {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawFnHandler").finish_non_exhaustive()
    }
}

impl<F> RawSyscallHandler for RawFnHandler<F>
where F: Fn(&mut dyn TrapContext) + Send + Sync + 'static {
    fn invoke(&self, ctx: &mut dyn TrapContext) { (self.0)(ctx); }
}

impl Default for SyscallTable {
    fn default() -> Self { Self::new() }
}

// ── Global install + dispatch ───────────────────────────────────────
//
// The published table sits behind an `AtomicPtr<SyscallTable>` rather
// than a lock. Read-side dispatch (the trap path) loads the pointer,
// dereferences it, and runs the handler — without holding any lock
// across the handler call. This is load-bearing for the polling-
// future path: a raw handler can `longjmp` out of the trap without
// returning, and any lock guard live across the call would leak.
// Switching to AtomicPtr lets the trap return via longjmp without
// dropping a lock.
//
// `install_global` swaps the pointer atomically and **leaks** the
// prior table — Stage-4 boot installs once and never re-installs at
// runtime, and during tests `__test_clear_global` is the only caller
// that nulls the slot (no concurrent dispatch is possible there).
// The leak is therefore bounded to test resets and is the price of
// long-jmp-safe dispatch. The test reset path drops the prior table
// because no concurrent dispatch is possible during test setup.

static GLOBAL: AtomicPtr<SyscallTable> = AtomicPtr::new(core::ptr::null_mut());

/// Publish `table` as the kernel-wide dispatch table. Replaces any
/// prior installation; the prior `Box<SyscallTable>` is leaked since
/// in-flight dispatchers may still hold references to it (the trap
/// path takes a snapshot of the pointer at entry and doesn't hold a
/// lock across the handler call). Stage-4 boot calls this once.
pub fn install_global(table: SyscallTable) {
    let new_ptr = Box::into_raw(Box::new(table));
    let _prev = GLOBAL.swap(new_ptr, Ordering::AcqRel);
    // Deliberately leak `_prev`: a raw handler in flight under the
    // prior pointer could be unwinding via longjmp; freeing here
    // would race with the read side. Re-installs are extremely rare
    // (one per boot), so the leak is a one-time cost.
}

/// Read-only access: is a global table installed?
pub fn global_installed() -> bool {
    !GLOBAL.load(Ordering::Acquire).is_null()
}

/// Clear the global table — test hook. Drops the prior `Box`. Safe
/// to call only when no syscall dispatch is in flight (test setup
/// boundary).
#[doc(hidden)]
pub fn __test_clear_global() {
    let prev = GLOBAL.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if !prev.is_null() {
        // SAFETY: caller guarantees no dispatch is in flight against
        // `prev`; this is the test reset boundary.
        unsafe { drop(Box::from_raw(prev)); }
    }
}

/// Entry point the arch trap stub calls after saving the user
/// register file.  `num` is the raw wire number (not pre-validated
/// against the `Syscall` enum); unknown numbers or missing handlers
/// surface `SyscallReturn::invalid_op()`.
///
/// A `None` global (no `install_global` yet) also returns
/// `invalid_op` — the arch stub shouldn't be running before boot
/// finishes, but a safe fallback beats an unwrap.
///
/// Arch trap code has two choices:
/// - **Plain path**: call `kernel_syscall_entry_plain(num, &args)`
///   which only fires plain handlers and returns a `SyscallReturn`
///   the caller writes into registers manually.
/// - **Raw-aware path**: call `kernel_syscall_entry(num, &mut ctx)`
///   so raw handlers can call `redirect_to_kernel` directly.
/// The arch trap path in this tree uses the raw-aware form.
#[inline]
pub fn kernel_syscall_entry(num: u32, ctx: &mut dyn TrapContext) {
    let n = match Syscall::from_raw(num) {
        Some(v) => v,
        None    => { ctx.set_return(SyscallReturn::invalid_op()); return; }
    };
    let p = GLOBAL.load(Ordering::Acquire);
    if p.is_null() { ctx.set_return(SyscallReturn::invalid_op()); return; }
    // SAFETY: `install_global` published `p` via `Box::into_raw`; the
    // pointer is valid for the lifetime of the kernel (or until
    // `__test_clear_global` runs at a test boundary, with no
    // dispatch in flight). The table is read-only post-publication,
    // so a `&` borrow is safe even if a raw handler unwinds via
    // longjmp — no lock guard survives the call.
    let table: &SyscallTable = unsafe { &*p };
    table.dispatch_ctx(n, ctx);
}

/// Legacy plain entry retained for the existing
/// `smoke_userspace_syscall_dispatch_via_global` test and any
/// caller that has `SyscallArgs` in hand but not a `TrapContext`.
#[inline]
pub fn kernel_syscall_entry_plain(num: u32, args: &SyscallArgs) -> SyscallReturn {
    let n = match Syscall::from_raw(num) {
        Some(v) => v,
        None    => return SyscallReturn::invalid_op(),
    };
    let p = GLOBAL.load(Ordering::Acquire);
    if p.is_null() { return SyscallReturn::invalid_op(); }
    // SAFETY: see `kernel_syscall_entry`.
    let table: &SyscallTable = unsafe { &*p };
    table.dispatch(n, args).unwrap_or_else(SyscallReturn::invalid_op)
}

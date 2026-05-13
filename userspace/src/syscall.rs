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
    unsafe fn save_user_state(&self, _out: *mut u8) -> bool {
        false
    }

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
    fn deliver_signal(&mut self, _handler_vaddr: u64, _signum: u32) -> bool {
        false
    }

    /// Pop a SigContext frame at the user vaddr `sc_vaddr` (passed
    /// explicitly because the libc trampoline's intervening call
    /// frames shift RSP between deliver_signal and sigreturn) and
    /// restore the live trap context from it. Inverse of
    /// `deliver_signal`. Returns true if the restore succeeded;
    /// false if the arch hasn't implemented sigreturn (in which
    /// case `sys_sigreturn` surfaces InvalidOp).
    fn perform_sigreturn(&mut self, _sc_vaddr: u64) -> bool {
        false
    }

    /// Whether the trap is about to return to user mode. The
    /// signal-delivery hook only fires on user-bound returns;
    /// kernel-bound returns (e.g. from a `redirect_to_kernel`
    /// raw handler) skip delivery so we don't synthesize a
    /// signal frame onto a kernel stack. Default: `false`
    /// (treat as kernel-bound) so non-x86_64 arches without a
    /// CPL/EL accessor behave conservatively.
    fn returning_to_user(&self) -> bool {
        false
    }

    /// Rewrite the trap frame so the upcoming return lands in
    /// user mode at `entry_rip` with stack `entry_rsp`. Used by
    /// `execve` to discard the post-syscall continuation in the
    /// caller's old image and resume in the freshly-loaded
    /// program. Sets CS=UCODE, SS=UDATA, RFLAGS to a clean user-
    /// mode value (interrupts enabled, no flags set), and zeros
    /// the GPR file so the new program doesn't observe stale
    /// register values from the caller. Returns `true` when the
    /// arch supports the rewrite (x86_64 today); `false`
    /// elsewhere.
    fn redirect_to_user(&mut self, _entry_rip: u64, _entry_rsp: u64) -> bool {
        false
    }
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
    Submit = 100,

    /// Bootstrap: mint the per-task SQ+CQ and config-page caps.
    Bootstrap = 101,

    /// Block until a new completion arrives on the per-task CQ.
    WaitCompl = 102,

    /// Exit the current task. No completion is emitted; the
    /// scheduler drops the slot.
    ExitTask = 103,

    /// Yield the CPU. Returns when rescheduled.
    Yield = 104,

    /// Sleep for `arg0` nanoseconds.
    Sleep = 105,

    /// Open a file by path (zero-terminated string pointer in
    /// arg0). Returns a file descriptor on the per-task CQ.
    OpenFile = 110,

    /// Read `arg1` bytes from file `arg0` into buffer at `arg2`.
    Read = 111,

    /// Write `arg1` bytes to file `arg0` from buffer at `arg2`.
    Write = 112,

    /// Close file `arg0`.
    Close = 113,

    // ── Tier-2 fd-table breadth + VFS path resolution + pipe(2) ────
    //
    // Slots 114..=117 are reserved for the second wave of POSIX-shaped
    // fd surface that lands alongside `Open`'s absolute-path support.
    // Co-agent C uses disjoint numbers for cwd / signal / sleep work;
    // do not re-use these here without coordination.
    /// Stat by absolute path. `arg0 = path_ptr, arg1 = path_len,
    /// arg2 = stat_out_ptr`. Writes a NARF [`StatBuf`] (see
    /// `handlers::StatBuf`) to `*stat_out_ptr`. Returns 0 on success.
    Stat = 115,

    /// Stat by fd. `arg0 = fd, arg1 = stat_out_ptr`. Same shape as
    /// [`Stat`] otherwise.
    Fstat = 116,

    /// `arg0 = path_ptr, arg1 = path_len, arg2 = stat_out_ptr`.
    /// Linux lstat(2): like stat but doesn't follow the final
    /// symlink. NARF has no symlinks; this aliases sys_stat.
    Lstat = 133,

    /// Create a pipe pair. `arg0 = pipefd_out_ptr` — kernel writes
    /// two `i32`s (read fd, write fd) to that pointer. Returns 0
    /// on success.
    Pipe = 117,

    /// `arg0 = fd`, `arg1 = len` (u64). Resize the underlying file
    /// to exactly `len` bytes — zero-fill on grow, truncate on
    /// shrink. Returns 0 on success, -1 on read-only FS / bad fd.
    /// Touches the file directly via `FileOps::truncate`; no fd
    /// offset state is altered (POSIX: ftruncate doesn't move the
    /// per-fd cursor).
    Ftruncate = 118,

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = len`. Path-
    /// based truncate (POSIX truncate(2)). Resolves the absolute
    /// path and calls `FileOps::truncate` directly — no fd table
    /// involvement. Returns 0 on success, -1 on bad path / read-
    /// only FS.
    Truncate = 132,

    /// `arg0 = fd`, `arg1 = buf_ptr`, `arg2 = len`, `arg3 = offset`
    /// (u64). Read at the explicit offset without altering the
    /// per-fd cursor. Returns the byte count read on success
    /// (possibly short), -1 on bad fd / null buffer.
    Pread64 = 119,

    /// `arg0 = fd`, `arg1 = buf_ptr`, `arg2 = len`, `arg3 = offset`
    /// (u64). Write at the explicit offset without altering the
    /// per-fd cursor. Returns the byte count written on success.
    Pwrite64 = 122,

    /// `arg0 = fd`. Flush buffered writes for the file. NARF FSes
    /// are in-memory so this is a structural no-op that succeeds
    /// for any open fd, fails (-1) for an unknown fd. The entry
    /// exists so consumer code that error-checks fsync sees a sane
    /// return.
    Fsync = 123,

    /// `arg0 = fd`. Like Fsync but only metadata-omitted. Mapped
    /// to the same handler — the FS surface has no metadata-only
    /// flush distinction.
    Fdatasync = 124,

    /// `arg0 = fd`, `arg1 = mode`, `arg2 = offset`, `arg3 = len`
    /// (all u64). Linux fallocate(2): preallocate file space.
    /// Honoured modes: 0 (default — extend the file to at least
    /// offset + len bytes, zero-fill new tail) and FALLOC_FL_
    /// ZERO_RANGE = 0x10 (zero the given range without changing
    /// size unless extending). Returns 0 on success, -1 on bad fd
    /// or read-only FS.
    Fallocate = 126,

    /// `arg0 = fd_in`, `arg1 = fd_out`, `arg2 = off_in` (u64,
    /// `!0` = use cur), `arg3 = off_out` (u64, `!0` = use cur),
    /// `arg4 = len`, `arg5 = flags` (must be 0). Linux
    /// copy_file_range(2): in-kernel copy between two file
    /// descriptors. NARF executes a chunked read-then-write
    /// loop. Returns the byte count copied on success, -1 on
    /// bad fd / non-zero flags.
    CopyFileRange = 127,

    /// `arg0 = name_ptr`, `arg1 = name_len` (debug only),
    /// `arg2 = flags` (accepted-and-ignored). Linux
    /// memfd_create(2): create an unnamed in-memory file and
    /// install it in the calling task's fd table. Returns the
    /// new fd on success, -1 on bad input or fd-table exhaustion.
    /// The name is recorded only for debug introspection (no
    /// directory entry), matching the spec.
    MemfdCreate = 128,

    /// `arg0 = fd`, `arg1 = mode`. fchmod(2). NARF doesn't
    /// enforce permission bits; the call succeeds on a known fd
    /// (-1 on closed fd). Round-trip is structural.
    Fchmod = 129,

    /// `arg0 = fd`, `arg1 = uid`, `arg2 = gid`. fchown(2). Same
    /// accept-and-record semantics as fchmod.
    Fchown = 131,

    /// `arg0 = dirfd` (ignored — NARF has no directory-fd type),
    /// `arg1 = path_ptr`, `arg2 = path_len`, `arg3 = mode`,
    /// `arg4 = flags` (ignored). Linux fchmodat(2). The path
    /// must be absolute. Returns 0 on a reachable path, -1
    /// otherwise (consumer code error-checks the chmod return).
    Fchmodat = 134,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = uid`, `arg4 = gid`, `arg5 = flags`. fchownat(2).
    /// Same path-must-be-absolute simplification as fchmodat.
    Fchownat = 135,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = mode`, `arg4 = flags`. Linux faccessat(2).
    /// dirfd ignored; path must be absolute. Routes to the same
    /// existence probe as SYS_OPEN (open + close).
    Faccessat = 136,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = flags`, `arg4 = mode`. Linux openat(2).
    /// dirfd ignored; path must be absolute. Returns the new fd
    /// or `!0u64` on failure (matching SYS_OPEN's convention so
    /// the user-runtime wrapper distinguishes consistently).
    Openat = 137,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = stat_out_ptr`, `arg4 = flags`. Linux newfstatat(2)
    /// / fstatat(2). dirfd ignored; path must be absolute. Routes
    /// to the same handler as SYS_STAT.
    Newfstatat = 138,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = flags`. Linux unlinkat(2). dirfd ignored;
    /// AT_REMOVEDIR (0x200) flag routes to rmdir, otherwise to
    /// unlink. Returns 0 / -1.
    Unlinkat = 139,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = mode`. Linux mkdirat(2). dirfd ignored; routes
    /// through SYS_MKDIR.
    Mkdirat = 228,

    /// `arg0 = old_dirfd`, `arg1 = old_path_ptr`,
    /// `arg2 = old_path_len`, `arg3 = new_dirfd`,
    /// `arg4 = new_path_ptr`, `arg5 = new_path_len`. Linux
    /// renameat(2). Both dirfds ignored; both paths must be
    /// absolute.
    Renameat = 229,

    /// `arg0 = target_ptr`, `arg1 = target_len`, `arg2 = dirfd`,
    /// `arg3 = link_ptr`, `arg4 = link_len`. Linux symlinkat(2).
    /// dirfd ignored; link path must be absolute. Forwards to
    /// the SYS_SYMLINK body.
    Symlinkat = 230,

    /// `arg0 = dirfd`, `arg1 = path_ptr`, `arg2 = path_len`,
    /// `arg3 = buf_ptr`, `arg4 = buf_len`. Linux readlinkat(2).
    /// dirfd ignored; path must be absolute. Forwards to the
    /// SYS_READLINK body.
    Readlinkat = 231,

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = mode`. Linux
    /// access(2): legacy entry point that forwards to the
    /// faccessat body with `dirfd = AT_FDCWD`. Path must be
    /// absolute (NARF has no per-task cwd-relative resolution at
    /// the syscall layer). Returns 0 if the path resolves, -1
    /// otherwise.
    Access = 232,

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = mode`. Linux
    /// chmod(2): legacy entry point that forwards to the
    /// fchmodat body. Mode bits aren't enforced; we only verify
    /// the path resolves.
    Chmod = 233,

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = uid`,
    /// `arg3 = gid`. Linux chown(2): legacy entry point that
    /// forwards to the fchownat body. uid/gid aren't enforced;
    /// we only verify the path resolves.
    Chown = 234,

    /// `arg0 = pipefd_out_ptr`, `arg1 = flags`. Linux pipe2(2):
    /// pipe + atomic flag set. Honoured flag: O_CLOEXEC (bit
    /// 0x80000) — both ends get FD_CLOEXEC stamped at install
    /// time. O_NONBLOCK is accepted and ignored (NARF pipes have
    /// no blocking model worth toggling — read on an empty pipe
    /// already short-returns).
    Pipe2 = 125,

    /// Map memory: `arg0` addr hint, `arg1` length, `arg2` flags.
    Mmap = 120,

    /// Unmap memory.
    Munmap = 121,

    /// Change protection on a memory range. arg0 = base addr,
    /// arg1 = length in bytes, arg2 = POSIX-shape prot bitmask
    /// (1 = READ, 2 = WRITE, 4 = EXEC). Walks the calling AS's
    /// region table and rewrites every page's PTE in place via
    /// `AddressSpace::change_perms_range`. Returns Ok(0) on
    /// success, InvalidOp if no region intersects the requested
    /// range or the AS lookup failed.
    MProtect = 172,

    /// `mlock(addr, len)` — force-back every lazy (demand-paged)
    /// page in `[addr, addr + len)` and set the LOCKED flag so
    /// future swap/reclaim passes leave the region alone.
    /// arg0 = base addr, arg1 = length in bytes. Ok(0) on
    /// success, InvalidOp on no-region / OOM.
    MLock = 173,

    /// `munlock(addr, len)` — clear the LOCKED flag. Frames stay
    /// backed (no swap exists yet to reclaim them). arg0 = base
    /// addr, arg1 = length in bytes. Ok(0) on success, InvalidOp
    /// on no-region.
    MUnlock = 174,

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
    Execve = 179,

    /// `wait4(pid, &status, options, &rusage)` — block (or
    /// poll under WNOHANG) until a child of the calling task
    /// exits, then reap its exit status. arg0 = pid (signed —
    /// >0 specific child, -1 any), arg1 = status user-pointer
    /// (may be 0), arg2 = options bitmask (low bit = WNOHANG),
    /// arg3 = rusage user-pointer (zeroed; no per-process
    /// resource accounting yet). Returns the reaped child pid
    /// on success, 0 on WNOHANG with no exited child, InvalidOp
    /// on no-children / timeout.
    Wait4 = 181,

    /// `mount(source, target, fstype, flags, data)` — mount the
    /// filesystem named by `fstype` (a packed string like "fat" or
    /// "ext2") at the absolute path `target`, backed by the
    /// block-device path `source`. arg0 = source ptr, arg1 = source
    /// len, arg2 = target ptr, arg3 = target len, arg4 = packed
    /// (fstype_ptr<<32 | fstype_len). flags + data passed via the
    /// extended-args ABI. Returns 0 on success, !0u64 on failure
    /// (POSIX -1 + errno path; libc maps to errno).
    Mount = 182,

    /// `umount2(target, flags)` — unmount the filesystem mounted at
    /// the absolute path `target`. arg0 = target ptr, arg1 = target
    /// len, arg2 = flags (currently ignored — POSIX MNT_FORCE et al.
    /// land later). Returns 0 on success, !0u64 on failure.
    Umount2 = 183,

    /// `statfs(path, &buf)` — fill `buf` (struct statvfs-shaped) with
    /// stats about the filesystem covering `path`. arg0 = path ptr,
    /// arg1 = path len, arg2 = buf ptr (must point at a 64-byte
    /// region in user memory). Returns 0 on success, !0u64 on
    /// failure.
    Statfs = 184,

    /// `fstatfs(fd, &buf)` — same as `statfs` but addressed by an
    /// open fd. arg0 = fd, arg1 = buf ptr. Returns 0 / !0u64.
    Fstatfs = 185,

    /// `unshare(flags)` — POSIX 2008 / Linux unshare(2) shape. The
    /// only flag honoured today is CLONE_NEWNS (0x00020000): the
    /// calling task snapshots the global mount table into a private
    /// MountNamespace, after which its mount/umount calls only
    /// affect its own view. Other flags are accepted but ignored.
    /// Returns 0 on success, !0u64 on failure.
    Unshare = 186,

    /// `sigreturn()` — restore the calling task's user-mode trap
    /// context from a SigContext frame at the current RSP. Called
    /// from a libc-provided signal trampoline after the user's
    /// handler returns. Never returns through the syscall ABI; the
    /// handler instead resumes execution at the saved RIP with all
    /// GP registers, RSP, and RFLAGS restored to their pre-delivery
    /// values. Linux numbering is 15 (32-bit) / 313 (64-bit
    /// rt_sigreturn); we pick 187 to keep the recently-added range
    /// contiguous.
    Sigreturn = 187,

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
    /// (AF_UNIX = 1, AF_INET = 2, AF_INET6 = 10), arg1 = type
    /// (SOCK_STREAM = 1, SOCK_DGRAM = 2), arg2 = protocol (0 for
    /// the family default). Returns the new fd; -1 on failure.
    SocketOpen = 197,

    /// `bind(fd, addr, addrlen)`. arg0 = fd, arg1 = addr ptr,
    /// arg2 = addrlen. addr layout per `narf_socket::SockAddr`
    /// (family u16 + body bytes); libc translates POSIX
    /// sockaddr_in / sockaddr_un / sockaddr_in6 in/out.
    SocketBind = 198,

    /// `listen(fd, backlog)`. arg0 = fd, arg1 = backlog.
    SocketListen = 199,

    /// `accept(fd, addr_out, addrlen_out)` → fd. arg0 = listening
    /// fd, arg1 = addr_out (may be 0), arg2 = addrlen_out (may be
    /// 0). Blocks until a connection arrives; returns the new
    /// connected fd.
    SocketAccept = 201,

    /// `connect(fd, addr, addrlen)`. arg0 = fd, arg1 = addr ptr,
    /// arg2 = addrlen. Blocks until peer accepts (for SOCK_STREAM).
    SocketConnect = 202,

    /// `sendto(fd, buf, len, flags, addr, addrlen)`. The 6-arg
    /// shape covers both `send()` (addr=NULL, addrlen=0) and
    /// `sendto()`. arg0 = fd, arg1 = buf ptr, arg2 = len,
    /// arg3 = flags (POSIX MSG_*), arg4 = addr ptr, arg5 = addrlen.
    SocketSend = 203,

    /// `recvfrom(fd, buf, len, flags, addr_out, addrlen_out)`.
    /// Mirror of SocketSend. arg0 = fd, arg1 = buf, arg2 = len,
    /// arg3 = flags, arg4 = addr_out, arg5 = addrlen_out.
    SocketRecv = 204,

    /// `shutdown(fd, how)`. how: 0 = SHUT_RD, 1 = SHUT_WR,
    /// 2 = SHUT_RDWR.
    SocketShutdown = 205,

    /// `getsockopt(fd, level, opt, buf, len_out)`. arg0 = fd,
    /// arg1 = level, arg2 = optname, arg3 = buf ptr, arg4 = len
    /// in/out u32 ptr.
    SocketGetSockOpt = 206,

    /// `setsockopt(fd, level, opt, buf, len)`.
    SocketSetSockOpt = 207,

    /// ZC fast path: register a user buffer for zerocopy I/O.
    /// `register_buffer(ptr, len) → buf_id`. The kernel pins the
    /// pages and assigns an opaque id usable in `SockSendZc`.
    /// Lifetime: until `unregister_buffer` (not yet wired) or task
    /// exit. arg0 = ptr, arg1 = len. Returns buf_id (u32) or -1.
    SockRegisterBuf = 208,

    /// ZC fast path: send a registered buffer slice.
    /// `send_zc(fd, buf_id, off, len, flags)`. arg0 = fd,
    /// arg1 = buf_id, arg2 = offset within buffer, arg3 = byte
    /// length, arg4 = flags. The user must not modify the buffer
    /// region until completion fires through the per-task
    /// completion ring (today: completion is synchronous —
    /// completion-ring delivery lands when the kernel-side NIC
    /// path goes async).
    SockSendZc = 209,

    /// Open an FB connection to a scanout. `arg0` = scanout id (0
    /// for the active scanout). Returns a non-zero `FbHandleId` on
    /// success, 0 on failure (no backend / OOM / not authorised).
    /// Auto-closed on process exit.
    FbConnect = 240,

    /// Query the connected scanout's geometry + format. `arg0` =
    /// `FbHandleId`, `arg1` = userspace pointer to a 24-byte
    /// `FbInfo` (`{u32 width, height, stride, format, scanout_id, _resv}`).
    /// Returns 0 on success, !0 on bad handle / bad pointer.
    FbInfo = 241,

    /// Map the connection's draw-ring into the caller's VA. `arg0`
    /// = `FbHandleId`. Returns the user VA (4 KiB region) or 0 on
    /// failure. The mapping is RW; userspace constructs a
    /// `SharedProducer<DrawCmd>` over it.
    FbRingMap = 242,

    /// Block (or report) until the kernel drain task has consumed
    /// at least one command past the caller's prior wait point.
    /// `arg0` = `FbHandleId`. Returns the current drain count
    /// snapshot. Today this is non-blocking — it returns immediately
    /// — but the contract leaves room for vsync / backpressure
    /// blocking once the scheduler-aware drain lands.
    FbFlushWait = 243,

    /// Tear down a connection. `arg0` = `FbHandleId`. Frees the
    /// ring, removes the mapping, and reaps the kernel-side
    /// consumer. Returns 0 on success, !0 on bad handle. Also
    /// auto-called on process exit; explicit calls are for
    /// graceful shutdown.
    FbDisconnect = 244,

    /// Allocate a fresh shared-memory region. `arg0` = byte length
    /// (rounded up to a page). Returns a non-zero `ShmemHandleId`
    /// on success, 0 on OOM / oversize / no kernel support. The
    /// region is page-aligned, zero-filled, and owned by the
    /// calling process; auto-reaped on exit.
    ShmemCreate = 250,

    /// Map a shmem region into the caller's VA. `arg0` =
    /// `ShmemHandleId`. Returns the user VA (page-aligned) or 0 on
    /// failure (bad handle, foreign owner, OOM). The mapping is RW
    /// and contiguous in VA even though the backing frames are
    /// scattered.
    ShmemMap = 251,

    /// Tear down a shmem region. `arg0` = `ShmemHandleId`. The
    /// userspace mapping stays installed for now (page-table
    /// teardown lands when shmem grows a `Drop` path that walks
    /// + unmaps the user VA range). Returns 0 on success, !0 on
    /// bad handle / not-owner.
    ShmemDestroy = 252,

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
    FirmwareInstall = 260,

    /// Kick the kernel-side dispatcher to drain the calling task's
    /// shared SubmissionRing and post Completions to the shared
    /// CompletionRing. Returns the number of submissions processed.
    RingKick = 130,

    /// Return the calling task's monotonic id. POSIX-shaped surface
    /// for relibc's `getpid()` / `gettid()` (we don't yet
    /// distinguish PID from TID — single-thread-per-process at
    /// Stage 4).
    GetPid = 140,
    /// Return the calling task's parent id, or 0 if none. Stage 4
    /// stub: returns 0 unconditionally; real ppid lands once the
    /// scheduler tracks parentage.
    GetPpid = 141,

    /// POSIX-shaped uid/gid query. NARF's authority model is
    /// capabilities; the per-task uid/gid table is structural
    /// state only (no security implication). Default identity
    /// is (0, 0); `SetUid` / `SetGid` mutate it.
    GetUid = 142,
    GetGid = 143,

    /// Set the calling task's uid (`arg0`) / gid (`arg0`). Both
    /// always succeed and return 0; capabilities still gate every
    /// privileged operation.
    SetUid = 144,
    SetGid = 145,

    /// `arg0 = pid` (0 = self). Linux getpgid(2): return the
    /// process-group id of `pid`. NARF tracks pgids per-task in
    /// a structural BTreeMap (no actual session/process-group
    /// scheduling). Default pgid = pid (each task is its own
    /// group leader). Returns the pgid on success, -1 on
    /// unknown pid.
    Getpgid = 224,

    /// `arg0 = pid` (0 = self), `arg1 = pgid` (0 = use pid).
    /// Linux setpgid(2): record the new pgid for the target
    /// task. Always succeeds.
    Setpgid = 225,

    /// `arg0 = pid` (0 = self). POSIX getsid(2): return the
    /// session id of `pid`. NARF tracks sids per-task in a
    /// structural BTreeMap; default sid = pid.
    Getsid = 226,

    /// No args. POSIX setsid(2): the calling task creates a new
    /// session with itself as the leader. Records sid = pid +
    /// pgid = pid in their respective tables; returns pid.
    Setsid = 227,

    /// `arg0 = buf_ptr`, `arg1 = buf_len`. Copy the kernel-wide
    /// hostname (NUL-terminated UTF-8) into the user buffer.
    /// Returns the byte length excluding the NUL on success, -1 on
    /// `buf_len < name_len + 1`.
    GetHostname = 146,

    /// `arg0 = buf_ptr`, `arg1 = buf_len`. Replace the kernel-wide
    /// hostname with the supplied bytes. Stage-4 simplification:
    /// any task can set the hostname (no cap gate yet — landing
    /// alongside the cap-table integration). Returns 0 on success,
    /// -1 on rejection (length cap, malformed UTF-8).
    SetHostname = 147,

    /// `arg0 = resource` (POSIX RLIMIT_*), `arg1 = rlimit_out_ptr`.
    /// Write the current task's `rlimit { cur, max }` pair into the
    /// user buffer. Returns 0 on success, -1 on bad pointer / out-
    /// of-range resource. NARF tracks rlimits as structural state
    /// only — capabilities still gate every privileged operation.
    Getrlimit = 148,

    /// `arg0 = resource`, `arg1 = rlimit_in_ptr`. Update the
    /// current task's `rlimit` for `resource`. Returns 0 on
    /// success, -1 on rejection.
    Setrlimit = 149,

    /// `arg0 = pid` (0 = self), `arg1 = resource`,
    /// `arg2 = new_in_ptr`, `arg3 = old_out_ptr`. Linux
    /// prlimit64(2): combined get-and-set. If `new` is non-null,
    /// write the [cur, max] pair. If `old` is non-null, return
    /// the prior value into it. Both null is a no-op-success.
    /// Returns 0 on success, -1 on bad pointer / out-of-range.
    Prlimit64 = 178,

    /// `arg0 = which` (PRIO_PROCESS=0 only honoured), `arg1 = who`
    /// (0 = self). Returns the current task's nice value (-20..=19),
    /// shifted by +20 so the wire value is 0..=39 (matches Linux's
    /// pre-shift convention so user code can subtract 20 without
    /// caring about negatives crossing the wire). -1 on bad which.
    Getpriority = 156,

    /// `arg0 = which`, `arg1 = who`, `arg2 = prio` (-20..=19,
    /// already user-side). Stores the new nice value. Returns 0
    /// on success, -1 on bad which / out-of-range prio.
    Setpriority = 157,

    /// `arg0 = tms_out_ptr`. POSIX times(2): write the calling
    /// task's `struct tms { i64 utime, stime, cutime, cstime }`
    /// (in CLK_TCK = 100Hz ticks) and return the elapsed wall-
    /// clock ticks since boot. NARF doesn't track per-task
    /// user/system splits yet — `utime` synthesises to monotonic
    /// ticks, `stime` and child fields are zero — but the surface
    /// round-trips so `clock(3)` and `time(1)`-shaped consumers
    /// see a calibratable wall clock.
    Times = 158,

    /// `arg0 = who` (RUSAGE_SELF=0; RUSAGE_CHILDREN=-1 returns
    /// zeroed struct), `arg1 = rusage_out_ptr`. Writes the
    /// glibc-shaped 16-i64 rusage struct: ru_utime.tv_sec /
    /// ru_utime.tv_usec from monotonic_ns, every other field
    /// zero. Returns 0 on success, -1 on bad pointer.
    Getrusage = 159,

    /// `arg0 = new_mask` (only the low 9 bits — POSIX 0o777). Sets
    /// the calling task's file-creation mask and returns the
    /// previous value. Stage-4 simplification: NARF doesn't yet
    /// enforce mode bits at file creation, so the mask is
    /// structural state — but the round-trip lets `umask(0o077)`
    /// followed by `umask(0o022)` see the prior value, which is
    /// what consumer init code expects.
    Umask = 155,

    /// `arg0 = cpu_out_ptr`, `arg1 = node_out_ptr`. Linux getcpu(2):
    /// write the calling CPU id + NUMA node id to the supplied
    /// out-pointers (each may be null). NARF user mode is
    /// single-CPU today — both return 0. Returns 0 on success.
    Getcpu = 165,

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

    /// `arg0 = policy`. Linux sched_get_priority_max(2): return
    /// the maximum valid `sched_priority` for `policy`.
    /// SCHED_OTHER (0) / SCHED_BATCH (3) / SCHED_IDLE (5) → 0;
    /// SCHED_FIFO (1) / SCHED_RR (2) → 99. Bad policy → -1.
    SchedGetPriorityMax = 220,

    /// `arg0 = policy`. sched_get_priority_min(2). Mirrors max
    /// with the inverse: 0 / 1 / -1 by policy.
    SchedGetPriorityMin = 221,

    /// `arg0 = pid` (0 = self), `arg1 = sched_param_out_ptr`.
    /// Linux sched_getparam(2): write a single-field
    /// `struct sched_param { int sched_priority }` (POSIX).
    /// Returns 0 on success, -1 on bad pointer.
    SchedGetparam = 222,

    /// `arg0 = pid`, `arg1 = sched_param_in_ptr`. Read the
    /// `sched_priority` field, store on the task. Returns 0.
    SchedSetparam = 223,

    /// Linux gettid(2): return the calling thread's distinct kernel
    /// task id. With `Clone` (56) wired, multi-threaded processes
    /// observe distinct tids per thread; the value is the
    /// scheduler's `TaskId.raw()` for the running task.
    Gettid = 168,

    /// Linux clone(2) — minimal viable thread spawn. NARF doesn't
    /// implement the full `flags / ptid / ctid / tls` surface;
    /// instead it takes a four-argument shape that creates one new
    /// task sharing the caller's address space:
    ///
    /// - `arg0 = entry_pc`  : user vaddr the new task starts at
    /// - `arg1 = stack_top` : user RSP the new task starts on
    ///                        (caller-allocated; kernel does NOT
    ///                        validate that the page is mapped)
    /// - `arg2 = arg`       : opaque u64 passed in RDI to `entry_pc`
    /// - `arg3 = fs_base`   : if non-zero, value the kernel writes
    ///                        into the new task's `IA32_FS_BASE` so
    ///                        it can find its own TLS block. Zero
    ///                        means "inherit parent's fs_base"
    ///                        (suitable for child code that does
    ///                        not touch TLS).
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
    Clone = 56,

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
    ///                      Arcs via Arc::clone)
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
    Fork = 57,

    /// Linux tkill(2) / tgkill(2): like kill but targets a specific
    /// thread within a process group. NARF is single-threaded per
    /// process — tgkill aliases sys_kill. `arg0 = tgid` (-1 = any),
    /// `arg1 = tid`, `arg2 = signum`. Returns 0 on success.
    Tgkill = 175,

    /// Linux futex(2) minimal scaffold. `arg0 = uaddr_ptr`,
    /// `arg1 = op`, `arg2 = val`, `arg3 = timeout/uaddr2`,
    /// `arg4 = val3`. Honoured ops:
    ///   - FUTEX_WAIT (0): if `*uaddr == val`, would block. NARF
    ///                     is single-threaded so no other task can
    ///                     wake us — we return 0 (spurious wakeup
    ///                     allowed by spec) so consumer code falls
    ///                     into its loop.
    ///   - FUTEX_WAKE (1): would wake up to `val` waiters; we have
    ///                     none, so return 0.
    ///   - FUTEX_PRIVATE (0x80) and FUTEX_CLOCK_REALTIME (0x100)
    ///                     bits are accepted-and-ignored.
    /// Other ops return -1.
    Futex = 177,

    /// Linux prctl(2): per-task settings switchboard. `arg0 = op`,
    /// `arg1 = argA`, `arg2 = argB`. Honoured ops:
    ///   - PR_SET_NAME  (15): argA = pointer to up-to-15-byte
    ///                        UTF-8 name; bytes copied into the
    ///                        kernel-side name slot, NUL-padded
    ///                        to 16. Returns 0.
    ///   - PR_GET_NAME  (16): argA = writable 16-byte buffer;
    ///                        kernel writes the recorded name +
    ///                        NUL. Returns 0.
    ///   - PR_SET_DUMPABLE (4) / PR_GET_DUMPABLE (3): round-trip
    ///                        the boolean.
    ///   - PR_SET_NO_NEW_PRIVS (38) / PR_GET_NO_NEW_PRIVS (39):
    ///                        round-trip the boolean.
    /// Everything else returns -1.
    Prctl = 169,

    /// Set or query the per-task heap break.
    /// `arg0 = 0` → return current break; `arg0 != 0` → resize.
    /// POSIX `brk(2)` semantics: failure returns the unchanged break.
    Brk = 150,

    /// Write monotonic time to the user buffer at `arg1` for clock id
    /// `arg0`. Buffer is `struct timespec { tv_sec: i64, tv_nsec: i64 }`.
    /// Returns 0 on success.
    ClockGetTime = 151,

    /// `arg0 = clock_id`, `arg1 = timespec_ptr` (read). Linux
    /// clock_settime(2): set the wall clock for CLOCK_REALTIME
    /// (clock_id = 0). NARF computes the monotonic→wall offset
    /// from the requested wall + current monotonic, then stores
    /// it via `time::set_wall_offset_uncapped`. Other clock_ids
    /// (CLOCK_MONOTONIC = 1, CLOCK_BOOTTIME = 7, ...) return -1.
    ClockSetTime = 176,

    /// Install a signal-handler stub. `arg0 = signum`,
    /// `arg1 = handler-vaddr` (0 to clear), `arg2 = old-out-ptr`
    /// (may be null). The recorded handler is fired on the
    /// trap-return path of any subsequent int-0x80 from this
    /// task that observes a pending signal; see `Kill` /
    /// `Sigprocmask`. Returns 0.
    Sigaction = 152,

    /// Mark `signum` pending on the task identified by
    /// `arg0 = target_pid`. `arg1 = signum`. Returns 0; the
    /// signal is delivered the next time the target task
    /// returns to user mode through the int-0x80 / svc-0 trap
    /// gate (see `handlers::deliver_pending_signals`). Stage-4
    /// stub: any task can signal any other; cap-gating lands
    /// later.
    Kill = 153,

    /// Update the calling task's signal-block mask.
    /// `arg0 = how` (0 = BLOCK, 1 = UNBLOCK, 2 = SETMASK),
    /// `arg1 = set` (32-bit bitmap). Returns the **previous**
    /// mask in the syscall return value.
    Sigprocmask = 154,

    // ── Dup family + fcntl ────────────────────────────────────────
    //
    // Slots 160..=163 are the second-wave fd-control surface real
    // libc programs reach for. POSIX `dup`/`dup2`/`dup3`/`fcntl`.
    // Numbers chosen above the signal block (152..=154) so signal
    // and dup work can land independently without renumbering.
    /// Duplicate `arg0 = oldfd` into the lowest free slot ≥ 3.
    /// Returns the new fd in the syscall return value.
    Dup = 160,

    /// Duplicate `arg0 = oldfd` to `arg1 = newfd`. Closes `newfd`
    /// first if it's open. Returns `newfd`.
    Dup2 = 161,

    /// Like `Dup2` but `arg2 = flags` controls `FD_CLOEXEC` on the
    /// duplicate. `dup3(fd, fd, 0)` is an error (per Linux); use
    /// `Dup2` for the same-fd no-op.
    Dup3 = 162,

    /// `arg0 = fd, arg1 = cmd, arg2 = arg`. Supported commands:
    /// F_GETFD / F_SETFD / F_GETFL / F_SETFL.
    Fcntl = 163,

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
    Chdir = 170,

    /// Copy the calling task's current working directory into the
    /// caller's buffer. `arg0 = buf_ptr`, `arg1 = buf_len`. The
    /// kernel writes a NUL-terminated UTF-8 string; the return
    /// value is the byte length **excluding** the terminator. If
    /// `buf_len < cwd.len() + 1` the call returns `InvalidOp` —
    /// a real libc translates that to ERANGE; the syscall return
    /// shape doesn't yet carry an errno channel.
    Getcwd = 171,

    // ── Tier-2.5 fd extensions ─────────────────────────────────────
    //
    // Slots 164/180 reserved for `lseek(2)` and `unlink(2)`. Numbers
    // chosen to leave the dup family + cwd block contiguous and to
    // give unlink room for a follow-on `rename(2)` at 181.
    /// `arg0 = fd`, `arg1 = offset (i64)`, `arg2 = whence`
    /// (0 = SEEK_SET, 1 = SEEK_CUR, 2 = SEEK_END). Updates the
    /// per-fd offset and returns the new value as the syscall's
    /// `value`. `InvalidOp` on out-of-range fd or negative result.
    Lseek = 164,

    /// `arg0 = path_ptr`, `arg1 = path_len`. Removes a file from the
    /// VFS via `DirOps::unlink` on the parent directory. Returns
    /// `value = 0` on success and `value = -1` on failure (the user-
    /// runtime asm wrapper observes only the value register, not the
    /// status word, so the value channel must distinguish).
    Unlink = 180,

    // ── Tier-3b directory mutation ─────────────────────────────────
    //
    // mkdir / rmdir / rename. Each routes through
    // `VfsRegistry::resolve_parent_absolute` and dispatches on the
    // parent `DirOps`. The default trait impls for FSes that don't
    // implement these return `Unsupported`; the handler then
    // surfaces `value = -1`. POSIX-shaped 0/-1 return convention.
    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = mode (ignored)`.
    /// Creates an empty subdirectory at the absolute path's leaf.
    Mkdir = 190,

    /// `arg0 = path_ptr`, `arg1 = path_len`. Removes an empty
    /// subdirectory.
    Rmdir = 191,

    /// `arg0 = old_path_ptr`, `arg1 = old_path_len`,
    /// `arg2 = new_path_ptr`, `arg3 = new_path_len`. Cross-
    /// directory rename is unsupported today; both paths must
    /// resolve to the same parent directory or the syscall returns
    /// failure.
    Rename = 192,

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = buf_ptr`,
    /// `arg3 = buf_len`. Path-based symlink read / create over MemFs
    /// symlink entries. Resolves `path` via `resolve_parent_absolute`,
    /// checks the leaf's `FileType::Symlink`, and copies up to
    /// `buf_len` target-bytes into the caller's buffer. Returns the
    /// byte count on success; -1 if the path doesn't resolve, the
    /// entry isn't a symlink, or the user pointers are bad.
    Readlink = 193,

    /// `arg0 = target_ptr`, `arg1 = target_len`, `arg2 = link_ptr`,
    /// `arg3 = link_len`. Path-based symlink read / create over MemFs
    /// symlink entries. Resolves `link_path`'s parent and inserts an
    /// `Entry::Symlink` whose target is the verbatim `target` string.
    /// Returns 0 on success, -1 on duplicate or bad input.
    Symlink = 194,

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
    Listdir = 195,

    /// `arg0 = path_ptr`, `arg1 = path_len`, `arg2 = cursor`,
    /// `arg3 = out_buf_ptr`, `arg4 = out_buf_len`. Batched
    /// directory read: serialise as many entries as fit into the
    /// caller's buffer in the Linux `linux_dirent64` wire format
    /// `{ d_ino: u64, d_off: u64, d_reclen: u16, d_type: u8, d_name }`.
    /// Each record is padded to 8-byte alignment. Returns the total
    /// bytes written on success, 0 on end-of-directory, -1 on error.
    Getdents64 = 196,

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
    GetRandom = 200,
}

impl Syscall {
    /// Raw wire number.
    #[inline]
    pub const fn raw(self) -> u32 {
        self as u32
    }

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
            126 => Syscall::Fallocate,
            127 => Syscall::CopyFileRange,
            128 => Syscall::MemfdCreate,
            129 => Syscall::Fchmod,
            131 => Syscall::Fchown,
            132 => Syscall::Truncate,
            133 => Syscall::Lstat,
            134 => Syscall::Fchmodat,
            135 => Syscall::Fchownat,
            136 => Syscall::Faccessat,
            137 => Syscall::Openat,
            138 => Syscall::Newfstatat,
            139 => Syscall::Unlinkat,
            228 => Syscall::Mkdirat,
            229 => Syscall::Renameat,
            230 => Syscall::Symlinkat,
            231 => Syscall::Readlinkat,
            232 => Syscall::Access,
            233 => Syscall::Chmod,
            234 => Syscall::Chown,
            120 => Syscall::Mmap,
            121 => Syscall::Munmap,
            172 => Syscall::MProtect,
            173 => Syscall::MLock,
            174 => Syscall::MUnlock,
            179 => Syscall::Execve,
            181 => Syscall::Wait4,
            182 => Syscall::Mount,
            183 => Syscall::Umount2,
            184 => Syscall::Statfs,
            185 => Syscall::Fstatfs,
            186 => Syscall::Unshare,
            187 => Syscall::Sigreturn,
            197 => Syscall::SocketOpen,
            198 => Syscall::SocketBind,
            199 => Syscall::SocketListen,
            201 => Syscall::SocketAccept,
            202 => Syscall::SocketConnect,
            203 => Syscall::SocketSend,
            204 => Syscall::SocketRecv,
            205 => Syscall::SocketShutdown,
            206 => Syscall::SocketGetSockOpt,
            207 => Syscall::SocketSetSockOpt,
            208 => Syscall::SockRegisterBuf,
            209 => Syscall::SockSendZc,
            130 => Syscall::RingKick,
            140 => Syscall::GetPid,
            141 => Syscall::GetPpid,
            142 => Syscall::GetUid,
            143 => Syscall::GetGid,
            144 => Syscall::SetUid,
            145 => Syscall::SetGid,
            224 => Syscall::Getpgid,
            225 => Syscall::Setpgid,
            226 => Syscall::Getsid,
            227 => Syscall::Setsid,
            146 => Syscall::GetHostname,
            147 => Syscall::SetHostname,
            148 => Syscall::Getrlimit,
            149 => Syscall::Setrlimit,
            155 => Syscall::Umask,
            165 => Syscall::Getcpu,
            166 => Syscall::SchedGetaffinity,
            167 => Syscall::SchedSetaffinity,
            220 => Syscall::SchedGetPriorityMax,
            221 => Syscall::SchedGetPriorityMin,
            222 => Syscall::SchedGetparam,
            223 => Syscall::SchedSetparam,
            56 => Syscall::Clone,
            57 => Syscall::Fork,
            168 => Syscall::Gettid,
            169 => Syscall::Prctl,
            175 => Syscall::Tgkill,
            177 => Syscall::Futex,
            178 => Syscall::Prlimit64,
            176 => Syscall::ClockSetTime,
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
            196 => Syscall::Getdents64,
            200 => Syscall::GetRandom,
            240 => Syscall::FbConnect,
            241 => Syscall::FbInfo,
            242 => Syscall::FbRingMap,
            243 => Syscall::FbFlushWait,
            244 => Syscall::FbDisconnect,
            250 => Syscall::ShmemCreate,
            251 => Syscall::ShmemMap,
            252 => Syscall::ShmemDestroy,
            260 => Syscall::FirmwareInstall,
            _ => return None,
        })
    }
}

// ── Args + Return ───────────────────────────────────────────────────

/// Syscall arguments in register-passing order. Six arguments
/// matches the x86_64 syscall convention (rdi/rsi/rdx/r10/r8/r9)
/// and is wide enough for aarch64 (x0..=x5).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SyscallArgs {
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
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
    pub value: u64,
}

impl SyscallReturn {
    pub const OK: u32 = 0;
    pub const INVALID_OP: u32 = 1;

    #[inline]
    pub const fn ok(value: u64) -> Self {
        Self {
            status: Self::OK,
            value,
        }
    }

    #[inline]
    pub const fn invalid_op() -> Self {
        Self {
            status: Self::INVALID_OP,
            value: 0,
        }
    }
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
where
    F: Fn(&SyscallArgs) -> SyscallReturn + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FnHandler").finish_non_exhaustive()
    }
}

impl<F> SyscallHandler for FnHandler<F>
where
    F: Fn(&SyscallArgs) -> SyscallReturn + Send + Sync + 'static,
{
    fn invoke(&self, args: &SyscallArgs) -> SyscallReturn {
        (self.0)(args)
    }
}

/// One table slot: the diagnostic name + zero/one handler of each
/// kind. Raw handler wins when both are installed.
///
/// **Versioning.** The Linux "don't break userspace" principle is
/// load-bearing once a syscall lands in narf-libc. To extend
/// semantics without minting a new number, callers can pack a
/// version into the **upper 8 bits** of the 32-bit syscall number
/// (see `SYS_VERSION_SHIFT`). Version 0 is the canonical wire ABI;
/// versions 1..255 land as overrides in `versioned`. Old binaries
/// always encode `version=0` implicitly, so they keep dispatching
/// to the v0 handler forever even after a v1 override is added.
pub struct SyscallEntry {
    pub number: Syscall,
    pub name: &'static str,
    pub handler: Option<Box<dyn SyscallHandler>>,
    pub raw_handler: Option<Box<dyn RawSyscallHandler>>,
    /// `(version, raw_handler)` pairs for non-zero versions. Probed
    /// before falling through to `raw_handler` / `handler`.
    pub versioned: Vec<(u8, Box<dyn RawSyscallHandler>)>,
}

impl core::fmt::Debug for SyscallEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SyscallEntry")
            .field("number", &self.number)
            .field("name", &self.name)
            .field("has_handler", &self.handler.is_some())
            .field("has_raw", &self.raw_handler.is_some())
            .field("versions", &self.versioned.len())
            .finish()
    }
}

// ── Syscall versioning ──────────────────────────────────────────────
//
// Wire format: the bottom 24 bits of the u32 syscall number are the
// canonical syscall id (room for 16M numbers — far past the ~234 we
// have). The top 8 bits are a version field. Userspace that knows
// nothing about versions encodes 0 implicitly — the upper bits stay
// zero — so it always reaches the canonical v0 handler.
//
// Adding a v1 of an existing syscall is a `install_raw_versioned`
// call in the kernel + a recompile of the libc that wants to use it
// with `(1 << SYS_VERSION_SHIFT) | SYS_FOO` at the call site. The v0
// handler stays alive for old binaries indefinitely.

/// Bit shift for the version field in a raw syscall number.
pub const SYS_VERSION_SHIFT: u32 = 24;
/// Mask isolating the version field.
pub const SYS_VERSION_MASK: u32 = 0xFF00_0000;
/// Mask isolating the canonical syscall number (low 24 bits).
pub const SYS_NUMBER_MASK: u32 = 0x00FF_FFFF;

/// Pull the version (0..=255) out of a raw syscall number.
#[inline]
pub const fn syscall_version(raw: u32) -> u8 {
    ((raw & SYS_VERSION_MASK) >> SYS_VERSION_SHIFT) as u8
}

/// Pull the canonical syscall number out of a raw syscall number.
#[inline]
pub const fn syscall_number(raw: u32) -> u32 {
    raw & SYS_NUMBER_MASK
}

/// Pack a `(version, syscall)` pair into the wire-format u32.
#[inline]
pub const fn syscall_pack(version: u8, n: Syscall) -> u32 {
    ((version as u32) << SYS_VERSION_SHIFT) | (n.raw() & SYS_NUMBER_MASK)
}

/// In-kernel syscall table. Constructed at boot, handed to
/// `install_global` once every subsystem has registered.
#[derive(Debug)]
pub struct SyscallTable {
    entries: Vec<SyscallEntry>,
}

impl SyscallTable {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Register a diagnostic name against a syscall number (no
    /// handler body). Useful when a subsystem wants the name to
    /// show up in tracing while implementation is pending.
    pub fn register(&mut self, n: Syscall, name: &'static str) {
        self.entries.push(SyscallEntry {
            number: n,
            name,
            handler: None,
            raw_handler: None,
            versioned: Vec::new(),
        });
    }

    /// Register a live plain handler for `n`. Replaces any prior
    /// plain handler for the same number so Stage-4 subsystems can
    /// take over stubs landed earlier. A raw handler registered
    /// separately still wins on dispatch.
    pub fn install<H: SyscallHandler + 'static>(
        &mut self,
        n: Syscall,
        name: &'static str,
        handler: H,
    ) {
        self.install_slot(
            n,
            name,
            Some(Box::new(handler) as Box<dyn SyscallHandler>),
            None,
        );
    }

    /// Register a raw handler for `n`. A raw handler receives the
    /// full `TrapContext` (args + return setter + redirect-to-
    /// kernel) and is chosen over a plain handler when both are
    /// installed.
    pub fn install_raw<H: RawSyscallHandler + 'static>(
        &mut self,
        n: Syscall,
        name: &'static str,
        handler: H,
    ) {
        self.install_slot(
            n,
            name,
            None,
            Some(Box::new(handler) as Box<dyn RawSyscallHandler>),
        );
    }

    fn install_slot(
        &mut self,
        n: Syscall,
        name: &'static str,
        plain: Option<Box<dyn SyscallHandler>>,
        raw: Option<Box<dyn RawSyscallHandler>>,
    ) {
        if let Some(slot) = self.entries.iter_mut().find(|e| e.number == n) {
            slot.name = name;
            if plain.is_some() {
                slot.handler = plain;
            }
            if raw.is_some() {
                slot.raw_handler = raw;
            }
        } else {
            self.entries.push(SyscallEntry {
                number: n,
                name,
                handler: plain,
                raw_handler: raw,
                versioned: Vec::new(),
            });
        }
    }

    /// Register a raw handler for `(syscall, version)`. `version=0`
    /// is reserved for the canonical wire ABI — register that with
    /// `install_raw` instead. Re-registering the same `(n, version)`
    /// pair replaces the prior handler.
    pub fn install_raw_versioned<H: RawSyscallHandler + 'static>(
        &mut self,
        n: Syscall,
        version: u8,
        handler: H,
    ) {
        assert!(
            version != 0,
            "version=0 is the canonical ABI; use install_raw"
        );
        let boxed = Box::new(handler) as Box<dyn RawSyscallHandler>;
        let slot = if let Some(s) = self.entries.iter_mut().find(|e| e.number == n) {
            s
        } else {
            self.entries.push(SyscallEntry {
                number: n,
                name: "<versioned-only>",
                handler: None,
                raw_handler: None,
                versioned: Vec::new(),
            });
            self.entries.last_mut().expect("just pushed")
        };
        if let Some(pos) = slot.versioned.iter().position(|(v, _)| *v == version) {
            slot.versioned[pos] = (version, boxed);
        } else {
            slot.versioned.push((version, boxed));
        }
    }

    /// Shorthand: install a closure as a plain handler.
    pub fn install_fn<F>(&mut self, n: Syscall, name: &'static str, f: F)
    where
        F: Fn(&SyscallArgs) -> SyscallReturn + Send + Sync + 'static,
    {
        self.install(n, name, FnHandler(f));
    }

    /// Shorthand: install a closure as a raw handler.
    pub fn install_raw_fn<F>(&mut self, n: Syscall, name: &'static str, f: F)
    where
        F: Fn(&mut dyn TrapContext) + Send + Sync + 'static,
    {
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

    /// Raw-aware dispatch (canonical, version=0). If a raw handler is
    /// installed, call it with `ctx` (it's responsible for
    /// `set_return` / `redirect_to_kernel`). Otherwise fall back to
    /// the plain handler. Absence of both means
    /// `SyscallReturn::invalid_op`.
    pub fn dispatch_ctx(&self, n: Syscall, ctx: &mut dyn TrapContext) {
        self.dispatch_ctx_versioned(n, 0, ctx)
    }

    /// Raw-aware dispatch with a version. Lookup order:
    /// 1. If `version != 0` and the slot has a matching versioned
    ///    handler, invoke it.
    /// 2. Else fall through to the v0 raw handler.
    /// 3. Else fall through to the v0 plain handler.
    /// 4. Else `SyscallReturn::invalid_op`.
    ///
    /// This makes a v1 caller of an as-yet-unversioned syscall fall
    /// back to v0 transparently — the right answer when v0 is the
    /// canonical wire ABI.
    pub fn dispatch_ctx_versioned(&self, n: Syscall, version: u8, ctx: &mut dyn TrapContext) {
        if let Some(slot) = self.entries.iter().find(|e| e.number == n) {
            if version != 0 {
                if let Some((_, h)) = slot.versioned.iter().find(|(v, _)| *v == version) {
                    h.invoke(ctx);
                    return;
                }
                // Versioned handler not installed; fall through to v0.
            }
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

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Closure-backed raw handler shim.
pub struct RawFnHandler<F: Fn(&mut dyn TrapContext) + Send + Sync + 'static>(pub F);

impl<F> core::fmt::Debug for RawFnHandler<F>
where
    F: Fn(&mut dyn TrapContext) + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RawFnHandler").finish_non_exhaustive()
    }
}

impl<F> RawSyscallHandler for RawFnHandler<F>
where
    F: Fn(&mut dyn TrapContext) + Send + Sync + 'static,
{
    fn invoke(&self, ctx: &mut dyn TrapContext) {
        (self.0)(ctx);
    }
}

impl Default for SyscallTable {
    fn default() -> Self {
        Self::new()
    }
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
        unsafe {
            drop(Box::from_raw(prev));
        }
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
    // Split `num` into version (top 8 bits) + canonical syscall
    // number (low 24 bits). v0 callers encode 0 in the upper bits
    // implicitly, so pre-versioning binaries dispatch to v0 forever.
    let version = syscall_version(num);
    let raw_n = syscall_number(num);
    let n = match Syscall::from_raw(raw_n) {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let p = GLOBAL.load(Ordering::Acquire);
    if p.is_null() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // SAFETY: `install_global` published `p` via `Box::into_raw`; the
    // pointer is valid for the lifetime of the kernel (or until
    // `__test_clear_global` runs at a test boundary, with no
    // dispatch in flight). The table is read-only post-publication,
    // so a `&` borrow is safe even if a raw handler unwinds via
    // longjmp — no lock guard survives the call.
    let table: &SyscallTable = unsafe { &*p };
    table.dispatch_ctx_versioned(n, version, ctx);
}

/// Legacy plain entry retained for the existing
/// `smoke_userspace_syscall_dispatch_via_global` test and any
/// caller that has `SyscallArgs` in hand but not a `TrapContext`.
#[inline]
pub fn kernel_syscall_entry_plain(num: u32, args: &SyscallArgs) -> SyscallReturn {
    let n = match Syscall::from_raw(num) {
        Some(v) => v,
        None => return SyscallReturn::invalid_op(),
    };
    let p = GLOBAL.load(Ordering::Acquire);
    if p.is_null() {
        return SyscallReturn::invalid_op();
    }
    // SAFETY: see `kernel_syscall_entry`.
    let table: &SyscallTable = unsafe { &*p };
    table
        .dispatch(n, args)
        .unwrap_or_else(SyscallReturn::invalid_op)
}

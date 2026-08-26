#[allow(unused_imports)]
use super::*;

/// Legacy `clone(2)` overloads its `parent_tid` register argument: with
/// `CLONE_PIDFD` it is the pidfd output pointer (and Linux rejects combining
/// that flag with `CLONE_PARENT_SETTID`). Keep this conversion separate so the
/// register ABI cannot silently drop the pointer while adapting to clone3.
pub(crate) fn legacy_clone_pidfd_ptr(flags: u64, parent_tid: u64) -> u64 {
    if flags & CLONE_PIDFD != 0 {
        parent_tid
    } else {
        0
    }
}

/// Linux `clone(2)` — same semantics as `clone3(2)` but the
/// arguments are passed in registers instead of via a
/// `clone_args` user struct. musl's `__clone` x86_64 asm wrapper
/// uses this entry, including for `pthread_create`. The
/// passed-in `stack` is the **top** of the new thread's stack;
/// `clone3` instead takes a `(base, size)` pair. We synthesize a
/// `CloneArgs` with `stack_size = 0` so `do_clone3`'s
/// `rsp = stack + stack_size` arithmetic recovers the original
/// top.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn sys_clone(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ca = CloneArgs {
        // Legacy clone carries the termination signal in the low byte;
        // clone3 carries it in its dedicated exit_signal field.
        // Linux's legacy entry truncates clone_flags to 32 bits. In
        // particular, clone3-only flags in the upper word must not leak into
        // this ABI.
        flags: (args.arg0 as u32 as u64) & !0xff,
        stack: args.arg1,
        // Linux's clone() takes the stack TOP directly; encode as
        // (top, size=0) so `rsp = stack + stack_size` lands at the
        // top, matching the clone3 path.
        stack_size: 0,
        parent_tid: args.arg2,
        // x86_64 clone(2) syscall ABI: arg3 = ctid, arg4 = tls.
        // (Only x86_32 — CONFIG_CLONE_BACKWARDS — flips these.)
        // musl's `__clone` x86_64 asm matches the default order:
        //     mov %r9, %r8        ; tls  -> syscall arg4 (r8)
        //     mov 8(%rsp), %r10   ; ctid -> syscall arg3 (r10)
        // We previously had these swapped (tls=arg3, ctid=arg4),
        // which made `pthread_create` set the child's FS_BASE to
        // `&__thread_list_lock` (in libc.so .bss, where ctid
        // pointed) instead of the real per-thread TP. The worker
        // then #PFed on `mov %fs:0,%rbx; movzbl 0x40(%rbx),%r11d`
        // because `%fs:0` read the lock word (`0x10`-ish), not
        // the self-pointer the TCB layout promises.
        #[cfg(target_arch = "x86_64")]
        tls: args.arg4,
        #[cfg(target_arch = "aarch64")]
        tls: args.arg3,
        #[cfg(target_arch = "x86_64")]
        child_tid: args.arg3,
        // arm64 selects Linux CONFIG_CLONE_BACKWARDS: arg3 is TLS and
        // arg4 is child_tid. This is also the ordering used by Linux's
        // arm64 ABI selftests and libc syscall wrappers.
        #[cfg(target_arch = "aarch64")]
        child_tid: args.arg4,
        pidfd: legacy_clone_pidfd_ptr(args.arg0, args.arg2),
        exit_signal: args.arg0 & 0xff,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };
    do_clone3(ctx, ca, true);
}

/// Linux `clone(2)` — same semantics as `clone3(2)` but the
/// arguments are passed in registers. Falls back to ENOSYS
/// on unsupported / non-linux-compat builds.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) fn sys_clone(ctx: &mut dyn TrapContext) {
    // Not implemented on this build config → ENOSYS.
    ctx.set_return(SyscallReturn::ok((-38i64) as u64));
}

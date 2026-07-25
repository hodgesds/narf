#[allow(unused_imports)]
use super::*;

/// Linux `clone(2)` — same semantics as `clone3(2)` but the
/// arguments are passed in registers (x86_64 syscall ABI:
/// flags, stack-TOP, ptid, tls, ctid) instead of via a
/// `clone_args` user struct. musl's `__clone` x86_64 asm wrapper
/// uses this entry, including for `pthread_create`. The
/// passed-in `stack` is the **top** of the new thread's stack;
/// `clone3` instead takes a `(base, size)` pair. We synthesize a
/// `CloneArgs` with `stack_size = 0` so `do_clone3`'s
/// `rsp = stack + stack_size` arithmetic recovers the original
/// top.
#[cfg(all(feature = "linux-compat", target_arch = "x86_64"))]
pub(crate) fn sys_clone(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let ca = CloneArgs {
        flags: args.arg0,
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
        tls: args.arg4,
        child_tid: args.arg3,
        pidfd: 0,
        exit_signal: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };
    do_clone3(ctx, ca);
}

/// Linux `clone(2)` — same semantics as `clone3(2)` but the
/// arguments are passed in registers. Falls back to InvalidOp
/// on non-x86_64 / non-linux-compat builds.
#[cfg(any(not(feature = "linux-compat"), not(target_arch = "x86_64")))]
pub(crate) fn sys_clone(ctx: &mut dyn TrapContext) {
    ctx.set_return(SyscallReturn::invalid_op());
}

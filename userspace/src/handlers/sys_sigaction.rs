#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sigaction(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let signum = args.arg0 as usize;
    let new_handler = args.arg1;
    let old_out = args.arg2;
    let flags = args.arg3 as u32;
    // Linux `do_sigaction` (kernel/signal.c): `!valid_signal(sig) || sig < 1`
    // → -EINVAL. `valid_signal` is `sig <= _NSIG` (64) and `sig < 1` rejects the
    // null signal, so the valid range is 1..=64. NARF stores signal N at slot N
    // (array size NSIG=65), i.e. 1..=NSIG-1. The blanket-EINVAL fold used to hide
    // this behind an `invalid_op()`; return the exact errno AND reject signal 0.
    if signum == 0 || signum >= NSIG {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    // Linux `do_sigaction`: `act && sig_kernel_only(sig)` → -EINVAL. SIGKILL(9)
    // and SIGSTOP(19) can never have their action changed. This flattened form
    // ALWAYS installs an action (there is no query-only mode, unlike the
    // pointer-to-struct `sys_rt_sigaction`), so `act` is effectively always
    // present — reject unconditionally. Without this a narf-libc caller could
    // install a handler for SIGKILL/SIGSTOP and the delivery path
    // (`default_signal_delivery_restricted_active`) would then run that handler
    // instead of terminating, breaking the uncatchable-signal invariant.
    if signum == 9 || signum == 19 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let task = current_task_id();

    let prior = {
        let h = match sighand_of(task) {
            Some(h) => h,
            None => {
                // No handler table for the task — a NARF-internal condition, not
                // a Linux-reachable path; EINVAL is the least-wrong answer
                // (matches sys_rt_sigaction).
                ctx.set_return(errno_ret(EINVAL));
                return;
            }
        };
        let mut slots = h.lock();
        let prior = slots[signum];
        slots[signum] = if new_handler == 0 {
            None
        } else {
            Some(SigAction {
                handler: new_handler,
                restorer: 0,
                flags,
            })
        };
        prior
    };

    if old_out != 0 {
        // Write the prior handler address to user space under the SMAP bracket.
        let val = prior.map(|a| a.handler).unwrap_or(0);
        // SAFETY: `old_out` is the user old-handler pointer (non-zero, checked above);
        // copy_to_user range-validates it and SMAP-brackets the 8-byte write.
        // SAFETY: Valid memory or trusted environment
        let _ = unsafe { copy_to_user(old_out, &val.to_ne_bytes()) };
    }

    ctx.set_return(SyscallReturn::ok(0));
}

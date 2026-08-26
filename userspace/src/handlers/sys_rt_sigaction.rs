#[allow(unused_imports)]
use super::*;

/// `sigaction(signum, handler, old_out_ptr, flags)` —
/// NARF-shaped sigaction surface (a Linux `rt_sigaction` is a
/// 4-arg `(sig, act, oact, sigsetsize)` over a `struct sigaction`;
/// we flatten the struct into registers for fewer copies).
///
/// arg0 = signum,
/// arg1 = handler vaddr (0 = clear),
/// arg2 = old_out_ptr (optional, may be 0; receives prior handler
///        vaddr — 8 bytes — for Linux's `oldact->sa_handler`),
/// arg3 = `sa_flags` (SA_*). Honoured: SA_SIGINFO, SA_RESTART,
///        SA_ONSTACK, SA_NODEFER, SA_RESETHAND. Unknown bits stored
///        but no action taken.
///
/// Older 3-arg callers (arg3 = 0) get flags = 0 as before — the
/// new arg slot is back-compatible.
pub(crate) fn sys_rt_sigaction(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let signum = args.arg0 as usize;
    let act_ptr = args.arg1;
    let oact_ptr = args.arg2;
    let sigsetsize = args.arg3 as usize;

    // Error order follows `SYSCALL_DEFINE4(rt_sigaction)` + `do_sigaction`
    // (kernel/signal.c, Linux 7.0):
    //   1. `sigsetsize != sizeof(sigset_t)` → -EINVAL, and `do_sigaction`'s
    //      `!valid_signal(sig) || sig < 1` → -EINVAL (signal 0 is invalid),
    //   2. if `act`: copy it in (-EFAULT) — the NEW action is read FIRST,
    //   3. `do_sigaction`'s `act && sig_kernel_only(sig)` → -EINVAL
    //      (SIGKILL/SIGSTOP actions can't be changed); snapshot the prior
    //      action and install the new one under one lock,
    //   4. if `oact`: copy the prior action out (-EFAULT) — written LAST and
    //      only when no earlier step errored.
    if signum == 0 || signum >= NSIG || sigsetsize != 8 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    // Linux: SIGKILL and SIGSTOP cannot be caught, ignored, or have
    // their action changed at all when `act` is non-NULL.
    if act_ptr != 0 && (signum == 9 || signum == 19) {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }

    // (2) Read the NEW action FIRST (Linux reads `act` before touching
    // `oact`, so a faulting `act` is -EFAULT even when `oact` is valid).
    // `Some(inner)` = act provided; `inner` = None clears, Some installs.
    let new_action: Option<Option<SigAction>> = if act_ptr != 0 {
        let mut buf = [0u8; 32]; // sa_handler(8) + sa_flags(8) + sa_restorer(8) + sa_mask(8)
        // SAFETY: `act_ptr` is the user sigaction pointer (non-zero, checked);
        // copy_from_user range-validates it and SMAP-brackets the 32-byte read.
        if unsafe { copy_from_user(&mut buf, act_ptr) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
        let handler = u64::from_ne_bytes(buf[0..8].try_into().unwrap());
        let flags = u64::from_ne_bytes(buf[8..16].try_into().unwrap()) as u32;
        let restorer = u64::from_ne_bytes(buf[16..24].try_into().unwrap());
        Some(if handler == 0 {
            None
        } else {
            Some(SigAction {
                handler,
                restorer,
                flags,
            })
        })
    } else {
        None
    };

    let task = current_task_id();
    let h = match sighand_of(task) {
        Some(h) => h,
        None => {
            // No handler table for the task — a NARF-internal condition, not a
            // Linux-reachable path; EINVAL is the least-wrong answer.
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
            return;
        }
    };

    // (3) Snapshot the prior action and install the new one atomically under a
    // single lock — Linux holds `sighand->siglock` across the whole read+write
    // in `do_sigaction`, so oldact reflects the pre-change state with no window
    // for a concurrent installer to interleave.
    let prior = {
        let mut guard = h.lock();
        let p = guard[signum];
        if let Some(installed) = new_action {
            guard[signum] = installed;
        }
        p
    };

    // (4) Write the prior action out LAST. Linux `struct sigaction`:
    // sa_handler(8) sa_flags(8) sa_restorer(8) sa_mask(8). sa_mask isn't
    // modelled per-action; report empty.
    if oact_ptr != 0 {
        let mut out = [0u8; 32];
        if let Some(a) = prior {
            out[0..8].copy_from_slice(&a.handler.to_ne_bytes());
            out[8..16].copy_from_slice(&u64::from(a.flags).to_ne_bytes());
            out[16..24].copy_from_slice(&a.restorer.to_ne_bytes());
        }
        // SAFETY: `oact_ptr` is the user oldact pointer (non-zero, checked);
        // copy_to_user range-validates it and SMAP-brackets the 32-byte write.
        if unsafe { copy_to_user(oact_ptr, &out) }.is_err() {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}

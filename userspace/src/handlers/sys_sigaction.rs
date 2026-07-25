#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sigaction(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let signum = args.arg0 as usize;
    let new_handler = args.arg1;
    let old_out = args.arg2;
    let flags = args.arg3 as u32;
    if signum >= NSIG {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let task = current_task_id();

    let prior = {
        let h = match sighand_of(task) {
            Some(h) => h,
            None => {
                ctx.set_return(SyscallReturn::invalid_op());
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

#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_flock(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let op = args.arg1 as u32;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    let arc_ops = fd::with_table(task, |t| t.get(fd).map(|e| e.ops.clone())).flatten();
    let arc_ops = match arc_ops {
        Some(a) => a,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    let file_ptr = alloc::sync::Arc::as_ptr(&arc_ops) as *const () as usize;
    let nonblock = op & LOCK_NB != 0;
    // The blocking path retries by parking via the yield hook and
    // re-executing the syscall on resume (a longjmp clippy can't see),
    // so every visible path through the body returns/diverges — hence
    // `never_loop`. The `loop` keeps the retry intent explicit.
    #[allow(clippy::never_loop)]
    loop {
        if flock_try(file_ptr, op, task).is_ok() {
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
        if nonblock {
            ctx.set_return(fail);
            return;
        }
        // Yield ~1ms then retry. Same shape as sys_futex's wait
        // loop — the unlock side bumps the table; we just re-poll.
        if let (Some(uctx), Some(hook)) = (
            crate::user_task::current_user_task(),
            crate::user_task::yield_hook(),
        ) {
            ctx.set_return(fail);
            let dl = narf_scheduler::narf_time::monotonic_ns().saturating_add(1_000_000);
            // SAFETY: `uctx` is the live per-task UserTaskCtx from current_user_task();
            // we hold the only reference while setting the deadline and saving CPU state
            // into `uc.state` before the yield hook hands the task to the executor.
            // SAFETY: Valid memory or trusted environment
            unsafe {
                let uc = &*uctx;
                uc.sleep_deadline_ns.store(dl, Ordering::Release);
                ctx.save_user_state(uc.state.get() as *mut u8);
                *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
                if narf_scheduler::stackful::user_own_stack_enabled() {
                    own_stack_block(ctx);
                    return;
                }
                hook(uctx);
            }
            // unreachable
        }
        ctx.set_return(fail);
        return;
    }
}

#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_yield(ctx: &mut dyn TrapContext) {
    if maybe_deliver_signal_before_yield(ctx, Syscall::Yield.raw()) {
        return;
    }

    // Polling-future path mirroring sys_exit_task.
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        // SAFETY: same contract as sys_exit_task's hook path.
        unsafe {
            let uc = &*uctx;
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                // sched_yield(2): hand the CPU to the executor ONCE so a ready
                // sibling on this CPU runs, then resume and return 0. Routing
                // through `own_stack_block` -> `own_stack_park` would break out
                // WITHOUT ever yielding, because a bare yield sets no park
                // condition (`park_should_block` returns false). `cooperative_yield`
                // is the correct primitive: it re-arms this task's slot waker
                // (so the executor keeps it Ready and re-polls it after the
                // siblings run) and `kernel_switch`es to the executor, returning
                // here once we are re-dispatched. If nothing else is runnable the
                // re-armed awake bit makes the executor re-poll us immediately, so
                // a lone yielder keeps running rather than stalling.
                narf_scheduler::stackful::cooperative_yield();
                ctx.set_return(SyscallReturn::ok(0));
                return;
            }
            hook(uctx);
        }
        // unreachable
    }

    // No polling executor wired yet — but a user task that yields
    // is asking for "let other work run." Drive the same pumps
    // sys_sleep does so the FB drain (and any other registered
    // background work) makes progress on yields. Without this, a
    // user-mode busy-wait pattern (e.g., retry-on-RingFull) spins
    // forever because nothing else runs.
    sleep_pumps::run();
    ctx.set_return(SyscallReturn::ok(0));
}

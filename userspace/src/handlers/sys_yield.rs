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
                own_stack_block(ctx);
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

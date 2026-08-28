#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_pause(ctx: &mut dyn TrapContext) {
    if maybe_deliver_signal_before_yield(ctx, Syscall::Pause.raw()) {
        return;
    }

    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        // SAFETY: `uctx` is the live per-task UserTaskCtx from current_user_task();
        // we hold the only reference while storing the deadline and saving CPU state
        // into `uc.state`, and the yield hook hands the task to the executor.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let uc = &*uctx;
            // Block forever by setting deadline to u64::MAX.
            // Any signal delivery will wake the task via wake_signal().
            // Bake EINTR into the saved frame so that when the poll loop
            // breaks the park on a pending signal and re-enters user mode,
            // pause(2) returns -EINTR; the next pause re-issue delivers it.
            ctx.set_return(SyscallReturn::ok((-4i64) as u64));
            uc.sleep_deadline_ns
                .store(u64::MAX, core::sync::atomic::Ordering::Release);
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

    // Fallback: no polling executor is wired (kernel-test contexts),
    // so there is nothing to park on. Pump any ready async work once
    // in case a signal is about to become deliverable, retry delivery,
    // then surface EINTR rather than spinning forever — a real task
    // always takes the yield-hook path above and never reaches here.
    //
    // `SYSCALL_DEFINE0(pause)` ends `return -ERESTARTNOHAND;`, which the
    // signal-return path turns into -EINTR. The comment above already said
    // "surface EINTR", but the value written was the bare -1, i.e. errno 1
    // = EPERM. pause(2) NEVER succeeds, so the return value carries no
    // information and every caller reads errno — where EPERM says the task
    // was not allowed to wait for a signal.
    narf_scheduler::sleep_pumps::run();
    if maybe_deliver_signal_before_yield(ctx, Syscall::Pause.raw()) {
        return;
    }
    ctx.set_return(SyscallReturn::ok((-4i64) as u64)); // -EINTR
}

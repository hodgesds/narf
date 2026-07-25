#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sleep(ctx: &mut dyn TrapContext) {
    let ns = ctx.args().arg0;
    if ns == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let start = narf_scheduler::narf_time::monotonic_ns();
    // Saturating add: u64 overflow on `start + ns` is structurally
    // impossible at realistic clock rates, but the saturate keeps
    // the deadline tight against pathological inputs.
    let deadline = start.saturating_add(ns);

    // Polling-future path: stash the deadline on the current
    // UserTaskCtx, bake the eventual return value (Ok(0)) into the
    // saved RAX so the user reads it on resume, save the user
    // state, then longjmp back via the yield hook. The next
    // `UserTaskFuture::poll` consults the deadline and parks the
    // task without re-entering user mode until it expires.
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        ctx.set_return(SyscallReturn::ok(0));
        // SAFETY: uctx is valid for the lifetime of the polling
        // routine (its caller, on the same CPU) which holds it
        // pinned. We're about to never return.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let uc = &*uctx;
            uc.sleep_deadline_ns
                .store(deadline, core::sync::atomic::Ordering::Release);
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

    // Fallback busy-wait (no polling future installed — test
    // trampolines, sub-polling test harnesses, etc.).
    while narf_scheduler::narf_time::monotonic_ns() < deadline {
        sleep_pumps::run();
        core::hint::spin_loop();
    }
    ctx.set_return(SyscallReturn::ok(0));
}

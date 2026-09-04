#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_yield(ctx: &mut dyn TrapContext) {
    // Own-stack syscalls execute inside the scheduler's currently-polling
    // task, so its directly-published id is authoritative. Keep this path
    // ahead of the legacy user-context/hook lookup: neither value is consumed
    // when the live syscall continuation resumes on its own kernel stack.
    if narf_scheduler::stackful::user_own_stack_enabled()
        && narf_scheduler::stackful::sched_yield_current()
    {
        // The scheduler preserves Linux's no-op behavior for a sole runnable
        // task and otherwise resumes this live continuation after a peer runs.
        // Pending signals are delivered by the common completed-syscall hook;
        // sched_yield itself is not interruptible and always returns 0.
        ctx.set_return(SyscallReturn::ok(0));
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
            // The legacy longjmp model resumes from this copied snapshot and
            // consumes EXIT_REASON_YIELDED in its polling future. Own-stack
            // yields resume the live syscall continuation above, so copying
            // all 152 bytes there would be dead work on every context switch.
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
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

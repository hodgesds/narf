#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_exit_task(ctx: &mut dyn TrapContext) {
    let exit_code = ctx.args().arg0 as u32;
    let wstatus = (exit_code & 0xff) << 8;
    let tid = current_task_id();
    let pid = task_to_pid_raw(tid).unwrap_or(tid);
    stage_pending_termination(pid, wstatus as i32);
    // Robust-futex owner-died walk — in-task context, before teardown
    // (see terminate_current_task).
    robust_list_exit_walk(tid);
    // wait4 rusage snapshot — must run here, while OUR address space is
    // still the active one (see EXIT_RUSAGE).
    record_exit_rusage(tid, pid);

    // Polling-future path: if a UserTaskCtx is installed AND an
    // exit hook is registered, save the user state, mark the
    // reason, and tail-call the hook — which longjmps back into
    // the polling routine.
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::exit_hook(),
    ) {
        // SAFETY: uctx is valid for as long as the polling routine
        // (its caller, on the same CPU) holds it pinned. We're
        // about to never return.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let uc = &*uctx;
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_EXITED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                // own-stack: the poll's EXIT_REASON_EXITED trap-back half is
                // dead — run its exit bookkeeping here before diverging: flip
                // the refcounted task to ZOMBIE (resolvable until reaped) and
                // fan out exit observers (`on_child_exit` drains wstatus +
                // WAKES a wait4-parked parent — without it the parent hangs
                // forever).
                crate::task::mark_zombie(tid);
                crate::user_task::notify_task_exited(pid, tid);
                narf_scheduler::stackful::exit_current_stackful();
            }
            hook(uctx);
        }
        // unreachable
    }

    // Legacy redirect-to-landing path (testbin runner uses this).
    let rip = EXIT_LANDING_RIP.load(Ordering::Acquire);
    let rsp = EXIT_LANDING_RSP.load(Ordering::Acquire);
    if rip == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    if !ctx.redirect_to_kernel(rip, rsp) {
        // Arch doesn't support redirect; best we can do is mark Ok.
        ctx.set_return(SyscallReturn::ok(0));
    }
    // Redirect succeeded → frame rewritten, `iretq` lands in kernel.
}

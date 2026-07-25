#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sigreturn(ctx: &mut dyn TrapContext) {
    // arg0 = SigContext vaddr (from libc trampoline, originally
    // delivered in RSI by deliver_signal). The trampoline keeps it
    // alive across the user's signal-handler call.
    let mut sc_vaddr = ctx.args().arg0;

    // Linux rt_sigreturn (#15 on x86_64) takes no argument — the
    // restorer trampoline that calls it leaves arbitrary garbage in
    // RDI, so we can't trust arg0. When the last delivered frame used
    // the restorer-based rt_sigframe layout, resolve it from the user
    // RSP (which points at the frame after the handler's `ret` popped
    // the restorer return address). NARF's own libc trampoline instead
    // forwards the SigContext vaddr in arg0.
    let task = current_task_id();
    if sigreturn_use_rsp(task) || sc_vaddr == 0 {
        sc_vaddr = ctx.user_rsp();
    }

    // Pass the authoritative frame layout the kernel recorded at delivery so the
    // arch code reads RIP/regs from the correct offsets instead of guessing from
    // user memory (which could pull a selector field into RIP → #UD).
    let is_rt = sigreturn_is_rt(task);
    if !ctx.perform_sigreturn(sc_vaddr, is_rt) {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    // POSIX: restore the signal mask that was in effect before the handler ran,
    // undoing the auto-block of the delivered signal. Only the async delivery
    // path records a saved mask; a `None` (e.g. a sync-fault handler return)
    // leaves the mask untouched. Without this the delivered signal stays blocked
    // forever and a second occurrence is never taken.
    if let Some(saved) = take_sigreturn_saved_mask(task) {
        let _ = set_signal_mask_for_task(task, saved);
    }
}

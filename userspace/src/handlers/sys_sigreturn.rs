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
    // Pop THIS handler's delivery record (a per-task stack — nested handlers each
    // restore their own frame). A missing record falls back to modern defaults
    // (rt layout, trust arg0). Consuming it here is correct: the record belongs
    // to exactly this sigreturn, and LIFO handler nesting keeps the stack ordered.
    let rec = pop_sigreturn_record(task);
    let use_rsp = rec.map(|r| r.use_rsp).unwrap_or(false);
    if use_rsp || sc_vaddr == 0 {
        sc_vaddr = ctx.user_rsp();
    }

    // Pass the authoritative frame layout the kernel recorded at delivery so the
    // arch code reads RIP/regs from the correct offsets instead of guessing from
    // user memory (which could pull a selector field into RIP → #UD). Default
    // `true`: modern (rt_sigaction + SA_SIGINFO/restorer) is the overwhelming case.
    let is_rt = rec.map(|r| r.is_rt).unwrap_or(true);
    if !ctx.perform_sigreturn(sc_vaddr, is_rt) {
        // A frame that will not restore is `badframe:` in
        // `arch/x86/kernel/signal_64.c::SYSCALL_DEFINE0(rt_sigreturn)`. Every
        // validation failure there jumps to it, and it ends in
        // `signal_fault()`, whose last statement is `force_sig(SIGSEGV)`. The
        // `return 0` that follows is a formality — the task is already dying.
        //
        // NARF used to return only that 0, as `invalid_op()` (whose `value` is
        // 0, which is what the Linux ABI reads), and let the task CONTINUE on
        // whatever register state the failed restore left behind. A corrupted
        // or attacker-supplied sigreturn frame is precisely the case the kill
        // exists for: sigreturn is the one syscall that rewrites the entire
        // user register file, so "it didn't work, carry on" resumes a thread
        // whose state nothing vouches for.
        //
        // Vector 13 (#GP) is the route, because `vector_to_signum` maps it to
        // SIGSEGV and the sync-fault path already does the rest of what
        // `force_sig` does: the ptrace intercept, the handler lookup (a task
        // with a SIGSEGV handler still runs it — `force_sig` only resets the
        // disposition when the signal is ignored or blocked), and the
        // force_sigsegv tail for a frame that cannot be placed. `addr: 0`
        // matches `force_sig(SIGSEGV)`, which leaves `si_addr` NULL.
        //
        // Going through the installed hook rather than calling
        // `default_sync_signal_delivery` directly is deliberate: it respects a
        // kernel (or test) that installed its own, and it is what lets this
        // path be exercised without tearing down the calling task.
        //
        // No log line here. The no-handler path inside the hook already prints
        // a full fatal-fault diagnostic and then terminates, which bounds it;
        // a task that *has* a SIGSEGV handler survives, so printing here would
        // hand userspace an unbounded console-spam loop.
        let killed = sync_signal_hook().is_some_and(|hook| hook(ctx, 13, SyncFaultInfo { addr: 0 }));
        if !killed {
            // No signal machinery wired at all. Linux's badframe arm literally
            // reads `return 0`, so that is the answer left standing.
            ctx.set_return(SyscallReturn::ok(0));
        }
        return;
    }
    // POSIX: restore the signal mask that was in effect before the handler ran,
    // undoing the auto-block of the delivered signal. Only the async delivery
    // path records a saved mask; a `None` (e.g. a sync-fault handler return)
    // leaves the mask untouched. Without this the delivered signal stays blocked
    // forever and a second occurrence is never taken.
    if let Some(saved) = rec.and_then(|r| r.saved_mask) {
        let _ = set_signal_mask_for_task(task, saved);
    }
}

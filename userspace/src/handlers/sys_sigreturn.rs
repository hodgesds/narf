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
        // x86_64 `rt_sigframe` is [pretcode][ucontext][siginfo]: after the
        // handler's `ret` popped pretcode, RSP points at the ucontext.
        // `perform_sigreturn` takes the siginfo address (what delivery put
        // in RSI), which sits `UCONTEXT_BYTES` above it. Linux's
        // `rt_sigreturn` finds the same frame as `regs->sp - sizeof(long)`.
        #[cfg(target_arch = "x86_64")]
        if rec.map(|r| r.is_rt).unwrap_or(true) {
            sc_vaddr = sc_vaddr.wrapping_add(narf_arch::x86_64::sigframe::UCONTEXT_BYTES);
        }
    }

    // Pass the authoritative frame layout the kernel recorded at delivery so the
    // arch code reads RIP/regs from the correct offsets instead of guessing from
    // user memory (which could pull a selector field into RIP → #UD). Default
    // `true`: modern (rt_sigaction + SA_SIGINFO/restorer) is the overwhelming case.
    let is_rt = rec.map(|r| r.is_rt).unwrap_or(true);
    // Linux restores uc_sigmask from the user frame: handlers may edit it.
    // musl's deferred-cancellation handler blocks SIGCANCEL in that mask and
    // requeues it until a cancellation point. Restoring the kernel's original
    // copy instead redelivers it immediately, livelocking pthread_cancel/join.
    // Read before restoring registers so a fault is a bad frame throughout.
    let saved_mask = if use_rsp && is_rt {
        #[cfg(target_arch = "x86_64")]
        let mask_address = sc_vaddr.checked_sub(8); // siginfo follows uc_sigmask
        #[cfg(target_arch = "aarch64")]
        let mask_address = sc_vaddr.checked_add(128 + 40); // rt_sigframe.uc.uc_sigmask
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let mask_address = None;
        let mut mask = [0u8; 8];
        mask_address.ok_or(()).and_then(|address| {
            // SAFETY: fixed-size local destination; guarded, range-checked
            // user read. Arbitrary frame contents grant no kernel authority.
            unsafe { copy_from_user(&mut mask, address) }
                .map(|_| Some(u64::from_ne_bytes(mask))).map_err(|_| ())
        })
    } else {
        // NARF's compact non-restorer ABI keeps the kernel-side mask record.
        Ok(rec.and_then(|r| r.saved_mask))
    };
    if saved_mask.is_err() || !ctx.perform_sigreturn(sc_vaddr, is_rt) {
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
        let killed = sync_signal_hook().is_some_and(|hook| hook(ctx, 13, SyncFaultInfo { addr: 0, bus: false }));
        if !killed {
            // No signal machinery wired at all. Linux's badframe arm literally
            // reads `return 0`, so that is the answer left standing.
            ctx.set_return(SyscallReturn::ok(0));
        }
        return;
    }
    // The common setter strips SIGKILL/SIGSTOP even from a forged user mask
    // and retargets shared pending work after the restored mask changes.
    if let Ok(Some(saved)) = saved_mask {
        let _ = set_signal_mask_for_task(task, saved);
    }
}

#[cfg(feature = "kernel-test")]
fn smoke_rt_sigreturn_restores_edited_user_mask() -> narf_kernel_test::TestResult {
    use narf_kernel_test::TestResult;
    let _buffers = kernel_buffers_guard();
    #[repr(align(16))]
    struct UserFrame([u8; 512]);
    let mut frame = UserFrame([0; 512]);
    #[cfg(target_arch = "x86_64")]
    const MASK_OFFSET: usize = 296; // RSP points at ucontext after pretcode pops
    #[cfg(target_arch = "aarch64")]
    const MASK_OFFSET: usize = 168;
    let edited = sig_bit(10) | sig_bit(12) | UNBLOCKABLE_MASK;
    frame.0[MASK_OFFSET..MASK_OFFSET + 8].copy_from_slice(&edited.to_ne_bytes());
    struct ReturnContext {
        args: SyscallArgs,
        rsp: u64,
        restored: bool,
    }
    impl TrapContext for ReturnContext {
        fn args(&self) -> &SyscallArgs { &self.args }
        fn set_return(&mut self, _: SyscallReturn) {}
        fn user_rsp(&self) -> u64 { self.rsp }
        fn redirect_to_kernel(&mut self, _: u64, _: u64) -> bool { false }
        fn rip(&self) -> u64 { 0 }
        fn set_rip(&mut self, _: u64) {}
        fn perform_sigreturn(&mut self, _: u64, _: bool) -> bool {
            self.restored = true;
            true
        }
    }
    let task = current_task_id();
    let old = signal_mask_of(task);
    push_sigreturn_record(task, true, true, u64::MAX, false);
    set_sigreturn_saved_mask(task, sig_bit(15));
    let mut ctx = ReturnContext {
        args: SyscallArgs::default(),
        rsp: frame.0.as_ptr() as u64,
        restored: false,
    };
    sys_sigreturn(&mut ctx);
    let restored = signal_mask_of(task);
    set_signal_mask_for_task(task, old);
    if !ctx.restored || restored != edited & !UNBLOCKABLE_MASK {
        return TestResult::Fail("rt_sigreturn ignored edited uc_sigmask or restored unblockable bits");
    }
    TestResult::Pass
}
#[cfg(feature = "kernel-test")]
narf_kernel_test::kernel_test_in!("userspace/signals", smoke_rt_sigreturn_restores_edited_user_mask);

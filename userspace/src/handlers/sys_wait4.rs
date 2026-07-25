#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_wait4(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let want_pid = args.arg0 as i64;
    let status_ptr = args.arg1;
    let options = args.arg2 as u32;
    let rusage_ptr = args.arg3; // filled with the reaped child's CPU time
    const WNOHANG: u32 = 1;

    let parent = current_task_id();

    // Try-reap closure: pops the matching (child_pid, status)
    // from the parent's queue if any. Returns Some on success.
    let try_reap = |parent: u64, want: i64| -> Option<(u64, i32)> {
        let mut g = PENDING_EXITS.lock();
        let m = g.as_mut()?;
        let q = m.get_mut(&parent)?;
        let idx = if want > 0 {
            // Specific child.
            q.iter().position(|&(p, _)| p == want as u64)?
        } else {
            // Any child (including pid == 0 / pid < -1 we
            // collapse to -1 for simplicity — no per-pgid wait
            // until process groups are real).
            if q.is_empty() {
                return None;
            }
            0
        };
        Some(q.remove(idx))
    };

    // Job-control stop/continue FIRST (WUNTRACED/WCONTINUED). A state
    // change is reported before the child's later exit, in order, matching
    // Linux — so `waitpid(WCONTINUED)` after `kill(SIGCONT)` sees the
    // continue even if the child has already run to exit. Only matches when
    // the option + a queued report are present; a plain wait falls straight
    // through to the exit reap. Does NOT release the PID — child lives (or
    // its exit stays queued for the next wait).
    if let Some((child, status)) = reap_stopcont(parent, want_pid, options) {
        if status_ptr != 0 {
            // SAFETY: `status_ptr` non-zero; copy_to_user range-validates
            // and SMAP-brackets the 4-byte write.
            let _ = unsafe { copy_to_user(status_ptr, &status.to_ne_bytes()) };
        }
        ctx.set_return(SyscallReturn::ok(child));
        return;
    }

    if let Some((reaped, status)) = try_reap(parent, want_pid) {
        if status_ptr != 0 {
            // Write i32 status under the SMAP bracket.
            // SAFETY: `status_ptr` is the user wstatus pointer (non-zero, checked);
            // copy_to_user range-validates it and SMAP-brackets the 4-byte write.
            // SAFETY: Valid memory or trusted environment
            let _ = unsafe { copy_to_user(status_ptr, &status.to_ne_bytes()) };
        }
        // Charge the reaped child's CPU time to the parent's children
        // accumulator (RUSAGE_CHILDREN / tms.cutime) and, if the caller
        // passed a `struct rusage*`, fill ru_utime with it.
        let child_cpu_ns = account_reaped_child(parent, reaped);
        // Consume the child's exit-time snapshot even when the caller
        // passed no rusage* — the entry must not outlive the reap.
        let snap = take_exit_rusage(reaped);
        if rusage_ptr != 0 {
            let (ns, kb) = snap.unwrap_or((child_cpu_ns, 0));
            write_rusage_utime(rusage_ptr, ns, kb);
        }
        // Reaped — release the refcounted Task, then return the PID to
        // the free pool.
        release_reaped_task(reaped);
        crate::release_pid(crate::ProcessId(reaped));
        // The child is gone — drop its parent record so a later wait4 sees
        // it's no longer a child (otherwise the ECHILD check below stays
        // blind to the reap and the parent blocks forever).
        parent_of_remove(reaped);
        ctx.set_return(SyscallReturn::ok(reaped));
        return;
    }

    // No matching exit was queued. If the caller has no remaining child that
    // could ever satisfy this wait, return ECHILD instead of blocking — Linux
    // semantics. Without this, a parent that has already reaped its last child
    // blocks forever (observed: stress-ng's parent `wait4(-1)` hanging after
    // its only worker exited, so the whole run never completes).
    if !has_living_child(parent, want_pid) {
        const ECHILD: i64 = 10;
        ctx.set_return(SyscallReturn::ok((-ECHILD) as u64));
        return;
    }

    if options & WNOHANG != 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // Blocking wait — cooperative yield to the scheduler.
    //
    // Previous implementation was a busy-spin that prevented the
    // child task from ever being scheduled (the child's UserTaskFuture
    // was on the ready queue but the parent's spin loop never returned
    // to the executor).
    //
    // New implementation mirrors `sys_futex` / `sys_sleep`:
    //   1. Set wait_child_pending + args on the current UserTaskCtx.
    //   2. Save user state (RAX will be overwritten by the poll
    //      routine once a reap succeeds).
    //   3. Longjmp back to the executor via the yield hook.
    //
    // `UserTaskFuture::poll` sees `wait_child_pending = true` and
    // tries to reap.  If the queue is empty it stores `cx.waker()`
    // (so `on_child_exit` can fire it) and returns `Poll::Pending`.
    // The child gets scheduled, exits, `on_child_exit` wakes the
    // parent, and the parent is re-polled; this time the reap
    // succeeds and the result is written into the saved RAX.
    //
    // Fallback: if no polling future is installed (test context),
    // the code falls through to the spin below.
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        // SAFETY: uctx is valid for the lifetime of the polling
        // routine which holds it pinned; we're about to longjmp.
        // SAFETY: Valid memory or trusted environment
        unsafe {
            let uc = &*uctx;
            // Stage the rusage out-pointer for finish_wait_child (it
            // runs as this task on the reap side — see WAIT_RUSAGE_PTR).
            set_wait_rusage_ptr(parent, rusage_ptr);
            uc.wait_child_pending
                .store(true, core::sync::atomic::Ordering::Release);
            uc.wait_child_want_pid
                .store(want_pid, core::sync::atomic::Ordering::Release);
            uc.wait_child_status_ptr
                .store(status_ptr, core::sync::atomic::Ordering::Release);
            // wait4 writes a wstatus int, not a waitid siginfo.
            uc.wait_child_is_waitid
                .store(false, core::sync::atomic::Ordering::Release);
            // Carry WUNTRACED/WCONTINUED so the poll-loop reap check
            // can also collect job-control stop/continue notifications.
            uc.wait_child_options
                .store(options, core::sync::atomic::Ordering::Release);
            // Save user-mode register state.  The RAX written here
            // is a placeholder; UserTaskFuture::poll overwrites it
            // with the reaped child pid before re-entering user mode.
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                own_stack_block(ctx);
                return;
            }
            hook(uctx);
        }
        // unreachable — hook() never returns
    }

    // Test/no-future fallback: synchronous busy-poll (same as
    // before, kept for tests that use StubCtx without a real
    // UserTaskFuture / yield hook).  Cap at 60 s.
    let deadline = narf_time::Deadline::after_ms(60_000);
    let mut reaped = None;
    while !deadline.expired() {
        if let Some(entry) = try_reap(parent, want_pid) {
            reaped = Some(entry);
            break;
        }
        narf_scheduler::sleep_pumps::run();
        for _ in 0..100_000 {
            core::hint::spin_loop();
        }
    }
    match reaped {
        Some((child, status)) => {
            if status_ptr != 0 {
                // SAFETY: `status_ptr` is the user wstatus pointer (non-zero, checked);
                // copy_to_user range-validates it and SMAP-brackets the 4-byte write.
                // SAFETY: Valid memory or trusted environment
                let _ = unsafe { copy_to_user(status_ptr, &status.to_ne_bytes()) };
            }
            ctx.set_return(SyscallReturn::ok(child));
        }
        // Use u64::MAX as the "error" sentinel since 0 is the
        // legitimate WNOHANG-with-no-exited-child return value
        // (so we can't reuse `invalid_op` whose rax = 0).
        None => ctx.set_return(SyscallReturn::ok(u64::MAX)),
    }
}

#[allow(unused_imports)]
use super::*;

/// `waitid(idtype, id, infop, options, rusage)` — wait for a child and
/// report its state via a `siginfo_t`. Reuses the wait4 reap machinery;
/// the blocking path is driven by `UserTaskCtx::wait_child_is_waitid`
/// so the poll routine writes a siginfo and returns 0.
pub(crate) fn sys_waitid(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let idtype = args.arg0 as u32;
    let id = args.arg1 as i64;
    let infop = args.arg2;
    let options = args.arg3 as u32;
    let rusage_ptr = args.arg4; // Linux waitid's 5th arg — glibc's wait4 shim uses it
    const P_ALL: u32 = 0;
    const P_PID: u32 = 1;
    const P_PGID: u32 = 2;
    const P_PIDFD: u32 = 3;
    const WNOHANG: u32 = 1;
    // WNOWAIT: report a waitable child WITHOUT reaping it — the zombie
    // (and its /proc/<pid> entry) stays in place for a later real wait.
    // systemd's manager_dispatch_sigchld peeks waitid(P_ALL, WEXITED|
    // WNOHANG|WNOWAIT) precisely so it can still read /proc/$PID (the
    // "is this my child" PPid check) before reaping with waitid(P_PID).
    const WNOWAIT: u32 = 0x0100_0000;

    // Translate (idtype, id) to the wait4-style want_pid: P_ALL → -1
    // (any child), P_PID → the pid. P_PGID collapses to -1 until
    // process groups are real (same simplification as wait4).
    let want_pid: i64 = match idtype {
        P_ALL => -1,
        P_PID => id,
        P_PGID => -1,
        // P_PIDFD: `id` is a pidfd; wait on its target process. The error
        // shape is LOAD-BEARING: glibc's `__clone_pidfd_supported()` probes
        // `waitid(P_PIDFD, INT_MAX, NULL, WEXITED|WNOHANG)` and requires
        // -EBADF from a P_PIDFD-aware kernel. Returning -EINVAL (the old
        // unknown-idtype arm) made glibc cache "no pidfd support", so
        // `pidfd_spawn` — systemd 258's ONLY service-executor spawn path —
        // returned ENOSYS without ever issuing clone3: every unit failed
        // with "Failed to spawn executor: Function not implemented".
        // Linux ref: `kernel/exit.c::kernel_waitid` → `pidfd_get_pid`.
        P_PIDFD => {
            let target = if (0..=u32::MAX as i64).contains(&id) {
                fd::with_table(current_task_id(), |t| {
                    t.get(id as u32).and_then(|e| e.ops.pidfd_target_pid())
                })
                .flatten()
            } else {
                None
            };
            match target {
                Some(p) => p as i64,
                // Bad fd, or an fd that isn't a pidfd: EBADF (Linux).
                None => {
                    ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
                    return;
                }
            }
        }
        _ => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
    };

    let parent = current_task_id();

    // Job-control stop/continue FIRST (WUNTRACED/WCONTINUED) — a state
    // change is reported before the child's later exit, in order, matching
    // Linux. Only matches when the option + a queued report are present, so
    // a plain wait falls through to the exit reap. No PID release.
    if let Some((child_pid, status)) = reap_stopcont(parent, want_pid, options) {
        if infop != 0 {
            let si = encode_waitid_siginfo(child_pid as i64, status);
            // SAFETY: `infop` non-zero; copy_to_user range-validates the write.
            let _ = unsafe { copy_to_user(infop, &si) };
        }
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // Real exit reap (releases the child PID) — unless WNOWAIT, which
    // only PEEKS the entry: the child stays queued (and its Task/pid
    // tables intact) so a later wait4/waitid can still reap it.
    let peek = options & WNOWAIT != 0;
    let reaped = {
        let mut g = PENDING_EXITS.lock();
        g.as_mut().and_then(|m| {
            let q = m.get_mut(&parent)?;
            let idx = if want_pid > 0 {
                q.iter().position(|&(p, _)| p == want_pid as u64)?
            } else if q.is_empty() {
                return None;
            } else {
                0
            };
            if peek {
                Some(q[idx])
            } else {
                Some(q.remove(idx))
            }
        })
    };
    if let Some((child_pid, status)) = reaped {
        if infop != 0 {
            let si = encode_waitid_siginfo(child_pid as i64, status);
            // SAFETY: `infop` is the user `siginfo_t*` (non-zero); copy_to_user
            // range-validates the 128-byte write.
            let _ = unsafe { copy_to_user(infop, &si) };
        }
        if peek {
            // WNOWAIT: status reported, nothing consumed. Accounting,
            // rusage and the pid/task release all belong to the eventual
            // real reap.
            ctx.set_return(SyscallReturn::ok(0));
            return;
        }
        // Charge the child's CPU to the parent (this path skipped the
        // fold wait4 does — RUSAGE_CHILDREN never saw waitid-reaped
        // children) and fill the 5th-arg rusage like wait4.
        let child_cpu_ns = account_reaped_child(parent, child_pid);
        let snap = take_exit_rusage(child_pid);
        if rusage_ptr != 0 {
            let (ns, kb) = snap.unwrap_or((child_cpu_ns, 0));
            write_rusage_utime(rusage_ptr, ns, kb);
        }
        release_reaped_task(child_pid);
        crate::release_pid(crate::ProcessId(child_pid));
        // Reaped — drop the parent record so wait4's ECHILD check is accurate.
        parent_of_remove(child_pid);
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    if options & WNOHANG != 0 {
        // No child ready: POSIX leaves infop's si_signo as 0 (the
        // caller pre-zeros it). Return success.
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // Blocking: park via the shared wait machinery with the waitid
    // flag set so the poll routine writes a siginfo + returns 0.
    if let (Some(uctx), Some(hook)) = (
        crate::user_task::current_user_task(),
        crate::user_task::yield_hook(),
    ) {
        // SAFETY: `uctx` is the live per-task UserTaskCtx; we hold the
        // only reference while staging the wait state and saving CPU
        // state before the yield hook hands the task to the executor.
        unsafe {
            let uc = &*uctx;
            // Stage waitid's own 5th-arg rusage pointer (also
            // invalidates any stale wait4 slot).
            set_wait_rusage_ptr(current_task_id(), rusage_ptr);
            uc.wait_child_is_waitid
                .store(true, core::sync::atomic::Ordering::Release);
            uc.wait_child_want_pid
                .store(want_pid, core::sync::atomic::Ordering::Release);
            uc.wait_child_status_ptr
                .store(infop, core::sync::atomic::Ordering::Release);
            uc.wait_child_options
                .store(options, core::sync::atomic::Ordering::Release);
            uc.wait_child_pending
                .store(true, core::sync::atomic::Ordering::Release);
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                own_stack_block(ctx);
                return;
            }
            hook(uctx);
        }
    }
    // Fallback (no polling future, e.g. kernel-test context): report no
    // child rather than spin.
    ctx.set_return(SyscallReturn::ok(0));
}

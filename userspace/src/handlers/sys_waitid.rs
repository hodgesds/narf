#[allow(unused_imports)]
use super::*;

/// Linux's waitid syscall wrapper writes a zero-result siginfo even when the
/// internal wait returns an error. Consequently a faulting `infop` overrides
/// EINVAL/EBADF/ECHILD/EAGAIN with EFAULT; wait4 does not have this behavior.
fn waitid_set_error(ctx: &mut dyn TrapContext, infop: u64, errno: i64) {
    if infop != 0 {
        let empty = [0u8; 128];
        // SAFETY: copy_to_user validates the complete siginfo range.
        if unsafe { copy_to_user(infop, &empty) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
    }
    ctx.set_return(errno_ret(errno));
}

fn waitid_write_empty_infop(infop: u64) -> Result<(), u64> {
    if infop == 0 {
        return Ok(());
    }
    let empty = [0u8; 128];
    // SAFETY: copy_to_user validates the complete siginfo range.
    unsafe { copy_to_user(infop, &empty) }
}

/// `waitid(idtype, id, infop, options, rusage)` — wait for a child and
/// report its state via a `siginfo_t`. Reuses the wait4 reap machinery;
/// the blocking path is driven by `UserTaskCtx::wait_child_is_waitid`
/// so the poll routine writes a siginfo and returns 0.
pub(crate) fn sys_waitid(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let idtype = args.arg0 as u32;
    // The kernel ABI declares `id` as pid_t: signed 32-bit even on LP64.
    let id = args.arg1 as i32 as i64;
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

    const VALID_WAIT_OPTIONS: u32 = WNOHANG
        | WUNTRACED
        | WEXITED
        | WCONTINUED
        | WNOWAIT
        | __WNOTHREAD
        | __WCLONE
        | __WALL;
    if options & !VALID_WAIT_OPTIONS != 0 || options & (WUNTRACED | WEXITED | WCONTINUED) == 0 {
        waitid_set_error(ctx, infop, EINVAL);
        return;
    }

    // Translate (idtype, id) to the wait4-style want_pid: P_ALL → -1
    // (any child), P_PID → the pid. P_PGID sets a process-group filter
    // (`want_pgid`) and waits on "any child" in that group (#29).
    let mut want_pgid = 0u64;
    let mut pidfd_nonblock = false;
    let want_pid: i64 = match idtype {
        P_ALL => -1,
        // `id` is a pid in the caller's namespace; the reap machinery keys on
        // the outer ProcessId. An inner pid NOT bound in the caller's namespace
        // names no child of this caller → ECHILD. Keeping the raw inner risked
        // reaping a ROOT-namespace child at a colliding outer number (#30).
        // Identity in the root ns.
        P_PID => {
            if id <= 0 {
                waitid_set_error(ctx, infop, EINVAL);
                return;
            }
            match accept_pid_from(current_task_id(), id as u64) {
                Some(o) => o as i64,
                None => {
                    waitid_set_error(ctx, infop, ECHILD);
                    return;
                }
            }
        }
        // `id` is a pgid in the caller's ns; id == 0 means the caller's OWN
        // process group. Resolve to the TASK-space group id the reap filters
        // on; a group that resolves to nothing is ECHILD. Then wait on any
        // child (want_pid = -1) — the pgid filter selects the member. (#29)
        P_PGID => {
            if id < 0 {
                waitid_set_error(ctx, infop, EINVAL);
                return;
            }
            want_pgid = if id == 0 {
                read_pgid(current_task_id())
            } else {
                pgid_from_user(id as u64)
            };
            if want_pgid == 0 {
                waitid_set_error(ctx, infop, ECHILD);
                return;
            }
            -1
        }
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
            if id < 0 {
                waitid_set_error(ctx, infop, EINVAL);
                return;
            }
            let target = if id <= u32::MAX as i64 {
                fd::with_table(current_task_id(), |t| {
                    let fd = id as u32;
                    t.get(fd).and_then(|e| {
                        e.ops
                            .pidfd_target_pid()
                            .map(|pid| (pid, t.status_flags(fd).unwrap_or(0)))
                    })
                })
                .flatten()
            } else {
                None
            };
            match target {
                Some((p, status_flags)) => {
                    pidfd_nonblock = status_flags & fd::O_NONBLOCK != 0;
                    p as i64
                }
                // Bad fd, or an fd that isn't a pidfd: EBADF (Linux).
                None => {
                    waitid_set_error(ctx, infop, EBADF);
                    return;
                }
            }
        }
        _ => {
            waitid_set_error(ctx, infop, EINVAL);
            return;
        }
    };

    let parent = current_task_id();
    let parents = wait_parent_ids(parent, options);

    // Job-control stop/continue FIRST (WUNTRACED/WCONTINUED) — a state
    // change is reported before the child's later exit, in order, matching
    // Linux. Only matches when the option + a queued report are present, so
    // a plain wait falls through to the exit reap. No PID release.
    if let Some((child_pid, status)) = reap_stopcont(&parents, want_pid, want_pgid, options) {
        // Linux copies the optional rusage before siginfo for waitid. The
        // state-change has already been consumed (unless WNOWAIT), so EFAULT
        // affects only the return value, not event visibility.
        if rusage_ptr != 0 {
            let child_tid = pid_to_task_raw(child_pid).unwrap_or(child_pid);
            let ns = cpu_time_ns_of(child_tid).saturating_add(child_cpu_time_ns_of(child_tid));
            if write_rusage_utime(rusage_ptr, ns, task_rss_bytes(child_tid) / 1024).is_err() {
                ctx.set_return(errno_ret(EFAULT));
                return;
            }
        }
        if infop != 0 {
            // Report the child in the CALLER's namespace view, exactly like
            // the exit-reap arm below; the raw child_pid leaked an outer pid
            // to a containerized waiter (Linux pid_vnr on wo_stat).
            let si = encode_waitid_siginfo(report_pid_to(parent, child_pid) as i64, status);
            // SAFETY: `infop` non-zero; copy_to_user range-validates the write.
            if unsafe { copy_to_user(infop, &si) }.is_err() {
                ctx.set_return(errno_ret(EFAULT));
                return;
            }
        }
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }

    // Real exit reap (releases the child PID) — unless WNOWAIT, which
    // only PEEKS the entry: the child stays queued (and its Task/pid
    // tables intact) so a later wait4/waitid can still reap it.
    let peek = options & WNOWAIT != 0;
    let reaped = reap_pending_exit(&parents, want_pid, want_pgid, options, peek);
    if let Some(entry) = reaped {
        let child_pid = entry.child_pid;
        let status = entry.status;
        // WNOWAIT reads but does not consume the saved usage. A real reap
        // charges the parent and removes the snapshot even if a later user
        // copy faults, matching Linux's consume-before-copy ordering.
        let (ns, kb) = if peek {
            let child_tid = pid_to_task_raw(child_pid).unwrap_or(child_pid);
            peek_exit_rusage(child_pid).unwrap_or_else(|| {
                (
                    cpu_time_ns_of(child_tid).saturating_add(child_cpu_time_ns_of(child_tid)),
                    task_rss_bytes(child_tid) / 1024,
                )
            })
        } else {
            let child_cpu_ns = account_reaped_child(parent, child_pid);
            take_exit_rusage(child_pid).unwrap_or((child_cpu_ns, 0))
        };
        let mut copy_errno = None;
        if rusage_ptr != 0 {
            if let Err(errno) = write_rusage_utime(rusage_ptr, ns, kb) {
                copy_errno = Some(errno);
            }
        }
        if copy_errno.is_none() && infop != 0 {
            // Report the child in the caller's namespace view (si_pid).
            let si = encode_waitid_siginfo(report_pid_to(parent, child_pid) as i64, status);
            // SAFETY: `infop` is the user `siginfo_t*` (non-zero); copy_to_user
            // range-validates the 128-byte write.
            if let Err(errno) = unsafe { copy_to_user(infop, &si) } {
                copy_errno = Some(errno);
            }
        }
        if peek {
            // WNOWAIT: status reported, nothing consumed. Accounting and the
            // pid/task release belong to the eventual real reap.
            ctx.set_return(match copy_errno {
                Some(errno) => errno_ret(errno as i64),
                None => SyscallReturn::ok(0),
            });
            return;
        }
        release_reaped_task(child_pid);
        crate::release_pid(crate::ProcessId(child_pid));
        // Reaped — drop the parent record so wait4's ECHILD check is accurate.
        parent_of_remove(child_pid);
        ctx.set_return(match copy_errno {
            Some(errno) => errno_ret(errno as i64),
            None => SyscallReturn::ok(0),
        });
        return;
    }

    // No matching exit was queued. If the caller has no remaining child that
    // could ever satisfy this wait, report ECHILD instead of blocking —
    // `sys_wait4` has had this guard since a parent that had already reaped
    // its last child blocked forever, and `waitid(2)` needs it for the same
    // reason. Linux decides both in the same place (`kernel/exit.c::do_wait`,
    // which returns -ECHILD when the tasklist walk finds no eligible child).
    //
    // It matters more here than in wait4: this park is `own_stack_wait_child`,
    // which registers only the child-exit and signal wakers. It arms no
    // timer-wheel backstop, so unlike a poll/epoll park there is nothing to
    // re-float the task after a wake that can never come — the strand is
    // unbounded, and invisible to the park-check heuristic because that path
    // does not tick `dbg_park_checks` either.
    if !has_living_child(&parents, want_pid, want_pgid, options) {
        waitid_set_error(ctx, infop, ECHILD);
        return;
    }

    if options & WNOHANG != 0 {
        // Linux writes a zeroed no-event siginfo; it does not require the
        // caller to pre-zero it. A bad output range is therefore EFAULT.
        ctx.set_return(if waitid_write_empty_infop(infop).is_err() {
            errno_ret(EFAULT)
        } else {
            SyscallReturn::ok(0)
        });
        return;
    }

    // Linux folds O_NONBLOCK on a pidfd into the internal WNOHANG walk, then
    // distinguishes it from an explicit WNOHANG request with EAGAIN.
    if pidfd_nonblock {
        waitid_set_error(ctx, infop, EAGAIN);
        return;
    }

    // Blocking: park via the shared wait machinery with the waitid
    // flag set so the poll routine writes a siginfo + returns 0.
    if let Some(uctx) = crate::user_task::current_user_task() {
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
            uc.wait_child_want_pgid
                .store(want_pgid, core::sync::atomic::Ordering::Release);
            uc.wait_child_status_ptr
                .store(infop, core::sync::atomic::Ordering::Release);
            uc.wait_child_options
                .store(options, core::sync::atomic::Ordering::Release);
            uc.wait_child_pending
                .store(true, core::sync::atomic::Ordering::Release);
            ctx.save_user_state(uc.state.get() as *mut u8);
            *uc.exit_reason.get() = crate::user_task::EXIT_REASON_YIELDED;
            if narf_scheduler::stackful::user_own_stack_enabled() {
                // The own-stack executor parks through `kernel_switch`; it
                // does not use the legacy longjmp yield hook. Requiring that
                // hook here made a real waitid(2) falsely return success with
                // a zeroed siginfo_t when a direct systemd PID 1 waited for a
                // generator child. systemd correctly treats that as an
                // unknown child state and aborts its generator sandbox.
                own_stack_block(ctx);
                return;
            }
            if let Some(hook) = crate::user_task::yield_hook() {
                hook(uctx);
            }
        }
    }
    // A blocking waitid with no task context cannot safely park. It must not
    // masquerade as a successful reap: Linux reports ECHILD when there is no
    // eligible child, while a successful waitid must fill siginfo_t.
    waitid_set_error(ctx, infop, ECHILD);
}

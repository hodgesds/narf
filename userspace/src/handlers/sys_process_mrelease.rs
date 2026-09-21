//! `process_mrelease(2)` — `mm/oom_kill.c`.

#[allow(unused_imports)]
use super::*;

/// `SYSCALL_DEFINE2(process_mrelease, int pidfd, unsigned int flags)` — 448
/// on both x86_64 and the generic table.
///
/// Reclaims the anonymous memory of a process that is ALREADY DYING, without
/// waiting for it to be scheduled so it can tear itself down. A userspace
/// low-memory killer (Android's lmkd, systemd-oomd) uses it to make a kill
/// return memory promptly instead of at the victim's leisure.
///
/// The gate is the whole security argument: `task_will_free_mem(p)` must
/// hold, or the call is -EINVAL. Without it this would be a way for any
/// caller holding a pidfd to destroy a LIVE process's memory.
pub(crate) fn sys_process_mrelease(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let pidfd = a.arg0 as u32;
    let flags = a.arg1 as u32;

    // `if (flags) return -EINVAL;` — first, before the fd is even looked at,
    // so a caller passing a flag this kernel does not know is told so rather
    // than having its unknown intent silently ignored.
    if flags != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }

    // `task = pidfd_get_task(pidfd, &f_flags); if (IS_ERR(task)) return
    // PTR_ERR(task);` — -EBADF when the descriptor is not a pidfd at all.
    let caller = current_task_id();
    let Some(target_pid) = fd::with_table(caller, |t| {
        t.get(pidfd).and_then(|e| e.ops.pidfd_target_pid())
    })
    .flatten() else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };

    // `get_pid_task(pid, PIDTYPE_TGID)` failing is -ESRCH: the descriptor is
    // valid but the process behind it is gone. A pidfd deliberately outlives
    // its process, so this is the ordinary race, not an error in the caller.
    let Some(target) = pid_to_task_raw(target_pid) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };

    // `p = find_lock_task_mm(task); if (!p) { ret = -ESRCH; ... }` — a task
    // with no mm has nothing to release. In NARF that is a kernel task, or
    // one whose address space has already been torn down.
    let Some(mm) = address_space_of_task(target) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };

    // `if (task_will_free_mem(p)) reap = true; else if
    // (!mm_flags_test(MMF_OOM_SKIP, mm)) ret = -EINVAL;`
    //
    // `__task_will_free_mem` is "already exiting, or carrying a fatal
    // signal". NARF spells the three states it has: a zombie has run its
    // exit, `group_exiting` is `exit_group(2)` in flight, and a pending
    // SIGKILL is a death that has been decided but not yet executed — which
    // is precisely the window this syscall exists to shorten.
    if !task_will_free_mem(target) {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }

    // `if (!mm_flags_test(MMF_OOM_SKIP, mm) && !__oom_reap_task_mm(mm)) ret =
    // -EAGAIN;`
    //
    // `sole_owner` is Linux's `mm_users <= 1` plus its "every task sharing
    // this mm is dying too" walk, in the form NARF's reaper already takes: an
    // `Arc` count of 1 means no scheduler slot still references the address
    // space, so no sibling thread can be mid-fault on it. The reaper returns
    // `Blocked` rather than reaping when that does not hold, which is exactly
    // the -EAGAIN the caller is expected to retry.
    let sole_owner = Arc::strong_count(&mm) == 1;
    let r = match mm.reap_anonymous_owned(sole_owner) {
        narf_memory::oom::ReapOutcome::Reaped(_) | narf_memory::oom::ReapOutcome::Nothing => {
            SyscallReturn::ok(0)
        }
        narf_memory::oom::ReapOutcome::Blocked => errno_ret(EAGAIN),
    };
    ctx.set_return(r);
}

/// `__task_will_free_mem` — is this task's memory on its way out anyway?
fn task_will_free_mem(task: u64) -> bool {
    let Some(t) = crate::task::task_get(task) else {
        // Not in the registry: it has already been reaped, so its memory is
        // gone by definition.
        return true;
    };
    if t.state.load(Ordering::Acquire) == crate::task::TASK_ZOMBIE {
        return true;
    }
    if t.group_exiting.load(Ordering::Acquire) {
        return true;
    }
    // A pending SIGKILL is a decided death. `sig_bit(9)`, not `1 << 9` —
    // signal N is bit N-1, and the off-by-one there names SIGUSR1.
    signal_pending_of(task) & sig_bit(9) != 0
}

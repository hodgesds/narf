#[allow(unused_imports)]
use super::*;

/// `process_madvise(pidfd, iov, iovcnt, advice, flags)` — apply `advice`
/// to ranges in a target process's address space. NARF supports the
/// caller's own AS (the common self-advise use); a foreign AS returns
/// EPERM. Returns the number of bytes advised.
pub(crate) fn sys_process_madvise(ctx: &mut dyn TrapContext) {
    const MADV_DONTNEED: i32 = 4;
    const MADV_FREE: i32 = 8;
    let a = *ctx.args();
    let pidfd = a.arg0 as u32;
    let iovcnt = a.arg2 as usize;
    let advice = a.arg3 as i32;
    let flags = a.arg4 as u32;
    // mm/madvise.c:2118-2131: `flags != 0` (-EINVAL), then the iovec import
    // (more than UIO_MAXIOV segments -EINVAL, a fault -EFAULT), then
    // `pidfd_get_task`: not a pidfd -EBADF; it resolves PIDTYPE_TGID, so a
    // PIDFD_THREAD pidfd naming a non-leader, or a reaped process, is -ESRCH.
    if flags != 0 || iovcnt > 1024 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let Some(iov) = read_iovecs(a.arg1, iovcnt) else {
        ctx.set_return(errno_ret(EFAULT));
        return;
    };
    let task = current_task_id();
    let Some(target_pid) = fd::with_table(task, |t| {
        t.get(pidfd).and_then(|e| e.ops.pidfd_target_pid())
    })
    .flatten() else {
        ctx.set_return(errno_ret(EBADF));
        return;
    };
    // The pidfd is keyed by an outer id, never a scheduler TaskId; only a
    // thread-group leader's pid names a TGID task.
    let Some(target) = pid_to_task_raw(target_pid)
        .filter(|&t| t == task || crate::task::task_get(t).is_some())
    else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };
    // LINUX-GAP: only the caller's own mm can be advised. Linux would go on
    // to mm_access / process_madvise_remote_valid / CAP_SYS_NICE for a
    // remote mm; NARF refuses every remote one with -EPERM.
    if !shares_mm(task, target) {
        ctx.set_return(errno_ret(EPERM));
        return;
    }
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(no_address_space());
            return;
        }
    };
    let mut total: u64 = 0;
    for (base, len) in iov {
        // Same split as sys_madvise: DONTNEED keeps the eager "next read
        // observes zeros" contract, FREE takes the lazy mark-discardable
        // path (see AddressSpace::madvise_free).
        if advice == MADV_DONTNEED {
            let _ = as_ref.madvise_dontneed(VirtAddr::new(base), len);
        } else if advice == MADV_FREE {
            let _ = as_ref.madvise_free(VirtAddr::new(base), len);
        }
        total = total.saturating_add(len);
    }
    ctx.set_return(SyscallReturn::ok(total));
}

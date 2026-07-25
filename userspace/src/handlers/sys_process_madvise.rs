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
    if iovcnt > 1024 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let task = current_task_id();
    let target_pid = match fd::with_table(task, |t| {
        t.get(pidfd).and_then(|e| e.ops.pidfd_target_pid())
    })
    .flatten()
    {
        Some(p) => p,
        None => {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
            return;
        }
    };
    // The pidfd was opened on getpid() = the VISIBLE ProcessId, so a self
    // pidfd's target_pid is the visible pid, not the raw TaskId — accept either
    // as "self" (otherwise a self-directed process_madvise wrongly EPERMs, seen
    // as mem2_smoke `mem2-fail: process_madvise`).
    let self_pid = task_to_pid_raw(task).unwrap_or(task);
    if target_pid != task && target_pid != self_pid {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM (foreign AS)
        return;
    }
    let as_ref = match current_address_space() {
        Some(a) => a,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    let iov = match read_iovecs(a.arg1, iovcnt) {
        Some(v) => v,
        None => {
            ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
            return;
        }
    };
    let mut total: u64 = 0;
    for (base, len) in iov {
        if advice == MADV_DONTNEED || advice == MADV_FREE {
            let _ = as_ref.madvise_dontneed(VirtAddr::new(base), len);
        }
        total = total.saturating_add(len);
    }
    ctx.set_return(SyscallReturn::ok(total));
}

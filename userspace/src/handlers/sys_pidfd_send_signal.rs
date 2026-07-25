#[allow(unused_imports)]
use super::*;

/// `pidfd_send_signal(pidfd, sig, info, flags)` — deliver `sig` to the
/// process referenced by `pidfd` (resolved via the FileOps hook),
/// reusing the same pending-signal queue as `kill(2)`.
pub(crate) fn sys_pidfd_send_signal(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let pidfd = a.arg0 as u32;
    let signum = a.arg1 as u32;
    if signum > 64 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    let task = current_task_id();
    let pid = fd::with_table(task, |t| {
        t.get(pidfd).and_then(|e| e.ops.pidfd_target_pid())
    })
    .flatten();
    let pid = match pid {
        Some(p) => p,
        None => {
            ctx.set_return(SyscallReturn::ok((-9i64) as u64)); // EBADF
            return;
        }
    };
    // sig 0 is an existence/permission probe — don't queue anything.
    if signum == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // SIGNAL_PENDING is keyed by TaskId; translate pid → tid.
    let mut target = pid;
    if let Some(tid) = pid_to_task_raw(target) {
        target = tid;
    }
    signal_stopcont_interaction(target, signum);
    {
        let mut g = SIGNAL_PENDING.lock();
        match g.as_mut() {
            Some(map) => *map.entry(target).or_insert(0) |= sig_bit(signum),
            None => {
                ctx.set_return(SyscallReturn::ok((-1i64) as u64));
                return;
            }
        }
    }
    wake_signal(target);
    ctx.set_return(SyscallReturn::ok(0));
}

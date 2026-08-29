#[allow(unused_imports)]
use super::*;

/// `pidfd_send_signal(pidfd, sig, info, flags)` — deliver `sig` to the
/// process referenced by `pidfd` (resolved via the FileOps hook),
/// reusing the same pending-signal queue as `kill(2)`.
///
/// A non-NULL `info` makes this the `rt_sigqueueinfo(2)` of the pidfd world:
/// the caller's `siginfo_t` (`si_code`, `si_pid`, `si_value`) travels with the
/// signal and MUST reach the target's `signalfd` / `sigtimedwait` read. Losing
/// it is not cosmetic — systemd's `pidref_sigqueue()` sends `SI_QUEUE` with
/// `si_pid = getpid()`, and a udev worker's `on_sigusr1` drops any SIGUSR1
/// whose `ssi_pid` is not its manager. With the payload discarded the worker
/// read `ssi_pid == 0`, ignored the manager's acknowledgement, and blocked in
/// `udev_watch_end()` forever: every device event with a devname wedged its
/// worker, `/run/udev/data` stayed empty, and udevd accumulated stuck children
/// while `udevadm settle` timed out.
pub(crate) fn sys_pidfd_send_signal(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let pidfd = a.arg0 as u32;
    let signum = a.arg1 as u32;
    let flags = a.arg3 as u32;
    // NARF does not yet implement Linux's signal-scope override flags. Reject
    // every nonzero value before touching the fd or user siginfo.
    if flags != 0 {
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
    // SIGNAL_PENDING is keyed by TaskId; translate pid → tid.
    let mut target = pid;
    if let Some(tid) = pid_to_task_raw(target) {
        target = tid;
    }
    let imported = if a.arg2 == 0 {
        None
    } else {
        let info = match import_queued_siginfo(a.arg2) {
            Ok(info) => info,
            Err(_) => {
                ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
                return;
            }
        };
        if info.signo != signum {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
            return;
        }
        if siginfo_requires_self_target(info) && target != task {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
            return;
        }
        Some(info)
    };
    // A pidfd keeps its numeric identity after exit; signal delivery must still
    // resolve a live task. This also precedes signal-number validation in Linux.
    if !signal_target_exists(target) {
        ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
        return;
    }
    if signum > 64 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    // sig 0 is an existence/permission probe — don't queue anything.
    if signum == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if let Some(info) = imported {
        // Store the payload and set the pending bit atomically so a racing
        // sigwait consumer can't strand the bit over an emptied queue (the sigq
        // spurious-sival=0 bug). A full queue is EAGAIN with nothing delivered.
        if sigqueue_deliver_imported(target, signum, info).is_none() {
            ctx.set_return(SyscallReturn::ok((-11i64) as u64)); // EAGAIN
            return;
        }
    } else {
        // NULL info is a kill(2)-shaped send: Linux's prepare_kill_siginfo
        // fills SI_USER with the sender's pid in the receiver's namespace
        // (do_pidfd_send_signal). Record it so the receiver's signalfd names
        // the sender, matching kill/tkill/tgkill.
        queue_sender_siginfo(target, signum);
        raise_signal_pending(target, signum);
    }
    ctx.set_return(SyscallReturn::ok(0));
}

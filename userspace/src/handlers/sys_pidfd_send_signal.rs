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
    // Stash the payload BEFORE the pending bit is visible, so a consumer that
    // observes the bit never races ahead of its own siginfo. A full queue is
    // -EAGAIN with nothing delivered (RLIMIT_SIGPENDING shape), matching
    // rt_sigqueueinfo.
    if !capture_queued_siginfo(target, signum, a.arg2) {
        ctx.set_return(SyscallReturn::ok((-11i64) as u64)); // -EAGAIN
        return;
    }
    if signal_bits_update(&SIGNAL_PENDING, target, |slot| *slot |= sig_bit(signum)).is_none() {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64));
        return;
    }
    wake_signal(target);
    ctx.set_return(SyscallReturn::ok(0));
}

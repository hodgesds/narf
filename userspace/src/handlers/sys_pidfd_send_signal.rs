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
    // [PROBE] Name the SENDER of a termination signal to a user-957 /
    // systemd-manager task. pidfd_send_signal is the path modern systemd uses to
    // signal its services, and it sets SIGNAL_PENDING DIRECTLY (bypassing
    // raise_signal_pending, where the twin probe lives), so a user@957 SIGTERM
    // was invisible until this hook. cgevt_trace-gated, termination signals only.
    if narf_filesystem::cgroupfs::cgevt_trace_enabled() && matches!(signum, 6 | 15) {
        let tgt_comm = proc_comm_of_task(target).unwrap_or_default();
        let tgt_cg = narf_filesystem::cgroupfs::cgroup_path_of(pid);
        if tgt_comm == "systemd"
            || tgt_comm.starts_with("(sd")
            || tgt_comm.starts_with("(systemd")
            || tgt_cg.contains("user-957")
        {
            let sender_pid = task_to_pid_raw(task).unwrap_or(task);
            let sender_comm = proc_comm_of_task(task).unwrap_or_default();
            use core::fmt::Write as _;
            let _ = writeln!(
                narf_console::Writer,
                "SIGSEND(pidfd) sig={} -> pid={} comm={} cg={} FROM pid={} comm={}",
                signum,
                pid,
                tgt_comm,
                tgt_cg,
                sender_pid,
                sender_comm
            );
        }
    }
    signal_stopcont_interaction(target, signum);
    if a.arg2 == 0 {
        // NULL info is a kill(2)-shaped send: Linux's prepare_kill_siginfo
        // fills SI_USER with the sender's pid in the receiver's namespace
        // (do_pidfd_send_signal). Record it so the receiver's signalfd names
        // the sender, matching kill/tkill/tgkill.
        queue_sender_siginfo(target, signum);
    } else if !capture_queued_siginfo(target, signum, a.arg2) {
        // Non-NULL info: the caller's own siginfo (systemd's pidref_sigqueue
        // sends SI_QUEUE). Stashed BEFORE the pending bit is visible so a
        // consumer that observes the bit never races ahead of its siginfo. A
        // full queue is -EAGAIN with nothing delivered (rt_sigqueueinfo shape).
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

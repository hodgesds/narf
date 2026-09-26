#[allow(unused_imports)]
use super::*;

/// `kernel/sched/syscalls.c::SYSCALL_DEFINE2(sched_rr_get_interval, pid_t,
/// pid, struct __kernel_timespec __user *, interval)`.
///
/// ```text
/// static int sched_rr_get_interval(pid_t pid, struct timespec64 *t)
/// {
///         if (pid < 0)                            return -EINVAL;
///         struct task_struct *p = find_process_by_pid(pid);
///         if (!p)                                 return -ESRCH;
///         if (p->sched_class->get_rr_interval)
///                 time_slice = p->sched_class->get_rr_interval(rq, p);
///         jiffies_to_timespec64(time_slice, t);
/// }
/// /* then */
/// if (retval == 0)
///         retval = put_timespec64(&t, interval);   /* -EFAULT */
/// ```
///
/// The quantum is per class: SCHED_RR reports `sched_rr_timeslice`
/// (100 ms), SCHED_FIFO 0, SCHED_DEADLINE 0 (the class has no
/// `get_rr_interval`), and the fair class `NS_TO_JIFFIES(se.slice)` — which
/// at this model's HZ truncates the default sub-10 ms slice to 0 and only a
/// larger custom `sched_setattr` slice shows through.
///
/// The destination is written only after the pid resolves, per the
/// `if (retval == 0)` guard above.
pub(crate) fn sys_sched_rr_get_interval(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `pid_t` is `int` — the argument is the low 32 bits, sign-extended.
    let pid = args.arg0 as i32;
    let buf = args.arg1;
    if pid < 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let Some(task) = find_process_by_pid(pid) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };
    let st = read_sched_state(task);
    const NSEC_PER_JIFFY: u64 = 1_000_000_000 / SCHED_HZ;
    let slice_ns = match st.policy {
        SCHED_RR => SCHED_RR_TIMESLICE_NS,
        SCHED_FIFO | SCHED_DEADLINE => 0,
        // `get_rr_interval_fair`: whole jiffies of `se.slice`.
        _ => task_slice_ns(&st) / NSEC_PER_JIFFY * NSEC_PER_JIFFY,
    };
    let mut kbuf = [0u8; 16];
    kbuf[..8].copy_from_slice(&((slice_ns / 1_000_000_000) as i64).to_ne_bytes());
    kbuf[8..].copy_from_slice(&((slice_ns % 1_000_000_000) as i64).to_ne_bytes());
    // `put_timespec64(&t, interval)`. A NULL destination fails range
    // validation here, which is Linux's path: there is no separate null
    // check.
    // SAFETY: copy_to_user range-validates `buf` (including the null case)
    // and SMAP-brackets the 16-byte write.
    if unsafe { copy_to_user(buf, &kbuf) }.is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

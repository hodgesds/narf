#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_getrusage(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `who` is a C int (SYSCALL_DEFINE2(getrusage, int, who, ...)): only the
    // low 32 bits count, so a -1 passed through a 32-bit register is
    // RUSAGE_CHILDREN whatever the upper half holds.
    let who = i64::from(args.arg0 as u32 as i32);
    let out = args.arg1;
    // kernel/sys.c getrusage(): RUSAGE_SELF is the whole thread group
    // (`thread_group_cputime_adjusted`), RUSAGE_THREAD the calling thread
    // (`task_cputime_adjusted(current)`), RUSAGE_CHILDREN the group's reaped
    // children (`sig->cutime/cstime`). The times are the scheduler's exact
    // user/kernel accounting.
    const RUSAGE_SELF: i64 = 0;
    const RUSAGE_CHILDREN: i64 = -1;
    const RUSAGE_THREAD: i64 = 1;
    // Linux SYSCALL_DEFINE2(getrusage): an unknown `who` is -EINVAL, checked
    // BEFORE `ru` is touched (so a bad `who` beats a NULL ru); the copy-out —
    // including a NULL/faulting ru — is -EFAULT.
    if who != RUSAGE_SELF && who != RUSAGE_CHILDREN && who != RUSAGE_THREAD {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    if out == 0 {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    let task = current_task_id();
    let times = match who {
        RUSAGE_CHILDREN => children_cpu_times(task),
        RUSAGE_THREAD => thread_cpu_times(task),
        _ => process_cpu_times(task),
    };
    // ru_maxrss: the caller's own VM footprint for RUSAGE_SELF/THREAD; 0 for
    // RUSAGE_CHILDREN (no accumulated per-child peak — wait4 reports each
    // child's footprint at reap instead).
    let maxrss_kb = if who == RUSAGE_CHILDREN {
        0
    } else {
        task_rss_bytes(task) / 1024
    };
    if write_rusage(out, times, maxrss_kb).is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

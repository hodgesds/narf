#[allow(unused_imports)]
use super::*;

/// `sched_setparam(pid, param)` — Linux `do_sched_setscheduler`
/// (kernel/sched/syscalls.c): `!param || pid < 0` → -EINVAL, then
/// `copy_from_user(&lparam, param, …)` → -EFAULT.
/// LINUX-GAP: setscheduler's -EPERM/-ESRCH permission and policy checks are
/// not modelled beyond the caller-ns pid resolution below.
pub(crate) fn sys_sched_setparam(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0;
    let inp = args.arg1;
    // `pid` is a u64 here; a userspace negative pid arrives as a huge value and
    // fails the pid resolution below with -ESRCH. A NULL param is -EINVAL.
    if inp == 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }
    // Read one i32 from user space under the SMAP bracket.
    let mut buf = [0u8; 4];
    // SAFETY: `inp` is the user sched_param pointer (non-zero, checked above);
    // copy_from_user range-validates it and SMAP-brackets the 4-byte read.
    if unsafe { copy_from_user(&mut buf, inp) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // -EFAULT
        return;
    }
    let val = i32::from_ne_bytes(buf);
    // `pid` is resolved in the CALLER's pid namespace (Linux
    // kernel/sched/syscalls.c find_process_by_pid -> find_task_by_vpid),
    // exactly as sys_sched_setaffinity does. Translate inner -> outer -> TaskId
    // before keying the sched-param table; the raw inner pid keyed an unrelated
    // task. Audit finding #18.
    let task = if pid == 0 {
        current_task_id()
    } else {
        let Some(outer) = accept_pid_from(current_task_id(), pid) else {
            ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
            return;
        };
        proc_pid_to_tid(outer)
    };
    let mut g = SCHED_PARAM_TABLE.lock();
    let m = match g.as_mut() {
        Some(m) => m,
        None => {
            // Internal: the sched-param table is uninitialized (unreachable for
            // a live task). -EPERM is a valid setscheduler errno.
            ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
            return;
        }
    };
    m.insert(task, val);
    ctx.set_return(SyscallReturn::ok(0));
}

#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sched_getaffinity(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0;
    let size = args.arg1 as usize;
    let out = args.arg2;
    // Linux requires enough bits for nr_cpu_ids and native-word alignment.
    if size < 8 || size & 7 != 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if out == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }

    let caller = current_task_id();
    let task = if pid == 0 {
        caller
    } else {
        let Some(outer) = accept_pid_from(caller, pid) else {
            ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
            return;
        };
        match pid_to_task_raw(outer) {
            Some(task) => task,
            None if narf_scheduler::task_affinity(narf_scheduler::TaskId(outer)).is_some() => outer,
            None => {
                ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
                return;
            }
        }
    };
    let Some(mask) = narf_scheduler::task_affinity(narf_scheduler::TaskId(task)) else {
        ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
        return;
    };
    let effective = mask.intersection(narf_scheduler::online_cpu_set());
    let bytes = effective.bits().to_ne_bytes();
    // SAFETY: copy_to_user range-validates and SMAP-brackets the write.
    if unsafe { copy_to_user(out, &bytes) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    ctx.set_return(SyscallReturn::ok(bytes.len() as u64));
}

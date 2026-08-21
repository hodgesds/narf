#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_sched_setaffinity(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0;
    let size = args.arg1 as usize;
    let buf = args.arg2;
    if size == 0 {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        return;
    }
    if buf == 0 {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    // Linux clears the kernel-sized mask first, then copies at most that many
    // bytes from a shorter/longer userspace cpu_set_t.
    let mut mask_bytes = [0u8; 8];
    let copy_len = size.min(mask_bytes.len());
    // SAFETY: copy_from_user range-validates and SMAP-brackets this read.
    if unsafe { copy_from_user(&mut mask_bytes[..copy_len], buf) }.is_err() {
        ctx.set_return(SyscallReturn::ok((-14i64) as u64)); // EFAULT
        return;
    }
    let requested = narf_scheduler::CpuSet::from_bits(u64::from_ne_bytes(mask_bytes));
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

    // Linux permits the owner (or CAP_SYS_NICE) to change a task's mask.
    // NARF has no ambient root authority; matching real/effective uid is the
    // compatibility bridge for a parent updating its own child.
    if task != caller {
        let me = read_uidgid(caller);
        let target = read_uidgid(task);
        if me.euid != target.uid && me.euid != target.euid {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // EPERM
            return;
        }
    }

    match narf_scheduler::set_task_affinity(narf_scheduler::TaskId(task), requested) {
        Ok(()) => {
            let effective = narf_scheduler::task_affinity(narf_scheduler::TaskId(task))
                .unwrap_or(narf_scheduler::CpuSet::EMPTY);
            if task == caller
                && !effective
                    .contains(narf_scheduler::CpuId(narf_lib::percpu::current_cpu() as u32))
            {
                // The stackful continuation itself remains live until the
                // syscall-exit boundary; request a cooperative switch there.
                #[cfg(target_arch = "x86_64")]
                narf_scheduler::stackful::request_syscall_backpressure_yield();
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        Err(narf_scheduler::SetAffinityError::TaskNotFound) => {
            ctx.set_return(SyscallReturn::ok((-3i64) as u64)); // ESRCH
        }
        Err(narf_scheduler::SetAffinityError::NoOnlineCpu) => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL
        }
        Err(narf_scheduler::SetAffinityError::RealtimePinned) => {
            ctx.set_return(SyscallReturn::ok((-16i64) as u64)); // EBUSY
        }
    }
}

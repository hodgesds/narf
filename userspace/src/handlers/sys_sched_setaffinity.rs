#[allow(unused_imports)]
use super::*;

/// `kernel/sched/syscalls.c::SYSCALL_DEFINE3(sched_setaffinity, pid_t, pid,
/// unsigned int, len, unsigned long __user *, user_mask_ptr)`.
///
/// ```text
/// retval = get_user_cpu_mask(user_mask_ptr, len, new_mask);   /* -EFAULT */
/// if (retval == 0) retval = sched_setaffinity(pid, new_mask);
///
/// long sched_setaffinity(pid_t pid, const struct cpumask *in_mask) {
///         p = find_get_task(pid);           if (!p) return -ESRCH;
///         if (!check_same_owner(p) &&
///             !ns_capable(__task_cred(p)->user_ns, CAP_SYS_NICE))
///                                           return -EPERM;
///         __sched_setaffinity(p, &ac);
///             dl_task_check_affinity()      -> -EBUSY
///             __set_cpus_allowed_ptr()      -> -EINVAL (no active CPU)
/// }
/// ```
///
/// Order matters, and differs from the obvious one: `len == 0` is NOT
/// rejected up front. `get_user_cpu_mask` clears the mask and copies zero
/// bytes (so even a NULL pointer does not fault), and the empty mask is
/// only refused -EINVAL at the very end — after a missing pid has
/// answered -ESRCH and someone else's task -EPERM.
pub(crate) fn sys_sched_setaffinity(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    // `pid_t pid`, `unsigned int len` — the low 32 bits of each.
    let pid = args.arg0 as i32;
    let len = args.arg1 as u32 as usize;
    let buf = args.arg2;
    // `get_user_cpu_mask`: a shorter mask is zero-extended, a longer one
    // truncated to `cpumask_size()`.
    let mut mask_bytes = [0u8; 8];
    let copy_len = len.min(mask_bytes.len());
    if copy_len != 0 {
        // SAFETY: copy_from_user range-validates and SMAP-brackets this read.
        if unsafe { copy_from_user(&mut mask_bytes[..copy_len], buf) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
    }
    let requested = narf_scheduler::CpuSet::from_bits(u64::from_ne_bytes(mask_bytes));
    let caller = current_task_id();
    let Some(task) = resolve_affinity_target(caller, pid) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };

    // `check_same_owner(p)`, else CAP_SYS_NICE in the TARGET's user
    // namespace. Without the capability arm a privileged caller could not
    // pin another user's task at all.
    if task != caller && !sched_check_same_owner(task) && !capable_over_task(task, CAP_SYS_NICE)
    {
        ctx.set_return(errno_ret(EPERM));
        return;
    }

    // `dl_task_check_affinity`: a SCHED_DEADLINE task must stay runnable on
    // every CPU of its root domain, or its admitted bandwidth is fiction.
    let span = narf_scheduler::online_cpu_set();
    if dl_policy(read_sched_state(task).policy)
        && span.bits() & !requested.bits() != 0
    {
        ctx.set_return(errno_ret(EBUSY));
        return;
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
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                narf_scheduler::stackful::request_syscall_backpressure_yield();
            }
            ctx.set_return(SyscallReturn::ok(0));
        }
        Err(narf_scheduler::SetAffinityError::TaskNotFound) => {
            ctx.set_return(errno_ret(ESRCH));
        }
        Err(narf_scheduler::SetAffinityError::NoOnlineCpu) => {
            ctx.set_return(errno_ret(EINVAL));
        }
        Err(narf_scheduler::SetAffinityError::RealtimePinned) => {
            ctx.set_return(errno_ret(EBUSY));
        }
    }
}

/// `find_process_by_pid` for the affinity pair, resolved to the scheduler
/// TaskId that owns the mask. Linux does NOT refuse a negative pid with
/// -EINVAL here (unlike the policy calls) — `find_task_by_vpid(-1)` simply
/// finds nothing, so it is -ESRCH.
///
/// A kernel-spawned task with no ProcessId binding is still addressable by
/// its raw TaskId while the scheduler knows its mask.
pub(crate) fn resolve_affinity_target(caller: u64, pid: i32) -> Option<u64> {
    if pid == 0 {
        return Some(caller);
    }
    if pid < 0 {
        return None;
    }
    let outer = accept_pid_from(caller, pid as u64)?;
    match pid_to_task_raw(outer) {
        Some(task) => Some(task),
        None if narf_scheduler::task_affinity(narf_scheduler::TaskId(outer)).is_some() => {
            Some(outer)
        }
        None => None,
    }
}

#[allow(unused_imports)]
use super::*;

/// `kernel/sched/syscalls.c::SYSCALL_DEFINE3(sched_getaffinity, pid_t, pid,
/// unsigned int, len, unsigned long __user *, user_mask_ptr)`.
///
/// ```text
/// if ((len * BITS_PER_BYTE) < nr_cpu_ids)          return -EINVAL;
/// if (len & (sizeof(unsigned long)-1))             return -EINVAL;
/// ret = sched_getaffinity(pid, mask);              /* -ESRCH */
/// if (ret == 0) {
///         unsigned int retlen = min(len, cpumask_size());
///         if (copy_to_user(user_mask_ptr, mask, retlen)) ret = -EFAULT;
///         else ret = retlen;
/// }
/// ```
///
/// There is no up-front NULL check: a NULL mask pointer with a pid that
/// names nothing is -ESRCH, and only a live pid reaches the -EFAULT copy.
/// `len` is `unsigned int`, so `len * 8` wraps — a caller passing
/// 0x2000_0000 gets -EINVAL on Linux, and gets it here too.
pub(crate) fn sys_sched_getaffinity(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let pid = args.arg0 as i32;
    let len = args.arg1 as u32;
    let out = args.arg2;
    // `nr_cpu_ids` — one past the highest possible CPU. NARF's mask is one
    // `unsigned long`, so every CPU fits in 64 bits.
    let online = narf_scheduler::online_cpu_set().bits();
    let nr_cpu_ids = (64 - online.leading_zeros()).max(1);
    if len.wrapping_mul(8) < nr_cpu_ids || len & 7 != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }

    let Some(task) = handler_sys_sched_setaffinity::resolve_affinity_target(current_task_id(), pid)
    else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };
    let Some(mask) = narf_scheduler::task_affinity(narf_scheduler::TaskId(task)) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };
    let effective = mask.intersection(narf_scheduler::online_cpu_set());
    let bytes = effective.bits().to_ne_bytes();
    // `retlen = min(len, cpumask_size())`; `len` is a non-zero multiple of 8.
    // SAFETY: copy_to_user range-validates (including NULL) and
    // SMAP-brackets the write.
    if unsafe { copy_to_user(out, &bytes) }.is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(bytes.len() as u64));
}

//! `sched_getattr(2)` — `kernel/sched/syscalls.c`.

#[allow(unused_imports)]
use super::*;

/// `SYSCALL_DEFINE4(sched_getattr, pid_t pid, struct sched_attr __user *uattr,
/// unsigned int usize, unsigned int flags)`.
///
/// ```text
/// if (unlikely(!uattr || pid < 0 || usize > PAGE_SIZE ||
///              usize < SCHED_ATTR_SIZE_VER0 || flags))
///         return -EINVAL;
/// p = find_process_by_pid(pid); if (!p) return -ESRCH;
/// kattr.sched_policy = p->policy;
/// if (p->sched_reset_on_fork)
///         kattr.sched_flags |= SCHED_FLAG_RESET_ON_FORK;
/// get_params(p, &kattr);
/// kattr.sched_flags &= SCHED_FLAG_ALL;
/// kattr.size = min(usize, sizeof(kattr));
/// return copy_struct_to_user(uattr, usize, &kattr, sizeof(kattr), NULL);
/// ```
///
/// Note the asymmetry with `sched_setattr`: an unusable `usize` is -EINVAL
/// here, where the setter answers -E2BIG. The setter is negotiating about a
/// struct the CALLER wrote and can rewrite; the getter is being handed a
/// buffer, and a buffer that cannot hold the first published version is
/// simply a bad argument.
///
/// The struct is built from the task's live state, not replayed from the
/// bytes the last `sched_setattr` stored: a nice set through setpriority, a
/// policy set through sched_setscheduler, and the fair-class slice all show
/// up here as they do on Linux.
pub(crate) fn sys_sched_getattr(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let uattr = a.arg1;
    let pid = a.arg0 as i32;
    let usize_bytes = a.arg2 as u32 as usize;
    // `usize > PAGE_SIZE || usize < SCHED_ATTR_SIZE_VER0` — one range.
    if uattr == 0
        || pid < 0
        || !(SCHED_ATTR_SIZE_VER0..=4096).contains(&usize_bytes)
        || a.arg3 as u32 != 0
    {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let Some(task) = find_process_by_pid(pid) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };

    let st = read_sched_state(task);
    let mut kattr = SchedAttr {
        policy: st.policy,
        flags: if st.reset_on_fork {
            SCHED_FLAG_RESET_ON_FORK
        } else {
            0
        },
        ..SchedAttr::default()
    };
    sched_get_params(task, &st, &mut kattr);
    kattr.flags &= SCHED_FLAG_ALL;
    // `kattr.size = min(usize, sizeof(kattr))` — what this kernel actually
    // filled in, so a caller with a larger buffer can tell how much of it
    // is meaningful rather than reading the zero padding below as data.
    kattr.size = usize_bytes.min(SCHED_ATTR_SIZE) as u32;

    // `copy_struct_to_user`: `if (usize > ksize) clear_user(dst + size,
    // rest);` then `copy_to_user(dst, src, size)` — both -EFAULT.
    //
    // ZERO the rest of the caller's buffer. Leaving it alone hands back
    // whatever was already there as though this kernel had written it: a
    // caller compiled against VER1 would read its own stack garbage as
    // `sched_util_min`/`max` and have no way to know.
    if usize_bytes > SCHED_ATTR_SIZE {
        let zeros = alloc::vec![0u8; usize_bytes - SCHED_ATTR_SIZE];
        // SAFETY: copy_to_user range-validates the tail, which lies inside
        // the caller-declared buffer.
        if unsafe { copy_to_user(uattr + SCHED_ATTR_SIZE as u64, &zeros) }.is_err() {
            ctx.set_return(errno_ret(EFAULT));
            return;
        }
    }
    // SAFETY: copy_to_user range-validates the write.
    if unsafe { copy_to_user(uattr, &kattr.to_bytes()) }.is_err() {
        ctx.set_return(errno_ret(EFAULT));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

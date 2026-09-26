//! `sched_setattr(2)` — `kernel/sched/syscalls.c`.

#[allow(unused_imports)]
use super::*;

/// `sched_copy_attr` — returns the normalised attr, or a positive errno.
fn copy_attr(uattr: u64) -> Result<SchedAttr, i64> {
    // `err_size` writes `sizeof(*attr)` back before failing. Best-effort:
    // the errno stands even if the caller's buffer turned out unwritable,
    // matching `put_user`'s return being ignored on this path.
    let err_size = || {
        // SAFETY: copy_to_user range-validates the four bytes; a failure is
        // deliberately not propagated, as in Linux.
        let _ = unsafe { copy_to_user(uattr, &(SCHED_ATTR_SIZE as u32).to_ne_bytes()) };
        E2BIG
    };

    let mut size_buf = [0u8; 4];
    // SAFETY: copy_from_user range-validates the four-byte read.
    if unsafe { copy_from_user(&mut size_buf, uattr) }.is_err() {
        return Err(EFAULT);
    }
    let mut size = u32::from_ne_bytes(size_buf) as usize;
    // `if (!size) size = SCHED_ATTR_SIZE_VER0;`
    if size == 0 {
        size = SCHED_ATTR_SIZE_VER0;
    }
    // `if (size < SCHED_ATTR_SIZE_VER0 || size > PAGE_SIZE) goto err_size;`
    if !(SCHED_ATTR_SIZE_VER0..=4096).contains(&size) {
        return Err(err_size());
    }

    let known = size.min(SCHED_ATTR_SIZE);
    let mut bytes = [0u8; SCHED_ATTR_SIZE];
    // SAFETY: copy_from_user range-validates the read; `known` is at most
    // the struct this kernel knows.
    if unsafe { copy_from_user(&mut bytes[..known], uattr) }.is_err() {
        return Err(EFAULT);
    }

    // `copy_struct_from_user`: every byte past the struct THIS kernel knows
    // must be zero. Truncating instead would silently discard a field the
    // caller set and believes is in effect — which is the whole reason the
    // extensible-struct rule exists.
    if size > SCHED_ATTR_SIZE {
        let rest = size - SCHED_ATTR_SIZE;
        // SAFETY: copy_from_user_vec range-validates the tail, which lies
        // inside the caller-declared struct.
        let tail = match unsafe { copy_from_user_vec(uattr + SCHED_ATTR_SIZE as u64, rest) } {
            Ok(v) => v,
            Err(_) => return Err(EFAULT),
        };
        if tail.iter().any(|&b| b != 0) {
            return Err(err_size());
        }
    }

    let mut attr = SchedAttr::from_bytes(&bytes);
    // `if ((attr->sched_flags & SCHED_FLAG_UTIL_CLAMP) && size <
    // SCHED_ATTR_SIZE_VER1) return -EINVAL;`
    //
    // -EINVAL here, NOT the -E2BIG above: the size was acceptable, the
    // combination was not.
    if attr.flags & SCHED_FLAG_UTIL_CLAMP != 0 && size < SCHED_ATTR_SIZE_VER1 {
        return Err(EINVAL);
    }
    // "XXX: Do we want to be lenient like existing syscalls; or do we want
    // to be strict and return an error on out-of-bounds values?" — Linux
    // chose lenient: the nice is clamped, not refused.
    attr.nice = attr.nice.clamp(-20, 19);
    Ok(attr)
}

/// `SYSCALL_DEFINE3(sched_setattr, pid_t pid, struct sched_attr __user *uattr,
/// unsigned int flags)`.
///
/// ```text
/// if (unlikely(!uattr || pid < 0 || flags))            return -EINVAL;
/// retval = sched_copy_attr(uattr, &attr);               /* E2BIG/EFAULT/EINVAL */
/// if ((int)attr.sched_policy < 0)                       return -EINVAL;
/// if (attr.sched_flags & SCHED_FLAG_KEEP_POLICY)
///         attr.sched_policy = SETPARAM_POLICY;
/// CLASS(find_get_task, p)(pid); if (!p)                 return -ESRCH;
/// if (attr.sched_flags & SCHED_FLAG_KEEP_PARAMS)
///         get_params(p, &attr);
/// return sched_setattr(p, &attr);                       /* __sched_setscheduler */
/// ```
///
/// This used to store the raw struct bytes after checking only the flag
/// mask — so an unknown flag beat -ESRCH, SCHED_FIFO at priority 0 and a
/// SCHED_DEADLINE triple that fails `__checkparam_dl` both succeeded, an
/// unprivileged task could claim a deadline reservation, and the nice it
/// asked for never reached getpriority. The whole of `__sched_setscheduler`
/// now runs, in [`sched_setscheduler_checked`].
pub(crate) fn sys_sched_setattr(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let uattr = a.arg1;
    // `pid_t pid`, `unsigned int flags` — the low 32 bits of each.
    let pid = a.arg0 as i32;
    if uattr == 0 || pid < 0 || a.arg2 as u32 != 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    let mut attr = match copy_attr(uattr) {
        Ok(a) => a,
        Err(e) => {
            ctx.set_return(errno_ret(e));
            return;
        }
    };
    // `if ((int)attr.sched_policy < 0) return -EINVAL;` — the cast is
    // load-bearing: `sched_policy` is a `__u32`.
    if attr.policy < 0 {
        ctx.set_return(errno_ret(EINVAL));
        return;
    }
    if attr.flags & SCHED_FLAG_KEEP_POLICY != 0 {
        attr.policy = SETPARAM_POLICY;
    }
    let Some(task) = find_process_by_pid(pid) else {
        ctx.set_return(errno_ret(ESRCH));
        return;
    };
    if attr.flags & SCHED_FLAG_KEEP_PARAMS != 0 {
        let st = read_sched_state(task);
        sched_get_params(task, &st, &mut attr);
    }
    match sched_setscheduler_checked(task, &attr) {
        Ok(()) => ctx.set_return(SyscallReturn::ok(0)),
        Err(e) => ctx.set_return(errno_ret(e)),
    }
}

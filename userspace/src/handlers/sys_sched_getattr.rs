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
/// ...
/// kattr.size = min(usize, sizeof(kattr));
/// return copy_struct_to_user(uattr, usize, &kattr, sizeof(kattr), NULL);
/// ```
///
/// Note the asymmetry with `sched_setattr`: an unusable `usize` is -EINVAL
/// here, where the setter answers -E2BIG. The setter is negotiating about a
/// struct the CALLER wrote and can rewrite; the getter is being handed a
/// buffer, and a buffer that cannot hold the first published version is
/// simply a bad argument.
pub(crate) fn sys_sched_getattr(ctx: &mut dyn TrapContext) {
    const EINVAL: i64 = -22;
    const EFAULT: i64 = -14;
    const ESRCH: i64 = -3;

    let a = *ctx.args();
    let uattr = a.arg1;
    let pid = a.arg0 as u32 as i32;
    let usize_bytes = a.arg2 as u32 as usize;
    // `usize > PAGE_SIZE || usize < SCHED_ATTR_SIZE_VER0` — one range.
    if uattr == 0
        || pid < 0
        || !(SCHED_ATTR_SIZE_VER0..=4096).contains(&usize_bytes)
        || a.arg3 != 0
    {
        ctx.set_return(SyscallReturn::ok(EINVAL as u64));
        return;
    }
    let Some(task) = handler_sys_sched_setattr::resolve_sched_target(pid as u64) else {
        ctx.set_return(SyscallReturn::ok(ESRCH as u64));
        return;
    };

    let mut buf = SCHED_ATTR_TABLE
        .lock()
        .as_ref()
        .and_then(|m| m.get(&task).copied())
        .unwrap_or([0u8; SCHED_ATTR_SIZE]);
    // `kattr.size = min(usize, sizeof(kattr))` — what this kernel actually
    // filled in, so a caller with a larger buffer can tell how much of it
    // is meaningful rather than reading the zero padding below as data.
    let reported = usize_bytes.min(SCHED_ATTR_SIZE) as u32;
    buf[0..4].copy_from_slice(&reported.to_ne_bytes());

    // SAFETY: copy_to_user range-validates the write.
    if unsafe { copy_to_user(uattr, &buf) }.is_err() {
        ctx.set_return(SyscallReturn::ok(EFAULT as u64));
        return;
    }
    // `if (usize > ksize) clear_user(dst + size, rest);` — ZERO the rest of
    // the caller's buffer. Leaving it alone hands back whatever was already
    // there as though this kernel had written it: a caller compiled against
    // VER1 would read its own stack garbage as `sched_util_min`/`max` and
    // have no way to know.
    if usize_bytes > SCHED_ATTR_SIZE {
        let rest = usize_bytes - SCHED_ATTR_SIZE;
        let zeros = alloc::vec![0u8; rest];
        // SAFETY: copy_to_user range-validates the tail, which lies inside
        // the caller-declared buffer.
        if unsafe { copy_to_user(uattr + SCHED_ATTR_SIZE as u64, &zeros) }.is_err() {
            ctx.set_return(SyscallReturn::ok(EFAULT as u64));
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}

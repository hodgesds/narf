#[allow(unused_imports)]
use super::*;

#[cfg(feature = "linux-compat")]
pub(crate) fn sys_fstat_linux(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let out_ptr = args.arg1 as *mut linux_compat::Stat;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let stat = fd::with_table(task, |t| {
        t.get(fd)
            .map(|e| (e.ops.stat(), e.ops.owners(), e.ops.rdev(), e.ops.ino()))
    });
    let (s, (uid, gid), rdev, ino) = match stat {
        Some(Some(tuple)) => tuple,
        _ => {
            ctx.set_return(fail);
            return;
        }
    };
    let out = linux_stat_from_fs(s, uid, gid, rdev, ino);
    // SAFETY: `out` is a live repr(C) Stat; the slice spans exactly its size
    // and borrows it for the duration of the copy below.
    // SAFETY: Valid memory or trusted environment
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &out as *const linux_compat::Stat as *const u8,
            core::mem::size_of::<linux_compat::Stat>(),
        )
    };
    // SAFETY: `out_ptr` is the user Stat pointer (null-checked above);
    // copy_to_user range-validates it and SMAP-brackets the write of `bytes`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out_ptr as u64, bytes) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

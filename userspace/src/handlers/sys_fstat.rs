#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_fstat(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let out_ptr = args.arg1 as *mut StatBuf;
    // See sys_stat for the failure-sentinel rationale.
    let fail = SyscallReturn::ok((-1i64) as u64);
    if out_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    let task = current_task_id();
    let stat = fd::with_table(task, |t| {
        t.get(fd).map(|e| StatBuf::from_stat(e.ops.stat()))
    });
    let stat = match stat {
        Some(Some(s)) => s,
        _ => {
            ctx.set_return(fail);
            return;
        }
    };
    // SAFETY: same contract as sys_stat above.
    let stat_bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(
            &stat as *const StatBuf as *const u8,
            core::mem::size_of::<StatBuf>(),
        )
    };
    // SAFETY: `out_ptr` is the user StatBuf pointer (null-checked above);
    // copy_to_user range-validates it and SMAP-brackets the write of `stat_bytes`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out_ptr as u64, stat_bytes) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

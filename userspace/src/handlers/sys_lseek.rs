#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_lseek(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let offset = args.arg1 as i64;
    let whence = args.arg2;
    let task = current_task_id();
    // Linux errno: bad fd → -EBADF; bad whence / negative or overflowing
    // result → -EINVAL (was a blanket InvalidOp).
    let ebadf = SyscallReturn::ok((-9i64) as u64);
    let einval = SyscallReturn::ok((-22i64) as u64);
    let outcome = fd::with_table(task, |t| {
        let entry = match t.get_mut(fd) {
            Some(e) => e,
            None => return Some(ebadf),
        };
        let base = match whence {
            SEEK_SET => 0i64,
            SEEK_CUR => entry.offset as i64,
            SEEK_END => entry.ops.stat().size as i64,
            _ => return Some(einval),
        };
        let new_off = match base.checked_add(offset) {
            Some(v) if v >= 0 => v,
            _ => return Some(einval),
        };
        entry.offset = new_off as u64;
        Some(SyscallReturn::ok(new_off as u64))
    });
    match outcome {
        Some(Some(r)) => ctx.set_return(r),
        _ => ctx.set_return(ebadf),
    }
}

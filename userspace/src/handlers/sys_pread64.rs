#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_pread64(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let ptr = args.arg1;
    let len = args.arg2 as usize;
    let offset = args.arg3;
    let fail = SyscallReturn::ok((-1i64) as u64);
    if len == 0 {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    if let Err(e) = validate_user_range(ptr, len) {
        ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
        return;
    }
    let task = current_task_id();
    // Bad fd → -EBADF, checked explicitly so it stays distinct from the
    // -1 read-error path in the `_` arm below (a blanket change would
    // mis-map genuine read failures).
    if !fd::with_table(task, |t| t.get(fd).is_some()).unwrap_or(false) {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        return;
    }
    let mut kbuf = alloc::vec![0u8; len];
    let outcome = fd::with_table(task, |t| {
        let entry = t.get(fd)?;
        let ops = entry.ops.clone();
        let res = poll_blocking(ops.read(offset, &mut kbuf))
            .unwrap_or(Err(narf_filesystem::FsError::ReadOnly));
        res.ok()
    });
    match outcome {
        Some(Some(n)) => {
            // SAFETY: ptr validated above; AS still active.
            if let Err(e) = unsafe { copy_to_user(ptr, &kbuf[..n]) } {
                ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            } else {
                ctx.set_return(SyscallReturn::ok(n as u64));
            }
        }
        _ => ctx.set_return(fail),
    }
}

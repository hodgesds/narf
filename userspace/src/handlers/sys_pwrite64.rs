#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_pwrite64(ctx: &mut dyn TrapContext) {
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
    // Validate length before allocating — reject oversized len with EINVAL
    // rather than OOMing the kernel heap.
    // SAFETY: single-threaded syscall; AS active.
    let kbuf = match unsafe { copy_from_user_vec(ptr, len) } {
        Ok(b) => b,
        Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e as i64)) as u64));
            return;
        }
    };
    let task = current_task_id();
    // Bad fd → -EBADF, checked explicitly so write errors keep the -1 path.
    if !fd::with_table(task, |t| t.get(fd).is_some()).unwrap_or(false) {
        ctx.set_return(SyscallReturn::ok((-9i64) as u64));
        return;
    }
    let outcome = fd::with_table(task, |t| {
        let entry = t
            .get(fd)
            .ok_or(narf_filesystem::FsError::ReadOnly)?;
        let ops = entry.ops.clone();
        poll_blocking(ops.write(offset, &kbuf))
            .unwrap_or(Err(narf_filesystem::FsError::ReadOnly))
    });
    match outcome {
        Some(Ok(n)) => ctx.set_return(SyscallReturn::ok(n as u64)),
        Some(Err(narf_filesystem::FsError::NoSpace)) => {
            ctx.set_return(SyscallReturn::ok((-28i64) as u64))
        }
        _ => ctx.set_return(fail),
    }
}

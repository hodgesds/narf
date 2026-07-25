#[allow(unused_imports)]
use super::*;

/// `tee(fd_in, fd_out, len, flags)` — copy up to `len` bytes from one
/// pipe to another WITHOUT consuming the input. `fd_in` must be a pipe
/// read end (peekable); `fd_out` receives the duplicated bytes.
pub(crate) fn sys_tee(ctx: &mut dyn TrapContext) {
    let a = *ctx.args();
    let fd_in = a.arg0 as u32;
    let fd_out = a.arg1 as u32;
    let len = a.arg2 as usize;
    let task = current_task_id();
    let peeked =
        fd::with_table(task, |t| t.get(fd_in).and_then(|e| e.ops.pipe_peek(len))).flatten();
    let data = match peeked {
        Some(d) => d,
        None => {
            ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // EINVAL (not a pipe read end)
            return;
        }
    };
    if data.is_empty() {
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    let w = fd::with_table(task, |t| {
        let entry = t.get_mut(fd_out).ok_or(())?;
        poll_blocking(entry.ops.write(0, &data))
            .unwrap_or(Err(narf_filesystem::FsError::ReadOnly))
            .map_err(|_| ())
    });
    match w {
        Some(Ok(n)) => ctx.set_return(SyscallReturn::ok(n as u64)),
        _ => ctx.set_return(SyscallReturn::ok((-22i64) as u64)), // EINVAL
    }
}

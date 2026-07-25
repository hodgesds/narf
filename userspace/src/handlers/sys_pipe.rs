#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_pipe(ctx: &mut dyn TrapContext) {
    let out_ptr = ctx.args().arg0;
    if out_ptr == 0 {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    let (rd, wr) = crate::pipe::pipe_pair();
    let task = current_task_id();
    let fds = fd::with_table(task, |t| {
        let r = t.open(crate::fd::FdEntry {
            ops: rd as alloc::sync::Arc<dyn narf_filesystem::FileOps>,
            offset: 0,
            flags: 0,
            status_flags: 0,
        });
        let w = t.open(crate::fd::FdEntry {
            ops: wr as alloc::sync::Arc<dyn narf_filesystem::FileOps>,
            offset: 0,
            flags: 0,
            status_flags: 0,
        });
        (r, w)
    });
    let (r, w) = match fds {
        Some(p) => p,
        None => {
            ctx.set_return(SyscallReturn::invalid_op());
            return;
        }
    };
    // Write two i32 fds to user buffer under the SMAP bracket.
    let mut buf = [0u8; 8];
    buf[..4].copy_from_slice(&(r as i32).to_ne_bytes());
    buf[4..].copy_from_slice(&(w as i32).to_ne_bytes());
    // SAFETY: `out_ptr` is the user fd-pair buffer; copy_to_user range-validates
    // it and SMAP-brackets the write of the 8-byte `buf`.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_to_user(out_ptr, &buf) }.is_err() {
        ctx.set_return(SyscallReturn::invalid_op());
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_pipe(ctx: &mut dyn TrapContext) {
    let out_ptr = ctx.args().arg0;
    let (rd, wr) = crate::pipe::pipe_pair();
    let task = current_task_id();
    // Access-mode status flags mirror `fs/pipe.c::create_pipe_files`:
    // the read end is O_RDONLY, the write end O_WRONLY (F_GETFL reports
    // them; the read/write direction checks live in the pipe FileOps).
    let fds = fd::install_pair(
        task,
        crate::fd::FdEntry {
            ops: rd as alloc::sync::Arc<dyn narf_filesystem::FileOps>,
            offset: 0,
            flags: 0,
            status_flags: crate::fd::O_RDONLY,
        },
        crate::fd::FdEntry {
            ops: wr as alloc::sync::Arc<dyn narf_filesystem::FileOps>,
            offset: 0,
            flags: 0,
            status_flags: crate::fd::O_WRONLY,
        },
    );
    let (r, w) = match fds {
        Some(pair) => pair,
        // Both ends are allocated or neither is; see `fd::install_pair`.
        None => {
            ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
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
        // Linux reserves both numbers before copy_to_user but publishes
        // neither file until that copy succeeds. NARF installed the pair to
        // obtain the numbers, so roll it back before reporting EFAULT.
        let _ = fd::with_table(task, |table| {
            table.close(r);
            table.close(w);
        });
        ctx.set_return(SyscallReturn::ok((-14i64) as u64));
        return;
    }
    ctx.set_return(SyscallReturn::ok(0));
}

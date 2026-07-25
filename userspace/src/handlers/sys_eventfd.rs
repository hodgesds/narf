#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_eventfd(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let initval = args.arg0;
    let flags = args.arg1 as u32;
    let efd = crate::io_mux::EventFd::new(initval, flags);
    let task = current_task_id();
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops: efd,
            offset: 0,
            flags: 0,
            status_flags: 0,
        })
    }) {
        Some(n) => n,
        None => {
            ctx.set_return(SyscallReturn::ok((-1i64) as u64));
            return;
        }
    };
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}

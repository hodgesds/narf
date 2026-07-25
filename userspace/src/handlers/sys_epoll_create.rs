#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_epoll_create(ctx: &mut dyn TrapContext) {
    let _flags = ctx.args().arg0;
    let ep = crate::io_mux::EpollFile::new();
    epoll_arc_register(&ep);
    let task = current_task_id();
    let new_fd = match fd::with_table(task, |t| {
        t.open(crate::fd::FdEntry {
            ops: ep,
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

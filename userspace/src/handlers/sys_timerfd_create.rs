#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_timerfd_create(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let flags = args.arg1 as u32;
    let cloexec = (flags & 0x80000) != 0;
    let nonblock = (flags & 0o4000) != 0;
    let install_flags = if cloexec { crate::fd::FD_CLOEXEC } else { 0 };
    let status_flags = if nonblock { crate::fd::O_NONBLOCK } else { 0 };

    let tfd = crate::io_mux::TimerFd::new();
    timerfd_arc_register(&tfd);
    let task = current_task_id();
    let new_fd = match fd::install(task, crate::fd::FdEntry {
            ops: tfd,
            offset: 0,
            flags: install_flags,
            status_flags,
        }) {
        Some(n) => n,
        None => {
            // `fs/timerfd.c::SYSCALL_DEFINE2(timerfd_create)` finishes with
            // `anon_inode_getfd(...)`, whose descriptor comes from
            // `get_unused_fd_flags`: a table at RLIMIT_NOFILE is -EMFILE.
            ctx.set_return(SyscallReturn::ok((-24i64) as u64)); // -EMFILE
            return;
        }
    };
    ctx.set_return(SyscallReturn::ok(new_fd as u64));
}

#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_timerfd_create(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let clockid = args.arg0 as i32;
    let flags = args.arg1 as u32;

    // `fs/timerfd.c::SYSCALL_DEFINE2(timerfd_create, int, clockid, int, flags)`:
    //
    //     if ((flags & ~TFD_CREATE_FLAGS) ||
    //         (clockid != CLOCK_MONOTONIC &&
    //          clockid != CLOCK_REALTIME &&
    //          clockid != CLOCK_REALTIME_ALARM &&
    //          clockid != CLOCK_BOOTTIME &&
    //          clockid != CLOCK_BOOTTIME_ALARM))
    //             return -EINVAL;
    //
    //     if ((clockid == CLOCK_REALTIME_ALARM ||
    //          clockid == CLOCK_BOOTTIME_ALARM) &&
    //         !capable(CAP_WAKE_ALARM))
    //             return -EPERM;
    const CLOCK_REALTIME: i32 = 0;
    const CLOCK_MONOTONIC: i32 = 1;
    const CLOCK_BOOTTIME: i32 = 7;
    const CLOCK_REALTIME_ALARM: i32 = 8;
    const CLOCK_BOOTTIME_ALARM: i32 = 9;

    const TFD_CLOEXEC: u32 = crate::fd::O_CLOEXEC;
    const TFD_NONBLOCK: u32 = crate::fd::O_NONBLOCK;
    const TFD_CREATE_FLAGS: u32 = TFD_CLOEXEC | TFD_NONBLOCK;

    if flags & !TFD_CREATE_FLAGS != 0
        || (clockid != CLOCK_MONOTONIC
            && clockid != CLOCK_REALTIME
            && clockid != CLOCK_REALTIME_ALARM
            && clockid != CLOCK_BOOTTIME
            && clockid != CLOCK_BOOTTIME_ALARM)
    {
        ctx.set_return(SyscallReturn::ok((-22i64) as u64)); // -EINVAL
        return;
    }

    if (clockid == CLOCK_REALTIME_ALARM || clockid == CLOCK_BOOTTIME_ALARM)
        && !capable(CAP_WAKE_ALARM)
    {
        ctx.set_return(SyscallReturn::ok((-1i64) as u64)); // -EPERM
        return;
    }

    let cloexec = (flags & TFD_CLOEXEC) != 0;
    let nonblock = (flags & TFD_NONBLOCK) != 0;
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

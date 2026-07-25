#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_epoll_ctl(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let epfd = args.arg0 as u32;
    let op = args.arg1 as u32;
    let fd = args.arg2 as i32;
    let event_ptr = args.arg3 as *const u8;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let task = current_task_id();
    let ep_arc = match epoll_arc_from_fd(task, epfd) {
        Some(e) => e,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    if op == EPOLL_CTL_DEL {
        ep_arc.ctl_del(fd);
        ctx.set_return(SyscallReturn::ok(0));
        return;
    }
    // ADD / MOD need to read the event struct (events: u32 + data: u64 = 12 B).
    if event_ptr.is_null() {
        ctx.set_return(fail);
        return;
    }
    let mut kbuf = [0u8; 12];
    // SAFETY: `event_ptr` is the user epoll_event pointer (non-null, checked above);
    // copy_from_user range-validates it and SMAP-brackets the 12-byte read.
    // SAFETY: Valid memory or trusted environment
    if unsafe { copy_from_user(&mut kbuf, event_ptr as u64) }.is_err() {
        ctx.set_return(fail);
        return;
    }
    let entry = crate::io_mux::EpollEntry {
        events: u32::from_le_bytes(kbuf[..4].try_into().unwrap()),
        user_data: u64::from_le_bytes(kbuf[4..].try_into().unwrap()),
    };
    match op {
        EPOLL_CTL_ADD => ep_arc.ctl_add(fd, entry),
        EPOLL_CTL_MOD => ep_arc.ctl_mod(fd, entry),
        _ => {
            ctx.set_return(fail);
            return;
        }
    }
    ctx.set_return(SyscallReturn::ok(0));
}

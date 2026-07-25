#[allow(unused_imports)]
use super::*;

/// `getsockopt(fd, level, optname, opt_val_out, opt_len_inout)`.
/// Linux ref: net/socket.c:SYSCALL_DEFINE5(getsockopt, ...).
pub(crate) fn sys_socket_getsockopt(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let level = args.arg1 as u32;
    let name = args.arg2 as u32;
    let val_ptr = args.arg3;
    let len_ptr = args.arg4;
    let fail = SyscallReturn::ok((-1i64) as u64);
    let sock = match current_socket(fd) {
        Some(s) => s,
        None => {
            ctx.set_return(fail);
            return;
        }
    };
    // Read the in/out length field via SMAP bracket.
    let in_len = if len_ptr != 0 {
        read_user_u32(len_ptr) as usize
    } else {
        0
    };
    if val_ptr == 0 || in_len == 0 {
        ctx.set_return(fail);
        return;
    }
    // Validate the output range before allocating — prevents OOM from a
    // user-supplied in_len larger than MAX_USER_COPY.
    if validate_user_range(val_ptr, in_len).is_err() {
        ctx.set_return(fail);
        return;
    }
    let mut buf = alloc::vec![0u8; in_len];
    let result = sock.dispatch_op(crate::socket::SocketOp::GetSockOpt {
        level,
        name,
        buf: &mut buf,
    });
    match result {
        crate::socket::SocketOpResult::OptValue { n } => {
            // SO_PEERCRED reports `struct ucred { pid, uid, gid }` with the
            // peer's OUTER ProcessId (stamped at connect/accept). Translate the
            // pid field into the READER's PID namespace view before handing it
            // back — dbus-broker et al. compare it against pids they hold.
            // Identity in the root namespace.
            const SOL_SOCKET: u32 = 1;
            if level == SOL_SOCKET && name == crate::socket::SO_PEERCRED && n >= 4 {
                let outer = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64;
                let visible = report_pid_to(current_task_id(), outer) as u32;
                buf[0..4].copy_from_slice(&visible.to_ne_bytes());
            }
            // Write value + updated optlen back to user under SMAP bracket.
            // SAFETY: val_ptr from userspace; AS active.
            let _ = unsafe { copy_to_user(val_ptr, &buf[..n]) };
            write_user_u32(len_ptr, n as u32);
            ctx.set_return(SyscallReturn::ok(0));
        }
        _ => ctx.set_return(fail),
    }
}

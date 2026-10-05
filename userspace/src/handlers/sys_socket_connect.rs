#[allow(unused_imports)]
use super::*;

pub(crate) fn sys_socket_connect(ctx: &mut dyn TrapContext) {
    let args = *ctx.args();
    let fd = args.arg0 as u32;
    let addr_ptr = args.arg1;
    let addr_len = args.arg2;
    // Linux __sys_connect: fdget gives -EBADF, then move_addr_to_kernel gives
    // -EINVAL / -EFAULT, then __sys_connect_file checks sock_from_file (-ENOTSOCK),
    // and finally the family's connect op (-ECONNREFUSED / -EINPROGRESS / …).
    let task = current_task_id();
    let ops = match fd::with_table(task, |table| table.get(fd).map(|e| e.ops.clone())).flatten() {
        Some(ops) => ops,
        None => {
            ctx.set_return(errno_ret(EBADF));
            return;
        }
    };
    let addr = match copy_user_addr_result(addr_ptr, addr_len) {
        Ok(a) => a,
        Err(errno) => {
            ctx.set_return(errno_ret(errno));
            return;
        }
    };
    let sock = match socket_from_file_ops(ops) {
        Some(s) => s,
        None => {
            ctx.set_return(errno_ret(ENOTSOCK));
            return;
        }
    };
    match sock.dispatch_op(crate::socket::SocketOp::Connect { addr }) {
        crate::socket::SocketOpResult::Ok(_) => ctx.set_return(SyscallReturn::ok(0)),
        crate::socket::SocketOpResult::Err(e) => {
            ctx.set_return(SyscallReturn::ok((-(e.errno() as i64)) as u64));
        }
        _ => ctx.set_return(errno_ret(EINVAL)), // unreachable
    }
}
